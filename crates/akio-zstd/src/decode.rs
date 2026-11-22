//! The decoder: frames, blocks, literals and sequences (RFC 8878 section 3.1).

use std::sync::OnceLock;

use crate::Error;
use crate::bits::BackReader;
use crate::fse;
use crate::huffman;
use crate::tables::{
    BLOCK_MAX, LL_BASE, LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, LL_MAX_LOG, MAGIC, MAX_LL,
    MAX_ML, MAX_OF, ML_BASE, ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM, ML_MAX_LOG, OF_DEFAULT_LOG,
    OF_DEFAULT_NORM, OF_MAX_LOG, SKIPPABLE_MAGIC, SKIPPABLE_MASK,
};
use crate::xxhash::xxh64;

fn le16(b: &[u8], at: usize) -> u32 {
    u32::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn le24(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], 0])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le_n(b: &[u8], at: usize, n: usize) -> u64 {
    let mut v = [0u8; 8];
    v[..n].copy_from_slice(&b[at..at + n]);
    u64::from_le_bytes(v)
}

/// Decompresses `data`: one or more frames, skippable frames included, into at most `limit`
/// bytes ([`Error::TooLarge`] beyond). Frame_Content_Size is checked against the content and
/// only reserves memory up to the limit; the content checksum is verified when present.
///
/// Like libzstd, input made only of skippable frames (or empty input) gives empty output, and
/// a match may not reach into a previous frame.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Out {
        buf: Vec::new(),
        pos: 0,
        limit,
    };
    // The tables and scratch space of the previous call on this thread (libzstd's reused
    // context): allocating and zeroing them again costs as much as decoding a small frame.
    let mut d = DECODER
        .try_with(|c| c.take())
        .ok()
        .flatten()
        .unwrap_or_default();
    let r = decompress_with(&mut d, data, &mut out);
    if d.lits.capacity() > LITS_KEEP {
        d.lits = Vec::new();
    }
    let _ = DECODER.try_with(|c| c.set(Some(d)));
    r?;
    out.buf.truncate(out.pos);
    Ok(out.buf)
}

thread_local! {
    static DECODER: std::cell::Cell<Option<Box<Decoder>>> = const { std::cell::Cell::new(None) };
}

/// Literals buffer capacity kept for the next call on the thread.
const LITS_KEEP: usize = 32 << 10;

fn decompress_with(d: &mut Decoder, data: &[u8], out: &mut Out) -> Result<(), Error> {
    let mut pos = 0;
    while data.len() - pos >= 5 {
        let rest = &data[pos..];
        let magic = le32(rest, 0);
        if magic & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
            if rest.len() < 8 {
                return Err(Error::Truncated);
            }
            let size = le32(rest, 4).checked_add(8).ok_or(Error::BadFrameHeader)? as usize;
            if size > rest.len() {
                return Err(Error::Truncated);
            }
            pos += size;
            continue;
        }
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }
        pos += d.frame(rest, out)?;
    }
    if pos != data.len() {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// A frame header (RFC 8878 section 3.1.1.1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameHeader {
    /// Size of the header, magic number included.
    pub(crate) size: usize,
    /// Window size (the content size for a single-segment frame).
    pub(crate) window: u64,
    pub(crate) dict_id: u32,
    pub(crate) content_size: Option<u64>,
    pub(crate) checksum: bool,
}

/// Parses the header of the frame at the start of `src` (whose magic number was checked):
/// `None` when `src` is shorter than the header.
pub(crate) fn frame_header(src: &[u8]) -> Result<Option<FrameHeader>, Error> {
    let Some(&fhd) = src.get(4) else {
        return Ok(None);
    };
    let single = fhd & 0x20 != 0;
    let dict_size = [0, 1, 2, 4][usize::from(fhd & 3)];
    let fcs_size = [usize::from(single), 2, 4, 8][usize::from(fhd >> 6)];
    let size = 5 + usize::from(!single) + dict_size + fcs_size;
    if src.len() < size {
        return Ok(None);
    }
    if fhd & 0x08 != 0 {
        return Err(Error::BadFrameHeader);
    }
    let mut p = 5;
    let mut window = 0u64;
    if !single {
        let wd = src[5];
        let log = 10 + u32::from(wd >> 3);
        if log > 31 {
            return Err(Error::WindowTooLarge);
        }
        window = (1u64 << log) + ((1u64 << log) >> 3) * u64::from(wd & 7);
        p += 1;
    }
    let dict_id = le_n(src, p, dict_size) as u32;
    p += dict_size;
    let content_size = match (fhd >> 6, single) {
        (0, false) => None,
        (1, _) => Some(le_n(src, p, 2) + 256),
        _ => Some(le_n(src, p, fcs_size)),
    };
    if single {
        window = content_size.unwrap_or(0);
    }
    Ok(Some(FrameHeader {
        size,
        window,
        dict_id,
        content_size,
        checksum: fhd & 0x04 != 0,
    }))
}

/// The entropy tables and repeat offsets of a dictionary, as the decoder starts a frame with.
#[derive(Clone)]
pub(crate) struct DictTables {
    huf: huffman::DTable,
    seq: SeqTables,
    reps: [u32; 3],
}

impl DictTables {
    /// Tables from a Huffman tree description and the normalized counts of the literal length,
    /// offset and match length codes (checked by the caller).
    pub(crate) fn new(
        huf_desc: &[u8],
        norms: [(&[i16], u32); 3],
        reps: [u32; 3],
    ) -> Option<DictTables> {
        let mut huf = huffman::DTable::default();
        huffman::read_table(huf_desc, &mut huf)?;
        let mut seq = SeqTables::default();
        for (i, kind) in [Kind::LitLen, Kind::Offset, Kind::MatchLen]
            .into_iter()
            .enumerate()
        {
            let (norm, log) = norms[i];
            build_seq_table(kind, norm, log, &mut seq.cells[i]);
            seq.log[i] = log;
        }
        Some(DictTables { huf, seq, reps })
    }
}

/// Bytes past the end of a literal run or a match that the fast paths may overwrite (with
/// bytes that are overwritten again later, or cut off at the end).
pub(crate) const WILD: usize = 32;

/// The output, which is also the window. `buf[..pos]` is the output so far; the rest of `buf`
/// is zeroed room for the next block, so that literals and matches can be copied in whole
/// 16-byte chunks. `buf` never grows past `limit` (neither its length nor its capacity).
pub(crate) struct Out {
    pub(crate) buf: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) limit: usize,
}

impl Out {
    /// Makes `buf` at least `pos + n` long (`n` <= `limit - pos`, checked by the caller), plus
    /// `WILD` bytes when the limit allows. Capacity grows geometrically up to the limit; the
    /// zeroed part only as far as needed, so that zeroing is cheap (in cache).
    fn grow(&mut self, n: usize) {
        let want = (self.pos + n)
            .saturating_add(WILD)
            .min(self.limit.max(self.pos + n));
        if self.buf.len() >= want {
            return;
        }
        if self.buf.capacity() < want {
            let cap = (self.buf.capacity() * 2)
                .max(want)
                .min(self.limit.max(want));
            self.buf.reserve_exact(cap - self.buf.len());
        }
        self.buf.resize(want, 0);
    }

    /// Appends `src` (whose length was checked against the limit).
    fn extend(&mut self, src: &[u8]) {
        self.grow(src.len());
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }

    /// Checks that `n` more bytes fit the limit.
    fn room(&self, n: u64) -> Result<(), Error> {
        if n > (self.limit - self.pos) as u64 {
            Err(Error::TooLarge)
        } else {
            Ok(())
        }
    }
}

/// Copies `len` bytes from `src` to `dst` within `buf` (`src + len <= dst` or overlapping
/// forwards, as LZ77 matches do: `src < dst`).
#[inline(always)]
fn copy_match(buf: &mut [u8], src: usize, dst: usize, len: usize) {
    let offset = dst - src;
    if offset >= 16 && dst + len + 16 <= buf.len() {
        // Whole chunks; each reads bytes already final (16 or more behind).
        let mut k = 0;
        loop {
            buf.copy_within(src + k..src + k + 16, dst + k);
            k += 16;
            if k >= len {
                return;
            }
        }
    }
    if offset >= len {
        buf.copy_within(src..src + len, dst);
        return;
    }
    if offset == 1 {
        let b = buf[src];
        buf[dst..dst + len].fill(b);
        return;
    }
    // Overlapping: the copied pattern doubles at each step.
    let mut d = dst;
    let end = dst + len;
    while d < end {
        let n = (d - src).min(end - d);
        buf.copy_within(src..src + n, d);
        d += n;
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SeqEntry {
    /// Baseline of the value (for offsets: the offset code).
    base: u32,
    /// Extra bits of the value.
    add_bits: u8,
    /// Bits of the next state and its baseline.
    nb_bits: u8,
    next: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    LitLen,
    Offset,
    MatchLen,
}

/// Offset codes are their own baselines and extra bits (the value is `(1 << code) + bits`,
/// worked out when decoding).
const OF_CODES: [u8; MAX_OF + 1] = {
    let mut t = [0u8; MAX_OF + 1];
    let mut i = 0;
    while i <= MAX_OF {
        t[i] = i as u8;
        i += 1;
    }
    t
};

const OF_BASES: [u32; MAX_OF + 1] = {
    let mut t = [0u32; MAX_OF + 1];
    let mut i = 0;
    while i <= MAX_OF {
        t[i] = i as u32;
        i += 1;
    }
    t
};

impl Kind {
    /// Baselines and extra bits by symbol.
    fn values(self) -> (&'static [u32], &'static [u8]) {
        match self {
            Kind::LitLen => (&LL_BASE, &LL_BITS),
            Kind::MatchLen => (&ML_BASE, &ML_BITS),
            Kind::Offset => (&OF_BASES, &OF_CODES),
        }
    }

    fn value(self, sym: u8) -> (u32, u8) {
        let (b, n) = self.values();
        (b[usize::from(sym)], n[usize::from(sym)])
    }

    fn max(self) -> usize {
        match self {
            Kind::LitLen => MAX_LL,
            Kind::Offset => MAX_OF,
            Kind::MatchLen => MAX_ML,
        }
    }

    fn max_log(self) -> u32 {
        match self {
            Kind::LitLen => LL_MAX_LOG,
            Kind::Offset => OF_MAX_LOG,
            Kind::MatchLen => ML_MAX_LOG,
        }
    }
}

/// Entries of a sequence table: accuracy logs are at most 9, and tables are stored this long
/// (the `1 << log` entries first) so that lookups need no bounds checks.
const SEQ_TABLE_SIZE: usize = 512;

type Cells = [SeqEntry; SEQ_TABLE_SIZE];

/// Builds the table of `norm` (symbols up to `kind.max()`) in the first `1 << log` cells.
fn build_seq_table(kind: Kind, norm: &[i16], log: u32, cells: &mut Cells) {
    let mut symbols = [0u8; SEQ_TABLE_SIZE];
    let mut next = fse::spread(norm, log, &mut symbols);
    let (bases, bits) = kind.values();
    for (e, &s) in cells[..1 << log].iter_mut().zip(&symbols) {
        let s = usize::from(s);
        let x = &mut next[s];
        let (nb_bits, next) = fse::next_state(u32::from(*x), log);
        *x += 1;
        *e = SeqEntry {
            base: bases[s],
            add_bits: bits[s],
            nb_bits,
            next,
        };
    }
}

/// The decoding tables of the three fields of sequences, in the order of [`Kind`], next to
/// each other so that one register addresses all three.
#[derive(Clone)]
struct SeqTables {
    cells: Box<[Cells; 3]>,
    log: [u32; 3],
    /// The slot holds the predefined table of its kind (copied there when first used).
    predef: [bool; 3],
}

impl Default for SeqTables {
    fn default() -> Self {
        SeqTables {
            cells: Box::new([[SeqEntry::default(); SEQ_TABLE_SIZE]; 3]),
            log: [0; 3],
            predef: [false; 3],
        }
    }
}

/// The predefined tables (accuracy log and cells) by [`Kind`].
fn predefined(kind: Kind) -> (u32, &'static [SeqEntry]) {
    static TABLES: OnceLock<[Vec<SeqEntry>; 3]> = OnceLock::new();
    let t = TABLES.get_or_init(|| {
        let make = |kind, norm: &[i16], log| {
            let mut c = [SeqEntry::default(); SEQ_TABLE_SIZE];
            build_seq_table(kind, norm, log, &mut c);
            c[..1 << log].to_vec()
        };
        [
            make(Kind::LitLen, &LL_DEFAULT_NORM, LL_DEFAULT_LOG),
            make(Kind::Offset, &OF_DEFAULT_NORM, OF_DEFAULT_LOG),
            make(Kind::MatchLen, &ML_DEFAULT_NORM, ML_DEFAULT_LOG),
        ]
    });
    match kind {
        Kind::LitLen => (LL_DEFAULT_LOG, &t[0]),
        Kind::Offset => (OF_DEFAULT_LOG, &t[1]),
        Kind::MatchLen => (ML_DEFAULT_LOG, &t[2]),
    }
}

impl SeqTables {
    /// Reads the table description of one sequence field in `mode`; returns its size.
    fn load(&mut self, kind: Kind, mode: u8, src: &[u8], repeat_ok: bool) -> Result<usize, Error> {
        let i = kind as usize;
        match mode {
            0 => {
                if !self.predef[i] {
                    let (log, cells) = predefined(kind);
                    self.cells[i][..cells.len()].copy_from_slice(cells);
                    self.log[i] = log;
                    self.predef[i] = true;
                }
                Ok(0)
            }
            1 => {
                let &sym = src.first().ok_or(Error::BadFseTable)?;
                if usize::from(sym) > kind.max() {
                    return Err(Error::BadFseTable);
                }
                let (base, add_bits) = kind.value(sym);
                self.cells[i][0] = SeqEntry {
                    base,
                    add_bits,
                    nb_bits: 0,
                    next: 0,
                };
                self.log[i] = 0;
                self.predef[i] = false;
                Ok(1)
            }
            2 => {
                let mut norm = [0i16; 256];
                let (max_sv, log, size) =
                    fse::read_ncount(src, kind.max(), &mut norm).ok_or(Error::BadFseTable)?;
                if log > kind.max_log() {
                    return Err(Error::BadFseTable);
                }
                build_seq_table(kind, &norm[..=max_sv], log, &mut self.cells[i]);
                self.log[i] = log;
                self.predef[i] = false;
                Ok(size)
            }
            _ => {
                if repeat_ok {
                    Ok(0)
                } else {
                    Err(Error::BadFseTable)
                }
            }
        }
    }
}

/// Makes the literals buffer at least `n + WILD` long. Its bytes are whatever an earlier block
/// left there: the literals overwrite the first `n`, the rest is read and never used.
fn lits_room(buf: &mut Vec<u8>, n: usize) {
    if buf.len() < n + WILD {
        buf.resize(n + WILD, 0);
    }
}

/// The FSE states of the three fields and the repeat offsets.
struct SeqState {
    ll: usize,
    of: usize,
    ml: usize,
    reps: [u64; 3],
}

impl SeqState {
    /// Decodes a sequence, then (`UPDATE`) moves the states on.
    #[inline(always)]
    fn decode<const UPDATE: bool>(&mut self, t: &[Cells; 3], br: &mut BackReader<'_>) -> Seq {
        const MASK: usize = SEQ_TABLE_SIZE - 1;
        let lle = t[0][self.ll & MASK];
        let ofe = t[1][self.of & MASK];
        let mle = t[2][self.ml & MASK];
        let code = ofe.base;
        let (llb, mlb) = (u32::from(lle.add_bits), u32::from(mle.add_bits));
        let extra = code + mlb + llb;
        let (ofx, mlx, llx);
        if extra < 31 {
            // The extra bits and the states' bits in one read of at most 56 bits (libzstd's
            // condition for one reload per sequence), split from the last field up.
            let (lln, mln, ofn) = if UPDATE {
                (
                    u32::from(lle.nb_bits),
                    u32::from(mle.nb_bits),
                    u32::from(ofe.nb_bits),
                )
            } else {
                (0, 0, 0)
            };
            let mut v = br.read_fast(extra + lln + mln + ofn);
            if UPDATE {
                self.of = usize::from(ofe.next) + low(v, ofn);
                v >>= ofn;
                self.ml = usize::from(mle.next) + low(v, mln);
                v >>= mln;
                self.ll = usize::from(lle.next) + low(v, lln);
                v >>= lln;
            }
            llx = low(v, llb) as u32;
            v >>= llb;
            mlx = low(v, mlb) as u32;
            ofx = v >> mlb;
        } else {
            ofx = br.read_fast(code);
            mlx = br.read_fast(mlb) as u32;
            br.reload();
            llx = br.read_fast(llb) as u32;
            if UPDATE {
                self.ll = usize::from(lle.next) + br.read_fast(u32::from(lle.nb_bits)) as usize;
                self.ml = usize::from(mle.next) + br.read_fast(u32::from(mle.nb_bits)) as usize;
                self.of = usize::from(ofe.next) + br.read_fast(u32::from(ofe.nb_bits)) as usize;
            }
        }
        br.reload();
        let reps = &mut self.reps;
        let off = if code > 1 {
            let o = ((1u64 << code) - 3) + ofx;
            *reps = [o, reps[0], reps[1]];
            o
        } else {
            let ll0 = lle.base == 0;
            if code == 0 {
                if ll0 {
                    reps.swap(0, 1);
                }
                reps[0]
            } else {
                let idx = 1 + u64::from(ll0) + ofx;
                let mut o = match idx {
                    1 => reps[1],
                    2 => reps[2],
                    _ => reps[0].wrapping_sub(1),
                };
                if o == 0 {
                    o = u64::MAX; // invalid, refused when executed
                }
                if idx != 1 {
                    reps[2] = reps[1];
                }
                reps[1] = reps[0];
                reps[0] = o;
                o
            }
        };
        let ml = mle.base + mlx;
        let ll = lle.base + llx;
        Seq { ll, ml, off }
    }
}

/// The low `n` bits (0..=63) of `v`.
#[inline(always)]
fn low(v: u64, n: u32) -> usize {
    (v & ((1u64 << n) - 1)) as usize
}

/// A decoded sequence.
#[derive(Clone, Copy, Default)]
struct Seq {
    ll: u32,
    ml: u32,
    off: u64,
}

/// Sequences decoded per batch.
const BATCH: usize = 64;

/// Bytes past the end of a sequence that its fast path may write (the 16-byte chunks of its
/// literals and match).
const FAST_SLACK: usize = 16;

/// Executes sequences: the output (the window) and the literals of the block.
struct Exec<'a> {
    buf: &'a mut [u8],
    pos: usize,
    lits: &'a [u8],
    lp: usize,
    nlits: usize,
    frame_start: usize,
    block_end: usize,
    limit: usize,
}

impl Exec<'_> {
    /// Executes `seqs`.
    #[inline(always)]
    fn run(&mut self, seqs: &[Seq]) -> Result<(), Error> {
        // A sequence ending at or before `fast_end`, whose literals end before `lits_fast`,
        // stays within the block and the limit (`buf` never exceeds it) and may copy whole
        // 16-byte chunks on both sides (matches are at least 3 bytes, so `end` > 0).
        let fast_end = self
            .block_end
            .min(self.buf.len().saturating_sub(FAST_SLACK));
        let lits_fast = (self.nlits + 1).min(self.lits.len().saturating_sub(15));
        let buf = &mut *self.buf;
        let lits = self.lits;
        let mut pos = self.pos;
        let mut lp = self.lp;
        for q in seqs {
            let (ll, ml) = (q.ll as usize, q.ml as usize);
            let end = pos + ll + ml;
            if end <= fast_end && lp + ll < lits_fast {
                buf[pos..][..16].copy_from_slice(&lits[lp..][..16]);
                let mut k = 16;
                while k < ll {
                    buf[pos + k..][..16].copy_from_slice(&lits[lp + k..][..16]);
                    k += 16;
                }
                pos += ll;
                lp += ll;
                if q.off > (pos - self.frame_start) as u64 {
                    return Err(Error::BadOffset);
                }
                let off = q.off as usize;
                let src = pos - off;
                if off >= 16 {
                    // Whole chunks; each reads bytes already final (16 or more behind).
                    let mut k = 0;
                    loop {
                        copy16_within(buf, src + k, pos + k);
                        k += 16;
                        if k >= ml {
                            break;
                        }
                    }
                } else {
                    copy_match(buf, src, pos, ml);
                }
                pos = end;
            } else {
                (pos, lp) = exec_exact(
                    buf,
                    lits,
                    self.nlits,
                    pos,
                    lp,
                    q,
                    self.frame_start,
                    self.block_end,
                    self.limit,
                )?;
            }
        }
        self.pos = pos;
        self.lp = lp;
        Ok(())
    }
}

/// Copies the 16 bytes at `from` to `to` (as a whole: `to` may be within them).
#[inline(always)]
fn copy16_within(buf: &mut [u8], from: usize, to: usize) {
    let mut c = [0u8; 16];
    c.copy_from_slice(&buf[from..][..16]);
    buf[to..][..16].copy_from_slice(&c);
}

/// Executes `q` at `pos` with the literals from `lp` (the sequence's literals and match may
/// end anywhere within `buf`, which reaches the end of the block or the limit); returns the
/// new `pos` and `lp`.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn exec_exact(
    buf: &mut [u8],
    lits: &[u8],
    nlits: usize,
    pos: usize,
    lp: usize,
    q: &Seq,
    frame_start: usize,
    block_end: usize,
    limit: usize,
) -> Result<(usize, usize), Error> {
    let (ll, ml) = (q.ll as usize, q.ml as usize);
    if ll > nlits - lp {
        return Err(Error::BadSequences);
    }
    let end = pos + ll + ml;
    if end > block_end {
        return Err(Error::BadBlock);
    }
    if end > limit {
        return Err(Error::TooLarge);
    }
    buf[pos..pos + ll].copy_from_slice(&lits[lp..lp + ll]);
    let pos = pos + ll;
    if q.off > (pos - frame_start) as u64 {
        return Err(Error::BadOffset);
    }
    copy_match(buf, pos - q.off as usize, pos, ml);
    Ok((end, lp + ll))
}

/// Decoding state kept across the blocks of a frame (and scratch space across frames).
#[derive(Default)]
pub(crate) struct Decoder {
    huf: huffman::DTable,
    have_huf: bool,
    seq_ready: bool,
    seq: SeqTables,
    reps: [u64; 3],
    lits: Vec<u8>,
}

impl Decoder {
    /// Resets the state carried from block to block for a new frame: no Huffman or sequence
    /// tables and the initial repeat offsets, or those of a dictionary.
    pub(crate) fn start_frame(&mut self, dict: Option<&DictTables>) {
        match dict {
            None => {
                self.have_huf = false;
                self.seq_ready = false;
                self.reps = [1, 4, 8];
            }
            Some(d) => {
                self.huf.clone_from(&d.huf);
                self.have_huf = true;
                *self.seq.cells = *d.seq.cells;
                self.seq.log = d.seq.log;
                self.seq.predef = [false; 3];
                self.seq_ready = true;
                self.reps = d.reps.map(u64::from);
            }
        }
    }

    /// Decodes the frame at the start of `src` (whose magic number was checked); returns its
    /// size.
    fn frame(&mut self, src: &[u8], out: &mut Out) -> Result<usize, Error> {
        let h = match frame_header(src)? {
            Some(h) if src.len() >= h.size + 3 => h,
            _ => return Err(Error::Truncated),
        };
        if h.dict_id != 0 {
            return Err(Error::DictionaryRequired);
        }
        let mut p = h.size;
        let window = h.window;
        let content_size = h.content_size;
        let block_max = window.min(BLOCK_MAX as u64) as usize;
        if let Some(n) = content_size {
            // A hint only: refuse early what cannot fit, reserve at most the limit.
            out.room(n)?;
            let want = (out.pos + n as usize).saturating_add(WILD).min(out.limit);
            out.buf.reserve_exact(want.saturating_sub(out.buf.len()));
        }
        self.start_frame(None);
        let start = out.pos;
        loop {
            if src.len() - p < 3 {
                return Err(Error::Truncated);
            }
            let bh = le24(src, p);
            p += 3;
            let size = (bh >> 3) as usize;
            match (bh >> 1) & 3 {
                0 => {
                    if size > src.len() - p {
                        return Err(Error::Truncated);
                    }
                    if size > block_max {
                        return Err(Error::BadBlock);
                    }
                    out.room(size as u64)?;
                    out.extend(&src[p..p + size]);
                    p += size;
                }
                1 => {
                    if src.len() - p < 1 {
                        return Err(Error::Truncated);
                    }
                    if size > block_max {
                        return Err(Error::BadBlock);
                    }
                    out.room(size as u64)?;
                    out.grow(size);
                    out.buf[out.pos..out.pos + size].fill(src[p]);
                    out.pos += size;
                    p += 1;
                }
                2 => {
                    if size > src.len() - p {
                        return Err(Error::Truncated);
                    }
                    if size > block_max {
                        return Err(Error::BadBlock);
                    }
                    self.block(&src[p..p + size], out, start, block_max)?;
                    p += size;
                }
                _ => return Err(Error::BadBlock),
            }
            if bh & 1 == 1 {
                break;
            }
        }
        if let Some(n) = content_size {
            if (out.pos - start) as u64 != n {
                return Err(Error::ContentSizeMismatch);
            }
        }
        if h.checksum {
            if src.len() - p < 4 {
                return Err(Error::Truncated);
            }
            if xxh64(&out.buf[start..out.pos], 0) as u32 != le32(src, p) {
                return Err(Error::ChecksumMismatch);
            }
            p += 4;
        }
        Ok(p)
    }

    /// Decodes a compressed block.
    pub(crate) fn block(
        &mut self,
        b: &[u8],
        out: &mut Out,
        frame_start: usize,
        block_max: usize,
    ) -> Result<(), Error> {
        if b.len() < 2 {
            return Err(Error::BadBlock);
        }
        let mut lits = std::mem::take(&mut self.lits);
        let r = self.literals(b, &mut lits, out.limit - out.pos, block_max);
        let r = r.and_then(|(raw, n, used)| {
            // Literals with at least WILD bytes after them when possible (raw ones: the rest
            // of the block).
            let l: &[u8] = match raw {
                Some(at) => &b[at..],
                None => &lits,
            };
            self.sequences(&b[used..], l, n, out, frame_start, block_max)
        });
        self.lits = lits;
        r
    }

    /// Decodes the literals section into `buf` (followed by `WILD` spare bytes), or locates raw
    /// literals in `b`. Returns where raw literals are (`None`: in `buf`), how many literals
    /// there are and the size of the section.
    #[allow(clippy::type_complexity)]
    fn literals(
        &mut self,
        b: &[u8],
        buf: &mut Vec<u8>,
        free: usize,
        block_max: usize,
    ) -> Result<(Option<usize>, usize, usize), Error> {
        let b0 = b[0];
        let sf = (b0 >> 2) & 3;
        match b0 & 3 {
            t @ (0 | 1) => {
                let (lh, size) = match sf {
                    1 => (2, (le16(b, 0) >> 4) as usize),
                    3 => {
                        if b.len() < 3 {
                            return Err(Error::BadLiterals);
                        }
                        (3, (le24(b, 0) >> 4) as usize)
                    }
                    _ => (1, usize::from(b0 >> 3)),
                };
                if t == 1 && b.len() < lh + 1 {
                    return Err(Error::BadLiterals);
                }
                if size > block_max {
                    return Err(Error::BadLiterals);
                }
                if size > free {
                    return Err(Error::TooLarge);
                }
                if t == 0 {
                    if lh + size > b.len() {
                        return Err(Error::BadLiterals);
                    }
                    Ok((Some(lh), size, lh + size))
                } else {
                    lits_room(buf, size);
                    buf[..size].fill(b[lh]);
                    Ok((None, size, lh + 1))
                }
            }
            t => {
                if t == 3 && !self.have_huf {
                    return Err(Error::BadLiterals);
                }
                if b.len() < 5 {
                    return Err(Error::BadLiterals);
                }
                let lhc = le32(b, 0) as usize;
                let (lh, size, csize, four) = match sf {
                    0 | 1 => (3, (lhc >> 4) & 0x3FF, (lhc >> 14) & 0x3FF, sf == 1),
                    2 => (4, (lhc >> 4) & 0x3FFF, lhc >> 18, true),
                    _ => (
                        5,
                        (lhc >> 4) & 0x3FFFF,
                        (lhc >> 22) + (usize::from(b[4]) << 10),
                        true,
                    ),
                };
                if size > block_max || (four && size < 6) || lh + csize > b.len() {
                    return Err(Error::BadLiterals);
                }
                if size > free {
                    return Err(Error::TooLarge);
                }
                let mut src = &b[lh..lh + csize];
                if t == 2 {
                    let h =
                        huffman::read_table(src, &mut self.huf).ok_or(Error::BadHuffmanTable)?;
                    if h >= src.len() {
                        return Err(Error::BadHuffmanTable);
                    }
                    self.have_huf = true;
                    src = &src[h..];
                }
                lits_room(buf, size);
                huffman::decode(&mut self.huf, src, &mut buf[..size], four, csize)?;
                Ok((None, size, lh + csize))
            }
        }
    }

    /// Decodes the sequences section `s` and executes it with the first `nlits` bytes of
    /// `lits` as literals (the bytes after them may be read, never used).
    fn sequences(
        &mut self,
        s: &[u8],
        lits: &[u8],
        nlits: usize,
        out: &mut Out,
        frame_start: usize,
        block_max: usize,
    ) -> Result<(), Error> {
        let block_start = out.pos;
        let &b0 = s.first().ok_or(Error::BadSequences)?;
        let (count, mut q) = match b0 {
            0..=0x7F => (usize::from(b0), 1),
            0xFF => {
                if s.len() < 3 {
                    return Err(Error::BadSequences);
                }
                (le16(s, 1) as usize + 0x7F00, 3)
            }
            _ => {
                if s.len() < 2 {
                    return Err(Error::BadSequences);
                }
                ((usize::from(b0 - 0x80) << 8) + usize::from(s[1]), 2)
            }
        };
        if count == 0 {
            if q != s.len() {
                return Err(Error::BadSequences);
            }
            out.room(nlits as u64)?;
            out.extend(&lits[..nlits]);
            return Ok(());
        }
        let &modes = s.get(q).ok_or(Error::BadSequences)?;
        q += 1;
        if modes & 3 != 0 {
            return Err(Error::BadSequences);
        }
        let ready = self.seq_ready;
        let t = &mut self.seq;
        q += t.load(Kind::LitLen, modes >> 6, &s[q..], ready)?;
        q += t.load(Kind::Offset, (modes >> 4) & 3, &s[q..], ready)?;
        q += t.load(Kind::MatchLen, (modes >> 2) & 3, &s[q..], ready)?;
        self.seq_ready = true;

        let mut br = BackReader::new(&s[q..]).ok_or(Error::BadSequences)?;
        let mut st = SeqState {
            ll: br.read(t.log[0]) as usize,
            of: br.read(t.log[1]) as usize,
            ml: br.read(t.log[2]) as usize,
            reps: self.reps,
        };
        br.reload();
        let cells = &*t.cells;
        // Room for the whole block (the zeroed part of `buf` beyond it allows wild copies).
        let block_end = block_start + block_max;
        out.grow(block_max.min(out.limit - block_start));
        let mut x = Exec {
            buf: &mut out.buf[..],
            pos: block_start,
            lits,
            lp: 0,
            nlits,
            frame_start,
            block_end,
            limit: out.limit,
        };
        // Sequences are decoded in batches and then executed: two loops with fewer live
        // values each than one doing both (which spilled to the stack).
        let mut seqs = [Seq::default(); BATCH];
        let mut left = count;
        while left > 0 {
            let n = left.min(BATCH);
            left -= n;
            // The states are not updated after the last sequence.
            let (body, last) = seqs[..n].split_at_mut(n - usize::from(left == 0));
            for q in body {
                *q = st.decode::<true>(cells, &mut br);
            }
            if let Some(q) = last.first_mut() {
                *q = st.decode::<false>(cells, &mut br);
            }
            x.run(&seqs[..n])?;
        }
        let reps = st.reps;
        let pos = x.pos;
        let lp = x.lp;
        out.pos = pos;
        if !br.finished() {
            return Err(Error::BadSequences);
        }
        self.reps = reps;
        let rest = &lits[lp..nlits];
        if out.pos + rest.len() > block_start + block_max {
            return Err(Error::BadBlock);
        }
        out.room(rest.len() as u64)?;
        out.extend(rest);
        Ok(())
    }
}
