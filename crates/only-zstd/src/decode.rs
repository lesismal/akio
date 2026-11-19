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
    let mut d = Decoder::default();
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
        pos += d.frame(rest, &mut out)?;
    }
    if pos != data.len() {
        return Err(Error::Truncated);
    }
    out.buf.truncate(out.pos);
    Ok(out.buf)
}

/// Bytes past the end of a literal run or a match that the fast paths may overwrite (with
/// bytes that are overwritten again later, or cut off at the end).
const WILD: usize = 32;

/// The output, which is also the window. `buf[..pos]` is the output so far; the rest of `buf`
/// is zeroed room for the next block, so that literals and matches can be copied in whole
/// 16-byte chunks. `buf` never grows past `limit` (neither its length nor its capacity).
struct Out {
    buf: Vec<u8>,
    pos: usize,
    limit: usize,
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

impl Kind {
    fn value(self, sym: u8) -> (u32, u8) {
        let s = usize::from(sym);
        match self {
            Kind::LitLen => (LL_BASE[s], LL_BITS[s]),
            Kind::MatchLen => (ML_BASE[s], ML_BITS[s]),
            Kind::Offset => (u32::from(sym), sym),
        }
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

#[derive(Clone, Debug, Default)]
struct SeqTable {
    log: u32,
    entries: Vec<SeqEntry>,
    /// Scratch space for building.
    cells: Vec<fse::DEntry>,
    /// The predefined table is in use (not copied here).
    predef: bool,
}

impl SeqTable {
    /// The table in use: this one or the predefined one of `kind`.
    fn active(&self, kind: Kind) -> &SeqTable {
        if self.predef { predefined(kind) } else { self }
    }

    fn cells(&self) -> Result<&[SeqEntry; SEQ_TABLE_SIZE], Error> {
        self.entries
            .get(..SEQ_TABLE_SIZE)
            .and_then(|e| e.try_into().ok())
            .ok_or(Error::BadFseTable)
    }
}

impl SeqTable {
    fn from_norm(kind: Kind, norm: &[i16], log: u32) -> SeqTable {
        let mut t = SeqTable::default();
        t.fill(kind, norm, log, &mut Vec::new());
        t
    }

    /// Builds the table of `norm` in place (`cells`: scratch space). Entries past `1 << log`
    /// are left as they are: states never reach them.
    fn fill(&mut self, kind: Kind, norm: &[i16], log: u32, cells: &mut Vec<fse::DEntry>) {
        fse::build_dtable(norm, log, cells);
        if self.entries.len() < SEQ_TABLE_SIZE {
            self.entries.resize(SEQ_TABLE_SIZE, SeqEntry::default());
        }
        for (e, c) in self.entries.iter_mut().zip(cells.iter()) {
            let (base, add_bits) = kind.value(c.symbol);
            *e = SeqEntry {
                base,
                add_bits,
                nb_bits: c.nb_bits,
                next: c.base,
            };
        }
        self.log = log;
    }

    fn set_rle(&mut self, kind: Kind, sym: u8) {
        let (base, add_bits) = kind.value(sym);
        if self.entries.len() < SEQ_TABLE_SIZE {
            self.entries.resize(SEQ_TABLE_SIZE, SeqEntry::default());
        }
        self.entries[0] = SeqEntry {
            base,
            add_bits,
            nb_bits: 0,
            next: 0,
        };
        self.log = 0;
    }
}

fn predefined(kind: Kind) -> &'static SeqTable {
    static TABLES: OnceLock<[SeqTable; 3]> = OnceLock::new();
    let t = TABLES.get_or_init(|| {
        [
            SeqTable::from_norm(Kind::LitLen, &LL_DEFAULT_NORM, LL_DEFAULT_LOG),
            SeqTable::from_norm(Kind::Offset, &OF_DEFAULT_NORM, OF_DEFAULT_LOG),
            SeqTable::from_norm(Kind::MatchLen, &ML_DEFAULT_NORM, ML_DEFAULT_LOG),
        ]
    });
    match kind {
        Kind::LitLen => &t[0],
        Kind::Offset => &t[1],
        Kind::MatchLen => &t[2],
    }
}

/// Reads the table description of one sequence field in `mode`; returns its size.
fn load_table(
    t: &mut SeqTable,
    kind: Kind,
    mode: u8,
    src: &[u8],
    repeat_ok: bool,
) -> Result<usize, Error> {
    match mode {
        0 => {
            t.predef = true;
            Ok(0)
        }
        1 => {
            let &sym = src.first().ok_or(Error::BadFseTable)?;
            if usize::from(sym) > kind.max() {
                return Err(Error::BadFseTable);
            }
            t.set_rle(kind, sym);
            t.predef = false;
            Ok(1)
        }
        2 => {
            let mut norm = [0i16; 256];
            let (max_sv, log, size) =
                fse::read_ncount(src, kind.max(), &mut norm).ok_or(Error::BadFseTable)?;
            if log > kind.max_log() {
                return Err(Error::BadFseTable);
            }
            let mut cells = std::mem::take(&mut t.cells);
            t.fill(kind, &norm[..=max_sv], log, &mut cells);
            t.cells = cells;
            t.predef = false;
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

/// Decoding state kept across the blocks of a frame (and scratch space across frames).
#[derive(Default)]
struct Decoder {
    huf: huffman::DTable,
    have_huf: bool,
    seq_ready: bool,
    ll: SeqTable,
    of: SeqTable,
    ml: SeqTable,
    reps: [u64; 3],
    lits: Vec<u8>,
}

impl Decoder {
    /// Decodes the frame at the start of `src` (whose magic number was checked); returns its
    /// size.
    fn frame(&mut self, src: &[u8], out: &mut Out) -> Result<usize, Error> {
        let fhd = src[4];
        let single = fhd & 0x20 != 0;
        let dict_size = [0, 1, 2, 4][usize::from(fhd & 3)];
        let fcs_size = [usize::from(single), 2, 4, 8][usize::from(fhd >> 6)];
        let header = 5 + usize::from(!single) + dict_size + fcs_size;
        if src.len() < header + 3 {
            return Err(Error::Truncated);
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
        let dict_id = le_n(src, p, dict_size);
        p += dict_size;
        let content_size = match (fhd >> 6, single) {
            (0, false) => None,
            (1, _) => Some(le_n(src, p, 2) + 256),
            _ => Some(le_n(src, p, fcs_size)),
        };
        p += fcs_size;
        if single {
            window = content_size.unwrap_or(0);
        }
        if dict_id != 0 {
            return Err(Error::DictionaryRequired);
        }
        let block_max = window.min(BLOCK_MAX as u64) as usize;
        if let Some(n) = content_size {
            // A hint only: refuse early what cannot fit, reserve at most the limit.
            out.room(n)?;
            let want = (out.pos + n as usize).saturating_add(WILD).min(out.limit);
            out.buf.reserve_exact(want.saturating_sub(out.buf.len()));
        }
        self.have_huf = false;
        self.seq_ready = false;
        self.reps = [1, 4, 8];
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
        if fhd & 0x04 != 0 {
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
    fn block(
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
                    buf.clear();
                    buf.resize(size + WILD, b[lh]);
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
                buf.clear();
                buf.resize(size + WILD, 0);
                huffman::decode(&self.huf, src, &mut buf[..size], four)?;
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
        q += load_table(&mut self.ll, Kind::LitLen, modes >> 6, &s[q..], ready)?;
        q += load_table(&mut self.of, Kind::Offset, (modes >> 4) & 3, &s[q..], ready)?;
        q += load_table(
            &mut self.ml,
            Kind::MatchLen,
            (modes >> 2) & 3,
            &s[q..],
            ready,
        )?;
        self.seq_ready = true;

        let mut br = BackReader::new(&s[q..]).ok_or(Error::BadSequences)?;
        let (ll, of, ml) = (
            self.ll.active(Kind::LitLen),
            self.of.active(Kind::Offset),
            self.ml.active(Kind::MatchLen),
        );
        let (ll_t, of_t, ml_t) = (ll.cells()?, of.cells()?, ml.cells()?);
        const MASK: usize = SEQ_TABLE_SIZE - 1;
        let mut ll_s = br.read(ll.log) as usize;
        let mut of_s = br.read(of.log) as usize;
        let mut ml_s = br.read(ml.log) as usize;
        br.reload();
        let mut reps = self.reps;
        let mut lp = 0usize;
        // Room for the whole block (the zeroed part of `buf` beyond it allows wild copies).
        let block_end = block_start + block_max;
        out.grow(block_max.min(out.limit - block_start));
        let limit = out.limit;
        let buf = &mut out.buf[..];
        let mut pos = block_start;
        for i in 0..count {
            let lle = ll_t[ll_s & MASK];
            let ofe = of_t[of_s & MASK];
            let mle = ml_t[ml_s & MASK];
            let code = ofe.base;
            let offset = if code > 1 {
                let o = ((1u64 << code) - 3) + br.read_fast(code);
                reps = [o, reps[0], reps[1]];
                o
            } else {
                let ll0 = lle.base == 0;
                if code == 0 {
                    if ll0 {
                        reps.swap(0, 1);
                    }
                    reps[0]
                } else {
                    let idx = 1 + u64::from(ll0) + br.read_fast(1);
                    let mut o = match idx {
                        1 => reps[1],
                        2 => reps[2],
                        _ => reps[0].wrapping_sub(1),
                    };
                    if o == 0 {
                        o = u64::MAX; // invalid, refused below
                    }
                    if idx != 1 {
                        reps[2] = reps[1];
                    }
                    reps[1] = reps[0];
                    reps[0] = o;
                    o
                }
            };
            let ml = mle.base as usize + br.read_fast(u32::from(mle.add_bits)) as usize;
            br.reload();
            let ll = lle.base as usize + br.read_fast(u32::from(lle.add_bits)) as usize;
            if i + 1 < count {
                ll_s = usize::from(lle.next) + br.read_fast(u32::from(lle.nb_bits)) as usize;
                ml_s = usize::from(mle.next) + br.read_fast(u32::from(mle.nb_bits)) as usize;
                of_s = usize::from(ofe.next) + br.read_fast(u32::from(ofe.nb_bits)) as usize;
                br.reload();
            }
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
            // Literals: whole 16-byte chunks when both sides have room.
            if lp + ll + 16 <= lits.len() && pos + ll + 16 <= buf.len() {
                let mut k = 0;
                loop {
                    buf[pos + k..pos + k + 16].copy_from_slice(&lits[lp + k..lp + k + 16]);
                    k += 16;
                    if k >= ll {
                        break;
                    }
                }
            } else {
                buf[pos..pos + ll].copy_from_slice(&lits[lp..lp + ll]);
            }
            pos += ll;
            lp += ll;
            if offset > (pos - frame_start) as u64 {
                return Err(Error::BadOffset);
            }
            copy_match(buf, pos - offset as usize, pos, ml);
            pos = end;
        }
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
