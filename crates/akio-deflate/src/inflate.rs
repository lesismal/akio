//! Streaming decompression of raw DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952).
//!
//! The decoder is a resumable state machine: every step (a block header, one code length, one
//! literal or one length/distance pair) is decoded only once all of its bits are available, so
//! input may be split anywhere and output may be taken in pieces of any size. Decoded bytes of
//! compressed blocks go to an internal window buffer first (the back-reference history) and are
//! copied out from there, which bounds the work done beyond the caller's output space to one
//! match (258 bytes). Stored blocks are copied straight from the input to the output; only the
//! last window's worth of them is copied into the history afterwards.

use std::sync::OnceLock;

use crate::checksum::{Adler32, Crc32};
use crate::tables::{
    CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA, fixed_lit_lens, length_counts,
    reverse_bits,
};
use crate::{Error, Format};

// ---- Huffman decoding tables ----------------------------------------------------------------
//
// An entry is a `u32`: bits 0..5 the code length (the bits to consume), bits 5..10 the extra
// bits (or, for a link, the index bits of the subtable), bits 10..13 the kind, bits 16..32 the
// value (literal, base length or distance, code length symbol, or subtable offset). Codes longer
// than the primary index go through one subtable level.

const K_LIT: u32 = 0;
const K_LEN: u32 = 1;
const K_EOB: u32 = 2;
const K_LINK: u32 = 3;
const K_BAD: u32 = 4;

const LIT_BITS: u32 = 10;
const DIST_BITS: u32 = 8;
const CL_BITS: u32 = 7;

const fn entry(kind: u32, val: u32, len: u32, extra: u32) -> u32 {
    (val << 16) | (kind << 10) | (extra << 5) | len
}

#[inline(always)]
const fn kind(e: u32) -> u32 {
    (e >> 10) & 7
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
    CodeLens,
    Lit,
    Dist,
}

impl Table {
    const fn primary_bits(self) -> u32 {
        match self {
            Table::CodeLens => CL_BITS,
            Table::Lit => LIT_BITS,
            Table::Dist => DIST_BITS,
        }
    }

    fn entry(self, sym: usize, len: u32) -> u32 {
        match self {
            Table::CodeLens => entry(K_LIT, sym as u32, len, 0),
            Table::Lit => match sym {
                0..=255 => entry(K_LIT, sym as u32, len, 0),
                256 => entry(K_EOB, 0, len, 0),
                257..=285 => entry(
                    K_LEN,
                    u32::from(LEN_BASE[sym - 257]),
                    len,
                    u32::from(LEN_EXTRA[sym - 257]),
                ),
                _ => entry(K_BAD, 0, len, 0),
            },
            Table::Dist => match sym {
                0..=29 => entry(
                    K_LIT,
                    u32::from(DIST_BASE[sym]),
                    len,
                    u32::from(DIST_EXTRA[sym]),
                ),
                _ => entry(K_BAD, 0, len, 0),
            },
        }
    }
}

/// Builds the decoding table of the canonical code with lengths `lens` into `out`. Returns false
/// for an over-subscribed code, or an incomplete one other than a single one-bit code (the same
/// rules as zlib). A code without any symbol gives a table of invalid entries.
fn build_table(lens: &[u8], code: Table, out: &mut Vec<u32>) -> bool {
    let pbits = code.primary_bits();
    let psize = 1usize << pbits;
    let count = length_counts(lens);
    let max = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0) as u32;
    let bad = entry(K_BAD, 0, pbits, 0);
    if max == 0 {
        out.clear();
        out.resize(psize, bad);
        return true;
    }
    let mut left: i32 = 1;
    for &c in &count[1..] {
        left = (left << 1) - i32::from(c);
        if left < 0 {
            return false;
        }
    }
    if left > 0 && (code == Table::CodeLens || max != 1) {
        return false;
    }
    if left > 0 {
        out.clear();
    } else {
        // A complete code writes every entry: the old contents need no clearing.
        out.truncate(psize);
    }
    out.resize(psize, bad);
    let mut next = [0u32; 16];
    let mut c = 0u32;
    for len in 1..16 {
        c = (c + u32::from(count[len - 1])) << 1;
        next[len] = c;
    }
    let pmask = (psize - 1) as u32;
    if max > pbits {
        let mut sub = [0u8; 1 << LIT_BITS];
        let mut nx = next;
        for &l in lens {
            let l = u32::from(l);
            if l == 0 {
                continue;
            }
            let code = nx[l as usize];
            nx[l as usize] += 1;
            if l > pbits {
                let p = (reverse_bits(code, l) & pmask) as usize;
                sub[p] = sub[p].max((l - pbits) as u8);
            }
        }
        for (p, &sb) in sub[..psize].iter().enumerate() {
            if sb != 0 {
                let sb = u32::from(sb);
                let off = out.len();
                out.resize(off + (1 << sb), entry(K_BAD, 0, pbits + sb, 0));
                out[p] = entry(K_LINK, off as u32, pbits, sb);
            }
        }
    }
    for (sym, &l) in lens.iter().enumerate() {
        let l = u32::from(l);
        if l == 0 {
            continue;
        }
        let r = reverse_bits(next[l as usize], l);
        next[l as usize] += 1;
        let e = code.entry(sym, l);
        if l <= pbits {
            for x in out[..psize].iter_mut().skip(r as usize).step_by(1 << l) {
                *x = e;
            }
        } else {
            let link = out[(r & pmask) as usize];
            let off = (link >> 16) as usize;
            let sb = (link >> 5) & 31;
            let sub = &mut out[off..off + (1 << sb)];
            for x in sub
                .iter_mut()
                .skip((r >> pbits) as usize)
                .step_by(1 << (l - pbits))
            {
                *x = e;
            }
        }
    }
    true
}

/// The primary part of a decoding table (`N` = `2^pbits` entries; tables are never shorter).
#[inline(always)]
fn primary<const N: usize>(table: &[u32]) -> &[u32; N] {
    const BAD: [u32; LIT_N] = [entry(K_BAD, 0, 0, 0); LIT_N];
    match table.first_chunk::<N>() {
        Some(p) => p,
        None => BAD.first_chunk::<N>().unwrap_or_else(|| unreachable!()),
    }
}

/// Looks up the next symbol in `table`, whose primary part is `primary`; the caller checks the
/// entry's length against the bits it has.
#[inline(always)]
fn lookup<const N: usize>(primary: &[u32; N], table: &[u32], bits: u64) -> u32 {
    let e = primary[(bits as usize) & (N - 1)];
    if kind(e) == K_LINK {
        let sb = (e >> 5) & 31;
        let pbits = N.trailing_zeros();
        table[(e >> 16) as usize + ((bits >> pbits) as usize & ((1 << sb) - 1))]
    } else {
        e
    }
}

const LIT_N: usize = 1 << LIT_BITS;
const DIST_N: usize = 1 << DIST_BITS;
const CL_N: usize = 1 << CL_BITS;

struct Fixed {
    lit: Vec<u32>,
    dist: Vec<u32>,
}

fn fixed() -> &'static Fixed {
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    FIXED.get_or_init(|| {
        let (mut lit, mut dist) = (Vec::new(), Vec::new());
        let ok = build_table(&fixed_lit_lens(), Table::Lit, &mut lit)
            && build_table(&[5u8; 32], Table::Dist, &mut dist);
        debug_assert!(ok);
        Fixed { lit, dist }
    })
}

// ---- bit input --------------------------------------------------------------------------------

#[inline(always)]
fn low_bits(n: u32) -> u64 {
    (1u64 << n) - 1
}

/// Tops the bit buffer up to at least 48 bits while input lasts (one step needs at most 48:
/// a 15-bit length code, 5 extra bits, a 15-bit distance code and 13 extra bits). Bits above
/// `bitcnt` are kept zero.
#[inline(always)]
fn refill(bb: &mut u64, bc: &mut u32, input: &[u8], ip: &mut usize) {
    if *bc >= 48 {
        return;
    }
    if let Some(w) = input.get(*ip..*ip + 8) {
        let word = u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]);
        let n = (63 - *bc) >> 3;
        *bb |= word << *bc;
        *ip += n as usize;
        *bc += n << 3;
        *bb &= low_bits(*bc);
    } else {
        while *bc < 48 && *ip < input.len() {
            *bb |= u64::from(input[*ip]) << *bc;
            *ip += 1;
            *bc += 8;
        }
    }
}

/// The eight bytes at `i`, little endian.
#[inline(always)]
fn load64(s: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(<[u8; 8]>::try_from(&s[i..i + 8]).unwrap_or_default())
}

/// Copies the `len` bytes `dist` back to `wpos` in 8- or 16-byte chunks, which may write up to
/// 15 bytes beyond `wpos + len` (later output overwrites them; `SLACK` keeps them inside).
#[inline(always)]
fn copy_match(win: &mut [u8], wpos: usize, dist: usize, len: usize) {
    let src = wpos - dist;
    if dist >= 16 {
        // Each chunk reads only bytes already final.
        let mut k = 0;
        while k < len {
            win.copy_within(src + k..src + k + 16, wpos + k);
            k += 16;
        }
    } else if dist >= 8 {
        let mut k = 0;
        while k < len {
            win.copy_within(src + k..src + k + 8, wpos + k);
            k += 8;
        }
    } else {
        // The first eight bytes one at a time (the pattern of period `dist`), then chunks from
        // a multiple of the period back that is at least eight bytes.
        for i in 0..8 {
            win[wpos + i] = win[src + i];
        }
        let p = dist * 8usize.div_ceil(dist);
        let mut k = 8;
        while k < len {
            win.copy_within(wpos + k - p..wpos + k - p + 8, wpos + k);
            k += 8;
        }
    }
}

// ---- the decoder ------------------------------------------------------------------------------

/// What one [`Inflater::decompress`] call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// Input bytes consumed. At the end of the stream, whole bytes read ahead are given back, so
    /// `input[consumed..]` is what follows the stream.
    pub consumed: usize,
    /// Output bytes written.
    pub produced: usize,
    /// The end of the stream was reached (and all of its output delivered).
    pub done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gz {
    Fixed,
    ExtraLen,
    Extra,
    Name,
    Comment,
    HeaderCrc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    ZlibHeader,
    GzHeader(Gz),
    Block,
    StoredLen,
    Stored,
    DynCounts,
    DynCodeLens,
    DynLens,
    Codes,
    Trailer,
    Done,
    Failed(Error),
}

const MAX_MATCH: usize = 258;
/// Room kept after `wpos` while decoding: one match plus the overrun of 16-byte chunk copies.
const SLACK: usize = MAX_MATCH + 16;
const GZ_FHCRC: u8 = 0x02;
const GZ_FEXTRA: u8 = 0x04;
const GZ_FNAME: u8 = 0x08;
const GZ_FCOMMENT: u8 = 0x10;

/// A streaming DEFLATE / zlib / gzip decompressor.
///
/// Feed input in pieces of any size with [`decompress`](Inflater::decompress) (into a slice) or
/// [`decompress_vec`](Inflater::decompress_vec) (into a `Vec` with a size limit, the defence
/// against decompression bombs). [`reset`](Inflater::reset) starts a new stream and keeps the
/// buffers.
///
/// ```
/// use akio_deflate::{Format, Inflater, Level, compress};
///
/// let packed = compress(Format::Gzip, Level::DEFAULT, b"hello hello hello hello");
/// let mut inf = Inflater::new(Format::Gzip);
/// let mut out = Vec::new();
/// // Any split of the input works.
/// for piece in packed.chunks(3) {
///     inf.decompress_vec(piece, &mut out, 1 << 20).unwrap();
/// }
/// assert!(inf.is_done());
/// assert_eq!(out, b"hello hello hello hello");
/// ```
pub struct Inflater {
    format: Format,
    wbits: u8,
    state: State,
    bitbuf: u64,
    bitcnt: u32,
    /// History and not yet delivered output: `win[..wpos]` is decoded, `win[flushed..wpos]`
    /// still has to be copied out.
    win: Vec<u8>,
    wpos: usize,
    flushed: usize,
    last: bool,
    fixed: bool,
    lit: Vec<u32>,
    dist: Vec<u32>,
    nlen: usize,
    ndist: usize,
    ncl: usize,
    idx: usize,
    lens: [u8; 320],
    stored_left: usize,
    hbuf: [u8; 10],
    hn: usize,
    gz_flags: u8,
    gz_left: usize,
    hcrc: Crc32,
    adler: Adler32,
    crc: Crc32,
    total_in: u64,
    total_out: u64,
}

impl std::fmt::Debug for Inflater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflater")
            .field("format", &self.format)
            .field("window_bits", &self.wbits)
            .field("state", &self.state)
            .field("total_in", &self.total_in)
            .field("total_out", &self.total_out)
            .finish_non_exhaustive()
    }
}

impl Inflater {
    /// A decompressor for `format` with the largest window (32 KiB), which decodes every valid
    /// stream.
    pub fn new(format: Format) -> Inflater {
        Inflater::with_window_bits(format, 15)
    }

    /// A decompressor whose window is `2^bits` bytes (`bits` clamped to 8..=15). Back-references
    /// further than the window are rejected ([`Error::BadDistance`]), and so is a zlib header
    /// announcing a larger window. A smaller window needs less memory.
    pub fn with_window_bits(format: Format, bits: u8) -> Inflater {
        let mut inf = Inflater {
            format,
            wbits: bits.clamp(8, 15),
            state: State::Block,
            bitbuf: 0,
            bitcnt: 0,
            win: Vec::new(),
            wpos: 0,
            flushed: 0,
            last: false,
            fixed: false,
            lit: Vec::new(),
            dist: Vec::new(),
            nlen: 0,
            ndist: 0,
            ncl: 0,
            idx: 0,
            lens: [0; 320],
            stored_left: 0,
            hbuf: [0; 10],
            hn: 0,
            gz_flags: 0,
            gz_left: 0,
            hcrc: Crc32::new(),
            adler: Adler32::new(),
            crc: Crc32::new(),
            total_in: 0,
            total_out: 0,
        };
        inf.reset();
        inf
    }

    /// Forgets the current stream (and its history) to decode a new one; buffers are kept.
    pub fn reset(&mut self) {
        self.wpos = 0;
        self.flushed = 0;
        self.reset_keep_window();
        self.total_in = 0;
        self.total_out = 0;
    }

    /// Starts a new stream that may refer back into the data of the previous one (its history
    /// is kept): permessage-deflate with context takeover after a message that ended with a
    /// final block. Output not yet delivered is dropped.
    pub fn reset_keep_window(&mut self) {
        self.flushed = self.wpos;
        self.state = match self.format {
            Format::Raw => State::Block,
            Format::Zlib => State::ZlibHeader,
            Format::Gzip => State::GzHeader(Gz::Fixed),
        };
        self.bitbuf = 0;
        self.bitcnt = 0;
        self.last = false;
        self.hn = 0;
        self.hcrc = Crc32::new();
        self.adler = Adler32::new();
        self.crc = Crc32::new();
    }

    /// The stream ended (and all of its output was delivered).
    pub fn is_done(&self) -> bool {
        self.state == State::Done && self.wpos == self.flushed
    }

    /// Input bytes consumed since the last reset.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Output bytes delivered since the last reset.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Decompresses from `input` into `output`. Returns when the output is full, the input is
    /// used up (everything decodable from it has been delivered), or the stream ended. So when
    /// `produced < output.len()` and not `done`, more input is needed.
    ///
    /// After an error the stream stays failed (every later call returns the same error) until
    /// [`reset`](Inflater::reset).
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut ip = 0usize;
        let mut op = 0usize;
        // Output of stored blocks copied straight from the input since `direct`: it still has
        // to enter the window (only its last `hist` bytes do, once, before the window is used).
        let mut direct: Option<usize> = None;
        let res = loop {
            op += self.drain(&mut output[op..]);
            if let State::Failed(e) = self.state {
                break Err(e);
            }
            if self.wpos != self.flushed || self.state == State::Done {
                break Ok(()); // output full, or finished
            }
            match self.state {
                State::Stored => {
                    let n = self.stored(input, &mut ip, &mut output[op..]);
                    if n > 0 {
                        direct.get_or_insert(op);
                        op += n;
                    }
                    match self.state {
                        State::Stored => break Ok(()), // output full or input used up
                        State::Done => self.give_back(&mut ip),
                        _ => {}
                    }
                    continue;
                }
                State::Block | State::StoredLen => {}
                _ => {
                    if let Some(from) = direct.take() {
                        self.push_history(&output[from..op]);
                    }
                }
            }
            match self.step(input, &mut ip, output.len() - op) {
                Ok(true) => {
                    if self.state == State::Done {
                        self.give_back(&mut ip);
                    }
                }
                Ok(false) => {
                    op += self.drain(&mut output[op..]);
                    break Ok(());
                }
                Err(e) => {
                    self.state = State::Failed(e);
                    break Err(e);
                }
            }
        };
        if let Some(from) = direct {
            self.push_history(&output[from..op]);
        }
        self.total_in += ip as u64;
        res.map(|()| Progress {
            consumed: ip,
            produced: op,
            done: self.is_done(),
        })
    }

    /// At the end of the stream: gives back whole bytes read ahead (when they came from this
    /// input).
    fn give_back(&mut self, ip: &mut usize) {
        *ip -= ((self.bitcnt / 8) as usize).min(*ip);
        self.bitbuf = 0;
        self.bitcnt = 0;
    }

    /// Decompresses `input`, appending to `out` but never growing it past `limit` bytes in
    /// total. Returns when the input is used up, the stream ended, or `out` reached `limit`.
    ///
    /// For a size limit `max` on the decompressed data, pass `limit = max + 1`: `out.len() >
    /// max` afterwards means the data is too large.
    pub fn decompress_vec(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<Progress, Error> {
        let start = out.len();
        let mut consumed = 0;
        let mut done = false;
        // Stored data appended since `direct`, not yet in the window (see `decompress`).
        let mut direct: Option<usize> = None;
        while out.len() < limit {
            let idle = self.wpos == self.flushed;
            if idle && self.state == State::Stored {
                // Appended straight from the input: no zero-filled room to write it into.
                let old = out.len();
                let mut ip = 0;
                self.stored_vec(&input[consumed..], &mut ip, out, limit);
                if out.len() > old {
                    direct.get_or_insert(old);
                }
                if self.state == State::Done {
                    self.give_back(&mut ip);
                }
                self.total_in += ip as u64;
                consumed += ip;
                match self.state {
                    State::Stored => break, // input used up or `limit` reached
                    State::Done => {
                        done = self.is_done();
                        break;
                    }
                    _ => continue,
                }
            }
            if idle && matches!(self.state, State::Block | State::StoredLen) {
                // Block headers need no output space (and leave the window alone).
                let p = match self.decompress(&input[consumed..], &mut []) {
                    Ok(p) => p,
                    Err(e) => {
                        if let Some(from) = direct {
                            self.push_history(&out[from..]);
                        }
                        return Err(e);
                    }
                };
                consumed += p.consumed;
                if matches!(self.state, State::Block | State::StoredLen) {
                    break; // input used up
                }
                continue;
            }
            if let Some(from) = direct.take() {
                self.push_history(&out[from..]);
            }
            let room = (limit - out.len()).min(((input.len() - consumed) * 4).clamp(1024, 1 << 18));
            let old = out.len();
            out.resize(old + room, 0);
            let r = self.decompress(&input[consumed..], &mut out[old..]);
            let p = match r {
                Ok(p) => p,
                Err(e) => {
                    out.truncate(old);
                    return Err(e);
                }
            };
            out.truncate(old + p.produced);
            consumed += p.consumed;
            if p.done {
                done = true;
                break;
            }
            if p.produced < room {
                break; // input used up
            }
        }
        if let Some(from) = direct {
            self.push_history(&out[from..]);
        }
        Ok(Progress {
            consumed,
            produced: out.len() - start,
            done,
        })
    }

    /// Copies pending output out of the window, updating the checksum.
    fn drain(&mut self, output: &mut [u8]) -> usize {
        let n = (self.wpos - self.flushed).min(output.len());
        if n == 0 {
            return 0;
        }
        let src = &self.win[self.flushed..self.flushed + n];
        output[..n].copy_from_slice(src);
        match self.format {
            Format::Raw => {}
            Format::Zlib => self.adler.update(src),
            Format::Gzip => self.crc.update(src),
        }
        self.flushed += n;
        self.total_out += n as u64;
        n
    }

    fn hist(&self) -> usize {
        1 << self.wbits
    }

    /// Makes room for at least `need` bytes at `wpos` by dropping history older than the window
    /// (only delivered bytes are dropped). False when there is no room yet.
    fn make_room(&mut self, need: usize) -> bool {
        if self.win.is_empty() {
            let h = self.hist();
            self.win = vec![0; h + h.max(16 << 10) + SLACK];
        }
        if self.wpos + need <= self.win.len() {
            return true;
        }
        let start = self.flushed.min(self.wpos.saturating_sub(self.hist()));
        if start == 0 {
            return false;
        }
        self.win.copy_within(start..self.wpos, 0);
        self.wpos -= start;
        self.flushed -= start;
        true
    }

    /// Takes one byte at a byte boundary.
    fn take_byte(&mut self, input: &[u8], ip: &mut usize) -> Option<u8> {
        if self.bitcnt < 8 {
            let &b = input.get(*ip)?;
            self.bitbuf |= u64::from(b) << self.bitcnt;
            self.bitcnt += 8;
            *ip += 1;
        }
        let b = self.bitbuf as u8;
        self.bitbuf >>= 8;
        self.bitcnt -= 8;
        Some(b)
    }

    fn align(&mut self) {
        let n = self.bitcnt & 7;
        self.bitbuf >>= n;
        self.bitcnt -= n;
    }

    fn end_of_blocks(&mut self) {
        self.state = match self.format {
            Format::Raw => State::Done,
            _ => State::Trailer,
        };
        self.hn = 0;
    }

    fn gz_next(&self, after: Gz) -> State {
        let f = self.gz_flags;
        let order = [
            (Gz::ExtraLen, GZ_FEXTRA),
            (Gz::Name, GZ_FNAME),
            (Gz::Comment, GZ_FCOMMENT),
            (Gz::HeaderCrc, GZ_FHCRC),
        ];
        let from = match after {
            Gz::Fixed => 0,
            Gz::ExtraLen | Gz::Extra => 1,
            Gz::Name => 2,
            Gz::Comment => 3,
            Gz::HeaderCrc => 4,
        };
        order[from.min(4)..]
            .iter()
            .find(|(_, bit)| f & bit != 0)
            .map_or(State::Block, |&(s, _)| State::GzHeader(s))
    }

    /// Runs the state machine. `Ok(true)`: call again (after draining output); `Ok(false)`: no
    /// progress is possible without more input or output space.
    fn step(&mut self, input: &[u8], ip: &mut usize, budget: usize) -> Result<bool, Error> {
        match self.state {
            State::ZlibHeader => {
                while self.hn < 2 {
                    let Some(b) = self.take_byte(input, ip) else {
                        return Ok(false);
                    };
                    self.hbuf[self.hn] = b;
                    self.hn += 1;
                }
                let (cmf, flg) = (self.hbuf[0], self.hbuf[1]);
                if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0
                    || cmf & 0x0f != 8
                    || (cmf >> 4) + 8 > self.wbits
                {
                    return Err(Error::BadHeader);
                }
                if flg & 0x20 != 0 {
                    return Err(Error::DictionaryRequired);
                }
                self.state = State::Block;
            }
            State::GzHeader(g) => {
                match g {
                    Gz::Fixed => {
                        while self.hn < 10 {
                            let Some(b) = self.take_byte(input, ip) else {
                                return Ok(false);
                            };
                            self.hbuf[self.hn] = b;
                            self.hn += 1;
                        }
                        let h = self.hbuf;
                        if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 || h[3] & 0xe0 != 0 {
                            return Err(Error::BadHeader);
                        }
                        self.hcrc.update(&h);
                        self.gz_flags = h[3];
                        self.hn = 0;
                    }
                    Gz::ExtraLen => {
                        while self.hn < 2 {
                            let Some(b) = self.take_byte(input, ip) else {
                                return Ok(false);
                            };
                            self.hcrc.update(&[b]);
                            self.hbuf[self.hn] = b;
                            self.hn += 1;
                        }
                        self.gz_left =
                            usize::from(u16::from_le_bytes([self.hbuf[0], self.hbuf[1]]));
                        self.hn = 0;
                        self.state = State::GzHeader(Gz::Extra);
                        return Ok(true);
                    }
                    Gz::Extra => {
                        while self.gz_left > 0 {
                            let Some(b) = self.take_byte(input, ip) else {
                                return Ok(false);
                            };
                            self.hcrc.update(&[b]);
                            self.gz_left -= 1;
                        }
                    }
                    Gz::Name | Gz::Comment => loop {
                        let Some(b) = self.take_byte(input, ip) else {
                            return Ok(false);
                        };
                        self.hcrc.update(&[b]);
                        if b == 0 {
                            break;
                        }
                    },
                    Gz::HeaderCrc => {
                        while self.hn < 2 {
                            let Some(b) = self.take_byte(input, ip) else {
                                return Ok(false);
                            };
                            self.hbuf[self.hn] = b;
                            self.hn += 1;
                        }
                        let want = (self.hcrc.finish() & 0xffff) as u16;
                        if u16::from_le_bytes([self.hbuf[0], self.hbuf[1]]) != want {
                            return Err(Error::BadHeader);
                        }
                        self.hn = 0;
                    }
                }
                self.state = self.gz_next(g);
            }
            State::Block => {
                refill(&mut self.bitbuf, &mut self.bitcnt, input, ip);
                if self.bitcnt < 3 {
                    return Ok(false);
                }
                let b = self.bitbuf as u32;
                self.bitbuf >>= 3;
                self.bitcnt -= 3;
                self.last = b & 1 != 0;
                self.state = match (b >> 1) & 3 {
                    0 => State::StoredLen,
                    1 => {
                        self.fixed = true;
                        State::Codes
                    }
                    2 => State::DynCounts,
                    _ => return Err(Error::BadBlockType),
                };
            }
            State::StoredLen => {
                self.align();
                refill(&mut self.bitbuf, &mut self.bitcnt, input, ip);
                if self.bitcnt < 32 {
                    return Ok(false);
                }
                let len = self.bitbuf as u16;
                let nlen = (self.bitbuf >> 16) as u16;
                if len != !nlen {
                    return Err(Error::BadStoredLength);
                }
                self.bitbuf >>= 32;
                self.bitcnt -= 32;
                self.stored_left = usize::from(len);
                self.state = State::Stored;
            }
            // Copied straight to the output by `decompress`.
            State::Stored => return Ok(false),
            State::DynCounts => {
                refill(&mut self.bitbuf, &mut self.bitcnt, input, ip);
                if self.bitcnt < 14 {
                    return Ok(false);
                }
                let b = self.bitbuf as usize;
                self.bitbuf >>= 14;
                self.bitcnt -= 14;
                self.nlen = 257 + (b & 31);
                self.ndist = 1 + ((b >> 5) & 31);
                self.ncl = 4 + ((b >> 10) & 15);
                if self.nlen > 286 || self.ndist > 30 {
                    return Err(Error::BadHuffmanCode);
                }
                self.idx = 0;
                self.lens[..19].fill(0);
                self.state = State::DynCodeLens;
            }
            State::DynCodeLens => {
                while self.idx < self.ncl {
                    refill(&mut self.bitbuf, &mut self.bitcnt, input, ip);
                    if self.bitcnt < 3 {
                        return Ok(false);
                    }
                    self.lens[CL_ORDER[self.idx]] = (self.bitbuf & 7) as u8;
                    self.bitbuf >>= 3;
                    self.bitcnt -= 3;
                    self.idx += 1;
                }
                let mut cl = [0u8; 19];
                cl.copy_from_slice(&self.lens[..19]);
                if !build_table(&cl, Table::CodeLens, &mut self.lit) || cl.iter().all(|&l| l == 0) {
                    return Err(Error::BadHuffmanCode);
                }
                self.idx = 0;
                self.state = State::DynLens;
            }
            State::DynLens => {
                let total = self.nlen + self.ndist;
                while self.idx < total {
                    refill(&mut self.bitbuf, &mut self.bitcnt, input, ip);
                    let e = lookup(primary::<CL_N>(&self.lit), &self.lit, self.bitbuf);
                    let n = e & 31;
                    if n > self.bitcnt {
                        return Ok(false);
                    }
                    let sym = e >> 16;
                    if sym < 16 {
                        self.lens[self.idx] = sym as u8;
                        self.idx += 1;
                        self.bitbuf >>= n;
                        self.bitcnt -= n;
                        continue;
                    }
                    let (xb, base) = match sym {
                        16 => (2, 3),
                        17 => (3, 3),
                        _ => (7, 11),
                    };
                    if n + xb > self.bitcnt {
                        return Ok(false);
                    }
                    let rep = base + ((self.bitbuf >> n) & low_bits(xb)) as usize;
                    let val = if sym == 16 {
                        if self.idx == 0 {
                            return Err(Error::BadHuffmanCode);
                        }
                        self.lens[self.idx - 1]
                    } else {
                        0
                    };
                    if self.idx + rep > total {
                        return Err(Error::BadHuffmanCode);
                    }
                    self.lens[self.idx..self.idx + rep].fill(val);
                    self.idx += rep;
                    self.bitbuf >>= n + xb;
                    self.bitcnt -= n + xb;
                }
                let (nlen, ndist) = (self.nlen, self.ndist);
                if self.lens[256] == 0
                    || !build_table(&self.lens[..nlen], Table::Lit, &mut self.lit)
                    || !build_table(&self.lens[nlen..nlen + ndist], Table::Dist, &mut self.dist)
                {
                    return Err(Error::BadHuffmanCode);
                }
                self.fixed = false;
                self.state = State::Codes;
            }
            State::Codes => return self.codes(input, ip, budget),
            State::Trailer => {
                if self.wpos != self.flushed {
                    return Ok(false); // the checksum covers output not yet delivered
                }
                self.align();
                let need = if self.format == Format::Gzip { 8 } else { 4 };
                while self.hn < need {
                    let Some(b) = self.take_byte(input, ip) else {
                        return Ok(false);
                    };
                    self.hbuf[self.hn] = b;
                    self.hn += 1;
                }
                let h = self.hbuf;
                let ok = if self.format == Format::Gzip {
                    u32::from_le_bytes([h[0], h[1], h[2], h[3]]) == self.crc.finish()
                        && u32::from_le_bytes([h[4], h[5], h[6], h[7]]) == self.total_out as u32
                } else {
                    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) == self.adler.finish()
                };
                if !ok {
                    return Err(Error::ChecksumMismatch);
                }
                self.state = State::Done;
            }
            State::Done | State::Failed(_) => return Ok(false),
        }
        Ok(true)
    }

    /// Copies stored block data straight into `output` (the window is updated later, by
    /// [`push_history`](Inflater::push_history)), updating the checksum. Leaves the state when
    /// the block is complete.
    fn stored(&mut self, input: &[u8], ip: &mut usize, output: &mut [u8]) -> usize {
        let room = output.len().min(self.stored_left);
        let mut n = 0;
        while n < room && self.bitcnt >= 8 {
            output[n] = self.bitbuf as u8;
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
            n += 1;
        }
        let take = (room - n).min(input.len() - *ip);
        output[n..n + take].copy_from_slice(&input[*ip..*ip + take]);
        *ip += take;
        n += take;
        self.stored_out(&output[..n]);
        n
    }

    /// [`stored`](Inflater::stored), appending to `out` up to `limit` bytes in total.
    fn stored_vec(&mut self, input: &[u8], ip: &mut usize, out: &mut Vec<u8>, limit: usize) {
        let old = out.len();
        let room = (limit - old).min(self.stored_left);
        while out.len() - old < room && self.bitcnt >= 8 {
            out.push(self.bitbuf as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
        }
        let take = (room - (out.len() - old)).min(input.len() - *ip);
        out.extend_from_slice(&input[*ip..*ip + take]);
        *ip += take;
        self.stored_out(&out[old..]);
    }

    /// Accounts for `data` delivered from a stored block, and leaves the block at its end.
    fn stored_out(&mut self, data: &[u8]) {
        self.stored_left -= data.len();
        match self.format {
            Format::Raw => {}
            Format::Zlib => self.adler.update(data),
            Format::Gzip => self.crc.update(data),
        }
        self.total_out += data.len() as u64;
        if self.stored_left == 0 {
            if self.last {
                self.end_of_blocks();
            } else {
                self.state = State::Block;
            }
        }
    }

    /// Appends output already delivered to the history: only its last `hist` bytes matter.
    fn push_history(&mut self, data: &[u8]) {
        debug_assert_eq!(self.wpos, self.flushed);
        let h = self.hist();
        let data = &data[data.len().saturating_sub(h)..];
        if data.len() == h {
            if self.win.is_empty() {
                self.make_room(0);
            }
            self.win[..h].copy_from_slice(data);
            self.wpos = h;
        } else {
            // With nothing pending, sliding always leaves room for `h` more bytes.
            let ok = self.make_room(data.len());
            debug_assert!(ok);
            if !ok {
                return;
            }
            self.win[self.wpos..self.wpos + data.len()].copy_from_slice(data);
            self.wpos += data.len();
        }
        self.flushed = self.wpos;
    }

    /// Decodes literals and matches of a compressed block.
    fn codes(&mut self, input: &[u8], ip: &mut usize, budget: usize) -> Result<bool, Error> {
        let hist = self.hist();
        let mut progressed = false;
        loop {
            if self.wpos - self.flushed >= budget {
                return Ok(progressed);
            }
            if !self.make_room(SLACK) {
                return Ok(progressed);
            }
            // Decode until the output budget, the buffer end or the input runs out.
            let f = fixed();
            let (lt, dt): (&[u32], &[u32]) = if self.fixed {
                (&f.lit, &f.dist)
            } else {
                (&self.lit, &self.dist)
            };
            let (lp, dp) = (primary::<LIT_N>(lt), primary::<DIST_N>(dt));
            let win = &mut self.win[..];
            let mut bb = self.bitbuf;
            let mut bc = self.bitcnt;
            let mut wpos = self.wpos;
            let stop = (self.flushed + budget).min(win.len() - SLACK + 1);
            let mut outcome: Option<Result<bool, Error>> = None;
            while wpos < stop {
                if *ip + 16 <= input.len() {
                    // Fast path: a branchless refill to at least 56 bits, which is enough for
                    // three literals or one length/distance pair. The bits above `bc` are the
                    // next input bits (`bb` is masked when leaving). Anything unusual (end of
                    // block, invalid symbols or distances) is left to the careful path below,
                    // which starts over from the same state.
                    bb |= load64(input, *ip) << bc;
                    *ip += ((63 - bc) >> 3) as usize;
                    bc |= 56;
                    let e = lookup(lp, lt, bb);
                    let n = e & 31;
                    match kind(e) {
                        K_LIT => {
                            win[wpos] = (e >> 16) as u8;
                            wpos += 1;
                            bb >>= n;
                            bc -= n;
                            for _ in 0..2 {
                                // Primary entries only (a link is not a literal here).
                                let e = lp[(bb as usize) & (LIT_N - 1)];
                                if kind(e) != K_LIT || wpos >= stop {
                                    break;
                                }
                                win[wpos] = (e >> 16) as u8;
                                wpos += 1;
                                bb >>= e & 31;
                                bc -= e & 31;
                            }
                            continue;
                        }
                        K_LEN => {
                            let xb = (e >> 5) & 31;
                            let len = (e >> 16) as usize + ((bb >> n) & low_bits(xb)) as usize;
                            let used = n + xb;
                            let d = lookup(dp, dt, bb >> used);
                            if kind(d) == K_LIT {
                                let dn = d & 31;
                                let dxb = (d >> 5) & 31;
                                let dist = (d >> 16) as usize
                                    + ((bb >> (used + dn)) & low_bits(dxb)) as usize;
                                if dist <= wpos.min(hist) {
                                    let used = used + dn + dxb;
                                    bb >>= used;
                                    bc -= used;
                                    copy_match(win, wpos, dist, len);
                                    wpos += len;
                                    continue;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                refill(&mut bb, &mut bc, input, ip);
                let e = lookup(lp, lt, bb);
                let n = e & 31;
                if n > bc {
                    outcome = Some(Ok(false));
                    break;
                }
                match kind(e) {
                    K_LIT => {
                        win[wpos] = (e >> 16) as u8;
                        wpos += 1;
                        bb >>= n;
                        bc -= n;
                    }
                    K_LEN => {
                        let xb = (e >> 5) & 31;
                        let mut used = n + xb;
                        if used > bc {
                            outcome = Some(Ok(false));
                            break;
                        }
                        let len = (e >> 16) as usize + ((bb >> n) & low_bits(xb)) as usize;
                        let d = lookup(dp, dt, bb >> used);
                        let dn = d & 31;
                        if used + dn > bc {
                            outcome = Some(Ok(false));
                            break;
                        }
                        if kind(d) == K_BAD {
                            outcome = Some(Err(Error::BadSymbol));
                            break;
                        }
                        let dxb = (d >> 5) & 31;
                        if used + dn + dxb > bc {
                            outcome = Some(Ok(false));
                            break;
                        }
                        let dist =
                            (d >> 16) as usize + ((bb >> (used + dn)) & low_bits(dxb)) as usize;
                        used += dn + dxb;
                        if dist > wpos.min(hist) {
                            outcome = Some(Err(Error::BadDistance));
                            break;
                        }
                        bb >>= used;
                        bc -= used;
                        copy_match(win, wpos, dist, len);
                        wpos += len;
                    }
                    K_EOB => {
                        bb >>= n;
                        bc -= n;
                        outcome = Some(Ok(true));
                        break;
                    }
                    _ => {
                        outcome = Some(Err(Error::BadSymbol));
                        break;
                    }
                }
            }
            if wpos != self.wpos {
                progressed = true;
            }
            self.bitbuf = bb & low_bits(bc);
            self.bitcnt = bc;
            self.wpos = wpos;
            match outcome {
                None => {} // budget or buffer end: drain or slide, then go on
                Some(Ok(true)) => {
                    if self.last {
                        self.end_of_blocks();
                    } else {
                        self.state = State::Block;
                    }
                    return Ok(true);
                }
                Some(Ok(false)) => return Ok(progressed),
                Some(Err(e)) => return Err(e),
            }
        }
    }
}

/// Decompresses a whole `format` stream. Fails with [`Error::TooLarge`] when the output would
/// exceed `limit` bytes and with [`Error::Truncated`] when `data` ends before the stream does.
/// Data after the end of the stream is ignored.
///
/// ```
/// use akio_deflate::{Error, Format, Level, compress, decompress};
///
/// let z = compress(Format::Zlib, Level::BEST, &[7u8; 10_000]);
/// assert_eq!(decompress(Format::Zlib, &z, 10_000).unwrap(), [7u8; 10_000]);
/// assert_eq!(decompress(Format::Zlib, &z, 9_999), Err(Error::TooLarge));
/// assert_eq!(decompress(Format::Zlib, &z[..z.len() - 1], 10_000), Err(Error::Truncated));
/// ```
pub fn decompress(format: Format, data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut inf = Inflater::new(format);
    // Room for the output of stored data (or twice the input) up front, so it is not moved
    // while growing.
    let mut out = Vec::with_capacity(
        data.len()
            .saturating_mul(2)
            .saturating_add(1024)
            .min(limit.saturating_add(1)),
    );
    let p = inf.decompress_vec(data, &mut out, limit.saturating_add(1))?;
    if out.len() > limit {
        return Err(Error::TooLarge);
    }
    if !p.done {
        return Err(Error::Truncated);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rules_follow_zlib() {
        let mut t = Vec::new();
        // Complete codes.
        assert!(build_table(&[1, 1], Table::Lit, &mut t));
        assert!(build_table(&[2, 2, 2, 2], Table::Dist, &mut t));
        // Over-subscribed.
        assert!(!build_table(&[1, 1, 1], Table::Lit, &mut t));
        // Incomplete: only a single one-bit code, and never for the code length code.
        assert!(build_table(&[0, 1], Table::Dist, &mut t));
        assert!(!build_table(&[0, 2], Table::Dist, &mut t));
        assert!(!build_table(&[1], Table::CodeLens, &mut t));
        // No symbols at all: an all-invalid table.
        assert!(build_table(&[0, 0], Table::Dist, &mut t));
        assert!(t.iter().all(|&e| kind(e) == K_BAD));
    }

    #[test]
    fn fixed_block_by_hand() {
        // "a" in a final fixed block: 1 01, literal 'a' (0x61 -> code 0x30+0x61 = 0x91, 8 bits),
        // end of block (0000000).
        let mut out = [0u8; 8];
        let data = [0x4b, 0x04, 0x00];
        let mut inf = Inflater::new(Format::Raw);
        let p = inf.decompress(&data, &mut out).unwrap();
        assert!(p.done);
        assert_eq!(&out[..p.produced], b"a");
        assert_eq!(p.consumed, 3);
    }

    #[test]
    fn stored_and_errors() {
        let mut d = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        d.extend_from_slice(b"hello");
        assert_eq!(decompress(Format::Raw, &d, 100).unwrap(), b"hello");
        d[3] = 0;
        assert_eq!(
            decompress(Format::Raw, &d, 100),
            Err(Error::BadStoredLength)
        );
        assert_eq!(
            decompress(Format::Raw, &[0x07], 100),
            Err(Error::BadBlockType)
        );
        // A distance before the start: fixed block, length 3 (257 = 0000001), distance 1.
        assert_eq!(
            decompress(Format::Raw, &[0x03, 0x02, 0x00, 0x00], 100),
            Err(Error::BadDistance)
        );
        // Every later call repeats the error.
        let mut inf = Inflater::new(Format::Raw);
        let mut o = [0u8; 4];
        assert_eq!(inf.decompress(&[0x07], &mut o), Err(Error::BadBlockType));
        assert_eq!(inf.decompress(&[0x01], &mut o), Err(Error::BadBlockType));
        inf.reset();
        assert!(inf.decompress(&[0x03, 0x00], &mut o).unwrap().done);
    }
}
