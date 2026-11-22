//! Streaming compression: LZ77 over a hash of the next four bytes, with one of four match
//! finders chosen by the level (as zlib-ng and zlib-rs do): `quick` (level 1: one probe, the
//! fixed code written directly), `fast` (level 2: greedy), `medium` (levels 3..=6: greedy with
//! a look one match ahead) and `slow` (levels 7..=9: lazy matching). Blocks are coded with
//! whichever is smallest of a dynamic Huffman code (length-limited), the fixed code, or stored.

use crate::checksum::{Adler32, Crc32};
use crate::tables::{
    CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA, fixed_lit_lens, length_counts,
    reverse_bits,
};
use crate::{Flush, Format, Level};

const MIN_MATCH: usize = 3;
/// Shortest match the finders look for (the hash covers four bytes).
const WANT_MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 258;
/// Lookahead needed to find a full-length match after the current position.
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
/// Bytes compared per candidate at most: a match plus the overrun of the last 8-byte compare.
const CMP: usize = MAX_MATCH + 8;
/// Zero bytes after the window, so that hashing and comparing near its end stay in bounds.
const WINDOW_PAD: usize = CMP + 8;
/// Symbols per block (zlib's `lit_bufsize - 1` at the default memory level).
const SYMS_PER_BLOCK: usize = 16383;
const MAX_STORED: usize = 65535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    Stored,
    Quick,
    Fast,
    Medium,
    Slow,
}

#[derive(Clone, Copy, Debug)]
struct Config {
    /// Reduce the chain search when the previous match is at least this long.
    good: u16,
    /// Slow: do not look for a better match after one this long. Fast and medium: insert the
    /// strings of matches up to this long (16 times this for medium) into the hash table.
    lazy: u16,
    /// Stop searching at a match this long.
    nice: u16,
    /// Longest hash chain walked.
    chain: u16,
    strategy: Strategy,
}

const fn cfg(good: u16, lazy: u16, nice: u16, chain: u16, strategy: Strategy) -> Config {
    Config {
        good,
        lazy,
        nice,
        chain,
        strategy,
    }
}

/// The configuration table of zlib-ng and zlib-rs.
const CONFIGS: [Config; 10] = [
    cfg(0, 0, 0, 0, Strategy::Stored),
    cfg(0, 0, 0, 0, Strategy::Quick),
    cfg(4, 4, 8, 4, Strategy::Fast),
    cfg(4, 6, 16, 6, Strategy::Medium),
    cfg(4, 12, 32, 24, Strategy::Medium),
    cfg(8, 16, 32, 32, Strategy::Medium),
    cfg(8, 16, 128, 128, Strategy::Medium),
    cfg(8, 32, 128, 256, Strategy::Slow),
    cfg(32, 128, 258, 1024, Strategy::Slow),
    cfg(32, 258, 258, 4096, Strategy::Slow),
];

/// Length symbol index (0..29) of `length - 3`.
const fn len_code_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut code = 0;
    while code < 28 {
        let base = LEN_BASE[code] as usize - 3;
        let n = 1usize << LEN_EXTRA[code];
        let mut i = 0;
        while i < n {
            t[base + i] = code as u8;
            i += 1;
        }
        code += 1;
    }
    t[255] = 28;
    t
}

/// Distance symbol of `dist - 1`: index `d` for `d < 256`, `256 + (d >> 7)` otherwise.
const fn dist_code_table() -> [u8; 512] {
    let mut t = [0u8; 512];
    let mut code = 0;
    while code < 30 {
        let base = DIST_BASE[code] as usize - 1;
        let n = 1usize << DIST_EXTRA[code];
        let mut i = 0;
        while i < n {
            let d = base + i;
            if d < 256 {
                t[d] = code as u8;
            } else {
                t[256 + (d >> 7)] = code as u8;
            }
            i += 1;
        }
        code += 1;
    }
    t
}

static LEN_CODE: [u8; 256] = len_code_table();
static DIST_CODE: [u8; 512] = dist_code_table();

#[inline(always)]
fn dist_code(dist: usize) -> usize {
    let d = (dist - 1) & 0x7fff;
    usize::from(if d < 256 {
        DIST_CODE[d]
    } else {
        DIST_CODE[256 + (d >> 7)]
    })
}

/// The four bytes at `i`, little endian.
#[inline(always)]
fn load32(w: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(<[u8; 4]>::try_from(&w[i..i + 4]).unwrap_or_default())
}

/// The eight bytes at `i`, little endian.
#[inline(always)]
fn load64(w: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(<[u8; 8]>::try_from(&w[i..i + 8]).unwrap_or_default())
}

/// The `CMP` bytes at `i` (the window is padded so that they exist for every position).
#[inline(always)]
fn cmp_window(w: &[u8], i: usize) -> &[u8; CMP] {
    const ZERO: [u8; CMP] = [0; CMP];
    <&[u8; CMP]>::try_from(&w[i..i + CMP]).unwrap_or(&ZERO)
}

/// Length of the common prefix of `a` and `b` given that the first `from` bytes are equal,
/// 8 bytes at a time (at most `MAX_MATCH + 7`; callers clamp it).
#[inline(always)]
fn common_len(a: &[u8; CMP], b: &[u8; CMP], mut from: usize) -> usize {
    while from < MAX_MATCH {
        let x = load64(a, from) ^ load64(b, from);
        if x != 0 {
            return from + (x.trailing_zeros() / 8) as usize;
        }
        from += 8;
    }
    from
}

/// The hash of four bytes, `bits` wide.
#[inline(always)]
fn hash4(v: u32, bits: u32) -> usize {
    (v.wrapping_mul(0x9E37_79B1) >> (32 - bits)) as usize
}

/// Bit output, least significant bit first, 32 bits at a time into the output `Vec`.
#[derive(Clone, Copy, Debug, Default)]
struct Bits {
    buf: u64,
    cnt: u32,
}

impl Bits {
    /// Appends the low `n` bits of `v` (`n <= 32`, `v` without higher bits).
    #[inline(always)]
    fn put(&mut self, out: &mut Vec<u8>, v: u32, n: u32) {
        self.buf |= u64::from(v) << self.cnt;
        self.cnt += n;
        if self.cnt >= 32 {
            out.extend_from_slice(&(self.buf as u32).to_le_bytes());
            self.buf >>= 32;
            self.cnt -= 32;
        }
    }

    /// Pads to a byte boundary and writes out everything.
    fn align(&mut self, out: &mut Vec<u8>) {
        while self.cnt > 0 {
            out.push(self.buf as u8);
            self.buf >>= 8;
            self.cnt = self.cnt.saturating_sub(8);
        }
        self.buf = 0;
    }

    /// Writes `data` as stored blocks (split at 65535 bytes); `last` marks the final one.
    fn stored(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) {
        let mut chunks = data.chunks(MAX_STORED).peekable();
        if chunks.peek().is_none() {
            self.stored_one(&[], last, out);
        }
        while let Some(c) = chunks.next() {
            let fin = last && chunks.peek().is_none();
            self.stored_one(c, fin, out);
        }
    }

    fn stored_one(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) {
        self.put(out, u32::from(last), 3);
        self.align(out);
        let len = data.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
    }
}

/// Bits of stored blocks for `len` bytes after `pending` bits of output.
fn stored_cost(pending: u32, len: usize) -> u64 {
    let pad = (8 - (u64::from(pending) + 3) % 8) % 8;
    let extra_chunks = len.saturating_sub(1) / MAX_STORED;
    3 + pad + 32 + 8 * len as u64 + 40 * extra_chunks as u64
}

/// A match (or, with `len < WANT_MIN_MATCH`, `len` literals) of the medium strategy.
#[derive(Clone, Copy, Debug, Default)]
struct Match {
    pos: usize,
    start: usize,
    len: usize,
}

/// Where a block of the quick strategy started in this call's output, to replace it with
/// stored blocks when that is smaller or to mark it as the final block.
#[derive(Clone, Copy, Debug)]
struct QuickMark {
    out_len: usize,
    bits: Bits,
}

/// A streaming DEFLATE / zlib / gzip compressor.
///
/// [`compress`](Deflater::compress) takes input of any size and appends compressed bytes to a
/// `Vec`. [`Flush::Sync`] ends the output on a byte boundary with an empty stored block (the
/// `00 00 ff ff` marker of permessage-deflate) while keeping the history for later data;
/// [`Flush::Full`] also forgets the history; [`Flush::Finish`] ends the stream.
///
/// ```
/// use akio_deflate::{Deflater, Flush, Format, Inflater, Level};
///
/// let mut d = Deflater::new(Format::Raw, Level::DEFAULT);
/// let mut wire = Vec::new();
/// d.compress(b"first message, ", &mut wire, Flush::Sync);
/// assert!(wire.ends_with(&[0, 0, 0xff, 0xff]));
/// d.compress(b"first message again", &mut wire, Flush::Finish);
///
/// let mut out = Vec::new();
/// Inflater::new(Format::Raw).decompress_vec(&wire, &mut out, 1 << 20).unwrap();
/// assert_eq!(out, b"first message, first message again");
/// ```
pub struct Deflater {
    format: Format,
    level: u8,
    cfg: Config,
    /// Window bits as asked for (8..=15) and as laid out (9..=15).
    wbits: u8,
    w_size: usize,
    hash_bits: u32,
    /// The bytes hashed: four, or three at level 9 (whose search finds three-byte matches).
    hash_mask: u32,
    /// `2 * w_size` bytes plus padding; positions in `head`/`prev` are indices into it (0 =
    /// none).
    window: Vec<u8>,
    prev: Vec<u16>,
    head: Vec<u16>,
    strstart: usize,
    block_start: isize,
    lookahead: usize,
    /// Positions before `strstart` not yet inserted into the hash table (end of input).
    insert: usize,
    /// The window slid since the last reset (positions of the stream are no longer all in
    /// `window[..strstart + lookahead]`).
    slid: bool,
    match_start: usize,
    match_length: usize,
    prev_length: usize,
    prev_match: usize,
    match_available: bool,
    /// Pending symbols of the current block: `dist << 16 | lit` or `dist << 16 | (len - 3)`.
    syms: Vec<u32>,
    lfreq: [u32; 286],
    dfreq: [u32; 30],
    /// Level 0: input not yet emitted.
    raw: Vec<u8>,
    bits: Bits,
    /// Quick strategy: a fixed-code block is open.
    quick_open: bool,
    /// Quick strategy: the open block started in the current call.
    quick_mark: Option<QuickMark>,
    started: bool,
    finished: bool,
    adler: Adler32,
    crc: Crc32,
    total_in: u64,
}

impl std::fmt::Debug for Deflater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deflater")
            .field("format", &self.format)
            .field("level", &self.level)
            .field("window_bits", &self.wbits)
            .field("total_in", &self.total_in)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Deflater {
    /// A compressor for `format` at `level` with a 32 KiB window.
    pub fn new(format: Format, level: Level) -> Deflater {
        Deflater::with_window_bits(format, level, 15)
    }

    /// A compressor whose back-references reach at most `2^bits` bytes (`bits` clamped to
    /// 8..=15), for a peer that decompresses with a smaller window (permessage-deflate
    /// `max_window_bits`). The window is laid out with at least 9 bits; the longest distance
    /// used is the window size minus 262 bytes, which is below 256 for `bits` 8 and 9.
    pub fn with_window_bits(format: Format, level: Level, bits: u8) -> Deflater {
        let wbits = bits.clamp(8, 15);
        let lay = wbits.max(9);
        let level = level.get();
        let mut d = Deflater {
            format,
            level,
            cfg: CONFIGS[usize::from(level)],
            wbits,
            w_size: 1 << lay,
            hash_bits: u32::from(lay + 1).clamp(10, 16),
            hash_mask: if CONFIGS[usize::from(level)].chain > 1024 {
                0x00ff_ffff
            } else {
                u32::MAX
            },
            window: Vec::new(),
            prev: Vec::new(),
            head: Vec::new(),
            strstart: 0,
            block_start: 0,
            lookahead: 0,
            insert: 0,
            slid: false,
            match_start: 0,
            match_length: 0,
            prev_length: 0,
            prev_match: 0,
            match_available: false,
            syms: Vec::new(),
            lfreq: [0; 286],
            dfreq: [0; 30],
            raw: Vec::new(),
            bits: Bits::default(),
            quick_open: false,
            quick_mark: None,
            started: false,
            finished: false,
            adler: Adler32::new(),
            crc: Crc32::new(),
            total_in: 0,
        };
        d.reset();
        d
    }

    /// Starts a new stream: the history is forgotten, buffers are kept.
    pub fn reset(&mut self) {
        self.clear_hash();
        self.strstart = 0;
        self.block_start = 0;
        self.lookahead = 0;
        self.insert = 0;
        self.match_start = 0;
        self.match_length = MIN_MATCH - 1;
        self.prev_length = MIN_MATCH - 1;
        self.prev_match = 0;
        self.match_available = false;
        self.syms.clear();
        self.lfreq = [0; 286];
        self.dfreq = [0; 30];
        self.raw.clear();
        self.bits = Bits::default();
        self.quick_open = false;
        self.quick_mark = None;
        self.started = false;
        self.finished = false;
        self.adler = Adler32::new();
        self.crc = Crc32::new();
        self.total_in = 0;
    }

    /// Input bytes taken since the last reset.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The stream was ended with [`Flush::Finish`]; further input is ignored until
    /// [`reset`](Deflater::reset).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Compresses all of `input`, appending output to `out`, then applies `flush`.
    ///
    /// With [`Flush::None`] some input may stay buffered (it is part of a later block); the
    /// other modes write everything taken so far.
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        if self.finished {
            return;
        }
        if !self.started {
            self.started = true;
            self.write_header(out);
        }
        self.total_in += input.len() as u64;
        match self.format {
            Format::Raw => {}
            Format::Zlib => self.adler.update(input),
            Format::Gzip => self.crc.update(input),
        }
        if self.level == 0 {
            self.compress_stored(input, out, flush);
        } else {
            if self.window.is_empty() {
                self.window = vec![0; 2 * self.w_size + WINDOW_PAD];
                self.prev = vec![0; self.w_size];
                self.head = vec![0; 1 << self.hash_bits];
                self.syms.reserve_exact(SYMS_PER_BLOCK);
            }
            out.reserve(input.len() / 2 + 64);
            // A quick block left open by an earlier call was written to another output.
            self.quick_mark = None;
            match self.cfg.strategy {
                Strategy::Quick => self.deflate_quick(input, out, flush),
                Strategy::Fast => self.deflate_fast(input, out, flush),
                Strategy::Medium => self.deflate_medium(input, out, flush),
                Strategy::Slow | Strategy::Stored => self.deflate_slow(input, out, flush),
            }
        }
        match flush {
            Flush::None => {}
            Flush::Sync | Flush::Full => {
                self.bits.stored(&[], false, out);
                if flush == Flush::Full && self.level != 0 {
                    self.clear_hash();
                    if self.lookahead == 0 {
                        self.strstart = 0;
                        self.block_start = 0;
                        self.insert = 0;
                    }
                }
            }
            Flush::Finish => {
                self.bits.align(out);
                self.write_trailer(out);
                self.finished = true;
            }
        }
    }

    fn write_header(&self, out: &mut Vec<u8>) {
        match self.format {
            Format::Raw => {}
            Format::Zlib => {
                let cmf = ((self.w_size.trailing_zeros() as u8 - 8) << 4) | 8;
                let flevel: u8 = match self.level {
                    0 | 1 => 0,
                    2..=5 => 1,
                    6 => 2,
                    _ => 3,
                };
                let mut flg = flevel << 6;
                flg += 31 - ((u16::from(cmf) * 256 + u16::from(flg)) % 31) as u8;
                out.extend_from_slice(&[cmf, flg]);
            }
            Format::Gzip => {
                let xfl = match self.level {
                    9 => 2,
                    1 => 4,
                    _ => 0,
                };
                out.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 255]);
            }
        }
    }

    fn write_trailer(&self, out: &mut Vec<u8>) {
        match self.format {
            Format::Raw => {}
            Format::Zlib => out.extend_from_slice(&self.adler.finish().to_be_bytes()),
            Format::Gzip => {
                out.extend_from_slice(&self.crc.finish().to_le_bytes());
                out.extend_from_slice(&(self.total_in as u32).to_le_bytes());
            }
        }
    }

    // ---- level 0 ------------------------------------------------------------------------------

    fn compress_stored(&mut self, input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        self.raw.extend_from_slice(input);
        let raw = &self.raw;
        let mut start = 0;
        while raw.len() - start > MAX_STORED {
            self.bits
                .stored_one(&raw[start..start + MAX_STORED], false, out);
            start += MAX_STORED;
        }
        match flush {
            Flush::None => {}
            Flush::Sync | Flush::Full => {
                if start < raw.len() {
                    self.bits.stored_one(&raw[start..], false, out);
                    start = raw.len();
                }
            }
            Flush::Finish => {
                self.bits.stored_one(&raw[start..], true, out);
                start = raw.len();
            }
        }
        self.raw.drain(..start);
    }

    // ---- LZ77 ---------------------------------------------------------------------------------

    /// Empties the hash table. After a short stream only the slots of its positions are
    /// cleared (permessage-deflate without context takeover resets after every message). A
    /// slot missed because its string changed after it was inserted only leaves a stale
    /// candidate, which the match search checks against the window like any other.
    fn clear_hash(&mut self) {
        let end = self.strstart + self.lookahead;
        if self.slid || end >= self.head.len() / 8 {
            self.head.fill(0);
        } else {
            let (bits, mask) = (self.hash_bits, self.hash_mask);
            for pos in 0..end {
                self.head[hash4(load32(&self.window, pos) & mask, bits)] = 0;
            }
        }
        self.slid = false;
    }

    fn max_dist(&self) -> usize {
        self.w_size - MIN_LOOKAHEAD
    }

    /// Inserts the string at `pos` and returns the previous position on its chain (0: none).
    #[inline(always)]
    fn insert_string(&mut self, pos: usize) -> usize {
        let h = hash4(load32(&self.window, pos) & self.hash_mask, self.hash_bits);
        let old = self.head[h];
        let slot = pos & (self.w_size - 1);
        if usize::from(old) == pos {
            // Already inserted: its chain goes on from `prev`.
            return usize::from(self.prev[slot]);
        }
        self.prev[slot] = old;
        self.head[h] = pos as u16;
        usize::from(old)
    }

    /// Inserts the strings at `from..to`.
    #[inline(always)]
    fn insert_range(&mut self, from: usize, to: usize) {
        let bits = self.hash_bits;
        let mask = self.hash_mask;
        let wmask = self.w_size - 1;
        let w = &self.window[..];
        let head = &mut self.head[..];
        let prev = &mut self.prev[..];
        for pos in from..to {
            let h = hash4(load32(w, pos) & mask, bits);
            let old = head[h];
            if usize::from(old) != pos {
                prev[pos & wmask] = old;
                head[h] = pos as u16;
            }
        }
    }

    /// Moves input into the window (sliding it by `w_size` when the position gets too far).
    fn fill_window(&mut self, input: &mut &[u8]) {
        let w = self.w_size;
        loop {
            let mut more = 2 * w - self.lookahead - self.strstart;
            if self.strstart >= w + self.max_dist() {
                self.window
                    .copy_within(w..self.strstart + self.lookahead, 0);
                self.match_start = self.match_start.saturating_sub(w);
                self.strstart -= w;
                self.block_start -= w as isize;
                self.insert = self.insert.min(self.strstart);
                self.slid = true;
                let wu = w as u16;
                for h in &mut self.head {
                    *h = h.saturating_sub(wu);
                }
                for p in &mut self.prev {
                    *p = p.saturating_sub(wu);
                }
                more += w;
            }
            if input.is_empty() {
                break;
            }
            let n = more.min(input.len());
            let dst = self.strstart + self.lookahead;
            self.window[dst..dst + n].copy_from_slice(&input[..n]);
            *input = &input[n..];
            self.lookahead += n;
            if self.insert > 0 && self.lookahead + self.insert >= WANT_MIN_MATCH {
                // Strings left before `strstart` at the end of the previous input.
                let n = self
                    .insert
                    .min(self.lookahead + self.insert - (WANT_MIN_MATCH - 1));
                let s = self.strstart - self.insert;
                self.insert_range(s, s + n);
                self.insert -= n;
            }
            if self.lookahead >= MIN_LOOKAHEAD || input.is_empty() {
                break;
            }
        }
    }

    /// Longest match at `strstart` along the chain starting at `cur`, longer than
    /// `prev_length`; sets `match_start`. With `early_exit`, stops at the first candidate that
    /// matches without improving.
    #[inline(always)]
    fn longest_match(&mut self, mut cur: usize, early_exit: bool) -> usize {
        let scan = self.strstart;
        let max_len = MAX_MATCH.min(self.lookahead);
        let mut best = self.prev_length.max(MIN_MATCH - 1);
        if best >= max_len {
            return max_len;
        }
        let mut chain = u32::from(self.cfg.chain);
        if best >= usize::from(self.cfg.good) {
            chain = (chain >> 2).max(1);
        }
        let nice = usize::from(self.cfg.nice).min(max_len);
        let limit = scan.saturating_sub(self.max_dist());
        let wmask = self.w_size - 1;
        let w = &self.window[..];
        let prev = &self.prev[..];
        let s = cmp_window(w, scan);
        let s0 = load64(s, 0);
        let mut s_end = load64(s, best.saturating_sub(7));
        let mut match_start = self.match_start;
        while cur < scan {
            let m = cmp_window(w, cur);
            // Cheap rejection first: the first eight bytes when the best match is shorter,
            // otherwise the eight bytes ending one past the best length, then the first eight.
            let len = if best < 8 {
                let x = s0 ^ load64(m, 0);
                if x != 0 {
                    let l = (x.trailing_zeros() / 8) as usize;
                    if l > best { Some(l) } else { None }
                } else {
                    Some(common_len(s, m, 8))
                }
            } else if load64(m, best - 7) == s_end && load64(m, 0) == s0 {
                Some(common_len(s, m, 8))
            } else {
                None
            };
            if let Some(len) = len {
                let len = len.min(max_len);
                if len > best {
                    match_start = cur;
                    best = len;
                    if len >= nice {
                        break;
                    }
                    if best >= 8 {
                        s_end = load64(s, best - 7);
                    }
                } else if early_exit {
                    break;
                }
            }
            chain -= 1;
            if chain == 0 {
                break;
            }
            cur = usize::from(prev[cur & wmask]);
            if cur <= limit {
                break;
            }
        }
        self.match_start = match_start;
        best
    }

    /// [`Deflater::longest_match`] for level 9 (zlib-ng's `longest_match_slow`): candidates
    /// are taken from the chain of whichever string inside the current best match (or at the
    /// current position plus an offset) reaches furthest back, which skips candidates that
    /// cannot be longer. A candidate on the chain of the string at offset `off` starts `off`
    /// bytes before the chain position.
    fn longest_match_slow(&mut self, cur0: usize) -> usize {
        let scan = self.strstart;
        let max_len = MAX_MATCH.min(self.lookahead);
        let mut best = self.prev_length.max(MIN_MATCH - 1);
        if best >= max_len {
            return max_len;
        }
        let mut chain = u32::from(self.cfg.chain);
        if best >= usize::from(self.cfg.good) {
            chain = (chain >> 2).max(1);
        }
        let nice = usize::from(self.cfg.nice).min(max_len);
        let limit_base = scan.saturating_sub(self.max_dist());
        let wmask = self.w_size - 1;
        let (bits, mask) = (self.hash_bits, self.hash_mask);
        let w = &self.window[..];
        let prev = &self.prev[..];
        let head = &self.head[..];
        let hash_at = |p: usize| usize::from(head[hash4(load32(w, p) & mask, bits)]);
        let s = cmp_window(w, scan);
        let s0 = load64(s, 0);
        let mut s_end = load64(s, best.saturating_sub(7));
        let mut match_start = self.match_start;
        let mut cur = cur0;
        let mut off = 0usize;
        if best >= MIN_MATCH {
            // Continuing a lazy search: start on the most distant chain of the strings inside
            // the previous match length.
            for i in 1..=best - 2 {
                let pos = hash_at(scan + i);
                if pos < cur {
                    off = i;
                    cur = pos;
                }
            }
            if cur <= limit_base + off {
                return best;
            }
        }
        loop {
            let start = cur - off;
            if start >= scan {
                break;
            }
            let m = cmp_window(w, start);
            let len = if best < 8 {
                let x = s0 ^ load64(m, 0);
                if x != 0 {
                    let l = (x.trailing_zeros() / 8) as usize;
                    if l > best { Some(l) } else { None }
                } else {
                    Some(common_len(s, m, 8))
                }
            } else if load64(m, best - 7) == s_end && load64(m, 0) == s0 {
                Some(common_len(s, m, 8))
            } else {
                None
            };
            let len = len.map_or(0, |l| l.min(max_len));
            if len > best {
                match_start = start;
                best = len;
                if len >= nice {
                    break;
                }
                if best >= 8 {
                    s_end = load64(s, best - 7);
                }
                if len > MIN_MATCH && start + len < scan {
                    // Switch to the most distant chain of the strings inside this match.
                    let mut next = start;
                    off = 0;
                    for i in 0..=len - MIN_MATCH {
                        let pos = usize::from(prev[(start + i) & wmask]);
                        if pos < next {
                            if pos <= limit_base + i {
                                self.match_start = match_start;
                                return best;
                            }
                            next = pos;
                            off = i;
                        }
                    }
                    cur = next;
                    // Or the chain of the string just before the end of the match, which
                    // includes the byte that would make it longer.
                    let o = len - (MIN_MATCH + 1);
                    let pos = hash_at(scan + o);
                    if pos < cur {
                        if pos <= limit_base + o {
                            self.match_start = match_start;
                            return best;
                        }
                        cur = pos;
                        off = o;
                    }
                    continue;
                }
            }
            chain -= 1;
            if chain == 0 {
                break;
            }
            cur = usize::from(prev[cur & wmask]);
            if cur <= limit_base + off {
                break;
            }
        }
        self.match_start = match_start;
        best
    }

    #[inline(always)]
    fn tally_lit(&mut self, c: u8) -> bool {
        self.syms.push(u32::from(c));
        self.lfreq[usize::from(c)] += 1;
        self.syms.len() == SYMS_PER_BLOCK
    }

    #[inline(always)]
    fn tally_match(&mut self, dist: usize, len: usize) -> bool {
        let lc = (len - MIN_MATCH) & 0xff;
        self.syms.push(((dist as u32) << 16) | lc as u32);
        self.lfreq[257 + usize::from(LEN_CODE[lc])] += 1;
        self.dfreq[dist_code(dist)] += 1;
        self.syms.len() == SYMS_PER_BLOCK
    }

    fn end_block(&mut self, last: bool, out: &mut Vec<u8>) {
        self.flush_block(last, out);
        self.block_start = self.strstart as isize;
    }

    /// Closes the input of a symbol-buffer strategy: the last block, or the pending symbols.
    fn finish_input(&mut self, out: &mut Vec<u8>, flush: Flush) {
        self.insert = self.strstart.min(WANT_MIN_MATCH - 1);
        if flush == Flush::Finish {
            self.end_block(true, out);
        } else if !self.syms.is_empty() {
            self.end_block(false, out);
        }
    }

    /// The head of the chain for the string at `strstart` (inserting it), or 0 when there is
    /// no usable candidate.
    #[inline(always)]
    fn candidate(&mut self) -> usize {
        if self.lookahead < WANT_MIN_MATCH {
            return 0;
        }
        let head = self.insert_string(self.strstart);
        if head != 0 && head < self.strstart && self.strstart - head <= self.max_dist() {
            head
        } else {
            0
        }
    }

    // ---- quick (level 1) ----------------------------------------------------------------------

    /// Opens a fixed-code block (not final; [`Deflater::quick_end`] may mark it so).
    fn quick_start(&mut self, out: &mut Vec<u8>) {
        self.quick_mark = Some(QuickMark {
            out_len: out.len(),
            bits: self.bits,
        });
        self.bits.put(out, 1 << 1, 3);
        self.quick_open = true;
        self.block_start = self.strstart as isize;
    }

    /// Ends the open fixed-code block: replaced by stored blocks when those are smaller (and
    /// the block started in this call), and marked final when `last`.
    fn quick_end(&mut self, last: bool, out: &mut Vec<u8>) {
        if !self.quick_open {
            if last {
                // An empty final block.
                self.bits.put(out, 1 | (1 << 1), 3);
                self.bits.put(out, 0, 7);
            }
            return;
        }
        self.bits.put(out, 0, 7); // end of block
        self.quick_open = false;
        let Some(mark) = self.quick_mark.take() else {
            if last {
                self.bits.put(out, 1 | (1 << 1), 3);
                self.bits.put(out, 0, 7);
            }
            self.block_start = self.strstart as isize;
            return;
        };
        let used = (out.len() - mark.out_len) as u64 * 8 + u64::from(self.bits.cnt)
            - u64::from(mark.bits.cnt);
        let len = (self.strstart as isize - self.block_start) as usize;
        if self.block_start >= 0 && stored_cost(mark.bits.cnt, len) < used {
            out.truncate(mark.out_len);
            self.bits = mark.bits;
            let s = self.block_start as usize;
            self.bits.stored(&self.window[s..s + len], last, out);
        } else if last {
            // Set BFINAL, the first bit of the block header.
            let p = mark.out_len * 8 + mark.bits.cnt as usize;
            if p < out.len() * 8 {
                out[p / 8] |= 1 << (p % 8);
            } else {
                self.bits.buf |= 1 << (p - out.len() * 8);
            }
        }
        self.block_start = self.strstart as isize;
    }

    /// One probe per position, matches of at least four bytes, the fixed code written
    /// directly; the strings inside matches are not inserted.
    fn deflate_quick(&mut self, mut input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                if self.quick_open && self.strstart >= self.w_size + self.max_dist() {
                    // The window slides: end the block while its data is still there.
                    self.quick_end(false, out);
                }
                self.fill_window(&mut input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            if !self.quick_open {
                self.quick_start(out);
            }
            let w = &self.window[..];
            let pos = self.strstart;
            if self.lookahead >= WANT_MIN_MATCH {
                let val = load32(w, pos);
                let h = hash4(val, self.hash_bits);
                let head = usize::from(self.head[h]);
                self.prev[pos & (self.w_size - 1)] = head as u16;
                self.head[h] = pos as u16;
                let dist = pos.wrapping_sub(head);
                if head != 0 && dist <= self.max_dist() && dist > 0 && load32(w, head) == val {
                    let len = common_len(cmp_window(w, pos), cmp_window(w, head), 4)
                        .min(MAX_MATCH)
                        .min(self.lookahead);
                    let (lv, ln) = STATIC_LEN[len - MIN_MATCH];
                    let dc = dist_code(dist);
                    let dv = u32::from(FIXED_DIST_CODES[dc])
                        | ((dist - usize::from(DIST_BASE[dc])) as u32) << 5;
                    self.bits.put(out, lv, u32::from(ln));
                    self.bits.put(out, dv, 5 + u32::from(DIST_EXTRA[dc]));
                    self.lookahead -= len;
                    self.strstart += len;
                    continue;
                }
            }
            let c = usize::from(w[pos]);
            self.bits.put(
                out,
                u32::from(FIXED_LIT_CODES[c]),
                u32::from(FIXED_LIT_LENS[c]),
            );
            self.strstart += 1;
            self.lookahead -= 1;
        }
        self.insert = self.strstart.min(WANT_MIN_MATCH - 1);
        self.quick_end(flush == Flush::Finish, out);
    }

    // ---- fast (level 2) -----------------------------------------------------------------------

    /// Greedy matching; the strings of short matches are inserted.
    fn deflate_fast(&mut self, mut input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(&mut input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            let head = self.candidate();
            let mut len = 0;
            if head != 0 {
                self.prev_length = MIN_MATCH - 1;
                len = self.longest_match(head, true);
            }
            let bflush;
            if len >= WANT_MIN_MATCH {
                bflush = self.tally_match(self.strstart - self.match_start, len);
                self.lookahead -= len;
                if len <= usize::from(self.cfg.lazy) && self.lookahead >= WANT_MIN_MATCH {
                    self.insert_range(self.strstart + 1, self.strstart + len);
                } else if self.lookahead >= WANT_MIN_MATCH {
                    self.insert_range(self.strstart + len - 1, self.strstart + len);
                }
                self.strstart += len;
            } else {
                bflush = self.tally_lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                self.end_block(false, out);
            }
        }
        self.finish_input(out, flush);
    }

    // ---- medium (levels 3..=6) ----------------------------------------------------------------

    /// The match (or literal) at `strstart`, searching the chain of `head`.
    #[inline(always)]
    fn medium_find(&mut self, head: usize, early_exit: bool) -> Match {
        let pos = self.strstart;
        let mut m = Match {
            pos,
            start: 0,
            len: 1,
        };
        if head != 0 {
            self.prev_length = MIN_MATCH - 1;
            let len = self.longest_match(head, early_exit);
            if len >= WANT_MIN_MATCH && self.match_start < pos {
                m.len = len;
                m.start = self.match_start;
            }
        }
        m
    }

    /// Inserts the strings covered by `m` (all of them for short matches, the last one for
    /// long ones, none near the end of the input); `inserted` is the first position not
    /// inserted yet.
    #[inline(always)]
    fn medium_insert(&mut self, m: Match, inserted: &mut usize) {
        if self.lookahead <= m.len + WANT_MIN_MATCH {
            return;
        }
        let end = m.pos + m.len;
        if m.len < WANT_MIN_MATCH || m.len <= 16 * usize::from(self.cfg.lazy) {
            let from = (m.pos + 1).max(*inserted);
            if from < end {
                self.insert_range(from, end);
            }
        } else {
            self.insert_range(end - 1, end);
        }
        *inserted = (*inserted).max(end);
    }

    /// Greedy matching that looks at the match after the current one (levels 5 and 6) and
    /// moves bytes from the end of the current match to the next one when they are equal, so
    /// that a short current match may become a literal.
    fn deflate_medium(&mut self, mut input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        let early_exit = self.level < 5;
        let mut next: Option<Match> = None;
        let mut inserted = 0usize;
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(&mut input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    break;
                }
                next = None;
                inserted = 0;
            }
            let mut cur = match next.take() {
                Some(m) => m,
                None => {
                    let head = self.candidate();
                    inserted = inserted.max(self.strstart + 1);
                    self.medium_find(head, early_exit)
                }
            };
            self.medium_insert(cur, &mut inserted);
            let next_pos = cur.pos + cur.len;
            if !early_exit
                && self.lookahead > MIN_LOOKAHEAD
                && next_pos < 2 * self.w_size - MIN_LOOKAHEAD
            {
                // Look one match ahead, with the lookahead seen from there.
                let ahead = self.lookahead;
                self.strstart = next_pos;
                self.lookahead = ahead - cur.len;
                let head = self.candidate();
                inserted = inserted.max(next_pos + 1);
                let mut n = self.medium_find(head, false);
                if n.len >= WANT_MIN_MATCH {
                    self.fizzle(&mut cur, &mut n);
                }
                next = Some(n);
                self.strstart = cur.pos;
                self.lookahead = ahead;
            }
            // Emit the current match or literals.
            let bflush = if cur.len >= WANT_MIN_MATCH {
                self.tally_match(cur.pos - cur.start, cur.len)
            } else {
                let mut f = false;
                for i in 0..cur.len {
                    f |= self.tally_lit(self.window[cur.pos + i]);
                }
                f
            };
            self.lookahead -= cur.len;
            self.strstart += cur.len;
            if bflush {
                self.end_block(false, out);
            }
        }
        self.finish_input(out, flush);
    }

    /// Moves the start of `next` back over bytes that end `cur` when they are equal (the match
    /// distance stays); applied only when `cur` shrinks to a literal.
    fn fizzle(&self, cur: &mut Match, next: &mut Match) {
        if cur.len < WANT_MIN_MATCH || next.start == 0 {
            return;
        }
        let w = &self.window[..];
        let limit = next.pos.saturating_sub(self.max_dist());
        let (mut c, mut n) = (*cur, *next);
        let mut changed = false;
        while c.len > 1
            && n.pos > limit
            && n.pos > c.pos + 1
            && n.len < MAX_MATCH - 2
            && n.start > 1
            && w[n.start - 1] == w[n.pos - 1]
        {
            n.pos -= 1;
            n.start -= 1;
            n.len += 1;
            c.len -= 1;
            changed = true;
        }
        if changed && c.len <= 1 {
            *cur = c;
            *next = n;
        }
    }

    // ---- slow (levels 7..=9) ------------------------------------------------------------------

    /// Lazy matching: a match is taken only if the next position does not start a longer
    /// one.
    fn deflate_slow(&mut self, mut input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(&mut input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            let head = self.candidate();
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if head != 0 && self.prev_length < usize::from(self.cfg.lazy) {
                self.match_length = if self.cfg.chain > 1024 {
                    self.longest_match_slow(head)
                } else {
                    self.longest_match(head, false)
                };
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                let max_insert = (self.strstart + self.lookahead).saturating_sub(WANT_MIN_MATCH);
                let bflush =
                    self.tally_match(self.strstart - 1 - self.prev_match, self.prev_length);
                // `strstart - 1` and `strstart` are inserted; insert the rest of the match.
                let end = self.strstart - 1 + self.prev_length;
                let to = end.min(max_insert + 1);
                if to > self.strstart + 1 {
                    self.insert_range(self.strstart + 1, to);
                }
                self.lookahead -= self.prev_length - 1;
                self.strstart = end;
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                if bflush {
                    self.end_block(false, out);
                }
            } else if self.match_available {
                if self.tally_lit(self.window[self.strstart - 1]) {
                    self.end_block(false, out);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.tally_lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
        self.finish_input(out, flush);
    }

    // ---- blocks -------------------------------------------------------------------------------

    /// Writes the pending symbols as one block, choosing the smallest coding.
    fn flush_block(&mut self, last: bool, out: &mut Vec<u8>) {
        let stored_len = (self.strstart as isize - self.block_start) as usize;
        self.lfreq[256] = 1;

        let mut llens = [0u8; 286];
        let mut dlens = [0u8; 30];
        huffman_lengths(&self.lfreq, 15, &mut llens);
        huffman_lengths(&self.dfreq, 15, &mut dlens);
        let nlit = 257
            + llens[257..]
                .iter()
                .rposition(|&l| l != 0)
                .map_or(0, |p| p + 1);
        let ndist = 1 + dlens[1..]
            .iter()
            .rposition(|&l| l != 0)
            .map_or(0, |p| p + 1);

        // Run-length code of the code lengths.
        let mut all = [0u8; 316];
        all[..nlit].copy_from_slice(&llens[..nlit]);
        all[nlit..nlit + ndist].copy_from_slice(&dlens[..ndist]);
        let mut rle = [(0u8, 0u8); 316];
        let nrle = rle_lengths(&all[..nlit + ndist], &mut rle);
        let mut clfreq = [0u32; 19];
        for &(s, _) in &rle[..nrle] {
            clfreq[usize::from(s)] += 1;
        }
        let mut cllens = [0u8; 19];
        huffman_lengths(&clfreq, 7, &mut cllens);
        let ncl = 4
            + (4..19)
                .rev()
                .find(|&i| cllens[CL_ORDER[i]] != 0)
                .map_or(0, |i| i + 1 - 4);

        let data_bits = |ll: &[u8], dl: &[u8]| -> u64 {
            let mut bits = 0u64;
            for (s, &f) in self.lfreq.iter().enumerate() {
                if f != 0 {
                    let extra = if s >= 257 { LEN_EXTRA[s - 257] } else { 0 };
                    bits += u64::from(f) * u64::from(ll[s] + extra);
                }
            }
            for (s, &f) in self.dfreq.iter().enumerate() {
                if f != 0 {
                    bits += u64::from(f) * u64::from(dl[s] + DIST_EXTRA[s]);
                }
            }
            bits
        };
        let mut dyn_bits = 3 + 14 + 3 * ncl as u64 + data_bits(&llens, &dlens);
        for &(s, _) in &rle[..nrle] {
            dyn_bits += u64::from(cllens[usize::from(s)])
                + match s {
                    16 => 2,
                    17 => 3,
                    18 => 7,
                    _ => 0,
                };
        }
        let fixed_bits = 3 + data_bits(&FIXED_LIT_LENS, &[5u8; 30]);

        if self.block_start >= 0
            && stored_cost(self.bits.cnt, stored_len) <= fixed_bits.min(dyn_bits)
        {
            let s = self.block_start as usize;
            self.bits.stored(&self.window[s..s + stored_len], last, out);
            self.clear_block();
            return;
        }
        if fixed_bits <= dyn_bits {
            self.bits.put(out, u32::from(last) | (1 << 1), 3);
            self.write_symbols(
                out,
                &FIXED_LIT_CODES,
                &FIXED_LIT_LENS,
                &FIXED_DIST_CODES,
                &[5; 30],
            );
        } else {
            let b = &mut self.bits;
            b.put(out, u32::from(last) | (2 << 1), 3);
            b.put(out, (nlit - 257) as u32, 5);
            b.put(out, (ndist - 1) as u32, 5);
            b.put(out, (ncl - 4) as u32, 4);
            for &i in &CL_ORDER[..ncl] {
                b.put(out, u32::from(cllens[i]), 3);
            }
            let clcodes = canonical_codes(&cllens);
            for &(s, x) in &rle[..nrle] {
                let s = usize::from(s);
                b.put(out, u32::from(clcodes[s]), u32::from(cllens[s]));
                match s {
                    16 => b.put(out, u32::from(x), 2),
                    17 => b.put(out, u32::from(x), 3),
                    18 => b.put(out, u32::from(x), 7),
                    _ => {}
                }
            }
            let lcodes = canonical_codes(&llens);
            let dcodes = canonical_codes(&dlens);
            self.write_symbols(out, &lcodes, &llens, &dcodes, &dlens);
        }
        self.clear_block();
    }

    fn clear_block(&mut self) {
        self.syms.clear();
        self.lfreq = [0; 286];
        self.dfreq = [0; 30];
    }

    fn write_symbols(
        &mut self,
        out: &mut Vec<u8>,
        lcodes: &[u16; 286],
        llens: &[u8; 286],
        dcodes: &[u16; 30],
        dlens: &[u8; 30],
    ) {
        let len_bits = |lc: usize| {
            let code = usize::from(LEN_CODE[lc]);
            let sym = 257 + code;
            let xv = (lc + 3 - usize::from(LEN_BASE[code])) as u32;
            (
                u32::from(lcodes[sym]) | (xv << llens[sym]),
                llens[sym] + LEN_EXTRA[code],
            )
        };
        // Code and extra bits of each length in one table, when the block is large enough.
        let mut len_tab = [(0u32, 0u8); 256];
        let use_tab = self.syms.len() >= 2048;
        if use_tab {
            for (lc, e) in len_tab.iter_mut().enumerate() {
                *e = len_bits(lc);
            }
        }
        let syms = std::mem::take(&mut self.syms);
        out.reserve(syms.len() * 4 + 16);
        let mut bb = self.bits.buf;
        let mut bc = self.bits.cnt;
        macro_rules! put {
            ($v:expr, $n:expr) => {{
                bb |= u64::from($v) << bc;
                bc += $n;
                if bc >= 32 {
                    out.extend_from_slice(&(bb as u32).to_le_bytes());
                    bb >>= 32;
                    bc -= 32;
                }
            }};
        }
        for &s in &syms {
            let dist = (s >> 16) as usize;
            let lc = (s & 0xff) as usize;
            if dist == 0 {
                put!(u32::from(lcodes[lc]), u32::from(llens[lc]));
            } else {
                let (lv, ln) = if use_tab { len_tab[lc] } else { len_bits(lc) };
                put!(lv, u32::from(ln));
                let dc = dist_code(dist);
                let dxv = (dist - usize::from(DIST_BASE[dc])) as u32;
                put!(
                    u32::from(dcodes[dc]) | (dxv << dlens[dc]),
                    u32::from(dlens[dc]) + u32::from(DIST_EXTRA[dc])
                );
            }
        }
        put!(u32::from(lcodes[256]), u32::from(llens[256]));
        self.bits = Bits { buf: bb, cnt: bc };
        self.syms = syms;
    }
}

/// Fixed-code bits of each length (`len - 3`): the code with its extra bits, and their count.
static STATIC_LEN: [(u32, u8); 256] = {
    let len_code = len_code_table();
    let lens = fixed_lit_lens();
    let codes = canonical_codes_const(&lens);
    let mut t = [(0u32, 0u8); 256];
    let mut lc = 0;
    while lc < 256 {
        let code = len_code[lc] as usize;
        let sym = 257 + code;
        let xv = (lc + 3 - LEN_BASE[code] as usize) as u32;
        let l = lens[sym];
        t[lc] = (codes[sym] as u32 | (xv << l), l + LEN_EXTRA[code]);
        lc += 1;
    }
    t
};

const FIXED_LIT_LENS: [u8; 286] = {
    let all = fixed_lit_lens();
    let mut l = [0u8; 286];
    let mut i = 0;
    while i < 286 {
        l[i] = all[i];
        i += 1;
    }
    l
};

const fn canonical_codes_const<const N: usize>(lens: &[u8; N]) -> [u16; N] {
    let mut count = [0u16; 16];
    let mut i = 0;
    while i < N {
        count[lens[i] as usize] += 1;
        i += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0u32;
    let mut len = 1;
    while len < 16 {
        code = (code + count[len - 1] as u32) << 1;
        next[len] = code;
        len += 1;
    }
    let mut out = [0u16; N];
    let mut s = 0;
    while s < N {
        let l = lens[s] as usize;
        if l != 0 {
            out[s] = reverse_bits(next[l], l as u32) as u16;
            next[l] += 1;
        }
        s += 1;
    }
    out
}

/// Codes of the fixed literal/length code: computed over all 288 symbols (286 and 287 take part
/// in the canonical numbering although they never occur).
static FIXED_LIT_CODES: [u16; 286] = {
    let all = canonical_codes_const(&fixed_lit_lens());
    let mut c = [0u16; 286];
    let mut i = 0;
    while i < 286 {
        c[i] = all[i];
        i += 1;
    }
    c
};
static FIXED_DIST_CODES: [u16; 30] = canonical_codes_const(&[5u8; 30]);

/// Bit-reversed canonical codes for `lens` (as the DEFLATE bit order needs them).
fn canonical_codes<const N: usize>(lens: &[u8; N]) -> [u16; N] {
    let count = length_counts(lens);
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for len in 1..16 {
        code = (code + u32::from(count[len - 1])) << 1;
        next[len] = code;
    }
    let mut out = [0u16; N];
    for (o, &l) in out.iter_mut().zip(lens.iter()) {
        if l != 0 {
            let l = usize::from(l & 15);
            *o = reverse_bits(next[l], l as u32) as u16;
            next[l] += 1;
        }
    }
    out
}

/// Run-length codes (symbols 16/17/18 with their extra values) of a code length sequence.
fn rle_lengths(lens: &[u8], out: &mut [(u8, u8)]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < lens.len() {
        let l = lens[i];
        let mut run = lens[i..].iter().take_while(|&&x| x == l).count();
        i += run;
        if l == 0 {
            while run >= 11 {
                let r = run.min(138);
                out[n] = (18, (r - 11) as u8);
                n += 1;
                run -= r;
            }
            if run >= 3 {
                out[n] = (17, (run - 3) as u8);
                n += 1;
                run = 0;
            }
        } else {
            out[n] = (l, 0);
            n += 1;
            run -= 1;
            while run >= 3 {
                let r = run.min(6);
                out[n] = (16, (r - 3) as u8);
                n += 1;
                run -= r;
            }
        }
        for _ in 0..run {
            out[n] = (l, 0);
            n += 1;
        }
    }
    n
}

/// Huffman code lengths for `freq`, at most `max_len` bits, written to `lens`. At least two
/// symbols get a code (a lone symbol is paired with a dummy one), so every code is complete.
fn huffman_lengths<const N: usize>(freq: &[u32; N], max_len: u32, lens: &mut [u8; N]) {
    lens.fill(0);
    // Frequency and symbol in one sort key.
    let mut syms = [0u64; N];
    let mut n = 0;
    for (s, &f) in freq.iter().enumerate() {
        if f != 0 {
            syms[n] = (u64::from(f) << 16) | s as u64;
            n += 1;
        }
    }
    // Force two codes (zlib does the same): pkzip-era decoders want at least one bit per code.
    let mut s = 0;
    while n < 2 {
        if freq[s] == 0 && syms[..n].iter().all(|&x| (x & 0xffff) as usize != s) {
            syms[n] = (1 << 16) | s as u64;
            n += 1;
        }
        s += 1;
    }
    let syms = &mut syms[..n];
    syms.sort_unstable();

    // Moffat & Katajainen, in place: code lengths of a minimum-redundancy code.
    let mut keys = [0u32; N];
    let a = &mut keys[..n];
    for (k, &x) in a.iter_mut().zip(syms.iter()) {
        *k = (x >> 16) as u32;
    }
    a[0] += a[1];
    let (mut root, mut leaf) = (0usize, 2usize);
    for next in 1..n - 1 {
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    a[n - 2] = 0;
    for next in (0..n.saturating_sub(2)).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    let (mut avbl, mut used, mut depth) = (1i64, 0i64, 0u32);
    let mut root = n as i64 - 2;
    let mut next = n as i64 - 1;
    while avbl > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avbl > used {
            a[next as usize] = depth;
            next -= 1;
            avbl -= 1;
        }
        avbl = 2 * used;
        depth += 1;
        used = 0;
    }

    // Limit the lengths (miniz's adjustment keeps the Kraft sum exact).
    // Depths beyond the limit are counted at the limit, then the Kraft sum is repaired.
    let max = max_len as usize;
    let mut num = [0u32; 16];
    for &d in a.iter() {
        num[(d as usize).min(max)] += 1;
    }
    let mut total: u64 = (1..=max).map(|i| u64::from(num[i]) << (max - i)).sum();
    while total != 1u64 << max {
        num[max] -= 1;
        for i in (1..max).rev() {
            if num[i] != 0 {
                num[i] -= 1;
                num[i + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
    // Most frequent symbols (the end of the sorted list) get the shortest codes.
    let mut j = n;
    for (len, &cnt) in num.iter().enumerate().take(max + 1).skip(1) {
        for _ in 0..cnt {
            j -= 1;
            lens[(syms[j] & 0xffff) as usize] = len as u8;
        }
    }
}

/// Compresses `data` into one complete `format` stream.
///
/// ```
/// use akio_deflate::{Format, Level, compress, decompress};
///
/// let text = b"a man a plan a canal panama, a man a plan a canal panama".repeat(20);
/// let z = compress(Format::Gzip, Level::DEFAULT, &text);
/// assert!(z.len() < text.len() / 10);
/// assert_eq!(decompress(Format::Gzip, &z, usize::MAX).unwrap(), text);
/// ```
pub fn compress(format: Format, level: Level, data: &[u8]) -> Vec<u8> {
    let mut d = Deflater::new(format, level);
    let mut out = Vec::with_capacity(data.len() / 2 + 32);
    d.compress(data, &mut out, Flush::Finish);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kraft(lens: &[u8]) -> f64 {
        lens.iter()
            .filter(|&&l| l != 0)
            .map(|&l| 0.5f64.powi(i32::from(l)))
            .sum()
    }

    #[test]
    fn huffman_lengths_are_complete_and_limited() {
        // Fibonacci frequencies make the unlimited code 30+ bits deep.
        let mut freq = [0u32; 286];
        let (mut a, mut b) = (1u32, 1u32);
        for f in freq.iter_mut().take(40) {
            *f = a;
            (a, b) = (b, a.saturating_add(b));
        }
        let mut lens = [0u8; 286];
        huffman_lengths(&freq, 15, &mut lens);
        assert!(lens.iter().all(|&l| l <= 15));
        assert!((kraft(&lens) - 1.0).abs() < 1e-12);
        let mut cl = [0u8; 19];
        let f19: [u32; 19] = freq[..19].try_into().unwrap();
        huffman_lengths(&f19, 7, &mut cl);
        assert!(cl.iter().all(|&l| l <= 7) && (kraft(&cl) - 1.0).abs() < 1e-12);
        // One symbol: paired with a dummy, two one-bit codes.
        let mut one = [0u32; 30];
        one[7] = 9;
        let mut dl = [0u8; 30];
        huffman_lengths(&one, 15, &mut dl);
        assert_eq!(dl.iter().filter(|&&l| l == 1).count(), 2);
        assert_eq!(dl[7], 1);
        // None: two dummies.
        huffman_lengths(&[0u32; 30], 15, &mut dl);
        assert_eq!(dl.iter().filter(|&&l| l == 1).count(), 2);
    }

    #[test]
    fn code_tables() {
        assert_eq!(LEN_CODE[0], 0);
        assert_eq!(LEN_CODE[8], 8); // length 11 -> symbol 265
        assert_eq!(LEN_CODE[254], 27);
        assert_eq!(LEN_CODE[255], 28);
        assert_eq!(dist_code(1), 0);
        assert_eq!(dist_code(5), 4);
        assert_eq!(dist_code(256), 15);
        assert_eq!(dist_code(257), 16);
        assert_eq!(dist_code(32768), 29);
        // Every distance maps to the symbol whose range holds it.
        for d in 1..=32768usize {
            let c = dist_code(d);
            let base = usize::from(DIST_BASE[c]);
            assert!(d >= base && d < base + (1 << DIST_EXTRA[c]), "{d}");
        }
    }

    #[test]
    fn rle() {
        let mut out = [(0u8, 0u8); 316];
        let n = rle_lengths(&[0; 150], &mut out);
        assert_eq!(&out[..n], &[(18, 127), (18, 1)][..]);
        let n = rle_lengths(&[8; 10], &mut out);
        assert_eq!(&out[..n], &[(8, 0), (16, 3), (16, 0)][..]);
    }
}
