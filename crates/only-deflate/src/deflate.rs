//! Streaming compression: LZ77 with hash chains (greedy for the fast levels, lazy matching for
//! the others, with zlib's level parameters), and blocks coded with whichever is smallest of a
//! dynamic Huffman code (length-limited), the fixed code, or stored.

use crate::checksum::{Adler32, Crc32};
use crate::tables::{
    CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA, fixed_lit_lens, reverse_bits,
};
use crate::{Flush, Format, Level};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Lookahead needed to find a full-length match after the current position.
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
/// Matches of length 3 further away than this are not worth it.
const TOO_FAR: usize = 4096;
/// Symbols per block (zlib's `lit_bufsize - 1` at the default memory level).
const SYMS_PER_BLOCK: usize = 16383;
const MAX_STORED: usize = 65535;

#[derive(Clone, Copy, Debug)]
struct Config {
    /// Reduce the chain search when the previous match is at least this long.
    good: u16,
    /// Lazy levels: do not look for a better match after one this long. Fast levels: insert
    /// the strings of matches up to this long into the hash table.
    lazy: u16,
    /// Stop searching at a match this long.
    nice: u16,
    /// Longest hash chain walked.
    chain: u16,
    lazy_matching: bool,
}

const fn cfg(good: u16, lazy: u16, nice: u16, chain: u16, lazy_matching: bool) -> Config {
    Config {
        good,
        lazy,
        nice,
        chain,
        lazy_matching,
    }
}

/// zlib's configuration table.
const CONFIGS: [Config; 10] = [
    cfg(0, 0, 0, 0, false), // stored
    cfg(4, 4, 8, 4, false),
    cfg(4, 5, 16, 8, false),
    cfg(4, 6, 32, 32, false),
    cfg(4, 4, 16, 16, true),
    cfg(8, 16, 32, 32, true),
    cfg(8, 16, 128, 128, true),
    cfg(8, 32, 128, 256, true),
    cfg(32, 128, 258, 1024, true),
    cfg(32, 258, 258, 4096, true),
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
    let d = dist - 1;
    usize::from(if d < 256 {
        DIST_CODE[d]
    } else {
        DIST_CODE[256 + (d >> 7)]
    })
}

/// A streaming DEFLATE / zlib / gzip compressor.
///
/// [`compress`](Deflater::compress) takes input of any size and appends compressed bytes to a
/// `Vec`. [`Flush::Sync`] ends the output on a byte boundary with an empty stored block (the
/// `00 00 ff ff` marker of permessage-deflate) while keeping the history for later data;
/// [`Flush::Full`] also forgets the history; [`Flush::Finish`] ends the stream.
///
/// ```
/// use only_deflate::{Deflater, Flush, Format, Inflater, Level};
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
    /// `2 * w_size` bytes; positions in `head`/`prev` are indices into it (0 = none).
    window: Vec<u8>,
    prev: Vec<u16>,
    head: Vec<u16>,
    strstart: usize,
    block_start: isize,
    lookahead: usize,
    /// Positions before `strstart` not yet inserted into the hash table (end of input).
    insert: usize,
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
    bitbuf: u64,
    bitcnt: u32,
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
            hash_bits: u32::from(lay).clamp(10, 15),
            window: Vec::new(),
            prev: Vec::new(),
            head: Vec::new(),
            strstart: 0,
            block_start: 0,
            lookahead: 0,
            insert: 0,
            match_start: 0,
            match_length: 0,
            prev_length: 0,
            prev_match: 0,
            match_available: false,
            syms: Vec::new(),
            lfreq: [0; 286],
            dfreq: [0; 30],
            raw: Vec::new(),
            bitbuf: 0,
            bitcnt: 0,
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
        self.head.fill(0);
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
        self.bitbuf = 0;
        self.bitcnt = 0;
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
                self.window = vec![0; 2 * self.w_size];
                self.prev = vec![0; self.w_size];
                self.head = vec![0; 1 << self.hash_bits];
                self.syms.reserve_exact(SYMS_PER_BLOCK);
            }
            out.reserve(input.len() / 2 + 64);
            if self.cfg.lazy_matching {
                self.deflate_slow(input, out, flush);
            } else {
                self.deflate_fast(input, out, flush);
            }
        }
        match flush {
            Flush::None => {}
            Flush::Sync | Flush::Full => {
                self.stored_block(&[], false, out);
                if flush == Flush::Full && self.level != 0 {
                    self.head.fill(0);
                    if self.lookahead == 0 {
                        self.strstart = 0;
                        self.block_start = 0;
                        self.insert = 0;
                    }
                }
            }
            Flush::Finish => {
                self.align(out);
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
        let mut raw = std::mem::take(&mut self.raw);
        let mut start = 0;
        while raw.len() - start > MAX_STORED {
            self.stored_one(&raw[start..start + MAX_STORED], false, out);
            start += MAX_STORED;
        }
        match flush {
            Flush::None => {}
            Flush::Sync | Flush::Full => {
                if start < raw.len() {
                    self.stored_one(&raw[start..], false, out);
                    start = raw.len();
                }
            }
            Flush::Finish => {
                self.stored_one(&raw[start..], true, out);
                start = raw.len();
            }
        }
        raw.drain(..start);
        self.raw = raw;
    }

    // ---- bit output ---------------------------------------------------------------------------

    #[inline(always)]
    fn put(&mut self, out: &mut Vec<u8>, v: u32, n: u32) {
        self.bitbuf |= u64::from(v) << self.bitcnt;
        self.bitcnt += n;
        if self.bitcnt >= 32 {
            out.extend_from_slice(&(self.bitbuf as u32).to_le_bytes());
            self.bitbuf >>= 32;
            self.bitcnt -= 32;
        }
    }

    fn align(&mut self, out: &mut Vec<u8>) {
        while self.bitcnt > 0 {
            out.push(self.bitbuf as u8);
            self.bitbuf >>= 8;
            self.bitcnt = self.bitcnt.saturating_sub(8);
        }
        self.bitbuf = 0;
    }

    /// Writes `data` as stored blocks (split at 65535 bytes); `last` marks the final one.
    fn stored_block(&mut self, data: &[u8], last: bool, out: &mut Vec<u8>) {
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

    // ---- LZ77 ---------------------------------------------------------------------------------

    fn max_dist(&self) -> usize {
        self.w_size - MIN_LOOKAHEAD
    }

    #[inline(always)]
    fn hash(&self, pos: usize) -> usize {
        let w = &self.window;
        let v = u32::from(w[pos]) | (u32::from(w[pos + 1]) << 8) | (u32::from(w[pos + 2]) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - self.hash_bits)) as usize
    }

    /// Inserts the string at `pos` and returns the previous head of its chain (0: none).
    #[inline(always)]
    fn insert_string(&mut self, pos: usize) -> usize {
        let h = self.hash(pos);
        let old = self.head[h];
        self.prev[pos & (self.w_size - 1)] = old;
        self.head[h] = pos as u16;
        usize::from(old)
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
            if self.lookahead + self.insert >= MIN_MATCH {
                let mut s = self.strstart - self.insert;
                while self.insert > 0 {
                    self.insert_string(s);
                    s += 1;
                    self.insert -= 1;
                    if self.lookahead + self.insert < MIN_MATCH {
                        break;
                    }
                }
            }
            if self.lookahead >= MIN_LOOKAHEAD || input.is_empty() {
                break;
            }
        }
    }

    /// Longest match at `strstart` along the chain starting at `cur`; sets `match_start`.
    fn longest_match(&mut self, mut cur: usize) -> usize {
        let mut chain = u32::from(self.cfg.chain);
        let scan = self.strstart;
        let mut best = self.prev_length;
        let nice = usize::from(self.cfg.nice).min(self.lookahead);
        let max_len = MAX_MATCH.min(self.lookahead);
        let limit = self.strstart.saturating_sub(self.max_dist());
        if self.prev_length >= usize::from(self.cfg.good) {
            chain >>= 2;
        }
        if best >= max_len {
            return max_len;
        }
        let w = &self.window[..];
        let wmask = self.w_size - 1;
        let head2 = [w[scan], w[scan + 1]];
        let mut end8 = eight(&w[(scan + best).saturating_sub(7)..]);
        loop {
            let m = cur;
            // Cheap rejection: the bytes ending at the current best length must match (8 at a
            // time once the best match is long enough), and so must the first two.
            let candidate = if best >= 7 {
                eight(&w[m + best - 7..]) == end8
            } else {
                w[m + best] == w[scan + best]
            };
            if candidate && [w[m], w[m + 1]] == head2 {
                let mut len = 2;
                while len + 8 <= max_len {
                    let a = u64::from_le_bytes(eight(&w[m + len..]));
                    let b = u64::from_le_bytes(eight(&w[scan + len..]));
                    let x = a ^ b;
                    if x != 0 {
                        len += (x.trailing_zeros() / 8) as usize;
                        break;
                    }
                    len += 8;
                }
                if len + 8 > max_len {
                    while len < max_len && w[m + len] == w[scan + len] {
                        len += 1;
                    }
                }
                let len = len.min(max_len);
                if len > best {
                    self.match_start = m;
                    best = len;
                    if len >= nice {
                        break;
                    }
                    if best >= 7 {
                        end8 = eight(&w[scan + best - 7..]);
                    }
                }
            }
            cur = usize::from(self.prev[m & wmask]);
            chain -= 1;
            if cur <= limit || chain == 0 {
                break;
            }
        }
        best.min(self.lookahead)
    }

    #[inline(always)]
    fn tally_lit(&mut self, c: u8) -> bool {
        self.syms.push(u32::from(c));
        self.lfreq[usize::from(c)] += 1;
        self.syms.len() == SYMS_PER_BLOCK
    }

    #[inline(always)]
    fn tally_match(&mut self, dist: usize, len: usize) -> bool {
        let lc = len - MIN_MATCH;
        self.syms.push(((dist as u32) << 16) | lc as u32);
        self.lfreq[257 + usize::from(LEN_CODE[lc])] += 1;
        self.dfreq[dist_code(dist)] += 1;
        self.syms.len() == SYMS_PER_BLOCK
    }

    fn end_block(&mut self, last: bool, out: &mut Vec<u8>) {
        self.flush_block(last, out);
        self.block_start = self.strstart as isize;
    }

    /// Greedy matching (levels 1..=3).
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
            let mut head = 0;
            if self.lookahead >= MIN_MATCH {
                head = self.insert_string(self.strstart);
            }
            if head != 0 && self.strstart - head <= self.max_dist() {
                self.match_length = self.longest_match(head);
            }
            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.tally_match(self.strstart - self.match_start, self.match_length);
                self.lookahead -= self.match_length;
                if self.match_length <= usize::from(self.cfg.lazy) && self.lookahead >= MIN_MATCH {
                    self.match_length -= 1;
                    while self.match_length > 0 {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                        self.match_length -= 1;
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                    self.match_length = 0;
                }
            } else {
                bflush = self.tally_lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                self.end_block(false, out);
            }
        }
        self.insert = self.strstart.min(MIN_MATCH - 1);
        if flush == Flush::Finish {
            self.end_block(true, out);
        } else if !self.syms.is_empty() {
            self.end_block(false, out);
        }
    }

    /// Lazy matching (levels 4..=9): a match is taken only if the next position does not
    /// start a longer one.
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
            let mut head = 0;
            if self.lookahead >= MIN_MATCH {
                head = self.insert_string(self.strstart);
            }
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if head != 0
                && self.prev_length < usize::from(self.cfg.lazy)
                && self.strstart - head <= self.max_dist()
            {
                self.match_length = self.longest_match(head);
                if self.match_length == MIN_MATCH && self.strstart - self.match_start > TOO_FAR {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;
                let bflush =
                    self.tally_match(self.strstart - 1 - self.prev_match, self.prev_length);
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
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
        self.insert = self.strstart.min(MIN_MATCH - 1);
        if flush == Flush::Finish {
            self.end_block(true, out);
        } else if !self.syms.is_empty() {
            self.end_block(false, out);
        }
    }

    // ---- blocks -------------------------------------------------------------------------------

    /// Writes the pending symbols as one block, choosing the smallest coding.
    fn flush_block(&mut self, last: bool, out: &mut Vec<u8>) {
        let stored_len = (self.strstart as isize - self.block_start) as usize;
        let raw = (self.block_start >= 0).then(|| {
            let s = self.block_start as usize;
            s..s + stored_len
        });
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
        let stored_bits = raw.as_ref().map(|_| {
            let pad = (8 - (u64::from(self.bitcnt) + 3) % 8) % 8;
            let extra_chunks = stored_len.saturating_sub(1) / MAX_STORED;
            3 + pad + 32 + 8 * stored_len as u64 + 40 * extra_chunks as u64
        });

        if let (Some(r), Some(sb)) = (raw, stored_bits) {
            if sb <= fixed_bits.min(dyn_bits) {
                let data = self.window[r].to_vec();
                self.stored_block(&data, last, out);
                self.clear_block();
                return;
            }
        }
        if fixed_bits <= dyn_bits {
            self.put(out, u32::from(last) | (1 << 1), 3);
            self.write_symbols(
                out,
                &FIXED_LIT_CODES,
                &FIXED_LIT_LENS,
                &FIXED_DIST_CODES,
                &[5; 30],
            );
        } else {
            self.put(out, u32::from(last) | (2 << 1), 3);
            self.put(out, (nlit - 257) as u32, 5);
            self.put(out, (ndist - 1) as u32, 5);
            self.put(out, (ncl - 4) as u32, 4);
            for &i in &CL_ORDER[..ncl] {
                self.put(out, u32::from(cllens[i]), 3);
            }
            let clcodes = canonical_codes(&cllens);
            for &(s, x) in &rle[..nrle] {
                let s = usize::from(s);
                self.put(out, u32::from(clcodes[s]), u32::from(cllens[s]));
                match s {
                    16 => self.put(out, u32::from(x), 2),
                    17 => self.put(out, u32::from(x), 3),
                    18 => self.put(out, u32::from(x), 7),
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
        lcodes: &[u16],
        llens: &[u8],
        dcodes: &[u16],
        dlens: &[u8],
    ) {
        let syms = std::mem::take(&mut self.syms);
        let mut bb = self.bitbuf;
        let mut bc = self.bitcnt;
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
                let code = usize::from(LEN_CODE[lc]);
                let sym = 257 + code;
                let xb = u32::from(LEN_EXTRA[code]);
                let xv = (lc + 3 - usize::from(LEN_BASE[code])) as u32;
                put!(
                    u32::from(lcodes[sym]) | (xv << llens[sym]),
                    u32::from(llens[sym]) + xb
                );
                let dc = dist_code(dist);
                let dxb = u32::from(DIST_EXTRA[dc]);
                let dxv = (dist - usize::from(DIST_BASE[dc])) as u32;
                put!(
                    u32::from(dcodes[dc]) | (dxv << dlens[dc]),
                    u32::from(dlens[dc]) + dxb
                );
            }
        }
        put!(u32::from(lcodes[256]), u32::from(llens[256]));
        self.bitbuf = bb;
        self.bitcnt = bc;
        self.syms = syms;
    }
}

#[inline(always)]
fn eight(s: &[u8]) -> [u8; 8] {
    // One bounds check instead of eight.
    match s.first_chunk::<8>() {
        Some(c) => *c,
        None => [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]],
    }
}

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
    canonical_codes_const(lens)
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
    let mut syms = [(0u32, 0u16); N];
    let mut n = 0;
    for (s, &f) in freq.iter().enumerate() {
        if f != 0 {
            syms[n] = (f, s as u16);
            n += 1;
        }
    }
    // Force two codes (zlib does the same): pkzip-era decoders want at least one bit per code.
    let mut s = 0;
    while n < 2 {
        if freq[s] == 0 && syms[..n].iter().all(|&(_, x)| usize::from(x) != s) {
            syms[n] = (1, s as u16);
            n += 1;
        }
        s += 1;
    }
    let syms = &mut syms[..n];
    syms.sort_unstable();

    // Moffat & Katajainen, in place: code lengths of a minimum-redundancy code.
    let mut keys = [0u32; N];
    let a = &mut keys[..n];
    for (k, &(f, _)) in a.iter_mut().zip(syms.iter()) {
        *k = f;
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
            lens[usize::from(syms[j].1)] = len as u8;
        }
    }
}

/// Compresses `data` into one complete `format` stream.
///
/// ```
/// use only_deflate::{Format, Level, compress, decompress};
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
