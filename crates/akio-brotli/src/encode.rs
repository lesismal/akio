//! Brotli compression.
//!
//! The input is cut into meta-blocks (1 MiB below level 10; at levels 10 and 11 up to twice the
//! window, parsed in blocks of 256 KiB, or 256 KiB when streaming), each parsed into
//! insert-and-copy commands by LZ77 (candidates from per-hash buckets of the last positions at
//! levels 0..=6, from hash chains above): greedy matching at levels 0..=3, lazy matching (up to
//! four steps, as in Google's encoder) at levels 4..=9, and at levels 10 and 11 a shortest-path
//! parse over all candidate matches priced with the code lengths of a previous pass (one pass
//! at level 10, two at 11). Candidates also include the four distances of the distance ring,
//! which cost a short code instead of extra bits. From level 5 the literals are coded with a
//! context map: the 64 contexts of each context mode are clustered greedily by the cost of
//! their histograms and the cheapest mode is kept. From level 4 the literals, insert-and-copy
//! symbols and distances are split into block types (`split`): greedily in one pass at levels
//! 4..=9, each literal block type with its own codes for the context map's clusters where they
//! pay; at 10 and 11 as Google's block splitter does, with a context map over block types and
//! contexts for literals and distances, kept only when that makes the meta-block smaller.
//! Prefix codes are limited to 15 bits (5 for the code length code), written in the simple form
//! when they have at most four symbols, and their code length sequences are run-length coded
//! like Google's encoder does. A meta-block that would come out larger than its bytes is stored
//! uncompressed instead.

use crate::bits::BitWriter;
use crate::huffman;
use crate::shared::Search;
use crate::tables::{
    BLOCK_LEN, CODE_LENGTH_ORDER, CONTEXT_LUT, COPY_BASE, COPY_EXTRA, INS_BASE, INS_EXTRA,
    split_command,
};
use crate::{Level, SharedDictionary};

mod bucket;
mod sdict;
mod split;

use split::{BlockSplit, Histo};

/// Compresses `data` into one complete brotli stream at `level`.
///
/// The output decodes with any brotli decoder (Google's `brotli`, `brotli-decompressor`) and
/// with [`decompress`](crate::decompress).
pub fn compress(level: Level, data: &[u8]) -> Vec<u8> {
    compress_impl(level, data, &[], false, 22)
}

/// [`compress`] with a raw (LZ77 prefix) dictionary: matches may copy from `dict` as if it
/// preceded the data, while the output is shorter than the window (Google's raw shared
/// dictionaries, `brotli -D`). Decode with the same dictionary
/// ([`decompress_with_dictionary`](crate::decompress_with_dictionary), `brotli -d -D`).
pub fn compress_with_dictionary(level: Level, data: &[u8], dict: &[u8]) -> Vec<u8> {
    compress_impl(level, data, dict, false, 22)
}

/// [`compress`] with a shared dictionary (RFC 9841): matches may copy from its LZ77 prefix as
/// [`compress_with_dictionary`] does from a raw dictionary, and at levels 10 and 11 (where
/// brotli's built-in words are searched) its custom static dictionaries are searched instead
/// of the built-in one: every word of the dictionary that a static dictionary reference at a
/// position uses first (by the literal context there, if the dictionary says so) under every
/// transform of its list (indexed once per dictionary, up to 2²¹ transformed words), as
/// Google's encoder does at its highest qualities. With a context-dependent dictionary the
/// literal context mode is UTF8 throughout (the mode selects the dictionary). Decode with
/// the same dictionary
/// ([`decompress_with_shared_dictionary`](crate::decompress_with_shared_dictionary)).
pub fn compress_with_shared_dictionary(
    level: Level,
    data: &[u8],
    dict: &SharedDictionary,
) -> Vec<u8> {
    let mut p = params(level.get());
    let mut custom = None;
    if !dict.is_raw() {
        p.static_words = false;
        if let Some(s) = dict.custom() {
            if s.context_based() {
                p.modes = &[2];
                p.fixed_mode = Some(2);
            }
        }
        custom = Some(dict.clone());
    }
    compress_shared(p, data, dict.prefix(), 22, custom)
}

/// [`compress`] into a large-window brotli stream (RFC 9841 section 6, Google's
/// `BROTLI_PARAM_LARGE_WINDOW`): the window is the smallest that holds all of `data`, up to
/// 2³⁰ bytes, so matches reach back over the whole input where a regular stream's reach at
/// most 4 MiB (the window [`compress`] uses; RFC 7932 allows 16 MiB). Only large-window
/// decoders decode it ([`decompress_large_window`](crate::decompress_large_window),
/// [`Decompressor::large_window`](crate::Decompressor::large_window), `brotli -d
/// --large_window`), even when the window is small: the header says large window.
pub fn compress_large_window(level: Level, data: &[u8]) -> Vec<u8> {
    let mut p = params(level.get());
    p.large = true;
    compress_with(p, data, &[], 30)
}

/// Writes the stream header (the window size; `large`: the large-window header).
pub(crate) fn write_window_bits(w: &mut BitWriter, wbits: u32, large: bool) {
    if large {
        // 0x11 in 8 bits (an invalid regular header), then the window bits in 6.
        w.bits(14, 0x11 | u64::from(wbits) << 8);
        return;
    }
    match wbits {
        16 => w.bits(1, 0),
        17 => w.bits(7, 1),
        18..=24 => w.bits(4, u64::from((wbits - 17) << 1 | 1)),
        _ => w.bits(7, u64::from((wbits - 8) << 4 | 1)),
    }
}

/// The one-shot stream of `data` at `level` (`large`: a large-window stream with a window of
/// up to `2^max_wbits`).
pub(crate) fn compress_impl(
    level: Level,
    data: &[u8],
    dict: &[u8],
    large: bool,
    max_wbits: u32,
) -> Vec<u8> {
    let mut p = params(level.get());
    p.large = large;
    compress_with(p, data, dict, if large { max_wbits } else { 22 })
}

fn compress_with(p: Params, data: &[u8], dict: &[u8], max_wbits: u32) -> Vec<u8> {
    compress_shared(p, data, dict, max_wbits, None)
}

/// [`compress_with`] with a shared dictionary's custom static dictionaries.
fn compress_shared(
    p: Params,
    data: &[u8],
    dict: &[u8],
    max_wbits: u32,
    custom: Option<SharedDictionary>,
) -> Vec<u8> {
    let wbits = window_bits(data.len(), max_wbits);
    let mut w = BitWriter::with_capacity(data.len() / 2 + 16);
    write_window_bits(&mut w, wbits, p.large);
    if data.is_empty() {
        w.bits(2, 0b11); // ISLAST, ISLASTEMPTY
        return w.finish();
    }
    let mut buf = Vec::new();
    let all = if dict.is_empty() {
        data
    } else {
        buf.reserve_exact(dict.len() + data.len());
        buf.extend_from_slice(dict);
        buf.extend_from_slice(data);
        &buf[..]
    };
    let mut e = Encoder::new(p, wbits, all, dict.len());
    e.custom = custom;
    e.insert_until(dict.len());
    let mut pos = dict.len();
    while pos < all.len() {
        if p.optimal > 0 {
            // Up to twice the window per meta-block, parsed in blocks (Google's sizes; a
            // meta-block holds at most 2^24 bytes).
            pos = e.long_meta_block(&mut w, pos, (pos + (2 << wbits.min(22))).min(all.len()));
        } else {
            let end = (pos + p.block).min(all.len());
            e.meta_block(&mut w, pos, end, end == all.len());
            pos = end;
        }
    }
    w.finish()
}

/// The smallest window holding all of `n` bytes, between 2^16 (a one-bit header) and
/// `2^max` (22: Google's default).
fn window_bits(n: usize, max: u32) -> u32 {
    let mut w = 16;
    while w < max && (1usize << w) - 16 < n {
        w += 1;
    }
    w
}

#[derive(Clone, Copy)]
struct Params {
    /// Hash chain candidates examined per position.
    depth: u32,
    /// A match this long ends the search.
    nice: usize,
    lazy: bool,
    hash_bits: u32,
    /// Literal context modes to try (context modeling with clustered contexts); none: one
    /// literal code.
    modes: &'static [u8],
    /// Passes of optimal parsing (0: greedy or lazy).
    optimal: u32,
    /// Insert every position of a match into the hash chains (otherwise only the first ones of
    /// long matches).
    insert_all: bool,
    block: usize,
    /// Rounds of block splitting (0: one block type per category, or greedy).
    split_iters: usize,
    /// Greedy block splitting (levels 4..=9).
    greedy: bool,
    /// Static dictionary words are candidates (of the optimal parse); off for shared
    /// dictionaries with custom static dictionaries.
    static_words: bool,
    /// A large-window stream (RFC 9841 section 6): windows up to 2^30, a larger distance
    /// alphabet.
    large: bool,
    /// The literal context mode of every literal block type (a context-dependent shared
    /// dictionary: the mode selects the dictionary of a static dictionary reference).
    fixed_mode: Option<u8>,
}

impl Params {
    /// The distance symbols a meta-block may use: 64 (`NPOSTFIX` = `NDIRECT` = 0), or 74 in a
    /// large-window stream (distances up to 2^31 - 4, Google's limit).
    fn dist_size(&self) -> usize {
        if self.large { 74 } else { 64 }
    }

    /// The bits of a distance symbol in a simple prefix code: of an alphabet of 64 symbols, or
    /// of the large window's 140.
    fn dist_bits(&self) -> u32 {
        if self.large { 8 } else { 6 }
    }

    /// The largest distance the distance symbols can code: 2^26 - 4, or 2^31 - 4.
    fn max_distance(&self) -> usize {
        if self.large {
            0x7fff_fffc
        } else {
            (1 << 26) - 4
        }
    }
}

fn params(level: u8) -> Params {
    const NONE: &[u8] = &[];
    const TWO: &[u8] = &[2, 3];
    const ALL: &[u8] = &[2, 0, 1, 3];
    let p = |depth, nice, lazy, hash_bits, modes, insert_all| Params {
        depth,
        nice,
        lazy,
        hash_bits,
        modes,
        optimal: 0,
        insert_all,
        block: 1 << 20,
        split_iters: 0,
        greedy: level >= 4,
        static_words: true,
        large: false,
        fixed_mode: None,
    };
    match level {
        0 => p(1, 16, false, 14, NONE, false),
        1 => p(2, 32, false, 15, NONE, false),
        2 => p(2, 32, false, 15, NONE, true),
        3 => p(4, 64, false, 16, NONE, true),
        4 => p(4, 64, true, 16, NONE, true),
        5 => p(16, 128, true, 16, TWO, true),
        6 => p(32, 128, true, 17, TWO, true),
        7 => p(64, 192, true, 17, ALL, true),
        8 => p(128, 256, true, 17, ALL, true),
        9 => p(256, 258, true, 17, ALL, true),
        10 => Params {
            optimal: 1,
            block: 1 << 18,
            split_iters: 3,
            ..p(128, 256, false, 17, ALL, true)
        },
        _ => Params {
            optimal: 2,
            block: 1 << 18,
            split_iters: 10,
            ..p(512, 512, false, 17, ALL, true)
        },
    }
}

/// An insert-and-copy command: `insert` literals, then `copy` bytes from `dist` back (`copy`
/// 0: the last command of a meta-block, literals only), or a static dictionary word of length
/// `copy` producing `out` bytes (`out` 0: a backward copy).
#[derive(Clone, Copy, Debug)]
struct Command {
    insert: u32,
    copy: u32,
    dist: u32,
    out: u32,
}

impl Command {
    /// The bytes the command produces.
    fn advance(&self) -> usize {
        (self.insert + if self.out > 0 { self.out } else { self.copy }) as usize
    }
}

const NIL: u32 = u32::MAX;
const MIN_SCORE: i64 = 1920 + 100;
const LAZY_MARGIN: i64 = 175;

pub(crate) struct Encoder<'a> {
    data: &'a [u8],
    p: Params,
    /// Largest backward distance (window - 16).
    max_dist: usize,
    head: Vec<u32>,
    prev: Vec<u32>,
    wmask: usize,
    /// Instead of chains (levels with up to 32 candidates and no optimal parsing): per hash,
    /// a bucket of the last `1 << block_bits` positions (`buckets`) and how many were entered
    /// (`num`, kept modulo twice the bucket size: it says which entries are filled and which
    /// is the oldest); the same candidates in the same order, in one or two cache lines.
    block_bits: u32,
    /// Hash the next five bytes instead of four (levels with 16 or more candidates: fewer of
    /// them that cannot match, as in Google's `H6`).
    hash5: bool,
    num: Vec<u8>,
    buckets: Vec<u32>,
    /// Next position to enter into the hash chains.
    ins: usize,
    /// The distance ring, most recent first.
    last: [u32; 4],
    /// `data[..zero]` is a raw dictionary (0: none, or no longer reachable).
    zero: usize,
    /// The stream position of `data[i]` is `i + fwd - back` (`back`: the dictionary's length;
    /// `fwd`: bytes a streaming encoder dropped from the front).
    fwd: usize,
    back: usize,
    /// The level's hash bits (`p.hash_bits` is what the tables have).
    level_bits: u32,
    /// How far back the tables need to reach: the window, and the dictionary if any.
    reach: usize,
    scratch: Box<Scratch>,
    /// A shared dictionary's custom static dictionaries (one-shot only).
    custom: Option<SharedDictionary>,
}

impl State {
    /// Positions are moved `drop` bytes down (the data before them was dropped, the
    /// dictionary with it); `drop` is a multiple of [`State::align`].
    pub(crate) fn rebase(&mut self, drop: usize) {
        let d = drop as u32;
        for v in self.head.iter_mut().chain(self.prev.iter_mut()) {
            *v = if *v == NIL || *v < d { NIL } else { *v - d };
        }
        for v in &mut self.buckets {
            *v = v.saturating_sub(d);
        }
        self.ins = self.ins.saturating_sub(drop);
        self.fwd += drop;
        self.zero = 0;
    }

    /// What dropped data must be a multiple of: the chains are indexed by position.
    pub(crate) fn align(&self) -> usize {
        self.wmask + 1
    }

    /// The meta-block size of the level.
    pub(crate) fn block(&self) -> usize {
        self.p.block
    }

    /// Keep the codes of each meta-block, to send them again where that costs no more bits
    /// than new ones (a stream's small meta-blocks).
    pub(crate) fn keep_codes(&mut self) {
        self.scratch.keep_codes();
    }

    /// The scratch buffers and kept codes.
    #[cfg(test)]
    pub(crate) fn scratch(&self) -> &Scratch {
        &self.scratch
    }

    /// Bytes allocated for the match tables.
    #[cfg(test)]
    pub(crate) fn table_bytes(&self) -> usize {
        4 * (self.head.len() + self.prev.len() + self.buckets.len()) + self.num.len()
    }
}

/// The state of an [`Encoder`] between the meta-blocks of a stream, apart from the data.
pub(crate) struct State {
    p: Params,
    max_dist: usize,
    head: Vec<u32>,
    prev: Vec<u32>,
    wmask: usize,
    block_bits: u32,
    hash5: bool,
    num: Vec<u8>,
    buckets: Vec<u32>,
    ins: usize,
    last: [u32; 4],
    zero: usize,
    fwd: usize,
    back: usize,
    level_bits: u32,
    reach: usize,
    scratch: Box<Scratch>,
}

#[inline(always)]
fn load8(d: &[u8], i: usize) -> u64 {
    match d.get(i..i + 8) {
        Some(s) => u64::from_le_bytes(s.try_into().unwrap_or([0; 8])),
        None => {
            let mut b = [0u8; 8];
            let rest = d.get(i..).unwrap_or(&[]);
            b[..rest.len().min(8)].copy_from_slice(&rest[..rest.len().min(8)]);
            u64::from_le_bytes(b)
        }
    }
}

#[inline(always)]
fn load4(d: &[u8], i: usize) -> u32 {
    match d.get(i..i + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

/// Length of the common prefix of `d[a..]` and `d[b..]`, at most `max`.
#[inline(always)]
fn match_len(d: &[u8], a: usize, b: usize, max: usize) -> usize {
    let (Some(x), Some(y)) = (d.get(a..), d.get(b..b + max)) else {
        return 0;
    };
    let mut n = 0;
    let mut xs = x.chunks_exact(8);
    for yc in y.chunks_exact(8) {
        let Some(xc) = xs.next() else { break };
        let xv = u64::from_le_bytes(xc.try_into().unwrap_or([0; 8]));
        let yv = u64::from_le_bytes(yc.try_into().unwrap_or([0; 8]));
        let diff = xv ^ yv;
        if diff != 0 {
            return n + (diff.trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < y.len() && x.get(n) == Some(&y[n]) {
        n += 1;
    }
    n
}

/// The next value of a bucket's counter of entered positions, for buckets of `size` entries
/// (a power of two up to 32): counted up to `2 * size`, then from `size` again, which keeps
/// both what is needed from it, how many entries are filled (`k.min(size)`) and the next
/// slot (`k % size`).
#[inline(always)]
fn bump(k: u8, size: usize) -> u8 {
    let n = k + 1;
    if usize::from(n) == 2 * size {
        size as u8
    } else {
        n
    }
}

fn log2_floor(x: usize) -> i64 {
    i64::from(usize::BITS - 1 - x.max(1).leading_zeros())
}

/// A match found at a position: length, distance and score (Google's backward reference
/// score: about 135 per byte, minus 30 per bit of distance, a bonus for the last distance).
#[derive(Clone, Copy)]
struct Found {
    len: usize,
    dist: usize,
    score: i64,
}

impl<'a> Encoder<'a> {
    /// An encoder of `data` whose first `dict` bytes are a raw dictionary.
    fn new(p: Params, wbits: u32, data: &'a [u8], dict: usize) -> Self {
        // The chains reach the dictionary as well as the window.
        let reach = if dict > 0 {
            2usize << wbits
        } else {
            1usize << wbits
        };
        let bucketed = p.optimal == 0 && p.depth <= 32;
        let block_bits = if bucketed {
            p.depth.trailing_zeros()
        } else {
            0
        };
        let mut e = Encoder {
            data,
            p,
            max_dist: (1usize << wbits) - 16,
            head: Vec::new(),
            prev: Vec::new(),
            wmask: 0,
            block_bits,
            hash5: bucketed && p.depth >= 16,
            num: Vec::new(),
            buckets: Vec::new(),
            ins: 0,
            last: [4, 11, 15, 16],
            zero: dict,
            fwd: 0,
            back: dict,
            level_bits: p.hash_bits,
            reach,
            scratch: Box::default(),
            custom: None,
        };
        let (hash_bits, wsize) = e.table_sizes(data.len());
        e.alloc_tables(hash_bits, wsize);
        e
    }

    /// The hash bits and chain size for tables over an input of `len` bytes: about twice as
    /// many entries as it has bytes, at most the level's.
    fn table_sizes(&self, len: usize) -> (u32, usize) {
        // A chain of at most 2^25 positions (a large window's would take gigabytes): older
        // links are overwritten, and a candidate found through one is checked like any other.
        let wsize = self
            .reach
            .min(1 << 25)
            .min(len.next_power_of_two().max(1024));
        let len_bits = usize::BITS - len.max(1).leading_zeros();
        let bits = if self.p.optimal == 0 && self.p.depth <= 32 {
            // At most 2^15 buckets.
            self.level_bits
                .min(15)
                .min((len_bits + 1).saturating_sub(self.block_bits))
                .max(8)
        } else {
            self.level_bits.min(len_bits + 1).max(10)
        };
        (bits, wsize)
    }

    /// Empty tables of `2^hash_bits` hashes (and a chain of `wsize` positions).
    fn alloc_tables(&mut self, hash_bits: u32, wsize: usize) {
        self.p.hash_bits = hash_bits;
        self.wmask = wsize - 1;
        if self.p.optimal == 0 && self.p.depth <= 32 {
            self.num = vec![0; 1 << hash_bits];
            self.buckets = vec![0; 1 << (hash_bits + self.block_bits)];
        } else {
            self.head = vec![NIL; 1 << hash_bits];
            self.prev = vec![NIL; wsize];
        }
    }

    /// A fresh state at `level` for a stream with a window of `2^wbits` bytes whose data
    /// starts with a raw dictionary of `dict` bytes. Its tables are those of an input of
    /// `dict` bytes; [`Encoder::fit`] grows them with the stream.
    pub(crate) fn state(level: Level, wbits: u32, dict: usize, large: bool) -> State {
        let mut p = params(level.get());
        p.large = large;
        Encoder::new(p, wbits, &[], dict).suspend_sized(dict)
    }

    /// [`Encoder::suspend`] with tables sized for `len` bytes.
    fn suspend_sized(mut self, len: usize) -> State {
        let (hash_bits, wsize) = self.table_sizes(len);
        self.alloc_tables(hash_bits, wsize);
        self.suspend()
    }

    /// Grows the tables to those of an input of the data's length (or of the reach, if less:
    /// a match never reaches further back, so a longer stream needs no larger tables),
    /// entering again the positions entered so far. A stream's tables then grow as its data
    /// does, as a one-shot encoder sizes them by its input: the first events of a stream
    /// clear and hold kilobytes of tables, not the level's full size.
    pub(crate) fn fit(&mut self) {
        let (hash_bits, mut wsize) = self.table_sizes(self.data.len().min(self.reach));
        if !self.num.is_empty() {
            // Buckets have no chain (the size is what a slide drops a multiple of).
            wsize = self.wmask + 1;
        }
        if hash_bits <= self.p.hash_bits && wsize <= self.wmask + 1 {
            return;
        }
        // Room for the stream to grow fourfold before the next rebuild (a stream that has sent
        // this much is likely to send as much again), and the full size once it holds a
        // sixteenth of the reach: a response written in 16 KiB pieces gets its final tables at
        // the first piece, an event stream rebuilds a few times in its first kilobytes.
        let (hash_bits, wsize) = if wsize > self.wmask + 1 || hash_bits > self.p.hash_bits {
            let len = self.data.len();
            let target = if 16 * len >= self.reach {
                self.reach
            } else {
                4 * len
            };
            let (h, w) = self.table_sizes(target.min(self.reach));
            let w = if self.num.is_empty() {
                w
            } else {
                self.wmask + 1
            };
            (h.max(self.p.hash_bits), w.max(self.wmask + 1))
        } else {
            (self.p.hash_bits, self.wmask + 1)
        };
        if hash_bits == self.p.hash_bits && self.num.is_empty() {
            // Only the chain grows: its links move to their slots in the larger one (a link
            // is a position, the same in both), with no hashing again.
            let old = self.wmask + 1;
            let mut prev = vec![NIL; wsize];
            for i in self.ins.saturating_sub(old)..self.ins {
                prev[i & (wsize - 1)] = self.prev[i & self.wmask];
            }
            self.prev = prev;
            self.wmask = wsize - 1;
            return;
        }
        self.alloc_tables(hash_bits, wsize);
        // Positions from the reach back on only: older ones are never matched (the slide keeps
        // up to two windows and the dictionary is within the reach).
        let upto = self.ins;
        self.ins = upto.saturating_sub(self.reach);
        self.insert_until(upto);
    }

    /// An encoder over `data` (the stream so far, in the coordinates of `s`) continuing `s`.
    pub(crate) fn resume(data: &'a [u8], s: State) -> Self {
        Encoder {
            data,
            p: s.p,
            max_dist: s.max_dist,
            head: s.head,
            prev: s.prev,
            wmask: s.wmask,
            block_bits: s.block_bits,
            hash5: s.hash5,
            num: s.num,
            buckets: s.buckets,
            ins: s.ins,
            last: s.last,
            zero: s.zero,
            fwd: s.fwd,
            back: s.back,
            level_bits: s.level_bits,
            reach: s.reach,
            scratch: s.scratch,
            custom: None,
        }
    }

    /// The state to continue from with [`Encoder::resume`].
    pub(crate) fn suspend(self) -> State {
        State {
            p: self.p,
            max_dist: self.max_dist,
            head: self.head,
            prev: self.prev,
            wmask: self.wmask,
            block_bits: self.block_bits,
            hash5: self.hash5,
            num: self.num,
            buckets: self.buckets,
            ins: self.ins,
            last: self.last,
            zero: self.zero,
            fwd: self.fwd,
            back: self.back,
            level_bits: self.level_bits,
            reach: self.reach,
            scratch: self.scratch,
        }
    }

    /// The farthest backward distance at `i`: the output so far, up to the window.
    #[inline(always)]
    fn reach(&self, i: usize) -> usize {
        (i + self.fwd - self.back).min(self.max_dist)
    }

    /// The longest copy from dictionary position `c` at `i` (0: none): the decoder takes a
    /// distance beyond the output so far as one into the dictionary while the output is within
    /// the window, and the copy must end within the dictionary.
    #[inline(always)]
    fn dict_room(&self, i: usize, c: usize) -> usize {
        if c < self.zero && i + self.fwd - self.back <= self.max_dist {
            self.zero - c
        } else {
            0
        }
    }

    /// The chains' hash of the four bytes at `i` (buckets: `bucket::Buckets::key`).
    #[inline(always)]
    fn hash(&self, i: usize) -> usize {
        (load4(self.data, i).wrapping_mul(0x1E35_A7BD) >> (32 - self.p.hash_bits)) as usize
    }

    /// Enters positions up to `upto` (exclusive) into the hash chains.
    pub(crate) fn insert_until(&mut self, upto: usize) {
        if !self.num.is_empty() {
            self.insert_buckets(upto);
            return;
        }
        let lim = upto.min(self.data.len().saturating_sub(3));
        while self.ins < lim {
            let i = self.ins;
            let h = self.hash(i);
            self.prev[i & self.wmask] = self.head[h];
            self.head[h] = i as u32;
            self.ins += 1;
        }
        self.ins = self.ins.max(upto);
    }

    /// The best match at `i` (not yet in the chains), ending at most at `end`.
    fn find(&self, i: usize, end: usize, ring: &[u32; 4]) -> Option<Found> {
        let d = self.data;
        let max_len = end - i;
        if max_len < 2 {
            return None;
        }
        let max_dist = self.reach(i);
        let mut best: Option<Found> = None;
        let mut best_score = MIN_SCORE;
        let mut best_len = 0;
        for (k, &rd) in ring.iter().enumerate() {
            let dist = rd as usize;
            if dist == 0 || dist > max_dist {
                continue;
            }
            // Quick rejects: at least two bytes, and longer than the best so far.
            if d.get(i) != d.get(i - dist)
                || d.get(i + 1) != d.get(i + 1 - dist)
                || (best_len > 0
                    && (best_len >= max_len || d.get(i + best_len) != d.get(i + best_len - dist)))
            {
                continue;
            }
            let len = match_len(d, i - dist, i, max_len);
            if len < if k < 2 { 2 } else { 3 } {
                continue;
            }
            let score = 135 * len as i64 + 1920 + if k == 0 { 15 } else { -60 };
            if score > best_score {
                best_score = score;
                best_len = len;
                best = Some(Found { len, dist, score });
            }
        }
        if max_len < 4 {
            return best;
        }
        let mut cand = self.head[self.hash(i)];
        let mut n = self.p.depth;
        while cand != NIL && n > 0 {
            let c = cand as usize;
            let mut max_len = max_len;
            if c >= i || i - c > max_dist {
                // Beyond the window: the dictionary, if any.
                let room = if c < i { self.dict_room(i, c) } else { 0 };
                if room == 0 {
                    break;
                }
                max_len = max_len.min(room);
            }
            n -= 1;
            let next = self.prev[c & self.wmask];
            cand = if next == NIL || next as usize >= c {
                NIL
            } else {
                next
            };
            if best_len >= max_len || d.get(c + best_len) != d.get(i + best_len) {
                continue;
            }
            let len = match_len(d, c, i, max_len);
            if len >= 4 {
                let dist = i - c;
                let score = 135 * len as i64 + 1920 - 30 * log2_floor(dist);
                if score > best_score {
                    best_score = score;
                    best_len = len;
                    best = Some(Found { len, dist, score });
                    if len >= self.p.nice {
                        break;
                    }
                }
            }
        }
        best
    }

    /// Greedy or lazy parse of `start..end` into `cmds`; updates the ring.
    fn parse_lazy(&mut self, start: usize, end: usize, cmds: &mut Vec<Command>) {
        if !self.num.is_empty() {
            self.parse_buckets(start, end, cmds);
            return;
        }
        let mut i = start;
        let mut lit_start = start;
        let mut ring = self.last;
        // Google's encoder's heuristic for data that does not compress: when no match was
        // found for a while, look at every second position, and later at every fourth.
        const RANDOM_WINDOW: usize = 64;
        while i < end {
            self.insert_until(i);
            let Some(mut cur) = self.find(i, end, &ring) else {
                let gap = i - lit_start;
                if gap > RANDOM_WINDOW && i + 20 < end {
                    let (span, step) = if gap > 5 * RANDOM_WINDOW {
                        (16, 4)
                    } else {
                        (8, 2)
                    };
                    let stop = i + span;
                    while i < stop {
                        self.insert_until(i + 1);
                        i += step;
                        self.ins = i;
                    }
                } else {
                    i += 1;
                }
                continue;
            };
            if self.p.lazy {
                let mut steps = 0;
                while steps < 4 && i + 1 < end {
                    self.insert_until(i + 1);
                    match self.find(i + 1, end, &ring) {
                        Some(nx) if nx.len >= 4 && nx.score > cur.score + LAZY_MARGIN => {
                            cur = nx;
                            i += 1;
                            steps += 1;
                        }
                        _ => break,
                    }
                }
            }
            cmds.push(Command {
                insert: (i - lit_start) as u32,
                copy: cur.len as u32,
                dist: cur.dist as u32,
                out: 0,
            });
            if cur.dist as u32 != ring[0] {
                ring = [cur.dist as u32, ring[0], ring[1], ring[2]];
            }
            let next = i + cur.len;
            if !self.p.insert_all && cur.len > 16 {
                self.insert_until(i + 8);
                self.ins = self.ins.max(next);
            }
            i = next;
            lit_start = i;
        }
        if lit_start < end {
            cmds.push(Command {
                insert: (end - lit_start) as u32,
                copy: 0,
                dist: 0,
                out: 0,
            });
        }
    }

    pub(crate) fn meta_block(&mut self, w: &mut BitWriter, start: usize, end: usize, last: bool) {
        let mut cmds = std::mem::take(&mut self.scratch.cmds);
        cmds.clear();
        if self.p.optimal > 0 {
            self.parse_optimal(start, end, &mut cmds);
        } else {
            self.parse_lazy(start, end, &mut cmds);
        }
        self.write_meta_block(w, start, end, last, &cmds);
        self.scratch.cmds = cmds;
    }

    /// Writes one meta-block from `start` to at most `limit`, parsed (optimally) in blocks of
    /// the level's size, ending early once it holds as many literals or commands as an eighth
    /// of its size limit; returns its end.
    fn long_meta_block(&mut self, w: &mut BitWriter, start: usize, limit: usize) -> usize {
        let max = (limit - start) / 8;
        let ring = self.last;
        let mut cmds: Vec<Command> = Vec::new();
        let mut literals = 0;
        let mut pos = start;
        while pos < limit {
            let end = (pos + self.p.block).min(limit);
            let mut part = Vec::new();
            self.parse_optimal(pos, end, &mut part);
            let mut r = self.last;
            for c in &part {
                code_command(c, &mut r);
            }
            self.last = r;
            // The literals ending the previous block go before the first command of this one.
            if let (Some(prev), Some(first)) = (cmds.last(), part.first_mut()) {
                if prev.copy == 0 {
                    first.insert += prev.insert;
                    literals -= prev.insert as usize;
                    cmds.pop();
                }
            }
            literals += part.iter().map(|c| c.insert as usize).sum::<usize>();
            cmds.extend_from_slice(&part);
            pos = end;
            if literals > max || cmds.len() > max {
                break;
            }
        }
        self.last = ring;
        let last = pos == self.data.len();
        self.write_meta_block(w, start, pos, last, &cmds);
        pos
    }

    /// One literal code, with the fixed context mode if any.
    fn single_model(&self) -> LiteralModel {
        let mut m = LiteralModel::single();
        if let Some(mode) = self.p.fixed_mode {
            m.mode = mode;
        }
        m
    }

    /// Writes the meta-block of `start..end` parsed into `cmds`, compressed or stored.
    fn write_meta_block(
        &mut self,
        w: &mut BitWriter,
        start: usize,
        end: usize,
        last: bool,
        cmds: &[Command],
    ) {
        let mark = w.mark();
        let before = w.bit_len();
        let ring = self.last;
        let z = self.zero;
        // Resolve the commands into symbols and extra bits.
        let mut coded = std::mem::take(&mut self.scratch.coded);
        coded.clear();
        for c in cmds {
            coded.push(code_command(c, &mut self.last));
        }
        let mut model = self.single_model();
        if !self.p.modes.is_empty() {
            // Clustering costs about as much as compressing a few kilobytes: below the optimal
            // parsing levels it is worth it only for more literals.
            let min_literals = if self.p.optimal > 0 { 2048 } else { 4096 };
            model = literal_model(&self.data[z..], start - z, cmds, self.p.modes, min_literals);
            if let Some(mode) = self.p.fixed_mode {
                // (One literal code: the mode only selects the custom dictionary.)
                model.mode = mode;
            }
        }
        let mb = MetaBlock {
            data: &self.data[z..],
            start: start - z,
            end: end - z,
            last,
            cmds,
            coded: &coded,
            dist_size: self.p.dist_size(),
            dist_bits: self.p.dist_bits(),
        };
        let single = self.single_model();
        let s = &mut self.scratch;
        if self.p.optimal == 0 {
            // The clustering's estimate says whether the context map pays for itself, and the
            // greedy split creates block types only where they pay.
            let lay = if self.p.greedy {
                greedy_layout(&mb, &model)
            } else {
                None
            };
            match lay {
                Some(lay) => write_compressed(w, &mb, &lay, s),
                None => {
                    let lay = s.single.take().unwrap_or_else(|| Layout::single(&model));
                    let lay = lay.with_model(&model);
                    write_compressed(w, &mb, &lay, s);
                    s.single = Some(lay);
                }
            }
        } else {
            // The smallest of: one literal code, the context map, block types.
            let mut layouts = vec![Layout::single(&single)];
            if model.ntrees > 1 {
                layouts.push(Layout::single(&model));
            }
            // (Block types never paid on inputs of a few kilobytes, and cost several times
            // their parse.)
            if self.p.split_iters > 0 && end - start >= 8 << 10 {
                let mode = if model.ntrees > 1 {
                    model.mode
                } else {
                    literal_model(mb.data, mb.start, cmds, self.p.modes, 0).mode
                };
                layouts.push(split_layout(&mb, mode, self.p.split_iters));
            }
            if layouts.len() == 1 {
                write_compressed(w, &mb, &layouts[0], s);
            } else {
                let mut best: Option<BitWriter> = None;
                for lay in &layouts {
                    let mut t = BitWriter::with_capacity((end - start) / 2);
                    write_compressed(&mut t, &mb, lay, s);
                    if best.as_ref().is_none_or(|b| t.bit_len() < b.bit_len()) {
                        best = Some(t);
                    }
                }
                if let Some(b) = best {
                    w.append(b);
                }
            }
        }
        self.scratch.coded = coded;
        let len = end - start;
        // An uncompressed meta-block: header, padding, bytes (and an empty last meta-block).
        let unc = 4 + 4 * nibbles(len) + 7 + 8 * len + if last { 2 + 7 } else { 0 };
        if w.bit_len() - before > unc {
            w.rollback(mark);
            self.last = ring;
            w.bits(1, 0); // ISLAST
            write_mlen(w, len);
            w.bits(1, 1); // ISUNCOMPRESSED
            w.bytes(&self.data[start..end]);
            if last {
                w.bits(2, 0b11);
            }
        }
    }
}

/// A parsed meta-block: `data[start..end]` (positions from the start of the stream: literal
/// contexts see no dictionary bytes) as commands, and their symbols and extra bits.
struct MetaBlock<'a> {
    data: &'a [u8],
    start: usize,
    end: usize,
    last: bool,
    cmds: &'a [Command],
    coded: &'a [Coded],
    /// The distance symbols counted (64; more in a large-window stream) and the bits of one
    /// in a simple prefix code.
    dist_size: usize,
    dist_bits: u32,
}

impl MetaBlock<'_> {
    /// Calls `f` with the position of each command's literals.
    fn literals(&self, mut f: impl FnMut(usize, &Command, &Coded)) {
        let mut pos = self.start;
        for (c, k) in self.cmds.iter().zip(self.coded) {
            f(pos, c, k);
            pos += c.advance();
        }
    }
}

/// Buffers that writing meta-blocks reuses (a stream of small flushed writes would otherwise
/// allocate a few dozen times per meta-block), and the codes a stream keeps.
#[derive(Default)]
pub(crate) struct Scratch {
    cmds: Vec<Command>,
    coded: Vec<Coded>,
    /// Histograms, all zero between meta-blocks: literals (256 per tree), insert-and-copy
    /// symbols (704 per block type), distances (per tree).
    lit_hist: Vec<u32>,
    cmd_hist: Vec<u32>,
    dist_hist: Vec<u32>,
    codes: [Vec<Code>; 3],
    prefix: PrefixScratch,
    /// The layout of one block type per category and one literal code, ready.
    single: Option<Layout>,
    /// The codes kept for literals, insert-and-copy symbols and distances (streams only).
    keep: Option<Box<[Kept; 3]>>,
}

impl Scratch {
    /// Keep codes across meta-blocks, to send them again where that is cheaper.
    pub(crate) fn keep_codes(&mut self) {
        self.keep.get_or_insert_with(Box::default);
    }

    /// Meta-blocks that sent a kept code again (literals, commands, distances).
    #[cfg(test)]
    pub(crate) fn reused(&self) -> [u32; 3] {
        self.keep
            .as_ref()
            .map_or([0; 3], |k| [k[0].reused, k[1].reused, k[2].reused])
    }
}

/// `v` with at least `n` entries (new ones zero).
fn at_least(v: &mut Vec<u32>, n: usize) -> &mut [u32] {
    if v.len() < n {
        v.resize(n, 0);
    }
    &mut v[..n]
}

/// Writes `mb` as a compressed meta-block coded as `lay` says.
fn write_compressed(w: &mut BitWriter, mb: &MetaBlock<'_>, lay: &Layout, s: &mut Scratch) {
    if lay.lit.ntypes > 1 || lay.cmd.ntypes > 1 || lay.dist.ntypes > 1 || lay.dist_trees > 1 {
        write_body::<true>(w, mb, lay, s);
    } else {
        // Without block switches (and with one distance code): no cursors in the loops.
        write_body::<false>(w, mb, lay, s);
    }
}

/// [`write_compressed`]; `SPLIT`: with block types (else one per category, one distance code).
fn write_body<const SPLIT: bool>(
    w: &mut BitWriter,
    mb: &MetaBlock<'_>,
    lay: &Layout,
    s: &mut Scratch,
) {
    let data = mb.data;
    let dsize = mb.dist_size;
    // Histograms: insert-and-copy symbols per block type, literals and distances per tree.
    let mut cmd_hist = std::mem::take(&mut s.cmd_hist);
    let mut lit_hist = std::mem::take(&mut s.lit_hist);
    let mut dist_hist = std::mem::take(&mut s.dist_hist);
    at_least(&mut cmd_hist, 704 * lay.cmd.ntypes);
    at_least(&mut lit_hist, 256 * lay.lit_trees);
    at_least(&mut dist_hist, dsize * lay.dist_trees);
    // Whether the literal tree depends on the context (or only on the block type).
    let lit_ctx = lay.lit_map.chunks(64).any(|m| m.iter().any(|&t| t != m[0]));
    let lit_map = &lay.lit_map[..];
    {
        let (mut cc, mut lc, mut dc) = (
            Cursor::new(&lay.cmd),
            Cursor::new(&lay.lit),
            Cursor::new(&lay.dist),
        );
        mb.literals(|pos, c, k| {
            let t = if SPLIT { cc.next() } else { 0 };
            cmd_hist[t * 704 + usize::from(k.cmd)] += 1;
            let (mut p, end) = (pos, pos + c.insert as usize);
            while p < end {
                // A run of literals in one block.
                let (t, n) = if SPLIT {
                    lc.take(end - p)
                } else {
                    (0, end - p)
                };
                let map = &lit_map[t * 64..t * 64 + 64];
                if lit_ctx {
                    let lut = 512 * usize::from(lay.modes[t]);
                    for q in p..p + n {
                        let tree = usize::from(map[context(data, q, lut)]);
                        lit_hist[tree * 256 + usize::from(data[q])] += 1;
                    }
                } else {
                    let tree = usize::from(map[0]);
                    let h = &mut lit_hist[tree * 256..tree * 256 + 256];
                    for &b in &data[p..p + n] {
                        h[usize::from(b)] += 1;
                    }
                }
                p += n;
            }
            if k.dsym != NO_DIST {
                let tree = if SPLIT {
                    usize::from(lay.dist_map[dc.next() * 4 + dist_context(k.cmd)])
                } else {
                    0
                };
                dist_hist[tree * dsize + usize::from(k.dsym)] += 1;
            }
        });
    }

    // Header.
    w.bits(1, u64::from(mb.last));
    if mb.last {
        w.bits(1, 0); // ISLASTEMPTY
    }
    write_mlen(w, mb.end - mb.start);
    if !mb.last {
        w.bits(1, 0); // ISUNCOMPRESSED
    }
    let mut lsw = Switcher::write(w, &lay.lit);
    let mut csw = Switcher::write(w, &lay.cmd);
    let mut dsw = Switcher::write(w, &lay.dist);
    w.bits(6, 0); // NPOSTFIX, NDIRECT
    for &m in &lay.modes {
        w.bits(2, u64::from(m));
    }
    write_var_len_u8(w, lay.lit_trees - 1);
    if lay.lit_trees > 1 {
        write_context_map(w, lit_map, lay.lit_trees);
    }
    write_var_len_u8(w, lay.dist_trees - 1);
    if lay.dist_trees > 1 {
        write_context_map(w, &lay.dist_map, lay.dist_trees);
    }
    // A category with a single code may send the stream's kept one again.
    let [mut lit_codes, mut cmd_codes, mut dist_codes] = std::mem::take(&mut s.codes);
    let mut keep = s.keep.take();
    {
        let [mut k0, mut k1, mut k2] = match keep.as_deref_mut() {
            Some([a, b, c]) => [Some(a), Some(b), Some(c)],
            None => [None, None, None],
        };
        let only = |k: &mut Option<&mut Kept>, n: usize| {
            if n != 1 {
                *k = None;
            }
        };
        only(&mut k0, lay.lit_trees);
        only(&mut k1, lay.cmd.ntypes);
        only(&mut k2, lay.dist_trees);
        // A small meta-block with one code per category: its symbols as bit sets.
        let mut sets = None;
        if !SPLIT && lay.lit_trees == 1 && mb.end - mb.start <= 2048 {
            let (mut l, mut c, mut d) = ([0u64; 4], [0u64; 11], [0u64; 2]);
            mb.literals(|pos, cmd, k| {
                let x = usize::from(k.cmd);
                c[x >> 6] |= 1 << (x & 63);
                for &b in &data[pos..pos + cmd.insert as usize] {
                    l[usize::from(b >> 6)] |= 1 << (b & 63);
                }
                if k.dsym != NO_DIST {
                    let x = usize::from(k.dsym);
                    d[x >> 6] |= 1 << (x & 63);
                }
            });
            sets = Some((l, c, d));
        }
        let ps = &mut s.prefix;
        for h in lit_hist[..256 * lay.lit_trees].chunks_exact_mut(256) {
            let u = sets.as_ref().map(|s| &s.0[..]);
            lit_codes.push(prefix_code(w, h, u, 8, ps, k0.as_deref_mut()));
        }
        for h in cmd_hist[..704 * lay.cmd.ntypes].chunks_exact_mut(704) {
            let u = sets.as_ref().map(|s| &s.1[..]);
            cmd_codes.push(prefix_code(w, h, u, 10, ps, k1.as_deref_mut()));
        }
        for h in dist_hist[..dsize * lay.dist_trees].chunks_exact_mut(dsize) {
            let u = sets.as_ref().map(|s| &s.2[..]);
            dist_codes.push(prefix_code(w, h, u, mb.dist_bits, ps, k2.as_deref_mut()));
        }
    }
    s.keep = keep;
    s.cmd_hist = cmd_hist;
    s.lit_hist = lit_hist;
    s.dist_hist = dist_hist;

    // Commands.
    mb.literals(|pos, c, k| {
        let t = if SPLIT { csw.next(w) } else { 0 };
        cmd_codes[t].put(w, usize::from(k.cmd));
        w.bits(u32::from(k.ins_n), u64::from(k.ins_x));
        w.bits(u32::from(k.copy_n), u64::from(k.copy_x));
        let (mut p, end) = (pos, pos + c.insert as usize);
        while p < end {
            let (t, n) = if SPLIT {
                lsw.take(w, end - p)
            } else {
                (0, end - p)
            };
            let map = &lit_map[t * 64..t * 64 + 64];
            if lit_ctx {
                let lut = 512 * usize::from(lay.modes[t]);
                for q in p..p + n {
                    let tree = usize::from(map[context(data, q, lut)]);
                    lit_codes[tree].put(w, usize::from(data[q]));
                }
            } else {
                let code = &lit_codes[usize::from(map[0])];
                for &b in &data[p..p + n] {
                    code.put(w, usize::from(b));
                }
            }
            p += n;
        }
        if k.dsym != NO_DIST {
            let tree = if SPLIT {
                usize::from(lay.dist_map[dsw.next(w) * 4 + dist_context(k.cmd)])
            } else {
                0
            };
            dist_codes[tree].put(w, usize::from(k.dsym));
            w.bits(u32::from(k.dist_n), u64::from(k.dist_x));
        }
    });
    for v in [&mut lit_codes, &mut cmd_codes, &mut dist_codes] {
        s.prefix.pool.extend(v.drain(..).map(|c| c.bits));
    }
    s.codes = [lit_codes, cmd_codes, dist_codes];
}

// ---- Optimal parsing -------------------------------------------------------------------------

/// The most distance symbols a meta-block uses (see [`Params::dist_size`]).
const MAX_DIST_SYMS: usize = 74;

/// Bit costs of symbols, from code lengths of a previous pass (or a first estimate).
struct CostModel {
    lit: [f32; 256],
    /// Per position of the block (when not empty): the cost of its byte as a literal.
    local: Vec<f32>,
    cmd: Vec<f32>,
    dist: [f32; MAX_DIST_SYMS],
}

fn costs_of(hist: &[u32], out: &mut [f32]) {
    let total: u64 = hist.iter().map(|&c| u64::from(c)).sum();
    let lt = (total.max(1) as f32).log2();
    for (o, &c) in out.iter_mut().zip(hist) {
        *o = if c == 0 {
            lt + 2.0
        } else {
            (lt - (c as f32).log2()).max(1.0)
        };
    }
}

/// The cost of each byte of `block` as a literal after block splitting the literals of
/// `cmds` (a parse of `block`): from the histogram of the literal block type its position falls
/// in (copied bytes take the type of the literals before them).
fn split_costs(block: &[u8], cmds: &[Command]) -> Vec<f32> {
    let mut lits = Vec::new();
    let mut pos = 0;
    for c in cmds {
        lits.extend_from_slice(&block[pos..pos + c.insert as usize]);
        pos += c.advance();
    }
    let s = split::split(&lits, 256, &split::LITERALS, 3);
    if s.ntypes == 1 {
        return Vec::new();
    }
    let mut hist = vec![[0u32; 256]; s.ntypes];
    let mut cur = Cursor::new(&s);
    for &b in &lits {
        hist[cur.next()][usize::from(b)] += 1;
    }
    let mut costs = vec![[0f32; 256]; s.ntypes];
    for (c, h) in costs.iter_mut().zip(&hist) {
        costs_of(h, c);
    }
    let mut out = Vec::with_capacity(block.len());
    let mut cur = Cursor::new(&s);
    let mut t = 0;
    let mut pos = 0;
    for c in cmds {
        for p in pos..pos + c.insert as usize {
            t = cur.next();
            out.push(costs[t][usize::from(block[p])]);
        }
        pos += c.insert as usize;
        let n = c.advance() - c.insert as usize;
        for p in pos..pos + n {
            out.push(costs[t][usize::from(block[p])]);
        }
        pos += n;
    }
    out
}

impl CostModel {
    fn initial(block: &[u8]) -> Self {
        let mut h = [0u32; 256];
        for &b in block {
            h[usize::from(b)] += 1;
        }
        let mut lit = [0f32; 256];
        costs_of(&h, &mut lit);
        CostModel {
            lit,
            local: Vec::new(),
            cmd: (0..704).map(|i| ((11 + i) as f32).log2()).collect(),
            dist: std::array::from_fn(|i| ((20 + i) as f32).log2()),
        }
    }

    fn from_commands(data: &[u8], start: usize, cmds: &[Command], ring: [u32; 4]) -> Self {
        let mut ring = ring;
        let mut ch = vec![0u32; 704];
        let mut dh = [0u32; MAX_DIST_SYMS];
        let mut lh = [0u32; 256];
        let mut pos = start;
        for c in cmds {
            let k = code_command(c, &mut ring);
            ch[usize::from(k.cmd)] += 1;
            if k.dsym != NO_DIST {
                dh[usize::from(k.dsym)] += 1;
            }
            for &b in &data[pos..pos + c.insert as usize] {
                lh[usize::from(b)] += 1;
            }
            pos += c.advance();
        }
        let mut m = CostModel {
            lit: [0.0; 256],
            local: Vec::new(),
            cmd: vec![0.0; 704],
            dist: [0.0; MAX_DIST_SYMS],
        };
        costs_of(&lh, &mut m.lit);
        costs_of(&ch, &mut m.cmd);
        costs_of(&dh, &mut m.dist);
        m
    }

    /// Cost of a copy of `len` after `ins` literals with distance symbol `dsym` (16 + 2 *
    /// bits..: explicit, with `dbits` extra bits).
    fn copy_cost(&self, ins: usize, len: usize, dsym: usize, dbits: u32) -> f32 {
        let ic = ins_code(ins);
        let cc = copy_code(len);
        let implicit = dsym == 0 && ic < 8 && cc < 16;
        let cmd = command_symbol(ic, cc, implicit);
        let mut c = self.cmd[cmd] + f32::from(INS_EXTRA[ic]) + f32::from(COPY_EXTRA[cc]);
        if !implicit {
            c += self.dist[dsym] + dbits as f32;
        }
        c
    }
}

#[derive(Clone, Copy)]
struct Node {
    cost: f32,
    prev: u32,
    /// Bytes the copy of the step into this node produces (0: a literal).
    len: u32,
    /// Its copy length when it is a static dictionary word (0: a backward copy of `len`).
    word: u32,
    dist: u32,
    /// Literals since the last copy.
    ins: u32,
    ring: [u32; 4],
}

/// The static dictionary references of each position of a meta-block.
struct Words<'a> {
    start: &'a [u32],
    list: &'a [sdict::DictMatch],
}

/// How many lengths of one match the shortest-path search tries one by one; longer ones only
/// at their full length.
const ENUM_LENGTHS: usize = 48;

impl Encoder<'_> {
    /// The custom static dictionary words at `i` (see [`compress_with_shared_dictionary`]),
    /// appended to `dlist`: the lowest address for each length produced. Apart from the parse's
    /// loop, which stays as it was without a custom dictionary.
    #[inline(never)]
    fn custom_words(
        &self,
        i: usize,
        end: usize,
        dlist: &mut Vec<sdict::DictMatch>,
        found: &mut Vec<sdict::DictMatch>,
    ) {
        let data = self.data;
        let Some(sd) = self.custom.as_ref().and_then(SharedDictionary::custom) else {
            return;
        };

        // The dictionary of the literal context here (the stream's last two bytes).
        let at = i - self.back;
        let p1 = if at >= 1 { data[i - 1] } else { 0 };
        let p2 = if at >= 2 { data[i - 2] } else { 0 };
        let lut = 512 * usize::from(self.p.fixed_mode.unwrap_or(0));
        let ctx = usize::from(
            CONTEXT_LUT[lut + usize::from(p1)] | CONTEXT_LUT[lut + 256 + usize::from(p2)],
        );
        // The lowest address for each length produced.
        let from = dlist.len();
        // (Addresses whose distance the distance alphabet cannot code are left out.)
        let max = self
            .p
            .max_distance()
            .saturating_sub(self.reach(i) + 1 + self.back);
        sd.search(ctx, |search, base| match search {
            Search::Builtin => {
                sdict::matches(&data[i..end], found);
                for m in found.iter() {
                    let addr = base(usize::from(m.len)) + m.addr;
                    if addr as usize <= max {
                        dlist.push(sdict::DictMatch { addr, ..*m });
                    }
                }
            }
            Search::Index(ix) => ix.matches(&data[i..end], |out, len, addr| {
                let addr = base(len) + addr;
                if addr as usize <= max {
                    dlist.push(sdict::DictMatch {
                        out: out as u16,
                        len: len as u8,
                        addr,
                    });
                }
            }),
        });
        dlist[from..].sort_unstable_by_key(|m| (m.out, m.addr));
        let mut k = from;
        for j in from..dlist.len() {
            if k == from || dlist[k - 1].out != dlist[j].out {
                dlist[k] = dlist[j];
                k += 1;
            }
        }
        dlist.truncate(k);
    }

    fn parse_optimal(&mut self, start: usize, end: usize, cmds: &mut Vec<Command>) {
        let data = self.data;
        let n = end - start;
        // Candidate matches of every position: increasing lengths at increasing distances.
        let mut mstart = Vec::with_capacity(n + 1);
        let mut mlist: Vec<(u32, u32)> = Vec::new();
        let mut long: Option<(usize, usize, usize)> = None; // pos, len, dist
        for i in start..end {
            self.insert_until(i);
            mstart.push(mlist.len() as u32);
            if let Some((p, l, d)) = long {
                if i < p + l - 4 {
                    // Inside a long match: its continuation is the only candidate.
                    let left = (p + l - i).min(end - i);
                    if left >= 4 {
                        mlist.push((left as u32, d as u32));
                    }
                    continue;
                }
                long = None;
            }
            let max_len = end - i;
            if max_len < 4 {
                continue;
            }
            let max_dist = self.reach(i);
            let mut cand = self.head[self.hash(i)];
            let mut depth = self.p.depth;
            let mut best = 3;
            let first = mlist.len();
            while cand != NIL && depth > 0 {
                let c = cand as usize;
                let mut max_len = max_len;
                if c >= i || i - c > max_dist {
                    // Beyond the window: the dictionary, if any.
                    let room = if c < i { self.dict_room(i, c) } else { 0 };
                    if room == 0 {
                        break;
                    }
                    max_len = max_len.min(room);
                }
                depth -= 1;
                let next = self.prev[c & self.wmask];
                cand = if next == NIL || next as usize >= c {
                    NIL
                } else {
                    next
                };
                if best >= max_len || data.get(c + best) != data.get(i + best) {
                    continue;
                }
                let len = match_len(data, c, i, max_len);
                if len > best {
                    best = len;
                    mlist.push((len as u32, (i - c) as u32));
                    if len >= self.p.nice || len == end - i {
                        break;
                    }
                }
            }
            if mlist.len() - first > 24 {
                // Keep the longest ones.
                mlist.drain(first..mlist.len() - 24);
            }
            if best >= self.p.nice {
                if let Some(&(l, d)) = mlist.last() {
                    long = Some((i, l as usize, d as usize));
                }
            }
        }
        mstart.push(mlist.len() as u32);
        // Static dictionary references of every position.
        let mut dstart = Vec::with_capacity(n + 1);
        let mut dlist: Vec<sdict::DictMatch> = Vec::new();
        let mut found = Vec::new();
        for i in start..end {
            dstart.push(dlist.len() as u32);
            if self.custom.is_some() {
                self.custom_words(i, end, &mut dlist, &mut found);
            } else if self.p.static_words {
                sdict::matches(&data[i..end], &mut found);
                dlist.extend_from_slice(&found);
            }
        }
        dstart.push(dlist.len() as u32);
        let words = Words {
            start: &dstart,
            list: &dlist,
        };

        let mut model = CostModel::initial(&data[start..end]);
        for pass in 0..self.p.optimal {
            cmds.clear();
            self.shortest_path(start, end, &mstart, &mlist, &words, &model, cmds);
            if pass + 1 < self.p.optimal {
                model = CostModel::from_commands(data, start, cmds, self.last);
                // Literals priced by their block type: the meta-block will be split.
                if self.p.split_iters > 0 {
                    model.local = split_costs(&data[start..end], cmds);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn shortest_path(
        &self,
        start: usize,
        end: usize,
        mstart: &[u32],
        mlist: &[(u32, u32)],
        words: &Words<'_>,
        model: &CostModel,
        cmds: &mut Vec<Command>,
    ) {
        let data = self.data;
        let n = end - start;
        let mut nodes = vec![
            Node {
                cost: f32::INFINITY,
                prev: 0,
                len: 0,
                word: 0,
                dist: 0,
                ins: 0,
                ring: [0; 4],
            };
            n + 1
        ];
        nodes[0].cost = 0.0;
        nodes[0].ring = self.last;
        let mut skip_to = 0;
        for i in 0..n {
            let node = nodes[i];
            if !node.cost.is_finite() || i < skip_to {
                continue;
            }
            let pos = start + i;
            let c = node.cost
                + match model.local.get(i) {
                    Some(&l) => l,
                    None => model.lit[usize::from(data[pos])],
                };
            if c < nodes[i + 1].cost {
                nodes[i + 1] = Node {
                    cost: c,
                    prev: i as u32,
                    len: 0,
                    word: 0,
                    dist: 0,
                    ins: node.ins + 1,
                    ring: node.ring,
                };
            }
            let max_len = n - i;
            if max_len < 2 {
                continue;
            }
            let max_dist = self.reach(pos);
            let ins = node.ins as usize;
            let relax = |nodes: &mut [Node], len: usize, dist: usize, cost: f32| {
                let j = i + len;
                if cost < nodes[j].cost {
                    let r = node.ring;
                    nodes[j] = Node {
                        cost,
                        prev: i as u32,
                        len: len as u32,
                        word: 0,
                        dist: dist as u32,
                        ins: 0,
                        ring: if dist as u32 == r[0] {
                            r
                        } else {
                            [dist as u32, r[0], r[1], r[2]]
                        },
                    };
                }
            };
            // The distance ring: lengths a cheaper ring entry already covers are skipped.
            let mut ring_best = 0;
            let mut longest = (0, 0, 0usize, 0u32); // len, dist, dsym, dbits
            for (k, &rd) in node.ring.iter().enumerate() {
                let dist = rd as usize;
                if dist == 0 || dist > max_dist {
                    continue;
                }
                // Long ring matches are also hash chain candidates: no need to measure past
                // `nice`.
                let len = match_len(data, pos - dist, pos, max_len.min(self.p.nice));
                let min = (if k < 2 { 2 } else { 3 }).max(ring_best + 1);
                if len < min {
                    continue;
                }
                if len > longest.0 {
                    longest = (len, dist, k, 0);
                }
                for l in min..=len.min(ENUM_LENGTHS.max(min)) {
                    let cost = node.cost + model.copy_cost(ins, l, k, 0);
                    relax(&mut nodes, l, dist, cost);
                }
                if len > ENUM_LENGTHS {
                    let cost = node.cost + model.copy_cost(ins, len, k, 0);
                    relax(&mut nodes, len, dist, cost);
                }
                ring_best = len;
            }
            // Hash chain matches.
            let (a, b) = (mstart[i] as usize, mstart[i + 1] as usize);
            let mut from = (ring_best + 1).max(4);
            for &(len, dist) in mlist.get(a..b).unwrap_or(&[]) {
                let (len, dist) = ((len as usize).min(max_len), dist as usize);
                if len < from || (dist > max_dist && self.dict_room(pos, pos - dist) < len) {
                    continue;
                }
                let (dsym, dbits) = match node.ring.iter().position(|&r| r as usize == dist) {
                    Some(k) => (k, 0),
                    None => {
                        let (s, _, nb) = explicit_distance(dist);
                        (usize::from(s), u32::from(nb))
                    }
                };
                if len > longest.0 {
                    longest = (len, dist, dsym, dbits);
                }
                for l in from..=len.min(ENUM_LENGTHS.max(from)) {
                    let cost = node.cost + model.copy_cost(ins, l, dsym, dbits);
                    relax(&mut nodes, l, dist, cost);
                }
                if len > ENUM_LENGTHS {
                    let cost = node.cost + model.copy_cost(ins, len, dsym, dbits);
                    relax(&mut nodes, len, dist, cost);
                }
                from = len + 1;
            }
            // Static dictionary words: each at the length it produces, leaving the ring alone.
            let (a, b) = (words.start[i] as usize, words.start[i + 1] as usize);
            for m in words.list.get(a..b).unwrap_or(&[]) {
                let out = usize::from(m.out);
                if out > max_len || out <= ring_best {
                    continue;
                }
                let dist = max_dist + 1 + self.back + m.addr as usize;
                let (dsym, dbits) = match node.ring.iter().position(|&r| r as usize == dist) {
                    Some(k) => (k, 0),
                    None => {
                        let (s, _, nb) = explicit_distance(dist);
                        (usize::from(s), u32::from(nb))
                    }
                };
                let cost = node.cost + model.copy_cost(ins, usize::from(m.len), dsym, dbits);
                let j = i + out;
                if cost < nodes[j].cost {
                    nodes[j] = Node {
                        cost,
                        prev: i as u32,
                        len: out as u32,
                        word: u32::from(m.len),
                        dist: dist as u32,
                        ins: 0,
                        ring: node.ring,
                    };
                }
            }
            // A long match is taken whole: the positions inside it are not expanded (as
            // Google's encoder does), which keeps long runs linear.
            if longest.0 >= self.p.nice {
                let (len, dist, dsym, dbits) = longest;
                let cost = node.cost + model.copy_cost(ins, len, dsym, dbits);
                relax(&mut nodes, len, dist, cost);
                skip_to = i + len;
            }
        }
        // Walk back.
        let mut steps = Vec::new();
        let mut j = n;
        while j > 0 {
            let nd = nodes[j];
            if nd.len > 0 {
                steps.push((nd.prev as usize, nd.len as usize, nd.word, nd.dist));
            }
            j = nd.prev as usize;
        }
        let mut lit_start = 0;
        for &(p, len, word, dist) in steps.iter().rev() {
            let (copy, out) = if word > 0 {
                (word, len as u32)
            } else {
                (len as u32, 0)
            };
            cmds.push(Command {
                insert: (p - lit_start) as u32,
                copy,
                dist,
                out,
            });
            lit_start = p + len;
        }
        if lit_start < n {
            cmds.push(Command {
                insert: (n - lit_start) as u32,
                copy: 0,
                dist: 0,
                out: 0,
            });
        }
    }
}

// ---- Commands and distances ------------------------------------------------------------------

const NO_DIST: u16 = u16::MAX;

/// A command's symbols and extra bits.
struct Coded {
    cmd: u16,
    ins_x: u32,
    ins_n: u8,
    copy_x: u32,
    copy_n: u8,
    dsym: u16,
    dist_x: u32,
    dist_n: u8,
}

/// The insert length code of `n` (Google's `GetInsertLengthCode`).
#[inline(always)]
fn ins_code(n: usize) -> usize {
    if n < 6 {
        n
    } else if n < 130 {
        let nbits = log2_floor(n - 2) as usize - 1;
        (nbits << 1) + ((n - 2) >> nbits) + 2
    } else if n < 2114 {
        log2_floor(n - 66) as usize + 10
    } else if n < 6210 {
        21
    } else if n < 22594 {
        22
    } else {
        23
    }
}

/// The copy length code of `n` (Google's `GetCopyLengthCode`; 0 below 2).
#[inline(always)]
fn copy_code(n: usize) -> usize {
    if n < 10 {
        n.saturating_sub(2)
    } else if n < 134 {
        let nbits = log2_floor(n - 6) as usize - 1;
        (nbits << 1) + ((n - 6) >> nbits) + 4
    } else if n < 2118 {
        log2_floor(n - 70) as usize + 12
    } else {
        23
    }
}

/// The block of 64 insert-and-copy symbols of insert code `ic >> 3` and copy code `cc >> 3`
/// with an explicit distance, at `(cc >> 3) + 3 * (ic >> 3)` (section 5).
const CMD_BLOCK: [u8; 9] = [2, 3, 6, 4, 5, 8, 7, 9, 10];

/// The insert-and-copy symbol of insert code `ic` and copy code `cc` (section 5).
#[inline(always)]
fn command_symbol(ic: usize, cc: usize, implicit: bool) -> usize {
    let block = if implicit {
        cc >> 3
    } else {
        usize::from(CMD_BLOCK[((cc >> 3) + 3 * (ic >> 3)).min(8)])
    };
    block * 64 + (ic & 7) * 8 + (cc & 7)
}

/// Distance symbol (16..64 with `NPOSTFIX` = `NDIRECT` = 0), extra bits and their number.
fn explicit_distance(d: usize) -> (u16, u32, u8) {
    let v = d + 3;
    let nb = log2_floor(v) as usize - 1;
    let h = (v >> nb) & 1;
    let sym = 16 + 2 * (nb - 1) + h;
    (sym as u16, (v & ((1 << nb) - 1)) as u32, nb as u8)
}

/// The short distance code of `d` (0..16) under ring `r`, if any: the first of the ring's
/// four distances, the last one plus or minus 1, 2, 3, then the second to last one's.
#[inline(always)]
fn short_code(d: u32, r: &[u32; 4]) -> Option<u16> {
    // Codes of `d - r + 3` for 0..=6 (3: `d` is that distance, coded before).
    const NEAR: [u16; 7] = [8, 6, 4, 0, 5, 7, 9];
    if d == r[0] {
        return Some(0);
    }
    if d == r[1] {
        return Some(1);
    }
    if d == r[2] {
        return Some(2);
    }
    if d == r[3] {
        return Some(3);
    }
    let o0 = i64::from(d) - i64::from(r[0]) + 3;
    if (0..7).contains(&o0) {
        return Some(NEAR[o0 as usize]);
    }
    let o1 = i64::from(d) - i64::from(r[1]) + 3;
    if (0..7).contains(&o1) {
        return Some(NEAR[o1 as usize] + 6);
    }
    None
}

#[inline(always)]
fn code_command(c: &Command, ring: &mut [u32; 4]) -> Coded {
    let ins = c.insert as usize;
    let ic = ins_code(ins);
    let ins_x = (ins - INS_BASE[ic] as usize) as u32;
    if c.copy == 0 {
        // The last command of the meta-block: its copy is never read.
        return Coded {
            cmd: command_symbol(ic, 0, ic < 8) as u16,
            ins_x,
            ins_n: INS_EXTRA[ic],
            copy_x: 0,
            copy_n: 0,
            dsym: NO_DIST,
            dist_x: 0,
            dist_n: 0,
        };
    }
    let copy = c.copy as usize;
    let cc = copy_code(copy);
    let d = c.dist;
    let r = *ring;
    let (dsym, dist_x, dist_n) = match short_code(d, &r) {
        Some(k) => (k, 0, 0),
        None => explicit_distance(d as usize),
    };
    if dsym != 0 && c.out == 0 {
        // (Static dictionary references leave the ring alone.)
        *ring = [d, r[0], r[1], r[2]];
    }
    let implicit = dsym == 0 && ic < 8 && cc < 16;
    Coded {
        cmd: command_symbol(ic, cc, implicit) as u16,
        ins_x,
        ins_n: INS_EXTRA[ic],
        copy_x: (copy - COPY_BASE[cc] as usize) as u32,
        copy_n: COPY_EXTRA[cc],
        dsym: if implicit { NO_DIST } else { dsym },
        dist_x,
        dist_n,
    }
}

// ---- Literal context modeling ----------------------------------------------------------------

#[inline(always)]
fn context(data: &[u8], p: usize, lut: usize) -> usize {
    let p1 = if p >= 1 { data[p - 1] } else { 0 };
    let p2 = if p >= 2 { data[p - 2] } else { 0 };
    usize::from(CONTEXT_LUT[lut + usize::from(p1)] | CONTEXT_LUT[lut + 256 + usize::from(p2)])
}

struct LiteralModel {
    mode: u8,
    ntrees: usize,
    map: [u8; 64],
}

impl LiteralModel {
    fn single() -> Self {
        LiteralModel {
            mode: 0,
            ntrees: 1,
            map: [0; 64],
        }
    }
}

/// How a meta-block is coded: the block types of each category, the literal context mode of
/// each literal block type, and the context maps from block type and context to prefix code.
struct Layout {
    modes: Vec<u8>,
    lit: BlockSplit,
    /// 64 entries per literal block type.
    lit_map: Vec<u8>,
    lit_trees: usize,
    cmd: BlockSplit,
    dist: BlockSplit,
    /// 4 entries per distance block type.
    dist_map: Vec<u8>,
    dist_trees: usize,
}

impl Layout {
    /// One block type per category, literals coded with `m`.
    fn single(m: &LiteralModel) -> Self {
        Layout {
            modes: vec![m.mode],
            lit: BlockSplit::single(),
            lit_map: m.map.to_vec(),
            lit_trees: m.ntrees,
            cmd: BlockSplit::single(),
            dist: BlockSplit::single(),
            dist_map: vec![0; 4],
            dist_trees: 1,
        }
    }

    /// This single layout with the literals coded with `m`.
    fn with_model(mut self, m: &LiteralModel) -> Self {
        self.modes[0] = m.mode;
        self.lit_map.copy_from_slice(&m.map);
        self.lit_trees = m.ntrees;
        self
    }
}

/// The block type of each next symbol of a category.
struct Cursor<'a> {
    s: &'a BlockSplit,
    i: usize,
    left: u32,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a BlockSplit) -> Self {
        Cursor {
            s,
            i: 0,
            left: s.lens[0],
        }
    }

    #[inline(always)]
    fn next(&mut self) -> usize {
        if self.left == 0 {
            self.i += 1;
            self.left = self.s.lens[self.i];
        }
        self.left -= 1;
        usize::from(self.s.types[self.i])
    }

    /// The block type of the next symbols and how many of them, up to `max`, it covers.
    #[inline(always)]
    fn take(&mut self, max: usize) -> (usize, usize) {
        if self.left == 0 {
            self.i += 1;
            self.left = self.s.lens[self.i];
        }
        let n = max.min(self.left as usize);
        self.left -= n as u32;
        (usize::from(self.s.types[self.i]), n)
    }
}

/// [`Cursor`] that writes the block switch commands.
struct Switcher<'a> {
    c: Cursor<'a>,
    /// The block type code of each block.
    codes: Vec<u16>,
    types: Option<Code>,
    lens: Option<Code>,
}

fn block_len_code(len: u32) -> usize {
    BLOCK_LEN.partition_point(|&(b, _)| b <= len) - 1
}

fn put_block_len(w: &mut BitWriter, code: &Code, len: u32) {
    let c = block_len_code(len);
    code.put(w, c);
    let (base, extra) = BLOCK_LEN[c];
    w.bits(u32::from(extra), u64::from(len - base));
}

impl<'a> Switcher<'a> {
    /// Writes the block types header of `s` (section 6): their number and, with two or more,
    /// the prefix codes of block types and counts and the first block's count.
    fn write(w: &mut BitWriter, s: &'a BlockSplit) -> Self {
        let mut sw = Switcher {
            c: Cursor::new(s),
            codes: Vec::new(),
            types: None,
            lens: None,
        };
        write_var_len_u8(w, s.ntypes - 1);
        if s.ntypes == 1 {
            return sw;
        }
        let (mut last, mut second) = (1usize, 0usize);
        let mut th = vec![0u32; s.ntypes + 2];
        let mut lh = [0u32; 26];
        for (i, (&t, &l)) in s.types.iter().zip(&s.lens).enumerate() {
            let t = usize::from(t);
            let code = if t == last + 1 {
                1
            } else if t == second {
                0
            } else {
                t + 2
            };
            second = last;
            last = t;
            sw.codes.push(code as u16);
            if i > 0 {
                th[code] += 1;
            }
            lh[block_len_code(l)] += 1;
        }
        let types = write_prefix_code(w, &th, s.ntypes + 2);
        let lens = write_prefix_code(w, &lh, 26);
        put_block_len(w, &lens, s.lens[0]);
        sw.types = Some(types);
        sw.lens = Some(lens);
        sw
    }

    /// The block type of the next symbol, after the block switch command it needs, if any.
    #[inline(always)]
    fn next(&mut self, w: &mut BitWriter) -> usize {
        self.switch(w);
        self.c.next()
    }

    /// Writes the block switch command if the current block is used up.
    #[inline(always)]
    fn switch(&self, w: &mut BitWriter) {
        if self.c.left == 0 {
            let i = self.c.i + 1;
            if let (Some(t), Some(l)) = (&self.types, &self.lens) {
                t.put(w, usize::from(self.codes[i]));
                put_block_len(w, l, self.c.s.lens[i]);
            }
        }
    }

    /// [`Cursor::take`], after the block switch command it needs, if any.
    #[inline(always)]
    fn take(&mut self, w: &mut BitWriter, max: usize) -> (usize, usize) {
        self.switch(w);
        self.c.take(max)
    }
}

/// The distance context of an insert-and-copy symbol: from its copy length (2, 3, 4, more).
fn dist_context(cmd: u16) -> usize {
    split_command(usize::from(cmd)).1.min(3)
}

/// The symbol sequences of the three categories of `cmds`: literals, insert-and-copy symbols,
/// distance symbols and their contexts.
struct Symbols {
    lits: Vec<u8>,
    cmds: Vec<u16>,
    dists: Vec<u16>,
    dctx: Vec<u8>,
}

fn symbols(mb: &MetaBlock<'_>) -> Symbols {
    let mut s = Symbols {
        lits: Vec::new(),
        cmds: Vec::with_capacity(mb.cmds.len()),
        dists: Vec::new(),
        dctx: Vec::new(),
    };
    mb.literals(|pos, c, k| {
        s.cmds.push(k.cmd);
        s.lits
            .extend_from_slice(&mb.data[pos..pos + c.insert as usize]);
        if k.dsym != NO_DIST {
            s.dists.push(k.dsym);
            s.dctx.push(dist_context(k.cmd) as u8);
        }
    });
    s
}

/// Block types found in one pass (levels 4..=9): the literal context map of `model` within
/// each literal block type (its codes clustered across types), one distance code per
/// distance block type; `None` where they do not pay (one block type per category).
fn greedy_layout(mb: &MetaBlock<'_>, model: &LiteralModel) -> Option<Layout> {
    if mb.end - mb.start < 64 << 10 {
        // Block types rarely pay below this (and cost a few percent of the time).
        return None;
    }
    let data = mb.data;
    // The literals first: where they do not pay for block types, the other categories rarely
    // do (and looking costs a few percent of the time).
    let mut lits = Vec::new();
    mb.literals(|pos, c, _| lits.extend_from_slice(&data[pos..pos + c.insert as usize]));
    // Each literal block type gets the trees of the context map, clustered across types: at
    // most about a thousand of them, or the clustering costs more than the parse.
    let max_lit = (1024 / model.ntrees).clamp(16, 256);
    let mut lit = split::greedy(&lits, 256, &split::GREEDY_LITERALS, max_lit);
    let l = split::split_gain(&lits, 256, &lit);
    if l.1 > 0.99 * l.0 {
        return None;
    }
    let syms = symbols(mb);
    let mut cmd = split::greedy(&syms.cmds, 704, &split::GREEDY_COMMANDS, 256);
    let mut dist = split::greedy(&syms.dists, mb.dist_size, &split::GREEDY_DISTANCES, 256);
    // Block types are kept only if they save at least 1% of the meta-block's estimated bits:
    // block switches cost time to write, and smaller savings are not worth it at these levels.
    let c = split::split_gain(&syms.cmds, 704, &cmd);
    let d = split::split_gain(&syms.dists, mb.dist_size, &dist);
    let (mut one, mut apart) = (0.0, 0.0);
    for (g, s) in [(l, &mut lit), (c, &mut cmd), (d, &mut dist)] {
        one += g.0;
        if g.1 < g.0 {
            apart += g.1;
        } else {
            apart += g.0;
            *s = BlockSplit::single();
        }
    }
    if apart > 0.99 * one {
        return None;
    }
    let (lit_map, lit_trees) = if lit.ntypes == 1 {
        (model.map.to_vec(), model.ntrees)
    } else {
        let nt = model.ntrees;
        let lut = 512 * usize::from(model.mode);
        let mut hs = vec![Histo::new(256); lit.ntypes * nt];
        let mut cur = Cursor::new(&lit);
        mb.literals(|pos, c, _| {
            for p in pos..pos + c.insert as usize {
                let t = cur.next();
                let tree = if nt > 1 {
                    usize::from(model.map[context(data, p, lut)])
                } else {
                    0
                };
                hs[t * nt + tree].add(usize::from(data[p]));
            }
        });
        let (m, n) = split::type_tree_map(&hs, lit.ntypes, nt, 256);
        let map = (0..lit.ntypes * 64)
            .map(|i| m[i / 64 * nt + usize::from(model.map[i % 64])])
            .collect();
        (map, n)
    };
    Some(Layout {
        modes: vec![model.mode; lit.ntypes],
        lit,
        lit_map,
        lit_trees,
        cmd,
        dist_map: (0..dist.ntypes * 4).map(|i| (i / 4) as u8).collect(),
        dist_trees: dist.ntypes,
        dist,
    })
}

/// Block types for the literals, insert-and-copy symbols and distances of `mb` (levels 10 and
/// 11), with context maps for literals (context mode `mode`) and distances.
fn split_layout(mb: &MetaBlock<'_>, mode: u8, iters: usize) -> Layout {
    let data = mb.data;
    let Symbols {
        lits,
        cmds: csyms,
        dists: dsyms,
        dctx,
    } = symbols(mb);
    let lit = split::split(&lits, 256, &split::LITERALS, iters);
    let cmd = split::split(&csyms, 704, &split::COMMANDS, iters);
    let dist = split::split(&dsyms, mb.dist_size, &split::DISTANCES, iters);
    let lut = 512 * usize::from(mode);
    let mut hs = vec![Histo::new(256); lit.ntypes * 64];
    let mut cur = Cursor::new(&lit);
    mb.literals(|pos, c, _| {
        for p in pos..pos + c.insert as usize {
            let t = cur.next();
            hs[t * 64 + context(data, p, lut)].add(usize::from(data[p]));
        }
    });
    let (lit_map, lit_trees) = split::context_map(&hs, 64, 4, 256);
    let mut hs = vec![Histo::new(mb.dist_size); dist.ntypes * 4];
    let mut cur = Cursor::new(&dist);
    for (&d, &x) in dsyms.iter().zip(&dctx) {
        hs[cur.next() * 4 + usize::from(x)].add(usize::from(d));
    }
    let (dist_map, dist_trees) = split::context_map(&hs, 4, 0, 256);
    Layout {
        modes: vec![mode; lit.ntypes],
        lit,
        lit_map,
        lit_trees,
        cmd,
        dist,
        dist_map,
        dist_trees,
    }
}

/// `n * log2(n)`, from a table for small `n`.
fn nlog2n(n: u32) -> f64 {
    nlog2n_in(nlog2n_table(), n)
}

/// `n log2 n` for `n` below 4096.
fn nlog2n_table() -> &'static [f64; 4096] {
    static TABLE: std::sync::OnceLock<Box<[f64; 4096]>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let t: Vec<f64> = (0..4096u32)
            .map(|n| {
                if n == 0 {
                    0.0
                } else {
                    f64::from(n) * f64::from(n).log2()
                }
            })
            .collect();
        t.into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!())
    })
}

/// [`nlog2n`] with the table at hand (fetched once per clustering, not per count).
#[inline(always)]
fn nlog2n_in(t: &[f64; 4096], n: u32) -> f64 {
    match t.get(n as usize) {
        Some(&v) => v,
        None => f64::from(n) * f64::from(n).log2(),
    }
}

/// A literal histogram and its used symbols (in the order they were first counted).
#[derive(Clone)]
struct Hist {
    h: [u32; 256],
    used: [u8; 256],
    nused: usize,
    total: u32,
}

impl Hist {
    fn new(h: &[u32; 256]) -> Self {
        let mut used = [0u8; 256];
        let mut nused = 0;
        for (s, &c) in h.iter().enumerate() {
            used[nused] = s as u8;
            nused += usize::from(c != 0);
        }
        Hist {
            h: *h,
            used,
            nused,
            total: h.iter().sum(),
        }
    }

    fn used(&self) -> &[u8] {
        &self.used[..self.nused]
    }

    fn add(&mut self, o: &Hist) {
        for &s in o.used() {
            if self.h[usize::from(s)] == 0 {
                self.used[self.nused] = s;
                self.nused += 1;
            }
            self.h[usize::from(s)] += o.h[usize::from(s)];
        }
        self.total += o.total;
    }
}

/// Estimated bits to code `total` symbols with `used` distinct ones whose counts' `n log n`
/// sum to `sum`, with their own prefix code (the code description included).
fn code_cost(t: &[f64; 4096], total: u32, sum: f64, used: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let header = if used <= 4 {
        6.0 + 8.0 * used as f64
    } else {
        40.0 + 5.0 * used as f64
    };
    nlog2n_in(t, total) - sum + header
}

fn hist_cost(t: &[f64; 4096], h: &Hist) -> f64 {
    let sum: f64 = h
        .used()
        .iter()
        .map(|&s| nlog2n_in(t, h.h[usize::from(s)]))
        .sum();
    code_cost(t, h.total, sum, h.nused)
}

/// The cost of `a` and `b` merged.
fn merged_cost(t: &[f64; 4096], a: &Hist, b: &Hist) -> f64 {
    let mut sum = 0.0;
    let mut used = a.nused;
    for &s in a.used() {
        sum += nlog2n_in(t, a.h[usize::from(s)] + b.h[usize::from(s)]);
    }
    for &s in b.used() {
        if a.h[usize::from(s)] == 0 {
            sum += nlog2n_in(t, b.h[usize::from(s)]);
            used += 1;
        }
    }
    code_cost(t, a.total + b.total, sum, used)
}

/// Chooses the context mode and clusters the 64 literal contexts of the commands' literals.
fn literal_model(
    data: &[u8],
    start: usize,
    cmds: &[Command],
    modes: &[u8],
    min_literals: usize,
) -> LiteralModel {
    let total: usize = cmds.iter().map(|c| c.insert as usize).sum();
    // Below this the context map rarely pays for its cost (and the clustering's).
    if total < min_literals {
        return LiteralModel::single();
    }
    let mut best = LiteralModel::single();
    let mut best_cost = f64::INFINITY;
    for &mode in modes {
        let lut = 512 * usize::from(mode);
        let mut hist = vec![[0u32; 256]; 64];
        let mut pos = start;
        for c in cmds {
            for p in pos..pos + c.insert as usize {
                hist[context(data, p, lut)][usize::from(data[p])] += 1;
            }
            pos += c.advance();
        }
        let (map, ntrees, cost) = cluster(&hist);
        if cost < best_cost {
            best_cost = cost;
            best = LiteralModel { mode, ntrees, map };
        }
    }
    best
}

/// Greedy agglomerative clustering of the context histograms; returns the context map, the
/// number of clusters and the estimated cost.
fn cluster(hist: &[[u32; 256]]) -> ([u8; 64], usize, f64) {
    struct C {
        h: Hist,
        cost: f64,
        members: Vec<usize>,
    }
    // Contexts with few literals start out together in one cluster: they could not pay for a
    // tree of their own, and fewer clusters make the pairwise search much cheaper.
    const FEW: u32 = 32;
    let mut rare = C {
        h: Hist::new(&[0; 256]),
        cost: 0.0,
        members: Vec::new(),
    };
    let t = nlog2n_table();
    let mut cl: Vec<C> = Vec::new();
    for (i, h) in hist.iter().enumerate() {
        let total: u32 = h.iter().sum();
        if total == 0 {
            continue;
        }
        let h = Hist::new(h);
        if total < FEW {
            rare.h.add(&h);
            rare.members.push(i);
        } else {
            cl.push(C {
                cost: hist_cost(t, &h),
                h,
                members: vec![i],
            });
        }
    }
    if !rare.members.is_empty() {
        rare.cost = hist_cost(t, &rare.h);
        cl.push(rare);
    }
    // Each extra tree also costs context map bits.
    const TREE_COST: f64 = 24.0;
    let n = cl.len();
    let mut delta = vec![f64::INFINITY; n * n];
    for a in 0..n {
        for b in a + 1..n {
            delta[a * n + b] = merged_cost(t, &cl[a].h, &cl[b].h) - cl[a].cost - cl[b].cost;
        }
    }
    let mut alive: Vec<bool> = vec![true; n];
    // Row minima: the best partner after each cluster.
    let row_min = |delta: &[f64], alive: &[bool], a: usize| -> (f64, usize) {
        let mut m = (f64::INFINITY, 0);
        for b in a + 1..n {
            if alive[b] && delta[a * n + b] < m.0 {
                m = (delta[a * n + b], b);
            }
        }
        m
    };
    let mut rows: Vec<(f64, usize)> = (0..n).map(|a| row_min(&delta, &alive, a)).collect();
    let mut count = n;
    while count > 1 {
        let mut m = (f64::INFINITY, 0, 0);
        for a in 0..n {
            if alive[a] && rows[a].0 < m.0 {
                m = (rows[a].0, a, rows[a].1);
            }
        }
        let (d, a, b) = m;
        if d > TREE_COST {
            break;
        }
        let hb = std::mem::replace(&mut cl[b].h, Hist::new(&[0; 256]));
        cl[a].h.add(&hb);
        let moved = std::mem::take(&mut cl[b].members);
        cl[a].members.extend(moved);
        cl[a].cost = hist_cost(t, &cl[a].h);
        alive[b] = false;
        count -= 1;
        for (o, _) in alive.iter().enumerate().filter(|&(o, &l)| l && o != a) {
            let (x, y) = if o < a { (o, a) } else { (a, o) };
            delta[x * n + y] = merged_cost(t, &cl[x].h, &cl[y].h) - cl[x].cost - cl[y].cost;
        }
        for o in 0..n {
            if alive[o] && (o == a || rows[o].1 == a || rows[o].1 == b || o < a) {
                rows[o] = row_min(&delta, &alive, o);
            }
        }
    }
    let mut map = [0u8; 64];
    let mut ids = 0usize;
    let mut cost = 0.0;
    // Number clusters in order of their first context, for a cheap move-to-front map.
    let mut order: Vec<usize> = (0..n).filter(|&i| alive[i]).collect();
    order.sort_by_key(|&i| cl[i].members.iter().min().copied().unwrap_or(0));
    for &i in &order {
        for &ctx in &cl[i].members {
            map[ctx] = ids as u8;
        }
        cost += cl[i].cost;
        ids += 1;
    }
    let ntrees = ids.max(1);
    if ntrees > 1 {
        cost += TREE_COST * ntrees as f64;
    }
    // Unused contexts take the tree of the context before them (cheaper runs).
    for ctx in 1..64 {
        if hist[ctx].iter().all(|&c| c == 0) {
            map[ctx] = map[ctx - 1];
        }
    }
    (map, ntrees, cost)
}

// ---- Writing headers and prefix codes --------------------------------------------------------

fn nibbles(len: usize) -> usize {
    match len - 1 {
        0..=0xffff => 4,
        0x1_0000..=0xf_ffff => 5,
        _ => 6,
    }
}

/// `MNIBBLES` and `MLEN - 1` of a meta-block of `len` (1..=2^24) bytes.
fn write_mlen(w: &mut BitWriter, len: usize) {
    let n = nibbles(len);
    w.bits(2, (n - 4) as u64);
    w.bits(4 * n as u32, (len - 1) as u64);
}

fn write_var_len_u8(w: &mut BitWriter, v: usize) {
    match v {
        0 => w.bits(1, 0),
        1 => w.bits(4, 1),
        _ => {
            let nb = log2_floor(v) as u32;
            w.bits(1, 1);
            w.bits(3, u64::from(nb));
            w.bits(nb, (v - (1 << nb)) as u64);
        }
    }
}

/// A prefix code ready for writing: per symbol its bit-reversed code and length,
/// `code << 4 | length`.
struct Code {
    bits: Vec<u32>,
}

impl Code {
    #[inline(always)]
    fn put(&self, w: &mut BitWriter, sym: usize) {
        let e = self.bits[sym];
        w.bits(e & 15, u64::from(e >> 4));
    }
}

/// Writes a prefix code for `hist` over an alphabet of `size` symbols and returns it.
fn write_prefix_code(w: &mut BitWriter, hist: &[u32], size: usize) -> Code {
    let mut h = hist[..size].to_vec();
    let mut s = PrefixScratch::default();
    let bits = alphabet_bits(size);
    prefix_code(w, &mut h, None, bits, &mut s, None)
}

/// The bits of a symbol of a simple prefix code over an alphabet of `size` symbols.
fn alphabet_bits(size: usize) -> u32 {
    usize::BITS - (size - 1).leading_zeros()
}

/// Buffers [`prefix_code`] reuses: building a code allocates nothing once they have grown.
#[derive(Default)]
struct PrefixScratch {
    /// `(count, symbol)` of the used symbols.
    used: Vec<(u32, u16)>,
    /// The used symbols in order.
    syms: Vec<u16>,
    /// Code lengths per symbol; all zero between calls.
    lens: Vec<u8>,
    tokens: [Vec<(u8, u8)>; 2],
    smooth: Vec<u32>,
    alt: Vec<u8>,
    /// Runs of counts [`optimize_for_rle_sparse`] leaves alone.
    runs: Vec<(u32, u32)>,
    /// A code's description, written apart to be kept ([`Kept`]).
    head: BitWriter,
    /// Code tables to reuse.
    pool: Vec<Vec<u32>>,
}

impl PrefixScratch {
    /// A code table of at least `size` entries (their values are stale: a code sets those of
    /// its symbols, and only those are ever written).
    fn table(&mut self, size: usize) -> Vec<u32> {
        let mut t = self.pool.pop().unwrap_or_default();
        if t.len() < size {
            t.resize(size, 0);
        }
        t
    }
}

/// The code a streaming encoder wrote last for a category (literals, insert-and-copy symbols
/// or distances), kept to be sent again: a meta-block must describe its codes, but it may
/// describe the same code as the one before, which costs no time to build. A stream of small
/// events uses mostly the same symbols in each, so the code of the last one often codes the
/// next as well as one of its own: [`prefix_code`] sends whichever of the two costs fewer bits.
#[derive(Default)]
pub(crate) struct Kept {
    /// Code length per symbol (all of the alphabet; 0: not coded).
    lens: Vec<u8>,
    /// The single symbol of a one-symbol code (its length is 0).
    single: Option<u16>,
    /// `code << 4 | length` of the coded symbols.
    code: Vec<u32>,
    /// The description, as written, and its length in bits.
    head: Vec<u8>,
    head_bits: usize,
    /// Symbols coded.
    n: usize,
    /// Meta-blocks that sent it again.
    reused: u32,
}

impl Kept {
    /// Sends this code again: writes its description and sets the codes of `syms` in `bits`.
    fn send(&mut self, w: &mut BitWriter, syms: &[u16], bits: &mut [u32]) {
        replay(w, &self.head, self.head_bits);
        for &x in syms {
            let x = usize::from(x);
            bits[x] = if self.single.is_some() {
                0
            } else {
                self.code[x]
            };
        }
        self.reused += 1;
    }

    /// Whether this is the code with lengths `lens` for exactly the symbols `syms` (in order;
    /// the Huffman lengths of a histogram, before a one-symbol code gets length 0): the code a
    /// meta-block would describe for them.
    fn is(&self, syms: &[u16], lens: &[u8]) -> bool {
        if self.head_bits == 0 {
            return false;
        }
        match (self.single, syms) {
            (Some(only), []) => only == 0,
            (Some(only), [x]) => only == *x,
            (Some(_), _) | (None, [] | [_]) => false,
            (None, _) => {
                self.n == syms.len()
                    && syms.iter().all(|&x| {
                        let x = usize::from(x);
                        self.lens.get(x) == Some(&lens[x])
                    })
            }
        }
    }

    /// The bits of `used` (`(count, symbol)`) coded with this code, if it codes all of them.
    fn cost(&self, used: &[(u32, u16)]) -> Option<usize> {
        if self.head_bits == 0 {
            return None;
        }
        if let Some(only) = self.single {
            return used
                .iter()
                .all(|&(_, s)| s == only)
                .then_some(self.head_bits);
        }
        let mut data = 0usize;
        for &(c, s) in used {
            let l = *self.lens.get(usize::from(s))?;
            if l == 0 {
                return None;
            }
            data += c as usize * usize::from(l);
        }
        Some(self.head_bits + data)
    }
}

/// Writes a prefix code for `hist` (an alphabet of `hist.len()` symbols; `simple_bits` per
/// symbol in the simple form) and returns it; `hist` is left all zero. `used`, if given, is a
/// bit set of the symbols with a non-zero count (cheaper to go through than the histogram
/// when they are few). With `keep`, the code
/// kept from the stream's last meta-block is sent again if it codes `hist` in no more bits than
/// a code of its own with exact lengths would (the cheaper alternative of a stream of small
/// meta-blocks), and otherwise the code written is kept.
///
/// The work is mostly over the used symbols: a meta-block of a flushed write of a few dozen
/// bytes has a few dozen literals and a handful of commands in alphabets of 256 and 704.
fn prefix_code(
    w: &mut BitWriter,
    hist: &mut [u32],
    used: Option<&[u64]>,
    simple_bits: u32,
    s: &mut PrefixScratch,
    mut keep: Option<&mut Kept>,
) -> Code {
    let size = hist.len();
    // The used symbols, in symbol order.
    s.used.clear();
    s.syms.clear();
    match used {
        Some(bits) => {
            for (k, &word) in bits.iter().enumerate() {
                let mut word = word;
                while word != 0 {
                    let i = k * 64 + word.trailing_zeros() as usize;
                    word &= word - 1;
                    s.used.push((hist[i], i as u16));
                    s.syms.push(i as u16);
                }
            }
        }
        None => huffman::nonzero_u32(hist, |i, c| {
            s.used.push((c, i as u16));
            s.syms.push(i as u16);
        }),
    }
    // Past the last used symbol every length is 0.
    let hi = s.syms.last().map_or(0, |&x| usize::from(x) + 1);
    if s.lens.len() < size {
        s.lens.resize(size, 0);
    }
    let mut bits = s.table(size);
    let n = s.used.len();
    let lens = &mut s.lens;
    huffman::depths(&mut s.used, 15, |x, d| lens[usize::from(x)] = d);
    let data_exact = |s: &PrefixScratch, hist: &[u32]| -> usize {
        s.syms
            .iter()
            .map(|&x| hist[usize::from(x)] as usize * usize::from(s.lens[usize::from(x)]))
            .sum()
    };
    // `s.used` is sorted by count now; the symbol order is in `s.syms`.
    if let Some(k) = keep.as_deref_mut() {
        if k.is(&s.syms, &s.lens) {
            // The kept code is this one: no need to build its description again.
            k.send(w, &s.syms, &mut bits);
            return finish_code(s, hist, hi, None, bits);
        }
    }
    let mut simple = [0usize; 4];
    let mut complex = None;
    if n <= 4 {
        for (d, &x) in simple.iter_mut().zip(&s.syms) {
            *d = usize::from(x);
        }
    } else {
        complex = Some(Complex::new_in(
            &s.lens[..hi],
            std::mem::take(&mut s.tokens[0]),
        ));
    }
    if let Some(k) = keep.as_deref_mut() {
        // The kept code against this one with exact lengths (an estimate of this one's cost
        // from above: smoothed lengths are used below only where they cost less).
        let exact = match &complex {
            Some(c) => c.bit_len() + data_exact(s, hist),
            None => {
                let k = n.max(1);
                let data = if n == 1 { 0 } else { data_exact(s, hist) };
                4 + k * simple_bits as usize + usize::from(k == 4) + data
            }
        };
        s.used.clear();
        s.used
            .extend(s.syms.iter().map(|&x| (hist[usize::from(x)], x)));
        if k.cost(&s.used).is_some_and(|c| c <= exact) {
            k.send(w, &s.syms, &mut bits);
            return finish_code(s, hist, hi, complex, bits);
        }
    }
    s.head.clear();
    let kept_single;
    if let Some(c) = complex.as_mut() {
        // The exact lengths, or those of counts smoothed for run-length coding (cheaper to
        // store, which matters for small inputs): whichever costs fewer bits in all.
        s.smooth.clear();
        s.smooth.extend_from_slice(&hist[..hi]);
        // Counts the smoothing left alone give the exact lengths again, which never cost less.
        let mut alt_used = 0;
        if optimize_for_rle_sparse(&mut s.smooth, &s.syms, &mut s.runs) {
            huffman::lengths(&s.smooth, 15, &mut s.alt);
            huffman::nonzero_u8(&s.alt, |_, _| alt_used += 1);
        }
        let mut alt = false;
        if alt_used > 4 {
            let data = |l: &[u8]| -> usize {
                hist[..hi]
                    .iter()
                    .zip(l)
                    .map(|(&h, &n)| h as usize * usize::from(n))
                    .sum()
            };
            let other = Complex::new_in(&s.alt, std::mem::take(&mut s.tokens[1]));
            if other.bit_len() + data(&s.alt) < c.bit_len() + data(&s.lens[..hi]) {
                s.lens[..hi].copy_from_slice(&s.alt);
                s.tokens[1] = std::mem::replace(c, other).tokens;
                alt = true;
            } else {
                s.tokens[1] = other.tokens;
            }
        }
        c.write(&mut s.head);
        if alt {
            // Symbols from `hi` on are never written.
            huffman::codes_into(&s.lens[..hi], &mut bits[..hi]);
        } else {
            huffman::codes_sparse(&s.syms, &s.lens, &mut bits);
        }
        kept_single = None;
    } else {
        // Simple prefix code.
        let syms = &mut simple[..n.max(1)];
        let lens = &mut s.lens;
        syms.sort_by_key(|&x| (lens[x], x));
        s.head.bits(2, 1);
        s.head.bits(2, (syms.len() - 1) as u64);
        for &x in syms.iter() {
            s.head.bits(simple_bits, x as u64);
        }
        if syms.len() == 1 {
            lens[syms[0]] = 0;
            bits[syms[0]] = 0;
        } else {
            huffman::codes_sparse(&s.syms, lens, &mut bits);
        }
        if syms.len() == 4 {
            s.head.bits(1, u64::from(lens[syms[0]] == 1));
        }
        kept_single = (syms.len() == 1).then_some(syms[0] as u16);
    }
    w.append_ref(&s.head);
    if let Some(k) = keep {
        // Kept for the next meta-block.
        k.head_bits = s.head.copy_to(&mut k.head);
        k.single = kept_single;
        k.lens.clear();
        k.lens.extend_from_slice(&s.lens[..hi]);
        k.n = k.lens.iter().filter(|&&l| l != 0).count();
        k.code.clear();
        k.code.extend_from_slice(&bits[..hi]);
    }
    finish_code(s, hist, hi, complex, bits)
}

/// Puts back what [`prefix_code`] borrowed and clears what it used.
fn finish_code(
    s: &mut PrefixScratch,
    hist: &mut [u32],
    hi: usize,
    complex: Option<Complex>,
    bits: Vec<u32>,
) -> Code {
    if let Some(c) = complex {
        s.tokens[0] = c.tokens;
    }
    for &x in &s.syms {
        hist[usize::from(x)] = 0;
    }
    s.lens[..hi].fill(0);
    Code { bits }
}

/// Writes the `n` bits of `head` (as [`BitWriter::copy_to`] left them).
fn replay(w: &mut BitWriter, head: &[u8], n: usize) {
    let mut chunks = head[..n / 8].chunks_exact(4);
    for c in &mut chunks {
        w.bits(32, u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]])));
    }
    for &b in chunks.remainder() {
        w.bits(8, u64::from(b));
    }
    if n % 8 > 0 {
        w.bits((n % 8) as u32, u64::from(head[n / 8]));
    }
}

/// Smooths `counts` so that their code lengths form longer runs (zopfli's
/// `OptimizeHuffmanForRle`, as Google's brotli encoder does): strides of similar counts are
/// replaced by their average; zero counts stay zero unless inside a collapsed stride.
#[cfg(test)]
fn optimize_for_rle(counts: &mut [u32], good: &mut Vec<bool>) {
    let mut length = counts.len();
    while length > 0 && counts[length - 1] == 0 {
        length -= 1;
    }
    if length == 0 {
        return;
    }
    let counts = &mut counts[..length];
    // Runs that already code well.
    good.clear();
    good.resize(length, false);
    let (mut symbol, mut stride) = (counts[0], 0usize);
    for i in 0..=length {
        if i == length || counts[i] != symbol {
            if (symbol == 0 && stride >= 5) || (symbol != 0 && stride >= 7) {
                good[i - stride..i].fill(true);
            }
            stride = 1;
            if i != length {
                symbol = counts[i];
            }
        } else {
            stride += 1;
        }
    }
    let (mut stride, mut sum, mut limit) = (0usize, 0u64, u64::from(counts[0]));
    for i in 0..=length {
        if i == length || good[i] || u64::from(counts[i]).abs_diff(limit) >= 4 {
            if stride >= 4 || (stride >= 3 && sum == 0) {
                let count = if sum == 0 {
                    0
                } else {
                    ((sum + stride as u64 / 2) / stride as u64).max(1)
                };
                counts[i - stride..i].fill(count as u32);
            }
            stride = 0;
            sum = 0;
            limit = if i + 3 < length {
                (counts[i..i + 4].iter().map(|&c| u64::from(c)).sum::<u64>() + 2) / 4
            } else if i < length {
                u64::from(counts[i])
            } else {
                0
            };
        }
        stride += 1;
        if i != length {
            sum += u64::from(counts[i]);
        }
    }
}

/// The number of bytes from `d[i]` on equal to it (at least 1), eight at a time: the code
/// lengths of a small meta-block's codes are mostly long runs of zeros.
#[inline]
fn run_at(d: &[u8], i: usize) -> usize {
    let v = d[i];
    let pat = u64::from(v) * 0x0101_0101_0101_0101;
    let mut j = i + 1;
    while let Some(c) = d.get(j..j + 8) {
        let x = u64::from_le_bytes(c.try_into().unwrap_or([0; 8])) ^ pat;
        if x != 0 {
            return j + (x.trailing_zeros() / 8) as usize - i;
        }
        j += 8;
    }
    while j < d.len() && d[j] == v {
        j += 1;
    }
    j - i
}

/// [`optimize_for_rle`] of `counts`, whose last entry is not zero and whose non-zero entries
/// are at `syms` (in order), in time proportional to the used symbols and the short runs of
/// zeros between them: positions in a run of five or more zeros are all ends of strides, so
/// only the first and the last of them need looking at. Returns whether a count changed.
fn optimize_for_rle_sparse(counts: &mut [u32], syms: &[u16], runs: &mut Vec<(u32, u32)>) -> bool {
    let length = counts.len();
    if length == 0 {
        return false;
    }
    debug_assert!(counts[length - 1] != 0);
    // Runs that already code well (the first pass of `optimize_for_rle`), in order: runs of
    // five zeros or more (the gaps between used symbols) and of seven equal counts or more.
    runs.clear();
    let mut prev = 0usize; // the end of the last used symbol
    let mut k = 0;
    while k < syms.len() {
        let s = usize::from(syms[k]);
        if s - prev >= 5 {
            runs.push((prev as u32, s as u32));
        }
        // Equal counts at consecutive symbols.
        let c = counts[s];
        let mut e = k + 1;
        while e < syms.len() && usize::from(syms[e]) == usize::from(syms[e - 1]) + 1 {
            if counts[usize::from(syms[e])] != c {
                break;
            }
            e += 1;
        }
        if e - k >= 7 {
            runs.push((s as u32, (s + e - k) as u32));
        }
        prev = usize::from(syms[e - 1]) + 1;
        k = e;
    }
    let mut r = 0usize;
    let (mut stride, mut sum, mut limit) = (0usize, 0u64, u64::from(counts[0]));
    let mut changed = false;
    let mut i = 0usize;
    loop {
        while r < runs.len() && runs[r].1 as usize <= i {
            r += 1;
        }
        let good = r < runs.len() && runs[r].0 as usize <= i;
        if i == length || good || u64::from(counts[i]).abs_diff(limit) >= 4 {
            if stride >= 4 || (stride >= 3 && sum == 0) {
                let count = if sum == 0 {
                    0
                } else {
                    ((sum + stride as u64 / 2) / stride as u64).max(1)
                } as u32;
                for c in &mut counts[i - stride..i] {
                    changed |= *c != count;
                    *c = count;
                }
            }
            stride = 0;
            sum = 0;
            limit = if i + 3 < length {
                (counts[i..i + 4].iter().map(|&c| u64::from(c)).sum::<u64>() + 2) / 4
            } else if i < length {
                u64::from(counts[i])
            } else {
                0
            };
        }
        if i == length {
            return changed;
        }
        stride += 1;
        sum += u64::from(counts[i]);
        // Inside a run of zeros that codes well each position ends a stride of one zero
        // (nothing to fill) and sets the limit again: on to the run's last position.
        if good && counts[i] == 0 && (runs[r].1 as usize) > i + 1 {
            i = runs[r].1 as usize - 1;
        } else {
            i += 1;
        }
    }
}

/// Run-length codes code lengths with symbols 0..=17 (Google's `BrotliWriteHuffmanTree`).
fn rle_lengths(depth: &[u8], tokens: &mut Vec<(u8, u8)>) {
    let len = depth.iter().rposition(|&d| d != 0).map_or(0, |p| p + 1);
    let depth = &depth[..len];
    let (mut rle_nonzero, mut rle_zero) = (false, false);
    if depth.len() > 50 {
        let (mut tz, mut tn, mut cz, mut cn) = (0usize, 0usize, 1usize, 1usize);
        let mut i = 0;
        while i < depth.len() {
            let v = depth[i];
            let reps = run_at(depth, i);
            if reps >= 3 && v == 0 {
                tz += reps;
                cz += 1;
            }
            if reps >= 4 && v != 0 {
                tn += reps;
                cn += 1;
            }
            i += reps;
        }
        rle_nonzero = tn > cn * 2;
        rle_zero = tz > cz * 2;
    }
    let mut previous = 8u8;
    let mut i = 0;
    while i < depth.len() {
        let v = depth[i];
        let reps = if (v != 0 && rle_nonzero) || (v == 0 && rle_zero) {
            run_at(depth, i)
        } else {
            1
        };
        if v == 0 {
            let mut r = reps;
            if r == 11 {
                tokens.push((0, 0));
                r -= 1;
            }
            if r < 3 {
                tokens.extend(std::iter::repeat_n((0, 0), r));
            } else {
                let s = tokens.len();
                r -= 3;
                loop {
                    tokens.push((17, (r & 7) as u8));
                    r >>= 3;
                    if r == 0 {
                        break;
                    }
                    r -= 1;
                }
                tokens[s..].reverse();
            }
        } else {
            let mut r = reps;
            if previous != v {
                tokens.push((v, 0));
                r -= 1;
            }
            if r == 7 {
                tokens.push((v, 0));
                r -= 1;
            }
            if r < 3 {
                tokens.extend(std::iter::repeat_n((v, 0), r));
            } else {
                let s = tokens.len();
                r -= 3;
                loop {
                    tokens.push((16, (r & 3) as u8));
                    r >>= 2;
                    if r == 0 {
                        break;
                    }
                    r -= 1;
                }
                tokens[s..].reverse();
            }
            previous = v;
        }
        i += reps;
    }
}

/// Code lengths of the code length alphabet: the static code (section 3.5), bit-reversed.
const CL_STATIC_CODE: [(u32, u64); 6] = [(2, 0), (4, 7), (3, 3), (2, 2), (2, 1), (4, 15)];

/// A complex prefix code (a complete code, at least two symbols) ready for writing: its code
/// lengths run-length coded, and the code length code that codes them.
struct Complex {
    tokens: Vec<(u8, u8)>,
    /// Code lengths of the code length symbols.
    cl: [u8; 18],
    /// Code length code lengths skipped at the start and stored (in `CODE_LENGTH_ORDER`).
    skip: usize,
    to_store: usize,
    /// Code length symbols used.
    num: usize,
}

impl Complex {
    /// The code with code lengths `lens` (trailing zeros may be left out), its tokens in
    /// `tokens` (cleared first).
    fn new_in(lens: &[u8], mut tokens: Vec<(u8, u8)>) -> Complex {
        tokens.clear();
        rle_lengths(lens, &mut tokens);
        let mut hist = [0u32; 18];
        for &(t, _) in &tokens {
            hist[usize::from(t)] += 1;
        }
        let mut used = [(0u32, 0u16); 18];
        let mut num = 0;
        huffman::nonzero_u32(&hist, |s, c| {
            used[num] = (c, s as u16);
            num += 1;
        });
        let used = &mut used[..num];
        let mut cl = [0u8; 18];
        huffman::depths(used, 5, |s, d| cl[usize::from(s)] = d);
        let mut to_store = 18;
        if num > 1 {
            while to_store > 0 && cl[CODE_LENGTH_ORDER[to_store - 1]] == 0 {
                to_store -= 1;
            }
        }
        let mut skip = 0;
        if cl[CODE_LENGTH_ORDER[0]] == 0 && cl[CODE_LENGTH_ORDER[1]] == 0 {
            skip = 2;
            if cl[CODE_LENGTH_ORDER[2]] == 0 {
                skip = 3;
            }
        }
        Complex {
            tokens,
            cl,
            skip,
            to_store,
            num,
        }
    }

    /// The code lengths the tokens are written with: a single code length symbol is decoded
    /// from zero bits.
    fn token_lens(&self) -> [u8; 18] {
        if self.num == 1 { [0; 18] } else { self.cl }
    }

    /// The bits [`Complex::write`] writes.
    fn bit_len(&self) -> usize {
        let header: usize = CODE_LENGTH_ORDER[self.skip..self.to_store]
            .iter()
            .map(|&s| CL_STATIC_CODE[usize::from(self.cl[s])].0 as usize)
            .sum();
        let tl = self.token_lens();
        let body: usize = self
            .tokens
            .iter()
            .map(|&(t, _)| {
                usize::from(tl[usize::from(t)])
                    + match t {
                        16 => 2,
                        17 => 3,
                        _ => 0,
                    }
            })
            .sum();
        2 + header + body
    }

    fn write(&self, w: &mut BitWriter) {
        w.bits(2, self.skip as u64);
        for &s in &CODE_LENGTH_ORDER[self.skip..self.to_store] {
            let (n, v) = CL_STATIC_CODE[usize::from(self.cl[s])];
            w.bits(n, v);
        }
        let cs = huffman::codes(&self.token_lens());
        for &(t, x) in &self.tokens {
            let e = cs[usize::from(t)];
            w.bits(e & 15, u64::from(e >> 4));
            match t {
                16 => w.bits(2, u64::from(x)),
                17 => w.bits(3, u64::from(x)),
                _ => {}
            }
        }
    }
}

/// Writes a context map (section 7.3), trying move-to-front and run-length settings and
/// keeping the shortest.
fn write_context_map(w: &mut BitWriter, map: &[u8], ntrees: usize) {
    let mtf: Vec<u8> = {
        let mut list: Vec<u8> = (0..=255).collect();
        map.iter()
            .map(|&v| {
                let i = list.iter().position(|&x| x == v).unwrap_or(0);
                list.remove(i);
                list.insert(0, v);
                i as u8
            })
            .collect()
    };
    let mut best: Option<BitWriter> = None;
    for use_mtf in [false, true] {
        let vals = if use_mtf { &mtf[..] } else { map };
        for rle in 0..=6usize {
            let mut t = BitWriter::with_capacity(64);
            // Symbols: 0, run of zeros (1..=rle with extra bits), value + rle.
            let mut syms: Vec<(usize, u32, u32)> = Vec::new();
            let mut i = 0;
            while i < vals.len() {
                if vals[i] != 0 {
                    syms.push((usize::from(vals[i]) + rle, 0, 0));
                    i += 1;
                    continue;
                }
                let mut run = vals[i..].iter().take_while(|&&v| v == 0).count();
                i += run;
                while run > 0 {
                    if rle == 0 || run == 1 {
                        syms.push((0, 0, 0));
                        run -= 1;
                    } else {
                        let k = (log2_floor(run) as usize).min(rle);
                        let take = run.min((2 << k) - 1);
                        syms.push((k, k as u32, (take - (1 << k)) as u32));
                        run -= take;
                    }
                }
            }
            let mut hist = vec![0u32; ntrees + rle];
            for &(s, _, _) in &syms {
                hist[s] += 1;
            }
            if rle > 0 {
                t.bits(1, 1);
                t.bits(4, (rle - 1) as u64);
            } else {
                t.bits(1, 0);
            }
            let code = write_prefix_code(&mut t, &hist, ntrees + rle);
            for &(s, n, x) in &syms {
                code.put(&mut t, s);
                t.bits(n, u64::from(x));
            }
            t.bits(1, u64::from(use_mtf));
            if best.as_ref().is_none_or(|b| t.bit_len() < b.bit_len()) {
                best = Some(t);
            }
        }
    }
    if let Some(b) = best {
        let n = b.bit_len();
        let bytes = b.finish();
        for i in 0..n {
            w.bits(1, u64::from(bytes[i / 8] >> (i % 8) & 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pieces of 4 KiB alternating between two random sources (lower-case letters and bytes
    /// above 0x80): literals of two distributions, so block types pay.
    pub(crate) fn interleaved(n: usize) -> Vec<u8> {
        const LETTERS: &[u8; 16] = b"etaoin shrdlucmf";
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        (0..n)
            .map(|i| {
                let r = next();
                if i / 4096 % 2 == 0 {
                    LETTERS[(r % 16) as usize]
                } else {
                    0x80 | (r % 48) as u8
                }
            })
            .collect()
    }

    /// The block types the level's splitter finds for `data` as one meta-block.
    fn types(level: u8, data: &[u8]) -> (usize, usize, usize) {
        let p = params(level);
        let mut e = Encoder::new(p, window_bits(data.len(), 22), data, 0);
        let mut cmds = Vec::new();
        if p.optimal > 0 {
            e.parse_optimal(0, data.len(), &mut cmds);
        } else {
            e.parse_lazy(0, data.len(), &mut cmds);
        }
        let mut ring = e.last;
        let coded: Vec<Coded> = cmds.iter().map(|c| code_command(c, &mut ring)).collect();
        let mb = MetaBlock {
            data,
            start: 0,
            end: data.len(),
            last: true,
            cmds: &cmds,
            coded: &coded,
            dist_size: p.dist_size(),
            dist_bits: p.dist_bits(),
        };
        let model = literal_model(data, 0, &cmds, p.modes, 0);
        let lay = if p.optimal > 0 {
            split_layout(&mb, model.mode, p.split_iters)
        } else {
            greedy_layout(&mb, &model).unwrap_or_else(|| Layout::single(&model))
        };
        let lens: u64 = lay.lit.lens.iter().map(|&l| u64::from(l)).sum();
        assert!(lay.lit.ntypes == 1 || lens >= mb.cmds.iter().map(|c| u64::from(c.insert)).sum());
        (lay.lit.ntypes, lay.cmd.ntypes, lay.dist.ntypes)
    }

    /// The closed-form length codes, command blocks and short distance codes give what the
    /// tables and the order of the specification give.
    #[test]
    fn command_codes_match_the_tables() {
        for n in 0..100_000usize {
            let ic = INS_BASE.partition_point(|&b| b as usize <= n) - 1;
            assert_eq!(ins_code(n), ic, "insert {n}");
            let cc = COPY_BASE.partition_point(|&b| b as usize <= n).max(1) - 1;
            assert_eq!(copy_code(n), cc, "copy {n}");
        }
        for ic in 0..24 {
            for cc in 0..24 {
                let block = match (ic >> 3, cc >> 3) {
                    (0, 0) => 2,
                    (0, 1) => 3,
                    (1, 0) => 4,
                    (1, 1) => 5,
                    (0, _) => 6,
                    (2, 0) => 7,
                    (1, _) => 8,
                    (_, 1) => 9,
                    _ => 10,
                };
                assert_eq!(
                    command_symbol(ic, cc, false),
                    block * 64 + (ic & 7) * 8 + (cc & 7)
                );
            }
        }
        // Short distance codes: the first match in the order of section 4.
        let mut x = 0x9E37_79B9u32;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let small = |v: u32| 1 + v % 12;
            let r = [small(x), small(x >> 4), small(x >> 8), small(x >> 12)];
            let d = small(x >> 16);
            let short = [
                Some(r[0]),
                Some(r[1]),
                Some(r[2]),
                Some(r[3]),
                r[0].checked_sub(1),
                r[0].checked_add(1),
                r[0].checked_sub(2),
                r[0].checked_add(2),
                r[0].checked_sub(3),
                r[0].checked_add(3),
                r[1].checked_sub(1),
                r[1].checked_add(1),
                r[1].checked_sub(2),
                r[1].checked_add(2),
                r[1].checked_sub(3),
                r[1].checked_add(3),
            ];
            let want = short.iter().position(|&s| s == Some(d)).map(|k| k as u16);
            assert_eq!(short_code(d, &r), want, "{d} {r:?}");
        }
    }

    /// The sparse smoothing and run counting give what the dense ones give.
    #[test]
    fn sparse_code_helpers_match_dense() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let mut runs = Vec::new();
        let mut good = Vec::new();
        for case in 0..20_000 {
            let size = [8, 26, 64, 74, 256, 704][case % 6];
            let density = 1 + rnd(100);
            let mut h: Vec<u32> = (0..size)
                .map(|_| {
                    if rnd(100) < density {
                        match rnd(4) {
                            0 => 1 + rnd(3) as u32,
                            1 => 5,
                            2 => 1 + rnd(40) as u32,
                            _ => 1 + rnd(2000) as u32,
                        }
                    } else {
                        0
                    }
                })
                .collect();
            if case % 7 == 0 {
                // Runs of equal counts.
                let a = rnd(size as u64 / 2) as usize;
                let n = rnd(12) as usize;
                for v in h.iter_mut().skip(a).take(n) {
                    *v = 9;
                }
            }
            let Some(hi) = h.iter().rposition(|&c| c != 0).map(|p| p + 1) else {
                continue;
            };
            let h = &h[..hi];
            let syms: Vec<u16> = (0..hi as u16).filter(|&i| h[usize::from(i)] != 0).collect();
            let mut dense = h.to_vec();
            optimize_for_rle(&mut dense, &mut good);
            let mut sparse = h.to_vec();
            let changed = optimize_for_rle_sparse(&mut sparse, &syms, &mut runs);
            assert_eq!(dense, sparse, "case {case}: {h:?}");
            assert_eq!(changed, dense != h, "case {case}");
            let lens: Vec<u8> = h.iter().map(|&c| (c % 5) as u8).collect();
            for i in 0..lens.len() {
                let naive = lens[i..].iter().take_while(|&&v| v == lens[i]).count();
                assert_eq!(run_at(&lens, i), naive);
            }
        }
    }

    #[test]
    fn block_types() {
        let data = interleaved(100_000);
        for level in [4, 5, 9, 10, 11] {
            let (lit, _, _) = types(level, &data);
            assert!(lit >= 2, "level {level}: {lit} literal block types");
            let z = compress(Level::new(u32::from(level)), &data);
            assert!(crate::decompress(&z, data.len()).unwrap() == data);
            // The stream uses them: a 7-bit window header (2^17), ISLAST, ISLASTEMPTY,
            // MNIBBLES and a 20-bit MLEN - 1, then NBLTYPESL (a first bit of 1: two or more).
            assert_eq!(z[3] >> 7, 1, "level {level}: NBLTYPESL");
        }
        // Too short to split.
        assert_eq!(types(11, &data[..2000]).0, 1);
        assert_eq!(types(5, &data[..60_000]).0, 1);
    }
}
