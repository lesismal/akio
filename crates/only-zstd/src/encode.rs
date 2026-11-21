//! The encoder: LZ77 (libzstd's `fast` and `double_fast` match finders at levels 1..=4, hash
//! chains above), Huffman-coded literals and FSE-coded sequences.

use crate::Level;
use crate::bits::BitWriter;
use crate::dict::Dictionary;
use crate::fse::{self, CTable};
use crate::huffman;
use crate::tables::{
    BLOCK_MAX, LL_BASE, LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, LL_MAX_LOG, MAGIC, ML_BASE,
    ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM, ML_MAX_LOG, OF_DEFAULT_LOG, OF_DEFAULT_NORM,
    OF_MAX_LOG, highbit, ll_code, ml_code,
};
use crate::xxhash::xxh64;

mod opt;

/// Largest window the encoder uses (the limit of RFC 9659 for HTTP): inputs up to this size
/// are one segment, larger ones have an 8 MiB window.
pub(crate) const MAX_WINDOW: usize = 8 << 20;
const MIN_MATCH: usize = 4;

/// Match-finder settings of a level.
#[derive(Clone, Copy, Debug)]
struct Params {
    /// How matches are found.
    strategy: Strategy,
    /// Candidates examined per position.
    depth: u32,
    /// 0: greedy; 1: also try one position later; 2: and two.
    lazy: u8,
    /// A match this long is taken at once.
    nice: usize,
    /// Positions skipped grow with the distance to the last match (`>> skip`; 0: never).
    skip: u32,
    hash_log: u32,
    chain_log: u32,
}

/// The match finders, after libzstd's strategies of the same names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    /// One hash table of the next `n` bytes (`hash_log` bits), probed once per position,
    /// greedy (`zstd_fast`).
    Fast(u32),
    /// Two hash tables, of the next 8 bytes (`hash_log`) and of the next 5 (`chain_log`),
    /// greedy (`zstd_double_fast`).
    DoubleFast,
    /// Hash chains, `depth` candidates, lazy matching (`lazy` / `lazy2`).
    Chain,
    /// Binary trees of suffixes (`depth` nodes per position), and a shortest-path parse priced
    /// by symbol statistics, in `n` passes (libzstd's `btopt` / `btultra`).
    Optimal(u32),
}

/// Links per position in `chain`: two in the binary trees of the optimal parser.
fn links(p: &Params) -> usize {
    if let Strategy::Optimal(_) = p.strategy {
        2
    } else {
        1
    }
}

fn params(level: Level) -> Params {
    let (depth, lazy, nice, skip, hash_log, chain_log) = match level.get() {
        1 => (1, 0, 16, 8, 15, 0),
        2 => (1, 0, 16, 9, 16, 0),
        3 => (1, 0, 16, 7, 17, 16),
        4 => (1, 0, 16, 7, 18, 17),
        5 => (8, 1, 64, 0, 18, 18),
        6 => (12, 2, 64, 0, 18, 18),
        7 => (16, 2, 96, 0, 18, 19),
        8 => (24, 2, 128, 0, 19, 19),
        9 => (32, 2, 128, 0, 19, 19),
        10 => (48, 2, 192, 0, 19, 20),
        11 => (64, 2, 256, 0, 20, 20),
        12 => (96, 2, 256, 0, 20, 20),
        13 => (96, 2, 256, 0, 20, 21),
        14 => (128, 2, 256, 0, 20, 21),
        15 => (160, 2, 256, 0, 21, 21),
        16 => (48, 2, 256, 0, 21, 22),
        17 => (64, 2, 512, 0, 21, 22),
        18 => (96, 2, 512, 0, 22, 22),
        19 => (128, 2, 512, 0, 22, 23),
        20 => (256, 2, 1024, 0, 22, 23),
        21 => (384, 2, 1024, 0, 22, 23),
        _ => (512, 2, 1024, 0, 22, 23),
    };
    let strategy = match level.get() {
        1 => Strategy::Fast(6),
        2 => Strategy::Fast(6),
        3 | 4 => Strategy::DoubleFast,
        16 => Strategy::Optimal(1),
        17 | 18 => Strategy::Optimal(2),
        19..=22 => Strategy::Optimal(3),
        _ => Strategy::Chain,
    };
    Params {
        strategy,
        depth,
        lazy,
        nice,
        skip,
        hash_log,
        chain_log,
    }
}

/// Compresses `data` into one frame with Frame_Content_Size and a content checksum. The
/// output decodes with any Zstandard decoder (inputs up to 8 MiB are a single segment; larger
/// ones use an 8 MiB window).
pub fn compress(level: Level, data: &[u8]) -> Vec<u8> {
    compress_impl(level, data, None)
}

/// [`compress`] with a dictionary: matches may refer back into its content, a trained
/// dictionary's entropy tables and repeat offsets are where the frame starts, and the frame
/// names its Dictionary_ID (none for raw content). Decode with the same dictionary
/// ([`decompress_with_dictionary`](crate::decompress_with_dictionary), `zstd -D`).
pub fn compress_with_dictionary(level: Level, data: &[u8], dict: &Dictionary) -> Vec<u8> {
    compress_impl(level, data, Some(dict))
}

/// Writes a frame header: magic number, descriptor, window descriptor (none for a single
/// segment), Dictionary_ID, Frame_Content_Size (`None`: unknown, never for a single segment).
pub(crate) fn frame_header(
    out: &mut Vec<u8>,
    content_size: Option<u64>,
    window_log: Option<u32>,
    dict_id: u32,
) {
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let single = window_log.is_none();
    let fcs_flag: u8 = match content_size {
        None => 0,
        Some(n) if single && n < 256 => 0,
        Some(n) if (256..=65791).contains(&n) => 1,
        Some(n) if u32::try_from(n).is_ok() => 2,
        Some(_) => 3,
    };
    let did_flag: u8 = match dict_id {
        0 => 0,
        1..=255 => 1,
        256..=65535 => 2,
        _ => 3,
    };
    out.push(fcs_flag << 6 | u8::from(single) << 5 | 0x04 | did_flag);
    if let Some(log) = window_log {
        out.push(((log - 10) << 3) as u8);
    }
    out.extend_from_slice(&dict_id.to_le_bytes()[..[0, 1, 2, 4][usize::from(did_flag)]]);
    if let Some(size) = content_size {
        match fcs_flag {
            0 => out.push(size as u8),
            1 => out.extend_from_slice(&((size - 256) as u16).to_le_bytes()),
            2 => out.extend_from_slice(&(size as u32).to_le_bytes()),
            _ => out.extend_from_slice(&size.to_le_bytes()),
        }
    }
}

pub(crate) fn compress_impl(level: Level, data: &[u8], dict: Option<&Dictionary>) -> Vec<u8> {
    let p = params(level);
    let n = data.len();
    let mut out = Vec::with_capacity(n / 2 + 32);
    let single = n <= MAX_WINDOW;
    // Window_Descriptor of 8 MiB when not a single segment: exponent 13, mantissa 0.
    frame_header(
        &mut out,
        Some(n as u64),
        (!single).then_some(23),
        dict.map_or(0, Dictionary::id),
    );
    let window = if single { n } else { MAX_WINDOW };
    if n == 0 {
        out.extend_from_slice(&[1, 0, 0]); // last, raw, empty
    } else if let Some(d) = dict {
        // The dictionary's content right before the data.
        let base = d.content().len();
        let mut buf = Vec::with_capacity(base + n);
        buf.extend_from_slice(d.content());
        buf.extend_from_slice(data);
        let mut e = Encoder::new(&buf, p, window);
        e.load_dictionary(d);
        let mut start = base;
        while start < buf.len() {
            let end = (start + BLOCK_MAX).min(buf.len());
            e.dict_window(end - base, window);
            e.block(start, end, end == buf.len(), &mut out);
            start = end;
        }
    } else {
        let mut e = Encoder::new(data, p, window);
        let mut start = 0;
        while start < n {
            let end = (start + BLOCK_MAX).min(n);
            e.block(start, end, end == n, &mut out);
            start = end;
        }
    }
    out.extend_from_slice(&(xxh64(data, 0) as u32).to_le_bytes());
    out
}

/// One sequence: literal length, match length, Offset_Value (1..=3: repeat offsets, else the
/// offset + 3).
#[derive(Clone, Copy, Debug)]
struct Seq {
    ll: u32,
    ml: u32,
    off: u32,
}

#[derive(Clone, Copy, Debug)]
struct Cand {
    len: usize,
    dist: usize,
    off: u32,
}

impl Cand {
    fn gain(&self) -> i64 {
        self.len as i64 * 4 - i64::from(highbit(self.off))
    }
}

#[inline(always)]
fn read32(d: &[u8], i: usize) -> u32 {
    match d.get(i..i + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

#[inline(always)]
fn read64(d: &[u8], i: usize) -> u64 {
    match d.get(i..i + 8) {
        Some(s) => u64::from_le_bytes(s.try_into().unwrap_or([0; 8])),
        None => 0,
    }
}

/// Hash of the `n` (4..=8) bytes at `i` into `log` bits.
#[inline(always)]
fn hash_n(d: &[u8], i: usize, n: u32, log: u32) -> usize {
    ((read64(d, i) << (64 - 8 * n)).wrapping_mul(0x9E37_79B1_85EB_CA87) >> (64 - log)) as usize
}

/// The Offset_Value of a match `dist` back with repeat offsets `reps`.
fn offset_value(dist: usize, ll0: bool, reps: &[u32; 3]) -> u32 {
    let d = dist as u32;
    if !ll0 {
        if d == reps[0] {
            return 1;
        }
        if d == reps[1] {
            return 2;
        }
        if d == reps[2] {
            return 3;
        }
    } else {
        if d == reps[1] {
            return 1;
        }
        if d == reps[2] {
            return 2;
        }
        if reps[0] > 1 && d == reps[0] - 1 {
            return 3;
        }
    }
    d + 3
}

/// Updates the repeat offsets as the decoder does after a sequence.
fn update_reps(reps: &mut [u32; 3], off: u32, dist: usize, ll0: bool) {
    if off > 3 {
        *reps = [off - 3, reps[0], reps[1]];
        return;
    }
    let idx = off + u32::from(ll0); // 1: reps[0], 2: reps[1], 3: reps[2] or reps[0] - 1
    match idx {
        1 => {}
        2 => *reps = [reps[1], reps[0], reps[2]],
        _ => *reps = [dist as u32, reps[0], reps[1]],
    }
}

pub(crate) struct Encoder<'a> {
    data: &'a [u8],
    p: Params,
    window: usize,
    hash_log: u32,
    head: Vec<u32>,
    chain: Vec<u32>,
    chain_mask: usize,
    /// Positions below this are in the hash chains.
    inserted: usize,
    reps: [u32; 3],
    lits: Vec<u8>,
    seqs: Vec<Seq>,
    tables: Tables,
    /// Symbol statistics of the optimal parser's last block.
    stats: Option<Box<opt::Stats>>,
}

/// The state of an [`Encoder`] between the blocks of a stream, apart from the data.
pub(crate) struct State {
    p: Params,
    window: usize,
    hash_log: u32,
    head: Vec<u32>,
    chain: Vec<u32>,
    chain_mask: usize,
    inserted: usize,
    reps: [u32; 3],
    lits: Vec<u8>,
    seqs: Vec<Seq>,
    tables: Tables,
    /// Symbol statistics of the optimal parser's last block.
    stats: Option<Box<opt::Stats>>,
}

impl State {
    /// A fresh state at `level` for a window of `window` bytes, with tables sized for inputs
    /// of `size` bytes.
    pub(crate) fn new(level: Level, window: usize, size: usize) -> State {
        let p = params(level);
        let bits = (usize::BITS - size.leading_zeros()).max(8);
        let hash_log = p.hash_log.min(bits + 1);
        let chain_log = p.chain_log.min(bits);
        State {
            p,
            window,
            hash_log,
            head: vec![0; 1 << hash_log],
            chain: vec![0; links(&p) << chain_log],
            chain_mask: (1 << chain_log) - 1,
            inserted: 0,
            reps: [1, 4, 8],
            lits: Vec::new(),
            seqs: Vec::new(),
            tables: Tables::new(None),
            stats: None,
        }
    }

    /// Positions are moved `drop` bytes down (the data before them was dropped); `drop` is a
    /// multiple of [`State::align`].
    pub(crate) fn rebase(&mut self, drop: usize) {
        let d = drop as u32;
        for v in self.head.iter_mut().chain(self.chain.iter_mut()) {
            *v = v.saturating_sub(d);
        }
        self.inserted = self.inserted.saturating_sub(drop);
    }

    /// What dropped data must be a multiple of: the hash chains are indexed by position.
    pub(crate) fn align(&self) -> usize {
        self.chain_mask + 1
    }
}

impl<'a> Encoder<'a> {
    fn new(data: &'a [u8], p: Params, window: usize) -> Self {
        let bits = (usize::BITS - data.len().leading_zeros()).max(8);
        let hash_log = p.hash_log.min(bits + 1);
        let chain_log = p.chain_log.min(bits);
        Encoder {
            data,
            p,
            window,
            hash_log,
            head: vec![0; 1 << hash_log],
            chain: vec![0; links(&p) << chain_log],
            chain_mask: (1 << chain_log) - 1,
            inserted: 0,
            reps: [1, 4, 8],
            lits: Vec::new(),
            seqs: Vec::new(),
            tables: Tables::new(None),
            stats: None,
        }
    }

    /// An encoder over `data` (the stream so far, in the coordinates of `s`) continuing `s`.
    pub(crate) fn resume(data: &'a [u8], s: State) -> Self {
        Encoder {
            data,
            p: s.p,
            window: s.window,
            hash_log: s.hash_log,
            head: s.head,
            chain: s.chain,
            chain_mask: s.chain_mask,
            inserted: s.inserted,
            reps: s.reps,
            lits: s.lits,
            seqs: s.seqs,
            tables: s.tables,
            stats: s.stats,
        }
    }

    /// The state to continue from with [`Encoder::resume`].
    pub(crate) fn suspend(self) -> State {
        State {
            p: self.p,
            window: self.window,
            hash_log: self.hash_log,
            head: self.head,
            chain: self.chain,
            chain_mask: self.chain_mask,
            inserted: self.inserted,
            reps: self.reps,
            lits: self.lits,
            seqs: self.seqs,
            tables: self.tables,
            stats: self.stats,
        }
    }

    /// Starts from `d` (whose content is `data[..d.content().len()]`): its repeat offsets and
    /// entropy tables, and its positions in the hash tables of the fast match finders (hash
    /// chains take them in as they go).
    pub(crate) fn load_dictionary(&mut self, d: &Dictionary) {
        if let Some(e) = &d.0.entropy {
            self.reps = e.reps;
        }
        self.tables = Tables::new(Some(d));
        self.fill_tables(0, d.content().len());
    }

    /// Enters the positions of `[from, to)` into the tables of the fast match finders.
    pub(crate) fn fill_tables(&mut self, from: usize, to: usize) {
        let d = self.data;
        let to = to.min(d.len().saturating_sub(8));
        match self.p.strategy {
            Strategy::Fast(mls) => {
                for i in from..to {
                    self.head[hash_n(d, i, mls, self.hash_log)] = i as u32 + 1;
                }
            }
            Strategy::DoubleFast => {
                let slog = self.chain_mask.count_ones();
                for i in from..to {
                    self.head[hash_n(d, i, 8, self.hash_log)] = i as u32 + 1;
                    self.chain[hash_n(d, i, 5, slog)] = i as u32 + 1;
                }
            }
            Strategy::Chain | Strategy::Optimal(_) => {}
        }
    }

    /// The farthest match for a block whose end is `end` bytes into a frame of `window`, with
    /// a dictionary: everything, dictionary included, while the frame is within its window (a
    /// decoder holds all of it then); the window after.
    pub(crate) fn dict_window(&mut self, end: usize, window: usize) {
        self.window = if end <= window { usize::MAX } else { window };
    }

    /// Sets the farthest match.
    pub(crate) fn set_window(&mut self, window: usize) {
        self.window = window;
    }

    #[inline]
    fn hash(&self, pos: usize) -> usize {
        let d = &self.data[pos..pos + 4];
        let v = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - self.hash_log)) as usize
    }

    fn insert_to(&mut self, pos: usize) {
        let last = self.data.len().saturating_sub(MIN_MATCH - 1);
        if let Strategy::Optimal(_) = self.p.strategy {
            while self.inserted < pos.min(last) {
                let i = self.inserted;
                let best = self.bt_insert(i, 0, None);
                // After a long match, positions are skipped (libzstd's speed-up).
                self.inserted = i + 1 + best.saturating_sub(384).min(192);
            }
            self.inserted = self.inserted.max(pos);
            return;
        }
        while self.inserted < pos.min(last) {
            let i = self.inserted;
            let h = self.hash(i);
            self.chain[i & self.chain_mask] = self.head[h];
            self.head[h] = i as u32 + 1;
            self.inserted += 1;
        }
        self.inserted = self.inserted.max(pos);
    }

    #[inline]
    fn common(&self, a: usize, b: usize, max: usize) -> usize {
        let d = self.data;
        let mut n = 0;
        while n + 8 <= max {
            let x = u64::from_le_bytes(d[a + n..a + n + 8].try_into().unwrap_or([0; 8]));
            let y = u64::from_le_bytes(d[b + n..b + n + 8].try_into().unwrap_or([0; 8]));
            if x != y {
                return n + ((x ^ y).trailing_zeros() / 8) as usize;
            }
            n += 8;
        }
        while n < max && d[a + n] == d[b + n] {
            n += 1;
        }
        n
    }

    /// The best match at `pos` ending by `end`.
    fn best(&mut self, pos: usize, end: usize, ll0: bool) -> Option<Cand> {
        let max = end - pos;
        if max < MIN_MATCH {
            return None;
        }
        let mut best: Option<Cand> = None;
        let consider = |best: &mut Option<Cand>, c: Cand| {
            if best.is_none_or(|b| c.gain() > b.gain()) {
                *best = Some(c);
            }
        };
        // Repeat offsets first: cheap to code.
        let reps = self.reps;
        for i in 0..3 {
            let dist = if ll0 {
                if i == 2 {
                    reps[0] as usize - 1
                } else {
                    reps[i + 1] as usize
                }
            } else {
                reps[i] as usize
            };
            if dist == 0 || dist > pos || dist > self.window {
                continue;
            }
            let len = self.common(pos, pos - dist, max);
            if len >= MIN_MATCH {
                consider(
                    &mut best,
                    Cand {
                        len,
                        dist,
                        off: i as u32 + 1,
                    },
                );
            }
        }
        self.insert_to(pos);
        let mut cand = self.head[self.hash(pos)] as usize;
        let mut depth = self.p.depth;
        let mut best_len = best.map_or(MIN_MATCH - 1, |b| b.len);
        while cand > 0 && depth > 0 {
            let c = cand - 1;
            let dist = pos - c;
            if dist > self.window || dist > self.chain_mask {
                break;
            }
            // Check the byte past the best length first.
            if self.data[c + best_len.min(max - 1)] == self.data[pos + best_len.min(max - 1)] {
                let len = self.common(pos, c, max);
                if len > best_len {
                    best_len = len;
                    let off = offset_value(dist, ll0, &self.reps);
                    consider(&mut best, Cand { len, dist, off });
                    if len >= self.p.nice || len == max {
                        break;
                    }
                }
            }
            let next = self.chain[c & self.chain_mask] as usize;
            if next >= cand {
                break; // stale link
            }
            cand = next;
            depth -= 1;
        }
        best
    }

    /// Finds the sequences of `[start, end)` into `self.lits` / `self.seqs`.
    fn parse(&mut self, start: usize, end: usize) {
        self.lits.clear();
        self.seqs.clear();
        let mut pos = start;
        let mut anchor = start;
        while pos + MIN_MATCH <= end {
            let Some(mut cur) = self.best(pos, end, pos == anchor) else {
                let step = if self.p.skip > 0 {
                    1 + ((pos - anchor) >> self.p.skip)
                } else {
                    1
                };
                pos += step;
                continue;
            };
            // Lazy matching: a better match one or two bytes later wins.
            if self.p.lazy > 0 {
                'lazy: while pos + 1 + MIN_MATCH <= end {
                    if let Some(next) = self.best(pos + 1, end, false) {
                        if next.gain() > cur.gain() + 4 {
                            pos += 1;
                            cur = next;
                            continue 'lazy;
                        }
                    }
                    if self.p.lazy > 1 && pos + 2 + MIN_MATCH <= end {
                        if let Some(next) = self.best(pos + 2, end, false) {
                            if next.gain() > cur.gain() + 7 {
                                pos += 2;
                                cur = next;
                                continue 'lazy;
                            }
                        }
                    }
                    break;
                }
            }
            let ll = pos - anchor;
            self.lits.extend_from_slice(&self.data[anchor..pos]);
            let off = offset_value(cur.dist, ll == 0, &self.reps);
            update_reps(&mut self.reps, off, cur.dist, ll == 0);
            self.seqs.push(Seq {
                ll: ll as u32,
                ml: cur.len as u32,
                off,
            });
            pos += cur.len;
            anchor = pos;
        }
        self.lits.extend_from_slice(&self.data[anchor..end]);
    }

    /// Appends the sequence of a match of `len` at `at`, `dist` back, after the literals
    /// from `anchor`.
    #[inline]
    fn emit(&mut self, anchor: usize, at: usize, len: usize, dist: usize) {
        let ll = at - anchor;
        self.lits.extend_from_slice(&self.data[anchor..at]);
        let off = offset_value(dist, ll == 0, &self.reps);
        update_reps(&mut self.reps, off, dist, ll == 0);
        self.seqs.push(Seq {
            ll: ll as u32,
            ml: len as u32,
            off,
        });
    }

    /// A match of the first repeat offset one byte after `pos` (where literals precede it),
    /// at least 4 long: its length.
    #[inline(always)]
    fn rep_at_next(&self, pos: usize, end: usize) -> Option<usize> {
        let r = self.reps[0] as usize;
        let at = pos + 1;
        if r == 0 || r > at || r > self.window {
            return None;
        }
        let d = self.data;
        if read32(d, at - r) != read32(d, at) {
            return None;
        }
        Some(4 + self.common(at + 4, at + 4 - r, end - at - 4))
    }

    /// Extends a match at `pos` from `cand` backwards over the literals since `anchor`.
    #[inline(always)]
    fn catch_up(&self, anchor: usize, mut pos: usize, mut cand: usize, len: &mut usize) -> usize {
        let d = self.data;
        while pos > anchor && cand > 0 && d[pos - 1] == d[cand - 1] {
            pos -= 1;
            cand -= 1;
            *len += 1;
        }
        pos
    }

    /// After a match ending at `pos`: matches of the second repeat offset right there (no
    /// literals before them), as many as follow each other. Returns the new position.
    #[inline]
    fn rep2_run(&mut self, mut pos: usize, ilimit: usize, end: usize) -> usize {
        let d = self.data;
        while pos < ilimit {
            let r = self.reps[1] as usize;
            if r == 0 || r > pos || r > self.window || read32(d, pos - r) != read32(d, pos) {
                break;
            }
            let len = 4 + self.common(pos + 4, pos + 4 - r, end - pos - 4);
            self.emit(pos, pos, len, r);
            pos += len;
        }
        pos
    }

    /// `zstd_fast`: one hash table of the next `mls` bytes, greedy, skipping ahead faster the
    /// longer no match is found.
    #[inline(never)]
    fn parse_fast(&mut self, start: usize, end: usize, mls: u32) {
        self.lits.clear();
        self.seqs.clear();
        let d = self.data;
        let hlog = self.hash_log;
        // Positions before this can read 8 bytes and match at least 4 within the block.
        let ilimit = end.saturating_sub(8);
        let mut pos = start;
        let mut anchor = start;
        while pos + 1 < ilimit {
            let h = hash_n(d, pos, mls, hlog);
            let cand = self.head[h] as usize;
            self.head[h] = pos as u32 + 1;
            let (at, len, dist) = if let Some(len) = self.rep_at_next(pos, end) {
                (pos + 1, len, self.reps[0] as usize)
            } else if cand > 0
                && pos - (cand - 1) <= self.window
                && read32(d, cand - 1) == read32(d, pos)
            {
                let c = cand - 1;
                let mut len = 4 + self.common(pos + 4, c + 4, end - pos - 4);
                let at = self.catch_up(anchor, pos, c, &mut len);
                (at, len, pos - c)
            } else {
                pos += 1 + ((pos - anchor) >> self.p.skip);
                continue;
            };
            self.emit(anchor, at, len, dist);
            pos = at + len;
            if pos < ilimit {
                self.head[hash_n(d, at + 2, mls, hlog)] = at as u32 + 3;
                self.head[hash_n(d, pos - 2, mls, hlog)] = pos as u32 - 1;
            }
            pos = self.rep2_run(pos, ilimit, end);
            anchor = pos;
        }
        self.lits.extend_from_slice(&d[anchor..end]);
    }

    /// `zstd_double_fast`: a table of the next 8 bytes (`head`) and one of the next 5
    /// (`chain`); a long match wins, a short one is checked against a long one a byte later.
    #[inline(never)]
    fn parse_double_fast(&mut self, start: usize, end: usize) {
        self.lits.clear();
        self.seqs.clear();
        let d = self.data;
        let (llog, slog) = (self.hash_log, self.chain_mask.count_ones());
        let ilimit = end.saturating_sub(8);
        let mut pos = start;
        let mut anchor = start;
        let ok = |pos: usize, cand: usize, window: usize| cand > 0 && pos - (cand - 1) <= window;
        while pos + 1 < ilimit {
            let hl = hash_n(d, pos, 8, llog);
            let hs = hash_n(d, pos, 5, slog);
            let cl = self.head[hl] as usize;
            let cs = self.chain[hs] as usize;
            self.head[hl] = pos as u32 + 1;
            self.chain[hs] = pos as u32 + 1;
            let (at, len, dist) = if let Some(len) = self.rep_at_next(pos, end) {
                (pos + 1, len, self.reps[0] as usize)
            } else if ok(pos, cl, self.window) && read64(d, cl - 1) == read64(d, pos) {
                let c = cl - 1;
                let mut len = 8 + self.common(pos + 8, c + 8, end - pos - 8);
                let at = self.catch_up(anchor, pos, c, &mut len);
                (at, len, pos - c)
            } else if ok(pos, cs, self.window) && read32(d, cs - 1) == read32(d, pos) {
                let p1 = pos + 1;
                let hl1 = hash_n(d, p1, 8, llog);
                let cl1 = self.head[hl1] as usize;
                self.head[hl1] = p1 as u32 + 1;
                if ok(p1, cl1, self.window) && read64(d, cl1 - 1) == read64(d, p1) {
                    let c = cl1 - 1;
                    let mut len = 8 + self.common(p1 + 8, c + 8, end - p1 - 8);
                    let at = self.catch_up(anchor, p1, c, &mut len);
                    (at, len, p1 - c)
                } else {
                    let c = cs - 1;
                    let mut len = 4 + self.common(pos + 4, c + 4, end - pos - 4);
                    let at = self.catch_up(anchor, pos, c, &mut len);
                    (at, len, pos - c)
                }
            } else {
                pos += 1 + ((pos - anchor) >> self.p.skip);
                continue;
            };
            self.emit(anchor, at, len, dist);
            pos = at + len;
            if pos < ilimit {
                for q in [at + 2, pos - 2] {
                    self.head[hash_n(d, q, 8, llog)] = q as u32 + 1;
                    self.chain[hash_n(d, q, 5, slog)] = q as u32 + 1;
                }
                self.chain[hash_n(d, pos - 1, 5, slog)] = pos as u32;
            }
            pos = self.rep2_run(pos, ilimit, end);
            anchor = pos;
        }
        self.lits.extend_from_slice(&d[anchor..end]);
    }

    /// Writes the block `[start, end)`.
    pub(crate) fn block(&mut self, start: usize, end: usize, last: bool, out: &mut Vec<u8>) {
        let src = &self.data[start..end];
        let len = src.len();
        let header = |kind: u32, size: usize| {
            let v = (size as u32) << 3 | kind << 1 | u32::from(last);
            [v as u8, (v >> 8) as u8, (v >> 16) as u8]
        };
        if len > 1 && src.iter().all(|&b| b == src[0]) {
            out.extend_from_slice(&header(1, len));
            out.push(src[0]);
            return;
        }
        let saved = self.reps;
        let saved_tables = self.tables.clone();
        match self.p.strategy {
            Strategy::Fast(n) => self.parse_fast(start, end, n),
            Strategy::DoubleFast => self.parse_double_fast(start, end),
            Strategy::Chain => self.parse(start, end),
            Strategy::Optimal(passes) => self.parse_optimal(start, end, passes),
        }
        let mut body = Vec::with_capacity(len);
        encode_literals(&self.lits, &mut body, &mut self.tables);
        encode_sequences(&self.seqs, &mut body, &mut self.tables);
        if body.len() < len {
            out.extend_from_slice(&header(2, body.len()));
            out.extend_from_slice(&body);
        } else {
            self.reps = saved;
            self.tables = saved_tables;
            out.extend_from_slice(&header(0, len));
            out.extend_from_slice(src);
        }
    }
}

fn raw_literals_header(kind: u8, n: usize, out: &mut Vec<u8>) {
    if n < 32 {
        out.push(kind | (n as u8) << 3);
    } else if n < 4096 {
        let v = u32::from(kind) | 1 << 2 | (n as u32) << 4;
        out.extend_from_slice(&v.to_le_bytes()[..2]);
    } else {
        let v = u32::from(kind) | 3 << 2 | (n as u32) << 4;
        out.extend_from_slice(&v.to_le_bytes()[..3]);
    }
}

#[inline(never)]
fn encode_literals(lits: &[u8], out: &mut Vec<u8>, t: &mut Tables) {
    let n = lits.len();
    if n > 1 && lits.iter().all(|&b| b == lits[0]) {
        raw_literals_header(1, n, out);
        out.push(lits[0]);
        return;
    }
    // As libzstd (`ZSTD_compressLiterals`, `ZSTD_minGain`): Huffman only from 64 literals, and
    // only when it saves more than 2 bytes plus 1/64 of them. Raw literals decode several times
    // faster than Huffman-coded ones, so a few bytes saved are not worth it (certificate chains
    // in TLS certificate compression decoded at half libzstd's speed before).
    if n >= 64 {
        let limit = n - ((n >> 6) + 2);
        let mut counts = [0u32; 256];
        for &b in lits {
            counts[usize::from(b)] += 1;
        }
        let fresh = huffman::Encoder::new(&counts);
        let fresh_cost = fresh
            .as_ref()
            .map(|e| e.description.len() + e.cost_bits(&counts) / 8);
        // The previous block's (or the dictionary's) table again, without a description
        // (Treeless_Literals_Block), when it codes every literal and comes out smaller.
        let repeat_cost = t
            .huf
            .as_ref()
            .filter(|e| e.covers(&counts))
            .map(|e| e.cost_bits(&counts) / 8);
        let repeat = match (repeat_cost, fresh_cost) {
            (Some(r), Some(f)) => r < f,
            (Some(_), None) => true,
            _ => false,
        };
        let (enc, estimate, kind) = if repeat {
            (t.huf.as_ref(), repeat_cost.unwrap_or(usize::MAX), 3u64)
        } else {
            (fresh.as_ref(), fresh_cost.unwrap_or(usize::MAX), 2u64)
        };
        if let Some(enc) = enc.filter(|_| estimate < limit) {
            let four = n >= 256;
            let mut body = if kind == 2 {
                enc.description.clone()
            } else {
                Vec::new()
            };
            if enc.encode(lits, four, &mut body).is_some() {
                let c = body.len();
                let (sf, lh) = if !four {
                    (0u64, 3)
                } else if n <= 1023 && c <= 1023 {
                    (1, 3)
                } else if n <= 16383 && c <= 16383 {
                    (2, 4)
                } else {
                    (3, 5)
                };
                if c < limit && (four || c <= 1023) {
                    let shift = match lh {
                        3 => 14,
                        4 => 18,
                        _ => 22,
                    };
                    let v = kind | sf << 2 | (n as u64) << 4 | (c as u64) << shift;
                    out.extend_from_slice(&v.to_le_bytes()[..lh]);
                    out.extend_from_slice(&body);
                    if kind == 2 {
                        t.huf = fresh;
                    }
                    return;
                }
            }
        }
    }
    raw_literals_header(0, n, out);
    out.extend_from_slice(lits);
}

/// A sequence field's table as the decoder holds it after a block, for the repeat mode.
#[derive(Clone, Debug)]
enum Prev {
    None,
    Predef,
    Rle(u8),
    Fse(Vec<i16>, u32),
}

/// The tables a decoder holds after the blocks so far (or from a dictionary): the Huffman
/// code of the literals and the literal length, offset and match length tables.
#[derive(Clone)]
pub(crate) struct Tables {
    huf: Option<huffman::Encoder>,
    seq: [Prev; 3],
}

impl Tables {
    pub(crate) fn new(dict: Option<&Dictionary>) -> Tables {
        match dict.and_then(|d| d.0.entropy.as_ref()) {
            None => Tables {
                huf: None,
                seq: [Prev::None, Prev::None, Prev::None],
            },
            Some(e) => Tables {
                huf: Some(huffman::Encoder::from_weights(&e.huf_weights)),
                seq: e.norms.clone().map(|(n, l)| Prev::Fse(n, l)),
            },
        }
    }
}

/// How one sequence field is coded.
enum FieldCode {
    Rle,
    Table(CTable),
}

impl FieldCode {
    fn init(&self, sym: u8) -> u32 {
        match self {
            FieldCode::Rle => 0,
            FieldCode::Table(t) => t.init(sym),
        }
    }

    #[inline(always)]
    fn encode_add(&self, w: &mut BitWriter<'_>, state: &mut u32, sym: u8) {
        if let FieldCode::Table(t) = self {
            t.encode_add(w, state, sym);
        }
    }

    fn flush(&self, w: &mut BitWriter<'_>, state: u32) {
        if let FieldCode::Table(t) = self {
            t.flush(w, state);
        }
    }
}

/// Chooses the cheapest of RLE, predefined, FSE-compressed and repeated tables for `codes`:
/// returns the mode, the coder and the table description, and updates `prev`.
fn choose_table(
    codes: &[u8],
    default_norm: &[i16],
    default_log: u32,
    max_log: u32,
    prev: &mut Prev,
) -> (u8, FieldCode, Vec<u8>) {
    let mut counts = [0u32; 64];
    for &c in codes {
        counts[usize::from(c)] += 1;
    }
    let last = counts.iter().rposition(|&c| c > 0).unwrap_or(0);
    let counts = &counts[..=last];
    let distinct = counts.iter().filter(|&&c| c > 0).count();
    if distinct == 1 {
        if matches!(prev, Prev::Rle(s) if usize::from(*s) == last) {
            return (3, FieldCode::Rle, Vec::new());
        }
        *prev = Prev::Rle(last as u8);
        return (1, FieldCode::Rle, vec![last as u8]);
    }
    let mut best_mode = 0u8;
    let mut best_cost = if last < default_norm.len() {
        fse::cost_bits(counts, default_norm, default_log)
    } else {
        f64::INFINITY
    };
    let mut best_table: Option<(Vec<i16>, u32, Vec<u8>)> = None;
    if let Prev::Fse(norm, log) = prev {
        let cost = fse::cost_bits(counts, norm, *log);
        if cost < best_cost {
            best_cost = cost;
            best_mode = 3;
        }
    }
    let min_log = (highbit(distinct as u32) + 1).max(5);
    let useful = (highbit(codes.len() as u32) + 2).max(min_log);
    for log in min_log..=max_log.min(useful) {
        let norm = fse::normalize(counts, log);
        let mut desc = Vec::new();
        fse::write_ncount(&norm, log, &mut desc);
        let cost = fse::cost_bits(counts, &norm, log) + desc.len() as f64 * 8.0;
        if cost < best_cost {
            best_cost = cost;
            best_mode = 2;
            best_table = Some((norm, log, desc));
        }
    }
    match (best_mode, best_table, &*prev) {
        (2, Some((norm, log, desc)), _) => {
            let c = CTable::new(&norm, log);
            *prev = Prev::Fse(norm, log);
            (2, FieldCode::Table(c), desc)
        }
        (3, _, Prev::Fse(norm, log)) => (3, FieldCode::Table(CTable::new(norm, *log)), Vec::new()),
        _ => {
            *prev = Prev::Predef;
            (
                0,
                FieldCode::Table(CTable::new(default_norm, default_log)),
                Vec::new(),
            )
        }
    }
}

#[inline(never)]
fn encode_sequences(seqs: &[Seq], out: &mut Vec<u8>, t: &mut Tables) {
    let n = seqs.len();
    if n < 128 {
        out.push(n as u8);
    } else if n < 0x7F00 {
        out.extend_from_slice(&[(n >> 8) as u8 + 0x80, n as u8]);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&((n - 0x7F00) as u16).to_le_bytes());
    }
    if n == 0 {
        return;
    }
    let ll: Vec<u8> = seqs.iter().map(|s| ll_code(s.ll)).collect();
    let ml: Vec<u8> = seqs.iter().map(|s| ml_code(s.ml)).collect();
    let of: Vec<u8> = seqs.iter().map(|s| highbit(s.off) as u8).collect();
    let [p_ll, p_of, p_ml] = &mut t.seq;
    let (ll_mode, ll_c, ll_d) =
        choose_table(&ll, &LL_DEFAULT_NORM, LL_DEFAULT_LOG, LL_MAX_LOG, p_ll);
    let (of_mode, of_c, of_d) =
        choose_table(&of, &OF_DEFAULT_NORM, OF_DEFAULT_LOG, OF_MAX_LOG, p_of);
    let (ml_mode, ml_c, ml_d) =
        choose_table(&ml, &ML_DEFAULT_NORM, ML_DEFAULT_LOG, ML_MAX_LOG, p_ml);
    out.push(ll_mode << 6 | of_mode << 4 | ml_mode << 2);
    out.extend_from_slice(&ll_d);
    out.extend_from_slice(&of_d);
    out.extend_from_slice(&ml_d);
    let mut w = BitWriter::new(out);
    // Per sequence at most 26 bits of states and 16 + 16 + 31 extra bits: two flushes.
    let extra = |w: &mut BitWriter<'_>, i: usize| {
        let s = seqs[i];
        let llc = usize::from(ll[i]);
        w.add(u64::from(s.ll - LL_BASE[llc]), u32::from(LL_BITS[llc]));
        w.flush_bytes();
        let mlc = usize::from(ml[i]);
        w.add(u64::from(s.ml - ML_BASE[mlc]), u32::from(ML_BITS[mlc]));
        w.add(u64::from(s.off - (1 << of[i])), u32::from(of[i]));
        w.flush_bytes();
    };
    let last = n - 1;
    let mut s_ml = ml_c.init(ml[last]);
    let mut s_of = of_c.init(of[last]);
    let mut s_ll = ll_c.init(ll[last]);
    extra(&mut w, last);
    for i in (0..last).rev() {
        of_c.encode_add(&mut w, &mut s_of, of[i]);
        ml_c.encode_add(&mut w, &mut s_ml, ml[i]);
        ll_c.encode_add(&mut w, &mut s_ll, ll[i]);
        extra(&mut w, i);
    }
    ml_c.flush(&mut w, s_ml);
    of_c.flush(&mut w, s_of);
    ll_c.flush(&mut w, s_ll);
    w.close();
}
