//! Brotli compression.
//!
//! The input is cut into meta-blocks (1 MiB, or 256 KiB at the levels with optimal parsing),
//! each parsed into insert-and-copy commands by LZ77 (candidates from per-hash buckets of the
//! last positions at levels 0..=6, from hash chains above): greedy matching at levels 0..=3,
//! lazy matching (up to four steps, as in Google's encoder) at levels 4..=9, and at levels 10
//! and 11 a shortest-path parse over all candidate matches priced with the code lengths of a
//! previous pass (one pass at level 10, two at 11). Candidates also include the four distances
//! of the distance ring, which cost a short code instead of extra bits. Each meta-block has one
//! block type per category; from level 5 the literals are coded with a context map: the 64
//! contexts of each context mode are clustered greedily by the cost of their histograms and the
//! cheapest mode is kept. Prefix codes are limited to 15 bits (5
//! for the code length code), written in the simple form when they have at most four symbols,
//! and their code length sequences are run-length coded like Google's encoder does. A
//! meta-block that would come out larger than its bytes is stored uncompressed instead.

use crate::Level;
use crate::bits::BitWriter;
use crate::huffman::{codes, lengths};
use crate::tables::{CODE_LENGTH_ORDER, CONTEXT_LUT, COPY_BASE, COPY_EXTRA, INS_BASE, INS_EXTRA};

/// Compresses `data` into one complete brotli stream at `level`.
///
/// The output decodes with any brotli decoder (Google's `brotli`, `brotli-decompressor`) and
/// with [`decompress`](crate::decompress).
pub fn compress(level: Level, data: &[u8]) -> Vec<u8> {
    let p = params(level.get());
    let wbits = window_bits(data.len());
    let mut w = BitWriter::with_capacity(data.len() / 2 + 16);
    match wbits {
        16 => w.bits(1, 0),
        17 => w.bits(7, 1),
        18..=24 => w.bits(4, u64::from((wbits - 17) << 1 | 1)),
        _ => w.bits(7, u64::from((wbits - 8) << 4 | 1)),
    }
    if data.is_empty() {
        w.bits(2, 0b11); // ISLAST, ISLASTEMPTY
        return w.finish();
    }
    let mut e = Encoder::new(p, wbits, data);
    let mut pos = 0;
    while pos < data.len() {
        let end = (pos + p.block).min(data.len());
        e.meta_block(&mut w, pos, end, end == data.len());
        pos = end;
    }
    w.finish()
}

/// The smallest window holding all of `n` bytes, between 2^16 (a one-bit header) and 2^22.
fn window_bits(n: usize) -> u32 {
    let mut w = 16;
    while w < 22 && (1usize << w) - 16 < n {
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
            ..p(128, 256, false, 17, ALL, true)
        },
        _ => Params {
            optimal: 2,
            block: 1 << 18,
            ..p(512, 512, false, 17, ALL, true)
        },
    }
}

/// An insert-and-copy command: `insert` literals, then `copy` bytes from `dist` back (`copy`
/// 0: the last command of a meta-block, literals only).
#[derive(Clone, Copy, Debug)]
struct Command {
    insert: u32,
    copy: u32,
    dist: u32,
}

const NIL: u32 = u32::MAX;
const MIN_SCORE: i64 = 1920 + 100;
const LAZY_MARGIN: i64 = 175;

struct Encoder<'a> {
    data: &'a [u8],
    p: Params,
    /// Largest backward distance (window - 16).
    max_dist: usize,
    head: Vec<u32>,
    prev: Vec<u32>,
    wmask: usize,
    /// Instead of chains (levels with up to 32 candidates and no optimal parsing): per hash,
    /// a bucket of the last `1 << block_bits` positions (`buckets`) and how many were entered
    /// (`num`); the same candidates in the same order, in one or two cache lines.
    block_bits: u32,
    /// Hash the next five bytes instead of four (levels with 16 or more candidates: fewer of
    /// them that cannot match, as in Google's `H6`).
    hash5: bool,
    num: Vec<u32>,
    buckets: Vec<u32>,
    /// Next position to enter into the hash chains.
    ins: usize,
    /// The distance ring, most recent first.
    last: [u32; 4],
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
    fn new(p: Params, wbits: u32, data: &'a [u8]) -> Self {
        let wsize = (1usize << wbits).min(data.len().next_power_of_two().max(1024));
        let len_bits = usize::BITS - data.len().max(1).leading_zeros();
        let bucketed = p.optimal == 0 && p.depth <= 32;
        let (hash_bits, block_bits) = if bucketed {
            let block_bits = p.depth.trailing_zeros();
            // At most 2^15 buckets, and about twice as many entries as the input has bytes.
            let bits = p
                .hash_bits
                .min(15)
                .min((len_bits + 1).saturating_sub(block_bits));
            (bits.max(8), block_bits)
        } else {
            (p.hash_bits.min(len_bits + 1).max(10), 0)
        };
        Encoder {
            data,
            p: Params { hash_bits, ..p },
            max_dist: (1usize << wbits) - 16,
            head: if bucketed {
                Vec::new()
            } else {
                vec![NIL; 1 << hash_bits]
            },
            prev: if bucketed {
                Vec::new()
            } else {
                vec![NIL; wsize]
            },
            wmask: wsize - 1,
            block_bits,
            hash5: bucketed && p.depth >= 16,
            num: if bucketed {
                vec![0; 1 << hash_bits]
            } else {
                Vec::new()
            },
            buckets: if bucketed {
                vec![0; 1 << (hash_bits + block_bits)]
            } else {
                Vec::new()
            },
            ins: 0,
            last: [4, 11, 15, 16],
        }
    }

    #[inline(always)]
    fn hash(&self, i: usize) -> usize {
        if self.hash5 {
            let v = load8(self.data, i) << 24;
            return (v.wrapping_mul(0x1E35_A7BD_1E35_A7BD) >> (64 - self.p.hash_bits)) as usize;
        }
        (load4(self.data, i).wrapping_mul(0x1E35_A7BD) >> (32 - self.p.hash_bits)) as usize
    }

    /// Enters positions up to `upto` (exclusive) into the hash chains.
    fn insert_until(&mut self, upto: usize) {
        let lim = upto.min(self.data.len().saturating_sub(3));
        if !self.num.is_empty() {
            let mask = (1u32 << self.block_bits) - 1;
            while self.ins < lim {
                let i = self.ins;
                let h = self.hash(i);
                let k = self.num[h];
                self.num[h] = k.wrapping_add(1);
                if let Some(b) = self
                    .buckets
                    .get_mut((h << self.block_bits) | (k & mask) as usize)
                {
                    *b = i as u32;
                }
                self.ins += 1;
            }
        }
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
        let max_dist = i.min(self.max_dist);
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
        if !self.num.is_empty() {
            // The bucket, most recent first.
            let h = self.hash(i);
            let k = self.num[h];
            let size = 1u32 << self.block_bits;
            let bucket = self
                .buckets
                .get(h << self.block_bits..(h + 1) << self.block_bits)
                .unwrap_or(&[]);
            for j in 1..=k.min(size) {
                let c = bucket
                    .get((k.wrapping_sub(j) & (size - 1)) as usize)
                    .copied()
                    .unwrap_or(0) as usize;
                // Entries are positions before `i`: `c >= i` wraps around and stops too.
                if i.wrapping_sub(c).wrapping_sub(1) >= max_dist {
                    break;
                }
                if best_len >= max_len {
                    break;
                }
                // `c + best_len < i + best_len < end`.
                if d[c + best_len] != d[i + best_len] {
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
            return best;
        }
        let mut cand = self.head[self.hash(i)];
        let mut n = self.p.depth;
        while cand != NIL && n > 0 {
            let c = cand as usize;
            if c >= i || i - c > max_dist {
                break;
            }
            n -= 1;
            cand = self.prev[c & self.wmask];
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
            });
        }
    }

    fn meta_block(&mut self, w: &mut BitWriter, start: usize, end: usize, last: bool) {
        let mut cmds = Vec::new();
        if self.p.optimal > 0 {
            self.parse_optimal(start, end, &mut cmds);
        } else {
            self.parse_lazy(start, end, &mut cmds);
        }
        let mark = w.mark();
        let before = w.bit_len();
        let ring = self.last;
        let mut model = LiteralModel::single();
        if !self.p.modes.is_empty() {
            // Clustering costs about as much as compressing a few kilobytes: below the optimal
            // parsing levels it is worth it only for more literals.
            let min_literals = if self.p.optimal > 0 { 2048 } else { 4096 };
            let m = literal_model(self.data, start, &cmds, self.p.modes, min_literals);
            if m.ntrees > 1 && self.p.optimal == 0 {
                // The clustering's estimate says the context map pays for itself.
                model = m;
            } else if m.ntrees > 1 {
                // Keep the context map only if it pays for itself.
                let mut a = BitWriter::with_capacity(0);
                self.write_compressed(&mut a, start, end, last, &cmds, &m);
                self.last = ring;
                let mut b = BitWriter::with_capacity(0);
                self.write_compressed(&mut b, start, end, last, &cmds, &model);
                self.last = ring;
                if a.bit_len() < b.bit_len() {
                    model = m;
                }
            }
        }
        self.write_compressed(w, start, end, last, &cmds, &model);
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

    fn write_compressed(
        &mut self,
        w: &mut BitWriter,
        start: usize,
        end: usize,
        last: bool,
        cmds: &[Command],
        model: &LiteralModel,
    ) {
        let data = self.data;
        // Resolve the commands into symbols and extra bits.
        let mut coded = Vec::with_capacity(cmds.len());
        let mut ring = self.last;
        let mut cmd_hist = vec![0u32; 704];
        let mut dist_hist = [0u32; 64];
        for c in cmds {
            let k = code_command(c, &mut ring);
            cmd_hist[usize::from(k.cmd)] += 1;
            if k.dsym != NO_DIST {
                dist_hist[usize::from(k.dsym)] += 1;
            }
            coded.push(k);
        }
        self.last = ring;

        // Literal contexts.
        let mut lit_hist = vec![[0u32; 256]; model.ntrees];
        let lut = 512 * usize::from(model.mode);
        {
            let mut pos = start;
            for c in cmds {
                let lits = &data[pos..pos + c.insert as usize];
                if model.ntrees == 1 {
                    for &b in lits {
                        lit_hist[0][usize::from(b)] += 1;
                    }
                } else {
                    for (p, &b) in (pos..).zip(lits) {
                        let ctx = context(data, p, lut);
                        lit_hist[usize::from(model.map[ctx])][usize::from(b)] += 1;
                    }
                }
                pos += (c.insert + c.copy) as usize;
            }
        }

        // Header.
        w.bits(1, u64::from(last));
        if last {
            w.bits(1, 0); // ISLASTEMPTY
        }
        write_mlen(w, end - start);
        if !last {
            w.bits(1, 0); // ISUNCOMPRESSED
        }
        w.bits(3, 0); // one block type of literals, commands and distances
        w.bits(6, 0); // NPOSTFIX, NDIRECT
        w.bits(2, u64::from(model.mode));
        write_var_len_u8(w, model.ntrees - 1);
        if model.ntrees > 1 {
            write_context_map(w, &model.map, model.ntrees);
        }
        write_var_len_u8(w, 0); // one distance tree
        let mut lit_codes = Vec::with_capacity(model.ntrees);
        for h in &lit_hist {
            lit_codes.push(write_prefix_code(w, h, 256));
        }
        let cmd_code = write_prefix_code(w, &cmd_hist, 704);
        let dist_code = write_prefix_code(w, &dist_hist, 64);

        // Commands.
        let mut pos = start;
        for (c, k) in cmds.iter().zip(&coded) {
            cmd_code.put(w, usize::from(k.cmd));
            w.bits(u32::from(k.ins_n), u64::from(k.ins_x));
            w.bits(u32::from(k.copy_n), u64::from(k.copy_x));
            let lits = &data[pos..pos + c.insert as usize];
            if model.ntrees == 1 {
                for &b in lits {
                    lit_codes[0].put(w, usize::from(b));
                }
            } else {
                for (p, &b) in (pos..).zip(lits) {
                    let tree = usize::from(model.map[context(data, p, lut)]);
                    lit_codes[tree].put(w, usize::from(b));
                }
            }
            if k.dsym != NO_DIST {
                dist_code.put(w, usize::from(k.dsym));
                w.bits(u32::from(k.dist_n), u64::from(k.dist_x));
            }
            pos += (c.insert + c.copy) as usize;
        }
    }
}

// ---- Optimal parsing -------------------------------------------------------------------------

/// Bit costs of symbols, from code lengths of a previous pass (or a first estimate).
struct CostModel {
    lit: [f32; 256],
    cmd: Vec<f32>,
    dist: [f32; 64],
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
            cmd: (0..704).map(|i| ((11 + i) as f32).log2()).collect(),
            dist: std::array::from_fn(|i| ((20 + i) as f32).log2()),
        }
    }

    fn from_commands(data: &[u8], start: usize, cmds: &[Command], ring: [u32; 4]) -> Self {
        let mut ring = ring;
        let mut ch = vec![0u32; 704];
        let mut dh = [0u32; 64];
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
            pos += (c.insert + c.copy) as usize;
        }
        let mut m = CostModel {
            lit: [0.0; 256],
            cmd: vec![0.0; 704],
            dist: [0.0; 64],
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
    /// Copy length of the step into this node (0: a literal).
    len: u32,
    dist: u32,
    /// Literals since the last copy.
    ins: u32,
    ring: [u32; 4],
}

/// How many lengths of one match the shortest-path search tries one by one; longer ones only
/// at their full length.
const ENUM_LENGTHS: usize = 48;

impl Encoder<'_> {
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
            let max_dist = i.min(self.max_dist);
            let mut cand = self.head[self.hash(i)];
            let mut depth = self.p.depth;
            let mut best = 3;
            let first = mlist.len();
            while cand != NIL && depth > 0 {
                let c = cand as usize;
                if c >= i || i - c > max_dist {
                    break;
                }
                depth -= 1;
                cand = self.prev[c & self.wmask];
                if data.get(c + best) != data.get(i + best) {
                    continue;
                }
                let len = match_len(data, c, i, max_len);
                if len > best {
                    best = len;
                    mlist.push((len as u32, (i - c) as u32));
                    if len >= self.p.nice || len == max_len {
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

        let mut model = CostModel::initial(&data[start..end]);
        for pass in 0..self.p.optimal {
            cmds.clear();
            self.shortest_path(start, end, &mstart, &mlist, &model, cmds);
            if pass + 1 < self.p.optimal {
                model = CostModel::from_commands(data, start, cmds, self.last);
            }
        }
    }

    fn shortest_path(
        &self,
        start: usize,
        end: usize,
        mstart: &[u32],
        mlist: &[(u32, u32)],
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
            let c = node.cost + model.lit[usize::from(data[pos])];
            if c < nodes[i + 1].cost {
                nodes[i + 1] = Node {
                    cost: c,
                    prev: i as u32,
                    len: 0,
                    dist: 0,
                    ins: node.ins + 1,
                    ring: node.ring,
                };
            }
            let max_len = n - i;
            if max_len < 2 {
                continue;
            }
            let max_dist = pos.min(self.max_dist);
            let ins = node.ins as usize;
            let relax = |nodes: &mut [Node], len: usize, dist: usize, cost: f32| {
                let j = i + len;
                if cost < nodes[j].cost {
                    let r = node.ring;
                    nodes[j] = Node {
                        cost,
                        prev: i as u32,
                        len: len as u32,
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
                if len < from || dist > max_dist {
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
                steps.push((nd.prev as usize, nd.len as usize, nd.dist));
            }
            j = nd.prev as usize;
        }
        let mut lit_start = 0;
        for &(p, len, dist) in steps.iter().rev() {
            cmds.push(Command {
                insert: (p - lit_start) as u32,
                copy: len as u32,
                dist,
            });
            lit_start = p + len;
        }
        if lit_start < n {
            cmds.push(Command {
                insert: (n - lit_start) as u32,
                copy: 0,
                dist: 0,
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

fn ins_code(n: usize) -> usize {
    INS_BASE.partition_point(|&b| b as usize <= n) - 1
}

fn copy_code(n: usize) -> usize {
    COPY_BASE.partition_point(|&b| b as usize <= n).max(1) - 1
}

/// The insert-and-copy symbol of insert code `ic` and copy code `cc` (section 5).
fn command_symbol(ic: usize, cc: usize, implicit: bool) -> usize {
    let block = if implicit {
        cc >> 3
    } else {
        match (ic >> 3, cc >> 3) {
            (0, 0) => 2,
            (0, 1) => 3,
            (1, 0) => 4,
            (1, 1) => 5,
            (0, _) => 6,
            (2, 0) => 7,
            (1, _) => 8,
            (_, 1) => 9,
            _ => 10,
        }
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
    let (dsym, dist_x, dist_n) = match short.iter().position(|&s| s == Some(d)) {
        Some(k) => (k as u16, 0, 0),
        None => explicit_distance(d as usize),
    };
    if dsym != 0 {
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

/// `n * log2(n)`, from a table for small `n`.
fn nlog2n(n: u32) -> f64 {
    static TABLE: std::sync::OnceLock<Vec<f64>> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        (0..4096u32)
            .map(|n| {
                if n == 0 {
                    0.0
                } else {
                    f64::from(n) * f64::from(n).log2()
                }
            })
            .collect()
    });
    match t.get(n as usize) {
        Some(&v) => v,
        None => f64::from(n) * f64::from(n).log2(),
    }
}

/// A literal histogram and its used symbols.
#[derive(Clone)]
struct Hist {
    h: [u32; 256],
    used: Vec<u8>,
    total: u32,
}

impl Hist {
    fn new(h: &[u32; 256]) -> Self {
        let used: Vec<u8> = (0..=255u8).filter(|&s| h[usize::from(s)] != 0).collect();
        Hist {
            h: *h,
            total: h.iter().sum(),
            used,
        }
    }

    fn add(&mut self, o: &Hist) {
        for &s in &o.used {
            if self.h[usize::from(s)] == 0 {
                self.used.push(s);
            }
            self.h[usize::from(s)] += o.h[usize::from(s)];
        }
        self.total += o.total;
    }
}

/// Estimated bits to code `total` symbols with `used` distinct ones whose counts' `n log n`
/// sum to `sum`, with their own prefix code (the code description included).
fn code_cost(total: u32, sum: f64, used: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let header = if used <= 4 {
        6.0 + 8.0 * used as f64
    } else {
        40.0 + 5.0 * used as f64
    };
    nlog2n(total) - sum + header
}

fn hist_cost(h: &Hist) -> f64 {
    let sum: f64 = h.used.iter().map(|&s| nlog2n(h.h[usize::from(s)])).sum();
    code_cost(h.total, sum, h.used.len())
}

/// The cost of `a` and `b` merged.
fn merged_cost(a: &Hist, b: &Hist) -> f64 {
    let mut sum = 0.0;
    let mut used = a.used.len();
    for &s in &a.used {
        sum += nlog2n(a.h[usize::from(s)] + b.h[usize::from(s)]);
    }
    for &s in &b.used {
        if a.h[usize::from(s)] == 0 {
            sum += nlog2n(b.h[usize::from(s)]);
            used += 1;
        }
    }
    code_cost(a.total + b.total, sum, used)
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
            pos += (c.insert + c.copy) as usize;
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
                cost: hist_cost(&h),
                h,
                members: vec![i],
            });
        }
    }
    if !rare.members.is_empty() {
        rare.cost = hist_cost(&rare.h);
        cl.push(rare);
    }
    // Each extra tree also costs context map bits.
    const TREE_COST: f64 = 24.0;
    let n = cl.len();
    let mut delta = vec![f64::INFINITY; n * n];
    for a in 0..n {
        for b in a + 1..n {
            delta[a * n + b] = merged_cost(&cl[a].h, &cl[b].h) - cl[a].cost - cl[b].cost;
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
        cl[a].cost = hist_cost(&cl[a].h);
        alive[b] = false;
        count -= 1;
        for (o, _) in alive.iter().enumerate().filter(|&(o, &l)| l && o != a) {
            let (x, y) = if o < a { (o, a) } else { (a, o) };
            delta[x * n + y] = merged_cost(&cl[x].h, &cl[y].h) - cl[x].cost - cl[y].cost;
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

/// A prefix code ready for writing: lengths and bit-reversed codes.
struct Code {
    lens: Vec<u8>,
    codes: Vec<u16>,
}

impl Code {
    #[inline(always)]
    fn put(&self, w: &mut BitWriter, sym: usize) {
        w.bits(u32::from(self.lens[sym]), u64::from(self.codes[sym]));
    }
}

/// Writes a prefix code for `hist` over an alphabet of `size` symbols and returns it.
fn write_prefix_code(w: &mut BitWriter, hist: &[u32], size: usize) -> Code {
    let mut lens = Vec::new();
    lengths(hist, 15, &mut lens);
    lens.resize(size, 0);
    let used: Vec<usize> = (0..size).filter(|&s| lens[s] != 0).collect();
    let alphabet_bits = usize::BITS - (size - 1).leading_zeros();
    if used.len() <= 4 {
        // Simple prefix code.
        let mut syms = used;
        if syms.is_empty() {
            syms.push(0);
        }
        syms.sort_by_key(|&s| (lens[s], s));
        w.bits(2, 1);
        w.bits(2, (syms.len() - 1) as u64);
        for &s in &syms {
            w.bits(alphabet_bits, s as u64);
        }
        if syms.len() == 1 {
            lens[syms[0]] = 0;
        }
        if syms.len() == 4 {
            w.bits(1, u64::from(lens[syms[0]] == 1));
        }
        let mut cs = Vec::new();
        codes(&lens, &mut cs);
        return Code { lens, codes: cs };
    }
    // The exact lengths, or those of counts smoothed for run-length coding (cheaper to store,
    // which matters for small inputs): whichever costs fewer bits in all.
    let mut smooth = hist[..size].to_vec();
    optimize_for_rle(&mut smooth);
    let mut alt = Vec::new();
    lengths(&smooth, 15, &mut alt);
    if alt.iter().filter(|&&l| l != 0).count() > 4 {
        let total = |l: &[u8]| -> usize {
            let mut t = BitWriter::with_capacity(0);
            store_complex(&mut t, l);
            t.bit_len()
                + hist[..size]
                    .iter()
                    .zip(l)
                    .map(|(&h, &n)| h as usize * usize::from(n))
                    .sum::<usize>()
        };
        if total(&alt) < total(&lens) {
            lens = alt;
        }
    }
    store_complex(w, &lens);
    let mut cs = Vec::new();
    codes(&lens, &mut cs);
    Code { lens, codes: cs }
}

/// Smooths `counts` so that their code lengths form longer runs (zopfli's
/// `OptimizeHuffmanForRle`, as Google's brotli encoder does): strides of similar counts are
/// replaced by their average; zero counts stay zero unless inside a collapsed stride.
fn optimize_for_rle(counts: &mut [u32]) {
    let mut length = counts.len();
    while length > 0 && counts[length - 1] == 0 {
        length -= 1;
    }
    if length == 0 {
        return;
    }
    let counts = &mut counts[..length];
    // Runs that already code well.
    let mut good = vec![false; length];
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
            let reps = depth[i..].iter().take_while(|&&x| x == v).count();
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
            depth[i..].iter().take_while(|&&x| x == v).count()
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

/// Writes a complex prefix code with code lengths `lens` (a complete code, at least two
/// symbols).
fn store_complex(w: &mut BitWriter, lens: &[u8]) {
    let mut tokens = Vec::new();
    rle_lengths(lens, &mut tokens);
    let mut hist = [0u32; 18];
    for &(t, _) in &tokens {
        hist[usize::from(t)] += 1;
    }
    let mut cl = Vec::new();
    lengths(&hist, 5, &mut cl);
    let num = cl.iter().filter(|&&l| l != 0).count();
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
    w.bits(2, skip as u64);
    for &s in &CODE_LENGTH_ORDER[skip..to_store] {
        let (n, v) = CL_STATIC_CODE[usize::from(cl[s])];
        w.bits(n, v);
    }
    if num == 1 {
        // A single code length symbol is decoded from zero bits.
        cl.fill(0);
    }
    let mut cs = Vec::new();
    codes(&cl, &mut cs);
    for &(t, x) in &tokens {
        let t = usize::from(t);
        w.bits(u32::from(cl[t]), u64::from(cs[t]));
        match t {
            16 => w.bits(2, u64::from(x)),
            17 => w.bits(3, u64::from(x)),
            _ => {}
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
