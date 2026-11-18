//! The encoder: LZ77 over hash chains, Huffman-coded literals and FSE-coded sequences.

use crate::Level;
use crate::bits::BitWriter;
use crate::fse::{self, CTable};
use crate::huffman;
use crate::tables::{
    BLOCK_MAX, LL_BASE, LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, LL_MAX_LOG, MAGIC, ML_BASE,
    ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM, ML_MAX_LOG, OF_DEFAULT_LOG, OF_DEFAULT_NORM,
    OF_MAX_LOG, highbit, ll_code, ml_code,
};
use crate::xxhash::xxh64;

/// Largest window the encoder uses (the limit of RFC 9659 for HTTP): inputs up to this size
/// are one segment, larger ones have an 8 MiB window.
const MAX_WINDOW: usize = 8 << 20;
const MIN_MATCH: usize = 4;

/// Match-finder settings of a level.
#[derive(Clone, Copy, Debug)]
struct Params {
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

fn params(level: Level) -> Params {
    let (depth, lazy, nice, skip, hash_log, chain_log) = match level.get() {
        1 => (1, 0, 16, 5, 16, 15),
        2 => (2, 0, 24, 6, 17, 16),
        3 => (4, 1, 32, 8, 17, 17),
        4 => (6, 1, 48, 8, 17, 17),
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
        16 => (192, 2, 512, 0, 21, 22),
        17 => (256, 2, 512, 0, 21, 22),
        18 => (320, 2, 512, 0, 22, 22),
        19 => (384, 2, 512, 0, 22, 23),
        20 => (512, 2, 1024, 0, 22, 23),
        21 => (640, 2, 1024, 0, 22, 23),
        _ => (768, 2, 1024, 0, 22, 23),
    };
    Params {
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
    let p = params(level);
    let n = data.len();
    let mut out = Vec::with_capacity(n / 2 + 32);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let single = n <= MAX_WINDOW;
    let size = n as u64;
    let fcs_flag: u8 = if single && size < 256 {
        0
    } else if (256..=65791).contains(&size) {
        1
    } else if u32::try_from(size).is_ok() {
        2
    } else {
        3
    };
    out.push(fcs_flag << 6 | u8::from(single) << 5 | 0x04);
    let window = if single {
        n
    } else {
        // Window_Descriptor of 8 MiB: exponent 13, mantissa 0.
        out.push(13 << 3);
        MAX_WINDOW
    };
    match fcs_flag {
        0 => out.push(size as u8),
        1 => out.extend_from_slice(&((size - 256) as u16).to_le_bytes()),
        2 => out.extend_from_slice(&(size as u32).to_le_bytes()),
        _ => out.extend_from_slice(&size.to_le_bytes()),
    }
    if n == 0 {
        out.extend_from_slice(&[1, 0, 0]); // last, raw, empty
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

struct Encoder<'a> {
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
            chain: vec![0; 1 << chain_log],
            chain_mask: (1 << chain_log) - 1,
            inserted: 0,
            reps: [1, 4, 8],
            lits: Vec::new(),
            seqs: Vec::new(),
        }
    }

    #[inline]
    fn hash(&self, pos: usize) -> usize {
        let d = &self.data[pos..pos + 4];
        let v = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - self.hash_log)) as usize
    }

    fn insert_to(&mut self, pos: usize) {
        let last = self.data.len().saturating_sub(MIN_MATCH - 1);
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

    /// Writes the block `[start, end)`.
    fn block(&mut self, start: usize, end: usize, last: bool, out: &mut Vec<u8>) {
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
        self.parse(start, end);
        let mut body = Vec::with_capacity(len);
        encode_literals(&self.lits, &mut body);
        encode_sequences(&self.seqs, &mut body);
        if body.len() < len {
            out.extend_from_slice(&header(2, body.len()));
            out.extend_from_slice(&body);
        } else {
            self.reps = saved;
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

fn encode_literals(lits: &[u8], out: &mut Vec<u8>) {
    let n = lits.len();
    if n > 1 && lits.iter().all(|&b| b == lits[0]) {
        raw_literals_header(1, n, out);
        out.push(lits[0]);
        return;
    }
    let raw_size = n + if n < 32 {
        1
    } else if n < 4096 {
        2
    } else {
        3
    };
    if n >= 32 {
        let mut counts = [0u32; 256];
        for &b in lits {
            counts[usize::from(b)] += 1;
        }
        // Worth trying when the entropy estimate saves something.
        if let Some(enc) = huffman::Encoder::new(&counts) {
            let estimate = enc.description.len() + enc.cost_bits(&counts) / 8 + 3;
            if estimate < raw_size {
                let four = n >= 256;
                let mut body = enc.description.clone();
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
                    if lh + c < raw_size && (four || c <= 1023) {
                        let shift = match lh {
                            3 => 14,
                            4 => 18,
                            _ => 22,
                        };
                        let v = 2 | sf << 2 | (n as u64) << 4 | (c as u64) << shift;
                        out.extend_from_slice(&v.to_le_bytes()[..lh]);
                        out.extend_from_slice(&body);
                        return;
                    }
                }
            }
        }
    }
    raw_literals_header(0, n, out);
    out.extend_from_slice(lits);
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

    #[inline]
    fn encode(&self, w: &mut BitWriter<'_>, state: &mut u32, sym: u8) {
        if let FieldCode::Table(t) = self {
            t.encode(w, state, sym);
        }
    }

    fn flush(&self, w: &mut BitWriter<'_>, state: u32) {
        if let FieldCode::Table(t) = self {
            t.flush(w, state);
        }
    }
}

/// Chooses the cheapest of RLE, predefined and FSE-compressed tables for `codes`: returns the
/// mode, the coder and the table description.
fn choose_table(
    codes: &[u8],
    default_norm: &[i16],
    default_log: u32,
    max_log: u32,
) -> (u8, FieldCode, Vec<u8>) {
    let mut counts = [0u32; 64];
    for &c in codes {
        counts[usize::from(c)] += 1;
    }
    let last = counts.iter().rposition(|&c| c > 0).unwrap_or(0);
    let counts = &counts[..=last];
    let distinct = counts.iter().filter(|&&c| c > 0).count();
    if distinct == 1 {
        return (1, FieldCode::Rle, vec![last as u8]);
    }
    let mut best_mode = 0u8;
    let mut best_cost = if last < default_norm.len() {
        fse::cost_bits(counts, default_norm, default_log)
    } else {
        f64::INFINITY
    };
    let mut best_table: Option<(Vec<i16>, u32, Vec<u8>)> = None;
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
    match best_table {
        Some((norm, log, desc)) if best_mode == 2 => {
            (2, FieldCode::Table(CTable::new(&norm, log)), desc)
        }
        _ => (
            0,
            FieldCode::Table(CTable::new(default_norm, default_log)),
            Vec::new(),
        ),
    }
}

fn encode_sequences(seqs: &[Seq], out: &mut Vec<u8>) {
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
    let (ll_mode, ll_c, ll_d) = choose_table(&ll, &LL_DEFAULT_NORM, LL_DEFAULT_LOG, LL_MAX_LOG);
    let (of_mode, of_c, of_d) = choose_table(&of, &OF_DEFAULT_NORM, OF_DEFAULT_LOG, OF_MAX_LOG);
    let (ml_mode, ml_c, ml_d) = choose_table(&ml, &ML_DEFAULT_NORM, ML_DEFAULT_LOG, ML_MAX_LOG);
    out.push(ll_mode << 6 | of_mode << 4 | ml_mode << 2);
    out.extend_from_slice(&ll_d);
    out.extend_from_slice(&of_d);
    out.extend_from_slice(&ml_d);
    let mut w = BitWriter::new(out);
    let extra = |w: &mut BitWriter<'_>, i: usize| {
        let s = seqs[i];
        let llc = usize::from(ll[i]);
        w.put(u64::from(s.ll - LL_BASE[llc]), u32::from(LL_BITS[llc]));
        let mlc = usize::from(ml[i]);
        w.put(u64::from(s.ml - ML_BASE[mlc]), u32::from(ML_BITS[mlc]));
        w.put(u64::from(s.off - (1 << of[i])), u32::from(of[i]));
    };
    let last = n - 1;
    let mut s_ml = ml_c.init(ml[last]);
    let mut s_of = of_c.init(of[last]);
    let mut s_ll = ll_c.init(ll[last]);
    extra(&mut w, last);
    for i in (0..last).rev() {
        of_c.encode(&mut w, &mut s_of, of[i]);
        ml_c.encode(&mut w, &mut s_ml, ml[i]);
        ll_c.encode(&mut w, &mut s_ll, ll[i]);
        extra(&mut w, i);
    }
    ml_c.flush(&mut w, s_ml);
    of_c.flush(&mut w, s_of);
    ll_c.flush(&mut w, s_ll);
    w.close();
}
