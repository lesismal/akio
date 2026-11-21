//! Block splitting and histogram clustering (section 6 and 7.3), after Google's encoder.
//!
//! A meta-block's literals, insert-and-copy symbols and distance symbols can each be cut into
//! blocks of up to 256 block types, every type with its own prefix codes (literals and
//! distances through their context maps). [`split`] finds such a split of one symbol sequence
//! as Google's `block_splitter` does at qualities 10 and 11: a set of histograms seeded from
//! samples of the sequence, then a few rounds of assigning each symbol to the histogram that
//! codes it cheapest with a penalty for switching (a shortest path over the histograms), and
//! re-estimating the histograms from the assignment; the blocks found are finally clustered
//! into block types. [`greedy`] is the cheap one-pass variant of the middle levels. The
//! clustering of [`cluster`] (agglomerative, by the estimated cost of the merged histograms
//! including their code descriptions) also builds the context maps.

use super::nlog2n;

/// `log2(n)` (0 for 0), from a table for small `n`.
fn log2(n: u32) -> f64 {
    static TABLE: std::sync::OnceLock<Vec<f64>> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        (0..4096u32)
            .map(|n| if n == 0 { 0.0 } else { f64::from(n).log2() })
            .collect()
    });
    match t.get(n as usize) {
        Some(&v) => v,
        None => f64::from(n).log2(),
    }
}

/// A histogram of symbols and its estimated cost in bits (see [`population_cost`]).
#[derive(Clone)]
pub(super) struct Histo {
    pub(super) h: Vec<u32>,
    pub(super) total: u32,
    pub(super) cost: f64,
}

impl Histo {
    pub(super) fn new(size: usize) -> Self {
        Histo {
            h: vec![0; size],
            total: 0,
            cost: 0.0,
        }
    }

    #[inline(always)]
    pub(super) fn add(&mut self, s: usize) {
        self.h[s] += 1;
        self.total += 1;
    }

    fn add_histo(&mut self, o: &Histo) {
        for (a, &b) in self.h.iter_mut().zip(&o.h) {
            *a += b;
        }
        self.total += o.total;
    }

    fn clear(&mut self) {
        self.h.fill(0);
        self.total = 0;
    }

    fn set_sum(&mut self, a: &Histo, b: &Histo) {
        for ((o, &x), &y) in self.h.iter_mut().zip(&a.h).zip(&b.h) {
            *o = x + y;
        }
        self.total = a.total + b.total;
    }
}

/// Shannon entropy of `p` in bits, at least one bit per symbol.
fn bits_entropy(p: &[u32]) -> f64 {
    let mut sum = 0u32;
    let mut bits = 0.0;
    for &c in p {
        if c != 0 {
            sum += c;
            bits -= nlog2n(c);
        }
    }
    bits += nlog2n(sum);
    bits.max(f64::from(sum))
}

/// Estimated bits to code the symbols of `h` with a prefix code of their own, the code's
/// description included (Google's `BrotliPopulationCost`).
pub(super) fn population_cost(h: &Histo) -> f64 {
    if h.total == 0 {
        return 12.0;
    }
    // The used symbols as a bit set: the loops below visit only them.
    let mut mask = [0u64; 11];
    let mut used = 0;
    for (m, chunk) in mask.iter_mut().zip(h.h.chunks(64)) {
        let mut v = 0u64;
        for (j, &c) in chunk.iter().enumerate() {
            v |= u64::from(c != 0) << j;
        }
        *m = v;
        used += v.count_ones();
    }
    let mut syms = mask.iter().enumerate().flat_map(|(k, &m)| {
        let mut m = m;
        std::iter::from_fn(move || {
            if m == 0 {
                return None;
            }
            let j = m.trailing_zeros() as usize;
            m &= m - 1;
            Some(k * 64 + j)
        })
    });
    if used <= 4 {
        let mut v = [0f64; 4];
        for (x, s) in v.iter_mut().zip(&mut syms) {
            *x = f64::from(h.h[s]);
        }
        return match used {
            1 => 12.0,
            2 => 20.0 + f64::from(h.total),
            3 => 28.0 + 2.0 * (v[0] + v[1] + v[2]) - v[0].max(v[1]).max(v[2]),
            _ => {
                v.sort_by(|x, y| y.total_cmp(x));
                let h23 = v[2] + v[3];
                37.0 + 3.0 * h23 + 2.0 * (v[0] + v[1]) - h23.max(v[0])
            }
        };
    }
    let mut bits = 0.0;
    let mut max_depth = 1;
    let mut depth_histo = [0u32; 18];
    let log2total = log2(h.total);
    let mut next = 0;
    for i in syms {
        // The zeros before (trailing zeros are implicit).
        let mut reps = (i - next) as u32;
        if reps > 0 {
            if reps < 3 {
                depth_histo[0] += reps;
            } else {
                reps -= 2;
                while reps > 0 {
                    depth_histo[17] += 1;
                    bits += 3.0;
                    reps >>= 3;
                }
            }
        }
        next = i + 1;
        let v = h.h[i];
        let log2p = log2total - log2(v);
        bits += f64::from(v) * log2p;
        let depth = ((log2p + 0.5) as usize).min(15);
        max_depth = max_depth.max(depth);
        depth_histo[depth] += 1;
    }
    bits + (18 + 2 * max_depth) as f64 + bits_entropy(&depth_histo)
}

/// The cost of adding `h` to `to` (whose cost is up to date).
fn cost_distance(h: &Histo, to: &Histo, tmp: &mut Histo) -> f64 {
    if h.total == 0 {
        return 0.0;
    }
    tmp.set_sum(h, to);
    population_cost(tmp) - to.cost
}

#[derive(Clone, Copy)]
struct Pair {
    a: u32,
    b: u32,
    diff: f64,
    combo: f64,
}

/// Whether `p` is a worse merge than `q`.
fn worse(p: &Pair, q: &Pair) -> bool {
    if p.diff != q.diff {
        p.diff > q.diff
    } else {
        p.b - p.a > q.b - q.a
    }
}

/// Bits saved in the stream of cluster ids by merging clusters of `a` and `b` members.
fn cluster_cost_diff(a: u32, b: u32) -> f64 {
    let c = a + b;
    f64::from(a) * log2(a) + f64::from(b) * log2(b) - f64::from(c) * log2(c)
}

/// The queue of candidate merges: `pairs[0]` is the best one, the rest unordered.
struct Pairs {
    v: Vec<Pair>,
    max: usize,
}

impl Pairs {
    fn push(&mut self, out: &[Histo], tmp: &mut Histo, sizes: &[u32], a: u32, b: u32) {
        if a == b {
            return;
        }
        let (a, b) = if b < a { (b, a) } else { (a, b) };
        let (ha, hb) = (&out[a as usize], &out[b as usize]);
        let mut p = Pair {
            a,
            b,
            diff: 0.5 * cluster_cost_diff(sizes[a as usize], sizes[b as usize]) - ha.cost - hb.cost,
            combo: 0.0,
        };
        if ha.total == 0 {
            p.combo = hb.cost;
        } else if hb.total == 0 {
            p.combo = ha.cost;
        } else {
            let threshold = match self.v.first() {
                None => f64::INFINITY,
                Some(top) => top.diff.max(0.0),
            };
            tmp.set_sum(ha, hb);
            let combo = population_cost(tmp);
            if combo >= threshold - p.diff {
                return;
            }
            p.combo = combo;
        }
        p.diff += p.combo;
        if !self.v.is_empty() && worse(&self.v[0], &p) {
            if self.v.len() < self.max {
                let top = self.v[0];
                self.v.push(top);
            }
            self.v[0] = p;
        } else if self.v.len() < self.max {
            self.v.push(p);
        }
    }
}

/// Merges the histograms `out[clusters]` greedily while that lowers the estimated cost, then
/// further while there are more than `max_clusters`; `sizes` counts the members of each,
/// `symbols` (the cluster of each member) is updated, and `clusters` keeps the survivors.
fn combine(
    out: &mut [Histo],
    tmp: &mut Histo,
    sizes: &mut [u32],
    symbols: &mut [u32],
    clusters: &mut Vec<u32>,
    max_clusters: usize,
    max_pairs: usize,
) {
    let mut threshold = 0.0;
    let mut min_clusters = 1;
    let mut pairs = Pairs {
        v: Vec::with_capacity(max_pairs.min(1 << 16)),
        max: max_pairs.max(1),
    };
    for i in 0..clusters.len() {
        for j in i + 1..clusters.len() {
            pairs.push(out, tmp, sizes, clusters[i], clusters[j]);
        }
    }
    while clusters.len() > min_clusters {
        let Some(&best) = pairs.v.first() else {
            break;
        };
        if best.diff >= threshold {
            threshold = f64::INFINITY;
            min_clusters = max_clusters;
            continue;
        }
        let (a, b) = (best.a as usize, best.b as usize);
        let hb = std::mem::take(&mut out[b].h);
        let tb = out[b].total;
        for (x, &y) in out[a].h.iter_mut().zip(&hb) {
            *x += y;
        }
        out[a].total += tb;
        out[b].h = hb;
        out[a].cost = best.combo;
        sizes[a] += sizes[b];
        for s in symbols.iter_mut() {
            if *s == best.b {
                *s = best.a;
            }
        }
        if let Some(i) = clusters.iter().position(|&c| c == best.b) {
            clusters.remove(i);
        }
        // Drop the pairs with either; keep the best remaining one in front.
        let mut kept = 0;
        for i in 0..pairs.v.len() {
            let p = pairs.v[i];
            if p.a == best.a || p.b == best.a || p.a == best.b || p.b == best.b {
                continue;
            }
            if worse(&pairs.v[0], &p) {
                let front = pairs.v[0];
                pairs.v[0] = p;
                pairs.v[kept] = front;
            } else {
                pairs.v[kept] = p;
            }
            kept += 1;
        }
        pairs.v.truncate(kept);
        for &c in clusters.iter() {
            pairs.push(out, tmp, sizes, best.a, c);
        }
    }
}

/// Clusters `input` into at most `max` histograms (Google's `BrotliClusterHistograms`):
/// returns the histograms and the cluster of each input histogram, numbered in order of first
/// use.
pub(super) fn cluster(input: &[Histo], max: usize) -> (Vec<Histo>, Vec<u8>) {
    const BATCH: usize = 64;
    let n = input.len();
    let size = input.first().map_or(1, |h| h.h.len());
    let mut tmp = Histo::new(size);
    let mut out: Vec<Histo> = input
        .iter()
        .map(|h| {
            let mut h = h.clone();
            h.cost = population_cost(&h);
            h
        })
        .collect();
    let mut sizes = vec![1u32; n];
    let mut symbols: Vec<u32> = (0..n as u32).collect();
    let mut clusters: Vec<u32> = Vec::new();
    for i in (0..n).step_by(BATCH) {
        let k = (n - i).min(BATCH);
        let mut batch: Vec<u32> = (i as u32..(i + k) as u32).collect();
        combine(
            &mut out,
            &mut tmp,
            &mut sizes,
            &mut symbols[i..i + k],
            &mut batch,
            max,
            BATCH * BATCH / 2,
        );
        clusters.extend_from_slice(&batch);
    }
    let nc = clusters.len();
    let max_pairs = (64 * nc).min(nc / 2 * nc);
    combine(
        &mut out,
        &mut tmp,
        &mut sizes,
        &mut symbols,
        &mut clusters,
        max,
        max_pairs,
    );
    // Each input to its best cluster, then the clusters recomputed from their members.
    for i in 0..n {
        let mut best = if i == 0 { symbols[0] } else { symbols[i - 1] };
        let mut best_bits = cost_distance(&input[i], &out[best as usize], &mut tmp);
        for &c in &clusters {
            let bits = cost_distance(&input[i], &out[c as usize], &mut tmp);
            if bits < best_bits {
                best_bits = bits;
                best = c;
            }
        }
        symbols[i] = best;
    }
    for &c in &clusters {
        out[c as usize].clear();
    }
    for i in 0..n {
        out[symbols[i] as usize].add_histo(&input[i]);
    }
    // Renumber in order of first use.
    let mut index = vec![u32::MAX; n];
    let mut result = Vec::new();
    let mut map = Vec::with_capacity(n);
    for &s in &symbols {
        if index[s as usize] == u32::MAX {
            index[s as usize] = result.len() as u32;
            result.push(std::mem::replace(&mut out[s as usize], Histo::new(0)));
        }
        map.push(index[s as usize] as u8);
    }
    (result, map)
}

/// Clusters context histograms, `per` contexts per block type, into a context map with at
/// most `max` codes; returns the map and the number of codes. The contexts of a block type with
/// fewer than `few` symbols start out as one histogram (they could not pay for a code of their
/// own, and fewer histograms make the clustering much cheaper), empty contexts take the code of
/// the context before them (cheaper runs in the map), and codes are numbered in order of first
/// use in the map (cheaper move-to-front coding).
pub(super) fn context_map(hs: &[Histo], per: usize, few: u32, max: usize) -> (Vec<u8>, usize) {
    const EMPTY: u32 = u32::MAX;
    let mut input: Vec<Histo> = Vec::new();
    let mut which = vec![EMPTY; hs.len()];
    for (t, group) in hs.chunks(per).enumerate() {
        let mut rare: Option<usize> = None;
        for (c, h) in group.iter().enumerate() {
            let i = t * per + c;
            if h.total == 0 {
                continue;
            }
            if h.total < few {
                let r = *rare.get_or_insert_with(|| {
                    input.push(Histo::new(h.h.len()));
                    input.len() - 1
                });
                input[r].add_histo(h);
                which[i] = r as u32;
            } else {
                which[i] = input.len() as u32;
                input.push(h.clone());
            }
        }
    }
    if input.is_empty() {
        return (vec![0; hs.len()], 1);
    }
    let (_, ids) = cluster(&input, max);
    let mut map = vec![0u8; hs.len()];
    let mut prev = None;
    for (m, &w) in map.iter_mut().zip(&which) {
        if w != EMPTY {
            prev = Some(ids[w as usize]);
        }
        *m = prev.unwrap_or(ids[0]);
    }
    let mut renum = [u8::MAX; 256];
    let mut n = 0usize;
    for m in &mut map {
        if renum[usize::from(*m)] == u8::MAX {
            renum[usize::from(*m)] = n as u8;
            n += 1;
        }
        *m = renum[usize::from(*m)];
    }
    (map, n)
}

/// A cheap clustering of the histograms of `types` block types by `trees` codes each (`hs[t *
/// trees + j]`), for the middle levels: histogram `(t, j)` keeps a code of its own only if
/// that costs less than adding it to the code shared by all block types for `j`, tried
/// largest first; at most `max` codes. Returns the code of each histogram and their number.
pub(super) fn type_tree_map(
    hs: &[Histo],
    types: usize,
    trees: usize,
    max: usize,
) -> (Vec<u8>, usize) {
    let mut map = vec![0u8; hs.len()];
    let mut n = trees;
    let mut own: Vec<(usize, usize)> = Vec::new(); // (index, code)
    let size = hs.first().map_or(256, |h| h.h.len());
    let mut tmp = Histo::new(size);
    for j in 0..trees {
        let mut order: Vec<usize> = (0..types).map(|t| t * trees + j).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(hs[i].total));
        // Start from the sum of all; take out those that pay for their own code.
        let mut sh = Histo::new(size);
        for &i in &order {
            sh.add_histo(&hs[i]);
        }
        sh.cost = population_cost(&sh);
        for &i in &order {
            let h = &hs[i];
            if h.total < 256 || n >= max {
                break;
            }
            for ((o, &a), &b) in tmp.h.iter_mut().zip(&sh.h).zip(&h.h) {
                *o = a - b;
            }
            tmp.total = sh.total - h.total;
            let rest = population_cost(&tmp);
            if rest + population_cost(h) < sh.cost {
                std::mem::swap(&mut sh.h, &mut tmp.h);
                sh.total = tmp.total;
                sh.cost = rest;
                own.push((i, n));
                n += 1;
            }
        }
    }
    for (i, m) in map.iter_mut().enumerate() {
        *m = (i % trees) as u8;
    }
    for &(i, code) in &own {
        map[i] = code as u8;
    }
    (map, n)
}

/// Blocks of one category: the type and length of each, and the number of types.
pub(super) struct BlockSplit {
    pub(super) types: Vec<u8>,
    pub(super) lens: Vec<u32>,
    pub(super) ntypes: usize,
}

impl BlockSplit {
    /// One block type for everything.
    pub(super) fn single() -> Self {
        BlockSplit {
            types: vec![0],
            lens: vec![u32::MAX],
            ntypes: 1,
        }
    }
}

/// Parameters of [`split`] for one category (Google's).
pub(super) struct SplitParams {
    /// Symbols per initial histogram.
    per_histo: usize,
    max_histos: usize,
    /// Length of the samples the histograms are seeded with.
    stride: usize,
    /// Cost of a block switch in bits.
    switch_cost: f64,
}

pub(super) const LITERALS: SplitParams = SplitParams {
    per_histo: 544,
    max_histos: 100,
    stride: 70,
    switch_cost: 28.1,
};
pub(super) const COMMANDS: SplitParams = SplitParams {
    per_histo: 530,
    max_histos: 50,
    stride: 40,
    switch_cost: 13.5,
};
pub(super) const DISTANCES: SplitParams = SplitParams {
    per_histo: 544,
    max_histos: 50,
    stride: 40,
    switch_cost: 14.6,
};

fn rand(seed: &mut u32) -> u32 {
    *seed = seed.wrapping_mul(16807);
    *seed
}

/// Splits `data` (symbols below `size`) into blocks and block types with `iters` rounds of
/// refinement.
pub(super) fn split<T: Copy + Into<usize>>(
    data: &[T],
    size: usize,
    sp: &SplitParams,
    iters: usize,
) -> BlockSplit {
    let len = data.len();
    if len < 128 {
        return BlockSplit::single();
    }
    let mut nh = (len / sp.per_histo + 1).min(sp.max_histos);
    let stride = sp.stride;
    // Seed the histograms from samples, one from each part of the data...
    let mut histos: Vec<Histo> = vec![Histo::new(size); nh];
    let mut seed = 7u32;
    let block = len / nh;
    for (i, h) in histos.iter_mut().enumerate() {
        let mut pos = len * i / nh;
        if i != 0 {
            pos += rand(&mut seed) as usize % block;
        }
        if pos + stride >= len {
            pos = len - stride - 1;
        }
        for &s in &data[pos..pos + stride] {
            h.add(s.into());
        }
    }
    // ...then from random ones.
    let mut seed = 7u32;
    let rounds = (2 * len / stride + 100).div_ceil(nh) * nh;
    for r in 0..rounds {
        let (pos, n) = if stride >= len {
            (0, len)
        } else {
            (rand(&mut seed) as usize % (len - stride + 1), stride)
        };
        let h = &mut histos[r % nh];
        for &s in &data[pos..pos + n] {
            h.add(s.into());
        }
    }
    let mut ids = vec![0u8; len];
    let mut nblocks = 1;
    let mut costs = vec![0f32; size * sp.max_histos];
    let mut signal = Vec::new();
    for _ in 0..iters {
        nblocks = find_blocks(
            data,
            &histos[..nh],
            sp.switch_cost,
            &mut costs,
            &mut signal,
            &mut ids,
        );
        // Renumber the types in use.
        let mut renum = [u8::MAX; 256];
        let mut next = 0u8;
        for id in &mut ids {
            if renum[usize::from(*id)] == u8::MAX {
                renum[usize::from(*id)] = next;
                next += 1;
            }
            *id = renum[usize::from(*id)];
        }
        nh = usize::from(next);
        for h in &mut histos[..nh] {
            h.clear();
        }
        for (&s, &id) in data.iter().zip(&ids) {
            histos[usize::from(id)].add(s.into());
        }
    }
    cluster_blocks(data, size, nblocks, &ids)
}

/// Assigns each symbol to a histogram: the cheapest path through the histograms, each switch
/// costing `switch_cost`. Returns the number of blocks.
fn find_blocks<T: Copy + Into<usize>>(
    data: &[T],
    histos: &[Histo],
    switch_cost: f64,
    costs: &mut [f32],
    signal: &mut Vec<u8>,
    ids: &mut [u8],
) -> usize {
    let nh = histos.len();
    let len = data.len();
    if nh <= 1 {
        ids.fill(0);
        return 1;
    }
    // The bits of each symbol in each histogram (absent symbols: 2 more than the rarest).
    let size = histos[0].h.len();
    let costs = &mut costs[..size * nh];
    for (j, h) in histos.iter().enumerate() {
        let lt = log2(h.total);
        for s in 0..size {
            let c = h.h[s];
            costs[s * nh + j] = (if c == 0 { lt + 2.0 } else { lt - log2(c) }) as f32;
        }
    }
    // cost[k]: the cheapest way to arrive here ending with histogram k, minus the cheapest
    // way overall, capped at the switch cost; a cap means a switch here when tracing back.
    let bitmap = nh.div_ceil(8);
    signal.clear();
    signal.resize(len * bitmap, 0);
    let mut cost = vec![0f32; nh];
    for (i, &s) in data.iter().enumerate() {
        let row = &costs[s.into() * nh..][..nh];
        let mut min = f32::INFINITY;
        let mut arg = 0;
        for (k, (c, &r)) in cost.iter_mut().zip(row).enumerate() {
            *c += r;
            if *c < min {
                min = *c;
                arg = k;
            }
        }
        ids[i] = arg as u8;
        let mut sw = switch_cost;
        if i < 2000 {
            // More blocks at the start.
            sw *= 0.77 + 0.07 * i as f64 / 2000.0;
        }
        let sw = sw as f32;
        let sig = &mut signal[i * bitmap..][..bitmap];
        for (k, c) in cost.iter_mut().enumerate() {
            *c -= min;
            if *c >= sw {
                *c = sw;
                sig[k >> 3] |= 1 << (k & 7);
            }
        }
    }
    // Trace back from the end, switching at the marks.
    let mut nblocks = 1;
    let mut cur = ids[len - 1];
    let mut i = len - 1;
    while i > 0 {
        i -= 1;
        if signal[i * bitmap + usize::from(cur >> 3)] & (1 << (cur & 7)) != 0 && cur != ids[i] {
            cur = ids[i];
            nblocks += 1;
        }
        ids[i] = cur;
    }
    nblocks
}

/// Clusters the blocks of `ids` into block types.
fn cluster_blocks<T: Copy + Into<usize>>(
    data: &[T],
    size: usize,
    nblocks: usize,
    ids: &[u8],
) -> BlockSplit {
    const BATCH: usize = 64;
    let mut lens = Vec::with_capacity(nblocks);
    let mut run = 0u32;
    for i in 0..ids.len() {
        run += 1;
        if i + 1 == ids.len() || ids[i] != ids[i + 1] {
            lens.push(run);
            run = 0;
        }
    }
    let nblocks = lens.len();
    let mut tmp = Histo::new(size);
    let mut all: Vec<Histo> = Vec::new();
    let mut all_sizes: Vec<u32> = Vec::new();
    let mut symbols = vec![0u32; nblocks];
    let mut pos = 0;
    for i in (0..nblocks).step_by(BATCH) {
        let k = (nblocks - i).min(BATCH);
        let mut hs: Vec<Histo> = Vec::with_capacity(k);
        for &l in &lens[i..i + k] {
            let mut h = Histo::new(size);
            for &s in &data[pos..pos + l as usize] {
                h.add(s.into());
            }
            pos += l as usize;
            h.cost = population_cost(&h);
            hs.push(h);
        }
        let mut sizes = vec![1u32; k];
        let mut syms: Vec<u32> = (0..k as u32).collect();
        let mut clusters: Vec<u32> = (0..k as u32).collect();
        combine(
            &mut hs,
            &mut tmp,
            &mut sizes,
            &mut syms,
            &mut clusters,
            BATCH,
            BATCH * BATCH / 2,
        );
        let base = all.len() as u32;
        let mut remap = vec![0u32; k];
        for (j, &c) in clusters.iter().enumerate() {
            remap[c as usize] = j as u32;
            all.push(std::mem::replace(&mut hs[c as usize], Histo::new(0)));
            all_sizes.push(sizes[c as usize]);
        }
        for j in 0..k {
            symbols[i + j] = base + remap[syms[j] as usize];
        }
    }
    let nc = all.len();
    let mut clusters: Vec<u32> = (0..nc as u32).collect();
    let max_pairs = (64 * nc).min(nc / 2 * nc);
    combine(
        &mut all,
        &mut tmp,
        &mut all_sizes,
        &mut symbols,
        &mut clusters,
        256,
        max_pairs,
    );
    // Each block to its best type (ties: the previous block's), numbered by first use.
    let mut index = vec![u32::MAX; nc];
    let mut next = 0usize;
    let mut block = Histo::new(size);
    let mut pos = 0;
    for i in 0..nblocks {
        block.clear();
        for &s in &data[pos..pos + lens[i] as usize] {
            block.add(s.into());
        }
        pos += lens[i] as usize;
        let mut best = if i == 0 { symbols[0] } else { symbols[i - 1] };
        let mut best_bits = cost_distance(&block, &all[best as usize], &mut tmp);
        for &c in &clusters {
            let bits = cost_distance(&block, &all[c as usize], &mut tmp);
            if bits < best_bits {
                best_bits = bits;
                best = c;
            }
        }
        symbols[i] = best;
        if index[best as usize] == u32::MAX {
            index[best as usize] = next as u32;
            next += 1;
        }
    }
    let mut out = BlockSplit {
        types: Vec::new(),
        lens: Vec::new(),
        ntypes: next,
    };
    let mut cur = 0u32;
    for i in 0..nblocks {
        cur += lens[i];
        if i + 1 == nblocks || symbols[i] != symbols[i + 1] {
            out.types.push(index[symbols[i] as usize] as u8);
            out.lens.push(cur);
            cur = 0;
        }
    }
    out
}

/// Parameters of [`greedy`] for one category (Google's).
pub(super) struct GreedyParams {
    /// Symbols per block at least.
    min_block: usize,
    /// Bits a block must save to get a type of its own.
    threshold: f64,
}

pub(super) const GREEDY_LITERALS: GreedyParams = GreedyParams {
    min_block: 512,
    threshold: 400.0,
};
pub(super) const GREEDY_COMMANDS: GreedyParams = GreedyParams {
    min_block: 1024,
    threshold: 500.0,
};
pub(super) const GREEDY_DISTANCES: GreedyParams = GreedyParams {
    min_block: 512,
    threshold: 100.0,
};

/// Splits `data` in one pass (Google's greedy `BlockSplitter` of qualities 4..=9): every
/// block of `min_block` symbols (longer after repeated merges) gets a new type if coding it
/// together with either of the last two types would cost `threshold` more bits than apart,
/// else it continues the last block or switches back to the type before. At most `max_types`
/// (up to 256) types.
pub(super) fn greedy<T: Copy + Into<usize>>(
    data: &[T],
    size: usize,
    gp: &GreedyParams,
    max_types: usize,
) -> BlockSplit {
    let mut out = BlockSplit {
        types: Vec::new(),
        lens: Vec::new(),
        ntypes: 0,
    };
    // `histos[t]`: type t's symbols; the last one gathers the current block.
    let mut histos = vec![Histo::new(size)];
    let mut last = [0usize; 2];
    let mut last_entropy = [0f64; 2];
    let mut target = gp.min_block;
    let mut merged = 0;
    let mut combined = [Histo::new(size), Histo::new(size)];
    let mut block = 0usize;
    let mut i = 0;
    while i < data.len() {
        let cur = histos.len() - 1;
        let n = (target - block).min(data.len() - i);
        for &s in &data[i..i + n] {
            histos[cur].add(s.into());
        }
        i += n;
        block += n;
        if block < target && i < data.len() {
            continue;
        }
        let len = block.max(gp.min_block) as u32;
        block = 0;
        if out.lens.is_empty() {
            out.lens.push(len);
            out.types.push(0);
            let e = bits_entropy(&histos[0].h);
            last_entropy = [e, e];
            out.ntypes = 1;
            histos.push(Histo::new(size));
            continue;
        }
        let entropy = bits_entropy(&histos[cur].h);
        let mut diff = [0f64; 2];
        let mut ce = [0f64; 2];
        for j in 0..2 {
            combined[j].set_sum(&histos[cur], &histos[last[j]]);
            ce[j] = bits_entropy(&combined[j].h);
            diff[j] = ce[j] - entropy - last_entropy[j];
        }
        if out.ntypes < max_types && diff[0] > gp.threshold && diff[1] > gp.threshold {
            // A new block type.
            out.lens.push(len);
            out.types.push(out.ntypes as u8);
            last = [out.ntypes, last[0]];
            last_entropy = [entropy, last_entropy[0]];
            out.ntypes += 1;
            histos.push(Histo::new(size));
            merged = 0;
            target = gp.min_block;
        } else if diff[1] < diff[0] - 20.0 {
            // Back to the type before the last.
            out.lens.push(len);
            let t = out.types[out.types.len() - 2];
            out.types.push(t);
            last.swap(0, 1);
            std::mem::swap(&mut histos[last[0]], &mut combined[1]);
            last_entropy = [ce[1], last_entropy[0]];
            histos[cur].clear();
            merged = 0;
            target = gp.min_block;
        } else {
            // The last block goes on.
            if let Some(l) = out.lens.last_mut() {
                *l += len;
            }
            std::mem::swap(&mut histos[last[0]], &mut combined[0]);
            last_entropy[0] = ce[0];
            if out.ntypes == 1 {
                last_entropy[1] = last_entropy[0];
            }
            histos[cur].clear();
            merged += 1;
            if merged > 1 {
                target += gp.min_block;
            }
        }
    }
    if out.ntypes <= 1 {
        return BlockSplit::single();
    }
    out
}

/// `split` if its block types save at least 1% of the estimated bits of `data` (symbols below
/// `size`) with one code, the block switches and the codes of the types included; else one
/// block type.
pub(super) fn paying<T: Copy + Into<usize>>(
    data: &[T],
    size: usize,
    split: BlockSplit,
) -> BlockSplit {
    if split.ntypes == 1 {
        return split;
    }
    let mut all = Histo::new(size);
    let mut types = vec![Histo::new(size); split.ntypes];
    let mut pos = 0;
    for (&t, &l) in split.types.iter().zip(&split.lens) {
        let end = (pos + l as usize).min(data.len());
        for &s in &data[pos..end] {
            types[usize::from(t)].add(s.into());
        }
        pos = end;
    }
    for h in &types {
        all.add_histo(h);
    }
    // A block switch: a type code and a count code with its extra bits, about 8 bits; the
    // codes for them about 64 bits.
    let switches = 8.0 * split.types.len() as f64 + 64.0;
    let apart: f64 = types.iter().map(population_cost).sum::<f64>() + switches;
    if apart < 0.99 * population_cost(&all) {
        split
    } else {
        BlockSplit::single()
    }
}
