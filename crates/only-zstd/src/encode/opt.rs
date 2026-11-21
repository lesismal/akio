//! Optimal parsing for the highest levels: every position's candidate matches from binary
//! trees of suffixes (libzstd's `bt` match finder), then a shortest path through the block priced with the bit costs of the literals and
//! of the literal length, match length and offset codes (estimated at first, then taken from
//! the previous pass), with the repeat offsets followed along each path, as libzstd's `btopt`
//! and `btultra` do.

use super::{Encoder, MIN_MATCH, Seq, offset_value, update_reps};
use crate::tables::{
    LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM,
    OF_DEFAULT_LOG, OF_DEFAULT_NORM, highbit, ll_code, ml_code,
};

/// Lengths of one match the search tries one by one; longer ones only at their full length.
const ENUM_LENGTHS: usize = 64;

/// Candidates kept per position (the longest ones).
const MAX_CANDIDATES: usize = 16;

/// Suffixes are compared this far in the binary trees; equal beyond it counts as the end of
/// the data (the subtrees below are dropped), which bounds long runs.
const BT_CAP: usize = 4096;

/// Symbol counts of a parse.
pub(super) struct Stats {
    lit: [u32; 256],
    ll: [u32; 36],
    ml: [u32; 53],
    of: [u32; 32],
}

impl Stats {
    fn from_parse(lits: &[u8], seqs: &[Seq]) -> Box<Stats> {
        let mut st = Box::new(Stats {
            lit: [0; 256],
            ll: [0; 36],
            ml: [0; 53],
            of: [0; 32],
        });
        for &b in lits {
            st.lit[usize::from(b)] += 1;
        }
        for s in seqs {
            st.ll[usize::from(ll_code(s.ll))] += 1;
            st.ml[usize::from(ml_code(s.ml))] += 1;
            st.of[highbit(s.off) as usize] += 1;
        }
        st
    }
}

/// Bit costs of the symbols of a block.
struct Costs {
    lit: [f32; 256],
    ll: [f32; 36],
    ml: [f32; 53],
    of: [f32; 32],
    /// Match length prices up to [`ENUM_LENGTHS`], with the literal length code of no
    /// literals (see [`Costs::seq`]).
    mlp: [f32; ENUM_LENGTHS + 1],
    /// What one more literal costs in literal length code after `i` (for `i` below 64).
    lld: [f32; 64],
}

/// Costs from counts: `log2(total / count)`, a little more than the rarest for unseen ones.
fn from_counts(counts: &[u32], out: &mut [f32]) {
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let lt = (total.max(1) as f32).log2();
    for (o, &c) in out.iter_mut().zip(counts) {
        *o = if c == 0 {
            lt + 2.0
        } else {
            (lt - (c as f32).log2()).max(0.5)
        };
    }
}

/// Costs from a predefined distribution (for symbols it has).
fn from_norm(norm: &[i16], log: u32, out: &mut [f32]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = match norm.get(i) {
            Some(&n) if n > 0 => log as f32 - f32::from(n).log2(),
            Some(_) => log as f32,
            None => log as f32 + 2.0,
        };
    }
}

impl Costs {
    /// A first estimate: the block's byte frequencies, the predefined distributions.
    fn initial(block: &[u8]) -> Costs {
        let mut h = [0u32; 256];
        for &b in block {
            h[usize::from(b)] += 1;
        }
        let mut c = Costs::empty();
        from_counts(&h, &mut c.lit);
        from_norm(&LL_DEFAULT_NORM, LL_DEFAULT_LOG, &mut c.ll);
        from_norm(&ML_DEFAULT_NORM, ML_DEFAULT_LOG, &mut c.ml);
        from_norm(&OF_DEFAULT_NORM, OF_DEFAULT_LOG, &mut c.of);
        c.finish();
        c
    }

    fn empty() -> Costs {
        Costs {
            lit: [0.0; 256],
            ll: [0.0; 36],
            ml: [0.0; 53],
            of: [0.0; 32],
            mlp: [0.0; ENUM_LENGTHS + 1],
            lld: [0.0; 64],
        }
    }

    /// Fills the price tables from the symbol costs.
    fn finish(&mut self) {
        let ll0 = self.lit_len(0);
        for len in MIN_MATCH.min(3)..=ENUM_LENGTHS {
            self.mlp[len] = ll0 + self.ml_cost(len);
        }
        for i in 0..64 {
            self.lld[i] = self.lit_len(i + 1) - self.lit_len(i);
        }
    }

    #[inline]
    fn ml_cost(&self, len: usize) -> f32 {
        let mlc = usize::from(ml_code(len as u32));
        self.ml[mlc] + f32::from(ML_BITS[mlc])
    }

    /// The cost of Offset_Value `off`.
    #[inline]
    fn off(&self, off: u32) -> f32 {
        let ofc = highbit(off);
        self.of[ofc as usize] + ofc as f32
    }

    /// Costs from the statistics of a parse.
    fn from_stats(st: &Stats) -> Costs {
        let mut c = Costs::empty();
        from_counts(&st.lit, &mut c.lit);
        for x in &mut c.lit {
            *x = x.max(1.0); // Huffman codes are at least a bit long
        }
        from_counts(&st.ll, &mut c.ll);
        from_counts(&st.ml, &mut c.ml);
        from_counts(&st.of, &mut c.of);
        c.finish();
        c
    }

    /// The cost of the literal length code of `ll` literals.
    #[inline]
    fn lit_len(&self, ll: usize) -> f32 {
        let llc = usize::from(ll_code(ll as u32));
        self.ll[llc] + f32::from(LL_BITS[llc])
    }

    /// The cost of one more literal, `b`, after `ins`: the literal and what its literal
    /// length code costs more (paths are compared with the literal lengths they have so far
    /// already paid for, as libzstd prices them).
    #[inline]
    fn literal(&self, b: u8, ins: usize) -> f32 {
        let ll = match self.lld.get(ins) {
            Some(&x) => x,
            None => self.lit_len(ins + 1) - self.lit_len(ins),
        };
        self.lit[usize::from(b)] + ll
    }

    /// The cost of a match of `len` after literals (whose length code was paid as they came,
    /// from that of no literals), without its offset ([`Costs::off`]).
    #[inline]
    fn seq(&self, len: usize) -> f32 {
        match self.mlp.get(len) {
            Some(&x) => x,
            None => self.lit_len(0) + self.ml_cost(len),
        }
    }
}

#[derive(Clone, Copy)]
struct Node {
    cost: f32,
    prev: u32,
    /// Match length of the step into this node (0: a literal).
    len: u32,
    dist: u32,
    /// Literals since the last match.
    ins: u32,
    reps: [u32; 3],
}

impl Encoder<'_> {
    /// Enters `pos` into the binary tree of its hash, as libzstd's `ZSTD_insertBt1`: `head`
    /// holds the root, the most recent position, and `chain` two links per position, to the
    /// subtrees of the older positions whose suffixes sort before and after it. The walk
    /// from the root re-links the tree around `pos` (which becomes the root), at most `depth`
    /// nodes, comparing each suffix from the shorter of the lengths already shared on either
    /// side. With `found`, each match longer than all closer ones is added (lengths limited to
    /// `max`). Returns the longest length seen.
    pub(super) fn bt_insert(
        &mut self,
        pos: usize,
        max: usize,
        mut found: Option<&mut Vec<(u32, u32)>>,
    ) -> usize {
        let d = self.data;
        let mask = self.chain_mask;
        let limit = (d.len() - pos).min(BT_CAP);
        let maxdist = mask.min(self.window);
        let h = self.hash(pos);
        let mut m = self.head[h] as usize;
        self.head[h] = pos as u32 + 1;
        let mut smaller = Some(2 * (pos & mask));
        let mut larger = Some(2 * (pos & mask) + 1);
        let (mut same_s, mut same_l) = (0, 0);
        let mut best = 0;
        let mut recorded = MIN_MATCH - 1;
        let mut depth = self.p.depth;
        while m > 0 && depth > 0 {
            let c = m - 1;
            let dist = pos - c;
            if c >= pos || dist > maxdist {
                break;
            }
            depth -= 1;
            let node = 2 * (c & mask);
            let mut len = same_s.min(same_l);
            len += self.common(pos + len, c + len, limit - len);
            if len > best {
                best = len;
                if let Some(f) = found.as_deref_mut() {
                    let full = if len == limit && len < max {
                        len + self.common(pos + len, c + len, max - len)
                    } else {
                        len.min(max)
                    };
                    if full > recorded {
                        recorded = full;
                        f.push((full as u32, dist as u32));
                    }
                }
            }
            if len == limit {
                break; // order unknown: the subtrees below are dropped
            }
            if d[c + len] < d[pos + len] {
                if let Some(s) = smaller {
                    self.chain[s] = m as u32;
                }
                same_s = len;
                smaller = Some(node + 1);
                m = self.chain[node + 1] as usize;
            } else {
                if let Some(l) = larger {
                    self.chain[l] = m as u32;
                }
                same_l = len;
                larger = Some(node);
                m = self.chain[node] as usize;
            }
        }
        for slot in [smaller, larger].into_iter().flatten() {
            self.chain[slot] = 0;
        }
        best
    }

    /// Finds the sequences of `[start, end)` into `self.lits` / `self.seqs` by optimal parsing
    /// in `passes` passes.
    pub(super) fn parse_optimal(&mut self, start: usize, end: usize, passes: u32) {
        let d = self.data;
        let n = end - start;
        // Candidate matches of every position: increasing lengths at increasing distances.
        let mut mstart: Vec<u32> = Vec::with_capacity(n + 1);
        let mut mlist: Vec<(u32, u32)> = Vec::new();
        let mut long: Option<(usize, usize, usize)> = None; // pos, len, dist
        for i in start..end {
            mstart.push(mlist.len() as u32);
            if let Some((p, l, dist)) = long {
                if i + 8 < p + l {
                    // Inside a long match: its continuation is the only candidate.
                    let left = (p + l - i).min(end - i);
                    mlist.push((left as u32, dist as u32));
                    continue;
                }
                long = None;
            }
            let max = end - i;
            if max < MIN_MATCH {
                continue;
            }
            self.insert_to(i);
            if self.inserted > i {
                continue; // skipped after a long match, as libzstd does
            }
            let first = mlist.len();
            self.bt_insert(i, max, Some(&mut mlist));
            self.inserted = i + 1;
            if mlist.len() - first > MAX_CANDIDATES {
                mlist.drain(first..mlist.len() - MAX_CANDIDATES);
            }
            let best = if mlist.len() > first {
                mlist[mlist.len() - 1].0 as usize
            } else {
                0
            };
            if best >= self.p.nice {
                let (l, dist) = mlist[mlist.len() - 1];
                long = Some((i, l as usize, dist as usize));
            }
        }
        mstart.push(mlist.len() as u32);

        // The first pass is priced with the previous block's statistics (libzstd carries them
        // over too), the first block's with estimates, so it gets at least two; further passes
        // with their own.
        let passes = if self.stats.is_none() {
            passes.max(2)
        } else {
            passes
        };
        let reps = self.reps;
        let mut costs = match &self.stats {
            Some(st) => Costs::from_stats(st),
            None => Costs::initial(&d[start..end]),
        };
        let mut nodes = Vec::new();
        for pass in 0..passes {
            self.reps = reps;
            self.shortest_path(start, end, &mstart, &mlist, &costs, &mut nodes);
            let st = Stats::from_parse(&self.lits, &self.seqs);
            if pass + 1 < passes {
                costs = Costs::from_stats(&st);
            }
            self.stats = Some(st);
        }
    }

    /// One pass: the cheapest parse of `[start, end)` under `costs`, into `self.lits` /
    /// `self.seqs` (and `self.reps` moved on).
    fn shortest_path(
        &mut self,
        start: usize,
        end: usize,
        mstart: &[u32],
        mlist: &[(u32, u32)],
        costs: &Costs,
        nodes: &mut Vec<Node>,
    ) {
        let d = self.data;
        let n = end - start;
        nodes.clear();
        nodes.resize(
            n + 1,
            Node {
                cost: f32::INFINITY,
                prev: 0,
                len: 0,
                dist: 0,
                ins: 0,
                reps: [0; 3],
            },
        );
        nodes[0].cost = 0.0;
        nodes[0].reps = self.reps;
        let mut skip_to = 0;
        for i in 0..n {
            let node = nodes[i];
            if !node.cost.is_finite() || i < skip_to {
                continue;
            }
            let pos = start + i;
            let c = node.cost + costs.literal(d[pos], node.ins as usize);
            if c < nodes[i + 1].cost {
                nodes[i + 1] = Node {
                    cost: c,
                    prev: i as u32,
                    len: 0,
                    dist: 0,
                    ins: node.ins + 1,
                    reps: node.reps,
                };
            }
            let max = n - i;
            if max < 3 {
                continue;
            }
            let ins = node.ins as usize;
            let ll0 = ins == 0;
            let relax = |nodes: &mut [Node], len: usize, dist: usize, off: u32, cost: f32| {
                let j = i + len;
                if cost < nodes[j].cost {
                    let mut r = node.reps;
                    update_reps(&mut r, off, dist, ll0);
                    nodes[j] = Node {
                        cost,
                        prev: i as u32,
                        len: len as u32,
                        dist: dist as u32,
                        ins: 0,
                        reps: r,
                    };
                }
            };
            // Repeat offsets: lengths a cheaper one already covers are skipped.
            let mut rep_best = 2;
            let mut longest = (0usize, 0usize, 0u32); // len, dist, offset value
            for k in 0..3u32 {
                let r = node.reps;
                let dist = if ll0 {
                    match k {
                        0 => r[1] as usize,
                        1 => r[2] as usize,
                        _ => (r[0] as usize).wrapping_sub(1),
                    }
                } else {
                    r[k as usize] as usize
                };
                if dist == 0 || dist > pos || dist > self.window {
                    continue;
                }
                let len = self.common(pos, pos - dist, max);
                if len <= rep_best {
                    continue;
                }
                let off = k + 1;
                if len > longest.0 {
                    longest = (len, dist, off);
                }
                let base = node.cost + costs.off(off);
                for l in rep_best + 1..=len.min(ENUM_LENGTHS) {
                    relax(nodes, l, dist, off, base + costs.mlp[l]);
                }
                if len > ENUM_LENGTHS {
                    relax(nodes, len, dist, off, base + costs.seq(len));
                }
                rep_best = len;
            }
            // Hash chain matches.
            let (a, b) = (mstart[i] as usize, mstart[i + 1] as usize);
            let mut from = (rep_best + 1).max(MIN_MATCH);
            for &(len, dist) in mlist.get(a..b).unwrap_or(&[]) {
                let (len, dist) = ((len as usize).min(max), dist as usize);
                if len < from {
                    continue;
                }
                let off = offset_value(dist, ll0, &node.reps);
                if len > longest.0 {
                    longest = (len, dist, off);
                }
                let base = node.cost + costs.off(off);
                for l in from..=len.min(ENUM_LENGTHS.max(from)) {
                    relax(nodes, l, dist, off, base + costs.seq(l));
                }
                if len > ENUM_LENGTHS {
                    relax(nodes, len, dist, off, base + costs.seq(len));
                }
                from = len + 1;
            }
            // A long match is taken whole: the positions inside it are not expanded, which
            // keeps long runs linear.
            if longest.0 >= self.p.nice {
                let (len, dist, off) = longest;
                relax(
                    nodes,
                    len,
                    dist,
                    off,
                    node.cost + costs.off(off) + costs.seq(len),
                );
                skip_to = i + len;
            }
        }
        // Walk back, then emit forwards.
        let mut steps = Vec::new();
        let mut j = n;
        while j > 0 {
            let nd = nodes[j];
            if nd.len > 0 {
                steps.push((nd.prev as usize, nd.len as usize, nd.dist as usize));
            }
            j = nd.prev as usize;
        }
        self.lits.clear();
        self.seqs.clear();
        let mut anchor = start;
        for &(p, len, dist) in steps.iter().rev() {
            self.emit(anchor, start + p, len, dist);
            anchor = start + p + len;
        }
        self.lits.extend_from_slice(&d[anchor..end]);
        // Positions past the block's last match are entered later, as in the other parsers.
    }
}
