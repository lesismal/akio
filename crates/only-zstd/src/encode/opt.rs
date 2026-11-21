//! Optimal parsing for the highest levels: every position's candidate matches from the hash
//! chains, then a shortest path through the block priced with the bit costs of the literals and
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

/// Bit costs of the symbols of a block.
struct Costs {
    lit: [f32; 256],
    ll: [f32; 36],
    ml: [f32; 53],
    of: [f32; 32],
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
        let mut c = Costs {
            lit: [0.0; 256],
            ll: [0.0; 36],
            ml: [0.0; 53],
            of: [0.0; 32],
        };
        from_counts(&h, &mut c.lit);
        from_norm(&LL_DEFAULT_NORM, LL_DEFAULT_LOG, &mut c.ll);
        from_norm(&ML_DEFAULT_NORM, ML_DEFAULT_LOG, &mut c.ml);
        from_norm(&OF_DEFAULT_NORM, OF_DEFAULT_LOG, &mut c.of);
        c
    }

    /// The statistics of a parse.
    fn from_parse(lits: &[u8], seqs: &[Seq]) -> Costs {
        let mut lh = [0u32; 256];
        for &b in lits {
            lh[usize::from(b)] += 1;
        }
        let (mut llh, mut mlh, mut ofh) = ([0u32; 36], [0u32; 53], [0u32; 32]);
        for s in seqs {
            llh[usize::from(ll_code(s.ll))] += 1;
            mlh[usize::from(ml_code(s.ml))] += 1;
            ofh[highbit(s.off) as usize] += 1;
        }
        let mut c = Costs {
            lit: [0.0; 256],
            ll: [0.0; 36],
            ml: [0.0; 53],
            of: [0.0; 32],
        };
        from_counts(&lh, &mut c.lit);
        for x in &mut c.lit {
            *x = x.max(1.0); // Huffman codes are at least a bit long
        }
        from_counts(&llh, &mut c.ll);
        from_counts(&mlh, &mut c.ml);
        from_counts(&ofh, &mut c.of);
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
        self.lit[usize::from(b)] + self.lit_len(ins + 1) - self.lit_len(ins)
    }

    /// The cost of a match of `len` with Offset_Value `off` after literals (whose length code
    /// was paid as they came, from that of no literals).
    #[inline]
    fn seq(&self, _ll: usize, len: usize, off: u32) -> f32 {
        let mlc = usize::from(ml_code(len as u32));
        let ofc = highbit(off);
        self.lit_len(0)
            + self.ml[mlc]
            + f32::from(ML_BITS[mlc])
            + self.of[ofc as usize]
            + ofc as f32
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
            let mut cand = self.head[self.hash(i)] as usize;
            let mut depth = self.p.depth;
            let mut best = MIN_MATCH - 1;
            let first = mlist.len();
            while cand > 0 && depth > 0 {
                let c = cand - 1;
                let dist = i - c;
                if dist > self.window || dist > self.chain_mask {
                    break;
                }
                if d[c + best.min(max - 1)] == d[i + best.min(max - 1)] {
                    let len = self.common(i, c, max);
                    if len > best {
                        best = len;
                        mlist.push((len as u32, dist as u32));
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
            if mlist.len() - first > MAX_CANDIDATES {
                mlist.drain(first..mlist.len() - MAX_CANDIDATES);
            }
            if best >= self.p.nice {
                if let Some(&(l, dist)) = mlist.last() {
                    long = Some((i, l as usize, dist as usize));
                }
            }
        }
        mstart.push(mlist.len() as u32);

        let reps = self.reps;
        let mut costs = Costs::initial(&d[start..end]);
        let mut nodes = Vec::new();
        for pass in 0..passes {
            self.reps = reps;
            self.shortest_path(start, end, &mstart, &mlist, &costs, &mut nodes);
            if pass + 1 < passes {
                costs = Costs::from_parse(&self.lits, &self.seqs);
            }
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
                for l in rep_best + 1..=len.min(ENUM_LENGTHS) {
                    relax(nodes, l, dist, off, node.cost + costs.seq(ins, l, off));
                }
                if len > ENUM_LENGTHS {
                    relax(nodes, len, dist, off, node.cost + costs.seq(ins, len, off));
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
                for l in from..=len.min(ENUM_LENGTHS.max(from)) {
                    relax(nodes, l, dist, off, node.cost + costs.seq(ins, l, off));
                }
                if len > ENUM_LENGTHS {
                    relax(nodes, len, dist, off, node.cost + costs.seq(ins, len, off));
                }
                from = len + 1;
            }
            // A long match is taken whole: the positions inside it are not expanded, which
            // keeps long runs linear.
            if longest.0 >= self.p.nice {
                let (len, dist, off) = longest;
                relax(nodes, len, dist, off, node.cost + costs.seq(ins, len, off));
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
