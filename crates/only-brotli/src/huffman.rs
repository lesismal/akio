//! Prefix codes: decoding tables built from code lengths, and length-limited code lengths and
//! canonical codes for the encoder.

use crate::bits::BitReader;

// ---- Decoding tables -------------------------------------------------------------------------
//
// An entry is a `u32`: bits 0..8 the code length (the bits to consume), bit 8 set for a link to
// a second-level table (then bits 0..8 are that table's index bits), bits 16..32 the symbol (or
// the second-level table's offset). The root table has `ROOT_BITS` index bits; codes are at
// most 15 bits long, so one second level is enough.

pub(crate) const ROOT_BITS: u32 = 8;
const ROOT_SIZE: usize = 1 << ROOT_BITS;
const LINK: u32 = 1 << 8;

const fn entry(sym: u32, len: u32) -> u32 {
    (sym << 16) | len
}

/// A table that decodes symbol `sym` from zero bits.
pub(crate) fn single(sym: usize, out: &mut Vec<u32>) {
    out.clear();
    out.resize(ROOT_SIZE, entry(sym as u32, 0));
}

fn reverse(code: u32, len: u32) -> u32 {
    code.reverse_bits() >> (32 - len)
}

/// Builds the decoding table of the canonical code with lengths `lens` (each 0..=15) into
/// `out`. The code must be complete (the callers check that); a code with a single symbol is
/// built with [`single`] instead.
pub(crate) fn build(lens: &[u8], out: &mut Vec<u32>) {
    let mut count = [0u32; 16];
    for &l in lens {
        count[usize::from(l & 15)] += 1;
    }
    count[0] = 0;
    let mut first = [0u32; 16];
    let mut c = 0u32;
    for len in 1..16 {
        c = (c + count[len - 1]) << 1;
        first[len] = c;
    }
    out.clear();
    out.resize(ROOT_SIZE, entry(0, 0));
    // Second-level table sizes: the longest code under each root index.
    let mut sub = [0u8; ROOT_SIZE];
    let mut next = first;
    for &l in lens {
        let l = u32::from(l & 15);
        if l > ROOT_BITS {
            let code = next[l as usize];
            next[l as usize] += 1;
            let r = reverse(code, l) as usize & (ROOT_SIZE - 1);
            sub[r] = sub[r].max((l - ROOT_BITS) as u8);
        }
    }
    for (r, &sb) in sub.iter().enumerate() {
        if sb != 0 {
            let off = out.len();
            out.resize(off + (1 << sb), entry(0, 0));
            out[r] = (off as u32) << 16 | LINK | u32::from(sb);
        }
    }
    let mut next = first;
    for (sym, &l) in lens.iter().enumerate() {
        let l = u32::from(l & 15);
        if l == 0 {
            continue;
        }
        let code = next[l as usize];
        next[l as usize] += 1;
        let r = reverse(code, l) as usize;
        let e = entry(sym as u32, l);
        if l <= ROOT_BITS {
            for x in out[..ROOT_SIZE].iter_mut().skip(r).step_by(1 << l) {
                *x = e;
            }
        } else {
            let link = out[r & (ROOT_SIZE - 1)];
            let off = (link >> 16) as usize;
            let sb = link & 0xff;
            if let Some(t) = out.get_mut(off..off + (1 << sb)) {
                for x in t
                    .iter_mut()
                    .skip(r >> ROOT_BITS)
                    .step_by(1 << (l - ROOT_BITS))
                {
                    *x = e;
                }
            }
        }
    }
}

/// Decodes one symbol with `table`.
#[inline(always)]
pub(crate) fn decode(table: &[u32], br: &mut BitReader<'_>) -> usize {
    br.refill();
    let bits = br.peek();
    let e = table
        .get((bits as usize) & (ROOT_SIZE - 1))
        .copied()
        .unwrap_or(0);
    if e & LINK == 0 {
        br.consume(e & 0xff);
        return (e >> 16) as usize;
    }
    let sb = e & 0xff;
    let i = (e >> 16) as usize + ((bits >> ROOT_BITS) as usize & ((1 << sb) - 1));
    let e = table.get(i).copied().unwrap_or(0);
    br.consume(e & 0xff);
    (e >> 16) as usize
}

// ---- Encoding --------------------------------------------------------------------------------

/// Code lengths of an optimal prefix code for `hist` with no length above `limit`; symbols
/// with a zero count get length 0. A histogram with a single used symbol gives it length 1.
pub(crate) fn lengths(hist: &[u32], limit: u8, out: &mut Vec<u8>) {
    out.clear();
    out.resize(hist.len(), 0);
    let mut syms: Vec<(u32, u16)> = hist
        .iter()
        .enumerate()
        .filter(|&(_, &c)| c != 0)
        .map(|(s, &c)| (c, s as u16))
        .collect();
    match syms.len() {
        0 => return,
        1 => {
            out[usize::from(syms[0].1)] = 1;
            return;
        }
        _ => {}
    }
    syms.sort_unstable();
    let n = syms.len();
    // Callers have at most 2^limit symbols (704 <= 2^15, 18 <= 2^5), so the loop below ends:
    // once every weight is the same the tree is balanced.
    debug_assert!(n <= 1 << limit);
    // Two-queue Huffman construction; nodes 0..n are leaves (sorted), n.. internal nodes.
    let mut floor = 1u32;
    loop {
        let w = |i: usize| syms[i].0.max(floor);
        let mut weight: Vec<u64> = Vec::with_capacity(2 * n);
        let mut parent: Vec<u32> = vec![0; 2 * n];
        for i in 0..n {
            weight.push(u64::from(w(i)));
        }
        let (mut li, mut ii) = (0usize, n);
        let take = |weight: &Vec<u64>, li: &mut usize, ii: &mut usize| -> usize {
            if *li < n && (*ii >= weight.len() || weight[*li] <= weight[*ii]) {
                *li += 1;
                *li - 1
            } else {
                *ii += 1;
                *ii - 1
            }
        };
        for _ in 0..n - 1 {
            let a = take(&weight, &mut li, &mut ii);
            let b = take(&weight, &mut li, &mut ii);
            let id = weight.len();
            weight.push(weight[a] + weight[b]);
            parent[a] = id as u32;
            parent[b] = id as u32;
        }
        // Depths: the root is the last node.
        let total = weight.len();
        let mut depth = vec![0u8; total];
        let mut max = 0u8;
        for i in (0..total - 1).rev() {
            depth[i] = depth[parent[i] as usize].saturating_add(1);
            if i < n {
                max = max.max(depth[i]);
            }
        }
        if max <= limit {
            for i in 0..n {
                out[usize::from(syms[i].1)] = depth[i];
            }
            return;
        }
        floor = floor.saturating_mul(2);
    }
}

/// Canonical codes for `lens`, bit-reversed for writing least significant bit first.
pub(crate) fn codes(lens: &[u8], out: &mut Vec<u16>) {
    let mut count = [0u32; 16];
    for &l in lens {
        count[usize::from(l & 15)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut c = 0u32;
    for len in 1..16 {
        c = (c + count[len - 1]) << 1;
        next[len] = c;
    }
    out.clear();
    out.extend(lens.iter().map(|&l| {
        let l = u32::from(l & 15);
        if l == 0 {
            return 0;
        }
        let code = next[l as usize];
        next[l as usize] += 1;
        reverse(code, l) as u16
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_lengths_are_complete() {
        // Fibonacci counts force deep trees.
        let mut hist = vec![0u32; 40];
        let (mut a, mut b) = (1u32, 1u32);
        for h in &mut hist {
            *h = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        for limit in [6u8, 7, 15] {
            let mut lens = Vec::new();
            lengths(&hist, limit, &mut lens);
            assert!(lens.iter().all(|&l| l >= 1 && l <= limit));
            let kraft: f64 = lens.iter().map(|&l| 0.5f64.powi(i32::from(l))).sum();
            assert!((kraft - 1.0).abs() < 1e-9, "{limit}: {kraft}");
        }
    }

    #[test]
    fn table_round_trip() {
        let hist: Vec<u32> = (0..300u32).map(|i| (i * 7919) % 1000 + 1).collect();
        let mut lens = Vec::new();
        lengths(&hist, 15, &mut lens);
        let mut cs = Vec::new();
        codes(&lens, &mut cs);
        let mut table = Vec::new();
        build(&lens, &mut table);
        let mut w = crate::bits::BitWriter::with_capacity(1000);
        for s in 0..300 {
            w.bits(u32::from(lens[s]), u64::from(cs[s]));
        }
        let buf = w.finish();
        let mut br = BitReader::new(&buf);
        for s in 0..300 {
            assert_eq!(decode(&table, &mut br), s);
        }
    }
}
