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

/// Appends to `out` a table that decodes symbol `sym` from zero bits.
pub(crate) fn single(sym: usize, out: &mut Vec<u32>) {
    out.resize(out.len() + ROOT_SIZE, entry(sym as u32, 0));
}

fn reverse(code: u32, len: u32) -> u32 {
    code.reverse_bits() >> (32 - len)
}

/// Bits of each byte in reverse order (x86-64 has no instruction for it).
const REV8: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = (i as u8).reverse_bits();
        i += 1;
    }
    t
};

/// `code` (at most 15 bits long, `len` of them) bit-reversed.
#[inline(always)]
fn reverse15(code: u32, len: u32) -> usize {
    let r = (u32::from(REV8[(code & 0xff) as usize]) << 8)
        | u32::from(REV8[(code >> 8) as usize & 0xff]);
    (r >> (16 - len)) as usize
}

/// The code lengths of a prefix code as they are read: the symbols with a non-zero length in
/// symbol order and the number of codes of each length, so that [`Lengths::build`] needs no
/// pass over the symbols without a code.
#[derive(Default)]
pub(crate) struct Lengths {
    /// `(symbol, length)` in symbol order, lengths 1..=15.
    pairs: Vec<(u16, u8)>,
    count: [u16; 16],
    /// Scratch: symbols sorted by length, then symbol.
    sorted: Vec<u16>,
}

impl Lengths {
    pub(crate) fn clear(&mut self) {
        self.pairs.clear();
        self.count = [0; 16];
    }

    /// Gives `sym` (greater than the symbols pushed before) the length `len` (1..=15).
    #[inline(always)]
    pub(crate) fn push(&mut self, sym: usize, len: u8) {
        self.pairs.push((sym as u16, len));
        self.count[usize::from(len & 15)] += 1;
    }

    /// Gives symbols `sym..sym + n` the length `len` (1..=15).
    pub(crate) fn push_run(&mut self, sym: usize, n: usize, len: u8) {
        self.pairs.extend((sym..sym + n).map(|s| (s as u16, len)));
        self.count[usize::from(len & 15)] += n as u16;
    }

    /// Appends to `out` the decoding table of the canonical code with these lengths; links to
    /// second-level tables are relative to the table's start. The code must be complete (the
    /// callers check that); a code with a single symbol is built with [`single`] instead.
    pub(crate) fn build(&mut self, out: &mut Vec<u32>) {
        let mut count = self.count;
        count[0] = 0;
        // The first canonical code of each length.
        let mut next = [0u32; 16];
        let mut c = 0u32;
        for len in 1..16 {
            c = (c + u32::from(count[len - 1])) << 1;
            next[len] = c;
        }
        let first_long = next[ROOT_BITS as usize + 1];
        let long = count[ROOT_BITS as usize + 1..].iter().any(|&n| n != 0);
        let base = out.len();
        out.resize(base + ROOT_SIZE, entry(0, 0));
        let Some(root) = out
            .get_mut(base..base + ROOT_SIZE)
            .and_then(|r| <&mut [u32; ROOT_SIZE]>::try_from(r).ok())
        else {
            return;
        };
        // Codes of up to `ROOT_BITS` go straight to the root, in symbol order; longer ones are
        // sorted by length (then symbol) for the second level.
        let mut long_next = [0u16; 16];
        if long {
            for len in ROOT_BITS as usize + 1..15 {
                long_next[len + 1] = long_next[len] + count[len];
            }
            self.sorted.clear();
            self.sorted.resize(
                count[ROOT_BITS as usize + 1..]
                    .iter()
                    .map(|&n| usize::from(n))
                    .sum(),
                0,
            );
        }
        for &(sym, len) in &self.pairs {
            let len = u32::from(len & 15);
            if len <= ROOT_BITS {
                let code = &mut next[len as usize];
                let e = entry(u32::from(sym), len);
                let mut i = reverse15(*code, len);
                *code += 1;
                while i < ROOT_SIZE {
                    root[i] = e;
                    i += 1 << len;
                }
            } else {
                let k = &mut long_next[len as usize];
                if let Some(x) = self.sorted.get_mut(usize::from(*k)) {
                    *x = sym;
                }
                *k += 1;
            }
        }
        if !long {
            return;
        }
        // Longer codes: a second-level table per root index, as large as the codes under it
        // need (they come in one run each, in canonical order).
        let mut syms = self.sorted.iter().map(|&s| u32::from(s));
        let mut code = first_long;
        let mut low = usize::MAX;
        let (mut sub, mut sub_bits) = (0usize, 0u32);
        for len in ROOT_BITS + 1..16 {
            while count[len as usize] > 0 {
                let r = reverse15(code, len);
                if r & (ROOT_SIZE - 1) != low {
                    low = r & (ROOT_SIZE - 1);
                    sub_bits = next_table_bits(&count, len);
                    sub = out.len() - base;
                    out.resize(out.len() + (1 << sub_bits), entry(0, 0));
                    out[base + low] = (sub as u32) << 16 | LINK | sub_bits;
                }
                let e = entry(syms.next().unwrap_or(0), len);
                if let Some(t) = out.get_mut(base + sub..base + sub + (1 << sub_bits)) {
                    let mut i = r >> ROOT_BITS;
                    while i < t.len() {
                        t[i] = e;
                        i += 1 << (len - ROOT_BITS);
                    }
                }
                count[len as usize] -= 1;
                code += 1;
            }
            code <<= 1;
        }
    }
}

/// The decoding table of the code length code (RFC 7932 section 3.5: lengths of at most 5
/// bits, `lens` indexed by code length symbol), indexed by the next 5 bits; entries as in the
/// other tables. A code with a single symbol decodes it from zero bits.
pub(crate) fn code_length_table(lens: &[u8; 18]) -> [u32; 32] {
    let mut count = [0u32; 6];
    for &l in lens {
        count[usize::from(l).min(5)] += 1;
    }
    count[0] = 0;
    if count.iter().sum::<u32>() == 1 {
        let s = lens.iter().position(|&l| l != 0).unwrap_or(0);
        return [entry(s as u32, 0); 32];
    }
    let mut next = [0u32; 6];
    let mut c = 0u32;
    for len in 1..6 {
        c = (c + count[len - 1]) << 1;
        next[len] = c;
    }
    let mut t = [entry(0, 0); 32];
    for (sym, &l) in lens.iter().enumerate() {
        let l = u32::from(l).min(5);
        if l == 0 {
            continue;
        }
        let code = next[l as usize];
        next[l as usize] += 1;
        let mut i = reverse15(code, l);
        while i < 32 {
            t[i] = entry(sym as u32, l);
            i += 1 << l;
        }
    }
    t
}

/// Index bits of the second-level table that starts with a code of length `len`, given the
/// codes of each length still to place (`count`, from `len` on): enough for all the codes that
/// share its root index (Google's `NextTableBitSize`).
fn next_table_bits(count: &[u16; 16], mut len: u32) -> u32 {
    let mut left = 1i32 << (len - ROOT_BITS);
    while len < 15 {
        left -= i32::from(count[len as usize]);
        if left <= 0 {
            break;
        }
        len += 1;
        left <<= 1;
    }
    len - ROOT_BITS
}

/// Appends to `out` the decoding table of the canonical code with lengths `lens` (each
/// 0..=15); see [`Lengths::build`].
#[cfg(test)]
pub(crate) fn build(lens: &[u8], out: &mut Vec<u32>) {
    let mut l = Lengths::default();
    for (s, &n) in lens.iter().enumerate() {
        if n != 0 {
            l.push(s, n);
        }
    }
    l.build(out);
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

/// Decodes one symbol with the table at `start` in `tables` from the loaded bits:
/// [`BitReader::refill`] must have run, and at most 57 bits (three 15-bit codes, say) be
/// consumed before the next one. One bounds check per level.
#[inline(always)]
pub(crate) fn decode_loaded_at(tables: &[u32], start: usize, br: &mut BitReader<'_>) -> usize {
    let bits = br.peek();
    let e = tables
        .get(start + ((bits as usize) & (ROOT_SIZE - 1)))
        .copied()
        .unwrap_or(0);
    if e & LINK == 0 {
        br.consume_loaded(e & 0xff);
        return (e >> 16) as usize;
    }
    let sb = e & 0xff;
    let i = start + (e >> 16) as usize + ((bits >> ROOT_BITS) as usize & ((1 << sb) - 1));
    let e = tables.get(i).copied().unwrap_or(0);
    br.consume_loaded(e & 0xff);
    (e >> 16) as usize
}

/// A zero table, for trees that do not exist (which the decoder never asks for).
static EMPTY: [u32; ROOT_SIZE] = [0; ROOT_SIZE];

/// One decoding table: its root, of fixed size so that root lookups need no bounds check, and
/// the whole table for second-level lookups.
#[derive(Clone, Copy)]
pub(crate) struct Tree<'a> {
    root: &'a [u32; ROOT_SIZE],
    all: &'a [u32],
}

impl<'a> Tree<'a> {
    /// The table at `start` in `tables`.
    pub(crate) fn at(tables: &'a [u32], start: usize) -> Self {
        let all = tables.get(start..).unwrap_or(&[]);
        let root = all
            .get(..ROOT_SIZE)
            .and_then(|r| r.try_into().ok())
            .unwrap_or(&EMPTY);
        Tree { root, all }
    }

    /// Decodes one symbol from the loaded bits: [`BitReader::refill`] must have run, and at
    /// most 57 bits (three 15-bit codes, say) be consumed before the next one.
    #[inline(always)]
    pub(crate) fn decode_loaded(self, br: &mut BitReader<'_>) -> usize {
        let bits = br.peek();
        let e = self.root[(bits as usize) & (ROOT_SIZE - 1)];
        if e & LINK == 0 {
            br.consume_loaded(e & 0xff);
            return (e >> 16) as usize;
        }
        let sb = e & 0xff;
        let i = (e >> 16) as usize + ((bits >> ROOT_BITS) as usize & ((1 << sb) - 1));
        let e = self.all.get(i).copied().unwrap_or(0);
        br.consume_loaded(e & 0xff);
        (e >> 16) as usize
    }
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
