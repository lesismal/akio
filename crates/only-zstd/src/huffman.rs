//! Huffman coding of literals: tree descriptions (weights), decoding tables and streams, and the
//! encoder's length-limited codes.

use crate::Error;
use crate::bits::{BackReader, BitWriter};
use crate::fse;
use crate::tables::highbit;

/// A decoding table: `1 << log` entries of `symbol | code_length << 8`.
#[derive(Debug, Default)]
pub(crate) struct DTable {
    log: u32,
    entries: Vec<u16>,
}

/// Reads a Huffman tree description into `table` (libzstd's `HUF_readStats` checks: weights up
/// to 12, a total that the implied last weight completes to a power of two, an even number of
/// codes of the longest length). Returns the size of the description.
pub(crate) fn read_table(src: &[u8], table: &mut DTable) -> Option<usize> {
    let &head = src.first()?;
    let mut w = [0u8; 258];
    let (count, size) = if head >= 128 {
        // Direct: 4 bits per weight.
        let count = usize::from(head) - 127;
        let bytes = count.div_ceil(2);
        if bytes + 1 > src.len() {
            return None;
        }
        for n in (0..count).step_by(2) {
            let b = src[1 + n / 2];
            w[n] = b >> 4;
            w[n + 1] = b & 15;
        }
        (count, bytes + 1)
    } else {
        let bytes = usize::from(head);
        if bytes + 1 > src.len() {
            return None;
        }
        let mut buf = [0u8; 256];
        let count = fse::decode_weights(&src[1..=bytes], &mut buf)?;
        w[..count].copy_from_slice(&buf[..count]);
        (count, bytes + 1)
    };
    let mut rank = [0u32; 13];
    let mut total = 0u32;
    for &x in &w[..count] {
        if x > 12 {
            return None;
        }
        rank[usize::from(x)] += 1;
        total += (1 << x) >> 1;
    }
    if total == 0 {
        return None;
    }
    let log = highbit(total) + 1;
    if log > 12 {
        return None;
    }
    let rest = (1u32 << log) - total;
    if rest != 1 << highbit(rest) {
        return None;
    }
    let last = highbit(rest) + 1;
    w[count] = last as u8;
    rank[last as usize] += 1;
    if rank[1] < 2 || rank[1] & 1 == 1 {
        return None;
    }
    let nsym = count + 1;
    // Codes in order of weight (longest first), then of symbol.
    let mut start = [0usize; 14];
    for wt in 1..=log as usize {
        start[wt + 1] = start[wt] + ((rank[wt] as usize) << (wt - 1));
    }
    table.log = log;
    // Only the first `1 << log` entries are used (and all of them are written below).
    if table.entries.len() < TABLE_SIZE {
        table.entries.resize(TABLE_SIZE, 0);
    }
    for (s, &wt) in w[..nsym].iter().enumerate() {
        if wt == 0 {
            continue;
        }
        let wt = usize::from(wt);
        let len = 1usize << (wt - 1);
        let e = s as u16 | ((log as u16 + 1 - wt as u16) << 8);
        table.entries[start[wt]..start[wt] + len].fill(e);
        start[wt] += len;
    }
    Some(size)
}

/// Size of the decoding table: codes are at most 12 bits long (`read_table` checks it), and a
/// table of `1 << log` entries is stored at the start of a table of this size so that lookups
/// need no bounds checks.
const TABLE_SIZE: usize = 1 << 12;

/// Decodes one symbol: the entry of the next `log` bits.
#[inline(always)]
fn step(e: &[u16; TABLE_SIZE], br: &mut BackReader<'_>, log: u32) -> u8 {
    let v = e[br.peek_fast(log) as usize & (TABLE_SIZE - 1)];
    br.consume(u32::from(v >> 8));
    v as u8
}

/// Decodes the symbols of `out` from `br`, which must then be exactly at the end of its
/// stream. Four symbols take at most 48 bits, so one reload covers them.
fn finish_stream(
    e: &[u16; TABLE_SIZE],
    log: u32,
    mut br: BackReader<'_>,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut chunks = out.chunks_exact_mut(4);
    for c in &mut chunks {
        br.reload();
        if br.overflowed() {
            return Err(Error::BadHuffmanStream);
        }
        for x in c {
            *x = step(e, &mut br, log);
        }
    }
    br.reload();
    for x in chunks.into_remainder() {
        *x = step(e, &mut br, log);
    }
    if br.finished() {
        Ok(())
    } else {
        Err(Error::BadHuffmanStream)
    }
}

fn entries(t: &DTable) -> Result<&[u16; TABLE_SIZE], Error> {
    t.entries
        .get(..TABLE_SIZE)
        .and_then(|e| e.try_into().ok())
        .ok_or(Error::BadHuffmanTable)
}

/// Decodes the literals of one stream (`four == false`) or of four streams behind a jump table.
pub(crate) fn decode(t: &DTable, src: &[u8], out: &mut [u8], four: bool) -> Result<(), Error> {
    let e = entries(t)?;
    let log = t.log;
    if !four {
        let br = BackReader::new(src).ok_or(Error::BadHuffmanStream)?;
        return finish_stream(e, log, br, out);
    }
    if src.len() < 10 {
        return Err(Error::BadLiterals);
    }
    let l1 = usize::from(u16::from_le_bytes([src[0], src[1]]));
    let l2 = usize::from(u16::from_le_bytes([src[2], src[3]]));
    let l3 = usize::from(u16::from_le_bytes([src[4], src[5]]));
    if 6 + l1 + l2 + l3 > src.len() {
        return Err(Error::BadLiterals);
    }
    let seg = out.len().div_ceil(4);
    // With at least 6 symbols (checked by the caller) the fourth segment is not negative.
    let (o1, rest) = out.split_at_mut(seg.min(out.len()));
    let (o2, rest) = rest.split_at_mut(seg.min(rest.len()));
    let (o3, o4) = rest.split_at_mut(seg.min(rest.len()));
    let (s1, rest) = src[6..].split_at(l1);
    let (s2, rest) = rest.split_at(l2);
    let (s3, s4) = rest.split_at(l3);
    let mut r1 = BackReader::new(s1).ok_or(Error::BadHuffmanStream)?;
    let mut r2 = BackReader::new(s2).ok_or(Error::BadHuffmanStream)?;
    let mut r3 = BackReader::new(s3).ok_or(Error::BadHuffmanStream)?;
    let mut r4 = BackReader::new(s4).ok_or(Error::BadHuffmanStream)?;
    // The four streams in lockstep, four symbols each per round, as long as the shortest
    // segment (the fourth) lasts; bits read past the end of a stream are caught by the checks
    // of `finish_stream`.
    let rounds = o4.len() / 4;
    for (((c1, c2), c3), c4) in o1
        .chunks_exact_mut(4)
        .zip(o2.chunks_exact_mut(4))
        .zip(o3.chunks_exact_mut(4))
        .zip(o4.chunks_exact_mut(4))
        .take(rounds)
    {
        r1.reload();
        r2.reload();
        r3.reload();
        r4.reload();
        for k in 0..4 {
            c1[k] = step(e, &mut r1, log);
            c2[k] = step(e, &mut r2, log);
            c3[k] = step(e, &mut r3, log);
            c4[k] = step(e, &mut r4, log);
        }
    }
    let done = rounds * 4;
    finish_stream(e, log, r1, &mut o1[done..])?;
    finish_stream(e, log, r2, &mut o2[done..])?;
    finish_stream(e, log, r3, &mut o3[done..])?;
    finish_stream(e, log, r4, &mut o4[done..])
}

// ---------------------------------------------------------------------------------------------
// Encoder side.

/// Code lengths of at most `limit` bits, optimal for `counts`: a plain Huffman code when it
/// stays within the limit, else package-merge. At least two symbols must be present. The code
/// is complete.
fn limited_lengths(counts: &[u32; 256], limit: u32) -> [u8; 256] {
    huffman_lengths(counts, limit).unwrap_or_else(|| package_merge(counts, limit))
}

/// The code lengths of a Huffman code for `counts` (at least two symbols present), built with
/// two queues; `None` when one is longer than `limit`.
fn huffman_lengths(counts: &[u32; 256], limit: u32) -> Option<[u8; 256]> {
    // Leaves sorted by count (then symbol): count << 8 | symbol.
    let mut leaves = [0u64; 256];
    let mut n = 0;
    for (s, &c) in counts.iter().enumerate() {
        if c > 0 {
            leaves[n] = u64::from(c) << 8 | s as u64;
            n += 1;
        }
    }
    let leaves = &mut leaves[..n];
    leaves.sort_unstable();
    // Nodes 0..n are the leaves, n.. the internal nodes in order of creation.
    let mut weight = [0u64; 512];
    let mut parent = [0u16; 512];
    for (w, l) in weight.iter_mut().zip(leaves.iter()) {
        *w = l >> 8;
    }
    let (mut li, mut ii, mut next) = (0usize, n, n);
    let mut take = |weight: &[u64; 512], next: usize| {
        if li < n && (ii >= next || weight[li] <= weight[ii]) {
            li += 1;
            li - 1
        } else {
            ii += 1;
            ii - 1
        }
    };
    for _ in 0..n - 1 {
        let a = take(&weight, next);
        let b = take(&weight, next);
        weight[next] = weight[a] + weight[b];
        parent[a] = next as u16;
        parent[b] = next as u16;
        next += 1;
    }
    // Depths, from the root (the last node) down.
    let mut depth = [0u8; 512];
    let mut lengths = [0u8; 256];
    for i in (0..next - 1).rev() {
        let d = depth[usize::from(parent[i])] + 1;
        if i < n {
            if u32::from(d) > limit {
                return None;
            }
            lengths[(leaves[i] & 0xff) as usize] = d;
        }
        depth[i] = d;
    }
    Some(lengths)
}

/// Code lengths of at most `limit` bits, optimal for `counts` (package-merge).
fn package_merge(counts: &[u32; 256], limit: u32) -> [u8; 256] {
    #[derive(Clone, Copy)]
    struct Item {
        w: u64,
        node: u32,
    }
    let mut leaves: Vec<Item> = (0..256u32)
        .filter(|&s| counts[s as usize] > 0)
        .map(|s| Item {
            w: u64::from(counts[s as usize]),
            node: s,
        })
        .collect();
    leaves.sort_by_key(|i| (i.w, i.node));
    let n = leaves.len();
    // Packages are nodes 256.. with two children each.
    let mut kids: Vec<(u32, u32)> = Vec::new();
    let mut list = leaves.clone();
    for _ in 1..limit {
        let mut packages = Vec::with_capacity(list.len() / 2);
        for p in list.chunks_exact(2) {
            kids.push((p[0].node, p[1].node));
            packages.push(Item {
                w: p[0].w + p[1].w,
                node: 255 + kids.len() as u32,
            });
        }
        let mut merged = Vec::with_capacity(n + packages.len());
        let (mut i, mut j) = (0, 0);
        while i < n || j < packages.len() {
            if j == packages.len() || (i < n && leaves[i].w <= packages[j].w) {
                merged.push(leaves[i]);
                i += 1;
            } else {
                merged.push(packages[j]);
                j += 1;
            }
        }
        list = merged;
    }
    let mut lengths = [0u8; 256];
    let mut stack: Vec<u32> = Vec::new();
    for item in &list[..2 * n - 2] {
        stack.push(item.node);
        while let Some(node) = stack.pop() {
            if node < 256 {
                lengths[node as usize] += 1;
            } else {
                let (a, b) = kids[(node - 256) as usize];
                stack.push(a);
                stack.push(b);
            }
        }
    }
    lengths
}

/// A Huffman code of the literals and its tree description.
pub(crate) struct Encoder {
    codes: [u16; 256],
    lens: [u8; 256],
    /// The tree description, as written in the literals section.
    pub(crate) description: Vec<u8>,
}

impl Encoder {
    /// A code for `counts` (at least two symbols present), or `None` when its tree cannot be
    /// described (more than 128 weights that do not compress).
    pub(crate) fn new(counts: &[u32; 256]) -> Option<Encoder> {
        let lens = limited_lengths(counts, 11);
        let max_len = u32::from(*lens.iter().max()?);
        let mut w = [0u8; 256];
        for s in 0..256 {
            if lens[s] > 0 {
                w[s] = (max_len + 1 - u32::from(lens[s])) as u8;
            }
        }
        let last = lens.iter().rposition(|&l| l > 0)?;
        let description = describe(&w[..last])?;
        // Canonical codes, laid out as the decoder's table is.
        let mut rank = [0usize; 13];
        for &x in &w {
            rank[usize::from(x)] += 1;
        }
        let mut start = [0usize; 14];
        for wt in 1..=12 {
            start[wt + 1] = start[wt] + (rank[wt] << (wt - 1));
        }
        let mut codes = [0u16; 256];
        for s in 0..256 {
            let wt = usize::from(w[s]);
            if wt > 0 {
                codes[s] = (start[wt] >> (wt - 1)) as u16;
                start[wt] += 1 << (wt - 1);
            }
        }
        Some(Encoder {
            codes,
            lens,
            description,
        })
    }

    /// Size in bits of `counts` coded with this code.
    pub(crate) fn cost_bits(&self, counts: &[u32; 256]) -> usize {
        counts
            .iter()
            .zip(&self.lens)
            .map(|(&c, &l)| c as usize * usize::from(l))
            .sum()
    }

    #[inline(never)]
    fn stream(&self, data: &[u8], out: &mut Vec<u8>) {
        let mut w = BitWriter::new(out);
        // Four codes of at most 11 bits between flushes.
        let mut chunks = data.rchunks_exact(4);
        for c in &mut chunks {
            for &b in c.iter().rev() {
                w.add(
                    u64::from(self.codes[usize::from(b)]),
                    u32::from(self.lens[usize::from(b)]),
                );
            }
            w.flush_bytes();
        }
        for &b in chunks.remainder().iter().rev() {
            w.add(
                u64::from(self.codes[usize::from(b)]),
                u32::from(self.lens[usize::from(b)]),
            );
        }
        w.flush_bytes();
        w.close();
    }

    /// Appends `data` coded in one stream, or in four behind a jump table (`None` when a stream
    /// is longer than the jump table can say).
    pub(crate) fn encode(&self, data: &[u8], four: bool, out: &mut Vec<u8>) -> Option<()> {
        if !four {
            self.stream(data, out);
            return Some(());
        }
        let seg = data.len().div_ceil(4);
        let jump = out.len();
        out.extend_from_slice(&[0; 6]);
        let mut at = out.len();
        for i in 0..4 {
            let part = &data[(i * seg).min(data.len())..((i + 1) * seg).min(data.len())];
            self.stream(part, out);
            if i < 3 {
                let len = u16::try_from(out.len() - at).ok()?;
                out[jump + 2 * i..jump + 2 * i + 2].copy_from_slice(&len.to_le_bytes());
            }
            at = out.len();
        }
        Some(())
    }
}

/// Describes the weights of all symbols but the last: FSE-compressed when that is smaller (and
/// possible), else 4 bits each (at most 128 weights).
fn describe(w: &[u8]) -> Option<Vec<u8>> {
    let mut best: Option<Vec<u8>> = None;
    if w.len() <= 128 {
        let mut d = vec![127 + w.len() as u8];
        for p in w.chunks(2) {
            d.push(p[0] << 4 | p.get(1).copied().unwrap_or(0));
        }
        best = Some(d);
    }
    let mut hist = [0u32; 13];
    for &x in w {
        hist[usize::from(x)] += 1;
    }
    let distinct = hist.iter().filter(|&&c| c > 0).count();
    if w.len() > 2 && distinct > 1 {
        let maxw = hist.iter().rposition(|&c| c > 0)?;
        for log in [5, 6] {
            let norm = fse::normalize(&hist[..=maxw], log);
            let mut d = vec![0u8];
            fse::write_ncount(&norm, log, &mut d);
            let ct = fse::CTable::new(&norm, log);
            let mut bw = BitWriter::new(&mut d);
            // Two interleaved states; the last two weights are their initial states.
            let n = w.len();
            let mut i = n - 2;
            let (mut a, mut b);
            if n % 2 == 1 {
                a = ct.init(w[n - 1]);
                b = ct.init(w[n - 2]);
                i -= 1;
                ct.encode(&mut bw, &mut a, w[i]);
            } else {
                b = ct.init(w[n - 1]);
                a = ct.init(w[n - 2]);
            }
            while i > 0 {
                ct.encode(&mut bw, &mut b, w[i - 1]);
                ct.encode(&mut bw, &mut a, w[i - 2]);
                i -= 2;
            }
            ct.flush(&mut bw, b);
            ct.flush(&mut bw, a);
            bw.close();
            if d.len() - 1 < 128 && best.as_ref().is_none_or(|b| d.len() < b.len()) {
                d[0] = (d.len() - 1) as u8;
                best = Some(d);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8], four: bool) {
        let mut counts = [0u32; 256];
        for &b in data {
            counts[usize::from(b)] += 1;
        }
        let enc = Encoder::new(&counts).expect("describable");
        let mut out = enc.description.clone();
        enc.encode(data, four, &mut out).expect("encodes");
        let mut t = DTable::default();
        let size = read_table(&out, &mut t).expect("reads");
        assert_eq!(size, enc.description.len());
        let mut back = vec![0u8; data.len()];
        decode(&t, &out[size..], &mut back, four).expect("decodes");
        assert_eq!(back, data);
    }

    #[test]
    fn codes_round_trip() {
        let mut x = 99u64;
        for round in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let alphabet = 2 + (x % 255) as usize;
            let n = 6 + (x >> 9) as usize % 5000;
            let skew = 1 + (x >> 20) % 6;
            let data: Vec<u8> = (0..n)
                .map(|i| {
                    let mut v = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ x;
                    v ^= v >> 29;
                    let r = (v % 1_000_000) as f64 / 1_000_000.0;
                    ((r.powi(skew as i32) * alphabet as f64) as usize).min(alphabet - 1) as u8
                })
                .collect();
            if data.iter().all(|&b| b == data[0]) {
                continue;
            }
            round_trip(&data, round % 2 == 0);
        }
        // Very skewed counts: lengths must be limited to 11 bits.
        let mut data = Vec::new();
        let (mut a, mut b) = (1usize, 1usize);
        for s in 0..21u8 {
            data.extend(std::iter::repeat_n(s, a));
            (a, b) = (b, a + b);
        }
        let mut counts = [0u32; 256];
        for &b in &data {
            counts[usize::from(b)] += 1;
        }
        assert_eq!(*limited_lengths(&counts, 11).iter().max().unwrap(), 11);
        round_trip(&data, true);
        // All 256 symbols equally: weights do not compress, 255 of them > 128.
        let flat: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let mut counts = [0u32; 256];
        for &b in &flat {
            counts[usize::from(b)] += 1;
        }
        assert!(Encoder::new(&counts).is_none());
    }
}
