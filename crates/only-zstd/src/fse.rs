//! Finite State Entropy: table descriptions (normalized counts), decoding tables, the decoding
//! of compressed Huffman weights, and the encoder's tables.

use crate::bits::BackReader;
use crate::tables::highbit;

/// One cell of a decoding table: the symbol, and the next state `base + read(nb_bits)`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DEntry {
    pub(crate) symbol: u8,
    pub(crate) nb_bits: u8,
    pub(crate) base: u16,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Reads a table description (normalized counts) of at most `max_sv + 1` symbols into `norm`.
/// Returns the highest symbol, the accuracy log and the size of the description. Ported from
/// libzstd's `FSE_readNCount` (including its way of reading near the end of the input) so that
/// the same descriptions are accepted.
pub(crate) fn read_ncount(
    src: &[u8],
    max_sv: usize,
    norm: &mut [i16; 256],
) -> Option<(usize, u32, usize)> {
    if src.len() < 8 {
        let mut buf = [0u8; 8];
        buf[..src.len()].copy_from_slice(src);
        let r = read_ncount_body(&buf, max_sv, norm)?;
        return (r.2 <= src.len()).then_some(r);
    }
    read_ncount_body(src, max_sv, norm)
}

fn read_ncount_body(
    src: &[u8],
    max_sv: usize,
    norm: &mut [i16; 256],
) -> Option<(usize, u32, usize)> {
    let iend = src.len(); // >= 8
    let max_sv1 = max_sv + 1;
    norm[..max_sv1].fill(0);
    let mut ip = 0usize;
    let mut bit_stream = le32(src, 0);
    let mut nb_bits = (bit_stream & 0xF) as i32 + 5;
    if nb_bits > 15 {
        return None;
    }
    let table_log = nb_bits as u32;
    bit_stream >>= 4;
    let mut bit_count: i32 = 4;
    let mut remaining: i32 = (1 << nb_bits) + 1;
    let mut threshold: i32 = 1 << nb_bits;
    nb_bits += 1;
    let mut charnum = 0usize;
    let mut previous0 = false;
    // Moves `ip` forward by whole bytes of `bit_count`, or clamps it to the last 4 bytes.
    let advance = |ip: &mut usize, bit_count: &mut i32| {
        if *ip + 7 <= iend || *ip + (*bit_count >> 3) as usize + 4 <= iend {
            *ip += (*bit_count >> 3) as usize;
            *bit_count &= 7;
        } else {
            *bit_count -= 8 * (iend as i32 - 4 - *ip as i32);
            *bit_count &= 31;
            *ip = iend - 4;
        }
    };
    loop {
        if previous0 {
            // Runs of zero counts: 2-bit repeat codes, 3 meaning "3 more and continue".
            let mut repeats = ((!bit_stream) | 0x8000_0000).trailing_zeros() >> 1;
            while repeats >= 12 {
                charnum += 3 * 12;
                if charnum >= max_sv1 {
                    return None; // libzstd fails the same way, later
                }
                if ip + 7 <= iend {
                    ip += 3;
                } else {
                    bit_count -= 8 * (iend as i32 - 7 - ip as i32);
                    bit_count &= 31;
                    ip = iend - 4;
                }
                bit_stream = le32(src, ip) >> bit_count;
                repeats = ((!bit_stream) | 0x8000_0000).trailing_zeros() >> 1;
            }
            charnum += 3 * repeats as usize;
            bit_stream >>= 2 * repeats;
            bit_count += 2 * repeats as i32;
            charnum += (bit_stream & 3) as usize;
            bit_count += 2;
            if charnum >= max_sv1 {
                break;
            }
            advance(&mut ip, &mut bit_count);
            bit_stream = le32(src, ip) >> bit_count;
        }
        let max = (2 * threshold - 1) - remaining;
        let mut count;
        if ((bit_stream & (threshold as u32 - 1)) as i32) < max {
            count = (bit_stream & (threshold as u32 - 1)) as i32;
            bit_count += nb_bits - 1;
        } else {
            count = (bit_stream & (2 * threshold as u32 - 1)) as i32;
            if count >= threshold {
                count -= max;
            }
            bit_count += nb_bits;
        }
        count -= 1;
        if count >= 0 {
            remaining -= count;
        } else {
            remaining += count;
        }
        norm[charnum] = count as i16;
        charnum += 1;
        previous0 = count == 0;
        if remaining < threshold {
            if remaining <= 1 {
                break;
            }
            nb_bits = highbit(remaining as u32) as i32 + 1;
            threshold = 1 << (nb_bits - 1);
        }
        if charnum >= max_sv1 {
            break;
        }
        advance(&mut ip, &mut bit_count);
        bit_stream = le32(src, ip) >> bit_count;
    }
    if remaining != 1 || charnum > max_sv1 || bit_count > 32 {
        return None;
    }
    ip += ((bit_count + 7) >> 3) as usize;
    Some((charnum - 1, table_log, ip))
}

/// Builds the decoding table of a valid distribution (as checked by [`read_ncount`]).
pub(crate) fn build_dtable(norm: &[i16], table_log: u32, table: &mut Vec<DEntry>) {
    let size = 1usize << table_log;
    table.clear();
    table.resize(size, DEntry::default());
    let mut next = [0u16; 256];
    let mut high = size - 1;
    for (s, &n) in norm.iter().enumerate() {
        if n == -1 {
            table[high].symbol = s as u8;
            high = high.wrapping_sub(1);
            next[s] = 1;
        } else {
            next[s] = n.max(0) as u16;
        }
    }
    let mask = size - 1;
    let step = (size >> 1) + (size >> 3) + 3;
    let mut pos = 0usize;
    for (s, &n) in norm.iter().enumerate() {
        for _ in 0..n.max(0) {
            table[pos].symbol = s as u8;
            pos = (pos + step) & mask;
            while pos > high {
                pos = (pos + step) & mask;
            }
        }
    }
    for e in table.iter_mut() {
        let s = usize::from(e.symbol);
        let x = u32::from(next[s]).max(1);
        next[s] = next[s].wrapping_add(1);
        let nb = table_log - highbit(x);
        e.nb_bits = nb as u8;
        e.base = ((x << nb) as usize).wrapping_sub(size) as u16;
    }
}

/// Decodes FSE-compressed Huffman weights (at most 255) into `out`, the way libzstd's
/// `FSE_decompress_wksp` does with two interleaved states. Returns how many there are.
pub(crate) fn decode_weights(src: &[u8], out: &mut [u8; 256]) -> Option<usize> {
    let mut norm = [0i16; 256];
    let (max_sv, table_log, hsize) = read_ncount(src, 255, &mut norm)?;
    if table_log > 6 {
        return None;
    }
    let mut table = Vec::new();
    build_dtable(&norm[..=max_sv], table_log, &mut table);
    let mut br = BackReader::new(&src[hsize..])?;
    let mut s1 = br.read(table_log) as usize;
    let mut s2 = br.read(table_log) as usize;
    br.reload();
    if br.overflowed() {
        return None;
    }
    let mut n = 0;
    // `step` emits the symbol of one state and moves it on; when that runs past the stream,
    // the other state's symbol is the last one.
    loop {
        if n > 253 {
            return None;
        }
        let e = table[s1 & (table.len() - 1)];
        out[n] = e.symbol;
        n += 1;
        s1 = usize::from(e.base) + br.read(u32::from(e.nb_bits)) as usize;
        br.reload();
        if br.overflowed() {
            out[n] = table[s2 & (table.len() - 1)].symbol;
            return Some(n + 1);
        }
        if n > 253 {
            return None;
        }
        let e = table[s2 & (table.len() - 1)];
        out[n] = e.symbol;
        n += 1;
        s2 = usize::from(e.base) + br.read(u32::from(e.nb_bits)) as usize;
        br.reload();
        if br.overflowed() {
            out[n] = table[s1 & (table.len() - 1)].symbol;
            return Some(n + 1);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Encoder side.

/// Normalizes `counts` (not all zero, at most `1 << table_log` of them non-zero) to a
/// distribution summing to `1 << table_log`, every present symbol keeping at least 1.
pub(crate) fn normalize(counts: &[u32], table_log: u32) -> Vec<i16> {
    let size = 1i64 << table_log;
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let mut norm: Vec<i64> = counts
        .iter()
        .map(|&c| {
            if c == 0 {
                0
            } else {
                ((u64::from(c) * size as u64 + total / 2) / total).max(1) as i64
            }
        })
        .collect();
    let mut sum: i64 = norm.iter().sum();
    // Fix the sum one unit at a time where it costs least (counts · log2 of the change).
    while sum != size {
        let mut best = usize::MAX;
        let mut best_cost = f64::INFINITY;
        for (s, &n) in norm.iter().enumerate() {
            if n == 0 || (sum > size && n == 1) {
                continue;
            }
            let c = f64::from(counts[s]);
            let cost = if sum > size {
                c * ((n as f64) / ((n - 1) as f64)).log2()
            } else {
                -c * (((n + 1) as f64) / (n as f64)).log2()
            };
            if cost < best_cost {
                best_cost = cost;
                best = s;
            }
        }
        if best == usize::MAX {
            break; // more symbols than cells: the caller avoids this
        }
        if sum > size {
            norm[best] -= 1;
            sum -= 1;
        } else {
            norm[best] += 1;
            sum += 1;
        }
    }
    norm.into_iter().map(|n| n as i16).collect()
}

/// Estimated size in bits of coding `counts` with `norm` (accuracy log `table_log`).
pub(crate) fn cost_bits(counts: &[u32], norm: &[i16], table_log: u32) -> f64 {
    let mut bits = 0.0;
    for (s, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let n = norm.get(s).copied().unwrap_or(0);
        if n == 0 {
            return f64::INFINITY;
        }
        let p = f64::from(n.unsigned_abs()) / f64::from(1u32 << table_log);
        bits -= f64::from(c) * p.log2();
    }
    bits
}

/// Writes a table description (libzstd's `FSE_writeNCount`); `norm` ends with its last
/// non-zero symbol.
pub(crate) fn write_ncount(norm: &[i16], table_log: u32, out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut n: u32 = 0;
    let mut put = |out: &mut Vec<u8>, v: u32, bits: u32| {
        acc |= u64::from(v) << n;
        n += bits;
        while n >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            n -= 8;
        }
    };
    put(out, table_log - 5, 4);
    let size = 1i32 << table_log;
    let mut remaining = size + 1;
    let mut threshold = size;
    let mut nb_bits = table_log + 1;
    let mut s = 0usize;
    let mut previous0 = false;
    while s < norm.len() && remaining > 1 {
        if previous0 {
            let mut start = s;
            while s < norm.len() && norm[s] == 0 {
                s += 1;
            }
            while s >= start + 3 {
                put(out, 3, 2);
                start += 3;
            }
            put(out, (s - start) as u32, 2);
        }
        let count = i32::from(norm[s]);
        s += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        let mut v = count + 1;
        if v >= threshold {
            v += max;
        }
        // Values below `max` take the short form, one bit less.
        put(out, v as u32, if v < max { nb_bits - 1 } else { nb_bits });
        previous0 = v == 1;
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    if n > 0 {
        out.push(acc as u8);
    }
}

/// An encoding table (libzstd's `FSE_CTable`).
pub(crate) struct CTable {
    pub(crate) table_log: u32,
    states: Vec<u16>,
    /// Per symbol: delta to find the state, delta of the number of bits.
    tt: Vec<(i32, u32)>,
}

impl CTable {
    pub(crate) fn new(norm: &[i16], table_log: u32) -> CTable {
        let size = 1usize << table_log;
        let mask = size - 1;
        let mut high = size - 1;
        let mut cumul = vec![0usize; norm.len() + 1];
        let mut symbols = vec![0u8; size];
        for (s, &n) in norm.iter().enumerate() {
            if n == -1 {
                cumul[s + 1] = cumul[s] + 1;
                symbols[high] = s as u8;
                high = high.wrapping_sub(1);
            } else {
                cumul[s + 1] = cumul[s] + n.max(0) as usize;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mut pos = 0;
        for (s, &n) in norm.iter().enumerate() {
            for _ in 0..n.max(0) {
                symbols[pos] = s as u8;
                pos = (pos + step) & mask;
                while pos > high {
                    pos = (pos + step) & mask;
                }
            }
        }
        let mut states = vec![0u16; size];
        for (u, &s) in symbols.iter().enumerate() {
            let s = usize::from(s);
            states[cumul[s]] = (size + u) as u16;
            cumul[s] += 1;
        }
        let mut tt = vec![(0i32, 0u32); norm.len()];
        let mut total = 0i32;
        for (s, &n) in norm.iter().enumerate() {
            tt[s] = match n {
                0 => (0, ((table_log + 1) << 16).wrapping_sub(size as u32)),
                -1 | 1 => {
                    let t = (total - 1, (table_log << 16).wrapping_sub(size as u32));
                    total += 1;
                    t
                }
                n => {
                    let n = n as u32;
                    let max_bits_out = table_log - highbit(n - 1);
                    let min_state_plus = n << max_bits_out;
                    let t = (
                        total - n as i32,
                        (max_bits_out << 16).wrapping_sub(min_state_plus),
                    );
                    total += n as i32;
                    t
                }
            };
        }
        CTable {
            table_log,
            states,
            tt,
        }
    }

    /// The first state, encoding `sym` without writing bits.
    pub(crate) fn init(&self, sym: u8) -> u32 {
        let (dfs, dnb) = self.tt[usize::from(sym)];
        let nb = (dnb.wrapping_add(1 << 15)) >> 16;
        let value = (nb << 16).wrapping_sub(dnb);
        u32::from(self.states[((value >> nb) as i32 + dfs) as usize])
    }

    /// Writes the bits that move `state` to one encoding `sym`.
    #[inline]
    pub(crate) fn encode(&self, w: &mut crate::bits::BitWriter<'_>, state: &mut u32, sym: u8) {
        let (dfs, dnb) = self.tt[usize::from(sym)];
        let nb = (state.wrapping_add(dnb)) >> 16;
        w.put(u64::from(*state), nb);
        *state = u32::from(self.states[((*state >> nb) as i32 + dfs) as usize]);
    }

    /// Writes the final state.
    pub(crate) fn flush(&self, w: &mut crate::bits::BitWriter<'_>, state: u32) {
        w.put(u64::from(state), self.table_log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::BitWriter;

    #[test]
    fn ncount_round_trip() {
        let mut x = 12345u64;
        for round in 0..2000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let nsym = 2 + (x % 60) as usize;
            let table_log = 5 + (x >> 8) as u32 % 5;
            let mut counts: Vec<u32> = (0..nsym)
                .map(|i| {
                    let v = (x >> (i % 50)) as u32;
                    if v % 3 == 0 { 0 } else { v % 1000 + 1 }
                })
                .collect();
            counts[nsym - 1] = 7;
            counts[0] += 1;
            if counts.iter().filter(|&&c| c > 0).count() > 1 << table_log {
                continue;
            }
            let mut norm = normalize(&counts, table_log);
            if round % 3 == 0 {
                // Turn some 1s into -1s (low-probability symbols).
                for n in &mut norm {
                    if *n == 1 && x & 1 == 1 {
                        *n = -1;
                    }
                }
            }
            assert_eq!(
                norm.iter().map(|n| i32::from(n.abs())).sum::<i32>(),
                1 << table_log
            );
            let mut out = Vec::new();
            write_ncount(&norm, table_log, &mut out);
            let mut back = [0i16; 256];
            let (max_sv, log, size) = read_ncount(&out, 255, &mut back).expect("reads");
            assert_eq!(
                (log, size, max_sv),
                (table_log, out.len(), nsym - 1),
                "round {round}"
            );
            assert_eq!(&back[..nsym], &norm[..]);
            // The same with trailing bytes after the description.
            out.extend_from_slice(&[0xAB; 9]);
            let (_, _, size2) = read_ncount(&out, 255, &mut back).expect("reads");
            assert_eq!(size2, size);
        }
    }

    #[test]
    fn encode_decode_two_states() {
        // Weight-like data through the encoder and `decode_weights`.
        let data: Vec<u8> = (0..200u32)
            .map(|i| [1u8, 2, 2, 3, 3, 3, 4, 0, 5, 1][i as usize % 10])
            .collect();
        let mut counts = [0u32; 13];
        for &d in &data {
            counts[usize::from(d)] += 1;
        }
        let last = counts.iter().rposition(|&c| c > 0).unwrap();
        let norm = normalize(&counts[..=last], 6);
        let mut out = Vec::new();
        write_ncount(&norm, 6, &mut out);
        let ct = CTable::new(&norm, 6);
        let mut w = BitWriter::new(&mut out);
        let n = data.len();
        let (mut a, mut b);
        let mut i = n;
        if n % 2 == 1 {
            a = ct.init(data[n - 1]);
            b = ct.init(data[n - 2]);
            i -= 2;
            i -= 1;
            ct.encode(&mut w, &mut a, data[i]);
        } else {
            b = ct.init(data[n - 1]);
            a = ct.init(data[n - 2]);
            i -= 2;
        }
        while i > 0 {
            i -= 1;
            ct.encode(&mut w, &mut b, data[i]);
            i -= 1;
            ct.encode(&mut w, &mut a, data[i]);
        }
        ct.flush(&mut w, b);
        ct.flush(&mut w, a);
        w.close();
        let mut back = [0u8; 256];
        let got = decode_weights(&out, &mut back).expect("decodes");
        assert_eq!(&back[..got], &data[..]);
    }
}
