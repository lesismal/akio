//! Huffman coding of literals: tree descriptions (weights), decoding tables and streams, and the
//! encoder's length-limited codes.

use crate::Error;
use crate::bits::{BackReader, BitWriter};
use crate::fse;
use crate::tables::highbit;

/// A decoding table: `1 << log` entries of `code_length | symbol << 8`, and the double-symbol
/// table made from it when a large literals section asks for one (see [`double_pays`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct DTable {
    log: u32,
    entries: Vec<u16>,
    /// `1 << double_log` entries of `bits | count << 8 | first << 16 | second << 24`:
    /// the one or two symbols whose codes fill the next `double_log` bits (libzstd's
    /// `HUF_DEltX2`). `double_log` is 0 until it is built.
    double: Vec<u32>,
    double_log: u32,
    /// The length of the shortest code.
    shortest: u32,
}

/// Reads a Huffman tree description into `table` (libzstd's `HUF_readStats` checks: weights up
/// to 12, a total that the implied last weight completes to a power of two, an even number of
/// codes of the longest length). Returns the size of the description.
pub(crate) fn read_table(src: &[u8], table: &mut DTable) -> Option<usize> {
    let mut w = [0u8; 258];
    let (nsym, size, rank, log) = parse_weights(src, &mut w)?;
    build_table(&w[..nsym], &rank, log, table);
    Some(size)
}

/// Reads a Huffman tree description: the weights of all symbols (the last one implied and
/// filled in), the number of symbols and the size of the description, with the checks of
/// [`read_table`].
pub(crate) fn read_weights(src: &[u8]) -> Option<([u8; 258], usize, usize)> {
    let mut w = [0u8; 258];
    let (nsym, size, _, _) = parse_weights(src, &mut w)?;
    Some((w, nsym, size))
}

/// The weights of a tree description into `w`: the number of symbols, the size of the
/// description, the number of symbols of each weight and the log of the total.
#[inline(always)]
fn parse_weights(src: &[u8], w: &mut [u8; 258]) -> Option<(usize, usize, [u32; 13], u32)> {
    let &head = src.first()?;
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
    Some((count + 1, size, rank, log))
}

/// Builds the decoding table of valid weights (as [`parse_weights`] returns them; `log` is
/// the longest code length).
#[inline(always)]
fn build_table(w: &[u8], rank: &[u32; 13], log: u32, table: &mut DTable) {
    // Codes in order of weight (longest first), then of symbol.
    let mut start = [0usize; 14];
    for wt in 1..=log as usize {
        start[wt + 1] = start[wt] + ((rank[wt] as usize) << (wt - 1));
    }
    table.log = log;
    table.double_log = 0;
    table.shortest = log + 1 - (1..=log).rev().find(|&w| rank[w as usize] > 0).unwrap_or(1);
    // Only the first `1 << log` entries are used (and all of them are written below).
    if table.entries.len() < TABLE_SIZE {
        table.entries.resize(TABLE_SIZE, 0);
    }
    for (s, &wt) in w.iter().enumerate() {
        if wt == 0 {
            continue;
        }
        let wt = usize::from(wt);
        let len = 1usize << (wt - 1);
        let e = (s as u16) << 8 | (log as u16 + 1 - wt as u16);
        table.entries[start[wt]..start[wt] + len].fill(e);
        start[wt] += len;
    }
}

/// Size of the decoding table: codes are at most 12 bits long (`read_table` checks it), and a
/// table of `1 << log` entries is stored at the start of a table of this size so that lookups
/// need no bounds checks.
const TABLE_SIZE: usize = 1 << 12;

/// Decodes one symbol: the entry of the next `log` bits.
#[inline(always)]
fn step(e: &[u16; TABLE_SIZE], br: &mut BackReader<'_>, log: u32) -> u8 {
    let v = e[br.peek_fast(log) as usize & (TABLE_SIZE - 1)];
    br.consume(u32::from(v & 0xFF));
    (v >> 8) as u8
}

/// The four streams of `body` (stream `i` is `body[bounds[i]..bounds[i + 1]]`) in lockstep, from the readers `r` to
/// the outputs `o`, for as long as every stream's 8-byte window stays within it: libzstd's
/// fast loop. Each stream's bits are kept left-aligned in a register with a 1 bit below the
/// last one loaded, so a symbol takes a shift by a constant (the table's `LOG`), a lookup and
/// a shift by its length, and a refill finds the bits used from the position of that 1 bit.
/// Returns how many symbols each stream got (the readers are moved past them).
#[inline(always)]
fn fast4<'a, const LOG: u32>(
    e: &[u16; TABLE_SIZE],
    body: &'a [u8],
    bounds: [usize; 5],
    r: &mut [BackReader<'a>; 4],
    o: [&mut [u8]; 4],
) -> usize {
    // Symbols per refill: a refill leaves at most 7 bits used, and the 1 bit must stay below
    // the bits looked up (7 + syms * LOG <= 63).
    let syms = (56 / LOG as usize).min(8);
    let mut ip = [0usize; 4];
    let mut bits = [0u64; 4];
    for i in 0..4 {
        let Some((ptr, used)) = r[i].window() else {
            return 0;
        };
        if used > 7 {
            return 0;
        }
        ip[i] = bounds[i] + ptr;
        bits[i] = (load8(body, ip[i]) | 1) << used;
    }
    let [o1, o2, o3, o4] = o;
    let mut done = 0;
    loop {
        // A refill moves a window back by at most 7 bytes.
        let n = (0..4)
            .map(|i| (ip[i] - bounds[i]) / 7)
            .min()
            .unwrap_or(0)
            .min((o4.len() - done) / syms);
        if n == 0 {
            break;
        }
        for (((c1, c2), c3), c4) in o1[done..]
            .chunks_exact_mut(syms)
            .zip(o2[done..].chunks_exact_mut(syms))
            .zip(o3[done..].chunks_exact_mut(syms))
            .zip(o4[done..].chunks_exact_mut(syms))
            .take(n)
        {
            for k in 0..syms {
                c1[k] = sym::<LOG>(e, &mut bits[0]);
                c2[k] = sym::<LOG>(e, &mut bits[1]);
                c3[k] = sym::<LOG>(e, &mut bits[2]);
                c4[k] = sym::<LOG>(e, &mut bits[3]);
            }
            for i in 0..4 {
                let used = bits[i].trailing_zeros();
                ip[i] -= (used >> 3) as usize;
                bits[i] = (load8(body, ip[i]) | 1) << (used & 7);
            }
        }
        done += n * syms;
    }
    for i in 0..4 {
        r[i] = BackReader::at(
            &body[bounds[i]..bounds[i + 1]],
            ip[i] - bounds[i],
            bits[i].trailing_zeros(),
        );
    }
    done
}

/// [`fast4`] with the double-symbol table of `D` bits: each lookup gives one or two symbols,
/// so the streams move apart, each with its own position in `out` (stream `i` writes up to
/// `ends[i]`, from where stream `i - 1` ends; returned). Streams also run out at different
/// times (their codes take more or fewer bits), so when one stops the others go on together,
/// three, two, then one, instead of finishing one by one.
#[inline(always)]
fn fast4_double<'a, const D: u32>(
    dt: &[u32; TABLE_SIZE],
    body: &'a [u8],
    bounds: [usize; 5],
    r: &mut [BackReader<'a>; 4],
    out: &mut [u8],
    ends: [usize; 4],
) -> [usize; 4] {
    let mut l = Lanes {
        ip: [0; 4],
        bits: [0; 4],
        op: [0, ends[0], ends[1], ends[2]],
    };
    for i in 0..4 {
        let Some((ptr, used)) = r[i].window() else {
            return l.op;
        };
        if used > 7 {
            return l.op;
        }
        l.ip[i] = bounds[i] + ptr;
        l.bits[i] = (load8(body, l.ip[i]) | 1) << used;
    }
    loop {
        // The streams that can take another round: 7 more bytes in, a round's bytes out.
        let mut go = [0usize; 4];
        let mut k = 0;
        for i in 0..4 {
            if l.ip[i] - bounds[i] >= 7 && ends[i] - l.op[i] >= 2 * (56 / D as usize) {
                go[k] = i;
                k += 1;
            }
        }
        match k {
            4 => lanes::<D, 4>(dt, body, &bounds, &mut l, out, &ends, [0, 1, 2, 3]),
            3 => lanes::<D, 3>(dt, body, &bounds, &mut l, out, &ends, [go[0], go[1], go[2]]),
            2 => lanes::<D, 2>(dt, body, &bounds, &mut l, out, &ends, [go[0], go[1]]),
            1 => lanes::<D, 1>(dt, body, &bounds, &mut l, out, &ends, [go[0]]),
            _ => break,
        }
    }
    for i in 0..4 {
        r[i] = BackReader::at(
            &body[bounds[i]..bounds[i + 1]],
            l.ip[i] - bounds[i],
            l.bits[i].trailing_zeros(),
        );
    }
    l.op
}

/// The state of the four streams of [`fast4_double`]: input position (its 8-byte window),
/// left-aligned bits above a marker bit, output position.
struct Lanes {
    ip: [usize; 4],
    bits: [u64; 4],
    op: [usize; 4],
}

/// Rounds of the streams `idx` until one of them stops.
#[inline(always)]
fn lanes<const D: u32, const K: usize>(
    dt: &[u32; TABLE_SIZE],
    body: &[u8],
    bounds: &[usize; 5],
    l: &mut Lanes,
    out: &mut [u8],
    ends: &[usize; 4],
    idx: [usize; K],
) {
    // Lookups per refill, as in `fast4`; each writes two bytes and moves on by one or two, so
    // a round writes at most `room` bytes and stays within its stream's part of `out`.
    let syms = 56 / D as usize;
    let room = 2 * syms;
    let mut ip = idx.map(|i| l.ip[i]);
    let mut bits = idx.map(|i| l.bits[i]);
    let mut op = idx.map(|i| l.op[i]);
    let lo = idx.map(|i| bounds[i]);
    let hi = idx.map(|i| ends[i]);
    loop {
        let mut n = usize::MAX;
        for k in 0..K {
            n = n.min((ip[k] - lo[k]) / 7).min((hi[k] - op[k]) / room);
        }
        if n == 0 {
            break;
        }
        for _ in 0..n {
            for _ in 0..syms {
                for k in 0..K {
                    let v = dt[(bits[k] >> (64 - D)) as usize & (TABLE_SIZE - 1)];
                    out[op[k]..][..2].copy_from_slice(&((v >> 16) as u16).to_le_bytes());
                    bits[k] <<= v & 63;
                    op[k] += (v >> 8 & 0xFF) as usize;
                }
            }
            for k in 0..K {
                let used = bits[k].trailing_zeros();
                ip[k] -= (used >> 3) as usize;
                bits[k] = (load8(body, ip[k]) | 1) << (used & 7);
            }
        }
    }
    for (k, &i) in idx.iter().enumerate() {
        l.ip[i] = ip[k];
        l.bits[i] = bits[k];
        l.op[i] = op[k];
    }
}

/// One symbol of a left-aligned bit register (see [`fast4`]).
#[inline(always)]
fn sym<const LOG: u32>(e: &[u16; TABLE_SIZE], bits: &mut u64) -> u8 {
    let v = e[(*bits >> (64 - LOG)) as usize & (TABLE_SIZE - 1)];
    *bits <<= v & 63;
    (v >> 8) as u8
}

#[inline(always)]
fn load8(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..][..8]);
    u64::from_le_bytes(w)
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

/// Builds the double-symbol table of `t`: entries of `double_log` bits (11, or 12 for a code of
/// 12 bits, as libzstd), each holding the symbol whose code starts them and, when the next
/// code fits in the bits left, the symbol after it.
fn build_double(t: &mut DTable) -> Result<(), Error> {
    let e: &[u16; TABLE_SIZE] = t
        .entries
        .get(..TABLE_SIZE)
        .and_then(|e| e.try_into().ok())
        .ok_or(Error::BadHuffmanTable)?;
    let log = t.log;
    let d = log.max(11);
    let shift = d - log;
    if t.double.len() < TABLE_SIZE {
        t.double.resize(TABLE_SIZE, 0);
    }
    let out: &mut [u32; TABLE_SIZE] = (&mut t.double[..TABLE_SIZE])
        .try_into()
        .map_err(|_| Error::BadHuffmanTable)?;
    let shortest = t.shortest;
    // The first table's entries run by symbol in code order (longest codes first): each
    // symbol of length `l1` starts `1 << (d - l1)` entries here, whose last `d - l1` bits are
    // the code after it. Codes too long for any code after them come first: one symbol each.
    let single = e[..1 << log].partition_point(|&a| u32::from(a & 0xFF) + shortest > d);
    for (x, o) in out[..single << shift].iter_mut().enumerate() {
        let a = u32::from(e[(x >> shift) & (TABLE_SIZE - 1)]);
        *o = (a & 0xFF) | 1 << 8 | (a >> 8) << 16;
    }
    // Symbols of one length follow each other and differ only in the first symbol, so all
    // but the first of them copy the entries before.
    let mut k = single;
    let mut prev = (0usize, 0u32);
    while k < 1 << log {
        let a = e[k];
        let l1 = u32::from(a & 0xFF);
        let run = 1usize << (log - l1);
        let first = l1 | 1 << 8 | u32::from(a >> 8) << 16;
        let start = k << shift;
        let len = run << shift;
        let (done, rest) = out.split_at_mut(start);
        let span = &mut rest[..len];
        if prev.1 & 0xFFFF == first & 0xFFFF && prev.0 + len == start {
            let delta = first.wrapping_sub(prev.1);
            for (x, &y) in span.iter_mut().zip(&done[prev.0..]) {
                *x = y.wrapping_add(delta);
            }
        } else {
            for (j, x) in span.iter_mut().enumerate() {
                let b = u32::from(e[(j << l1 >> shift) & (TABLE_SIZE - 1)]);
                let l2 = b & 0xFF;
                let fits = u32::from(l1 + l2 <= d).wrapping_neg();
                *x = first + ((l2 | 1 << 8 | (b >> 8) << 24) & fits);
            }
        }
        prev = (start, first);
        k += run;
    }
    t.double_log = d;
    Ok(())
}

/// Whether the double-symbol table pays for its building on `size` literals coded in
/// `coded` bytes: libzstd's `HUF_selectDecoder` (its timings of both tables per 1/16 of
/// compression ratio, the double one charged 1/32 more for its cache footprint).
fn double_pays(size: usize, coded: usize) -> bool {
    const TIME: [[(u32, u32); 2]; 16] = [
        [(0, 0), (1, 1)],
        [(0, 0), (1, 1)],
        [(150, 216), (381, 119)],
        [(170, 205), (514, 112)],
        [(177, 199), (539, 110)],
        [(197, 194), (644, 107)],
        [(221, 192), (735, 107)],
        [(256, 189), (881, 106)],
        [(359, 188), (1167, 109)],
        [(582, 187), (1570, 114)],
        [(688, 187), (1712, 122)],
        [(825, 186), (1965, 136)],
        [(976, 185), (2131, 150)],
        [(1180, 186), (2070, 175)],
        [(1377, 185), (1731, 202)],
        [(1412, 185), (1695, 202)],
    ];
    let q = if coded >= size { 15 } else { coded * 16 / size };
    let d256 = (size >> 8) as u32;
    let [(t1, d1), (t2, d2)] = TIME[q];
    let single = t1 + d1 * d256;
    let double = t2 + d2 * d256;
    double + (double >> 5) < single
}

/// Decodes the literals of one stream (`four == false`) or of four streams behind a jump table.
/// `coded` is the size of the literals section's Huffman data, tree description included.
pub(crate) fn decode(
    t: &mut DTable,
    src: &[u8],
    out: &mut [u8],
    four: bool,
    coded: usize,
) -> Result<(), Error> {
    if four && t.double_log == 0 && double_pays(out.len(), coded) {
        build_double(t)?;
    }
    let t = &*t;
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
    let (s1, rest) = src[6..].split_at(l1);
    let (s2, rest) = rest.split_at(l2);
    let (s3, s4) = rest.split_at(l3);
    let mut r = [
        BackReader::new(s1).ok_or(Error::BadHuffmanStream)?,
        BackReader::new(s2).ok_or(Error::BadHuffmanStream)?,
        BackReader::new(s3).ok_or(Error::BadHuffmanStream)?,
        BackReader::new(s4).ok_or(Error::BadHuffmanStream)?,
    ];
    for x in &mut r {
        x.reload();
    }
    let body = &src[6..];
    let bounds = [0, l1, l1 + l2, l1 + l2 + l3, body.len()];
    let seg = out.len().div_ceil(4);
    // With at least 6 symbols (checked by the caller) the fourth segment is not negative.
    let ends = [seg, 2 * seg, 3 * seg, out.len()].map(|x| x.min(out.len()));
    if t.double_log != 0 {
        let dt: &[u32; TABLE_SIZE] = t
            .double
            .get(..TABLE_SIZE)
            .and_then(|d| d.try_into().ok())
            .ok_or(Error::BadHuffmanTable)?;
        let done = if t.double_log == 11 {
            fast4_double::<11>(dt, body, bounds, &mut r, out, ends)
        } else {
            fast4_double::<12>(dt, body, bounds, &mut r, out, ends)
        };
        let [r1, r2, r3, r4] = r;
        finish_stream(e, log, r1, &mut out[done[0]..ends[0]])?;
        finish_stream(e, log, r2, &mut out[done[1]..ends[1]])?;
        finish_stream(e, log, r3, &mut out[done[2]..ends[2]])?;
        return finish_stream(e, log, r4, &mut out[done[3]..ends[3]]);
    }
    let (o1, rest) = out.split_at_mut(ends[0]);
    let (o2, rest) = rest.split_at_mut(ends[1] - ends[0]);
    let (o3, o4) = rest.split_at_mut(ends[2] - ends[1]);
    let o = [&mut *o1, &mut *o2, &mut *o3, &mut *o4];
    let fast = match log {
        1 => fast4::<1>(e, body, bounds, &mut r, o),
        2 => fast4::<2>(e, body, bounds, &mut r, o),
        3 => fast4::<3>(e, body, bounds, &mut r, o),
        4 => fast4::<4>(e, body, bounds, &mut r, o),
        5 => fast4::<5>(e, body, bounds, &mut r, o),
        6 => fast4::<6>(e, body, bounds, &mut r, o),
        7 => fast4::<7>(e, body, bounds, &mut r, o),
        8 => fast4::<8>(e, body, bounds, &mut r, o),
        9 => fast4::<9>(e, body, bounds, &mut r, o),
        10 => fast4::<10>(e, body, bounds, &mut r, o),
        11 => fast4::<11>(e, body, bounds, &mut r, o),
        _ => fast4::<12>(e, body, bounds, &mut r, o),
    };
    let [mut r1, mut r2, mut r3, mut r4] = r;
    // The rest in lockstep, four symbols each per round, as long as the shortest segment (the
    // fourth) lasts; bits read past the end of a stream are caught by the checks of
    // `finish_stream`.
    let rounds = (o4.len() - fast) / 4;
    for (((c1, c2), c3), c4) in o1[fast..]
        .chunks_exact_mut(4)
        .zip(o2[fast..].chunks_exact_mut(4))
        .zip(o3[fast..].chunks_exact_mut(4))
        .zip(o4[fast..].chunks_exact_mut(4))
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
    let done = fast + rounds * 4;
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
#[derive(Clone)]
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
        Self::with_limit(counts, 11)
    }

    /// [`Encoder::new`] with codes of at most `limit` bits (11 or 12).
    fn with_limit(counts: &[u32; 256], limit: u32) -> Option<Encoder> {
        let lens = limited_lengths(counts, limit);
        let max_len = u32::from(*lens.iter().max()?);
        let mut w = [0u8; 256];
        for s in 0..256 {
            if lens[s] > 0 {
                w[s] = (max_len + 1 - u32::from(lens[s])) as u8;
            }
        }
        let last = lens.iter().rposition(|&l| l > 0)?;
        let description = describe(&w[..last])?;
        let codes = canonical_codes(&w);
        Some(Encoder {
            codes,
            lens,
            description,
        })
    }

    /// The code of a tree description's weights (valid ones, as `read_weights` returns them:
    /// the last symbol's included), without a description (a dictionary's table, repeated).
    pub(crate) fn from_weights(weights: &[u8]) -> Encoder {
        let mut w = [0u8; 256];
        let n = weights.len().min(256);
        w[..n].copy_from_slice(&weights[..n]);
        let total: u32 = w.iter().map(|&x| (1u32 << x) >> 1).sum();
        let log = highbit(total.max(1));
        let mut lens = [0u8; 256];
        for s in 0..256 {
            if w[s] > 0 {
                lens[s] = (log + 1 - u32::from(w[s])) as u8;
            }
        }
        Encoder {
            codes: canonical_codes(&w),
            lens,
            description: Vec::new(),
        }
    }

    /// Whether every symbol counted in `counts` has a code.
    pub(crate) fn covers(&self, counts: &[u32; 256]) -> bool {
        counts
            .iter()
            .zip(&self.lens)
            .all(|(&c, &l)| c == 0 || l > 0)
    }
}

/// Canonical codes of weights `w`, laid out as the decoder's table is.
fn canonical_codes(w: &[u8; 256]) -> [u16; 256] {
    let mut rank = [0usize; 13];
    for &x in w {
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
    codes
}

impl Encoder {
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
        // Four codes of at most 12 bits between flushes.
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

    /// Codes `data` with codes of at most `limit` bits and decodes it with the single-symbol
    /// table (a coded size of at least `data.len()` never picks the other) and, for four
    /// streams, with the double-symbol table; also checks that both reject the stream with
    /// its last byte changed.
    fn round_trip_limit(data: &[u8], four: bool, limit: u32) {
        let mut counts = [0u32; 256];
        for &b in data {
            counts[usize::from(b)] += 1;
        }
        let enc = Encoder::with_limit(&counts, limit).expect("describable");
        let mut out = enc.description.clone();
        enc.encode(data, four, &mut out).expect("encodes");
        let mut t = DTable::default();
        let size = read_table(&out, &mut t).expect("reads");
        assert_eq!(size, enc.description.len());
        let mut back = vec![0u8; data.len()];
        decode(&mut t, &out[size..], &mut back, four, usize::MAX).expect("decodes");
        assert_eq!(t.double_log, 0);
        assert_eq!(back, data);
        let mut bad = out[size..].to_vec();
        *bad.last_mut().unwrap() ^= 0x40;
        let single = decode(&mut t, &bad, &mut back, four, usize::MAX).is_ok();
        if four {
            build_double(&mut t).unwrap();
            back.fill(0);
            decode(&mut t, &out[size..], &mut back, four, usize::MAX).expect("decodes");
            assert_eq!(back, data);
            let double = decode(&mut t, &bad, &mut back, four, usize::MAX).is_ok();
            assert_eq!(single, double);
        }
    }

    fn round_trip(data: &[u8], four: bool) {
        round_trip_limit(data, four, 11);
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
        // 12-bit codes (a double-symbol table of 12 bits; libzstd's encoder writes at most 11).
        assert_eq!(*limited_lengths(&counts, 12).iter().max().unwrap(), 12);
        round_trip_limit(&data, true, 12);
        let mut long = data.clone();
        long.extend((0..20_000u32).map(|i| (i * i % 21) as u8));
        round_trip_limit(&long, true, 12);
        // All 256 symbols equally: weights do not compress, 255 of them > 128.
        let flat: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let mut counts = [0u32; 256];
        for &b in &flat {
            counts[usize::from(b)] += 1;
        }
        assert!(Encoder::new(&counts).is_none());
    }
}
