//! One-shot brotli decompression (RFC 7932).
//!
//! The output vector is the sliding window: back-references read the bytes already written,
//! and distances beyond `min(output so far, window - 16)` address the static dictionary. Every
//! length declared by the stream is checked against the meta-block length and the caller's
//! limit before any byte is produced or any space is reserved for it, so memory stays within
//! the limit plus the prefix code tables (a few megabytes at most, whatever the stream says).
//! Reading past the end of the input yields zero bits that are counted, and the decoder checks
//! at least once per command and per literal that none of them was consumed, so a truncated
//! stream costs no more than its own length plus the output limit.

use crate::Error;
use crate::bits::BitReader;
use crate::dictionary::{DICTIONARY, OFFSETS_BY_LENGTH, SIZE_BITS_BY_LENGTH, transform_word};
use crate::huffman::{Lengths, Tree, code_length_table, decode, decode_loaded_at, single};
use crate::tables::{BLOCK_LEN, CMD_LUT, CODE_LENGTH_ORDER, CONTEXT_LUT};

/// Decompresses the brotli stream `data`, which must be exactly one complete stream, into at
/// most `limit` bytes.
///
/// Fails with [`Error::TooLarge`] as soon as the output would exceed `limit` (before reserving
/// memory for it), with [`Error::Truncated`] if `data` ends early and with
/// [`Error::TrailingData`] if bytes follow the end of the stream.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut d = Decoder {
        br: BitReader::new(data),
        buf: Vec::new(),
        pos: 0,
        limit,
        last: [4, 11, 15, 16],
        lens: Lengths::default(),
    };
    d.stream(data.len())?;
    d.buf.truncate(d.pos);
    Ok(d.buf)
}

/// Bytes past the end of a match that its fast path may overwrite (with bytes that are
/// overwritten again later, or cut off at the end).
const WILD: usize = 32;

/// How far ahead of the output the window is zeroed at a time.
const AHEAD: usize = 1 << 17;

/// Copies `len` bytes from `src` to `dst` within `buf` (`src < dst`; overlapping forwards as
/// LZ77 copies do).
#[inline(always)]
fn copy_match(buf: &mut [u8], src: usize, dst: usize, len: usize) {
    let offset = dst - src;
    if dst + len + 16 <= buf.len() {
        if offset >= 16 {
            // Whole chunks; each reads bytes already final (16 or more behind).
            let mut k = 0;
            loop {
                buf.copy_within(src + k..src + k + 16, dst + k);
                k += 16;
                if k >= len {
                    return;
                }
            }
        }
        if len <= 32 {
            // A short copy with a short period: 8-byte chunks from `d` behind, `d` the
            // smallest multiple of the offset that is at least 8 (the same bytes, by
            // periodicity), each reading bytes already final; below an offset of 8, the first
            // `d - offset` bytes one at a time so that the first chunk reads from `src` on.
            // (Longer ones are left to the loop below: each chunk here waits for the store of
            // the one before.)
            let d = if offset >= 8 {
                offset
            } else {
                offset * 8usize.div_ceil(offset)
            };
            let head = (d - offset).min(len);
            for i in 0..head {
                buf[dst + i] = buf[src + i];
            }
            let mut k = head;
            while k < len {
                buf.copy_within(dst + k - d..dst + k - d + 8, dst + k);
                k += 8;
            }
            return;
        }
    }
    if offset >= len {
        buf.copy_within(src..src + len, dst);
        return;
    }
    if offset == 1 {
        let b = buf[src];
        buf[dst..dst + len].fill(b);
        return;
    }
    // Overlapping: the copied pattern doubles at each step.
    let mut d = dst;
    let end = dst + len;
    while d < end {
        let n = (d - src).min(end - d);
        buf.copy_within(src..src + n, d);
        d += n;
    }
}

/// Makes `buf` at least `pos + n` long (`n` checked against the limit by the caller), plus
/// `WILD` bytes when the limit allows, zeroing up to `AHEAD` bytes ahead at a time (but not
/// past the end of the meta-block, `end`) and growing the capacity geometrically, never past
/// the limit.
#[inline]
fn reserve(buf: &mut Vec<u8>, pos: usize, n: usize, end: usize, limit: usize) {
    let need = (pos + n).saturating_add(WILD).min(limit.max(pos + n));
    if buf.len() < need {
        grow(buf, pos, need, end, limit);
    }
}

#[cold]
fn grow(buf: &mut Vec<u8>, pos: usize, need: usize, end: usize, limit: usize) {
    let cap_limit = limit.max(need);
    let ahead = (pos + AHEAD).min(end.saturating_add(WILD));
    let want = need.max(ahead).min(cap_limit);
    if buf.capacity() < want {
        let cap = (buf.capacity() * 2).max(want).min(cap_limit);
        buf.reserve_exact(cap - buf.len());
    }
    buf.resize(want, 0);
}

/// The output position up to which a meta-block ending at `end` can write without checks:
/// within the meta-block and the limit, with `WILD` bytes of `buf` to spare.
#[inline(always)]
fn fast_end(buf: &[u8], end: usize, limit: usize) -> usize {
    end.min(limit).min(buf.len().saturating_sub(WILD))
}

/// The checks for `n` more bytes at `pos` when they pass [`fast_end`]: within the meta-block
/// ending at `end` (else `BadBlockLength`), within the limit (else `TooLarge`), then room in
/// `buf`. Returns the new [`fast_end`].
#[cold]
#[inline(never)]
fn make_room(
    buf: &mut Vec<u8>,
    pos: usize,
    n: usize,
    end: usize,
    limit: usize,
) -> Result<usize, Error> {
    if n > end - pos {
        return Err(Error::BadBlockLength);
    }
    if n > limit - pos {
        return Err(Error::TooLarge);
    }
    reserve(buf, pos, n, end, limit);
    Ok(fast_end(buf, end, limit))
}

/// Writes the static dictionary word that distance `dist` (beyond `max_distance`) and length
/// `copy` address at `pos`; returns its length.
#[inline(never)]
fn dictionary_word(
    buf: &mut Vec<u8>,
    pos: usize,
    dist: usize,
    max_distance: usize,
    copy: usize,
    end: usize,
    limit: usize,
) -> Result<usize, Error> {
    if dist > MAX_ALLOWED_DISTANCE {
        return Err(Error::BadDistance);
    }
    if !(4..=24).contains(&copy) {
        return Err(Error::BadDictionaryReference);
    }
    let shift = SIZE_BITS_BY_LENGTH[copy];
    let address = dist - max_distance - 1;
    let word = address & ((1 << shift) - 1);
    let t = address >> shift;
    if t >= 121 {
        return Err(Error::BadDictionaryReference);
    }
    let start = OFFSETS_BY_LENGTH[copy] as usize + word * copy;
    let w = DICTIONARY
        .get(start..start + copy)
        .ok_or(Error::BadDictionaryReference)?;
    let mut tmp = [0u8; 64];
    let n = transform_word(&mut tmp, w, t);
    if n > end - pos {
        return Err(Error::BadBlockLength);
    }
    if n > limit - pos {
        return Err(Error::TooLarge);
    }
    reserve(buf, pos, n, end, limit);
    buf[pos..pos + n].copy_from_slice(&tmp[..n]);
    Ok(n)
}

/// Distance codes 0..16: which of the last four distances (most recent first) and what to add
/// to it (RFC 7932 section 4).
const SHORT_DISTANCES: [(u8, i8); 16] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (0, -1),
    (0, 1),
    (0, -2),
    (0, 2),
    (0, -3),
    (0, 3),
    (1, -1),
    (1, 1),
    (1, -2),
    (1, 2),
    (1, -3),
    (1, 3),
];

/// The largest distance the reference decoder accepts (`BROTLI_MAX_ALLOWED_DISTANCE`).
const MAX_ALLOWED_DISTANCE: usize = 0x7fff_fffc;

fn block_len(br: &mut BitReader<'_>, code: &[u32]) -> u32 {
    let (base, extra) = BLOCK_LEN[decode(code, br) % 26];
    base + br.read(u32::from(extra))
}

/// Reads a block switch command of a category with at least two block types.
fn switch(br: &mut BitReader<'_>, b: &mut Blocks) {
    let sym = decode(&b.type_code, br);
    let mut t = match sym {
        0 => b.ring[0],
        1 => b.ring[1] + 1,
        s => s - 2,
    };
    if t >= b.types {
        t -= b.types;
    }
    b.ring = [b.ring[1], t];
    b.left = block_len(br, &b.len_code);
}

fn check(br: &BitReader<'_>) -> Result<(), Error> {
    if br.overrun() {
        Err(Error::Truncated)
    } else {
        Ok(())
    }
}

/// Code lengths of the code length code: bit length and symbol for each value of the next four
/// bits (RFC 7932 section 3.5).
const CL_CODE_LEN: [u8; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
const CL_CODE_VAL: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

struct Decoder<'a> {
    br: BitReader<'a>,
    /// The output, which is also the window: `buf[..pos]`. The rest of `buf` is zeroed room
    /// ahead (never past `limit`, in length or capacity), so that matches can be copied in
    /// whole chunks.
    buf: Vec<u8>,
    pos: usize,
    limit: usize,
    /// The last four distances, most recent first.
    last: [usize; 4],
    /// Scratch space for code lengths.
    lens: Lengths,
}

/// A group of prefix codes (the trees of one category), stored back to back.
#[derive(Default)]
struct Group {
    tables: Vec<u32>,
    starts: Vec<usize>,
}

impl Group {
    /// Where tree `i` starts in `tables` (0 for a tree that does not exist, which callers
    /// never ask for).
    #[inline(always)]
    fn start(&self, i: usize) -> usize {
        self.starts.get(i).copied().unwrap_or(0)
    }
}

/// Block switching state of one category (literals, commands or distances).
struct Blocks {
    types: usize,
    type_code: Vec<u32>,
    len_code: Vec<u32>,
    /// The second last and the last block type.
    ring: [usize; 2],
    /// Items left in the current block.
    left: u32,
}

impl Blocks {
    fn current(&self) -> usize {
        self.ring[1]
    }
}

impl Decoder<'_> {
    fn check(&self) -> Result<(), Error> {
        if self.br.overrun() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Appends `src` (whose length was checked against the limit).
    fn extend(&mut self, src: &[u8]) {
        let end = self.pos + src.len();
        reserve(&mut self.buf, self.pos, src.len(), end, self.limit);
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }

    fn room(&self, n: usize) -> Result<(), Error> {
        if n > self.limit - self.pos {
            Err(Error::TooLarge)
        } else {
            Ok(())
        }
    }

    fn stream(&mut self, input_len: usize) -> Result<(), Error> {
        let wbits = self.window_bits()?;
        let max_backward = (1usize << wbits) - 16;
        loop {
            let is_last = self.br.read(1) == 1;
            if is_last && self.br.read(1) == 1 {
                break; // ISLASTEMPTY
            }
            let mnibbles = self.br.read(2);
            if mnibbles == 3 {
                // Metadata: skipped.
                if self.br.read(1) != 0 {
                    return Err(Error::BadHeader);
                }
                let nbytes = self.br.read(2);
                let mut len = 0usize;
                for i in 0..nbytes {
                    let b = self.br.read(8) as usize;
                    if i + 1 == nbytes && nbytes > 1 && b == 0 {
                        return Err(Error::BadHeader);
                    }
                    len |= b << (8 * i);
                }
                if nbytes > 0 {
                    len += 1;
                }
                self.check()?;
                if !self.br.align() {
                    return Err(Error::BadPadding);
                }
                self.br.take_bytes(len).ok_or(Error::Truncated)?;
                if is_last {
                    break;
                }
                continue;
            }
            let nibbles = 4 + mnibbles;
            let mut mlen = 0usize;
            for i in 0..nibbles {
                let v = self.br.read(4) as usize;
                if i + 1 == nibbles && nibbles > 4 && v == 0 {
                    return Err(Error::BadHeader);
                }
                mlen |= v << (4 * i);
            }
            mlen += 1;
            let uncompressed = !is_last && self.br.read(1) == 1;
            self.check()?;
            if uncompressed {
                if !self.br.align() {
                    return Err(Error::BadPadding);
                }
                let bytes = self.br.take_bytes(mlen).ok_or(Error::Truncated)?;
                self.room(mlen)?;
                self.extend(bytes);
                continue;
            }
            self.meta_block(mlen, max_backward)?;
            if is_last {
                break;
            }
        }
        self.check()?;
        if !self.br.align() {
            return Err(Error::BadPadding);
        }
        match self.br.byte_pos() {
            None => Err(Error::Truncated),
            Some(p) if p < input_len => Err(Error::TrailingData),
            Some(_) => Ok(()),
        }
    }

    fn window_bits(&mut self) -> Result<u32, Error> {
        if self.br.read(1) == 0 {
            return Ok(16);
        }
        let n = self.br.read(3);
        if n != 0 {
            return Ok(17 + n);
        }
        match self.br.read(3) {
            1 => Err(Error::BadWindow), // the large-window extension
            0 => Ok(17),
            m => Ok(8 + m),
        }
    }

    /// `VarLenUint8` (section 9.2): 0..=255.
    fn var_len_u8(&mut self) -> usize {
        if self.br.read(1) == 0 {
            return 0;
        }
        let n = self.br.read(3);
        if n == 0 {
            return 1;
        }
        (1usize << n) + self.br.read(n) as usize
    }

    /// Reads a prefix code over an alphabet of `size` symbols and appends its table to `out`.
    fn prefix_code(&mut self, size: usize, out: &mut Vec<u32>) -> Result<(), Error> {
        let hskip = self.br.read(2);
        if hskip == 1 {
            return self.simple_code(size, out);
        }
        // Code lengths of the code length code.
        let mut cl = [0u8; 18];
        let mut space = 32i32;
        let mut num = 0;
        for &sym in &CODE_LENGTH_ORDER[hskip as usize..] {
            self.br.refill();
            let ix = (self.br.peek() & 15) as usize;
            self.br.consume(u32::from(CL_CODE_LEN[ix]));
            let v = CL_CODE_VAL[ix];
            cl[sym] = v;
            if v != 0 {
                space -= 32 >> v;
                num += 1;
                if space <= 0 {
                    break;
                }
            }
        }
        if !(num == 1 || space == 0) {
            return Err(Error::BadPrefixCode);
        }
        let cl_table = code_length_table(&cl);
        let mut lens = std::mem::take(&mut self.lens);
        // Symbol code lengths.
        lens.clear();
        let mut sym = 0usize;
        let mut space = 32768i32;
        let mut prev = 8u8;
        let mut repeat = 0usize;
        let mut repeat_len = 0u8;
        while sym < size && space > 0 {
            self.br.refill();
            let e = cl_table[(self.br.peek() & 31) as usize];
            self.br.consume_loaded(e & 0xff);
            let code = (e >> 16) as usize;
            if code < 16 {
                repeat = 0;
                if code != 0 {
                    lens.push(sym, code as u8);
                    prev = code as u8;
                    space -= 32768 >> code;
                }
                sym += 1;
            } else {
                let (extra, new_len) = if code == 16 { (2, prev) } else { (3, 0) };
                if repeat_len != new_len {
                    repeat = 0;
                    repeat_len = new_len;
                }
                let old = repeat;
                if repeat > 0 {
                    repeat = (repeat - 2) << extra;
                }
                repeat += self.br.read(extra) as usize + 3;
                let delta = repeat - old;
                if sym + delta > size {
                    self.lens = lens;
                    return Err(Error::BadPrefixCode);
                }
                if repeat_len != 0 {
                    lens.push_run(sym, delta, repeat_len);
                    space -= (delta as i32) << (15 - repeat_len);
                }
                sym += delta;
            }
        }
        let r = if space != 0 {
            Err(Error::BadPrefixCode)
        } else {
            lens.build(out);
            Ok(())
        };
        self.lens = lens;
        self.check()?;
        r
    }

    fn simple_code(&mut self, size: usize, out: &mut Vec<u32>) -> Result<(), Error> {
        let nsym = self.br.read(2) as usize + 1;
        let max_bits = usize::BITS - (size - 1).leading_zeros();
        let mut syms = [0usize; 4];
        for s in syms.iter_mut().take(nsym) {
            *s = self.br.read(max_bits) as usize;
            if *s >= size {
                return Err(Error::BadPrefixCode);
            }
        }
        for i in 0..nsym {
            for j in i + 1..nsym {
                if syms[i] == syms[j] {
                    return Err(Error::BadPrefixCode);
                }
            }
        }
        let shape: &[u8] = match nsym {
            1 => {
                single(syms[0], out);
                return Ok(());
            }
            2 => &[1, 1],
            3 => &[1, 2, 2],
            _ => {
                if self.br.read(1) == 0 {
                    &[2, 2, 2, 2]
                } else {
                    &[1, 2, 3, 3]
                }
            }
        };
        // Lengths go to the symbols in the order given; codes are assigned in symbol order.
        let mut pairs = [(0usize, 0u8); 4];
        for (p, (&s, &l)) in pairs.iter_mut().zip(syms.iter().zip(shape)) {
            *p = (s, l);
        }
        let pairs = &mut pairs[..nsym];
        pairs.sort_unstable();
        self.lens.clear();
        for &(s, l) in pairs.iter() {
            self.lens.push(s, l);
        }
        self.lens.build(out);
        Ok(())
    }

    fn group(&mut self, n: usize, size: usize) -> Result<Group, Error> {
        let mut g = Group {
            tables: Vec::with_capacity(n * 320),
            starts: Vec::with_capacity(n),
        };
        for _ in 0..n {
            g.starts.push(g.tables.len());
            self.prefix_code(size, &mut g.tables)?;
        }
        Ok(g)
    }

    fn context_map(&mut self, size: usize) -> Result<(usize, Vec<u8>), Error> {
        let ntrees = self.var_len_u8() + 1;
        let mut map = vec![0u8; size];
        if ntrees == 1 {
            return Ok((1, map));
        }
        let rle = if self.br.read(1) == 1 {
            self.br.read(4) as usize + 1
        } else {
            0
        };
        let mut table = Vec::new();
        self.prefix_code(ntrees + rle, &mut table)?;
        let mut i = 0;
        while i < size {
            self.check()?;
            let code = decode(&table, &mut self.br);
            if code == 0 {
                i += 1;
            } else if code <= rle {
                let reps = (1usize << code) + self.br.read(code as u32) as usize;
                if i + reps > size {
                    return Err(Error::BadContextMap);
                }
                i += reps;
            } else {
                map[i] = (code - rle) as u8;
                i += 1;
            }
        }
        if self.br.read(1) == 1 {
            // Inverse move-to-front.
            let mut mtf: [u8; 256] = std::array::from_fn(|i| i as u8);
            for v in &mut map {
                let idx = usize::from(*v);
                let val = mtf[idx];
                *v = val;
                mtf.copy_within(0..idx, 1);
                mtf[0] = val;
            }
        }
        self.check()?;
        Ok((ntrees, map))
    }

    fn blocks(&mut self) -> Result<Blocks, Error> {
        let types = self.var_len_u8() + 1;
        let mut b = Blocks {
            types,
            type_code: Vec::new(),
            len_code: Vec::new(),
            ring: [1, 0],
            left: 1 << 24,
        };
        if types >= 2 {
            let mut t = Vec::new();
            self.prefix_code(types + 2, &mut t)?;
            b.type_code = t;
            let mut t = Vec::new();
            self.prefix_code(26, &mut t)?;
            b.len_code = t;
            b.left = block_len(&mut self.br, &b.len_code);
        }
        Ok(b)
    }

    fn meta_block(&mut self, mlen: usize, max_backward: usize) -> Result<(), Error> {
        let mut lit = self.blocks()?;
        let mut cmd = self.blocks()?;
        let mut dst = self.blocks()?;
        let npostfix = self.br.read(2);
        let ndirect = (self.br.read(4) as usize) << npostfix;
        let mut modes = vec![0u8; lit.types];
        for m in &mut modes {
            *m = self.br.read(2) as u8;
        }
        self.check()?;
        let (lit_trees, lit_map) = self.context_map(64 * lit.types)?;
        let (dist_trees, dist_map) = self.context_map(4 * dst.types)?;
        let lit_codes = self.group(lit_trees, 256)?;
        let cmd_codes = self.group(cmd.types, 704)?;
        let dist_size = 16 + ndirect + (48 << npostfix);
        let dist_codes = self.group(dist_trees, dist_size)?;
        // Distance symbol -> (offset, extra bits), RFC 7932 section 4.
        let mut dist_lut = vec![(0u32, 0u8); dist_size];
        for (j, e) in dist_lut[16..16 + ndirect].iter_mut().enumerate() {
            *e = (j as u32 + 1, 0);
        }
        {
            let postfix = 1usize << npostfix;
            let (mut bits, mut half) = (1u32, 0u32);
            let mut i = 16 + ndirect;
            while i < dist_size {
                let base = ndirect as u32 + ((((2 + half) << bits) - 4) << npostfix) + 1;
                for j in 0..postfix {
                    if let Some(e) = dist_lut.get_mut(i) {
                        *e = (base + j as u32, bits as u8);
                    }
                    i += 1;
                }
                bits += half;
                half ^= 1;
            }
        }

        // Literal trees: one for all 64 contexts of a block type when its context map says
        // so (then the literals of that block type need no context).
        let uniform: Vec<Option<usize>> = lit_map
            .chunks_exact(64)
            .map(|m| {
                m.iter()
                    .all(|&t| t == m[0])
                    .then(|| lit_codes.start(usize::from(m[0])))
            })
            .collect();
        let lit_tree_of = |t: usize| uniform.get(t).copied().flatten();
        // Per block type: where the tree of each context starts in `lit_codes.tables`.
        let ctx_starts: Vec<[u32; 64]> = lit_map
            .chunks_exact(64)
            .map(|m| std::array::from_fn(|c| lit_codes.start(usize::from(m[c])) as u32))
            .collect();
        let lut_of = |t: usize| -> &'static [u8; 512] {
            let m = usize::from(modes.get(t).copied().unwrap_or(0) & 3);
            CONTEXT_LUT[512 * m..512 * m + 512]
                .try_into()
                .unwrap_or(&[0; 512])
        };
        // Per distance block type: the start of the tree of each of the four distance contexts.
        let dist_trees_of = |t: usize| -> [Tree<'_>; 4] {
            std::array::from_fn(|c| {
                let tree = dist_map.get(4 * t + c).copied().unwrap_or(0);
                Tree::at(&dist_codes.tables, dist_codes.start(usize::from(tree)))
            })
        };
        // The decoding state lives in locals, so that it can stay in registers (stores to the
        // output through `self` would otherwise force it back to memory); it is put back at the
        // end (on errors the decoder is dropped).
        let mut br = std::mem::replace(&mut self.br, BitReader::new(&[]));
        let mut buf = std::mem::take(&mut self.buf);
        let mut pos = self.pos;
        let mut last = self.last;
        let limit = self.limit;
        let end = pos.saturating_add(mlen);
        // `pos + n <= fast` means that `n` more bytes are within the meta-block and the limit,
        // and that `buf` has `WILD` bytes of room past them; otherwise `make_room` sorts it out.
        let mut fast = fast_end(&buf, end, limit);
        let mut lit_type = 0usize;
        let mut lut = lut_of(0);
        let mut lit_tree = lit_tree_of(0);
        let mut cmd_tree = Tree::at(&cmd_codes.tables, cmd_codes.start(0));
        let mut dist_trees = dist_trees_of(0);
        let lit_tables = &lit_codes.tables[..];
        loop {
            check(&br)?;
            if cmd.left == 0 && cmd.types > 1 {
                switch(&mut br, &mut cmd);
                cmd_tree = Tree::at(&cmd_codes.tables, cmd_codes.start(cmd.current()));
            }
            cmd.left = cmd.left.wrapping_sub(1);
            br.refill();
            let sym = cmd_tree.decode_loaded(&mut br);
            let c = CMD_LUT[sym & 1023];
            // The two extra bit fields together are at most 48 bits.
            br.refill();
            let bits = br.peek();
            let insert = c.ins_base as usize + (bits & ((1 << c.ins_extra) - 1)) as usize;
            let copy =
                c.copy_base as usize + ((bits >> c.ins_extra) & ((1 << c.copy_extra) - 1)) as usize;
            br.consume_loaded(u32::from(c.ins_extra) + u32::from(c.copy_extra));
            if insert > 0 {
                if pos + insert > fast {
                    fast = make_room(&mut buf, pos, insert, end, limit)?;
                }
                let mut left = insert;
                loop {
                    let mut n = left;
                    if lit.types > 1 {
                        if lit.left == 0 {
                            switch(&mut br, &mut lit);
                            let t = lit.current();
                            lit_type = t;
                            lut = lut_of(t);
                            lit_tree = lit_tree_of(t);
                        }
                        n = n.min(lit.left as usize);
                        lit.left -= n as u32;
                    }
                    // Codes are at most 15 bits: three per refill.
                    if let Some(start) = lit_tree {
                        let tree = Tree::at(lit_tables, start);
                        let out = &mut buf[pos..pos + n];
                        let mut chunks = out.chunks_exact_mut(3);
                        for c in &mut chunks {
                            br.refill();
                            c[0] = tree.decode_loaded(&mut br) as u8;
                            c[1] = tree.decode_loaded(&mut br) as u8;
                            c[2] = tree.decode_loaded(&mut br) as u8;
                        }
                        br.refill();
                        for x in chunks.into_remainder() {
                            *x = tree.decode_loaded(&mut br) as u8;
                        }
                    } else {
                        let mut p1 = if pos > 0 { buf[pos - 1] } else { 0 };
                        let mut p2 = if pos > 1 { buf[pos - 2] } else { 0 };
                        let starts = ctx_starts.get(lit_type).unwrap_or(&[0; 64]);
                        let out = &mut buf[pos..pos + n];
                        let mut chunks = out.chunks_exact_mut(3);
                        for c in &mut chunks {
                            br.refill();
                            for x in c.iter_mut() {
                                let ctx = lut[usize::from(p1)] | lut[256 + usize::from(p2)];
                                let start = starts[usize::from(ctx & 63)] as usize;
                                let b = decode_loaded_at(lit_tables, start, &mut br) as u8;
                                *x = b;
                                p2 = p1;
                                p1 = b;
                            }
                        }
                        br.refill();
                        for x in chunks.into_remainder() {
                            let ctx = lut[usize::from(p1)] | lut[256 + usize::from(p2)];
                            let start = starts[usize::from(ctx & 63)] as usize;
                            let b = decode_loaded_at(lit_tables, start, &mut br) as u8;
                            *x = b;
                            p2 = p1;
                            p1 = b;
                        }
                    }
                    pos += n;
                    left -= n;
                    if left == 0 {
                        break;
                    }
                }
                if br.overrun() {
                    return Err(Error::Truncated);
                }
                if pos == end {
                    break;
                }
            }

            let dist;
            let mut push = true;
            if c.implicit {
                dist = last[0];
                push = false;
            } else {
                if dst.left == 0 && dst.types > 1 {
                    switch(&mut br, &mut dst);
                    dist_trees = dist_trees_of(dst.current());
                }
                dst.left = dst.left.wrapping_sub(1);
                // Distance context: copy lengths 2, 3, 4 and more (copies are at least 2 long).
                let dctx = copy.min(5) - 2;
                // A code (at most 15 bits) and its extra bits (at most 24) fit in one refill.
                br.refill();
                let code = dist_trees[dctx].decode_loaded(&mut br);
                if code < 16 {
                    let (i, delta) = SHORT_DISTANCES[code];
                    let d = last[usize::from(i)] as i64 + i64::from(delta);
                    if d <= 0 {
                        return Err(Error::BadDistance);
                    }
                    dist = d as usize;
                    push = code != 0;
                } else {
                    let (off, extra) = dist_lut.get(code).copied().unwrap_or((0, 0));
                    let x = (br.peek() & ((1u64 << extra) - 1)) as usize;
                    br.consume_loaded(u32::from(extra));
                    dist = off as usize + (x << npostfix);
                }
            }
            check(&br)?;
            let max_distance = pos.min(max_backward);
            if dist > max_distance {
                let n = dictionary_word(&mut buf, pos, dist, max_distance, copy, end, limit)?;
                pos += n;
                fast = fast_end(&buf, end, limit);
            } else {
                if push {
                    last = [dist, last[0], last[1], last[2]];
                }
                if pos + copy > fast {
                    fast = make_room(&mut buf, pos, copy, end, limit)?;
                }
                copy_match(&mut buf, pos - dist, pos, copy);
                pos += copy;
            }
            if pos == end {
                break;
            }
        }
        self.br = br;
        self.buf = buf;
        self.pos = pos;
        self.last = last;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::copy_match;

    #[test]
    fn copy_match_is_a_bytewise_copy() {
        for offset in 1..48 {
            for len in 1..80 {
                for slack in [0, 7, 16, 40] {
                    let start = 50;
                    let mut buf: Vec<u8> = (0..start + len + slack)
                        .map(|i| (i * 7 + 3) as u8)
                        .collect();
                    let mut want = buf.clone();
                    for i in 0..len {
                        want[start + i] = want[start + i - offset];
                    }
                    copy_match(&mut buf, start - offset, start, len);
                    assert_eq!(
                        buf[..start + len],
                        want[..start + len],
                        "offset {offset} len {len} slack {slack}"
                    );
                }
            }
        }
    }
}
