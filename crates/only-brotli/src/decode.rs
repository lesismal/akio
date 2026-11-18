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
use crate::huffman::{build, decode, single};
use crate::tables::{
    BLOCK_LEN, CODE_LENGTH_ORDER, CONTEXT_LUT, COPY_BASE, COPY_EXTRA, INS_BASE, INS_EXTRA,
    split_command,
};

/// Decompresses the brotli stream `data`, which must be exactly one complete stream, into at
/// most `limit` bytes.
///
/// Fails with [`Error::TooLarge`] as soon as the output would exceed `limit` (before reserving
/// memory for it), with [`Error::Truncated`] if `data` ends early and with
/// [`Error::TrailingData`] if bytes follow the end of the stream.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut d = Decoder {
        br: BitReader::new(data),
        out: Vec::new(),
        limit,
        last: [4, 11, 15, 16],
        lens: Vec::new(),
    };
    d.stream(data.len())?;
    Ok(d.out)
}

/// The largest distance the reference decoder accepts (`BROTLI_MAX_ALLOWED_DISTANCE`).
const MAX_ALLOWED_DISTANCE: usize = 0x7fff_fffc;

/// Code lengths of the code length code: bit length and symbol for each value of the next four
/// bits (RFC 7932 section 3.5).
const CL_CODE_LEN: [u8; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
const CL_CODE_VAL: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

struct Decoder<'a> {
    br: BitReader<'a>,
    out: Vec<u8>,
    limit: usize,
    /// The last four distances, most recent first.
    last: [usize; 4],
    /// Scratch space for code lengths.
    lens: Vec<u8>,
}

/// A group of prefix codes (the trees of one category), stored back to back.
#[derive(Default)]
struct Group {
    tables: Vec<u32>,
    starts: Vec<usize>,
}

impl Group {
    #[inline(always)]
    fn tree(&self, i: usize) -> &[u32] {
        let s = self.starts.get(i).copied().unwrap_or(usize::MAX);
        self.tables.get(s..).unwrap_or(&[])
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

    /// Makes room for `n` more output bytes (the caller has checked them against the limit),
    /// growing geometrically but never past the limit.
    fn reserve(&mut self, n: usize) {
        let len = self.out.len();
        if self.out.capacity() - len < n {
            let want = len
                .saturating_mul(2)
                .max(len + n)
                .max(1024)
                .min(self.limit)
                .max(len + n);
            self.out.reserve_exact(want - len);
        }
    }

    fn room(&self, n: usize) -> Result<(), Error> {
        if n > self.limit - self.out.len() {
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
                self.reserve(mlen);
                self.out.extend_from_slice(bytes);
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

    /// Reads a prefix code over an alphabet of `size` symbols into `out`.
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
        let mut cl_table = Vec::new();
        if num == 1 {
            let s = cl.iter().position(|&l| l != 0).unwrap_or(0);
            single(s, &mut cl_table);
        } else {
            build(&cl, &mut cl_table);
        }
        // Symbol code lengths.
        let mut lens = std::mem::take(&mut self.lens);
        lens.clear();
        lens.resize(size, 0);
        let mut sym = 0usize;
        let mut space = 32768i32;
        let mut prev = 8u8;
        let mut repeat = 0usize;
        let mut repeat_len = 0u8;
        while sym < size && space > 0 {
            let code = decode(&cl_table, &mut self.br);
            if code < 16 {
                repeat = 0;
                if code != 0 {
                    lens[sym] = code as u8;
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
                    lens[sym..sym + delta].fill(repeat_len);
                    space -= (delta as i32) << (15 - repeat_len);
                }
                sym += delta;
            }
        }
        let r = if space != 0 {
            Err(Error::BadPrefixCode)
        } else {
            build(&lens, out);
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
        let mut lens = std::mem::take(&mut self.lens);
        lens.clear();
        lens.resize(size, 0);
        for (&s, &l) in syms.iter().zip(shape) {
            lens[s] = l;
        }
        build(&lens, out);
        self.lens = lens;
        Ok(())
    }

    fn group(&mut self, n: usize, size: usize) -> Result<Group, Error> {
        let mut g = Group::default();
        let mut t = Vec::new();
        for _ in 0..n {
            self.prefix_code(size, &mut t)?;
            g.starts.push(g.tables.len());
            g.tables.extend_from_slice(&t);
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
            b.left = self.block_len(&b.len_code);
        }
        Ok(b)
    }

    fn block_len(&mut self, code: &[u32]) -> u32 {
        let (base, extra) = BLOCK_LEN[decode(code, &mut self.br) % 26];
        base + self.br.read(u32::from(extra))
    }

    /// Reads a block switch command of a category with at least two block types.
    fn switch(&mut self, b: &mut Blocks) {
        let sym = decode(&b.type_code, &mut self.br);
        let mut t = match sym {
            0 => b.ring[0],
            1 => b.ring[1] + 1,
            s => s - 2,
        };
        if t >= b.types {
            t -= b.types;
        }
        b.ring = [b.ring[1], t];
        b.left = self.block_len(&b.len_code);
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

        let mut remaining = mlen;
        let mut lit_slice = 0usize; // lit.current() * 64
        let mut lut = 512 * usize::from(modes[0] & 3);
        let (mut p1, mut p2) = match self.out.len() {
            0 => (0u8, 0u8),
            1 => (self.out[0], 0),
            n => (self.out[n - 1], self.out[n - 2]),
        };
        loop {
            self.check()?;
            if cmd.left == 0 && cmd.types > 1 {
                self.switch(&mut cmd);
            }
            cmd.left = cmd.left.wrapping_sub(1);
            let sym = decode(cmd_codes.tree(cmd.current()), &mut self.br);
            let (ic, cc, implicit) = split_command(sym);
            let (ic, cc) = (ic % 24, cc % 24);
            let insert = INS_BASE[ic] as usize + self.br.read(u32::from(INS_EXTRA[ic])) as usize;
            let copy = COPY_BASE[cc] as usize + self.br.read(u32::from(COPY_EXTRA[cc])) as usize;
            if insert > remaining {
                return Err(Error::BadBlockLength);
            }
            self.room(insert)?;
            self.reserve(insert);
            for _ in 0..insert {
                if lit.left == 0 && lit.types > 1 {
                    self.switch(&mut lit);
                    let t = lit.current();
                    lit_slice = 64 * t;
                    lut = 512 * usize::from(modes.get(t).copied().unwrap_or(0) & 3);
                }
                lit.left = lit.left.wrapping_sub(1);
                let ctx =
                    CONTEXT_LUT[lut + usize::from(p1)] | CONTEXT_LUT[lut + 256 + usize::from(p2)];
                let tree = lit_map
                    .get(lit_slice + usize::from(ctx))
                    .copied()
                    .unwrap_or(0);
                let b = decode(lit_codes.tree(usize::from(tree)), &mut self.br) as u8;
                self.out.push(b);
                p2 = p1;
                p1 = b;
                if self.br.overrun() {
                    return Err(Error::Truncated);
                }
            }
            remaining -= insert;
            if remaining == 0 {
                break;
            }

            let dist;
            let mut push = true;
            if implicit {
                dist = self.last[0];
                push = false;
            } else {
                if dst.left == 0 && dst.types > 1 {
                    self.switch(&mut dst);
                }
                dst.left = dst.left.wrapping_sub(1);
                let dctx = match copy {
                    2 => 0,
                    3 => 1,
                    4 => 2,
                    _ => 3,
                };
                let tree = dist_map.get(4 * dst.current() + dctx).copied().unwrap_or(0);
                let code = decode(dist_codes.tree(usize::from(tree)), &mut self.br);
                if code < 16 {
                    dist = match code {
                        0 => {
                            push = false;
                            self.last[0]
                        }
                        1..=3 => self.last[code],
                        _ => {
                            let (base, delta): (usize, i64) = match code {
                                4 => (self.last[0], -1),
                                5 => (self.last[0], 1),
                                6 => (self.last[0], -2),
                                7 => (self.last[0], 2),
                                8 => (self.last[0], -3),
                                9 => (self.last[0], 3),
                                10 => (self.last[1], -1),
                                11 => (self.last[1], 1),
                                12 => (self.last[1], -2),
                                13 => (self.last[1], 2),
                                14 => (self.last[1], -3),
                                _ => (self.last[1], 3),
                            };
                            let d = base as i64 + delta;
                            if d <= 0 {
                                return Err(Error::BadDistance);
                            }
                            d as usize
                        }
                    };
                } else {
                    let (off, extra) = dist_lut.get(code).copied().unwrap_or((0, 0));
                    let x = self.br.read(u32::from(extra)) as usize;
                    dist = off as usize + (x << npostfix);
                }
            }
            self.check()?;
            let max_distance = self.out.len().min(max_backward);
            if dist > max_distance {
                // A static dictionary reference.
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
                let mut buf = [0u8; 64];
                let n = transform_word(&mut buf, w, t);
                if n > remaining {
                    return Err(Error::BadBlockLength);
                }
                self.room(n)?;
                self.reserve(n);
                self.out.extend_from_slice(&buf[..n]);
                remaining -= n;
            } else {
                if push {
                    self.last = [dist, self.last[0], self.last[1], self.last[2]];
                }
                if copy > remaining {
                    return Err(Error::BadBlockLength);
                }
                self.room(copy)?;
                self.reserve(copy);
                let start = self.out.len() - dist;
                let mut left = copy;
                while left > 0 {
                    let n = left.min(self.out.len() - start);
                    self.out.extend_from_within(start..start + n);
                    left -= n;
                }
                remaining -= copy;
            }
            let n = self.out.len();
            p1 = self.out.get(n.wrapping_sub(1)).copied().unwrap_or(0);
            p2 = self.out.get(n.wrapping_sub(2)).copied().unwrap_or(0);
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    }
}
