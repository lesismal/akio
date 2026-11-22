//! Brotli decompression (RFC 7932): one-shot, and the resumable pieces the streaming
//! [`Decompressor`](crate::Decompressor) is made of.
//!
//! The output vector is the sliding window: back-references read the bytes already written,
//! and distances beyond `min(output so far, window - 16)` address a raw dictionary, if any,
//! then the static dictionary. Every length declared by the stream is checked against the
//! meta-block length and the caller's limit before any byte is produced or any space is
//! reserved for it, so memory stays within the limit plus the prefix code tables (a few
//! megabytes at most, whatever the stream says). Reading past the end of the input yields zero
//! bits that are counted, and the decoder checks at least once per command and per literal
//! that none of them was consumed, so a truncated stream costs no more than its own length
//! plus the output limit.

use crate::Error;
use crate::bits::BitReader;
use crate::dictionary::{DICTIONARY, OFFSETS_BY_LENGTH, SIZE_BITS_BY_LENGTH, transform_word};
use crate::huffman::{Lengths, Tree, code_length_table, decode, decode_loaded_at, single};
use crate::shared::{Dict, MAX_TRANSFORMED, Shared, SharedDictionary};
use crate::tables::{BLOCK_LEN, CMD_LUT, CODE_LENGTH_ORDER, CONTEXT_LUT};

/// Decompresses the brotli stream `data`, which must be exactly one complete stream, into at
/// most `limit` bytes.
///
/// Fails with [`Error::TooLarge`] as soon as the output would exceed `limit` (before reserving
/// memory for it), with [`Error::Truncated`] if `data` ends early and with
/// [`Error::TrailingData`] if bytes follow the end of the stream.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    decompress_with_dictionary(data, limit, &[])
}

/// [`decompress`] with a raw (LZ77 prefix) dictionary, as `brotli -D` and Google's
/// `BrotliDecoderAttachDictionary(BROTLI_SHARED_DICTIONARY_RAW, ...)` use one: distances just
/// beyond the window (beyond the output so far while it is shorter than the window) copy
/// from `dict`, as if it preceded the output, and the static dictionary's addresses start
/// after it. The stream must have been compressed with the same dictionary.
pub fn decompress_with_dictionary(
    data: &[u8],
    limit: usize,
    dict: &[u8],
) -> Result<Vec<u8>, Error> {
    one_shot(data, limit, Dict::raw(dict))
}

/// [`decompress`] with a shared dictionary (RFC 9841): its LZ77 prefix as
/// [`decompress_with_dictionary`] uses a raw dictionary, and its custom static dictionaries,
/// if any, in place of brotli's built-in one (see [`SharedDictionary`]). The stream must have
/// been compressed with the same dictionary.
pub fn decompress_with_shared_dictionary(
    data: &[u8],
    limit: usize,
    dict: &SharedDictionary,
) -> Result<Vec<u8>, Error> {
    one_shot(data, limit, dict.view())
}

fn one_shot(data: &[u8], limit: usize, dict: Dict<'_>) -> Result<Vec<u8>, Error> {
    let mut d = Decoder::new(BitReader::new(data), Vec::new(), 0, limit, dict);
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

/// What a distance beyond the window refers to, written at `pos`: bytes of the raw
/// dictionary `dict.prefix` (`Ok((n, true))`: the distance enters the ring like a backward
/// copy's) or a static dictionary word (`Ok((n, false))`); `max_distance` is the window's
/// reach, `lut` the context lookup of the current literal block type (which selects among the
/// custom static dictionaries, if any).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn dictionary_word(
    buf: &mut Vec<u8>,
    pos: usize,
    dist: usize,
    max_distance: usize,
    copy: usize,
    end: usize,
    limit: usize,
    dict: &Dict<'_>,
    lut: &[u8; 512],
) -> Result<(usize, bool), Error> {
    if dist > MAX_ALLOWED_DISTANCE {
        return Err(Error::BadDistance);
    }
    let beyond = dist - max_distance - 1;
    let prefix = dict.prefix;
    if beyond < prefix.len() {
        let dict = prefix;
        // As Google's decoder: the copy stays within the dictionary.
        let at = dict.len() - beyond - 1;
        if copy > dict.len() - at {
            return Err(Error::BadDistance);
        }
        if copy > end - pos {
            return Err(Error::BadBlockLength);
        }
        if copy > limit - pos {
            return Err(Error::TooLarge);
        }
        reserve(buf, pos, copy, end, limit);
        buf[pos..pos + copy].copy_from_slice(&dict[at..at + copy]);
        return Ok((copy, true));
    }
    let address = beyond - prefix.len();
    if let Some(s) = dict.shared {
        return custom_word(buf, pos, dist, address, copy, end, limit, s, lut);
    }
    if !(4..=24).contains(&copy) {
        return Err(Error::BadDictionaryReference);
    }
    let shift = SIZE_BITS_BY_LENGTH[copy];
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
    Ok((n, false))
}

/// [`dictionary_word`] for a static dictionary reference to the custom static dictionaries of
/// `s`, the one tried first chosen by the literal context of the last two output bytes.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn custom_word(
    buf: &mut Vec<u8>,
    pos: usize,
    dist: usize,
    address: usize,
    copy: usize,
    end: usize,
    limit: usize,
    s: &Shared,
    lut: &[u8; 512],
) -> Result<(usize, bool), Error> {
    let p1 = if pos > 0 { buf[pos - 1] } else { 0 };
    let p2 = if pos > 1 { buf[pos - 2] } else { 0 };
    let ctx = usize::from(lut[usize::from(p1)] | lut[256 + usize::from(p2)]);
    let mut tmp = [0u8; MAX_TRANSFORMED];
    let n = s
        .word(address, copy, ctx, &mut tmp)
        .ok_or(Error::BadDictionaryReference)?;
    // As Google's decoder: an empty word at a distance that may take no bits to code (and
    // could repeat forever) is an error.
    if n == 0 && dist <= 120 {
        return Err(Error::BadDictionaryReference);
    }
    if n > end - pos {
        return Err(Error::BadBlockLength);
    }
    if n > limit - pos {
        return Err(Error::TooLarge);
    }
    reserve(buf, pos, n, end, limit);
    buf[pos..pos + n].copy_from_slice(&tmp[..n]);
    Ok((n, false))
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

/// Code lengths of the code length code: bit length and symbol for each value of the next four
/// bits (RFC 7932 section 3.5).
const CL_CODE_LEN: [u8; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
const CL_CODE_VAL: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

pub(crate) struct Decoder<'a, 'd> {
    pub(crate) br: BitReader<'a>,
    /// The output, which is also the window: `buf[..pos]`. The rest of `buf` is zeroed room
    /// ahead (never past `limit`, in length or capacity), so that matches can be copied in
    /// whole chunks.
    pub(crate) buf: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) limit: usize,
    /// The stream position of `buf[0]`: 0, unless a streaming decoder slid its window.
    pub(crate) base: usize,
    /// The last four distances, most recent first.
    pub(crate) last: [usize; 4],
    /// Scratch space for code lengths.
    pub(crate) lens: Lengths,
    /// The raw prefix and custom static dictionaries.
    dict: Dict<'d>,
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
#[derive(Default)]
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

/// What a meta-block header (RFC 7932 section 9.2) up to its length says.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MetaHead {
    /// ISLAST and ISLASTEMPTY: the stream ends.
    LastEmpty,
    /// Metadata of `len` bytes (skipped), after the byte alignment.
    Metadata { len: usize, last: bool },
    /// `len` uncompressed bytes, after the byte alignment.
    Uncompressed { len: usize },
    /// A compressed meta-block of `len` bytes.
    Compressed { len: usize, last: bool },
}

/// A compressed meta-block's header, decoded: what its commands need. The block switching
/// state in it changes as the commands are decoded.
#[derive(Default)]
pub(crate) struct Meta {
    lit: Blocks,
    cmd: Blocks,
    dst: Blocks,
    npostfix: u32,
    modes: Vec<u8>,
    lit_codes: Group,
    cmd_codes: Group,
    dist_codes: Group,
    dist_map: Vec<u8>,
    /// Distance symbol -> (offset, extra bits), RFC 7932 section 4.
    dist_lut: Vec<(u32, u8)>,
    /// Per literal block type: the one tree of all its contexts, if its context map says so.
    uniform: Vec<Option<usize>>,
    /// Per literal block type: where the tree of each context starts in `lit_codes.tables`.
    ctx_starts: Vec<[u32; 64]>,
}

/// A context map being read.
#[derive(Default)]
struct MapState {
    size: usize,
    ntrees: usize,
    rle: usize,
    table: Vec<u32>,
    map: Vec<u8>,
    /// Entries read; `usize::MAX` before the tree count and code are.
    i: usize,
}

/// A compressed meta-block's header being read, one unit at a time (a block type
/// description, a context map entry, a prefix code), so that a streaming decoder short of
/// input resumes at the last unit instead of starting the header again.
#[derive(Default)]
pub(crate) struct HeaderBuild {
    stage: u8,
    lit: Blocks,
    cmd: Blocks,
    dst: Blocks,
    npostfix: u32,
    ndirect: usize,
    modes: Vec<u8>,
    map: MapState,
    lit_map: (usize, Vec<u8>),
    dist_map: (usize, Vec<u8>),
    lit_codes: Group,
    cmd_codes: Group,
    dist_codes: Group,
}

/// What [`HeaderBuild::restore`] puts back: the stage, the context map's position and the
/// sizes of the prefix code groups.
#[derive(Clone, Copy)]
struct HeaderMark {
    stage: u8,
    map_i: usize,
    groups: [(usize, usize); 3],
}

impl HeaderBuild {
    fn mark(&self) -> HeaderMark {
        let g = |g: &Group| (g.tables.len(), g.starts.len());
        HeaderMark {
            stage: self.stage,
            map_i: self.map.i,
            groups: [g(&self.lit_codes), g(&self.cmd_codes), g(&self.dist_codes)],
        }
    }

    fn restore(&mut self, m: HeaderMark) {
        self.stage = m.stage;
        self.map.i = m.map_i;
        for (g, (t, s)) in [
            &mut self.lit_codes,
            &mut self.cmd_codes,
            &mut self.dist_codes,
        ]
        .into_iter()
        .zip(m.groups)
        {
            g.tables.truncate(t);
            g.starts.truncate(s);
        }
    }
}

/// How [`Decoder::commands`] stopped (other than with an error).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Run {
    /// The meta-block is complete.
    Done,
    /// The output reached the pause position (at a command boundary).
    Paused,
    /// The input ran out; the state is back at the last command boundary.
    Suspended,
}

/// The state of the command loop at a command boundary.
#[derive(Clone, Copy)]
struct Checkpoint<'a> {
    br: BitReader<'a>,
    pos: usize,
    last: [usize; 4],
    lit: ([usize; 2], u32),
    cmd: ([usize; 2], u32),
    dst: ([usize; 2], u32),
}

impl<'a, 'd> Decoder<'a, 'd> {
    pub(crate) fn new(
        br: BitReader<'a>,
        buf: Vec<u8>,
        pos: usize,
        limit: usize,
        dict: Dict<'d>,
    ) -> Self {
        Decoder {
            br,
            buf,
            pos,
            limit,
            base: 0,
            last: [4, 11, 15, 16],
            lens: Lengths::default(),
            dict,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.br.overrun() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Appends `src` (whose length was checked against the limit).
    pub(crate) fn extend(&mut self, src: &[u8]) {
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
            match self.meta_head()? {
                MetaHead::LastEmpty => break,
                MetaHead::Metadata { len, last } => {
                    self.br.take_bytes(len).ok_or(Error::Truncated)?;
                    if last {
                        break;
                    }
                }
                MetaHead::Uncompressed { len } => {
                    let bytes = self.br.take_bytes(len).ok_or(Error::Truncated)?;
                    self.room(len)?;
                    self.extend(bytes);
                }
                MetaHead::Compressed { len, last } => {
                    let mut h = HeaderBuild::default();
                    let mut m = self.header::<false>(&mut h)?.ok_or(Error::Truncated)?;
                    let end = self.pos.saturating_add(len);
                    self.commands::<false>(&mut m, end, max_backward, usize::MAX)?;
                    if last {
                        break;
                    }
                }
            }
        }
        self.end_of_stream(input_len)
    }

    /// After the last meta-block: the padding bits are zero and the input ends there.
    pub(crate) fn end_of_stream(&mut self, input_len: usize) -> Result<(), Error> {
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

    /// Reads a meta-block header up to its length (and the alignment that follows metadata and
    /// uncompressed lengths).
    pub(crate) fn meta_head(&mut self) -> Result<MetaHead, Error> {
        let is_last = self.br.read(1) == 1;
        if is_last && self.br.read(1) == 1 {
            return Ok(MetaHead::LastEmpty);
        }
        let mnibbles = self.br.read(2);
        if mnibbles == 3 {
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
            return Ok(MetaHead::Metadata { len, last: is_last });
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
            return Ok(MetaHead::Uncompressed { len: mlen });
        }
        Ok(MetaHead::Compressed {
            len: mlen,
            last: is_last,
        })
    }

    pub(crate) fn window_bits(&mut self) -> Result<u32, Error> {
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

    /// Reads the next unit of a compressed meta-block's header into `h`; `Some` with the
    /// decoded header after the last one.
    fn header_unit<const STREAM: bool>(
        &mut self,
        h: &mut HeaderBuild,
    ) -> Result<Option<Meta>, Error> {
        match h.stage {
            0 => h.lit = self.blocks()?,
            1 => h.cmd = self.blocks()?,
            2 => h.dst = self.blocks()?,
            3 => {
                h.npostfix = self.br.read(2);
                h.ndirect = (self.br.read(4) as usize) << h.npostfix;
                h.modes = vec![0u8; h.lit.types];
                for m in &mut h.modes {
                    *m = self.br.read(2) as u8;
                }
                self.check()?;
                h.map = MapState {
                    size: 64 * h.lit.types,
                    i: usize::MAX,
                    ..MapState::default()
                };
            }
            4 | 5 => {
                if !self.context_map_unit::<STREAM>(&mut h.map)? {
                    return Ok(None);
                }
                let st = std::mem::take(&mut h.map);
                if h.stage == 4 {
                    h.lit_map = (st.ntrees, st.map);
                    h.map = MapState {
                        size: 4 * h.dst.types,
                        i: usize::MAX,
                        ..MapState::default()
                    };
                } else {
                    h.dist_map = (st.ntrees, st.map);
                }
            }
            6..=8 => {
                let (g, n, size) = match h.stage {
                    6 => (&mut h.lit_codes, h.lit_map.0, 256),
                    7 => (&mut h.cmd_codes, h.cmd.types, 704),
                    _ => (
                        &mut h.dist_codes,
                        h.dist_map.0,
                        16 + h.ndirect + (48 << h.npostfix),
                    ),
                };
                if g.starts.len() < n {
                    if g.tables.capacity() == 0 {
                        g.tables.reserve(n * 320);
                        g.starts.reserve(n);
                    }
                    let at = g.tables.len();
                    let r = self.prefix_code(size, &mut g.tables);
                    if r.is_err() {
                        g.tables.truncate(at);
                    }
                    r?;
                    g.starts.push(at);
                    if g.starts.len() < n {
                        return Ok(None);
                    }
                }
            }
            _ => return Ok(Some(Self::finish_header(h))),
        }
        h.stage += 1;
        Ok(None)
    }

    /// Reads the next unit of a context map: its tree count and code, one entry or run (all
    /// of them in one go without `STREAM`), or the inverse move-to-front bit at the end.
    /// `true` when the map is complete.
    fn context_map_unit<const STREAM: bool>(&mut self, st: &mut MapState) -> Result<bool, Error> {
        if st.i == usize::MAX {
            st.ntrees = self.var_len_u8() + 1;
            st.map = vec![0u8; st.size];
            if st.ntrees == 1 {
                st.i = st.size;
                return Ok(true);
            }
            st.rle = if self.br.read(1) == 1 {
                self.br.read(4) as usize + 1
            } else {
                0
            };
            let mut table = Vec::new();
            self.prefix_code(st.ntrees + st.rle, &mut table)?;
            st.table = table;
            st.i = 0;
            return Ok(false);
        }
        if st.i < st.size {
            loop {
                self.check()?;
                let code = decode(&st.table, &mut self.br);
                if code == 0 {
                    st.map[st.i] = 0;
                    st.i += 1;
                } else if code <= st.rle {
                    let reps = (1usize << code) + self.br.read(code as u32) as usize;
                    if st.i + reps > st.size {
                        return Err(Error::BadContextMap);
                    }
                    st.map[st.i..st.i + reps].fill(0);
                    st.i += reps;
                } else {
                    st.map[st.i] = (code - st.rle) as u8;
                    st.i += 1;
                }
                if STREAM || st.i >= st.size {
                    break;
                }
            }
            self.check()?;
            return Ok(false);
        }
        let imtf = self.br.read(1) == 1;
        self.check()?;
        if imtf {
            // Inverse move-to-front.
            let mut mtf: [u8; 256] = std::array::from_fn(|i| i as u8);
            for v in &mut st.map {
                let idx = usize::from(*v);
                let val = mtf[idx];
                *v = val;
                mtf.copy_within(0..idx, 1);
                mtf[0] = val;
            }
        }
        Ok(true)
    }

    fn finish_header(h: &mut HeaderBuild) -> Meta {
        let h = std::mem::take(h);
        let npostfix = h.npostfix;
        let ndirect = h.ndirect;
        let dist_size = 16 + ndirect + (48 << npostfix);
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
        let lit_codes = h.lit_codes;
        let lit_map = h.lit_map.1;
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
        let ctx_starts: Vec<[u32; 64]> = lit_map
            .chunks_exact(64)
            .map(|m| std::array::from_fn(|c| lit_codes.start(usize::from(m[c])) as u32))
            .collect();
        Meta {
            lit: h.lit,
            cmd: h.cmd,
            dst: h.dst,
            npostfix,
            modes: h.modes,
            lit_codes,
            cmd_codes: h.cmd_codes,
            dist_codes: h.dist_codes,
            dist_map: h.dist_map.1,
            dist_lut,
            uniform,
            ctx_starts,
        }
    }

    /// Reads a compressed meta-block's header (after its length) into `h`. A streaming
    /// decoder (`STREAM`) short of input gets `Ok(None)`, with the reader at the end of the
    /// last complete unit (in `h`) to resume from with more input.
    pub(crate) fn header<const STREAM: bool>(
        &mut self,
        h: &mut HeaderBuild,
    ) -> Result<Option<Meta>, Error> {
        loop {
            let cp = self.br;
            let mark = if STREAM { Some(h.mark()) } else { None };
            let r = self.header_unit::<STREAM>(h);
            if let Some(mark) = mark.filter(|_| self.br.overrun()) {
                // The unit used bits past the input (whatever it concluded from them).
                self.br = cp;
                h.restore(mark);
                return Ok(None);
            }
            if let Some(m) = r? {
                return Ok(Some(m));
            }
        }
    }

    /// Decodes the commands of the meta-block `m` ending at `end` (in `buf`) with distances
    /// up to `max_backward`. A streaming decoder (`STREAM`) stops at a command boundary when
    /// the input runs out ([`Run::Suspended`], with the reader and the output back at that
    /// boundary) or once the output reaches `pause_at` ([`Run::Paused`]).
    pub(crate) fn commands<const STREAM: bool>(
        &mut self,
        m: &mut Meta,
        end: usize,
        max_backward: usize,
        pause_at: usize,
    ) -> Result<Run, Error> {
        let mut lit = std::mem::take(&mut m.lit);
        let mut cmd = std::mem::take(&mut m.cmd);
        let mut dst = std::mem::take(&mut m.dst);
        let mr: &Meta = m;
        let npostfix = mr.npostfix;
        let lit_codes = &mr.lit_codes;
        let cmd_codes = &mr.cmd_codes;
        let dist_codes = &mr.dist_codes;
        let dist_lut = &mr.dist_lut[..];
        let lit_tree_of = |t: usize| mr.uniform.get(t).copied().flatten();
        let lut_of = |t: usize| -> &'static [u8; 512] {
            let m = usize::from(mr.modes.get(t).copied().unwrap_or(0) & 3);
            CONTEXT_LUT[512 * m..512 * m + 512]
                .try_into()
                .unwrap_or(&[0; 512])
        };
        // Per distance block type: the start of the tree of each of the four distance contexts.
        let dist_trees_of = |t: usize| -> [Tree<'_>; 4] {
            std::array::from_fn(|c| {
                let tree = mr.dist_map.get(4 * t + c).copied().unwrap_or(0);
                Tree::at(&dist_codes.tables, dist_codes.start(usize::from(tree)))
            })
        };
        let dict = self.dict;
        let base = if STREAM { self.base } else { 0 };
        // The decoding state lives in locals, so that it can stay in registers (stores to the
        // output through `self` would otherwise force it back to memory); it is put back at the
        // end (on errors the decoder is dropped).
        let mut br = std::mem::replace(&mut self.br, BitReader::new(&[]));
        let mut buf = std::mem::take(&mut self.buf);
        let mut pos = self.pos;
        let mut last = self.last;
        let limit = self.limit;
        // `pos + n <= fast` means that `n` more bytes are within the meta-block and the limit,
        // and that `buf` has `WILD` bytes of room past them; otherwise `make_room` sorts it out.
        let mut fast = fast_end(&buf, end, limit);
        let mut lit_type = lit.current();
        let mut lut = lut_of(lit_type);
        let mut lit_tree = lit_tree_of(lit_type);
        let mut cmd_tree = Tree::at(&cmd_codes.tables, cmd_codes.start(cmd.current()));
        let mut dist_trees = dist_trees_of(dst.current());
        let lit_tables = &lit_codes.tables[..];
        let mut cp = Checkpoint {
            br,
            pos,
            last,
            lit: (lit.ring, lit.left),
            cmd: (cmd.ring, cmd.left),
            dst: (dst.ring, dst.left),
        };
        // A streaming decoder short of input goes back to the last command boundary; an
        // error is the stream's only if no bit past the input was used.
        macro_rules! bail {
            ($e:expr) => {{
                let e = $e;
                if STREAM && br.overrun() {
                    break Run::Suspended;
                }
                return Err(e);
            }};
        }
        macro_rules! tryb {
            ($r:expr) => {
                match $r {
                    Ok(v) => v,
                    Err(e) => bail!(e),
                }
            };
        }
        let run = loop {
            if br.overrun() {
                bail!(Error::Truncated);
            }
            if STREAM {
                cp = Checkpoint {
                    br,
                    pos,
                    last,
                    lit: (lit.ring, lit.left),
                    cmd: (cmd.ring, cmd.left),
                    dst: (dst.ring, dst.left),
                };
                if pos >= pause_at {
                    break Run::Paused;
                }
            }
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
                    fast = tryb!(make_room(&mut buf, pos, insert, end, limit));
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
                        let starts = mr.ctx_starts.get(lit_type).unwrap_or(&[0; 64]);
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
                    bail!(Error::Truncated);
                }
                if pos == end {
                    break Run::Done;
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
                        bail!(Error::BadDistance);
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
            if br.overrun() {
                bail!(Error::Truncated);
            }
            let max_distance = (pos + base).min(max_backward);
            if dist > max_distance {
                let (n, ring) = tryb!(dictionary_word(
                    &mut buf,
                    pos,
                    dist,
                    max_distance,
                    copy,
                    end,
                    limit,
                    &dict,
                    lut
                ));
                if ring && push {
                    last = [dist, last[0], last[1], last[2]];
                }
                pos += n;
                fast = fast_end(&buf, end, limit);
            } else {
                if push {
                    last = [dist, last[0], last[1], last[2]];
                }
                if pos + copy > fast {
                    fast = tryb!(make_room(&mut buf, pos, copy, end, limit));
                }
                copy_match(&mut buf, pos - dist, pos, copy);
                pos += copy;
            }
            if pos == end {
                break Run::Done;
            }
        };
        if STREAM && run == Run::Suspended {
            br = cp.br;
            pos = cp.pos;
            last = cp.last;
            (lit.ring, lit.left) = cp.lit;
            (cmd.ring, cmd.left) = cp.cmd;
            (dst.ring, dst.left) = cp.dst;
        }
        self.br = br;
        self.buf = buf;
        self.pos = pos;
        self.last = last;
        m.lit = lit;
        m.cmd = cmd;
        m.dst = dst;
        Ok(run)
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
