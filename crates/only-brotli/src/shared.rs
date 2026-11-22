//! Shared dictionaries (RFC 9841): an LZ77 prefix, custom static dictionaries (word lists and
//! transform lists, possibly several, chosen by the literal context) or both, from the
//! serialized format of RFC 9841 section 5.
//!
//! The layout follows Google's parser (`c/common/shared_dictionary.c`), the format's reference
//! implementation, where the RFC's prose differs: a transform is the triplet (prefix index,
//! operation, suffix index), in that order (the RFC lists the operation last); the LZ77 prefix
//! is at most 2³⁰ - 1 bytes, its length a varint of at most five bytes. Unlike Google's parser,
//! bytes after the last field are refused.

use std::ops::Range;
use std::sync::{Arc, OnceLock};

use crate::Error;
use crate::dictionary::{
    DICTIONARY, OFFSETS_BY_LENGTH, SIZE_BITS_BY_LENGTH, TRANSFORMS, to_upper, transform_word,
};

/// The longest word of a custom word list.
pub(crate) const MAX_WORD: usize = 31;

/// Room for a transformed word: a prefix and a suffix of up to 255 bytes around a word.
pub(crate) const MAX_TRANSFORMED: usize = 255 + MAX_WORD + 255;

/// The index of brotli's built-in word list or transform list in [`Custom::dicts`].
const BUILTIN: u8 = u8::MAX;

/// Word lists, transform lists and dictionaries of one shared dictionary (at most 64 each).
const MAX_LISTS: usize = 64;

/// The largest operation index (`ShiftAll`).
const MAX_OP: u8 = 22;
const OP_FERMENT_FIRST: u8 = 10;
const OP_FERMENT_ALL: u8 = 11;
const OP_SHIFT_FIRST: u8 = 21;
const OP_SHIFT_ALL: u8 = 22;

/// A shared dictionary for brotli (RFC 9841): an LZ77 prefix (a raw dictionary) and, from the
/// serialized format, custom static dictionaries that replace or extend brotli's built-in
/// one.
///
/// - [`SharedDictionary::new`] parses the serialized format (RFC 9841 section 5, signature
///   `0x91 0x00`): an LZ77 prefix, up to 64 custom word lists (words of 4 to 31 bytes) and
///   transform lists (prefix, suffix and one of 23 operations, the RFC 7932 ones plus
///   `ShiftFirst` / `ShiftAll`), up to 64 dictionaries that pair a word list with a transform
///   list (each may be brotli's own), and optionally a map from the 64 literal contexts to the
///   dictionary tried first. A static dictionary reference picks the dictionary of the
///   context of the last two output bytes (by the current literal block type's context mode),
///   and addresses beyond it continue in the others, in order.
/// - [`SharedDictionary::raw`] is a raw (LZ77 prefix) dictionary with the built-in static
///   dictionary, what [`decompress_with_dictionary`](crate::decompress_with_dictionary) takes.
///
/// Decoding: [`decompress_with_shared_dictionary`](crate::decompress_with_shared_dictionary),
/// [`Decompressor::with_shared_dictionary`](crate::Decompressor::with_shared_dictionary).
/// Encoding ([`compress_with_shared_dictionary`](crate::compress_with_shared_dictionary)) uses
/// the prefix only, and no static dictionary words when the dictionary has custom ones.
/// Cloning shares the dictionary.
///
/// ```
/// use only_brotli::{Level, SharedDictionary, compress_with_shared_dictionary,
///                   decompress_with_shared_dictionary};
///
/// // A serialized dictionary with only an LZ77 prefix: signature, varint length, bytes, no
/// // word lists, no transform lists.
/// let mut ser = vec![0x91, 0x00, 11];
/// ser.extend_from_slice(b"hello world");
/// ser.extend_from_slice(&[0, 0]);
/// let dict = SharedDictionary::new(&ser).unwrap();
/// assert_eq!(dict.prefix(), b"hello world");
/// let packed = compress_with_shared_dictionary(Level::DEFAULT, b"hello world!", &dict);
/// assert_eq!(decompress_with_shared_dictionary(&packed, 100, &dict).unwrap(), b"hello world!");
/// ```
#[derive(Clone)]
pub struct SharedDictionary {
    inner: Arc<Shared>,
}

impl std::fmt::Debug for SharedDictionary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("SharedDictionary");
        d.field("prefix_len", &self.inner.prefix.len());
        if let Some(c) = &self.inner.custom {
            d.field("word_lists", &c.words.len())
                .field("transform_lists", &c.transforms.len())
                .field("dictionaries", &c.dicts.len())
                .field("context_based", &c.context_map.is_some());
        }
        d.finish()
    }
}

impl SharedDictionary {
    /// Parses a serialized shared dictionary (RFC 9841 section 5). Fails with
    /// [`Error::BadDictionary`] if `serialized` is not one (a wrong signature, a field out of
    /// range, an index to a list that does not exist, data missing or left over).
    pub fn new(serialized: &[u8]) -> Result<SharedDictionary, Error> {
        let mut s = parse(serialized).ok_or(Error::BadDictionary)?;
        s.bytes = serialized.into();
        Ok(SharedDictionary { inner: Arc::new(s) })
    }

    /// A raw (LZ77 prefix) dictionary `prefix` with brotli's built-in static dictionary.
    pub fn raw(prefix: &[u8]) -> SharedDictionary {
        SharedDictionary {
            inner: Arc::new(Shared {
                bytes: prefix.into(),
                prefix: 0..prefix.len(),
                custom: None,
                index: OnceLock::new(),
            }),
        }
    }

    /// The LZ77 prefix (empty: none).
    pub fn prefix(&self) -> &[u8] {
        self.inner.prefix()
    }

    /// Whether the static dictionary is brotli's built-in one (no custom word or transform
    /// lists): then the dictionary is the same as the raw dictionary [`prefix`](Self::prefix).
    pub fn is_raw(&self) -> bool {
        self.inner.custom.is_none()
    }

    /// This dictionary with `prefix` as its LZ77 prefix (its custom static dictionaries
    /// kept): what several prefixes and a serialized dictionary attached together make (the
    /// prefixes concatenated in order, as Google's compound dictionary).
    pub(crate) fn with_prefix(&self, prefix: &[u8]) -> SharedDictionary {
        let Some(custom) = &self.inner.custom else {
            return SharedDictionary::raw(prefix);
        };
        // The custom lists index `bytes`: the new prefix goes after them.
        let mut bytes = self.inner.bytes.to_vec();
        let at = bytes.len();
        bytes.extend_from_slice(prefix);
        SharedDictionary {
            inner: Arc::new(Shared {
                bytes: bytes.into(),
                prefix: at..at + prefix.len(),
                custom: Some(Custom {
                    words: custom
                        .words
                        .iter()
                        .map(|w| WordList {
                            size_bits: w.size_bits,
                            offsets: w.offsets,
                            data: w.data.clone(),
                        })
                        .collect(),
                    transforms: custom
                        .transforms
                        .iter()
                        .map(|t| TransformList {
                            strings: t.strings.clone(),
                            list: t.list.clone(),
                        })
                        .collect(),
                    dicts: custom.dicts.clone(),
                    context_map: custom.context_map,
                }),
                index: OnceLock::new(),
            }),
        }
    }

    /// The custom static dictionaries, for the encoder (`None`: brotli's built-in one).
    pub(crate) fn custom(&self) -> Option<&Shared> {
        self.inner.custom.as_ref().map(|_| &*self.inner)
    }

    /// What the decoder uses.
    pub(crate) fn view(&self) -> Dict<'_> {
        Dict {
            prefix: self.inner.prefix(),
            shared: self.inner.custom.as_ref().map(|_| &*self.inner),
        }
    }
}

/// The dictionaries a decoder uses: a raw prefix (possibly empty) and, if not brotli's own,
/// the custom static dictionaries.
#[derive(Clone, Copy, Default)]
pub(crate) struct Dict<'d> {
    pub(crate) prefix: &'d [u8],
    pub(crate) shared: Option<&'d Shared>,
}

impl<'d> Dict<'d> {
    pub(crate) fn raw(prefix: &'d [u8]) -> Self {
        Dict {
            prefix,
            shared: None,
        }
    }
}

pub(crate) struct Shared {
    /// The serialized dictionary (or the raw prefix); the ranges below index it.
    bytes: Box<[u8]>,
    prefix: Range<usize>,
    /// `None`: brotli's built-in static dictionary.
    custom: Option<Custom>,
    /// The encoder's index of each dictionary's transformed words, built when first needed.
    index: OnceLock<Vec<Option<WordIndex>>>,
}

struct Custom {
    words: Vec<WordList>,
    transforms: Vec<TransformList>,
    /// Each dictionary's word list and transform list (`BUILTIN`: brotli's own).
    dicts: Vec<(u8, u8)>,
    /// The dictionary to try first for each literal context (none: the first one).
    context_map: Option<[u8; 64]>,
}

struct WordList {
    /// log2 of the number of words of each length 0..=31 (0: none).
    size_bits: [u8; 32],
    /// Where the words of each length start in `data`.
    offsets: [u32; 32],
    data: Range<usize>,
}

struct TransformList {
    /// The contents of each prefix / suffix stringlet.
    strings: Vec<Range<usize>>,
    list: Vec<Transform>,
}

#[derive(Clone, Copy)]
struct Transform {
    prefix: u8,
    op: u8,
    suffix: u8,
    param: u16,
}

/// A cursor over the serialized bytes; every read fails past the end.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn take(&mut self, n: usize) -> Option<Range<usize>> {
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let r = self.pos..end;
        self.pos = end;
        Some(r)
    }

    /// A varint of at most five bytes that fits 32 bits (Google's `ReadVarint32`).
    fn varint32(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..5 {
            let b = self.u8()?;
            if i == 4 && b > 15 {
                return None;
            }
            v |= u32::from(b & 127) << (7 * i);
            if b < 128 {
                return Some(v);
            }
        }
        None
    }
}

fn parse(b: &[u8]) -> Option<Shared> {
    if b.get(..2)? != [0x91, 0] {
        return None;
    }
    let mut r = Reader { b, pos: 2 };
    let plen = r.varint32()?;
    if plen > (1 << 30) - 1 {
        return None;
    }
    let prefix = r.take(plen as usize)?;
    let nwords = usize::from(r.u8()?);
    if nwords > MAX_LISTS {
        return None;
    }
    let mut words = Vec::with_capacity(nwords);
    for _ in 0..nwords {
        words.push(word_list(&mut r)?);
    }
    let ntransforms = usize::from(r.u8()?);
    if ntransforms > MAX_LISTS {
        return None;
    }
    let mut transforms = Vec::with_capacity(ntransforms);
    for _ in 0..ntransforms {
        transforms.push(transform_list(&mut r)?);
    }
    let custom = if nwords > 0 || ntransforms > 0 {
        let ndicts = usize::from(r.u8()?);
        if ndicts == 0 || ndicts > MAX_LISTS {
            return None;
        }
        let mut dicts = Vec::with_capacity(ndicts);
        for _ in 0..ndicts {
            let w = usize::from(r.u8()?);
            let t = usize::from(r.u8()?);
            if w > nwords || t > ntransforms {
                return None;
            }
            let id = |i: usize, n: usize| if i == n { BUILTIN } else { i as u8 };
            dicts.push((id(w, nwords), id(t, ntransforms)));
        }
        let context_map = match r.u8()? {
            0 => None,
            1 => {
                let mut map = [0u8; 64];
                for m in &mut map {
                    *m = r.u8()?;
                    if usize::from(*m) >= ndicts {
                        return None;
                    }
                }
                Some(map)
            }
            _ => return None,
        };
        Some(Custom {
            words,
            transforms,
            dicts,
            context_map,
        })
    } else {
        None
    };
    if r.pos != b.len() {
        return None;
    }
    Some(Shared {
        bytes: Box::default(),
        prefix,
        custom,
        index: OnceLock::new(),
    })
}

fn word_list(r: &mut Reader<'_>) -> Option<WordList> {
    let mut size_bits = [0u8; 32];
    let mut offsets = [0u32; 32];
    let mut total = 0u32;
    for b in &mut size_bits[4..] {
        *b = r.u8()?;
        if *b > 15 {
            return None;
        }
    }
    for (len, (&bits, off)) in size_bits.iter().zip(&mut offsets).enumerate() {
        *off = total;
        if bits > 0 {
            total += (len as u32) << bits;
        }
    }
    let data = r.take(total as usize)?;
    Some(WordList {
        size_bits,
        offsets,
        data,
    })
}

fn transform_list(r: &mut Reader<'_>) -> Option<TransformList> {
    let lo = r.u8()?;
    let hi = r.u8()?;
    let len = usize::from(u16::from_le_bytes([lo, hi]));
    if len == 0 {
        return None;
    }
    // The stringlets, then at least the transform count.
    let area = r.take(len)?;
    if r.pos >= r.b.len() {
        return None;
    }
    let mut strings = Vec::new();
    let mut at = area.start;
    loop {
        let n = usize::from(r.b[at]);
        at += 1;
        strings.push(at..at + n);
        if n == 0 {
            if at != area.end {
                return None;
            }
            break;
        }
        if strings.len() > 255 {
            return None;
        }
        at += n;
        if at >= area.end {
            return None;
        }
    }
    let count = usize::from(r.u8()?);
    let triplets = r.take(3 * count)?;
    let mut list = Vec::with_capacity(count);
    let mut has_params = false;
    for t in r.b[triplets].chunks_exact(3) {
        let (prefix, op, suffix) = (t[0], t[1], t[2]);
        if usize::from(prefix) >= strings.len()
            || op > MAX_OP
            || usize::from(suffix) >= strings.len()
        {
            return None;
        }
        has_params |= op == OP_SHIFT_FIRST || op == OP_SHIFT_ALL;
        list.push(Transform {
            prefix,
            op,
            suffix,
            param: 0,
        });
    }
    if has_params {
        let params = r.take(2 * count)?;
        for (t, p) in list.iter_mut().zip(r.b[params].chunks_exact(2)) {
            let param = u16::from_le_bytes([p[0], p[1]]);
            if param != 0 && t.op != OP_SHIFT_FIRST && t.op != OP_SHIFT_ALL {
                return None;
            }
            t.param = param;
        }
    }
    Some(TransformList { strings, list })
}

impl Shared {
    fn prefix(&self) -> &[u8] {
        &self.bytes[self.prefix.clone()]
    }

    fn size_bits(&self, c: &Custom, w: u8, len: usize) -> u32 {
        u32::from(if w == BUILTIN {
            SIZE_BITS_BY_LENGTH.get(len).copied().unwrap_or(0)
        } else {
            c.words[usize::from(w)].size_bits[len]
        })
    }

    fn num_transforms(c: &Custom, t: u8) -> usize {
        if t == BUILTIN {
            TRANSFORMS.len()
        } else {
            c.transforms[usize::from(t)].list.len()
        }
    }

    /// Writes the static dictionary word at `address` of length `len` (4..=31), chosen for
    /// literal context `ctx`, transformed, to the start of `out` and returns its length;
    /// `None` if the address names no word (RFC 9841 section 3.1, Google's decoder).
    #[inline(never)]
    pub(crate) fn word(
        &self,
        address: usize,
        len: usize,
        ctx: usize,
        out: &mut [u8; MAX_TRANSFORMED],
    ) -> Option<usize> {
        let c = self.custom.as_ref()?;
        if !(4..=MAX_WORD).contains(&len) {
            return None;
        }
        let first = c.context_map.map_or(0, |m| m[ctx & 63]);
        let (mut w, mut t) = c.dicts[usize::from(first)];
        let mut shift = self.size_bits(c, w, len);
        let mut address = address;
        if (address >> shift >= Self::num_transforms(c, t) || shift == 0) && c.dicts.len() > 1 {
            // Beyond the first dictionary: the others, in order.
            let words = |shift: u32| if shift == 0 { 0 } else { 1usize << shift };
            let mut rem = address.checked_sub(words(shift) * Self::num_transforms(c, t))?;
            for (i, &(w2, t2)) in c.dicts.iter().enumerate() {
                let shift2 = self.size_bits(c, w2, len);
                if i == usize::from(first) || shift2 == 0 {
                    continue;
                }
                let n = words(shift2) * Self::num_transforms(c, t2);
                if rem < n {
                    (w, t, shift, address) = (w2, t2, shift2, rem);
                    break;
                }
                rem -= n;
            }
        }
        if shift == 0 {
            return None;
        }
        let idx = address & ((1 << shift) - 1);
        let ti = address >> shift;
        if ti >= Self::num_transforms(c, t) {
            return None;
        }
        let word = if w == BUILTIN {
            let at = OFFSETS_BY_LENGTH[len] as usize + idx * len;
            DICTIONARY.get(at..at + len)?
        } else {
            let l = &c.words[usize::from(w)];
            let at = l.data.start + l.offsets[len] as usize + idx * len;
            self.bytes.get(at..at + len)?
        };
        if t == BUILTIN {
            let mut tmp = [0u8; 64];
            let n = transform_word(&mut tmp, word, ti);
            out[..n].copy_from_slice(&tmp[..n]);
            return Some(n);
        }
        let list = &c.transforms[usize::from(t)];
        Some(self.transform(list, ti, word, out))
    }

    /// `word` under transform `ti` of the custom list `list`.
    fn transform(
        &self,
        list: &TransformList,
        ti: usize,
        word: &[u8],
        out: &mut [u8; MAX_TRANSFORMED],
    ) -> usize {
        let tr = list.list[ti];
        let prefix = &self.bytes[list.strings[usize::from(tr.prefix)].clone()];
        let suffix = &self.bytes[list.strings[usize::from(tr.suffix)].clone()];
        let mut n = prefix.len();
        out[..n].copy_from_slice(prefix);
        let w = match tr.op {
            1..=9 => &word[..word.len().saturating_sub(usize::from(tr.op))],
            12..=20 => word.get(usize::from(tr.op - 11)..).unwrap_or(&[]),
            _ => word,
        };
        let start = n;
        out[n..n + w.len()].copy_from_slice(w);
        n += w.len();
        let body = &mut out[start..n];
        match tr.op {
            OP_FERMENT_FIRST => {
                to_upper(body);
            }
            OP_FERMENT_ALL => {
                let mut i = 0;
                while i < body.len() {
                    i += to_upper(&mut body[i..]);
                }
            }
            OP_SHIFT_FIRST => {
                shift(body, tr.param);
            }
            OP_SHIFT_ALL => {
                let mut i = 0;
                while i < body.len() {
                    i += shift(&mut body[i..], tr.param);
                }
            }
            _ => {}
        }
        out[n..n + suffix.len()].copy_from_slice(suffix);
        n + suffix.len()
    }
}

/// `ShiftFirst` on the start of `w` (RFC 9841 section 3.1.1): adds the sign-extended `param`
/// to the scalar of the 1- to 4-byte pattern there and returns the pattern's length (all of
/// `w` if it is cut short; a lone continuation byte or an invalid lead byte is 1).
fn shift(w: &mut [u8], param: u16) -> usize {
    let Some(&b0) = w.first() else {
        return 1;
    };
    let len = w.len();
    // Limited sign extension (24 bits are enough: no scalar has more than 21).
    let add = u32::from(param & 0x7fff) + (0x100_0000 - u32::from(param & 0x8000));
    let cont = |b: u8| u32::from(b & 0x3f);
    if b0 < 0x80 {
        let s = add + u32::from(b0);
        w[0] = (s & 0x7f) as u8;
        1
    } else if b0 < 0xc0 {
        1
    } else if b0 < 0xe0 {
        if len < 2 {
            return 1;
        }
        let s = add + (cont(w[1]) | u32::from(b0 & 0x1f) << 6);
        w[0] = 0xc0 | ((s >> 6) & 0x1f) as u8;
        w[1] = (w[1] & 0xc0) | (s & 0x3f) as u8;
        2
    } else if b0 < 0xf0 {
        if len < 3 {
            return len;
        }
        let s = add + (cont(w[2]) | cont(w[1]) << 6 | u32::from(b0 & 0x0f) << 12);
        w[0] = 0xe0 | ((s >> 12) & 0x0f) as u8;
        w[1] = (w[1] & 0xc0) | ((s >> 6) & 0x3f) as u8;
        w[2] = (w[2] & 0xc0) | (s & 0x3f) as u8;
        3
    } else if b0 < 0xf8 {
        if len < 4 {
            return len;
        }
        let s =
            add + (cont(w[3]) | cont(w[2]) << 6 | cont(w[1]) << 12 | u32::from(b0 & 0x07) << 18);
        w[0] = 0xf0 | ((s >> 18) & 0x07) as u8;
        w[1] = (w[1] & 0xc0) | ((s >> 12) & 0x3f) as u8;
        w[2] = (w[2] & 0xc0) | ((s >> 6) & 0x3f) as u8;
        w[3] = (w[3] & 0xc0) | (s & 0x3f) as u8;
        4
    } else {
        1
    }
}

// ---- The encoder's search ----------------------------------------------------------------------

/// A dictionary for the encoder to search.
pub(crate) enum Search<'a> {
    /// Brotli's built-in words and transforms (addresses as in RFC 7932).
    Builtin,
    /// An index of the dictionary's transformed words.
    Index(&'a WordIndex),
}

/// Every word of one dictionary (a word list and a transform list) under every transform,
/// as far as the result has at least four bytes, by its first four (Google's encoder builds
/// such a trie at its highest qualities): `matches` finds those that the input starts with.
pub(crate) struct WordIndex {
    /// Per bucket, where its entries start (and the next bucket's start).
    starts: Vec<u32>,
    entries: Vec<Entry>,
    /// The transformed words, back to back.
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Entry {
    at: u32,
    out: u16,
    len: u8,
    addr: u32,
}

const INDEX_BITS: u32 = 16;
/// At most this many transformed words are indexed per dictionary (in transform order: the
/// first transforms of a list are usually the most useful), and this many bytes of them.
const MAX_ENTRIES: usize = 1 << 21;
const MAX_BYTES: usize = 32 << 20;

fn index_bucket(b: &[u8]) -> usize {
    let k = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (k.wrapping_mul(0x1E35_A7BD) >> (32 - INDEX_BITS)) as usize
}

impl WordIndex {
    /// Calls `f(output length, word length, address)` for each indexed word whose
    /// transformation `s` starts with.
    pub(crate) fn matches(&self, s: &[u8], mut f: impl FnMut(usize, usize, u32)) {
        if s.len() < 4 {
            return;
        }
        let b = index_bucket(s);
        let (from, to) = (self.starts[b] as usize, self.starts[b + 1] as usize);
        for e in &self.entries[from..to] {
            let (at, out) = (e.at as usize, usize::from(e.out));
            if out <= s.len() && s[..out] == self.bytes[at..at + out] {
                f(out, usize::from(e.len), e.addr);
            }
        }
    }
}

impl Shared {
    /// Whether the dictionary used first depends on the literal context.
    pub(crate) fn context_based(&self) -> bool {
        self.custom
            .as_ref()
            .is_some_and(|c| c.context_map.is_some())
    }

    /// The dictionaries a static dictionary reference at literal context `ctx` addresses, in
    /// order: the context's own first (its addresses from 0), then the others in the order of
    /// the list, each after all words of the ones before (as the decoder resolves an address;
    /// Google's encoder searches the first two). Calls `f(search, base)` for each with
    /// `base(len)`: the address of its first word of length `len`.
    pub(crate) fn search(&self, ctx: usize, mut f: impl FnMut(Search<'_>, &dyn Fn(usize) -> u32)) {
        let Some(c) = &self.custom else {
            f(Search::Builtin, &|_| 0);
            return;
        };
        let first = usize::from(c.context_map.map_or(0, |m| m[ctx & 63]));
        let index = self.index.get_or_init(|| {
            c.dicts
                .iter()
                .map(|&(w, t)| ((w, t) != (BUILTIN, BUILTIN)).then(|| self.build_index(c, w, t)))
                .collect()
        });
        // The addresses of all words of length `len` of dictionary `d`.
        let size = |d: usize, len: usize| -> u32 {
            let (w, t) = c.dicts[d];
            let shift = self.size_bits(c, w, len);
            if shift == 0 {
                0
            } else {
                (Self::num_transforms(c, t) as u32) << shift
            }
        };
        let search = |d: usize| match &index[d] {
            Some(ix) => Search::Index(ix),
            None => Search::Builtin,
        };
        f(search(first), &|_| 0);
        for d in (0..c.dicts.len()).filter(|&d| d != first) {
            let base = |len: usize| {
                size(first, len)
                    + (0..d)
                        .filter(|&e| e != first)
                        .map(|e| size(e, len))
                        .sum::<u32>()
            };
            f(search(d), &base);
        }
    }

    /// The index of the dictionary of word list `w` and transform list `t`.
    fn build_index(&self, c: &Custom, w: u8, t: u8) -> WordIndex {
        let ntrans = Self::num_transforms(c, t);
        let mut keyed: Vec<(u32, Entry)> = Vec::new();
        let mut bytes = Vec::new();
        let mut out = [0u8; MAX_TRANSFORMED];
        'all: for ti in 0..ntrans {
            for len in 4..=MAX_WORD {
                let shift = self.size_bits(c, w, len);
                if shift == 0 {
                    continue;
                }
                for idx in 0..1usize << shift {
                    let word = if w == BUILTIN {
                        let at = OFFSETS_BY_LENGTH[len] as usize + idx * len;
                        &DICTIONARY[at..at + len]
                    } else {
                        let l = &c.words[usize::from(w)];
                        let at = l.data.start + l.offsets[len] as usize + idx * len;
                        &self.bytes[at..at + len]
                    };
                    let n = if t == BUILTIN {
                        let mut tmp = [0u8; 64];
                        let n = transform_word(&mut tmp, word, ti);
                        out[..n].copy_from_slice(&tmp[..n]);
                        n
                    } else {
                        self.transform(&c.transforms[usize::from(t)], ti, word, &mut out)
                    };
                    if n < 4 {
                        continue;
                    }
                    if keyed.len() >= MAX_ENTRIES || bytes.len() + n > MAX_BYTES {
                        break 'all;
                    }
                    keyed.push((
                        index_bucket(&out[..n]) as u32,
                        Entry {
                            at: bytes.len() as u32,
                            out: n as u16,
                            len: len as u8,
                            addr: ((ti as u32) << shift) | idx as u32,
                        },
                    ));
                    bytes.extend_from_slice(&out[..n]);
                }
            }
        }
        keyed.sort_by_key(|&(b, e)| (b, e.addr));
        let mut starts = vec![0u32; (1 << INDEX_BITS) + 1];
        for &(b, _) in &keyed {
            starts[b as usize + 1] += 1;
        }
        for i in 0..1 << INDEX_BITS {
            starts[i + 1] += starts[i];
        }
        WordIndex {
            starts,
            entries: keyed.into_iter().map(|(_, e)| e).collect(),
            bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SharedDictionary;
    use crate::fuzzing::shared::{
        DictSpec, Reference, Source, TransformSpec, random_references, random_spec,
        references_stream,
    };
    use crate::{
        Decompressor, Error, Level, compress_with_shared_dictionary,
        decompress_with_shared_dictionary,
    };

    /// Word list with `n` words of length 4 (`bits` = log2 n) and nothing else.
    fn words4(bits: u8, words: &[u8]) -> ([u8; 28], Vec<u8>) {
        let mut b = [0u8; 28];
        b[0] = bits;
        assert_eq!(words.len(), 4 << bits);
        (b, words.to_vec())
    }

    /// One static reference of length 4 at `address` (window reach `lead.len()`), the
    /// literal context mode `mode`, expecting `mlen` bytes.
    fn word(
        spec: &DictSpec,
        lead: &[u8],
        mode: u8,
        address: usize,
        mlen: usize,
    ) -> Result<Vec<u8>, Error> {
        let dict = SharedDictionary::new(&spec.serialize()).expect("parses");
        let dist = lead.len() + 1 + spec.prefix.len() + address;
        let s = references_stream(
            lead,
            &[Reference {
                mode,
                len: 4,
                dist,
                mlen,
            }],
        );
        let one = decompress_with_shared_dictionary(&s, 1 << 16, &dict);
        // The streaming decoder agrees, fed a byte at a time.
        let mut d = Decompressor::with_shared_dictionary(&dict);
        let mut out = Vec::new();
        let mut st = Ok(());
        for b in s.chunks(1) {
            if let Err(e) = d.decompress_vec(b, &mut out, 1 << 16) {
                st = Err(e);
                break;
            }
        }
        match &one {
            Ok(o) => assert!(st.is_ok() && d.is_done() && out == *o, "streaming differs"),
            Err(_) => assert!(st.is_err() || !d.is_done(), "streaming accepts"),
        }
        one.map(|o| o[lead.len()..].to_vec())
    }

    fn transforms(strings: &[&[u8]], list: &[(u8, u8, u8, u16)]) -> TransformSpec {
        (strings.iter().map(|s| s.to_vec()).collect(), list.to_vec())
    }

    #[test]
    fn custom_words_and_transforms() {
        // Strings: 0 "<", 1 ">", 2 "" (the terminator).
        let spec = DictSpec {
            prefix: b"PREFIX".to_vec(),
            words: vec![words4(1, b"abcd\xc3\xa9xy")],
            transforms: vec![transforms(
                &[b"<", b">"],
                &[
                    (2, 0, 2, 0),       // identity
                    (0, 0, 1, 0),       // "<" word ">"
                    (2, 11, 2, 0),      // FermentAll
                    (2, 14, 0, 0),      // OmitFirst3, suffix "<"
                    (2, 2, 2, 0),       // OmitLast2
                    (2, 21, 2, 1),      // ShiftFirst +1
                    (2, 22, 2, 0xffff), // ShiftAll -1
                    (2, 10, 2, 0),      // FermentFirst
                ],
            )],
            dicts: vec![(0, 0)],
            context_map: None,
        };
        let w = |a, n| word(&spec, b"", 0, a, n);
        assert_eq!(w(0, 4).unwrap(), b"abcd");
        assert_eq!(w(1, 4).unwrap(), b"\xc3\xa9xy");
        assert_eq!(w(2, 6).unwrap(), b"<abcd>");
        assert_eq!(w(4, 4).unwrap(), b"ABCD");
        // Upper-casing a two-byte character flips bit 5 of its second byte.
        assert_eq!(w(5, 4).unwrap(), b"\xc3\x89XY");
        assert_eq!(w(6, 2).unwrap(), b"d<");
        assert_eq!(w(9, 2).unwrap(), b"\xc3\xa9");
        assert_eq!(w(10, 4).unwrap(), b"bbcd");
        // U+00E9 + 1 = U+00EA.
        assert_eq!(w(11, 4).unwrap(), b"\xc3\xaaxy");
        assert_eq!(w(12, 4).unwrap(), b"`abc");
        assert_eq!(w(13, 4).unwrap(), b"\xc3\xa8wx");
        assert_eq!(w(15, 4).unwrap(), b"\xc3\x89xy");
        // Past the 8 transforms; a length without words.
        assert_eq!(w(16, 4), Err(Error::BadDictionaryReference));
        let dict = SharedDictionary::new(&spec.serialize()).unwrap();
        let s = references_stream(
            b"",
            &[Reference {
                mode: 0,
                len: 5,
                dist: 7,
                mlen: 5,
            }],
        );
        assert_eq!(
            decompress_with_shared_dictionary(&s, 99, &dict),
            Err(Error::BadDictionaryReference)
        );
        // Distances within the prefix still copy from it.
        let s = references_stream(
            b"",
            &[Reference {
                mode: 0,
                len: 3,
                dist: 3,
                mlen: 3,
            }],
        );
        assert_eq!(
            decompress_with_shared_dictionary(&s, 99, &dict).unwrap(),
            b"FIX"
        );
    }

    #[test]
    fn shift_scalars() {
        // Words: a 3-byte character + "a", a 4-byte one, a lone continuation byte + "abc",
        // "zab" + a 2-byte lead cut short at the end (ShiftAll stops there).
        let spec = DictSpec {
            words: vec![words4(2, b"\xe2\x82\xaca\xf0\x9f\x98\x80\x80abczab\xc3")],
            transforms: vec![transforms(&[], &[(0, 22, 0, 2), (0, 21, 0, 0x8000)])],
            dicts: vec![(0, 0)],
            ..DictSpec::default()
        };
        let w = |a, n| word(&spec, b"", 0, a, n);
        assert_eq!(w(0, 4).unwrap(), b"\xe2\x82\xaec"); // U+20AC + 2, 'a' + 2
        assert_eq!(w(1, 4).unwrap(), b"\xf0\x9f\x98\x82"); // U+1F600 + 2
        assert_eq!(w(2, 4).unwrap(), b"\x80cde");
        assert_eq!(w(3, 4).unwrap(), b"|cd\xc3");
        // 0x8000 sign-extends to 0xFF8000: U+20AC - 0x8000 wraps to U+A0AC (16 bits).
        assert_eq!(w(4, 4).unwrap(), b"\xea\x82\xaca");
    }

    #[test]
    fn context_selects_the_dictionary() {
        // Dictionary 0: "aaaa" "bbbb"; dictionary 1: "cccc" "dddd" with brotli's transforms;
        // dictionary 2: brotli's own words and transforms. Context (LSB6 of the last byte)
        // 'x' & 63 starts at dictionary 1, everything else at dictionary 0.
        let mut map = [0u8; 64];
        map[usize::from(b'x' & 63)] = 1;
        let spec = DictSpec {
            words: vec![words4(1, b"aaaabbbb"), words4(1, b"ccccdddd")],
            transforms: vec![transforms(&[], &[(0, 0, 0, 0)])],
            dicts: vec![(0, 0), (1, 1), (2, 1)],
            context_map: Some(map),
            ..DictSpec::default()
        };
        let w = |lead: &[u8], mode, a, n| word(&spec, lead, mode, a, n);
        assert_eq!(w(b"", 0, 0, 4).unwrap(), b"aaaa");
        assert_eq!(w(b"", 0, 1, 4).unwrap(), b"bbbb");
        // Beyond dictionary 0 (2 words x 1 transform): dictionary 1 with brotli's transforms
        // (2 x 121), then dictionary 2 (1024 x 121).
        assert_eq!(w(b"", 0, 2, 4).unwrap(), b"cccc");
        assert_eq!(w(b"", 0, 2 + 2 * 9, 4).unwrap(), b"Cccc");
        assert_eq!(w(b"", 0, 2 + 242, 4).unwrap(), b"time");
        assert_eq!(w(b"", 0, 2 + 242 + (9 << 10), 4).unwrap(), b"Time");
        assert_eq!(
            w(b"", 0, 2 + 242 + (121 << 10), 4),
            Err(Error::BadDictionaryReference)
        );
        // After an 'x', dictionary 1 comes first, then 0, then 2.
        assert_eq!(w(b"x", 0, 0, 4).unwrap(), b"cccc");
        assert_eq!(w(b"x", 0, 1 + 2 * 10, 9).unwrap(), b"dddd and ");
        assert_eq!(w(b"x", 0, 242, 4).unwrap(), b"aaaa");
        assert_eq!(w(b"x", 0, 243, 4).unwrap(), b"bbbb");
        assert_eq!(w(b"x", 0, 244, 4).unwrap(), b"time");
        // The context follows the literal context mode: under MSB6, 'x' >> 2 is context 30.
        assert_eq!(w(b"x", 1, 0, 4).unwrap(), b"aaaa");
        let mut spec2 = spec.clone();
        let mut map = [0u8; 64];
        map[usize::from(b'x' >> 2)] = 1;
        spec2.context_map = Some(map);
        assert_eq!(word(&spec2, b"x", 1, 0, 4).unwrap(), b"cccc");
        assert_eq!(word(&spec2, b"x", 0, 0, 4).unwrap(), b"aaaa");
        // Without the context map the order is 0, 1, 2 whatever the context.
        let mut spec3 = spec.clone();
        spec3.context_map = None;
        assert_eq!(word(&spec3, b"x", 0, 0, 4).unwrap(), b"aaaa");
        // Lengths without words in the first dictionary go to the next one that has some:
        // brotli's 5-byte word 0 is "first".
        let s = SharedDictionary::new(&spec.serialize()).unwrap();
        let st = references_stream(
            b"",
            &[Reference {
                mode: 0,
                len: 5,
                dist: 1,
                mlen: 5,
            }],
        );
        assert_eq!(
            decompress_with_shared_dictionary(&st, 9, &s).unwrap(),
            b"first"
        );
    }

    #[test]
    fn empty_words() {
        // OmitFirst9 of a 4-byte word is empty: an error at a distance of 120 or less (as in
        // Google's decoder), nothing at all beyond.
        let spec = DictSpec {
            words: vec![words4(1, b"abcdefgh")],
            transforms: vec![transforms(&[], &[(0, 20, 0, 0)])],
            dicts: vec![(0, 0)],
            ..DictSpec::default()
        };
        let dict = SharedDictionary::new(&spec.serialize()).unwrap();
        let st = references_stream(
            b"",
            &[Reference {
                mode: 0,
                len: 4,
                dist: 1,
                mlen: 1,
            }],
        );
        assert_eq!(
            decompress_with_shared_dictionary(&st, 9, &dict),
            Err(Error::BadDictionaryReference)
        );
    }

    #[test]
    fn malformed_dictionaries_are_refused() {
        let good = DictSpec {
            prefix: b"pre".to_vec(),
            words: vec![words4(1, b"abcdefgh")],
            transforms: vec![transforms(&[b"x"], &[(0, 21, 1, 7), (1, 0, 0, 0)])],
            dicts: vec![(0, 0), (1, 1)],
            context_map: Some([1; 64]),
        };
        let ser = good.serialize();
        let d = SharedDictionary::new(&ser).unwrap();
        assert_eq!(d.prefix(), b"pre");
        assert!(!d.is_raw());
        // Every truncation fails, and so do trailing bytes.
        for n in 0..ser.len() {
            assert_eq!(
                SharedDictionary::new(&ser[..n]).err(),
                Some(Error::BadDictionary),
                "{n}"
            );
        }
        let mut long = ser;
        long.push(0);
        assert!(SharedDictionary::new(&long).is_err());
        let bad = |f: &dyn Fn(&mut DictSpec)| {
            let mut s = good.clone();
            f(&mut s);
            SharedDictionary::new(&s.serialize()).err()
        };
        let e = Some(Error::BadDictionary);
        assert_eq!(bad(&|s| s.words[0].0[3] = 16), e); // more than 2^15 words
        assert_eq!(bad(&|s| s.transforms[0].1[0].0 = 2), e); // no stringlet 2
        assert_eq!(bad(&|s| s.transforms[0].1[0].2 = 9), e);
        assert_eq!(bad(&|s| s.transforms[0].1[0].1 = 23), e); // no operation 23
        assert_eq!(bad(&|s| s.transforms[0].1[1].3 = 1), e); // a parameter on identity
        assert_eq!(bad(&|s| s.dicts.clear()), e);
        assert_eq!(bad(&|s| s.dicts[0].0 = 2), e); // word lists 0, 1 (built-in) only
        assert_eq!(bad(&|s| s.dicts[0].1 = 2), e);
        assert_eq!(bad(&|s| s.dicts = vec![(0, 0); 65]), e);
        assert_eq!(bad(&|s| s.context_map = Some([2; 64])), e);
        assert_eq!(bad(&|s| s.transforms[0].0 = vec![vec![b'y'; 255]; 256]), e); // 257 strings
        assert_eq!(
            bad(&|s| s.transforms[0].0 = vec![vec![b'y'; 255]; 255]),
            None
        );
        // The serializer writes the list lengths as bytes: 65 lists need the raw bytes.
        let mut ser = vec![0x91, 0, 0, 65];
        ser.extend(std::iter::repeat_n(0, 65 * 28 + 1));
        assert!(SharedDictionary::new(&ser).is_err());
        // Signature, the context flag, an empty stringlet that is not last, a varint too long.
        assert!(SharedDictionary::new(&[0x91, 1, 0, 0, 0]).is_err());
        let mut s = good.serialize();
        let flag = s.len() - 65;
        s[flag] = 2;
        assert!(SharedDictionary::new(&s).is_err());
        assert!(SharedDictionary::new(&[0x91, 0, 0, 0, 1, 3, 0, 0, 1, 0, 0, 1, 0, 0, 0]).is_err());
        assert!(SharedDictionary::new(&[0x91, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0]).is_err());
        assert!(SharedDictionary::new(&[0x91, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0]).is_ok());
        assert!(SharedDictionary::new(&[0x91, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0, 0]).is_err());
        assert!(SharedDictionary::new(&[0x91, 0, 0x80, 0x80, 0x80, 0x80, 0x00, 0, 0]).is_ok());
        // A prefix only, and an empty dictionary, are raw.
        let d = SharedDictionary::new(&[0x91, 0, 2, b'h', b'i', 0, 0]).unwrap();
        assert!(d.is_raw() && d.prefix() == b"hi");
        assert!(SharedDictionary::new(&[0x91, 0, 0, 0, 0]).unwrap().is_raw());
    }

    /// Random dictionaries and reference streams decode to what the model says, one-shot and
    /// streamed (the fuzz target's checks, over fixed seeds).
    #[test]
    fn random_dictionaries() {
        let (mut valid, mut words) = (0, 0);
        for seed in 1..3000u64 {
            let mut s = Source::seeded(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let spec = random_spec(&mut s);
            let dict = SharedDictionary::new(&spec.serialize()).expect("parses");
            let (stream, want) = random_references(&mut s, &spec, &dict);
            let got = decompress_with_shared_dictionary(&stream, 1 << 20, &dict);
            match want {
                Some(w) => {
                    assert_eq!(got.as_ref(), Ok(&w), "seed {seed}");
                    valid += 1;
                    // The encoder finds the words (its own references), and its stream
                    // decodes.
                    if seed % 3 == 0 {
                        let q = 10 + (seed / 3 % 2) as u32;
                        let packed = compress_with_shared_dictionary(Level::new(q), &w, &dict);
                        let back = decompress_with_shared_dictionary(&packed, w.len(), &dict);
                        assert_eq!(back.as_ref(), Ok(&w), "seed {seed} level {q}");
                        words += usize::from(packed.len() < w.len() / 2);
                    }
                }
                None => assert!(got.is_err(), "seed {seed}"),
            }
        }
        assert!(valid > 1000, "{valid}");
        assert!(words > 100, "{words}");
    }
}
