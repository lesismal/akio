//! RFC 9841 shared dictionaries for tests and fuzzing: a serializer, random dictionaries and
//! hand-made streams of exact dictionary references (one per meta-block, under a chosen
//! literal context mode), and the `brotli_shared` target.

use crate::bits::BitWriter;
use crate::shared::MAX_TRANSFORMED;
use crate::tables::{CMD_LUT, CONTEXT_LUT};
use crate::{
    Decompressor, Level, SharedDictionary, compress_with_shared_dictionary,
    decompress_with_shared_dictionary,
};

use super::{LIMIT, agree, piece, streamed};

/// A transform list: the prefix / suffix stringlets (the empty one that ends the list is
/// added, at index `strings.len()`), then (prefix, operation, suffix, parameter) of each
/// transform.
pub type TransformSpec = (Vec<Vec<u8>>, Vec<(u8, u8, u8, u16)>);

/// A shared dictionary to serialize (RFC 9841 section 5, with Google's transform layout).
#[derive(Clone, Debug, Default)]
pub struct DictSpec {
    /// The LZ77 prefix.
    pub prefix: Vec<u8>,
    /// Word lists: log2 of the word count of each length 4..=31 (0: none), then the words.
    pub words: Vec<([u8; 28], Vec<u8>)>,
    /// Transform lists.
    pub transforms: Vec<TransformSpec>,
    /// (word list, transform list) of each dictionary; the list count means brotli's own.
    pub dicts: Vec<(u8, u8)>,
    /// The dictionary to try first per literal context.
    pub context_map: Option<[u8; 64]>,
}

impl DictSpec {
    /// The serialized dictionary.
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = vec![0x91, 0];
        let mut n = self.prefix.len();
        loop {
            let b = (n & 127) as u8;
            n >>= 7;
            if n == 0 {
                o.push(b);
                break;
            }
            o.push(b | 128);
        }
        o.extend_from_slice(&self.prefix);
        o.push(self.words.len() as u8);
        for (bits, data) in &self.words {
            o.extend_from_slice(bits);
            o.extend_from_slice(data);
        }
        o.push(self.transforms.len() as u8);
        for (strings, list) in &self.transforms {
            let mut area = Vec::new();
            for s in strings {
                area.push(s.len() as u8);
                area.extend_from_slice(s);
            }
            area.push(0);
            o.extend_from_slice(&(area.len() as u16).to_le_bytes());
            o.extend_from_slice(&area);
            o.push(list.len() as u8);
            for &(p, op, s, _) in list {
                o.extend_from_slice(&[p, op, s]);
            }
            if list.iter().any(|t| t.1 == 21 || t.1 == 22) {
                for t in list {
                    o.extend_from_slice(&t.3.to_le_bytes());
                }
            }
        }
        if !self.words.is_empty() || !self.transforms.is_empty() {
            o.push(self.dicts.len() as u8);
            for &(w, t) in &self.dicts {
                o.extend_from_slice(&[w, t]);
            }
            match &self.context_map {
                None => o.push(0),
                Some(m) => {
                    o.push(1);
                    o.extend_from_slice(m);
                }
            }
        }
        o
    }

    /// The number of words of length `len` in list `w`.
    fn count(&self, w: u8, len: usize) -> usize {
        match self.words.get(usize::from(w)) {
            Some((bits, _)) if bits[len - 4] > 0 => 1 << bits[len - 4],
            Some(_) => 0,
            None if len <= 24 => 1 << crate::dictionary::SIZE_BITS_BY_LENGTH[len],
            None => 0,
        }
    }

    fn num_transforms(&self, t: u8) -> usize {
        self.transforms
            .get(usize::from(t))
            .map_or(121, |(_, list)| list.len())
    }
}

/// A source of choices: the fuzzer's bytes (zeros once they run out), or a seeded generator.
#[derive(Debug)]
pub struct Source<'a> {
    data: &'a [u8],
    at: usize,
    seed: u64,
}

impl<'a> Source<'a> {
    /// Choices from `data`.
    pub fn bytes(data: &'a [u8]) -> Self {
        Source {
            data,
            at: 0,
            seed: 0,
        }
    }

    /// Pseudo-random choices from `seed` (not 0).
    pub fn seeded(seed: u64) -> Source<'static> {
        Source {
            data: &[],
            at: 0,
            seed: seed | 1,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.seed != 0 {
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            return (self.seed >> 24) as u8;
        }
        let b = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }

    /// 0..n (n <= 65536).
    fn below(&mut self, n: usize) -> usize {
        let v = usize::from(self.byte()) | usize::from(self.byte()) << 8;
        if n == 0 { 0 } else { v % n }
    }

    /// The bytes not used yet (none for a seeded source).
    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.at..).unwrap_or(&[])
    }

    /// A byte of text that exercises the transforms: ASCII letters, spaces, UTF-8 lead and
    /// continuation bytes, anything.
    fn text(&mut self) -> u8 {
        const LEADS: [u8; 6] = [0xc3, 0xd0, 0xe2, 0xe9, 0xf0, 0xf8];
        match self.byte() % 8 {
            0..=2 => b'a' + self.byte() % 26,
            3 => b'A' + self.byte() % 26,
            4 => b" .,<>\"'"[usize::from(self.byte() % 7)],
            5 => LEADS[usize::from(self.byte() % 6)],
            6 => 0x80 | (self.byte() % 64),
            _ => self.byte(),
        }
    }
}

/// A small random dictionary: a prefix of up to 40 bytes, up to 3 word lists (up to 16 words
/// of a length), up to 3 transform lists (up to 12 transforms of any operation), up to 4
/// dictionaries, sometimes context-dependent.
pub fn random_spec(s: &mut Source<'_>) -> DictSpec {
    let mut d = DictSpec {
        prefix: (0..s.below(41)).map(|_| s.text()).collect(),
        ..DictSpec::default()
    };
    for _ in 0..s.below(4) {
        let mut bits = [0u8; 28];
        let mut data = Vec::new();
        for (i, b) in bits.iter_mut().enumerate() {
            if s.below(10) < 3 {
                *b = 1 + s.below(4) as u8;
                data.extend((0..(i + 4) << *b).map(|_| s.text()));
            }
        }
        d.words.push((bits, data));
    }
    for _ in 0..s.below(4) {
        let strings: Vec<Vec<u8>> = (0..s.below(6))
            .map(|_| (0..=s.below(6)).map(|_| s.text()).collect())
            .collect();
        let n = strings.len() + 1;
        let list = (0..s.below(13))
            .map(|_| {
                let op = s.below(23) as u8;
                let param = if op >= 21 { s.below(65536) as u16 } else { 0 };
                (s.below(n) as u8, op, s.below(n) as u8, param)
            })
            .collect();
        d.transforms.push((strings, list));
    }
    if !d.words.is_empty() || !d.transforms.is_empty() {
        let (nw, nt) = (d.words.len() + 1, d.transforms.len() + 1);
        d.dicts = (0..=s.below(4))
            .map(|_| (s.below(nw) as u8, s.below(nt) as u8))
            .collect();
        if s.byte() & 1 == 1 {
            let n = d.dicts.len();
            d.context_map = Some(std::array::from_fn(|_| s.below(n) as u8));
        }
    }
    d
}

/// One reference of [`references_stream`]: a static dictionary word (`len` 4..=31, distance
/// beyond the window and the prefix by `address`), or a copy from the LZ77 prefix.
#[derive(Clone, Copy, Debug)]
pub struct Reference {
    /// Literal context mode of the meta-block (0..=3).
    pub mode: u8,
    /// Copy length.
    pub len: usize,
    /// Distance.
    pub dist: usize,
    /// The meta-block's length (the bytes the reference should produce).
    pub mlen: usize,
}

/// The insert-and-copy symbol for insert 0 and copy `len` with an explicit distance, and the
/// copy length's extra bits.
fn copy_symbol(len: usize) -> (u64, u32, u64) {
    for (sym, c) in CMD_LUT.iter().enumerate().take(704) {
        let base = c.copy_base as usize;
        if !c.implicit
            && c.ins_base == 0
            && c.ins_extra == 0
            && base <= len
            && len < base + (1 << c.copy_extra)
        {
            return (sym as u64, u32::from(c.copy_extra), (len - base) as u64);
        }
    }
    (0, 0, 0)
}

/// A stream (window 2¹⁶) of `lead` as an uncompressed meta-block (if not empty, up to 64 KiB),
/// then one compressed meta-block per reference whose prefix codes all have a single symbol:
/// the command is (insert 0, copy `len`), the distance coded with `NPOSTFIX` = `NDIRECT` = 0.
pub fn references_stream(lead: &[u8], refs: &[Reference]) -> Vec<u8> {
    let mut w = BitWriter::with_capacity(64 + lead.len() + 16 * refs.len());
    w.bits(1, 0); // WBITS 16
    if !lead.is_empty() {
        w.bits(1, 0);
        w.bits(2, 0);
        w.bits(16, (lead.len() - 1) as u64);
        w.bits(1, 1);
        w.bytes(lead);
    }
    for (i, r) in refs.iter().enumerate() {
        let last = i + 1 == refs.len();
        w.bits(1, u64::from(last));
        if last {
            w.bits(1, 0);
        }
        w.bits(2, 0);
        w.bits(16, (r.mlen.clamp(1, 65536) - 1) as u64);
        if !last {
            w.bits(1, 0);
        }
        w.bits(3, 0); // one block type each
        w.bits(6, 0); // NPOSTFIX, NDIRECT
        w.bits(2, u64::from(r.mode & 3));
        w.bits(2, 0); // one literal tree, one distance tree
        w.bits(2, 1); // literals: a single symbol
        w.bits(2, 0);
        w.bits(8, u64::from(b'z'));
        let (sym, nextra, extra) = copy_symbol(r.len);
        w.bits(2, 1);
        w.bits(2, 0);
        w.bits(10, sym);
        // Distance symbol and extra bits (as in RFC 7932 section 4).
        let v = r.dist as u64 + 3;
        let nb = 63 - v.leading_zeros() - 1;
        let dsym = 16 + 2 * u64::from(nb - 1) + ((v >> nb) & 1);
        w.bits(2, 1);
        w.bits(2, 0);
        w.bits(6, dsym);
        w.bits(nextra, extra);
        w.bits(nb, v & ((1 << nb) - 1));
    }
    if refs.is_empty() {
        w.bits(2, 0b11);
    }
    w.finish()
}

/// A random case for dictionary `spec`: a stream of a few references (mostly valid) and the
/// output of our decoder's model of them (`None` when a reference is invalid: the stream
/// ends with it). The window reach is the output so far; static references are chosen from
/// the address space of every dictionary for their length.
pub fn random_references(
    s: &mut Source<'_>,
    spec: &DictSpec,
    dict: &SharedDictionary,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let lead: Vec<u8> = (0..s.below(7)).map(|_| s.text()).collect();
    let mut out = lead.clone();
    let mut refs = Vec::new();
    let view = dict.view();
    let mut valid = true;
    for _ in 0..=s.below(4) {
        let mode = s.byte() & 3;
        let max_distance = out.len();
        let base = max_distance + 1 + spec.prefix.len();
        let (len, dist, produced);
        if !spec.prefix.is_empty() && s.below(5) == 0 {
            // A copy from the prefix (the copy must stay within it).
            let at = s.below(spec.prefix.len());
            len = (2 + s.below(8)).min(spec.prefix.len() - at);
            if len < 2 {
                continue;
            }
            dist = max_distance + spec.prefix.len() - at;
            produced = Some(spec.prefix[at..at + len].to_vec());
        } else {
            len = 4 + s.below(28);
            let space: usize = if spec.dicts.is_empty() {
                spec.count(0, len) * 121
            } else {
                spec.dicts
                    .iter()
                    .map(|&(w, t)| spec.count(w, len) * spec.num_transforms(t))
                    .sum()
            };
            // Mostly within the space, sometimes just past it.
            let address = s.below(space + 2);
            dist = base + address;
            let p1 = out.last().copied().unwrap_or(0);
            let p2 = if out.len() > 1 { out[out.len() - 2] } else { 0 };
            let lut = &CONTEXT_LUT[512 * usize::from(mode)..];
            let ctx = usize::from(lut[usize::from(p1)] | lut[256 + usize::from(p2)]);
            let mut tmp = [0u8; MAX_TRANSFORMED];
            produced = match view.shared {
                Some(sh) => sh.word(address, len, ctx, &mut tmp),
                None => (4..=24)
                    .contains(&len)
                    .then(|| {
                        let shift = crate::dictionary::SIZE_BITS_BY_LENGTH[len];
                        let t = address >> shift;
                        (t < 121).then(|| {
                            let at = crate::dictionary::OFFSETS_BY_LENGTH[len] as usize
                                + (address & ((1 << shift) - 1)) * len;
                            let mut b = [0u8; 64];
                            let n = crate::dictionary::transform_word(
                                &mut b,
                                &crate::dictionary::DICTIONARY[at..at + len],
                                t,
                            );
                            tmp[..n].copy_from_slice(&b[..n]);
                            n
                        })
                    })
                    .flatten(),
            }
            .map(|n| tmp[..n].to_vec());
        }
        match produced {
            Some(p) if p.is_empty() => continue,
            Some(p) => {
                refs.push(Reference {
                    mode,
                    len,
                    dist,
                    mlen: p.len(),
                });
                out.extend_from_slice(&p);
            }
            None => {
                refs.push(Reference {
                    mode,
                    len,
                    dist,
                    mlen: len,
                });
                valid = false;
                break;
            }
        }
    }
    (references_stream(&lead, &refs), valid.then_some(out))
}

/// `brotli_shared`: a dictionary and a stream from the fuzzer's bytes. `data[0]`: with bit 0
/// clear, `data[1..]` is parsed as a serialized dictionary (never panics; a dictionary that
/// parses decodes a reference stream); with bit 0 set, a random valid dictionary (checked to
/// parse) and a stream of references to it decode to what the model says, one-shot and
/// streamed in pieces sized by `data[0]`, and the rest of the bytes, as an arbitrary stream,
/// decodes the same both ways, and compresses and decompresses with the dictionary.
pub fn shared(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let step = piece(cfg >> 1);
    if cfg & 1 == 0 {
        if let Ok(dict) = SharedDictionary::new(body) {
            let mut s = Source::bytes(body);
            let spec = DictSpec {
                prefix: dict.prefix().to_vec(),
                ..DictSpec::default()
            };
            let (stream, _) = random_references(&mut s, &spec, &dict);
            let one = decompress_with_shared_dictionary(&stream, LIMIT, &dict);
            let st = streamed(
                Decompressor::with_shared_dictionary(&dict),
                &stream,
                step,
                LIMIT + 1,
            );
            agree(one, st);
        }
        return;
    }
    let mut s = Source::bytes(body);
    let spec = random_spec(&mut s);
    let ser = spec.serialize();
    let dict = SharedDictionary::new(&ser).expect("generated dictionary parses");
    assert_eq!(dict.prefix(), &spec.prefix[..]);
    let (stream, want) = random_references(&mut s, &spec, &dict);
    let one = decompress_with_shared_dictionary(&stream, LIMIT, &dict);
    match &want {
        Some(w) => assert!(one.as_ref() == Ok(w), "reference stream decodes wrong"),
        None => assert!(one.is_err(), "invalid reference accepted"),
    }
    let st = streamed(
        Decompressor::with_shared_dictionary(&dict),
        &stream,
        step,
        LIMIT + 1,
    );
    agree(one, st);
    let rest = s.rest();
    let one = decompress_with_shared_dictionary(rest, LIMIT, &dict);
    let st = streamed(
        Decompressor::with_shared_dictionary(&dict),
        rest,
        step,
        LIMIT + 1,
    );
    agree(one, st);
    let level = Level::new(u32::from(cfg >> 4));
    let packed = compress_with_shared_dictionary(level, rest, &dict);
    let back = decompress_with_shared_dictionary(&packed, rest.len(), &dict);
    assert!(
        back.as_deref() == Ok(rest),
        "shared dictionary round trip differs"
    );
}
