//! The shared brotli framing format (RFC 9841 section 8): a container of resources, each in
//! one data chunk or a run of partial ones, with metadata, dictionary references and an
//! optional central directory.
//!
//! Where the RFC is unclear this follows its main text: bit 2 of the container flags set means
//! a container of several resources with a final footer (section 8.1 and 8.4.11; section
//! 8.4.12 says the opposite); a pointer is the offset of a chunk's first byte (its length
//! varint) in the container; flag bits the RFC does not define must be zero. The RFC names
//! HighwayHash as the hash of resources and dictionaries but no key, so hash codes are opaque
//! here: hash references are resolved by the caller, given hashes are kept but not checked.
//! Repeat metadata (section 8.4.9) is checked against the chunks it repeats: the n-th repeat
//! chunk copies the n-th metadata or footer metadata chunk, its fields are a selection of that
//! chunk's fields (matched as code and value; order free), and a field code given in one is
//! given in all whose copied chunk has it.

use std::borrow::Cow;
use std::ops::Range;

use crate::{
    Compressor, Decompressor, Error, Flush, Level, SharedDictionary, compress,
    compress_with_dictionary, compress_with_shared_dictionary,
};

/// The container signature (its first byte is an invalid brotli window size).
const SIGNATURE: [u8; 4] = [0x91, 0x0a, 0x42, 0x52];
/// Container flag bit 2: several resources, metadata and a final footer.
const MULTI: u8 = 4;

const PADDING: u8 = 0;
const METADATA: u8 = 1;
const DATA: u8 = 2;
const FIRST_PART: u8 = 3;
const MIDDLE_PART: u8 = 4;
const LAST_PART: u8 = 5;
const FOOTER_METADATA: u8 = 6;
const GLOBAL_METADATA: u8 = 7;
const REPEAT_METADATA: u8 = 8;
const DIRECTORY: u8 = 9;
const FINAL_FOOTER: u8 = 10;

const UNCOMPRESSED: u8 = 0;
const KEEP_DECODER: u8 = 1;
const BROTLI: u8 = 2;
const SHARED_BROTLI: u8 = 3;

/// The only hash type: 256-bit HighwayHash.
const HIGHWAYHASH_256: u8 = 3;

/// A resource of a container read by [`read_container`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resource {
    /// The `id` metadata field: a name (UTF-8 by the RFC, not checked), a path if the
    /// container is an archive.
    pub name: Option<Vec<u8>>,
    /// The `mt` metadata field: microseconds since the Unix epoch.
    pub modified: Option<i64>,
    /// The data.
    pub data: Vec<u8>,
    /// The 256-bit HighwayHash of the data the container gives, if any (not checked: the RFC
    /// does not say with which key).
    pub hash: Option<[u8; 32]>,
    /// Not to be extracted: data for other resources to use as a dictionary.
    pub hidden: bool,
    /// The custom fields (two upper-case letters, then the value) of the resource's metadata
    /// chunk, in order.
    pub fields: Vec<([u8; 2], Vec<u8>)>,
    /// The fields of the resource's footer metadata chunk (custom ones only: the RFC defines
    /// no other), in order.
    pub footer: Vec<([u8; 2], Vec<u8>)>,
}

/// A container read by [`Container::read`]: its resources and its global metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Container {
    /// The resources in order, hidden ones included (see [`read_container`]).
    pub resources: Vec<Resource>,
    /// The fields of the global metadata chunks (custom ones only), in order.
    pub global: Vec<([u8; 2], Vec<u8>)>,
}

/// A metadata field: its code and value.
type Field = ([u8; 2], Vec<u8>);

/// What a chunk's header says.
#[derive(Clone, Debug)]
struct Chunk {
    /// Where it starts (its length varint) and ends.
    pos: usize,
    end: usize,
    kind: u8,
    /// `None` for padding, central directory and final footer chunks.
    codec: Option<u8>,
    /// The uncompressed size of its content (compressed codecs).
    size: usize,
    refs: Vec<DictRef>,
    /// Data chunk flags.
    flags: u8,
    hash: Option<[u8; 32]>,
    /// The chunk type a repeat metadata chunk repeats.
    repeats: u8,
    /// Where the header ends: the content.
    content: Range<usize>,
}

#[derive(Clone, Copy, Debug)]
struct DictRef {
    /// 0: a resource by pointer, 1: one chunk's content by pointer, 2: by hash.
    source: u8,
    serialized: bool,
    pointer: usize,
    hash: [u8; 32],
}

/// A cursor over the container; every read fails past the end (as `BadContainer`).
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    end: usize,
}

fn bad<T>() -> Result<T, Error> {
    Err(Error::BadContainer)
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, Error> {
        if self.pos >= self.end {
            return bad();
        }
        self.pos += 1;
        Ok(self.b[self.pos - 1])
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.end - self.pos {
            return bad();
        }
        self.pos += n;
        Ok(&self.b[self.pos - n..self.pos])
    }

    /// A varint (RFC 9841 section 4): at most 63 bits, nine bytes.
    fn varint(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for i in 0..9 {
            let b = self.u8()?;
            v |= u64::from(b & 127) << (7 * i);
            if b < 128 {
                return Ok(v);
            }
        }
        bad()
    }

    fn usize(&mut self) -> Result<usize, Error> {
        usize::try_from(self.varint()?).or_else(|_| bad())
    }
}

/// A reversed varint ending at `end` (exclusive) in `b[start..end]`: its value and where it
/// starts.
fn reversed_varint(b: &[u8], start: usize, end: usize) -> Result<(u64, usize), Error> {
    let mut v = 0u64;
    let mut at = end;
    for i in 0..9 {
        if at <= start {
            return bad();
        }
        at -= 1;
        let x = b[at];
        v |= u64::from(x & 127) << (7 * i);
        if x < 128 {
            return Ok((v, at));
        }
    }
    bad()
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 128 {
        out.push(v as u8 | 128);
        v >>= 7;
    }
    out.push(v as u8);
}

fn varint_len(v: u64) -> usize {
    let mut n = 1;
    let mut v = v >> 7;
    while v > 0 {
        n += 1;
        v >>= 7;
    }
    n
}

/// Parses the chunk at `r.pos` (the container's bytes up to `r.end`).
fn parse_chunk(r: &mut Reader<'_>) -> Result<Chunk, Error> {
    let pos = r.pos;
    let len = r.usize()?;
    if len > r.end - r.pos {
        return bad();
    }
    let end = r.pos + len;
    let mut c = Chunk {
        pos,
        end,
        kind: PADDING,
        codec: None,
        size: 0,
        refs: Vec::new(),
        flags: 0,
        hash: None,
        repeats: 0,
        content: end..end,
    };
    if len == 0 {
        return Ok(c);
    }
    let mut r = Reader {
        b: r.b,
        pos: r.pos,
        end,
    };
    c.kind = r.u8()?;
    match c.kind {
        PADDING => {
            if r.b[r.pos..end].iter().any(|&x| x != 0) {
                return bad();
            }
            c.content = end..end;
            return Ok(c);
        }
        DIRECTORY | FINAL_FOOTER => {
            c.content = r.pos..end;
            return Ok(c);
        }
        METADATA..=REPEAT_METADATA => {}
        _ => return bad(),
    }
    let codec = r.u8()?;
    if codec > SHARED_BROTLI {
        return bad();
    }
    c.codec = Some(codec);
    if codec != UNCOMPRESSED {
        c.size = r.usize()?;
    }
    if codec == SHARED_BROTLI {
        let n = r.u8()?;
        for _ in 0..n {
            let flags = r.u8()?;
            let source = flags & 3;
            let kind = (flags >> 2) & 3;
            if source == 3 || kind > 1 || flags >> 4 != 0 {
                return bad();
            }
            let mut d = DictRef {
                source,
                serialized: kind == 1,
                pointer: 0,
                hash: [0; 32],
            };
            if source == 2 {
                if r.u8()? != HIGHWAYHASH_256 {
                    return bad();
                }
                d.hash.copy_from_slice(r.take(32)?);
            } else {
                d.pointer = r.usize()?;
                // A single chunk's contents cannot be a serialized dictionary.
                if source == 1 && d.serialized {
                    return bad();
                }
            }
            c.refs.push(d);
        }
    }
    match c.kind {
        DATA..=LAST_PART => {
            c.flags = r.u8()?;
            let allowed = match c.kind {
                DATA => 3,
                FIRST_PART => 1,
                MIDDLE_PART => 0,
                _ => 2,
            };
            if c.flags & !allowed != 0 {
                return bad();
            }
            if c.flags & 2 != 0 {
                if r.u8()? != HIGHWAYHASH_256 {
                    return bad();
                }
                let mut h = [0; 32];
                h.copy_from_slice(r.take(32)?);
                c.hash = Some(h);
            }
        }
        REPEAT_METADATA => {
            c.repeats = r.u8()?;
            if !matches!(c.repeats, METADATA | FOOTER_METADATA) {
                return bad();
            }
        }
        _ => {}
    }
    c.content = r.pos..end;
    if codec == UNCOMPRESSED {
        c.size = end - r.pos;
    }
    Ok(c)
}

/// The fields of metadata content (RFC 9841 section 8.3) of a chunk of type `kind`, in order:
/// lower-case fields not defined for the type, a field code that is not two letters of one
/// case, a repeated `id` or `mt`, an `mt` that is not 8 bytes and content past the last field
/// are errors.
fn parse_metadata(b: &[u8], kind: u8) -> Result<Vec<Field>, Error> {
    let mut r = Reader {
        b,
        pos: 0,
        end: b.len(),
    };
    let (mut name, mut modified) = (false, false);
    let mut fields = Vec::new();
    while r.pos < r.end {
        let code = r.take(2)?;
        let (a, z) = (code[0], code[1]);
        let lower = a.is_ascii_lowercase() && z.is_ascii_lowercase();
        let upper = a.is_ascii_uppercase() && z.is_ascii_uppercase();
        if !lower && !upper {
            return bad();
        }
        let n = r.usize()?;
        let v = r.take(n)?;
        if lower {
            match (kind, code) {
                (METADATA, b"id") if !name => name = true,
                (METADATA, b"mt") if !modified && v.len() == 8 => modified = true,
                _ => return bad(),
            }
        }
        fields.push(([a, z], v.to_vec()));
    }
    Ok(fields)
}

/// A metadata chunk's fields as a resource's name, modification time and custom fields.
fn split_metadata(fields: Vec<Field>, res: &mut Resource) {
    for (code, v) in fields {
        match &code {
            b"id" => res.name = Some(v),
            b"mt" => {
                let mut x = [0; 8];
                x.copy_from_slice(&v);
                res.modified = Some(i64::from_le_bytes(x));
            }
            _ => res.fields.push((code, v)),
        }
    }
}

/// The repeat metadata chunks (section 8.4.9) against the chunks they repeat, both as (type,
/// fields) in container order: none, or one per metadata and footer metadata chunk, in the
/// same order and of the same type, each field one of the copied chunk's (code and value), and
/// a code given in any repeat chunk given in every one whose copied chunk has it.
fn check_repeats(
    originals: &[(u8, Vec<Field>)],
    repeats: &[(u8, Vec<Field>)],
) -> Result<(), Error> {
    if repeats.is_empty() {
        return Ok(());
    }
    if repeats.len() != originals.len() {
        return bad();
    }
    let mut given: Vec<[u8; 2]> = repeats
        .iter()
        .flat_map(|(_, f)| f.iter().map(|(c, _)| *c))
        .collect();
    given.sort_unstable();
    given.dedup();
    for ((ok, of), (rk, rf)) in originals.iter().zip(repeats) {
        if ok != rk {
            return bad();
        }
        // A selection of the copied fields: a sub-multiset, by sorting both.
        let mut a: Vec<&Field> = of.iter().collect();
        let mut b: Vec<&Field> = rf.iter().collect();
        a.sort_unstable();
        b.sort_unstable();
        let mut i = 0;
        for f in b {
            while i < a.len() && a[i] < f {
                i += 1;
            }
            if i == a.len() || a[i] != f {
                return bad();
            }
            i += 1;
        }
        // Every code given somewhere and present in the copied chunk is here.
        let mut here: Vec<[u8; 2]> = rf.iter().map(|(c, _)| *c).collect();
        here.sort_unstable();
        for (c, _) in of {
            if given.binary_search(c).is_ok() && here.binary_search(c).is_err() {
                return bad();
            }
        }
    }
    Ok(())
}

/// Repeat metadata chunks decode on their own (section 8.4.9): dictionaries only by hash or an
/// earlier repeat metadata chunk's content, and a "keep decoder" chunk only after another
/// repeat metadata chunk (padding aside).
fn check_repeat_codecs(chunks: &[Chunk]) -> Result<(), Error> {
    let mut prev = PADDING;
    for c in chunks {
        if c.kind == REPEAT_METADATA {
            if c.codec == Some(KEEP_DECODER) && prev != REPEAT_METADATA {
                return bad();
            }
            for d in &c.refs {
                let ok = d.source == 2
                    || (d.source == 1
                        && at(chunks, d.pointer).is_some_and(|p| p.kind == REPEAT_METADATA));
                if !ok {
                    return bad();
                }
            }
        }
        if c.kind != PADDING {
            prev = c.kind;
        }
    }
    Ok(())
}

/// A resource being assembled, and where its chunks are.
struct Building {
    res: Resource,
    /// The position of its first data chunk.
    first: usize,
    complete: bool,
}

/// Reads a shared brotli framing format container (RFC 9841 section 8) and returns its
/// resources in order (hidden ones, meant as dictionaries for others, included and marked);
/// [`Container::read`] also returns the global metadata.
///
/// Every rule of the format is checked: the signature and flags, each chunk's header
/// (types, codecs, dictionary references, flags), metadata fields, the order of chunks (a
/// metadata chunk just before its resource's data, partial data chunks in a run, at most one
/// central directory, the final footer last and only when the flags announce it), a central
/// directory's copies of the chunk headers and the footer's pointers, repeat metadata against
/// the chunks it repeats. Content is decoded by its codec: uncompressed, brotli, shared brotli
/// (large-window streams included, with the dictionaries it references: other resources or
/// chunks by pointer, or by hash through `dictionary`, which returns the dictionary's bytes for
/// a hash or `None`), or the continuation of the previous chunk's stream. All decoded content
/// together (dictionaries and metadata included) must fit in `limit` bytes, or the result is
/// [`Error::TooLarge`].
///
/// Fails with [`Error::BadContainer`] if the container is malformed, with
/// [`Error::MissingDictionary`] if `dictionary` does not know a hash, and with the error of a
/// stream that does not decode (or decodes to another size than its chunk says).
pub fn read_container(
    data: &[u8],
    limit: usize,
    dictionary: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Vec<Resource>, Error> {
    Container::read(data, limit, dictionary).map(|c| c.resources)
}

impl Container {
    /// Reads a container as [`read_container`] does, returning its global metadata besides
    /// its resources.
    pub fn read(
        data: &[u8],
        limit: usize,
        dictionary: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Result<Container, Error> {
        read(data, limit, dictionary)
    }
}

fn read(
    data: &[u8],
    limit: usize,
    dictionary: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Container, Error> {
    if data.get(..4) != Some(&SIGNATURE[..]) {
        return bad();
    }
    let flags = *data.get(4).ok_or(Error::BadContainer)?;
    // Version 0; only bit 2 is defined.
    if flags & !MULTI != 0 {
        return bad();
    }
    let multi = flags & MULTI != 0;
    let mut r = Reader {
        b: data,
        pos: 5,
        end: data.len(),
    };
    let mut chunks = Vec::new();
    while r.pos < r.end {
        let c = parse_chunk(&mut r)?;
        r.pos = c.end;
        chunks.push(c);
    }
    check_order(&chunks, multi)?;
    check_repeat_codecs(&chunks)?;
    let mut left = limit;
    let mut out: Vec<Building> = Vec::new();
    // Decoded content of each chunk with content (for references to one chunk).
    let mut contents: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut stream: Option<Decompressor> = None;
    let mut meta: Vec<Field> = Vec::new();
    let mut global: Vec<Field> = Vec::new();
    // Metadata and footer metadata chunks, and repeat metadata chunks: (type, fields).
    let mut originals: Vec<(u8, Vec<Field>)> = Vec::new();
    let mut repeats: Vec<(u8, Vec<Field>)> = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let Some(codec) = c.codec else {
            if c.kind == DIRECTORY {
                check_directory(data, c, &chunks)?;
            } else if c.kind == FINAL_FOOTER {
                check_footer(data, c, &chunks)?;
            }
            continue;
        };
        if c.size > left {
            return Err(Error::TooLarge);
        }
        let raw = &data[c.content.clone()];
        let content = match codec {
            UNCOMPRESSED => {
                if stream.is_some() {
                    return bad(); // the previous chunk's stream did not end
                }
                raw.to_vec()
            }
            KEEP_DECODER => {
                let mut d = stream.take().ok_or(Error::BadContainer)?;
                let v = run(&mut d, raw, c.size)?;
                stream = (!d.is_done()).then_some(d);
                v
            }
            _ => {
                if stream.is_some() {
                    return bad();
                }
                let mut d = if codec == BROTLI {
                    Decompressor::new()
                } else {
                    let dict = resolve(&c.refs, c.pos, &chunks, &out, &contents, dictionary)?;
                    Decompressor::with_shared_dictionary(&dict)
                        .large_window(true)
                        .max_window_bits(30)
                };
                let v = run(&mut d, raw, c.size)?;
                stream = (!d.is_done()).then_some(d);
                v
            }
        };
        left -= content.len();
        // A stream that goes on must go on in the next chunk (padding aside).
        if stream.is_some() {
            let next = chunks[i + 1..].iter().find(|n| n.kind != PADDING);
            if next.and_then(|n| n.codec) != Some(KEEP_DECODER) {
                return bad();
            }
        }
        match c.kind {
            METADATA => {
                meta = parse_metadata(&content, METADATA)?;
                originals.push((METADATA, meta.clone()));
            }
            FOOTER_METADATA => {
                let f = parse_metadata(&content, FOOTER_METADATA)?;
                originals.push((FOOTER_METADATA, f.clone()));
                // Right after a resource's data (check_order).
                out.last_mut().ok_or(Error::BadContainer)?.res.footer = f;
            }
            GLOBAL_METADATA => global.extend(parse_metadata(&content, GLOBAL_METADATA)?),
            REPEAT_METADATA => repeats.push((c.repeats, parse_metadata(&content, c.repeats)?)),
            DATA | FIRST_PART => {
                let mut res = Resource {
                    data: content.clone(),
                    hash: c.hash,
                    hidden: c.flags & 1 != 0,
                    ..Resource::default()
                };
                split_metadata(std::mem::take(&mut meta), &mut res);
                out.push(Building {
                    res,
                    first: c.pos,
                    complete: c.kind == DATA,
                });
            }
            _ => {
                // Middle and last parts.
                let b = out.last_mut().ok_or(Error::BadContainer)?;
                b.res.data.extend_from_slice(&content);
                if c.kind == LAST_PART {
                    b.complete = true;
                    if c.hash.is_some() {
                        b.res.hash = c.hash;
                    }
                }
            }
        }
        contents.push((c.pos, content));
    }
    if stream.is_some() {
        return bad();
    }
    check_repeats(&originals, &repeats)?;
    Ok(Container {
        resources: out.into_iter().map(|b| b.res).collect(),
        global,
    })
}

/// Decodes `input` with `d` into exactly `size` bytes.
fn run(d: &mut Decompressor, input: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut input = input;
    loop {
        let p = d.decompress_vec(input, &mut out, size.saturating_add(1))?;
        input = &input[p.consumed..];
        if out.len() > size {
            return bad();
        }
        if input.is_empty() || p.done || (p.consumed == 0 && p.produced == 0) {
            break;
        }
    }
    if !input.is_empty() || out.len() != size {
        return bad();
    }
    Ok(out)
}

/// The dictionary of a shared brotli chunk at `pos` from its references: the prefixes
/// concatenated in order, a serialized dictionary's own prefix in its place.
fn resolve(
    refs: &[DictRef],
    pos: usize,
    chunks: &[Chunk],
    out: &[Building],
    contents: &[(usize, Vec<u8>)],
    lookup: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<SharedDictionary, Error> {
    let mut prefix = Vec::new();
    let mut serialized: Option<SharedDictionary> = None;
    let mut prefixes = 0;
    for d in refs {
        let bytes: Vec<u8> = match d.source {
            0 => {
                // A whole resource: its first data chunk, earlier, complete.
                if d.pointer >= pos {
                    return bad();
                }
                let b = out
                    .binary_search_by_key(&d.pointer, |b| b.first)
                    .map(|i| &out[i])
                    .or_else(|_| bad())?;
                if !b.complete {
                    return bad();
                }
                b.res.data.clone()
            }
            1 => {
                if d.pointer >= pos {
                    return bad();
                }
                if !at(chunks, d.pointer).is_some_and(|c| c.codec.is_some()) {
                    return bad();
                }
                contents
                    .binary_search_by_key(&d.pointer, |(p, _)| *p)
                    .map(|i| contents[i].1.clone())
                    .or_else(|_| bad())?
            }
            _ => lookup(&d.hash).ok_or(Error::MissingDictionary)?,
        };
        if d.serialized {
            if serialized.is_some() {
                return bad();
            }
            let s = SharedDictionary::new(&bytes)?;
            if !s.prefix().is_empty() {
                prefixes += 1;
            }
            prefix.extend_from_slice(s.prefix());
            serialized = Some(s);
        } else {
            prefixes += 1;
            prefix.extend_from_slice(&bytes);
        }
    }
    // At most 15 prefixes (Google's compound dictionary), and a prefix within a window.
    if prefixes > 15 || prefix.len() > (1 << 30) - 1 {
        return bad();
    }
    Ok(match serialized {
        Some(s) => s.with_prefix(&prefix),
        None => SharedDictionary::raw(&prefix),
    })
}

/// The chunk at `pos` (chunks are in container order).
fn at(chunks: &[Chunk], pos: usize) -> Option<&Chunk> {
    chunks
        .binary_search_by_key(&pos, |c| c.pos)
        .ok()
        .map(|i| &chunks[i])
}

/// The chunk order of RFC 9841 section 8.4.12 (padding anywhere).
fn check_order(chunks: &[Chunk], multi: bool) -> Result<(), Error> {
    #[derive(PartialEq)]
    enum At {
        /// Between resources.
        Idle,
        /// After a resource's metadata chunk: its data next.
        Meta,
        /// Inside a run of partial data chunks.
        Parts,
        /// After a resource's data: its footer metadata may follow.
        Data,
    }
    let mut at = At::Idle;
    let (mut resources, mut directories, mut footers) = (0, 0, 0);
    let mut footer_meta = false;
    let kinds: Vec<u8> = chunks
        .iter()
        .map(|c| c.kind)
        .filter(|&k| k != PADDING)
        .collect();
    for (i, &k) in kinds.iter().enumerate() {
        if !multi && !matches!(k, DATA..=LAST_PART) {
            // One resource only: no metadata, directory or footer.
            return bad();
        }
        at = match (k, &at) {
            (METADATA, At::Idle | At::Data) => At::Meta,
            (DATA, At::Idle | At::Meta | At::Data) => {
                resources += 1;
                footer_meta = false;
                At::Data
            }
            (FIRST_PART, At::Idle | At::Meta | At::Data) => {
                resources += 1;
                footer_meta = false;
                At::Parts
            }
            (MIDDLE_PART, At::Parts) => At::Parts,
            (LAST_PART, At::Parts) => At::Data,
            (FOOTER_METADATA, At::Data) if !footer_meta => {
                footer_meta = true;
                At::Data
            }
            (GLOBAL_METADATA | REPEAT_METADATA, At::Idle | At::Data) => At::Idle,
            (DIRECTORY, At::Idle | At::Data) => {
                directories += 1;
                At::Idle
            }
            (FINAL_FOOTER, At::Idle | At::Data) if i + 1 == kinds.len() => {
                footers += 1;
                At::Idle
            }
            _ => return bad(),
        };
        if k != FOOTER_METADATA && k != DATA && k != LAST_PART {
            footer_meta = footer_meta && at == At::Data;
        }
    }
    let ok = !matches!(at, At::Meta | At::Parts)
        && directories <= 1
        && if multi {
            footers == 1 && chunks.last().is_some_and(|c| c.kind == FINAL_FOOTER)
        } else {
            resources <= 1
        };
    if ok { Ok(()) } else { bad() }
}

/// The header bytes of a chunk (its length varint up to its content).
fn header<'a>(data: &'a [u8], c: &Chunk) -> &'a [u8] {
    &data[c.pos..c.content.start]
}

/// A central directory lists every data and metadata chunk, in order, with copies of their
/// headers; its repeat metadata pointer is the first repeat metadata chunk, 0 if there is none.
fn check_directory(data: &[u8], d: &Chunk, chunks: &[Chunk]) -> Result<(), Error> {
    let mut r = Reader {
        b: data,
        pos: d.content.start,
        end: d.content.end,
    };
    let repeat = r.usize()?;
    let first = chunks
        .iter()
        .find(|c| c.kind == REPEAT_METADATA)
        .map_or(0, |c| c.pos);
    if repeat != first {
        return bad();
    }
    let mut listed = chunks
        .iter()
        .filter(|c| matches!(c.kind, METADATA..=REPEAT_METADATA));
    while r.pos < r.end {
        let p = r.usize()?;
        let n = r.usize()?;
        let copy = r.take(n)?;
        match listed.next() {
            Some(c) if c.pos == p && header(data, c) == copy => {}
            _ => return bad(),
        }
    }
    if listed.next().is_some() {
        return bad();
    }
    Ok(())
}

/// A final footer's reversed varints: the container's size (0: not given) and the central
/// directory's position (0: none).
fn check_footer(data: &[u8], f: &Chunk, chunks: &[Chunk]) -> Result<(), Error> {
    let (dir, at) = reversed_varint(data, f.content.start, f.content.end)?;
    let (size, at) = reversed_varint(data, f.content.start, at)?;
    if at != f.content.start || (size != 0 && size != data.len() as u64) {
        return bad();
    }
    if dir != 0
        && !chunks
            .iter()
            .any(|c| c.pos as u64 == dir && c.kind == DIRECTORY)
    {
        return bad();
    }
    Ok(())
}

/// The dictionary [`ContainerWriter::add_resource`] compresses a resource with (shared
/// brotli).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum DictionaryRef<'a> {
    /// An earlier resource of the container, by the index the writer returned for it: a prefix
    /// dictionary, referenced by pointer.
    Resource(usize),
    /// A serialized dictionary, referenced by its hash code (its 256-bit HighwayHash; the
    /// reader resolves it).
    Shared(&'a SharedDictionary, &'a [u8; 32]),
}

/// Writes a shared brotli framing format container (RFC 9841 section 8) of several resources
/// (container flag bit 2): each resource is a metadata chunk (its name, modification time and
/// custom fields, if any), its data in one data chunk or, past [`part_size`](Self::part_size),
/// a run of partial data chunks, and a footer metadata chunk (if it has footer fields); global
/// metadata goes where it is added; [repeat metadata](Self::repeat_metadata) chunks, a central
/// directory and the final footer close the container.
///
/// Data is compressed with brotli at the writer's level, or with shared brotli and a
/// dictionary: an earlier resource (referenced by pointer, as a prefix dictionary) or a
/// serialized [`SharedDictionary`] referenced by its hash code (which the reader must be
/// able to resolve); data that does not compress is stored. Metadata is compressed with brotli
/// when that is smaller.
///
/// ```
/// use akio_brotli::{ContainerWriter, Level, read_container};
///
/// let mut w = ContainerWriter::new(Level::new(9));
/// let common = w.add_dictionary(b"<html><head><title>akio</title></head><body>");
/// w.add_with_dictionary("index.html", b"<html><head><title>akio</title></head><body>hi", common);
/// w.add("notes.txt", b"plain text, compressed with brotli");
/// let packed = w.finish();
///
/// let res = read_container(&packed, 1 << 20, &mut |_| None).unwrap();
/// let files: Vec<_> = res.iter().filter(|r| !r.hidden).collect();
/// assert_eq!(files[0].name.as_deref(), Some(&b"index.html"[..]));
/// assert_eq!(files[1].data, b"plain text, compressed with brotli");
/// ```
#[derive(Debug)]
pub struct ContainerWriter {
    level: Level,
    out: Vec<u8>,
    /// Position (of its first data chunk) and data of each resource.
    resources: Vec<(usize, Vec<u8>)>,
    /// Position and header length of each data and metadata chunk.
    listed: Vec<(usize, usize)>,
    /// Data longer than this goes in partial data chunks of this size (0: never).
    part_size: usize,
    repeat: bool,
    /// Type and content of each metadata and footer metadata chunk, for repeat metadata.
    metas: Vec<(u8, Vec<u8>)>,
}

impl ContainerWriter {
    /// An empty container whose data is compressed at `level`.
    pub fn new(level: Level) -> ContainerWriter {
        let mut out = SIGNATURE.to_vec();
        out.push(MULTI);
        ContainerWriter {
            level,
            out,
            resources: Vec::new(),
            listed: Vec::new(),
            part_size: 0,
            repeat: false,
            metas: Vec::new(),
        }
    }

    /// Writes data longer than `n` bytes as a run of partial data chunks (a first, middle ones
    /// and a last) of `n` uncompressed bytes each, the last one shorter; 0 (the default) never
    /// splits. The parts are one stream cut where the encoder flushed, each chunk after the
    /// first keeping the decoder, so a reader produces a part as it reaches its chunk; with a
    /// serialized dictionary ([`DictionaryRef::Shared`]) each part is a stream of its own
    /// referencing the dictionary (the streaming encoder has no serialized dictionaries). Data
    /// whose stream is not smaller than the data is stored, every part uncompressed. Before
    /// the first resource.
    #[must_use]
    pub fn part_size(mut self, n: usize) -> ContainerWriter {
        self.part_size = n;
        self
    }

    /// Repeats every metadata and footer metadata chunk, whole, in repeat metadata chunks
    /// (RFC 9841 section 8.4.9) before the central directory, which points at the first, so a
    /// reader lists the resources from the end of the container: one brotli stream cut into a
    /// chunk per copy (each after the first keeping the decoder) when that is smaller,
    /// uncompressed otherwise. Off by default. Before the first resource.
    #[must_use]
    pub fn repeat_metadata(mut self, on: bool) -> ContainerWriter {
        self.repeat = on;
        self
    }

    /// Adds a resource named `name` (no metadata if empty) with brotli; returns its index.
    pub fn add(&mut self, name: &str, data: &[u8]) -> usize {
        self.write(&named(name), data, None)
    }

    /// Adds a hidden resource (not extracted: a dictionary for later ones); returns its
    /// index.
    pub fn add_dictionary(&mut self, data: &[u8]) -> usize {
        let r = Resource {
            hidden: true,
            ..Resource::default()
        };
        self.write(&r, data, None)
    }

    /// Adds a resource compressed with shared brotli, the earlier resource `dict` (an index
    /// that [`add`](Self::add) and the others returned) as its prefix dictionary; returns its
    /// index.
    ///
    /// # Panics
    ///
    /// If `dict` is not the index of an earlier resource.
    pub fn add_with_dictionary(&mut self, name: &str, data: &[u8], dict: usize) -> usize {
        self.write(&named(name), data, Some(DictionaryRef::Resource(dict)))
    }

    /// Adds a resource compressed with shared brotli and the serialized dictionary `dict`,
    /// referenced by `hash` (its 256-bit HighwayHash; the reader resolves it); returns its
    /// index.
    pub fn add_with_shared_dictionary(
        &mut self,
        name: &str,
        data: &[u8],
        dict: &SharedDictionary,
        hash: &[u8; 32],
    ) -> usize {
        self.write(&named(name), data, Some(DictionaryRef::Shared(dict, hash)))
    }

    /// Adds `res` with all it says: its data, a metadata chunk with its name (`id`, also when
    /// empty), modification time (`mt`) and custom fields (if it has any of them), the hidden
    /// flag and hash code on its data chunks, a footer metadata chunk with its footer fields
    /// (if any); compressed with brotli, or shared brotli with `dictionary`. Returns its index.
    /// A resource [`read_container`] returns is written back as it was read.
    ///
    /// # Panics
    ///
    /// If a custom field's code is not two upper-case ASCII letters, or the dictionary is
    /// [`DictionaryRef::Resource`] and not the index of an earlier resource.
    pub fn add_resource(&mut self, res: &Resource, dictionary: Option<DictionaryRef<'_>>) -> usize {
        self.write(res, &res.data, dictionary)
    }

    /// Adds a global metadata chunk (metadata of the whole container) with `fields`.
    ///
    /// # Panics
    ///
    /// If a field's code is not two upper-case ASCII letters (the RFC defines no other global
    /// fields).
    pub fn add_global_metadata(&mut self, fields: &[([u8; 2], Vec<u8>)]) {
        let mut m = Vec::new();
        for (code, v) in fields {
            put_custom(&mut m, code, v);
        }
        self.metadata_chunk(GLOBAL_METADATA, &m);
    }

    /// Writes the chunks of a resource with `meta`'s metadata and flags (not its data) and
    /// `data`; returns its index.
    fn write(
        &mut self,
        meta: &Resource,
        data: &[u8],
        dictionary: Option<DictionaryRef<'_>>,
    ) -> usize {
        // Check the codes before writing anything.
        for (code, _) in meta.fields.iter().chain(&meta.footer) {
            check_custom(code);
        }
        let mut m = Vec::new();
        if let Some(name) = &meta.name {
            put_field(&mut m, *b"id", name);
        }
        if let Some(t) = meta.modified {
            put_field(&mut m, *b"mt", &t.to_le_bytes());
        }
        for (code, v) in &meta.fields {
            put_field(&mut m, *code, v);
        }
        if !m.is_empty() {
            self.metadata_chunk(METADATA, &m);
        }
        let pos = self.data_chunks(meta, data, dictionary);
        if !meta.footer.is_empty() {
            let mut m = Vec::new();
            for (code, v) in &meta.footer {
                put_field(&mut m, *code, v);
            }
            self.metadata_chunk(FOOTER_METADATA, &m);
        }
        self.resources.push((pos, data.to_vec()));
        self.resources.len() - 1
    }

    /// The data chunk, or the run of partial data chunks, of `data` with `meta`'s flags;
    /// returns the position of the first.
    fn data_chunks(
        &mut self,
        meta: &Resource,
        data: &[u8],
        dictionary: Option<DictionaryRef<'_>>,
    ) -> usize {
        let level = self.level;
        // The codec and the dictionary references (with their count) of a stream's start.
        let mut refs = Vec::new();
        let (codec, prefix): (u8, &[u8]) = match dictionary {
            None => (BROTLI, &[]),
            Some(DictionaryRef::Resource(i)) => {
                let (pos, ref d) = self.resources[i];
                refs.push(1);
                refs.push(0); // a resource by pointer, a prefix dictionary
                put_varint(&mut refs, pos as u64);
                (SHARED_BROTLI, d)
            }
            Some(DictionaryRef::Shared(_, hash)) => {
                // By hash code, a serialized dictionary.
                refs.extend_from_slice(&[1, 2 | 1 << 2, HIGHWAYHASH_256]);
                refs.extend_from_slice(hash);
                (SHARED_BROTLI, &[])
            }
        };
        let parts: Vec<&[u8]> = if self.part_size > 0 && data.len() > self.part_size {
            data.chunks(self.part_size).collect()
        } else {
            vec![data]
        };
        // Each part's codec and content.
        let coded: Vec<(u8, Cow<'_, [u8]>)> =
            if parts.len() == 1 || matches!(dictionary, Some(DictionaryRef::Shared(..))) {
                // Each part a stream of its own.
                parts
                    .iter()
                    .map(|&p| {
                        let packed = match dictionary {
                            None => compress(level, p),
                            Some(DictionaryRef::Resource(_)) => {
                                compress_with_dictionary(level, p, prefix)
                            }
                            Some(DictionaryRef::Shared(d, _)) => {
                                compress_with_shared_dictionary(level, p, d)
                            }
                        };
                        if packed.len() < p.len() {
                            (codec, Cow::Owned(packed))
                        } else {
                            (UNCOMPRESSED, Cow::Borrowed(p))
                        }
                    })
                    .collect()
            } else {
                // One stream, cut where it was flushed.
                let mut c = if prefix.is_empty() {
                    Compressor::new(level)
                } else {
                    Compressor::with_dictionary(level, prefix)
                };
                let segments = flushed_segments(&mut c, &parts);
                if segments.iter().map(Vec::len).sum::<usize>() < data.len() {
                    segments
                        .into_iter()
                        .enumerate()
                        .map(|(k, s)| (if k == 0 { codec } else { KEEP_DECODER }, Cow::Owned(s)))
                        .collect()
                } else {
                    parts
                        .iter()
                        .map(|&p| (UNCOMPRESSED, Cow::Borrowed(p)))
                        .collect()
                }
            };
        let n = coded.len();
        let mut first = 0;
        for (k, ((codec, content), part)) in coded.iter().zip(&parts).enumerate() {
            let kind = match (n, k) {
                (1, _) => DATA,
                (_, 0) => FIRST_PART,
                _ if k + 1 == n => LAST_PART,
                _ => MIDDLE_PART,
            };
            let mut head = vec![*codec];
            if *codec != UNCOMPRESSED {
                put_varint(&mut head, part.len() as u64);
            }
            if *codec == SHARED_BROTLI {
                head.extend_from_slice(&refs);
            }
            // The hidden flag on a resource's first chunk, the hash on its last.
            let hidden = meta.hidden && matches!(kind, DATA | FIRST_PART);
            let hash = meta.hash.filter(|_| matches!(kind, DATA | LAST_PART));
            head.push(u8::from(hidden) | u8::from(hash.is_some()) << 1);
            if let Some(h) = hash {
                head.push(HIGHWAYHASH_256);
                head.extend_from_slice(&h);
            }
            let pos = self.chunk(kind, &head, content);
            if k == 0 {
                first = pos;
            }
        }
        first
    }

    /// A metadata chunk of `kind` with the metadata content `fields` (brotli if smaller).
    fn metadata_chunk(&mut self, kind: u8, fields: &[u8]) {
        let packed = compress(self.level, fields);
        let mut head = Vec::new();
        let content = if packed.len() < fields.len() {
            head.push(BROTLI);
            put_varint(&mut head, fields.len() as u64);
            &packed[..]
        } else {
            head.push(UNCOMPRESSED);
            fields
        };
        self.chunk(kind, &head, content);
        if self.repeat && kind != GLOBAL_METADATA {
            self.metas.push((kind, fields.to_vec()));
        }
    }

    /// Writes a chunk of `kind` with header bytes `head` (after the type) and `content`;
    /// returns its position.
    fn chunk(&mut self, kind: u8, head: &[u8], content: &[u8]) -> usize {
        let pos = self.out.len();
        put_varint(&mut self.out, (1 + head.len() + content.len()) as u64);
        self.out.push(kind);
        self.out.extend_from_slice(head);
        if kind != DIRECTORY && kind != FINAL_FOOTER {
            self.listed.push((pos, self.out.len() - pos));
        }
        self.out.extend_from_slice(content);
        pos
    }

    /// The repeat metadata chunks; returns the position of the first (0 if none).
    fn repeat_chunks(&mut self) -> usize {
        let metas = std::mem::take(&mut self.metas);
        if metas.is_empty() {
            return 0;
        }
        let parts: Vec<&[u8]> = metas.iter().map(|(_, f)| &f[..]).collect();
        let segments = flushed_segments(&mut Compressor::new(self.level), &parts);
        let packed = segments.iter().map(Vec::len).sum::<usize>()
            < parts.iter().map(|p| p.len()).sum::<usize>();
        let mut first = 0;
        for (k, ((kind, fields), s)) in metas.iter().zip(&segments).enumerate() {
            let mut head = Vec::new();
            let content = if packed {
                head.push(if k == 0 { BROTLI } else { KEEP_DECODER });
                put_varint(&mut head, fields.len() as u64);
                &s[..]
            } else {
                head.push(UNCOMPRESSED);
                &fields[..]
            };
            head.push(*kind);
            let pos = self.chunk(REPEAT_METADATA, &head, content);
            if k == 0 {
                first = pos;
            }
        }
        first
    }

    /// The container: the resources, repeat metadata (if asked for), a central directory and
    /// the final footer.
    pub fn finish(mut self) -> Vec<u8> {
        let repeat = self.repeat_chunks();
        let mut dir = Vec::new();
        put_varint(&mut dir, repeat as u64);
        for &(pos, n) in &self.listed {
            put_varint(&mut dir, pos as u64);
            put_varint(&mut dir, n as u64);
            dir.extend_from_slice(&self.out[pos..pos + n]);
        }
        let dir_pos = self.chunk(DIRECTORY, &[], &dir);
        // The footer: the reversed varints of the container's size (with the footer) and the
        // directory's position; the size's length depends on itself.
        let at = self.out.len();
        let mut size = at as u64;
        loop {
            let body = varint_len(size) + varint_len(dir_pos as u64);
            let total = (at + varint_len(1 + body as u64) + 1 + body) as u64;
            if total == size {
                break;
            }
            size = total;
        }
        let mut body = Vec::new();
        let mut v = Vec::new();
        put_varint(&mut v, size);
        body.extend(v.iter().rev());
        v.clear();
        put_varint(&mut v, dir_pos as u64);
        body.extend(v.iter().rev());
        self.chunk(FINAL_FOOTER, &[], &body);
        debug_assert_eq!(self.out.len() as u64, size);
        self.out
    }
}

/// A resource's metadata with only a name (none if empty).
fn named(name: &str) -> Resource {
    Resource {
        name: (!name.is_empty()).then(|| name.as_bytes().to_vec()),
        ..Resource::default()
    }
}

/// One stream of `parts`, flushed after each but the last and finished after that: the
/// output of each.
fn flushed_segments(c: &mut Compressor, parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts
        .iter()
        .enumerate()
        .map(|(k, p)| {
            let mut s = Vec::new();
            let flush = if k + 1 == parts.len() {
                Flush::Finish
            } else {
                Flush::Flush
            };
            c.compress(p, &mut s, flush);
            s
        })
        .collect()
}

fn put_field(out: &mut Vec<u8>, code: [u8; 2], value: &[u8]) {
    out.extend_from_slice(&code);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn check_custom(code: &[u8; 2]) {
    assert!(
        code.iter().all(u8::is_ascii_uppercase),
        "a custom metadata field's code is two upper-case ASCII letters, not {code:?}"
    );
}

fn put_custom(out: &mut Vec<u8>, code: &[u8; 2], value: &[u8]) {
    check_custom(code);
    put_field(out, *code, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for v in [0u64, 1, 127, 128, 300, 1 << 35, (1 << 63) - 1] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(b.len(), varint_len(v));
            let mut r = Reader {
                b: &b,
                pos: 0,
                end: b.len(),
            };
            assert_eq!(r.varint(), Ok(v));
            let rev: Vec<u8> = b.iter().rev().copied().collect();
            assert_eq!(reversed_varint(&rev, 0, rev.len()), Ok((v, 0)));
        }
        // A ninth byte with its top bit set.
        let b = [0xff; 9];
        let mut r = Reader {
            b: &b,
            pos: 0,
            end: 9,
        };
        assert_eq!(r.varint(), Err(Error::BadContainer));
    }
}
