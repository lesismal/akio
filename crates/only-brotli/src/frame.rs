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

use std::ops::Range;

use crate::{
    Decompressor, Error, Level, SharedDictionary, compress, compress_with_dictionary,
    compress_with_shared_dictionary,
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
}

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

/// The fields of metadata content (RFC 9841 section 8.3) of a chunk of type `kind`: the name
/// and modification time of a metadata chunk; lower-case fields not defined for the type, a
/// field code that is not two letters of one case, a repeated `id` or `mt` and content past
/// the last field are errors.
fn parse_metadata(b: &[u8], kind: u8) -> Result<(Option<Vec<u8>>, Option<i64>), Error> {
    let mut r = Reader {
        b,
        pos: 0,
        end: b.len(),
    };
    let (mut name, mut modified) = (None, None);
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
        if upper {
            continue; // custom user fields
        }
        match (kind, code) {
            (METADATA, b"id") if name.is_none() => name = Some(v.to_vec()),
            (METADATA, b"mt") if modified.is_none() && v.len() == 8 => {
                let mut x = [0; 8];
                x.copy_from_slice(v);
                modified = Some(i64::from_le_bytes(x));
            }
            _ => return bad(),
        }
    }
    Ok((name, modified))
}

/// A resource being assembled, and where its chunks are.
struct Building {
    res: Resource,
    /// The position of its first data chunk.
    first: usize,
    complete: bool,
}

/// Reads a shared brotli framing format container (RFC 9841 section 8) and returns its
/// resources in order (hidden ones, meant as dictionaries for others, included and marked).
///
/// Every rule of the format is checked: the signature and flags, each chunk's header
/// (types, codecs, dictionary references, flags), metadata fields, the order of chunks (a
/// metadata chunk just before its resource's data, partial data chunks in a run, at most one
/// central directory, the final footer last and only when the flags announce it), a central
/// directory's copies of the chunk headers and the footer's pointers. Content is decoded by
/// its codec: uncompressed, brotli, shared brotli (large-window streams included, with the
/// dictionaries it references: other resources or chunks by pointer, or by hash through
/// `dictionary`, which returns the dictionary's bytes for a hash or `None`), or the
/// continuation of the previous chunk's stream. All decoded content together (dictionaries and
/// metadata included) must fit in `limit` bytes, or the result is [`Error::TooLarge`].
///
/// Fails with [`Error::BadContainer`] if the container is malformed, with
/// [`Error::MissingDictionary`] if `dictionary` does not know a hash, and with the error of a
/// stream that does not decode (or decodes to another size than its chunk says).
pub fn read_container(
    data: &[u8],
    limit: usize,
    dictionary: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Vec<Resource>, Error> {
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
    let mut left = limit;
    let mut out: Vec<Building> = Vec::new();
    // Decoded content of each chunk with content (for references to one chunk).
    let mut contents: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut stream: Option<Decompressor> = None;
    let mut meta: (Option<Vec<u8>>, Option<i64>) = (None, None);
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
            METADATA => meta = parse_metadata(&content, METADATA)?,
            FOOTER_METADATA | GLOBAL_METADATA => {
                parse_metadata(&content, c.kind)?;
            }
            REPEAT_METADATA => {
                parse_metadata(&content, c.repeats)?;
            }
            DATA | FIRST_PART => {
                let (name, modified) = std::mem::take(&mut meta);
                out.push(Building {
                    res: Resource {
                        name,
                        modified,
                        data: content.clone(),
                        hash: c.hash,
                        hidden: c.flags & 1 != 0,
                    },
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
    Ok(out.into_iter().map(|b| b.res).collect())
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
                    .iter()
                    .find(|b| b.first == d.pointer)
                    .ok_or(Error::BadContainer)?;
                if !b.complete {
                    return bad();
                }
                b.res.data.clone()
            }
            1 => {
                if d.pointer >= pos {
                    return bad();
                }
                if !chunks
                    .iter()
                    .any(|c| c.pos == d.pointer && c.codec.is_some())
                {
                    return bad();
                }
                contents
                    .iter()
                    .find(|(p, _)| *p == d.pointer)
                    .map(|(_, v)| v.clone())
                    .ok_or(Error::BadContainer)?
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
/// headers; its repeat metadata pointer is 0 or a repeat metadata chunk.
fn check_directory(data: &[u8], d: &Chunk, chunks: &[Chunk]) -> Result<(), Error> {
    let mut r = Reader {
        b: data,
        pos: d.content.start,
        end: d.content.end,
    };
    let repeat = r.usize()?;
    if repeat != 0
        && !chunks
            .iter()
            .any(|c| c.pos == repeat && c.kind == REPEAT_METADATA)
    {
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

/// Writes a shared brotli framing format container (RFC 9841 section 8) of several resources
/// (container flag bit 2), each a metadata chunk with its name (if any) and one data chunk,
/// then a central directory and the final footer.
///
/// Data is compressed with brotli at the writer's level, or with shared brotli and a
/// dictionary: an earlier resource (referenced by pointer, as a prefix dictionary) or a
/// serialized [`SharedDictionary`] referenced by its hash code (which the reader must be
/// able to resolve); data that does not compress is stored.
///
/// ```
/// use only_brotli::{ContainerWriter, Level, read_container};
///
/// let mut w = ContainerWriter::new(Level::new(9));
/// let common = w.add_dictionary(b"<html><head><title>only</title></head><body>");
/// w.add_with_dictionary("index.html", b"<html><head><title>only</title></head><body>hi", common);
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
    /// Position and data of each resource's data chunk.
    resources: Vec<(usize, Vec<u8>)>,
    /// Position and header length of each data and metadata chunk.
    listed: Vec<(usize, usize)>,
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
        }
    }

    /// Adds a resource named `name` (no metadata if empty) with brotli; returns its index.
    pub fn add(&mut self, name: &str, data: &[u8]) -> usize {
        self.metadata(name);
        let packed = compress(self.level, data);
        self.data_chunk(data, BROTLI, &[], &packed, 0)
    }

    /// Adds a hidden resource (not extracted: a dictionary for later ones); returns its
    /// index.
    pub fn add_dictionary(&mut self, data: &[u8]) -> usize {
        let packed = compress(self.level, data);
        self.data_chunk(data, BROTLI, &[], &packed, 1)
    }

    /// Adds a resource compressed with shared brotli, the earlier resource `dict` (an index
    /// that [`add`](Self::add) and the others returned) as its prefix dictionary; returns its
    /// index.
    ///
    /// # Panics
    ///
    /// If `dict` is not the index of an earlier resource.
    pub fn add_with_dictionary(&mut self, name: &str, data: &[u8], dict: usize) -> usize {
        let (pos, ref d) = self.resources[dict];
        let packed = compress_with_dictionary(self.level, data, d);
        let mut refs = vec![0u8]; // a resource by pointer, a prefix dictionary
        put_varint(&mut refs, pos as u64);
        self.metadata(name);
        self.data_chunk(data, SHARED_BROTLI, &[refs], &packed, 0)
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
        let packed = compress_with_shared_dictionary(self.level, data, dict);
        // By hash code, a serialized dictionary.
        let mut refs = vec![2 | 1 << 2, HIGHWAYHASH_256];
        refs.extend_from_slice(hash);
        self.metadata(name);
        self.data_chunk(data, SHARED_BROTLI, &[refs], &packed, 0)
    }

    /// A metadata chunk (uncompressed) with the `id` field, if `name` is not empty.
    fn metadata(&mut self, name: &str) {
        if name.is_empty() {
            return;
        }
        let mut field = b"id".to_vec();
        put_varint(&mut field, name.len() as u64);
        field.extend_from_slice(name.as_bytes());
        self.chunk(METADATA, &[UNCOMPRESSED], &field);
    }

    /// A data chunk of `data` with `codec` (stored instead if `packed` is not smaller) and
    /// `flags`.
    fn data_chunk(
        &mut self,
        data: &[u8],
        codec: u8,
        refs: &[Vec<u8>],
        packed: &[u8],
        flags: u8,
    ) -> usize {
        let mut head = Vec::new();
        let content = if packed.len() < data.len() {
            head.push(codec);
            put_varint(&mut head, data.len() as u64);
            if codec == SHARED_BROTLI {
                head.push(refs.len() as u8);
                for r in refs {
                    head.extend_from_slice(r);
                }
            }
            packed
        } else {
            head.push(UNCOMPRESSED);
            data
        };
        head.push(flags);
        let pos = self.chunk(DATA, &head, content);
        self.resources.push((pos, data.to_vec()));
        self.resources.len() - 1
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

    /// The container: the resources, a central directory and the final footer.
    pub fn finish(mut self) -> Vec<u8> {
        let mut dir = vec![0u8]; // no repeat metadata chunks
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
