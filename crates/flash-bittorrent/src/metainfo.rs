//! .torrent files (BEP 3, v1): [`MetaInfo`] and its [`Info`] dictionary, the [`InfoHash`],
//! the piece and file layout, piece verification, and a [`Builder`] that hashes files into a
//! torrent. Trackers (BEP 12 announce-list), DHT nodes (BEP 5), web seeds (BEP 19 `url-list`),
//! the private flag (BEP 27) and padding files (BEP 47) are understood.
//!
//! Parsing rejects what a client must not trust: file paths that could escape the download
//! directory (`..`, empty or absolute components, separators inside a component), clashing
//! paths, and piece hashes that do not match the total length. v2-only torrents (BEP 52) are
//! refused with [`MetaError::Unsupported`]; hybrid torrents are read as their v1 part.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use sha1::{Digest, Sha1};

use crate::bencode::{self, Value};

/// The 20-byte SHA-1 of a torrent's info dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct InfoHash(pub [u8; 20]);

impl InfoHash {
    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 40 hex digits.
    pub fn from_hex(s: &str) -> Option<InfoHash> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (hexval(b[2 * i])? << 4) | hexval(b[2 * i + 1])?;
        }
        Some(InfoHash(out))
    }

    /// The SHA-1 of `data`.
    pub fn of(data: &[u8]) -> InfoHash {
        InfoHash(sha1(data))
    }
}

impl fmt::Debug for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InfoHash({})", self.to_hex())
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub(crate) fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(D[usize::from(x >> 4)]));
        s.push(char::from(D[usize::from(x & 15)]));
    }
    s
}

pub(crate) fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Why a torrent was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum MetaError {
    /// Not bencoding.
    Bencode(bencode::Error),
    /// A required field is missing or of the wrong type, or a value is invalid.
    Invalid(&'static str),
    /// A file path that could escape the download directory, or two files at one path.
    UnsafePath(String),
    /// A torrent kind this crate does not read (v2-only, BEP 52).
    Unsupported(&'static str),
    /// Reading files for [`Builder`] failed.
    Io(std::io::Error),
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaError::Bencode(e) => write!(f, "{e}"),
            MetaError::Invalid(m) => write!(f, "invalid torrent: {m}"),
            MetaError::UnsafePath(p) => write!(f, "unsafe file path: {p}"),
            MetaError::Unsupported(m) => write!(f, "unsupported torrent: {m}"),
            MetaError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for MetaError {}

impl From<bencode::Error> for MetaError {
    fn from(e: bencode::Error) -> Self {
        MetaError::Bencode(e)
    }
}

impl From<std::io::Error> for MetaError {
    fn from(e: std::io::Error) -> Self {
        MetaError::Io(e)
    }
}

/// One file of a torrent, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileEntry {
    /// Path components below the torrent's directory (for a single-file torrent: its name).
    pub path: Vec<String>,
    /// Size in bytes.
    pub length: u64,
    /// Offset of its first byte in the torrent's concatenated data.
    pub offset: u64,
    /// A BEP 47 padding file: zeros, never written to disk.
    pub padding: bool,
}

/// A byte range of one file, as [`Info::segments`] maps a range of the torrent's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Segment {
    /// Index into [`Info::files`].
    pub file: usize,
    /// Offset within the file.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
}

/// The info dictionary: what the info hash covers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Info {
    /// Suggested name: the file, or the directory of a multi-file torrent.
    pub name: String,
    /// Bytes per piece (the last may be shorter).
    pub piece_length: u32,
    /// SHA-1 of each piece.
    pub pieces: Vec<[u8; 20]>,
    /// Files in order, with offsets.
    pub files: Vec<FileEntry>,
    /// A single-file torrent (no directory).
    pub single_file: bool,
    /// BEP 27: use the torrent's trackers only (no DHT, PEX).
    pub private: bool,
    /// Sum of the file lengths.
    pub total_length: u64,
    raw: Vec<u8>,
}

fn safe_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains(['/', '\\', '\0'])
        && !(c.len() >= 2 && c.as_bytes()[1] == b':') // a Windows drive
}

impl Info {
    /// Parses an info dictionary from its encoded bytes (kept, for [`Info::raw`] and the hash).
    pub fn parse(raw: &[u8]) -> Result<Info, MetaError> {
        let v = bencode::decode(raw)?;
        if v.as_dict().is_none() {
            return Err(MetaError::Invalid("info is not a dictionary"));
        }
        let name = v
            .str_at("name.utf-8")
            .or_else(|| v.str_at("name"))
            .ok_or(MetaError::Invalid("name"))?
            .to_owned();
        let piece_length = v
            .int("piece length")
            .ok_or(MetaError::Invalid("piece length"))?;
        if !(1..=1 << 28).contains(&piece_length) {
            return Err(MetaError::Invalid("piece length out of range"));
        }
        let piece_length = piece_length as u32;
        let Some(pieces_raw) = v.bytes_at("pieces") else {
            if v.int("meta version") == Some(2) {
                return Err(MetaError::Unsupported("v2-only torrent (BEP 52)"));
            }
            return Err(MetaError::Invalid("pieces"));
        };
        if pieces_raw.len() % 20 != 0 {
            return Err(MetaError::Invalid("pieces is not a multiple of 20 bytes"));
        }
        let pieces: Vec<[u8; 20]> = pieces_raw
            .chunks_exact(20)
            .map(|c| c.try_into().unwrap_or([0; 20]))
            .collect();
        if !safe_component(&name) {
            return Err(MetaError::UnsafePath(name));
        }
        let private = v.int("private") == Some(1);
        let mut files = Vec::new();
        let single_file;
        let mut offset = 0u64;
        if let Some(len) = v.int("length") {
            if len < 0 {
                return Err(MetaError::Invalid("negative length"));
            }
            single_file = true;
            files.push(FileEntry {
                path: vec![name.clone()],
                length: len as u64,
                offset: 0,
                padding: false,
            });
            offset = len as u64;
        } else {
            single_file = false;
            let list = v
                .get("files")
                .and_then(Value::as_list)
                .ok_or(MetaError::Invalid("neither length nor files"))?;
            if list.is_empty() {
                return Err(MetaError::Invalid("empty file list"));
            }
            let mut seen = HashSet::new();
            for f in list {
                let len = f.int("length").ok_or(MetaError::Invalid("file length"))?;
                if len < 0 {
                    return Err(MetaError::Invalid("negative file length"));
                }
                let comps = f
                    .get("path.utf-8")
                    .or_else(|| f.get("path"))
                    .and_then(Value::as_list)
                    .ok_or(MetaError::Invalid("file path"))?;
                let mut path = Vec::with_capacity(comps.len());
                for c in comps {
                    let s = c
                        .as_str()
                        .ok_or(MetaError::Invalid("file path is not UTF-8"))?;
                    if !safe_component(s) {
                        return Err(MetaError::UnsafePath(s.to_owned()));
                    }
                    path.push(s.to_owned());
                }
                if path.is_empty() {
                    return Err(MetaError::UnsafePath(String::new()));
                }
                let padding = f.str_at("attr").is_some_and(|a| a.contains('p'));
                if !padding && !seen.insert(path.join("/").to_lowercase()) {
                    return Err(MetaError::UnsafePath(path.join("/")));
                }
                files.push(FileEntry {
                    path,
                    length: len as u64,
                    offset,
                    padding,
                });
                offset = offset
                    .checked_add(len as u64)
                    .ok_or(MetaError::Invalid("total length overflows"))?;
            }
            // A file must not be a directory of another ("a" and "a/b").
            for f in &files {
                for i in 1..f.path.len() {
                    if seen.contains(&f.path[..i].join("/").to_lowercase()) {
                        return Err(MetaError::UnsafePath(f.path.join("/")));
                    }
                }
            }
        }
        let want = offset.div_ceil(u64::from(piece_length));
        if want != pieces.len() as u64 {
            return Err(MetaError::Invalid("piece count does not match the length"));
        }
        Ok(Info {
            name,
            piece_length,
            pieces,
            files,
            single_file,
            private,
            total_length: offset,
            raw: raw.to_vec(),
        })
    }

    /// The info dictionary exactly as encoded (what metadata exchange sends).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The info hash.
    pub fn info_hash(&self) -> InfoHash {
        InfoHash::of(&self.raw)
    }

    /// Number of pieces.
    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    /// Size of piece `i` (the last may be shorter).
    pub fn piece_size(&self, i: usize) -> u32 {
        let start = i as u64 * u64::from(self.piece_length);
        (self.total_length.saturating_sub(start)).min(u64::from(self.piece_length)) as u32
    }

    /// Offset of piece `i` in the concatenated data.
    pub fn piece_offset(&self, i: usize) -> u64 {
        i as u64 * u64::from(self.piece_length)
    }

    /// Whether `data` is piece `i`.
    pub fn verify_piece(&self, i: usize, data: &[u8]) -> bool {
        self.pieces.get(i).is_some_and(|h| *h == sha1(data))
            && data.len() == self.piece_size(i) as usize
    }

    /// Maps `len` bytes at `offset` of the concatenated data onto the files they cover.
    pub fn segments(&self, offset: u64, len: u64) -> Vec<Segment> {
        let mut out = Vec::new();
        let end = (offset + len).min(self.total_length);
        // First file whose end is past `offset`.
        let start = self
            .files
            .partition_point(|f| f.offset + f.length <= offset);
        let mut pos = offset;
        for (i, f) in self.files.iter().enumerate().skip(start) {
            if pos >= end {
                break;
            }
            let fend = f.offset + f.length;
            if fend <= pos {
                continue;
            }
            let n = fend.min(end) - pos;
            out.push(Segment {
                file: i,
                offset: pos - f.offset,
                len: n,
            });
            pos += n;
        }
        out
    }

    /// The files that piece `i` touches.
    pub fn piece_segments(&self, i: usize) -> Vec<Segment> {
        self.segments(self.piece_offset(i), u64::from(self.piece_size(i)))
    }
}

/// A parsed .torrent file.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MetaInfo {
    /// The info dictionary.
    pub info: Info,
    /// Its hash.
    pub info_hash: InfoHash,
    /// `announce`: the single tracker URL.
    pub announce: Option<String>,
    /// `announce-list` (BEP 12): tiers of tracker URLs.
    pub announce_list: Vec<Vec<String>>,
    /// `nodes` (BEP 5): DHT bootstrap nodes as (host, port).
    pub nodes: Vec<(String, u16)>,
    /// `url-list` (BEP 19): web seeds.
    pub url_list: Vec<String>,
    /// `comment`.
    pub comment: Option<String>,
    /// `created by`.
    pub created_by: Option<String>,
    /// `creation date` (Unix seconds).
    pub creation_date: Option<i64>,
}

impl MetaInfo {
    /// Parses a .torrent file.
    pub fn parse(data: &[u8]) -> Result<MetaInfo, MetaError> {
        let v = bencode::decode(data)?;
        let range = bencode::raw_value(data, b"info")?.ok_or(MetaError::Invalid("no info"))?;
        let info = Info::parse(&data[range])?;
        let info_hash = info.info_hash();
        let announce = v.str_at("announce").map(str::to_owned);
        let mut announce_list = Vec::new();
        if let Some(tiers) = v.get("announce-list").and_then(Value::as_list) {
            for t in tiers {
                let tier: Vec<String> = t
                    .as_list()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|u| u.as_str().map(str::to_owned))
                    .collect();
                if !tier.is_empty() {
                    announce_list.push(tier);
                }
            }
        }
        let nodes = v
            .get("nodes")
            .and_then(Value::as_list)
            .unwrap_or_default()
            .iter()
            .filter_map(|n| {
                let l = n.as_list()?;
                let host = l.first()?.as_str()?.to_owned();
                let port = u16::try_from(l.get(1)?.as_int()?).ok()?;
                Some((host, port))
            })
            .collect();
        let url_list = match v.get("url-list") {
            Some(Value::Bytes(b)) => std::str::from_utf8(b)
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default(),
            Some(Value::List(l)) => l
                .iter()
                .filter_map(|u| u.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        Ok(MetaInfo {
            info,
            info_hash,
            announce,
            announce_list,
            nodes,
            url_list,
            comment: v.str_at("comment").map(str::to_owned),
            created_by: v.str_at("created by").map(str::to_owned),
            creation_date: v.int("creation date"),
        })
    }

    /// Reads and parses a .torrent file.
    pub fn load(path: impl AsRef<Path>) -> Result<MetaInfo, MetaError> {
        MetaInfo::parse(&std::fs::read(path)?)
    }

    /// A torrent of `info` with no trackers.
    pub fn from_info(info: Info) -> MetaInfo {
        MetaInfo {
            info_hash: info.info_hash(),
            info,
            announce: None,
            announce_list: Vec::new(),
            nodes: Vec::new(),
            url_list: Vec::new(),
            comment: None,
            created_by: None,
            creation_date: None,
        }
    }

    /// The tracker tiers: `announce-list`, or `announce` as one tier.
    pub fn trackers(&self) -> Vec<Vec<String>> {
        if !self.announce_list.is_empty() {
            return self.announce_list.clone();
        }
        self.announce.iter().map(|a| vec![a.clone()]).collect()
    }

    /// Encodes the torrent (the info dictionary byte for byte as parsed).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Keys sorted: announce, announce-list, comment, created by, creation date, info, nodes,
        // url-list. The info dictionary is spliced in raw.
        let mut out = vec![b'd'];
        let key = |out: &mut Vec<u8>, k: &str| Value::bytes(k).encode_to(out);
        if let Some(a) = &self.announce {
            key(&mut out, "announce");
            Value::from(a.as_str()).encode_to(&mut out);
        }
        if !self.announce_list.is_empty() {
            key(&mut out, "announce-list");
            Value::List(
                self.announce_list
                    .iter()
                    .map(|t| Value::List(t.iter().map(|u| Value::from(u.as_str())).collect()))
                    .collect(),
            )
            .encode_to(&mut out);
        }
        if let Some(c) = &self.comment {
            key(&mut out, "comment");
            Value::from(c.as_str()).encode_to(&mut out);
        }
        if let Some(c) = &self.created_by {
            key(&mut out, "created by");
            Value::from(c.as_str()).encode_to(&mut out);
        }
        if let Some(d) = self.creation_date {
            key(&mut out, "creation date");
            Value::Int(d).encode_to(&mut out);
        }
        key(&mut out, "info");
        out.extend_from_slice(self.info.raw());
        if !self.nodes.is_empty() {
            key(&mut out, "nodes");
            Value::List(
                self.nodes
                    .iter()
                    .map(|(h, p)| {
                        Value::List(vec![Value::from(h.as_str()), Value::Int(i64::from(*p))])
                    })
                    .collect(),
            )
            .encode_to(&mut out);
        }
        if !self.url_list.is_empty() {
            key(&mut out, "url-list");
            Value::List(
                self.url_list
                    .iter()
                    .map(|u| Value::from(u.as_str()))
                    .collect(),
            )
            .encode_to(&mut out);
        }
        out.push(b'e');
        out
    }

    /// A magnet link for this torrent (info hash, name and trackers).
    pub fn magnet(&self) -> crate::magnet::Magnet {
        let mut m = crate::magnet::Magnet::new(self.info_hash);
        m.name = Some(self.info.name.clone());
        m.trackers = self.trackers().into_iter().flatten().collect();
        m
    }
}

/// Makes a v1 torrent from files: hashes the data into pieces and writes the info dictionary.
///
/// ```
/// use flash_bittorrent::metainfo::Builder;
/// let mi = Builder::new("hello.txt")
///     .piece_length(16384)
///     .tracker("http://127.0.0.1:6969/announce")
///     .build_bytes(b"hello, world")
///     .unwrap();
/// assert_eq!(mi.info.total_length, 12);
/// ```
#[derive(Clone, Debug)]
pub struct Builder {
    name: String,
    piece_length: u32,
    trackers: Vec<Vec<String>>,
    private: bool,
    comment: Option<String>,
    nodes: Vec<(String, u16)>,
    url_list: Vec<String>,
}

impl Builder {
    /// A builder for a torrent named `name` (piece length 256 KiB).
    pub fn new(name: impl Into<String>) -> Builder {
        Builder {
            name: name.into(),
            piece_length: 256 * 1024,
            trackers: Vec::new(),
            private: false,
            comment: None,
            nodes: Vec::new(),
            url_list: Vec::new(),
        }
    }

    /// Bytes per piece (a power of two of at least 16 KiB is conventional).
    #[must_use]
    pub fn piece_length(mut self, n: u32) -> Builder {
        self.piece_length = n.max(1);
        self
    }

    /// Adds a tracker in a tier of its own.
    #[must_use]
    pub fn tracker(mut self, url: impl Into<String>) -> Builder {
        self.trackers.push(vec![url.into()]);
        self
    }

    /// Sets the private flag (BEP 27).
    #[must_use]
    pub fn private(mut self, private: bool) -> Builder {
        self.private = private;
        self
    }

    /// Sets the comment.
    #[must_use]
    pub fn comment(mut self, c: impl Into<String>) -> Builder {
        self.comment = Some(c.into());
        self
    }

    /// Adds a DHT bootstrap node.
    #[must_use]
    pub fn node(mut self, host: impl Into<String>, port: u16) -> Builder {
        self.nodes.push((host.into(), port));
        self
    }

    /// Adds a web seed (BEP 19).
    #[must_use]
    pub fn web_seed(mut self, url: impl Into<String>) -> Builder {
        self.url_list.push(url.into());
        self
    }

    /// A single-file torrent of `data`.
    pub fn build_bytes(&self, data: &[u8]) -> Result<MetaInfo, MetaError> {
        let pieces = data
            .chunks(self.piece_length as usize)
            .flat_map(sha1)
            .collect::<Vec<u8>>();
        let info = Value::dict()
            .with("length", data.len() as i64)
            .with("name", self.name.as_str())
            .with("piece length", i64::from(self.piece_length))
            .with("pieces", pieces);
        self.finish(info)
    }

    /// A multi-file torrent of in-memory files (path components, data).
    pub fn build_files(&self, files: &[(Vec<String>, Vec<u8>)]) -> Result<MetaInfo, MetaError> {
        let mut h = PieceHasher::new(self.piece_length);
        let mut list = Vec::new();
        for (path, data) in files {
            h.update(data);
            list.push(
                Value::dict().with("length", data.len() as i64).with(
                    "path",
                    path.iter()
                        .map(|c| Value::from(c.as_str()))
                        .collect::<Vec<_>>(),
                ),
            );
        }
        let info = Value::dict()
            .with("files", list)
            .with("name", self.name.as_str())
            .with("piece length", i64::from(self.piece_length))
            .with("pieces", h.finish());
        self.finish(info)
    }

    /// A torrent of the file or directory at `path` (a directory's files sorted by path).
    /// Reads the data once, streaming.
    pub fn build_path(&self, path: impl AsRef<Path>) -> Result<MetaInfo, MetaError> {
        use std::io::Read;
        let path = path.as_ref();
        let meta = std::fs::metadata(path)?;
        let mut h = PieceHasher::new(self.piece_length);
        let mut buf = vec![0u8; 1 << 16];
        let mut hash_file = |p: &Path, h: &mut PieceHasher| -> Result<u64, MetaError> {
            let mut f = std::fs::File::open(p)?;
            let mut total = 0u64;
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    return Ok(total);
                }
                h.update(&buf[..n]);
                total += n as u64;
            }
        };
        let info = if meta.is_file() {
            let len = hash_file(path, &mut h)?;
            Value::dict().with("length", len as i64)
        } else {
            let mut files = Vec::new();
            walk(path, &mut Vec::new(), &mut files)?;
            files.sort();
            let mut list = Vec::new();
            for comps in files {
                let mut p = path.to_path_buf();
                p.extend(&comps);
                let len = hash_file(&p, &mut h)?;
                list.push(Value::dict().with("length", len as i64).with(
                    "path",
                    comps.into_iter().map(Value::from).collect::<Vec<_>>(),
                ));
            }
            Value::dict().with("files", list)
        };
        let info = info
            .with("name", self.name.as_str())
            .with("piece length", i64::from(self.piece_length))
            .with("pieces", h.finish());
        self.finish(info)
    }

    fn finish(&self, mut info: Value) -> Result<MetaInfo, MetaError> {
        if self.private {
            info.insert("private", 1);
        }
        let raw = bencode::encode(&info);
        let info = Info::parse(&raw)?;
        let mut mi = MetaInfo::from_info(info);
        if let Some(first) = self.trackers.first().and_then(|t| t.first()) {
            mi.announce = Some(first.clone());
        }
        if self.trackers.len() > 1 {
            mi.announce_list = self.trackers.clone();
        }
        mi.comment = self.comment.clone();
        mi.created_by = Some(concat!("flash-bittorrent/", env!("CARGO_PKG_VERSION")).to_owned());
        mi.nodes = self.nodes.clone();
        mi.url_list = self.url_list.clone();
        Ok(mi)
    }
}

fn walk(dir: &Path, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let ft = e.file_type()?;
        prefix.push(name);
        if ft.is_dir() {
            walk(&e.path(), prefix, out)?;
        } else if ft.is_file() {
            out.push(prefix.clone());
        }
        prefix.pop();
    }
    Ok(())
}

struct PieceHasher {
    piece_length: usize,
    cur: Sha1,
    filled: usize,
    out: Vec<u8>,
}

impl PieceHasher {
    fn new(piece_length: u32) -> PieceHasher {
        PieceHasher {
            piece_length: piece_length as usize,
            cur: Sha1::new(),
            filled: 0,
            out: Vec::new(),
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = (self.piece_length - self.filled).min(data.len());
            self.cur.update(&data[..n]);
            self.filled += n;
            data = &data[n..];
            if self.filled == self.piece_length {
                let h = std::mem::replace(&mut self.cur, Sha1::new()).finalize();
                self.out.extend_from_slice(&h);
                self.filled = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.out.extend_from_slice(&self.cur.finalize());
        }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_round_trip() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mi = Builder::new("a.bin")
            .piece_length(16384)
            .tracker("http://t/announce")
            .tracker("udp://u:1/announce")
            .build_bytes(&data)
            .unwrap();
        assert_eq!(mi.info.num_pieces(), 7);
        assert_eq!(mi.info.piece_size(6), 100_000 - 6 * 16384);
        for i in 0..7 {
            let off = i * 16384;
            let end = (off + 16384).min(data.len());
            assert!(mi.info.verify_piece(i, &data[off..end]));
        }
        let enc = mi.to_bytes();
        let back = MetaInfo::parse(&enc).unwrap();
        assert_eq!(back.info_hash, mi.info_hash);
        assert_eq!(back.announce_list.len(), 2);
        assert_eq!(back.trackers()[1][0], "udp://u:1/announce");
    }

    #[test]
    fn multi_file_segments() {
        let files = vec![
            (vec!["d".to_owned(), "x".to_owned()], vec![1u8; 10]),
            (vec!["y".to_owned()], vec![2u8; 5]),
            (vec!["z".to_owned()], vec![3u8; 20]),
        ];
        let mi = Builder::new("dir")
            .piece_length(8)
            .build_files(&files)
            .unwrap();
        assert_eq!(mi.info.total_length, 35);
        assert_eq!(mi.info.num_pieces(), 5);
        let s = mi.info.piece_segments(1); // bytes 8..16
        assert_eq!(
            s,
            vec![
                Segment {
                    file: 0,
                    offset: 8,
                    len: 2
                },
                Segment {
                    file: 1,
                    offset: 0,
                    len: 5
                },
                Segment {
                    file: 2,
                    offset: 0,
                    len: 1
                }
            ]
        );
    }

    #[test]
    fn unsafe_paths_refused() {
        for bad in [&[".."][..], &["a", ""], &["/etc"], &["a/b"]] {
            let info = Value::dict()
                .with(
                    "files",
                    vec![Value::dict().with("length", 1).with(
                        "path",
                        bad.iter().map(|c| Value::from(*c)).collect::<Vec<_>>(),
                    )],
                )
                .with("name", "n")
                .with("piece length", 16384)
                .with("pieces", vec![0u8; 20]);
            assert!(
                matches!(
                    Info::parse(&bencode::encode(&info)),
                    Err(MetaError::UnsafePath(_))
                ),
                "{bad:?}"
            );
        }
        let clash = Value::dict()
            .with(
                "files",
                vec![
                    Value::dict()
                        .with("length", 1)
                        .with("path", vec![Value::from("a")]),
                    Value::dict()
                        .with("length", 1)
                        .with("path", vec![Value::from("a"), Value::from("b")]),
                ],
            )
            .with("name", "n")
            .with("piece length", 16384)
            .with("pieces", vec![0u8; 20]);
        assert!(Info::parse(&bencode::encode(&clash)).is_err());
    }

    #[test]
    fn hex() {
        let h = InfoHash::of(b"x");
        assert_eq!(InfoHash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(InfoHash::from_hex("zz"), None);
    }
}
