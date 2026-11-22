//! .torrent files (BEP 3 v1, BEP 52 v2 and hybrid): [`MetaInfo`] and its [`Info`] dictionary,
//! the info hashes ([`InfoHash`], [`InfoHashV2`]), the piece and file layout, piece
//! verification (SHA-1 for v1, SHA-256 merkle trees for v2, both for hybrid torrents), the v2
//! [`PieceLayers`], and a [`Builder`] that hashes files into a torrent of any of the three
//! kinds. Trackers (BEP 12 announce-list), DHT nodes (BEP 5), web seeds (BEP 19 `url-list`),
//! the private flag (BEP 27) and padding files (BEP 47) are understood.
//!
//! Parsing rejects what a client must not trust: file paths that could escape the download
//! directory (`..`, empty or absolute components, separators inside a component), clashing
//! paths, piece hashes that do not match the total length, v2 piece layers that do not match
//! their file's root, and hybrid torrents whose v1 and v2 parts describe different files.
//!
//! In the piece space every kind shares, a v2 file starts on a piece boundary: the gaps are
//! padding files, real ones (BEP 47) in a hybrid torrent and synthesized ones (path
//! `.pad/<size>`, [`FileEntry::padding`]) in a v2-only torrent, so piece `i` covers the same
//! bytes in both views and storage never writes padding. A v2-only torrent's last file is
//! padded to a whole piece as well, as libtorrent does: every v2-only piece is whole.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use akio_crypto::hash::Sha1;

use crate::bencode::{self, Value};
use crate::merkle::{self, Hash};

/// The 20-byte hash peers, trackers and the DHT name a torrent by: the SHA-1 of the info
/// dictionary (v1 and hybrid torrents), or the v2 hash truncated to 20 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct InfoHash(pub [u8; 20]);

impl InfoHash {
    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 40 hex digits.
    pub fn from_hex(s: &str) -> Option<InfoHash> {
        let mut out = [0u8; 20];
        unhex(s, &mut out).then_some(InfoHash(out))
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

/// The 32-byte v2 info hash (BEP 52): the SHA-256 of the info dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct InfoHashV2(pub [u8; 32]);

impl InfoHashV2 {
    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 64 hex digits.
    pub fn from_hex(s: &str) -> Option<InfoHashV2> {
        let mut out = [0u8; 32];
        unhex(s, &mut out).then_some(InfoHashV2(out))
    }

    /// The SHA-256 of `data`.
    pub fn of(data: &[u8]) -> InfoHashV2 {
        InfoHashV2(merkle::sha256(data))
    }

    /// The first 20 bytes: what the handshake, trackers and the DHT use.
    pub fn truncated(&self) -> InfoHash {
        let mut h = [0u8; 20];
        h.copy_from_slice(&self.0[..20]);
        InfoHash(h)
    }
}

impl fmt::Debug for InfoHashV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InfoHashV2({})", self.to_hex())
    }
}

impl fmt::Display for InfoHashV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn unhex(s: &str, out: &mut [u8]) -> bool {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        match (hexval(b[2 * i]), hexval(b[2 * i + 1])) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data)
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

/// Which formats a torrent carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TorrentVersion {
    /// BEP 3: SHA-1 piece hashes.
    #[default]
    V1,
    /// BEP 52 only: per-file SHA-256 merkle trees.
    V2,
    /// Both, describing the same files (BEP 52 hybrid).
    Hybrid,
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
    /// A torrent kind this crate does not read (a `meta version` above 2).
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
    /// v2 and hybrid torrents: the root of the file's merkle tree (`None` for empty files and
    /// padding).
    pub pieces_root: Option<Hash>,
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
    /// SHA-1 of each piece (empty for a v2-only torrent).
    pub pieces: Vec<[u8; 20]>,
    /// Files in order, with offsets (padding files included).
    pub files: Vec<FileEntry>,
    /// A single-file torrent (no directory).
    pub single_file: bool,
    /// BEP 27: use the torrent's trackers only (no DHT, PEX, LSD).
    pub private: bool,
    /// Sum of the file lengths.
    pub total_length: u64,
    /// v1, v2 or hybrid.
    pub version: TorrentVersion,
    num_pieces: usize,
    raw: Vec<u8>,
}

fn safe_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains(['/', '\\', '\0'])
        && !(c.len() >= 2 && c.as_bytes()[1] == b':') // a Windows drive
}

/// A v2 file from the file tree.
struct TreeFile {
    path: Vec<String>,
    length: u64,
    root: Option<Hash>,
}

fn walk_tree(
    node: &BTreeMap<Vec<u8>, Value>,
    prefix: &mut Vec<String>,
    out: &mut Vec<TreeFile>,
) -> Result<(), MetaError> {
    for (k, v) in node {
        let d = v
            .as_dict()
            .ok_or(MetaError::Invalid("file tree node is not a dictionary"))?;
        if k.is_empty() {
            return Err(MetaError::Invalid(
                "file tree: a file at a directory's place",
            ));
        }
        let name =
            std::str::from_utf8(k).map_err(|_| MetaError::Invalid("file name is not UTF-8"))?;
        if !safe_component(name) {
            return Err(MetaError::UnsafePath(name.to_owned()));
        }
        prefix.push(name.to_owned());
        if let Some(leaf) = d.get(&b""[..]) {
            if d.len() != 1 {
                return Err(MetaError::Invalid("file tree: a file with children"));
            }
            let length = leaf
                .int("length")
                .ok_or(MetaError::Invalid("file length"))?;
            if length < 0 {
                return Err(MetaError::Invalid("negative file length"));
            }
            let root = match leaf.bytes_at("pieces root") {
                Some(r) => Some(
                    <Hash>::try_from(r)
                        .map_err(|_| MetaError::Invalid("pieces root is not 32 bytes"))?,
                ),
                None => None,
            };
            if length > 0 && root.is_none() {
                return Err(MetaError::Invalid("pieces root missing"));
            }
            out.push(TreeFile {
                path: prefix.clone(),
                length: length as u64,
                root: if length > 0 { root } else { None },
            });
        } else {
            if d.is_empty() {
                return Err(MetaError::Invalid("file tree: empty directory"));
            }
            walk_tree(d, prefix, out)?;
        }
        prefix.pop();
    }
    Ok(())
}

/// Refuses clashing paths: the same file twice, or a file that is another's directory.
fn check_clashes(files: &[FileEntry]) -> Result<(), MetaError> {
    let mut seen = HashSet::new();
    for f in files.iter().filter(|f| !f.padding) {
        if !seen.insert(f.path.join("/").to_lowercase()) {
            return Err(MetaError::UnsafePath(f.path.join("/")));
        }
    }
    for f in files.iter().filter(|f| !f.padding) {
        for i in 1..f.path.len() {
            if seen.contains(&f.path[..i].join("/").to_lowercase()) {
                return Err(MetaError::UnsafePath(f.path.join("/")));
            }
        }
    }
    Ok(())
}

impl Info {
    /// Parses an info dictionary from its encoded bytes (kept, for [`Info::raw`] and the hash).
    pub fn parse(raw: &[u8]) -> Result<Info, MetaError> {
        let v = bencode::decode(raw)?;
        if v.as_dict().is_none() {
            return Err(MetaError::Invalid("info is not a dictionary"));
        }
        let meta_version = v.int("meta version");
        if meta_version.is_some_and(|m| m > 2) {
            return Err(MetaError::Unsupported("meta version above 2"));
        }
        let has_v2 = meta_version == Some(2);
        let tree = v.get("file tree").and_then(Value::as_dict);
        if has_v2 && tree.is_none() {
            return Err(MetaError::Invalid("file tree"));
        }
        let pieces_raw = v.bytes_at("pieces");
        let has_v1 = pieces_raw.is_some();
        if !has_v1 && !has_v2 {
            return Err(MetaError::Invalid("pieces"));
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
        if has_v2 && (piece_length < 16384 || !piece_length.is_power_of_two()) {
            return Err(MetaError::Invalid(
                "v2 piece length is not a power of two of 16 KiB or more",
            ));
        }
        if !safe_component(&name) {
            return Err(MetaError::UnsafePath(name));
        }
        let private = v.int("private") == Some(1);
        let pl = u64::from(piece_length);

        // The v1 part.
        let mut v1 = None;
        if let Some(pieces_raw) = pieces_raw {
            if pieces_raw.len() % 20 != 0 {
                return Err(MetaError::Invalid("pieces is not a multiple of 20 bytes"));
            }
            let pieces: Vec<[u8; 20]> = pieces_raw
                .chunks_exact(20)
                .map(|c| c.try_into().unwrap_or([0; 20]))
                .collect();
            let (files, single, total) = Self::v1_files(&v, &name)?;
            if total.div_ceil(pl) != pieces.len() as u64 {
                return Err(MetaError::Invalid("piece count does not match the length"));
            }
            v1 = Some((pieces, files, single, total));
        }

        // The v2 part, laid out on piece boundaries.
        let mut v2 = None;
        if let Some(tree) = tree.filter(|_| has_v2) {
            let mut tf = Vec::new();
            walk_tree(tree, &mut Vec::new(), &mut tf)?;
            if tf.is_empty() {
                return Err(MetaError::Invalid("empty file tree"));
            }
            let single = tf.len() == 1 && tf[0].path.len() == 1 && tree.len() == 1;
            // A v2 single-file torrent has its padding entry after the file too.
            let mut files = Vec::with_capacity(tf.len() * 2);
            let mut offset = 0u64;
            for f in tf {
                if f.length > 0 && offset % pl != 0 {
                    let pad = pl - offset % pl;
                    files.push(FileEntry {
                        path: vec![".pad".to_owned(), pad.to_string()],
                        length: pad,
                        offset,
                        padding: true,
                        pieces_root: None,
                    });
                    offset += pad;
                }
                files.push(FileEntry {
                    path: f.path,
                    length: f.length,
                    offset,
                    padding: false,
                    pieces_root: f.root,
                });
                offset = offset
                    .checked_add(f.length)
                    .filter(|o| *o < 1 << 62)
                    .ok_or(MetaError::Invalid("total length overflows"))?;
            }
            // The last piece is whole too: libtorrent pads the last file as well, and asks for
            // whole blocks of it.
            if offset % pl != 0 {
                let pad = pl - offset % pl;
                files.push(FileEntry {
                    path: vec![".pad".to_owned(), pad.to_string()],
                    length: pad,
                    offset,
                    padding: true,
                    pieces_root: None,
                });
                offset += pad;
            }
            check_clashes(&files)?;
            v2 = Some((files, single, offset));
        }

        let (pieces, files, single_file, total_length, version) = match (v1, v2) {
            (Some((pieces, f1, s1, t1)), Some((f2, _, t2))) => {
                // Hybrid: the v1 files (pads aside) must be the v2 files, at the same offsets.
                let real1: Vec<&FileEntry> = f1.iter().filter(|f| !f.padding).collect();
                let real2: Vec<&FileEntry> = f2.iter().filter(|f| !f.padding).collect();
                let same = real1.len() == real2.len()
                    && real1.iter().zip(&real2).all(|(a, b)| {
                        a.path == b.path
                            && a.length == b.length
                            && (a.length == 0 || a.offset == b.offset)
                    })
                    && t2 / pl == pieces.len() as u64;
                if !same {
                    return Err(MetaError::Invalid("hybrid torrent: v1 and v2 files differ"));
                }
                let mut files = f1;
                let mut roots = real2.iter().map(|f| f.pieces_root);
                for f in files.iter_mut().filter(|f| !f.padding) {
                    f.pieces_root = roots.next().flatten();
                }
                (pieces, files, s1, t1, TorrentVersion::Hybrid)
            }
            (Some((pieces, files, single, total)), None) => {
                (pieces, files, single, total, TorrentVersion::V1)
            }
            (None, Some((files, single, total))) => {
                (Vec::new(), files, single, total, TorrentVersion::V2)
            }
            (None, None) => return Err(MetaError::Invalid("pieces")),
        };
        Ok(Info {
            name,
            piece_length,
            num_pieces: total_length.div_ceil(pl) as usize,
            pieces,
            files,
            single_file,
            private,
            total_length,
            version,
            raw: raw.to_vec(),
        })
    }

    fn v1_files(v: &Value, name: &str) -> Result<(Vec<FileEntry>, bool, u64), MetaError> {
        let mut files = Vec::new();
        if let Some(len) = v.int("length") {
            if len < 0 {
                return Err(MetaError::Invalid("negative length"));
            }
            files.push(FileEntry {
                path: vec![name.to_owned()],
                length: len as u64,
                offset: 0,
                padding: false,
                pieces_root: None,
            });
            return Ok((files, true, len as u64));
        }
        let list = v
            .get("files")
            .and_then(Value::as_list)
            .ok_or(MetaError::Invalid("neither length nor files"))?;
        if list.is_empty() {
            return Err(MetaError::Invalid("empty file list"));
        }
        let mut offset = 0u64;
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
            files.push(FileEntry {
                path,
                length: len as u64,
                offset,
                padding,
                pieces_root: None,
            });
            offset = offset
                .checked_add(len as u64)
                .filter(|o| *o < 1 << 62)
                .ok_or(MetaError::Invalid("total length overflows"))?;
        }
        check_clashes(&files)?;
        Ok((files, false, offset))
    }

    /// The info dictionary exactly as encoded (what metadata exchange sends).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The info hash peers use: the SHA-1 of the dictionary, or for a v2-only torrent the
    /// truncated v2 hash.
    pub fn info_hash(&self) -> InfoHash {
        match self.version {
            TorrentVersion::V2 => self.info_hash_v2().unwrap_or_default().truncated(),
            _ => InfoHash::of(&self.raw),
        }
    }

    /// The SHA-1 of the dictionary, for v1 and hybrid torrents.
    pub fn info_hash_v1(&self) -> Option<InfoHash> {
        self.has_v1().then(|| InfoHash::of(&self.raw))
    }

    /// The v2 info hash, for v2 and hybrid torrents.
    pub fn info_hash_v2(&self) -> Option<InfoHashV2> {
        self.has_v2().then(|| InfoHashV2::of(&self.raw))
    }

    /// Carries SHA-1 piece hashes (v1 or hybrid).
    pub fn has_v1(&self) -> bool {
        self.version != TorrentVersion::V2
    }

    /// Carries merkle roots (v2 or hybrid).
    pub fn has_v2(&self) -> bool {
        self.version != TorrentVersion::V1
    }

    /// Number of pieces.
    pub fn num_pieces(&self) -> usize {
        self.num_pieces
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

    /// For v2 and hybrid torrents: the file piece `i` belongs to (`None` for a v1 torrent or a
    /// piece of padding only) and the piece's index within that file.
    pub fn piece_file(&self, i: usize) -> Option<(usize, u64)> {
        if !self.has_v2() || i >= self.num_pieces {
            return None;
        }
        let s = *self.segments(self.piece_offset(i), 1).first()?;
        let f = &self.files[s.file];
        (!f.padding && f.pieces_root.is_some())
            .then(|| (s.file, s.offset / u64::from(self.piece_length)))
    }

    /// The pieces of file `file` (v2 and hybrid torrents start every file on a boundary).
    pub fn file_pieces(&self, file: usize) -> std::ops::Range<usize> {
        let Some(f) = self.files.get(file) else {
            return 0..0;
        };
        let pl = u64::from(self.piece_length);
        (f.offset / pl) as usize..(f.offset + f.length).div_ceil(pl) as usize
    }

    /// Whether file `file` needs a piece layer: a v2 file larger than one piece.
    pub fn needs_piece_layer(&self, file: usize) -> bool {
        self.files
            .get(file)
            .is_some_and(|f| f.pieces_root.is_some() && f.length > u64::from(self.piece_length))
    }

    /// The file whose merkle root is `root`.
    pub fn file_of_root(&self, root: &Hash) -> Option<usize> {
        self.files
            .iter()
            .position(|f| f.pieces_root.as_ref() == Some(root))
    }

    /// Whether `layer` is the piece layer of the file whose root is `root`.
    pub fn check_piece_layer(&self, root: &Hash, layer: &[Hash]) -> bool {
        let Some(f) = self.file_of_root(root).map(|i| &self.files[i]) else {
            return false;
        };
        let n = f.length.div_ceil(u64::from(self.piece_length));
        layer.len() as u64 == n
            && n > 1
            && merkle::root_from_piece_layer(layer, self.piece_length, f.length) == *root
    }

    /// Whether `data` is piece `i`, as far as the info dictionary alone can tell: the SHA-1
    /// hash for v1 and hybrid torrents; for a v2-only torrent the merkle root of a file that
    /// fits one piece (larger files need [`Info::verify_piece_with`] and the piece layers).
    pub fn verify_piece(&self, i: usize, data: &[u8]) -> bool {
        self.verify_piece_with(&PieceLayers::default(), i, data)
    }

    /// Whether `data` is piece `i`: the SHA-1 hash (v1, hybrid) and the v2 merkle hash (v2,
    /// hybrid) where it can be checked. A v2-only piece whose piece layer is not in `layers`
    /// fails; a hybrid one passes on its SHA-1 alone.
    pub fn verify_piece_with(&self, layers: &PieceLayers, i: usize, data: &[u8]) -> bool {
        if i >= self.num_pieces || data.len() != self.piece_size(i) as usize {
            return false;
        }
        if self.has_v1() && self.pieces.get(i).is_none_or(|h| *h != sha1(data)) {
            return false;
        }
        if !self.has_v2() {
            return true;
        }
        match self.verify_piece_v2(layers, i, data) {
            Some(ok) => ok,
            None => self.has_v1(),
        }
    }

    /// The v2 check of piece `i`: `None` if it cannot be made (no layer known).
    pub(crate) fn verify_piece_v2(
        &self,
        layers: &PieceLayers,
        i: usize,
        data: &[u8],
    ) -> Option<bool> {
        let Some((file, local)) = self.piece_file(i) else {
            // Padding only: zeros.
            return Some(data.iter().all(|&b| b == 0));
        };
        let f = &self.files[file];
        let root = f.pieces_root?;
        let pl = u64::from(self.piece_length);
        let n = (f.length - local * pl).min(pl) as usize;
        let (real, pad) = data.split_at(n.min(data.len()));
        if pad.iter().any(|&b| b != 0) {
            return Some(false);
        }
        if f.length <= pl {
            return Some(merkle::file_root(real) == root);
        }
        let layer = layers.get(&root)?;
        let want = layer.get(local as usize)?;
        Some(merkle::piece_root(real, self.piece_length) == *want)
    }

    /// Whether piece `i` can be checked with `layers` (always for v1 and hybrid torrents).
    pub fn can_verify(&self, layers: &PieceLayers, i: usize) -> bool {
        if self.has_v1() {
            return true;
        }
        match self.piece_file(i) {
            None => true,
            Some((f, _)) => {
                !self.needs_piece_layer(f)
                    || self.files[f]
                        .pieces_root
                        .is_some_and(|r| layers.get(&r).is_some())
            }
        }
    }

    /// Maps `len` bytes at `offset` of the concatenated data onto the files they cover.
    pub fn segments(&self, offset: u64, len: u64) -> Vec<Segment> {
        let mut out = Vec::new();
        let end = offset.saturating_add(len).min(self.total_length);
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

/// The piece layers of a v2 or hybrid torrent (BEP 52 `piece layers`): for each file larger
/// than a piece, the hashes of its merkle tree at the piece layer, keyed by the file's root.
/// Cheap to clone (layers are shared).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PieceLayers {
    map: HashMap<Hash, Arc<Vec<Hash>>>,
}

impl PieceLayers {
    /// No layers.
    pub fn new() -> PieceLayers {
        PieceLayers::default()
    }

    /// The layer of the file whose root is `root`.
    pub fn get(&self, root: &Hash) -> Option<&[Hash]> {
        self.map.get(root).map(|l| l.as_slice())
    }

    /// Layers held.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// No layers held.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Adds the layer of `root` if it is that file's layer in `info`; `false` if not.
    pub fn insert(&mut self, info: &Info, root: Hash, layer: Vec<Hash>) -> bool {
        if !info.check_piece_layer(&root, &layer) {
            return false;
        }
        self.map.insert(root, Arc::new(layer));
        true
    }

    /// The files of `info` that need a layer not held.
    pub fn missing(&self, info: &Info) -> Vec<usize> {
        (0..info.files.len())
            .filter(|&f| {
                info.needs_piece_layer(f)
                    && info.files[f]
                        .pieces_root
                        .is_some_and(|r| !self.map.contains_key(&r))
            })
            .collect()
    }

    /// Every layer `info` needs is held.
    pub fn is_complete(&self, info: &Info) -> bool {
        self.missing(info).is_empty()
    }

    /// `(root, layer)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &[Hash])> {
        self.map.iter().map(|(k, v)| (k, v.as_slice()))
    }

    fn encode(&self) -> Value {
        let mut d = BTreeMap::new();
        for (k, v) in &self.map {
            d.insert(k.to_vec(), Value::Bytes(v.concat()));
        }
        Value::Dict(d)
    }
}

/// A parsed .torrent file.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MetaInfo {
    /// The info dictionary.
    pub info: Info,
    /// The hash peers name it by ([`Info::info_hash`]).
    pub info_hash: InfoHash,
    /// The v2 hash (v2 and hybrid torrents).
    pub info_hash_v2: Option<InfoHashV2>,
    /// The v2 piece layers (v2 and hybrid torrents; checked against the roots).
    pub piece_layers: PieceLayers,
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
        let mut layers = PieceLayers::new();
        if info.has_v2() {
            let pl = v.get("piece layers").and_then(Value::as_dict);
            for f in 0..info.files.len() {
                if !info.needs_piece_layer(f) {
                    continue;
                }
                let Some(root) = info.files[f].pieces_root else {
                    continue;
                };
                if layers.get(&root).is_some() {
                    continue; // identical files share a root
                }
                let Some(b) = pl.and_then(|d| d.get(&root[..])).and_then(Value::as_bytes) else {
                    return Err(MetaError::Invalid("piece layers: a layer is missing"));
                };
                if b.len() % 32 != 0 {
                    return Err(MetaError::Invalid(
                        "piece layers: not a multiple of 32 bytes",
                    ));
                }
                let layer: Vec<Hash> = b
                    .chunks_exact(32)
                    .map(|c| c.try_into().unwrap_or([0; 32]))
                    .collect();
                if !layers.insert(&info, root, layer) {
                    return Err(MetaError::Invalid(
                        "piece layers: a layer does not match its root",
                    ));
                }
            }
        }
        let mut mi = MetaInfo::from_info(info);
        mi.piece_layers = layers;
        mi.announce = v.str_at("announce").map(str::to_owned);
        if let Some(tiers) = v.get("announce-list").and_then(Value::as_list) {
            for t in tiers {
                let tier: Vec<String> = t
                    .as_list()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|u| u.as_str().map(str::to_owned))
                    .collect();
                if !tier.is_empty() {
                    mi.announce_list.push(tier);
                }
            }
        }
        mi.nodes = v
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
        mi.url_list = match v.get("url-list") {
            Some(Value::Bytes(b)) => std::str::from_utf8(b)
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default(),
            Some(Value::List(l)) => l
                .iter()
                .filter_map(|u| u.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        mi.comment = v.str_at("comment").map(str::to_owned);
        mi.created_by = v.str_at("created by").map(str::to_owned);
        mi.creation_date = v.int("creation date");
        Ok(mi)
    }

    /// Reads and parses a .torrent file.
    pub fn load(path: impl AsRef<Path>) -> Result<MetaInfo, MetaError> {
        MetaInfo::parse(&std::fs::read(path)?)
    }

    /// A torrent of `info` with no trackers (and, for v2, no piece layers yet).
    pub fn from_info(info: Info) -> MetaInfo {
        MetaInfo {
            info_hash: info.info_hash(),
            info_hash_v2: info.info_hash_v2(),
            piece_layers: PieceLayers::new(),
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

    /// Whether `data` is piece `i` (every hash the torrent has, with its piece layers).
    pub fn verify_piece(&self, i: usize, data: &[u8]) -> bool {
        self.info.verify_piece_with(&self.piece_layers, i, data)
    }

    /// Encodes the torrent (the info dictionary byte for byte as parsed).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Keys sorted: announce, announce-list, comment, created by, creation date, info, nodes,
        // piece layers, url-list. The info dictionary is spliced in raw.
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
        if self.info.has_v2() {
            key(&mut out, "piece layers");
            self.piece_layers.encode().encode_to(&mut out);
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

    /// A magnet link for this torrent (info hashes, name and trackers).
    pub fn magnet(&self) -> crate::magnet::Magnet {
        let mut m = crate::magnet::Magnet::new(self.info_hash);
        m.info_hash_v2 = self.info_hash_v2;
        m.name = Some(self.info.name.clone());
        m.trackers = self.trackers().into_iter().flatten().collect();
        m
    }
}

/// Makes a torrent from files: hashes the data into pieces (SHA-1 for v1, per-file SHA-256
/// merkle trees for v2, both for hybrid torrents, whose files are then padded to piece
/// boundaries with BEP 47 padding files) and writes the info dictionary.
///
/// ```
/// use akio_bittorrent::metainfo::{Builder, TorrentVersion};
/// let mi = Builder::new("hello.txt")
///     .piece_length(16384)
///     .version(TorrentVersion::Hybrid)
///     .tracker("http://127.0.0.1:6969/announce")
///     .build_bytes(b"hello, world")
///     .unwrap();
/// assert_eq!(mi.info.total_length, 12);
/// assert!(mi.info_hash_v2.is_some());
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
    version: TorrentVersion,
}

/// Where a file's bytes come from.
enum Source<'a> {
    Bytes(&'a [u8]),
    Path(std::path::PathBuf),
}

/// The v2 hashes of one file, fed in order.
struct FileHasher {
    piece_length: u32,
    block: Vec<u8>,
    blocks: Vec<Hash>,
    layer: Vec<Hash>,
    len: u64,
}

impl FileHasher {
    fn new(piece_length: u32) -> FileHasher {
        FileHasher {
            piece_length,
            block: Vec::with_capacity(merkle::BLOCK),
            blocks: Vec::new(),
            layer: Vec::new(),
            len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        let bpp = merkle::blocks_per_piece(self.piece_length) as usize;
        self.len += data.len() as u64;
        while !data.is_empty() {
            let n = (merkle::BLOCK - self.block.len()).min(data.len());
            self.block.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.block.len() == merkle::BLOCK {
                self.blocks.push(merkle::sha256(&self.block));
                self.block.clear();
                if self.blocks.len() == bpp {
                    self.flush_piece();
                }
            }
        }
    }

    fn flush_piece(&mut self) {
        let bpp = merkle::blocks_per_piece(self.piece_length) as usize;
        let r = merkle::subtree_root(&self.blocks, 0, bpp);
        self.layer.push(r);
        self.blocks.clear();
    }

    /// The root and, for a file larger than a piece, its piece layer.
    fn finish(mut self) -> (Option<Hash>, Vec<Hash>) {
        if !self.block.is_empty() {
            self.blocks.push(merkle::sha256(&self.block));
        }
        if self.len == 0 {
            return (None, Vec::new());
        }
        if self.len <= u64::from(self.piece_length) {
            // One piece: the root covers the blocks only (a whole piece was flushed already).
            let root = match self.layer.first() {
                Some(r) => *r,
                None => {
                    merkle::subtree_root(&self.blocks, 0, self.blocks.len().next_power_of_two())
                }
            };
            return (Some(root), Vec::new());
        }
        if !self.blocks.is_empty() {
            self.flush_piece();
        }
        let root = merkle::root_from_piece_layer(&self.layer, self.piece_length, self.len);
        (Some(root), self.layer)
    }
}

impl Builder {
    /// A builder for a v1 torrent named `name` (piece length 256 KiB).
    pub fn new(name: impl Into<String>) -> Builder {
        Builder {
            name: name.into(),
            piece_length: 256 * 1024,
            trackers: Vec::new(),
            private: false,
            comment: None,
            nodes: Vec::new(),
            url_list: Vec::new(),
            version: TorrentVersion::V1,
        }
    }

    /// Bytes per piece (a power of two of at least 16 KiB is conventional, and required for
    /// v2 and hybrid torrents).
    #[must_use]
    pub fn piece_length(mut self, n: u32) -> Builder {
        self.piece_length = n.max(1);
        self
    }

    /// v1 (the default), v2 or hybrid.
    #[must_use]
    pub fn version(mut self, v: TorrentVersion) -> Builder {
        self.version = v;
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
        self.build(vec![(vec![self.name.clone()], Source::Bytes(data))], true)
    }

    /// A multi-file torrent of in-memory files (path components, data). v2 and hybrid
    /// torrents list them in path order (the order of BEP 52's file tree).
    pub fn build_files(&self, files: &[(Vec<String>, Vec<u8>)]) -> Result<MetaInfo, MetaError> {
        self.build(
            files
                .iter()
                .map(|(p, d)| (p.clone(), Source::Bytes(d)))
                .collect(),
            false,
        )
    }

    /// A torrent of the file or directory at `path` (a directory's files sorted by path).
    /// Reads the data once, streaming.
    pub fn build_path(&self, path: impl AsRef<Path>) -> Result<MetaInfo, MetaError> {
        let path = path.as_ref();
        if std::fs::metadata(path)?.is_file() {
            return self.build(
                vec![(vec![self.name.clone()], Source::Path(path.to_path_buf()))],
                true,
            );
        }
        let mut files = Vec::new();
        walk(path, &mut Vec::new(), &mut files)?;
        files.sort();
        self.build(
            files
                .into_iter()
                .map(|comps| {
                    let mut p = path.to_path_buf();
                    p.extend(&comps);
                    (comps, Source::Path(p))
                })
                .collect(),
            false,
        )
    }

    fn build(
        &self,
        mut files: Vec<(Vec<String>, Source<'_>)>,
        single: bool,
    ) -> Result<MetaInfo, MetaError> {
        use std::io::Read;
        let v1 = self.version != TorrentVersion::V2;
        let v2 = self.version != TorrentVersion::V1;
        if v2 {
            // The file tree is a dictionary: its files come in path order, and a hybrid
            // torrent's v1 list must follow the same order.
            files.sort_by(|a, b| a.0.cmp(&b.0));
        }
        let hybrid = v1 && v2;
        if v2 && (self.piece_length < 16384 || !self.piece_length.is_power_of_two()) {
            return Err(MetaError::Invalid(
                "v2 piece length is not a power of two of 16 KiB or more",
            ));
        }
        let pl = u64::from(self.piece_length);
        let mut h1 = PieceHasher::new(self.piece_length);
        let mut v1_list = Vec::new();
        let mut tree: Vec<(Vec<String>, u64, Option<Hash>)> = Vec::new();
        let mut layers = PieceLayers::new();
        let mut layer_list: Vec<(Hash, Vec<Hash>)> = Vec::new();
        let mut total = 0u64;
        let mut buf = vec![0u8; 1 << 16];
        let n = files.len();
        for (i, (comps, src)) in files.into_iter().enumerate() {
            let mut fh = FileHasher::new(self.piece_length);
            let mut feed = |d: &[u8]| {
                if v1 {
                    h1.update(d);
                }
                if v2 {
                    fh.update(d);
                }
            };
            let len = match src {
                Source::Bytes(d) => {
                    feed(d);
                    d.len() as u64
                }
                Source::Path(p) => {
                    let mut f = std::fs::File::open(p)?;
                    let mut len = 0u64;
                    loop {
                        let k = f.read(&mut buf)?;
                        if k == 0 {
                            break len;
                        }
                        feed(&buf[..k]);
                        len += k as u64;
                    }
                }
            };
            total += len;
            v1_list.push(
                Value::dict().with("length", len as i64).with(
                    "path",
                    comps
                        .iter()
                        .map(|c| Value::from(c.as_str()))
                        .collect::<Vec<_>>(),
                ),
            );
            let (root, layer) = if v2 { fh.finish() } else { (None, Vec::new()) };
            if let Some(r) = root {
                if !layer.is_empty() {
                    layer_list.push((r, layer));
                }
            }
            tree.push((comps, len, root));
            // Hybrid: pad every file but the last to a piece boundary.
            if hybrid && !single && i + 1 < n && len > 0 && total % pl != 0 {
                let pad = pl - total % pl;
                h1.update_zeros(pad);
                total += pad;
                v1_list.push(
                    Value::dict()
                        .with("attr", "p")
                        .with("length", pad as i64)
                        .with(
                            "path",
                            vec![Value::from(".pad"), Value::from(pad.to_string())],
                        ),
                );
            }
        }
        let mut info = Value::dict()
            .with("name", self.name.as_str())
            .with("piece length", i64::from(self.piece_length));
        if v1 {
            if single {
                info.insert("length", total as i64);
            } else {
                info.insert("files", v1_list);
            }
            info.insert("pieces", h1.finish());
        }
        if v2 {
            info.insert("meta version", 2);
            info.insert("file tree", file_tree(&tree, single));
        }
        let mut mi = self.finish(info)?;
        for (root, layer) in layer_list {
            if !layers.insert(&mi.info, root, layer) {
                return Err(MetaError::Invalid("piece layer"));
            }
        }
        mi.piece_layers = layers;
        Ok(mi)
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
        mi.created_by = Some(concat!("akio-bittorrent/", env!("CARGO_PKG_VERSION")).to_owned());
        mi.nodes = self.nodes.clone();
        mi.url_list = self.url_list.clone();
        Ok(mi)
    }
}

/// The v2 `file tree` of `files` (path, length, root).
fn file_tree(files: &[(Vec<String>, u64, Option<Hash>)], _single: bool) -> Value {
    fn put(node: &mut BTreeMap<Vec<u8>, Value>, path: &[String], leaf: Value) {
        let Some((first, rest)) = path.split_first() else {
            return;
        };
        let entry = node
            .entry(first.as_bytes().to_vec())
            .or_insert_with(Value::dict);
        let Value::Dict(child) = entry else { return };
        if rest.is_empty() {
            child.insert(Vec::new(), leaf);
        } else {
            put(child, rest, leaf);
        }
    }
    let mut root = BTreeMap::new();
    for (path, len, r) in files {
        let mut leaf = Value::dict().with("length", *len as i64);
        if let Some(r) = r {
            leaf.insert("pieces root", r.to_vec());
        }
        put(&mut root, path, leaf);
    }
    Value::Dict(root)
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

    fn update_zeros(&mut self, mut n: u64) {
        let z = [0u8; 4096];
        while n > 0 {
            let k = n.min(z.len() as u64) as usize;
            self.update(&z[..k]);
            n -= k as u64;
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

    fn sample_files() -> Vec<(Vec<String>, Vec<u8>)> {
        let d = |n: usize, k: u8| {
            (0..n)
                .map(|i| (i as u8).wrapping_mul(k))
                .collect::<Vec<u8>>()
        };
        vec![
            (vec!["a".to_owned()], d(100_000, 3)), // 7 pieces of 16 KiB
            (vec!["e".to_owned()], Vec::new()),    // empty
            (vec!["s".to_owned(), "b".to_owned()], d(5000, 5)), // one short piece
            (vec!["s".to_owned(), "c".to_owned()], d(16384, 7)), // exactly one piece
            (vec!["z".to_owned()], d(40_000, 11)),
        ]
    }

    /// The torrent's piece-space data: files with padding zeros.
    fn piece_space(info: &Info, files: &[(Vec<String>, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0u8; info.total_length as usize];
        for f in info.files.iter().filter(|f| !f.padding) {
            let (_, d) = files.iter().find(|(p, _)| *p == f.path).unwrap();
            out[f.offset as usize..f.offset as usize + d.len()].copy_from_slice(d);
        }
        out
    }

    #[test]
    fn v2_and_hybrid_round_trip() {
        let files = sample_files();
        for v in [TorrentVersion::V2, TorrentVersion::Hybrid] {
            let mi = Builder::new("t")
                .piece_length(16384)
                .version(v)
                .build_files(&files)
                .unwrap();
            assert_eq!(mi.info.version, v);
            let v2 = mi.info_hash_v2.unwrap();
            assert_eq!(v2, InfoHashV2::of(mi.info.raw()));
            if v == TorrentVersion::V2 {
                assert_eq!(mi.info_hash, v2.truncated());
                assert!(mi.info.pieces.is_empty());
            } else {
                assert_eq!(mi.info_hash, InfoHash::of(mi.info.raw()));
            }
            // a: 7 pieces, pad; e; s/b: 1; s/c: 1; z: 3 pieces.
            assert_eq!(mi.info.num_pieces(), 7 + 1 + 1 + 3);
            assert_eq!(mi.piece_layers.len(), 2); // a and z
            let back = MetaInfo::parse(&mi.to_bytes()).unwrap();
            assert_eq!(back.info_hash, mi.info_hash);
            assert_eq!(back.piece_layers, mi.piece_layers);
            let data = piece_space(&mi.info, &files);
            for i in 0..mi.info.num_pieces() {
                let p = &data[mi.info.piece_offset(i) as usize..][..mi.info.piece_size(i) as usize];
                assert!(back.verify_piece(i, p), "{v:?} piece {i}");
                let mut bad = p.to_vec();
                bad[0] ^= 1;
                assert!(!back.verify_piece(i, &bad));
                // Without layers a v2-only torrent can check single-piece files alone.
                let alone = back.info.verify_piece(i, p);
                let big = back
                    .info
                    .piece_file(i)
                    .is_some_and(|(f, _)| back.info.needs_piece_layer(f));
                assert_eq!(
                    alone,
                    v == TorrentVersion::Hybrid || !big,
                    "{v:?} piece {i}"
                );
            }
            let z = back
                .info
                .files
                .iter()
                .position(|f| f.path == ["z"])
                .unwrap();
            assert_eq!(back.info.file_pieces(z), 9..12);
            assert_eq!(back.info.piece_file(10), Some((z, 1)));
            // Every v2-only piece is whole (the last file is padded too).
            if v == TorrentVersion::V2 {
                assert_eq!(back.info.total_length % 16384, 0);
            }
        }
    }

    #[test]
    fn v2_single_file_and_errors() {
        let data: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        let mi = Builder::new("one.bin")
            .piece_length(32768)
            .version(TorrentVersion::V2)
            .build_bytes(&data)
            .unwrap();
        assert!(mi.info.single_file);
        assert_eq!(mi.info.files[0].path, vec!["one.bin"]);
        assert_eq!(mi.info.files[0].pieces_root, Some(merkle::file_root(&data)));
        assert!(
            Builder::new("x")
                .piece_length(20000)
                .version(TorrentVersion::V2)
                .build_bytes(b"x")
                .is_err()
        );
        // A layer that does not match its root.
        let mut bad = mi.clone();
        let root = mi.info.files[0].pieces_root.unwrap();
        bad.piece_layers = PieceLayers::new();
        bad.piece_layers
            .map
            .insert(root, Arc::new(vec![[1; 32]; 3]));
        assert!(matches!(
            MetaInfo::parse(&bad.to_bytes()),
            Err(MetaError::Invalid(_))
        ));
        // A missing layer.
        bad.piece_layers = PieceLayers::new();
        assert!(MetaInfo::parse(&bad.to_bytes()).is_err());
        // meta version 3.
        let info = Value::dict()
            .with("meta version", 3)
            .with("name", "n")
            .with("piece length", 16384)
            .with("file tree", Value::dict());
        assert!(matches!(
            Info::parse(&bencode::encode(&info)),
            Err(MetaError::Unsupported(_))
        ));
        // Unsafe names in the file tree.
        let leaf = Value::dict().with(
            "",
            Value::dict()
                .with("length", 1)
                .with("pieces root", vec![0u8; 32]),
        );
        let info = Value::dict()
            .with("meta version", 2)
            .with("name", "n")
            .with("piece length", 16384)
            .with("file tree", Value::dict().with("..", leaf));
        assert!(matches!(
            Info::parse(&bencode::encode(&info)),
            Err(MetaError::UnsafePath(_))
        ));
    }

    #[test]
    fn hybrid_mismatch_refused() {
        let files = sample_files();
        let mi = Builder::new("t")
            .piece_length(16384)
            .version(TorrentVersion::Hybrid)
            .build_files(&files)
            .unwrap();
        let mut v = bencode::decode(mi.info.raw()).unwrap();
        // Drop a v1 padding file: the v1 offsets no longer match v2's.
        if let Value::Dict(d) = &mut v {
            if let Some(Value::List(l)) = d.get_mut(&b"files"[..]) {
                l.remove(1);
            }
        }
        assert!(Info::parse(&bencode::encode(&v)).is_err());
    }

    #[test]
    fn hex() {
        let h = InfoHash::of(b"x");
        assert_eq!(InfoHash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(InfoHash::from_hex("zz"), None);
    }
}
