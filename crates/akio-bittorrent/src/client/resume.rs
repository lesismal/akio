//! Fast-resume data (ADR-033): what a torrent needs to start again without hash-checking its
//! data. A bencoded dictionary, versioned, closed by a SHA-256 checksum of everything before it:
//!
//! | Key | Value |
//! |---|---|
//! | `file` | `akio-bittorrent resume` |
//! | `version` | 1 |
//! | `info-hash` | 20 bytes: the torrent's key hash |
//! | `info-hash-v2` | 32 bytes (v2 and hybrid torrents) |
//! | `name` | the name, if known |
//! | `info` | the info dictionary as raw bytes, once known |
//! | `pieces` | the have-bitfield (with `info`) |
//! | `piece-layers` | v2: file root to its piece layer, concatenated hashes |
//! | `files` | per file of `info`: `[size, mtime ns]`, `[]` for a missing or padding file |
//! | `clean` | 1 if no write could follow the save (paused, nothing in flight) |
//! | `paused` | 1 if paused by the user or a seed limit |
//! | `peers`, `peers6` | compact peers |
//! | `trackers`, `url-list` | announce URLs, web seeds |
//! | `uploaded`, `downloaded`, `seeding-time` | totals across sessions (bytes, seconds) |
//! | `upload-limit`, `download-limit`, `seed-ratio` (thousandths), `seed-time` (seconds) | limits |
//! | `checksum` | SHA-256 of the encoding of the dictionary without this key |
//!
//! Decoding never panics and checks everything it can on its own (the checksum, lengths, the
//! info dictionary against the hash); [`plan`] checks the rest against the files on disk.

use std::fmt;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::storage::FileStamp;
use super::{RateLimits, SeedLimits};
use crate::bencode::{self, Value};
use crate::merkle::{self, Hash};
use crate::metainfo::{Info, InfoHash, InfoHashV2, PieceLayers};
use crate::wire::{Bitfield, compact_peers, parse_compact_peers};

const MAGIC: &str = "akio-bittorrent resume";
/// The format version written; a later version is refused.
pub(crate) const VERSION: i64 = 1;
/// Peers kept in resume data.
pub(crate) const MAX_PEERS: usize = 200;
/// Trackers and web seeds kept (each).
const MAX_URLS: usize = 256;

/// Why fast-resume data was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResumeError {
    /// Not resume data, truncated or malformed.
    Malformed(String),
    /// A format version this client does not read.
    Version(i64),
    /// The checksum does not match: the data was damaged.
    Checksum,
    /// The data is of another torrent, or does not fit it.
    Mismatch(String),
}

impl fmt::Display for ResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResumeError::Malformed(s) => write!(f, "malformed resume data: {s}"),
            ResumeError::Version(v) => write!(f, "resume data version {v} not supported"),
            ResumeError::Checksum => f.write_str("resume data checksum mismatch"),
            ResumeError::Mismatch(s) => write!(f, "resume data does not fit the torrent: {s}"),
        }
    }
}

impl std::error::Error for ResumeError {}

fn bad(s: &str) -> ResumeError {
    ResumeError::Malformed(s.to_owned())
}

/// Decoded resume data.
#[derive(Clone, Debug, Default)]
pub(crate) struct ResumeData {
    pub(crate) info_hash: InfoHash,
    pub(crate) info_hash_v2: Option<InfoHashV2>,
    pub(crate) name: Option<String>,
    pub(crate) info: Option<Arc<Info>>,
    pub(crate) pieces: Option<Vec<u8>>,
    pub(crate) layers: Vec<(Hash, Vec<Hash>)>,
    /// Layers held by a running torrent (encoded with `layers`).
    pub(crate) held: PieceLayers,
    /// `None`: the storage had no file stamps when saved.
    pub(crate) files: Option<Vec<Option<FileStamp>>>,
    pub(crate) clean: bool,
    pub(crate) paused: bool,
    pub(crate) peers: Vec<SocketAddr>,
    pub(crate) trackers: Vec<String>,
    pub(crate) url_list: Vec<String>,
    pub(crate) uploaded: u64,
    pub(crate) downloaded: u64,
    pub(crate) seeding_time: Duration,
    pub(crate) rate_limits: RateLimits,
    pub(crate) seed_limits: SeedLimits,
}

fn mtime_ns(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_nanos()).map_or(i64::MIN, |n| -n),
    }
}

fn from_ns(n: i64) -> SystemTime {
    if n >= 0 {
        UNIX_EPOCH + Duration::from_nanos(n as u64)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_nanos(n.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn uint(v: &Value, key: &str) -> Result<Option<u64>, ResumeError> {
    match v.get(key) {
        None => Ok(None),
        Some(Value::Int(n)) if *n >= 0 => Ok(Some(*n as u64)),
        Some(_) => Err(ResumeError::Malformed(format!("`{key}` is not a count"))),
    }
}

fn flag(v: &Value, key: &str) -> Result<bool, ResumeError> {
    Ok(uint(v, key)?.unwrap_or(0) != 0)
}

fn urls(v: &Value, key: &str) -> Result<Vec<String>, ResumeError> {
    let Some(l) = v.get(key) else {
        return Ok(Vec::new());
    };
    let l = l
        .as_list()
        .ok_or_else(|| ResumeError::Malformed(format!("`{key}` is not a list")))?;
    let mut out = Vec::new();
    for u in l.iter().take(MAX_URLS) {
        let s = u
            .as_str()
            .ok_or_else(|| ResumeError::Malformed(format!("`{key}` holds a non-string")))?;
        if !out.iter().any(|o| o == s) {
            out.push(s.to_owned());
        }
    }
    Ok(out)
}

impl ResumeData {
    /// Decodes `b`, checking the format, version, checksum and the data's own consistency.
    pub(crate) fn decode(b: &[u8]) -> Result<ResumeData, ResumeError> {
        let v = bencode::decode(b).map_err(|e| ResumeError::Malformed(e.to_string()))?;
        let Value::Dict(mut d) = v else {
            return Err(bad("not a dictionary"));
        };
        if d.get(b"file".as_slice()).and_then(Value::as_str) != Some(MAGIC) {
            return Err(bad("not akio-bittorrent resume data"));
        }
        match d.get(b"version".as_slice()) {
            Some(Value::Int(VERSION)) => {}
            Some(Value::Int(n)) => return Err(ResumeError::Version(*n)),
            _ => return Err(bad("no version")),
        }
        let sum = match d.remove(b"checksum".as_slice()) {
            Some(Value::Bytes(s)) if s.len() == 32 => s,
            _ => return Err(bad("no checksum")),
        };
        let v = Value::Dict(d);
        if merkle::sha256(&bencode::encode(&v)).as_slice() != sum.as_slice() {
            return Err(ResumeError::Checksum);
        }
        let mut r = ResumeData::default();
        let ih: [u8; 20] = v
            .bytes_at("info-hash")
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("no info hash"))?;
        r.info_hash = InfoHash(ih);
        if let Some(b) = v.get("info-hash-v2") {
            let h: [u8; 32] = b
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("bad v2 info hash"))?;
            r.info_hash_v2 = Some(InfoHashV2(h));
        }
        if let Some(n) = v.get("name") {
            r.name = Some(n.as_str().ok_or_else(|| bad("bad name"))?.to_owned());
        }
        if let Some(raw) = v.get("info") {
            let raw = raw.as_bytes().ok_or_else(|| bad("bad info"))?;
            let info =
                Info::parse(raw).map_err(|e| ResumeError::Malformed(format!("info: {e}")))?;
            if !info_matches(&info, &r.info_hash) {
                return Err(ResumeError::Mismatch(
                    "the info dictionary is of another torrent".into(),
                ));
            }
            if let Some(v2) = info.info_hash_v2() {
                if r.info_hash_v2.is_some_and(|h| h != v2) {
                    return Err(ResumeError::Mismatch("v2 hash differs".into()));
                }
                r.info_hash_v2 = Some(v2);
            }
            r.info = Some(Arc::new(info));
        }
        if let Some(p) = v.get("pieces") {
            let p = p.as_bytes().ok_or_else(|| bad("bad pieces"))?;
            let Some(info) = &r.info else {
                return Err(bad("pieces without info"));
            };
            if Bitfield::from_bytes(p, info.num_pieces()).is_none() {
                return Err(ResumeError::Mismatch("bitfield length".into()));
            }
            r.pieces = Some(p.to_vec());
        }
        if let Some(l) = v.get("piece-layers") {
            let l = l.as_dict().ok_or_else(|| bad("bad piece layers"))?;
            for (root, hashes) in l {
                let root: Hash = root
                    .as_slice()
                    .try_into()
                    .map_err(|_| bad("bad piece layer root"))?;
                let hashes = hashes.as_bytes().ok_or_else(|| bad("bad piece layer"))?;
                if hashes.is_empty() || hashes.len() % 32 != 0 {
                    return Err(bad("bad piece layer length"));
                }
                let layer = hashes
                    .chunks_exact(32)
                    .map(|c| {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(c);
                        h
                    })
                    .collect();
                r.layers.push((root, layer));
            }
        }
        if let Some(f) = v.get("files") {
            let f = f.as_list().ok_or_else(|| bad("bad files"))?;
            let Some(info) = &r.info else {
                return Err(bad("files without info"));
            };
            if f.len() != info.files.len() {
                return Err(ResumeError::Mismatch("file count".into()));
            }
            let mut out = Vec::with_capacity(f.len());
            for e in f {
                match e.as_list() {
                    Some([]) => out.push(None),
                    Some([Value::Int(size), Value::Int(mtime)]) if *size >= 0 => {
                        out.push(Some(FileStamp::new(*size as u64, from_ns(*mtime))));
                    }
                    _ => return Err(bad("bad file entry")),
                }
            }
            r.files = Some(out);
        }
        r.clean = flag(&v, "clean")?;
        r.paused = flag(&v, "paused")?;
        for (key, v6) in [("peers", false), ("peers6", true)] {
            if let Some(p) = v.get(key) {
                let p = p
                    .as_bytes()
                    .ok_or_else(|| ResumeError::Malformed(format!("bad {key}")))?;
                if p.len() % if v6 { 18 } else { 6 } != 0 {
                    return Err(ResumeError::Malformed(format!("bad {key} length")));
                }
                r.peers.extend(parse_compact_peers(p, v6));
            }
        }
        r.peers.truncate(MAX_PEERS);
        r.trackers = urls(&v, "trackers")?;
        r.url_list = urls(&v, "url-list")?;
        r.uploaded = uint(&v, "uploaded")?.unwrap_or(0);
        r.downloaded = uint(&v, "downloaded")?.unwrap_or(0);
        r.seeding_time = Duration::from_secs(uint(&v, "seeding-time")?.unwrap_or(0));
        r.rate_limits = RateLimits::new(uint(&v, "upload-limit")?, uint(&v, "download-limit")?);
        r.seed_limits = SeedLimits::new(
            uint(&v, "seed-ratio")?.map(|m| m as f64 / 1000.0),
            uint(&v, "seed-time")?.map(Duration::from_secs),
        );
        Ok(r)
    }

    /// Encodes, closing with the checksum.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut d = Value::dict()
            .with("file", MAGIC)
            .with("version", VERSION)
            .with("info-hash", Value::bytes(self.info_hash.0));
        if let Some(h) = self.info_hash_v2 {
            d.insert("info-hash-v2", Value::bytes(h.0));
        }
        if let Some(n) = &self.name {
            d.insert("name", n.as_str());
        }
        if let Some(info) = &self.info {
            d.insert("info", Value::bytes(info.raw()));
            if let Some(p) = &self.pieces {
                d.insert("pieces", Value::bytes(p));
            }
            if let Some(files) = &self.files {
                let l: Vec<Value> = files
                    .iter()
                    .map(|f| match f {
                        None => Value::List(Vec::new()),
                        Some(s) => Value::List(vec![
                            Value::Int(s.size.min(i64::MAX as u64) as i64),
                            Value::Int(mtime_ns(s.mtime)),
                        ]),
                    })
                    .collect();
                d.insert("files", l);
            }
        }
        if !self.layers.is_empty() || !self.held.is_empty() {
            let mut l = std::collections::BTreeMap::new();
            for (root, layer) in &self.layers {
                l.insert(root.to_vec(), Value::Bytes(layer.concat()));
            }
            for (root, layer) in self.held.iter() {
                l.insert(root.to_vec(), Value::Bytes(layer.concat()));
            }
            d.insert("piece-layers", Value::Dict(l));
        }
        d.insert("clean", i64::from(self.clean));
        d.insert("paused", i64::from(self.paused));
        let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) =
            self.peers.iter().take(MAX_PEERS).partition(|a| a.is_ipv4());
        if !v4.is_empty() {
            d.insert("peers", compact_peers(&v4, false));
        }
        if !v6.is_empty() {
            d.insert("peers6", compact_peers(&v6, true));
        }
        let list = |l: &[String]| -> Value {
            Value::List(
                l.iter()
                    .take(MAX_URLS)
                    .map(|s| Value::from(s.as_str()))
                    .collect(),
            )
        };
        d.insert("trackers", list(&self.trackers));
        d.insert("url-list", list(&self.url_list));
        let int = |n: u64| Value::Int(n.min(i64::MAX as u64) as i64);
        d.insert("uploaded", int(self.uploaded));
        d.insert("downloaded", int(self.downloaded));
        d.insert("seeding-time", int(self.seeding_time.as_secs()));
        if let Some(n) = self.rate_limits.upload {
            d.insert("upload-limit", int(n));
        }
        if let Some(n) = self.rate_limits.download {
            d.insert("download-limit", int(n));
        }
        if let Some(r) = self.seed_limits.ratio {
            if r.is_finite() && r >= 0.0 {
                d.insert("seed-ratio", int((r * 1000.0).round() as u64));
            }
        }
        if let Some(t) = self.seed_limits.time {
            d.insert("seed-time", int(t.as_secs()));
        }
        let sum = merkle::sha256(&bencode::encode(&d));
        d.insert("checksum", Value::bytes(sum));
        bencode::encode(&d)
    }

    /// Checks the data belongs to the torrent of `info_hash` (any of its hashes) and `info`.
    pub(crate) fn check(
        &self,
        info_hash: &InfoHash,
        info: Option<&Info>,
    ) -> Result<(), ResumeError> {
        let same = self.info_hash == *info_hash
            || self
                .info_hash_v2
                .is_some_and(|h| h.truncated() == *info_hash)
            || self
                .info
                .as_ref()
                .is_some_and(|i| info_matches(i, info_hash));
        if !same {
            return Err(ResumeError::Mismatch(format!(
                "resume data of {}, not {info_hash}",
                self.info_hash
            )));
        }
        if let (Some(a), Some(b)) = (&self.info, info) {
            if a.raw() != b.raw() {
                return Err(ResumeError::Mismatch("info dictionary differs".into()));
            }
        }
        Ok(())
    }

    /// The piece layers that check out against `info`.
    pub(crate) fn layers_for(&self, info: &Info) -> PieceLayers {
        let mut l = PieceLayers::new();
        for (root, layer) in &self.layers {
            l.insert(info, *root, layer.clone());
        }
        for (root, layer) in self.held.iter() {
            l.insert(info, *root, layer.to_vec());
        }
        l
    }
}

/// `v` with a correct checksum, encoded: lets the fuzzer past the checksum.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn seal(v: Value) -> Option<Vec<u8>> {
    let Value::Dict(mut d) = v else {
        return None;
    };
    d.remove(b"checksum".as_slice());
    let mut v = Value::Dict(d);
    let sum = merkle::sha256(&bencode::encode(&v));
    v.insert("checksum", Value::bytes(sum));
    Some(bencode::encode(&v))
}

fn info_matches(info: &Info, ih: &InfoHash) -> bool {
    info.info_hash() == *ih
        || info.info_hash_v1() == Some(*ih)
        || info.info_hash_v2().map(|h| h.truncated()) == Some(*ih)
}

/// What a check after resuming does: pieces taken as had, and pieces to hash-check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) trusted: Bitfield,
    pub(crate) recheck: Vec<usize>,
}

/// Decides which claimed pieces to trust: a file whose size or modification time differs from
/// the saved one has its pieces checked again, all of them (claimed or not), unless the save was
/// taken while the torrent ran and the file was still being downloaded (`clean` false, some of
/// its pieces missing): then the client itself may have written it after the save, so only a
/// file now missing, shorter than its last claimed piece or longer than it should be is checked
/// again. `now` is `None` for storage without files: the claims are trusted if it may hold data.
pub(crate) fn plan(
    info: &Info,
    claimed: &Bitfield,
    saved: Option<&[Option<FileStamp>]>,
    now: Option<&[Option<FileStamp>]>,
    clean: bool,
    may_have_data: bool,
) -> Plan {
    let n = info.num_pieces();
    let Some(now) = now else {
        return Plan {
            trusted: if may_have_data {
                claimed.clone()
            } else {
                Bitfield::new(n)
            },
            recheck: Vec::new(),
        };
    };
    let Some(saved) = saved.filter(|s| s.len() == info.files.len() && now.len() == s.len()) else {
        // Nothing to compare with: check everything.
        return Plan {
            trusted: Bitfield::new(n),
            recheck: (0..n).collect(),
        };
    };
    let mut recheck = Bitfield::new(n);
    for (i, f) in info.files.iter().enumerate() {
        if f.padding || f.length == 0 {
            continue;
        }
        if saved[i] == now[i] {
            continue;
        }
        let pieces = info.file_pieces(i);
        let complete = pieces.clone().all(|p| claimed.get(p));
        let again = if clean || complete {
            true
        } else {
            // Bytes of the file the claimed pieces cover.
            let need = pieces
                .clone()
                .filter(|&p| claimed.get(p))
                .map(|p| {
                    let end = info.piece_offset(p) + u64::from(info.piece_size(p));
                    end.min(f.offset + f.length) - f.offset
                })
                .max();
            match (&now[i], need) {
                (_, None) => now[i].is_some_and(|s| s.size > f.length),
                (None, Some(_)) => true,
                (Some(s), Some(need)) => s.size < need || s.size > f.length,
            }
        };
        if again {
            for p in pieces {
                recheck.set(p, true);
            }
        }
    }
    let mut trusted = claimed.clone();
    for p in recheck.ones() {
        trusted.set(p, false);
    }
    Plan {
        trusted,
        recheck: recheck.ones().collect(),
    }
}

/// `<dir>/<hex>.resume`.
pub(crate) fn path(dir: &Path, ih: &InfoHash) -> PathBuf {
    dir.join(format!("{}.resume", ih.to_hex()))
}

/// Writes `data` to `path` atomically: a temporary file, synced, renamed over it.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let res = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{Builder, TorrentVersion};

    fn info(version: TorrentVersion) -> Info {
        let files = vec![
            (vec!["a".to_owned()], vec![1u8; 40_000]),
            (vec!["b".to_owned()], vec![2u8; 70_000]),
        ];
        Builder::new("t")
            .piece_length(16 * 1024)
            .version(version)
            .build_files(&files)
            .unwrap()
            .info
    }

    fn sample(info: &Info) -> ResumeData {
        let mut bf = Bitfield::new(info.num_pieces());
        bf.set(0, true);
        bf.set(2, true);
        ResumeData {
            info_hash: info.info_hash(),
            info_hash_v2: info.info_hash_v2(),
            name: Some("t".into()),
            info: Some(Arc::new(info.clone())),
            pieces: Some(bf.as_bytes().to_vec()),
            layers: Vec::new(),
            held: PieceLayers::new(),
            files: Some(
                info.files
                    .iter()
                    .map(|f| {
                        (!f.padding)
                            .then(|| FileStamp::new(f.length, from_ns(1_700_000_000_123_456_789)))
                    })
                    .collect(),
            ),
            clean: true,
            paused: true,
            peers: vec!["1.2.3.4:5".parse().unwrap(), "[::1]:7".parse().unwrap()],
            trackers: vec!["http://t/announce".into()],
            url_list: vec!["http://w/".into()],
            uploaded: 10,
            downloaded: 20,
            seeding_time: Duration::from_secs(30),
            rate_limits: RateLimits::new(Some(1000), None),
            seed_limits: SeedLimits::new(Some(1.5), Some(Duration::from_secs(60))),
        }
    }

    #[test]
    fn round_trip_all_versions() {
        for v in [
            TorrentVersion::V1,
            TorrentVersion::V2,
            TorrentVersion::Hybrid,
        ] {
            let i = info(v);
            let r = sample(&i);
            let b = r.encode();
            let d = ResumeData::decode(&b).unwrap();
            assert_eq!(d.info_hash, r.info_hash);
            assert_eq!(d.info_hash_v2, r.info_hash_v2);
            assert_eq!(d.pieces, r.pieces);
            assert_eq!(d.files, r.files);
            assert_eq!(d.peers, r.peers);
            assert_eq!(d.trackers, r.trackers);
            assert_eq!(d.url_list, r.url_list);
            assert_eq!((d.uploaded, d.downloaded), (10, 20));
            assert_eq!(d.seeding_time, Duration::from_secs(30));
            assert_eq!(d.rate_limits, r.rate_limits);
            assert_eq!(d.seed_limits, r.seed_limits);
            assert!(d.clean && d.paused);
            assert_eq!(d.encode(), b, "{v:?}: stable encoding");
            d.check(&i.info_hash(), Some(&i)).unwrap();
            assert!(d.check(&InfoHash([9; 20]), None).is_err());
        }
    }

    #[test]
    fn damage_is_refused() {
        let i = info(TorrentVersion::V1);
        let b = sample(&i).encode();
        for n in [0, 1, b.len() / 2, b.len() - 1] {
            assert!(ResumeData::decode(&b[..n]).is_err(), "truncated at {n}");
        }
        // Every single-byte flip is caught (bencode syntax, magic, or the checksum).
        for at in 0..b.len() {
            let mut c = b.clone();
            c[at] ^= 0x01;
            assert!(ResumeData::decode(&c).is_err(), "flip at {at}");
        }
        let mut v = bencode::decode(&b).unwrap();
        v.insert("version", 2i64);
        assert_eq!(
            ResumeData::decode(&bencode::encode(&v)).unwrap_err(),
            ResumeError::Version(2)
        );
    }

    fn stamps(info: &Info, t: i64) -> Vec<Option<FileStamp>> {
        info.files
            .iter()
            .map(|f| (!f.padding).then(|| FileStamp::new(f.length, from_ns(t))))
            .collect()
    }

    #[test]
    fn plan_rechecks_changed_files() {
        let i = info(TorrentVersion::V1); // a: pieces 0..3, b: pieces 2..7 (piece 2 spans)
        let n = i.num_pieces();
        let full = Bitfield::full(n);
        let saved = stamps(&i, 5);
        let p = plan(&i, &full, Some(&saved), Some(&saved), false, true);
        assert_eq!(p.trusted, full);
        assert!(p.recheck.is_empty());
        let mut now = saved.clone();
        now[0] = Some(FileStamp::new(40_000, from_ns(6)));
        let p = plan(&i, &full, Some(&saved), Some(&now), false, true);
        assert_eq!(p.recheck, vec![0, 1, 2]);
        assert_eq!(p.trusted.count(), n - 3);
        // Storage without files.
        let p = plan(&i, &full, Some(&saved), None, true, true);
        assert_eq!(p.trusted, full);
        let p = plan(&i, &full, Some(&saved), None, true, false);
        assert_eq!(p.trusted.count(), 0);
    }

    #[test]
    fn plan_unclean_incomplete_files_are_ours() {
        let i = info(TorrentVersion::V1);
        let n = i.num_pieces();
        let mut claimed = Bitfield::new(n);
        claimed.set(3, true); // in b, which is incomplete
        let saved = stamps(&i, 5);
        let mut now = saved.clone();
        now[1] = Some(FileStamp::new(70_000, from_ns(9)));
        // Unclean: the client may have written b after the save.
        let p = plan(&i, &claimed, Some(&saved), Some(&now), false, true);
        assert_eq!(p.trusted, claimed);
        assert!(p.recheck.is_empty());
        // Clean: it may not.
        let p = plan(&i, &claimed, Some(&saved), Some(&now), true, true);
        assert_eq!(p.recheck, (2..n).collect::<Vec<_>>());
        // Unclean but shorter than the claimed piece needs, or gone: checked.
        now[1] = Some(FileStamp::new(100, from_ns(9)));
        let p = plan(&i, &claimed, Some(&saved), Some(&now), false, true);
        assert!(p.recheck.contains(&3));
        now[1] = None;
        let p = plan(&i, &claimed, Some(&saved), Some(&now), false, true);
        assert!(p.recheck.contains(&3));
    }
}
