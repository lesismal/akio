//! Static files: path safety, MIME types, conditional requests, ranges, pre-compressed variants,
//! an in-memory cache for small files and `sendfile(2)` for large ones.

use std::{
    collections::HashMap,
    fs,
    hash::{BuildHasher, Hasher},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use only_core::{Pool, PoolConfig};

use crate::{
    context::{Context, Service},
    message::{FileBody, Headers, Method, Request, Response, format_http_date, percent_decode},
};

/// Serves files below a root directory. Mount it on a wildcard route
/// (`router.get("/static/*path", Files::new("public"))`, parameter name `path`) or use it as the
/// router fallback (then the request path is used).
///
/// * `GET`/`HEAD`, `ETag` + `Last-Modified`; `If-None-Match` / `If-Modified-Since` answer `304`,
///   `If-Match` / `If-Unmodified-Since` answer `412`; `Range` requests (`206`/`416`), honoured
///   only while `If-Range` (an entity tag or a date) still matches.
/// * Several ranges (`bytes=0-9,20-29`) answer `206` with a `multipart/byteranges` body, parts
///   in request order. Overlapping ranges and ranges less than 80 bytes apart are coalesced
///   (RFC 9110 section 14.2); a header with more than 32 ranges, or whose parts would exceed
///   1 MiB, is ignored and the whole file is sent. A multipart body is built in memory.
/// * `index.html` for directories; `..` and other escapes are refused. Symlinks are followed.
/// * `file.ext.br` / `file.ext.zst` / `file.ext.gz` next to `file.ext` are served to clients
///   that accept them (`br`, `zstd`, `gzip`; tried in that order);
///   whether they exist is cached with the file, so a hit costs no `stat` per variant.
/// * Files up to [`max_cached_bytes`](Files::max_cached_bytes) are cached in memory and
///   re-checked against the disk at most every [`check_interval`](Files::check_interval);
///   larger ones are sent with `sendfile` from a handle kept open (with its metadata) for up to
///   [`max_open_files`](Files::max_open_files) files, under the same re-check rule, so a hit
///   costs no `stat`/`open`. When the handles are all taken, a new file evicts the least
///   recently used one (CLOCK). An entry is dropped or replaced when its file is deleted, or
///   when its size, modification time or inode change (an atomic rename over it included).
/// * Only a cache hit inside its trust window is answered on the I/O thread. Everything that
///   touches the disk (`stat`, `open`, reading a file into the cache, the parts of a
///   multi-range response from a large file) runs on a small pool of its own (up to 16 threads,
///   4096 queued requests; past that the answer is `503` with `Retry-After: 1`), and the
///   response is sent from there.
pub struct Files {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    index: String,
    max_cached: u64,
    check_interval: Duration,
    cache_control: Option<String>,
    max_open: usize,
    /// The cache, sharded by path: a hit takes one shard's read lock.
    shards: Box<[RwLock<HashMap<PathBuf, Entry>>]>,
    /// The entries holding an open file, in CLOCK order. Only cache fills and evictions (on
    /// the disk pool) take it, always before a shard lock.
    ring: Mutex<Ring>,
}

const SHARDS: usize = 16;

/// The `.br`, `.zst` and `.gz` twins of a file: `Content-Encoding` token and file extension,
/// in order of preference.
const TWINS: [(&str, &str); 3] = [("br", "br"), ("zstd", "zst"), ("gzip", "gz")];

enum Entry {
    File(Arc<Cached>),
    /// A directory, served as its index file, and when that was last checked.
    Dir(Arc<Path>, AtomicU64),
}

/// The open-file entries (at most `max_open`) and the CLOCK hand: the next slot considered
/// for eviction.
#[derive(Default)]
struct Ring {
    slots: Vec<(PathBuf, Arc<Cached>)>,
    hand: usize,
}

impl Ring {
    fn position(&self, path: &Path) -> Option<usize> {
        self.slots.iter().position(|(p, _)| p == path)
    }

    /// The slot of the entry to evict: the first one from the hand that was not used since the
    /// hand last passed it (each used entry gets its bit cleared and a second chance).
    fn victim(&mut self) -> usize {
        loop {
            if self.hand >= self.slots.len() {
                self.hand = 0;
            }
            if !self.slots[self.hand].1.used.swap(false, Ordering::Relaxed) {
                return self.hand;
            }
            self.hand += 1;
        }
    }
}

impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files").finish_non_exhaustive()
    }
}

/// The content of a cache entry: the bytes of a small file, or an open handle to a large one.
enum Body {
    Mem(Arc<[u8]>),
    File(Arc<fs::File>),
}

impl Clone for Body {
    fn clone(&self) -> Body {
        match self {
            Body::Mem(b) => Body::Mem(b.clone()),
            Body::File(f) => Body::File(f.clone()),
        }
    }
}

struct Cached {
    body: Body,
    len: u64,
    mtime: SystemTime,
    mtime_secs: u64,
    /// Device and inode: a file renamed over the cached one has another.
    id: (u64, u64),
    /// Used since the CLOCK hand last passed (open-file entries).
    used: AtomicBool,
    /// When the disk was last consulted, in [`clock_ms`] milliseconds.
    checked: AtomicU64,
    etag: Box<str>,
    /// The content type (of the original file, for a compressed twin).
    mime: &'static str,
    /// The fields every answer about this file carries: `ETag`, `Last-Modified`,
    /// `Accept-Ranges`, `Cache-Control`, `Content-Encoding`, `Vary`; formatted once.
    meta: Headers,
    /// `Content-Type`, then `meta`.
    full: Headers,
    /// The compressed twins (see [`TWINS`]); `None` when there is no such file. Checked with
    /// the entry itself.
    twins: [Option<Arc<Cached>>; 3],
}

impl Cached {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: Body,
        len: u64,
        mtime: SystemTime,
        id: (u64, u64),
        mime: &'static str,
        encoding: Option<&str>,
        cache_control: Option<&str>,
        twins: [Option<Arc<Cached>>; 3],
    ) -> Cached {
        let secs = unix_secs(mtime);
        let etag = match encoding {
            None => format!("\"{len:x}-{secs:x}\""),
            Some(e) => format!("\"{len:x}-{secs:x}-{e}\""),
        };
        let mut meta = Headers::with_capacity(6, 160);
        meta.append("ETag", &etag);
        meta.append("Last-Modified", format_http_date(secs));
        meta.append("Accept-Ranges", "bytes");
        if let Some(cc) = cache_control {
            meta.append("Cache-Control", cc);
        }
        if let Some(e) = encoding {
            meta.append("Content-Encoding", e);
        }
        meta.append("Vary", "Accept-Encoding");
        let mut full = Headers::with_capacity(7, 192);
        full.append("Content-Type", mime);
        for (n, v) in meta.iter() {
            full.append(n, v);
        }
        Cached {
            body,
            len,
            mtime,
            mtime_secs: secs,
            id,
            used: AtomicBool::new(false),
            checked: AtomicU64::new(clock_ms()),
            etag: etag.into(),
            mime,
            meta,
            full,
            twins,
        }
    }

    /// Whether `md` still describes the file this entry was read from.
    fn matches(&self, md: &fs::Metadata) -> bool {
        self.len == md.len()
            && self.mtime == md.modified().unwrap_or(SystemTime::UNIX_EPOCH)
            && self.id == (md.dev(), md.ino())
    }
}

/// Milliseconds since the first call: the clock of cache freshness.
fn clock_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The pool every [`Files`] does its disk work on.
fn disk_pool() -> &'static Arc<Pool> {
    static POOL: OnceLock<Arc<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut cfg = PoolConfig::default();
        cfg.max_threads = 16;
        cfg.queue_capacity = 4096;
        Pool::new(cfg)
    })
}

fn read_lock<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}

fn write_lock<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Files {
    /// Serves `root`.
    pub fn new(root: impl Into<PathBuf>) -> Files {
        Files {
            inner: Arc::new(Inner {
                root: root.into(),
                index: "index.html".into(),
                max_cached: 256 << 10,
                check_interval: Duration::from_secs(5),
                cache_control: None,
                max_open: 64,
                shards: (0..SHARDS).map(|_| RwLock::default()).collect(),
                ring: Mutex::default(),
            }),
        }
    }

    /// The settings, while the `Files` is being built (nothing else holds it yet).
    fn cfg(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.inner).expect("Files is configured before it serves")
    }

    /// The file served for a directory (default `index.html`).
    #[must_use]
    pub fn index(mut self, name: &str) -> Files {
        self.cfg().index = name.to_owned();
        self
    }

    /// Largest file kept in memory (default 256 KiB; 0 disables the cache).
    #[must_use]
    pub fn max_cached_bytes(mut self, n: u64) -> Files {
        self.cfg().max_cached = n;
        self
    }

    /// How many files larger than [`max_cached_bytes`](Files::max_cached_bytes) keep an open
    /// handle and their metadata cached (default 64; 0 opens such files per request). Each
    /// holds a file descriptor (and one more per compressed twin) until it is evicted (least
    /// recently used first, CLOCK), its file changes or the `Files` is dropped; responses still
    /// being sent keep their own handle.
    #[must_use]
    pub fn max_open_files(mut self, n: usize) -> Files {
        self.cfg().max_open = n;
        self
    }

    /// How long a cached file is trusted before the disk is consulted again (default 5 s).
    #[must_use]
    pub fn check_interval(mut self, d: Duration) -> Files {
        self.cfg().check_interval = d;
        self
    }

    /// A `Cache-Control` header for every file response.
    #[must_use]
    pub fn cache_control(mut self, v: &str) -> Files {
        self.cfg().cache_control = Some(v.to_owned());
        self
    }

    /// The path below the root asked for, or `None` if it is unsafe.
    fn relative(ctx: &Context) -> Option<PathBuf> {
        let raw = ctx
            .param_raw("path")
            .map_or_else(|| ctx.path().to_owned(), str::to_owned);
        let decoded = percent_decode(&raw)?;
        let mut rel = PathBuf::new();
        for seg in decoded.split('/').filter(|s| !s.is_empty() && *s != ".") {
            if seg == ".." || seg.contains(['\\', '\0', ':']) {
                return None;
            }
            rel.push(seg);
        }
        Some(rel)
    }

    fn mime(path: &Path) -> &'static str {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("html" | "htm") => "text/html; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("js" | "mjs") => "text/javascript; charset=utf-8",
            Some("json") => "application/json",
            Some("txt") => "text/plain; charset=utf-8",
            Some("xml") => "application/xml",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("wasm") => "application/wasm",
            Some("pdf") => "application/pdf",
            Some("mp4") => "video/mp4",
            Some("webm") => "video/webm",
            Some("mp3") => "audio/mpeg",
            _ => "application/octet-stream",
        }
    }
}

impl Inner {
    fn shard(&self, path: &Path) -> &RwLock<HashMap<PathBuf, Entry>> {
        // FNV-1a: cheap, and only spreads paths over the shards (each map hashes again).
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in path.as_os_str().as_encoded_bytes() {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
        &self.shards[(h as usize) % self.shards.len()]
    }

    fn is_fresh(&self, checked: &AtomicU64) -> bool {
        let age = clock_ms().saturating_sub(checked.load(Ordering::Relaxed));
        u128::from(age) < self.check_interval.as_millis()
    }

    /// A cached entry still inside its trust window, without touching the disk (a directory
    /// is followed to its index file).
    fn fresh(&self, path: &Path) -> Option<Arc<Cached>> {
        let index = {
            let g = read_lock(self.shard(path));
            match g.get(path)? {
                Entry::File(c) => {
                    return self.is_fresh(&c.checked).then(|| {
                        c.used.store(true, Ordering::Relaxed);
                        c.clone()
                    });
                }
                Entry::Dir(index, checked) => {
                    if !self.is_fresh(checked) {
                        return None;
                    }
                    index.clone()
                }
            }
        };
        let g = read_lock(self.shard(&index));
        match g.get(&*index)? {
            Entry::File(c) if self.is_fresh(&c.checked) => {
                c.used.store(true, Ordering::Relaxed);
                Some(c.clone())
            }
            _ => None,
        }
    }

    /// Drops the entry of a path that is gone, freeing its open-file slot.
    fn forget(&self, path: &Path) {
        let mut ring = lock(&self.ring);
        if let Some(i) = ring.position(path) {
            ring.slots.swap_remove(i);
        }
        write_lock(self.shard(path)).remove(path);
    }

    /// Answers a request from the disk (on the disk pool): `stat`, directory index, (re)loading
    /// the cache entry and its compressed twins.
    fn serve_disk(&self, req: &Request, mut path: PathBuf) -> Response {
        let Ok(mut md) = fs::metadata(&path) else {
            self.forget(&path);
            return Response::text(404, "Not Found");
        };
        if md.is_dir() {
            let dir = path.clone();
            path.push(&self.index);
            match fs::metadata(&path) {
                Ok(m) if m.is_file() => md = m,
                _ => return Response::text(404, "Not Found"),
            }
            let entry = Entry::Dir(Arc::from(path.as_path()), AtomicU64::new(clock_ms()));
            write_lock(self.shard(&dir)).insert(dir, entry);
        }
        let Some(c) = self.load(&path, &md) else {
            return Response::text(404, "Not Found");
        };
        let served = pick(&c, req.headers.get("accept-encoding").unwrap_or(""));
        self.build(req, served, true)
            .unwrap_or_else(|| Response::text(500, "Internal Server Error"))
    }

    /// The entry of `path` (whose metadata is `md`), reusing what is cached when the file did
    /// not change, and caching it when it is small enough or open handles are cached at all.
    /// Runs on the disk pool.
    fn load(&self, path: &Path, md: &fs::Metadata) -> Option<Arc<Cached>> {
        let old = match read_lock(self.shard(path)).get(path) {
            Some(Entry::File(c)) => Some(c.clone()),
            _ => None,
        };
        let mime = Files::mime(path);
        let twins: [Option<Arc<Cached>>; 3] = std::array::from_fn(|i| {
            let (enc, ext) = TWINS[i];
            let mut p = path.as_os_str().to_owned();
            p.push(".");
            p.push(ext);
            let p = PathBuf::from(p);
            let m = fs::metadata(&p).ok().filter(fs::Metadata::is_file)?;
            match old.as_ref().and_then(|o| o.twins[i].clone()) {
                Some(t) if t.matches(&m) => Some(t),
                _ => self.read(&p, &m, mime, Some(enc), [None, None, None]),
            }
        });
        let c = match old {
            Some(o) if o.matches(md) => {
                let same = o.twins.iter().zip(&twins).all(|(a, b)| match (a, b) {
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    (None, None) => true,
                    _ => false,
                });
                if same {
                    o.checked.store(clock_ms(), Ordering::Relaxed);
                    for t in o.twins.iter().flatten() {
                        t.checked.store(clock_ms(), Ordering::Relaxed);
                    }
                    return Some(o);
                }
                // Same file, other twins: keep its content.
                Arc::new(Cached::new(
                    o.body.clone(),
                    o.len,
                    o.mtime,
                    o.id,
                    mime,
                    None,
                    self.cache_control.as_deref(),
                    twins,
                ))
            }
            _ => self.read(path, md, mime, None, twins)?,
        };
        let big = c.len > self.max_cached;
        if big && self.max_open == 0 {
            return Some(c); // not cached: opened for this request only
        }
        let mut ring = lock(&self.ring);
        match (big, ring.position(path)) {
            (true, Some(i)) => ring.slots[i].1 = c.clone(),
            (true, None) if ring.slots.len() >= self.max_open => {
                // Every slot is taken: the new file replaces the CLOCK victim.
                let v = ring.victim();
                let (gone, _) = std::mem::replace(&mut ring.slots[v], (path.to_owned(), c.clone()));
                write_lock(self.shard(&gone)).remove(&gone);
                ring.hand = v + 1;
            }
            (true, None) => ring.slots.push((path.to_owned(), c.clone())),
            (false, Some(i)) => {
                ring.slots.swap_remove(i);
            }
            (false, None) => {}
        }
        write_lock(self.shard(path)).insert(path.to_owned(), Entry::File(c.clone()));
        Some(c)
    }

    /// Reads (small) or opens (large) the file at `path`, described by `md`.
    fn read(
        &self,
        path: &Path,
        md: &fs::Metadata,
        mime: &'static str,
        encoding: Option<&str>,
        twins: [Option<Arc<Cached>>; 3],
    ) -> Option<Arc<Cached>> {
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let id = (md.dev(), md.ino());
        let (body, len) = if md.len() > self.max_cached {
            let f = fs::File::open(path).ok()?;
            // The metadata of the handle itself: the path may have been replaced since `md`.
            let fmd = f.metadata().ok()?;
            if fmd.len() != md.len()
                || fmd.modified().ok() != Some(mtime)
                || (fmd.dev(), fmd.ino()) != id
            {
                return None;
            }
            (Body::File(Arc::new(f)), md.len())
        } else {
            let data = fs::read(path).ok()?;
            let n = data.len() as u64;
            (Body::Mem(data.into()), n)
        };
        Some(Arc::new(Cached::new(
            body,
            len,
            mtime,
            id,
            mime,
            encoding,
            self.cache_control.as_deref(),
            twins,
        )))
    }
}

/// The variant of `c` to send for `Accept-Encoding: accept`: a compressed twin the client
/// accepts, else `c` itself.
fn pick<'a>(c: &'a Arc<Cached>, accept: &str) -> &'a Arc<Cached> {
    for ((enc, _), twin) in TWINS.iter().zip(&c.twins) {
        if let Some(t) = twin {
            if accept
                .split(',')
                .any(|tok| tok.trim().split(';').next() == Some(*enc))
            {
                return t;
            }
        }
    }
    c
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parses an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, the format senders must use) to
/// seconds since the Unix epoch.
fn parse_http_date(s: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut it = s.trim().split(' ');
    it.next()?.strip_suffix(',')?;
    let d: i64 = it.next()?.parse().ok()?;
    let mon = it.next()?;
    let m = MONTHS.iter().position(|&m| m == mon)? as i64 + 1;
    let y: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':').map(|v| v.parse::<i64>().ok());
    let (h, mi, sec) = (hms.next()??, hms.next()??, hms.next()??);
    if it.next() != Some("GMT") || it.next().is_some() || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

/// More range specs than this in one header: the header is ignored (a DoS guard, RFC 9110
/// section 14.2 lets a server ignore or reject such requests).
const MAX_RANGES: usize = 32;
/// Ranges closer than this are sent as one part: a part header costs about as much.
const COALESCE_GAP: u64 = 80;
/// Largest multipart body built (in memory); beyond it the whole file is sent instead.
const MAX_MULTIPART_BYTES: u64 = 1 << 20;

/// What a `Range` header asks of a file.
#[derive(Debug, PartialEq, Eq)]
enum Ranges {
    /// No usable header: send the whole file.
    Ignore,
    /// Malformed, or no range overlaps the file: `416`.
    Unsatisfiable,
    /// Inclusive byte ranges, coalesced, in the order the response sends them.
    Some(Vec<(u64, u64)>),
}

/// Parses a `Range` header against a file of `len` bytes (RFC 9110 section 14.1.2). Ranges that
/// start past the end are dropped; overlapping and nearby ranges are coalesced (section 14.2),
/// and the parts keep the order of the first range of each in the header.
fn parse_ranges(h: &str, len: u64) -> Ranges {
    let h = h.trim();
    let Some(spec) = h
        .get(..6)
        .filter(|u| u.eq_ignore_ascii_case("bytes="))
        .map(|_| &h[6..])
    else {
        return Ranges::Ignore; // another unit
    };
    let specs = spec.split(',').map(str::trim).filter(|s| !s.is_empty());
    if specs.clone().nth(MAX_RANGES).is_some() {
        return Ranges::Ignore;
    }
    let digits = |s: &str| -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    // (start, end, position in the header)
    let mut rs: Vec<(u64, u64, usize)> = Vec::new();
    for (i, r) in specs.enumerate() {
        let Some((a, b)) = r.split_once('-') else {
            return Ranges::Unsatisfiable;
        };
        let (a, b) = (a.trim(), b.trim());
        let (start, end) = if a.is_empty() {
            // Suffix: the last `n` bytes.
            let Some(n) = digits(b) else {
                return Ranges::Unsatisfiable;
            };
            if n == 0 || len == 0 {
                continue;
            }
            (len.saturating_sub(n), len - 1)
        } else {
            let Some(start) = digits(a) else {
                return Ranges::Unsatisfiable;
            };
            let end = if b.is_empty() {
                u64::MAX
            } else {
                match digits(b) {
                    Some(e) if e >= start => e,
                    _ => return Ranges::Unsatisfiable,
                }
            };
            if start >= len {
                continue; // unsatisfiable on its own: dropped
            }
            (start, end.min(len - 1))
        };
        rs.push((start, end, i));
    }
    if rs.is_empty() {
        return Ranges::Unsatisfiable;
    }
    // Coalesce: by start, merging what overlaps or nearly touches; each merged part takes the
    // header position of its earliest member.
    rs.sort_unstable();
    let mut out: Vec<(u64, u64, usize)> = Vec::with_capacity(rs.len());
    for (s, e, i) in rs {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(COALESCE_GAP) => {
                last.1 = last.1.max(e);
                last.2 = last.2.min(i);
            }
            _ => out.push((s, e, i)),
        }
    }
    out.sort_unstable_by_key(|r| r.2);
    Ranges::Some(out.into_iter().map(|(s, e, _)| (s, e)).collect())
}

/// A multipart boundary: 128 random bits (std's per-process random hash keys, advanced per call).
fn boundary() -> String {
    let mut out = String::with_capacity(36);
    out.push_str("only");
    for i in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// The `multipart/byteranges` body (RFC 9110 section 14.6) for `ranges` of a file of `len`
/// bytes, reading each part with `read(offset, buf)`. Returns the boundary and the body.
fn multipart(
    ranges: &[(u64, u64)],
    len: u64,
    mime: &str,
    mut read: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> std::io::Result<(String, Vec<u8>)> {
    let mut parts = Vec::with_capacity(ranges.len());
    for &(a, b) in ranges {
        let mut buf = vec![0; (b - a + 1) as usize];
        read(a, &mut buf)?;
        parts.push(buf);
    }
    // A boundary must not occur in the content; with 128 random bits it practically never does,
    // but the parts are at hand, so make sure.
    let mut bnd = boundary();
    while parts
        .iter()
        .any(|p| p.windows(bnd.len()).any(|w| w == bnd.as_bytes()))
    {
        bnd = boundary();
    }
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut body = Vec::with_capacity(total + ranges.len() * (bnd.len() + mime.len() + 80));
    for (&(a, b), data) in ranges.iter().zip(&parts) {
        if !body.is_empty() {
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(
            format!(
                "--{bnd}\r\nContent-Type: {mime}\r\nContent-Range: bytes {a}-{b}/{len}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
    }
    body.extend_from_slice(format!("\r\n--{bnd}--\r\n").as_bytes());
    Ok((bnd, body))
}

impl Service for Files {
    fn call(&self, ctx: &mut Context) {
        let head = *ctx.method() == Method::Head;
        if *ctx.method() != Method::Get && !head {
            return ctx
                .respond(Response::text(405, "Method Not Allowed").header("Allow", "GET, HEAD"));
        }
        let Some(rel) = Files::relative(ctx) else {
            return ctx.text(404, "Not Found");
        };
        let path = self.inner.root.join(&rel);
        // Fast path: an entry still inside its trust window needs no syscall at all.
        if let Some(c) = self.inner.fresh(&path) {
            let served = pick(&c, ctx.header("accept-encoding").unwrap_or(""));
            if let Some(r) = self.inner.build(ctx.req(), served, false) {
                return ctx.respond(r);
            }
        }
        // Anything else touches the disk: on the disk pool, never on the I/O thread.
        let Some(d) = ctx.detach() else { return };
        let inner = self.inner.clone();
        let cell = Arc::new(Mutex::new(Some(d)));
        let job_cell = cell.clone();
        let job = Box::new(move || {
            let d = lock(&job_cell).take();
            let Some(d) = d else { return };
            let r = inner.serve_disk(d.req(), path);
            d.respond(r);
        });
        if disk_pool().try_execute(job).is_err() {
            let d = lock(&cell).take();
            if let Some(d) = d {
                d.respond(Response::text(503, "Service Unavailable").header("Retry-After", "1"));
            }
        }
    }

    fn streams_bodies(&self) -> bool {
        false
    }
}

impl Inner {
    /// The response to `req` from entry `c` (the file, or a compressed twin of it). `None` when it needs the disk and `disk` is false (the parts of a
    /// multi-range response from an open file).
    fn build(&self, req: &Request, c: &Arc<Cached>, disk: bool) -> Option<Response> {
        let head = req.method == Method::Head;
        let etag = &*c.etag;
        let header = |n: &str| req.headers.get(n);
        // Conditional requests.
        // RFC 9110 section 13.2.2 order: If-Match / If-Unmodified-Since, then If-None-Match /
        // If-Modified-Since, then If-Range.
        let precondition_failed = match header("if-match") {
            Some(v) => !v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t == etag // strong comparison
            }),
            None => header("if-unmodified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| c.mtime_secs > d),
        };
        if precondition_failed {
            let mut r = Response::new(412);
            r.headers.append("ETag", etag);
            return Some(r);
        }
        let not_modified = match header("if-none-match") {
            Some(v) => v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.trim_start_matches("W/") == etag
            }),
            None => header("if-modified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| c.mtime_secs <= d),
        };
        if not_modified {
            let mut r = Response::new(304);
            r.headers = c.meta.clone();
            return Some(r);
        }
        // `If-Range`: the range applies only while the client's copy is current (a strong entity
        // tag, or exactly the modification date); otherwise the whole file is sent.
        let range_ok = header("if-range").is_none_or(|v| {
            let v = v.trim();
            if v.starts_with('"') || v.starts_with("W/") {
                v == etag
            } else {
                parse_http_date(v) == Some(c.mtime_secs)
            }
        });
        let len = c.len;
        // Ranges (GET only).
        let ranges = match header("range") {
            Some(h) if !head && range_ok => parse_ranges(h, len),
            _ => Ranges::Ignore,
        };
        let ranges = match ranges {
            Ranges::Unsatisfiable => {
                let mut r = Response::new(416);
                r.headers.append("Content-Range", format!("bytes */{len}"));
                return Some(r);
            }
            Ranges::Some(rs)
                if rs.len() > 1
                    && rs.iter().map(|(a, b)| b - a + 1).sum::<u64>() > MAX_MULTIPART_BYTES =>
            {
                Vec::new() // too large to assemble: the whole file
            }
            Ranges::Some(rs) => rs,
            Ranges::Ignore => Vec::new(),
        };
        let mut resp = if ranges.len() > 1 {
            if matches!(c.body, Body::File(_)) && !disk {
                return None;
            }
            let read = |off: u64, buf: &mut [u8]| -> std::io::Result<()> {
                match &c.body {
                    Body::Mem(b) => {
                        buf.copy_from_slice(&b[off as usize..off as usize + buf.len()]);
                        Ok(())
                    }
                    Body::File(f) => f.read_exact_at(buf, off),
                }
            };
            let Ok((bnd, body)) = multipart(&ranges, len, c.mime, read) else {
                // The file shrank under us: the client retries.
                return Some(Response::text(500, "Internal Server Error"));
            };
            let mut r = Response::new(206);
            r.headers = Headers::with_capacity(8, 256);
            r.headers.append(
                "Content-Type",
                format!("multipart/byteranges; boundary={bnd}"),
            );
            for (n, v) in c.meta.iter() {
                r.headers.append(n, v);
            }
            r.body = body;
            r
        } else {
            let (status, offset, count) = match ranges.first() {
                Some(&(a, b)) => (206, a, b - a + 1),
                None => (200, 0, len),
            };
            let mut r = Response::new(status);
            r.headers = c.full.clone();
            if status == 206 {
                r.headers.append(
                    "Content-Range",
                    format!("bytes {offset}-{}/{len}", offset + count - 1),
                );
            }
            match &c.body {
                // HEAD sends no body: nothing to copy.
                Body::Mem(_) if head => {}
                Body::Mem(bytes) => {
                    r.body = bytes[offset as usize..(offset + count) as usize].to_vec();
                }
                Body::File(f) => {
                    r.file = Some(FileBody {
                        file: f.clone(),
                        offset,
                        len: count,
                    });
                }
            }
            r
        };
        // HEAD announces the length of the full representation.
        if head {
            let mut b = Vec::with_capacity(20);
            crate::message::push_uint(&mut b, len);
            resp.headers
                .append("Content-Length", std::str::from_utf8(&b).unwrap_or("0"));
        }
        Some(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates_round_trip() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        for secs in [0, 951_782_400, 1_700_000_000, 4_102_444_800] {
            assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
        }
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }

    fn some(v: &[(u64, u64)]) -> Ranges {
        Ranges::Some(v.to_vec())
    }

    #[test]
    fn single_range_parsing() {
        assert_eq!(parse_ranges("bytes=0-4", 10), some(&[(0, 4)]));
        assert_eq!(parse_ranges("bytes=5-", 10), some(&[(5, 9)]));
        assert_eq!(parse_ranges("bytes=-3", 10), some(&[(7, 9)]));
        assert_eq!(parse_ranges("bytes=-30", 10), some(&[(0, 9)]));
        assert_eq!(
            parse_ranges("bytes=2-99", 10),
            some(&[(2, 9)]),
            "end is clamped"
        );
        assert_eq!(
            parse_ranges("BYTES = 1-2", 10),
            Ranges::Ignore,
            "no space in the unit"
        );
        assert_eq!(
            parse_ranges("Bytes=1-2", 10),
            some(&[(1, 2)]),
            "unit is case-insensitive"
        );
        assert_eq!(parse_ranges("bytes=10-12", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=5-2", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=-0", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=0-0", 0), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=-5", 0), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("items=0-1", 10), Ranges::Ignore);
        assert_eq!(parse_ranges("bytes=", 10), Ranges::Unsatisfiable);
        for bad in [
            "bytes=a-1",
            "bytes=1-b",
            "bytes=+1-2",
            "bytes=1",
            "bytes=--1",
            "bytes=1-2-3",
        ] {
            assert_eq!(parse_ranges(bad, 10), Ranges::Unsatisfiable, "{bad}");
        }
        assert_eq!(
            parse_ranges("bytes=0-99999999999999999999", 10),
            Ranges::Unsatisfiable,
            "overflow"
        );
    }

    #[test]
    fn multi_range_parsing_and_coalescing() {
        let len = 1000;
        assert_eq!(
            parse_ranges("bytes=0-9,200-209", len),
            some(&[(0, 9), (200, 209)])
        );
        // Request order is kept for parts that are not merged.
        assert_eq!(
            parse_ranges("bytes=500-509, 0-9 ,-10", len),
            some(&[(500, 509), (0, 9), (990, 999)])
        );
        // Overlapping, adjacent and nearby (< 80 bytes apart) ranges merge; the merged part sits
        // where its first member was asked for.
        assert_eq!(
            parse_ranges("bytes=500-599,0-9,550-650,5-20", len),
            some(&[(500, 650), (0, 20)])
        );
        assert_eq!(parse_ranges("bytes=0-9,10-19", len), some(&[(0, 19)]));
        assert_eq!(parse_ranges("bytes=0-9,89-99", len), some(&[(0, 99)]));
        assert_eq!(
            parse_ranges("bytes=0-9,91-99", len),
            some(&[(0, 9), (91, 99)])
        );
        assert_eq!(parse_ranges("bytes=0-,5-10", len), some(&[(0, 999)]));
        // The same range many times is one part.
        let many = vec!["0-0"; 20].join(",");
        assert_eq!(parse_ranges(&format!("bytes={many}"), len), some(&[(0, 0)]));
        // Unsatisfiable members are dropped; if none is left, 416.
        assert_eq!(parse_ranges("bytes=2000-3000,0-1", len), some(&[(0, 1)]));
        assert_eq!(
            parse_ranges("bytes=2000-3000,1000-", len),
            Ranges::Unsatisfiable
        );
        // One malformed member spoils the header.
        assert_eq!(parse_ranges("bytes=0-1,x-2", len), Ranges::Unsatisfiable);
        // Empty list elements are allowed.
        assert_eq!(parse_ranges("bytes=0-1,,", len), some(&[(0, 1)]));
        // Too many ranges: the header is ignored (DoS guard).
        let r: Vec<String> = (0..=MAX_RANGES)
            .map(|i| format!("{}-{}", i * 100, i * 100))
            .collect();
        assert_eq!(
            parse_ranges(&format!("bytes={}", r.join(",")), 100_000),
            Ranges::Ignore
        );
        let r = &r[..MAX_RANGES];
        let Ranges::Some(got) = parse_ranges(&format!("bytes={}", r.join(",")), 100_000) else {
            panic!("32 ranges are served");
        };
        assert_eq!(got.len(), MAX_RANGES);
    }

    #[test]
    fn multipart_bodies() {
        let file: Vec<u8> = (0..100u8).collect();
        let (bnd, body) = multipart(&[(0, 2), (10, 11)], 100, "text/plain", |off, buf| {
            buf.copy_from_slice(&file[off as usize..off as usize + buf.len()]);
            Ok(())
        })
        .unwrap();
        assert!(bnd.len() >= 32 && bnd.bytes().all(|b| b.is_ascii_alphanumeric()));
        let mut want = Vec::new();
        want.extend_from_slice(
            format!("--{bnd}\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-2/100\r\n\r\n")
                .as_bytes(),
        );
        want.extend_from_slice(&[0, 1, 2]);
        want.extend_from_slice(
            format!(
                "\r\n--{bnd}\r\nContent-Type: text/plain\r\nContent-Range: bytes 10-11/100\r\n\r\n"
            )
            .as_bytes(),
        );
        want.extend_from_slice(&[10, 11]);
        want.extend_from_slice(format!("\r\n--{bnd}--\r\n").as_bytes());
        assert_eq!(body, want);
        assert_ne!(boundary(), boundary());
        // A read error (the file shrank) is reported.
        assert!(
            multipart(&[(0, 1), (5, 6)], 10, "x/y", |_, _| Err(
                std::io::ErrorKind::UnexpectedEof.into()
            ))
            .is_err()
        );
    }

    /// A scratch directory under the system temp dir.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("only-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The cache invariants: the ring lists exactly the open-file entries, at most `max`.
    fn check_ring(f: &Files, max: usize) {
        let ring = lock(&f.inner.ring);
        assert!(
            ring.slots.len() <= max,
            "{} open files > {max}",
            ring.slots.len()
        );
        let mut files = 0;
        for s in &f.inner.shards {
            for (p, e) in read_lock(s).iter() {
                if let Entry::File(c) = e {
                    if matches!(c.body, Body::File(_)) {
                        files += 1;
                        let i = ring.position(p).expect("an open file outside the ring");
                        assert!(Arc::ptr_eq(&ring.slots[i].1, c), "a stale ring entry");
                    }
                }
            }
        }
        assert_eq!(files, ring.slots.len());
        let mut sorted: Vec<&PathBuf> = ring.slots.iter().map(|(p, _)| p).collect();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ring.slots.len(), "a path twice in the ring");
    }

    fn open_cached(f: &Files, p: &Path) -> Arc<Cached> {
        f.inner.load(p, &fs::metadata(p).unwrap()).unwrap()
    }

    fn cached_entry(f: &Files, p: &Path) -> Option<Arc<Cached>> {
        match read_lock(f.inner.shard(p)).get(p) {
            Some(Entry::File(c)) => Some(c.clone()),
            _ => None,
        }
    }

    #[test]
    fn open_file_cache_evicts_under_churn_and_keeps_hot_files() {
        let dir = scratch("churn");
        let paths: Vec<PathBuf> = (0..40)
            .map(|i| {
                let p = dir.join(format!("f{i}.bin"));
                fs::write(&p, vec![i as u8; 100 + i]).unwrap();
                p
            })
            .collect();
        let f = Files::new(&dir).max_cached_bytes(10).max_open_files(4);
        let hot = &paths[0];
        open_cached(&f, hot);
        // A pseudo-random walk over the cold files, with the hot one used in between.
        let mut x = 7u64;
        for _ in 0..500 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let p = &paths[1 + (x >> 33) as usize % (paths.len() - 1)];
            let c = open_cached(&f, p);
            assert_eq!(c.len, fs::metadata(p).unwrap().len());
            check_ring(&f, 4);
            let c = f.inner.fresh(hot).unwrap_or_else(|| open_cached(&f, hot));
            assert_eq!(c.len, 100);
        }
        assert!(cached_entry(&f, hot).is_some(), "the hot file was evicted");
        // A file that turns small leaves the ring; one that is deleted leaves the cache.
        fs::write(&paths[0], b"tiny").unwrap();
        open_cached(&f, hot);
        check_ring(&f, 4);
        assert!(matches!(cached_entry(&f, hot).unwrap().body, Body::Mem(_)));
        assert_eq!(lock(&f.inner.ring).slots.len(), 3);
        let victim = lock(&f.inner.ring).slots[0].0.clone();
        f.inner.forget(&victim);
        check_ring(&f, 4);
        assert_eq!(lock(&f.inner.ring).slots.len(), 2);
        assert!(cached_entry(&f, &victim).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_file_cache_notices_a_file_renamed_over_the_cached_one() {
        let dir = scratch("rename");
        let p = dir.join("a.bin");
        fs::write(&p, vec![1u8; 1000]).unwrap();
        let f = Files::new(&dir).max_cached_bytes(10);
        let before = open_cached(&f, &p);
        // Same size and modification time, another inode.
        let tmp = dir.join("a.bin.tmp");
        fs::write(&tmp, vec![2u8; 1000]).unwrap();
        let t = fs::metadata(&p).unwrap().modified().unwrap();
        fs::File::options()
            .write(true)
            .open(&tmp)
            .unwrap()
            .set_modified(t)
            .unwrap();
        fs::rename(&tmp, &p).unwrap();
        let after = open_cached(&f, &p);
        assert_ne!(before.id, after.id);
        let Body::File(h) = &after.body else {
            panic!("an open file")
        };
        let mut b = [0u8; 1];
        h.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(b[0], 2, "served from the old inode");
        check_ring(&f, 64);
        assert_eq!(lock(&f.inner.ring).slots.len(), 1, "replaced in place");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn twins_are_cached_with_the_file_including_their_absence() {
        let dir = scratch("twins");
        let p = dir.join("app.js");
        fs::write(&p, b"console.log(1)").unwrap();
        fs::write(dir.join("app.js.gz"), b"gz-bytes").unwrap();
        let f = Files::new(&dir);
        let c = open_cached(&f, &p);
        assert!(c.twins[0].is_none(), "no .br");
        assert!(c.twins[1].is_none(), "no .zst");
        let gz = c.twins[2].as_ref().expect("the .gz twin");
        assert_eq!(gz.mime, "text/javascript; charset=utf-8");
        assert_eq!(gz.meta.get("content-encoding"), Some("gzip"));
        assert!(gz.etag.ends_with("-gzip\""));
        let enc = |c: &Arc<Cached>, accept: &str| {
            pick(c, accept)
                .meta
                .get("content-encoding")
                .map(str::to_owned)
        };
        assert_eq!(enc(&c, "gzip, br").as_deref(), Some("gzip"));
        assert_eq!(enc(&c, "identity"), None);
        // Unchanged on disk: the same entries are kept.
        let again = open_cached(&f, &p);
        assert!(Arc::ptr_eq(&c, &again));
        // A new twin appears: the entry is renewed with it, the content is shared.
        fs::write(dir.join("app.js.br"), b"br-bytes").unwrap();
        let renewed = open_cached(&f, &p);
        assert!(!Arc::ptr_eq(&c, &renewed));
        assert_eq!(enc(&renewed, "gzip, br").as_deref(), Some("br"));
        fs::write(dir.join("app.js.zst"), b"zstd-bytes").unwrap();
        let renewed = open_cached(&f, &p);
        assert_eq!(enc(&renewed, "gzip, zstd").as_deref(), Some("zstd"));
        assert_eq!(enc(&renewed, "gzip, zstd, br").as_deref(), Some("br"));
        assert_eq!(enc(&renewed, "gzip").as_deref(), Some("gzip"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mime_types() {
        assert_eq!(
            Files::mime(Path::new("a/b.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(Files::mime(Path::new("x.wasm")), "application/wasm");
        assert_eq!(Files::mime(Path::new("noext")), "application/octet-stream");
    }
}
