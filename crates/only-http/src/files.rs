//! Static files: path safety, MIME types, conditional requests, ranges, pre-compressed variants,
//! an in-memory cache for small files and `sendfile(2)` for large ones.

use std::{
    collections::HashMap,
    fs,
    hash::{BuildHasher, Hasher},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use crate::{
    context::{Context, Service},
    message::{FileBody, Headers, Method, Response, format_http_date, percent_decode},
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
/// * `file.ext.br` / `file.ext.gz` next to `file.ext` are served to clients that accept them.
/// * Files up to [`max_cached_bytes`](Files::max_cached_bytes) are cached in memory and
///   re-checked against the disk at most every [`check_interval`](Files::check_interval);
///   larger ones are sent with `sendfile` from a handle kept open (with its metadata) for up to
///   [`max_open_files`](Files::max_open_files) files, under the same re-check rule, so a hit
///   costs no `stat`/`open`. When the handles are all taken, a new file evicts the least
///   recently used one (CLOCK). An entry is dropped or replaced when its file is deleted, or
///   when its size, modification time or inode change (an atomic rename over it included). A
///   cache miss reads the file on the I/O thread: keep cached files small.
pub struct Files {
    root: PathBuf,
    index: String,
    max_cached: u64,
    check_interval: Duration,
    cache_control: Option<String>,
    max_open: usize,
    cache: Mutex<Cache>,
}

/// The cache: every entry by path, and the entries holding an open file in CLOCK order.
#[derive(Default)]
struct Cache {
    map: HashMap<PathBuf, Arc<Cached>>,
    /// Paths of the entries whose body is an open file (at most `max_open`).
    ring: Vec<PathBuf>,
    /// The CLOCK hand: the next slot of `ring` considered for eviction.
    hand: usize,
}

impl Cache {
    /// Removes `path`'s entry, freeing its open-file slot.
    fn remove(&mut self, path: &Path) {
        if let Some(old) = self.map.remove(path) {
            if matches!(old.body, Body::File(_)) {
                if let Some(i) = self.ring.iter().position(|p| p == path) {
                    self.ring.swap_remove(i);
                }
            }
        }
    }

    /// The slot of the entry to evict: the first one from the hand that was not used since the
    /// hand last passed it (each used entry gets its bit cleared and a second chance).
    fn victim(&mut self) -> usize {
        loop {
            if self.hand >= self.ring.len() {
                self.hand = 0;
            }
            let used = self
                .map
                .get(&self.ring[self.hand])
                .is_some_and(|c| c.used.swap(false, Ordering::Relaxed));
            if !used {
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
    Mem(Vec<u8>),
    File(Arc<fs::File>),
}

struct Cached {
    body: Body,
    len: u64,
    mtime: SystemTime,
    /// Device and inode: a file renamed over the cached one has another.
    id: (u64, u64),
    /// Used since the CLOCK hand last passed (open-file entries).
    used: AtomicBool,
    checked: Mutex<Instant>,
    etag: String,
    last_modified: String,
}

impl Files {
    /// Serves `root`.
    pub fn new(root: impl Into<PathBuf>) -> Files {
        Files {
            root: root.into(),
            index: "index.html".into(),
            max_cached: 256 << 10,
            check_interval: Duration::from_secs(5),
            cache_control: None,
            max_open: 64,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// The file served for a directory (default `index.html`).
    #[must_use]
    pub fn index(mut self, name: &str) -> Files {
        self.index = name.to_owned();
        self
    }

    /// Largest file kept in memory (default 256 KiB; 0 disables the cache).
    #[must_use]
    pub fn max_cached_bytes(mut self, n: u64) -> Files {
        self.max_cached = n;
        self
    }

    /// How many files larger than [`max_cached_bytes`](Files::max_cached_bytes) keep an open
    /// handle and their metadata cached (default 64; 0 opens such files per request). Each
    /// holds a file descriptor until it is evicted (least recently used first, CLOCK), its file
    /// changes or the `Files` is dropped; responses still being sent keep their own handle.
    #[must_use]
    pub fn max_open_files(mut self, n: usize) -> Files {
        self.max_open = n;
        self
    }

    /// How long a cached file is trusted before the disk is consulted again (default 5 s).
    #[must_use]
    pub fn check_interval(mut self, d: Duration) -> Files {
        self.check_interval = d;
        self
    }

    /// A `Cache-Control` header for every file response.
    #[must_use]
    pub fn cache_control(mut self, v: &str) -> Files {
        self.cache_control = Some(v.to_owned());
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

    fn meta_validators(len: u64, mtime: SystemTime) -> (String, String) {
        let secs = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        (format!("\"{len:x}-{secs:x}\""), format_http_date(secs))
    }

    /// The cached copy of `path` (reading or opening it if absent or stale), when the file is
    /// small enough to keep in memory or open handles are cached at all.
    fn cached(&self, path: &Path, md: &fs::Metadata) -> Option<Arc<Cached>> {
        let big = md.len() > self.max_cached;
        if big && self.max_open == 0 {
            return None;
        }
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let id = (md.dev(), md.ino());
        if let Some(c) = self.lock().map.get(path) {
            if c.len == md.len() && c.mtime == mtime && c.id == id {
                *c.checked.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
                c.used.store(true, Ordering::Relaxed);
                return Some(c.clone());
            }
        }
        let (body, len) = if big {
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
            (Body::Mem(data), n)
        };
        let (etag, last_modified) = Self::meta_validators(len, mtime);
        let c = Arc::new(Cached {
            len,
            body,
            mtime,
            id,
            used: AtomicBool::new(false),
            checked: Mutex::new(Instant::now()),
            etag,
            last_modified,
        });
        let mut g = self.lock();
        let was_file = g
            .map
            .get(path)
            .is_some_and(|o| matches!(o.body, Body::File(_)));
        if big && !was_file {
            if g.ring.len() >= self.max_open {
                // Every slot is taken: the new file replaces the CLOCK victim.
                let v = g.victim();
                let old = std::mem::replace(&mut g.ring[v], path.to_owned());
                g.map.remove(&old);
                g.hand = v + 1;
            } else {
                g.ring.push(path.to_owned());
            }
        } else if !big && was_file {
            g.remove(path);
        }
        g.map.insert(path.to_owned(), c.clone());
        Some(c)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drops the entry of a file that is gone.
    fn forget(&self, path: &Path) {
        self.lock().remove(path);
    }

    /// A cached entry still inside its trust window, without touching the disk.
    fn fresh(&self, path: &Path) -> Option<Arc<Cached>> {
        let g = self.lock();
        let c = g.map.get(path)?;
        let ok = c
            .checked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .elapsed()
            < self.check_interval;
        ok.then(|| {
            c.used.store(true, Ordering::Relaxed);
            c.clone()
        })
    }
}

/// What a response describes: from a cache entry or from fresh metadata.
struct Served {
    len: u64,
    etag: String,
    last_modified: String,
    mtime: SystemTime,
    /// An in-memory cache entry.
    data: Option<Arc<Cached>>,
    /// An open file to send from.
    file: Option<Arc<fs::File>>,
}

impl From<Arc<Cached>> for Served {
    fn from(c: Arc<Cached>) -> Served {
        let mut s = Served {
            len: c.len,
            etag: c.etag.clone(),
            last_modified: c.last_modified.clone(),
            mtime: c.mtime,
            data: None,
            file: None,
        };
        match &c.body {
            Body::File(f) => s.file = Some(f.clone()),
            Body::Mem(_) => s.data = Some(c),
        }
        s
    }
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
        let mut path = self.root.join(&rel);
        // Fast path: a file still inside its trust window needs no syscall at all.
        let cached = self.fresh(&path);
        let md = match &cached {
            Some(_) => None,
            None => {
                let Ok(mut md) = fs::metadata(&path) else {
                    self.forget(&path);
                    return ctx.text(404, "Not Found");
                };
                if md.is_dir() {
                    path.push(&self.index);
                    match fs::metadata(&path) {
                        Ok(m) if m.is_file() => md = m,
                        _ => return ctx.text(404, "Not Found"),
                    }
                }
                Some(md)
            }
        };
        let accept = ctx.header("accept-encoding").unwrap_or("").to_owned();
        let mut encoding = None;
        let mut serve = path.clone();
        for (enc, ext) in [("br", "br"), ("gzip", "gz")] {
            if accept
                .split(',')
                .any(|t| t.trim().split(';').next() == Some(enc))
            {
                let mut p = path.clone().into_os_string();
                p.push(format!(".{ext}"));
                if fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                    serve = PathBuf::from(p);
                    encoding = Some(enc);
                    break;
                }
            }
        }
        let mime = Files::mime(&path);
        // Everything below describes `serve` (possibly the compressed twin).
        let Served {
            len,
            etag,
            last_modified,
            mtime,
            data,
            file,
        } = if let Some(c) = cached.filter(|_| encoding.is_none()) {
            Served::from(c)
        } else {
            let md = match (md, encoding) {
                (Some(m), None) => m,
                _ => match fs::metadata(&serve) {
                    Ok(m) => m,
                    Err(_) => {
                        self.forget(&serve);
                        return ctx.text(404, "Not Found");
                    }
                },
            };
            let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let (etag, lm) = Files::meta_validators(md.len(), mtime);
            match self.cached(&serve, &md) {
                Some(c) => Served::from(c),
                None => match fs::File::open(&serve) {
                    Ok(f) => Served {
                        len: md.len(),
                        etag,
                        last_modified: lm,
                        mtime,
                        data: None,
                        file: Some(Arc::new(f)),
                    },
                    Err(_) => return ctx.text(404, "Not Found"),
                },
            }
        };
        let etag = match encoding {
            Some(e) => format!("{}-{e}\"", &etag[..etag.len() - 1]),
            None => etag,
        };
        let mut headers = Headers::new();
        headers.set("ETag", etag.clone());
        headers.set("Last-Modified", last_modified);
        headers.set("Accept-Ranges", "bytes");
        if let Some(cc) = &self.cache_control {
            headers.set("Cache-Control", cc.clone());
        }
        if let Some(e) = encoding {
            headers.set("Content-Encoding", e);
        }
        headers.set("Vary", "Accept-Encoding");
        // Conditional requests.
        // RFC 9110 section 13.2.2 order: If-Match / If-Unmodified-Since, then If-None-Match /
        // If-Modified-Since, then If-Range.
        let mtime_secs = unix_secs(mtime);
        let precondition_failed = match ctx.header("if-match") {
            Some(v) => !v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t == etag // strong comparison
            }),
            None => ctx
                .header("if-unmodified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| mtime_secs > d),
        };
        if precondition_failed {
            let mut r = Response::new(412);
            r.headers.set("ETag", etag);
            return ctx.respond(r);
        }
        let not_modified = match ctx.header("if-none-match") {
            Some(v) => v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.trim_start_matches("W/") == etag
            }),
            None => ctx
                .header("if-modified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| mtime_secs <= d),
        };
        if not_modified {
            let mut r = Response::new(304);
            r.headers = headers;
            return ctx.respond(r);
        }
        // `If-Range`: the range applies only while the client's copy is current (a strong entity
        // tag, or exactly the modification date); otherwise the whole file is sent.
        let range_ok = ctx.header("if-range").is_none_or(|v| {
            let v = v.trim();
            if v.starts_with('"') || v.starts_with("W/") {
                v == etag
            } else {
                parse_http_date(v) == Some(mtime_secs)
            }
        });
        // Ranges (GET only).
        let ranges = match ctx.header("range") {
            Some(h) if !head && range_ok => parse_ranges(h, len),
            _ => Ranges::Ignore,
        };
        let ranges = match ranges {
            Ranges::Unsatisfiable => {
                let mut r = Response::new(416);
                r.headers.set("Content-Range", format!("bytes */{len}"));
                return ctx.respond(r);
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
            let read = |off: u64, buf: &mut [u8]| -> std::io::Result<()> {
                match (&data, &file) {
                    (Some(c), _) => match &c.body {
                        Body::Mem(b) => {
                            buf.copy_from_slice(&b[off as usize..off as usize + buf.len()]);
                            Ok(())
                        }
                        Body::File(f) => f.read_exact_at(buf, off),
                    },
                    (None, Some(f)) => f.read_exact_at(buf, off),
                    _ => Err(std::io::ErrorKind::NotFound.into()),
                }
            };
            match multipart(&ranges, len, mime, read) {
                Ok((bnd, body)) => {
                    Response::with_body(206, &format!("multipart/byteranges; boundary={bnd}"), body)
                }
                // The file shrank under us: the client retries.
                Err(_) => return ctx.text(500, "Internal Server Error"),
            }
        } else {
            let (status, offset, count) = match ranges.first() {
                Some(&(a, b)) => {
                    headers.set("Content-Range", format!("bytes {a}-{b}/{len}"));
                    (206, a, b - a + 1)
                }
                None => (200, 0, len),
            };
            match (data, file) {
                (Some(c), _) => {
                    let Body::Mem(bytes) = &c.body else {
                        return ctx.text(500, "Internal Server Error");
                    };
                    let body = bytes[offset as usize..(offset + count) as usize].to_vec();
                    Response::with_body(status, mime, body)
                }
                (None, Some(f)) => Response::from_file(
                    status,
                    mime,
                    FileBody {
                        file: f,
                        offset,
                        len: count,
                    },
                ),
                _ => return ctx.text(404, "Not Found"),
            }
        };
        for (n, v) in headers.iter() {
            resp.headers.set(n, v);
        }
        // HEAD announces the length of the full representation.
        if head {
            resp.headers.set("Content-Length", len.to_string());
        }
        ctx.respond(resp);
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
        let g = f.lock();
        assert!(g.ring.len() <= max, "{} open files > {max}", g.ring.len());
        let files = g
            .map
            .values()
            .filter(|c| matches!(c.body, Body::File(_)))
            .count();
        assert_eq!(files, g.ring.len());
        for p in &g.ring {
            assert!(matches!(g.map.get(p).map(|c| &c.body), Some(Body::File(_))));
        }
        let mut sorted = g.ring.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), g.ring.len(), "a path twice in the ring");
    }

    fn open_cached(f: &Files, p: &Path) -> Arc<Cached> {
        f.cached(p, &fs::metadata(p).unwrap()).unwrap()
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
            let c = f.fresh(hot).unwrap_or_else(|| open_cached(&f, hot));
            assert_eq!(c.len, 100);
        }
        assert!(f.lock().map.contains_key(hot), "the hot file was evicted");
        // A file that turns small leaves the ring; one that is deleted leaves the cache.
        fs::write(&paths[0], b"tiny").unwrap();
        open_cached(&f, hot);
        check_ring(&f, 4);
        assert!(matches!(f.lock().map[hot].body, Body::Mem(_)));
        assert_eq!(f.lock().ring.len(), 3);
        let victim = f.lock().ring[0].clone();
        f.forget(&victim);
        check_ring(&f, 4);
        assert_eq!(f.lock().ring.len(), 2);
        assert!(!f.lock().map.contains_key(&victim));
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
        assert_eq!(f.lock().ring.len(), 1, "replaced in place");
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
