//! Static files: path safety, MIME types, conditional requests, ranges, pre-compressed variants,
//! an in-memory cache for small files and `sendfile(2)` for large ones.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
///   `If-Match` / `If-Unmodified-Since` answer `412`; single `Range` requests (`206`/`416`),
///   honoured only while `If-Range` (an entity tag or a date) still matches.
/// * `index.html` for directories; `..` and other escapes are refused. Symlinks are followed.
/// * `file.ext.br` / `file.ext.gz` next to `file.ext` are served to clients that accept them.
/// * Files up to [`max_cached_bytes`](Files::max_cached_bytes) are cached in memory and
///   re-checked against the disk at most every [`check_interval`](Files::check_interval);
///   larger ones are sent with `sendfile` from a handle kept open (with its metadata) for up to
///   [`max_open_files`](Files::max_open_files) files, under the same re-check rule, so a hit
///   costs no `stat`/`open`. A cache miss reads the file on the I/O thread: keep cached files
///   small.
pub struct Files {
    root: PathBuf,
    index: String,
    max_cached: u64,
    check_interval: Duration,
    cache_control: Option<String>,
    max_open: usize,
    open_files: AtomicUsize,
    cache: Mutex<HashMap<PathBuf, Arc<Cached>>>,
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
            open_files: AtomicUsize::new(0),
            cache: Mutex::new(HashMap::new()),
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
    /// holds a file descriptor while the `Files` lives.
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
    /// small enough to keep in memory or an open-file slot is available.
    fn cached(&self, path: &Path, md: &fs::Metadata) -> Option<Arc<Cached>> {
        let big = md.len() > self.max_cached;
        if big && self.max_open == 0 {
            return None;
        }
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if let Some(c) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(path)
        {
            if c.len == md.len() && c.mtime == mtime {
                *c.checked.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
                return Some(c.clone());
            }
        }
        let (body, len) = if big {
            let f = fs::File::open(path).ok()?;
            // The metadata of the handle itself: the path may have been replaced since `md`.
            let fmd = f.metadata().ok()?;
            if fmd.len() != md.len() || fmd.modified().ok() != Some(mtime) {
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
            checked: Mutex::new(Instant::now()),
            etag,
            last_modified,
        });
        let mut g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let was_file = g.get(path).is_some_and(|o| matches!(o.body, Body::File(_)));
        if big && !was_file {
            if self.open_files.load(Ordering::Relaxed) >= self.max_open {
                // No slot: serve this response from the handle, without caching it.
                drop(g);
                return Some(c);
            }
            self.open_files.fetch_add(1, Ordering::Relaxed);
        } else if !big && was_file {
            self.open_files.fetch_sub(1, Ordering::Relaxed);
        }
        g.insert(path.to_owned(), c.clone());
        Some(c)
    }

    /// A cached entry still inside its trust window, without touching the disk.
    fn fresh(&self, path: &Path) -> Option<Arc<Cached>> {
        let g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let c = g.get(path)?;
        let ok = c
            .checked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .elapsed()
            < self.check_interval;
        ok.then(|| c.clone())
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

/// Parses a single `bytes=` range against a file of `len` bytes. `Err(())`: unsatisfiable.
/// `Ok(None)`: no usable range header (serve everything).
fn parse_range(h: &str, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = h.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None); // multiple ranges: answered with the whole file
    }
    let Some((a, b)) = spec.split_once('-') else {
        return Ok(None);
    };
    let (start, end) = match (a.trim(), b.trim()) {
        ("", n) => {
            let n: u64 = n.parse().map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            (len.saturating_sub(n), len.saturating_sub(1))
        }
        (s, "") => (s.parse().map_err(|_| ())?, len.saturating_sub(1)),
        (s, e) => (
            s.parse().map_err(|_| ())?,
            e.parse::<u64>().map_err(|_| ())?.min(len.saturating_sub(1)),
        ),
    };
    if len == 0 || start > end || start >= len {
        return Err(());
    }
    Ok(Some((start, end)))
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
                    Err(_) => return ctx.text(404, "Not Found"),
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
        let mut status = 200;
        let (mut offset, mut count) = (0, len);
        if !head && range_ok {
            if let Some(h) = ctx.header("range") {
                match parse_range(h, len) {
                    Ok(Some((a, b))) => {
                        status = 206;
                        offset = a;
                        count = b - a + 1;
                        headers.set("Content-Range", format!("bytes {a}-{b}/{len}"));
                    }
                    Ok(None) => {}
                    Err(()) => {
                        let mut r = Response::new(416);
                        r.headers.set("Content-Range", format!("bytes */{len}"));
                        return ctx.respond(r);
                    }
                }
            }
        }
        let mut resp = match (data, file) {
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

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("bytes=0-4", 10), Ok(Some((0, 4))));
        assert_eq!(parse_range("bytes=5-", 10), Ok(Some((5, 9))));
        assert_eq!(parse_range("bytes=-3", 10), Ok(Some((7, 9))));
        assert_eq!(
            parse_range("bytes=2-99", 10),
            Ok(Some((2, 9))),
            "end is clamped"
        );
        assert_eq!(parse_range("bytes=10-12", 10), Err(()));
        assert_eq!(parse_range("bytes=5-2", 10), Err(()));
        assert_eq!(parse_range("bytes=-0", 10), Err(()));
        assert_eq!(parse_range("bytes=0-1,4-5", 10), Ok(None));
        assert_eq!(parse_range("items=0-1", 10), Ok(None));
        assert_eq!(parse_range("bytes=0-0", 0), Err(()));
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
