//! Static files: path safety, MIME types, conditional requests, ranges, pre-compressed variants,
//! an in-memory cache for small files and `sendfile(2)` for large ones.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
/// * `GET`/`HEAD`, `ETag` + `Last-Modified` with `304`, single `Range` requests (`206`/`416`).
/// * `index.html` for directories; `..` and other escapes are refused. Symlinks are followed.
/// * `file.ext.br` / `file.ext.gz` next to `file.ext` are served to clients that accept them.
/// * Files up to [`max_cached_bytes`](Files::max_cached_bytes) are cached in memory and
///   re-checked against the disk at most every [`check_interval`](Files::check_interval);
///   larger ones are opened per request and sent with `sendfile`. A cache miss reads the file on
///   the I/O thread: keep cached files small.
pub struct Files {
    root: PathBuf,
    index: String,
    max_cached: u64,
    check_interval: Duration,
    cache_control: Option<String>,
    cache: Mutex<HashMap<PathBuf, Arc<Cached>>>,
}

struct Cached {
    data: Vec<u8>,
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
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The file served for a directory (default `index.html`).
    pub fn index(mut self, name: &str) -> Files {
        self.index = name.to_owned();
        self
    }

    /// Largest file kept in memory (default 256 KiB; 0 disables the cache).
    pub fn max_cached_bytes(mut self, n: u64) -> Files {
        self.max_cached = n;
        self
    }

    /// How long a cached file is trusted before the disk is consulted again (default 5 s).
    pub fn check_interval(mut self, d: Duration) -> Files {
        self.check_interval = d;
        self
    }

    /// A `Cache-Control` header for every file response.
    pub fn cache_control(mut self, v: &str) -> Files {
        self.cache_control = Some(v.to_owned());
        self
    }

    /// The path below the root asked for, or `None` if it is unsafe.
    fn relative(ctx: &Context) -> Option<PathBuf> {
        let raw = ctx
            .param("path")
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

    /// The cached copy of `path` (reading it if absent or stale), when the file is small enough.
    fn cached(&self, path: &Path, md: &fs::Metadata) -> Option<Arc<Cached>> {
        if md.len() > self.max_cached {
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
        let data = fs::read(path).ok()?;
        let (etag, last_modified) = Self::meta_validators(data.len() as u64, mtime);
        let c = Arc::new(Cached {
            len: data.len() as u64,
            data,
            mtime,
            checked: Mutex::new(Instant::now()),
            etag,
            last_modified,
        });
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(path.to_owned(), c.clone());
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
        let (len, etag, last_modified, data, file) =
            if let Some(c) = cached.filter(|_| encoding.is_none()) {
                (
                    c.len,
                    c.etag.clone(),
                    c.last_modified.clone(),
                    Some(c),
                    None,
                )
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
                    Some(c) => (
                        c.len,
                        c.etag.clone(),
                        c.last_modified.clone(),
                        Some(c),
                        None,
                    ),
                    None => match fs::File::open(&serve) {
                        Ok(f) => (md.len(), etag, lm, None, Some(Arc::new(f))),
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
        headers.set("Last-Modified", last_modified.clone());
        headers.set("Accept-Ranges", "bytes");
        if let Some(cc) = &self.cache_control {
            headers.set("Cache-Control", cc.clone());
        }
        if let Some(e) = encoding {
            headers.set("Content-Encoding", e);
        }
        headers.set("Vary", "Accept-Encoding");
        // Conditional requests.
        let inm = ctx.header("if-none-match");
        let not_modified = match inm {
            Some(v) => v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.trim_start_matches("W/") == etag
            }),
            None => ctx.header("if-modified-since") == Some(last_modified.as_str()),
        };
        if not_modified {
            let mut r = Response::new(304);
            r.headers = headers;
            return ctx.respond(r);
        }
        // Ranges (GET only).
        let mut status = 200;
        let (mut offset, mut count) = (0, len);
        if !head {
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
                let body = c.data[offset as usize..(offset + count) as usize].to_vec();
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
