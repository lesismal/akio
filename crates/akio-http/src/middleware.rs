//! Ready-made [`Middleware`]: recover, request id, CORS, logger, response time, compress, ETag,
//! CSRF and a per-IP rate limiter. Metrics and the structured access log are in [`crate::observe`].

use std::{
    collections::HashMap,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    coding::StreamCoding,
    context::{Context, Middleware, Service},
    message::{Headers, Method, Request, Response},
};

/// Turns a panic in the wrapped service into a `500` instead of closing the connection.
pub fn recover() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        if catch_unwind(AssertUnwindSafe(|| next.call(ctx))).is_err() && !ctx.responded() {
            ctx.text(500, "Internal Server Error");
        }
    }
}

/// Gives every request an id: the incoming `X-Request-Id` if there is one, else a new one. It is
/// stored as `ctx.local("request_id")` and echoed in the response.
pub fn request_id() -> impl Middleware {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    |ctx: &mut Context, next: &dyn Service| {
        let id = match ctx.header("x-request-id") {
            Some(v) if !v.is_empty() && v.len() <= 128 => v.to_owned(),
            _ => {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
                // `{t:016x}-{n:x}`, written straight into the one string it ends up in.
                let mut id = String::with_capacity(33);
                push_hex(&mut id, t, 16);
                id.push('-');
                push_hex(&mut id, n, 1);
                id
            }
        };
        ctx.add_response_header("X-Request-Id", &id);
        ctx.set_local("request_id", id);
        next.call(ctx);
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `n` in lowercase hex, at least `width` digits.
fn push_hex(out: &mut String, n: u64, width: usize) {
    let digits = (16 - n.leading_zeros() as usize / 4).max(width).min(16);
    for i in (0..digits).rev() {
        out.push(char::from(HEX[(n >> (i * 4)) as usize & 15]));
    }
}

/// CORS policy for [`cors`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Cors {
    /// `Access-Control-Allow-Origin` value (`*` or one origin).
    pub allow_origin: String,
    /// Methods allowed in preflight answers.
    pub allow_methods: String,
    /// Headers allowed in preflight answers.
    pub allow_headers: String,
    /// Preflight cache time.
    pub max_age: Duration,
}

impl Default for Cors {
    fn default() -> Self {
        Cors {
            allow_origin: "*".into(),
            allow_methods: "GET, POST, PUT, PATCH, DELETE, OPTIONS".into(),
            allow_headers: "Content-Type, Authorization".into(),
            max_age: Duration::from_secs(600),
        }
    }
}

/// Answers CORS preflights (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) with 204
/// and adds the allow-origin header to every other response to a request that has an `Origin`.
pub fn cors(policy: Cors) -> impl Middleware {
    // The preflight answer's fields never change: built once.
    let mut preflight_headers = Headers::new();
    preflight_headers.append("Access-Control-Allow-Origin", &policy.allow_origin);
    preflight_headers.append("Access-Control-Allow-Methods", &policy.allow_methods);
    preflight_headers.append("Access-Control-Allow-Headers", &policy.allow_headers);
    preflight_headers.append(
        "Access-Control-Max-Age",
        policy.max_age.as_secs().to_string(),
    );
    preflight_headers.append("Vary", "Origin");
    move |ctx: &mut Context, next: &dyn Service| {
        if ctx.header("origin").is_none() {
            return next.call(ctx);
        }
        let preflight = *ctx.method() == Method::Options
            && ctx.header("access-control-request-method").is_some();
        if preflight {
            let mut resp = Response::new(204);
            resp.headers = preflight_headers.clone();
            return ctx.respond(resp);
        }
        ctx.add_response_header("Access-Control-Allow-Origin", &policy.allow_origin);
        ctx.add_response_header("Vary", "Origin");
        next.call(ctx);
    }
}

/// One finished request, for [`logger`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogRecord {
    /// Request method.
    pub method: String,
    /// Request target.
    pub target: String,
    /// Peer address.
    pub peer: std::net::SocketAddr,
    /// Response status, or `None` if the response is sent later (detached).
    pub status: Option<u16>,
    /// Time spent in the wrapped service (not including time after a detach).
    pub elapsed: Duration,
}

/// Calls `log` after each request.
pub fn logger(log: impl Fn(&LogRecord) + Send + Sync + 'static) -> impl Middleware {
    move |ctx: &mut Context, next: &dyn Service| {
        let t0 = Instant::now();
        next.call(ctx);
        log(&LogRecord {
            method: ctx.method().as_str().to_owned(),
            target: ctx.req().target.clone(),
            peer: ctx.peer(),
            status: ctx.status(),
            elapsed: t0.elapsed(),
        });
    }
}

/// Adds `X-Response-Time: <ms>` to every response (time since the request was dispatched).
pub fn response_time() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        ctx.set_response_time_header_static("X-Response-Time");
        next.call(ctx);
    }
}

/// Settings for [`compress`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Compress {
    /// Bodies shorter than this are left alone.
    pub min_bytes: usize,
    /// zlib level 0..=9 (`gzip`, `deflate`).
    pub level: u32,
    /// brotli quality 0..=11 for clients accepting `br`, preferred over the others (`None`, the
    /// default: `br` is not used).
    pub brotli: Option<u32>,
    /// zstd level 1..=22 for clients accepting `zstd`, preferred over `gzip` and `deflate`
    /// (`None`, the default: `zstd` is not used).
    pub zstd: Option<u32>,
    /// Compress streamed responses ([`Context::stream_response`]) too, with these settings
    /// (`None`, the default: they are sent as written). The coding is negotiated as for
    /// buffered responses, among the same encodings; `min_bytes` does not apply (the length
    /// is not known).
    pub stream: Option<StreamCompress>,
}

impl Default for Compress {
    fn default() -> Self {
        Compress {
            min_bytes: 1024,
            level: 6,
            brotli: None,
            zstd: None,
            stream: None,
        }
    }
}

/// Settings for streamed responses in [`Compress::stream`].
///
/// A streamed response keeps its encoder (window and match tables) for as long as it is open,
/// and a server-sent-events stream may be open for hours, so the defaults are small: about
/// 0.3 MiB per stream for `gzip` and `deflate`, 0.5 MiB for `zstd` and 1.3 MiB for `br` once
/// a window of output has gone through (less before). Every write is flushed, so that the
/// client can decode it at once.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct StreamCompress {
    /// zlib level 0..=9 for `gzip` and `deflate` streams (default 1).
    pub level: u32,
    /// brotli quality 0..=11 for `br` streams, when [`Compress::brotli`] offers `br`
    /// (default 4).
    pub brotli: u32,
    /// brotli window, `2^brotli_window_bits` bytes, 10..=24 (default 18: 256 KiB).
    pub brotli_window_bits: u32,
    /// zstd level 1..=22 for `zstd` streams, when [`Compress::zstd`] offers `zstd` (default 1).
    pub zstd: u32,
    /// zstd window, `2^zstd_window_log` bytes, 10..=23 (default 17: 128 KiB).
    pub zstd_window_log: u32,
}

impl Default for StreamCompress {
    fn default() -> Self {
        StreamCompress {
            level: 1,
            brotli: 4,
            brotli_window_bits: 18,
            zstd: 1,
            zstd_window_log: 17,
        }
    }
}

/// Whether a body of `content_type` is worth compressing: text, JSON, JavaScript, XML, SVG,
/// WebAssembly, uncompressed fonts and icons; not images, video, archives and the like, which
/// are compressed already (ADR-112). Parameters (`; charset=...`) and case are ignored.
pub fn compressible(content_type: &str) -> bool {
    let t = content_type.split(';').next().unwrap_or("").trim();
    let lower;
    let t = if t.bytes().any(|b| b.is_ascii_uppercase()) {
        lower = t.to_ascii_lowercase();
        lower.as_str()
    } else {
        t
    };
    t.starts_with("text/")
        || t.ends_with("json")
        || t.ends_with("javascript")
        || t.ends_with("xml")
        || matches!(
            t,
            "image/svg+xml"
                | "application/wasm"
                | "application/ecmascript"
                | "application/vnd.ms-fontobject"
                | "application/x-font-ttf"
                | "font/ttf"
                | "font/otf"
                | "image/x-icon"
                | "image/vnd.microsoft.icon"
                | "image/bmp"
        )
}

/// The first of `encodings` the client accepts (honouring `q=0`).
fn accepted_encoding(accept: &str, encodings: &[&'static str]) -> Option<&'static str> {
    let ok = |name: &str| {
        accept.split(',').any(|t| {
            let mut p = t.trim().split(';');
            p.next() == Some(name)
                && !p.any(|q| matches!(q.trim().strip_prefix("q="), Some(v) if v.parse::<f32>() == Ok(0.0)))
        })
    };
    encodings.iter().copied().find(|n| ok(n))
}

/// Compresses text-like response bodies with `br` or `zstd` when configured, else `gzip` or
/// `deflate`, whichever the client accepts first in that order. Buffered bodies are
/// compressed whole; streamed ones only with [`Compress::stream`], write by write.
///
/// Only `200` responses with a compressible `Content-Type` and no `Content-Encoding` are
/// compressed; they lose `Content-Length` and get `Vary: Accept-Encoding`.
pub fn compress(cfg: Compress) -> impl Middleware {
    // Decided once: the levels, and the encodings on offer in order of preference.
    let level = akio_deflate::Level::new(cfg.level);
    let brotli = cfg.brotli.map(akio_brotli::Level::new);
    let zstd = cfg.zstd.map(akio_zstd::Level::new);
    let encodings: &'static [&'static str] = match (brotli.is_some(), zstd.is_some()) {
        (true, true) => &["br", "zstd", "gzip", "deflate"],
        (true, false) => &["br", "gzip", "deflate"],
        (false, true) => &["zstd", "gzip", "deflate"],
        (false, false) => &["gzip", "deflate"],
    };
    let min_bytes = cfg.min_bytes;
    // The coding of a streamed response, by encoding (levels and windows clamped once).
    let stream = cfg.stream.map(|s| {
        let level = akio_deflate::Level::new(s.level).get();
        move |enc: &str| match enc {
            "br" => StreamCoding::Br {
                quality: akio_brotli::Level::new(s.brotli).get(),
                window_bits: s.brotli_window_bits.clamp(10, 24) as u8,
            },
            "zstd" => StreamCoding::Zstd {
                level: akio_zstd::Level::new(s.zstd).get(),
                window_log: s.zstd_window_log.clamp(10, 23) as u8,
            },
            "gzip" => StreamCoding::Gzip(level),
            _ => StreamCoding::Deflate(level),
        }
    });
    move |ctx: &mut Context, next: &dyn Service| {
        if let Some(enc) = ctx
            .header("accept-encoding")
            .and_then(|a| accepted_encoding(a, encodings))
        {
            ctx.add_response_filter(move |resp: &mut Response, _req: &Request| {
                if resp.streaming {
                    // The head of a streamed response: the body is encoded write by write
                    // (`BodyStream`).
                    let Some(coding) = stream else { return };
                    if resp.status != 200
                        || resp.headers.get("content-encoding").is_some()
                        || !compressible(resp.headers.get("content-type").unwrap_or(""))
                    {
                        return;
                    }
                    resp.stream_coding = Some(coding(enc));
                    resp.headers.set("Content-Encoding", enc);
                    resp.headers.remove("Content-Length");
                    resp.headers.set("Vary", "Accept-Encoding");
                    return;
                }
                if resp.status != 200
                    || resp.file.is_some()
                    || resp.body.len() < min_bytes
                    || resp.headers.get("content-encoding").is_some()
                    || !compressible(resp.headers.get("content-type").unwrap_or(""))
                {
                    return;
                }
                let body = match (enc, brotli, zstd) {
                    ("br", Some(l), _) => akio_brotli::compress(l, &resp.body),
                    ("zstd", _, Some(l)) => akio_zstd::compress(l, &resp.body),
                    ("gzip", ..) => {
                        akio_deflate::compress(akio_deflate::Format::Gzip, level, &resp.body)
                    }
                    _ => akio_deflate::compress(akio_deflate::Format::Zlib, level, &resp.body),
                };
                if body.len() < resp.body.len() {
                    resp.body = body;
                    resp.headers.set("Content-Encoding", enc);
                    resp.headers.remove("Content-Length");
                }
                resp.headers.set("Vary", "Accept-Encoding");
            });
        }
        next.call(ctx);
    }
}

/// FNV-1a, 64 bit: cheap, and good enough to fingerprint a body for an ETag.
fn fnv64(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Adds a weak `ETag` to 200 responses and answers `If-None-Match` hits with `304`.
pub fn etag() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        ctx.add_response_filter(|resp: &mut Response, req: &Request| {
            // A streamed body is not known when its head goes out.
            if resp.status != 200
                || resp.streaming
                || resp.file.is_some()
                || resp.headers.get("etag").is_some()
                || !matches!(req.method, Method::Get | Method::Head)
            {
                return;
            }
            let tag = format!("W/\"{:x}-{:016x}\"", resp.body.len(), fnv64(&resp.body));
            let hit = req.headers.get("if-none-match").is_some_and(|v| {
                v.split(',').any(|t| {
                    let t = t.trim();
                    t == "*" || t.trim_start_matches("W/") == tag.trim_start_matches("W/")
                })
            });
            resp.headers.set("ETag", tag);
            if hit {
                resp.status = 304;
                resp.body.clear();
                resp.headers.remove("Content-Length");
                resp.headers.remove("Content-Type");
            }
        });
        next.call(ctx);
    }
}

/// 16 random bytes as lowercase hex, from the operating system (one `getrandom`/`getentropy`
/// call, no file to open).
fn random_hex() -> String {
    let mut b = [0u8; 16];
    let ok = akio_crypto::rand::fill_random(&mut b);
    if ok.is_err() {
        // No OS randomness: mix clock and a counter. Weaker, but never a constant.
        static C: AtomicU64 = AtomicU64::new(1);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let seed = t ^ C.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        for (i, x) in b.iter_mut().enumerate() {
            *x = (seed >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(31);
        }
    }
    let mut out = String::with_capacity(2 * b.len());
    for x in b {
        out.push(char::from(HEX[usize::from(x >> 4)]));
        out.push(char::from(HEX[usize::from(x & 15)]));
    }
    out
}

/// Constant-time equality for secrets of equal length.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Double-submit-cookie CSRF protection. Safe methods get a `csrf_token` cookie if they have none
/// (readable by scripts, `SameSite=Lax`); `POST`/`PUT`/`PATCH`/`DELETE` must repeat the cookie's
/// value in the `X-CSRF-Token` header or get `403`. The token is also `ctx.local("csrf_token")`.
pub fn csrf() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        let cookie = ctx
            .header("cookie")
            .and_then(|c| {
                c.split(';')
                    .filter_map(|kv| kv.trim().split_once('='))
                    .find(|(k, _)| *k == "csrf_token")
                    .map(|(_, v)| v.to_owned())
            })
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()));
        let unsafe_method = matches!(
            ctx.method(),
            Method::Post | Method::Put | Method::Patch | Method::Delete
        );
        if unsafe_method {
            let sent = ctx.header("x-csrf-token").map(str::to_owned);
            match (&cookie, sent) {
                (Some(c), Some(h)) if ct_eq(c, &h) => {}
                _ => return ctx.text(403, "CSRF token missing or wrong"),
            }
        }
        let token = match cookie {
            Some(t) => t,
            None => {
                let t = random_hex();
                ctx.add_response_header(
                    "Set-Cookie",
                    format!("csrf_token={t}; Path=/; SameSite=Lax"),
                );
                t
            }
        };
        ctx.set_local("csrf_token", token);
        next.call(ctx);
    }
}

/// Per-client-IP token bucket: `rate` requests per second with bursts of `burst`; over the limit
/// gets `429` with `Retry-After`.
pub fn limiter(rate: f64, burst: u32) -> impl Middleware {
    // Sharded by client address: threads serving different clients rarely share a lock.
    type Buckets = Mutex<(HashMap<IpAddr, (f64, Instant)>, u64)>;
    const SHARDS: usize = 16;
    let shards: Box<[Buckets]> = (0..SHARDS)
        .map(|_| Mutex::new((HashMap::new(), 0)))
        .collect();
    let burst = f64::from(burst.max(1));
    move |ctx: &mut Context, next: &dyn Service| {
        let ip = ctx.peer().ip();
        let shard = match ip {
            IpAddr::V4(a) => u64::from(a.to_bits()),
            IpAddr::V6(a) => {
                let b = a.to_bits();
                (b as u64) ^ ((b >> 64) as u64)
            }
        };
        let shard = (shard.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 60) as usize % SHARDS;
        let now = Instant::now();
        let wait = {
            let mut g = shards[shard].lock().unwrap_or_else(|p| p.into_inner());
            g.1 += 1;
            if g.1 % 1024 == 0 {
                // Forget clients that have been quiet long enough to be full again.
                let idle = Duration::from_secs_f64((burst / rate).max(1.0) + 60.0);
                g.0.retain(|_, (_, t)| now.duration_since(*t) < idle);
            }
            let e = g.0.entry(ip).or_insert((burst, now));
            e.0 = (e.0 + now.duration_since(e.1).as_secs_f64() * rate).min(burst);
            e.1 = now;
            if e.0 >= 1.0 {
                e.0 -= 1.0;
                None
            } else {
                Some(((1.0 - e.0) / rate).ceil().max(1.0) as u64)
            }
        };
        match wait {
            None => next.call(ctx),
            Some(secs) => ctx.respond(
                Response::text(429, "Too Many Requests").header("Retry-After", secs.to_string()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers_match_format() {
        for (n, w) in [
            (0u64, 1),
            (0, 16),
            (1, 1),
            (0xabc, 1),
            (0xabc, 16),
            (u64::MAX, 1),
        ] {
            let mut s = String::new();
            push_hex(&mut s, n, w);
            assert_eq!(s, format!("{n:0w$x}"), "{n} {w}");
        }
        let t = random_hex();
        assert_eq!(t.len(), 32);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(t, random_hex());
    }
}
