//! Ready-made [`Middleware`](crate::Middleware): recover, request id, CORS, access log.

use std::{
    collections::HashMap,
    io::Write,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    context::{Context, Middleware, Service},
    message::{Method, Request, Response},
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
                format!("{:016x}-{n:x}", t)
            }
        };
        ctx.add_response_header("X-Request-Id", id.clone());
        ctx.set_local("request_id", id);
        next.call(ctx);
    }
}

/// CORS policy for [`cors`].
#[derive(Clone, Debug)]
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
    move |ctx: &mut Context, next: &dyn Service| {
        if ctx.header("origin").is_none() {
            return next.call(ctx);
        }
        let preflight = *ctx.method() == Method::Options
            && ctx.header("access-control-request-method").is_some();
        if preflight {
            let resp = Response::new(204)
                .header("Access-Control-Allow-Origin", policy.allow_origin.clone())
                .header("Access-Control-Allow-Methods", policy.allow_methods.clone())
                .header("Access-Control-Allow-Headers", policy.allow_headers.clone())
                .header(
                    "Access-Control-Max-Age",
                    policy.max_age.as_secs().to_string(),
                )
                .header("Vary", "Origin");
            return ctx.respond(resp);
        }
        ctx.add_response_header("Access-Control-Allow-Origin", policy.allow_origin.clone());
        ctx.add_response_header("Vary", "Origin");
        next.call(ctx);
    }
}

/// One finished request, for [`logger`].
#[derive(Debug, Clone)]
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
        ctx.set_response_time_header("X-Response-Time");
        next.call(ctx);
    }
}

/// Settings for [`compress`].
#[derive(Clone, Debug)]
pub struct Compress {
    /// Bodies shorter than this are left alone.
    pub min_bytes: usize,
    /// zlib level 0..=9.
    pub level: u32,
}

impl Default for Compress {
    fn default() -> Self {
        Compress {
            min_bytes: 1024,
            level: 6,
        }
    }
}

fn compressible(content_type: &str) -> bool {
    let t = content_type.split(';').next().unwrap_or("").trim();
    t.starts_with("text/")
        || t.ends_with("json")
        || t.ends_with("javascript")
        || t.ends_with("xml")
        || t == "image/svg+xml"
        || t == "application/wasm"
}

/// Which of `gzip` / `deflate` the client accepts (honouring `q=0`), gzip preferred.
fn accepted_encoding(accept: &str) -> Option<&'static str> {
    let ok = |name: &str| {
        accept.split(',').any(|t| {
            let mut p = t.trim().split(';');
            p.next() == Some(name)
                && !p.any(|q| matches!(q.trim().strip_prefix("q="), Some(v) if v.parse::<f32>() == Ok(0.0)))
        })
    };
    ["gzip", "deflate"].into_iter().find(|n| ok(n))
}

/// Compresses text-like response bodies with gzip or deflate when the client accepts it.
pub fn compress(cfg: Compress) -> impl Middleware {
    move |ctx: &mut Context, next: &dyn Service| {
        if let Some(enc) = ctx.header("accept-encoding").and_then(accepted_encoding) {
            let cfg = cfg.clone();
            ctx.add_response_filter(move |resp: &mut Response, _req: &Request| {
                let ct = resp.headers.get("content-type").unwrap_or("").to_owned();
                if resp.status != 200
                    || resp.file.is_some()
                    || resp.body.len() < cfg.min_bytes
                    || resp.headers.get("content-encoding").is_some()
                    || !compressible(&ct)
                {
                    return;
                }
                let level = flate2::Compression::new(cfg.level.min(9));
                let out = if enc == "gzip" {
                    let mut e = flate2::write::GzEncoder::new(Vec::new(), level);
                    e.write_all(&resp.body).and_then(|()| e.finish())
                } else {
                    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), level);
                    e.write_all(&resp.body).and_then(|()| e.finish())
                };
                if let Ok(body) = out {
                    if body.len() < resp.body.len() {
                        resp.body = body;
                        resp.headers.set("Content-Encoding", enc);
                        resp.headers.remove("Content-Length");
                    }
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
            if resp.status != 200
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

/// `n` random bytes as lowercase hex, from the operating system.
fn random_hex(n: usize) -> String {
    use std::io::Read;
    let mut b = vec![0u8; n];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
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
    b.iter().map(|x| format!("{x:02x}")).collect()
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
                let t = random_hex(16);
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
    type Buckets = Mutex<(HashMap<IpAddr, (f64, Instant)>, u64)>;
    let b: Buckets = Mutex::new((HashMap::new(), 0));
    let burst = f64::from(burst.max(1));
    move |ctx: &mut Context, next: &dyn Service| {
        let ip = ctx.peer().ip();
        let now = Instant::now();
        let wait = {
            let mut g = b.lock().unwrap_or_else(|p| p.into_inner());
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
