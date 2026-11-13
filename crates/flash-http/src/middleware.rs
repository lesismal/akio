//! Ready-made [`Middleware`](crate::Middleware): recover, request id, CORS, access log.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crate::{
    context::{Context, Middleware, Service},
    message::{Method, Response},
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
