//! Observability for HTTP servers: request metrics, a Prometheus endpoint, a structured access
//! log and an opt-in runtime debug endpoint.
//!
//! ```no_run
//! use flash::{Config, Engine, Listener};
//! use flash_http::{Router, observe, serve};
//!
//! let cfg = Config::default();
//! let tel = cfg.telemetry.clone();
//! let http = observe::HttpMetrics::new();
//! let app = Router::new()
//!     .get("/", |ctx: &mut flash_http::Context| ctx.text(200, "hi"))
//!     .get("/metrics", observe::metrics_handler(tel.clone(), Some(http.clone())))
//!     .get("/debug/flash/*view", observe::debug_handler(tel, Some("secret".into())))
//!     .layer(http.middleware())
//!     .layer(observe::access_log());
//! let engine = Engine::builder()
//!     .config(cfg)
//!     .listen(Listener::tcp("127.0.0.1:8080".parse().unwrap()).serve(serve(app)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```

use std::{
    cell::Cell,
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use flash_core::{
    Telemetry,
    telemetry::{connections_json, json_str, prometheus_header, slow_callbacks_json},
};

use crate::{
    context::{Context, Middleware, Service},
    message::Response,
};

/// Upper bounds (seconds) of the request-latency histogram buckets.
pub const LATENCY_BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const NB: usize = LATENCY_BUCKETS.len() + 1; // + the +Inf bucket
const SHARDS: usize = 16;

/// One shard of counters; threads are spread over shards so I/O threads rarely share a line.
#[repr(align(128))]
#[derive(Default)]
struct Shard {
    /// 1xx, 2xx, 3xx, 4xx, 5xx, other.
    classes: [AtomicU64; 6],
    buckets: [AtomicU64; NB],
    sum_ns: AtomicU64,
}

struct Inner {
    shards: Box<[Shard]>,
    in_flight: AtomicI64,
}

/// Request counters by status class and a latency histogram, cheap enough for every request
/// (sharded relaxed atomics, no locks). Install with [`HttpMetrics::middleware`]; render with
/// [`HttpMetrics::write_prometheus`] or serve with [`metrics_handler`].
#[derive(Clone)]
pub struct HttpMetrics(Arc<Inner>);

impl Default for HttpMetrics {
    fn default() -> Self {
        HttpMetrics(Arc::new(Inner {
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
            in_flight: AtomicI64::new(0),
        }))
    }
}

impl std::fmt::Debug for HttpMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpMetrics")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// A snapshot of [`HttpMetrics`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpSnapshot {
    /// Responses by status class: `[1xx, 2xx, 3xx, 4xx, 5xx, other]`.
    pub by_class: [u64; 6],
    /// Non-cumulative histogram counts per bucket of [`LATENCY_BUCKETS`], plus `+Inf` last.
    pub buckets: [u64; NB],
    /// Sum of all latencies.
    pub sum: Duration,
    /// Requests dispatched whose response has not been sent yet.
    pub in_flight: i64,
}

impl HttpSnapshot {
    /// Responses counted.
    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
}

fn shard_index() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static IDX: Cell<usize> = const { Cell::new(usize::MAX) };
    }
    IDX.with(|c| {
        let mut i = c.get();
        if i == usize::MAX {
            i = NEXT.fetch_add(1, Ordering::Relaxed) % SHARDS;
            c.set(i);
        }
        i
    })
}

/// Decrements `in_flight` however the request ends; records the response when it is sent.
struct Pending {
    m: HttpMetrics,
    t0: Instant,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.m.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl HttpMetrics {
    /// Empty metrics.
    pub fn new() -> HttpMetrics {
        HttpMetrics::default()
    }

    /// Records one response.
    pub fn observe(&self, status: u16, latency: Duration) {
        let s = &self.0.shards[shard_index()];
        let class = match status {
            100..=599 => (status / 100 - 1) as usize,
            _ => 5,
        };
        s.classes[class].fetch_add(1, Ordering::Relaxed);
        let secs = latency.as_secs_f64();
        let b = LATENCY_BUCKETS
            .iter()
            .position(|&ub| secs <= ub)
            .unwrap_or(NB - 1);
        s.buckets[b].fetch_add(1, Ordering::Relaxed);
        s.sum_ns
            .fetch_add(latency.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Middleware that records every response: status class and the time from dispatch until
    /// the response is handed to the connection (detached responses included). Streamed
    /// responses and upgrades are not counted.
    pub fn middleware(&self) -> impl Middleware {
        let m = self.clone();
        move |ctx: &mut Context, next: &dyn Service| {
            m.0.in_flight.fetch_add(1, Ordering::Relaxed);
            let p = Pending {
                m: m.clone(),
                t0: Instant::now(),
            };
            ctx.add_response_filter(move |resp: &mut Response, _| {
                p.m.observe(resp.status, p.t0.elapsed());
            });
            next.call(ctx);
        }
    }

    /// Sums the shards.
    pub fn snapshot(&self) -> HttpSnapshot {
        let mut out = HttpSnapshot {
            in_flight: self.0.in_flight.load(Ordering::Relaxed),
            ..HttpSnapshot::default()
        };
        let mut sum = 0u64;
        for s in &self.0.shards {
            for (o, c) in out.by_class.iter_mut().zip(&s.classes) {
                *o += c.load(Ordering::Relaxed);
            }
            for (o, c) in out.buckets.iter_mut().zip(&s.buckets) {
                *o += c.load(Ordering::Relaxed);
            }
            sum += s.sum_ns.load(Ordering::Relaxed);
        }
        out.sum = Duration::from_nanos(sum);
        out
    }

    /// Appends the Prometheus rendering (`flash_http_requests_total{class}`,
    /// `flash_http_request_duration_seconds` histogram, `flash_http_requests_in_flight`).
    pub fn write_prometheus(&self, out: &mut String) {
        let s = self.snapshot();
        prometheus_header(
            out,
            "flash_http_requests_total",
            "counter",
            "HTTP responses by status class.",
        );
        for (i, class) in ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]
            .iter()
            .enumerate()
        {
            let _ = writeln!(
                out,
                "flash_http_requests_total{{class=\"{class}\"}} {}",
                s.by_class[i]
            );
        }
        let name = "flash_http_request_duration_seconds";
        prometheus_header(out, name, "histogram", "Time from dispatch to response.");
        let mut cum = 0;
        for (i, ub) in LATENCY_BUCKETS.iter().enumerate() {
            cum += s.buckets[i];
            let _ = writeln!(out, "{name}_bucket{{le=\"{ub}\"}} {cum}");
        }
        cum += s.buckets[NB - 1];
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {cum}");
        let _ = writeln!(out, "{name}_sum {}", s.sum.as_secs_f64());
        let _ = writeln!(out, "{name}_count {cum}");
        prometheus_header(
            out,
            "flash_http_requests_in_flight",
            "gauge",
            "Requests dispatched but not answered yet.",
        );
        let _ = writeln!(out, "flash_http_requests_in_flight {}", s.in_flight);
    }
}

/// A service answering with the engine's metrics (and `http`'s, if given) in the Prometheus text
/// format. Mount it on a route such as `/metrics`.
pub fn metrics_handler(tel: Arc<Telemetry>, http: Option<HttpMetrics>) -> impl Service {
    move |ctx: &mut Context| {
        let mut body = tel.metrics().to_prometheus();
        if let Some(h) = &http {
            h.write_prometheus(&mut body);
        }
        ctx.respond(Response::with_body(
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            body.into_bytes(),
        ));
    }
}

/// Structured access log through the `log` facade (target `flash_http::access`, level `info`):
/// one record per response with the key-values `method`, `target`, `status`, `peer`,
/// `elapsed_us` and `request_id` (when the request-id middleware ran first). Costs nothing
/// beyond one level check while that target is disabled.
pub fn access_log() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        if !log::log_enabled!(target: "flash_http::access", log::Level::Info) {
            return next.call(ctx);
        }
        let t0 = Instant::now();
        let peer = ctx.peer();
        let rid = ctx.local("request_id").map(str::to_owned);
        ctx.add_response_filter(move |resp: &mut Response, req| {
            let elapsed_us = t0.elapsed().as_micros() as u64;
            let rid = rid.as_deref().unwrap_or("");
            log::info!(
                target: "flash_http::access",
                method = req.method.as_str(), target = req.target.as_str(), status = resp.status,
                peer:% = peer, elapsed_us = elapsed_us, request_id = rid;
                "{} {} {} {}us", req.method.as_str(), req.target, resp.status, elapsed_us
            );
        });
        next.call(ctx);
    }
}

/// An opt-in runtime debug endpoint (the counterpart of Go's `pprof` pages), answering JSON.
/// Mount it under a wildcard route, e.g. `/debug/flash/*view`; the last path segment picks the
/// view:
///
/// * `conns`: the connection table (id, peer, local, owning thread, age, idle, bytes in/out,
///   queued bytes, read-held, backpressure, transport);
/// * `loops`: per-thread counters (iterations, events, callbacks, time in callbacks...), totals
///   and the logical pool;
/// * `slow`: the most recent slow callbacks;
/// * `live`: the live (reloadable) settings;
/// * anything else: the list of views.
///
/// With `token`, requests must carry `Authorization: Bearer <token>` or get `401`. The
/// connection table is gathered off the I/O thread (the request is detached), so it never stalls
/// the thread serving it.
pub fn debug_handler(tel: Arc<Telemetry>, token: Option<String>) -> impl Service {
    move |ctx: &mut Context| {
        if let Some(t) = &token {
            let ok = ctx
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|v| ct_eq(v.trim(), t));
            if !ok {
                return ctx.respond(
                    Response::text(401, "unauthorized").header("WWW-Authenticate", "Bearer"),
                );
            }
        }
        let view = ctx
            .path()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_owned();
        let json = |ctx: &mut Context, body: String| {
            ctx.bytes(200, "application/json", body.into_bytes());
        };
        match view.as_str() {
            "conns" | "connections" => {
                let Some(d) = ctx.detach() else { return };
                let tel = tel.clone();
                let spawned = std::thread::Builder::new()
                    .name("flash-debug".into())
                    .spawn(move || {
                        let rows = tel.connections(Duration::from_secs(2));
                        d.respond(Response::with_body(
                            200,
                            "application/json",
                            connections_json(&rows).into_bytes(),
                        ));
                    });
                // Without a thread the detached request is dropped, which closes the connection.
                drop(spawned);
            }
            "loops" | "metrics" => json(ctx, tel.metrics().to_json()),
            "slow" => json(ctx, slow_callbacks_json(&tel.slow_callbacks())),
            "live" => {
                let l = tel.live();
                let mut o = String::from("{");
                let ms = |d: Option<Duration>| {
                    d.map_or_else(|| "null".to_owned(), |d| d.as_millis().to_string())
                };
                let _ = write!(
                    o,
                    "\"idle_timeout_ms\":{},\"slow_callback_threshold_us\":{},\"max_queued_bytes\":{},\
                     \"write_high_watermark\":{},\"max_connections\":{},\"shutdown_timeout_ms\":{},\
                     \"open_connections\":{},\"log_level\":",
                    ms(l.idle_timeout()),
                    l.slow_callback_threshold()
                        .map_or_else(|| "null".to_owned(), |d| d.as_micros().to_string()),
                    l.max_queued_bytes(),
                    l.write_high_watermark(),
                    l.max_connections(),
                    l.shutdown_timeout().as_millis(),
                    tel.open_connections(),
                );
                json_str(&mut o, log::max_level().as_str());
                o.push('}');
                json(ctx, o);
            }
            _ => json(
                ctx,
                r#"{"views":["conns","loops","slow","live"]}"#.to_owned(),
            ),
        }
    }
}

/// Constant-time equality for secrets.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
