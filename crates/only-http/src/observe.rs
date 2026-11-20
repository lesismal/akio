//! Observability for HTTP servers: request metrics, a Prometheus endpoint, a structured access
//! log and an opt-in runtime debug endpoint.
//!
//! ```no_run
//! use only::{Config, Engine, Listener};
//! use only_http::{Router, observe, serve};
//!
//! let cfg = Config::default();
//! let tel = cfg.telemetry.clone();
//! let http = observe::HttpMetrics::new();
//! let app = Router::new()
//!     .get("/", |ctx: &mut only_http::Context| ctx.text(200, "hi"))
//!     .get("/metrics", observe::metrics_handler(tel.clone(), Some(http.clone())))
//!     .get("/debug/only/*view", observe::debug_handler(tel, Some("secret".into())))
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
        Arc, OnceLock,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use only_core::{
    Telemetry,
    metrics::{Collector, ExemplarReservoir, Families, HistogramSnapshot},
    telemetry::{connections_json, json_str, slow_callbacks_json},
};

use crate::{
    context::{Context, Middleware, Service},
    message::{Request, Response, Version},
    router::RouteInfo,
};

/// Upper bounds (seconds) of the request-latency histogram buckets.
pub const LATENCY_BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const NB: usize = LATENCY_BUCKETS.len() + 1; // + the +Inf bucket
const SHARDS: usize = 16;

/// One shard of counters; threads are spread over shards so I/O threads rarely share a line.
/// Laid out so that a typical response (any class, the first latency bucket) touches one cache
/// line: `classes`, `sum_ns` and `buckets[0]` share the first 64 bytes.
#[repr(C, align(128))]
#[derive(Default)]
struct Shard {
    /// 1xx, 2xx, 3xx, 4xx, 5xx, other.
    classes: [AtomicU64; 6],
    sum_ns: AtomicU64,
    buckets: [AtomicU64; NB],
    /// Responses per version: HTTP/1.0, (unused), HTTP/2, HTTP/3. HTTP/1.1 is the rest of the
    /// responses, so the most common version costs no extra atomic add.
    versions: [AtomicU64; 4],
    /// Requests dispatched on this shard's threads and not answered yet.
    in_flight: AtomicI64,
    /// Per-route counters ([`HttpMetrics::with_routes`]): one per route slot, then the
    /// overflow slot and the unmatched slot. Empty when per-route labels are off.
    routes: Box<[RouteCounters]>,
}

/// The counters of one route in one shard.
#[repr(C, align(64))]
#[derive(Default)]
struct RouteCounters {
    classes: [AtomicU64; 6],
    sum_ns: AtomicU64,
    buckets: [AtomicU64; NB],
}

#[inline]
fn class_of(status: u16) -> usize {
    match status {
        100..=599 => (status / 100 - 1) as usize,
        _ => 5,
    }
}

#[inline]
fn bucket_of(latency: Duration) -> usize {
    let secs = latency.as_secs_f64();
    LATENCY_BUCKETS
        .iter()
        .position(|&ub| secs <= ub)
        .unwrap_or(NB - 1)
}

impl RouteCounters {
    #[inline]
    fn observe(&self, status: u16, latency: Duration) {
        self.classes[class_of(status)].fetch_add(1, Ordering::Relaxed);
        self.buckets[bucket_of(latency)].fetch_add(1, Ordering::Relaxed);
        self.sum_ns
            .fetch_add(latency.as_nanos() as u64, Ordering::Relaxed);
    }
}

/// Route slots of [`HttpMetrics::with_routes`]: a fixed open-addressing table from a route's
/// id to its slot, filled lock-free as routes are first seen; once `max` routes have slots,
/// further routes share the overflow slot.
struct RouteTable {
    /// `(id << 24) | slot`, 0 = empty. Twice as many entries as slots, so probing ends.
    keys: Box<[AtomicU64]>,
    infos: Box<[OnceLock<&'static RouteInfo>]>,
    next: AtomicUsize,
    max: usize,
}

const SLOT_BITS: u32 = 24;

impl RouteTable {
    fn new(max: usize) -> RouteTable {
        let cap = (max * 2).next_power_of_two().max(2);
        RouteTable {
            keys: (0..cap).map(|_| AtomicU64::new(0)).collect(),
            infos: (0..max).map(|_| OnceLock::new()).collect(),
            next: AtomicUsize::new(0),
            max,
        }
    }

    fn overflow(&self) -> usize {
        self.max
    }

    fn unmatched(&self) -> usize {
        self.max + 1
    }

    #[inline]
    fn slot(&self, info: &'static RouteInfo) -> usize {
        let id = info.id();
        let mask = self.keys.len() - 1;
        let mut h = (id.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40) as usize & mask;
        loop {
            let k = self.keys[h].load(Ordering::Acquire);
            if k >> SLOT_BITS == id {
                return (k & ((1 << SLOT_BITS) - 1)) as usize;
            }
            if k == 0 {
                return self.claim(h, info);
            }
            h = (h + 1) & mask;
        }
    }

    #[cold]
    fn claim(&self, mut h: usize, info: &'static RouteInfo) -> usize {
        let id = info.id();
        let mask = self.keys.len() - 1;
        if self.next.load(Ordering::Relaxed) >= self.max {
            return self.overflow();
        }
        let slot = self.next.fetch_add(1, Ordering::Relaxed);
        if slot >= self.max {
            return self.overflow();
        }
        // The slot's route is published before its key, so a reader that finds the key finds
        // the route. A slot lost in a race keeps its route with no counts: snapshots merge
        // slots of the same route.
        let _ = self.infos[slot].set(info);
        let packed = (id << SLOT_BITS) | slot as u64;
        loop {
            match self.keys[h].compare_exchange(0, packed, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return slot,
                Err(k) if k >> SLOT_BITS == id => return (k & ((1 << SLOT_BITS) - 1)) as usize,
                Err(_) => {}
            }
            // Next empty or matching entry.
            loop {
                h = (h + 1) & mask;
                let k = self.keys[h].load(Ordering::Acquire);
                if k >> SLOT_BITS == id {
                    return (k & ((1 << SLOT_BITS) - 1)) as usize;
                }
                if k == 0 {
                    break;
                }
            }
        }
    }
}

/// The most route slots [`HttpMetrics::with_routes`] accepts.
pub const MAX_ROUTE_SLOTS: usize = 4096;

/// Per-route counters in a [`HttpMetrics::route_snapshot`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RouteSnapshot {
    /// The route's method (`*` for the overflow and unmatched rows).
    pub method: String,
    /// The route pattern (`/users/:id`), `other` for routes past the slot limit, `unmatched`
    /// for requests no route matched (404/405).
    pub route: String,
    /// Responses by status class: `[1xx, 2xx, 3xx, 4xx, 5xx, other]`.
    pub by_class: [u64; 6],
    /// Non-cumulative histogram counts per bucket of [`LATENCY_BUCKETS`], plus `+Inf` last.
    pub buckets: [u64; NB],
    /// Sum of all latencies.
    pub sum: Duration,
}

impl RouteSnapshot {
    /// Responses counted.
    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
}

impl Shard {
    /// Records one response, and its request's version (index into [`VERSION_LABELS`]).
    #[inline]
    fn observe(&self, status: u16, latency: Duration, version: Option<usize>) {
        if let Some(v) = version.filter(|&v| v != 1) {
            self.versions[v].fetch_add(1, Ordering::Relaxed);
        }
        self.classes[class_of(status)].fetch_add(1, Ordering::Relaxed);
        self.buckets[bucket_of(latency)].fetch_add(1, Ordering::Relaxed);
        self.sum_ns
            .fetch_add(latency.as_nanos() as u64, Ordering::Relaxed);
    }
}

/// Label values of the status classes, in order.
const CLASS_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Label values of [`HttpSnapshot::by_version`], in order.
pub const VERSION_LABELS: [&str; 4] = ["1.0", "1.1", "2", "3"];

struct Inner {
    /// Each shard behind its own `Arc`: a request in flight holds its thread's shard, so the
    /// reference count a request bumps is shared only by the threads of that shard (not by
    /// every thread, as the metrics' own count would be).
    shards: Box<[Arc<Shard>]>,
    /// Highest HTTP/1.1 count a snapshot reported: the count is derived from shards read one
    /// after the other, and must not appear to go down when a response lands mid-read.
    h11_seen: AtomicU64,
    /// Route slots, when per-route labels are on.
    routes: Option<RouteTable>,
    /// Exemplars of the latency histogram ([`HttpMetrics::with_exemplars`]).
    exemplars: Option<Arc<ExemplarReservoir>>,
}

/// Request counters by status class and a latency histogram, cheap enough for every request
/// (sharded relaxed atomics, no locks). Install with [`HttpMetrics::middleware`]; render with
/// [`HttpMetrics::write_prometheus`] or serve with [`metrics_handler`].
#[derive(Clone)]
pub struct HttpMetrics(Arc<Inner>);

impl Default for HttpMetrics {
    fn default() -> Self {
        HttpMetrics::build(None)
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
    /// Responses per HTTP version of the request (see [`VERSION_LABELS`]), counted by
    /// [`HttpMetrics::middleware`]: on h2 and h3 this is the number of answered request streams.
    /// Responses recorded with [`HttpMetrics::observe`] directly count as HTTP/1.1.
    pub by_version: [u64; 4],
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
    shard: Arc<Shard>,
    t0: Instant,
    /// The route slot, `usize::MAX` without per-route labels.
    route: usize,
    /// Where the latency goes as an exemplar: only with exemplars on and a sampled request span.
    /// Boxed: a request without one carries a null pointer, not the context.
    exemplar: Option<Box<(Arc<ExemplarReservoir>, only_log::span::SpanContext)>>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.shard.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl HttpMetrics {
    /// Empty metrics.
    pub fn new() -> HttpMetrics {
        HttpMetrics::default()
    }

    /// Empty metrics that also count per route: requests by status class and a latency
    /// histogram labelled with the matched route's method and pattern
    /// ([`Context::route`]: `GET /users/:id`, never the raw path), for at most `max_routes`
    /// routes (capped at [`MAX_ROUTE_SLOTS`]); routes seen after that share the `route="other"`
    /// row, and requests no route matched are `route="unmatched"`. Install the middleware with
    /// [`Router::layer`](crate::Router::layer) so the route is known when it runs (installed
    /// around a whole router, every request is unmatched). Memory: about 200 bytes per route
    /// per shard (16 shards).
    pub fn with_routes(max_routes: usize) -> HttpMetrics {
        HttpMetrics::build(Some(max_routes.clamp(1, MAX_ROUTE_SLOTS)))
    }

    fn build(routes: Option<usize>) -> HttpMetrics {
        let slots = routes.map_or(0, |n| n + 2);
        HttpMetrics(Arc::new(Inner {
            shards: (0..SHARDS)
                .map(|_| {
                    Arc::new(Shard {
                        routes: (0..slots).map(|_| RouteCounters::default()).collect(),
                        ..Shard::default()
                    })
                })
                .collect(),
            h11_seen: AtomicU64::new(0),
            routes: routes.map(RouteTable::new),
            exemplars: None,
        }))
    }

    /// Keeps exemplars on the request-latency histogram
    /// (`only_http_request_duration_seconds`): each bucket remembers the latest request whose
    /// request span was sampled, with that span's trace and span ids, so a slow bucket on a
    /// dashboard leads to a trace. Exported over OTLP (`only-export`); needs request spans
    /// (`only_http::request`, level `info`) to be on. Costs nothing per request otherwise; with
    /// a sampled span, a clock read and an uncontended `try_lock`. Call it on new metrics,
    /// before cloning them (a shared value is replaced by fresh metrics).
    #[must_use]
    pub fn with_exemplars(self) -> HttpMetrics {
        let mut m = if Arc::strong_count(&self.0) == 1 {
            self
        } else {
            HttpMetrics::build(self.0.routes.as_ref().map(|t| t.max))
        };
        if let Some(inner) = Arc::get_mut(&mut m.0) {
            inner.exemplars = Some(Arc::new(ExemplarReservoir::new(NB)));
        }
        m
    }

    /// Records one response.
    pub fn observe(&self, status: u16, latency: Duration) {
        self.0.shards[shard_index()].observe(status, latency, None);
    }

    /// Middleware that records every response: status class, request version and the time from dispatch until
    /// the response is handed to the connection (detached responses included). Streamed
    /// responses and upgrades are not counted.
    pub fn middleware(&self) -> impl Middleware {
        let m = self.clone();
        move |ctx: &mut Context, next: &dyn Service| {
            let shard = m.0.shards[shard_index()].clone();
            shard.in_flight.fetch_add(1, Ordering::Relaxed);
            let route =
                m.0.routes
                    .as_ref()
                    .map_or(usize::MAX, |t| match ctx.route() {
                        Some(info) => t.slot(info),
                        None => t.unmatched(),
                    });
            let exemplar = match &m.0.exemplars {
                None => None,
                Some(ex) => ctx
                    .span_context()
                    .filter(only_log::span::SpanContext::is_sampled)
                    .map(|c| Box::new((ex.clone(), c))),
            };
            let p = Pending {
                shard,
                t0: Instant::now(),
                route,
                exemplar,
            };
            ctx.add_response_filter(move |resp: &mut Response, req: &Request| {
                let v = match req.version {
                    Version::Http10 => 0,
                    Version::Http11 => 1,
                    Version::Http2 => 2,
                    Version::Http3 => 3,
                };
                let latency = p.t0.elapsed();
                p.shard.observe(resp.status, latency, Some(v));
                if let Some(rc) = p.shard.routes.get(p.route) {
                    rc.observe(resp.status, latency);
                }
                if let Some(e) = &p.exemplar {
                    let (ex, c) = &**e;
                    ex.offer(
                        bucket_of(latency),
                        latency.as_secs_f64(),
                        c.trace_id(),
                        c.span_id(),
                    );
                }
            });
            next.call(ctx);
        }
    }

    /// Sums the shards.
    pub fn snapshot(&self) -> HttpSnapshot {
        let mut out = HttpSnapshot::default();
        let mut sum = 0u64;
        for s in &self.0.shards {
            out.in_flight += s.in_flight.load(Ordering::Relaxed);
            for (o, c) in out.by_class.iter_mut().zip(&s.classes) {
                *o += c.load(Ordering::Relaxed);
            }
            for (o, c) in out.buckets.iter_mut().zip(&s.buckets) {
                *o += c.load(Ordering::Relaxed);
            }
            for (o, c) in out.by_version.iter_mut().zip(&s.versions) {
                *o += c.load(Ordering::Relaxed);
            }
            sum += s.sum_ns.load(Ordering::Relaxed);
        }
        out.sum = Duration::from_nanos(sum);
        let others = out.by_version[0] + out.by_version[2] + out.by_version[3];
        let h11 = out.count().saturating_sub(others);
        out.by_version[1] = self.0.h11_seen.fetch_max(h11, Ordering::Relaxed).max(h11);
        out
    }

    /// Per-route counters (empty unless built with [`HttpMetrics::with_routes`]), one row per
    /// route seen, plus the `other` and `unmatched` rows when they have counts.
    pub fn route_snapshot(&self) -> Vec<RouteSnapshot> {
        let Some(t) = &self.0.routes else {
            return Vec::new();
        };
        let mut rows: Vec<RouteSnapshot> = Vec::new();
        let mut index: std::collections::HashMap<(String, String), usize> = Default::default();
        for slot in 0..t.max + 2 {
            let (method, route) = if slot < t.max {
                match t.infos[slot].get() {
                    Some(i) => (i.method().as_str().to_owned(), i.pattern().to_owned()),
                    None => continue,
                }
            } else if slot == t.overflow() {
                ("*".to_owned(), "other".to_owned())
            } else {
                ("*".to_owned(), "unmatched".to_owned())
            };
            let mut row = RouteSnapshot {
                method,
                route,
                ..RouteSnapshot::default()
            };
            let mut sum = 0u64;
            for s in &self.0.shards {
                let c = &s.routes[slot];
                for (o, v) in row.by_class.iter_mut().zip(&c.classes) {
                    *o += v.load(Ordering::Relaxed);
                }
                for (o, v) in row.buckets.iter_mut().zip(&c.buckets) {
                    *o += v.load(Ordering::Relaxed);
                }
                sum += c.sum_ns.load(Ordering::Relaxed);
            }
            row.sum = Duration::from_nanos(sum);
            if slot >= t.max && row.count() == 0 {
                continue;
            }
            match index.get(&(row.method.clone(), row.route.clone())) {
                Some(&i) => {
                    let o = &mut rows[i];
                    for (a, b) in o.by_class.iter_mut().zip(row.by_class) {
                        *a += b;
                    }
                    for (a, b) in o.buckets.iter_mut().zip(row.buckets) {
                        *a += b;
                    }
                    o.sum += row.sum;
                }
                None => {
                    index.insert((row.method.clone(), row.route.clone()), rows.len());
                    rows.push(row);
                }
            }
        }
        rows
    }

    /// Appends the Prometheus rendering (`only_http_requests_total{class}`,
    /// `only_http_request_duration_seconds` histogram, `only_http_requests_in_flight`,
    /// `only_http_requests_by_version_total{version}`); the same series [`Collector::collect`]
    /// reports.
    pub fn write_prometheus(&self, out: &mut String) {
        let mut f = Families::new();
        self.collect(&mut f);
        f.write_prometheus(out);
    }
}

impl Collector for HttpMetrics {
    fn collect(&self, out: &mut Families) {
        let s = self.snapshot();
        for (i, class) in CLASS_LABELS.iter().enumerate() {
            out.counter(
                "only_http_requests_total",
                "HTTP responses by status class.",
                &[("class", class)],
                s.by_class[i] as f64,
            );
        }
        let h = HistogramSnapshot::new(
            LATENCY_BUCKETS.to_vec(),
            s.buckets.to_vec(),
            s.sum.as_secs_f64(),
        )
        .map(|h| match &self.0.exemplars {
            Some(ex) => h.with_exemplars(ex.snapshot()),
            None => h,
        });
        if let Some(h) = h {
            out.histogram(
                "only_http_request_duration_seconds",
                "Time from dispatch to response.",
                &[],
                &h,
            );
        }
        out.gauge(
            "only_http_requests_in_flight",
            "Requests dispatched but not answered yet.",
            &[],
            s.in_flight as f64,
        );
        for (i, v) in VERSION_LABELS.iter().enumerate() {
            out.counter(
                "only_http_requests_by_version_total",
                "HTTP responses by request protocol version (h2/h3: request streams).",
                &[("version", v)],
                s.by_version[i] as f64,
            );
        }
        for r in self.route_snapshot() {
            for (i, class) in CLASS_LABELS.iter().enumerate() {
                if r.by_class[i] == 0 {
                    continue;
                }
                out.counter(
                    "only_http_route_requests_total",
                    "HTTP responses by route and status class.",
                    &[("method", &r.method), ("route", &r.route), ("class", class)],
                    r.by_class[i] as f64,
                );
            }
            let h = HistogramSnapshot::new(
                LATENCY_BUCKETS.to_vec(),
                r.buckets.to_vec(),
                r.sum.as_secs_f64(),
            );
            if let Some(h) = h {
                out.histogram(
                    "only_http_route_request_duration_seconds",
                    "Time from dispatch to response, by route.",
                    &[("method", &r.method), ("route", &r.route)],
                    &h,
                );
            }
        }
    }
}

/// One shard of [`H2Stats`].
#[repr(C, align(128))]
#[derive(Default, Debug)]
pub(crate) struct H2Shard {
    pub(crate) conns_opened: AtomicU64,
    pub(crate) conns_closed: AtomicU64,
    pub(crate) streams_opened: AtomicU64,
    pub(crate) streams_closed: AtomicU64,
    pub(crate) resets_received: AtomicU64,
    pub(crate) resets_sent: AtomicU64,
    pub(crate) goaways_sent: AtomicU64,
    pub(crate) goaways_received: AtomicU64,
}

impl H2Shard {
    #[inline]
    pub(crate) fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// HTTP/2 connection and stream counters of a server: set [`H2Config::stats`] and register it
/// as a collector ([`Telemetry::register_collector`]) or read [`H2Stats::snapshot`]. Sharded
/// relaxed atomics; a connection adds to its I/O thread's shard. Several servers may share one.
///
/// [`H2Config::stats`]: crate::H2Config::stats
#[derive(Clone)]
pub struct H2Stats(Arc<[Arc<H2Shard>]>);

impl Default for H2Stats {
    fn default() -> Self {
        H2Stats((0..SHARDS).map(|_| Arc::new(H2Shard::default())).collect())
    }
}

impl std::fmt::Debug for H2Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Stats")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// A snapshot of [`H2Stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct H2Snapshot {
    /// HTTP/2 connections open now.
    pub connections_open: u64,
    /// HTTP/2 connections started (prior knowledge, `h2c` upgrade or ALPN `h2`).
    pub connections_total: u64,
    /// Streams open now (requests in progress and promised pushes).
    pub streams_open: u64,
    /// Streams opened.
    pub streams_total: u64,
    /// `RST_STREAM` frames received.
    pub resets_received: u64,
    /// `RST_STREAM` frames sent.
    pub resets_sent: u64,
    /// `GOAWAY` frames sent.
    pub goaways_sent: u64,
    /// `GOAWAY` frames received.
    pub goaways_received: u64,
}

impl H2Stats {
    /// Empty counters.
    pub fn new() -> H2Stats {
        H2Stats::default()
    }

    /// The shard of the calling thread.
    pub(crate) fn shard(&self) -> Arc<H2Shard> {
        self.0[shard_index()].clone()
    }

    /// Sums the shards.
    pub fn snapshot(&self) -> H2Snapshot {
        let mut o = H2Snapshot::default();
        let (mut co, mut cc, mut so, mut sc) = (0u64, 0u64, 0u64, 0u64);
        for s in self.0.iter() {
            let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
            co += l(&s.conns_opened);
            cc += l(&s.conns_closed);
            so += l(&s.streams_opened);
            sc += l(&s.streams_closed);
            o.resets_received += l(&s.resets_received);
            o.resets_sent += l(&s.resets_sent);
            o.goaways_sent += l(&s.goaways_sent);
            o.goaways_received += l(&s.goaways_received);
        }
        o.connections_total = co;
        o.connections_open = co.saturating_sub(cc);
        o.streams_total = so;
        o.streams_open = so.saturating_sub(sc);
        o
    }
}

impl Collector for H2Stats {
    fn collect(&self, out: &mut Families) {
        let s = self.snapshot();
        out.gauge(
            "only_http2_connections_open",
            "HTTP/2 connections open now.",
            &[],
            s.connections_open as f64,
        );
        out.counter(
            "only_http2_connections_total",
            "HTTP/2 connections started.",
            &[],
            s.connections_total as f64,
        );
        out.gauge(
            "only_http2_streams_open",
            "HTTP/2 streams open now.",
            &[],
            s.streams_open as f64,
        );
        out.counter(
            "only_http2_streams_total",
            "HTTP/2 streams opened.",
            &[],
            s.streams_total as f64,
        );
        for (dir, v) in [("received", s.resets_received), ("sent", s.resets_sent)] {
            out.counter(
                "only_http2_resets_total",
                "HTTP/2 RST_STREAM frames.",
                &[("direction", dir)],
                v as f64,
            );
        }
        for (dir, v) in [("received", s.goaways_received), ("sent", s.goaways_sent)] {
            out.counter(
                "only_http2_goaways_total",
                "HTTP/2 GOAWAY frames.",
                &[("direction", dir)],
                v as f64,
            );
        }
    }
}

/// A service answering with the engine's metrics, the collectors registered with
/// [`Telemetry::register_collector`] and `http`'s metrics (if given; pass `None` when `http` is
/// registered as a collector already) in the Prometheus text format. Mount it on a route such as
/// `/metrics`.
pub fn metrics_handler(tel: Arc<Telemetry>, http: Option<HttpMetrics>) -> impl Service {
    move |ctx: &mut Context| {
        let mut body = tel.render_prometheus();
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

/// Structured access log through the `only-log` facade (`only::log`; target
/// `only_http::access`, level `info`): one record per response with the key-values `method`,
/// `target`, `status`, `peer`, `elapsed_us` and `request_id` (when the request-id middleware
/// ran first). Costs nothing beyond one level check while that target is disabled.
pub fn access_log() -> impl Middleware {
    |ctx: &mut Context, next: &dyn Service| {
        if !only_log::log_enabled!(target: "only_http::access", only_log::Level::Info) {
            return next.call(ctx);
        }
        let t0 = Instant::now();
        let peer = ctx.peer();
        let rid = ctx.local("request_id").map(str::to_owned);
        ctx.add_response_filter(move |resp: &mut Response, req| {
            let elapsed_us = t0.elapsed().as_micros() as u64;
            let rid = rid.as_deref().unwrap_or("");
            only_log::info!(
                target: "only_http::access",
                method = req.method.as_str(), target = req.target.as_str(), status = resp.status,
                peer:% = peer, elapsed_us = elapsed_us, request_id = rid;
                "{} {} {} {}us", req.method.as_str(), req.target, resp.status, elapsed_us
            );
        });
        next.call(ctx);
    }
}

/// An opt-in runtime debug endpoint (the counterpart of Go's `pprof` pages), answering JSON.
/// Mount it under a wildcard route, e.g. `/debug/only/*view`; the last path segment picks the
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
                let spawned =
                    std::thread::Builder::new()
                        .name("only-debug".into())
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
                json_str(&mut o, only_log::max_level().as_str());
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
