#![forbid(unsafe_code)]
//! Push export for [`only`](https://docs.rs/only): metrics and spans to an OpenTelemetry
//! collector over OTLP/HTTP (protobuf or JSON), and metrics to StatsD / DogStatsD over UDP,
//! from one background thread, without dependencies.
//!
//! ```no_run
//! use std::{sync::Arc, time::Duration};
//! use only::{Config, log::LevelFilter};
//! use only_export::{Exporter, Flavor};
//!
//! let cfg = Config::default();
//! let exporter = Exporter::builder()
//!     .service_name("checkout")
//!     .telemetry(cfg.telemetry.clone()) // engine series + registered collectors
//!     .interval(Duration::from_secs(10))
//!     .otlp_http("http://127.0.0.1:4318")
//!     .statsd("127.0.0.1:8125", Flavor::DogStatsd)
//!     .traces(LevelFilter::Info) // install the span tracer: request spans go to OTLP
//!     .start()
//!     .unwrap();
//! // ... run the engine ...
//! exporter.shutdown(); // a last push, then the thread ends
//! ```
//!
//! # Where the work happens
//!
//! Nothing is exported from an I/O thread. Metrics are read (the same [`Families`] a
//! Prometheus scrape renders) and sent every [`interval`](ExporterBuilder::interval) by the
//! exporter's own thread. Finished spans are handed to a bounded, sharded queue (one short
//! uncontended lock per span, never a wait); when it is full, spans are dropped and counted
//! (`only_export_spans_dropped_total`). The thread sends them in batches every
//! [`span_interval`](ExporterBuilder::span_interval), or earlier once a batch is full.
//!
//! # Formats
//!
//! * **OTLP/HTTP** (`POST /v1/metrics`, `/v1/traces`): counters as cumulative monotonic sums,
//!   gauges, histograms with explicit bounds; spans with their W3C ids, kind, status and fields
//!   as attributes, one instrumentation scope per span target. Plain `http://` only: point it
//!   at a local collector (or a TLS-terminating sidecar).
//! * **StatsD** (plain or DogStatsD tags): counters as deltas since the last push, gauges as
//!   values, histograms as `.count` / `.sum` / `.bucket` (with an `le` tag) deltas. Spans are
//!   not sent to StatsD.
//!
//! Failed pushes are counted and dropped: cumulative metrics are complete again at the next
//! push, and spans are not retried (the queue stays bounded).
#![warn(clippy::unwrap_used)]

mod http;
mod otlp;
mod statsd;
mod tree;

use std::{
    io,
    net::{ToSocketAddrs, UdpSocket},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use only_core::{
    Telemetry,
    metrics::{Collector, Families},
};
use only_log::{
    LevelFilter, Metadata,
    span::{self, SpanContext, SpanData, Tracer},
};

pub use otlp::Encoding;
pub use statsd::Flavor;

/// Default push interval of metrics.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
/// Default interval of span batches.
pub const DEFAULT_SPAN_INTERVAL: Duration = Duration::from_secs(2);
/// Default capacity of the span queue.
pub const DEFAULT_MAX_QUEUED_SPANS: usize = 4096;
/// Default number of spans per OTLP request.
pub const DEFAULT_MAX_BATCH: usize = 512;
/// Default largest StatsD datagram.
pub const DEFAULT_MAX_PACKET: usize = 1432;
/// Default number of StatsD series whose last value is remembered (for counter deltas).
pub const DEFAULT_MAX_SERIES: usize = 10_000;
/// Default timeout of each OTLP/HTTP step (connect, write, read).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

const SPAN_SHARDS: usize = 8;

// ---- the span queue -------------------------------------------------------------------------

/// The process-wide span queue (a tracer can be installed once per process).
static QUEUE: OnceLock<Arc<SpanQueue>> = OnceLock::new();

struct SpanQueue {
    shards: [Mutex<Vec<SpanData>>; SPAN_SHARDS],
    /// Most spans queued at once.
    max: usize,
    batch: usize,
    /// Wakes the exporter thread when a shard holds a full batch.
    wake: Mutex<Option<mpsc::SyncSender<Cmd>>>,
    /// Sampling threshold on the trace id's low 64 bits (`u64::MAX` = everything).
    threshold: AtomicU64,
    open: AtomicBool,
    queued: AtomicUsize,
    dropped: AtomicU64,
    exported: AtomicU64,
}

fn span_shard() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static IDX: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    }
    IDX.with(|c| {
        let mut i = c.get();
        if i == usize::MAX {
            i = NEXT.fetch_add(1, Ordering::Relaxed) % SPAN_SHARDS;
            c.set(i);
        }
        i
    })
}

impl SpanQueue {
    fn drain(&self, max: usize) -> Vec<SpanData> {
        let mut out = Vec::new();
        for s in &self.shards {
            if out.len() >= max {
                break;
            }
            let mut g = s.lock().unwrap_or_else(|p| p.into_inner());
            let take = g.len().min(max - out.len());
            out.extend(g.drain(..take));
        }
        self.queued.fetch_sub(out.len(), Ordering::Relaxed);
        out
    }
}

/// The tracer installed by [`ExporterBuilder::traces`].
struct QueueTracer(Arc<SpanQueue>);

impl Tracer for QueueTracer {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        self.0.open.load(Ordering::Relaxed)
    }

    fn sample(&self, trace_id: u128, parent: Option<&SpanContext>) -> bool {
        match parent {
            Some(p) => p.is_sampled(),
            None => (trace_id as u64) <= self.0.threshold.load(Ordering::Relaxed),
        }
    }

    fn on_end(&self, span: SpanData) {
        let q = &self.0;
        if !q.open.load(Ordering::Relaxed) {
            return;
        }
        // The bound is on the total; the shards only spread the locks over threads.
        let n = q.queued.fetch_add(1, Ordering::Relaxed);
        if n >= q.max {
            q.queued.fetch_sub(1, Ordering::Relaxed);
            q.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.shards[span_shard()]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(span);
        if (n + 1) % q.batch == 0 {
            if let Some(w) = &*q.wake.lock().unwrap_or_else(|p| p.into_inner()) {
                let _ = w.try_send(Cmd::Spans);
            }
        }
    }
}

// ---- configuration --------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct OtlpCfg {
    endpoint: String,
    encoding: Encoding,
    headers: Vec<(String, String)>,
    metrics: bool,
}

#[derive(Clone, Debug)]
struct StatsdCfg {
    addr: String,
    flavor: Flavor,
    prefix: String,
    max_packet: usize,
    max_series: usize,
}

/// Configures and starts an [`Exporter`]; see the crate documentation.
#[derive(Clone)]
#[must_use = "call `start` to run the exporter"]
pub struct ExporterBuilder {
    resource: Vec<(String, String)>,
    telemetry: Option<Arc<Telemetry>>,
    collectors: Vec<Arc<dyn Collector>>,
    interval: Duration,
    span_interval: Duration,
    timeout: Duration,
    otlp: Option<OtlpCfg>,
    statsd: Option<StatsdCfg>,
    traces: Option<LevelFilter>,
    sample_ratio: f64,
    max_queued_spans: usize,
    max_batch: usize,
}

impl std::fmt::Debug for ExporterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExporterBuilder")
            .field("resource", &self.resource)
            .field("interval", &self.interval)
            .field("otlp", &self.otlp)
            .field("statsd", &self.statsd)
            .field("traces", &self.traces)
            .finish_non_exhaustive()
    }
}

impl Default for ExporterBuilder {
    fn default() -> Self {
        ExporterBuilder {
            resource: vec![("service.name".to_owned(), "unknown_service".to_owned())],
            telemetry: None,
            collectors: Vec::new(),
            interval: DEFAULT_INTERVAL,
            span_interval: DEFAULT_SPAN_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            otlp: None,
            statsd: None,
            traces: None,
            sample_ratio: 1.0,
            max_queued_spans: DEFAULT_MAX_QUEUED_SPANS,
            max_batch: DEFAULT_MAX_BATCH,
        }
    }
}

impl ExporterBuilder {
    /// The OTLP resource attribute `service.name` (default `unknown_service`).
    pub fn service_name(self, name: &str) -> ExporterBuilder {
        self.resource_attr("service.name", name)
    }

    /// Adds (or replaces) an OTLP resource attribute (`deployment.environment`,
    /// `service.version` ...).
    pub fn resource_attr(mut self, key: &str, value: &str) -> ExporterBuilder {
        match self.resource.iter_mut().find(|(k, _)| k == key) {
            Some(kv) => kv.1 = value.to_owned(),
            None => self.resource.push((key.to_owned(), value.to_owned())),
        }
        self
    }

    /// Exports the engine's series and every collector registered with it
    /// ([`Telemetry::collect_all`]).
    pub fn telemetry(mut self, tel: Arc<Telemetry>) -> ExporterBuilder {
        self.telemetry = Some(tel);
        self
    }

    /// Exports one more collector (in addition to the telemetry's).
    pub fn collector(mut self, c: Arc<dyn Collector>) -> ExporterBuilder {
        self.collectors.push(c);
        self
    }

    /// How often metrics are pushed (default 10 s, at least 100 ms).
    pub fn interval(mut self, d: Duration) -> ExporterBuilder {
        self.interval = d.max(Duration::from_millis(100));
        self
    }

    /// How often queued spans are sent (default 2 s, at least 10 ms); a full batch goes earlier.
    pub fn span_interval(mut self, d: Duration) -> ExporterBuilder {
        self.span_interval = d.max(Duration::from_millis(10));
        self
    }

    /// Timeout of each OTLP/HTTP step: connect, write, read (default 5 s).
    pub fn timeout(mut self, d: Duration) -> ExporterBuilder {
        self.timeout = d;
        self
    }

    /// Sends metrics (and spans, with [`traces`](Self::traces)) to an OTLP/HTTP collector at
    /// `endpoint` (`http://host:4318`; `/v1/metrics` and `/v1/traces` are appended), in protobuf.
    pub fn otlp_http(self, endpoint: &str) -> ExporterBuilder {
        self.otlp_http_with(endpoint, Encoding::Protobuf, &[])
    }

    /// [`otlp_http`](Self::otlp_http) with an encoding and extra request headers
    /// (`authorization`, tenant ids ...).
    pub fn otlp_http_with(
        mut self,
        endpoint: &str,
        encoding: Encoding,
        headers: &[(&str, &str)],
    ) -> ExporterBuilder {
        self.otlp = Some(OtlpCfg {
            endpoint: endpoint.to_owned(),
            encoding,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            metrics: true,
        });
        self
    }

    /// Sends spans to the OTLP endpoint but not metrics (when metrics go to StatsD or are
    /// scraped).
    pub fn otlp_traces_only(mut self) -> ExporterBuilder {
        if let Some(o) = &mut self.otlp {
            o.metrics = false;
        }
        self
    }

    /// Sends metrics to a StatsD server at `addr` (`host:8125`, resolved when the exporter
    /// starts) over UDP.
    pub fn statsd(mut self, addr: &str, flavor: Flavor) -> ExporterBuilder {
        self.statsd = Some(StatsdCfg {
            addr: addr.to_owned(),
            flavor,
            prefix: String::new(),
            max_packet: DEFAULT_MAX_PACKET,
            max_series: DEFAULT_MAX_SERIES,
        });
        self
    }

    /// StatsD options: a prefix for every name (`"myapp."`), the largest datagram (default
    /// 1432 bytes) and how many series' last values are kept for counter deltas (default
    /// 10 000; new series past it are skipped and counted).
    pub fn statsd_options(
        mut self,
        prefix: &str,
        max_packet: usize,
        max_series: usize,
    ) -> ExporterBuilder {
        if let Some(s) = &mut self.statsd {
            s.prefix = prefix.to_owned();
            s.max_packet = max_packet.max(64);
            s.max_series = max_series;
        }
        self
    }

    /// Installs the exporter's span queue as the process-wide tracer and sets the maximum span
    /// level to `level` (only-log spans: `only_http` request spans are `info`, connection spans
    /// `debug`). Needs [`otlp_http`](Self::otlp_http). A tracer can be installed once per
    /// process: [`start`](Self::start) fails if another one (or an earlier exporter's) is.
    pub fn traces(mut self, level: LevelFilter) -> ExporterBuilder {
        self.traces = Some(level);
        self
    }

    /// The fraction of new traces recorded (default 1.0); spans with a remote parent follow its
    /// sampled flag.
    pub fn sample_ratio(mut self, ratio: f64) -> ExporterBuilder {
        self.sample_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Span queue capacity (default 4096; past it spans are dropped and counted) and spans per
    /// OTLP request (default 512).
    pub fn span_queue(mut self, max_queued: usize, max_batch: usize) -> ExporterBuilder {
        self.max_queued_spans = max_queued.max(1);
        self.max_batch = max_batch.max(1);
        self
    }

    /// Starts the exporter thread (`only-export`).
    ///
    /// # Errors
    /// An endpoint that does not parse, a StatsD address that does not resolve or a socket that
    /// cannot be opened, [`traces`](Self::traces) without OTLP, or a tracer already installed.
    pub fn start(self) -> io::Result<Exporter> {
        let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_owned());
        let otlp = match &self.otlp {
            Some(o) => Some((
                http::Client::new(
                    http::Endpoint::parse(&o.endpoint)?,
                    self.timeout,
                    o.headers.clone(),
                ),
                o.clone(),
            )),
            None => None,
        };
        let statsd = match &self.statsd {
            Some(s) => {
                let addr = s
                    .addr
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| invalid("statsd address did not resolve"))?;
                let bind = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = UdpSocket::bind(bind)?;
                sock.connect(addr)?;
                Some((
                    sock,
                    statsd::Renderer::new(s.flavor, s.prefix.clone(), s.max_series),
                    s.max_packet,
                ))
            }
            None => None,
        };
        let (tx, rx) = mpsc::sync_channel::<Cmd>(16);
        let queue = match self.traces {
            Some(level) => {
                if otlp.is_none() {
                    return Err(invalid("traces need an OTLP endpoint"));
                }
                let q = Arc::new(SpanQueue {
                    shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
                    max: self.max_queued_spans,
                    batch: self.max_batch,
                    wake: Mutex::new(Some(tx.clone())),
                    threshold: AtomicU64::new(ratio_threshold(self.sample_ratio)),
                    open: AtomicBool::new(true),
                    queued: AtomicUsize::new(0),
                    dropped: AtomicU64::new(0),
                    exported: AtomicU64::new(0),
                });
                if QUEUE.set(q.clone()).is_err()
                    || span::set_boxed_tracer(Box::new(QueueTracer(q.clone()))).is_err()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "a tracer is already installed in this process",
                    ));
                }
                span::set_max_span_level(level);
                Some(q)
            }
            None => None,
        };
        let stats = Arc::new(Stats::default());
        let worker = Worker {
            resource: self.resource,
            telemetry: self.telemetry,
            collectors: self.collectors,
            interval: self.interval,
            span_interval: self.span_interval,
            max_batch: self.max_batch,
            otlp,
            statsd,
            queue: queue.clone(),
            stats: stats.clone(),
            start: SystemTime::now(),
        };
        let handle = thread::Builder::new()
            .name("only-export".into())
            .spawn(move || worker.run(&rx))?;
        Ok(Exporter {
            tx,
            handle: Mutex::new(Some(handle)),
            stats,
            queue,
        })
    }
}

fn ratio_threshold(r: f64) -> u64 {
    if r >= 1.0 {
        u64::MAX
    } else {
        (r * u64::MAX as f64) as u64
    }
}

// ---- the exporter thread --------------------------------------------------------------------

enum Cmd {
    /// A shard holds a full batch.
    Spans,
    /// Push everything now and answer.
    Flush(mpsc::Sender<()>),
    /// A last push, then end.
    Stop,
}

#[derive(Default, Debug)]
struct Stats {
    otlp_metrics_ok: AtomicU64,
    otlp_metrics_failed: AtomicU64,
    otlp_traces_ok: AtomicU64,
    otlp_traces_failed: AtomicU64,
    statsd_ok: AtomicU64,
    statsd_failed: AtomicU64,
    statsd_dropped_series: AtomicU64,
}

struct Worker {
    resource: Vec<(String, String)>,
    telemetry: Option<Arc<Telemetry>>,
    collectors: Vec<Arc<dyn Collector>>,
    interval: Duration,
    span_interval: Duration,
    max_batch: usize,
    otlp: Option<(http::Client, OtlpCfg)>,
    statsd: Option<(UdpSocket, statsd::Renderer, usize)>,
    queue: Option<Arc<SpanQueue>>,
    stats: Arc<Stats>,
    start: SystemTime,
}

fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Worker {
    fn run(mut self, rx: &mpsc::Receiver<Cmd>) {
        let mut next_metrics = Instant::now() + self.interval;
        let mut next_spans = Instant::now() + self.span_interval;
        loop {
            let now = Instant::now();
            let mut wait = next_metrics.saturating_duration_since(now);
            if self.queue.is_some() {
                wait = wait.min(next_spans.saturating_duration_since(now));
            }
            match rx.recv_timeout(wait) {
                Ok(Cmd::Spans) => self.push_spans(false),
                Ok(Cmd::Flush(done)) => {
                    self.push_metrics();
                    self.push_spans(true);
                    let _ = done.send(());
                }
                Ok(Cmd::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(q) = &self.queue {
                        q.open.store(false, Ordering::Relaxed);
                    }
                    self.push_metrics();
                    self.push_spans(true);
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            if now >= next_metrics {
                self.push_metrics();
                next_metrics = (next_metrics + self.interval).max(now + self.interval / 2);
            }
            if now >= next_spans {
                self.push_spans(false);
                next_spans = now + self.span_interval;
            }
        }
    }

    fn snapshot(&self) -> Families {
        let mut f = match &self.telemetry {
            Some(t) => t.collect_all(),
            None => Families::new(),
        };
        for c in &self.collectors {
            f.collect_from(&**c, &[] as &[(&str, &str)]);
        }
        f
    }

    fn push_metrics(&mut self) {
        let want_otlp = self.otlp.as_ref().is_some_and(|(_, c)| c.metrics);
        if !want_otlp && self.statsd.is_none() {
            return;
        }
        let f = self.snapshot();
        if want_otlp {
            if let Some((client, cfg)) = &mut self.otlp {
                let body = cfg.encoding.encode(otlp::metrics_request(
                    &f,
                    &self.resource,
                    self.start,
                    SystemTime::now(),
                ));
                let ok = matches!(
                    client.post("/v1/metrics", cfg.encoding.content_type(), &body),
                    Ok(200..=299)
                );
                inc(if ok {
                    &self.stats.otlp_metrics_ok
                } else {
                    &self.stats.otlp_metrics_failed
                });
            }
        }
        if let Some((sock, r, max)) = &mut self.statsd {
            let lines = r.render(&f);
            self.stats
                .statsd_dropped_series
                .store(r.dropped, Ordering::Relaxed);
            let mut ok = true;
            for p in statsd::packets(&lines, *max) {
                ok &= sock.send(&p).is_ok();
            }
            inc(if ok {
                &self.stats.statsd_ok
            } else {
                &self.stats.statsd_failed
            });
        }
    }

    fn push_spans(&mut self, all: bool) {
        let (Some(q), Some((client, cfg))) = (&self.queue, &mut self.otlp) else {
            return;
        };
        loop {
            let batch = q.drain(self.max_batch);
            if batch.is_empty() {
                return;
            }
            let n = batch.len() as u64;
            let body = cfg
                .encoding
                .encode(otlp::traces_request(&batch, &self.resource));
            let ok = matches!(
                client.post("/v1/traces", cfg.encoding.content_type(), &body),
                Ok(200..=299)
            );
            if ok {
                inc(&self.stats.otlp_traces_ok);
                q.exported.fetch_add(n, Ordering::Relaxed);
            } else {
                inc(&self.stats.otlp_traces_failed);
                q.dropped.fetch_add(n, Ordering::Relaxed);
            }
            if !all && q.queued.load(Ordering::Relaxed) < self.max_batch {
                return;
            }
        }
    }
}

// ---- the handle -----------------------------------------------------------------------------

/// A running exporter (see [`Exporter::builder`]). Dropping it stops the thread after a last
/// push, like [`shutdown`](Self::shutdown).
pub struct Exporter {
    tx: mpsc::SyncSender<Cmd>,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
    stats: Arc<Stats>,
    queue: Option<Arc<SpanQueue>>,
}

impl std::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exporter")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

/// Counters of an [`Exporter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportStats {
    /// OTLP metrics requests answered 2xx.
    pub otlp_metrics_ok: u64,
    /// OTLP metrics requests that failed (connection error, timeout, non-2xx).
    pub otlp_metrics_failed: u64,
    /// OTLP trace requests answered 2xx.
    pub otlp_traces_ok: u64,
    /// OTLP trace requests that failed.
    pub otlp_traces_failed: u64,
    /// StatsD pushes whose datagrams all went out.
    pub statsd_ok: u64,
    /// StatsD pushes where a datagram could not be sent.
    pub statsd_failed: u64,
    /// StatsD series not tracked because the series limit was reached.
    pub statsd_dropped_series: u64,
    /// Spans sent.
    pub spans_exported: u64,
    /// Spans dropped: the queue was full, or their request failed.
    pub spans_dropped: u64,
    /// Spans waiting in the queue.
    pub spans_queued: u64,
}

impl Exporter {
    /// A builder.
    pub fn builder() -> ExporterBuilder {
        ExporterBuilder::default()
    }

    /// Pushes metrics and every queued span now, and waits until that is done.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Cmd::Flush(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Stops the thread after a last push (spans ending later are dropped). Idempotent.
    pub fn shutdown(&self) {
        let h = self.handle.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(h) = h {
            let _ = self.tx.send(Cmd::Stop);
            let _ = h.join();
        }
        if let Some(q) = &self.queue {
            q.open.store(false, Ordering::Relaxed);
            *q.wake.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
    }

    /// The counters.
    pub fn stats(&self) -> ExportStats {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let s = &self.stats;
        let mut o = ExportStats {
            otlp_metrics_ok: l(&s.otlp_metrics_ok),
            otlp_metrics_failed: l(&s.otlp_metrics_failed),
            otlp_traces_ok: l(&s.otlp_traces_ok),
            otlp_traces_failed: l(&s.otlp_traces_failed),
            statsd_ok: l(&s.statsd_ok),
            statsd_failed: l(&s.statsd_failed),
            statsd_dropped_series: l(&s.statsd_dropped_series),
            ..ExportStats::default()
        };
        if let Some(q) = &self.queue {
            o.spans_exported = l(&q.exported);
            o.spans_dropped = l(&q.dropped);
            o.spans_queued = q.queued.load(Ordering::Relaxed) as u64;
        }
        o
    }

    /// A collector reporting [`stats`](Self::stats) as `only_export_*` series (register it
    /// with the telemetry to export or scrape them).
    pub fn collector(&self) -> Arc<dyn Collector> {
        Arc::new(StatsCollector {
            stats: self.stats.clone(),
            queue: self.queue.clone(),
        })
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct StatsCollector {
    stats: Arc<Stats>,
    queue: Option<Arc<SpanQueue>>,
}

impl Collector for StatsCollector {
    fn collect(&self, out: &mut Families) {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64;
        let s = &self.stats;
        for (sink, kind, ok, failed) in [
            (
                "otlp",
                "metrics",
                &s.otlp_metrics_ok,
                &s.otlp_metrics_failed,
            ),
            ("otlp", "traces", &s.otlp_traces_ok, &s.otlp_traces_failed),
            ("statsd", "metrics", &s.statsd_ok, &s.statsd_failed),
        ] {
            for (result, v) in [("ok", ok), ("failed", failed)] {
                out.counter(
                    "only_export_pushes_total",
                    "Pushes by sink, signal and result.",
                    &[("sink", sink), ("signal", kind), ("result", result)],
                    l(v),
                );
            }
        }
        out.counter(
            "only_export_statsd_dropped_series_total",
            "StatsD series not tracked (series limit).",
            &[],
            l(&s.statsd_dropped_series),
        );
        if let Some(q) = &self.queue {
            out.counter(
                "only_export_spans_exported_total",
                "Spans sent.",
                &[],
                l(&q.exported),
            );
            out.counter(
                "only_export_spans_dropped_total",
                "Spans dropped (queue full or request failed).",
                &[],
                l(&q.dropped),
            );
            out.gauge(
                "only_export_spans_queued",
                "Spans waiting to be sent.",
                &[],
                q.queued.load(Ordering::Relaxed) as f64,
            );
        }
    }
}
