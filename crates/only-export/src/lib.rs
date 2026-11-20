#![forbid(unsafe_code)]
//! Push export for [`only`](https://docs.rs/only): metrics, spans and log records to an
//! OpenTelemetry collector over OTLP (HTTP with protobuf or JSON, or gRPC; plain or TLS), and
//! metrics to StatsD / DogStatsD over UDP, from one background thread, without third-party
//! dependencies.
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
//!     .otlp_grpc("https://collector.internal:4317") // or .otlp_http("http://127.0.0.1:4318")
//!     .statsd("127.0.0.1:8125", Flavor::DogStatsd)
//!     .traces(LevelFilter::Info) // install the span tracer: request spans go to OTLP
//!     .logs(LevelFilter::Info) // install a logger: records go to OTLP as LogRecords
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
//! exporter's own thread. Finished spans and log records are handed to bounded, sharded queues
//! (one short uncontended lock per item, never a wait); when a queue is full, items are dropped
//! and counted (`only_export_spans_dropped_total`, `only_export_logs_dropped_total`). The
//! thread sends them in batches every [`span_interval`](ExporterBuilder::span_interval), or
//! earlier once a batch is full. OTLP/gRPC runs on a private engine with one client I/O thread
//! (started on first use); the exporter thread waits for each answer.
//!
//! # Formats
//!
//! * **OTLP** (`POST /v1/metrics`, `/v1/traces`, `/v1/logs`, or the gRPC `Export` methods):
//!   counters as cumulative monotonic sums, gauges, histograms with explicit bounds and
//!   exemplars ([`Histogram::with_exemplars`](only_core::metrics::Histogram::with_exemplars));
//!   spans with their W3C ids, kind, status, fields as attributes, events and links, one
//!   instrumentation scope per span target; log records with severity, body, key-values,
//!   source location and the ids of the span current where they were logged.
//! * **StatsD** (plain or DogStatsD tags): counters as deltas since the last push, gauges as
//!   values, histograms as `.count` / `.sum` / `.bucket` (with an `le` tag) deltas. Spans and
//!   logs are not sent to StatsD.
//!
//! # TLS
//!
//! An `https://` endpoint is reached over only-tls, verified against the system's roots unless
//! [`tls_roots`](ExporterBuilder::tls_roots) gives others; [`tls_client_cert`](ExporterBuilder::tls_client_cert)
//! adds a client certificate (mutual TLS).
//!
//! # Failures
//!
//! A push that fails for a reason that may pass (no connection, a timeout, HTTP 429 / 502 /
//! 503 / 504, gRPC `UNAVAILABLE` and the other retryable codes) puts the collector in backoff:
//! exponential from [`retry`](ExporterBuilder::retry)'s first delay (default 1 s) to its maximum
//! (default 30 s), with jitter, or the server's `Retry-After`. Meanwhile the failed batch of each
//! signal waits to be sent again (until its maximum age, default 5 min, then it is dropped and
//! counted), new spans and records wait in their bounded queues, and metrics are pushed again
//! when the backoff ends (they are cumulative: a fresh snapshot replaces the missed ones). Other
//! failures (HTTP 400, gRPC `INVALID_ARGUMENT` ...) drop the batch at once. Items a collector
//! reports as rejected in a partial success are counted.
#![warn(clippy::unwrap_used)]

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
mod grpc;
mod http;
mod logs;
mod otlp;
mod queue;
#[cfg(test)]
mod roundtrip;
mod statsd;
mod tree;

use std::{
    io,
    net::{ToSocketAddrs, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
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
    LevelFilter, Logger, Metadata,
    span::{self, SpanContext, SpanData, Tracer},
};
use only_tls::{Certificate, ClientConfig, PrivateKey, RootCerts};

use crate::{logs::LogData, otlp::Signal, queue::Queue, tree::Msg};

pub use otlp::Encoding;
pub use statsd::Flavor;

/// Default push interval of metrics.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
/// Default interval of span and log batches.
pub const DEFAULT_SPAN_INTERVAL: Duration = Duration::from_secs(2);
/// Default capacity of the span queue.
pub const DEFAULT_MAX_QUEUED_SPANS: usize = 4096;
/// Default capacity of the log record queue.
pub const DEFAULT_MAX_QUEUED_LOGS: usize = 4096;
/// Default number of spans (or log records) per OTLP request.
pub const DEFAULT_MAX_BATCH: usize = 512;
/// Default largest StatsD datagram.
pub const DEFAULT_MAX_PACKET: usize = 1432;
/// Default number of StatsD series whose last value is remembered (for counter deltas).
pub const DEFAULT_MAX_SERIES: usize = 10_000;
/// Default timeout of each OTLP step (connect, TLS handshake, write, read; a gRPC call).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default first backoff delay after a retryable failure.
pub const DEFAULT_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Default longest backoff delay.
pub const DEFAULT_RETRY_MAX: Duration = Duration::from_secs(30);
/// Default age past which a batch that keeps failing is dropped.
pub const DEFAULT_RETRY_MAX_ELAPSED: Duration = Duration::from_secs(300);

// ---- the span tracer ------------------------------------------------------------------------

/// The tracer installed by [`ExporterBuilder::traces`].
struct QueueTracer {
    queue: Arc<Queue<SpanData>>,
    /// Sampling threshold on the trace id's low 64 bits (`u64::MAX` = everything).
    threshold: u64,
}

impl Tracer for QueueTracer {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        self.queue.open.load(Ordering::Relaxed)
    }

    fn sample(&self, trace_id: u128, parent: Option<&SpanContext>) -> bool {
        match parent {
            Some(p) => p.is_sampled(),
            None => (trace_id as u64) <= self.threshold,
        }
    }

    fn on_end(&self, span: SpanData) {
        self.queue.push(span);
    }
}

// ---- configuration --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Http(Encoding),
    Grpc,
}

#[derive(Clone, Debug)]
struct OtlpCfg {
    endpoint: String,
    protocol: Protocol,
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

#[derive(Clone, Default)]
struct TlsCfg {
    roots: Option<RootCerts>,
    client_cert: Option<(Vec<Certificate>, PrivateKey)>,
    server_name: Option<String>,
}

impl TlsCfg {
    fn is_set(&self) -> bool {
        self.roots.is_some() || self.client_cert.is_some() || self.server_name.is_some()
    }
}

#[derive(Clone, Copy, Debug)]
struct RetryCfg {
    initial: Duration,
    max: Duration,
    max_elapsed: Duration,
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
    tls: TlsCfg,
    retry: RetryCfg,
    statsd: Option<StatsdCfg>,
    traces: Option<LevelFilter>,
    sample_ratio: f64,
    max_queued_spans: usize,
    max_batch: usize,
    logs: Option<LevelFilter>,
    forward_logs: Option<(Arc<dyn Logger>, LevelFilter)>,
    max_queued_logs: usize,
    max_log_batch: usize,
}

impl std::fmt::Debug for ExporterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExporterBuilder")
            .field("resource", &self.resource)
            .field("interval", &self.interval)
            .field("otlp", &self.otlp)
            .field("tls", &self.tls.is_set())
            .field("retry", &self.retry)
            .field("statsd", &self.statsd)
            .field("traces", &self.traces)
            .field("logs", &self.logs)
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
            tls: TlsCfg::default(),
            retry: RetryCfg {
                initial: DEFAULT_RETRY_INITIAL,
                max: DEFAULT_RETRY_MAX,
                max_elapsed: DEFAULT_RETRY_MAX_ELAPSED,
            },
            statsd: None,
            traces: None,
            sample_ratio: 1.0,
            max_queued_spans: DEFAULT_MAX_QUEUED_SPANS,
            max_batch: DEFAULT_MAX_BATCH,
            logs: None,
            forward_logs: None,
            max_queued_logs: DEFAULT_MAX_QUEUED_LOGS,
            max_log_batch: DEFAULT_MAX_BATCH,
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

    /// How often queued spans and log records are sent (default 2 s, at least 10 ms); a full
    /// batch goes earlier.
    pub fn span_interval(mut self, d: Duration) -> ExporterBuilder {
        self.span_interval = d.max(Duration::from_millis(10));
        self
    }

    /// Timeout of each OTLP step: connect, TLS handshake, write, read, or a whole gRPC call
    /// (default 5 s).
    pub fn timeout(mut self, d: Duration) -> ExporterBuilder {
        self.timeout = d;
        self
    }

    /// Sends metrics (and spans and logs, with [`traces`](Self::traces) and
    /// [`logs`](Self::logs)) to an OTLP/HTTP collector at `endpoint` (`http://host:4318` or
    /// `https://...`; `/v1/metrics`, `/v1/traces` and `/v1/logs` are appended), in protobuf.
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
            protocol: Protocol::Http(encoding),
            headers: owned_pairs(headers),
            metrics: true,
        });
        self
    }

    /// Sends metrics (and spans and logs) to an OTLP/gRPC collector at `endpoint`
    /// (`http://host:4317` for h2c, `https://host:4317` for TLS), with the unary `Export`
    /// methods of only-grpc's client. Replaces an OTLP/HTTP endpoint (one OTLP destination).
    pub fn otlp_grpc(self, endpoint: &str) -> ExporterBuilder {
        self.otlp_grpc_with(endpoint, &[])
    }

    /// [`otlp_grpc`](Self::otlp_grpc) with request metadata (`authorization` ...; keys in lower
    /// case).
    pub fn otlp_grpc_with(mut self, endpoint: &str, metadata: &[(&str, &str)]) -> ExporterBuilder {
        self.otlp = Some(OtlpCfg {
            endpoint: endpoint.to_owned(),
            protocol: Protocol::Grpc,
            headers: owned_pairs(metadata),
            metrics: true,
        });
        self
    }

    /// Sends spans and logs to the OTLP endpoint but not metrics (when metrics go to StatsD or
    /// are scraped).
    pub fn otlp_traces_only(mut self) -> ExporterBuilder {
        if let Some(o) = &mut self.otlp {
            o.metrics = false;
        }
        self
    }

    /// For an `https://` endpoint: trust these roots (a private CA) instead of the system's.
    pub fn tls_roots(mut self, roots: RootCerts) -> ExporterBuilder {
        self.tls.roots = Some(roots);
        self
    }

    /// For an `https://` endpoint: present this certificate chain and key when the collector
    /// asks for one (mutual TLS).
    pub fn tls_client_cert(mut self, chain: Vec<Certificate>, key: PrivateKey) -> ExporterBuilder {
        self.tls.client_cert = Some((chain, key));
        self
    }

    /// For an `https://` endpoint: the name sent in SNI and verified in the collector's
    /// certificate (default: the endpoint's host).
    pub fn tls_server_name(mut self, name: &str) -> ExporterBuilder {
        self.tls.server_name = Some(name.to_owned());
        self
    }

    /// Backoff after a retryable OTLP failure: the first delay (default 1 s), doubled per
    /// failure up to `max` (default 30 s), with jitter; a batch is retried until it is
    /// `max_elapsed` old (default 5 min; `Duration::ZERO`: never retried, dropped at the first
    /// failure, the collector still backed off).
    pub fn retry(
        mut self,
        initial: Duration,
        max: Duration,
        max_elapsed: Duration,
    ) -> ExporterBuilder {
        let initial = initial.max(Duration::from_millis(1));
        self.retry = RetryCfg {
            initial,
            max: max.max(initial),
            max_elapsed,
        };
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
    /// `debug`). Needs an OTLP endpoint. A tracer can be installed once per process:
    /// [`start`](Self::start) fails if another one (or an earlier exporter's) is.
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

    /// Installs a logger (the process-wide only-log logger) that sends records up to `level`
    /// to the OTLP endpoint as `LogRecord`s: message as body, key-values as attributes, source
    /// file and line, and the trace and span ids of the span current where the record was
    /// logged. Sets the maximum log level to the more verbose of `level` and the
    /// [`forward_logs`](Self::forward_logs) level (`Config::log_level`, when set, is applied
    /// by the engine later and wins). A logger can be installed once per process:
    /// [`start`](Self::start) fails if one is. Records logged on the exporter's own threads
    /// are not exported.
    pub fn logs(mut self, level: LevelFilter) -> ExporterBuilder {
        self.logs = Some(level);
        self
    }

    /// With [`logs`](Self::logs): also hands records up to `level` to `logger` (an
    /// [`FmtLogger`](only_log::FmtLogger) on stderr, say), which filters them further with its
    /// own `enabled`.
    pub fn forward_logs(
        mut self,
        logger: impl Logger + 'static,
        level: LevelFilter,
    ) -> ExporterBuilder {
        self.forward_logs = Some((Arc::new(logger), level));
        self
    }

    /// Log queue capacity (default 4096; past it records are dropped and counted) and records
    /// per OTLP request (default 512).
    pub fn log_queue(mut self, max_queued: usize, max_batch: usize) -> ExporterBuilder {
        self.max_queued_logs = max_queued.max(1);
        self.max_log_batch = max_batch.max(1);
        self
    }

    fn tls_for(
        &self,
        ep: &http::Endpoint,
        alpn: &str,
    ) -> io::Result<Option<(ClientConfig, String)>> {
        if !ep.tls {
            if self.tls.is_set() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS options need an https:// endpoint",
                ));
            }
            return Ok(None);
        }
        let roots = match &self.tls.roots {
            Some(r) => r.clone(),
            None => RootCerts::system()?,
        };
        let mut b = ClientConfig::builder().roots(roots).alpn([alpn]);
        if let Some((chain, key)) = &self.tls.client_cert {
            b = b.client_cert(chain.clone(), key.clone());
        }
        let name = self
            .tls
            .server_name
            .clone()
            .unwrap_or_else(|| ep.host.clone());
        Ok(Some((b.build()?, name)))
    }

    /// Starts the exporter thread (`only-export`).
    ///
    /// # Errors
    /// An endpoint that does not parse, TLS options without an `https://` endpoint or a TLS
    /// configuration that does not build (no system roots), a StatsD address that does not
    /// resolve or a socket that cannot be opened, [`traces`](Self::traces) or
    /// [`logs`](Self::logs) without OTLP, or a tracer or logger already installed.
    pub fn start(self) -> io::Result<Exporter> {
        let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_owned());
        let otlp = match &self.otlp {
            Some(o) => {
                let ep = http::Endpoint::parse(&o.endpoint)?;
                let sink = match o.protocol {
                    Protocol::Http(enc) => {
                        let tls = self.tls_for(&ep, "http/1.1")?;
                        Sink::Http(
                            http::Client::new(ep, self.timeout, o.headers.clone(), tls),
                            enc,
                        )
                    }
                    Protocol::Grpc => {
                        if !ep.base.is_empty() {
                            return Err(invalid("a gRPC endpoint has no path"));
                        }
                        let tls = self.tls_for(&ep, "h2")?;
                        Sink::Grpc(grpc::Client::new(ep, self.timeout, o.headers.clone(), tls))
                    }
                };
                Some((sink, o.metrics))
            }
            None => {
                if self.tls.is_set() {
                    return Err(invalid("TLS options need an OTLP endpoint"));
                }
                None
            }
        };
        if otlp.is_none() && (self.traces.is_some() || self.logs.is_some()) {
            return Err(invalid("traces and logs need an OTLP endpoint"));
        }
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
        let taken = |what: &str| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("a {what} is already installed in this process"),
            )
        };
        // Check both before installing either: neither can be uninstalled.
        if self.traces.is_some() && span::tracer().is_some() {
            return Err(taken("tracer"));
        }
        if self.logs.is_some() && only_log::logger().is_some() {
            return Err(taken("logger"));
        }
        let (tx, rx) = mpsc::sync_channel::<Cmd>(16);
        let spans = match self.traces {
            Some(level) => {
                let q = Arc::new(Queue::new(
                    self.max_queued_spans,
                    self.max_batch,
                    tx.clone(),
                    || Cmd::Batch,
                ));
                let t = QueueTracer {
                    queue: q.clone(),
                    threshold: ratio_threshold(self.sample_ratio),
                };
                if span::set_boxed_tracer(Box::new(t)).is_err() {
                    return Err(taken("tracer"));
                }
                span::set_max_span_level(level);
                Some(q)
            }
            None => None,
        };
        let logs = match self.logs {
            Some(level) => {
                let q = Arc::new(Queue::new(
                    self.max_queued_logs,
                    self.max_log_batch,
                    tx.clone(),
                    || Cmd::Batch,
                ));
                let fwd_level = self.forward_logs.as_ref().map_or(LevelFilter::Off, |f| f.1);
                let l = logs::OtlpLogger {
                    queue: q.clone(),
                    level,
                    forward: self.forward_logs.clone(),
                };
                if only_log::set_boxed_logger(Box::new(l)).is_err() {
                    q.close();
                    return Err(taken("logger"));
                }
                only_log::set_max_level(level.max(fwd_level));
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
            batch: [0, self.max_batch, self.max_log_batch],
            otlp,
            statsd,
            spans: spans.clone(),
            logs: logs.clone(),
            pending: [None, None, None],
            backoff: Backoff::new(self.retry),
            otlp_metrics_due: false,
            round_failed: false,
            stats: stats.clone(),
            start: SystemTime::now(),
        };
        let handle = thread::Builder::new()
            .name("only-export".into())
            .spawn(move || {
                logs::suppress_this_thread();
                worker.run(&rx);
            })?;
        Ok(Exporter {
            tx,
            handle: Mutex::new(Some(handle)),
            stats,
            spans,
            logs,
        })
    }
}

fn owned_pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn ratio_threshold(r: f64) -> u64 {
    if r >= 1.0 {
        u64::MAX
    } else {
        (r * u64::MAX as f64) as u64
    }
}

// ---- the OTLP sink and its backoff ----------------------------------------------------------

/// Where OTLP requests go.
enum Sink {
    Http(http::Client, Encoding),
    Grpc(grpc::Client),
}

/// What became of one request.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Accepted; this many items were rejected (partial success).
    Sent(u64),
    /// Failed in a way that may pass: back off (for this long, if the server said).
    Retry(Option<Duration>),
    /// Failed for good: drop it.
    Failed,
}

impl Sink {
    fn encode(&self, root: Msg) -> Vec<u8> {
        match self {
            Sink::Http(_, enc) => enc.encode(root),
            Sink::Grpc(_) => Encoding::Protobuf.encode(root),
        }
    }

    fn send(&mut self, sig: Signal, body: &[u8]) -> Outcome {
        match self {
            Sink::Http(c, enc) => match c.post(sig.http_path(), enc.content_type(), body) {
                Ok(r) => match r.status {
                    200..=299 => Outcome::Sent(if *enc == Encoding::Protobuf {
                        otlp::partial_success(&r.body).0
                    } else {
                        0
                    }),
                    429 | 502 | 503 | 504 => Outcome::Retry(r.retry_after),
                    _ => Outcome::Failed,
                },
                Err(_) => Outcome::Retry(None),
            },
            Sink::Grpc(c) => match c.export(sig.grpc_path(), body) {
                grpc::Answer::Ok(resp) => Outcome::Sent(otlp::partial_success(&resp).0),
                grpc::Answer::Retry => Outcome::Retry(None),
                grpc::Answer::Fail => Outcome::Failed,
            },
        }
    }

    fn close(&mut self) {
        if let Sink::Grpc(c) = self {
            c.close();
        }
    }
}

/// Exponential backoff with jitter, shared by the signals (they go to one collector).
#[derive(Debug)]
struct Backoff {
    cfg: RetryCfg,
    /// The last delay (zero while things work).
    delay: Duration,
    until: Option<Instant>,
    rng: u64,
}

impl Backoff {
    fn new(cfg: RetryCfg) -> Backoff {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64)
            | 1;
        Backoff {
            cfg,
            delay: Duration::ZERO,
            until: None,
            rng: seed,
        }
    }

    fn waiting(&self, now: Instant) -> bool {
        self.until.is_some_and(|u| now < u)
    }

    /// The last attempt failed.
    fn failing(&self) -> bool {
        !self.delay.is_zero()
    }

    fn ok(&mut self) {
        self.delay = Duration::ZERO;
        self.until = None;
    }

    /// Records a failure; `hint` is the server's `Retry-After`.
    fn failed(&mut self, hint: Option<Duration>) -> Duration {
        self.delay = if self.delay.is_zero() {
            self.cfg.initial
        } else {
            (self.delay * 2).min(self.cfg.max)
        };
        // xorshift; jitter: a delay between half and all of the nominal one.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let frac = 0.5 + (self.rng >> 11) as f64 / (1u64 << 53) as f64 / 2.0;
        let d = match hint {
            Some(h) => h.min(self.cfg.max_elapsed.max(self.cfg.max)),
            None => self.delay.mul_f64(frac),
        };
        self.until = Some(Instant::now() + d);
        d
    }
}

// ---- the exporter thread --------------------------------------------------------------------

pub(crate) enum Cmd {
    /// A queue holds a full batch.
    Batch,
    /// Push everything now and answer.
    Flush(mpsc::Sender<()>),
    /// A last push, then end.
    Stop,
}

#[derive(Default, Debug)]
struct Stats {
    ok: [AtomicU64; 3],
    failed: [AtomicU64; 3],
    retried: AtomicU64,
    metric_points_rejected: AtomicU64,
    statsd_ok: AtomicU64,
    statsd_failed: AtomicU64,
    statsd_dropped_series: AtomicU64,
}

/// A batch waiting to be sent again.
struct Pending {
    body: Vec<u8>,
    items: usize,
    since: Instant,
}

struct Worker {
    resource: Vec<(String, String)>,
    telemetry: Option<Arc<Telemetry>>,
    collectors: Vec<Arc<dyn Collector>>,
    interval: Duration,
    span_interval: Duration,
    /// Items per request, by signal.
    batch: [usize; 3],
    otlp: Option<(Sink, bool)>,
    statsd: Option<(UdpSocket, statsd::Renderer, usize)>,
    spans: Option<Arc<Queue<SpanData>>>,
    logs: Option<Arc<Queue<LogData>>>,
    /// A failed batch per signal (traces, logs), retried after the backoff.
    pending: [Option<Pending>; 3],
    backoff: Backoff,
    /// OTLP metrics were skipped during a backoff: push them when it ends.
    otlp_metrics_due: bool,
    /// In a flush or the last push: a retryable failure ends the round (no waiting for every
    /// signal's timeout on a dead collector).
    round_failed: bool,
    stats: Arc<Stats>,
    start: SystemTime,
}

fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Worker {
    fn has_queues(&self) -> bool {
        self.spans.is_some() || self.logs.is_some()
    }

    fn run(mut self, rx: &mpsc::Receiver<Cmd>) {
        let mut next_metrics = Instant::now() + self.interval;
        let mut next_batch = Instant::now() + self.span_interval;
        loop {
            let now = Instant::now();
            let mut wait = next_metrics.saturating_duration_since(now);
            if self.has_queues() {
                wait = wait.min(next_batch.saturating_duration_since(now));
            }
            if let Some(u) = self.backoff.until {
                if u > now {
                    wait = wait.min(u - now);
                }
            }
            match rx.recv_timeout(wait) {
                Ok(Cmd::Batch) => self.push_queues(false, false),
                Ok(Cmd::Flush(done)) => {
                    self.round_failed = false;
                    self.push_metrics(true);
                    self.push_queues(true, true);
                    self.round_failed = false;
                    let _ = done.send(());
                }
                Ok(Cmd::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(q) = &self.spans {
                        q.close();
                    }
                    if let Some(q) = &self.logs {
                        q.close();
                    }
                    self.round_failed = false;
                    self.push_metrics(true);
                    self.push_queues(true, true);
                    if let Some((s, _)) = &mut self.otlp {
                        s.close();
                    }
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            if now >= next_metrics {
                self.push_metrics(false);
                next_metrics = (next_metrics + self.interval).max(now + self.interval / 2);
            } else if self.otlp_metrics_due && !self.backoff.waiting(now) {
                self.push_otlp_metrics(&self.snapshot(), false);
            }
            if now >= next_batch {
                self.push_queues(false, false);
                next_batch = now + self.span_interval;
            } else if !self.backoff.waiting(now) && self.after_failure() {
                // The backoff ended: send what waited (the failed batch, the queues) now
                // rather than at the next interval.
                self.push_queues(false, false);
            }
        }
    }

    /// A batch waits to be retried, or the collector failed last and items are queued.
    fn after_failure(&self) -> bool {
        self.pending.iter().any(Option::is_some)
            || (self.backoff.failing()
                && (self.spans.as_ref().is_some_and(|q| q.len() > 0)
                    || self.logs.as_ref().is_some_and(|q| q.len() > 0)))
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

    /// The scheduled push (or a forced one: flush, stop).
    fn push_metrics(&mut self, force: bool) {
        let want_otlp = self.otlp.as_ref().is_some_and(|(_, m)| *m);
        if !want_otlp && self.statsd.is_none() {
            return;
        }
        let f = self.snapshot();
        if want_otlp {
            self.push_otlp_metrics(&f, force);
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

    fn push_otlp_metrics(&mut self, f: &Families, force: bool) {
        let i = Signal::Metrics.index();
        if self.round_failed || (!force && self.backoff.waiting(Instant::now())) {
            self.otlp_metrics_due = true;
            return;
        }
        let Some((sink, _)) = &mut self.otlp else {
            return;
        };
        let root = otlp::metrics_request(f, &self.resource, self.start, SystemTime::now());
        let body = sink.encode(root);
        match sink.send(Signal::Metrics, &body) {
            Outcome::Sent(rejected) => {
                inc(&self.stats.ok[i]);
                self.stats
                    .metric_points_rejected
                    .fetch_add(rejected, Ordering::Relaxed);
                self.backoff.ok();
                self.otlp_metrics_due = false;
            }
            Outcome::Retry(hint) => {
                inc(&self.stats.failed[i]);
                inc(&self.stats.retried);
                self.backoff.failed(hint);
                self.otlp_metrics_due = true;
                self.round_failed |= force;
            }
            Outcome::Failed => {
                inc(&self.stats.failed[i]);
                self.otlp_metrics_due = false;
            }
        }
    }

    fn push_queues(&mut self, all: bool, force: bool) {
        if let Some(q) = self.spans.clone() {
            self.push_signal(Signal::Traces, &q, all, force, otlp::traces_request);
        }
        if let Some(q) = self.logs.clone() {
            self.push_signal(Signal::Logs, &q, all, force, otlp::logs_request);
        }
    }

    /// Sends batches of `q` (and first its pending batch): one, or until the queue holds less
    /// than a batch, or everything (`all`).
    fn push_signal<T>(
        &mut self,
        sig: Signal,
        q: &Queue<T>,
        all: bool,
        force: bool,
        build: impl Fn(&[T], &[(String, String)]) -> Msg,
    ) {
        let i = sig.index();
        let max = self.batch[i];
        loop {
            if self.round_failed || (!force && self.backoff.waiting(Instant::now())) {
                return;
            }
            let Some((sink, _)) = &mut self.otlp else {
                return;
            };
            let p = match self.pending[i].take() {
                Some(p) => p,
                None => {
                    let batch = q.drain(max);
                    if batch.is_empty() {
                        return;
                    }
                    Pending {
                        body: sink.encode(build(&batch, &self.resource)),
                        items: batch.len(),
                        since: Instant::now(),
                    }
                }
            };
            q.pending.store(p.items, Ordering::Relaxed);
            let n = p.items as u64;
            match sink.send(sig, &p.body) {
                Outcome::Sent(rejected) => {
                    inc(&self.stats.ok[i]);
                    let rejected = rejected.min(n);
                    q.exported.fetch_add(n - rejected, Ordering::Relaxed);
                    q.rejected.fetch_add(rejected, Ordering::Relaxed);
                    q.pending.store(0, Ordering::Relaxed);
                    self.backoff.ok();
                }
                Outcome::Retry(hint) => {
                    inc(&self.stats.failed[i]);
                    self.backoff.failed(hint);
                    self.round_failed |= force;
                    if p.since.elapsed() >= self.backoff.cfg.max_elapsed {
                        q.dropped.fetch_add(n, Ordering::Relaxed);
                        q.pending.store(0, Ordering::Relaxed);
                    } else {
                        inc(&self.stats.retried);
                        self.pending[i] = Some(p);
                    }
                    return;
                }
                Outcome::Failed => {
                    inc(&self.stats.failed[i]);
                    q.dropped.fetch_add(n, Ordering::Relaxed);
                    q.pending.store(0, Ordering::Relaxed);
                }
            }
            if !all && q.len() < max {
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
    spans: Option<Arc<Queue<SpanData>>>,
    logs: Option<Arc<Queue<LogData>>>,
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
    /// OTLP metrics requests accepted.
    pub otlp_metrics_ok: u64,
    /// OTLP metrics requests that failed (connection error, timeout, non-2xx, gRPC error).
    pub otlp_metrics_failed: u64,
    /// OTLP trace requests accepted.
    pub otlp_traces_ok: u64,
    /// OTLP trace requests that failed.
    pub otlp_traces_failed: u64,
    /// OTLP log requests accepted.
    pub otlp_logs_ok: u64,
    /// OTLP log requests that failed.
    pub otlp_logs_failed: u64,
    /// Failed OTLP requests that will be tried again after the backoff.
    pub otlp_retried: u64,
    /// Metric data points the collector rejected (partial success).
    pub metric_points_rejected: u64,
    /// StatsD pushes whose datagrams all went out.
    pub statsd_ok: u64,
    /// StatsD pushes where a datagram could not be sent.
    pub statsd_failed: u64,
    /// StatsD series not tracked because the series limit was reached.
    pub statsd_dropped_series: u64,
    /// Spans sent and accepted.
    pub spans_exported: u64,
    /// Spans dropped: the queue was full, their request failed for good, or kept failing
    /// past the retry limit.
    pub spans_dropped: u64,
    /// Spans the collector rejected (partial success).
    pub spans_rejected: u64,
    /// Spans waiting: in the queue, or in the batch to be retried.
    pub spans_queued: u64,
    /// Log records sent and accepted.
    pub logs_exported: u64,
    /// Log records dropped (as for spans).
    pub logs_dropped: u64,
    /// Log records the collector rejected (partial success).
    pub logs_rejected: u64,
    /// Log records waiting: in the queue, or in the batch to be retried.
    pub logs_queued: u64,
}

fn queue_counts<T>(q: &Queue<T>) -> (u64, u64, u64, u64) {
    let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
    (
        l(&q.exported),
        l(&q.dropped),
        l(&q.rejected),
        (q.len() + q.pending.load(Ordering::Relaxed)) as u64,
    )
}

impl Exporter {
    /// A builder.
    pub fn builder() -> ExporterBuilder {
        ExporterBuilder::default()
    }

    /// Pushes metrics and every queued span and log record now (ignoring a backoff), and waits
    /// until that is done. A retryable failure ends the flush; what was not sent stays queued.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Cmd::Flush(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Stops the thread after a last push (spans and records ending later are dropped).
    /// Idempotent.
    pub fn shutdown(&self) {
        let h = self.handle.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(h) = h {
            let _ = self.tx.send(Cmd::Stop);
            let _ = h.join();
        }
        if let Some(q) = &self.spans {
            q.close();
        }
        if let Some(q) = &self.logs {
            q.close();
        }
    }

    /// The counters.
    pub fn stats(&self) -> ExportStats {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let s = &self.stats;
        let (m, t, g) = (
            Signal::Metrics.index(),
            Signal::Traces.index(),
            Signal::Logs.index(),
        );
        let mut o = ExportStats {
            otlp_metrics_ok: l(&s.ok[m]),
            otlp_metrics_failed: l(&s.failed[m]),
            otlp_traces_ok: l(&s.ok[t]),
            otlp_traces_failed: l(&s.failed[t]),
            otlp_logs_ok: l(&s.ok[g]),
            otlp_logs_failed: l(&s.failed[g]),
            otlp_retried: l(&s.retried),
            metric_points_rejected: l(&s.metric_points_rejected),
            statsd_ok: l(&s.statsd_ok),
            statsd_failed: l(&s.statsd_failed),
            statsd_dropped_series: l(&s.statsd_dropped_series),
            ..ExportStats::default()
        };
        if let Some(q) = &self.spans {
            (
                o.spans_exported,
                o.spans_dropped,
                o.spans_rejected,
                o.spans_queued,
            ) = queue_counts(q);
        }
        if let Some(q) = &self.logs {
            (
                o.logs_exported,
                o.logs_dropped,
                o.logs_rejected,
                o.logs_queued,
            ) = queue_counts(q);
        }
        o
    }

    /// A collector reporting [`stats`](Self::stats) as `only_export_*` series (register it
    /// with the telemetry to export or scrape them).
    pub fn collector(&self) -> Arc<dyn Collector> {
        Arc::new(StatsCollector {
            stats: self.stats.clone(),
            spans: self.spans.clone(),
            logs: self.logs.clone(),
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
    spans: Option<Arc<Queue<SpanData>>>,
    logs: Option<Arc<Queue<LogData>>>,
}

fn queue_series<T>(out: &mut Families, what: &str, q: &Queue<T>) {
    let (exported, dropped, rejected, queued) = queue_counts(q);
    out.counter(
        &format!("only_export_{what}_exported_total"),
        "Items sent and accepted.",
        &[],
        exported as f64,
    );
    out.counter(
        &format!("only_export_{what}_dropped_total"),
        "Items dropped (queue full, request failed for good or past the retry limit).",
        &[],
        dropped as f64,
    );
    out.counter(
        &format!("only_export_{what}_rejected_total"),
        "Items the collector rejected (partial success).",
        &[],
        rejected as f64,
    );
    out.gauge(
        &format!("only_export_{what}_queued"),
        "Items waiting to be sent (queued or to be retried).",
        &[],
        queued as f64,
    );
}

impl Collector for StatsCollector {
    fn collect(&self, out: &mut Families) {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64;
        let s = &self.stats;
        for (sig, kind) in [
            (Signal::Metrics, "metrics"),
            (Signal::Traces, "traces"),
            (Signal::Logs, "logs"),
        ] {
            for (result, v) in [
                ("ok", &s.ok[sig.index()]),
                ("failed", &s.failed[sig.index()]),
            ] {
                out.counter(
                    "only_export_pushes_total",
                    "Pushes by sink, signal and result.",
                    &[("sink", "otlp"), ("signal", kind), ("result", result)],
                    l(v),
                );
            }
        }
        for (result, v) in [("ok", &s.statsd_ok), ("failed", &s.statsd_failed)] {
            out.counter(
                "only_export_pushes_total",
                "Pushes by sink, signal and result.",
                &[
                    ("sink", "statsd"),
                    ("signal", "metrics"),
                    ("result", result),
                ],
                l(v),
            );
        }
        out.counter(
            "only_export_otlp_retries_total",
            "Failed OTLP requests to be tried again after a backoff.",
            &[],
            l(&s.retried),
        );
        out.counter(
            "only_export_metric_points_rejected_total",
            "Metric data points the collector rejected (partial success).",
            &[],
            l(&s.metric_points_rejected),
        );
        out.counter(
            "only_export_statsd_dropped_series_total",
            "StatsD series not tracked (series limit).",
            &[],
            l(&s.statsd_dropped_series),
        );
        if let Some(q) = &self.spans {
            queue_series(out, "spans", q);
        }
        if let Some(q) = &self.logs {
            queue_series(out, "logs", q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_with_jitter_and_honours_retry_after() {
        let mut b = Backoff::new(RetryCfg {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(400),
            max_elapsed: Duration::from_secs(1),
        });
        let now = Instant::now();
        assert!(!b.waiting(now));
        let mut nominal = Duration::from_millis(100);
        for _ in 0..6 {
            let d = b.failed(None);
            assert!(d >= nominal / 2 && d <= nominal, "{d:?} vs {nominal:?}");
            assert!(b.waiting(Instant::now()));
            nominal = (nominal * 2).min(Duration::from_millis(400));
        }
        // Retry-After wins, capped at the retry limit.
        assert_eq!(
            b.failed(Some(Duration::from_millis(700))),
            Duration::from_millis(700)
        );
        assert_eq!(
            b.failed(Some(Duration::from_secs(60))),
            Duration::from_secs(1)
        );
        b.ok();
        assert!(!b.waiting(Instant::now()));
        assert!(b.failed(None) <= Duration::from_millis(100));
    }
}
