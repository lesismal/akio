//! Observability and live settings of one engine: metrics, the connection table, per-thread loop
//! statistics, slow-callback records and the settings that can change without a restart.
//!
//! Every engine owns one [`Telemetry`] (reachable as `Config::telemetry` before the engine is
//! built and as `Engine::telemetry()` after). The I/O threads update plain per-thread counters
//! with relaxed atomics; nothing is locked or allocated per event. Snapshots
//! ([`Telemetry::metrics`], [`Telemetry::connections`]) are assembled on demand.

use std::{
    collections::VecDeque,
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime},
};

use crate::{
    Config, Pool, PoolStats, SlowCallback, SlowHook,
    metrics::{Collector, CollectorId, Families},
};

/// How many slow-callback records [`Telemetry::slow_callbacks`] keeps (oldest dropped first).
pub const SLOW_RING: usize = 256;

/// A monotonically increasing (or, for gauges, adjustable) counter. Relaxed atomics: readers on
/// other threads see a recent value, never a torn one.
#[derive(Default, Debug)]
#[doc(hidden)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Adds `n`; safe from any thread.
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` when only one thread ever writes this counter (the owning I/O thread): a plain
    /// load and store, no read-modify-write instruction.
    #[inline]
    pub fn add_local(&self, n: u64) {
        self.0.store(
            self.0.load(Ordering::Relaxed).wrapping_add(n),
            Ordering::Relaxed,
        );
    }

    /// Subtracts `n` (gauges); safe from any thread.
    #[inline]
    pub fn sub(&self, n: u64) {
        self.0.fetch_sub(n, Ordering::Relaxed);
    }

    /// Current value.
    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Which I/O thread a connection, a slow callback or a metrics row belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoopMeta {
    /// Backend name: `epoll`, `kqueue`, `io_uring` or `udp`.
    pub backend: &'static str,
    /// The listener this thread serves (`None` for client-only threads).
    pub listener: Option<SocketAddr>,
    /// Index of the thread within its listener's group.
    pub thread: usize,
}

impl LoopMeta {
    /// Backend-facing constructor.
    #[doc(hidden)]
    pub fn new(backend: &'static str, listener: Option<SocketAddr>, thread: usize) -> LoopMeta {
        LoopMeta {
            backend,
            listener,
            thread,
        }
    }
}

macro_rules! loop_counters {
    ($( $(#[$m:meta])* $field:ident : $kind:literal, $prom:literal, $help:literal; )*) => {
        /// Live counters of one I/O thread. Backend-facing (updated by the loops); read them
        /// through [`Telemetry::metrics`].
        #[derive(Debug)]
        #[doc(hidden)]
        #[repr(align(128))] // threads' counters never share a cache line
        pub struct LoopStats {
            meta: LoopMeta,
            running: AtomicBool,
            retiring: AtomicBool,
            /// Connections handed to this thread by another one at accept time (ADR-105) and
            /// not opened here yet.
            incoming: AtomicU64,
            $( #[doc(hidden)] pub $field: Counter, )*
        }

        /// Counters of one I/O thread (or a sum of several) in a [`Metrics`] snapshot.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        #[non_exhaustive]
        pub struct LoopCounters {
            $( $(#[$m])* pub $field: u64, )*
        }

        impl LoopStats {
            /// Counters of a thread described by `meta`.
            pub fn new(meta: LoopMeta) -> LoopStats {
                LoopStats { meta, running: AtomicBool::new(false), retiring: AtomicBool::new(false), incoming: AtomicU64::new(0), $( $field: Counter::default(), )* }
            }

            /// Copies the counters.
            pub fn snapshot(&self) -> LoopCounters {
                LoopCounters { $( $field: self.$field.get(), )* }
            }
        }

        impl LoopCounters {
            /// Field-wise sum.
            pub fn add(&mut self, o: &LoopCounters) {
                $( self.$field = self.$field.wrapping_add(o.$field); )*
            }

            /// `(prometheus name, type, help)` of every field, in declaration order.
            const FIELDS: &'static [(&'static str, &'static str, &'static str)] =
                &[ $( ($prom, $kind, $help), )* ];

            fn values(&self) -> Vec<u64> {
                vec![ $( self.$field, )* ]
            }

            fn names() -> &'static [&'static str] {
                &[ $( stringify!($field), )* ]
            }
        }
    };
}

loop_counters! {
    /// Connections accepted (UDP: peers seen for the first time).
    accepted: "counter", "akio_connections_accepted_total", "Connections accepted (UDP: new peers).";
    /// Connections established with `Engine::dial`/`dial_udp`.
    dialed: "counter", "akio_connections_dialed_total", "Connections established by dialing.";
    /// Connections closed (after `on_close`).
    closed: "counter", "akio_connections_closed_total", "Connections closed.";
    /// Connections refused because `max_connections` was reached.
    rejected: "counter", "akio_connections_rejected_total", "Connections refused by max_connections.";
    /// Connections refused by the listener's accept filter (`Listener::filter`).
    filtered: "counter", "akio_connections_filtered_total", "Connections refused by the listener's accept filter.";
    /// `accept(2)` failures (EMFILE...).
    accept_errors: "counter", "akio_accept_errors_total", "accept(2) failures.";
    /// Connections closed by the idle timeout.
    idle_timeouts: "counter", "akio_idle_timeouts_total", "Connections closed by the idle timeout.";
    /// Connections closed by the write timeout.
    write_timeouts: "counter", "akio_write_timeouts_total", "Connections closed by the write timeout.";
    /// Bytes read from sockets.
    bytes_in: "counter", "akio_read_bytes_total", "Bytes read from sockets.";
    /// Successful reads (UDP: datagrams received).
    reads: "counter", "akio_reads_total", "Successful socket reads.";
    /// Bytes written to sockets.
    bytes_out: "counter", "akio_written_bytes_total", "Bytes written to sockets.";
    /// Successful writes (`write`, `writev`, `sendfile`, `send_to`).
    writes: "counter", "akio_writes_total", "Successful socket writes.";
    /// UDP datagrams received.
    datagrams_in: "counter", "akio_udp_datagrams_received_total", "UDP datagrams received.";
    /// UDP datagrams sent.
    datagrams_out: "counter", "akio_udp_datagrams_sent_total", "UDP datagrams sent.";
    /// Bytes queued for sending right now (gauge).
    queued_bytes: "gauge", "akio_send_queue_bytes", "Bytes queued for sending.";
    /// Times a connection's reads were paused because its send queue reached the high watermark.
    backpressure: "counter", "akio_backpressure_events_total", "Reads paused by send-queue backpressure.";
    /// Sends refused with `Error::Overloaded` (`max_queued_bytes`).
    overloaded: "counter", "akio_overloaded_total", "Sends refused because the queue was full.";
    /// Connections whose transport (TLS) failed during its handshake.
    handshake_failures: "counter", "akio_tls_handshake_failures_total", "Transport (TLS) handshakes that failed.";
    /// Connections whose transport (TLS) failed after its handshake.
    transport_errors: "counter", "akio_transport_errors_total", "Transport (TLS) errors after the handshake.";
    /// Event-loop iterations (one poll/submit-and-wait each).
    iterations: "counter", "akio_loop_iterations_total", "Event loop iterations.";
    /// Readiness events / completions processed.
    events: "counter", "akio_loop_events_total", "Readiness events or completions processed.";
    /// Handler callbacks run (`on_data`, `on_close`, completions).
    callbacks: "counter", "akio_loop_callbacks_total", "Handler callbacks run on I/O threads.";
    /// Time spent in handler callbacks, in nanoseconds (measured while a slow-callback threshold
    /// is set, which is the default).
    callback_ns: "nanos", "akio_loop_callback_seconds_total", "Time spent in handler callbacks.";
    /// Callbacks longer than the slow-callback threshold.
    slow_callbacks: "counter", "akio_slow_callbacks_total", "Callbacks longer than the slow-callback threshold.";
}

impl LoopStats {
    /// Which thread this is.
    pub fn meta(&self) -> &LoopMeta {
        &self.meta
    }

    /// Marks the thread as running (`true`) or exited.
    pub fn set_running(&self, r: bool) {
        self.running.store(r, Ordering::Release);
    }

    /// Whether the thread is running.
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Marks the thread as retiring (`Engine::set_threads` shrank its group: it takes no new
    /// connections and exits once its own are closed) or active again.
    pub fn set_retiring(&self, r: bool) {
        self.retiring.store(r, Ordering::Release);
    }

    /// Whether the thread is retiring.
    pub fn retiring(&self) -> bool {
        self.retiring.load(Ordering::Acquire)
    }

    /// Connections open on this thread now, plus those handed to it and not opened yet: what
    /// accept-time balancing (ADR-105) compares. Readable from any thread.
    pub fn load(&self) -> u64 {
        (self.accepted.get() + self.dialed.get())
            .saturating_sub(self.closed.get())
            .saturating_add(self.incoming.load(Ordering::Relaxed))
    }

    /// Another thread is handing this one a connection (counted in [`load`](Self::load) until
    /// [`handoff_done`](Self::handoff_done)).
    pub fn handoff_begin(&self) {
        self.incoming.fetch_add(1, Ordering::Relaxed);
    }

    /// A connection handed to this thread arrived (opened here, passed on or dropped).
    pub fn handoff_done(&self) {
        // Never below zero, even if a command is ever delivered twice.
        let _ = self
            .incoming
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    }

    /// Counts one received datagram of `n` bytes.
    #[inline]
    pub fn datagram_in(&self, n: usize) {
        self.reads.add_local(1);
        self.bytes_in.add_local(n as u64);
        self.datagrams_in.add_local(1);
    }

    /// Records one finished callback started at `t0` (`None` when timing is off).
    #[inline]
    pub fn callback(&self, t0: Option<Instant>) -> Option<Duration> {
        self.callbacks.add_local(1);
        let d = t0?.elapsed();
        self.callback_ns.add_local(d.as_nanos() as u64);
        Some(d)
    }
}

/// A request a [`Telemetry`] sends to an I/O thread. Backend-facing.
#[doc(hidden)]
pub enum LoopCmd {
    /// Describe every connection of the thread.
    Inspect(Box<dyn FnOnce(Vec<ConnInfo>) + Send>),
    /// Live settings changed: re-arm timers, re-evaluate backpressure.
    Reload,
}

impl std::fmt::Debug for LoopCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopCmd").finish_non_exhaustive()
    }
}

struct LoopEntry {
    stats: Arc<LoopStats>,
    post: Box<dyn Fn(LoopCmd) + Send + Sync>,
}

/// One row of the connection table ([`Telemetry::connections`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConnInfo {
    /// Connection id (as in [`SlowCallback::conn_id`]).
    pub id: u64,
    /// Remote address.
    pub peer: SocketAddr,
    /// Local address.
    pub local: SocketAddr,
    /// Thread that owns it.
    pub owner: LoopMeta,
    /// Time since it opened.
    pub age: Duration,
    /// Time since data last arrived.
    pub idle: Duration,
    /// Bytes read.
    pub bytes_in: u64,
    /// Bytes written.
    pub bytes_out: u64,
    /// Bytes queued for sending.
    pub queued_bytes: usize,
    /// The handler paused reads (`hold_reads`).
    pub read_held: bool,
    /// Reads are paused by backpressure.
    pub backpressure: bool,
    /// Name of the transport layer (`"tls"`), if any.
    pub transport: Option<&'static str>,
    /// A UDP peer rather than a TCP connection.
    pub udp: bool,
}

impl ConnInfo {
    /// Backend-facing: the row for connection `id`, with what `inner` knows filled in; the
    /// backend sets `age`, `idle`, `bytes_in` and `backpressure`.
    #[doc(hidden)]
    pub fn new(id: u64, inner: &crate::ConnInner, owner: LoopMeta) -> ConnInfo {
        let (bytes_out, queued_bytes, transport, udp) = inner.debug_state();
        ConnInfo {
            id,
            peer: inner.peer_addr(),
            local: inner.local_addr(),
            owner,
            age: Duration::ZERO,
            idle: Duration::ZERO,
            bytes_in: 0,
            bytes_out,
            queued_bytes,
            read_held: inner.read_held(),
            backpressure: false,
            transport,
            udp,
        }
    }
}

/// One slow callback (see [`Telemetry::slow_callbacks`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SlowRecord {
    /// When it was reported.
    pub at: SystemTime,
    /// Which callback.
    pub kind: &'static str,
    /// Its connection.
    pub conn_id: u64,
    /// How long it ran.
    pub elapsed: Duration,
    /// The threshold in force.
    pub threshold: Duration,
    /// The I/O thread it blocked.
    pub owner: LoopMeta,
}

/// The settings that take effect without a restart. Change them with the setters (or
/// `Engine::reload`); the I/O threads read them on every use (one relaxed load), or, for the
/// read buffer, the listen backlog and the UDP idle timeout, when they are told settings
/// changed. After changing anything but the queue limit, the connection limit, the slow-callback
/// settings and the shutdown timeout through a setter, call [`Telemetry::notify_reload`] so the
/// I/O threads apply it to what is already open ([`Telemetry::reload`] does this itself):
///
/// * `idle_timeout`, `udp_idle_timeout`: idle timers of open connections and UDP peers are
///   re-armed against the new value.
/// * `write_high_watermark`: backpressure is re-evaluated.
/// * `read_buffer`: each I/O thread replaces its read buffer between two batches of events, when
///   no `on_data` holds a borrow of it, so open connections get the new size at their next read
///   (io_uring: a new provided-buffer group; each connection moves to it when its multishot
///   receive is re-armed). UDP threads with GRO on keep at least 64 KiB.
/// * `backlog`: every listening socket is `listen(2)`ed again with the new value.
///
/// Not reloadable (fixed when the engine is built): `max_pending_responses`, `write_timeout`,
/// `connect_timeout`, `udp_max_peers`, `udp_gro`, listeners, backends and pool sizes. Thread
/// counts change with `Engine::set_threads` (ADR-028).
pub struct Live {
    idle_ms: AtomicU64,
    slow_ns: AtomicU64,
    slow_hook: RwLock<Option<SlowHook>>,
    max_queued: AtomicUsize,
    high_wm: AtomicUsize,
    max_conns: AtomicUsize,
    shutdown_ms: AtomicU64,
    read_buffer: AtomicUsize,
    backlog: AtomicI32,
    udp_idle_ms: AtomicU64,
    retire_ms: AtomicU64,
}

fn opt_ms(d: Option<Duration>) -> u64 {
    d.map_or(0, |d| (d.as_millis() as u64).max(1))
}

impl Default for Live {
    /// The values of `Config::default()`.
    fn default() -> Live {
        use crate::config::*;
        Live {
            idle_ms: AtomicU64::new(0),
            slow_ns: AtomicU64::new(DEFAULT_SLOW_CALLBACK.as_nanos() as u64),
            slow_hook: RwLock::new(None),
            max_queued: AtomicUsize::new(DEFAULT_MAX_QUEUED_BYTES),
            high_wm: AtomicUsize::new(DEFAULT_WRITE_HIGH_WATERMARK),
            max_conns: AtomicUsize::new(0),
            shutdown_ms: AtomicU64::new(DEFAULT_SHUTDOWN_TIMEOUT.as_millis() as u64),
            read_buffer: AtomicUsize::new(DEFAULT_READ_BUFFER),
            backlog: AtomicI32::new(DEFAULT_BACKLOG),
            udp_idle_ms: AtomicU64::new(DEFAULT_UDP_IDLE_TIMEOUT.as_millis() as u64),
            retire_ms: AtomicU64::new(0),
        }
    }
}

impl Live {
    fn apply(&self, c: &Config) {
        self.set_idle_timeout(c.idle_timeout);
        self.set_slow_callback_threshold(c.slow_callback_threshold);
        self.set_slow_hook(c.slow_hook.clone());
        self.set_max_queued_bytes(c.max_queued_bytes);
        self.set_write_high_watermark(c.write_high_watermark);
        self.set_max_connections(c.max_connections);
        self.set_shutdown_timeout(c.shutdown_timeout);
        self.set_read_buffer(c.read_buffer);
        self.set_backlog(c.backlog);
        self.set_udp_idle_timeout(c.udp_idle_timeout);
        self.set_retire_timeout(c.retire_timeout);
    }

    /// Current `Config::idle_timeout`.
    #[inline]
    pub fn idle_timeout(&self) -> Option<Duration> {
        match self.idle_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Idle timeout in milliseconds, 0 when off.
    #[doc(hidden)]
    #[inline]
    #[doc(hidden)]
    pub fn idle_ms(&self) -> u64 {
        self.idle_ms.load(Ordering::Relaxed)
    }

    /// Sets the idle timeout (applies to open connections too).
    pub fn set_idle_timeout(&self, d: Option<Duration>) {
        self.idle_ms.store(opt_ms(d), Ordering::Relaxed);
    }

    /// Current `Config::slow_callback_threshold`.
    #[inline]
    pub fn slow_callback_threshold(&self) -> Option<Duration> {
        match self.slow_ns.load(Ordering::Relaxed) {
            0 => None,
            ns => Some(Duration::from_nanos(ns)),
        }
    }

    /// Sets the slow-callback threshold (`None` disables detection and callback timing).
    pub fn set_slow_callback_threshold(&self, d: Option<Duration>) {
        let ns = d.map_or(0, |d| (d.as_nanos() as u64).max(1));
        self.slow_ns.store(ns, Ordering::Relaxed);
    }

    /// Current slow-callback hook.
    pub fn slow_hook(&self) -> Option<SlowHook> {
        self.slow_hook
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replaces the slow-callback hook.
    pub fn set_slow_hook(&self, h: Option<SlowHook>) {
        *self.slow_hook.write().unwrap_or_else(|p| p.into_inner()) = h;
    }

    /// Current `Config::max_queued_bytes`.
    #[inline]
    pub fn max_queued_bytes(&self) -> usize {
        self.max_queued.load(Ordering::Relaxed)
    }

    /// Sets the per-connection send-queue limit.
    pub fn set_max_queued_bytes(&self, n: usize) {
        self.max_queued.store(n, Ordering::Relaxed);
    }

    /// Current `Config::write_high_watermark`.
    #[inline]
    pub fn write_high_watermark(&self) -> usize {
        self.high_wm.load(Ordering::Relaxed)
    }

    /// Sets the backpressure watermark (re-evaluated for open connections).
    pub fn set_write_high_watermark(&self, n: usize) {
        self.high_wm.store(n.max(1), Ordering::Relaxed);
    }

    /// Current `Config::max_connections` (0 = unlimited).
    #[inline]
    pub fn max_connections(&self) -> usize {
        self.max_conns.load(Ordering::Relaxed)
    }

    /// Sets the limit on open connections; existing connections are never closed by lowering it.
    pub fn set_max_connections(&self, n: usize) {
        self.max_conns.store(n, Ordering::Relaxed);
    }

    /// Current `Config::shutdown_timeout`.
    pub fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.shutdown_ms.load(Ordering::Relaxed))
    }

    /// Sets the graceful-shutdown deadline (used when shutdown begins).
    pub fn set_shutdown_timeout(&self, d: Duration) {
        self.shutdown_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Current `Config::read_buffer`.
    #[inline]
    pub fn read_buffer(&self) -> usize {
        self.read_buffer.load(Ordering::Relaxed)
    }

    /// Sets the read buffer size (at least 1 byte); each I/O thread switches to it at its next
    /// reload notification ([`Telemetry::notify_reload`]), between two batches of events.
    pub fn set_read_buffer(&self, n: usize) {
        self.read_buffer.store(n.max(1), Ordering::Relaxed);
    }

    /// Current `Config::backlog`.
    #[inline]
    pub fn backlog(&self) -> i32 {
        self.backlog.load(Ordering::Relaxed)
    }

    /// Sets the `listen(2)` backlog; listening sockets are `listen`ed again with it at the next
    /// reload notification. The kernel caps it (`net.core.somaxconn` on Linux,
    /// `kern.ipc.somaxconn` on macOS).
    pub fn set_backlog(&self, n: i32) {
        self.backlog.store(n, Ordering::Relaxed);
    }

    /// Current `Config::udp_idle_timeout`.
    #[inline]
    pub fn udp_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.udp_idle_ms.load(Ordering::Relaxed))
    }

    /// UDP idle timeout in milliseconds (at least 1).
    #[doc(hidden)]
    #[inline]
    pub fn udp_idle_ms(&self) -> u64 {
        self.udp_idle_ms.load(Ordering::Relaxed)
    }

    /// Sets the UDP peer idle timeout; open peers' timers are re-armed at the next reload
    /// notification.
    pub fn set_udp_idle_timeout(&self, d: Duration) {
        self.udp_idle_ms.store(opt_ms(Some(d)), Ordering::Relaxed);
    }

    /// Current `Config::retire_timeout`.
    pub fn retire_timeout(&self) -> Option<Duration> {
        match self.retire_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Sets how long a retiring I/O thread (see `Engine::set_threads`) serves its connections
    /// before it shuts the rest down gracefully; `None` lets them run until they close.
    /// Read when a thread starts retiring.
    pub fn set_retire_timeout(&self, d: Option<Duration>) {
        self.retire_ms.store(opt_ms(d), Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("idle_timeout", &self.idle_timeout())
            .field("slow_callback_threshold", &self.slow_callback_threshold())
            .field("max_queued_bytes", &self.max_queued_bytes())
            .field("write_high_watermark", &self.write_high_watermark())
            .field("max_connections", &self.max_connections())
            .field("shutdown_timeout", &self.shutdown_timeout())
            .field("read_buffer", &self.read_buffer())
            .field("backlog", &self.backlog())
            .field("udp_idle_timeout", &self.udp_idle_timeout())
            .field("retire_timeout", &self.retire_timeout())
            .finish()
    }
}

/// The settings fixed at build time, kept to tell what a reload could not change.
#[derive(Clone)]
struct Fixed {
    max_pending_responses: Option<usize>,
    write_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    udp_max_peers: Option<usize>,
    udp_gro: bool,
}

/// What [`Telemetry::reload`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReloadReport {
    /// Settings that changed and now apply.
    pub applied: Vec<&'static str>,
    /// Settings that differ from the running engine but need a restart.
    pub ignored: Vec<&'static str>,
}

/// Observability hub and live settings of one engine. See the [module docs](self).
pub struct Telemetry {
    live: Live,
    bound: AtomicBool,
    fixed: Mutex<Option<Fixed>>,
    loops: Mutex<Vec<LoopEntry>>,
    /// Counters of the threads that left `loops` (`unregister_loops`), kept in the totals.
    gone: Mutex<LoopCounters>,
    slow: Mutex<VecDeque<SlowRecord>>,
    open: AtomicUsize,
    pool: Mutex<Weak<Pool>>,
    started: Instant,
    log_level: Mutex<Option<akio_log::LevelFilter>>,
    collectors: Mutex<Vec<Registration>>,
    next_collector: AtomicU64,
}

type Registration = (CollectorId, Arc<dyn Collector>, Vec<(String, String)>);

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("live", &self.live)
            .field("open_connections", &self.open_connections())
            .finish_non_exhaustive()
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Telemetry {
            live: Live::default(),
            bound: AtomicBool::new(false),
            fixed: Mutex::new(None),
            loops: Mutex::new(Vec::new()),
            gone: Mutex::new(LoopCounters::default()),
            slow: Mutex::new(VecDeque::new()),
            open: AtomicUsize::new(0),
            pool: Mutex::new(Weak::new()),
            started: Instant::now(),
            log_level: Mutex::new(None),
            collectors: Mutex::new(Vec::new()),
            next_collector: AtomicU64::new(0),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Telemetry {
    /// A fresh hub.
    pub fn new() -> Arc<Telemetry> {
        Arc::new(Telemetry::default())
    }

    /// The live settings.
    #[inline]
    pub fn live(&self) -> &Live {
        &self.live
    }

    /// Adopts `cfg` as the starting configuration. The first call wins (every group of an engine
    /// calls it with the same config). Backend-facing.
    #[doc(hidden)]
    pub fn bind(&self, cfg: &Config) {
        if self.bound.swap(true, Ordering::AcqRel) {
            return;
        }
        self.live.apply(cfg);
        *lock(&self.fixed) = Some(Fixed {
            max_pending_responses: cfg.max_pending_responses,
            write_timeout: cfg.write_timeout,
            connect_timeout: cfg.connect_timeout,
            udp_max_peers: cfg.udp_max_peers,
            udp_gro: cfg.udp_gro,
        });
        if let Some(l) = cfg.log_level {
            self.set_log_level(l);
        }
    }

    /// Whether an engine already adopted this hub.
    #[doc(hidden)]
    pub fn is_bound(&self) -> bool {
        self.bound.load(Ordering::Acquire)
    }

    /// Lets [`metrics`](Self::metrics) report the engine's logical pool. Backend-facing.
    #[doc(hidden)]
    pub fn set_pool(&self, pool: &Arc<Pool>) {
        *lock(&self.pool) = Arc::downgrade(pool);
    }

    /// Registers an I/O thread: its counters and how to send it a [`LoopCmd`]. A thread that
    /// replaces an exited one with the same counters (`Engine::set_threads` growing a group
    /// again) takes over its entry, so the series stay continuous and the table stays bounded.
    /// Backend-facing.
    #[doc(hidden)]
    pub fn register_loop(&self, stats: Arc<LoopStats>, post: Box<dyn Fn(LoopCmd) + Send + Sync>) {
        let mut loops = lock(&self.loops);
        match loops.iter_mut().find(|l| Arc::ptr_eq(&l.stats, &stats)) {
            Some(l) => l.post = post,
            None => loops.push(LoopEntry { stats, post }),
        }
    }

    /// Removes the threads with these counters from the table (the exited threads of a listener
    /// removed at run time, ADR-099); what they counted stays in [`Metrics::total`], so totals
    /// never go back. Backend-facing.
    #[doc(hidden)]
    pub fn unregister_loops(&self, stats: &[Arc<LoopStats>]) {
        let mut loops = lock(&self.loops);
        let mut gone = lock(&self.gone);
        loops.retain(|l| {
            if !stats.iter().any(|s| Arc::ptr_eq(s, &l.stats)) {
                return true;
            }
            let mut c = l.stats.snapshot();
            c.queued_bytes = 0; // a gauge: nothing is queued on an exited thread
            gone.add(&c);
            false
        });
    }

    /// Applies the reloadable settings of `cfg` to the running engine and reports what changed
    /// and what would need a restart. See [`Live`] for the list.
    pub fn reload(&self, cfg: &Config) -> ReloadReport {
        // Held throughout: concurrent reloads apply one after the other.
        let fixed = lock(&self.fixed);
        let mut r = ReloadReport::default();
        let l = &self.live;
        let mut note = |changed: bool, name| {
            if changed {
                r.applied.push(name);
            }
        };
        note(
            l.idle_timeout()
                != cfg
                    .idle_timeout
                    .map(|d| Duration::from_millis(opt_ms(Some(d)))),
            "idle_timeout",
        );
        note(
            l.slow_callback_threshold()
                != cfg
                    .slow_callback_threshold
                    .map(|d| Duration::from_nanos((d.as_nanos() as u64).max(1))),
            "slow_callback_threshold",
        );
        let hook_changed = match (l.slow_hook(), &cfg.slow_hook) {
            (None, None) => false,
            (Some(a), Some(b)) => !Arc::ptr_eq(&a.0, &b.0),
            _ => true,
        };
        note(hook_changed, "slow_hook");
        note(
            l.max_queued_bytes() != cfg.max_queued_bytes,
            "max_queued_bytes",
        );
        note(
            l.write_high_watermark() != cfg.write_high_watermark.max(1),
            "write_high_watermark",
        );
        note(
            l.max_connections() != cfg.max_connections,
            "max_connections",
        );
        note(
            l.shutdown_timeout() != Duration::from_millis(cfg.shutdown_timeout.as_millis() as u64),
            "shutdown_timeout",
        );
        note(
            *lock(&self.log_level) != cfg.log_level && cfg.log_level.is_some(),
            "log_level",
        );
        note(l.read_buffer() != cfg.read_buffer.max(1), "read_buffer");
        note(l.backlog() != cfg.backlog, "backlog");
        note(
            l.udp_idle_timeout() != Duration::from_millis(opt_ms(Some(cfg.udp_idle_timeout))),
            "udp_idle_timeout",
        );
        note(
            l.retire_timeout()
                != cfg
                    .retire_timeout
                    .map(|d| Duration::from_millis(opt_ms(Some(d)))),
            "retire_timeout",
        );
        if let Some(f) = fixed.as_ref() {
            for (differs, name) in [
                (
                    f.max_pending_responses != cfg.max_pending_responses,
                    "max_pending_responses",
                ),
                (f.write_timeout != cfg.write_timeout, "write_timeout"),
                (f.connect_timeout != cfg.connect_timeout, "connect_timeout"),
                (f.udp_max_peers != cfg.udp_max_peers, "udp_max_peers"),
                (f.udp_gro != cfg.udp_gro, "udp_gro"),
            ] {
                if differs {
                    r.ignored.push(name);
                }
            }
        }
        l.apply(cfg);
        if let Some(lv) = cfg.log_level {
            self.set_log_level(lv);
        }
        self.notify_reload();
        if !r.applied.is_empty() || !r.ignored.is_empty() {
            akio_log::info!(target: "akio", applied:? = r.applied, ignored:? = r.ignored; "configuration reloaded");
        }
        r
    }

    /// Tells every I/O thread that live settings changed (call after using the [`Live`] setters
    /// directly, so idle timers and backpressure are re-evaluated for open connections).
    pub fn notify_reload(&self) {
        for l in lock(&self.loops).iter() {
            if l.stats.running() {
                (l.post)(LoopCmd::Reload);
            }
        }
    }

    /// Sets the global maximum log level ([`akio_log::set_max_level`]; with the `log` feature also
    /// the `log` crate's).
    pub fn set_log_level(&self, level: akio_log::LevelFilter) {
        *lock(&self.log_level) = Some(level);
        akio_log::set_max_level(level);
    }

    // ---- connection accounting --------------------------------------------------------------

    /// Counts a new connection. `limited`: refuse it (return `false`) when `max_connections` is
    /// reached. Backend-facing.
    #[doc(hidden)]
    #[inline]
    pub fn conn_opened(&self, limited: bool) -> bool {
        let n = self.open.fetch_add(1, Ordering::Relaxed);
        let max = self.live.max_connections();
        if limited && max != 0 && n >= max {
            self.open.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Counts a closed connection. Backend-facing.
    #[doc(hidden)]
    #[inline]
    pub fn conn_closed(&self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }

    /// Connections open right now (all listeners, dialed ones and UDP peers included).
    pub fn open_connections(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    // ---- slow callbacks ---------------------------------------------------------------------

    /// `Some(now)` when callbacks should be timed (a slow-callback threshold is set).
    #[doc(hidden)]
    #[inline]
    pub fn timing(&self) -> Option<Instant> {
        if self.live.slow_ns.load(Ordering::Relaxed) == 0 {
            None
        } else {
            Some(Instant::now())
        }
    }

    /// Whether callbacks are timed (a slow-callback threshold is set). Backend-facing.
    #[doc(hidden)]
    #[inline]
    pub fn timing_enabled(&self) -> bool {
        self.live.slow_ns.load(Ordering::Relaxed) != 0
    }

    /// Like [`callback_done`](Self::callback_done) for a timed callback, returning the instant
    /// it finished, so a backend can start timing the next callback from it instead of reading
    /// the clock again (the clock is a real cost per request on some VMs). Backend-facing.
    #[doc(hidden)]
    #[inline]
    pub fn callback_done_at(
        &self,
        stats: &LoopStats,
        kind: &'static str,
        id: u64,
        t0: Instant,
    ) -> Instant {
        let end = Instant::now();
        let elapsed = end.saturating_duration_since(t0);
        stats.callbacks.add_local(1);
        stats.callback_ns.add_local(elapsed.as_nanos() as u64);
        if let Some(limit) = self.live.slow_callback_threshold() {
            if elapsed >= limit {
                self.report_slow(stats, kind, id, elapsed, limit);
            }
        }
        end
    }

    /// Accounts a finished callback started at `t0` and reports it if it was slow.
    /// Backend-facing.
    #[doc(hidden)]
    #[inline]
    pub fn callback_done(
        &self,
        stats: &LoopStats,
        kind: &'static str,
        id: u64,
        t0: Option<Instant>,
    ) {
        if let Some(elapsed) = stats.callback(t0) {
            if let Some(limit) = self.live.slow_callback_threshold() {
                if elapsed >= limit {
                    self.report_slow(stats, kind, id, elapsed, limit);
                }
            }
        }
    }

    #[cold]
    fn report_slow(
        &self,
        stats: &LoopStats,
        kind: &'static str,
        id: u64,
        elapsed: Duration,
        limit: Duration,
    ) {
        stats.slow_callbacks.add(1);
        {
            let mut ring = lock(&self.slow);
            if ring.len() == SLOW_RING {
                ring.pop_front();
            }
            ring.push_back(SlowRecord {
                at: SystemTime::now(),
                kind,
                conn_id: id,
                elapsed,
                threshold: limit,
                owner: stats.meta.clone(),
            });
        }
        let rep = SlowCallback {
            kind,
            conn_id: id,
            elapsed,
        };
        if let Some(h) = self.live.slow_hook() {
            return (h.0)(&rep);
        }
        let msg = format!(
            "slow callback: {kind} on connection {id} blocked its I/O thread for {elapsed:?} \
             (limit {limit:?}); move blocking work to Conn::spawn_blocking"
        );
        if akio_log::log_enabled!(target: "akio", akio_log::Level::Warn) {
            akio_log::warn!(
                target: "akio",
                kind = kind, conn_id = id, elapsed_us = elapsed.as_micros() as u64,
                limit_us = limit.as_micros() as u64, thread = stats.meta.thread,
                listener:? = stats.meta.listener; "{msg}"
            );
        } else {
            eprintln!("akio: {msg}");
        }
    }

    /// The most recent slow callbacks (up to [`SLOW_RING`]), oldest first.
    pub fn slow_callbacks(&self) -> Vec<SlowRecord> {
        lock(&self.slow).iter().cloned().collect()
    }

    // ---- snapshots --------------------------------------------------------------------------

    /// Counters of every I/O thread, their sum, open connections and pool statistics.
    pub fn metrics(&self) -> Metrics {
        let loops: Vec<LoopMetrics> = lock(&self.loops)
            .iter()
            .map(|l| LoopMetrics {
                owner: l.stats.meta.clone(),
                running: l.stats.running(),
                retiring: l.stats.retiring(),
                counters: l.stats.snapshot(),
            })
            .collect();
        let mut total = *lock(&self.gone);
        for l in &loops {
            total.add(&l.counters);
        }
        Metrics {
            loops,
            total,
            open_connections: self.open_connections(),
            pool: lock(&self.pool).upgrade().map(|p| p.stats()),
            uptime: self.started.elapsed(),
        }
    }

    // ---- pluggable collectors (ADR-015) ------------------------------------------------------

    /// Adds `collector` to every scrape ([`Telemetry::collect`], [`Telemetry::render_prometheus`],
    /// akio-http's `metrics_handler`), with `labels` added to each of its samples. Use distinct
    /// labels when two collectors report the same families (two QUIC servers, say).
    pub fn register_collector(
        &self,
        collector: Arc<dyn Collector>,
        labels: &[(&str, &str)],
    ) -> CollectorId {
        let id = CollectorId(self.next_collector.fetch_add(1, Ordering::Relaxed));
        let labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        lock(&self.collectors).push((id, collector, labels));
        id
    }

    /// Removes a registration; `false` if it was not registered.
    pub fn unregister_collector(&self, id: CollectorId) -> bool {
        let mut g = lock(&self.collectors);
        let n = g.len();
        g.retain(|(i, _, _)| *i != id);
        g.len() != n
    }

    /// Runs the registered collectors (in registration order) and returns their samples. The
    /// engine's own series are in [`Telemetry::metrics`].
    pub fn collect(&self) -> Families {
        // Collectors run outside the lock: a slow one never blocks a registration.
        let regs: Vec<Registration> = lock(&self.collectors).clone();
        let mut out = Families::new();
        for (_, c, labels) in &regs {
            out.collect_from(&**c, labels);
        }
        out
    }

    /// The engine's series ([`Metrics::collect_into`]) followed by the registered collectors':
    /// everything [`render_prometheus`](Self::render_prometheus) serves, as [`Families`] (for
    /// push exporters).
    pub fn collect_all(&self) -> Families {
        let mut out = Families::new();
        self.metrics().collect_into(&mut out);
        let regs: Vec<Registration> = lock(&self.collectors).clone();
        for (_, c, labels) in &regs {
            out.collect_from(&**c, labels);
        }
        out
    }

    /// The engine's series ([`Metrics::to_prometheus`]) followed by the registered collectors',
    /// in the Prometheus text format (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let mut out = self.metrics().to_prometheus();
        self.collect().write_prometheus(&mut out);
        out
    }

    /// The connection table: every connection of every running I/O thread, gathered by the
    /// threads themselves (so nothing is tracked per event). Threads that do not answer within
    /// `timeout` (blocked by a slow callback) are left out. Do not call it from an I/O thread's
    /// callback: that thread cannot answer while it waits (it would only cost the timeout).
    pub fn connections(&self, timeout: Duration) -> Vec<ConnInfo> {
        let (tx, rx) = mpsc::channel::<Vec<ConnInfo>>();
        let mut asked = 0;
        for l in lock(&self.loops).iter() {
            if !l.stats.running() {
                continue;
            }
            let tx = tx.clone();
            (l.post)(LoopCmd::Inspect(Box::new(move |v| {
                let _ = tx.send(v);
            })));
            asked += 1;
        }
        drop(tx);
        let deadline = Instant::now() + timeout;
        let mut out = Vec::new();
        for _ in 0..asked {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(mut v) => out.append(&mut v),
                Err(_) => break,
            }
        }
        out.sort_by_key(|c| c.id);
        out
    }
}

/// Counters of one I/O thread in a [`Metrics`] snapshot.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LoopMetrics {
    /// Which thread.
    pub owner: LoopMeta,
    /// Whether it is running.
    pub running: bool,
    /// Whether it is retiring: a smaller thread count (`Engine::set_threads`) took it out of
    /// its group; it serves the connections it has and exits once they are closed.
    pub retiring: bool,
    /// Its counters.
    pub counters: LoopCounters,
}

impl LoopMetrics {
    /// Connections open on this thread.
    pub fn open(&self) -> u64 {
        let c = &self.counters;
        (c.accepted + c.dialed).saturating_sub(c.closed)
    }
}

/// A metrics snapshot ([`Telemetry::metrics`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Metrics {
    /// Per I/O thread.
    pub loops: Vec<LoopMetrics>,
    /// Sum over all threads.
    pub total: LoopCounters,
    /// Connections open now.
    pub open_connections: usize,
    /// The logical pool, when the engine has one.
    pub pool: Option<PoolStats>,
    /// Time since the hub was created.
    pub uptime: Duration,
}

/// Escapes a Prometheus label value.
fn label(out: &mut String, v: &str) {
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

fn loop_labels(out: &mut String, m: &LoopMeta) {
    out.push_str("{listener=\"");
    match m.listener {
        Some(a) => label(out, &a.to_string()),
        None => out.push_str("client"),
    }
    let _ = write!(
        out,
        "\",backend=\"{}\",thread=\"{}\"}}",
        m.backend, m.thread
    );
}

/// Writes a `# HELP` / `# TYPE` header (Prometheus text exposition format 0.0.4).
#[doc(hidden)]
pub fn prometheus_header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

fn as_refs(l: &[(String, String); 3]) -> [(&str, &str); 3] {
    [
        (l[0].0.as_str(), l[0].1.as_str()),
        (l[1].0.as_str(), l[1].1.as_str()),
        (l[2].0.as_str(), l[2].1.as_str()),
    ]
}

impl Metrics {
    /// Renders the snapshot in the Prometheus text exposition format (version 0.0.4), one series
    /// per I/O thread labelled `listener`, `backend` and `thread`.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096 + self.loops.len() * 2048);
        self.write_prometheus(&mut out);
        out
    }

    /// Appends the Prometheus rendering to `out`.
    pub fn write_prometheus(&self, out: &mut String) {
        let values: Vec<Vec<u64>> = self.loops.iter().map(|l| l.counters.values()).collect();
        for (i, (name, kind, help)) in LoopCounters::FIELDS.iter().enumerate() {
            let prom_kind = if *kind == "nanos" { "counter" } else { kind };
            prometheus_header(out, name, prom_kind, help);
            for (l, v) in self.loops.iter().zip(&values) {
                out.push_str(name);
                loop_labels(out, &l.owner);
                if *kind == "nanos" {
                    let _ = writeln!(out, " {}", v[i] as f64 / 1e9);
                } else {
                    let _ = writeln!(out, " {}", v[i]);
                }
            }
        }
        prometheus_header(
            out,
            "akio_connections_open",
            "gauge",
            "Connections open now.",
        );
        for l in &self.loops {
            out.push_str("akio_connections_open");
            loop_labels(out, &l.owner);
            let _ = writeln!(out, " {}", l.open());
        }
        prometheus_header(
            out,
            "akio_loop_running",
            "gauge",
            "Whether the I/O thread is running.",
        );
        for l in &self.loops {
            out.push_str("akio_loop_running");
            loop_labels(out, &l.owner);
            let _ = writeln!(out, " {}", u8::from(l.running));
        }
        prometheus_header(
            out,
            "akio_loop_retiring",
            "gauge",
            "Whether the I/O thread is retiring (taking no new connections).",
        );
        for l in &self.loops {
            out.push_str("akio_loop_retiring");
            loop_labels(out, &l.owner);
            let _ = writeln!(out, " {}", u8::from(l.retiring));
        }
        if let Some(p) = &self.pool {
            for (name, kind, help, v) in [
                (
                    "akio_pool_threads",
                    "gauge",
                    "Logical pool threads.",
                    p.threads as u64,
                ),
                (
                    "akio_pool_active",
                    "gauge",
                    "Logical pool threads running a job.",
                    p.threads.saturating_sub(p.idle) as u64,
                ),
                (
                    "akio_pool_queued",
                    "gauge",
                    "Jobs waiting in the logical pool queue.",
                    p.queued as u64,
                ),
                (
                    "akio_pool_completed_total",
                    "counter",
                    "Jobs the logical pool completed.",
                    p.completed,
                ),
                (
                    "akio_pool_panicked_total",
                    "counter",
                    "Jobs that panicked.",
                    p.panicked,
                ),
                (
                    "akio_pool_rejected_total",
                    "counter",
                    "Jobs refused because the queue was full.",
                    p.rejected,
                ),
            ] {
                prometheus_header(out, name, kind, help);
                let _ = writeln!(out, "{name} {v}");
            }
        }
        prometheus_header(
            out,
            "akio_uptime_seconds",
            "gauge",
            "Seconds since the engine was created.",
        );
        let _ = writeln!(out, "akio_uptime_seconds {}", self.uptime.as_secs_f64());
    }

    /// Adds the snapshot's series to `out`: the same names, labels and values as
    /// [`write_prometheus`](Self::write_prometheus).
    pub fn collect_into(&self, out: &mut Families) {
        let labels: Vec<[(String, String); 3]> = self
            .loops
            .iter()
            .map(|l| {
                let m = &l.owner;
                [
                    (
                        "listener".to_owned(),
                        m.listener
                            .map_or_else(|| "client".to_owned(), |a| a.to_string()),
                    ),
                    ("backend".to_owned(), m.backend.to_owned()),
                    ("thread".to_owned(), m.thread.to_string()),
                ]
            })
            .collect();
        let values: Vec<Vec<u64>> = self.loops.iter().map(|l| l.counters.values()).collect();
        for (i, (name, kind, help)) in LoopCounters::FIELDS.iter().enumerate() {
            for (l, v) in labels.iter().zip(&values) {
                let ls = as_refs(l);
                match *kind {
                    "nanos" => out.counter(name, help, &ls, v[i] as f64 / 1e9),
                    "gauge" => out.gauge(name, help, &ls, v[i] as f64),
                    _ => out.counter(name, help, &ls, v[i] as f64),
                }
            }
        }
        for (l, lm) in labels.iter().zip(&self.loops) {
            out.gauge(
                "akio_connections_open",
                "Connections open now.",
                &as_refs(l),
                lm.open() as f64,
            );
        }
        for (l, lm) in labels.iter().zip(&self.loops) {
            out.gauge(
                "akio_loop_running",
                "Whether the I/O thread is running.",
                &as_refs(l),
                f64::from(u8::from(lm.running)),
            );
        }
        for (l, lm) in labels.iter().zip(&self.loops) {
            out.gauge(
                "akio_loop_retiring",
                "Whether the I/O thread is retiring (taking no new connections).",
                &as_refs(l),
                f64::from(u8::from(lm.retiring)),
            );
        }
        if let Some(p) = &self.pool {
            out.gauge(
                "akio_pool_threads",
                "Logical pool threads.",
                &[],
                p.threads as f64,
            );
            out.gauge(
                "akio_pool_active",
                "Logical pool threads running a job.",
                &[],
                p.threads.saturating_sub(p.idle) as f64,
            );
            out.gauge(
                "akio_pool_queued",
                "Jobs waiting in the logical pool queue.",
                &[],
                p.queued as f64,
            );
            out.counter(
                "akio_pool_completed_total",
                "Jobs the logical pool completed.",
                &[],
                p.completed as f64,
            );
            out.counter(
                "akio_pool_panicked_total",
                "Jobs that panicked.",
                &[],
                p.panicked as f64,
            );
            out.counter(
                "akio_pool_rejected_total",
                "Jobs refused because the queue was full.",
                &[],
                p.rejected as f64,
            );
        }
        out.gauge(
            "akio_uptime_seconds",
            "Seconds since the engine was created.",
            &[],
            self.uptime.as_secs_f64(),
        );
    }

    /// Renders the snapshot as JSON (threads with their counters, totals, pool).
    pub fn to_json(&self) -> String {
        let mut o = String::with_capacity(1024 + self.loops.len() * 1024);
        o.push_str("{\"open_connections\":");
        let _ = write!(
            o,
            "{},\"uptime_secs\":{:.3},\"total\":",
            self.open_connections,
            self.uptime.as_secs_f64()
        );
        counters_json(&mut o, &self.total);
        o.push_str(",\"loops\":[");
        for (i, l) in self.loops.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push('{');
            meta_json(&mut o, &l.owner);
            let _ = write!(
                o,
                ",\"running\":{},\"retiring\":{},\"open\":{},\"counters\":",
                l.running,
                l.retiring,
                l.open()
            );
            counters_json(&mut o, &l.counters);
            o.push('}');
        }
        o.push_str("],\"pool\":");
        match &self.pool {
            Some(p) => {
                let _ = write!(
                    o,
                    "{{\"threads\":{},\"idle\":{},\"queued\":{},\"completed\":{},\"panicked\":{},\"rejected\":{}}}",
                    p.threads, p.idle, p.queued, p.completed, p.panicked, p.rejected
                );
            }
            None => o.push_str("null"),
        }
        o.push('}');
        o
    }
}

/// Appends `s` as a JSON string literal.
#[doc(hidden)]
pub fn json_str(o: &mut String, s: &str) {
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

fn counters_json(o: &mut String, c: &LoopCounters) {
    o.push('{');
    for (i, (n, v)) in LoopCounters::names().iter().zip(c.values()).enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(o, "\"{n}\":{v}");
    }
    o.push('}');
}

fn meta_json(o: &mut String, m: &LoopMeta) {
    o.push_str("\"backend\":");
    json_str(o, m.backend);
    o.push_str(",\"listener\":");
    match m.listener {
        Some(a) => json_str(o, &a.to_string()),
        None => o.push_str("null"),
    }
    let _ = write!(o, ",\"thread\":{}", m.thread);
}

/// Renders a connection table as a JSON array.
pub fn connections_json(conns: &[ConnInfo]) -> String {
    let mut o = String::with_capacity(64 + conns.len() * 256);
    o.push('[');
    for (i, c) in conns.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(o, "{{\"id\":{},\"peer\":", c.id);
        json_str(&mut o, &c.peer.to_string());
        o.push_str(",\"local\":");
        json_str(&mut o, &c.local.to_string());
        o.push(',');
        meta_json(&mut o, &c.owner);
        let _ = write!(
            o,
            ",\"age_ms\":{},\"idle_ms\":{},\"bytes_in\":{},\"bytes_out\":{},\"queued_bytes\":{},\
             \"read_held\":{},\"backpressure\":{},\"udp\":{},\"transport\":",
            c.age.as_millis(),
            c.idle.as_millis(),
            c.bytes_in,
            c.bytes_out,
            c.queued_bytes,
            c.read_held,
            c.backpressure,
            c.udp
        );
        match c.transport {
            Some(t) => json_str(&mut o, t),
            None => o.push_str("null"),
        }
        o.push('}');
    }
    o.push(']');
    o
}

/// Renders slow-callback records as a JSON array.
pub fn slow_callbacks_json(recs: &[SlowRecord]) -> String {
    let mut o = String::with_capacity(64 + recs.len() * 192);
    o.push('[');
    for (i, r) in recs.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let at =
            r.at.duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
        let _ = write!(o, "{{\"at_unix\":{at:.6},\"kind\":");
        json_str(&mut o, r.kind);
        let _ = write!(
            o,
            ",\"conn_id\":{},\"elapsed_us\":{},\"threshold_us\":{},",
            r.conn_id,
            r.elapsed.as_micros(),
            r.threshold.as_micros()
        );
        meta_json(&mut o, &r.owner);
        o.push('}');
    }
    o.push(']');
    o
}

/// Logs `msg` through the `akio-log` facade at `level` when a logger accepts it, else prints it to
/// stderr (so errors are never silently lost when no logger is installed). Not for hot paths.
#[doc(hidden)]
pub fn log_or_stderr(level: akio_log::Level, msg: std::fmt::Arguments<'_>) {
    akio_log::log_or_stderr(level, "akio", msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_loops_leave_the_table_but_not_the_totals() {
        let t = Telemetry::new();
        let a = Arc::new(LoopStats::new(LoopMeta::new("epoll", None, 0)));
        let b = Arc::new(LoopStats::new(LoopMeta::new("epoll", None, 1)));
        for s in [&a, &b] {
            t.register_loop(s.clone(), Box::new(|_| {}));
        }
        a.accepted.add_local(3);
        a.filtered.add_local(2);
        a.queued_bytes.add_local(7);
        b.accepted.add_local(5);
        t.unregister_loops(std::slice::from_ref(&a));
        let m = t.metrics();
        assert_eq!(m.loops.len(), 1);
        assert_eq!(m.total.accepted, 8);
        assert_eq!(m.total.filtered, 2);
        assert_eq!(
            m.total.queued_bytes, 0,
            "a gauge of an exited thread is not kept"
        );
        // Unknown counters change nothing; the rest keeps counting.
        t.unregister_loops(&[Arc::new(LoopStats::new(LoopMeta::new("epoll", None, 9)))]);
        b.accepted.add_local(1);
        assert_eq!(t.metrics().total.accepted, 9);
        assert!(
            t.metrics()
                .to_prometheus()
                .contains("akio_connections_filtered_total")
        );
    }
}
