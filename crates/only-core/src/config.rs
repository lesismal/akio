use std::{sync::Arc, time::Duration};

use crate::Telemetry;

pub(crate) const DEFAULT_WRITE_HIGH_WATERMARK: usize = 256 << 10;
pub(crate) const DEFAULT_MAX_QUEUED_BYTES: usize = 64 << 20;
pub(crate) const DEFAULT_SLOW_CALLBACK: Duration = Duration::from_millis(100);
pub(crate) const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// What the slow-callback detector reports.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SlowCallback {
    /// Which callback ran long.
    pub kind: &'static str,
    /// Connection it ran for.
    pub conn_id: u64,
    /// How long it took.
    pub elapsed: Duration,
}

/// Receives [`SlowCallback`] reports on the I/O thread that ran the callback.
#[derive(Clone)]
pub struct SlowHook(pub Arc<dyn Fn(&SlowCallback) + Send + Sync>);

impl std::fmt::Debug for SlowHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlowHook(..)")
    }
}

/// Tunables shared by all connections of an engine.
///
/// `#[non_exhaustive]`: start from [`Config::default()`] and set the fields you need, so new
/// settings can be added in minor releases (docs/api-stability.md):
///
/// ```
/// let mut cfg = only_core::Config::default();
/// cfg.idle_timeout = Some(std::time::Duration::from_secs(30));
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Config {
    /// Size of each I/O thread's read buffer; `on_data` never sees more than this at once.
    pub read_buffer: usize,
    /// Reads pause while a connection has at least this many bytes queued for sending, and resume
    /// at a quarter of it (backpressure).
    pub write_high_watermark: usize,
    /// `send` fails with `Overloaded` beyond this many queued bytes per connection.
    pub max_queued_bytes: usize,
    /// `listen(2)` backlog.
    pub backlog: i32,
    /// Close a connection (with `ErrorKind::TimedOut`) when the peer has sent nothing for this
    /// long. `None` (the default) disables it. Resolution is about a millisecond; only inbound
    /// data counts as activity.
    pub idle_timeout: Option<Duration>,
    /// Close a connection (with `ErrorKind::TimedOut`) when it has output queued and none of it
    /// could be written for this long: a peer that stopped reading. `None` (the default)
    /// disables it. Checked about every `write_timeout` while output is queued, so a stalled
    /// connection is closed between one and two timeouts after its last progress. TCP only.
    pub write_timeout: Option<Duration>,
    /// A handler callback (`on_data`, `on_close`, a `spawn_blocking` completion) that runs longer
    /// than this blocks its I/O thread and every other connection on it: it is reported to
    /// `slow_hook`, or printed to stderr when there is none. `None` disables the check.
    pub slow_callback_threshold: Option<Duration>,
    /// Where slow callbacks are reported (default: stderr).
    pub slow_hook: Option<SlowHook>,
    /// UDP: a peer that sent nothing for this long is dropped (its `on_close` runs) so idle peers
    /// do not accumulate. `idle_timeout`, when set and shorter, wins.
    pub udp_idle_timeout: Duration,
    /// UDP: most peers one listener keeps open at once (`None`, the default: no limit). While
    /// at the limit, datagrams from new peers are dropped without creating a connection and
    /// counted in `UdpStats::rejected` (see `Engine::udp_stats`); known peers are unaffected.
    pub udp_max_peers: Option<usize>,
    /// UDP, Linux: let the kernel coalesce datagrams of one flow into one receive (UDP GRO);
    /// `only` splits them again, so `on_data` still sees one datagram per call. It pays off for
    /// bulk flows from GSO senders (QUIC transfers) and costs for request/response traffic, so
    /// it is off by default. Needs `read_buffer` of at least 64 KiB (otherwise ignored).
    pub udp_gro: bool,
    /// After `shutdown`, connections still open after this long are closed forcibly.
    pub shutdown_timeout: Duration,
    /// Accepted connections beyond this many open ones (engine-wide, dialed connections and UDP
    /// peers included in the count) are closed right after `accept`. 0 (the default) = no limit.
    pub max_connections: usize,
    /// When set, the engine calls [`only_log::set_max_level`] with it (`only` logs through the
    /// `only-log` facade, re-exported as `only::log`, under the `only` target; install a logger
    /// such as `only::log::init(..)` to see the records, or enable the `log` feature to send
    /// them to the `log` crate's logger).
    pub log_level: Option<only_log::LevelFilter>,
    /// Metrics, debug snapshots and live settings of the engine built with this config (see
    /// [`Telemetry`]). Grab a clone before building the engine to wire up a metrics endpoint.
    /// A config whose telemetry an engine already adopted gets a fresh one at the next `build`.
    ///
    /// Reloadable at runtime (`Engine::reload` / [`Telemetry::reload`]): `idle_timeout`,
    /// `slow_callback_threshold`, `slow_hook`, `max_queued_bytes`, `write_high_watermark`,
    /// `max_connections`, `shutdown_timeout`, `log_level`. Fixed at build time: `read_buffer`,
    /// `backlog`, `udp_idle_timeout`, `write_timeout`.
    pub telemetry: Arc<Telemetry>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            read_buffer: 64 << 10,
            write_high_watermark: DEFAULT_WRITE_HIGH_WATERMARK,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            backlog: 1024,
            idle_timeout: None,
            write_timeout: None,
            slow_callback_threshold: Some(DEFAULT_SLOW_CALLBACK),
            slow_hook: None,
            udp_idle_timeout: Duration::from_secs(60),
            udp_max_peers: None,
            udp_gro: false,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            max_connections: 0,
            log_level: None,
            telemetry: Telemetry::new(),
        }
    }
}
