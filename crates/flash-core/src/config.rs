use std::{sync::Arc, time::Duration};

/// What the slow-callback detector reports.
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Debug)]
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
    /// flash splits them again, so `on_data` still sees one datagram per call. It pays off for
    /// bulk flows from GSO senders (QUIC transfers) and costs for request/response traffic, so
    /// it is off by default. Needs `read_buffer` of at least 64 KiB (otherwise ignored).
    pub udp_gro: bool,
    /// After `shutdown`, connections still open after this long are closed forcibly.
    pub shutdown_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            read_buffer: 64 << 10,
            write_high_watermark: 256 << 10,
            max_queued_bytes: 64 << 20,
            backlog: 1024,
            idle_timeout: None,
            slow_callback_threshold: Some(Duration::from_millis(100)),
            slow_hook: None,
            udp_idle_timeout: Duration::from_secs(60),
            udp_max_peers: None,
            udp_gro: false,
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}
