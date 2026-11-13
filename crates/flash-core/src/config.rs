use std::time::Duration;

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
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}
