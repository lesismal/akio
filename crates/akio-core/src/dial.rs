//! Options of one dial (`Engine::dial_with`, ADR-154).

use std::time::Duration;

/// Options of one TCP dial (`Engine::dial_with`, ADR-154). Start from `DialOptions::new()` (or
/// `default()`) and set what differs from the engine's settings:
///
/// ```
/// use std::time::Duration;
/// let opts = akio_core::DialOptions::new().connect_timeout(Duration::from_millis(500));
/// assert_eq!(opts.connect_timeout, Some(Duration::from_millis(500)));
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DialOptions {
    /// How long the TCP handshake may take: a dial still connecting after it fails with
    /// `ErrorKind::TimedOut` (through `on_error`). `None` (the default): the engine's
    /// `Config::connect_timeout` (on DPDK, its stack's own 10 s). Counted in whole milliseconds
    /// on the I/O thread's timer wheel, at least one; never early.
    pub connect_timeout: Option<Duration>,
}

impl DialOptions {
    /// The engine's settings for everything.
    pub const fn new() -> DialOptions {
        DialOptions {
            connect_timeout: None,
        }
    }

    /// Sets [`connect_timeout`](Self::connect_timeout) for this dial.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> DialOptions {
        self.connect_timeout = Some(timeout);
        self
    }
}
