//! The reconnect policy of the RTMP and RTSP clients ([`Reconnect`]).

use std::{
    fmt,
    sync::{Arc, Weak},
    time::Duration,
};

use only::Engine;

/// Makes an RTMP or RTSP client ([`crate::rtmp::client`], [`crate::rtsp::client`]) connect
/// again when its session ends with an error that another try may cure (the connection
/// closing or failing, a timeout, a refusal other than for credentials), waiting
/// `initial_delay`, then twice as long after each failed try up to `max_delay`. A session
/// that goes live resets the delay. `max_attempts` bounds the tries in a row (`None`: until
/// the client is closed).
///
/// A pull keeps its hub path reserved meanwhile: players stay subscribed, and the hub sees
/// the new session's tracks as a republish (sinks restart their timelines, HLS writes a
/// discontinuity). A push subscribes again and starts from the cached GOP.
///
/// The client dials again on the engine given to [`new`](Self::new), which it holds weakly:
/// once the engine is dropped the client ends. The RTSP client looks the URL's host name up
/// again for every try (on the reconnecting thread; a name that fails to resolve is tried
/// again like a refused connect), so a server that moved is found; the RTMP client dials the
/// address resolved when it started.
#[derive(Clone)]
#[non_exhaustive]
pub struct Reconnect {
    /// The wait before the first try. Default 500 ms.
    pub initial_delay: Duration,
    /// The longest wait between tries. Default 30 s.
    pub max_delay: Duration,
    /// Tries in a row before the client gives up and ends with the last error; `None` (the
    /// default) tries until it is closed.
    pub max_attempts: Option<u32>,
    engine: Weak<Engine>,
}

impl Reconnect {
    /// Reconnects on `engine` with the default delays, without a bound on the tries.
    pub fn new(engine: &Arc<Engine>) -> Reconnect {
        Reconnect {
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            max_attempts: None,
            engine: Arc::downgrade(engine),
        }
    }

    /// Sets [`initial_delay`](Self::initial_delay).
    #[must_use]
    pub fn initial_delay(mut self, d: Duration) -> Reconnect {
        self.initial_delay = d;
        self
    }

    /// Sets [`max_delay`](Self::max_delay).
    #[must_use]
    pub fn max_delay(mut self, d: Duration) -> Reconnect {
        self.max_delay = d;
        self
    }

    /// Sets [`max_attempts`](Self::max_attempts).
    #[must_use]
    pub fn max_attempts(mut self, n: Option<u32>) -> Reconnect {
        self.max_attempts = n;
        self
    }

    /// The wait before try number `attempt` (0, 1, ...) since the last live session.
    pub(crate) fn delay(&self, attempt: u32) -> Duration {
        let max = self.max_delay.max(self.initial_delay);
        self.initial_delay
            .checked_mul(1u32 << attempt.min(20))
            .map_or(max, |d| d.min(max))
    }

    /// Whether try number `attempt` may be made.
    pub(crate) fn allows(&self, attempt: u32) -> bool {
        self.max_attempts.is_none_or(|n| attempt < n)
    }

    /// The engine to dial on, while it lives.
    pub(crate) fn engine(&self) -> Option<Arc<Engine>> {
        self.engine.upgrade()
    }
}

// The configs that carry a `Reconnect` stay unwind safe: it only holds delays and a weak
// engine handle it upgrades to dial, and no state of it can be seen half updated after a
// panic (the engine's own state is behind its locks, which ignore poisoning or recover).
impl std::panic::UnwindSafe for Reconnect {}
impl std::panic::RefUnwindSafe for Reconnect {}

impl fmt::Debug for Reconnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconnect")
            .field("initial_delay", &self.initial_delay)
            .field("max_delay", &self.max_delay)
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_double_up_to_the_bound() {
        let e = Arc::new(Engine::builder().build().expect("engine"));
        let r = Reconnect::new(&e)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(1))
            .max_attempts(Some(3));
        let d: Vec<u64> = (0..6).map(|a| r.delay(a).as_millis() as u64).collect();
        assert_eq!(d, [100, 200, 400, 800, 1000, 1000]);
        assert_eq!(r.delay(u32::MAX), Duration::from_secs(1));
        assert!(r.allows(2) && !r.allows(3));
        assert!(Reconnect::new(&e).allows(u32::MAX));
        assert!(r.engine().is_some());
        drop(e);
        assert!(r.engine().is_none());
        assert!(format!("{r:?}").contains("max_attempts: Some(3)"));
    }
}
