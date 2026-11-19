//! Where a server records the ClientHellos whose early data (0-RTT) it accepted, so that a
//! replayed ClientHello has its early data rejected (RFC 8446 §8.2 "ClientHello recording",
//! which RFC 9147 keeps for DTLS 1.3). The default, [`MemoryAntiReplay`], is a bounded
//! in-memory record private to one [`Config`](crate::Config); servers that share a
//! [`TicketKey`](crate::TicketKey) across processes or machines plug in a shared store with
//! [`Config::with_anti_replay`](crate::Config::with_anti_replay). The same design as
//! `only_tls::AntiReplayStore` (ADR-013), kept here because only-dtls must not depend on
//! only-tls (ADR-021).

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::session::unix_now_ms;

/// A record of the ClientHellos whose early data was accepted, shared by the servers that
/// accept the same session tickets.
///
/// The server calls [`check_and_insert`](Self::check_and_insert) once per ClientHello whose
/// early data it would otherwise accept, inside
/// [`Connection::handle_datagram`](crate::Connection::handle_datagram). An implementation
/// backed by a remote store (Redis `SET key 1 NX PX ttl`, memcached `add`, a database) makes
/// one round trip there: keep it short and bounded by a timeout, since the caller waits for
/// it. A failure costs only the early data: the handshake continues as a 1-RTT resumption.
pub trait AntiReplayStore: Send + Sync {
    /// Records `binder` (the first PSK binder of a ClientHello, 32 or 48 bytes; unique per
    /// ClientHello and unpredictable) for `ttl`, atomically: `Ok(true)` if it was not recorded
    /// yet (the early data is accepted), `Ok(false)` if it was (a replay: the early data is
    /// rejected). `Ok(false)` is also the answer when the store cannot take more entries.
    ///
    /// Errors **fail closed**: the early data is rejected and the handshake goes on as a
    /// 1-RTT resumption.
    fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool>;
}

/// Binders recorded (first 32 bytes), and their expiry times (Unix ms) in order.
type Seen = (HashSet<[u8; 32]>, VecDeque<(u64, [u8; 32])>);

/// The default [`AntiReplayStore`]: a bounded in-memory record, private to the process. When
/// it holds `entries` binders, early data is rejected until some expire.
pub struct MemoryAntiReplay {
    cap: usize,
    inner: Mutex<Seen>,
}

impl fmt::Debug for MemoryAntiReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryAntiReplay")
            .field("entries", &self.cap)
            .finish_non_exhaustive()
    }
}

impl MemoryAntiReplay {
    /// A record holding up to `entries` ClientHellos (the default of
    /// [`Config::with_early_data`](crate::Config::with_early_data) is 100,000).
    #[must_use]
    pub fn new(entries: usize) -> MemoryAntiReplay {
        MemoryAntiReplay {
            cap: entries,
            inner: Mutex::new((HashSet::new(), VecDeque::new())),
        }
    }

    /// [`check_and_insert`](AntiReplayStore::check_and_insert) at `now_ms` (Unix ms).
    fn record(&self, binder: &[u8], ttl_ms: u64, now_ms: u64) -> io::Result<bool> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("anti-replay record poisoned"))?;
        let (set, order) = &mut *g;
        while let Some((exp, k)) = order.front() {
            if *exp > now_ms {
                break;
            }
            set.remove(k);
            order.pop_front();
        }
        let mut key = [0u8; 32];
        let n = binder.len().min(32);
        key[..n].copy_from_slice(&binder[..n]);
        if set.contains(&key) || set.len() >= self.cap {
            return Ok(false);
        }
        set.insert(key);
        order.push_back((now_ms.saturating_add(ttl_ms), key));
        Ok(true)
    }
}

impl AntiReplayStore for MemoryAntiReplay {
    fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool> {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        self.record(binder, ttl_ms, unix_now_ms())
    }
}

/// Entries of the default [`MemoryAntiReplay`].
pub(crate) const DEFAULT_ENTRIES: usize = 100_000;
/// The freshness window (RFC 8446 §8.3): the ticket age the client reports and the one the
/// server computes may differ by this much (plus one second: tickets record their issue
/// time in seconds).
pub(crate) const WINDOW_MS: u64 = 10_000;

/// A server's 0-RTT anti-replay state: the freshness check and the ClientHello record.
#[derive(Clone)]
pub(crate) struct AntiReplay {
    store: Arc<dyn AntiReplayStore>,
}

impl fmt::Debug for AntiReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AntiReplay").finish_non_exhaustive()
    }
}

impl AntiReplay {
    pub(crate) fn new(store: Arc<dyn AntiReplayStore>) -> AntiReplay {
        AntiReplay { store }
    }

    pub(crate) fn memory() -> AntiReplay {
        AntiReplay::new(Arc::new(MemoryAntiReplay::new(DEFAULT_ENTRIES)))
    }

    /// Whether a ticket issued at `issued_s` (Unix seconds) and presented at `now_ms` with the
    /// client's view of its age `client_age_ms` is fresh.
    pub(crate) fn fresh(issued_s: u64, client_age_ms: u32, now_ms: u64) -> bool {
        let server_age = now_ms.saturating_sub(issued_s.saturating_mul(1000));
        server_age.abs_diff(u64::from(client_age_ms)) <= WINDOW_MS + 1000
    }

    /// Records the ClientHello identified by `binder`: `false` if it was seen before within
    /// the retention time, if the store is full or if it failed. Retention is three windows:
    /// a replay passes the freshness check up to twice the window (plus the issue-time
    /// rounding) after the first use, and one more window covers servers sharing a store
    /// whose clocks disagree.
    pub(crate) fn record(&self, binder: &[u8]) -> bool {
        let ttl = Duration::from_millis(3 * (WINDOW_MS + 1000));
        self.store.check_and_insert(binder, ttl).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_record() {
        let a = MemoryAntiReplay::new(2);
        let ttl = 20_000;
        assert!(a.record(&[1; 32], ttl, 0).unwrap());
        assert!(!a.record(&[1; 32], ttl, 5).unwrap());
        assert!(!a.record(&[1; 32], ttl, 19_999).unwrap());
        assert!(a.record(&[2; 48], ttl, 10).unwrap());
        // Full: refused until the oldest entry expires.
        assert!(!a.record(&[3; 32], ttl, 100).unwrap());
        assert!(a.record(&[3; 32], ttl, 20_000).unwrap());
        assert!(a.record(&[1; 32], ttl, 20_011).unwrap());
        let b = AntiReplay::new(Arc::new(MemoryAntiReplay::new(10)));
        assert!(b.record(&[7; 32]));
        assert!(!b.record(&[7; 32]));
        assert!(format!("{b:?} {a:?}").contains("MemoryAntiReplay"));
    }

    #[test]
    fn freshness() {
        let now = 1_000_000_000;
        // Issued 5 s ago: the client says 5 s, 14 s, or 0 s.
        assert!(AntiReplay::fresh(999_995, 5_000, now));
        assert!(AntiReplay::fresh(999_995, 15_000, now));
        assert!(!AntiReplay::fresh(999_995, 17_000, now));
        assert!(AntiReplay::fresh(999_995, 0, now));
        // An hour-old ticket presented as fresh: a replay of an old ClientHello.
        assert!(!AntiReplay::fresh(996_400, 2_000, now));
    }

    struct Failing;
    impl AntiReplayStore for Failing {
        fn check_and_insert(&self, _: &[u8], _: Duration) -> io::Result<bool> {
            Err(io::Error::other("down"))
        }
    }

    #[test]
    fn store_errors_fail_closed() {
        assert!(!AntiReplay::new(Arc::new(Failing)).record(&[1; 32]));
    }
}
