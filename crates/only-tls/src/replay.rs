//! Where a server records the ClientHellos whose early data (0-RTT) it accepted, so that a
//! replayed ClientHello has its early data rejected (RFC 8446 section 8.2, "ClientHello
//! recording"). The default, [`MemoryAntiReplay`], is a bounded in-memory record private to one
//! [`ServerConfig`](crate::ServerConfig); servers that share session tickets across processes
//! or machines plug in a shared store with
//! [`ServerConfigBuilder::anti_replay_store`](crate::ServerConfigBuilder::anti_replay_store).

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use crate::proto::common::now_millis;

/// A record of the ClientHellos whose early data was accepted, shared by the servers that
/// accept the same session tickets.
///
/// The server calls [`check_and_insert`](Self::check_and_insert) once per ClientHello that
/// would otherwise have its early data accepted, on the connection's I/O thread, during the
/// handshake. An implementation backed by a remote store (Redis, memcached, a database) makes
/// one round trip there: keep it short and bounded by a timeout, because that connection's
/// I/O thread waits for it (a full handshake is the fallback, so failing fast costs one round
/// trip of latency, not the connection).
///
/// For example, with Redis: `SET <prefix><hex binder> 1 NX PX <ttl ms>`, answering `Ok(true)`
/// for `OK`, `Ok(false)` for a nil reply (the key exists) and `Err` for a timeout or any other
/// failure. The book's TLS chapter has a full sketch.
pub trait AntiReplayStore: Send + Sync {
    /// Records `binder` (the first PSK binder of a ClientHello, 32 or 48 bytes; unique per
    /// ClientHello and unpredictable) for `ttl` (30 seconds), atomically: `Ok(true)` if it was not
    /// recorded yet (the early data is accepted), `Ok(false)` if it was (a replay: the early
    /// data is rejected). `Ok(false)` is also the answer when the store cannot take more
    /// entries.
    ///
    /// Errors **fail closed**: the early data is rejected and the handshake goes on as a
    /// 1-RTT resumption, the client sending the same data again once it completes.
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
    /// A record holding up to `entries` ClientHellos (the server default is 100,000).
    pub fn new(entries: usize) -> MemoryAntiReplay {
        MemoryAntiReplay {
            cap: entries,
            inner: Mutex::new((HashSet::new(), VecDeque::new())),
        }
    }

    /// [`check_and_insert`](AntiReplayStore::check_and_insert) at `now_ms` (Unix ms).
    pub(crate) fn record(&self, binder: &[u8], ttl_ms: u64, now_ms: u64) -> io::Result<bool> {
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
        self.record(binder, ttl_ms, now_millis())
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
        // A replay inside the retention time is refused, also later in it.
        assert!(!a.record(&[1; 32], ttl, 5).unwrap());
        assert!(!a.record(&[1; 32], ttl, 19_999).unwrap());
        assert!(a.record(&[2; 48], ttl, 10).unwrap());
        // Full: refused, until the oldest entry expires.
        assert!(!a.record(&[3; 32], ttl, 100).unwrap());
        assert!(a.record(&[3; 32], ttl, 20_000).unwrap());
        // The first entry expired: accepted again (the freshness check covers this case).
        assert!(a.record(&[1; 32], ttl, 20_011).unwrap());
        // Through the trait, with the clock.
        let b = MemoryAntiReplay::new(10);
        let d = Duration::from_secs(20);
        assert!(b.check_and_insert(&[7; 32], d).unwrap());
        assert!(!b.check_and_insert(&[7; 32], d).unwrap());
        assert!(format!("{b:?}").contains("MemoryAntiReplay"));
    }
}
