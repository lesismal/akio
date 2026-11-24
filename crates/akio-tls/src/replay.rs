//! Where a server records the ClientHellos whose early data (0-RTT) it accepted, so that a
//! replayed ClientHello has its early data rejected (RFC 8446 section 8.2, "ClientHello
//! recording"). The default, [`MemoryAntiReplay`], is a bounded in-memory record private to one
//! [`ServerConfig`](crate::ServerConfig); servers that share session tickets across processes
//! or machines plug in a shared store with
//! [`ServerConfigBuilder::anti_replay_store`](crate::ServerConfigBuilder::anti_replay_store),
//! or, for a remote store answered without blocking the I/O thread, an
//! [`AsyncAntiReplayStore`] with
//! [`ServerConfigBuilder::async_anti_replay_store`](crate::ServerConfigBuilder::async_anti_replay_store).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

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
/// failure. The book's TLS chapter has a full sketch. A store that cannot answer without
/// waiting on the network should implement [`AsyncAntiReplayStore`] instead, which never
/// holds up the I/O thread.
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

/// A shared record of the ClientHellos whose early data was accepted, answered
/// **asynchronously**: for stores across the network (Redis, memcached, a database), so that no
/// I/O thread waits for the round trip (ADR-062).
///
/// The server calls [`check_and_insert`](Self::check_and_insert) on the connection's I/O
/// thread, once per ClientHello that would otherwise have its early data accepted, and
/// suspends that handshake (only that one: the thread goes on with its other connections)
/// until the store answers through the [`ReplayCheck`], from any thread. The call itself must
/// not block: send the request and return, then complete the check from the client
/// library's callback or reader thread. Answering inside the call (a local cache hit) is
/// allowed and costs no suspension.
///
/// The answer has the meaning of [`AntiReplayStore::check_and_insert`]'s: `Ok(true)` accepts
/// the early data, `Ok(false)` (a replay, or the store is full) and `Err` reject it, the
/// handshake going on as a 1-RTT resumption. A check that is dropped without an answer, or
/// that is not answered within the configured timeout
/// ([`ServerConfigBuilder::anti_replay_timeout`](crate::ServerConfigBuilder::anti_replay_timeout),
/// 1 second by default), is rejected the same way (fail closed).
pub trait AsyncAntiReplayStore: Send + Sync {
    /// Records `binder` (32 or 48 bytes, unique per ClientHello) for `ttl`, atomically, and
    /// answers through `done`. Must return without waiting for the store.
    fn check_and_insert(&self, binder: &[u8], ttl: Duration, done: ReplayCheck);
}

/// The answer slot of one [`AsyncAntiReplayStore::check_and_insert`] call: complete it, from
/// any thread, with [`complete`](Self::complete). Dropping it unanswered rejects the early data.
pub struct ReplayCheck {
    slot: Arc<Slot>,
}

impl fmt::Debug for ReplayCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayCheck").finish_non_exhaustive()
    }
}

impl ReplayCheck {
    /// Answers the check: `Ok(true)` if the binder was not recorded yet (the early data is
    /// accepted), `Ok(false)` if it was (or the store is full), `Err` if the store failed
    /// (both reject the early data). The suspended handshake resumes on its I/O thread. An
    /// answer after the timeout is ignored.
    pub fn complete(self, result: io::Result<bool>) {
        self.slot.set(matches!(result, Ok(true)));
    }
}

impl Drop for ReplayCheck {
    fn drop(&mut self) {
        // Unanswered: fail closed (does nothing after `complete`).
        self.slot.set(false);
    }
}

/// Wakes the connection waiting for a [`Slot`].
pub(crate) type Waker = Arc<dyn Fn() + Send + Sync>;

struct SlotState<T> {
    /// The answer (anti-replay: accept the early data or not; certificate resolver: the
    /// certificate, ADR-098).
    result: Option<T>,
    waker: Option<Waker>,
}

/// Where an answer a suspended handshake waits for lands (an asynchronous anti-replay check,
/// ADR-062, or a certificate resolver, ADR-098): the handshake polls it, its connection
/// registers a waker, a blocking driver can wait on it.
pub(crate) struct Slot<T = bool> {
    st: Mutex<SlotState<T>>,
    cv: Condvar,
    /// The answer when the deadline passes (or the lock is poisoned).
    expired: T,
}

impl<T: Clone> Slot<T> {
    /// An empty slot; `expired` is what a missed deadline answers.
    pub(crate) fn new(expired: T) -> Slot<T> {
        Slot {
            st: Mutex::new(SlotState {
                result: None,
                waker: None,
            }),
            cv: Condvar::new(),
            expired,
        }
    }

    /// The first answer wins (the store's or resolver's, or the timeout's).
    pub(crate) fn set(&self, v: T) {
        let waker = {
            let Ok(mut g) = self.st.lock() else { return };
            if g.result.is_some() {
                return;
            }
            g.result = Some(v);
            g.waker.take()
        };
        self.cv.notify_all();
        if let Some(w) = waker {
            w();
        }
    }

    /// The answer, if there is one yet (a poisoned slot answers `expired`).
    pub(crate) fn result(&self) -> Option<T> {
        match self.st.lock() {
            Ok(g) => g.result.clone(),
            Err(_) => Some(self.expired.clone()),
        }
    }

    /// Registers the waker to call when the answer comes; `false` if it is already here
    /// (nothing registered: the caller goes on right away).
    pub(crate) fn set_waker(&self, w: Waker) -> bool {
        match self.st.lock() {
            Ok(mut g) if g.result.is_none() => {
                g.waker = Some(w);
                true
            }
            _ => false,
        }
    }

    /// Blocks until the answer is here (the blocking test stream only).
    pub(crate) fn wait(&self) {
        let Ok(mut g) = self.st.lock() else {
            return;
        };
        while g.result.is_none() {
            g = match self.cv.wait(g) {
                Ok(g) => g,
                Err(_) => return,
            };
        }
    }

    /// Answers `expired` at `at` unless answered before (the shared timer thread).
    pub(crate) fn expire_at(self: &Arc<Self>, at: Instant)
    where
        T: Send + Sync + 'static,
    {
        let weak: Weak<dyn Expire> = Arc::downgrade(self) as Weak<dyn Expire>;
        deadlines().add(at, weak);
    }
}

/// A slot the timer thread can answer.
trait Expire: Send + Sync {
    fn expire(&self);
}

impl<T: Clone + Send + Sync> Expire for Slot<T> {
    fn expire(&self) {
        self.set(self.expired.clone());
    }
}

/// Starts an asynchronous check: the slot the handshake polls, answered by `store` or, after
/// `timeout`, rejected by the shared timer thread.
pub(crate) fn start_check(
    store: &dyn AsyncAntiReplayStore,
    binder: &[u8],
    ttl: Duration,
    timeout: Duration,
) -> Arc<Slot> {
    let slot = Arc::new(Slot::new(false));
    store.check_and_insert(binder, ttl, ReplayCheck { slot: slot.clone() });
    if slot.result().is_none() {
        slot.expire_at(Instant::now() + timeout);
    }
    slot
}

/// Deadlines of pending checks, ordered; a weak reference each (a check answered in time
/// just expires as a no-op).
struct Deadlines {
    heap: Mutex<BinaryHeap<Reverse<Deadline>>>,
    cv: Condvar,
}

struct Deadline(Instant, u64, Weak<dyn Expire>);

impl PartialEq for Deadline {
    fn eq(&self, o: &Deadline) -> bool {
        (self.0, self.1) == (o.0, o.1)
    }
}
impl Eq for Deadline {}
impl PartialOrd for Deadline {
    fn partial_cmp(&self, o: &Deadline) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Deadline {
    fn cmp(&self, o: &Deadline) -> std::cmp::Ordering {
        (self.0, self.1).cmp(&(o.0, o.1))
    }
}

/// The process-wide timer of suspended handshakes' answers (asynchronous anti-replay checks,
/// certificate resolvers): one thread, started by the first answer that is not given right
/// away.
fn deadlines() -> &'static Arc<Deadlines> {
    static D: OnceLock<Arc<Deadlines>> = OnceLock::new();
    D.get_or_init(|| {
        let d = Arc::new(Deadlines {
            heap: Mutex::new(BinaryHeap::new()),
            cv: Condvar::new(),
        });
        let t = d.clone();
        let spawned = std::thread::Builder::new()
            .name("akio-tls-replay-timer".into())
            .spawn(move || t.run());
        if spawned.is_err() {
            akio_log::warn!(target: "akio::tls", "cannot start the anti-replay timer thread: checks rely on the store answering");
        }
        d
    })
}

impl Deadlines {
    fn add(&self, at: Instant, slot: Weak<dyn Expire>) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut h) = self.heap.lock() else { return };
        let first = h.peek().is_none_or(|Reverse(d)| at < d.0);
        h.push(Reverse(Deadline(at, seq, slot)));
        drop(h);
        if first {
            self.cv.notify_one();
        }
    }

    fn run(&self) {
        let Ok(mut h) = self.heap.lock() else { return };
        loop {
            let now = Instant::now();
            let mut due = Vec::new();
            while h.peek().is_some_and(|Reverse(d)| d.0 <= now) {
                if let Some(Reverse(d)) = h.pop() {
                    due.push(d.2);
                }
            }
            if !due.is_empty() {
                drop(h);
                for s in due.iter().filter_map(Weak::upgrade) {
                    s.expire();
                }
                h = match self.heap.lock() {
                    Ok(h) => h,
                    Err(_) => return,
                };
                continue;
            }
            let wait = h
                .peek()
                .map(|Reverse(d)| d.0.saturating_duration_since(now));
            h = match wait {
                Some(w) => match self.cv.wait_timeout(h, w) {
                    Ok((h, _)) => h,
                    Err(_) => return,
                },
                None => match self.cv.wait(h) {
                    Ok(h) => h,
                    Err(_) => return,
                },
            };
        }
    }
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
