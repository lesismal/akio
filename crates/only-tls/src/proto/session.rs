//! Session resumption state: what a server seals into a ticket or keeps in its cache, and what
//! a client remembers per server.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::alert::{Alert, Fatal, fatal};
use super::codec::{DResult, Reader, put_u8, put_u16, put_u32, put_vec8, put_vec16, put_vec24};
use super::common::random;
use crate::replay::{AntiReplayStore, AsyncAntiReplayStore, Slot, start_check};

/// A resumable session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Session {
    /// 0x0303 or 0x0304.
    pub(crate) version: u16,
    pub(crate) suite: u16,
    /// TLS 1.3: the resumption PSK; TLS 1.2: the master secret.
    pub(crate) secret: Vec<u8>,
    /// Unix seconds.
    pub(crate) created: u64,
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) sni: Option<String>,
    pub(crate) ems: bool,
    /// The client's certificate chain (server side).
    pub(crate) peer_chain: Vec<Vec<u8>>,
    /// TLS 1.3: the max_early_data_size of the ticket (0: no early data).
    pub(crate) max_early_data: u32,
    /// TLS 1.3 early data context. Server: what the early data was bound to besides the
    /// ticket (QUIC: the transport parameters 0-RTT may use, RFC 9001 section 4.6.2). Client
    /// (QUIC): the server's transport parameters, remembered for 0-RTT (RFC 9000 7.4.1).
    pub(crate) early_ctx: Vec<u8>,
    /// QUIC: the version of the connection the ticket belongs to (RFC 9369 section 5);
    /// 0 for TLS over TCP and for QUIC handshakes not bound to a version.
    pub(crate) quic_version: u32,
}

impl Session {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(128);
        put_u8(&mut o, 3); // format
        put_u16(&mut o, self.version);
        put_u16(&mut o, self.suite);
        put_vec8(&mut o, &self.secret);
        o.extend_from_slice(&self.created.to_be_bytes());
        put_u32(&mut o, self.lifetime);
        put_u32(&mut o, self.age_add);
        put_u8(&mut o, u8::from(self.alpn.is_some()));
        put_vec8(&mut o, self.alpn.as_deref().unwrap_or_default());
        put_u8(&mut o, u8::from(self.sni.is_some()));
        put_vec16(&mut o, self.sni.as_deref().unwrap_or_default().as_bytes());
        put_u8(&mut o, u8::from(self.ems));
        put_u16(&mut o, self.peer_chain.len() as u16);
        for c in &self.peer_chain {
            put_vec24(&mut o, c);
        }
        put_u32(&mut o, self.max_early_data);
        put_vec16(&mut o, &self.early_ctx);
        put_u32(&mut o, self.quic_version);
        o
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Session> {
        Self::try_decode(b).ok()
    }

    fn try_decode(b: &[u8]) -> DResult<Session> {
        let mut r = Reader::new(b);
        // Format 2 predates the QUIC version (read as 0, unbound).
        let format = r.u8()?;
        if format != 2 && format != 3 {
            return fatal(Alert::DecodeError, "session format");
        }
        let version = r.u16()?;
        let suite = r.u16()?;
        let secret = r.vec8()?.to_vec();
        let created = u64::from_be_bytes(r.array()?);
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let has_alpn = r.u8()? == 1;
        let alpn = r.vec8()?.to_vec();
        let has_sni = r.u8()? == 1;
        let sni = String::from_utf8(r.vec16()?.to_vec())
            .map_err(|_| Fatal::new(Alert::DecodeError, "session sni"))?;
        let ems = r.u8()? == 1;
        let n = r.u16()?;
        let mut peer_chain = Vec::new();
        for _ in 0..n {
            peer_chain.push(r.vec24()?.to_vec());
        }
        let max_early_data = r.u32()?;
        let early_ctx = r.vec16()?.to_vec();
        let quic_version = if format == 3 { r.u32()? } else { 0 };
        r.finish()?;
        Ok(Session {
            version,
            suite,
            secret,
            created,
            lifetime,
            age_add,
            alpn: has_alpn.then_some(alpn),
            sni: has_sni.then_some(sni),
            ems,
            peer_chain,
            max_early_data,
            early_ctx,
            quic_version,
        })
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        now < self.created || now - self.created > u64::from(self.lifetime)
    }
}

/// Seals sessions into stateless tickets: `key_name(16) || nonce(12) || ChaCha20-Poly1305`,
/// under one key for the configuration's lifetime (the default, and `session_ticket_key`) or
/// under rotating [`TicketKeys`](crate::TicketKeys).
pub(crate) enum Ticketer {
    Fixed(crate::tickets::TicketKey),
    Rotating(crate::tickets::TicketKeys),
}

impl std::fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticketer").finish_non_exhaustive()
    }
}

impl Ticketer {
    pub(crate) fn new() -> Option<Ticketer> {
        Some(Ticketer::from_key(&random::<48>().ok()?))
    }

    /// A ticketer whose tickets every ticketer with the same key opens.
    pub(crate) fn from_key(key: &[u8; 48]) -> Ticketer {
        Ticketer::Fixed(crate::tickets::TicketKey::new(key))
    }

    pub(crate) fn seal(&self, s: &Session) -> Option<Vec<u8>> {
        match self {
            Ticketer::Fixed(k) => k.seal(s),
            Ticketer::Rotating(k) => k.seal(s),
        }
    }

    pub(crate) fn open(&self, ticket: &[u8]) -> Option<Session> {
        match self {
            Ticketer::Fixed(k) => k.open(ticket),
            Ticketer::Rotating(k) => k.open(ticket),
        }
    }
}

type Lru<K, V> = Mutex<(HashMap<K, V>, VecDeque<K>)>;

/// A bounded server-side cache: TLS 1.2 session IDs and single-use TLS 1.3 ticket IDs.
#[derive(Debug)]
pub(crate) struct SessionCache {
    cap: usize,
    inner: Lru<Vec<u8>, Session>,
}

impl SessionCache {
    pub(crate) fn new(cap: usize) -> SessionCache {
        SessionCache {
            cap,
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    pub(crate) fn put(&self, id: Vec<u8>, s: Session) {
        let Ok(mut g) = self.inner.lock() else { return };
        let (map, order) = &mut *g;
        while map.len() >= self.cap {
            match order.pop_front() {
                Some(old) => {
                    map.remove(&old);
                }
                None => break,
            }
        }
        if map.insert(id.clone(), s).is_none() {
            order.push_back(id);
        }
    }

    pub(crate) fn get(&self, id: &[u8]) -> Option<Session> {
        self.inner.lock().ok()?.0.get(id).cloned()
    }

    pub(crate) fn take(&self, id: &[u8]) -> Option<Session> {
        let mut g = self.inner.lock().ok()?;
        let s = g.0.remove(id)?;
        g.1.retain(|k| k != id);
        Some(s)
    }
}

/// The server's 0-RTT anti-replay state (RFC 8446 section 8.2, "ClientHello recording", with
/// the freshness check of section 8.3): the PSK binder of every ClientHello whose early data
/// was accepted is recorded in the store for three freshness windows, and a ClientHello
/// whose binder is already there has its early data rejected (it falls back to a 1-RTT
/// resumption). Early data is accepted only when the ticket age the client reports is within
/// the window of the age the server computes, so a replay that comes after its entry expired
/// fails the freshness check instead. The store is a bounded in-memory record per server
/// configuration unless the application plugs in a shared one; store errors reject the early
/// data (fail closed).
pub(crate) struct AntiReplay {
    /// The freshness window, milliseconds.
    pub(crate) window_ms: u64,
    store: ReplayStore,
}

/// Where accepted ClientHellos are recorded.
pub(crate) enum ReplayStore {
    /// Answered in the call (the default in-memory record, or an application's).
    Sync(Arc<dyn AntiReplayStore>),
    /// Answered later; the handshake waits at most the timeout.
    Async(Arc<dyn AsyncAntiReplayStore>, Duration),
}

/// The answer of [`AntiReplay::record`].
pub(crate) enum Verdict {
    /// Known now: accept the early data or not.
    Now(bool),
    /// Comes later through the slot: the handshake suspends.
    Later(Arc<Slot>),
}

impl std::fmt::Debug for AntiReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AntiReplay")
            .field("window_ms", &self.window_ms)
            .field("async", &matches!(self.store, ReplayStore::Async(..)))
            .finish_non_exhaustive()
    }
}

impl AntiReplay {
    pub(crate) fn new(window_ms: u64, store: ReplayStore) -> AntiReplay {
        AntiReplay { window_ms, store }
    }

    /// Whether a ticket issued at `issued_ms` and presented at `now_ms` with the client's view
    /// of its age `client_age_ms` is fresh: both ages within the window of each other.
    pub(crate) fn fresh(&self, issued_ms: u64, client_age_ms: u32, now_ms: u64) -> bool {
        let server_age = now_ms.saturating_sub(issued_ms);
        server_age.abs_diff(u64::from(client_age_ms)) <= self.window_ms
    }

    /// Records the ClientHello identified by `binder` (its first PSK binder): `false` if it
    /// was seen before within the retention time, if the store is full or if it failed; or,
    /// with an asynchronous store that did not answer in the call, the slot the answer
    /// comes to.
    ///
    /// Retention: a replay passes the freshness check up to twice the window after the first
    /// use on the same clock; servers sharing a store may disagree on the time, so one more
    /// window covers clocks up to that far apart (three windows, 30 s by default).
    pub(crate) fn record(&self, binder: &[u8]) -> Verdict {
        let ttl = Duration::from_millis(self.window_ms.saturating_mul(3));
        match &self.store {
            ReplayStore::Sync(st) => {
                Verdict::Now(st.check_and_insert(binder, ttl).unwrap_or(false))
            }
            ReplayStore::Async(st, timeout) => {
                let slot = start_check(&**st, binder, ttl, *timeout);
                match slot.result() {
                    Some(r) => Verdict::Now(r),
                    None => Verdict::Later(slot),
                }
            }
        }
    }
}

/// A TLS 1.3 ticket a client holds.
#[derive(Clone, Debug)]
pub(crate) struct Ticket13 {
    pub(crate) ticket: Vec<u8>,
    pub(crate) session: Session,
    /// When it was received, Unix milliseconds.
    pub(crate) received_ms: u64,
    /// The server's record_size_limit on the connection that sent it (0: none): early data
    /// sent with it goes under that limit.
    pub(crate) record_limit: u16,
}

/// A TLS 1.2 session a client holds.
#[derive(Clone, Debug)]
pub(crate) struct Resume12 {
    pub(crate) session_id: Vec<u8>,
    pub(crate) ticket: Option<Vec<u8>>,
    pub(crate) session: Session,
}

#[derive(Default, Debug)]
struct Entry {
    tls13: VecDeque<Ticket13>,
    tls12: Option<Resume12>,
}

/// The client's per-server memory of sessions.
#[derive(Debug)]
pub(crate) struct ClientCache {
    inner: Lru<String, Entry>,
}

const CLIENT_SERVERS: usize = 256;
const TICKETS_PER_SERVER: usize = 8;

impl ClientCache {
    pub(crate) fn new() -> ClientCache {
        ClientCache {
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    fn with<R>(&self, server: &str, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        let mut g = self.inner.lock().ok()?;
        let (map, order) = &mut *g;
        if !map.contains_key(server) {
            while map.len() >= CLIENT_SERVERS {
                match order.pop_front() {
                    Some(old) => {
                        map.remove(&old);
                    }
                    None => break,
                }
            }
            map.insert(server.to_owned(), Entry::default());
            order.push_back(server.to_owned());
        }
        map.get_mut(server).map(f)
    }

    pub(crate) fn add_ticket13(&self, server: &str, t: Ticket13) {
        self.with(server, |e| {
            if e.tls13.len() >= TICKETS_PER_SERVER {
                e.tls13.pop_front();
            }
            e.tls13.push_back(t);
        });
    }

    /// Takes the newest usable ticket for QUIC version `quic_version` (0: TLS over TCP or an
    /// unbound QUIC handshake); tickets are single use. Expired ones are dropped, tickets of
    /// other versions stay.
    pub(crate) fn take_ticket13(
        &self,
        server: &str,
        now: u64,
        quic_version: u32,
    ) -> Option<Ticket13> {
        self.with(server, |e| {
            e.tls13.retain(|t| !t.session.expired(now));
            let i = e
                .tls13
                .iter()
                .rposition(|t| t.session.quic_version == quic_version)?;
            e.tls13.remove(i)
        })
        .flatten()
    }

    /// The QUIC version of the newest usable QUIC ticket for `server`, if any.
    pub(crate) fn quic_ticket_version(&self, server: &str, now: u64) -> Option<u32> {
        let g = self.inner.lock().ok()?;
        g.0.get(server)?
            .tls13
            .iter()
            .rev()
            .find(|t| t.session.quic_version != 0 && !t.session.expired(now))
            .map(|t| t.session.quic_version)
    }

    pub(crate) fn set_tls12(&self, server: &str, r: Option<Resume12>) {
        self.with(server, |e| e.tls12 = r);
    }

    pub(crate) fn tls12(&self, server: &str, now: u64) -> Option<Resume12> {
        self.with(server, |e| {
            e.tls12.clone().filter(|r| !r.session.expired(now))
        })
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            version: 0x0304,
            suite: 0x1301,
            secret: vec![1; 32],
            created: 100,
            lifetime: 10,
            age_add: 7,
            alpn: Some(b"h2".to_vec()),
            sni: Some("a.test".into()),
            ems: true,
            peer_chain: vec![vec![1, 2], vec![3]],
            max_early_data: 16384,
            early_ctx: vec![9, 9],
            quic_version: 0x6b33_43cf,
        }
    }

    #[test]
    fn session_codec_and_tickets() {
        let s = session();
        assert_eq!(Session::decode(&s.encode()).unwrap(), s);
        assert!(Session::decode(&s.encode()[..10]).is_none());
        // Format 2 (before the QUIC version): unbound.
        let mut old = s.encode();
        old[0] = 2;
        old.truncate(old.len() - 4);
        let o = Session::decode(&old).unwrap();
        assert_eq!(o.quic_version, 0);
        assert_eq!(o.early_ctx, s.early_ctx);
        assert!(!s.expired(105));
        assert!(s.expired(111));
        assert!(s.expired(99));
        let t = Ticketer::new().unwrap();
        let sealed = t.seal(&s).unwrap();
        assert_eq!(t.open(&sealed).unwrap(), s);
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(t.open(&bad).is_none());
        assert!(Ticketer::new().unwrap().open(&sealed).is_none());
        let (a, b) = (
            Ticketer::from_key(&{
                let mut k = [1; 48];
                k[16..].fill(2);
                k
            }),
            Ticketer::from_key(&{
                let mut k = [1; 48];
                k[16..].fill(2);
                k
            }),
        );
        assert_eq!(b.open(&a.seal(&s).unwrap()).unwrap(), s);
        assert!(
            Ticketer::from_key(&{
                let mut k = [1; 48];
                k[16..].fill(3);
                k
            })
            .open(&a.seal(&s).unwrap())
            .is_none()
        );
        assert!(t.open(&[0; 10]).is_none());
    }

    #[test]
    fn anti_replay() {
        use crate::replay::MemoryAntiReplay;
        let now = |v: Verdict| match v {
            Verdict::Now(b) => b,
            Verdict::Later(_) => panic!("a synchronous store answers now"),
        };
        let a = AntiReplay::new(
            10_000,
            ReplayStore::Sync(Arc::new(MemoryAntiReplay::new(2))),
        );
        assert!(a.fresh(1_000, 5_000, 6_000));
        assert!(a.fresh(1_000, 0, 11_000));
        assert!(!a.fresh(1_000, 0, 11_001));
        assert!(!a.fresh(30_000, 15_000, 30_000));
        assert!(now(a.record(&[1; 32])));
        assert!(!now(a.record(&[1; 32])));
        assert!(now(a.record(&[2; 32])));
        // Full.
        assert!(!now(a.record(&[3; 32])));
        // A failing store fails closed.
        struct Down;
        impl AntiReplayStore for Down {
            fn check_and_insert(&self, _: &[u8], _: Duration) -> std::io::Result<bool> {
                Err(std::io::Error::other("down"))
            }
        }
        assert!(!now(AntiReplay::new(
            10_000,
            ReplayStore::Sync(Arc::new(Down))
        )
        .record(&[4; 32])));
    }

    #[test]
    fn async_anti_replay() {
        use crate::replay::{AsyncAntiReplayStore, ReplayCheck};
        use std::sync::Mutex;
        /// Answers inline when `inline`, else keeps the checks for the test to answer.
        struct Remote {
            inline: bool,
            held: Mutex<Vec<ReplayCheck>>,
        }
        impl AsyncAntiReplayStore for Remote {
            fn check_and_insert(&self, binder: &[u8], ttl: Duration, done: ReplayCheck) {
                assert_eq!(ttl, Duration::from_secs(30));
                if self.inline {
                    done.complete(Ok(binder[0] == 1));
                } else {
                    self.held.lock().unwrap().push(done);
                }
            }
        }
        let inline = Arc::new(Remote {
            inline: true,
            held: Mutex::new(Vec::new()),
        });
        let a = AntiReplay::new(10_000, ReplayStore::Async(inline, Duration::from_secs(1)));
        assert!(matches!(a.record(&[1; 32]), Verdict::Now(true)));
        assert!(matches!(a.record(&[2; 32]), Verdict::Now(false)));

        let remote = Arc::new(Remote {
            inline: false,
            held: Mutex::new(Vec::new()),
        });
        let a = AntiReplay::new(
            10_000,
            ReplayStore::Async(remote.clone(), Duration::from_millis(200)),
        );
        let Verdict::Later(s1) = a.record(&[1; 32]) else {
            panic!("pending")
        };
        let Verdict::Later(s2) = a.record(&[2; 32]) else {
            panic!("pending")
        };
        let Verdict::Later(s3) = a.record(&[3; 32]) else {
            panic!("pending")
        };
        let Verdict::Later(s4) = a.record(&[4; 32]) else {
            panic!("pending")
        };
        assert_eq!(s1.result(), None);
        let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = woken.clone();
        assert!(s1.set_waker(Arc::new(move || {
            w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })));
        let mut held = std::mem::take(&mut *remote.held.lock().unwrap());
        let c4 = held.pop().unwrap();
        let c3 = held.pop().unwrap();
        let c2 = held.pop().unwrap();
        let c1 = held.pop().unwrap();
        // Answered from another thread: the waker runs once.
        std::thread::spawn(move || c1.complete(Ok(true)))
            .join()
            .unwrap();
        assert_eq!(s1.result(), Some(true));
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!s1.set_waker(Arc::new(|| {})), "already answered");
        // A store error and a dropped check reject.
        c2.complete(Err(std::io::Error::other("down")));
        assert_eq!(s2.result(), Some(false));
        drop(c3);
        assert_eq!(s3.result(), Some(false));
        // No answer: the timeout rejects, and a late answer changes nothing.
        assert!(!s4.wait());
        c4.complete(Ok(true));
        assert_eq!(s4.result(), Some(false));
    }

    #[test]
    fn caches() {
        let c = SessionCache::new(2);
        c.put(vec![1], session());
        c.put(vec![2], session());
        c.put(vec![3], session());
        assert!(c.get(&[1]).is_none());
        assert!(c.get(&[2]).is_some());
        assert!(c.take(&[3]).is_some());
        assert!(c.take(&[3]).is_none());

        let cc = ClientCache::new();
        for i in 0..10u8 {
            let mut s = session();
            s.secret = vec![i];
            cc.add_ticket13(
                "a",
                Ticket13 {
                    ticket: vec![i],
                    session: s,
                    received_ms: 0,
                    record_limit: 0,
                },
            );
        }
        // Tickets of another QUIC version stay for a connection in that version.
        let mut v1 = session();
        v1.quic_version = 1;
        cc.add_ticket13(
            "a",
            Ticket13 {
                ticket: vec![100],
                session: v1,
                received_ms: 0,
                record_limit: 0,
            },
        );
        assert_eq!(cc.quic_ticket_version("a", 105), Some(1));
        assert_eq!(cc.take_ticket13("a", 105, 1).unwrap().ticket, vec![100]);
        assert!(cc.take_ticket13("a", 105, 1).is_none());
        assert!(cc.take_ticket13("a", 105, 0).is_none());
        assert_eq!(cc.quic_ticket_version("a", 105), Some(0x6b33_43cf));
        assert_eq!(
            cc.take_ticket13("a", 105, 0x6b33_43cf).unwrap().ticket,
            vec![9]
        );
        assert_eq!(
            cc.take_ticket13("a", 105, 0x6b33_43cf).unwrap().ticket,
            vec![8]
        );
        assert!(cc.take_ticket13("a", 1000, 0x6b33_43cf).is_none());
        assert_eq!(cc.quic_ticket_version("a", 105), None);
        assert!(cc.take_ticket13("b", 105, 0x6b33_43cf).is_none());
        cc.set_tls12(
            "a",
            Some(Resume12 {
                session_id: vec![1],
                ticket: None,
                session: session(),
            }),
        );
        assert!(cc.tls12("a", 105).is_some());
        assert!(cc.tls12("a", 1000).is_none());
    }
}
