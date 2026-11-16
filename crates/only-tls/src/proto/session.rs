//! Session resumption state: what a server seals into a ticket or keeps in its cache, and what
//! a client remembers per server.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use only_crypto::chacha::ChaCha20Poly1305;

use super::alert::{Alert, Fatal, fatal};
use super::codec::{DResult, Reader, put_u8, put_u16, put_u32, put_vec8, put_vec16, put_vec24};
use super::common::random;

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
}

impl Session {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(128);
        put_u8(&mut o, 2); // format
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
        o
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Session> {
        Self::try_decode(b).ok()
    }

    fn try_decode(b: &[u8]) -> DResult<Session> {
        let mut r = Reader::new(b);
        if r.u8()? != 2 {
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
        })
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        now < self.created || now - self.created > u64::from(self.lifetime)
    }
}

/// Seals sessions into stateless tickets: `key_name(16) || nonce(12) || ChaCha20-Poly1305`.
pub(crate) struct Ticketer {
    name: [u8; 16],
    key: ChaCha20Poly1305,
}

impl std::fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticketer").finish_non_exhaustive()
    }
}

impl Ticketer {
    pub(crate) fn new() -> Option<Ticketer> {
        let name = random::<16>().ok()?;
        let key = random::<32>().ok()?;
        Some(Ticketer {
            name,
            key: ChaCha20Poly1305::new(&key),
        })
    }

    pub(crate) fn seal(&self, s: &Session) -> Option<Vec<u8>> {
        let nonce = random::<12>().ok()?;
        let mut out = self.name.to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&self.key.encrypt(&nonce, &self.name, &s.encode()));
        Some(out)
    }

    pub(crate) fn open(&self, ticket: &[u8]) -> Option<Session> {
        if ticket.len() < 16 + 12 + 16 || ticket[..16] != self.name {
            return None;
        }
        let nonce: [u8; 12] = ticket[16..28].try_into().ok()?;
        let plain = self.key.decrypt(&nonce, &self.name, &ticket[28..]).ok()?;
        Session::decode(&plain)
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

/// Binders recorded (first 32 bytes), and their expiry times in order.
type Seen = (std::collections::HashSet<[u8; 32]>, VecDeque<(u64, [u8; 32])>);

/// The server's 0-RTT anti-replay state (RFC 8446 section 8.2, "ClientHello recording", with
/// the freshness check of section 8.3): the PSK binder of every ClientHello whose early data
/// was accepted is kept for twice the freshness window, and a ClientHello whose binder is
/// already there has its early data rejected (it falls back to a full 1-RTT handshake). Early
/// data is accepted only when the ticket age the client reports is within the window of the
/// age the server computes, so a replay that comes after its entry expired fails the freshness
/// check instead. Bounded: when the cache is full, early data is rejected until entries
/// expire. One per server configuration (and so per process): servers sharing tickets across
/// processes or machines need a shared store (or single-use tickets) instead.
#[derive(Debug)]
pub(crate) struct AntiReplay {
    /// The freshness window, milliseconds.
    pub(crate) window_ms: u64,
    cap: usize,
    inner: Mutex<Seen>,
}

impl AntiReplay {
    pub(crate) fn new(window_ms: u64, cap: usize) -> AntiReplay {
        AntiReplay {
            window_ms,
            cap,
            inner: Mutex::new((std::collections::HashSet::new(), VecDeque::new())),
        }
    }

    /// Whether a ticket issued at `issued_ms` and presented at `now_ms` with the client's view
    /// of its age `client_age_ms` is fresh: both ages within the window of each other.
    pub(crate) fn fresh(&self, issued_ms: u64, client_age_ms: u32, now_ms: u64) -> bool {
        let server_age = now_ms.saturating_sub(issued_ms);
        server_age.abs_diff(u64::from(client_age_ms)) <= self.window_ms
    }

    /// Records the ClientHello identified by `binder` (its first PSK binder) at `now_ms`:
    /// `false` if it was seen before within the retention time, or if the cache is full.
    pub(crate) fn record(&self, binder: &[u8], now_ms: u64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
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
            return false;
        }
        set.insert(key);
        order.push_back((now_ms + 2 * self.window_ms, key));
        true
    }
}

/// A TLS 1.3 ticket a client holds.
#[derive(Clone, Debug)]
pub(crate) struct Ticket13 {
    pub(crate) ticket: Vec<u8>,
    pub(crate) session: Session,
    /// When it was received, Unix milliseconds.
    pub(crate) received_ms: u64,
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

    /// Takes the newest usable ticket (tickets are single use).
    pub(crate) fn take_ticket13(&self, server: &str, now: u64) -> Option<Ticket13> {
        self.with(server, |e| {
            while let Some(t) = e.tls13.pop_back() {
                if !t.session.expired(now) {
                    return Some(t);
                }
            }
            None
        })
        .flatten()
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
        }
    }

    #[test]
    fn session_codec_and_tickets() {
        let s = session();
        assert_eq!(Session::decode(&s.encode()).unwrap(), s);
        assert!(Session::decode(&s.encode()[..10]).is_none());
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
        assert!(t.open(&[0; 10]).is_none());
    }

    #[test]
    fn anti_replay() {
        let a = AntiReplay::new(10_000, 2);
        assert!(a.fresh(1_000, 5_000, 6_000));
        assert!(a.fresh(1_000, 0, 11_000));
        assert!(!a.fresh(1_000, 0, 11_001));
        assert!(!a.fresh(30_000, 15_000, 30_000));
        assert!(a.record(&[1; 32], 0));
        // A replay inside the retention time is refused, also later in it.
        assert!(!a.record(&[1; 32], 5));
        assert!(!a.record(&[1; 32], 19_999));
        assert!(a.record(&[2; 48], 10));
        // Full: refused, until the oldest entry expires.
        assert!(!a.record(&[3; 32], 100));
        assert!(a.record(&[3; 32], 20_000));
        // The first entry expired: accepted again (the freshness check covers this case).
        assert!(a.record(&[1; 32], 20_011));
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
                },
            );
        }
        assert_eq!(cc.take_ticket13("a", 105).unwrap().ticket, vec![9]);
        assert!(cc.take_ticket13("a", 1000).is_none());
        assert!(cc.take_ticket13("b", 105).is_none());
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
