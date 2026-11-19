//! Pre-shared keys and session resumption state: client [`Session`]s, server tickets sealed
//! with a [`TicketKey`] (DTLS 1.2 RFC 5077 tickets and DTLS 1.3 NewSessionTicket), and the
//! bounded DTLS 1.2 session-ID cache.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;

use crate::codec::{Reader, put_u16, put_vec8, put_vec24};
use crate::config::Version;
use crate::{CipherSuite, Error};

/// An external pre-shared key: an identity and the secret (RFC 4279 for DTLS 1.2, RFC 8446
/// §4.2.11 external PSKs for DTLS 1.3, with SHA-256).
#[derive(Clone, PartialEq, Eq)]
pub struct Psk {
    pub(crate) identity: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Psk")
            .field("identity", &String::from_utf8_lossy(&self.identity))
            .finish_non_exhaustive()
    }
}

impl Psk {
    /// A PSK. The identity is 1 to 65535 bytes, the key 1 to 65535 bytes (at least 16 random
    /// bytes is the sensible minimum).
    pub fn new(identity: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Result<Psk, Error> {
        let (identity, key) = (identity.into(), key.into());
        if identity.is_empty() || identity.len() > 0xffff {
            return Err(Error::Config("PSK identity must be 1 to 65535 bytes"));
        }
        if key.is_empty() || key.len() > 0xffff {
            return Err(Error::Config("PSK must be 1 to 65535 bytes"));
        }
        Ok(Psk { identity, key })
    }

    /// The identity.
    #[must_use]
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}

/// Seconds since the Unix epoch: ticket issue times must survive restarts and be comparable
/// between servers sharing a [`TicketKey`], which `Instant` is not.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Milliseconds since the Unix epoch (0-RTT ticket ages).
pub(crate) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// What a server needs to resume a session; also what a ticket carries.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SessionState {
    pub(crate) version: Version,
    pub(crate) suite: CipherSuite,
    /// DTLS 1.2: the master secret; DTLS 1.3: the resumption PSK.
    pub(crate) secret: Vec<u8>,
    pub(crate) ems: bool,
    /// Unix seconds.
    pub(crate) issued: u64,
    /// Seconds.
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    /// The peer's certificate chain (checked again by the verifier on resumption).
    pub(crate) peer_chain: Vec<Vec<u8>>,
    /// DTLS 1.3: the max_early_data_size the ticket allows (0: no early data).
    pub(crate) max_early_data: u32,
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("version", &self.version)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// Largest encoded state put into a ticket (a long client certificate chain makes the session
/// not resumable rather than the ticket huge).
const MAX_STATE: usize = 8 << 10;

impl SessionState {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![2];
        put_u16(&mut out, self.version.wire());
        put_u16(&mut out, self.suite.id());
        out.push(u8::from(self.ems));
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.lifetime.to_be_bytes());
        out.extend_from_slice(&self.age_add.to_be_bytes());
        put_vec8(&mut out, &self.secret);
        let mut chain = Vec::new();
        for c in &self.peer_chain {
            put_vec24(&mut chain, c);
        }
        put_vec24(&mut out, &chain);
        out.extend_from_slice(&self.max_early_data.to_be_bytes());
        out
    }

    fn decode(b: &[u8]) -> Option<SessionState> {
        let mut r = Reader::new(b);
        // Format 1 (before ADR-045) has no max_early_data.
        let format = r.u8().ok()?;
        if format != 1 && format != 2 {
            return None;
        }
        let version = Version::from_wire(r.u16().ok()?)?;
        let suite = CipherSuite::from_id(r.u16().ok()?)?;
        let ems = r.u8().ok()? == 1;
        let issued = r.u64().ok()?;
        let lifetime = r.u32().ok()?;
        let age_add = r.u32().ok()?;
        let secret = r.vec8().ok()?.to_vec();
        let mut chain = Reader::new(r.vec24().ok()?);
        let max_early_data = if format == 2 { r.u32().ok()? } else { 0 };
        r.finish().ok()?;
        let mut peer_chain = Vec::new();
        while !chain.is_empty() {
            peer_chain.push(chain.vec24().ok()?.to_vec());
        }
        Some(SessionState {
            version,
            suite,
            secret,
            ems,
            issued,
            lifetime,
            age_add,
            peer_chain,
            max_early_data,
        })
    }

    /// Whether the state is still within its lifetime (and not issued in the future).
    pub(crate) fn is_fresh(&self) -> bool {
        let now = unix_now();
        self.issued <= now + 60 && now < self.issued + u64::from(self.lifetime)
    }
}

/// The key that seals session tickets (AES-256-GCM, key derived from a 32-byte secret). Every
/// server that should accept a ticket needs the same key; rotate it by replacing the
/// [`Config`](crate::Config).
#[derive(Clone)]
pub struct TicketKey {
    name: [u8; 8],
    aead: Box<AesGcm>,
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKey").finish_non_exhaustive()
    }
}

impl TicketKey {
    /// A key from a fresh random secret.
    pub fn generate() -> Result<TicketKey, Error> {
        let mut secret = [0u8; 32];
        only_crypto::rand::fill_random(&mut secret)
            .map_err(|_| Error::Crypto(only_crypto::Error::Random))?;
        TicketKey::from_secret(&secret)
    }

    /// A key from a 32-byte secret shared by several servers.
    pub fn from_secret(secret: &[u8; 32]) -> Result<TicketKey, Error> {
        let key = Hmac::<Sha256>::mac(secret, b"only-dtls ticket key");
        let id = Hmac::<Sha256>::mac(secret, b"only-dtls ticket key name");
        let mut name = [0u8; 8];
        name.copy_from_slice(&id[..8]);
        Ok(TicketKey {
            name,
            aead: Box::new(AesGcm::new(&key)?),
        })
    }

    /// `name || nonce || AES-256-GCM(state)`, or `None` if the state is too large.
    pub(crate) fn seal(&self, state: &SessionState) -> Option<Vec<u8>> {
        let plain = state.encode();
        if plain.len() > MAX_STATE {
            return None;
        }
        let mut nonce = [0u8; 12];
        only_crypto::rand::fill_random(&mut nonce).ok()?;
        let mut out = Vec::with_capacity(8 + 12 + plain.len() + 16);
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&self.aead.encrypt(&nonce, &self.name, &plain));
        Some(out)
    }

    /// The state in a ticket of ours that is still fresh.
    pub(crate) fn open(&self, ticket: &[u8]) -> Option<SessionState> {
        if ticket.len() < 8 + 12 + 16 || ticket[..8] != self.name {
            return None;
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&ticket[8..20]);
        let plain = self.aead.decrypt(&nonce, &self.name, &ticket[20..]).ok()?;
        SessionState::decode(&plain).filter(SessionState::is_fresh)
    }
}

/// A session a client can resume with [`Connection::client_resume`](crate::Connection::client_resume),
/// from [`Event::NewSession`](crate::Event::NewSession). It holds secrets: keep it in memory.
#[derive(Clone)]
pub struct Session {
    pub(crate) state: SessionState,
    /// DTLS 1.2: the session ID to offer (random with a ticket); DTLS 1.3: unused.
    pub(crate) session_id: Vec<u8>,
    /// The ticket (DTLS 1.2 RFC 5077 or DTLS 1.3), empty for a DTLS 1.2 session ID.
    pub(crate) ticket: Vec<u8>,
    pub(crate) received: Instant,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("version", &self.state.version)
            .field("cipher_suite", &self.state.suite)
            .field("ticket", &!self.ticket.is_empty())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The protocol version the session was established with (it resumes only with it).
    #[must_use]
    pub fn version(&self) -> Version {
        self.state.version
    }

    /// The cipher suite of the session.
    #[must_use]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.state.suite
    }

    /// Whether the session is resumed by a ticket (rather than a DTLS 1.2 session ID).
    #[must_use]
    pub fn has_ticket(&self) -> bool {
        !self.ticket.is_empty()
    }

    /// DTLS 1.3: how many bytes of early data (0-RTT) the server accepts when this session
    /// is resumed (0: none). A client sends them with
    /// [`Connection::send_early_data`](crate::Connection::send_early_data) when its
    /// [`Config::with_early_data`](crate::Config::with_early_data) is on.
    #[must_use]
    pub fn max_early_data(&self) -> u32 {
        self.state.max_early_data
    }

    /// When the server stops accepting it (as the server announced; servers may forget it
    /// earlier).
    #[must_use]
    pub fn expires(&self) -> Instant {
        self.received + Duration::from_secs(u64::from(self.state.lifetime))
    }
}

/// The bounded DTLS 1.2 session-ID cache of a server: `capacity` entries, oldest evicted.
pub(crate) struct SessionCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<Vec<u8>, (SessionState, Instant)>,
    order: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl fmt::Debug for SessionCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCache").finish_non_exhaustive()
    }
}

impl SessionCache {
    pub(crate) fn new(capacity: usize) -> SessionCache {
        SessionCache {
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                capacity,
            }),
        }
    }

    pub(crate) fn insert(&self, id: Vec<u8>, state: SessionState, expires: Instant) {
        let Ok(mut c) = self.inner.lock() else {
            return;
        };
        if c.capacity == 0 {
            return;
        }
        while c.map.len() >= c.capacity {
            let Some(old) = c.order.pop_front() else {
                break;
            };
            c.map.remove(&old);
        }
        if c.map.insert(id.clone(), (state, expires)).is_none() {
            c.order.push_back(id);
        }
    }

    pub(crate) fn get(&self, id: &[u8], now: Instant) -> Option<SessionState> {
        let mut c = self.inner.lock().ok()?;
        match c.map.get(id) {
            Some((s, exp)) if *exp > now => Some(s.clone()),
            Some(_) => {
                c.map.remove(id);
                c.order.retain(|k| k != id);
                None
            }
            None => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().map_or(0, |c| c.map.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SessionState {
        SessionState {
            version: Version::Dtls13,
            suite: CipherSuite::Tls13Aes128GcmSha256,
            secret: vec![7; 32],
            ems: true,
            issued: unix_now(),
            lifetime: 3600,
            age_add: 99,
            peer_chain: vec![vec![1, 2, 3], vec![4]],
            max_early_data: 0,
        }
    }

    #[test]
    fn tickets_roundtrip_and_reject() {
        let k = TicketKey::from_secret(&[3; 32]).unwrap();
        let t = k.seal(&state()).unwrap();
        assert_eq!(k.open(&t).unwrap(), state());
        let other = TicketKey::generate().unwrap();
        assert!(other.open(&t).is_none(), "another key");
        let mut bad = t.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(k.open(&bad).is_none(), "tampered");
        assert!(k.open(&t[..30]).is_none());
        let mut old = state();
        old.issued -= 7200;
        assert!(k.open(&k.seal(&old).unwrap()).is_none(), "expired");
        let mut big = state();
        big.peer_chain = vec![vec![0; MAX_STATE]];
        assert!(k.seal(&big).is_none(), "too large");
        // Same secret, same key: tickets work across servers.
        assert!(TicketKey::from_secret(&[3; 32]).unwrap().open(&t).is_some());
        let mut early = state();
        early.max_early_data = 1234;
        assert_eq!(k.open(&k.seal(&early).unwrap()).unwrap(), early);
        // Format 1 (before 0-RTT) still decodes, without early data.
        let mut v1 = state().encode();
        v1[0] = 1;
        v1.truncate(v1.len() - 4);
        assert_eq!(SessionState::decode(&v1).unwrap(), state());
        v1[0] = 3;
        assert!(SessionState::decode(&v1).is_none());
    }

    #[test]
    fn cache_is_bounded() {
        let c = SessionCache::new(3);
        let now = Instant::now();
        for i in 0..10u8 {
            c.insert(vec![i], state(), now + Duration::from_secs(60));
            assert!(c.len() <= 3);
        }
        assert!(c.get(&[0], now).is_none(), "evicted");
        assert!(c.get(&[9], now).is_some());
        assert!(
            c.get(&[9], now + Duration::from_secs(61)).is_none(),
            "expired"
        );
        assert_eq!(c.len(), 2);
        assert!(SessionCache::new(0).get(&[1], now).is_none());
    }

    #[test]
    fn psk_bounds() {
        assert!(Psk::new("", "k").is_err());
        assert!(Psk::new("id", "").is_err());
        let p = Psk::new("id", vec![1; 16]).unwrap();
        assert_eq!(p.identity(), b"id");
        assert!(!format!("{p:?}").contains("[1"));
    }
}
