//! The endpoint of a UDP socket: routes datagrams to connections by connection ID, accepts new
//! connections (Initial packets), answers unknown versions with Version Negotiation, validates
//! client addresses with Retry and NEW_TOKEN tokens, and sends stateless resets for unknown
//! connection IDs.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::rand::ChaChaRng;

use super::cid::{ConnectionId, LOCAL_CID_LEN, reset_token};
use super::coding::Reader;
use super::conn::{
    ConnConfig, Connection, EndpointEvent, EndpointKeys, Transmit, push_ip, unix_secs,
};
use super::crypto::TokenKey;
use super::packet::{self, HeaderError, MIN_INITIAL_SIZE, PacketType};

pub(crate) const TOKEN_RETRY: u8 = 1;
pub(crate) const TOKEN_NEW: u8 = 2;
const RETRY_TOKEN_LIFETIME: u64 = 10;
const NEW_TOKEN_LIFETIME: u64 = 24 * 3600;
/// Handshakes in progress above which new clients must prove their address with a Retry.
const RETRY_THRESHOLD: usize = 4096;
/// Stateless resets sent per second at most.
const RESETS_PER_SECOND: u32 = 64;

pub(crate) type ConnHandle = u64;

/// How a server endpoint accepts connections.
pub(crate) struct ServerSetup {
    pub tls: only_tls::ServerConfig,
    pub cfg: ConnConfig,
    /// Always validate client addresses with a Retry first.
    pub retry: bool,
}

pub(crate) enum DatagramEvent {
    /// For this connection: hand it the datagram.
    Conn(ConnHandle),
    /// A new connection (it already has the datagram).
    New(ConnHandle, Box<Connection>),
    /// A reply the endpoint sends by itself (Version Negotiation, Retry, stateless reset).
    Respond(Transmit),
}

pub(crate) struct Endpoint {
    keys: Arc<EndpointKeys>,
    rng: ChaChaRng,
    server: Option<ServerSetup>,
    routes: HashMap<ConnectionId, ConnHandle>,
    initial: HashMap<ConnectionId, ConnHandle>,
    ids: HashMap<ConnHandle, Vec<ConnectionId>>,
    handshaking: HashSet<ConnHandle>,
    next: ConnHandle,
    resets: (Instant, u32),
}

impl Endpoint {
    pub fn new(server: Option<ServerSetup>) -> Endpoint {
        let mut rng = ChaChaRng::from_os().unwrap_or_else(|_| {
            // No OS randomness: fall back to a time-derived seed (still unique per process).
            let mut seed = [0u8; 32];
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            seed[..16].copy_from_slice(&t.to_le_bytes());
            ChaChaRng::from_seed(seed)
        });
        Endpoint::with_rng(server, &mut rng)
    }

    pub fn with_rng(server: Option<ServerSetup>, rng: &mut ChaChaRng) -> Endpoint {
        let mut reset_key = [0u8; 32];
        rng.fill(&mut reset_key);
        let mut tk = [0u8; 16];
        rng.fill(&mut tk);
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        Endpoint {
            keys: Arc::new(EndpointKeys {
                reset_key,
                token_key: TokenKey::new(&tk),
            }),
            rng: ChaChaRng::from_seed(seed),
            server,
            routes: HashMap::new(),
            initial: HashMap::new(),
            ids: HashMap::new(),
            handshaking: HashSet::new(),
            next: 1,
            resets: (Instant::now(), 0),
        }
    }

    fn child_rng(&mut self) -> ChaChaRng {
        let mut s = [0u8; 32];
        self.rng.fill(&mut s);
        ChaChaRng::from_seed(s)
    }

    fn register(&mut self, h: ConnHandle, cid: ConnectionId) {
        self.routes.insert(cid, h);
        self.ids.entry(h).or_default().push(cid);
    }

    /// Starts a client connection.
    pub fn connect(
        &mut self,
        now: Instant,
        cfg: ConnConfig,
        tls: &only_tls::ClientConfig,
        server_name: &str,
        addr: SocketAddr,
        token: Vec<u8>,
    ) -> Result<(ConnHandle, Connection), crate::Error> {
        let rng = self.child_rng();
        let c = Connection::client(
            now,
            cfg,
            self.keys.clone(),
            rng,
            tls,
            server_name,
            addr,
            token,
        )?;
        let h = self.next;
        self.next += 1;
        self.register(h, c.local_cid());
        Ok((h, c))
    }

    /// Routes a datagram from `from`.
    pub fn handle(&mut self, now: Instant, from: SocketAddr, data: &[u8]) -> Option<DatagramEvent> {
        let first = *data.first()?;
        if first & 0x80 == 0 {
            let cid = ConnectionId::new(data.get(1..1 + LOCAL_CID_LEN)?)?;
            if let Some(&h) = self.routes.get(&cid) {
                return Some(DatagramEvent::Conn(h));
            }
            if self.server.is_none() {
                // A client's only connection gets what it cannot route (a stateless reset
                // carries no connection ID of ours).
                if self.ids.len() == 1 {
                    return self.ids.keys().next().map(|&h| DatagramEvent::Conn(h));
                }
                return None;
            }
            return self.stateless_reset(now, from, &cid, data.len());
        }
        let h = match packet::parse_header(data, LOCAL_CID_LEN) {
            Ok(h) => h,
            Err(HeaderError::UnsupportedVersion { dcid, scid }) => {
                if self.server.is_some() && data.len() >= MIN_INITIAL_SIZE {
                    let r = (self.rng.next_u32() & 0x7f) as u8;
                    return Some(DatagramEvent::Respond(Transmit {
                        dest: from,
                        segment_size: None,
                        data: packet::version_negotiation(&dcid, &scid, r),
                    }));
                }
                return None;
            }
            Err(HeaderError::Invalid) => return None,
        };
        if let Some(&c) = self
            .routes
            .get(&h.dcid)
            .or_else(|| self.initial.get(&h.dcid))
        {
            return Some(DatagramEvent::Conn(c));
        }
        if self.server.is_none() || h.ty != PacketType::Initial {
            return None;
        }
        // A new connection: only from a full-size Initial with a long enough ID.
        if data.len() < MIN_INITIAL_SIZE || h.dcid.len() < 8 {
            return None;
        }
        let (orig, retry_scid, validated) = match self.check_token(from, h.token, &h.dcid) {
            TokenCheck::Retry(odcid) => (odcid, Some(h.dcid), true),
            TokenCheck::New => (h.dcid, None, true),
            TokenCheck::Invalid => return None,
            TokenCheck::None => {
                let must = self
                    .server
                    .as_ref()
                    .is_some_and(|s| s.retry || self.handshaking.len() >= RETRY_THRESHOLD);
                if must {
                    return Some(self.retry(from, &h.dcid, &h.scid));
                }
                (h.dcid, None, false)
            }
        };
        let rng = self.child_rng();
        let s = self.server.as_ref()?;
        let mut c = Connection::server(
            now,
            s.cfg.clone(),
            self.keys.clone(),
            rng,
            &s.tls,
            from,
            h.dcid,
            h.scid,
            orig,
            retry_scid,
            validated,
        );
        let handle = self.next;
        self.next += 1;
        self.register(handle, c.local_cid());
        self.initial.insert(h.dcid, handle);
        self.ids.entry(handle).or_default().push(h.dcid);
        self.handshaking.insert(handle);
        c.handle_datagram(now, from, data.to_vec());
        Some(DatagramEvent::New(handle, Box::new(c)))
    }

    fn retry(
        &mut self,
        from: SocketAddr,
        odcid: &ConnectionId,
        client_scid: &ConnectionId,
    ) -> DatagramEvent {
        let new_scid = ConnectionId::random(&mut self.rng, LOCAL_CID_LEN);
        let mut plain = Vec::with_capacity(64);
        plain.extend_from_slice(&unix_secs().to_be_bytes());
        plain.push(odcid.len() as u8);
        plain.extend_from_slice(odcid);
        plain.push(new_scid.len() as u8);
        plain.extend_from_slice(&new_scid);
        push_ip(&mut plain, from);
        plain.extend_from_slice(&from.port().to_be_bytes());
        let token = self.keys.token_key.seal(&mut self.rng, TOKEN_RETRY, &plain);
        let r = (self.rng.next_u32() & 0x0f) as u8;
        DatagramEvent::Respond(Transmit {
            dest: from,
            segment_size: None,
            data: packet::retry(client_scid, &new_scid, odcid, &token, r),
        })
    }

    fn check_token(&self, from: SocketAddr, token: &[u8], dcid: &ConnectionId) -> TokenCheck {
        if token.is_empty() {
            return TokenCheck::None;
        }
        let Some((kind, plain)) = self.keys.token_key.open(token) else {
            // Not ours (or corrupted): treat as no token.
            return TokenCheck::None;
        };
        let mut r = Reader::new(&plain);
        let Some(ts) = r
            .bytes(8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap_or_default()))
        else {
            return TokenCheck::None;
        };
        let age = unix_secs().saturating_sub(ts);
        let mut ip = Vec::new();
        push_ip(&mut ip, from);
        match kind {
            TOKEN_RETRY => {
                let parsed = (|| {
                    let odcid = ConnectionId::new(r.vbytes_u8()?)?;
                    let scid = ConnectionId::new(r.vbytes_u8()?)?;
                    let addr = r.bytes(ip.len())?;
                    let port = r.u16()?;
                    Some((odcid, scid, addr == &ip[..] && port == from.port()))
                })();
                match parsed {
                    Some((odcid, scid, true)) if age <= RETRY_TOKEN_LIFETIME && scid == *dcid => {
                        TokenCheck::Retry(odcid)
                    }
                    _ => TokenCheck::Invalid,
                }
            }
            TOKEN_NEW => {
                if age <= NEW_TOKEN_LIFETIME && r.rest() == &ip[..] {
                    TokenCheck::New
                } else {
                    TokenCheck::None
                }
            }
            _ => TokenCheck::None,
        }
    }

    fn stateless_reset(
        &mut self,
        now: Instant,
        from: SocketAddr,
        cid: &ConnectionId,
        len: usize,
    ) -> Option<DatagramEvent> {
        // Smaller than what triggered it, so two endpoints cannot loop (RFC 9000 10.3.3).
        if len <= 22 {
            return None;
        }
        if now.duration_since(self.resets.0) >= Duration::from_secs(1) {
            self.resets = (now, 0);
        }
        if self.resets.1 >= RESETS_PER_SECOND {
            return None;
        }
        self.resets.1 += 1;
        let size = (len - 1).min(43);
        let mut out = vec![0u8; size];
        self.rng.fill(&mut out[..size - 16]);
        out[0] = 0x40 | (out[0] & 0x3f);
        out[size - 16..].copy_from_slice(&reset_token(&self.keys.reset_key, cid));
        Some(DatagramEvent::Respond(Transmit {
            dest: from,
            segment_size: None,
            data: out,
        }))
    }

    /// Applies a connection's endpoint event.
    pub fn handle_event(&mut self, h: ConnHandle, ev: &EndpointEvent) {
        match ev {
            EndpointEvent::NewCid(c) => self.register(h, *c),
            EndpointEvent::RetireCid(c) => {
                self.routes.remove(c);
                if let Some(v) = self.ids.get_mut(&h) {
                    v.retain(|x| x != c);
                }
            }
            EndpointEvent::HandshakeDone => {
                // The client's original destination ID stays routed until the connection is
                // gone: a late retransmitted Initial must not start a second connection.
                self.handshaking.remove(&h);
            }
            EndpointEvent::Drained => {
                self.handshaking.remove(&h);
                if let Some(v) = self.ids.remove(&h) {
                    for c in v {
                        if self.routes.get(&c) == Some(&h) {
                            self.routes.remove(&c);
                        }
                        if self.initial.get(&c) == Some(&h) {
                            self.initial.remove(&c);
                        }
                    }
                }
            }
            EndpointEvent::NewToken(_) => {}
        }
    }
}

enum TokenCheck {
    None,
    Invalid,
    Retry(ConnectionId),
    New,
}

trait ReaderExt<'a> {
    fn vbytes_u8(&mut self) -> Option<&'a [u8]>;
}

impl<'a> ReaderExt<'a> for Reader<'a> {
    fn vbytes_u8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.bytes(n)
    }
}
