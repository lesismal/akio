//! The endpoint of a UDP socket: routes datagrams to connections by connection ID, accepts new
//! connections (Initial packets), answers unknown versions with Version Negotiation, validates
//! client addresses with Retry and NEW_TOKEN tokens, and sends stateless resets for unknown
//! connection IDs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use akio_crypto::rand::ChaChaRng;

use super::cid::{ConnectionId, LOCAL_CID_LEN, reset_token};
use super::coding::Reader;
use super::conn::{
    ClientToken, ConnConfig, Connection, EndpointEvent, EndpointKeys, Transmit, push_ip, unix_secs,
};
use super::crypto::TokenKey;
use super::packet::{self, HeaderError, MIN_INITIAL_SIZE, PacketType};
use super::{KeyedMap, KeyedSet, keyed_from_rng};

pub(crate) const TOKEN_RETRY: u8 = 1;
pub(crate) const TOKEN_NEW: u8 = 2;
const RETRY_TOKEN_LIFETIME: u64 = 10;
const NEW_TOKEN_LIFETIME: u64 = 24 * 3600;
/// Stateless resets sent per second at most.
const RESETS_PER_SECOND: u32 = 64;

pub(crate) type ConnHandle = u64;

/// How a server endpoint accepts connections.
pub(crate) struct ServerSetup {
    pub tls: akio_tls::ServerConfig,
    pub cfg: ConnConfig,
    /// Always validate client addresses with a Retry first.
    pub retry: bool,
    /// Connections held at once; new ones beyond it are refused (CONNECTION_REFUSED).
    pub max_connections: usize,
    /// Handshakes in progress at once: from half of it on, a client without a token proves
    /// its address with a Retry first; at it, a new client's Initial is dropped unanswered.
    pub max_handshakes: usize,
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
    routes: KeyedMap<ConnectionId, ConnHandle>,
    initial: KeyedMap<ConnectionId, ConnHandle>,
    ids: KeyedMap<ConnHandle, Vec<ConnectionId>>,
    handshaking: KeyedSet<ConnHandle>,
    next: ConnHandle,
    resets: (Instant, u32),
    /// Connections refused (over `max_connections`, or dropped over `max_handshakes`) since
    /// the endpoint started.
    refused: u64,
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
        let routes = keyed_from_rng(rng);
        let initial = keyed_from_rng(rng);
        Endpoint {
            keys: Arc::new(EndpointKeys {
                reset_key,
                token_key: TokenKey::new(&tk),
            }),
            rng: ChaChaRng::from_seed(seed),
            server,
            routes: KeyedMap::with_hasher(routes),
            initial: KeyedMap::with_hasher(initial),
            ids: KeyedMap::default(),
            handshaking: KeyedSet::default(),
            next: 1,
            resets: (Instant::now(), 0),
            refused: 0,
        }
    }

    /// New connections refused since the endpoint started (over `max_connections`, or dropped
    /// over `max_handshakes`).
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// The server's TLS configuration (tests: a second server sharing its tickets).
    #[cfg(test)]
    pub fn server_tls(&self) -> Option<akio_tls::ServerConfig> {
        self.server.as_ref().map(|s| s.tls.clone())
    }

    /// The server's connection settings (tests: changing them between connections).
    #[cfg(test)]
    pub fn server_cfg_mut(&mut self) -> Option<&mut ConnConfig> {
        self.server.as_mut().map(|s| &mut s.cfg)
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
        tls: &akio_tls::ClientConfig,
        server_name: &str,
        addr: SocketAddr,
        token: Option<ClientToken>,
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
    #[cfg(test)]
    pub fn handle(&mut self, now: Instant, from: SocketAddr, data: &[u8]) -> Option<DatagramEvent> {
        self.handle_ecn(now, from, 0, data)
    }

    /// The connection a short-header datagram is routed to by its destination connection ID,
    /// with that ID, if it is one of ours (no other effect). The I/O layer remembers the
    /// answer per peer and routes the peer's next datagrams with the same ID without the
    /// endpoint until a route is removed (`RetireCid`, `Drained` in [`Endpoint::handle_event`]).
    pub fn route_short(&self, data: &[u8]) -> Option<(ConnectionId, ConnHandle)> {
        if *data.first()? & 0x80 != 0 {
            return None;
        }
        let cid = ConnectionId::new(data.get(1..1 + LOCAL_CID_LEN)?)?;
        self.routes.get(&cid).map(|&h| (cid, h))
    }

    /// Routes a datagram from `from` that arrived with ECN codepoint `ecn`.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn handle_ecn(
        &mut self,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        data: &[u8],
    ) -> Option<DatagramEvent> {
        self.handle_gated(now, from, ecn, data, &|_| true)
    }

    /// [`handle_ecn`](Self::handle_ecn), asking `admit` before a new connection is made for
    /// an Initial packet (ADR-178: the listener's accept filter): refused, the datagram is
    /// dropped with nothing kept and nothing sent (no Retry, no CONNECTION_REFUSED).
    pub fn handle_gated(
        &mut self,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        data: &[u8],
        admit: &dyn Fn(&SocketAddr) -> bool,
    ) -> Option<DatagramEvent> {
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
                return self.version_negotiation(from, &dcid, &scid, data.len());
            }
            Err(HeaderError::Invalid) => return None,
        };
        // A version this server does not offer.
        if let Some(s) = &self.server {
            if h.ty != PacketType::VersionNegotiation && !s.cfg.versions.contains(&h.version) {
                let (d, sc) = (h.dcid, h.scid);
                return self.version_negotiation(from, &d, &sc, data.len());
            }
        }
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
        let version = h.version;
        // Before the connection limit, as a TCP listener's filter runs before its own.
        if !admit(&from) {
            return None;
        }
        if self
            .server
            .as_ref()
            .is_some_and(|s| self.ids.len() >= s.max_connections)
        {
            self.refused += 1;
            return self.refuse(now, version, from, &h.dcid, &h.scid);
        }
        let max_handshakes = self
            .server
            .as_ref()
            .map_or(usize::MAX, |s| s.max_handshakes);
        if self.handshaking.len() >= max_handshakes {
            // Dropped unanswered, keeping nothing: the client sends its Initial again and gets
            // in once a handshake is over (as fit's QUIC listener does).
            self.refused += 1;
            return None;
        }
        let (orig, retry_scid, validated) = match self.check_token(from, h.token, &h.dcid, version)
        {
            TokenCheck::Retry(odcid) => (odcid, Some(h.dcid), true),
            TokenCheck::New => (h.dcid, None, true),
            TokenCheck::Invalid => return None,
            TokenCheck::None => {
                let must = self
                    .server
                    .as_ref()
                    .is_some_and(|s| s.retry || self.handshaking.len() >= max_handshakes / 2);
                if must {
                    return Some(self.retry(version, from, &h.dcid, &h.scid));
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
            version,
        );
        let handle = self.next;
        self.next += 1;
        self.register(handle, c.local_cid());
        self.initial.insert(h.dcid, handle);
        self.ids.entry(handle).or_default().push(h.dcid);
        self.handshaking.insert(handle);
        c.handle_shared_ecn(now, from, ecn, crate::bytes::pool::copy(data).into());
        Some(DatagramEvent::New(handle, Box::new(c)))
    }

    /// A Version Negotiation packet listing this server's versions, in answer to a full-size
    /// datagram (RFC 9000 section 6.1).
    fn version_negotiation(
        &mut self,
        from: SocketAddr,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        len: usize,
    ) -> Option<DatagramEvent> {
        let s = self.server.as_ref()?;
        if len < MIN_INITIAL_SIZE {
            return None;
        }
        let data = packet::version_negotiation(dcid, scid, 0, &s.cfg.versions);
        let r = (self.rng.next_u32() & 0x7f) as u8;
        let mut data = data;
        data[0] |= r;
        Some(DatagramEvent::Respond(Transmit {
            dest: from,
            segment_size: None,
            data,
            ecn: 0,
            probe: false,
        }))
    }

    fn retry(
        &mut self,
        version: u32,
        from: SocketAddr,
        odcid: &ConnectionId,
        client_scid: &ConnectionId,
    ) -> DatagramEvent {
        let new_scid = ConnectionId::random(&mut self.rng, LOCAL_CID_LEN);
        let mut plain = Vec::with_capacity(64);
        plain.extend_from_slice(&unix_secs().to_be_bytes());
        plain.extend_from_slice(&version.to_be_bytes());
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
            data: packet::retry(version, client_scid, &new_scid, odcid, &token, r),
            ecn: 0,
            probe: false,
        })
    }

    /// Checks the token of an Initial in `version`: Retry and NEW_TOKEN tokens carry the
    /// version they were issued in and count only for it (RFC 9369 section 5).
    fn check_token(
        &self,
        from: SocketAddr,
        token: &[u8],
        dcid: &ConnectionId,
        version: u32,
    ) -> TokenCheck {
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
        let same_version = r.u32() == Some(version);
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
                    Some((odcid, scid, true))
                        if same_version && age <= RETRY_TOKEN_LIFETIME && scid == *dcid =>
                    {
                        TokenCheck::Retry(odcid)
                    }
                    _ => TokenCheck::Invalid,
                }
            }
            TOKEN_NEW => {
                // Another version's token leaves the address unvalidated.
                if same_version && age <= NEW_TOKEN_LIFETIME && r.rest() == &ip[..] {
                    TokenCheck::New
                } else {
                    TokenCheck::None
                }
            }
            _ => TokenCheck::None,
        }
    }

    /// Answers a client's first Initial with CONNECTION_CLOSE (CONNECTION_REFUSED) in an Initial
    /// packet, keeping no state (RFC 9000 section 5.2.2); within the stateless reset budget,
    /// silence beyond it.
    fn refuse(
        &mut self,
        now: Instant,
        version: u32,
        from: SocketAddr,
        odcid: &ConnectionId,
        client_scid: &ConnectionId,
    ) -> Option<DatagramEvent> {
        if !self.reply_budget(now) {
            return None;
        }
        let keys = super::crypto::initial_keys(odcid, false, version);
        let scid = ConnectionId::random(&mut self.rng, LOCAL_CID_LEN);
        let mut data = Vec::with_capacity(64);
        let b = packet::PacketBuilder::long(
            &mut data,
            version,
            PacketType::Initial,
            client_scid,
            &scid,
            &[],
            0,
            1,
        );
        super::frame::put_close(
            &mut data,
            false,
            super::frame::code::CONNECTION_REFUSED,
            0,
            b"server busy",
        );
        b.finish(&mut data, &keys.local.packet, &keys.local.header);
        Some(DatagramEvent::Respond(Transmit {
            dest: from,
            segment_size: None,
            data,
            ecn: 0,
            probe: false,
        }))
    }

    /// Whether one more stateless answer (reset, refusal) fits this second's budget.
    fn reply_budget(&mut self, now: Instant) -> bool {
        if now.duration_since(self.resets.0) >= Duration::from_secs(1) {
            self.resets = (now, 0);
        }
        if self.resets.1 >= RESETS_PER_SECOND {
            return false;
        }
        self.resets.1 += 1;
        true
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
        if !self.reply_budget(now) {
            return None;
        }
        let size = (len - 1).min(43);
        let mut out = vec![0u8; size];
        self.rng.fill(&mut out[..size - 16]);
        out[0] = 0x40 | (out[0] & 0x3f);
        out[size - 16..].copy_from_slice(&reset_token(&self.keys.reset_key, cid));
        Some(DatagramEvent::Respond(Transmit {
            dest: from,
            segment_size: None,
            data: out,
            ecn: 0,
            probe: false,
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
            EndpointEvent::NewToken(_)
            | EndpointEvent::Migrated { .. }
            | EndpointEvent::MigrationFailed => {}
        }
    }
}

#[cfg_attr(test, derive(Debug, PartialEq))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::packet::{VERSION_1, VERSION_2};

    #[test]
    fn tokens_are_bound_to_the_version() {
        let mut rng = ChaChaRng::from_seed([7; 32]);
        let ep = Endpoint::with_rng(None, &mut rng);
        let from: SocketAddr = "10.0.0.1:5000".parse().expect("addr");
        let dcid = ConnectionId::new(&[1; 8]).expect("cid");
        // A NEW_TOKEN token issued in version 1 (as Connection::new_token seals it).
        let mut plain = unix_secs().to_be_bytes().to_vec();
        plain.extend_from_slice(&VERSION_1.to_be_bytes());
        push_ip(&mut plain, from);
        let tok = ep.keys.token_key.seal(&mut rng, TOKEN_NEW, &plain);
        assert_eq!(
            ep.check_token(from, &tok, &dcid, VERSION_1),
            TokenCheck::New
        );
        // In another version it validates nothing (RFC 9369 section 5).
        assert_eq!(
            ep.check_token(from, &tok, &dcid, VERSION_2),
            TokenCheck::None
        );
        // Neither does a token sealed before tokens carried the version.
        let mut old = unix_secs().to_be_bytes().to_vec();
        push_ip(&mut old, from);
        let tok = ep.keys.token_key.seal(&mut rng, TOKEN_NEW, &old);
        assert_eq!(
            ep.check_token(from, &tok, &dcid, VERSION_1),
            TokenCheck::None
        );
        // A Retry token is only good in the version of the Retry.
        let mut plain = unix_secs().to_be_bytes().to_vec();
        plain.extend_from_slice(&VERSION_2.to_be_bytes());
        plain.push(8);
        plain.extend_from_slice(&[2; 8]);
        plain.push(8);
        plain.extend_from_slice(&dcid);
        push_ip(&mut plain, from);
        plain.extend_from_slice(&from.port().to_be_bytes());
        let tok = ep.keys.token_key.seal(&mut rng, TOKEN_RETRY, &plain);
        let odcid = ConnectionId::new(&[2; 8]).expect("cid");
        assert_eq!(
            ep.check_token(from, &tok, &dcid, VERSION_2),
            TokenCheck::Retry(odcid)
        );
        assert_eq!(
            ep.check_token(from, &tok, &dcid, VERSION_1),
            TokenCheck::Invalid
        );
    }
}
