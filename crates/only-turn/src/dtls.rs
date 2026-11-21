//! TURN over DTLS (RFC 7350, `turns:` with `transport=udp`): the [`TurnServer`](crate::TurnServer)
//! acceptor for UDP listeners whose clients talk DTLS ([`TurnServer::dtls`](crate::TurnServer::dtls)).
//!
//! Each client 5-tuple gets a [`DtlsSession`]: ClientHellos are answered statelessly
//! (HelloVerifyRequest / HelloRetryRequest cookies from one [`HelloVerifier`] per acceptor)
//! until one comes back with a valid cookie, and only then is a DTLS connection created. Every
//! application-data record is one STUN message or ChannelData message, with UDP semantics
//! (no framing, no padding: RFC 7350 section 4). An allocation lives as long as its DTLS
//! association: close_notify, a fatal alert, the listener's idle timeout or a new handshake
//! from the same 5-tuple free it.
//!
//! Connection IDs (RFC 9146 for DTLS 1.2, RFC 9147 §9 for 1.3; [`CID_LEN`] bytes, on by
//! default): the server asks clients to put one in their records, and keeps an index from
//! its live CIDs to their association. A datagram from a 5-tuple the listener does not know
//! whose CID names an association is fed to that association; once one of its records
//! authenticates (an application-data record came out of it), the client's path moves there
//! (RFC 9146 §6): responses and relayed data go to the new 5-tuple, while the allocation keeps
//! the identity of the address the association started from. Records that do not
//! authenticate (spoofed, replayed) move nothing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use only::tls;
use only_dtls::{Config, Connection, Event, HelloCheck, HelloVerifier, Identity, PeerVerifier};

/// The length of the connection IDs the server asks clients for.
pub(crate) const CID_LEN: u8 = 8;
/// Most CIDs indexed per listener (each live association has one or a few).
const MAX_CIDS: usize = 1 << 17;

/// The DTLS configuration of a TURN server: the certificate and key of `cfg` (its default
/// chain), DTLS 1.3 with fallback to 1.2 (1.3 only if `cfg` is TLS 1.3 only), client
/// certificates only when `cfg` asks for them, cookies left to the listener, connection IDs
/// of `cid` bytes asked for (`None`: none).
pub(crate) fn server_config(cfg: &tls::ServerConfig, cid: Option<u8>) -> io::Result<Arc<Config>> {
    let bad = |what: &str, e: &dyn std::fmt::Display| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("turn dtls: {what}: {e}"),
        )
    };
    let p = cfg.__parts();
    let key = only_crypto::pkey::PrivateKey::from_pkcs8_der(&p.key_pkcs8)
        .map_err(|e| bad("private key", &e))?;
    let identity = Identity::new(p.chain.clone(), key).map_err(|e| bad("certificate", &e))?;
    let versions = if p.tls13_only {
        vec![only_dtls::Version::Dtls13]
    } else {
        vec![only_dtls::Version::Dtls13, only_dtls::Version::Dtls12]
    };
    let mut c = Config::new(identity)
        .with_versions(versions)
        .with_hello_verify(false)
        .with_require_client_certificate(false)
        .with_connection_id(cid);
    if let Some((roots, required)) = &p.client_auth {
        c = c
            .with_require_client_certificate(*required)
            .with_verifier(chain_verifier(roots, None));
    }
    Ok(Arc::new(c))
}

/// A [`PeerVerifier`] validating the peer's chain against `roots` (DER): as a server
/// certificate for `server_name`, or as a client certificate when `None`.
fn chain_verifier(roots: &[Vec<u8>], server_name: Option<&str>) -> PeerVerifier {
    let mut store = only_x509::RootStore::new();
    for r in roots {
        if let Ok(c) = only_x509::Certificate::from_der(r.clone()) {
            store.add(c);
        }
    }
    let name = server_name.map(str::to_owned);
    PeerVerifier::Custom(Arc::new(move |chain: &[Vec<u8>]| {
        let mut certs = chain
            .iter()
            .map(|d| only_x509::Certificate::from_der(d.clone()).map_err(|e| e.to_string()));
        let leaf = certs.next().ok_or("no certificate")??;
        let rest = certs.collect::<Result<Vec<_>, _>>()?;
        let v = only_x509::Verifier::new(&store);
        match &name {
            Some(n) => v.verify_server(&leaf, &rest, n),
            None => v.verify_client(&leaf, &rest),
        }
        .map(drop)
        .map_err(|e| e.to_string())
    }))
}

/// What one input to a [`DtlsSession`] produced.
#[derive(Debug, Default)]
pub(crate) struct DtlsOutput {
    /// Datagrams for the client.
    pub(crate) transmit: Vec<Vec<u8>>,
    /// STUN / ChannelData messages from the client (one per application-data record).
    pub(crate) messages: Vec<Vec<u8>>,
    /// A new handshake replaced the association: the old allocation must go.
    pub(crate) restarted: bool,
    /// The association ended (close_notify, a fatal error, the handshake timed out).
    pub(crate) closed: bool,
}

/// The server side of one client's DTLS association, sans-io.
pub(crate) struct DtlsSession {
    cfg: Arc<Config>,
    verifier: Arc<HelloVerifier>,
    peer: Vec<u8>,
    conn: Option<Connection>,
    /// The random of the ClientHello that started `conn`: a retransmission of it is not a
    /// new handshake.
    random: [u8; 32],
    closed: bool,
    /// The CIDs of ours indexed for this session ([`DtlsShared::sync_cids`]).
    indexed: Vec<Vec<u8>>,
    /// The listener connection (5-tuple) the client's path is on, once a record
    /// authenticated (0: not yet).
    path: u64,
}

impl std::fmt::Debug for DtlsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsSession")
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

/// The client random of a datagram starting with an epoch-0 ClientHello record (record header
/// 13 bytes, handshake header 12, client_version 2), if it is one.
fn client_hello_random(d: &[u8]) -> Option<[u8; 32]> {
    const AT: usize = 13 + 12 + 2;
    if d.len() < AT + 32 || d[0] != 22 || d[3..5] != [0, 0] || d[13] != 1 {
        return None;
    }
    d[AT..AT + 32].try_into().ok()
}

impl DtlsSession {
    /// A session for the client whose address encodes as `peer`.
    pub(crate) fn new(
        cfg: Arc<Config>,
        verifier: Arc<HelloVerifier>,
        peer: Vec<u8>,
    ) -> DtlsSession {
        DtlsSession {
            cfg,
            verifier,
            peer,
            conn: None,
            random: [0; 32],
            closed: false,
            indexed: Vec::new(),
            path: 0,
        }
    }

    /// After an input on listener connection `conn` that authenticated (`authenticated`):
    /// whether the path just moved to `conn`, and whether the live CIDs changed.
    pub(crate) fn after_input(&mut self, conn: u64, authenticated: bool) -> (bool, bool) {
        let moved = authenticated && self.path != conn;
        if moved {
            self.path = conn;
        }
        let live: &[Vec<u8>] = match &self.conn {
            Some(c) if !self.closed && c.is_connected() => c.local_connection_ids(),
            _ => &[],
        };
        (moved, live != self.indexed.as_slice())
    }

    /// Whether a DTLS connection exists (a ClientHello with a valid cookie arrived).
    pub(crate) fn has_connection(&self) -> bool {
        self.conn.is_some()
    }

    /// The CIDs of ours now live, and those indexed before: (to add, to remove).
    fn cid_changes(&mut self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let live: &[Vec<u8>] = match &self.conn {
            Some(c) if !self.closed && c.is_connected() => c.local_connection_ids(),
            _ => &[],
        };
        if live == self.indexed.as_slice() {
            return (Vec::new(), Vec::new());
        }
        let add = live
            .iter()
            .filter(|c| !self.indexed.contains(c))
            .cloned()
            .collect();
        let remove = self
            .indexed
            .iter()
            .filter(|c| !live.contains(c))
            .cloned()
            .collect();
        self.indexed = live.to_vec();
        (add, remove)
    }

    /// Fuzzing: a connection as if the ClientHello's cookie had been checked.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn fuzz_accept(&mut self, now: Instant) {
        self.conn = Connection::server(self.cfg.clone(), now, &self.peer).ok();
    }

    /// Whether the handshake completed and the association is up.
    pub(crate) fn is_connected(&self) -> bool {
        !self.closed && self.conn.as_ref().is_some_and(Connection::is_connected)
    }

    /// A datagram from the client.
    pub(crate) fn input(&mut self, now: Instant, datagram: &[u8], out: &mut DtlsOutput) {
        if self.closed {
            return;
        }
        if let Some(random) = client_hello_random(datagram) {
            // A ClientHello before any connection, or a new one (not a retransmission) on an
            // established association: the client restarted. Either way its cookie decides.
            let fresh = match &self.conn {
                None => true,
                Some(c) => c.is_connected() && random != self.random,
            };
            if fresh {
                match self.verifier.check(now, &self.peer, datagram) {
                    HelloCheck::Respond(r) => {
                        out.transmit.push(r);
                        return;
                    }
                    HelloCheck::Accept => {
                        let Ok(c) = Connection::server(self.cfg.clone(), now, &self.peer) else {
                            return;
                        };
                        out.restarted |= self.conn.is_some();
                        self.conn = Some(c);
                        self.random = random;
                    }
                    _ => return,
                }
            }
        }
        let Some(c) = self.conn.as_mut() else { return };
        if c.handle_datagram(now, datagram).is_err() {
            self.closed = true;
            out.closed = true;
        }
        self.drain(out);
    }

    /// Runs the DTLS timers that are due (retransmissions, the handshake deadline).
    pub(crate) fn handle_timeout(&mut self, now: Instant, out: &mut DtlsOutput) {
        let Some(c) = self.conn.as_mut() else { return };
        if self.closed || c.poll_timeout().is_none_or(|t| t > now) {
            return;
        }
        if c.handle_timeout(now).is_err() {
            self.closed = true;
            out.closed = true;
        }
        self.drain(out);
    }

    /// Encrypts one message for the client into datagrams appended to `out` (dropped before
    /// the handshake completed).
    pub(crate) fn seal(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) {
        if !self.is_connected() {
            return;
        }
        let Some(c) = self.conn.as_mut() else { return };
        if c.send_application_data(data).is_ok() {
            while let Some(d) = c.poll_transmit() {
                out.push(d);
            }
        }
    }

    /// Sends close_notify.
    pub(crate) fn close(&mut self, out: &mut Vec<Vec<u8>>) {
        if let Some(c) = self.conn.as_mut() {
            if !self.closed {
                c.close();
                while let Some(d) = c.poll_transmit() {
                    out.push(d);
                }
            }
        }
        self.closed = true;
    }

    fn drain(&mut self, out: &mut DtlsOutput) {
        let Some(c) = self.conn.as_mut() else { return };
        while let Some(e) = c.poll_event() {
            match e {
                Event::ApplicationData(d) => out.messages.push(d),
                Event::Closed => {
                    self.closed = true;
                    out.closed = true;
                }
                _ => {}
            }
        }
        while let Some(d) = c.poll_transmit() {
            out.transmit.push(d);
        }
    }
}

/// The association a CID names: the address it started from (the allocation's identity)
/// and its session.
pub(crate) type CidTarget = (SocketAddr, Arc<Mutex<DtlsSession>>);

/// An indexed CID: the association's first address and its session.
type CidEntry = (SocketAddr, Weak<Mutex<DtlsSession>>);

/// Shared by the clients of one DTLS listener.
pub(crate) struct DtlsShared {
    pub(crate) cfg: Arc<Config>,
    pub(crate) verifier: Arc<HelloVerifier>,
    /// The CID length asked for (`None`: no CIDs).
    pub(crate) cid_len: Option<u8>,
    /// Live CIDs of ours -> (the association's first address, its session).
    cids: Mutex<HashMap<Vec<u8>, CidEntry>>,
}

impl DtlsShared {
    pub(crate) fn new(cfg: &tls::ServerConfig, cid_len: Option<u8>) -> io::Result<DtlsShared> {
        let cid_len = cid_len.filter(|l| *l > 0);
        Ok(DtlsShared {
            cfg: server_config(cfg, cid_len)?,
            verifier: Arc::new(
                HelloVerifier::new(Instant::now()).map_err(|e| io::Error::other(e.to_string()))?,
            ),
            cid_len,
            cids: Mutex::new(HashMap::new()),
        })
    }

    /// The association whose CID a datagram from an unknown 5-tuple carries.
    pub(crate) fn by_cid(&self, datagram: &[u8]) -> Option<CidTarget> {
        let len = usize::from(self.cid_len?);
        let cid = only_dtls::connection_id(datagram, len)?;
        let m = self
            .cids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (addr, s) = m.get(cid)?;
        Some((*addr, s.upgrade()?))
    }

    /// Keeps the index in step with the CIDs `session` (whose association started at
    /// `client`) accepts now; with `gone`, forgets them all.
    pub(crate) fn sync_cids(
        &self,
        client: SocketAddr,
        session: &Arc<Mutex<DtlsSession>>,
        gone: bool,
    ) {
        if self.cid_len.is_none() {
            return;
        }
        let (add, remove) = {
            let mut s = session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if gone {
                (Vec::new(), std::mem::take(&mut s.indexed))
            } else {
                s.cid_changes()
            }
        };
        if add.is_empty() && remove.is_empty() {
            return;
        }
        let mut m = self
            .cids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for c in remove {
            if m.get(&c)
                .is_some_and(|(_, w)| w.as_ptr() == Arc::as_ptr(session))
            {
                m.remove(&c);
            }
        }
        for c in add {
            if m.len() < MAX_CIDS {
                m.insert(c, (client, Arc::downgrade(session)));
            }
        }
    }

    pub(crate) fn session(&self, peer: SocketAddr) -> Arc<Mutex<DtlsSession>> {
        Arc::new(Mutex::new(DtlsSession::new(
            self.cfg.clone(),
            self.verifier.clone(),
            peer.to_string().into_bytes(),
        )))
    }
}
