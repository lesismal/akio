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

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use only::tls;
use only_dtls::{Config, Connection, Event, HelloCheck, HelloVerifier, Identity, PeerVerifier};

/// The DTLS configuration of a TURN server: the certificate and key of `cfg` (its default
/// chain), DTLS 1.3 with fallback to 1.2 (1.3 only if `cfg` is TLS 1.3 only), client
/// certificates only when `cfg` asks for them, cookies left to the listener.
pub(crate) fn server_config(cfg: &tls::ServerConfig) -> io::Result<Arc<Config>> {
    let bad = |what: &str, e: &dyn std::fmt::Display| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("turn dtls: {what}: {e}"))
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
        .with_require_client_certificate(false);
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
    pub(crate) fn new(cfg: Arc<Config>, verifier: Arc<HelloVerifier>, peer: Vec<u8>) -> DtlsSession {
        DtlsSession {
            cfg,
            verifier,
            peer,
            conn: None,
            random: [0; 32],
            closed: false,
        }
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

/// Shared by the clients of one DTLS listener.
pub(crate) struct DtlsShared {
    pub(crate) cfg: Arc<Config>,
    pub(crate) verifier: Arc<HelloVerifier>,
}

impl DtlsShared {
    pub(crate) fn new(cfg: &tls::ServerConfig) -> io::Result<DtlsShared> {
        Ok(DtlsShared {
            cfg: server_config(cfg)?,
            verifier: Arc::new(
                HelloVerifier::new(Instant::now()).map_err(|e| io::Error::other(e.to_string()))?,
            ),
        })
    }

    pub(crate) fn session(&self, peer: std::net::SocketAddr) -> Arc<Mutex<DtlsSession>> {
        Arc::new(Mutex::new(DtlsSession::new(
            self.cfg.clone(),
            self.verifier.clone(),
            peer.to_string().into_bytes(),
        )))
    }
}
