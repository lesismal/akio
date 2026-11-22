//! The TLS 1.3 handshake for QUIC (RFC 9001), without records: handshake bytes in and out per
//! encryption level, traffic secrets per level, the quic_transport_parameters extension, ALPN
//! required, no middlebox compatibility, 0-RTT when the QUIC layer enables it (no
//! EndOfEarlyData; the 0-RTT keys are an event like the others). **Internal** (for the in-house QUIC
//! of the next wave): not covered by the semver promise.
//!
//! ```
//! # use akio_tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};
//! use akio_tls::quic::{Event, QuicTls};
//! # let (cert, key) = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
//! # let chain = vec![Certificate::from_der(cert.as_der().to_vec())];
//! # let mut roots = RootCerts::empty();
//! # roots.add(&chain[0]).unwrap();
//! # let skey = PrivateKey::from_pkcs8_der(key.to_pkcs8_der());
//! let server_cfg = ServerConfig::builder(chain, skey).alpn(["h3"]).build().unwrap();
//! let client_cfg = ClientConfig::builder().roots(roots).alpn(["h3"]).build().unwrap();
//! let mut c = QuicTls::client(&client_cfg, "localhost", b"client params".to_vec()).unwrap();
//! let mut s = QuicTls::server(&server_cfg, b"server params".to_vec());
//! // Shuttle handshake bytes between the two until both are done.
//! while c.handshaking() || s.handshaking() {
//!     while let Some(e) = c.poll_event() {
//!         if let Event::Data(level, bytes) = e { s.read_handshake(level, &bytes).unwrap(); }
//!     }
//!     while let Some(e) = s.poll_event() {
//!         if let Event::Data(level, bytes) = e { c.read_handshake(level, &bytes).unwrap(); }
//!     }
//! }
//! assert_eq!(c.peer_transport_params(), Some(&b"server params"[..]));
//! assert_eq!(s.alpn(), Some(&b"h3"[..]));
//! ```

use std::collections::VecDeque;

pub use crate::EarlyData;
pub use crate::proto::alert::{Alert, Fatal};
pub use crate::proto::common::{Keys, Level};
pub use crate::proto::suites::{AeadAlg, HashAlg, Suite};

use crate::config::{ClientConfig, ServerConfig};
use crate::proto::client::Client;
use crate::proto::common::Action;
use crate::proto::conn::{MAX_HANDSHAKE, Machine};
use crate::proto::server::Server;
use crate::replay::Waker;

/// What the handshake produced, in order.
#[derive(Debug)]
pub enum Event {
    /// Handshake bytes to send in CRYPTO frames at this level.
    Data(Level, Vec<u8>),
    /// Packets at this level are now decrypted with keys from this secret.
    ReadKeys(Level, Keys),
    /// Packets at this level are now encrypted with keys from this secret.
    WriteKeys(Level, Keys),
    /// The handshake is complete (the client is done; the server has the client's Finished).
    Done,
}

/// A TLS 1.3 handshake driven by QUIC.
pub struct QuicTls {
    m: Machine,
    hs: Vec<u8>,
    read_level: Level,
    events: VecDeque<Event>,
    error: Option<Fatal>,
    /// Called when a suspended handshake can go on.
    waker: Option<Waker>,
}

impl std::fmt::Debug for QuicTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTls")
            .field("read_level", &self.read_level)
            .field("handshaking", &self.handshaking())
            .finish_non_exhaustive()
    }
}

impl QuicTls {
    /// A client handshake with `server_name`, sending `params` as our transport parameters.
    /// The ClientHello is the first event.
    pub fn client(
        cfg: &ClientConfig,
        server_name: &str,
        params: Vec<u8>,
    ) -> Result<QuicTls, Fatal> {
        QuicTls::client_early(cfg, server_name, params, false)
    }

    /// [`QuicTls::client`], offering 0-RTT with `early` when a ticket allows it: then the
    /// `WriteKeys(EarlyData)` event follows the ClientHello and
    /// [`early_params`](Self::early_params) has the server's remembered transport parameters.
    pub fn client_early(
        cfg: &ClientConfig,
        server_name: &str,
        params: Vec<u8>,
        early: bool,
    ) -> Result<QuicTls, Fatal> {
        QuicTls::client_versioned(cfg, server_name, params, early, 0)
    }

    /// [`QuicTls::client_early`] for a connection starting in QUIC version `version`
    /// (RFC 9369 section 5): only a ticket issued in that version is offered, and tickets
    /// the server sends are kept under it (or the version given to
    /// [`set_ticket_version`](Self::set_ticket_version)). Version 0 is "not bound", what
    /// the unversioned constructors use.
    pub fn client_versioned(
        cfg: &ClientConfig,
        server_name: &str,
        params: Vec<u8>,
        early: bool,
        version: u32,
    ) -> Result<QuicTls, Fatal> {
        let mut c = Client::new(cfg.inner.clone(), server_name, Some(params), early, version)?;
        let mut acts = Vec::new();
        c.start(&mut acts)?;
        let mut q = QuicTls::new(Machine::Client(Box::new(c)));
        q.push(acts);
        Ok(q)
    }

    /// A server handshake sending `params` as our transport parameters.
    pub fn server(cfg: &ServerConfig, params: Vec<u8>) -> QuicTls {
        QuicTls::server_early(cfg, params, None)
    }

    /// [`QuicTls::server`] accepting 0-RTT with `early_ctx`: the transport parameters 0-RTT
    /// depends on, encoded. Tickets carry it (and allow 0xffffffff bytes of early data), and
    /// 0-RTT is accepted only with a ticket carrying the same (plus the TLS conditions and
    /// replay protection); then the `ReadKeys(EarlyData)` event comes before the handshake
    /// read keys.
    pub fn server_early(
        cfg: &ServerConfig,
        params: Vec<u8>,
        early_ctx: Option<Vec<u8>>,
    ) -> QuicTls {
        QuicTls::server_versioned(cfg, params, early_ctx, 0)
    }

    /// [`QuicTls::server_early`] for a connection the client started in QUIC version
    /// `version` (RFC 9369 section 5): only a ticket issued in that version resumes (another
    /// one falls back to a full handshake, without 0-RTT), and tickets issued carry it (or
    /// the version given to [`set_ticket_version`](Self::set_ticket_version)).
    pub fn server_versioned(
        cfg: &ServerConfig,
        params: Vec<u8>,
        early_ctx: Option<Vec<u8>>,
        version: u32,
    ) -> QuicTls {
        let mut s = Server::new(cfg.inner.clone(), Some(params), early_ctx);
        s.quic_accept_version = version;
        s.quic_ticket_version = version;
        QuicTls::new(Machine::Server(Box::new(s)))
    }

    /// The QUIC version tickets issued (server) or received (client) from now on belong to:
    /// the negotiated one after compatible version negotiation moved the connection away
    /// from the version it started in (RFC 9369 section 5). The ticket the handshake offers
    /// or accepts stays bound to the starting version.
    pub fn set_ticket_version(&mut self, version: u32) {
        match &mut self.m {
            Machine::Client(c) => c.quic_ticket_version = version,
            Machine::Server(s) => s.quic_ticket_version = version,
        }
    }

    fn new(m: Machine) -> QuicTls {
        QuicTls {
            m,
            hs: Vec::new(),
            read_level: Level::Initial,
            events: VecDeque::new(),
            error: None,
            waker: None,
        }
    }

    /// Sets what to call (from any thread) when a suspended handshake can go on: the server
    /// waits for an asynchronous anti-replay store (ADR-062). The QUIC connection then calls
    /// [`resume`](Self::resume) from its own thread. `w` is never called from inside a
    /// method of this handshake.
    pub fn set_waker(&mut self, w: std::sync::Arc<dyn Fn() + Send + Sync>) {
        if self.m.suspended() {
            // Already answered: the next `resume` goes on.
            let _ = self.m.set_replay_waker(w.clone());
        }
        self.waker = Some(w);
    }

    /// The server's handshake waits for an asynchronous anti-replay answer: nothing more
    /// comes out until [`resume`](Self::resume) takes it up again.
    pub fn suspended(&self) -> bool {
        self.m.suspended()
    }

    /// Takes a suspended handshake up again if its anti-replay answer is here; `Ok(false)`
    /// while it is not (the waker is called when it is). An error is fatal, as for
    /// [`read_handshake`](Self::read_handshake).
    pub fn resume(&mut self) -> Result<bool, Fatal> {
        if !self.m.suspended() {
            return Ok(false);
        }
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let level = self.read_level;
        let before = self.m.suspended();
        let r = self.read_inner(level, &[]);
        if let Err(e) = &r {
            self.error = Some(e.clone());
        }
        r.map(|()| before && !self.m.suspended())
    }

    /// Suspended: takes the ClientHello up again if the answer is here (`true`), else
    /// registers the waker.
    fn resume_now(&mut self) -> Result<bool, Fatal> {
        loop {
            let mut acts = Vec::new();
            if self.m.resume(&mut acts)? {
                if self.push(acts) && !self.hs.is_empty() {
                    return Err(Fatal::new(
                        Alert::UnexpectedMessage,
                        "handshake data across a key change",
                    ));
                }
                return Ok(true);
            }
            match &self.waker {
                Some(w) if !self.m.set_replay_waker(w.clone()) => {}
                _ => return Ok(false),
            }
        }
    }

    fn push(&mut self, acts: Vec<Action>) -> bool {
        let mut read_changed = false;
        for a in acts {
            match a {
                Action::Msg(l, m) => match self.events.back_mut() {
                    Some(Event::Data(bl, b)) if *bl == l => b.extend_from_slice(&m),
                    _ => self.events.push_back(Event::Data(l, m)),
                },
                // 0-RTT keys are for packets, never for CRYPTO data.
                Action::ReadKeys(Level::EarlyData, k) => {
                    self.events.push_back(Event::ReadKeys(Level::EarlyData, k));
                }
                Action::ReadKeys(l, k) => {
                    self.read_level = l;
                    read_changed = true;
                    self.events.push_back(Event::ReadKeys(l, k));
                }
                Action::WriteKeys(l, k) => self.events.push_back(Event::WriteKeys(l, k)),
                Action::Done => self.events.push_back(Event::Done),
                Action::Ccs
                | Action::Warning(_)
                | Action::RejectEarlyData
                | Action::EarlyOffered(_)
                | Action::EarlyAccepted(_)
                | Action::RecordLimit { .. } => {}
            }
        }
        read_changed
    }

    /// Feeds CRYPTO frame bytes received at `level`, in order. An error is fatal: close the
    /// connection with CRYPTO_ERROR (0x100 + alert code).
    pub fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), Fatal> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let r = self.read_inner(level, data);
        if let Err(e) = &r {
            self.error = Some(e.clone());
        }
        r
    }

    fn read_inner(&mut self, level: Level, data: &[u8]) -> Result<(), Fatal> {
        if level != self.read_level {
            return Err(Fatal::new(
                Alert::UnexpectedMessage,
                "handshake data at the wrong encryption level",
            ));
        }
        self.hs.extend_from_slice(data);
        loop {
            if self.m.suspended() {
                if self.hs.len() > MAX_HANDSHAKE {
                    return Err(Fatal::new(
                        Alert::UnexpectedMessage,
                        "handshake data while the anti-replay check is pending",
                    ));
                }
                if !self.resume_now()? {
                    return Ok(());
                }
                continue;
            }
            if self.hs.len() < 4 {
                return Ok(());
            }
            let len = (usize::from(self.hs[1]) << 16)
                | (usize::from(self.hs[2]) << 8)
                | usize::from(self.hs[3]);
            if len > MAX_HANDSHAKE {
                return Err(Fatal::new(Alert::DecodeError, "handshake message too long"));
            }
            if self.hs.len() < 4 + len {
                return Ok(());
            }
            let msg: Vec<u8> = self.hs.drain(..4 + len).collect();
            let mut acts = Vec::new();
            self.m.handle(&msg, &mut acts)?;
            if self.push(acts) && !self.m.suspended() && !self.hs.is_empty() {
                return Err(Fatal::new(
                    Alert::UnexpectedMessage,
                    "handshake data across a key change",
                ));
            }
        }
    }

    /// The next thing to do, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Still negotiating.
    pub fn handshaking(&self) -> bool {
        self.m.handshaking() && self.error.is_none()
    }

    /// The peer's transport parameters (once received).
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.m.peer_quic()
    }

    /// The negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.m.alpn()
    }

    /// The SNI name the client asked for (server side).
    pub fn server_name(&self) -> Option<&str> {
        self.m.server_name()
    }

    /// The peer's certificate chain (DER, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.m.peer_chain()
    }

    /// The session was resumed with a ticket.
    pub fn resumed(&self) -> bool {
        self.m.resumed()
    }

    /// The negotiated suite.
    pub fn suite(&self) -> Option<&'static Suite> {
        self.m.suite()
    }

    /// Whether 0-RTT was accepted (client: known with the server's EncryptedExtensions).
    pub fn early_data_accepted(&self) -> bool {
        self.m.early() == EarlyData::Accepted
    }

    /// What happened to 0-RTT.
    pub fn early_data(&self) -> EarlyData {
        self.m.early()
    }

    /// Client offering 0-RTT: the transport parameters of the server, remembered with the
    /// ticket (what 0-RTT packets may use, RFC 9000 section 7.4.1).
    pub fn early_params(&self) -> Option<&[u8]> {
        match &self.m {
            Machine::Client(c) => c.early_params(),
            Machine::Server(_) => None,
        }
    }
}

/// The QUIC version of the newest usable session ticket `cfg` holds for `server_name`, if
/// it holds one issued on a QUIC connection bound to a version: a client starts in that
/// version so the ticket can be used (RFC 9369 section 5).
pub fn ticket_version(cfg: &ClientConfig, server_name: &str) -> Option<u32> {
    cfg.inner
        .cache
        .as_ref()?
        .quic_ticket_version(server_name, crate::proto::common::now_secs())
}

/// How much of a ClientHello handshake message (header included) `hs`, the start of the
/// Initial CRYPTO stream, needs to be complete: `None` until the 4-byte header is there.
pub fn client_hello_len(hs: &[u8]) -> Option<usize> {
    let h = hs.get(..4)?;
    Some(4 + ((usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3])))
}

/// The quic_transport_parameters of a complete ClientHello handshake message (header
/// included), without running the handshake: what a QUIC server reads to choose a compatible
/// version (RFC 9368 section 4) before it answers. `None` if it is not a ClientHello that
/// parses, or carries no parameters.
pub fn client_hello_transport_params(msg: &[u8]) -> Option<&[u8]> {
    if msg.first() != Some(&crate::proto::msgs::CLIENT_HELLO) {
        return None;
    }
    let body = msg.get(4..client_hello_len(msg)?)?;
    crate::proto::msgs::ClientHello::parse(body)
        .ok()?
        .quic_params
}

/// QUIC v1 initial salt (RFC 9001 section 5.2).
pub const V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The client and server Initial secrets for a destination connection ID (RFC 9001 5.2).
pub fn initial_secrets(salt: &[u8], dcid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let h = HashAlg::Sha256;
    let initial = h.extract(salt, dcid);
    (
        h.expand_label(&initial, b"client in", &[], 32),
        h.expand_label(&initial, b"server in", &[], 32),
    )
}

/// Packet protection material from a traffic secret: (key, iv, header-protection key).
pub fn packet_keys(suite: &Suite, secret: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let h = suite.hash;
    let kl = suite.aead.key_len();
    (
        h.expand_label(secret, b"quic key", &[], kl),
        h.expand_label(secret, b"quic iv", &[], 12),
        h.expand_label(secret, b"quic hp", &[], kl),
    )
}

/// The next 1-RTT secret for a QUIC key update (RFC 9001 section 6).
pub fn next_secret(suite: &Suite, secret: &[u8]) -> Vec<u8> {
    suite
        .hash
        .expand_label(secret, b"quic ku", &[], suite.hash.len())
}

/// HKDF-Expand-Label with the suite's hash.
pub fn hkdf_expand_label(
    hash: HashAlg,
    secret: &[u8],
    label: &[u8],
    ctx: &[u8],
    len: usize,
) -> Vec<u8> {
    hash.expand_label(secret, label, ctx, len)
}

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
