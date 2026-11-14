//! The TLS 1.3 handshake for QUIC (RFC 9001), without records: handshake bytes in and out per
//! encryption level, traffic secrets per level, the quic_transport_parameters extension, ALPN
//! required, no middlebox compatibility, 0-RTT rejected. **Internal** (for the in-house QUIC
//! of the next wave): not covered by the semver promise.
//!
//! ```
//! # use only_tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};
//! use only_tls::quic::{Event, QuicTls};
//! # let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
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

pub use crate::proto::alert::{Alert, Fatal};
pub use crate::proto::common::{Keys, Level};
pub use crate::proto::suites::{AeadAlg, HashAlg, Suite};

use crate::config::{ClientConfig, ServerConfig};
use crate::proto::client::Client;
use crate::proto::common::Action;
use crate::proto::conn::{MAX_HANDSHAKE, Machine};
use crate::proto::server::Server;

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
        let mut c = Client::new(cfg.inner.clone(), server_name, Some(params))?;
        let mut acts = Vec::new();
        c.start(&mut acts)?;
        let mut q = QuicTls::new(Machine::Client(Box::new(c)));
        q.push(acts);
        Ok(q)
    }

    /// A server handshake sending `params` as our transport parameters.
    pub fn server(cfg: &ServerConfig, params: Vec<u8>) -> QuicTls {
        QuicTls::new(Machine::Server(Box::new(Server::new(
            cfg.inner.clone(),
            Some(params),
        ))))
    }

    fn new(m: Machine) -> QuicTls {
        QuicTls {
            m,
            hs: Vec::new(),
            read_level: Level::Initial,
            events: VecDeque::new(),
            error: None,
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
                Action::ReadKeys(l, k) => {
                    self.read_level = l;
                    read_changed = true;
                    self.events.push_back(Event::ReadKeys(l, k));
                }
                Action::WriteKeys(l, k) => self.events.push_back(Event::WriteKeys(l, k)),
                Action::Done => self.events.push_back(Event::Done),
                Action::Ccs | Action::Warning(_) | Action::RejectEarlyData => {}
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
            if self.push(acts) && !self.hs.is_empty() {
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

    /// 0-RTT is never accepted (yet).
    pub fn early_data_accepted(&self) -> bool {
        false
    }
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
