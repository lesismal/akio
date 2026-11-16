#![forbid(unsafe_code)]
//! TLS 1.3 and 1.2 for `only`, implemented in this crate without third-party dependencies: the
//! protocol is written from the RFCs on `only-crypto` and `only-x509`, sans-io.
//!
//! Wrap any [`Acceptor`] in [`Tls::server`] (or [`Tls::client`] for [`dial`](../only/struct.Engine.html))
//! and its handlers see **plaintext**: `on_data` receives decrypted bytes and `Conn::send*` encrypts.
//! The handshake runs on the connection's I/O thread, interleaved with other connections, and
//! never blocks; application bytes sent during the handshake are held back and go out as soon as
//! it completes.
//!
//! Configure with this crate's own types: [`ServerConfig::builder`] (certificate chain and key
//! from PEM or DER, SNI-selected chains, ALPN, client authentication, session resumption) and
//! [`ClientConfig::builder`] (roots, ALPN, client certificate, SNI). The protocol internals stay
//! out of the public API. [`tls_info`] reads what was negotiated.
//!
//! Protocol coverage: TLS 1.3 (RFC 8446: full and PSK-resumed handshakes, HelloRetryRequest,
//! KeyUpdate, client certificates, early data (0-RTT) when both sides enable it, with replay
//! protection: [`ServerConfigBuilder::early_data`], [`ClientConfigBuilder::early_data`],
//! [`TlsInfo::early_data`]) and TLS 1.2 (RFC 5246 with ECDHE and AEAD
//! suites only, extended master secret, renegotiation indication with renegotiation refused,
//! session IDs and tickets); AES-128/256-GCM and ChaCha20-Poly1305; X25519, P-256, P-384;
//! ECDSA, Ed25519 and RSA (PSS; PKCS#1 v1.5 in TLS 1.2) certificates verified with
//! `only-x509`; SNI and ALPN.
//!
//! ```no_run
//! use only_tls::{Certificate, PrivateKey, ServerConfig, Tls};
//! # struct Echo; impl only_core::Handler for Echo { fn on_data(&mut self, _: &only_core::Conn<Self>, _: &[u8]) {} }
//! let chain = Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
//! let key = PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
//! let cfg = ServerConfig::builder(chain, key)
//!     .alpn(["h2", "http/1.1"])
//!     .build()
//!     .unwrap();
//! let acceptor = Tls::server(cfg, only_core::fn_acceptor(|_c: &only_core::Conn<Echo>| Echo));
//! # let _ = acceptor;
//! ```
//!
//! Guide: [TLS](https://lesismal.github.io/only/en/protocols/tls.html)
//! (中文: [TLS](https://lesismal.github.io/only/zh-CN/protocols/tls.html)).
#![warn(clippy::unwrap_used)]

use std::{any::Any, io};

use only_core::{Acceptor, Conn, Transport};

mod config;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
#[cfg(all(target_os = "linux", feature = "experimental-ktls"))]
mod ktls;
mod proto;
#[doc(hidden)]
pub mod quic;
#[doc(hidden)]
pub mod stream;

pub use config::{
    Certificate, ClientConfig, ClientConfigBuilder, Error, PrivateKey, RootCerts, ServerConfig,
    ServerConfigBuilder,
};
#[doc(hidden)]
pub use config::{ClientParts, ServerParts};
pub use proto::EarlyData;

/// The protocol core, for tests, fuzzing and interop tools. **Not** a public API.
#[doc(hidden)]
pub mod __proto {
    pub use crate::proto::alert::{Alert, Fatal};
    pub use crate::proto::suites;
    pub use crate::proto::{Connection, Group, Keys, Level};
    #[cfg(feature = "experimental-ktls")]
    pub use crate::proto::{DirKeys, Offload, OffloadEvent};

    /// A client connection (the ClientHello is queued for the first `recv`/`seal`).
    pub fn client(cfg: &crate::ClientConfig, name: &str) -> Result<Connection, Fatal> {
        Connection::client(cfg.inner.clone(), name)
    }

    /// A server connection.
    pub fn server(cfg: &crate::ServerConfig) -> Connection {
        Connection::server(cfg.inner.clone())
    }
}

/// Wraps an acceptor so that its connections speak TLS.
pub struct Tls<A> {
    mode: Mode,
    inner: A,
}

impl<A> std::fmt::Debug for Tls<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

enum Mode {
    Server(ServerConfig),
    Client(ClientConfig, String),
}

impl<A: Acceptor> Tls<A> {
    /// Serves TLS with `config`; `inner` handles the decrypted connection.
    pub fn server(config: ServerConfig, inner: A) -> Self {
        Tls {
            mode: Mode::Server(config),
            inner,
        }
    }

    /// Connects with TLS to `server_name` (for certificate verification and SNI), for
    /// connections made with `Engine::dial`.
    pub fn client(config: ClientConfig, server_name: &str, inner: A) -> io::Result<Self> {
        only_x509::ServerName::parse(server_name).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid server name: {e}"),
            )
        })?;
        Ok(Tls {
            mode: Mode::Client(config, server_name.to_owned()),
            inner,
        })
    }
}

impl<A: Acceptor> Acceptor for Tls<A> {
    type Handler = A::Handler;

    fn on_open(&self, c: &Conn<A::Handler>) -> A::Handler {
        self.inner.on_open(c)
    }

    fn on_shutdown(&self, c: &Conn<A::Handler>) {
        self.inner.on_shutdown(c);
    }

    fn transport(&self) -> Option<Box<dyn Transport>> {
        let conn = match &self.mode {
            Mode::Server(cfg) => Ok(proto::Connection::server(cfg.inner.clone())),
            Mode::Client(cfg, name) => proto::Connection::client(cfg.inner.clone(), name),
        };
        match conn {
            Ok(conn) => Some(Box::new(TlsTransport { conn })),
            Err(e) => {
                only_log::warn!(target: "only::tls", "cannot start TLS session: {e}");
                // No transport would mean plaintext; refuse by installing a dead one.
                Some(Box::new(Failed))
            }
        }
    }
}

/// Installed when a session cannot be created: every operation fails, so the connection closes
/// instead of silently falling back to plaintext.
struct Failed;

impl Transport for Failed {
    fn recv(&mut self, _: &[u8], _: &mut Vec<u8>, _: &mut Vec<u8>) -> io::Result<()> {
        Err(io::Error::other("TLS session could not be created"))
    }
    fn seal(&mut self, _: &[u8], _: &mut Vec<u8>) -> io::Result<()> {
        Err(io::Error::other("TLS session could not be created"))
    }
    fn shutdown(&mut self, _: &mut Vec<u8>) {}
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
    fn name(&self) -> &'static str {
        "tls"
    }
    fn handshaking(&self) -> bool {
        true
    }
}

struct TlsTransport {
    conn: proto::Connection,
}

fn io_err(e: proto::Fatal) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl Transport for TlsTransport {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        // An empty input still gives a client the chance to emit its first flight.
        self.conn.recv(cipher, plain, out).map_err(io_err)
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.conn.seal(plain, out).map_err(io_err)
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        self.conn.close(out);
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn name(&self) -> &'static str {
        "tls"
    }

    fn handshaking(&self) -> bool {
        self.conn.handshaking()
    }
}

/// What a connection negotiated; see [`tls_info`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsInfo {
    /// The handshake has not finished yet (the other fields may still be empty).
    pub handshaking: bool,
    /// Negotiated ALPN protocol, e.g. `b"h2"`.
    pub alpn: Option<Vec<u8>>,
    /// SNI name the client asked for (server side only).
    pub server_name: Option<String>,
    /// Negotiated protocol version, e.g. `"TLSv1_3"`.
    pub version: Option<String>,
    /// What happened to TLS 1.3 early data (0-RTT).
    pub early_data: EarlyData,
    /// Bytes of application data that went as early data: the first this many bytes the
    /// server's `on_data` received (server; they may be a replay, see
    /// [`ServerConfigBuilder::early_data`]), or the first this many bytes the client sent
    /// (client; sent again after the handshake if `early_data` is `Rejected`).
    pub early_data_len: u64,
}

/// TLS details of `c`, or `None` if it is not a TLS connection.
pub fn tls_info<H>(c: &Conn<H>) -> Option<TlsInfo> {
    c.with_transport(|t| {
        let t = t.as_any().downcast_mut::<TlsTransport>()?;
        Some(TlsInfo {
            handshaking: t.conn.handshaking(),
            alpn: t.conn.alpn().map(<[u8]>::to_vec),
            server_name: t.conn.server_name().map(str::to_owned),
            version: t.conn.version_name().map(str::to_owned),
            early_data: t.conn.early_data(),
            early_data_len: t.conn.early_data_len(),
        })
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nop;
    impl only_core::Handler for Nop {
        fn on_data(&mut self, _: &Conn<Self>, _: &[u8]) {}
    }

    fn client_cfg() -> ClientConfig {
        ClientConfig::builder().build().unwrap()
    }

    #[test]
    fn invalid_server_name_is_rejected() {
        let acc = only_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let Err(e) = Tls::client(client_cfg(), "not a valid name!", acc) else {
            panic!("accepted an invalid name");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn client_transport_starts_handshaking() {
        let acc = only_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let tls = Tls::client(client_cfg(), "localhost", acc).unwrap();
        let mut t = tls.transport().unwrap();
        assert_eq!(t.name(), "tls");
        assert!(t.handshaking());
        // The first call emits the ClientHello.
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        t.recv(&[], &mut plain, &mut out).unwrap();
        assert_eq!(out[0], 22);
        assert!(t.as_any().downcast_mut::<TlsTransport>().is_some());
    }

    #[test]
    fn failed_transport_refuses_everything() {
        let mut f = Failed;
        let (mut a, mut b) = (Vec::new(), Vec::new());
        assert!(f.recv(b"x", &mut a, &mut b).is_err());
        assert!(f.seal(b"x", &mut a).is_err());
        f.shutdown(&mut a);
        assert!(a.is_empty());
        assert_eq!(f.name(), "tls");
        assert!(f.handshaking());
        assert!(f.as_any().downcast_mut::<Failed>().is_some());
    }
}
