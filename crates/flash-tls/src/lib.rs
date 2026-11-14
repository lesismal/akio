#![forbid(unsafe_code)]
//! TLS for flash, on top of [rustls](https://docs.rs/rustls) driven sans-io.
//!
//! Wrap any [`Acceptor`] in [`Tls::server`] (or [`Tls::client`] for [`dial`](../flash/struct.Engine.html))
//! and its handlers see **plaintext**: `on_data` receives decrypted bytes and `Conn::send*` encrypts.
//! The handshake runs on the connection's I/O thread, interleaved with other connections, and
//! never blocks; application bytes sent during the handshake are held back and go out as soon as
//! it completes.
//!
//! Everything rustls offers is configured through its own `ServerConfig` / `ClientConfig`:
//! certificates and SNI-based selection (`ResolvesServerCert`), ALPN (`alpn_protocols`), session
//! tickets (`ticketer`), client authentication, protocol versions. [`tls_info`] reads what was
//! negotiated.
//!
//! ```no_run
//! use std::sync::Arc;
//! use flash_tls::{Tls, rustls};
//! # fn certs() -> (Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>) { unimplemented!() }
//! # struct Echo; impl flash_core::Handler for Echo { fn on_data(&mut self, _: &flash_core::Conn<Self>, _: &[u8]) {} }
//! let (chain, key) = certs();
//! let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key).unwrap();
//! cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
//! let acceptor = Tls::server(Arc::new(cfg), flash_core::fn_acceptor(|_c: &flash_core::Conn<Echo>| Echo));
//! # let _ = acceptor;
//! ```
//!
//! Guide: [TLS](https://lesismal.github.io/flash/en/protocols/tls.html)
//! (中文: [TLS](https://lesismal.github.io/flash/zh-CN/protocols/tls.html)).
#![warn(clippy::unwrap_used)]

use std::{
    any::Any,
    io::{self, Read, Write},
    sync::Arc,
};

use flash_core::{Acceptor, Conn, Transport};
pub use rustls;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

/// Wraps an acceptor so that its connections speak TLS.
pub struct Tls<A> {
    mode: Mode,
    inner: A,
}

enum Mode {
    Server(Arc<ServerConfig>),
    Client(Arc<ClientConfig>, rustls::pki_types::ServerName<'static>),
}

impl<A: Acceptor> Tls<A> {
    /// Serves TLS with `config`; `inner` handles the decrypted connection.
    pub fn server(config: Arc<ServerConfig>, inner: A) -> Self {
        Tls {
            mode: Mode::Server(config),
            inner,
        }
    }

    /// Connects with TLS to `server_name` (for certificate verification and SNI), for
    /// connections made with `Engine::dial`.
    pub fn client(config: Arc<ClientConfig>, server_name: &str, inner: A) -> io::Result<Self> {
        let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Tls {
            mode: Mode::Client(config, name),
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
            Mode::Server(cfg) => ServerConnection::new(cfg.clone()).map(Connection::Server),
            Mode::Client(cfg, name) => {
                ClientConnection::new(cfg.clone(), name.clone()).map(Connection::Client)
            }
        };
        match conn {
            Ok(conn) => Some(Box::new(RustlsTransport { conn })),
            Err(e) => {
                eprintln!("flash-tls: cannot start TLS session: {e}");
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

struct RustlsTransport {
    conn: Connection,
}

impl RustlsTransport {
    /// Moves every record rustls has ready into `out`.
    fn drain_records(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(out)?;
        }
        Ok(())
    }
}

impl Transport for RustlsTransport {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        let mut rd = cipher;
        let mut tmp = [0u8; 16 << 10];
        // An empty input still gives a client the chance to emit its first flight.
        loop {
            if !rd.is_empty() {
                self.conn.read_tls(&mut rd)?;
                if let Err(e) = self.conn.process_new_packets() {
                    // rustls queued an alert; send it before the connection is closed.
                    let _ = self.drain_records(out);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
                loop {
                    match self.conn.reader().read(&mut tmp) {
                        Ok(0) => break, // close_notify: the transport FIN follows
                        Ok(n) => plain.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            if rd.is_empty() {
                break;
            }
        }
        self.drain_records(out)
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        // rustls accepts plaintext only while its pending-records buffer is below a limit
        // (64 KiB by default), so a big write goes in as record-sized pieces, draining the
        // records after each.
        for piece in plain.chunks(16 << 10) {
            self.conn.writer().write_all(piece)?;
            self.drain_records(out)?;
        }
        self.drain_records(out)
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        self.conn.send_close_notify();
        let _ = self.drain_records(out);
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn name(&self) -> &'static str {
        "tls"
    }

    fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }
}

/// What a connection negotiated; see [`tls_info`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsInfo {
    /// The handshake has not finished yet (the other fields may still be empty).
    pub handshaking: bool,
    /// Negotiated ALPN protocol, e.g. `b"h2"`.
    pub alpn: Option<Vec<u8>>,
    /// SNI name the client asked for (server side only).
    pub server_name: Option<String>,
    /// Negotiated protocol version, e.g. `"TLSv1_3"`.
    pub version: Option<String>,
}

/// TLS details of `c`, or `None` if it is not a TLS connection.
pub fn tls_info<H>(c: &Conn<H>) -> Option<TlsInfo> {
    c.with_transport(|t| {
        let t = t.as_any().downcast_mut::<RustlsTransport>()?;
        Some(TlsInfo {
            handshaking: t.conn.is_handshaking(),
            alpn: t.conn.alpn_protocol().map(<[u8]>::to_vec),
            server_name: match &t.conn {
                Connection::Server(s) => s.server_name().map(str::to_owned),
                Connection::Client(_) => None,
            },
            version: t.conn.protocol_version().map(|v| format!("{v:?}")),
        })
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nop;
    impl flash_core::Handler for Nop {
        fn on_data(&mut self, _: &Conn<Self>, _: &[u8]) {}
    }

    fn client_cfg() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    #[test]
    fn invalid_server_name_is_rejected() {
        let acc = flash_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let Err(e) = Tls::client(client_cfg(), "not a valid name!", acc) else {
            panic!("accepted an invalid name");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn client_transport_starts_handshaking() {
        let acc = flash_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let tls = Tls::client(client_cfg(), "localhost", acc).unwrap();
        let t = tls.transport().unwrap();
        assert_eq!(t.name(), "tls");
        assert!(t.handshaking());
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
