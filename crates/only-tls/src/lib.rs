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
//! protection, shareable across servers through an [`AntiReplayStore`] (or a remote
//! [`AsyncAntiReplayStore`] answered without blocking the I/O thread), session tickets under
//! rotating [`TicketKeys`]:
//! [`ServerConfigBuilder::early_data`], [`ClientConfigBuilder::early_data`],
//! [`TlsInfo::early_data`]) and TLS 1.2 (RFC 5246 with ECDHE and AEAD
//! suites only, extended master secret, renegotiation indication with renegotiation refused,
//! session IDs and tickets); AES-128/256-GCM and ChaCha20-Poly1305; X25519, P-256, P-384, X448,
//! P-521; ECDSA (P-256, P-384, P-521), Ed25519, Ed448 and RSA (PSS with `rsaEncryption` or
//! `id-RSASSA-PSS` keys; PKCS#1 v1.5 in TLS 1.2) certificates verified with `only-x509`; SNI and
//! ALPN; revocation checking, off by default ([`RevocationPolicy`]: the stapled OCSP response
//! with [`ClientConfigBuilder::ocsp_policy`], a TLS 1.3 client's with
//! [`ServerConfigBuilder::client_ocsp_policy`], application-supplied [`Crls`] for server and
//! client chains).
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

use std::{
    any::Any,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use only_core::{
    Acceptor, Conn, Transport,
    metrics::{Collector, Families},
};

mod config;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
#[cfg(all(target_os = "linux", feature = "ktls"))]
mod ktls;
mod proto;
#[doc(hidden)]
pub mod quic;
mod replay;
#[doc(hidden)]
pub mod stream;
mod system;
mod tickets;
mod trust;

pub use config::{
    CertCompression, Certificate, ClientConfig, ClientConfigBuilder, Crls, Error, Ktls, PrivateKey,
    RevocationPolicy, RootCerts, ServerConfig, ServerConfigBuilder,
};

/// Who does one direction's record protection once a connection moved it into the kernel
/// ([`Ktls`], [`TlsInfo::ktls_tx`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KtlsPath {
    /// The kernel, on the CPU.
    Software,
    /// The NIC (TLS device offload).
    Hardware,
}
#[doc(hidden)]
pub use config::{ClientParts, ServerParts};
pub use replay::{AntiReplayStore, AsyncAntiReplayStore, MemoryAntiReplay, ReplayCheck};
pub use tickets::{MAX_TICKET_KEYS, TicketKeys};

/// The protocol core, for tests, fuzzing and interop tools. **Not** a public API.
#[doc(hidden)]
pub mod __proto {
    pub use crate::proto::alert::{Alert, Fatal};
    pub use crate::proto::suites;
    pub use crate::proto::{Connection, Group, Keys, Level};
    #[cfg(feature = "ktls")]
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
    stats: TlsStats,
}

/// Handshake outcomes of the connections of one [`Tls`] acceptor, from [`Tls::stats`]; cheap to
/// clone (shared counters). A [`Collector`] (ADR-015) reporting
/// `only_tls_handshakes_total{side, version}`, `only_tls_resumed_total{side}` and
/// `only_tls_early_data_total{side, outcome}` (`accepted` / `rejected`), and
/// `only_tls_ktls_total{side, dir, path}` (directions moved into the kernel, [`Ktls`]: `dir` is
/// `tx` / `rx`, `path` `software` / `hardware`). Failed handshakes are counted by the engine
/// (`only_tls_handshake_failures_total`).
#[derive(Clone, Debug, Default)]
pub struct TlsStats(Arc<StatsInner>);

#[derive(Debug, Default)]
struct StatsInner {
    server: bool,
    tls13: AtomicU64,
    tls12: AtomicU64,
    resumed: AtomicU64,
    early_accepted: AtomicU64,
    early_rejected: AtomicU64,
    /// Kernel TLS installs: [tx software, tx hardware, rx software, rx hardware].
    ktls: [AtomicU64; 4],
}

/// A snapshot of [`TlsStats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsCounts {
    /// Completed TLS 1.3 handshakes.
    pub tls13: u64,
    /// Completed TLS 1.2 handshakes.
    pub tls12: u64,
    /// Handshakes that resumed a session.
    pub resumed: u64,
    /// Handshakes whose early data (0-RTT) was accepted.
    pub early_accepted: u64,
    /// Handshakes whose early data was rejected.
    pub early_rejected: u64,
    /// Connections whose send direction moved into the kernel, in software ([`Ktls`]).
    pub ktls_tx_software: u64,
    /// Connections whose send direction a NIC took.
    pub ktls_tx_hardware: u64,
    /// Connections whose receive direction moved into the kernel, in software.
    pub ktls_rx_software: u64,
    /// Connections whose receive direction a NIC took.
    pub ktls_rx_hardware: u64,
}

impl TlsStats {
    fn new(server: bool) -> TlsStats {
        TlsStats(Arc::new(StatsInner {
            server,
            ..StatsInner::default()
        }))
    }

    /// Current counts.
    pub fn counts(&self) -> TlsCounts {
        let s = &self.0;
        TlsCounts {
            tls13: s.tls13.load(Ordering::Relaxed),
            tls12: s.tls12.load(Ordering::Relaxed),
            resumed: s.resumed.load(Ordering::Relaxed),
            early_accepted: s.early_accepted.load(Ordering::Relaxed),
            early_rejected: s.early_rejected.load(Ordering::Relaxed),
            ktls_tx_software: s.ktls[0].load(Ordering::Relaxed),
            ktls_tx_hardware: s.ktls[1].load(Ordering::Relaxed),
            ktls_rx_software: s.ktls[2].load(Ordering::Relaxed),
            ktls_rx_hardware: s.ktls[3].load(Ordering::Relaxed),
        }
    }

    /// A direction moved into the kernel.
    #[cfg_attr(not(all(target_os = "linux", feature = "ktls")), allow(dead_code))]
    pub(crate) fn ktls_installed(&self, tx: bool, path: KtlsPath) {
        let i = usize::from(!tx) * 2 + usize::from(path == KtlsPath::Hardware);
        self.0.ktls[i].fetch_add(1, Ordering::Relaxed);
    }

    fn handshake_done(&self, c: &proto::Connection) {
        let s = &self.0;
        match c.version_name() {
            Some("TLSv1_2") => &s.tls12,
            _ => &s.tls13,
        }
        .fetch_add(1, Ordering::Relaxed);
        if c.resumed() {
            s.resumed.fetch_add(1, Ordering::Relaxed);
        }
        match c.early_data() {
            EarlyData::Accepted => {
                s.early_accepted.fetch_add(1, Ordering::Relaxed);
            }
            EarlyData::Rejected => {
                s.early_rejected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

impl Collector for TlsStats {
    fn collect(&self, out: &mut Families) {
        let c = self.counts();
        let side = if self.0.server { "server" } else { "client" };
        let h = "Completed TLS handshakes.";
        out.counter(
            "only_tls_handshakes_total",
            h,
            &[("side", side), ("version", "1.3")],
            c.tls13 as f64,
        );
        out.counter(
            "only_tls_handshakes_total",
            h,
            &[("side", side), ("version", "1.2")],
            c.tls12 as f64,
        );
        out.counter(
            "only_tls_resumed_total",
            "TLS handshakes that resumed a session.",
            &[("side", side)],
            c.resumed as f64,
        );
        let h = "TLS handshakes with early data (0-RTT), by outcome.";
        out.counter(
            "only_tls_early_data_total",
            h,
            &[("side", side), ("outcome", "accepted")],
            c.early_accepted as f64,
        );
        out.counter(
            "only_tls_early_data_total",
            h,
            &[("side", side), ("outcome", "rejected")],
            c.early_rejected as f64,
        );
        let h = "TLS connections whose record layer moved into the kernel, by direction and path.";
        for (dir, path, v) in [
            ("tx", "software", c.ktls_tx_software),
            ("tx", "hardware", c.ktls_tx_hardware),
            ("rx", "software", c.ktls_rx_software),
            ("rx", "hardware", c.ktls_rx_hardware),
        ] {
            out.counter(
                "only_tls_ktls_total",
                h,
                &[("side", side), ("dir", dir), ("path", path)],
                v as f64,
            );
        }
    }
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
            stats: TlsStats::new(true),
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
            stats: TlsStats::new(false),
        })
    }

    /// The handshake counters of this acceptor's connections (clones share them); register
    /// them with `Telemetry::register_collector` to export them.
    pub fn stats(&self) -> TlsStats {
        self.stats.clone()
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
        let (conn, timeout, ktls) = match &self.mode {
            Mode::Server(cfg) => (
                Ok(proto::Connection::server(cfg.inner.clone())),
                cfg.handshake_timeout,
                cfg.ktls,
            ),
            Mode::Client(cfg, name) => (
                proto::Connection::client(cfg.inner.clone(), name),
                cfg.handshake_timeout,
                cfg.ktls,
            ),
        };
        match conn {
            Ok(mut conn) => {
                if let Some(n) = ktls.key_update_after {
                    conn.set_key_update_after(n);
                }
                Some(Box::new(TlsTransport {
                    #[cfg(all(target_os = "linux", feature = "ktls"))]
                    // `Hardware` on a host without a NIC that offloads TLS: as `Off`.
                    ktls: match ktls.mode {
                        Ktls::Off => false,
                        Ktls::Hardware => ktls::any_hardware(),
                        _ => true,
                    }
                    .then(|| {
                        conn.set_keep_keys(true);
                        Box::new(ktls::KtlsState::new(ktls, self.stats.clone()))
                    }),
                    conn,
                    stats: Some(self.stats.clone()),
                    timeout,
                }))
            }
            Err(e) => {
                only_log::warn!(target: "only::tls", "cannot start TLS session: {e}");
                // No transport would mean plaintext; refuse by installing a dead one.
                Some(Box::new(Failed(timeout)))
            }
        }
    }
}

/// Installed when a session cannot be created: every operation fails, so the connection closes
/// instead of silently falling back to plaintext.
struct Failed(Option<Duration>);

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
    fn handshake_timeout(&self) -> Option<Duration> {
        self.0
    }
}

struct TlsTransport {
    conn: proto::Connection,
    /// Taken when the completed handshake has been counted.
    stats: Option<TlsStats>,
    /// [`ServerConfigBuilder::handshake_timeout`] / [`ClientConfigBuilder::handshake_timeout`].
    timeout: Option<Duration>,
    /// Kernel TLS ([`Ktls`] other than `Off`).
    #[cfg(all(target_os = "linux", feature = "ktls"))]
    ktls: Option<Box<ktls::KtlsState>>,
}

impl TlsTransport {
    /// Where each direction's record protection is: `None` while in user space.
    fn ktls_paths(&self) -> (Option<KtlsPath>, Option<KtlsPath>) {
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        if let Some(k) = &self.ktls {
            return k.paths();
        }
        (None, None)
    }
}

fn io_err(e: proto::Fatal) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl Transport for TlsTransport {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        // An empty input still gives a client the chance to emit its first flight.
        self.conn.recv(cipher, plain, out).map_err(io_err)?;
        if self.stats.is_some() && !self.conn.handshaking() {
            if let Some(s) = self.stats.take() {
                s.handshake_done(&self.conn);
            }
        }
        Ok(())
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

    fn handshake_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn set_waker(&mut self, waker: only_core::TransportWaker) {
        // A suspended handshake (asynchronous anti-replay store) resumes through it.
        self.conn.set_waker(Arc::new(move || waker.wake()));
    }

    #[cfg(all(target_os = "linux", feature = "ktls"))]
    fn wants_offload(&self) -> bool {
        self.ktls.as_ref().is_some_and(|k| k.wants())
    }

    #[cfg(all(target_os = "linux", feature = "ktls"))]
    fn offload(
        &mut self,
        fd: std::os::fd::RawFd,
        local: std::net::SocketAddr,
        rx_ok: bool,
    ) -> io::Result<only_core::Offloaded> {
        match self.ktls.as_mut() {
            Some(k) => k.offload(&mut self.conn, fd, local.ip(), rx_ok),
            None => Ok(only_core::Offloaded::default()),
        }
    }

    #[cfg(all(target_os = "linux", feature = "ktls"))]
    fn kernel_send(
        &mut self,
        len: usize,
        ops: &mut Vec<Box<dyn only_core::SocketOp>>,
    ) -> io::Result<()> {
        match self.ktls.as_mut() {
            Some(k) => k.kernel_send(&mut self.conn, len, ops),
            None => Ok(()),
        }
    }

    #[cfg(all(target_os = "linux", feature = "ktls"))]
    fn take_ops(&mut self, ops: &mut Vec<Box<dyn only_core::SocketOp>>) {
        if let Some(k) = self.ktls.as_mut() {
            k.take_ops(&mut self.conn, ops);
        }
    }

    #[cfg(all(target_os = "linux", feature = "ktls"))]
    fn kernel_record(&mut self, typ: u8, content: &[u8]) -> io::Result<bool> {
        match self.ktls.as_mut() {
            Some(k) => k.kernel_record(&mut self.conn, typ, content),
            None => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

/// What happened to TLS 1.3 early data (0-RTT) on a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EarlyData {
    /// None was sent (client: early data off, or no ticket allowing it; server: the client
    /// offered none).
    #[default]
    NotAttempted,
    /// The client sent early data and the server has not answered yet (client only).
    Pending,
    /// The server accepted the early data: it was processed before the handshake completed,
    /// and may be a replay of an earlier connection's (see the security notes).
    Accepted,
    /// The server rejected the early data: it was skipped by the server, and the client sends
    /// it again as ordinary data after the handshake.
    Rejected,
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
    /// The OCSP response (DER) the peer stapled to its certificate. Client side: the server's,
    /// when asked for with [`ClientConfigBuilder::ocsp_stapling`] (verified only under an
    /// [`ocsp_policy`](ClientConfigBuilder::ocsp_policy)). Server side: a TLS 1.3 client's,
    /// when asked for with [`ServerConfigBuilder::client_ocsp_policy`] (which verified it).
    pub ocsp_response: Option<Vec<u8>>,
    /// Where the send direction's record protection is, once moved into the kernel ([`Ktls`]);
    /// `None` while only-tls does it.
    pub ktls_tx: Option<KtlsPath>,
    /// Where the receive direction's record protection is, once moved into the kernel.
    pub ktls_rx: Option<KtlsPath>,
}

/// TLS details of `c`, or `None` if it is not a TLS connection.
pub fn tls_info<H>(c: &Conn<H>) -> Option<TlsInfo> {
    c.with_transport(|t| {
        let t = t.as_any().downcast_mut::<TlsTransport>()?;
        let (ktls_tx, ktls_rx) = t.ktls_paths();
        Some(TlsInfo {
            ktls_tx,
            ktls_rx,
            handshaking: t.conn.handshaking(),
            alpn: t.conn.alpn().map(<[u8]>::to_vec),
            server_name: t.conn.server_name().map(str::to_owned),
            version: t.conn.version_name().map(str::to_owned),
            early_data: t.conn.early_data(),
            early_data_len: t.conn.early_data_len(),
            ocsp_response: t.conn.ocsp_response().map(<[u8]>::to_vec),
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
        // A safe handshake deadline by default.
        assert_eq!(t.handshake_timeout(), Some(Duration::from_secs(10)));
        // The first call emits the ClientHello.
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        t.recv(&[], &mut plain, &mut out).unwrap();
        assert_eq!(out[0], 22);
        assert!(t.as_any().downcast_mut::<TlsTransport>().is_some());
    }

    #[test]
    fn handshake_timeout_is_configurable() {
        let acc = only_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let cfg = ClientConfig::builder()
            .handshake_timeout(None)
            .build()
            .unwrap();
        let tls = Tls::client(cfg, "localhost", acc).unwrap();
        assert_eq!(tls.transport().unwrap().handshake_timeout(), None);
        let acc = only_core::fn_acceptor(|_c: &Conn<Nop>| Nop);
        let cfg = ClientConfig::builder()
            .handshake_timeout(Some(Duration::from_millis(1500)))
            .build()
            .unwrap();
        let tls = Tls::client(cfg, "localhost", acc).unwrap();
        let t = tls.transport().unwrap();
        assert_eq!(t.handshake_timeout(), Some(Duration::from_millis(1500)));
        assert_eq!(
            Failed(Some(Duration::from_secs(1))).handshake_timeout(),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn failed_transport_refuses_everything() {
        let mut f = Failed(None);
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
