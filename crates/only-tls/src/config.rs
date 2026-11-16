//! The configuration types: certificates, keys, root stores, server and client configs, and
//! the error type. They hide the TLS implementation (this crate's own, in `proto`), so it can
//! change without breaking this API.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;

use only_crypto::pkey;

use crate::proto::common::{CertKey, ClientSettings, ServerSettings};
use crate::proto::kx::{DEFAULT_GROUPS, Group};
use crate::proto::session::{AntiReplay, ClientCache, SessionCache, Ticketer};
use crate::proto::suites::{self, Suite};

/// A TLS configuration or certificate problem.
pub struct Error {
    msg: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub(crate) fn new(msg: impl Into<String>) -> Error {
        Error {
            msg: msg.into(),
            source: None,
        }
    }

    pub(crate) fn wrap(
        msg: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Error {
        Error {
            msg: msg.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("msg", &self.msg)
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(s) => write!(f, "tls: {}: {s}", self.msg),
            None => write!(f, "tls: {}", self.msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

fn alpn_list<I, P>(protocols: I) -> Vec<Vec<u8>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    protocols.into_iter().map(|p| p.as_ref().to_vec()).collect()
}

// ---- certificates and keys ----

/// An X.509 certificate (DER).
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate(Vec<u8>);

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("der_len", &self.0.len())
            .finish()
    }
}

impl Certificate {
    /// A certificate from its DER encoding (not validated until it is used).
    pub fn from_der(der: impl Into<Vec<u8>>) -> Certificate {
        Certificate(der.into())
    }

    /// Every `CERTIFICATE` block of a PEM file, in order (a chain: leaf first). Fails when
    /// there is none or a block does not decode.
    pub fn from_pem(pem: &[u8]) -> Result<Vec<Certificate>, Error> {
        let blocks = only_crypto::pem::decode_label(pem, "CERTIFICATE")
            .map_err(|e| Error::wrap("bad PEM certificate", e))?;
        if blocks.is_empty() {
            return Err(Error::new("no certificate in PEM input"));
        }
        Ok(blocks.into_iter().map(Certificate).collect())
    }

    /// The DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyFormat {
    Pkcs8,
    Any,
}

/// A private key (PKCS#8, PKCS#1 RSA or SEC1 EC; DER). Its `Debug` output does not show the
/// key.
#[derive(Clone)]
pub struct PrivateKey(KeyBytes);

#[derive(Clone)]
struct KeyBytes {
    der: Vec<u8>,
    format: KeyFormat,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// A PKCS#8 key (`BEGIN PRIVATE KEY`, what most tools produce today) from its DER encoding
    /// (checked when a configuration is built).
    pub fn from_pkcs8_der(der: impl Into<Vec<u8>>) -> PrivateKey {
        PrivateKey(KeyBytes {
            der: der.into(),
            format: KeyFormat::Pkcs8,
        })
    }

    /// A key from its DER encoding, guessing the format (PKCS#8, PKCS#1 or SEC1).
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<PrivateKey, Error> {
        let der = der.into();
        pkey::PrivateKey::from_der(&der).map_err(|e| Error::wrap("unrecognised private key", e))?;
        Ok(PrivateKey(KeyBytes {
            der,
            format: KeyFormat::Any,
        }))
    }

    /// The first private key of a PEM file (`PRIVATE KEY`, `RSA PRIVATE KEY` or
    /// `EC PRIVATE KEY`).
    pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
        let blocks = only_crypto::pem::decode(pem)
            .map_err(|e| Error::wrap("no usable private key in PEM input", e))?;
        for (label, der) in blocks {
            if matches!(
                label.as_str(),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
            ) {
                return PrivateKey::from_der(der);
            }
        }
        Err(Error::new("no usable private key in PEM input"))
    }

    pub(crate) fn parse(&self) -> Result<pkey::PrivateKey, Error> {
        let r = match self.0.format {
            KeyFormat::Pkcs8 => pkey::PrivateKey::from_pkcs8_der(&self.0.der),
            KeyFormat::Any => pkey::PrivateKey::from_der(&self.0.der),
        };
        r.map_err(|e| Error::wrap("private key", e))
    }
}

/// Trust anchors: the CAs a peer's certificate must chain to.
#[derive(Clone, Default)]
pub struct RootCerts(only_x509::RootStore);

impl fmt::Debug for RootCerts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootCerts")
            .field("len", &self.len())
            .finish()
    }
}

impl RootCerts {
    /// No roots.
    pub fn empty() -> RootCerts {
        RootCerts(only_x509::RootStore::new())
    }

    /// Adds a CA certificate.
    pub fn add(&mut self, cert: &Certificate) -> Result<(), Error> {
        let c = only_x509::Certificate::from_der(cert.0.clone())
            .map_err(|e| Error::wrap("bad root certificate", e))?;
        self.0.add(c);
        Ok(())
    }

    /// Adds every certificate of a PEM file; returns how many.
    pub fn add_pem(&mut self, pem: &[u8]) -> Result<usize, Error> {
        let certs = Certificate::from_pem(pem)?;
        for c in &certs {
            self.add(c)?;
        }
        Ok(certs.len())
    }

    /// Number of roots.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no roots.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn ders(&self) -> Vec<Vec<u8>> {
        self.0.roots().iter().map(|c| c.as_der().to_vec()).collect()
    }
}

fn suites_from_ids(ids: &[u16]) -> Result<Vec<&'static Suite>, Error> {
    ids.iter()
        .map(|id| suites::by_id(*id).ok_or_else(|| Error::new(format!("unknown suite {id:#06x}"))))
        .collect()
}

fn groups_from_ids(ids: &[u16]) -> Result<Vec<Group>, Error> {
    ids.iter()
        .map(|id| Group::from_id(*id).ok_or_else(|| Error::new(format!("unknown group {id:#06x}"))))
        .collect()
}

/// The configuration as given, for the QUIC crate's still rustls-based handshake (until the
/// in-house QUIC replaces it). Not a public API.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ServerParts {
    /// Default chain (DER, leaf first) and its key (PKCS#8 DER).
    pub chain: Vec<Vec<u8>>,
    /// PKCS#8 DER.
    pub key_pkcs8: Vec<u8>,
    /// SNI name, chain, PKCS#8 key.
    pub sni: Vec<(String, Vec<Vec<u8>>, Vec<u8>)>,
    /// ALPN protocols.
    pub alpn: Vec<Vec<u8>>,
    /// Client-auth roots (DER) and whether a certificate is required.
    pub client_auth: Option<(Vec<Vec<u8>>, bool)>,
    /// Session cache entries.
    pub session_cache: usize,
    /// Stateless tickets.
    pub tickets: bool,
    /// TLS 1.3 only.
    pub tls13_only: bool,
}

/// See [`ServerParts`]. Not a public API.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ClientParts {
    /// Roots (DER).
    pub roots: Vec<Vec<u8>>,
    /// ALPN protocols.
    pub alpn: Vec<Vec<u8>>,
    /// Client chain and PKCS#8 key.
    pub client_cert: Option<(Vec<Vec<u8>>, Vec<u8>)>,
    /// Skip verification.
    pub insecure: bool,
    /// Send SNI.
    pub sni: bool,
    /// Resume sessions.
    pub resumption: bool,
    /// TLS 1.3 only.
    pub tls13_only: bool,
}

/// Keeps the configs `Send + Sync` but neither `UnwindSafe` nor `RefUnwindSafe`, as they were
/// when they wrapped rustls (`api/only-tls.txt`): promising those auto traits now would forbid
/// unwind-unsafe state (a callback, a cache) in a later release.
type NotUnwindSafe = PhantomData<Box<dyn std::any::Any + Send + Sync>>;

// ---- server ----

/// A TLS server configuration: what [`Tls::server`](crate::Tls::server) and the QUIC, HTTP/3
/// and other servers take. Cheap to clone. Build one with [`ServerConfig::builder`].
#[derive(Clone)]
pub struct ServerConfig {
    pub(crate) inner: Arc<ServerSettings>,
    parts: Arc<ServerParts>,
    _reserved: NotUnwindSafe,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("alpn", &self.inner.alpn)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// Starts a configuration serving the certificate chain `chain` (leaf first) with `key`.
    pub fn builder(chain: Vec<Certificate>, key: PrivateKey) -> ServerConfigBuilder {
        ServerConfigBuilder {
            chain,
            key,
            sni: Vec::new(),
            alpn: Vec::new(),
            client_auth: None,
            session_cache: 256,
            tickets: false,
            tls13_only: false,
            tls12_only: false,
            suites: None,
            groups: None,
            force_hrr: false,
            tickets13: 2,
            max_early_data: 0,
            anti_replay: (ANTI_REPLAY_WINDOW_MS, ANTI_REPLAY_ENTRIES),
        }
    }

    /// The ALPN protocols offered, in preference order.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn
    }

    /// The configuration as given (QUIC's rustls bridge); not a public API.
    #[doc(hidden)]
    pub fn __parts(&self) -> &ServerParts {
        &self.parts
    }
}

/// Builds a [`ServerConfig`].
#[must_use]
pub struct ServerConfigBuilder {
    chain: Vec<Certificate>,
    key: PrivateKey,
    sni: Vec<(String, Vec<Certificate>, PrivateKey)>,
    alpn: Vec<Vec<u8>>,
    client_auth: Option<(RootCerts, bool)>,
    session_cache: usize,
    tickets: bool,
    tls13_only: bool,
    tls12_only: bool,
    suites: Option<Vec<u16>>,
    groups: Option<Vec<u16>>,
    force_hrr: bool,
    tickets13: usize,
    max_early_data: u32,
    anti_replay: (u64, usize),
}

/// The 0-RTT freshness window (RFC 8446 section 8.3): a ClientHello with early data must
/// arrive within this long of when its ticket age says it was sent.
const ANTI_REPLAY_WINDOW_MS: u64 = 10_000;
/// ClientHellos remembered for replay detection (each for twice the window).
const ANTI_REPLAY_ENTRIES: usize = 100_000;

impl fmt::Debug for ServerConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfigBuilder")
            .field("alpn", &self.alpn)
            .field(
                "sni_names",
                &self.sni.iter().map(|s| &s.0).collect::<Vec<_>>(),
            )
            .field("client_auth", &self.client_auth.as_ref().map(|c| c.1))
            .field("session_cache", &self.session_cache)
            .field("tickets", &self.tickets)
            .field("tls13_only", &self.tls13_only)
            .field("max_early_data", &self.max_early_data)
            .finish_non_exhaustive()
    }
}

impl ServerConfigBuilder {
    /// The ALPN protocols to offer, in preference order (e.g. `["h2", "http/1.1"]`).
    pub fn alpn<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn = alpn_list(protocols);
        self
    }

    /// Serves `chain` and `key` to clients asking for `server_name` (SNI); others get the
    /// default chain.
    pub fn sni_cert(
        mut self,
        server_name: impl Into<String>,
        chain: Vec<Certificate>,
        key: PrivateKey,
    ) -> Self {
        self.sni
            .push((server_name.into().to_ascii_lowercase(), chain, key));
        self
    }

    /// Requires a client certificate chaining to `roots` (mutual TLS).
    pub fn client_auth_required(mut self, roots: RootCerts) -> Self {
        self.client_auth = Some((roots, true));
        self
    }

    /// Verifies a client certificate against `roots` when the client sends one, and also
    /// accepts clients without a certificate.
    pub fn client_auth_optional(mut self, roots: RootCerts) -> Self {
        self.client_auth = Some((roots, false));
        self
    }

    /// Entries of the stateful session-resumption cache (default 256; 0 disables it).
    pub fn session_cache(mut self, entries: usize) -> Self {
        self.session_cache = entries;
        self
    }

    /// Issues stateless session tickets (default off).
    pub fn session_tickets(mut self, yes: bool) -> Self {
        self.tickets = yes;
        self
    }

    /// Accepts TLS 1.3 only (default: TLS 1.2 and 1.3).
    pub fn tls13_only(mut self, yes: bool) -> Self {
        self.tls13_only = yes;
        self
    }

    /// Accepts TLS 1.3 early data (0-RTT, RFC 8446 section 4.2.10) of up to `max_bytes` per
    /// connection from clients resuming a session (default 0: off). Tickets issued from then
    /// on allow it; it needs session resumption ([`session_tickets`](Self::session_tickets)
    /// or the session cache).
    ///
    /// **Early data can be replayed**: an attacker who recorded a client's first flight can
    /// send it again. Replays are refused within this server (a bounded record of recent
    /// ClientHellos and a 10-second freshness window on the ticket age; when the record is
    /// full, early data is rejected), but not across servers sharing tickets. Early data is
    /// processed before the handshake completes, so only accept requests that are safe to
    /// repeat: check [`TlsInfo::early_data`](crate::TlsInfo) and
    /// [`TlsInfo::early_data_len`](crate::TlsInfo) (for HTTP, answer `425 Too Early`,
    /// RFC 8470). Rejected early data is skipped and the client sends it again after the
    /// handshake.
    pub fn early_data(mut self, max_bytes: u32) -> Self {
        self.max_early_data = max_bytes;
        self
    }

    /// Tests: the 0-RTT anti-replay freshness window and record size.
    #[doc(hidden)]
    pub fn __anti_replay(mut self, window: std::time::Duration, entries: usize) -> Self {
        self.anti_replay = (window.as_millis() as u64, entries);
        self
    }

    /// Tests and interop tools: TLS 1.2 only.
    #[doc(hidden)]
    pub fn __tls12_only(mut self, yes: bool) -> Self {
        self.tls12_only = yes;
        self
    }

    /// Tests and interop tools: the cipher suites, by IANA code, in preference order.
    #[doc(hidden)]
    pub fn __suites(mut self, ids: &[u16]) -> Self {
        self.suites = Some(ids.to_vec());
        self
    }

    /// Tests and interop tools: the groups, by IANA code, in preference order.
    #[doc(hidden)]
    pub fn __groups(mut self, ids: &[u16]) -> Self {
        self.groups = Some(ids.to_vec());
        self
    }

    /// Tests: always answer the first ClientHello with a HelloRetryRequest.
    #[doc(hidden)]
    pub fn __force_hello_retry(mut self, yes: bool) -> Self {
        self.force_hrr = yes;
        self
    }

    /// Tests: how many TLS 1.3 tickets to send after a handshake (default 2).
    #[doc(hidden)]
    pub fn __tickets13(mut self, n: usize) -> Self {
        self.tickets13 = n;
        self
    }

    /// Checks the certificates and key and builds the configuration.
    pub fn build(self) -> Result<ServerConfig, Error> {
        if self.chain.is_empty() {
            return Err(Error::new("empty certificate chain"));
        }
        let certified = |chain: &[Certificate], key: &PrivateKey| -> Result<CertKey, Error> {
            let k = key.parse()?;
            let leaf = only_x509::Certificate::from_der(chain[0].0.clone())
                .map_err(|e| Error::wrap("bad certificate", e))?;
            let pk = leaf
                .public_key()
                .map_err(|e| Error::wrap("certificate public key", e))?;
            if pk != k.public_key() {
                return Err(Error::new("private key does not match the certificate"));
            }
            Ok(CertKey {
                chain: chain.iter().map(|c| c.0.clone()).collect(),
                key: k,
            })
        };
        if self.client_auth.as_ref().is_some_and(|(r, _)| r.is_empty()) {
            return Err(Error::new("client authentication roots: no roots"));
        }
        let default = certified(&self.chain, &self.key)?;
        let mut by_name = HashMap::new();
        let mut sni_parts = Vec::new();
        for (name, chain, key) in &self.sni {
            if chain.is_empty() {
                return Err(Error::new("empty certificate chain"));
            }
            let ck = certified(chain, key)?;
            sni_parts.push((name.clone(), ck.chain.clone(), ck.key.to_pkcs8_der()));
            by_name.insert(name.clone(), Arc::new(ck));
        }
        let mut suites = match &self.suites {
            Some(ids) => suites_from_ids(ids)?,
            None => suites::ALL.to_vec(),
        };
        if self.tls13_only {
            suites.retain(|s| s.is_tls13());
        }
        if self.tls12_only {
            suites.retain(|s| !s.is_tls13());
        }
        if suites.is_empty() {
            return Err(Error::new("no cipher suites left"));
        }
        let groups = match &self.groups {
            Some(ids) => groups_from_ids(ids)?,
            None => DEFAULT_GROUPS.to_vec(),
        };
        if groups.is_empty() {
            return Err(Error::new("no groups"));
        }
        let ticketer = if self.tickets {
            Some(Ticketer::new().ok_or_else(|| Error::new("no randomness for tickets"))?)
        } else {
            None
        };
        let parts = ServerParts {
            chain: default.chain.clone(),
            key_pkcs8: default.key.to_pkcs8_der(),
            sni: sni_parts,
            alpn: self.alpn.clone(),
            client_auth: self.client_auth.as_ref().map(|(r, req)| (r.ders(), *req)),
            session_cache: self.session_cache,
            tickets: self.tickets,
            tls13_only: self.tls13_only,
        };
        let settings = ServerSettings {
            cert: Arc::new(default),
            sni: by_name,
            alpn: self.alpn,
            client_auth: self.client_auth.map(|(r, req)| (Arc::new(r.0), req)),
            cache: (self.session_cache > 0).then(|| SessionCache::new(self.session_cache)),
            ticketer,
            tls12: suites.iter().any(|s| !s.is_tls13()),
            tls13: suites.iter().any(|s| s.is_tls13()),
            suites,
            groups,
            tickets13: self.tickets13,
            ticket_lifetime: 6 * 3600,
            force_hrr: self.force_hrr,
            max_early_data: self.max_early_data,
            anti_replay: AntiReplay::new(self.anti_replay.0, self.anti_replay.1),
        };
        Ok(ServerConfig {
            inner: Arc::new(settings),
            parts: Arc::new(parts),
            _reserved: PhantomData,
        })
    }
}

// ---- client ----

/// A TLS client configuration: what [`Tls::client`](crate::Tls::client), the HTTP, HTTP/2,
/// WebSocket and QUIC clients take. Cheap to clone. Build one with [`ClientConfig::builder`].
#[derive(Clone)]
pub struct ClientConfig {
    pub(crate) inner: Arc<ClientSettings>,
    parts: Arc<ClientParts>,
    _reserved: NotUnwindSafe,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("alpn", &self.inner.alpn)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Starts a configuration with no roots (add them with
    /// [`roots`](ClientConfigBuilder::roots)).
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder {
            roots: RootCerts::empty(),
            alpn: Vec::new(),
            client_cert: None,
            insecure: false,
            sni: true,
            resumption: true,
            tls13_only: false,
            tls12_only: false,
            suites: None,
            groups: None,
            early_data: false,
        }
    }

    /// The ALPN protocols asked for, in preference order.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn
    }

    /// The configuration as given (QUIC's rustls bridge); not a public API.
    #[doc(hidden)]
    pub fn __parts(&self) -> &ClientParts {
        &self.parts
    }
}

/// Builds a [`ClientConfig`].
#[must_use]
pub struct ClientConfigBuilder {
    roots: RootCerts,
    alpn: Vec<Vec<u8>>,
    client_cert: Option<(Vec<Certificate>, PrivateKey)>,
    insecure: bool,
    sni: bool,
    resumption: bool,
    tls13_only: bool,
    tls12_only: bool,
    suites: Option<Vec<u16>>,
    groups: Option<Vec<u16>>,
    early_data: bool,
}

impl fmt::Debug for ClientConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigBuilder")
            .field("roots", &self.roots)
            .field("alpn", &self.alpn)
            .field("client_cert", &self.client_cert.is_some())
            .field("insecure", &self.insecure)
            .field("sni", &self.sni)
            .field("resumption", &self.resumption)
            .field("tls13_only", &self.tls13_only)
            .field("early_data", &self.early_data)
            .finish_non_exhaustive()
    }
}

impl ClientConfigBuilder {
    /// The CAs server certificates must chain to.
    pub fn roots(mut self, roots: RootCerts) -> Self {
        self.roots = roots;
        self
    }

    /// The ALPN protocols to ask for, in preference order.
    pub fn alpn<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn = alpn_list(protocols);
        self
    }

    /// Presents `chain` (leaf first) and `key` when the server asks for a client certificate.
    pub fn client_cert(mut self, chain: Vec<Certificate>, key: PrivateKey) -> Self {
        self.client_cert = Some((chain, key));
        self
    }

    /// Sends the server name in the handshake (SNI; default on).
    pub fn sni(mut self, yes: bool) -> Self {
        self.sni = yes;
        self
    }

    /// Resumes sessions with servers seen before (default on).
    pub fn resumption(mut self, yes: bool) -> Self {
        self.resumption = yes;
        self
    }

    /// Accepts TLS 1.3 only (default: TLS 1.2 and 1.3).
    pub fn tls13_only(mut self, yes: bool) -> Self {
        self.tls13_only = yes;
        self
    }

    /// Sends TLS 1.3 early data (0-RTT) when resuming with a ticket that allows it (default
    /// off): what the application sends before the handshake completes goes out with the
    /// ClientHello, up to the ticket's limit, saving a round trip. The server may reject it;
    /// then it is sent again after the handshake, so the stream is the same either way.
    /// [`TlsInfo::early_data`](crate::TlsInfo) and
    /// [`TlsInfo::early_data_len`](crate::TlsInfo) tell which bytes went early and what
    /// became of them.
    ///
    /// Early data can be **replayed** by an attacker and is not forward secret: only send
    /// requests early that are safe to repeat (no orders, payments or other state changes).
    pub fn early_data(mut self, yes: bool) -> Self {
        self.early_data = yes;
        self
    }

    /// Accepts **any** server certificate, without verifying it: for tests and interop runs
    /// against self-signed servers only, never in production.
    pub fn insecure_skip_verify(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Tests and interop tools: TLS 1.2 only.
    #[doc(hidden)]
    pub fn __tls12_only(mut self, yes: bool) -> Self {
        self.tls12_only = yes;
        self
    }

    /// Tests and interop tools: the cipher suites, by IANA code, in preference order.
    #[doc(hidden)]
    pub fn __suites(mut self, ids: &[u16]) -> Self {
        self.suites = Some(ids.to_vec());
        self
    }

    /// Tests and interop tools: the groups, by IANA code; a key share goes for the first.
    #[doc(hidden)]
    pub fn __groups(mut self, ids: &[u16]) -> Self {
        self.groups = Some(ids.to_vec());
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ClientConfig, Error> {
        let cert = match &self.client_cert {
            None => None,
            Some((chain, key)) => {
                if chain.is_empty() {
                    return Err(Error::new("empty client certificate chain"));
                }
                Some(Arc::new(CertKey {
                    chain: chain.iter().map(|c| c.0.clone()).collect(),
                    key: key
                        .parse()
                        .map_err(|e| Error::wrap("client certificate", e))?,
                }))
            }
        };
        let mut suites = match &self.suites {
            Some(ids) => suites_from_ids(ids)?,
            None => suites::ALL.to_vec(),
        };
        if self.tls13_only {
            suites.retain(|s| s.is_tls13());
        }
        if self.tls12_only {
            suites.retain(|s| !s.is_tls13());
        }
        if suites.is_empty() {
            return Err(Error::new("no cipher suites left"));
        }
        let groups = match &self.groups {
            Some(ids) => groups_from_ids(ids)?,
            None => DEFAULT_GROUPS.to_vec(),
        };
        if groups.is_empty() {
            return Err(Error::new("no groups"));
        }
        let parts = ClientParts {
            roots: self.roots.ders(),
            alpn: self.alpn.clone(),
            client_cert: cert
                .as_ref()
                .map(|c| (c.chain.clone(), c.key.to_pkcs8_der())),
            insecure: self.insecure,
            sni: self.sni,
            resumption: self.resumption,
            tls13_only: self.tls13_only,
        };
        let settings = ClientSettings {
            roots: Arc::new(self.roots.0),
            insecure: self.insecure,
            alpn: self.alpn,
            cert,
            sni: self.sni,
            cache: self.resumption.then(ClientCache::new),
            tls12: suites.iter().any(|s| !s.is_tls13()),
            tls13: suites.iter().any(|s| s.is_tls13()),
            suites,
            groups,
            early_data: self.early_data,
        };
        Ok(ClientConfig {
            inner: Arc::new(settings),
            parts: Arc::new(parts),
            _reserved: PhantomData,
        })
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
