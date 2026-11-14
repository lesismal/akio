//! The configuration types: certificates, keys, root stores, server and client configs, and
//! the error type. They hide the TLS implementation (rustls today), so it can be upgraded or
//! replaced without breaking this API; raw access is behind the `unstable` cargo feature.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

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

/// The crypto provider every config is built with (ring).
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn versions(tls13_only: bool) -> &'static [&'static rustls::SupportedProtocolVersion] {
    if tls13_only {
        TLS13_ONLY
    } else {
        rustls::DEFAULT_VERSIONS
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
pub struct Certificate(CertificateDer<'static>);

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
        Certificate(CertificateDer::from(der.into()))
    }

    /// Every `CERTIFICATE` block of a PEM file, in order (a chain: leaf first). Fails when
    /// there is none or a block does not decode.
    pub fn from_pem(pem: &[u8]) -> Result<Vec<Certificate>, Error> {
        let mut out = Vec::new();
        for c in CertificateDer::pem_slice_iter(pem) {
            out.push(Certificate(
                c.map_err(|e| Error::wrap("bad PEM certificate", e))?,
            ));
        }
        if out.is_empty() {
            return Err(Error::new("no certificate in PEM input"));
        }
        Ok(out)
    }

    /// The DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// A private key (PKCS#8, PKCS#1 RSA or SEC1 EC; DER). Its `Debug` output does not show the
/// key.
pub struct PrivateKey(PrivateKeyDer<'static>);

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey(self.0.clone_key())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// A PKCS#8 key (`BEGIN PRIVATE KEY`, what most tools produce today) from its DER encoding.
    pub fn from_pkcs8_der(der: impl Into<Vec<u8>>) -> PrivateKey {
        PrivateKey(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.into())))
    }

    /// A key from its DER encoding, guessing the format (PKCS#8, PKCS#1 or SEC1).
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<PrivateKey, Error> {
        PrivateKeyDer::try_from(der.into())
            .map(PrivateKey)
            .map_err(|e| Error::new(format!("unrecognised private key: {e}")))
    }

    /// The first private key of a PEM file (`PRIVATE KEY`, `RSA PRIVATE KEY` or
    /// `EC PRIVATE KEY`).
    pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
        PrivateKeyDer::from_pem_slice(pem)
            .map(PrivateKey)
            .map_err(|e| Error::wrap("no usable private key in PEM input", e))
    }
}

/// Trust anchors: the CAs a peer's certificate must chain to.
#[derive(Clone)]
pub struct RootCerts(rustls::RootCertStore);

impl Default for RootCerts {
    fn default() -> Self {
        RootCerts::empty()
    }
}

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
        RootCerts(rustls::RootCertStore::empty())
    }

    /// Adds a CA certificate.
    pub fn add(&mut self, cert: &Certificate) -> Result<(), Error> {
        self.0
            .add(cert.0.clone())
            .map_err(|e| Error::wrap("bad root certificate", e))
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
}

// ---- server ----

/// A TLS server configuration: what [`Tls::server`](crate::Tls::server) and the QUIC, HTTP/3
/// and other servers take. Cheap to clone. Build one with [`ServerConfig::builder`].
#[derive(Clone)]
pub struct ServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("alpn", &self.inner.alpn_protocols)
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
        }
    }

    /// The ALPN protocols offered, in preference order.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn_protocols
    }

    /// Wraps a rustls configuration. **Unstable** (cargo feature `unstable`, outside the semver
    /// promise): rustls's types change with its versions.
    #[cfg(feature = "unstable")]
    pub fn from_rustls(config: impl Into<Arc<rustls::ServerConfig>>) -> ServerConfig {
        ServerConfig {
            inner: config.into(),
        }
    }

    /// The rustls configuration. **Unstable** (cargo feature `unstable`).
    #[cfg(feature = "unstable")]
    pub fn as_rustls(&self) -> &Arc<rustls::ServerConfig> {
        &self.inner
    }

    /// For the other crates of this workspace (QUIC); not a public API.
    #[doc(hidden)]
    pub fn __rustls(&self) -> &Arc<rustls::ServerConfig> {
        &self.inner
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
}

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

    /// Checks the certificates and key and builds the configuration.
    pub fn build(self) -> Result<ServerConfig, Error> {
        let p = provider();
        let b = rustls::ServerConfig::builder_with_provider(p.clone())
            .with_protocol_versions(versions(self.tls13_only))
            .map_err(|e| Error::wrap("protocol versions", e))?;
        let b = match self.client_auth {
            None => b.with_no_client_auth(),
            Some((roots, required)) => {
                let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots.0),
                    p.clone(),
                );
                let v = if required {
                    v
                } else {
                    v.allow_unauthenticated()
                };
                let v = v
                    .build()
                    .map_err(|e| Error::wrap("client authentication roots", e))?;
                b.with_client_cert_verifier(v)
            }
        };
        let certified = |chain: Vec<Certificate>, key: PrivateKey| -> Result<_, Error> {
            let signing = p
                .key_provider
                .load_private_key(key.0)
                .map_err(|e| Error::wrap("private key", e))?;
            Ok(Arc::new(CertifiedKey::new(
                chain.into_iter().map(|c| c.0).collect(),
                signing,
            )))
        };
        let default = certified(self.chain, self.key)?;
        let mut by_name = HashMap::new();
        for (name, chain, key) in self.sni {
            by_name.insert(name, certified(chain, key)?);
        }
        let mut cfg = b.with_cert_resolver(Arc::new(Resolver { default, by_name }));
        cfg.alpn_protocols = self.alpn;
        cfg.session_storage = if self.session_cache == 0 {
            Arc::new(rustls::server::NoServerSessionStorage {})
        } else {
            rustls::server::ServerSessionMemoryCache::new(self.session_cache)
        };
        if self.tickets {
            cfg.ticketer = rustls::crypto::ring::Ticketer::new()
                .map_err(|e| Error::wrap("session tickets", e))?;
        }
        Ok(ServerConfig {
            inner: Arc::new(cfg),
        })
    }
}

/// The default chain, or the one registered for the SNI name.
#[derive(Debug)]
struct Resolver {
    default: Arc<CertifiedKey>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let named = hello
            .server_name()
            .and_then(|n| self.by_name.get(&n.to_ascii_lowercase()));
        Some(named.unwrap_or(&self.default).clone())
    }
}

// ---- client ----

/// A TLS client configuration: what [`Tls::client`](crate::Tls::client), the HTTP, HTTP/2,
/// WebSocket and QUIC clients take. Cheap to clone. Build one with [`ClientConfig::builder`].
#[derive(Clone)]
pub struct ClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("alpn", &self.inner.alpn_protocols)
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
        }
    }

    /// The ALPN protocols asked for, in preference order.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn_protocols
    }

    /// Wraps a rustls configuration. **Unstable** (cargo feature `unstable`, outside the semver
    /// promise).
    #[cfg(feature = "unstable")]
    pub fn from_rustls(config: impl Into<Arc<rustls::ClientConfig>>) -> ClientConfig {
        ClientConfig {
            inner: config.into(),
        }
    }

    /// The rustls configuration. **Unstable** (cargo feature `unstable`).
    #[cfg(feature = "unstable")]
    pub fn as_rustls(&self) -> &Arc<rustls::ClientConfig> {
        &self.inner
    }

    /// For the other crates of this workspace (QUIC); not a public API.
    #[doc(hidden)]
    pub fn __rustls(&self) -> &Arc<rustls::ClientConfig> {
        &self.inner
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
            .finish()
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

    /// Accepts **any** server certificate, without verifying it: for tests and interop runs
    /// against self-signed servers only, never in production.
    pub fn insecure_skip_verify(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ClientConfig, Error> {
        let p = provider();
        let b = rustls::ClientConfig::builder_with_provider(p.clone())
            .with_protocol_versions(versions(self.tls13_only))
            .map_err(|e| Error::wrap("protocol versions", e))?;
        let b = if self.insecure {
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        } else {
            b.with_root_certificates(self.roots.0)
        };
        let mut cfg = match self.client_cert {
            None => b.with_no_client_auth(),
            Some((chain, key)) => b
                .with_client_auth_cert(chain.into_iter().map(|c| c.0).collect(), key.0)
                .map_err(|e| Error::wrap("client certificate", e))?,
        };
        cfg.alpn_protocols = self.alpn;
        cfg.enable_sni = self.sni;
        if !self.resumption {
            cfg.resumption = rustls::client::Resumption::disabled();
        }
        Ok(ClientConfig {
            inner: Arc::new(cfg),
        })
    }
}

/// Accepts every server certificate (signatures are still checked).
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
