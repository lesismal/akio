//! Server certificates chosen per handshake (ADR-098): a [`CertResolver`] on the server
//! configuration is asked for the certificate of each full handshake and answers through a
//! [`CertDone`], right away (a certificate in memory) or later from any thread (one being
//! issued), the handshake waiting without holding its I/O thread. [`CertStore`] is a ready-made
//! resolver whose certificates are replaced while serving.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{
    Certificate, Error, NotUnwindSafe, PrivateKey, certified_key, check_ocsp_response,
};
use crate::proto::alert::Alert;
use crate::proto::common::CertKey;
use crate::replay::Slot;

/// Chooses the certificate of a server handshake (ADR-098); set with
/// [`ServerConfigBuilder::cert_resolver`](crate::ServerConfigBuilder::cert_resolver) or
/// [`ServerConfig::builder_with_resolver`](crate::ServerConfig::builder_with_resolver).
///
/// Called on the connection's I/O thread for every full handshake (not for a resumed one, which
/// sends no certificate), once the ClientHello has been checked; with a HelloRetryRequest, for
/// the second ClientHello. **It must not block**: answer `done` before returning when the
/// certificate is at hand (the handshake goes on in the same call, nothing is suspended), or
/// keep `done` and answer it later from any thread (an ACME order, a remote key store): the
/// handshake waits without holding the thread, and resumes on its I/O thread when answered.
///
/// A handshake waits at most
/// [`cert_resolver_timeout`](crate::ServerConfigBuilder::cert_resolver_timeout) (10 s by
/// default; then it fails with `internal_error`), and at most
/// [`max_pending_cert_resolutions`](crate::ServerConfigBuilder::max_pending_cert_resolutions)
/// handshakes of a configuration wait at once (1024 by default; beyond that, a handshake the
/// resolver does not answer inside the call fails, its `done` abandoned).
///
/// The ClientHello is not authenticated: a resolver doing work per name (issuing a certificate)
/// must bound it itself (an allow-list, a rate limit).
pub trait CertResolver: Send + Sync {
    /// Chooses the certificate for `hello`, answering through `done` now or later.
    fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone);
}

/// What a [`CertResolver`] sees of the ClientHello.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloInfo<'a> {
    pub(crate) server_name: Option<&'a str>,
    pub(crate) alpn: &'a [&'a [u8]],
    pub(crate) signature_schemes: &'a [u16],
    pub(crate) cipher_suites: &'a [u16],
    pub(crate) tls13: bool,
    pub(crate) quic: bool,
}

impl<'a> ClientHelloInfo<'a> {
    /// The SNI host name (lowercase, no trailing dot), if the client sent one.
    pub fn server_name(&self) -> Option<&'a str> {
        self.server_name
    }

    /// The ALPN protocols the client offered, in its order (empty if it sent none).
    pub fn alpn(&self) -> &'a [&'a [u8]] {
        self.alpn
    }

    /// The signature schemes the client accepts (IANA codes, its order); for a TLS 1.2 client
    /// that sent no signature_algorithms, the RFC 5246 defaults the server assumes.
    pub fn signature_schemes(&self) -> &'a [u16] {
        self.signature_schemes
    }

    /// The cipher suites the client offered (IANA codes, its order).
    pub fn cipher_suites(&self) -> &'a [u16] {
        self.cipher_suites
    }

    /// The version being negotiated, as [`TlsInfo::version`](crate::TlsInfo::version) names it:
    /// `"TLSv1_3"` or `"TLSv1_2"`.
    pub fn version(&self) -> &'static str {
        if self.tls13 { "TLSv1_3" } else { "TLSv1_2" }
    }

    /// The handshake is QUIC's (RFC 9001).
    pub fn is_quic(&self) -> bool {
        self.quic
    }
}

/// A certificate chain and its private key, checked to match, for a [`CertResolver`] to serve.
/// Cheap to clone (shared); the compressed certificate messages (RFC 8879) it computes are kept
/// with it, so reuse one value for the handshakes that serve the same chain.
#[derive(Clone)]
pub struct CertifiedKey(pub(crate) Arc<CertKey>, NotUnwindSafe);

impl fmt::Debug for CertifiedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CertifiedKey").field(&self.0).finish()
    }
}

impl CertifiedKey {
    /// `chain` (leaf first) and `key`; fails if the chain is empty, the leaf does not parse or
    /// the key is not the leaf's.
    pub fn new(chain: Vec<Certificate>, key: PrivateKey) -> Result<CertifiedKey, Error> {
        Ok(CertifiedKey(
            Arc::new(certified_key(&chain, &key)?),
            std::marker::PhantomData,
        ))
    }

    /// From PEM: the chain (leaf first) and the key (PKCS#8, PKCS#1 or SEC1).
    pub fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, Error> {
        CertifiedKey::new(
            Certificate::from_pem(chain_pem)?,
            PrivateKey::from_pem(key_pem)?,
        )
    }

    /// Staples `der`, an OCSP response for the leaf, for clients asking for one (as
    /// [`ServerConfigBuilder::ocsp_response`](crate::ServerConfigBuilder::ocsp_response)).
    pub fn with_ocsp_response(self, der: impl Into<Vec<u8>>) -> Result<CertifiedKey, Error> {
        let der = der.into();
        check_ocsp_response(&der)?;
        let mut ck = CertKey::new(self.0.chain.clone(), self.0.key.clone());
        ck.ocsp = Some(der);
        Ok(CertifiedKey(Arc::new(ck), std::marker::PhantomData))
    }

    /// The chain's certificates, DER, leaf first.
    pub fn chain_der(&self) -> impl Iterator<Item = &[u8]> {
        self.0.chain.iter().map(Vec::as_slice)
    }
}

/// A fatal alert a [`CertResolver`] ends the handshake with ([`CertDone::fail`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertAlert {
    /// `handshake_failure` (40): no acceptable certificate.
    HandshakeFailure,
    /// `unrecognized_name` (112): no certificate for this name (RFC 6066 section 3).
    UnrecognizedName,
    /// `access_denied` (49): the name is not served to this client.
    AccessDenied,
    /// `internal_error` (80): the resolver failed (an issuance error).
    InternalError,
}

impl CertAlert {
    fn alert(self) -> Alert {
        match self {
            CertAlert::HandshakeFailure => Alert::HandshakeFailure,
            CertAlert::UnrecognizedName => Alert::UnrecognizedName,
            CertAlert::AccessDenied => Alert::AccessDenied,
            CertAlert::InternalError => Alert::InternalError,
        }
    }
}

/// What a resolver answered.
#[derive(Clone)]
pub(crate) enum CertAnswer {
    Key(Arc<CertKey>),
    Default,
    Alert(Alert),
    /// No answer within the timeout.
    TimedOut,
    /// The [`CertDone`] was dropped unanswered.
    Dropped,
}

/// The answer of one [`CertResolver::resolve`] call: `Send`, answered once from any thread.
/// Dropping it unanswered fails the handshake (`internal_error`).
pub struct CertDone {
    slot: Arc<Slot<CertAnswer>>,
    _reserved: NotUnwindSafe,
}

impl fmt::Debug for CertDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertDone")
            .field("abandoned", &self.is_abandoned())
            .finish_non_exhaustive()
    }
}

impl CertDone {
    pub(crate) fn new(slot: Arc<Slot<CertAnswer>>) -> CertDone {
        CertDone {
            slot,
            _reserved: std::marker::PhantomData,
        }
    }

    /// Serves `key`. The handshake goes on (on its I/O thread if it was waiting).
    pub fn complete(self, key: CertifiedKey) {
        self.slot.set(CertAnswer::Key(key.0));
    }

    /// Serves what the configuration serves without a resolver: the
    /// [`sni_cert`](crate::ServerConfigBuilder::sni_cert) chain for the name, else the default
    /// chain; a configuration made with
    /// [`builder_with_resolver`](crate::ServerConfig::builder_with_resolver) and no `sni_cert`
    /// for the name has none and ends the handshake with `unrecognized_name`.
    pub fn use_default(self) {
        self.slot.set(CertAnswer::Default);
    }

    /// Ends the handshake with `alert`.
    pub fn fail(self, alert: CertAlert) {
        self.slot.set(CertAnswer::Alert(alert.alert()));
    }

    /// The handshake no longer waits for this answer: its connection closed or failed, or the
    /// [`cert_resolver_timeout`](crate::ServerConfigBuilder::cert_resolver_timeout) passed. A
    /// resolver may skip work nobody waits for (answering is still harmless).
    pub fn is_abandoned(&self) -> bool {
        Arc::strong_count(&self.slot) == 1 || self.slot.result().is_some()
    }
}

impl Drop for CertDone {
    fn drop(&mut self) {
        // Unanswered: fail (does nothing after an answer).
        self.slot.set(CertAnswer::Dropped);
    }
}

/// A server configuration's resolver and its limits.
pub(crate) struct ResolverSettings {
    pub(crate) resolver: Arc<dyn CertResolver>,
    pub(crate) timeout: Duration,
    pub(crate) max_pending: usize,
    /// Handshakes waiting for an answer now.
    pub(crate) pending: Arc<AtomicUsize>,
}

impl fmt::Debug for ResolverSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverSettings")
            .field("timeout", &self.timeout)
            .field("max_pending", &self.max_pending)
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// One waiting handshake counted in [`ResolverSettings::pending`]; uncounted when dropped.
pub(crate) struct PendingGuard(Arc<AtomicUsize>);

impl PendingGuard {
    /// Counts one more waiting handshake, unless `max` already wait.
    pub(crate) fn acquire(pending: &Arc<AtomicUsize>, max: usize) -> Option<PendingGuard> {
        if pending.fetch_add(1, Ordering::AcqRel) >= max {
            pending.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(PendingGuard(pending.clone()))
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Certificates by host name, replaced at any time from any thread: a [`CertResolver`] that
/// answers inline (nothing suspends). Clones share the same certificates.
///
/// A name is looked up exactly, then as a wildcard for its first label (`a.example.com` matches
/// `*.example.com`, not `a.b.example.com`), then the store's default; with none of these, the
/// handshake gets the configuration's own certificate ([`CertDone::use_default`]). Each full
/// handshake takes a read lock and clones an `Arc`.
///
/// ```no_run
/// use std::sync::Arc;
/// use akio_tls::{CertStore, CertifiedKey, ServerConfig};
/// let store = CertStore::new();
/// let pem = |f: &str| std::fs::read(f).unwrap();
/// let key = CertifiedKey::from_pem(&pem("a.pem"), &pem("a.key")).unwrap();
/// store.insert("a.example.com", key);
/// let cfg = ServerConfig::builder_with_resolver(Arc::new(store.clone())).build().unwrap();
/// // Later, renewed: handshakes from now on serve the new certificate.
/// # let renewed = CertifiedKey::from_pem(b"", b"").unwrap();
/// store.insert("a.example.com", renewed);
/// # let _ = cfg;
/// ```
#[derive(Clone, Default)]
pub struct CertStore(Arc<RwLock<StoreInner>>, NotUnwindSafe);

#[derive(Default)]
struct StoreInner {
    names: HashMap<String, CertifiedKey>,
    default: Option<CertifiedKey>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("names", &self.len())
            .finish_non_exhaustive()
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl CertStore {
    /// An empty store.
    pub fn new() -> CertStore {
        CertStore::default()
    }

    /// Serves `key` for `name` (a host name, or `*.` and a domain for its subdomains one label
    /// deep), replacing and returning what it served before.
    pub fn insert(&self, name: &str, key: CertifiedKey) -> Option<CertifiedKey> {
        let mut g = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.names.insert(normalize(name), key)
    }

    /// Stops serving `name` (as given to [`insert`](Self::insert)), returning what it served.
    pub fn remove(&self, name: &str) -> Option<CertifiedKey> {
        let mut g = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.names.remove(&normalize(name))
    }

    /// What names that match nothing get (`None`: the configuration's own certificate).
    pub fn set_default(&self, key: Option<CertifiedKey>) {
        let mut g = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.default = key;
    }

    /// What a handshake for `server_name` gets: the exact name, else the wildcard covering it,
    /// else the default.
    pub fn get(&self, server_name: Option<&str>) -> Option<CertifiedKey> {
        let g = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        server_name
            .and_then(|n| {
                if let Some(k) = g.names.get(n) {
                    return Some(k.clone());
                }
                let (_, parent) = n.split_once('.')?;
                if parent.is_empty() {
                    return None;
                }
                g.names.get(&format!("*.{parent}")).cloned()
            })
            .or_else(|| g.default.clone())
    }

    /// Names served (wildcards included, the default not).
    pub fn len(&self) -> usize {
        self.0.read().map_or(0, |g| g.names.len())
    }

    /// No names served.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CertResolver for CertStore {
    fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone) {
        match self.get(hello.server_name()) {
            Some(k) => done.complete(k),
            None => done.use_default(),
        }
    }
}
