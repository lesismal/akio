//! Configuration: identity, peer verification, SRTP profiles, timers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use only_crypto::hash::{Sha1, Sha256, Sha384, Sha512};
use only_crypto::pkey::PrivateKey;
use only_x509::{Certificate, CertificateParams};

use crate::session::{Psk, SessionCache, TicketKey};
use crate::{CipherSuite, Error};

/// A DTLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Version {
    /// DTLS 1.2 (RFC 6347).
    Dtls12,
    /// DTLS 1.3 (RFC 9147).
    Dtls13,
}

impl Version {
    pub(crate) fn wire(self) -> u16 {
        match self {
            Version::Dtls12 => crate::record::DTLS12,
            Version::Dtls13 => crate::record::DTLS13,
        }
    }

    pub(crate) fn from_wire(v: u16) -> Option<Version> {
        match v {
            crate::record::DTLS12 => Some(Version::Dtls12),
            crate::record::DTLS13 => Some(Version::Dtls13),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Version::Dtls12 => "DTLS 1.2",
            Version::Dtls13 => "DTLS 1.3",
        })
    }
}

/// Session-ID cache entries a DTLS 1.2 server keeps with resumption on.
const SESSION_CACHE: usize = 1024;
/// Longest ticket lifetime (RFC 8446 §4.6.1).
const MAX_TICKET_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);

/// A certificate (DER) with its private key: what this endpoint authenticates with.
#[derive(Clone)]
pub struct Identity {
    chain: Vec<Vec<u8>>,
    key: PrivateKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint().to_string())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// An identity from a DER certificate chain (leaf first) and its private key. Fails if the
    /// leaf does not parse or its public key is not the key's.
    pub fn new(chain: Vec<Vec<u8>>, key: PrivateKey) -> Result<Identity, Error> {
        let leaf = chain
            .first()
            .ok_or(Error::Config("empty certificate chain"))?;
        let cert = Certificate::from_der(leaf.clone())
            .map_err(|_| Error::Config("certificate does not parse"))?;
        let public = cert
            .public_key()
            .map_err(|_| Error::Config("unsupported certificate key"))?;
        if public != key.public_key() {
            return Err(Error::Config("private key does not match the certificate"));
        }
        Ok(Identity { chain, key })
    }

    /// An identity from PEM: the certificate chain and a PKCS#8, SEC1 or PKCS#1 private key.
    pub fn from_pem(certificates: &[u8], key: &[u8]) -> Result<Identity, Error> {
        let chain = Certificate::from_pem(certificates)
            .map_err(|_| Error::Config("certificate PEM does not parse"))?
            .into_iter()
            .map(|c| c.as_der().to_vec())
            .collect();
        let key = PrivateKey::from_pem(key).map_err(|_| Error::Config("key PEM does not parse"))?;
        Identity::new(chain, key)
    }

    /// A fresh self-signed ECDSA P-256 certificate (common name `WebRTC`, valid for a year from
    /// one hour ago), as WebRTC endpoints use.
    pub fn generate_self_signed() -> Result<Identity, Error> {
        let key = PrivateKey::P256(only_crypto::p256::SecretKey::generate()?);
        let mut params = CertificateParams::new(["WebRTC"]);
        params.subject_alt_names.clear();
        let cert = params
            .self_signed(&key)
            .map_err(|_| Error::Config("certificate generation failed"))?;
        Ok(Identity {
            chain: vec![cert.as_der().to_vec()],
            key,
        })
    }

    /// The leaf certificate (DER).
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    /// The certificate chain (DER, leaf first).
    #[must_use]
    pub fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// The private key.
    #[must_use]
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// The SHA-256 fingerprint of the leaf certificate (what goes into the SDP).
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(FingerprintAlgorithm::Sha256, self.certificate())
    }
}

/// The hash function of a certificate [`Fingerprint`] (RFC 8122 names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FingerprintAlgorithm {
    /// `sha-1`.
    Sha1,
    /// `sha-256`.
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl FingerprintAlgorithm {
    /// The RFC 8122 / SDP name (`sha-256`, ...).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FingerprintAlgorithm::Sha1 => "sha-1",
            FingerprintAlgorithm::Sha256 => "sha-256",
            FingerprintAlgorithm::Sha384 => "sha-384",
            FingerprintAlgorithm::Sha512 => "sha-512",
        }
    }

    fn from_name(s: &str) -> Option<FingerprintAlgorithm> {
        [
            FingerprintAlgorithm::Sha1,
            FingerprintAlgorithm::Sha256,
            FingerprintAlgorithm::Sha384,
            FingerprintAlgorithm::Sha512,
        ]
        .into_iter()
        .find(|a| a.name().eq_ignore_ascii_case(s))
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            FingerprintAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            FingerprintAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            FingerprintAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            FingerprintAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A certificate fingerprint (RFC 8122 `a=fingerprint`): a hash of the DER certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    algorithm: FingerprintAlgorithm,
    value: Vec<u8>,
}

impl Fingerprint {
    /// The fingerprint of a DER certificate.
    #[must_use]
    pub fn of(algorithm: FingerprintAlgorithm, certificate: &[u8]) -> Fingerprint {
        Fingerprint {
            algorithm,
            value: algorithm.digest(certificate),
        }
    }

    /// Parses the SDP form `sha-256 AB:CD:...` (algorithm name case-insensitive, hex either
    /// case).
    pub fn parse(s: &str) -> Result<Fingerprint, Error> {
        let bad = Error::Config("malformed fingerprint");
        let (alg, hex) = s.trim().split_once(' ').ok_or_else(|| bad.clone())?;
        let algorithm = FingerprintAlgorithm::from_name(alg).ok_or_else(|| bad.clone())?;
        let value = hex
            .trim()
            .split(':')
            .map(|b| {
                if b.len() == 2 {
                    u8::from_str_radix(b, 16).ok()
                } else {
                    None
                }
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(|| bad.clone())?;
        if value.len() != algorithm.digest(b"").len() {
            return Err(bad);
        }
        Ok(Fingerprint { algorithm, value })
    }

    /// The hash function.
    #[must_use]
    pub fn algorithm(&self) -> FingerprintAlgorithm {
        self.algorithm
    }

    /// The hash value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Whether `certificate` (DER) has this fingerprint (constant-time comparison).
    #[must_use]
    pub fn matches(&self, certificate: &[u8]) -> bool {
        only_crypto::ct_eq(&self.algorithm.digest(certificate), &self.value)
    }
}

impl fmt::Display for Fingerprint {
    /// The SDP form: `sha-256 AB:CD:...` (upper-case hex).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.algorithm.name())?;
        for (i, b) in self.value.iter().enumerate() {
            write!(f, "{}{b:02X}", if i == 0 { ' ' } else { ':' })?;
        }
        Ok(())
    }
}

/// An SRTP protection profile negotiated with `use_srtp` (RFC 5764, RFC 7714).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SrtpProfile {
    /// `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001).
    Aes128CmHmacSha1_80,
    /// `SRTP_AES128_CM_HMAC_SHA1_32` (0x0002).
    Aes128CmHmacSha1_32,
    /// `SRTP_AEAD_AES_128_GCM` (0x0007).
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM` (0x0008).
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// Every profile, in the default preference order (AEAD first).
    pub const ALL: [SrtpProfile; 4] = [
        SrtpProfile::AeadAes128Gcm,
        SrtpProfile::AeadAes256Gcm,
        SrtpProfile::Aes128CmHmacSha1_80,
        SrtpProfile::Aes128CmHmacSha1_32,
    ];

    /// The IANA code point.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            SrtpProfile::Aes128CmHmacSha1_80 => 0x0001,
            SrtpProfile::Aes128CmHmacSha1_32 => 0x0002,
            SrtpProfile::AeadAes128Gcm => 0x0007,
            SrtpProfile::AeadAes256Gcm => 0x0008,
        }
    }

    /// The profile for a code point, if supported.
    #[must_use]
    pub fn from_id(id: u16) -> Option<SrtpProfile> {
        SrtpProfile::ALL.into_iter().find(|p| p.id() == id)
    }

    /// The master key length in bytes.
    #[must_use]
    pub fn master_key_len(self) -> usize {
        match self {
            SrtpProfile::AeadAes256Gcm => 32,
            _ => 16,
        }
    }

    /// The master salt length in bytes (14 for AES-CM, 12 for AEAD-GCM).
    #[must_use]
    pub fn master_salt_len(self) -> usize {
        match self {
            SrtpProfile::Aes128CmHmacSha1_80 | SrtpProfile::Aes128CmHmacSha1_32 => 14,
            _ => 12,
        }
    }
}

/// SRTP master keys and salts exported with the `EXTRACTOR-dtls_srtp` label (RFC 5764 §4.2).
#[derive(Clone, PartialEq, Eq)]
pub struct SrtpKeys {
    /// The negotiated profile.
    pub profile: SrtpProfile,
    /// The client's master key (protects what the DTLS client sends).
    pub client_master_key: Vec<u8>,
    /// The client's master salt.
    pub client_master_salt: Vec<u8>,
    /// The server's master key (protects what the DTLS server sends).
    pub server_master_key: Vec<u8>,
    /// The server's master salt.
    pub server_master_salt: Vec<u8>,
}

impl fmt::Debug for SrtpKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpKeys")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl SrtpKeys {
    /// Splits exported keying material `client_key | server_key | client_salt | server_salt`.
    pub(crate) fn from_material(profile: SrtpProfile, m: &[u8]) -> SrtpKeys {
        let (k, s) = (profile.master_key_len(), profile.master_salt_len());
        SrtpKeys {
            profile,
            client_master_key: m[..k].to_vec(),
            server_master_key: m[k..2 * k].to_vec(),
            client_master_salt: m[2 * k..2 * k + s].to_vec(),
            server_master_salt: m[2 * k + s..2 * (k + s)].to_vec(),
        }
    }

    /// The (key, salt) this endpoint protects its outgoing SRTP with.
    #[must_use]
    pub fn local(&self, role: crate::Role) -> (&[u8], &[u8]) {
        match role {
            crate::Role::Client => (&self.client_master_key, &self.client_master_salt),
            crate::Role::Server => (&self.server_master_key, &self.server_master_salt),
        }
    }

    /// The (key, salt) the peer protects its SRTP with.
    #[must_use]
    pub fn remote(&self, role: crate::Role) -> (&[u8], &[u8]) {
        match role {
            crate::Role::Client => self.local(crate::Role::Server),
            crate::Role::Server => self.local(crate::Role::Client),
        }
    }
}

/// A custom certificate check: receives the peer's DER chain (leaf first, never empty) and
/// returns why it is refused.
pub type VerifyFn = dyn Fn(&[Vec<u8>]) -> Result<(), String> + Send + Sync;

/// How the peer's certificate is authenticated. There is no CA path validation by default:
/// WebRTC peers use self-signed certificates bound to the session by the SDP fingerprint. The
/// peer always has to prove possession of the certificate's key (ServerKeyExchange /
/// CertificateVerify signatures).
#[derive(Clone)]
#[non_exhaustive]
pub enum PeerVerifier {
    /// Accept a certificate whose fingerprint equals one of these (the SDP `a=fingerprint`
    /// lines).
    Fingerprints(Vec<Fingerprint>),
    /// Accept what the function accepts (for example `only_x509::Verifier` chain validation).
    Custom(Arc<VerifyFn>),
    /// Accept any certificate. The caller must check
    /// [`HandshakeInfo::peer_fingerprint`](crate::HandshakeInfo::peer_fingerprint) before
    /// trusting the connection (for example when the remote SDP arrives after the handshake).
    AcceptAny,
}

impl fmt::Debug for PeerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerVerifier::Fingerprints(v) => f.debug_tuple("Fingerprints").field(v).finish(),
            PeerVerifier::Custom(_) => f.write_str("Custom(..)"),
            PeerVerifier::AcceptAny => f.write_str("AcceptAny"),
        }
    }
}

impl PeerVerifier {
    pub(crate) fn verify(&self, chain: &[Vec<u8>]) -> Result<(), Error> {
        match self {
            PeerVerifier::AcceptAny => Ok(()),
            PeerVerifier::Fingerprints(fps) => {
                if fps.iter().any(|f| f.matches(&chain[0])) {
                    Ok(())
                } else {
                    Err(Error::Certificate("fingerprint mismatch".into()))
                }
            }
            PeerVerifier::Custom(f) => f(chain).map_err(Error::Certificate),
        }
    }
}

/// Endpoint configuration, shared by any number of connections (`Arc<Config>`).
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) identity: Option<Identity>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) srtp_profiles: Vec<SrtpProfile>,
    pub(crate) srtp_mki: Vec<u8>,
    pub(crate) srtp_accept_mki: bool,
    pub(crate) verifier: PeerVerifier,
    pub(crate) require_client_certificate: bool,
    pub(crate) require_extended_master_secret: bool,
    pub(crate) hello_verify: bool,
    pub(crate) mtu: usize,
    pub(crate) initial_retransmit: Duration,
    pub(crate) max_retransmit: Duration,
    pub(crate) handshake_timeout: Duration,
    pub(crate) versions: Vec<Version>,
    pub(crate) psks: Vec<Psk>,
    pub(crate) resumption: bool,
    pub(crate) ticket_key: Option<TicketKey>,
    pub(crate) session_cache: Option<Arc<SessionCache>>,
    pub(crate) ticket_lifetime: Duration,
    pub(crate) connection_id: Option<u8>,
}

impl Config {
    /// A configuration authenticating with `identity` (required for servers without a
    /// [`Psk`]; clients send it when the server asks). Defaults: DTLS 1.2 only, every
    /// [`CipherSuite`] (DTLS 1.3 suites first; a server uses those that fit its key, PSK
    /// suites only with a PSK), no SRTP, [`PeerVerifier::AcceptAny`], client certificates
    /// required, extended master secret required, HelloVerifyRequest / HelloRetryRequest
    /// cookies on, MTU 1200, retransmission 1 s doubling to 60 s, handshake timeout 30 s, no
    /// PSK, no session resumption, no connection IDs.
    #[must_use]
    pub fn new(identity: Identity) -> Config {
        let mut c = Config::without_identity();
        c.identity = Some(identity);
        c
    }

    /// A client configuration without a certificate (servers asking for one get an empty
    /// Certificate message).
    #[must_use]
    pub fn without_identity() -> Config {
        Config {
            identity: None,
            cipher_suites: CipherSuite::TLS13
                .into_iter()
                .chain(CipherSuite::PSK)
                .chain(CipherSuite::ALL)
                .collect(),
            srtp_profiles: Vec::new(),
            srtp_mki: Vec::new(),
            srtp_accept_mki: false,
            verifier: PeerVerifier::AcceptAny,
            require_client_certificate: true,
            require_extended_master_secret: true,
            hello_verify: true,
            mtu: 1200,
            initial_retransmit: Duration::from_secs(1),
            max_retransmit: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(30),
            versions: vec![Version::Dtls12],
            psks: Vec::new(),
            resumption: false,
            ticket_key: None,
            session_cache: None,
            ticket_lifetime: Duration::from_secs(2 * 3600),
            connection_id: None,
        }
    }

    /// The WebRTC profile (RFC 8827): DTLS 1.2, `identity`, the SRTP profiles
    /// AEAD-AES-128-GCM, AEAD-AES-256-GCM and AES128-CM-HMAC-SHA1-80, mutual authentication by
    /// `verifier`, no HelloVerifyRequest (ICE already proved return routability). DTLS 1.3
    /// stays off here: browsers and pion negotiate DTLS 1.2 for WebRTC (see ADR-021).
    #[must_use]
    pub fn webrtc(identity: Identity, verifier: PeerVerifier) -> Config {
        Config::new(identity)
            .with_srtp_profiles(vec![
                SrtpProfile::AeadAes128Gcm,
                SrtpProfile::AeadAes256Gcm,
                SrtpProfile::Aes128CmHmacSha1_80,
            ])
            .with_verifier(verifier)
            .with_hello_verify(false)
    }

    /// The cipher suites, in preference order (a server picks its first that the client
    /// offers and that fits its key).
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<CipherSuite>) -> Config {
        self.cipher_suites = suites;
        self
    }

    /// The SRTP profiles offered (client) or accepted (server), in preference order; empty
    /// disables `use_srtp`.
    #[must_use]
    pub fn with_srtp_profiles(mut self, profiles: Vec<SrtpProfile>) -> Config {
        self.srtp_profiles = profiles;
        self
    }

    /// Client: offers to put this SRTP Master Key Identifier in every SRTP and SRTCP packet
    /// protected with the keys of this handshake (`srtp_mki` of `use_srtp`, RFC 5764
    /// §4.1.3); empty (the default) offers none. Pick a value distinct from the previous
    /// handshake's, so packets under old and new keys can be told apart while re-keying. Whether
    /// the server agreed is in [`HandshakeInfo::srtp_mki`](crate::HandshakeInfo::srtp_mki).
    ///
    /// # Panics
    ///
    /// When `mki` is longer than 255 bytes.
    #[must_use]
    pub fn with_srtp_mki(mut self, mki: Vec<u8>) -> Config {
        assert!(mki.len() <= 255, "srtp_mki is at most 255 bytes");
        self.srtp_mki = mki;
        self
    }

    /// Server: agrees to a client's SRTP MKI by echoing it in `use_srtp` (default off: the
    /// server answers with an empty MKI, and SRTP runs without one). Turn it on only when the
    /// SRTP layer builds its contexts with [`HandshakeInfo::srtp_mki`](crate::HandshakeInfo::srtp_mki).
    #[must_use]
    pub fn with_srtp_accept_mki(mut self, on: bool) -> Config {
        self.srtp_accept_mki = on;
        self
    }

    /// How the peer's certificate is checked.
    #[must_use]
    pub fn with_verifier(mut self, verifier: PeerVerifier) -> Config {
        self.verifier = verifier;
        self
    }

    /// Server: request a client certificate and fail the handshake without one (default on).
    #[must_use]
    pub fn with_require_client_certificate(mut self, on: bool) -> Config {
        self.require_client_certificate = on;
        self
    }

    /// Refuse peers without the extended master secret (RFC 7627; default on).
    #[must_use]
    pub fn with_require_extended_master_secret(mut self, on: bool) -> Config {
        self.require_extended_master_secret = on;
        self
    }

    /// Server: answer a ClientHello without a valid cookie with a stateless HelloVerifyRequest
    /// (RFC 6347 §4.2.1; default on).
    #[must_use]
    pub fn with_hello_verify(mut self, on: bool) -> Config {
        self.hello_verify = on;
        self
    }

    /// The largest datagram sent during the handshake (path MTU minus IP/UDP headers; at least
    /// 256). Handshake messages are fragmented to fit.
    #[must_use]
    pub fn with_mtu(mut self, mtu: usize) -> Config {
        self.mtu = mtu.max(256);
        self
    }

    /// The first retransmission timeout and its cap; it doubles after each retransmission
    /// (RFC 6347 §4.2.4.1).
    #[must_use]
    pub fn with_retransmit(mut self, initial: Duration, max: Duration) -> Config {
        self.initial_retransmit = initial;
        self.max_retransmit = max.max(initial);
        self
    }

    /// The time from the start until the handshake must complete.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Config {
        self.handshake_timeout = timeout;
        self
    }

    /// The protocol versions this endpoint speaks. A client offering both starts with a
    /// DTLS 1.3 ClientHello that DTLS 1.2 servers understand (and falls back, with the
    /// RFC 8446 downgrade check); a server picks the highest both support. Default: DTLS 1.2
    /// only.
    #[must_use]
    pub fn with_versions(mut self, versions: Vec<Version>) -> Config {
        self.versions = versions;
        self
    }

    /// External pre-shared keys. A client offers the first (DTLS 1.2 PSK / ECDHE-PSK suites,
    /// DTLS 1.3 `psk_dhe_ke`); a server accepts any of them, and needs no certificate when it
    /// only does PSK.
    #[must_use]
    pub fn with_psks(mut self, psks: Vec<Psk>) -> Config {
        self.psks = psks;
        self
    }

    /// Session resumption (default off). Client: asks for DTLS 1.2 tickets and reports
    /// resumable sessions as [`Event::NewSession`](crate::Event::NewSession). Server: issues
    /// DTLS 1.2 tickets (or session IDs, in a bounded cache of 1024) and one DTLS 1.3
    /// NewSessionTicket per handshake, sealed with a random [`TicketKey`] unless
    /// [`with_ticket_key`](Config::with_ticket_key) sets one.
    #[must_use]
    pub fn with_session_resumption(mut self, on: bool) -> Config {
        self.resumption = on;
        if on {
            if self.ticket_key.is_none() {
                self.ticket_key = TicketKey::generate().ok();
            }
            if self.session_cache.is_none() {
                self.session_cache = Some(Arc::new(SessionCache::new(SESSION_CACHE)));
            }
        }
        self
    }

    /// The key that seals session tickets (share it between servers that should resume each
    /// other's sessions).
    #[must_use]
    pub fn with_ticket_key(mut self, key: TicketKey) -> Config {
        self.ticket_key = Some(key);
        self
    }

    /// How long a session can be resumed (default 2 hours, at most 7 days).
    #[must_use]
    pub fn with_ticket_lifetime(mut self, lifetime: Duration) -> Config {
        self.ticket_lifetime = lifetime.min(MAX_TICKET_LIFETIME);
        self
    }

    /// Connection IDs (RFC 9146 for DTLS 1.2, RFC 9147 §9 for DTLS 1.3; default off): each
    /// connection asks the peer to put a random CID of `len` bytes (0: none, but send one if
    /// the peer asks) in the records it sends, so a listener can route them by
    /// [`connection_id`](crate::connection_id) when the peer's address changes.
    #[must_use]
    pub fn with_connection_id(mut self, len: Option<u8>) -> Config {
        self.connection_id = len;
        self
    }

    /// The identity, if any.
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// The handshake timeout.
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format() {
        let f = Fingerprint::of(FingerprintAlgorithm::Sha256, b"abc");
        let s = f.to_string();
        assert!(s.starts_with("sha-256 BA:78:16:BF:"), "{s}");
        assert_eq!(Fingerprint::parse(&s).unwrap(), f);
        assert_eq!(Fingerprint::parse(&s.to_lowercase()).unwrap(), f);
        assert!(f.matches(b"abc"));
        assert!(!f.matches(b"abd"));
        assert!(Fingerprint::parse("sha-256 AB").is_err());
        assert!(Fingerprint::parse("md5 AB:CD").is_err());
        assert!(Fingerprint::parse("sha-256").is_err());
        let f1 = Fingerprint::of(FingerprintAlgorithm::Sha1, b"abc");
        assert_eq!(Fingerprint::parse(&f1.to_string()).unwrap(), f1);
    }

    #[test]
    fn identity() {
        let id = Identity::generate_self_signed().unwrap();
        let again = Identity::new(id.chain().to_vec(), id.private_key().clone()).unwrap();
        assert_eq!(again.fingerprint(), id.fingerprint());
        let other = Identity::generate_self_signed().unwrap();
        assert!(Identity::new(id.chain().to_vec(), other.private_key().clone()).is_err());
        assert!(Identity::new(Vec::new(), other.private_key().clone()).is_err());
        let cert = Certificate::from_der(id.certificate().to_vec()).unwrap();
        let pem = Identity::from_pem(
            cert.to_pem().as_bytes(),
            id.private_key().to_pkcs8_pem().as_bytes(),
        )
        .unwrap();
        assert_eq!(pem.fingerprint(), id.fingerprint());
        let c = Config::new(id);
        assert_eq!(c.cipher_suites.len(), 15);
        assert_eq!(c.versions, vec![Version::Dtls12]);
    }

    #[test]
    fn srtp_split() {
        let p = SrtpProfile::Aes128CmHmacSha1_80;
        let m: Vec<u8> = (0..60).collect();
        let k = SrtpKeys::from_material(p, &m);
        assert_eq!(k.client_master_key, (0..16).collect::<Vec<u8>>());
        assert_eq!(k.server_master_key, (16..32).collect::<Vec<u8>>());
        assert_eq!(k.client_master_salt, (32..46).collect::<Vec<u8>>());
        assert_eq!(k.server_master_salt, (46..60).collect::<Vec<u8>>());
        assert_eq!(k.local(crate::Role::Server).0, &m[16..32]);
        assert_eq!(k.remote(crate::Role::Server).1, &m[32..46]);
        for p in SrtpProfile::ALL {
            assert_eq!(SrtpProfile::from_id(p.id()), Some(p));
        }
    }
}
