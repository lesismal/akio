//! What the handshake state machines share: encryption levels, the actions they emit, the
//! transcript, the TLS 1.3 key schedule and the settings they run with.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use akio_crypto::pkey::PrivateKey;
use akio_x509::RootStore;

use super::alert::{Alert, Fatal};
use super::kx::Group;
use super::msgs::{
    CERTIFICATE, CompAlgs, MESSAGE_HASH, certificate13_body, compressed_certificate, message,
};
use super::session::{AntiReplay, ClientCache, SessionCache, Ticketer};
use super::suites::{HashAlg, HashCtx, Suite};
pub(crate) use crate::EarlyData;

/// An encryption level (QUIC's packet number spaces map onto these).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    /// Plaintext: ClientHello, ServerHello, HelloRetryRequest.
    Initial,
    /// 0-RTT application data.
    EarlyData,
    /// Handshake traffic keys.
    Handshake,
    /// Application traffic keys.
    Application,
}

/// Traffic keys as the handshake hands them to the record layer (or to QUIC).
#[derive(Clone)]
pub enum Keys {
    /// A TLS 1.3 traffic secret (keys are derived from it with "key" / "iv", or QUIC's
    /// "quic key" / "quic iv" / "quic hp").
    Tls13 {
        /// The negotiated suite.
        suite: &'static Suite,
        /// The traffic secret.
        secret: Vec<u8>,
    },
    /// TLS 1.2 key block material.
    Tls12 {
        /// The negotiated suite.
        suite: &'static Suite,
        /// The write key.
        key: Vec<u8>,
        /// The fixed IV (4 bytes for GCM, 12 for ChaCha20-Poly1305).
        iv: Vec<u8>,
    },
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keys::Tls13 { suite, .. } => write!(f, "Keys::Tls13({})", suite.name),
            Keys::Tls12 { suite, .. } => write!(f, "Keys::Tls12({})", suite.name),
        }
    }
}

/// What a handshake step asks the layer below to do, in order.
#[derive(Debug)]
pub(crate) enum Action {
    /// Send a handshake message at this level.
    Msg(Level, Vec<u8>),
    /// Send a ChangeCipherSpec record (TLS 1.2, or the TLS 1.3 compatibility one).
    Ccs,
    /// Decrypt what follows with these keys.
    ReadKeys(Level, Keys),
    /// Encrypt what follows with these keys.
    WriteKeys(Level, Keys),
    /// Send a warning alert.
    Warning(Alert),
    /// The client offered 0-RTT data and it is rejected: skip it (server), or take back what
    /// was sent early and send it again after the handshake (client).
    RejectEarlyData,
    /// The client offers early data, at most this many bytes (the ticket's limit); the early
    /// write keys follow.
    EarlyOffered(u32),
    /// Early data is accepted: the server reads at most this many bytes of it.
    EarlyAccepted(u32),
    /// record_size_limit (RFC 8449) values from now on, 0 for none: `read` is what we
    /// advertised (records we accept, except early data), `write` what the peer advertised
    /// (records we send under keys).
    RecordLimit { read: u16, write: u16 },
    /// The handshake is complete.
    Done,
}

/// The handshake transcript: the raw messages (TLS 1.2 client CertificateVerify signs them, PSK
/// binders and HelloRetryRequest need them before the hash is known) and the running hash.
#[derive(Clone, Default)]
pub(crate) struct Transcript {
    buf: Vec<u8>,
    ctx: Option<HashCtx>,
    alg: Option<HashAlg>,
}

impl Transcript {
    pub(crate) fn add(&mut self, msg: &[u8]) {
        self.buf.extend_from_slice(msg);
        if let Some(c) = &mut self.ctx {
            c.update(msg);
        }
    }

    pub(crate) fn set_hash(&mut self, alg: HashAlg) {
        if self.alg == Some(alg) {
            return;
        }
        let mut c = alg.context();
        c.update(&self.buf);
        self.ctx = Some(c);
        self.alg = Some(alg);
    }

    pub(crate) fn hash(&self) -> Vec<u8> {
        match (&self.ctx, self.alg) {
            (Some(c), _) => c.current(),
            _ => Vec::new(),
        }
    }

    /// The hash of the transcript followed by `extra`, under `alg`.
    pub(crate) fn hash_with(&self, alg: HashAlg, extra: &[u8]) -> Vec<u8> {
        if self.alg == Some(alg) {
            if let Some(c) = &self.ctx {
                let mut c = c.clone();
                c.update(extra);
                return c.current();
            }
        }
        let mut c = alg.context();
        c.update(&self.buf);
        c.update(extra);
        c.current()
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.buf
    }

    /// Replaces ClientHello1 by `message_hash` (RFC 8446 section 4.4.1) for a
    /// HelloRetryRequest.
    pub(crate) fn rollup_for_hrr(&mut self, alg: HashAlg) {
        let h = alg.digest(&self.buf);
        let mut b = vec![MESSAGE_HASH, 0, 0, h.len() as u8];
        b.extend_from_slice(&h);
        self.buf.clear();
        self.ctx = None;
        self.alg = None;
        self.add(&b);
        self.set_hash(alg);
    }
}

/// The TLS 1.3 key schedule (RFC 8446 section 7.1): the current stage secret.
#[derive(Clone)]
pub(crate) struct Schedule {
    pub(crate) hash: HashAlg,
    pub(crate) current: Vec<u8>,
}

impl Schedule {
    /// The early secret from `psk` (zeros without one).
    pub(crate) fn early(hash: HashAlg, psk: Option<&[u8]>) -> Schedule {
        let zeros = vec![0u8; hash.len()];
        Schedule {
            hash,
            current: hash.extract(&zeros, psk.unwrap_or(&zeros)),
        }
    }

    pub(crate) fn derive(&self, label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        self.hash
            .derive_secret(&self.current, label, transcript_hash)
    }

    /// Moves to the next stage: handshake secret with `ikm` = the (EC)DHE secret, then master
    /// secret with `ikm` = None.
    pub(crate) fn next(&mut self, ikm: Option<&[u8]>) {
        let empty = self.hash.digest(&[]);
        let derived = self.derive(b"derived", &empty);
        let zeros = vec![0u8; self.hash.len()];
        self.current = self.hash.extract(&derived, ikm.unwrap_or(&zeros));
    }

    /// The PSK binder key.
    pub(crate) fn binder_key(&self, external: bool) -> Vec<u8> {
        let empty = self.hash.digest(&[]);
        self.derive(
            if external {
                b"ext binder"
            } else {
                b"res binder"
            },
            &empty,
        )
    }
}

/// verify_data of a TLS 1.3 Finished (or PSK binder) for `base_key` over `transcript_hash`.
pub(crate) fn finished_mac(hash: HashAlg, base_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let k = hash.expand_label(base_key, b"finished", &[], hash.len());
    hash.hmac(&k, transcript_hash)
}

/// The next application traffic secret (KeyUpdate).
pub(crate) fn next_secret(hash: HashAlg, secret: &[u8]) -> Vec<u8> {
    hash.expand_label(secret, b"traffic upd", &[], hash.len())
}

/// A certificate chain and its key.
pub(crate) struct CertKey {
    pub(crate) chain: Vec<Vec<u8>>,
    pub(crate) key: PrivateKey,
    /// A DER OCSP response stapled for clients asking for one (server certificates).
    pub(crate) ocsp: Option<Vec<u8>>,
    /// The TLS 1.3 CompressedCertificate messages (empty context; without and with the OCSP
    /// response; zlib, brotli, zstd), compressed on first use: `None` when compression does not
    /// make them smaller.
    compressed: [[OnceLock<Option<Vec<u8>>>; 3]; 2],
}

impl CertKey {
    pub(crate) fn new(chain: Vec<Vec<u8>>, key: PrivateKey) -> CertKey {
        CertKey {
            chain,
            key,
            ocsp: None,
            compressed: Default::default(),
        }
    }

    /// The TLS 1.3 Certificate message for this chain under `context`, stapling the OCSP
    /// response when `ocsp`; compressed (RFC 8879) with whichever of `algs` gives the smallest
    /// message, when one makes it smaller.
    pub(crate) fn certificate13(&self, context: &[u8], ocsp: bool, algs: CompAlgs) -> Vec<u8> {
        let ocsp = self.ocsp.as_deref().filter(|_| ocsp);
        let body = |o: &mut Vec<u8>| certificate13_body(o, context, &self.chain, ocsp);
        let mut best: Option<Vec<u8>> = None;
        for alg in algs.ids() {
            let make = || {
                let mut b = Vec::new();
                body(&mut b);
                compressed_certificate(&b, alg)
            };
            let c = if context.is_empty() {
                self.compressed[usize::from(ocsp.is_some())][usize::from(alg - 1)]
                    .get_or_init(make)
                    .clone()
            } else {
                make()
            };
            if let Some(c) = c {
                if best.as_ref().is_none_or(|b| c.len() < b.len()) {
                    best = Some(c);
                }
            }
        }
        best.unwrap_or_else(|| message(CERTIFICATE, body))
    }
}

impl std::fmt::Debug for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertKey")
            .field("chain_len", &self.chain.len())
            .field("ocsp", &self.ocsp.is_some())
            .finish_non_exhaustive()
    }
}

/// What a server runs with.
#[derive(Debug)]
pub(crate) struct ServerSettings {
    pub(crate) cert: Arc<CertKey>,
    pub(crate) sni: HashMap<String, Arc<CertKey>>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) client_auth: Option<(Arc<RootStore>, bool)>,
    /// CRLs for client chains (None: no check).
    pub(crate) client_crls: Option<CrlCheck>,
    /// Ask TLS 1.3 clients for an OCSP response and validate it (Off: not asked).
    pub(crate) client_ocsp: crate::RevocationPolicy,
    pub(crate) cache: Option<SessionCache>,
    pub(crate) ticketer: Option<Ticketer>,
    pub(crate) tls12: bool,
    pub(crate) tls13: bool,
    pub(crate) suites: Vec<&'static Suite>,
    pub(crate) groups: Vec<Group>,
    /// NewSessionTicket messages sent after a TLS 1.3 handshake.
    pub(crate) tickets13: usize,
    pub(crate) ticket_lifetime: u32,
    /// Send a HelloRetryRequest even when the client's key share is usable (tests).
    pub(crate) force_hrr: bool,
    /// TLS 1.3 early data accepted over TCP, bytes (0: off; QUIC enables it per connection).
    pub(crate) max_early_data: u32,
    /// The ClientHellos whose early data was accepted (replay protection).
    pub(crate) anti_replay: AntiReplay,
    /// The record_size_limit advertised to clients that send one (RFC 8449; capped to the
    /// protocol's maximum when sent).
    pub(crate) record_limit: u16,
    /// Send compressed certificates (RFC 8879) to clients that accept one of these algorithms,
    /// and accept compressed client certificates (empty: off).
    pub(crate) cert_compression: CompAlgs,
}

impl ServerSettings {
    pub(crate) fn resumption(&self) -> bool {
        self.cache.is_some() || self.ticketer.is_some()
    }
}

/// What a client runs with.
#[derive(Debug)]
pub(crate) struct ClientSettings {
    pub(crate) roots: Arc<RootStore>,
    pub(crate) insecure: bool,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) cert: Option<Arc<CertKey>>,
    pub(crate) sni: bool,
    pub(crate) cache: Option<ClientCache>,
    pub(crate) tls12: bool,
    pub(crate) tls13: bool,
    pub(crate) suites: Vec<&'static Suite>,
    /// Supported groups; a key share is sent for the first.
    pub(crate) groups: Vec<Group>,
    /// Send early data (0-RTT) when a ticket allows it (TCP; QUIC decides per connection).
    pub(crate) early_data: bool,
    /// The record_size_limit sent in the ClientHello (RFC 8449; not over QUIC).
    pub(crate) record_limit: u16,
    /// Offer to receive compressed certificates (RFC 8879) with these algorithms, and compress
    /// our own when the server offers one of them (empty: off).
    pub(crate) cert_compression: CompAlgs,
    /// Ask for a stapled OCSP response (status_request, RFC 6066 / RFC 8446 section 4.4.2.1).
    pub(crate) ocsp: bool,
    /// Validate the stapled OCSP response.
    pub(crate) ocsp_policy: crate::RevocationPolicy,
    /// CRLs for the server's chain (None: no check).
    pub(crate) crls: Option<CrlCheck>,
}

/// CRLs and what to do when none covers a certificate.
pub(crate) type CrlCheck = (Arc<akio_x509::CrlSet>, akio_x509::RevocationMode);

/// A verified peer chain: the leaf's key, and the leaf and its issuer (for OCSP).
pub(crate) struct Verified {
    pub(crate) key: akio_crypto::pkey::PublicKey,
    pub(crate) leaf: akio_x509::Certificate,
    pub(crate) issuer: akio_x509::Certificate,
}

/// Unix time in seconds.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Unix time in milliseconds.
pub(crate) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Random bytes, or an internal_error.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Fatal> {
    let mut b = [0u8; N];
    akio_crypto::rand::fill_random(&mut b)
        .map_err(|_| Fatal::new(Alert::InternalError, "no randomness"))?;
    Ok(b)
}

/// Verifies a peer chain with `akio-x509`: the server's for `server_name`, or a client's;
/// against `crls` when given.
pub(crate) fn verify_chain(
    roots: &RootStore,
    chain: &[Vec<u8>],
    server_name: Option<&str>,
    crls: Option<&CrlCheck>,
) -> Result<Verified, Fatal> {
    let leaf_der = chain
        .first()
        .ok_or_else(|| Fatal::new(Alert::DecodeError, "empty certificate chain"))?;
    let leaf = akio_x509::Certificate::from_der(leaf_der.clone())
        .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?;
    check_signing_usage(&leaf)?;
    let mut inter = Vec::new();
    for c in &chain[1..] {
        inter.push(
            akio_x509::Certificate::from_der(c.clone())
                .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?,
        );
    }
    let mut v = akio_x509::Verifier::new(roots);
    if let Some((set, mode)) = crls {
        v = v.crls(set).revocation_mode(*mode);
    }
    let r = match server_name {
        Some(n) => v.verify_server(&leaf, &inter, n),
        None => v.verify_client(&leaf, &inter),
    };
    let path = match r {
        Ok(p) => p,
        Err(e) => {
            use akio_x509::Error as E;
            let alert = match e {
                E::Expired | E::NotYetValid => Alert::CertificateExpired,
                E::UnknownIssuer => Alert::UnknownCa,
                E::Revoked(_) => Alert::CertificateRevoked,
                E::RevocationUnknown => Alert::CertificateUnknown,
                _ => Alert::BadCertificate,
            };
            return Err(Fatal::new(
                alert,
                format!("certificate verification failed: {e}"),
            ));
        }
    };
    let key = leaf
        .public_key()
        .map_err(|_| Fatal::new(Alert::UnsupportedCertificate, "unsupported public key"))?;
    let issuer = path
        .into_iter()
        .nth(1)
        .ok_or_else(|| Fatal::new(Alert::InternalError, "path without an issuer"))?;
    Ok(Verified { key, leaf, issuer })
}

/// Checks the OCSP response stapled for `leaf` (issued by `issuer`; the `peer`'s, "server" or
/// "client", for the messages) under `policy`.
pub(crate) fn check_stapled_ocsp(
    policy: crate::RevocationPolicy,
    response: Option<&[u8]>,
    leaf: &akio_x509::Certificate,
    issuer: &akio_x509::Certificate,
    peer: &str,
) -> Result<(), Fatal> {
    use crate::RevocationPolicy as P;
    use akio_x509::RevocationStatus as S;
    if policy == P::Off {
        return Ok(());
    }
    let r = match response {
        None => Err(None),
        Some(der) => akio_x509::OcspResponse::from_der(der)
            .and_then(|r| r.verify(leaf, issuer, &akio_x509::OcspValidation::new()))
            .map_err(Some),
    };
    match r {
        Ok(S::Revoked { reason, .. }) => Err(Fatal::new(
            Alert::CertificateRevoked,
            match reason {
                Some(r) => format!("{peer} certificate revoked (stapled OCSP: {r})"),
                None => format!("{peer} certificate revoked (stapled OCSP)"),
            },
        )),
        Ok(S::Good) => Ok(()),
        _ if policy == P::SoftFail => Ok(()),
        Ok(_) => Err(Fatal::new(
            Alert::BadCertificateStatusResponse,
            "stapled OCSP response: status unknown",
        )),
        Err(None) => Err(Fatal::new(
            Alert::BadCertificateStatusResponse,
            "no stapled OCSP response",
        )),
        Err(Some(e)) => Err(Fatal::new(
            Alert::BadCertificateStatusResponse,
            format!("invalid stapled OCSP response: {e}"),
        )),
    }
}

/// The peer's leaf signs the handshake (CertificateVerify, ServerKeyExchange): a keyUsage
/// extension, when present, must allow digitalSignature (RFC 8446 section 4.4.2.2, RFC 5246
/// section 7.4.2, RFC 5280 section 4.2.1.3).
fn check_signing_usage(leaf: &akio_x509::Certificate) -> Result<(), Fatal> {
    match leaf.key_usage() {
        Some(ku) if ku.0 & akio_x509::KeyUsage::DIGITAL_SIGNATURE.0 == 0 => Err(Fatal::new(
            Alert::BadCertificate,
            "certificate key usage does not allow signing",
        )),
        _ => Ok(()),
    }
}

/// The leaf's public key without verifying anything (insecure mode).
pub(crate) fn leaf_key(chain: &[Vec<u8>]) -> Result<akio_crypto::pkey::PublicKey, Fatal> {
    let leaf_der = chain
        .first()
        .ok_or_else(|| Fatal::new(Alert::DecodeError, "empty certificate chain"))?;
    let leaf = akio_x509::Certificate::from_der(leaf_der.clone())
        .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?;
    check_signing_usage(&leaf)?;
    leaf.public_key()
        .map_err(|_| Fatal::new(Alert::UnsupportedCertificate, "unsupported public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hashes() {
        let mut t = Transcript::default();
        t.add(b"abc");
        assert!(t.hash().is_empty());
        assert_eq!(
            t.hash_with(HashAlg::Sha256, b"d"),
            HashAlg::Sha256.digest(b"abcd")
        );
        t.set_hash(HashAlg::Sha256);
        t.add(b"d");
        assert_eq!(t.hash(), HashAlg::Sha256.digest(b"abcd"));
        assert_eq!(
            t.hash_with(HashAlg::Sha256, b"e"),
            HashAlg::Sha256.digest(b"abcde")
        );
        assert_eq!(
            t.hash_with(HashAlg::Sha384, b""),
            HashAlg::Sha384.digest(b"abcd")
        );
        assert_eq!(t.raw(), b"abcd");
        t.rollup_for_hrr(HashAlg::Sha256);
        let mut want = vec![254, 0, 0, 32];
        want.extend_from_slice(&HashAlg::Sha256.digest(b"abcd"));
        assert_eq!(t.raw(), &want[..]);
        assert_eq!(t.hash(), HashAlg::Sha256.digest(&want));
    }
}
