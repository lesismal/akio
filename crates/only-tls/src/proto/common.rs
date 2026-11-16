//! What the handshake state machines share: encryption levels, the actions they emit, the
//! transcript, the TLS 1.3 key schedule and the settings they run with.

use std::collections::HashMap;
use std::sync::Arc;

use only_crypto::pkey::PrivateKey;
use only_x509::RootStore;

use super::alert::{Alert, Fatal};
use super::kx::Group;
use super::msgs::MESSAGE_HASH;
use super::session::{AntiReplay, ClientCache, SessionCache, Ticketer};
use super::suites::{HashAlg, HashCtx, Suite};

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
}

impl std::fmt::Debug for CertKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertKey")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
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

/// What a server runs with.
#[derive(Debug)]
pub(crate) struct ServerSettings {
    pub(crate) cert: Arc<CertKey>,
    pub(crate) sni: HashMap<String, Arc<CertKey>>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) client_auth: Option<(Arc<RootStore>, bool)>,
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
    only_crypto::rand::fill_random(&mut b)
        .map_err(|_| Fatal::new(Alert::InternalError, "no randomness"))?;
    Ok(b)
}

/// Verifies a peer chain with `only-x509`: the server's for `server_name`, or a client's.
pub(crate) fn verify_chain(
    roots: &RootStore,
    chain: &[Vec<u8>],
    server_name: Option<&str>,
) -> Result<only_crypto::pkey::PublicKey, Fatal> {
    let leaf_der = chain
        .first()
        .ok_or_else(|| Fatal::new(Alert::DecodeError, "empty certificate chain"))?;
    let leaf = only_x509::Certificate::from_der(leaf_der.clone())
        .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?;
    let mut inter = Vec::new();
    for c in &chain[1..] {
        inter.push(
            only_x509::Certificate::from_der(c.clone())
                .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?,
        );
    }
    let v = only_x509::Verifier::new(roots);
    let r = match server_name {
        Some(n) => v.verify_server(&leaf, &inter, n),
        None => v.verify_client(&leaf, &inter),
    };
    if let Err(e) = r {
        use only_x509::Error as E;
        let alert = match e {
            E::Expired | E::NotYetValid => Alert::CertificateExpired,
            E::UnknownIssuer => Alert::UnknownCa,
            E::NameMismatch | E::ExtendedKeyUsage | E::KeyUsage | E::CaUsedAsEndEntity => {
                Alert::BadCertificate
            }
            _ => Alert::BadCertificate,
        };
        return Err(Fatal::new(
            alert,
            format!("certificate verification failed: {e}"),
        ));
    }
    leaf.public_key()
        .map_err(|_| Fatal::new(Alert::UnsupportedCertificate, "unsupported public key"))
}

/// The leaf's public key without verifying anything (insecure mode).
pub(crate) fn leaf_key(chain: &[Vec<u8>]) -> Result<only_crypto::pkey::PublicKey, Fatal> {
    let leaf_der = chain
        .first()
        .ok_or_else(|| Fatal::new(Alert::DecodeError, "empty certificate chain"))?;
    let leaf = only_x509::Certificate::from_der(leaf_der.clone())
        .map_err(|_| Fatal::new(Alert::BadCertificate, "unparsable certificate"))?;
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
