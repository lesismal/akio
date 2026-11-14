//! Stateless HelloVerifyRequest cookies (RFC 6347 §4.2.1).

use std::time::{Duration, Instant};

use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;

use crate::Error;
use crate::handshake::{self, ClientHello};
use crate::record::{self, CT_HANDSHAKE, Header};

/// How long a cookie stays valid (between one and two periods).
const PERIOD: Duration = Duration::from_secs(60);

/// What to do with a datagram that may start a handshake, as decided by [`HelloVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelloCheck {
    /// A ClientHello with a valid cookie: create the server [`Connection`](crate::Connection)
    /// and feed it the datagram.
    Accept,
    /// A ClientHello without a valid cookie: send this HelloVerifyRequest datagram back and
    /// keep no state.
    Respond(Vec<u8>),
    /// Not a ClientHello (or malformed): drop it.
    Drop,
}

/// Stateless cookie generation and checking for a listener in front of many connections: the
/// cookie is an HMAC over the peer's transport address, the client random and its offered
/// parameters, keyed by a secret that changes every minute.
///
/// A server [`Connection`](crate::Connection) with
/// [`Config::with_hello_verify`](crate::Config::with_hello_verify) on uses one internally; a
/// listener that wants to allocate nothing before return routability is proven calls
/// [`HelloVerifier::check`] itself and creates connections with cookies off.
#[derive(Clone)]
pub struct HelloVerifier {
    secret: [u8; 32],
    start: Instant,
}

impl std::fmt::Debug for HelloVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelloVerifier").finish_non_exhaustive()
    }
}

impl HelloVerifier {
    /// A verifier with a fresh random secret.
    pub fn new(now: Instant) -> Result<HelloVerifier, Error> {
        let mut secret = [0u8; 32];
        only_crypto::rand::fill_random(&mut secret)
            .map_err(|_| Error::Crypto(only_crypto::Error::Random))?;
        Ok(HelloVerifier { secret, start: now })
    }

    fn epoch(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs() / PERIOD.as_secs()
    }

    pub(crate) fn cookie(&self, epoch: u64, peer: &[u8], ch: &ClientHello) -> [u8; 32] {
        let suites: Vec<u8> = ch
            .cipher_suites
            .iter()
            .flat_map(|s| s.to_be_bytes())
            .collect();
        Hmac::<Sha256>::new(&self.secret)
            .chain(&epoch.to_be_bytes())
            .chain(&(peer.len() as u64).to_be_bytes())
            .chain(peer)
            .chain(&ch.version.to_be_bytes())
            .chain(&ch.random)
            .chain(&[ch.session_id.len() as u8])
            .chain(&ch.session_id)
            .chain(&suites)
            .chain(&ch.compression)
            .finalize()
    }

    /// The cookie to send for `ch` from `peer` now.
    pub(crate) fn make(&self, now: Instant, peer: &[u8], ch: &ClientHello) -> [u8; 32] {
        self.cookie(self.epoch(now), peer, ch)
    }

    /// Whether `ch` carries a cookie made for `peer` in this period or the previous one.
    pub(crate) fn valid(&self, now: Instant, peer: &[u8], ch: &ClientHello) -> bool {
        let e = self.epoch(now);
        [Some(e), e.checked_sub(1)]
            .into_iter()
            .flatten()
            .any(|e| only_crypto::ct_eq(&self.cookie(e, peer, ch), &ch.cookie))
    }

    /// Inspects the first record of `datagram` from `peer` (any stable encoding of the
    /// transport address): a complete, unfragmented epoch-0 ClientHello is accepted when its
    /// cookie is valid and otherwise answered with a HelloVerifyRequest.
    #[must_use]
    pub fn check(&self, now: Instant, peer: &[u8], datagram: &[u8]) -> HelloCheck {
        let Some((h, payload)) = record::split(datagram).into_iter().next() else {
            return HelloCheck::Drop;
        };
        if h.content_type != CT_HANDSHAKE || h.epoch != 0 {
            return HelloCheck::Drop;
        }
        let Ok(frags) = handshake::parse_fragments(payload) else {
            return HelloCheck::Drop;
        };
        let Some(f) = frags.first() else {
            return HelloCheck::Drop;
        };
        if f.msg_type != handshake::CLIENT_HELLO || f.offset != 0 || f.body.len() != f.length {
            return HelloCheck::Drop;
        }
        let Ok(ch) = ClientHello::parse(f.body) else {
            return HelloCheck::Drop;
        };
        if self.valid(now, peer, &ch) {
            return HelloCheck::Accept;
        }
        HelloCheck::Respond(hello_verify_datagram(
            f.seq,
            h.seq,
            &self.make(now, peer, &ch),
        ))
    }
}

/// A HelloVerifyRequest record: message_seq and record sequence number mirror the
/// ClientHello's (RFC 6347 §4.2.1), so nothing has to be remembered.
pub(crate) fn hello_verify_datagram(msg_seq: u16, record_seq: u64, cookie: &[u8]) -> Vec<u8> {
    let msg = handshake::encode_message(
        handshake::HELLO_VERIFY_REQUEST,
        msg_seq,
        &handshake::encode_hello_verify(cookie),
    );
    let mut out = Vec::with_capacity(record::HEADER_LEN + msg.len());
    Header {
        content_type: CT_HANDSHAKE,
        version: record::DTLS10,
        epoch: 0,
        seq: record_seq,
    }
    .encode(msg.len(), &mut out);
    out.extend_from_slice(&msg);
    out
}
