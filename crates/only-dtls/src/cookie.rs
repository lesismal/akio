//! Stateless return-routability cookies: DTLS 1.2 HelloVerifyRequest (RFC 6347 §4.2.1) and
//! DTLS 1.3 HelloRetryRequest cookies (RFC 9147 §5.1, RFC 8446 §4.2.2).

use std::time::{Duration, Instant};

use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;

use crate::Error;
use crate::crypto::{CipherSuite, NamedGroup};
use crate::handshake::{self, ClientHello, Extensions, ServerHello};
use crate::record::{self, CT_HANDSHAKE, DTLS12, DTLS13, Header};

/// How long a cookie stays valid (between one and two periods).
const PERIOD: Duration = Duration::from_secs(60);

/// What to do with a datagram that may start a handshake, as decided by [`HelloVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelloCheck {
    /// A ClientHello with a valid cookie: create the server [`Connection`](crate::Connection)
    /// and feed it the datagram.
    Accept,
    /// A ClientHello without a valid cookie: send this HelloVerifyRequest (DTLS 1.2) or
    /// HelloRetryRequest (DTLS 1.3) datagram back and keep no state.
    Respond(Vec<u8>),
    /// Not a ClientHello (or malformed): drop it.
    Drop,
}

/// Stateless cookie generation and checking for a listener in front of many connections: the
/// cookie is an HMAC over the peer's transport address, the client random and its offered
/// parameters, keyed by a secret that changes every minute. A ClientHello offering DTLS 1.3
/// gets a HelloRetryRequest whose cookie also carries what the server needs to continue the
/// transcript (the ClientHello hash, the cipher suite and group it picked); the connection
/// created for the second ClientHello (with cookies off) trusts that cookie.
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

    /// The HelloRetryRequest cookie for `c`: its fields and an HMAC over them and `peer`.
    pub(crate) fn hrr_cookie(&self, now: Instant, peer: &[u8], c: &HrrCookie) -> Vec<u8> {
        let mut out = c.encode();
        let mac = self.hrr_mac(self.epoch(now), peer, &out);
        out.extend_from_slice(&mac);
        out
    }

    fn hrr_mac(&self, epoch: u64, peer: &[u8], body: &[u8]) -> [u8; 32] {
        Hmac::<Sha256>::new(&self.secret)
            .chain(b"hrr")
            .chain(&epoch.to_be_bytes())
            .chain(&(peer.len() as u64).to_be_bytes())
            .chain(peer)
            .chain(body)
            .finalize()
    }

    /// The fields of a cookie made for `peer` in this period or the previous one.
    pub(crate) fn open_hrr_cookie(
        &self,
        now: Instant,
        peer: &[u8],
        cookie: &[u8],
    ) -> Option<HrrCookie> {
        let body = cookie.get(..cookie.len().checked_sub(32)?)?;
        let mac = &cookie[body.len()..];
        let e = self.epoch(now);
        [Some(e), e.checked_sub(1)]
            .into_iter()
            .flatten()
            .any(|e| only_crypto::ct_eq(&self.hrr_mac(e, peer, body), mac))
            .then(|| HrrCookie::decode(body))
            .flatten()
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
        if offers13(&ch) {
            if let Some(c) = &ch.extensions.cookie {
                return if self.open_hrr_cookie(now, peer, c).is_some() {
                    HelloCheck::Accept
                } else {
                    HelloCheck::Drop
                };
            }
            // The client's first DTLS 1.3 suite we implement, and a group when its key
            // shares have none we support.
            let Some(suite) = ch
                .cipher_suites
                .iter()
                .filter_map(|&id| CipherSuite::from_id(id))
                .find(|s| s.is_tls13())
            else {
                return HelloCheck::Drop;
            };
            let group = hrr_group(&ch, &NamedGroup::ALL);
            let c = HrrCookie::new(suite, group, f.body);
            let cookie = self.hrr_cookie(now, peer, &c);
            return HelloCheck::Respond(hrr_datagram(f.seq, h.seq, &ch, suite, group, &cookie));
        }
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

/// Whether a ClientHello offers DTLS 1.3.
pub(crate) fn offers13(ch: &ClientHello) -> bool {
    ch.extensions
        .supported_versions
        .as_ref()
        .is_some_and(|v| v.contains(&DTLS13))
}

/// The group a HelloRetryRequest must ask for: none when the client sent a share of a group
/// in `ours`, else the first of `ours` it supports (`None` too when there is none).
pub(crate) fn hrr_group(ch: &ClientHello, ours: &[NamedGroup]) -> Option<NamedGroup> {
    let e = &ch.extensions;
    let shares = e.key_shares.as_deref().unwrap_or_default();
    if ours
        .iter()
        .any(|g| shares.iter().any(|(id, _)| *id == g.id()))
    {
        return None;
    }
    let groups = e.groups.as_deref().unwrap_or_default();
    ours.iter().copied().find(|g| groups.contains(&g.id()))
}

/// What a DTLS 1.3 HelloRetryRequest cookie carries: the server's choices and the hash of
/// ClientHello1 (RFC 8446 §4.4.1 `message_hash`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HrrCookie {
    pub(crate) suite: CipherSuite,
    pub(crate) group: Option<NamedGroup>,
    pub(crate) ch1_hash: Vec<u8>,
}

impl HrrCookie {
    /// The cookie for ClientHello1 `ch1_body` (its handshake body).
    pub(crate) fn new(suite: CipherSuite, group: Option<NamedGroup>, ch1_body: &[u8]) -> HrrCookie {
        let t = handshake::transcript13(handshake::CLIENT_HELLO, ch1_body);
        HrrCookie {
            suite,
            group,
            ch1_hash: suite.prf_hash().digest(&t),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![1];
        out.extend_from_slice(&self.suite.id().to_be_bytes());
        out.extend_from_slice(&self.group.map_or(0, NamedGroup::id).to_be_bytes());
        out.push(self.ch1_hash.len() as u8);
        out.extend_from_slice(&self.ch1_hash);
        out
    }

    fn decode(b: &[u8]) -> Option<HrrCookie> {
        let mut r = crate::codec::Reader::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let suite = CipherSuite::from_id(r.u16().ok()?).filter(|s| s.is_tls13())?;
        let group = match r.u16().ok()? {
            0 => None,
            g => Some(NamedGroup::from_id(g)?),
        };
        let ch1_hash = r.vec8().ok()?.to_vec();
        r.finish().ok()?;
        (ch1_hash.len() == suite.prf_hash().len()).then_some(HrrCookie {
            suite,
            group,
            ch1_hash,
        })
    }

    /// The fields of a cookie whose MAC another component (a listener's
    /// [`HelloVerifier`]) checked.
    pub(crate) fn decode_unverified(cookie: &[u8]) -> Option<HrrCookie> {
        HrrCookie::decode(cookie.get(..cookie.len().checked_sub(32)?)?)
    }
}

/// The HelloRetryRequest body for `ch` (deterministic: the server rebuilds it from the
/// second ClientHello and the cookie for the transcript).
pub(crate) fn hrr_body(
    session_id: &[u8],
    suite: CipherSuite,
    group: Option<NamedGroup>,
    cookie: &[u8],
) -> Vec<u8> {
    ServerHello {
        version: DTLS12,
        random: handshake::HRR_RANDOM,
        session_id: session_id.to_vec(),
        cipher_suite: suite.id(),
        compression: 0,
        extensions: Extensions {
            supported_versions: Some(vec![DTLS13]),
            cookie: Some(cookie.to_vec()),
            hrr_group: group.map(NamedGroup::id),
            ..Extensions::default()
        },
    }
    .encode()
}

/// A HelloRetryRequest in a plaintext record that mirrors the ClientHello's message and
/// record sequence numbers (RFC 9147 §5.1).
pub(crate) fn hrr_datagram(
    msg_seq: u16,
    record_seq: u64,
    ch: &ClientHello,
    suite: CipherSuite,
    group: Option<NamedGroup>,
    cookie: &[u8],
) -> Vec<u8> {
    let msg = handshake::encode_message(
        handshake::SERVER_HELLO,
        msg_seq,
        &hrr_body(&ch.session_id, suite, group, cookie),
    );
    let mut out = Vec::with_capacity(record::HEADER_LEN + msg.len());
    Header {
        content_type: CT_HANDSHAKE,
        version: DTLS12,
        epoch: 0,
        seq: record_seq,
    }
    .encode(msg.len(), &mut out);
    out.extend_from_slice(&msg);
    out
}
