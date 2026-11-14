#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Sans-io DTLS 1.2 (RFC 6347) for the `only` crates, on [`only_crypto`] and [`only_x509`] with
//! no other dependencies: the DTLS layer of the in-house WebRTC stack (DTLS-SRTP, SCTP data
//! channels).
//!
//! A [`Connection`] is a state machine without I/O, threads or clocks of its own: the caller
//! feeds it received datagrams ([`Connection::handle_datagram`]) and the current time, sends
//! what [`Connection::poll_transmit`] returns, calls [`Connection::handle_timeout`] at
//! [`Connection::poll_timeout`] and reads [`Event`]s from [`Connection::poll_event`].
//!
//! - Record layer: epochs, 48-bit sequence numbers, a 64-record anti-replay window, several
//!   records per datagram; records that do not authenticate are dropped silently.
//! - Handshake: full ECDHE handshakes as client or server; messages fragmented to the MTU and
//!   reassembled in any order; flights retransmitted with exponential backoff (RFC 6347
//!   §4.2.4) and when the peer repeats its previous flight; stateless HelloVerifyRequest
//!   cookies (HMAC-SHA-256 over the peer address and the ClientHello, rotating secret; see
//!   [`HelloVerifier`]).
//! - Cipher suites: `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
//!   CHACHA20_POLY1305_SHA256}`; groups X25519, P-256, P-384; ECDSA, Ed25519, RSA-PSS and
//!   RSA PKCS#1 signatures. Extended master secret (RFC 7627, required by default);
//!   renegotiation is refused (RFC 5746 `renegotiation_info`, `no_renegotiation` alerts).
//! - Authentication: mutual by default, with self-signed certificates checked by fingerprint
//!   ([`PeerVerifier::Fingerprints`]), a callback, or deferred to the caller; the peer always
//!   proves possession of its key.
//! - DTLS-SRTP: `use_srtp` (RFC 5764) with the AEAD-AES-GCM and AES-CM-HMAC-SHA1 profiles;
//!   the SRTP master keys come with [`Event::Connected`]. The RFC 5705 exporter is
//!   [`Connection::export_keying_material`].
//! - Alerts: close_notify both ways, fatal alerts on protocol errors.
//!
//! Not implemented: DTLS 1.3 (RFC 9147) and its ACKs, session resumption, connection IDs
//! (RFC 9146), PSK and non-ECDHE key exchanges, CBC suites.
//!
//! ```
//! use std::sync::Arc;
//! use std::time::Instant;
//! use only_dtls::{Config, Connection, Event, Identity, PeerVerifier};
//!
//! let (ci, si) = (Identity::generate_self_signed()?, Identity::generate_self_signed()?);
//! // Each side pins the other's fingerprint (from the SDP in WebRTC).
//! let client_cfg = Config::webrtc(ci.clone(), PeerVerifier::Fingerprints(vec![si.fingerprint()]));
//! let server_cfg = Config::webrtc(si, PeerVerifier::Fingerprints(vec![ci.fingerprint()]));
//! let now = Instant::now();
//! let mut client = Connection::client(Arc::new(client_cfg), now)?;
//! let mut server = Connection::server(Arc::new(server_cfg), now, b"198.51.100.7:5000")?;
//! for _ in 0..10 {
//!     while let Some(d) = client.poll_transmit() {
//!         server.handle_datagram(now, &d)?;
//!     }
//!     while let Some(d) = server.poll_transmit() {
//!         client.handle_datagram(now, &d)?;
//!     }
//! }
//! let Some(Event::Connected(info)) = client.poll_event() else { panic!() };
//! let keys = info.srtp_keys.expect("SRTP negotiated");
//! assert_eq!(keys.client_master_key.len(), 16);
//! client.send_application_data(b"hello")?;
//! server.handle_datagram(now, &client.poll_transmit().unwrap())?;
//! assert!(matches!(server.poll_event(), Some(Event::Connected(_))));
//! assert!(matches!(server.poll_event(), Some(Event::ApplicationData(d)) if d == b"hello"));
//! # Ok::<(), only_dtls::Error>(())
//! ```
//!
//! This is an implementation crate of `only` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.
//!
//! Guide: [Architecture](https://lesismal.github.io/only/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/only/zh-CN/architecture.html)).

mod codec;
mod config;
mod conn;
mod cookie;
mod crypto;
mod error;
mod handshake;
mod record;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

pub use config::{
    Config, Fingerprint, FingerprintAlgorithm, Identity, PeerVerifier, SrtpKeys, SrtpProfile,
    VerifyFn,
};
pub use conn::{Connection, Event, HandshakeInfo, Role};
pub use cookie::{HelloCheck, HelloVerifier};
pub use crypto::CipherSuite;
pub use error::{AlertDescription, Error};

/// The RFC 5764 exporter label for DTLS-SRTP keys.
pub const SRTP_EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";
