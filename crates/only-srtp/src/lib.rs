#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! SRTP and SRTCP (RFC 3711, RFC 7714) for the `only` WebRTC stack, on [`only_crypto`] with no
//! other dependencies.
//!
//! A [`Context`] holds one direction of an SRTP session: the session keys derived from the
//! DTLS-SRTP master key and salt, and per-SSRC state (rollover counter, replay window, SRTCP
//! index). It has no I/O: [`Context::protect_rtp`] / [`Context::protect_rtcp`] turn RTP/RTCP
//! packets into SRTP/SRTCP, [`Context::unprotect_rtp`] / [`Context::unprotect_rtcp`] go back.
//!
//! - Profiles ([`Profile`], RFC 5764 §4.1.2 and RFC 7714 §14.2): `SRTP_AES128_CM_HMAC_SHA1_80`,
//!   `SRTP_AES128_CM_HMAC_SHA1_32` (SRTCP still uses 80-bit tags), `SRTP_AEAD_AES_128_GCM`,
//!   `SRTP_AEAD_AES_256_GCM`.
//! - Key derivation: the AES-CM PRF with key derivation rate 0 (RFC 3711 §4.3, RFC 6188 for
//!   256-bit master keys).
//! - SRTP (RFC 3711 §3.3, §4.1.1, §4.2; RFC 7714 §8): the header (CSRCs and header extension
//!   included) is authenticated but never encrypted; the payload and padding are encrypted.
//!   The packet index is estimated from the sequence number and the per-SSRC rollover counter
//!   (§3.3.1, Appendix A); the tag is verified before decryption; the replay window (64
//!   packets by default, [`Context::with_replay_window`]) is updated only after successful
//!   authentication, and replays are reported as [`Error::Replay`].
//! - SRTCP (RFC 3711 §3.4; RFC 7714 §9): the E flag and a 31-bit index per sender SSRC; replay
//!   protected; received packets with the E flag clear are authenticated only.
//! - Per-direction state is bounded: beyond 1024 SSRCs ([`Context::with_max_ssrcs`]) the least
//!   recently used SSRC is forgotten.
//!
//! Not implemented: MKIs, key derivation rates other than 0, re-keying, the NULL cipher, AES-192
//! and AES-256-CM profiles, encrypted header extensions (RFC 6904) and cryptex (RFC 9335).
//!
//! ```
//! use only_srtp::{Context, Error, Profile};
//!
//! let (key, salt) = ([7u8; 16], [9u8; 12]);
//! let mut tx = Context::new(Profile::AeadAes128Gcm, &key, &salt)?;
//! let mut rx = Context::new(Profile::AeadAes128Gcm, &key, &salt)?;
//! let rtp = [0x80, 96, 0x12, 0x34, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef, b'h', b'i'];
//! let srtp = tx.protect_rtp(&rtp)?;
//! assert_eq!(srtp.len(), rtp.len() + Profile::AeadAes128Gcm.rtp_tag_len());
//! assert_eq!(rx.unprotect_rtp(&srtp)?, rtp);
//! assert_eq!(rx.unprotect_rtp(&srtp), Err(Error::Replay));
//! # Ok::<(), Error>(())
//! ```
//!
//! This is an implementation crate of `only` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.

mod cipher;
mod context;
mod error;
mod profile;
mod replay;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

#[cfg(test)]
mod tests;

pub use context::{Context, DEFAULT_MAX_SSRCS, DEFAULT_REPLAY_WINDOW, MAX_REPLAY_WINDOW};
pub use error::Error;
pub use profile::Profile;
