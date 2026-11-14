#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! RTP and RTCP for the `only` WebRTC stack, in safe Rust with no dependencies.
//!
//! Everything is sans-io: types take packets and `Instant`s and return packets; nothing owns
//! a socket, a thread or a clock, and randomness (initial sequence numbers, SSRCs) comes
//! from the caller.
//!
//! - [`RtpHeader`] (RFC 3550 §5.1): fixed header, CSRCs, padding, and header extensions in
//!   the RFC 8285 one-byte and two-byte forms, with typed values ([`ExtensionValues`]) for
//!   the extensions WebRTC negotiates ([`Extension`], mapped by an [`ExtensionMap`] from
//!   `a=extmap`). [`is_rtcp`] demultiplexes RTP and RTCP on one flow (RFC 5761 §4).
//! - [`Rtcp`] / [`parse_compound`] / [`write_compound`]: SR, RR, SDES, BYE (RFC 3550 §6),
//!   generic NACK (RFC 4585 §6.2.1), PLI (§6.3.1), FIR (RFC 5104 §4.3.1), REMB
//!   (draft-alvestrand-rmcat-remb), transport-wide CC feedback
//!   (draft-holmer-rmcat-transport-wide-cc-extensions-01), anything else as
//!   [`Rtcp::Unknown`].
//! - [`SendStream`]: sequence numbering, a retransmission history (1024 packets / 2 s),
//!   NACK responses as RTX (RFC 4588) or plain resends, sender reports, RTT from report
//!   blocks. [`RecvStream`]: sequence unwrapping, duplicate detection, loss and jitter
//!   (RFC 3550 A.3, A.8) for report blocks, NACK scheduling with reordering wait, RTT-paced
//!   repeats and give-up.
//! - [`TwccSender`] / [`TwccReceiver`]: transport-wide sequence numbers, feedback
//!   generation (libwebrtc's packing) and matching; [`BandwidthEstimator`]: a GCC-like
//!   delay-gradient + loss-based estimator.
//! - [`codec`]: payload packetizers / depacketizers and frame assembly.
//!
//! Not implemented: RTCP XR, SDES items beyond type/text pairs, TMMBR/TMMBN, FEC (ULPFEC /
//! FlexFEC), RFC 8888 congestion control feedback, SRTP (see `only-srtp`), probing in the
//! estimator, RTP header extension encryption.
//!
//! ```
//! use std::time::{Duration, Instant};
//! use only_rtp::{ExtensionMap, ExtensionValues, RecvStream, RtpHeader, SendStream};
//!
//! let map = ExtensionMap::default_video();
//! let mut tx = SendStream::new(0x1234, 90_000, Some(0x5678), 1000);
//! let mut rx = RecvStream::new(0x1234, 90_000, true);
//! let now = Instant::now();
//! let ext = ExtensionValues { mid: Some("0".into()), ..Default::default() };
//! let pkts: Vec<_> = (0..3)
//!     .map(|i| tx.write(now, 96, i == 2, 3000, b"frame", &ext, &map))
//!     .collect();
//! for p in [&pkts[0], &pkts[2]] {
//!     let h = RtpHeader::parse(p, &map).unwrap();
//!     assert_eq!(h.ext.mid.as_deref(), Some("0"));
//!     assert_eq!(h.payload(p), b"frame");
//!     rx.receive(now, h.sequence_number, h.timestamp);
//! }
//! // Packet 1001 is missing: after a short reordering wait it is NACKed...
//! let lost = rx.poll_nack(now + Duration::from_millis(30)).unwrap();
//! assert_eq!(lost, [1001]);
//! // ...and the sender answers with an RTX packet carrying the original sequence number.
//! let rtx = tx.resend(now, &lost, Some(97), &map);
//! let h = RtpHeader::parse(&rtx[0], &map).unwrap();
//! assert_eq!((h.ssrc, h.payload_type), (0x5678, 97));
//! assert_eq!(&h.payload(&rtx[0])[..2], &1001u16.to_be_bytes());
//! ```
//!
//! This is an implementation crate of `only` (docs/api-stability.md, Internal tier): its API
//! follows the needs of the WebRTC stack and may change in any release.

mod bwe;
pub mod codec;
mod packet;
mod rtcp;
mod stream;
mod twcc;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

#[cfg(test)]
mod tests;

pub use bwe::{BandwidthEstimator, BandwidthUsage, DEFAULT_MAX_BITRATE, DEFAULT_MIN_BITRATE};
pub use packet::{Extension, ExtensionMap, ExtensionValues, RtpHeader, abs_send_time, is_rtcp};
pub use rtcp::{
    Error, MAX_TWCC_STATUSES, ReportBlock, Rtcp, SenderInfo, TwccFeedback, compact_ntp, ntp_time,
    parse_compound, write_compound,
};
pub use stream::{RecvStream, SEND_HISTORY_AGE, SEND_HISTORY_PACKETS, SendStream};
pub use twcc::{PacketResult, TWCC_FEEDBACK_INTERVAL, TwccReceiver, TwccSender};
