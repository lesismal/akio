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
//!   (draft-holmer-rmcat-transport-wide-cc-extensions-01), TMMBR / TMMBN (RFC 5104 §4.2),
//!   RTP congestion control feedback (RFC 8888), extended reports with every RFC 3611 block
//!   ([`XrBlock`]), anything else as [`Rtcp::Unknown`].
//! - [`SendStream`]: sequence numbering, a retransmission history (1024 packets / 2 s),
//!   NACK responses as RTX (RFC 4588) or plain resends, sender reports, RTT from report
//!   blocks. [`RecvStream`]: sequence unwrapping, duplicate detection, loss and jitter
//!   (RFC 3550 A.3, A.8) for report blocks, NACK scheduling with reordering wait, RTT-paced
//!   repeats and give-up.
//! - [`TwccSender`] / [`TwccReceiver`]: transport-wide sequence numbers, feedback
//!   generation (libwebrtc's packing) and matching; [`CcfbSender`] / [`CcfbReceiver`]: the
//!   same for RFC 8888; [`BandwidthEstimator`]: a GCC-like delay-gradient + loss-based
//!   estimator fed by either, with libwebrtc-like probing ([`BandwidthEstimator::poll_probe`],
//!   [`SendStream::padding`], ADR-050).
//! - [`RrtrResponder`], [`RecvStream::handle_dlrr`], [`RecvStream::statistics_summary`],
//!   [`BurstLossModel`]: the XR receiver RTT exchange, statistics summaries and VoIP burst
//!   metrics. [`TmmbrHandler`] / [`bounding_set`]: TMMBR handling for a media sender.
//! - [`fec`]: ULPFEC (RFC 5109), FlexFEC (`flexfec-03` and RFC 8627) encoding and recovery,
//!   RED (RFC 2198).
//! - [`codec`]: payload packetizers / depacketizers and frame assembly.
//!
//! - [`SdesItem`]: typed SDES items (PRIV prefix / value, every registered type) and
//!   [`random_cname`] (RFC 7022); [`ReceiptLog`]: loss / duplicate RLE and receipt times XR
//!   blocks from received packets; [`BurstLossModel::report`]: complete VoIP metrics.
//!
//! Not implemented: SRTP (see `only-srtp`), RTP header extension encryption; see ADR-036 and
//! ADR-053 for what the FEC and XR support leaves out.
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
mod ccfb;
pub mod codec;
mod emodel;
pub mod fec;
mod packet;
mod probe;
mod rtcp;
mod sdes;
mod stream;
mod tmmbr;
mod twcc;
mod xr;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_ext;
#[cfg(test)]
mod tests_fec_policy;
#[cfg(test)]
mod tests_levels;
#[cfg(test)]
mod tests_probe;

pub use bwe::{
    BandwidthEstimator, BandwidthUsage, DEFAULT_MAX_BITRATE, DEFAULT_MIN_BITRATE, EcnResponse,
};
pub use ccfb::{CCFB_FEEDBACK_INTERVAL, CcfbReceiver, CcfbSender};
pub use emodel::{EModel, EModelScore, mos_from_r};
pub use packet::{Extension, ExtensionMap, ExtensionValues, RtpHeader, abs_send_time, is_rtcp};
pub use probe::ProbePacket;
pub use rtcp::{
    CCFB_ATO_OVERRANGE, CCFB_ATO_UNAVAILABLE, CCFB_MAX_REPORTS, CcfbFeedback, CcfbMetric,
    CcfbStream, Error, MAX_TWCC_STATUSES, ReportBlock, Rtcp, SenderInfo, TmmbItem, TwccFeedback,
    compact_ntp, ntp_time, parse_compound, write_compound,
};
pub use sdes::{SdesItem, random_cname};
pub use stream::{RecvStream, SEND_HISTORY_AGE, SEND_HISTORY_PACKETS, SendStream};
pub use tmmbr::{TMMBR_TIMEOUT, TmmbrHandler, bounded_bitrate, bounding_set};
pub use twcc::{PacketResult, TWCC_FEEDBACK_INTERVAL, TwccReceiver, TwccSender};
pub use xr::{
    BurstLossModel, DlrrItem, JitterBufferConfig, JitterStats, MAX_XR_SPAN, Plc, ReceiptLog,
    RleReport, RrtrResponder, StatisticsSummary, TtlStats, VOIP_UNAVAILABLE, VoipMetrics,
    VoipQuality, XrBlock, pcm_level_dbm0, rtt_from_dlrr,
};
