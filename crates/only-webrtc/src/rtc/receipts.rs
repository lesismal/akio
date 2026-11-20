//! RTCP XR blocks about received streams (RFC 3611 §4.1-4.3, §4.7, ADR-058) and received SDES
//! items.
//!
//! - Negotiation (§5.1): a line sends a block kind when both sides list its `a=rtcp-xr`
//!   format ([`RtcConfig::enable_rtcp_xr_blocks`](crate::RtcConfig::enable_rtcp_xr_blocks));
//!   VoIP metrics only on audio lines.
//! - Sending: each received stream of such a line keeps a receipt log
//!   ([`RecvStream::enable_receipt_log`]); with every report interval its loss RLE,
//!   duplicate RLE and receipt times blocks about the sequence numbers since the previous one
//!   go out, thinned (§4.1 T) so the compound fits a datagram, after an empty receiver
//!   report from the line's sender SSRC (RFC 3550 §6.1). VoIP metrics come from a
//!   [`BurstLossModel`] fed with the interval's loss trace, with the round-trip time as the
//!   only quality field known here.
//! - Receiving: the blocks about a stream this side sends become events.

use super::*;
use only_rtp::{BurstLossModel, SdesItem, VoipQuality, XrBlock};

/// Sequence numbers a receipt log keeps per interval.
pub(super) const RECEIPT_LOG_CAPACITY: usize = 4096;
/// Most sequence numbers one RLE block reports (a bit-vector chunk per 15: at most about
/// 200 bytes).
const MAX_RLE_SEQS: usize = 1500;
/// Most receipt times reported per interval (4 bytes each).
const MAX_RECEIPT_TIMES: usize = 96;
/// Bytes of XR blocks per compound packet.
const XR_BUDGET: usize = 900;
/// Media per packet assumed by the VoIP metrics' burst and gap durations (the usual ptime).
const VOIP_PACKET_MS: u16 = 20;
/// Remote sources whose SDES items are remembered.
const MAX_SDES_SOURCES: usize = 64;

/// The blocks a line of `kind` offers out of `blocks`: VoIP metrics on audio only.
pub(super) fn line_xr_blocks(blocks: XrBlocks, kind: MediaKind) -> XrBlocks {
    if kind == MediaKind::Audio {
        blocks
    } else {
        blocks & (XrBlocks::LOSS_RLE | XrBlocks::DUPLICATE_RLE | XrBlocks::RECEIPT_TIMES)
    }
}

/// The blocks both sides listed for a remote media section.
pub(super) fn remote_xr_blocks(cfg: &ConfigInner, m: &Media, kind: MediaKind) -> XrBlocks {
    line_xr_blocks(cfg.xr_blocks, kind) & XrBlocks::from_sdp(m.all("rtcp-xr"))
}

/// The smallest thinning (0..=15) that reports at most `max` of `span` sequence numbers.
fn thinning(span: usize, max: usize) -> u8 {
    (0..15u8).find(|t| (span >> t) <= max).unwrap_or(15)
}

/// The size of a block on the wire.
fn block_size(b: &XrBlock) -> usize {
    match b {
        XrBlock::LossRle(r) | XrBlock::DuplicateRle(r) => {
            12 + 2 * r.chunks.len().next_multiple_of(2)
        }
        XrBlock::PacketReceiptTimes { times, .. } => 12 + 4 * times.len(),
        _ => 36,
    }
}

impl Rtc {
    /// The XR compounds about every received stream with blocks negotiated; ends their
    /// receipt logs' intervals.
    pub(super) fn receipt_reports(&mut self) -> Vec<Vec<Rtcp>> {
        let mut out = Vec::new();
        for r in self.recv.values_mut() {
            let Some(l) = self.media.get(r.line) else {
                continue;
            };
            let blocks = l.xr_blocks;
            if blocks.is_empty() || l.stopped {
                continue;
            }
            let sender = l.send.ssrc();
            if r.stream.receipt_log().is_none() {
                // Negotiated after the stream started: reports from the next interval.
                r.stream.enable_receipt_log(RECEIPT_LOG_CAPACITY);
                continue;
            }
            let rtt = r.stream.rtt();
            let Some(log) = r.stream.receipt_log().filter(|l| !l.is_empty()) else {
                continue;
            };
            let span = log.len();
            let mut xr = Vec::new();
            if blocks.contains(XrBlocks::VOIP_METRICS) {
                if let Some(XrBlock::LossRle(trace)) = log.loss_rle(0) {
                    let m = r.burst.get_or_insert_with(BurstLossModel::default);
                    for (_, received) in trace.decode() {
                        m.on_packet(!received, false);
                    }
                    let q = VoipQuality {
                        round_trip: rtt,
                        ..VoipQuality::default()
                    };
                    xr.push(XrBlock::VoipMetrics(m.report(
                        log.ssrc(),
                        VOIP_PACKET_MS,
                        &q,
                    )));
                }
            }
            let t = thinning(span, MAX_RLE_SEQS);
            if blocks.contains(XrBlocks::LOSS_RLE) {
                xr.extend(log.loss_rle(t));
            }
            if blocks.contains(XrBlocks::DUPLICATE_RLE) {
                xr.extend(log.duplicate_rle(t));
            }
            if blocks.contains(XrBlocks::RECEIPT_TIMES) {
                xr.extend(log.receipt_times(thinning(span, MAX_RECEIPT_TIMES)));
            }
            let mut size = 0;
            xr.retain(|b| {
                size += block_size(b);
                size <= XR_BUDGET
            });
            // Ends the interval.
            r.stream.receipt_blocks(0, false, false, false);
            if !xr.is_empty() {
                out.push(vec![
                    Rtcp::ReceiverReport {
                        ssrc: sender,
                        reports: Vec::new(),
                    },
                    Rtcp::ExtendedReport {
                        ssrc: sender,
                        blocks: xr,
                    },
                ]);
            }
        }
        out
    }

    /// The receipt and VoIP metrics blocks of a received XR from `reporter`, about streams
    /// this side sends.
    pub(super) fn handle_receipts(&mut self, reporter: u32, blocks: &[XrBlock]) {
        // (sent SSRC, received, lost, duplicated, receipt times)
        let mut sums: Vec<(u32, u64, u64, u64, u64)> = Vec::new();
        fn entry(sums: &mut Vec<(u32, u64, u64, u64, u64)>, ssrc: u32) -> usize {
            match sums.iter().position(|s| s.0 == ssrc) {
                Some(i) => i,
                None => {
                    sums.push((ssrc, 0, 0, 0, 0));
                    sums.len() - 1
                }
            }
        }
        for b in blocks {
            match b {
                XrBlock::LossRle(r) => {
                    let i = entry(&mut sums, r.ssrc);
                    for (_, got) in r.decode() {
                        if got {
                            sums[i].1 += 1;
                        } else {
                            sums[i].2 += 1;
                        }
                    }
                }
                XrBlock::DuplicateRle(r) => {
                    let i = entry(&mut sums, r.ssrc);
                    sums[i].3 += r.decode().iter().filter(|(_, single)| !single).count() as u64;
                }
                XrBlock::PacketReceiptTimes { ssrc, times, .. } => {
                    let i = entry(&mut sums, *ssrc);
                    sums[i].4 += times.len() as u64;
                }
                XrBlock::VoipMetrics(m) => {
                    if let Some(mid) = self.mid_sending(m.ssrc) {
                        self.events.push_back(RtcEvent::Other(Other::VoipMetrics {
                            mid,
                            reporter,
                            metrics: *m,
                        }));
                    }
                }
                _ => {}
            }
        }
        for (ssrc, received, lost, duplicated, receipt_times) in sums {
            let Some(mid) = self.mid_sending(ssrc) else {
                continue;
            };
            self.stats.xr_received += received;
            self.stats.xr_lost += lost;
            self.stats.xr_duplicated += duplicated;
            self.events.push_back(RtcEvent::Other(Other::XrReceipts {
                mid,
                ssrc,
                reporter,
                received,
                lost,
                duplicated,
                receipt_times,
            }));
        }
    }

    /// The line that sends `ssrc`.
    fn mid_sending(&self, ssrc: u32) -> Option<Mid> {
        self.media
            .iter()
            .find(|l| l.send_of(ssrc).is_some())
            .map(|l| l.mid)
    }

    /// Received SDES chunks: the typed items of each source, reported when they change.
    pub(super) fn handle_sdes(&mut self, chunks: &[(u32, Vec<(u8, String)>)]) {
        for (ssrc, items) in chunks {
            let typed: Vec<SdesItem> = items
                .iter()
                .map(|(t, s)| SdesItem::from_pair(*t, s))
                .collect();
            if self.remote_sdes.get(ssrc) == Some(&typed) {
                continue;
            }
            if self.remote_sdes.len() >= MAX_SDES_SOURCES && !self.remote_sdes.contains_key(ssrc) {
                continue;
            }
            self.remote_sdes.insert(*ssrc, typed.clone());
            self.events
                .push_back(RtcEvent::Other(Other::SourceDescription {
                    ssrc: *ssrc,
                    items: typed,
                }));
        }
    }
}
