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
//!   [`BurstLossModel`] fed with the interval's loss trace, with the round-trip time and the
//!   R factor, MOS-LQ and MOS-CQ of the E-model ([`EModel`], ITU-T G.107 / G.107.1) from the
//!   loss so far, its burst ratio, the round-trip time and the end system delay (the
//!   application's, else its jitter buffer's nominal delay, else twice the interarrival
//!   jitter), with the received codec's planning values ([`EModel::for_codec`]). The
//!   receiver configuration's concealment is the codec's own ([`Plc::of_codec`]). What the
//!   application knows ([`Peer::set_voip_quality`](crate::Peer::set_voip_quality): levels,
//!   RERL, its jitter buffer, an external R factor, its own scores) goes in as given; the
//!   rest is sent unavailable (127).
//! - Receiving: the blocks about a stream this side sends become events.

use super::*;
use akio_rtp::{BurstLossModel, EModel, JitterBufferConfig, Plc, SdesItem, VoipQuality, XrBlock};

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

/// The VoIP quality fields of a report about a stream received on a line: what the
/// application gave (`app`) wins; the round-trip time is measured; the jitter buffer is
/// the audio jitter buffer's (`jb`) when there is one; the concealment is the received
/// codec's own when the application did not say; R, MOS-LQ and MOS-CQ come from the E-model
/// with the codec's planning values at its measured `bitrate` (`model` when the application
/// chose them, G.711 with concealment for a codec without any) and the loss so far of `m`.
#[allow(clippy::too_many_arguments)]
fn voip_quality(
    app: VoipQuality,
    model: Option<EModel>,
    codec: Option<&CodecParams>,
    bitrate: Option<u32>,
    rtt: Option<Duration>,
    jitter: Duration,
    jb: Option<JitterBufferConfig>,
    m: &BurstLossModel,
) -> VoipQuality {
    let name = codec.map_or("", |c| c.codec.name());
    let mut q = VoipQuality {
        round_trip: app.round_trip.or(rtt),
        plc: if app.plc == Plc::Unspecified {
            Plc::of_codec(name)
        } else {
            app.plc
        },
        jitter_buffer: app.jitter_buffer.or(jb),
        ..app
    };
    let model = model
        .or_else(|| EModel::for_codec_rate(name, q.plc, bitrate))
        .unwrap_or_default();
    let packet = Duration::from_millis(u64::from(VOIP_PACKET_MS));
    model.estimate_report(m, &q, jitter, packet).fill(&mut q);
    q
}

impl Rtc {
    /// Sets what the application knows of the VoIP quality of the streams received on `mid`
    /// and, with `model`, the E-model codec values. `false`: no such line.
    pub(crate) fn set_voip_quality(
        &mut self,
        mid: Mid,
        quality: VoipQuality,
        model: Option<EModel>,
    ) -> bool {
        let Some(l) = self.media.iter_mut().find(|l| l.mid == mid) else {
            return false;
        };
        l.voip = quality;
        l.voip_model = model;
        true
    }

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
            let pt = match (&r.jitter, &r.assembler) {
                (Some(j), _) => Some(j.pt),
                (None, Some((pt, _))) => Some(*pt),
                (None, None) => None,
            };
            let codec = pt.and_then(|pt| l.codec(pt));
            let clock = codec.map_or(48_000, |c| c.clock);
            let jitter = Duration::from_secs_f64(f64::from(r.stream.jitter()) / f64::from(clock));
            let Some(log) = r.stream.receipt_log().filter(|l| !l.is_empty()) else {
                continue;
            };
            let span = log.len();
            let mut xr = Vec::new();
            if blocks.contains(XrBlocks::VOIP_METRICS) {
                if let Some(XrBlock::LossRle(trace)) = log.loss_rle(0) {
                    // Received but discarded by the jitter buffer (late or overflow).
                    let mut discarded: Vec<u16> = r
                        .jitter
                        .as_mut()
                        .map(|j| j.buf.drain_discarded().map(|s| s as u16).collect())
                        .unwrap_or_default();
                    discarded.sort_unstable();
                    let m = r.burst.get_or_insert_with(BurstLossModel::default);
                    for (seq, received) in trace.decode() {
                        let dropped = received && discarded.binary_search(&seq).is_ok();
                        m.on_packet(!received, dropped);
                    }
                    // The codec's bitrate: payload bits per packet over the packet length
                    // (the frame length the jitter buffer measured, else 20 ms); packets of
                    // at most 2 bytes (Opus DTX) left out of the average.
                    let (bytes, packets) = std::mem::take(&mut r.audio_rate);
                    let frame = r
                        .jitter
                        .as_ref()
                        .and_then(|j| j.buf.frame_duration())
                        .unwrap_or_else(|| Duration::from_millis(u64::from(VOIP_PACKET_MS)));
                    let bitrate = (packets > 0 && !frame.is_zero()).then(|| {
                        (bytes as f64 * 8.0 / packets as f64 / frame.as_secs_f64()) as u32
                    });
                    let jb = r.jitter.as_ref().map(|j| j.buf.xr_config());
                    let q = voip_quality(l.voip, l.voip_model, codec, bitrate, rtt, jitter, jb, m);
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
