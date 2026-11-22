//! RTCP extended reports (RFC 3611): the report blocks, the receiver-side RTT exchange
//! (receiver reference time + DLRR, §4.4 / §4.5) and the VoIP burst model (Appendix A.2).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::rtcp::compact_ntp;

/// Block types.
const LOSS_RLE: u8 = 1;
const DUPLICATE_RLE: u8 = 2;
const RECEIPT_TIMES: u8 = 3;
const RRTR: u8 = 4;
const DLRR: u8 = 5;
const STATS: u8 = 6;
const VOIP: u8 = 7;

/// Largest block body (the block length field counts 32-bit words in 16 bits).
const MAX_BLOCK_BODY: usize = 0xffff * 4;

/// A run-length report (loss RLE, BT 1, or duplicate RLE, BT 2; RFC 3611 §4.1, §4.2).
///
/// `chunks` are the raw 16-bit chunks (run-length chunks `0 | type | 14-bit run`, bit-vector
/// chunks `1 | 15 bits`); a trailing null chunk (0) is padding and is dropped by the parser.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RleReport {
    /// The source reported on.
    pub ssrc: u32,
    /// Thinning (T, 0..=15): only every 2^T-th sequence number is reported.
    pub thinning: u8,
    /// First sequence number of the interval.
    pub begin_seq: u16,
    /// Last sequence number of the interval plus one.
    pub end_seq: u16,
    /// The chunks.
    pub chunks: Vec<u16>,
}

/// One DLRR sub-block (RFC 3611 §4.5): the answer to a receiver reference time block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DlrrItem {
    /// The receiver that sent the RRTR.
    pub ssrc: u32,
    /// Middle 32 bits of the RRTR's NTP timestamp (0: none received).
    pub last_rr: u32,
    /// Delay since that RRTR arrived, in 1/65536 s.
    pub delay_since_last_rr: u32,
}

/// Jitter statistics of a statistics summary, in timestamp units.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    /// Minimum relative transit time difference.
    pub min: u32,
    /// Maximum.
    pub max: u32,
    /// Mean.
    pub mean: u32,
    /// Standard deviation.
    pub dev: u32,
}

/// TTL / hop limit statistics of a statistics summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TtlStats {
    /// `false`: IPv4 TTL values (ToH 1); `true`: IPv6 hop limits (ToH 2).
    pub hop_limit: bool,
    /// Minimum.
    pub min: u8,
    /// Maximum.
    pub max: u8,
    /// Mean.
    pub mean: u8,
    /// Standard deviation.
    pub dev: u8,
}

/// Statistics summary block (BT 6, RFC 3611 §4.6). `None` fields are not reported (their
/// flag is clear on the wire).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatisticsSummary {
    /// The source reported on.
    pub ssrc: u32,
    /// First sequence number of the interval.
    pub begin_seq: u16,
    /// Last sequence number of the interval plus one.
    pub end_seq: u16,
    /// Packets lost in the interval.
    pub lost_packets: Option<u32>,
    /// Duplicate packets in the interval.
    pub dup_packets: Option<u32>,
    /// Jitter statistics.
    pub jitter: Option<JitterStats>,
    /// TTL or hop limit statistics.
    pub ttl: Option<TtlStats>,
}

/// VoIP metrics block (BT 7, RFC 3611 §4.7), raw field values: rates and densities are
/// fractions in 1/256, durations and delays in milliseconds, levels in signed dB (127 =
/// unavailable), R factors 0..=100 (127 = unavailable), MOS ×10 (127 = unavailable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct VoipMetrics {
    /// The source reported on.
    pub ssrc: u32,
    pub loss_rate: u8,
    pub discard_rate: u8,
    pub burst_density: u8,
    pub gap_density: u8,
    pub burst_duration: u16,
    pub gap_duration: u16,
    pub round_trip_delay: u16,
    pub end_system_delay: u16,
    pub signal_level: u8,
    pub noise_level: u8,
    /// Residual echo return loss.
    pub rerl: u8,
    /// The gap threshold (16 recommended).
    pub gmin: u8,
    pub r_factor: u8,
    pub ext_r_factor: u8,
    pub mos_lq: u8,
    pub mos_cq: u8,
    /// Receiver configuration byte (PLC, jitter buffer adaptive / rate).
    pub rx_config: u8,
    pub jb_nominal: u16,
    pub jb_maximum: u16,
    pub jb_abs_max: u16,
}

/// One report block of an extended report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrBlock {
    /// Loss RLE (BT 1): run-length coded received / lost packets.
    LossRle(RleReport),
    /// Duplicate RLE (BT 2): run-length coded duplicates.
    DuplicateRle(RleReport),
    /// Packet receipt times (BT 3, §4.3).
    PacketReceiptTimes {
        /// The source reported on.
        ssrc: u32,
        /// Thinning (0..=15).
        thinning: u8,
        /// First sequence number.
        begin_seq: u16,
        /// Last sequence number plus one.
        end_seq: u16,
        /// Receipt times in timestamp units, one per reported sequence number.
        times: Vec<u32>,
    },
    /// Receiver reference time (BT 4, §4.4): the 64-bit NTP time at which it was sent.
    ReceiverReferenceTime {
        /// NTP time ([`ntp_time`](crate::ntp_time)).
        ntp: u64,
    },
    /// DLRR (BT 5, §4.5).
    Dlrr(Vec<DlrrItem>),
    /// Statistics summary (BT 6).
    StatisticsSummary(StatisticsSummary),
    /// VoIP metrics (BT 7).
    VoipMetrics(VoipMetrics),
    /// Any other block: type, type-specific byte and body (a multiple of four bytes; the
    /// writer pads it).
    Unknown {
        /// Block type.
        block_type: u8,
        /// Type-specific byte.
        type_specific: u8,
        /// Body after the block header.
        data: Vec<u8>,
    },
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Parses the blocks of an XR body (after the sender SSRC). `None` if a block runs past the
/// end or a fixed-size block has the wrong length.
pub(crate) fn parse_blocks(mut b: &[u8]) -> Option<Vec<XrBlock>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let h = b.get(..4)?;
        let (bt, ts) = (h[0], h[1]);
        let len = 4 * usize::from(be16(h, 2));
        let d = b.get(4..4 + len)?;
        b = &b[4 + len..];
        out.push(match bt {
            LOSS_RLE | DUPLICATE_RLE | RECEIPT_TIMES => {
                if d.len() < 8 {
                    return None;
                }
                let (ssrc, begin_seq, end_seq) = (be32(d, 0), be16(d, 4), be16(d, 6));
                let thinning = ts & 0x0f;
                if bt == RECEIPT_TIMES {
                    XrBlock::PacketReceiptTimes {
                        ssrc,
                        thinning,
                        begin_seq,
                        end_seq,
                        times: d[8..].chunks_exact(4).map(|c| be32(c, 0)).collect(),
                    }
                } else {
                    let mut chunks: Vec<u16> = d[8..].chunks_exact(2).map(|c| be16(c, 0)).collect();
                    while chunks.last() == Some(&0) {
                        chunks.pop();
                    }
                    let r = RleReport {
                        ssrc,
                        thinning,
                        begin_seq,
                        end_seq,
                        chunks,
                    };
                    if bt == LOSS_RLE {
                        XrBlock::LossRle(r)
                    } else {
                        XrBlock::DuplicateRle(r)
                    }
                }
            }
            RRTR => {
                if d.len() != 8 {
                    return None;
                }
                XrBlock::ReceiverReferenceTime {
                    ntp: (u64::from(be32(d, 0)) << 32) | u64::from(be32(d, 4)),
                }
            }
            DLRR => {
                if d.len() % 12 != 0 {
                    return None;
                }
                XrBlock::Dlrr(
                    d.chunks_exact(12)
                        .map(|c| DlrrItem {
                            ssrc: be32(c, 0),
                            last_rr: be32(c, 4),
                            delay_since_last_rr: be32(c, 8),
                        })
                        .collect(),
                )
            }
            STATS => {
                if d.len() != 36 {
                    return None;
                }
                let toh = (ts >> 3) & 3;
                XrBlock::StatisticsSummary(StatisticsSummary {
                    ssrc: be32(d, 0),
                    begin_seq: be16(d, 4),
                    end_seq: be16(d, 6),
                    lost_packets: (ts & 0x80 != 0).then(|| be32(d, 8)),
                    dup_packets: (ts & 0x40 != 0).then(|| be32(d, 12)),
                    jitter: (ts & 0x20 != 0).then(|| JitterStats {
                        min: be32(d, 16),
                        max: be32(d, 20),
                        mean: be32(d, 24),
                        dev: be32(d, 28),
                    }),
                    // ToH 3 is undefined: treated as not reported.
                    ttl: matches!(toh, 1 | 2).then(|| TtlStats {
                        hop_limit: toh == 2,
                        min: d[32],
                        max: d[33],
                        mean: d[34],
                        dev: d[35],
                    }),
                })
            }
            VOIP => {
                if d.len() != 32 {
                    return None;
                }
                XrBlock::VoipMetrics(VoipMetrics {
                    ssrc: be32(d, 0),
                    loss_rate: d[4],
                    discard_rate: d[5],
                    burst_density: d[6],
                    gap_density: d[7],
                    burst_duration: be16(d, 8),
                    gap_duration: be16(d, 10),
                    round_trip_delay: be16(d, 12),
                    end_system_delay: be16(d, 14),
                    signal_level: d[16],
                    noise_level: d[17],
                    rerl: d[18],
                    gmin: d[19],
                    r_factor: d[20],
                    ext_r_factor: d[21],
                    mos_lq: d[22],
                    mos_cq: d[23],
                    rx_config: d[24],
                    jb_nominal: be16(d, 26),
                    jb_maximum: be16(d, 28),
                    jb_abs_max: be16(d, 30),
                })
            }
            _ => XrBlock::Unknown {
                block_type: bt,
                type_specific: ts,
                data: d.to_vec(),
            },
        });
    }
    Some(out)
}

fn block(out: &mut Vec<u8>, bt: u8, ts: u8, body: &[u8]) {
    let body = &body[..body.len().min(MAX_BLOCK_BODY)];
    let pad = (4 - body.len() % 4) % 4;
    out.push(bt);
    out.push(ts);
    out.extend_from_slice(&(((body.len() + pad) / 4) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + pad, 0);
}

fn seq_range(b: &mut Vec<u8>, ssrc: u32, begin: u16, end: u16) {
    b.extend_from_slice(&ssrc.to_be_bytes());
    b.extend_from_slice(&begin.to_be_bytes());
    b.extend_from_slice(&end.to_be_bytes());
}

/// Serializes blocks (lists too long for a block's 16-bit length are truncated).
pub(crate) fn write_blocks(blocks: &[XrBlock], out: &mut Vec<u8>) {
    for blk in blocks {
        let mut b = Vec::new();
        match blk {
            XrBlock::LossRle(r) | XrBlock::DuplicateRle(r) => {
                seq_range(&mut b, r.ssrc, r.begin_seq, r.end_seq);
                let n = r.chunks.len().min((MAX_BLOCK_BODY - 8) / 2);
                r.chunks[..n]
                    .iter()
                    .for_each(|c| b.extend_from_slice(&c.to_be_bytes()));
                let bt = if matches!(blk, XrBlock::LossRle(_)) {
                    LOSS_RLE
                } else {
                    DUPLICATE_RLE
                };
                // An odd chunk count is padded with a null chunk.
                block(out, bt, r.thinning & 0x0f, &b);
            }
            XrBlock::PacketReceiptTimes {
                ssrc,
                thinning,
                begin_seq,
                end_seq,
                times,
            } => {
                seq_range(&mut b, *ssrc, *begin_seq, *end_seq);
                let n = times.len().min((MAX_BLOCK_BODY - 8) / 4);
                times[..n]
                    .iter()
                    .for_each(|t| b.extend_from_slice(&t.to_be_bytes()));
                block(out, RECEIPT_TIMES, thinning & 0x0f, &b);
            }
            XrBlock::ReceiverReferenceTime { ntp } => block(out, RRTR, 0, &ntp.to_be_bytes()),
            XrBlock::Dlrr(items) => {
                for i in items.iter().take(MAX_BLOCK_BODY / 12) {
                    b.extend_from_slice(&i.ssrc.to_be_bytes());
                    b.extend_from_slice(&i.last_rr.to_be_bytes());
                    b.extend_from_slice(&i.delay_since_last_rr.to_be_bytes());
                }
                block(out, DLRR, 0, &b);
            }
            XrBlock::StatisticsSummary(s) => {
                let mut ts = 0u8;
                seq_range(&mut b, s.ssrc, s.begin_seq, s.end_seq);
                if let Some(l) = s.lost_packets {
                    ts |= 0x80;
                    b.extend_from_slice(&l.to_be_bytes());
                } else {
                    b.extend_from_slice(&[0; 4]);
                }
                if let Some(d) = s.dup_packets {
                    ts |= 0x40;
                    b.extend_from_slice(&d.to_be_bytes());
                } else {
                    b.extend_from_slice(&[0; 4]);
                }
                let j = s.jitter.unwrap_or_default();
                if s.jitter.is_some() {
                    ts |= 0x20;
                }
                for v in [j.min, j.max, j.mean, j.dev] {
                    b.extend_from_slice(&v.to_be_bytes());
                }
                match s.ttl {
                    Some(t) => {
                        ts |= if t.hop_limit { 2 << 3 } else { 1 << 3 };
                        b.extend_from_slice(&[t.min, t.max, t.mean, t.dev]);
                    }
                    None => b.extend_from_slice(&[0; 4]),
                }
                block(out, STATS, ts, &b);
            }
            XrBlock::VoipMetrics(v) => {
                b.extend_from_slice(&v.ssrc.to_be_bytes());
                b.extend_from_slice(&[v.loss_rate, v.discard_rate, v.burst_density, v.gap_density]);
                for x in [
                    v.burst_duration,
                    v.gap_duration,
                    v.round_trip_delay,
                    v.end_system_delay,
                ] {
                    b.extend_from_slice(&x.to_be_bytes());
                }
                b.extend_from_slice(&[v.signal_level, v.noise_level, v.rerl, v.gmin]);
                b.extend_from_slice(&[v.r_factor, v.ext_r_factor, v.mos_lq, v.mos_cq]);
                b.extend_from_slice(&[v.rx_config, 0]);
                for x in [v.jb_nominal, v.jb_maximum, v.jb_abs_max] {
                    b.extend_from_slice(&x.to_be_bytes());
                }
                block(out, VOIP, 0, &b);
            }
            XrBlock::Unknown {
                block_type,
                type_specific,
                data,
            } => block(out, *block_type, *type_specific, data),
        }
    }
}

/// The round-trip time from a DLRR sub-block received at NTP time `ntp_now` (RFC 3611
/// §4.5: `now - LRR - DLRR`), or `None` if it carries no LRR or the result is negative or
/// more than a minute (clock trouble).
#[must_use]
pub fn rtt_from_dlrr(ntp_now: u64, item: &DlrrItem) -> Option<Duration> {
    if item.last_rr == 0 {
        return None;
    }
    let rtt = compact_ntp(ntp_now)
        .wrapping_sub(item.last_rr)
        .wrapping_sub(item.delay_since_last_rr);
    (rtt < 60 << 16).then(|| Duration::from_micros((u64::from(rtt) * 1_000_000) >> 16))
}

/// Receivers whose receiver reference times are answered.
const MAX_RRTR_SOURCES: usize = 32;
/// Receiver reference times older than this are no longer answered.
const RRTR_MAX_AGE: Duration = Duration::from_secs(60);

/// The media sender's side of the XR round-trip exchange: remembers the last receiver
/// reference time (RRTR) of each receiver and answers them with a DLRR block, so receivers
/// that send no sender reports can measure the RTT (with [`rtt_from_dlrr`] or
/// [`RecvStream::handle_dlrr`](crate::RecvStream::handle_dlrr)).
#[derive(Debug, Default)]
pub struct RrtrResponder {
    last: BTreeMap<u32, (u32, Instant)>,
}

impl RrtrResponder {
    /// An empty responder.
    #[must_use]
    pub fn new() -> RrtrResponder {
        RrtrResponder::default()
    }

    /// Records the receiver reference time `ntp` in an XR from `ssrc`, received at `now`.
    /// At most 32 receivers are kept (the least recently heard one is dropped).
    pub fn on_rrtr(&mut self, now: Instant, ssrc: u32, ntp: u64) {
        self.last.insert(ssrc, (compact_ntp(ntp), now));
        if self.last.len() > MAX_RRTR_SOURCES {
            if let Some((&old, _)) = self.last.iter().min_by_key(|(_, (_, at))| *at) {
                self.last.remove(&old);
            }
        }
    }

    /// A DLRR block answering every receiver heard in the last minute, or `None`.
    pub fn dlrr(&mut self, now: Instant) -> Option<XrBlock> {
        self.last
            .retain(|_, (_, at)| now.saturating_duration_since(*at) <= RRTR_MAX_AGE);
        let items: Vec<DlrrItem> = self
            .last
            .iter()
            .map(|(&ssrc, &(lrr, at))| {
                let d = (now.saturating_duration_since(at).as_micros() << 16) / 1_000_000;
                DlrrItem {
                    ssrc,
                    last_rr: lrr,
                    delay_since_last_rr: d.min(u128::from(u32::MAX)) as u32,
                }
            })
            .collect();
        (!items.is_empty()).then_some(XrBlock::Dlrr(items))
    }
}

/// Unknown value of the VoIP metrics level, R factor and MOS fields.
pub const VOIP_UNAVAILABLE: u8 = 127;

/// The burst / gap loss model of RFC 3611 Appendix A.2 (from ETSI TS 101 329-5), producing
/// the loss, discard, burst and gap fields of [`VoipMetrics`]. The call starts in a gap (as
/// in the §4.7.2 example, which this reproduces): the first loss is judged as if at least
/// Gmin packets preceded it.
#[derive(Debug, Clone)]
pub struct BurstLossModel {
    gmin: u32,
    start: bool,
    pkt: u64,
    lost: u64,
    loss_count: u64,
    discard_count: u64,
    c11: u64,
    c13: u64,
    c14: u64,
    c22: u64,
    c23: u64,
    c33: u64,
    /// Packets recorded.
    total: u64,
}

impl Default for BurstLossModel {
    fn default() -> BurstLossModel {
        BurstLossModel::new(16)
    }
}

impl BurstLossModel {
    /// A model with gap threshold `gmin` (16 is recommended; at least 1).
    #[must_use]
    pub fn new(gmin: u8) -> BurstLossModel {
        BurstLossModel {
            gmin: u32::from(gmin.max(1)),
            start: true,
            pkt: 0,
            lost: 1,
            loss_count: 0,
            discard_count: 0,
            c11: 0,
            c13: 0,
            c14: 0,
            c22: 0,
            c23: 0,
            c33: 0,
            total: 0,
        }
    }

    /// Records the next expected packet: received and played, lost, or received but
    /// discarded by the jitter buffer.
    pub fn on_packet(&mut self, lost: bool, discarded: bool) {
        self.total += 1;
        if lost {
            self.loss_count += 1;
        }
        if discarded {
            self.discard_count += 1;
        }
        if !lost && !discarded {
            self.pkt += 1;
            return;
        }
        if self.pkt >= u64::from(self.gmin) || std::mem::take(&mut self.start) {
            if self.lost == 1 {
                self.c14 += 1;
            } else {
                self.c13 += 1;
            }
            self.lost = 1;
            self.c11 += self.pkt;
        } else {
            self.lost += 1;
            if self.pkt == 0 {
                self.c33 += 1;
            } else {
                self.c23 += 1;
                self.c22 += self.pkt - 1;
            }
        }
        self.pkt = 0;
    }

    /// The fraction of the packets recorded that were lost or discarded.
    #[must_use]
    pub fn loss_fraction(&self) -> f64 {
        let bad = (self.loss_count + self.discard_count).min(self.total);
        if self.total == 0 {
            0.0
        } else {
            bad as f64 / self.total as f64
        }
    }

    /// The burst ratio of ITU-T G.107 (BurstR, for [`EModel`](crate::EModel)): the mean
    /// length of the runs of lost (or discarded) packets over the one random loss of the
    /// same rate would give, `(1 - loss) x mean run`; 1 for random loss (and with no loss),
    /// above 1 when losses come in bursts.
    #[must_use]
    pub fn burst_ratio(&self) -> f64 {
        let bad = (self.loss_count + self.discard_count).min(self.total);
        if bad == 0 || bad == self.total {
            return 1.0;
        }
        // A loss right after a loss (c33) continues a run.
        let runs = bad.saturating_sub(self.c33).max(1);
        let mean_run = bad as f64 / runs as f64;
        ((1.0 - self.loss_fraction()) * mean_run).max(0.1)
    }

    /// The metrics so far for `ssrc`, with `packet_ms` milliseconds of media per packet;
    /// the delay, level, quality and jitter buffer fields are left unknown / zero for the
    /// caller to fill.
    #[must_use]
    pub fn metrics(&self, ssrc: u32, packet_ms: u16) -> VoipMetrics {
        // The pending run of received packets belongs to the current gap.
        let c11 = self.c11 + self.pkt;
        let (c31, c32) = (self.c13, self.c23);
        let ctotal = c11 + self.c14 + self.c13 + self.c22 + self.c23 + c31 + c32 + self.c33;
        let frac = |n: u64, d: u64| (256 * n).checked_div(d).map_or(0, |v| v.min(255) as u8);
        let p32 = if c31 + c32 + self.c33 == 0 {
            0.0
        } else {
            c32 as f64 / (c31 + c32 + self.c33) as f64
        };
        let p23 = if self.c22 + self.c23 < 1 {
            1.0
        } else {
            1.0 - self.c22 as f64 / (self.c22 + self.c23) as f64
        };
        let burst_density = if self.c13 == 0 {
            0
        } else {
            (256.0 * p23 / (p23 + p32)).min(255.0) as u8
        };
        let m = f64::from(packet_ms);
        let (gap_ms, burst_ms) = if self.c13 == 0 {
            // No burst yet: the whole call is one gap.
            (ctotal as f64 * m, 0.0)
        } else {
            let gap = (c11 + self.c14 + self.c13) as f64 * m / self.c13 as f64;
            (gap, (ctotal as f64 * m / self.c13 as f64 - gap).max(0.0))
        };
        VoipMetrics {
            ssrc,
            loss_rate: frac(self.loss_count, ctotal),
            discard_rate: frac(self.discard_count, ctotal),
            burst_density,
            gap_density: frac(self.c14, c11 + self.c14),
            burst_duration: burst_ms.min(65535.0) as u16,
            gap_duration: gap_ms.min(65535.0) as u16,
            signal_level: VOIP_UNAVAILABLE,
            noise_level: VOIP_UNAVAILABLE,
            rerl: VOIP_UNAVAILABLE,
            gmin: self.gmin as u8,
            r_factor: VOIP_UNAVAILABLE,
            ext_r_factor: VOIP_UNAVAILABLE,
            mos_lq: VOIP_UNAVAILABLE,
            mos_cq: VOIP_UNAVAILABLE,
            ..VoipMetrics::default()
        }
    }
}

/// Longest run a run-length chunk holds.
const MAX_RUN: usize = 0x3fff;

impl RleReport {
    /// Encodes a trace (one value per reported sequence number, in order) as chunks: a run
    /// of 15 or more equal values, or one reaching the end of the trace, becomes run-length
    /// chunks, anything else 15-bit vectors (bits past the end zero). The writer adds the
    /// null chunk that rounds an odd count out. This gives the second encoding of the RFC
    /// 3611 §4.1 examples.
    #[must_use]
    pub fn encode(trace: &[bool]) -> Vec<u16> {
        let mut chunks = Vec::new();
        let mut i = 0;
        while i < trace.len() {
            let v = trace[i];
            let run = trace[i..].iter().take_while(|&&x| x == v).count();
            if run >= 15 || i + run == trace.len() {
                let n = run.min(MAX_RUN);
                chunks.push(u16::from(v) << 14 | n as u16);
                i += n;
            } else {
                let mut c = 0x8000u16;
                for (b, &x) in trace[i..].iter().take(15).enumerate() {
                    c |= u16::from(x) << (14 - b);
                }
                chunks.push(c);
                i += 15;
            }
        }
        chunks
    }

    /// The sequence numbers reported on, in order: those in `begin_seq..end_seq` (with
    /// wraparound) that are multiples of 2^`thinning`.
    pub fn reported_seqs(&self) -> impl Iterator<Item = u16> {
        reported(self.thinning, self.begin_seq, self.end_seq)
    }

    /// Decodes the chunks into `(sequence number, value)` pairs for the reported sequence
    /// numbers (loss RLE: `true` = received; duplicate RLE: `true` = no duplicate). Stops at
    /// whichever of the chunks and the interval ends first.
    #[must_use]
    pub fn decode(&self) -> Vec<(u16, bool)> {
        let mut values = Vec::new();
        for &c in &self.chunks {
            if c & 0x8000 != 0 {
                values.extend((0..15).map(|b| c & (1 << (14 - b)) != 0));
            } else {
                let n = usize::from(c & 0x3fff);
                values.extend(std::iter::repeat_n(c & 0x4000 != 0, n));
            }
        }
        self.reported_seqs().zip(values).collect()
    }
}

/// The sequence numbers in `begin..end` (wrapping) that are multiples of 2^`thinning`.
fn reported(thinning: u8, begin: u16, end: u16) -> impl Iterator<Item = u16> {
    let step = 1u32 << (thinning & 0x0f);
    let span = u32::from(end.wrapping_sub(begin));
    let first = u32::from(begin).div_ceil(step) * step;
    let skip = first - u32::from(begin);
    (skip..span)
        .step_by(step as usize)
        .map(move |o| begin.wrapping_add(o as u16))
}

/// What a [`ReceiptLog`] knows about one sequence number.
#[derive(Debug, Clone, Copy, Default)]
struct Receipt {
    received: bool,
    duplicate: bool,
    /// Receipt time of the first copy, in RTP timestamp units.
    time: u32,
}

/// Most sequence numbers one RLE block may span (RFC 3611 §4.1: less than 65534).
pub const MAX_XR_SPAN: usize = 65_533;

/// A per-sequence-number log of one source's packets for the RFC 3611 loss RLE (§4.1),
/// duplicate RLE (§4.2) and packet receipt times (§4.3) blocks, over a reporting interval
/// from the first packet (or the end of the previous interval) to the highest sequence
/// number received.
///
/// Sequence numbers are unwrapped as §4.1 / Appendix A.1 require (within 32768 of the last
/// one, ties without rollover). Receipt times are the arrival times in the source's RTP
/// clock, anchored at the first packet's RTP timestamp, so send and receipt times of a
/// packet are comparable (their difference is the one-way delay plus a constant). FEC-
/// rebuilt packets are not fed in, so they count as lost (as in receiver reports).
/// [`RecvStream::enable_receipt_log`](crate::RecvStream::enable_receipt_log) keeps one
/// fed with the stream's packets.
#[derive(Debug, Clone)]
pub struct ReceiptLog {
    ssrc: u32,
    clock_rate: u32,
    capacity: usize,
    anchor: Option<(Instant, u32)>,
    last: Option<u64>,
    begin: u64,
    log: std::collections::VecDeque<Receipt>,
}

impl ReceiptLog {
    /// A log for source `ssrc` with RTP clock rate `clock_rate` (Hz), keeping at most
    /// `capacity` sequence numbers per interval (clamped to 1..=[`MAX_XR_SPAN`]; older ones
    /// are dropped from the start of the interval).
    #[must_use]
    pub fn new(ssrc: u32, clock_rate: u32, capacity: usize) -> ReceiptLog {
        ReceiptLog {
            ssrc,
            clock_rate: clock_rate.max(1),
            capacity: capacity.clamp(1, MAX_XR_SPAN),
            anchor: None,
            last: None,
            begin: 0,
            log: std::collections::VecDeque::new(),
        }
    }

    /// The source reported on.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Records a packet with sequence number `seq` and RTP timestamp `timestamp` received at
    /// `now` (duplicates included). Packets from before the interval are ignored.
    pub fn on_packet(&mut self, now: Instant, seq: u16, timestamp: u32) {
        let (t0, ts0) = *self.anchor.get_or_insert((now, timestamp));
        let ext = match self.last {
            None => {
                self.begin = (1 << 32) + u64::from(seq);
                self.begin
            }
            Some(last) => {
                let d = seq.wrapping_sub(last as u16);
                if d == 0x8000 {
                    // Equally far both ways: the choice without a rollover.
                    if u32::from(last as u16) < 0x8000 {
                        last + 0x8000
                    } else {
                        last - 0x8000
                    }
                } else {
                    (last as i64 + i64::from(d as i16)) as u64
                }
            }
        };
        if self.last.is_none_or(|l| ext > l) {
            self.last = Some(ext);
        }
        if ext < self.begin {
            return;
        }
        let i = (ext - self.begin) as usize;
        if i >= self.log.len() {
            if i >= self.capacity {
                let drop = i + 1 - self.capacity;
                if drop >= self.log.len() {
                    self.log.clear();
                } else {
                    self.log.drain(..drop);
                }
                self.begin += drop as u64;
            }
            let i = (ext - self.begin) as usize;
            self.log.resize(i + 1, Receipt::default());
        }
        let ticks =
            now.saturating_duration_since(t0).as_micros() * u128::from(self.clock_rate) / 1_000_000;
        let r = &mut self.log[(ext - self.begin) as usize];
        if r.received {
            r.duplicate = true;
        } else {
            r.received = true;
            r.time = ts0.wrapping_add(ticks as u32);
        }
    }

    /// Sequence numbers in the current interval (up to the highest received).
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether the current interval is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// The reported entries `(sequence number, receipt)` of the interval with `thinning`.
    fn reported(&self, thinning: u8) -> impl Iterator<Item = (u16, Receipt)> + '_ {
        let mask = (1u64 << (thinning & 0x0f)) - 1;
        self.log
            .iter()
            .enumerate()
            .map(|(i, r)| (self.begin + i as u64, *r))
            .filter(move |(e, _)| e & mask == 0)
            .map(|(e, r)| (e as u16, r))
    }

    fn rle(&self, thinning: u8, value: impl Fn(&Receipt) -> bool) -> Option<RleReport> {
        if self.log.is_empty() {
            return None;
        }
        let trace: Vec<bool> = self.reported(thinning).map(|(_, r)| value(&r)).collect();
        Some(RleReport {
            ssrc: self.ssrc,
            thinning: thinning & 0x0f,
            begin_seq: self.begin as u16,
            end_seq: (self.begin + self.log.len() as u64) as u16,
            chunks: RleReport::encode(&trace),
        })
    }

    /// A loss RLE block (BT 1) of the interval: `true` = received. `None` if it is empty.
    #[must_use]
    pub fn loss_rle(&self, thinning: u8) -> Option<XrBlock> {
        self.rle(thinning, |r| r.received).map(XrBlock::LossRle)
    }

    /// A duplicate RLE block (BT 2) of the interval: per §4.2 a zero marks a sequence
    /// number received more than once, a one anything else (losses included). `None` if
    /// the interval is empty.
    #[must_use]
    pub fn duplicate_rle(&self, thinning: u8) -> Option<XrBlock> {
        self.rle(thinning, |r| !r.duplicate)
            .map(XrBlock::DuplicateRle)
    }

    /// Packet receipt times blocks (BT 3) of the interval: since every sequence number a
    /// block reports on must have been received, one block per run of received reported
    /// sequence numbers (split at the block size limit), each with the first copy's time.
    #[must_use]
    pub fn receipt_times(&self, thinning: u8) -> Vec<XrBlock> {
        let step = 1u16 << (thinning & 0x0f);
        let max = (MAX_BLOCK_BODY - 8) / 4;
        let mut out = Vec::new();
        let mut run: Option<(u16, Vec<u32>)> = None;
        let flush = |run: &mut Option<(u16, Vec<u32>)>, out: &mut Vec<XrBlock>| {
            if let Some((begin, times)) = run.take() {
                let n = times.len() as u16;
                out.push(XrBlock::PacketReceiptTimes {
                    ssrc: self.ssrc,
                    thinning: thinning & 0x0f,
                    begin_seq: begin,
                    // One past the last reported sequence number.
                    end_seq: begin
                        .wrapping_add((n - 1).wrapping_mul(step))
                        .wrapping_add(1),
                    times,
                });
            }
        };
        for (seq, r) in self.reported(thinning) {
            if !r.received {
                flush(&mut run, &mut out);
                continue;
            }
            match &mut run {
                Some((_, times)) if times.len() < max => times.push(r.time),
                _ => {
                    flush(&mut run, &mut out);
                    run = Some((seq, vec![r.time]));
                }
            }
        }
        flush(&mut run, &mut out);
        out
    }

    /// Starts the next interval after the highest sequence number received.
    pub fn next_interval(&mut self) {
        self.begin += self.log.len() as u64;
        self.log.clear();
    }
}

/// Packet loss concealment of a VoIP receiver (RFC 3611 §4.7.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Plc {
    /// No information (00).
    #[default]
    Unspecified,
    /// Silence is inserted (01).
    Disabled,
    /// Enhanced interpolation (10).
    Enhanced,
    /// Simple replay or interpolation (11).
    Standard,
}

/// The jitter buffer of a VoIP receiver (RFC 3611 §4.7.6, §4.7.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterBufferConfig {
    /// Adaptive (`true`) or fixed size.
    pub adaptive: bool,
    /// Adjustment rate J (0..=15): about `2 * J * frame size` ms to adapt from 30 to 100 ms
    /// peak-to-peak jitter.
    pub rate: u8,
    /// Current nominal delay.
    pub nominal: Duration,
    /// Current maximum delay (for a fixed buffer, the nominal one).
    pub maximum: Duration,
    /// The absolute maximum delay an adaptive buffer can reach.
    pub abs_max: Duration,
}

/// The VoIP metrics fields beyond the loss and burst model (RFC 3611 §4.7.3 to §4.7.7):
/// levels, echo and the jitter buffer only the media application knows, the scores it or
/// the E-model ([`EModel::estimate_report`](crate::EModel::estimate_report)) gives;
/// [`BurstLossModel::report`] puts them into a [`VoipMetrics`] and
/// [`VoipMetrics::quality`] reads them back. Anything `None` is sent as unavailable (127 for levels and quality
/// scores, 0 for delays, unknown for the receiver configuration).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VoipQuality {
    /// The latest round-trip time (for example [`RecvStream::rtt`](crate::RecvStream::rtt)).
    pub round_trip: Option<Duration>,
    /// End system delay: sending-side accumulation and encoding plus receiving-side jitter
    /// buffer, decoding and playout.
    pub end_system_delay: Option<Duration>,
    /// Speech level in dBm0 ([`pcm_level_dbm0`] over talkspurts).
    pub signal_level: Option<i8>,
    /// Background noise level in dBm0 ([`pcm_level_dbm0`] over silence).
    pub noise_level: Option<i8>,
    /// Residual echo return loss in dB (ERL + ERLE from the echo canceller).
    pub rerl: Option<u8>,
    /// R factor of the RTP segment, 0..=100 (ITU-T G.107).
    pub r_factor: Option<u8>,
    /// R factor of an external segment, 0..=100.
    pub ext_r_factor: Option<u8>,
    /// MOS-LQ × 10, 10..=50.
    pub mos_lq: Option<u8>,
    /// MOS-CQ × 10, 10..=50.
    pub mos_cq: Option<u8>,
    /// Packet loss concealment.
    pub plc: Plc,
    /// The jitter buffer, if known.
    pub jitter_buffer: Option<JitterBufferConfig>,
}

fn ms16(d: Duration) -> u16 {
    d.as_millis().min(0xffff) as u16
}

impl BurstLossModel {
    /// A complete VoIP metrics block for `ssrc`: the loss, discard, burst and gap fields of
    /// [`metrics`](Self::metrics) (with `packet_ms` milliseconds of media per packet) and
    /// the fields of `quality`. Out-of-range quality scores are sent as unavailable (127),
    /// as §4.7.5 requires; levels are capped at 126 dB (127 means unavailable).
    #[must_use]
    pub fn report(&self, ssrc: u32, packet_ms: u16, quality: &VoipQuality) -> VoipMetrics {
        let q = quality;
        let level = |l: Option<i8>| l.map_or(VOIP_UNAVAILABLE, |v| v.min(126) as u8);
        let score = |v: Option<u8>, lo: u8, hi: u8| {
            v.filter(|v| (lo..=hi).contains(v))
                .unwrap_or(VOIP_UNAVAILABLE)
        };
        let plc = match q.plc {
            Plc::Unspecified => 0,
            Plc::Disabled => 1,
            Plc::Enhanced => 2,
            Plc::Standard => 3,
        };
        let jb = q.jitter_buffer.unwrap_or_default();
        let jba = match q.jitter_buffer {
            None => 0,
            Some(j) if j.adaptive => 3,
            Some(_) => 2,
        };
        VoipMetrics {
            round_trip_delay: q.round_trip.map_or(0, ms16),
            end_system_delay: q.end_system_delay.map_or(0, ms16),
            signal_level: level(q.signal_level),
            noise_level: level(q.noise_level),
            rerl: q.rerl.map_or(VOIP_UNAVAILABLE, |v| v.min(126)),
            r_factor: score(q.r_factor, 0, 100),
            ext_r_factor: score(q.ext_r_factor, 0, 100),
            mos_lq: score(q.mos_lq, 10, 50),
            mos_cq: score(q.mos_cq, 10, 50),
            rx_config: plc << 6 | jba << 4 | (jb.rate & 0x0f),
            jb_nominal: ms16(jb.nominal),
            jb_maximum: ms16(jb.maximum),
            jb_abs_max: ms16(jb.abs_max),
            ..self.metrics(ssrc, packet_ms)
        }
    }
}

impl VoipMetrics {
    /// The delay, level, quality and receiver configuration fields as [`VoipQuality`] (the
    /// inverse of [`BurstLossModel::report`]): 127 (unavailable) and out-of-range scores
    /// become `None`, as do zero delays and an unknown or reserved jitter buffer kind.
    #[must_use]
    pub fn quality(&self) -> VoipQuality {
        let ms = |v: u16| (v != 0).then(|| Duration::from_millis(u64::from(v)));
        let level = |v: u8| (v != VOIP_UNAVAILABLE).then_some(v as i8);
        let score = |v: u8, lo: u8, hi: u8| (lo..=hi).contains(&v).then_some(v);
        let plc = match self.rx_config >> 6 {
            1 => Plc::Disabled,
            2 => Plc::Enhanced,
            3 => Plc::Standard,
            _ => Plc::Unspecified,
        };
        let jitter_buffer = match (self.rx_config >> 4) & 3 {
            k @ (2 | 3) => Some(JitterBufferConfig {
                adaptive: k == 3,
                rate: self.rx_config & 0x0f,
                nominal: Duration::from_millis(u64::from(self.jb_nominal)),
                maximum: Duration::from_millis(u64::from(self.jb_maximum)),
                abs_max: Duration::from_millis(u64::from(self.jb_abs_max)),
            }),
            _ => None,
        };
        VoipQuality {
            round_trip: ms(self.round_trip_delay),
            end_system_delay: ms(self.end_system_delay),
            signal_level: level(self.signal_level),
            noise_level: level(self.noise_level),
            rerl: score(self.rerl, 0, 126),
            r_factor: score(self.r_factor, 0, 100),
            ext_r_factor: score(self.ext_r_factor, 0, 100),
            mos_lq: score(self.mos_lq, 10, 50),
            mos_cq: score(self.mos_cq, 10, 50),
            plc,
            jitter_buffer,
        }
    }
}

/// The level of 16-bit linear PCM in dBm0 (RFC 3611 §4.7.4: 10 log10 of the RMS power,
/// relative to 0 dBm0, a full-scale sine being +3.14 dBm0 as in G.711 µ-law), rounded and
/// clamped to -127..=3. `None` for no samples; digital silence gives -127.
#[must_use]
pub fn pcm_level_dbm0(samples: &[i16]) -> Option<i8> {
    if samples.is_empty() {
        return None;
    }
    let power = samples.iter().map(|&s| f64::from(s).powi(2)).sum::<f64>() / samples.len() as f64;
    if power == 0.0 {
        return Some(-127);
    }
    // A full-scale sine has power 32767^2 / 2 and is +3.14 dBm0 (G.711 µ-law).
    const FULL_SINE_DBM0: f64 = 314.0 / 100.0;
    let full_sine = 32767.0f64 * 32767.0 / 2.0;
    let db = 10.0 * (power / full_sine).log10() + FULL_SINE_DBM0;
    Some(db.round().clamp(-127.0, 3.0) as i8)
}
