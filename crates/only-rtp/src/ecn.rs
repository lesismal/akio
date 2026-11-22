//! RFC 6679 ECN feedback for RTP: the RTCP ECN feedback message (RTPFB FMT 8, §5.1), the
//! XR ECN summary report (block type 13, §5.2) and a receiver that keeps their counters.
//!
//! Both carry per-SSRC cumulative counters: packets received ECT(0), ECT(1), CE and
//! not-ECT, packets lost (expected minus received, RFC 3550 style) and duplicates. A sender
//! compares the differences between two reports with what it sent (ECN validation, §7.2.1
//! and §7.4) and responds to the CE difference.
//!
//! The message and the block travel as [`Rtcp::Unknown`] / [`XrBlock::Unknown`] (adding
//! variants to those enums would break exhaustive matches): [`EcnFeedback::from_rtcp`] /
//! [`EcnFeedback::to_rtcp`] and [`EcnSummary::from_xr`] / [`EcnSummary::to_xr`] convert.

use std::collections::VecDeque;

use crate::rtcp::Rtcp;
use crate::xr::XrBlock;

/// RTPFB packet type and the ECN feedback's FMT.
const RTPFB: u8 = 205;
/// FMT of the RTCP ECN feedback message (RFC 6679 §5.1).
pub const ECN_FEEDBACK_FMT: u8 = 8;
/// Block type of the XR ECN summary report (RFC 6679 §5.2).
pub const ECN_SUMMARY_BT: u8 = 13;
/// Sources a [`EcnReceiver`] keeps counters for; the one heard from longest ago goes first.
const MAX_SOURCES: usize = 64;
/// Sequence numbers remembered per source for spotting duplicates.
const DUP_WINDOW: usize = 512;

/// The cumulative counters of one source (RFC 6679 §5.1). The 32-bit counters and the
/// 16-bit ones wrap; compare reports with wrapping differences.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcnCounters {
    /// Packets received with ECT(0).
    pub ect0: u32,
    /// Packets received with ECT(1).
    pub ect1: u32,
    /// Packets received with CE (duplicates included).
    pub ce: u16,
    /// Packets received not-ECT.
    pub not_ect: u16,
    /// Packets lost: expected minus received (late arrivals are not lost).
    pub lost: u16,
    /// Duplicate packets.
    pub duplicates: u16,
}

impl EcnCounters {
    fn write(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.ect0.to_be_bytes());
        b.extend_from_slice(&self.ect1.to_be_bytes());
        b.extend_from_slice(&self.ce.to_be_bytes());
        b.extend_from_slice(&self.not_ect.to_be_bytes());
        b.extend_from_slice(&self.lost.to_be_bytes());
        b.extend_from_slice(&self.duplicates.to_be_bytes());
    }

    /// From 16 bytes.
    fn read(b: &[u8]) -> EcnCounters {
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        EcnCounters {
            ect0: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            ect1: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ce: u16_at(8),
            not_ect: u16_at(10),
            lost: u16_at(12),
            duplicates: u16_at(14),
        }
    }

    /// What changed since `prev` (wrapping); a lost count that went down (late arrivals)
    /// gives 0.
    #[must_use]
    pub fn since(&self, prev: &EcnCounters) -> EcnDelta {
        let lost = self.lost.wrapping_sub(prev.lost);
        EcnDelta {
            ect0: u64::from(self.ect0.wrapping_sub(prev.ect0)),
            ect1: u64::from(self.ect1.wrapping_sub(prev.ect1)),
            ce: u64::from(self.ce.wrapping_sub(prev.ce)),
            not_ect: u64::from(self.not_ect.wrapping_sub(prev.not_ect)),
            lost: if lost > 0x8000 { 0 } else { u64::from(lost) },
            duplicates: u64::from(self.duplicates.wrapping_sub(prev.duplicates)),
        }
    }
}

/// The difference of two [`EcnCounters`] ([`EcnCounters::since`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcnDelta {
    /// Packets received ECT(0), ECT(1), CE and not-ECT in between.
    pub ect0: u64,
    /// See `ect0`.
    pub ect1: u64,
    /// See `ect0`.
    pub ce: u64,
    /// See `ect0`.
    pub not_ect: u64,
    /// Packets newly counted lost.
    pub lost: u64,
    /// Duplicates.
    pub duplicates: u64,
}

/// The RTCP ECN feedback message (RTPFB FMT 8, RFC 6679 §5.1): one source's counters and
/// its extended highest sequence number received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcnFeedback {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source reported on.
    pub media_ssrc: u32,
    /// Extended highest sequence number received (cycles << 16 | highest).
    pub extended_highest_seq: u32,
    /// The counters.
    pub counters: EcnCounters,
}

impl EcnFeedback {
    /// The message in `p`, if it is one (an [`Rtcp::Unknown`] of type 205, FMT 8, with a
    /// 20-byte FCI).
    #[must_use]
    pub fn from_rtcp(p: &Rtcp) -> Option<EcnFeedback> {
        let Rtcp::Unknown {
            packet_type: RTPFB,
            fmt: ECN_FEEDBACK_FMT,
            data,
        } = p
        else {
            return None;
        };
        let d = data.get(..28)?;
        let be32 = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
        Some(EcnFeedback {
            sender_ssrc: be32(0),
            media_ssrc: be32(4),
            extended_highest_seq: be32(8),
            counters: EcnCounters::read(&d[12..28]),
        })
    }

    /// The message as an RTCP packet for [`write_compound`](crate::write_compound).
    #[must_use]
    pub fn to_rtcp(&self) -> Rtcp {
        let mut data = Vec::with_capacity(28);
        data.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        data.extend_from_slice(&self.media_ssrc.to_be_bytes());
        data.extend_from_slice(&self.extended_highest_seq.to_be_bytes());
        self.counters.write(&mut data);
        Rtcp::Unknown {
            packet_type: RTPFB,
            fmt: ECN_FEEDBACK_FMT,
            data,
        }
    }
}

/// One source of an XR ECN summary report (block type 13, RFC 6679 §5.2). The extended
/// highest sequence number is the one of the report block about the same source in the same
/// compound packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcnSummary {
    /// SSRC of the media sender reported on.
    pub ssrc: u32,
    /// The counters.
    pub counters: EcnCounters,
}

impl EcnSummary {
    /// The sources of an ECN summary block (an [`XrBlock::Unknown`] of type 13); `None` for
    /// other blocks and for lengths that are not a multiple of five words (which RFC 6679
    /// says to discard).
    #[must_use]
    pub fn from_xr(b: &XrBlock) -> Option<Vec<EcnSummary>> {
        let XrBlock::Unknown {
            block_type: ECN_SUMMARY_BT,
            data,
            ..
        } = b
        else {
            return None;
        };
        if data.len() % 20 != 0 {
            return None;
        }
        Some(
            data.chunks_exact(20)
                .map(|c| EcnSummary {
                    ssrc: u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                    counters: EcnCounters::read(&c[4..]),
                })
                .collect(),
        )
    }

    /// One block about `sources` (at most 3276 of them, the block length's limit).
    #[must_use]
    pub fn to_xr(sources: &[EcnSummary]) -> XrBlock {
        let mut data = Vec::with_capacity(20 * sources.len());
        for s in sources.iter().take(3276) {
            data.extend_from_slice(&s.ssrc.to_be_bytes());
            s.counters.write(&mut data);
        }
        XrBlock::Unknown {
            block_type: ECN_SUMMARY_BT,
            type_specific: 0,
            data,
        }
    }
}

/// One source's reception state.
#[derive(Debug, Clone)]
struct Source {
    ssrc: u32,
    /// First extended sequence number, highest one, packets received (not duplicates).
    base: u64,
    max: u64,
    received: u64,
    ect0: u64,
    ect1: u64,
    ce: u64,
    not_ect: u64,
    duplicates: u64,
    /// Extended sequence numbers by slot, for duplicates.
    seen: Vec<u64>,
    /// An ECN-capable packet arrived and was not reported yet (the first one, or CE).
    urgent: bool,
    reported_ect: bool,
    /// Something arrived since the last feedback message.
    changed: bool,
}

impl Source {
    fn counters(&self) -> EcnCounters {
        let expected = self.max - self.base + 1;
        EcnCounters {
            ect0: self.ect0 as u32,
            ect1: self.ect1 as u32,
            ce: self.ce as u16,
            not_ect: self.not_ect as u16,
            lost: expected.saturating_sub(self.received) as u16,
            duplicates: self.duplicates as u16,
        }
    }
}

/// The receiving side of RFC 6679: counts what each source's packets arrived with and
/// makes the feedback messages and summary reports. A first ECN-capable packet and every
/// CE mark make feedback [`urgent`](Self::urgent) (§7.2.1, §7.3.2: early feedback).
#[derive(Debug, Default)]
pub struct EcnReceiver {
    sources: VecDeque<Source>,
}

impl EcnReceiver {
    /// A receiver without sources.
    #[must_use]
    pub fn new() -> EcnReceiver {
        EcnReceiver::default()
    }

    /// Packet `seq` of `ssrc` arrived with the ECN bits `ecn`.
    pub fn on_received(&mut self, ssrc: u32, seq: u16, ecn: u8) {
        let i = match self.sources.iter().position(|s| s.ssrc == ssrc) {
            Some(i) => i,
            None => {
                if self.sources.len() >= MAX_SOURCES {
                    self.sources.pop_front();
                }
                let ext = u64::from(seq) + (1 << 16);
                self.sources.push_back(Source {
                    ssrc,
                    base: ext,
                    max: ext,
                    received: 0,
                    ect0: 0,
                    ect1: 0,
                    ce: 0,
                    not_ect: 0,
                    duplicates: 0,
                    seen: vec![u64::MAX; DUP_WINDOW],
                    urgent: false,
                    reported_ect: false,
                    changed: false,
                });
                self.sources.len() - 1
            }
        };
        let s = &mut self.sources[i];
        // The extended number closest to the highest so far.
        let cycle = s.max & !0xffff;
        let mut ext = cycle | u64::from(seq);
        if ext + 0x8000 < s.max {
            ext += 1 << 16;
        } else if ext > s.max + 0x8000 && ext >= 1 << 16 {
            ext -= 1 << 16;
        }
        s.changed = true;
        let slot = (ext as usize) % DUP_WINDOW;
        let dup = s.seen[slot] == ext;
        match ecn & 3 {
            0 => s.not_ect += 1,
            1 => s.ect1 += 1,
            2 => s.ect0 += 1,
            _ => {
                s.ce += 1;
                s.urgent = true;
            }
        }
        if ecn & 3 != 0 && !s.reported_ect {
            s.urgent = true;
        }
        if dup {
            s.duplicates += 1;
            return;
        }
        s.seen[slot] = ext;
        s.received += 1;
        if ext < s.base {
            s.base = ext;
        }
        s.max = s.max.max(ext);
    }

    /// Whether a source has news that should be reported early: its first ECN-capable
    /// packet, or a CE mark.
    #[must_use]
    pub fn urgent(&self) -> bool {
        self.sources.iter().any(|s| s.urgent)
    }

    /// Feedback messages from `sender_ssrc` about the sources heard from since the last
    /// call (all of them with `all`); clears [`urgent`](Self::urgent).
    pub fn feedback(&mut self, sender_ssrc: u32, all: bool) -> Vec<EcnFeedback> {
        let mut out = Vec::new();
        for s in &mut self.sources {
            if !(all || s.changed) {
                continue;
            }
            if s.ect0 + s.ect1 + s.ce > 0 {
                s.reported_ect = true;
            }
            s.urgent = false;
            s.changed = false;
            out.push(EcnFeedback {
                sender_ssrc,
                media_ssrc: s.ssrc,
                // Counted from cycle 1 internally (room for reordering before the
                // first packet); reported from cycle 0, as RFC 3550 report blocks are.
                extended_highest_seq: (s.max - (1 << 16)) as u32,
                counters: s.counters(),
            });
        }
        out
    }

    /// The summary of `ssrc`'s counters (for the XR summary report next to its report
    /// block).
    #[must_use]
    pub fn summary(&self, ssrc: u32) -> Option<EcnSummary> {
        let s = self.sources.iter().find(|s| s.ssrc == ssrc)?;
        Some(EcnSummary {
            ssrc,
            counters: s.counters(),
        })
    }

    /// Forgets `ssrc`.
    pub fn remove(&mut self, ssrc: u32) {
        self.sources.retain(|s| s.ssrc != ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_and_summary_round_trip() {
        let fb = EcnFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            extended_highest_seq: 0x0001_0005,
            counters: EcnCounters {
                ect0: 7,
                ect1: 0x1234_5678,
                ce: 3,
                not_ect: 9,
                lost: 2,
                duplicates: 1,
            },
        };
        let raw = crate::write_compound(&[fb.to_rtcp()]);
        assert_eq!(raw.len(), 4 + 28);
        assert_eq!(raw[0] & 0x1f, 8);
        assert_eq!(raw[1], 205);
        let back = crate::parse_compound(&raw).unwrap();
        assert_eq!(EcnFeedback::from_rtcp(&back[0]), Some(fb));
        let sums = [
            EcnSummary {
                ssrc: 5,
                counters: fb.counters,
            },
            EcnSummary {
                ssrc: 6,
                counters: EcnCounters::default(),
            },
        ];
        let xr = Rtcp::ExtendedReport {
            ssrc: 1,
            blocks: vec![EcnSummary::to_xr(&sums)],
        };
        let raw = crate::write_compound(&[xr]);
        // Header, originator, block header and two five-word sources.
        assert_eq!(raw.len(), 4 + 4 + 4 + 40);
        assert_eq!((raw[8], u16::from_be_bytes([raw[10], raw[11]])), (13, 10));
        let back = crate::parse_compound(&raw).unwrap();
        let Rtcp::ExtendedReport { blocks, .. } = &back[0] else {
            panic!("{back:?}");
        };
        assert_eq!(EcnSummary::from_xr(&blocks[0]).unwrap(), sums);
        // Lengths that are not a multiple of five words are discarded.
        let bad = XrBlock::Unknown {
            block_type: 13,
            type_specific: 0,
            data: vec![0; 24],
        };
        assert!(EcnSummary::from_xr(&bad).is_none());
        assert!(
            EcnFeedback::from_rtcp(&Rtcp::Unknown {
                packet_type: 205,
                fmt: 8,
                data: vec![0; 27],
            })
            .is_none()
        );
    }

    #[test]
    fn receiver_counts_codepoints_losses_and_duplicates() {
        let mut r = EcnReceiver::new();
        // 65530.. wrapping, one lost (65533), one duplicate, a CE.
        for (seq, ecn) in [
            (65530u16, 0u8),
            (65531, 1),
            (65532, 1),
            (65534, 3),
            (65535, 1),
        ] {
            r.on_received(9, seq, ecn);
        }
        r.on_received(9, 65532, 1);
        r.on_received(9, 0, 1);
        r.on_received(9, 1, 2);
        assert!(r.urgent());
        let fb = r.feedback(4, false);
        assert_eq!(fb.len(), 1);
        let c = fb[0].counters;
        assert_eq!(fb[0].extended_highest_seq, 0x0001_0001);
        assert_eq!(
            (c.ect0, c.ect1, c.ce, c.not_ect, c.lost, c.duplicates),
            (1, 5, 1, 1, 1, 1)
        );
        assert!(!r.urgent());
        // Nothing new: no message unless all are asked for.
        assert!(r.feedback(4, false).is_empty());
        assert_eq!(r.feedback(4, true).len(), 1);
        // A late arrival is no longer lost.
        r.on_received(9, 65533, 1);
        let c2 = r.summary(9).unwrap().counters;
        assert_eq!(c2.lost, 0);
        let d = c2.since(&c);
        assert_eq!((d.ect1, d.lost), (1, 0));
        // ECT after reporting only urgent again on CE.
        r.on_received(9, 2, 1);
        assert!(!r.urgent());
        r.on_received(9, 3, 3);
        assert!(r.urgent());
        r.remove(9);
        assert!(r.summary(9).is_none());
    }
}
