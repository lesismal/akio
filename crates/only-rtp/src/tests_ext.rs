//! Tests of RTCP XR, TMMBR / TMMBN, RFC 8888 feedback and FEC: libwebrtc unit-test vectors
//! (modules/rtp_rtcp/source/rtcp_packet/{tmmbr,tmmbn,rrtr,dlrr}_unittest.cc and
//! flexfec_03_header_reader_writer_unittest.cc), the RFC 3611 §4.7.2 burst example,
//! hand-assembled RFC 8888 packets, round trips and FEC recovery under simulated loss.

use std::time::{Duration, Instant};

use crate::fec::{FecDecoder, FecEncoder, FecHeader, FecScheme, interleaved_masks, red};
use crate::tests::hex;
use crate::*;

// --- TMMBR / TMMBN ---

const LW_TMMBR: &str = "83cd0004123456780000000023456789 0a6161fe";
const LW_TMMBN: &str = "84cd0004123456780000000023456789 0a6161fe";

#[test]
fn tmmbr_tmmbn_libwebrtc_vectors() {
    let item = TmmbItem {
        ssrc: 0x2345_6789,
        bitrate: 312_000,
        overhead: 0x1fe,
    };
    let tmmbr = Rtcp::Tmmbr {
        sender_ssrc: 0x1234_5678,
        entries: vec![item],
    };
    let tmmbn = Rtcp::Tmmbn {
        sender_ssrc: 0x1234_5678,
        entries: vec![item],
    };
    assert_eq!(write_compound(std::slice::from_ref(&tmmbr)), hex(LW_TMMBR));
    assert_eq!(write_compound(std::slice::from_ref(&tmmbn)), hex(LW_TMMBN));
    assert_eq!(parse_compound(&hex(LW_TMMBR)).unwrap(), [tmmbr]);
    assert_eq!(parse_compound(&hex(LW_TMMBN)).unwrap(), [tmmbn]);
    // Zero items; an unaligned item list.
    let empty = hex("83cd00021234567800000000");
    assert_eq!(
        parse_compound(&empty).unwrap(),
        [Rtcp::Tmmbr {
            sender_ssrc: 0x1234_5678,
            entries: vec![]
        }]
    );
    let bad = hex("83cd0005123456780000000023456789 0a6161fe 3456789a");
    assert!(parse_compound(&bad).is_err());
    // Exponent overflow saturates; overheads clamp to 9 bits.
    let big = hex("83cd0004123456780000000000000001 fffffe00");
    match &parse_compound(&big).unwrap()[0] {
        Rtcp::Tmmbr { entries, .. } => assert_eq!(entries[0].bitrate, u64::MAX),
        p => panic!("{p:?}"),
    }
    let w = write_compound(&[Rtcp::Tmmbn {
        sender_ssrc: 1,
        entries: vec![TmmbItem {
            ssrc: 2,
            bitrate: 1,
            overhead: 4000,
        }],
    }]);
    assert_eq!(&w[16..], &[0, 0, 3, 0xff]);
}

fn tmmb(ssrc: u32, kbps: u64, overhead: u16) -> TmmbItem {
    TmmbItem {
        ssrc,
        bitrate: kbps * 1000,
        overhead,
    }
}

#[test]
fn tmmbr_bounding_set() {
    // A single tuple, and zero bitrates ignored.
    assert_eq!(
        bounding_set(&[tmmb(1, 0, 10), tmmb(2, 500, 40)]),
        [tmmb(2, 500, 40)]
    );
    // The lowest bitrate bounds at rate 0; a steeper tuple bounds at higher packet rates;
    // a tuple above the envelope everywhere is dropped; an equal-overhead duplicate with a
    // higher bitrate is dropped.
    let set = bounding_set(&[
        tmmb(1, 1000, 20),
        tmmb(2, 1100, 60),
        tmmb(3, 2000, 61),
        tmmb(4, 1200, 60),
        tmmb(5, 1500, 10),
    ]);
    assert_eq!(set, [tmmb(1, 1000, 20), tmmb(2, 1100, 60)]);
    // 1000k - 160·r vs 1100k - 480·r cross at r = 312.5 pkt/s.
    assert_eq!(bounded_bitrate(&set, 0.0), Some(1_000_000));
    assert_eq!(bounded_bitrate(&set, 100.0), Some(1_000_000 - 16_000));
    assert_eq!(bounded_bitrate(&set, 1000.0), Some(1_100_000 - 480_000));
    assert_eq!(bounded_bitrate(&[], 1.0), None);
    // A steeper tuple crossing only after the bounding line reached zero is irrelevant.
    assert_eq!(
        bounding_set(&[tmmb(1, 100, 500), tmmb(2, 10_000, 501)]),
        [tmmb(1, 100, 500)]
    );
    // Equal lowest bitrates: the steeper one wins.
    assert_eq!(
        bounding_set(&[tmmb(1, 300, 10), tmmb(2, 300, 30)]),
        [tmmb(2, 300, 30)]
    );
}

#[test]
fn tmmbr_handler() {
    let t0 = Instant::now();
    let mut h = TmmbrHandler::new(0xaaaa);
    assert_eq!(h.max_bitrate(t0, 50.0), None);
    // A request for another media source is ignored.
    assert!(!h.on_tmmbr(t0, 1, &[tmmb(0xbbbb, 100, 0)]));
    assert!(h.on_tmmbr(t0, 1, &[tmmb(0xaaaa, 800, 40)]));
    assert!(h.on_tmmbr(t0, 2, &[tmmb(0xaaaa, 600, 40)]));
    // Not in the bounding set: no change.
    assert!(!h.on_tmmbr(t0, 3, &[tmmb(0xaaaa, 900, 40)]));
    assert_eq!(h.max_bitrate(t0, 0.0), Some(600_000));
    match h.tmmbn(t0) {
        Rtcp::Tmmbn {
            sender_ssrc,
            entries,
        } => {
            assert_eq!(sender_ssrc, 0xaaaa);
            assert_eq!(entries, [tmmb(2, 600, 40)]);
        }
        p => panic!("{p:?}"),
    }
    // Withdrawal, then expiry.
    assert!(h.on_tmmbr(t0, 2, &[tmmb(0xaaaa, 0, 0)]));
    assert_eq!(h.max_bitrate(t0, 0.0), Some(800_000));
    assert_eq!(h.max_bitrate(t0 + TMMBR_TIMEOUT * 2, 0.0), None);
}

// --- XR ---

#[test]
fn xr_libwebrtc_vectors() {
    // rrtr_unittest.cc / dlrr_unittest.cc blocks inside an XR from 0x12345678
    // (extended_reports_unittest.cc's sender).
    let rrtr = XrBlock::ReceiverReferenceTime {
        ntp: 0x1234_5678_2345_6789,
    };
    let dlrr = XrBlock::Dlrr(vec![DlrrItem {
        ssrc: 0x1234_5678,
        last_rr: 0x2334_4556,
        delay_since_last_rr: 0x3334_3536,
    }]);
    let pkt = Rtcp::ExtendedReport {
        ssrc: 0x1234_5678,
        blocks: vec![rrtr, dlrr],
    };
    let want = hex("80cf0008 12345678 040000021234567823456789 0500000312345678233445563334 3536");
    assert_eq!(write_compound(std::slice::from_ref(&pkt)), want);
    assert_eq!(parse_compound(&want).unwrap(), [pkt]);
    // The empty packet of extended_reports_unittest.cc.
    assert_eq!(
        parse_compound(&hex("80cf000112345678")).unwrap(),
        [Rtcp::ExtendedReport {
            ssrc: 0x1234_5678,
            blocks: vec![]
        }]
    );
}

#[test]
fn xr_blocks_round_trip_and_errors() {
    let blocks = vec![
        XrBlock::LossRle(RleReport {
            ssrc: 1,
            thinning: 3,
            begin_seq: 65530,
            end_seq: 10,
            chunks: vec![0x4006, 0xbfff, 0x2001],
        }),
        XrBlock::DuplicateRle(RleReport {
            ssrc: 2,
            thinning: 0,
            begin_seq: 1,
            end_seq: 2,
            chunks: vec![],
        }),
        XrBlock::PacketReceiptTimes {
            ssrc: 3,
            thinning: 15,
            begin_seq: 7,
            end_seq: 9,
            times: vec![1000, 2000],
        },
        XrBlock::StatisticsSummary(StatisticsSummary {
            ssrc: 4,
            begin_seq: 100,
            end_seq: 200,
            lost_packets: Some(3),
            dup_packets: None,
            jitter: Some(JitterStats {
                min: 1,
                max: 90,
                mean: 20,
                dev: 9,
            }),
            ttl: Some(TtlStats {
                hop_limit: true,
                min: 60,
                max: 64,
                mean: 63,
                dev: 1,
            }),
        }),
        XrBlock::VoipMetrics(VoipMetrics {
            ssrc: 5,
            loss_rate: 12,
            gmin: 16,
            r_factor: VOIP_UNAVAILABLE,
            jb_abs_max: 0xffff,
            ..VoipMetrics::default()
        }),
        XrBlock::Unknown {
            block_type: 42,
            type_specific: 9,
            data: vec![1, 2, 3, 4],
        },
    ];
    let pkt = Rtcp::ExtendedReport {
        ssrc: 9,
        blocks: blocks.clone(),
    };
    let w = write_compound(std::slice::from_ref(&pkt));
    assert_eq!(parse_compound(&w).unwrap(), [pkt]);
    // Statistics summary wire form: L, J and ToH = 2 set, D clear.
    let ss = write_compound(&[Rtcp::ExtendedReport {
        ssrc: 9,
        blocks: vec![blocks[3].clone()],
    }]);
    assert_eq!(
        ss[8..],
        hex(
            "06b00009 00000004 006400c8 00000003 00000000 00000001 0000005a 00000014 00000009 3c403f01"
        )[..]
    );
    // VoIP metrics are eight words.
    let v = write_compound(&[Rtcp::ExtendedReport {
        ssrc: 9,
        blocks: vec![blocks[4].clone()],
    }]);
    assert_eq!(v.len(), 8 + 4 + 32);
    assert_eq!(&v[8..12], &[7, 0, 0, 8]);
    // A block running past the packet; fixed-size blocks with a wrong length.
    for bad in [
        "80cf0002 00000009 04000003",
        "80cf0003 00000009 04000001 00000000",
        "80cf0003 00000009 05000001 00000000",
        "80cf0003 00000009 06000001 00000000",
        "80cf0003 00000009 07000001 00000000",
        "80cf0003 00000009 01000001 00000000",
    ] {
        assert!(parse_compound(&hex(bad)).is_err(), "{bad}");
    }
    // ToH 3 is undefined: not reported.
    let mut raw = ss;
    raw[9] |= 0x18;
    match &parse_compound(&raw).unwrap()[0] {
        Rtcp::ExtendedReport { blocks, .. } => match &blocks[0] {
            XrBlock::StatisticsSummary(s) => assert_eq!(s.ttl, None),
            b => panic!("{b:?}"),
        },
        p => panic!("{p:?}"),
    }
}

#[test]
fn xr_rtt_exchange() {
    let t0 = Instant::now();
    let ntp0 = 0x0000_1000_0000_0000u64;
    let ntp_at = |d: Duration| ntp0 + ((d.as_micros() as u64) << 32) / 1_000_000;
    // The receiver (SSRC 0x77) sends an RRTR at t0; it reaches the sender 20 ms later.
    let mut resp = RrtrResponder::new();
    assert_eq!(resp.dlrr(t0), None);
    resp.on_rrtr(t0 + Duration::from_millis(20), 0x77, ntp0);
    // The sender answers 15 ms later; the answer takes another 20 ms.
    let Some(XrBlock::Dlrr(items)) = resp.dlrr(t0 + Duration::from_millis(35)) else {
        panic!()
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].ssrc, 0x77);
    assert_eq!(items[0].last_rr, compact_ntp(ntp0));
    let mut rx = RecvStream::new(0x99, 90_000, true);
    let rtt = rx
        .handle_dlrr(ntp_at(Duration::from_millis(55)), &items[0])
        .unwrap();
    assert!(
        rtt.abs_diff(Duration::from_millis(40)) < Duration::from_micros(100),
        "{rtt:?}"
    );
    assert_eq!(rx.rtt(), Some(rtt));
    // No LRR, negative or absurd values.
    assert_eq!(rtt_from_dlrr(ntp0, &DlrrItem::default()), None);
    let mut late = items[0];
    late.delay_since_last_rr = 0x8000_0000;
    assert_eq!(rtt_from_dlrr(ntp0, &late), None);
    // Stale receivers are no longer answered; at most 32 are kept.
    assert_eq!(resp.dlrr(t0 + Duration::from_secs(120)), None);
    for s in 0..40 {
        resp.on_rrtr(t0 + Duration::from_millis(s), s as u32, ntp0);
    }
    let Some(XrBlock::Dlrr(items)) = resp.dlrr(t0 + Duration::from_secs(1)) else {
        panic!()
    };
    assert_eq!(items.len(), 32);
    assert!(items.iter().all(|i| i.ssrc >= 8));
}

#[test]
fn xr_statistics_summary_from_stream() {
    let t0 = Instant::now();
    let mut rx = RecvStream::new(0x99, 1000, false);
    assert_eq!(rx.statistics_summary(), None);
    // 1 ms clock, 20 ms packets; packets 1003 and 1005 lost, 1002 duplicated, 1007 late
    // by 10 ms.
    for seq in [1000u16, 1001, 1002, 1002, 1004, 1006, 1007, 1008, 1009] {
        let late = if seq == 1007 { 10 } else { 0 };
        let at = t0 + Duration::from_millis(u64::from(seq - 1000) * 20 + late);
        rx.receive(at, seq, u32::from(seq - 1000) * 20);
    }
    assert_eq!(rx.duplicates(), 1);
    let s = rx.statistics_summary().unwrap();
    assert_eq!((s.ssrc, s.begin_seq, s.end_seq), (0x99, 1000, 1010));
    assert_eq!(s.lost_packets, Some(2));
    assert_eq!(s.dup_packets, Some(1));
    let j = s.jitter.unwrap();
    assert_eq!((j.min, j.max), (0, 10));
    assert!(j.mean > 0 && j.dev > 0, "{j:?}");
    assert_eq!(s.ttl, None);
    // Nothing new.
    assert_eq!(rx.statistics_summary(), None);
    // The next interval starts after the previous one.
    rx.receive(t0 + Duration::from_millis(400), 1012, 240);
    let s = rx.statistics_summary().unwrap();
    assert_eq!(
        (s.begin_seq, s.end_seq, s.lost_packets),
        (1010, 1013, Some(2))
    );
}

#[test]
fn xr_voip_burst_model_rfc3611_example() {
    // RFC 3611 §4.7.2: 1 received, 0 lost, X discarded.
    let pattern = "11110111111111111111111X111X1011110111111111111111111X111111111";
    let mut m = BurstLossModel::default();
    for c in pattern.chars() {
        m.on_packet(c == '0', c == 'X');
    }
    let v = m.metrics(7, 10);
    assert_eq!(v.ssrc, 7);
    assert_eq!(v.gmin, 16);
    // 3 lost, 3 discarded of 63.
    assert_eq!((v.loss_rate, v.discard_rate), (12, 12));
    // One burst of 12 packets (120 ms) between gaps of 230 + 290 ms; the RFC rounds the
    // burst density 1/3 to 84.
    assert_eq!(v.burst_duration, 120);
    assert_eq!(v.gap_duration, 520);
    assert_eq!(v.gap_density, 10);
    assert_eq!(v.burst_density, 85);
    assert_eq!(v.r_factor, VOIP_UNAVAILABLE);
    // A clean call is one long gap.
    let mut clean = BurstLossModel::new(16);
    (0..100).for_each(|_| clean.on_packet(false, false));
    let v = clean.metrics(1, 20);
    assert_eq!((v.loss_rate, v.burst_density, v.gap_duration), (0, 0, 2000));
}

// --- RFC 8888 ---

/// Hand-assembled from RFC 8888 §3.1: sender 0x11223344; stream 0x55667788 from 0xfffe:
/// received ECT(0) ATO 0x123, lost, received CE ATO unavailable (+ 2 bytes of padding);
/// report timestamp 0xaabbccdd.
const CCFB: &str = "8bcd0006 11223344 55667788 fffe0003 c1230000 ffff0000 aabbccdd";

#[test]
fn ccfb_wire_format() {
    let fb = CcfbFeedback {
        sender_ssrc: 0x1122_3344,
        streams: vec![CcfbStream {
            ssrc: 0x5566_7788,
            begin_seq: 0xfffe,
            reports: vec![
                Some(CcfbMetric {
                    ecn: 2,
                    arrival_offset: 0x123,
                }),
                None,
                Some(CcfbMetric {
                    ecn: 3,
                    arrival_offset: CCFB_ATO_UNAVAILABLE,
                }),
            ],
        }],
        report_timestamp: 0xaabb_ccdd,
    };
    let p = Rtcp::CongestionControl(fb);
    assert_eq!(write_compound(std::slice::from_ref(&p)), hex(CCFB));
    assert_eq!(parse_compound(&hex(CCFB)).unwrap(), [p]);
    // No streams; two streams with an even count; a not-received report with stray bits
    // is still "not received".
    let empty = Rtcp::CongestionControl(CcfbFeedback {
        sender_ssrc: 1,
        streams: vec![],
        report_timestamp: 2,
    });
    assert_eq!(
        write_compound(std::slice::from_ref(&empty)),
        hex("8bcd0002 00000001 00000002")
    );
    assert_eq!(
        parse_compound(&hex("8bcd0002 00000001 00000002")).unwrap(),
        [empty]
    );
    let two = hex("8bcd0007 00000001 00000005 00010002 a0017fff 00000006 00090000 00000002");
    match &parse_compound(&two).unwrap()[0] {
        Rtcp::CongestionControl(f) => {
            assert_eq!(f.streams.len(), 2);
            assert_eq!(
                f.streams[0].reports,
                [
                    Some(CcfbMetric {
                        ecn: 1,
                        arrival_offset: 1
                    }),
                    None
                ]
            );
            assert_eq!((f.streams[1].begin_seq, f.streams[1].reports.len()), (9, 0));
            // The stray bits of the not-received report are not written back.
            let w = write_compound(&[Rtcp::CongestionControl(f.clone())]);
            assert_eq!(w[..18], two[..18]);
            assert_eq!(w[18..], hex("0000 00000006 00090000 00000002")[..]);
        }
        p => panic!("{p:?}"),
    }
    // Truncated: reports past the end, a stream header cut short, too short for the
    // timestamp.
    for bad in [
        "8bcd0004 00000001 00000005 00010004 00000002",
        "8bcd0003 00000001 00000005 00000002",
        "8bcd0001 00000001",
    ] {
        assert!(parse_compound(&hex(bad)).is_err(), "{bad}");
    }
}

#[test]
fn ccfb_receiver_generates_reports() {
    let t0 = Instant::now();
    let ntp0 = 0x0000_2000_0000_0000u64;
    let mut rx = CcfbReceiver::new();
    assert_eq!(rx.poll_feedback(t0, ntp0, 1), None);
    // Stream A: 65534, 65535, (0 lost), 1; stream B: 7 with ECN CE.
    rx.on_received(0xa, 65534, t0, 2);
    rx.on_received(0xa, 65535, t0 + Duration::from_millis(10), 2);
    rx.on_received(0xa, 1, t0 + Duration::from_millis(20), 2);
    rx.on_received(0xa, 1, t0 + Duration::from_millis(21), 2); // duplicate
    rx.on_received(0xb, 7, t0 + Duration::from_millis(25), 3);
    let now = t0 + Duration::from_millis(30);
    let ntp_now = ntp0 + ((30u64 << 32) / 1000);
    let Some(Rtcp::CongestionControl(fb)) = rx.poll_feedback(now, ntp_now, 0x55) else {
        panic!()
    };
    assert_eq!(fb.sender_ssrc, 0x55);
    assert_eq!(fb.report_timestamp, compact_ntp(ntp_now));
    assert_eq!(fb.streams.len(), 2);
    let a = &fb.streams[0];
    assert_eq!((a.ssrc, a.begin_seq), (0xa, 65534));
    let ato: Vec<Option<u16>> = a
        .reports
        .iter()
        .map(|r| r.map(|m| m.arrival_offset))
        .collect();
    // 30 ms, 20 ms, lost, 10 ms in 1/1024 s.
    assert_eq!(ato, [Some(30), Some(20), None, Some(10)]);
    assert_eq!(a.reports[0].unwrap().ecn, 2);
    assert_eq!(
        fb.streams[1].reports,
        [Some(CcfbMetric {
            ecn: 3,
            arrival_offset: 5
        })]
    );
    // Nothing pending; a late arrival of the reported-lost packet is not reported.
    rx.on_received(0xa, 0, now, 0);
    assert_eq!(
        rx.poll_feedback(now + Duration::from_secs(1), ntp_now, 0x55),
        None
    );
    // Not due before the interval unless 100 packets wait; a backlog is split.
    rx.on_received(0xa, 2, now, 0);
    assert_eq!(
        rx.poll_feedback(now + Duration::from_millis(10), ntp_now, 0x55),
        None
    );
    rx.set_interval(Duration::from_millis(5));
    assert!(
        rx.poll_feedback(now + Duration::from_millis(10), ntp_now, 0x55)
            .is_some()
    );
    for s in 3..1203u16 {
        rx.on_received(0xa, s, now, 0);
    }
    let mut total = 0;
    let mut polls = 0;
    while let Some(Rtcp::CongestionControl(fb)) =
        rx.poll_feedback(now + Duration::from_millis(11), ntp_now, 0x55)
    {
        assert!(fb.streams[0].reports.len() <= 500);
        total += fb.streams[0].reports.len();
        polls += 1;
    }
    assert_eq!((total, polls), (1200, 3));
}

#[test]
fn ccfb_end_to_end_into_estimator() {
    let t0 = Instant::now();
    let ntp0 = 0x0000_3000_0000_0000u64;
    let ntp = |t: Instant| ntp0 + ((t.duration_since(t0).as_micros() as u64) << 32) / 1_000_000;
    let mut tx = CcfbSender::new();
    let mut rx = CcfbReceiver::new();
    let mut bwe = BandwidthEstimator::new(300_000);
    let mut results = Vec::new();
    // 2 streams, 2000 packets each 5 ms apart, every 10th of stream 2 lost, 30 ms one-way.
    for i in 0..2000u32 {
        let now = t0 + Duration::from_millis(u64::from(i) * 5);
        for (ssrc, size) in [(1u32, 1200usize), (2, 300)] {
            let seq = (60_000 + i) as u16;
            tx.on_sent(ssrc, seq, now, size);
            if !(ssrc == 2 && i % 10 == 0) {
                rx.on_received(ssrc, seq, now + Duration::from_millis(30), 0);
            }
        }
        let at = now + Duration::from_millis(31);
        while let Some(Rtcp::CongestionControl(fb)) = rx.poll_feedback(at, ntp(at), 9) {
            // Through the wire format.
            let p = parse_compound(&write_compound(&[Rtcp::CongestionControl(fb)])).unwrap();
            let Rtcp::CongestionControl(fb) = &p[0] else {
                panic!()
            };
            let r = tx.on_feedback(at + Duration::from_millis(30), fb);
            bwe.on_packet_results(at, &r);
            results.extend(r);
        }
    }
    let lost = results.iter().filter(|r| r.received.is_none()).count();
    let recv = results.len() - lost;
    assert!(recv > 3700 && (190..=200).contains(&lost), "{recv} {lost}");
    // Send order and constant one-way delay are preserved through the mapping.
    assert!(results.windows(2).all(|w| w[0].seq < w[1].seq));
    let d: Vec<Duration> = results
        .iter()
        .filter_map(|r| r.received.map(|a| a.saturating_duration_since(r.sent)))
        .collect();
    let (lo, hi) = (d.iter().min().unwrap(), d.iter().max().unwrap());
    assert!(
        (*hi).checked_sub(*lo).unwrap() < Duration::from_millis(2),
        "{lo:?} {hi:?}"
    );
    assert!(bwe.estimate() > 300_000);
    // Unknown streams and unavailable / over-range offsets produce no result.
    let fb = CcfbFeedback {
        sender_ssrc: 9,
        streams: vec![
            CcfbStream {
                ssrc: 77,
                begin_seq: 0,
                reports: vec![None],
            },
            CcfbStream {
                ssrc: 1,
                begin_seq: 59_999,
                reports: vec![Some(CcfbMetric {
                    ecn: 0,
                    arrival_offset: CCFB_ATO_OVERRANGE,
                })],
            },
        ],
        report_timestamp: 0,
    };
    tx.on_sent(1, 59_999, t0, 100);
    assert_eq!(tx.on_feedback(t0, &fb), []);
    // A packet reported twice in one feedback (overlapping blocks) gives one result; a
    // "received" report wins over "lost".
    tx.on_sent(3, 10, t0, 100);
    let lost = CcfbStream {
        ssrc: 3,
        begin_seq: 10,
        reports: vec![None],
    };
    let got = CcfbStream {
        ssrc: 3,
        begin_seq: 10,
        reports: vec![Some(CcfbMetric {
            ecn: 0,
            arrival_offset: 1,
        })],
    };
    let twice = |streams| CcfbFeedback {
        sender_ssrc: 9,
        streams,
        report_timestamp: 1 << 16,
    };
    assert_eq!(
        tx.on_feedback(t0, &twice(vec![lost.clone(), lost.clone()]))
            .len(),
        1
    );
    let r = tx.on_feedback(t0, &twice(vec![lost, got]));
    assert_eq!(r.len(), 1);
    assert!(r[0].received.is_some());
}

// --- FEC ---

/// libwebrtc's ULPFEC-form masks and the FlexFEC-03 masks its writer produces / its reader
/// accepts (flexfec_03_header_reader_writer_unittest.cc).
const LW_FLEXFEC03_MASKS: [(&str, &str); 4] = [
    ("1102", "8881"),
    ("910208440084", "488182110021"),
    ("222244444441", "11111111111 0a0000000000000 00"),
    (
        "9102084400840888888888888888",
        "4881021100218111111111111111",
    ),
];

fn offsets(ulp: &[u8]) -> Vec<u16> {
    (0..ulp.len() * 8)
        .filter(|&i| ulp[i / 8] & (0x80 >> (i % 8)) != 0)
        .map(|i| i as u16)
        .collect()
}

#[test]
fn flexfec03_libwebrtc_header_vectors() {
    for (i, (ulp, flex)) in LW_FLEXFEC03_MASKS.iter().enumerate() {
        let ulp = hex(ulp);
        let flex = hex(flex);
        let mut o = offsets(&ulp);
        // The reader case with K-bit 2: bits past offset 108 do not exist.
        o.retain(|&x| x <= 108);
        let h = FecHeader {
            pxcc_recovery: 0,
            mpt_recovery: 123,
            length_recovery: 0xabcd,
            ts_recovery: 0x0123_4567,
            ssrc: Some(0x1122_3344),
            base_seq: 0xaabb,
            offsets: o.clone(),
            header_len: 0,
            protection_len: 0,
            ulp_levels: Vec::new(),
        };
        let w = h.write(FecScheme::Flexfec03);
        let mut want = hex("007babcd 01234567 01000000 11223344 aabb");
        want.extend_from_slice(&flex);
        if i < 3 {
            // The writer cases.
            assert_eq!(w, want, "case {i}");
        }
        // The reader: libwebrtc's packets plus 4 payload bytes.
        want.extend_from_slice(&[0; 4]);
        let p = FecHeader::parse(FecScheme::Flexfec03, &want).unwrap();
        assert_eq!(p.offsets, o, "case {i}");
        assert_eq!(p.header_len, 18 + flex.len());
        assert_eq!(p.protection_len, 4);
        assert_eq!(
            (
                p.mpt_recovery,
                p.length_recovery,
                p.ts_recovery,
                p.ssrc,
                p.base_seq
            ),
            (123, 0xabcd, 0x0123_4567, Some(0x1122_3344), 0xaabb)
        );
    }
    // R / F bits, SSRCCount != 1, a missing K-bit 2, truncation: rejected.
    let ok = hex("007babcd 01234567 01000000 11223344 aabb 8881");
    assert!(FecHeader::parse(FecScheme::Flexfec03, &ok).is_some());
    for (i, v) in [0x80u8, 0x40].into_iter().enumerate() {
        let mut b = ok.clone();
        b[0] |= v;
        assert!(FecHeader::parse(FecScheme::Flexfec03, &b).is_none(), "{i}");
    }
    let mut b = ok.clone();
    b[8] = 2;
    assert!(FecHeader::parse(FecScheme::Flexfec03, &b).is_none());
    let no_k2 = hex("007babcd 01234567 01000000 11223344 aabb 0881 02110021 0000000000000000");
    assert!(FecHeader::parse(FecScheme::Flexfec03, &no_k2).is_none());
    assert!(FecHeader::parse(FecScheme::Flexfec03, &ok[..19]).is_none());
}

#[test]
fn ulpfec_and_rfc8627_headers() {
    // libwebrtc ulpfec_header_reader_writer_unittest.cc: L clear and L set.
    let short = hex("0012abcd 12345678 abcd1122 3344 00000000");
    let h = FecHeader::parse(FecScheme::Ulpfec, &short).unwrap();
    assert_eq!(
        (h.base_seq, h.header_len, h.protection_len),
        (0xabcd, 14, 0x1122)
    );
    assert_eq!(
        (h.ts_recovery, h.length_recovery, h.mpt_recovery),
        (0x1234_5678, 0xabcd, 0x12)
    );
    assert_eq!(h.offsets, offsets(&hex("3344")));
    let long = hex("4012abcd 12345678 abcd1122 33445566 7788 00000000");
    let h2 = FecHeader::parse(FecScheme::Ulpfec, &long).unwrap();
    assert_eq!(h2.header_len, 18);
    assert_eq!(h2.offsets, offsets(&hex("334455667788")));
    assert_eq!(h.write(FecScheme::Ulpfec), short[..14]);
    assert_eq!(h2.write(FecScheme::Ulpfec), long[..18]);
    // E bit set: unsupported.
    let mut e = short;
    e[0] |= 0x80;
    assert!(FecHeader::parse(FecScheme::Ulpfec, &e).is_none());
    // RFC 8627 Figure 12: k = 1 means another segment follows; the third has no k bit.
    for o in [vec![0u16, 14], vec![0, 15, 45], vec![1, 46, 109]] {
        let h = FecHeader {
            pxcc_recovery: 0x21,
            mpt_recovery: 0x80 | 96,
            length_recovery: 7,
            ts_recovery: 9,
            ssrc: None,
            base_seq: 65535,
            offsets: o.clone(),
            header_len: 0,
            protection_len: 0,
            ulp_levels: Vec::new(),
        };
        let w = h.write(FecScheme::Flexfec);
        let p = FecHeader::parse(FecScheme::Flexfec, &w).unwrap();
        assert_eq!(p.offsets, o);
        assert_eq!(p.header_len, w.len());
        assert_eq!(w[0], 0x21);
        match o.last() {
            Some(14) => assert_eq!(&w[8..], &hex("ffff 4001")[..]),
            Some(45) => assert_eq!(w[10..12], [0xc0, 0x00]),
            _ => assert_eq!(w.len(), 24),
        }
    }
    // A mask without bits protects nothing.
    assert!(FecHeader::parse(FecScheme::Flexfec, &hex("00000000 00000000 00000000")).is_none());
}

/// Seeds for the `rtp_fec` fuzz corpus: per scheme, a FEC payload of two packets, a RED
/// payload, and pseudo-packets (`[kind][len][bytes]`) of media and FEC.
pub(crate) fn fec_seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (sel, scheme) in [FecScheme::Ulpfec, FecScheme::Flexfec03, FecScheme::Flexfec]
        .into_iter()
        .enumerate()
    {
        let ssrc = 0x0102_0304;
        let a = media_packet(ssrc, 100, 1);
        let b = media_packet(ssrc, 101, 2);
        let fec = FecEncoder::new(scheme, ssrc, 1)
            .encode(&[&a[..60], &b[..40]], &[vec![0, 1]])
            .unwrap()
            .remove(0);
        let mut s = vec![sel as u8];
        s.extend_from_slice(&fec);
        out.push(s);
        let mut s = vec![sel as u8];
        for (kind, body) in [(2u8, &a[..60]), (1, &fec[..])] {
            s.push(kind);
            s.push(body.len() as u8);
            s.extend_from_slice(body);
        }
        out.push(s);
    }
    let mut s = vec![0];
    s.extend(red::write(&[
        red::RedBlock {
            pt: 5,
            timestamp_offset: 320,
            data: b"abc",
        },
        red::RedBlock {
            pt: 0,
            timestamp_offset: 0,
            data: b"primary",
        },
    ]));
    out.push(s);
    out
}

#[test]
fn fec_seeds_decode() {
    for s in fec_seeds() {
        fuzzing::rtp_fec(&s);
    }
}

/// A deterministic generator for loss patterns.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }
}

/// RTP packets with varying CSRCs, extensions, padding, markers and lengths.
fn media_packet(ssrc: u32, seq: u16, i: u32) -> Vec<u8> {
    let map = ExtensionMap::default_video();
    let h = RtpHeader {
        marker: i % 10 == 9,
        payload_type: 96 + (i % 3) as u8,
        sequence_number: seq,
        timestamp: 3000 * (i / 10),
        ssrc,
        csrc: (0..i % 3).collect(),
        ext: ExtensionValues {
            mid: (i % 4 == 0).then(|| "v".to_string()),
            transport_cc: Some(i as u16),
            ..Default::default()
        },
        padding_len: if i % 7 == 0 { 3 } else { 0 },
        ..RtpHeader::default()
    };
    let payload: Vec<u8> = (0..(50 + (i * 37) % 900)).map(|b| (b ^ i) as u8).collect();
    h.write(&map, &payload)
}

/// Sends `n` packets through `scheme` FEC with `rate`, drops packets per `drop(index)`
/// (FEC packets are indexed after the media), and returns (lost media, recovered media).
fn run_fec(
    scheme: FecScheme,
    rate: u8,
    n: u32,
    mut drop: impl FnMut(bool) -> bool,
) -> (usize, usize) {
    let ssrc = 0x1234;
    let mut enc = FecEncoder::new(scheme, ssrc, rate);
    let mut dec = FecDecoder::new(scheme, ssrc);
    let mut sent = std::collections::HashMap::new();
    let mut lost = std::collections::HashSet::new();
    let mut recovered = 0;
    let mut check = |pkts: Vec<Vec<u8>>, sent: &std::collections::HashMap<u16, Vec<u8>>| {
        for p in pkts {
            let seq = u16::from_be_bytes([p[2], p[3]]);
            assert_eq!(Some(&p), sent.get(&seq), "recovered {seq} differs");
            recovered += 1;
        }
    };
    for i in 0..n {
        let seq = (65_000 + i) as u16;
        let pkt = media_packet(ssrc, seq, i);
        sent.insert(seq, pkt.clone());
        let fec = enc.push(&pkt, i % 10 == 9);
        if drop(false) {
            lost.insert(seq);
        } else {
            let r = dec.on_media(&pkt);
            check(r, &sent);
        }
        for f in fec {
            let payload = match scheme {
                // Through RED as WebRTC sends it.
                FecScheme::Ulpfec => {
                    let red = red::write(&[red::RedBlock {
                        pt: 117,
                        timestamp_offset: 0,
                        data: &f,
                    }]);
                    let blocks = red::parse(&red).unwrap();
                    assert_eq!(blocks[0].pt, 117);
                    blocks[0].data.to_vec()
                }
                _ => f,
            };
            if !drop(true) {
                let r = dec.on_fec(&payload);
                check(r, &sent);
            }
        }
    }
    assert_eq!(dec.recovered() as usize, recovered);
    (lost.len(), recovered)
}

#[test]
fn fec_recovers_bursts_within_a_group() {
    for scheme in [FecScheme::Ulpfec, FecScheme::Flexfec03, FecScheme::Flexfec] {
        // 50 %: 5 interleaved FEC packets per 10-packet frame; lose the first 5 media
        // packets of every frame (a burst) and no FEC.
        let mut k = 0u32;
        let (lost, rec) = run_fec(scheme, 128, 200, |is_fec| {
            if is_fec {
                return false;
            }
            k += 1;
            (k - 1) % 10 < 5
        });
        assert_eq!((lost, rec), (100, 100), "{scheme:?}");
        // A burst of 6 in a frame protected by 5 interleaved packets: 4 recoverable.
        let mut k = 0u32;
        let (lost, rec) = run_fec(scheme, 128, 100, |is_fec| {
            if is_fec {
                return false;
            }
            k += 1;
            (k - 1) % 10 < 6
        });
        assert_eq!((lost, rec), (60, 40), "{scheme:?}");
    }
}

#[test]
fn fec_under_random_loss() {
    for scheme in [FecScheme::Ulpfec, FecScheme::Flexfec03, FecScheme::Flexfec] {
        let mut rng = Lcg(42);
        // 5 % random loss of media and FEC, 30 % protection.
        let (lost, rec) = run_fec(scheme, 77, 5000, |_| rng.next() % 100 < 5);
        assert!(lost > 200, "{lost}");
        // Most losses come back.
        assert!(
            rec * 100 >= lost * 70,
            "{scheme:?}: lost {lost}, recovered {rec}"
        );
    }
    // No protection: nothing comes back.
    let mut rng = Lcg(7);
    let (lost, rec) = run_fec(FecScheme::Flexfec03, 0, 500, |_| rng.next() % 10 == 0);
    assert!(lost > 0 && rec == 0);
}

#[test]
fn fec_encoder_groups_and_explicit_masks() {
    let ssrc = 5;
    let pkts: Vec<Vec<u8>> = (0..60)
        .map(|i| media_packet(ssrc, 65_530u16.wrapping_add(i as u16), i))
        .collect();
    // Groups close at MAX_FEC_GROUP packets without a marker.
    let mut enc = FecEncoder::new(FecScheme::Ulpfec, ssrc, 255);
    let mut out = 0;
    for p in &pkts {
        out += enc.push(p, false).len();
    }
    assert_eq!(out, 48);
    assert_eq!(enc.flush().len(), 12);
    // Other SSRCs, non-RTP input and rate 0 produce nothing.
    assert!(enc.push(&media_packet(6, 1, 1), true).is_empty());
    assert!(enc.push(&[0u8; 5], true).is_empty());
    enc.set_rate(0);
    assert_eq!(enc.rate(), 0);
    assert!(enc.push(&pkts[0], true).is_empty());
    // Explicit masks: one parity packet over 3 packets across the sequence wrap.
    let enc = FecEncoder::new(FecScheme::Flexfec, ssrc, 1);
    let refs: Vec<&[u8]> = pkts[4..7].iter().map(Vec::as_slice).collect();
    let fec = enc.encode(&refs, &[vec![0, 1, 2]]).unwrap();
    let h = FecHeader::parse(FecScheme::Flexfec, &fec[0]).unwrap();
    assert_eq!((h.base_seq, h.offsets), (65_534, vec![0, 1, 2]));
    let mut dec = FecDecoder::new(FecScheme::Flexfec, ssrc);
    assert!(dec.on_media(&pkts[4]).is_empty());
    assert!(dec.on_media(&pkts[6]).is_empty());
    assert_eq!(dec.on_fec(&fec[0]), [pkts[5].clone()]);
    // Spans beyond the mask and foreign packets are refused.
    let wide: Vec<&[u8]> = vec![&pkts[0], &pkts[59]];
    assert!(
        FecEncoder::new(FecScheme::Ulpfec, ssrc, 1)
            .encode(&wide, &[vec![0, 1]])
            .is_none()
    );
    assert!(
        FecEncoder::new(FecScheme::Flexfec03, ssrc, 1)
            .encode(&wide, &[vec![0, 1]])
            .is_some()
    );
    assert!(enc.encode(&[&media_packet(9, 1, 1)], &[vec![0]]).is_none());
    assert_eq!(interleaved_masks(5, 2), [vec![0, 2, 4], vec![1, 3]]);
    assert_eq!(interleaved_masks(2, 9), [vec![0], vec![1]]);
}

#[test]
fn fec_decoder_ignores_foreign_and_short() {
    let mut dec = FecDecoder::new(FecScheme::Flexfec03, 5);
    let p = media_packet(5, 10, 1);
    let q = media_packet(5, 11, 2);
    let enc = FecEncoder::new(FecScheme::Flexfec03, 5, 1);
    let fec = enc.encode(&[&p, &q], &[vec![0, 1]]).unwrap().remove(0);
    // flexfec-03 for another SSRC.
    let mut other = fec.clone();
    other[12] ^= 1;
    assert!(dec.on_fec(&other).is_empty());
    assert!(dec.on_media(&media_packet(6, 10, 1)).is_empty());
    assert!(dec.on_media(&p).is_empty());
    assert_eq!(dec.on_fec(&fec), std::slice::from_ref(&q));
    // ULPFEC whose protection length exceeds the payload is ignored.
    let mut dec = FecDecoder::new(FecScheme::Ulpfec, 5);
    let u = FecEncoder::new(FecScheme::Ulpfec, 5, 1)
        .encode(&[&p, &q], &[vec![0, 1]])
        .unwrap()
        .remove(0);
    assert!(dec.on_media(&p).is_empty());
    assert!(dec.on_fec(&u[..u.len() - 1]).is_empty());
    assert_eq!(dec.on_fec(&u), [q]);
}

#[test]
fn red_blocks_wrap_and_unwrap() {
    // RFC 2198 §3 example layout: one redundant block (PT 5, offset 320, 7 bytes) then the
    // primary (PT 0).
    let blocks = [
        red::RedBlock {
            pt: 5,
            timestamp_offset: 320,
            data: b"redund!",
        },
        red::RedBlock {
            pt: 0,
            timestamp_offset: 0,
            data: b"primary",
        },
    ];
    let w = red::write(&blocks);
    assert_eq!(&w[..5], &[0x85, 0x05, 0x00, 0x07, 0x00]);
    assert_eq!(red::parse(&w).unwrap(), blocks);
    // Truncated headers or blocks.
    assert!(red::parse(&w[..3]).is_none());
    assert!(red::parse(&w[..8]).is_none());
    assert!(red::parse(&[]).is_none());
    // Oversized redundant blocks are dropped.
    let big = vec![0u8; 1024];
    let w = red::write(&[
        red::RedBlock {
            pt: 1,
            timestamp_offset: 0,
            data: &big,
        },
        blocks[1],
    ]);
    assert_eq!(w[0], 0);
    assert!(red::write(&[]).is_empty());
    // Wrap / unwrap an RTP packet keeps the header and extensions.
    let map = ExtensionMap::default_video();
    let p = media_packet(5, 77, 7); // with padding
    let red_pkt = red::wrap(&p, 116).unwrap();
    let h = RtpHeader::parse(&red_pkt, &map).unwrap();
    assert_eq!((h.payload_type, h.padding_len), (116, 0));
    let back = red::unwrap_primary(&red_pkt).unwrap();
    let orig = RtpHeader::parse(&p, &map).unwrap();
    let hb = RtpHeader::parse(&back, &map).unwrap();
    assert_eq!(hb.payload_type, orig.payload_type);
    assert_eq!(hb.ext, orig.ext);
    assert_eq!(hb.payload(&back), orig.payload(&p));
    assert!(red::wrap(&[1, 2], 1).is_none());
}

#[test]
fn recovered_packets_stop_nacks_but_count_as_lost() {
    let t0 = Instant::now();
    let mut r = RecvStream::new(1, 90_000, true);
    for seq in [10u16, 11, 13, 14] {
        r.receive(t0, seq, 0);
    }
    assert_eq!(r.missing_count(), 1);
    // FEC rebuilt 12: no NACK for it, but the report still shows it lost.
    assert_eq!(r.receive_recovered(t0, 12), Some(12));
    assert_eq!(r.missing_count(), 0);
    assert_eq!(r.poll_nack(t0 + Duration::from_secs(1)), None);
    let rb = r.report_block(t0).unwrap();
    assert_eq!((rb.cumulative_lost, rb.fraction_lost), (1, 51));
    assert_eq!(r.packets_received(), 4);
    // A late copy is a duplicate (not counted), and so is recovering it again.
    assert_eq!(r.receive(t0, 12, 0), None);
    assert_eq!(r.receive_recovered(t0, 12), None);
    assert_eq!(r.duplicates(), 1);
    // A recovered packet beyond the highest one advances it.
    assert_eq!(r.receive_recovered(t0, 16), Some(16));
    assert_eq!(r.extended_highest_seq(), Some(16));
    assert_eq!(r.missing_count(), 1);
}
