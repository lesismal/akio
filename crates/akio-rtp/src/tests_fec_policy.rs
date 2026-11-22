//! libwebrtc's FEC masks and group rules, the protection policy, partially rebuilt packets and
//! the E-model (ADR-073).

use std::time::{Duration, Instant};

use crate::codec::{CodecKind, FrameAssembler};
use crate::fec::{
    FecDecoder, FecEncoder, FecMaskType, FecProtection, FecScheme, ProtectionPolicy,
    interleaved_masks, packet_masks, protection_factors,
};
use crate::{BurstLossModel, EModel, ExtensionMap, ExtensionValues, RtpHeader, VoipQuality};
use crate::{VOIP_UNAVAILABLE, mos_from_r};

fn bits(k: usize, rows: &[u16]) -> Vec<Vec<usize>> {
    rows.iter()
        .map(|&r| (0..k).filter(|&j| r & (0x8000 >> j) != 0).collect())
        .collect()
}

#[test]
fn libwebrtc_mask_tables() {
    // Spot checks against fec_private_tables_{random,bursty}.cc.
    assert_eq!(packet_masks(1, 1, FecMaskType::Random), bits(1, &[0x8000]));
    assert_eq!(
        packet_masks(3, 3, FecMaskType::Random),
        bits(3, &[0xc000, 0xa000, 0x6000])
    );
    assert_eq!(
        packet_masks(4, 4, FecMaskType::Random),
        bits(4, &[0xc000, 0xa000, 0x3000, 0x5000])
    );
    assert_eq!(
        packet_masks(5, 2, FecMaskType::Random),
        bits(5, &[0xa800, 0xd000])
    );
    // Above 12 packets: interleaved, as libwebrtc builds them.
    assert_eq!(
        packet_masks(13, 4, FecMaskType::Random),
        interleaved_masks(13, 4)
    );
    assert_eq!(
        packet_masks(30, 5, FecMaskType::Bursty),
        interleaved_masks(30, 5)
    );
    assert!(packet_masks(0, 3, FecMaskType::Random).is_empty());
    // m is clamped to 1..=k.
    assert_eq!(packet_masks(3, 9, FecMaskType::Random).len(), 3);
    assert_eq!(packet_masks(3, 0, FecMaskType::Random).len(), 1);
    // Every table entry: m masks, each non-empty and within the group, and together they
    // cover every media packet.
    for mask in [FecMaskType::Random, FecMaskType::Bursty] {
        for k in 1..=12 {
            for m in 1..=k {
                let ms = packet_masks(k, m, mask);
                assert_eq!(ms.len(), m);
                for x in &ms {
                    assert!(
                        !x.is_empty() && x.iter().all(|&j| j < k),
                        "{mask:?} {k} {m}"
                    );
                }
                for j in 0..k {
                    assert!(ms.iter().any(|x| x.contains(&j)), "{mask:?} {k} {m} {j}");
                }
            }
        }
    }
    // The two tables differ (bursty masks favour consecutive packets).
    assert_ne!(
        packet_masks(10, 5, FecMaskType::Random),
        packet_masks(10, 5, FecMaskType::Bursty)
    );
}

fn pkt(ssrc: u32, seq: u16, ts: u32, marker: bool, len: usize) -> Vec<u8> {
    let h = RtpHeader {
        marker,
        payload_type: 96,
        sequence_number: seq,
        timestamp: ts,
        ssrc,
        ext: ExtensionValues::default(),
        ..RtpHeader::default()
    };
    let payload: Vec<u8> = (0..len).map(|i| (i as u16 ^ seq) as u8).collect();
    h.write(&ExtensionMap::default(), &payload)
}

#[test]
fn groups_span_frames_as_libwebrtc() {
    let ssrc = 7;
    // Factor 128 (> 80: at least 4 packets), up to 6 frames per group, one packet per
    // frame: the group closes after 4 frames (2 FEC packets: exactly the factor).
    let mut e = FecEncoder::new(FecScheme::Ulpfec, ssrc, 0);
    e.set_protection(FecProtection {
        max_frames: 6,
        ..FecProtection::rate(128)
    });
    let mut out = Vec::new();
    for i in 0..12u16 {
        let f = e.push(&pkt(ssrc, i, u32::from(i) * 3000, true, 100), true);
        out.push(f.len());
    }
    assert_eq!(out, [0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2]);
    // Factor 20 (<= 80: 1 packet suffices) with 3-packet frames: the first frame's 3 packets
    // would need 1 FEC packet (85 / 256: over the factor by 65 >= 50), so it waits.
    let mut e = FecEncoder::new(FecScheme::Ulpfec, ssrc, 0);
    e.set_protection(FecProtection {
        max_frames: 6,
        ..FecProtection::rate(20)
    });
    let mut n = 0;
    for i in 0..3u16 {
        n += e.push(&pkt(ssrc, i, 0, i == 2, 100), i == 2).len();
    }
    assert_eq!(n, 0, "1 FEC for 3 packets: 85 - 20 >= 50, wait for more");
    let mut closed_at = None;
    for f in 1..6u16 {
        for i in 0..3u16 {
            let s = 3 * f + i;
            let fec = e.push(&pkt(ssrc, s, u32::from(f) * 3000, i == 2, 100), i == 2);
            if !fec.is_empty() && closed_at.is_none() {
                closed_at = Some(f);
            }
        }
    }
    // 6 packets: 1 FEC (42 / 256 for 20); it closes at the second frame.
    assert_eq!(closed_at, Some(1));
    // max_frames 1 (the default): every frame end closes the group.
    let mut e = FecEncoder::new(FecScheme::Flexfec03, ssrc, 40);
    assert_eq!(e.push(&pkt(ssrc, 0, 0, true, 100), true).len(), 1);
    // Key frames use the key factor: 255 gives one FEC per packet.
    let mut e = FecEncoder::new(FecScheme::Ulpfec, ssrc, 0);
    e.set_protection(FecProtection {
        delta_rate: 26,
        key_rate: 255,
        max_frames: 1,
        mask: FecMaskType::Random,
    });
    let mut key = 0;
    for i in 0..4u16 {
        key += e
            .push_frame(&pkt(ssrc, i, 0, i == 3, 100), i == 3, true)
            .len();
    }
    let mut delta = 0;
    for i in 4..8u16 {
        delta += e
            .push_frame(&pkt(ssrc, i, 3000, i == 7, 100), i == 7, false)
            .len();
    }
    assert_eq!((key, delta), (4, 1));
    // Off: nothing, and the group is reset.
    e.set_rate(0);
    assert!(e.push(&pkt(ssrc, 8, 6000, true, 100), true).is_empty());
}

#[test]
fn protection_follows_loss_rtt_and_frames() {
    let rtt = |ms| Duration::from_millis(ms);
    // 30 fps at 720 kbps (24 kbits / frame), 3 packets per frame, keyframes of 10.
    let f = |loss: f64, nack: bool, r: Duration| {
        protection_factors(loss, 720_000, 30.0, 3.0, 10.0, None, nack, r)
    };
    assert_eq!(f(0.0, false, rtt(50)).delta_rate, 0);
    let mut last = 0;
    for l in [0.01, 0.02, 0.05, 0.1, 0.2, 0.3] {
        let p = f(l, false, rtt(50));
        assert!(p.delta_rate >= last, "{l}: {p:?}");
        assert!(p.key_rate >= p.delta_rate, "{l}: {p:?}");
        assert_eq!(p.max_frames, 1);
        last = p.delta_rate;
    }
    assert!(
        f(0.05, false, rtt(50)).delta_rate >= 64,
        "at least 20 % code rate"
    );
    // The hybrid: no delta FEC below 20 ms; groups grow with the RTT (2 x 30 fps x RTT).
    let low = f(0.05, true, rtt(10));
    assert!(low.delta_rate == 0 && low.key_rate > 0, "{low:?}");
    assert_eq!(f(0.05, true, rtt(20)).max_frames, 1);
    assert_eq!(f(0.05, true, rtt(50)).max_frames, 3);
    assert_eq!(f(0.05, true, rtt(300)).max_frames, 6);
    assert!(f(0.05, true, rtt(50)).delta_rate > 0);
    // Small frames (under 700 bytes at 4CIF) and an RTT under 200 ms: NACK alone.
    let small = protection_factors(0.05, 120_000, 30.0, 1.0, 3.0, None, true, rtt(100));
    assert_eq!((small.delta_rate, small.key_rate), (0, 0));
    // From 200 ms on, the table's protection (none for delta frames this small, some for
    // key frames).
    let small_far = protection_factors(0.05, 120_000, 30.0, 1.0, 3.0, None, true, rtt(250));
    assert!(small_far.key_rate > 0, "{small_far:?}");
    // Without NACK too.
    let p = protection_factors(0.05, 120_000, 30.0, 1.0, 3.0, None, false, rtt(100));
    assert_eq!(
        p,
        FecProtection {
            max_frames: 1,
            ..small_far
        }
    );
    // A larger picture lowers the bits per pixel: no less protection than a smaller one at
    // the same bitrate.
    let big = protection_factors(
        0.05,
        720_000,
        30.0,
        3.0,
        10.0,
        Some(1280 * 720),
        false,
        rtt(50),
    );
    let cif = protection_factors(
        0.05,
        720_000,
        30.0,
        3.0,
        10.0,
        Some(352 * 288),
        false,
        rtt(50),
    );
    assert!(big.delta_rate >= cif.delta_rate, "{big:?} {cif:?}");
}

#[test]
fn policy_measures_the_stream() {
    let t0 = Instant::now();
    let mut pol = ProtectionPolicy::new(false);
    // 30 fps of 3 kB frames, a keyframe every second, until `until` (seconds).
    let mut sent = 0u64;
    let mut run = |pol: &mut ProtectionPolicy, until: u64| {
        while sent * 33 <= until * 1000 {
            pol.on_frame(
                t0 + Duration::from_millis(sent * 33),
                3,
                3000,
                sent % 30 == 0,
            );
            sent += 1;
        }
        t0 + Duration::from_millis((sent - 1) * 33)
    };
    let now = run(&mut pol, 2);
    assert_eq!(pol.protection(now).delta_rate, 0);
    // Loss is kept as the maximum of the last 10 s.
    pol.on_loss(now, 0.1);
    let later = run(&mut pol, 4);
    pol.on_loss(later, 0.0);
    let p = pol.protection(later);
    assert!(p.delta_rate > 0, "{p:?}");
    let t = run(&mut pol, 10);
    assert_eq!(p, pol.protection(t));
    let t = run(&mut pol, 14);
    assert_eq!(pol.protection(t).delta_rate, 0);
    // Masks follow the setting.
    pol.set_mask(FecMaskType::Bursty);
    pol.on_loss(t, 0.1);
    assert_eq!(pol.protection(t).mask, FecMaskType::Bursty);
    // The hybrid needs the RTT: below 20 ms, NACK.
    pol.set_nack(true);
    pol.set_rtt(Duration::from_millis(5));
    assert_eq!(pol.protection(t).delta_rate, 0);
    // An idle stream (no frame in the last second) has no bits per frame to protect.
    assert!(pol.protection(t + Duration::from_secs(5)).delta_rate == 0);
}

#[test]
fn partially_rebuilt_packets() {
    let ssrc = 9;
    // Three 300-byte packets protected by three FEC packets with a 40-byte level 0 and a
    // level 1 over the group in the last; lose packets 0 and 1: level 0 rebuilds their
    // starts, level 1 cannot (two missing).
    let mut e = FecEncoder::new(FecScheme::Ulpfec, ssrc, 255);
    e.set_ulp_level0(Some(40));
    let media: Vec<Vec<u8>> = (0..3u16)
        .map(|i| pkt(ssrc, 100 + i, 9000, i == 2, 300))
        .collect();
    let mut fec = Vec::new();
    for (i, m) in media.iter().enumerate() {
        fec.extend(e.push(m, i == 2));
    }
    assert_eq!(fec.len(), 3);
    let mut d = FecDecoder::new(FecScheme::Ulpfec, ssrc);
    assert!(d.on_media(&media[2]).is_empty());
    for f in &fec {
        assert!(d.on_fec(f).is_empty());
    }
    assert_eq!(d.partially_recovered(), 2);
    // Not while packets of the same frame arrive.
    assert!(d.take_partials(9000).is_empty());
    let parts = d.take_partials(12_000);
    assert_eq!(parts.len(), 2);
    for (p, m) in parts.iter().zip(&media) {
        assert_eq!(p.length, m.len() - 12);
        assert_eq!(p.packet.len(), 12 + 40);
        assert_eq!(p.packet[..], m[..52]);
    }
    // Taken once.
    assert!(d.take_partials(12_000).is_empty());
    // A frame with a partial packet: emitted, marked partial, with the truncated payload.
    let mut asm = FrameAssembler::new(CodecKind::Other, 30);
    let now = Instant::now();
    asm.push(1, 0, true, b"whole", now);
    let f = asm.pop().expect("frame");
    assert!(!f.partial);
    asm.push_partial(2, 3000, true, b"start", now);
    let f = asm.pop().expect("partial frame");
    assert!(f.partial && f.data == b"start");
}

#[test]
fn emodel_scores() {
    let e = EModel::default();
    // No impairment: R = 93.2, MOS 4.41 (tests_voip has the G.107 reference cases).
    let s0 = e.score(0.0, 1.0, Duration::ZERO);
    // 5 % random loss with G.711 + PLC: Ie,eff = 95 x 5 / (5 + 25.1) = 15.78.
    let s = e.score(0.05, 1.0, Duration::ZERO);
    assert!(
        (s0.r_factor - s.r_factor - 95.0 * 5.0 / 30.1).abs() < 1e-9,
        "{s:?}"
    );
    // Bursty loss hurts more.
    let b = e.score(0.05, 3.0, Duration::ZERO);
    assert!(b.r_factor < s.r_factor);
    // A codec without concealment.
    assert!(
        EModel::codec(0.0, 4.3)
            .score(0.05, 1.0, Duration::ZERO)
            .r_factor
            < s.r_factor
    );
    assert!((mos_from_r(50.0) - 2.58).abs() < 0.01);
    // The receiver's view: half the RTT plus a jitter buffer of twice the jitter.
    let r = e.estimate(
        0.0,
        1.0,
        Some(Duration::from_millis(200)),
        Duration::from_millis(30),
        Duration::from_millis(20),
        None,
    );
    let d = e.score(0.0, 1.0, Duration::from_millis(100 + 60 + 20));
    assert!((r.r_factor - d.r_factor).abs() < 1e-9);
    // Into the VoIP metrics block: R and MOS x 10.
    let mut q = VoipQuality::default();
    s.apply(&mut q);
    let m = BurstLossModel::default().report(1, 20, &q);
    assert_eq!(m.r_factor, s.r_factor.round() as u8);
    assert_eq!(u32::from(m.mos_cq), (s.mos_cq * 10.0).round() as u32);
    assert_ne!(m.mos_lq, VOIP_UNAVAILABLE);
}

#[test]
fn burst_ratio_from_the_loss_pattern() {
    // Random-looking single losses: about 1.
    let mut m = BurstLossModel::default();
    for i in 0..2000u32 {
        m.on_packet(i % 20 == 7, false);
    }
    assert!((m.loss_fraction() - 0.05).abs() < 1e-9);
    assert!((m.burst_ratio() - 0.95).abs() < 0.01, "{}", m.burst_ratio());
    // Runs of 4 losses every 80 packets: (1 - 0.05) x 4 = 3.8.
    let mut m = BurstLossModel::default();
    for i in 0..8000u32 {
        m.on_packet(i % 80 < 4, false);
    }
    assert!((m.burst_ratio() - 3.8).abs() < 0.01, "{}", m.burst_ratio());
    // Nothing lost: 1.
    assert_eq!(BurstLossModel::default().burst_ratio(), 1.0);
}
