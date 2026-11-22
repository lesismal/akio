//! E-model reference cases (ITU-T G.107, G.107.1, G.109, G.113) and VoIP metrics round trips.

use std::time::Duration;

use crate::rtcp::{parse_compound, write_compound};
use crate::{
    BurstLossModel, EModel, JitterBufferConfig, Plc, Rtcp, VOIP_UNAVAILABLE, VoipQuality, XrBlock,
    mos_from_r,
};

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

#[test]
fn emodel_g107_defaults() {
    // G.107 §7: every parameter at its default gives R = 93.2.
    let s = EModel::default().score(0.0, 1.0, Duration::ZERO);
    assert!((s.r_factor - 93.2).abs() < 0.05, "{s:?}");
    assert!((s.r_lq - s.r_factor).abs() < 1e-9);
    assert!((s.mos_cq - 4.41).abs() < 0.005, "{s:?}");
    // G.107.1 (the ITU-T SG12 wideband E-model calculator): R = 128.8, MOS 4.50 with every
    // default (Ie,wb 0, Bpl 4.3); on the narrowband scale 128.8 / 1.29.
    let w = EModel::wideband(0.0, 4.3).score(0.0, 1.0, Duration::ZERO);
    assert!((w.r_factor * 1.29 - 128.8).abs() < 0.05, "{w:?}");
    assert!((w.mos_cq - 4.50).abs() < 0.005, "{w:?}");
}

#[test]
fn emodel_g109_mos_table() {
    // G.109 Table 1: the R of each category boundary and its MOS (G.107 Annex B; G.109
    // rounds 4.024 up to 4.03).
    for (r, mos) in [
        (90.0, 4.34),
        (80.0, 4.03),
        (70.0, 3.60),
        (60.0, 3.10),
        (50.0, 2.58),
    ] {
        assert!(
            (mos_from_r(r) - mos).abs() < 0.0075,
            "R {r}: {}",
            mos_from_r(r)
        );
    }
    assert_eq!(mos_from_r(-5.0), 1.0);
    assert_eq!(mos_from_r(120.0), 4.5);
}

#[test]
fn emodel_g107_delay() {
    let id = |v| EModel::delay_impairment(ms(v));
    // Listener echo alone at 0 ms (WEPL 110 dB): part of the 93.2.
    assert!((id(0) - 0.149).abs() < 0.001, "{}", id(0));
    // By hand from G.107 §7.4 with the defaults (Ta = T, Tr = 2T): at 150 ms Idte 2.81,
    // Idle 0.84, Idd 0.16; at 300 ms Idte 4.83, Idle 1.09, Idd 14.75.
    assert!((id(150) - 3.82).abs() < 0.02, "{}", id(150));
    assert!((id(300) - 20.69).abs() < 0.03, "{}", id(300));
    // Cole and Rosenbluth's fit of the default curve (Id = 0.024 d + 0.11 (d - 177.3) H),
    // within a point up to 300 ms.
    for d in (0..=300).step_by(10) {
        let cole = 0.024 * d as f64
            + if d as f64 > 177.3 {
                0.11 * (d as f64 - 177.3)
            } else {
                0.0
            };
        assert!((id(d) - cole).abs() < 1.0, "{d} ms: {} vs {cole}", id(d));
    }
    // Monotone; delay lowers the conversational score only.
    assert!((1..60).all(|i| id(i * 10) > id((i - 1) * 10)));
    let e = EModel::default();
    let near = e.score(0.02, 1.0, ms(20));
    let far = e.score(0.02, 1.0, ms(300));
    assert!((far.r_lq - near.r_lq).abs() < 1e-9 && far.mos_cq < far.mos_lq);
    assert!((near.r_factor - far.r_factor - (id(300) - id(20))).abs() < 0.01);
}

#[test]
fn emodel_g113_equipment_impairment() {
    // G.729A + VAD (Ie 11, Bpl 19) at 2 % random loss: 11 + 84 x 2 / 21 = 19.
    let g729 = EModel::for_codec("G729", Plc::Unspecified).expect("table");
    assert!((g729.equipment_impairment(0.02, 1.0) - 19.0).abs() < 1e-9);
    // Bursty (BurstR 2): 11 + 84 x 2 / (1 + 19) = 19.4.
    assert!((g729.equipment_impairment(0.02, 2.0) - 19.4).abs() < 1e-9);
    // G.711 with and without concealment at 1 %: 95 / 26.1, 95 / 5.3.
    let plc = EModel::for_codec("PCMU", Plc::Standard).expect("table");
    let none = EModel::for_codec("pcma", Plc::Disabled).expect("table");
    assert!((plc.equipment_impairment(0.01, 1.0) - 95.0 / 26.1).abs() < 1e-9);
    assert!((none.equipment_impairment(0.01, 1.0) - 95.0 / 5.3).abs() < 1e-9);
    assert_eq!(plc, EModel::default());
    // G.722 (Ie,wb 13) at 1 % on the wideband scale: 13 + 116 / 5.3.
    let g722 = EModel::for_codec("g722", Plc::Unspecified).expect("table");
    assert!(g722.is_wideband());
    assert!((g722.equipment_impairment(0.01, 1.0) - (13.0 + 116.0 / 5.3)).abs() < 1e-9);
    // Unimpaired wideband codecs rate above G.711; G.722 sits between.
    let opus = EModel::for_codec("opus", Plc::Unspecified).expect("table");
    let r = |e: EModel| e.score(0.0, 1.0, ms(40)).r_factor;
    assert!(r(opus) > r(g722) && r(g722) > r(plc) - 10.0 && r(opus) > r(plc));
    assert!(EModel::for_codec("H264", Plc::Unspecified).is_none());
    // Loss: Opus with its concealment loses less than G.722 without.
    let lossy = |e: EModel| e.score(0.03, 1.5, ms(40)).r_factor;
    assert!(lossy(opus) > lossy(g722));
    assert!(lossy(EModel::default()) < r(EModel::default()));
}

#[test]
fn codec_concealment() {
    assert_eq!(Plc::of_codec("OPUS"), Plc::Enhanced);
    assert_eq!(Plc::of_codec("G729"), Plc::Standard);
    assert_eq!(Plc::of_codec("PCMU"), Plc::Unspecified);
    assert_eq!(Plc::of_codec("G722"), Plc::Unspecified);
}

#[test]
fn estimate_from_a_report() {
    let mut m = BurstLossModel::default();
    for i in 0..1000 {
        m.on_packet(i % 25 == 3, false);
    }
    let e = EModel::default();
    let jitter = ms(10);
    let packet = ms(20);
    // No jitter buffer known: twice the jitter (at least a packet) plus a packet.
    let q = VoipQuality {
        round_trip: Some(ms(100)),
        ..VoipQuality::default()
    };
    let s = e.estimate_report(&m, &q, jitter, packet);
    let want = e.score(m.loss_fraction(), m.burst_ratio(), ms(50 + 20 + 20));
    assert_eq!(s, want);
    // The jitter buffer's nominal delay plus a packet.
    let jb = VoipQuality {
        jitter_buffer: Some(JitterBufferConfig {
            adaptive: true,
            rate: 3,
            nominal: ms(80),
            maximum: ms(120),
            abs_max: ms(300),
        }),
        ..q
    };
    let s = e.estimate_report(&m, &jb, jitter, packet);
    assert_eq!(s, e.score(m.loss_fraction(), m.burst_ratio(), ms(50 + 100)));
    // An end system delay the application measured wins.
    let end = VoipQuality {
        end_system_delay: Some(ms(30)),
        ..jb
    };
    let s = e.estimate_report(&m, &end, jitter, packet);
    assert_eq!(s, e.score(m.loss_fraction(), m.burst_ratio(), ms(80)));
    // fill keeps what the application set.
    let mut app = VoipQuality {
        mos_lq: Some(33),
        ..VoipQuality::default()
    };
    s.fill(&mut app);
    assert_eq!(app.mos_lq, Some(33));
    assert_eq!(app.r_factor, Some(s.r_factor.round() as u8));
    assert_eq!(
        app.mos_cq.map(u32::from),
        Some((s.mos_cq * 10.0).round() as u32)
    );
}

#[test]
fn voip_quality_round_trip() {
    let mut m = BurstLossModel::new(16);
    for i in 0..300 {
        m.on_packet(i % 40 == 9 || i % 40 == 10, i == 200);
    }
    let mut q = VoipQuality {
        round_trip: Some(ms(84)),
        end_system_delay: Some(ms(60)),
        signal_level: Some(-21),
        noise_level: Some(-127),
        rerl: Some(38),
        ext_r_factor: Some(77),
        plc: Plc::Enhanced,
        jitter_buffer: Some(JitterBufferConfig {
            adaptive: true,
            rate: 7,
            nominal: ms(40),
            maximum: ms(100),
            abs_max: ms(400),
        }),
        ..VoipQuality::default()
    };
    EModel::for_codec("opus", Plc::Enhanced)
        .expect("table")
        .estimate_report(&m, &q, ms(5), ms(20))
        .apply(&mut q);
    let v = m.report(0x1234, 20, &q);
    assert_eq!(v.gmin, 16);
    assert_eq!(v.rx_config, 0b1011_0111);
    // Through the wire and back.
    let w = write_compound(&[Rtcp::ExtendedReport {
        ssrc: 9,
        blocks: vec![XrBlock::VoipMetrics(v)],
    }]);
    let Ok(p) = parse_compound(&w) else { panic!() };
    let [Rtcp::ExtendedReport { blocks, .. }] = p.as_slice() else {
        panic!("{p:?}")
    };
    let [XrBlock::VoipMetrics(got)] = blocks.as_slice() else {
        panic!("{blocks:?}")
    };
    assert_eq!(*got, v);
    assert_eq!(got.quality(), q);
    // Unavailable and unknown fields come back as None.
    let u = m.report(1, 20, &VoipQuality::default()).quality();
    assert_eq!(u, VoipQuality::default());
    // A fixed buffer; a reserved kind (01) is unknown.
    let fixed = VoipQuality {
        jitter_buffer: Some(JitterBufferConfig {
            adaptive: false,
            rate: 0,
            nominal: ms(60),
            maximum: ms(60),
            abs_max: ms(60),
        }),
        ..VoipQuality::default()
    };
    assert_eq!(m.report(1, 20, &fixed).quality(), fixed);
    let mut r = m.report(1, 20, &fixed);
    r.rx_config = 0b0001_0000;
    assert_eq!(r.quality().jitter_buffer, None);
    // Out-of-range scores read as unavailable.
    r.r_factor = 101;
    r.mos_cq = 9;
    assert_eq!((r.quality().r_factor, r.quality().mos_cq), (None, None));
    assert_eq!(r.signal_level, VOIP_UNAVAILABLE);
}
