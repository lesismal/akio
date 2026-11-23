//! E-model reference cases (ITU-T G.107, G.107.1, G.109, G.113) and VoIP metrics round trips.

use std::time::Duration;

use crate::rtcp::{parse_compound, write_compound};
use crate::{
    BurstLossModel, DelaySensitivity, EModel, JitterBufferConfig, OpusBand, Plc, Rtcp,
    VOIP_UNAVAILABLE, VoipQuality, XrBlock, mos_from_r,
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
    // G.722 without concealment (diotic Ie,wb 5, G.107.1's Bpl 4.3) at 1 %: G.107.1
    // Eq. 7-15, 5 + 90 / 5.3.
    let g722 = EModel::for_codec("g722", Plc::Unspecified).expect("table");
    assert!(g722.is_wideband());
    assert!((g722.equipment_impairment(0.01, 1.0) - (5.0 + 90.0 / 5.3)).abs() < 1e-9);
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

/// G.107.1 (2019, Corrigendum 1) and G.113 Appendix IV: the wideband model.
#[test]
fn emodel_g107_1_wideband() {
    // Defaults: Idle,WB alone (Rle = 10.5 x 117 = 1228.5): 0.1537, R = 128.846.
    let clean = EModel::wideband(0.0, 4.3);
    assert!((clean.scaled_delay_impairment(Duration::ZERO) - 0.153_685).abs() < 1e-5);
    let s = clean.score(0.0, 1.0, Duration::ZERO);
    assert!((s.r_factor * 1.29 - 128.846_315).abs() < 1e-5, "{s:?}");
    assert!((s.mos_cq - 4.499_152).abs() < 1e-5, "{s:?}");
    // G.722 64 kbit/s with Appendix III concealment (Table IV.4: Ie,wb 5, Bpl,wb 7.1) at
    // 2 % uniform loss: Ie,eff,WB = 5 + 90 x 2 / 9.1 = 24.7802, R = 104.0661, MOS 4.0491.
    let g722 = EModel::for_codec("G722", Plc::Enhanced).expect("table");
    assert!((g722.equipment_impairment(0.02, 1.0) - 24.780_22).abs() < 1e-4);
    let s = g722.score(0.02, 1.0, Duration::ZERO);
    assert!((s.r_factor * 1.29 - 104.066_1).abs() < 1e-3, "{s:?}");
    assert!((s.mos_lq - 4.0491).abs() < 1e-4, "{s:?}");
    // Appendix IV's low-complexity concealment (Bpl,wb 5.1): 5 + 180 / 7.1 = 30.3521.
    let low = EModel::for_codec("g722", Plc::Standard).expect("table");
    assert!((low.equipment_impairment(0.02, 1.0) - 30.352_11).abs() < 1e-4);
    // Without concealment G.107.1's default 4.3; 56 and 48 kbit/s from Table IV.3.
    assert_eq!(
        EModel::for_codec("g722", Plc::Disabled),
        Some(EModel::wideband(5.0, 4.3))
    );
    assert_eq!(
        EModel::for_codec_rate("g722", Plc::Enhanced, Some(56_000)),
        Some(EModel::wideband(10.0, 4.3))
    );
    assert_eq!(
        EModel::for_codec_rate("g722", Plc::Enhanced, Some(48_000)),
        Some(EModel::wideband(41.0, 4.3))
    );
    // Idd,WB = 1.29 Idd: 3.927294 at 200 ms and 19.041296 at 300 ms (Ta = T); talker echo
    // with K and Roe = 106.5 (Cor. 1) is small at the default TELR.
    let idd_wb = |t: u64| {
        let all = clean.scaled_delay_impairment(ms(t));
        let rle = 10.5 * 117.0 * (2.0 * t as f64 + 1.0).powf(-0.25);
        let idle = (129.0 - rle) / 2.0 + ((129.0f64 - rle).powi(2) / 4.0 + 169.0).sqrt();
        let terv =
            65.0 + 18.0 - 40.0 * ((1.0 + t as f64 / 10.0) / (1.0 + t as f64 / 150.0)).log10();
        let re = 80.0 + 3.0 * (terv - 14.0);
        let idte = (106.5 - re) / 2.0 + ((106.5 - re).powi(2) / 4.0 + 100.0).sqrt() - 1.0;
        all - idle - idte
    };
    assert!((idd_wb(200) - 3.927_294).abs() < 1e-5, "{}", idd_wb(200));
    assert!((idd_wb(300) - 19.041_296).abs() < 1e-5, "{}", idd_wb(300));
    // AMR-WB by mode (Tables IV.3, IV.4): 12.65 without a rate; 23.85 with Bpl,wb 4.9; 14.25
    // takes 12.65's row, 7 kbit/s 6.6's.
    let amr = |r| EModel::for_codec_rate("AMR-WB", Plc::Standard, r).expect("table");
    assert_eq!(amr(None), EModel::wideband(20.0, 4.3));
    assert_eq!(amr(Some(23_850)), EModel::wideband(10.0, 4.9));
    assert_eq!(amr(Some(23_050)), EModel::wideband(8.0, 4.6));
    assert_eq!(amr(Some(14_250)), amr(Some(12_650)));
    assert_eq!(amr(Some(6_000)), EModel::wideband(56.0, 4.3));
    assert_eq!(Plc::of_codec("AMR-WB"), Plc::Standard);
}

/// G.107.2 (03/2023) and G.113 Appendix V: the fullband model.
#[test]
fn emodel_g107_2_fullband() {
    // Unimpaired: R = 148, MOS 4.5 (Annex A: R / 1.48); 100 on the VoIP block's scale.
    let clean = EModel::fullband(0.0, 4.3);
    assert!(clean.is_fullband() && !clean.is_wideband());
    let s = clean.score(0.0, 1.0, Duration::ZERO);
    assert!(
        (s.r_factor - 100.0).abs() < 1e-9 && s.mos_cq == 4.5,
        "{s:?}"
    );
    // A rating of 129 on the fullband scale: Rx = 87.16, MOS 4.2634.
    let s = EModel::fullband(19.0, 4.3).score(0.0, 1.0, Duration::ZERO);
    assert!((s.mos_lq - 4.2634).abs() < 1e-4, "{s:?}");
    // Id,FB = 1.48 Idd: 4.505733 at 200 ms, 21.845828 at 300 ms; nothing up to 100 ms.
    let id = |t| clean.scaled_delay_impairment(ms(t));
    assert_eq!(id(100), 0.0);
    assert!((id(200) - 4.505_733).abs() < 1e-5, "{}", id(200));
    assert!((id(300) - 21.845_828).abs() < 1e-5, "{}", id(300));
    // EVS 13.2 kbit/s (Table V.3: Ie,fb 17.1, Bpl 11.7, Brf 3.28) at 2 % random loss:
    // Ie,eff,FB = 17.1 + 114.9 x 2 / 13.7 = 33.8737, R = 114.1263, MOS 3.9103.
    let evs = EModel::for_codec("EVS", Plc::Enhanced).expect("table");
    assert!((evs.equipment_impairment(0.02, 1.0) - 33.873_72).abs() < 1e-4);
    let s = evs.score(0.02, 1.0, Duration::ZERO);
    assert!((s.r_factor * 1.48 - 114.126_3).abs() < 1e-3, "{s:?}");
    assert!((s.mos_lq - 3.9103).abs() < 1e-4, "{s:?}");
    // Bursty (BurstR 2, Eq. 7-10): 17.1 + 114.9 (2 + 1 / 3.28) / 13.7 = 36.4307.
    assert!((evs.equipment_impairment(0.02, 2.0) - 36.430_7).abs() < 1e-4);
    // EVS 48 kbit/s at 1 %: 10.2 + 121.8 / 10.6 = 21.6906.
    let evs48 = EModel::for_codec_rate("evs", Plc::Enhanced, Some(48_000)).expect("table");
    assert!((evs48.equipment_impairment(0.01, 1.0) - 21.690_57).abs() < 1e-4);
    // Rates between modes take the lower mode; burstiness robustness only at 13.2.
    let at = |r| EModel::for_codec_rate("evs", Plc::Enhanced, Some(r)).expect("table");
    assert_eq!(at(20_000), EModel::fullband(10.8, 10.3));
    assert_eq!(
        at(13_200),
        EModel::fullband(17.1, 11.7).with_burst_robustness(3.28)
    );
    assert_eq!(at(7_200), EModel::fullband(22.7, 13.0));
    // No loss: Ie,FB whatever the burst ratio.
    assert_eq!(evs.equipment_impairment(0.0, 4.0), 17.1);
}

#[test]
fn emodel_opus_by_bitrate() {
    let opus = |r| EModel::for_codec_rate("opus", Plc::Enhanced, r).expect("table");
    // Without a rate: ADR-085's wideband assumption.
    assert_eq!(opus(None), EModel::wideband(0.0, 25.1));
    // With one: fullband, Ie,FB from P.863 (DAGA 2021), EVS's Bpl,fb at the rate.
    assert_eq!(opus(Some(32_000)), EModel::fullband(2.58, 9.3));
    assert_eq!(opus(Some(64_000)), EModel::fullband(0.0, 9.6));
    assert_eq!(opus(Some(8_000)), EModel::fullband(37.85, 13.0));
    let mid = opus(Some(20_000));
    assert!((mid.equipment_impairment(0.0, 1.0) - (21.96 + 9.82) / 2.0).abs() < 1e-9);
    // Monotone in the bitrate.
    let r = |b| opus(Some(b)).score(0.0, 1.0, ms(50)).r_factor;
    assert!((10..60).all(|k| r(k * 1000 + 1000) >= r(k * 1000)));
    assert!(r(48_000) > r(24_000) && r(24_000) > r(13_000));
    // Under loss a fullband rating stays in range.
    let s = opus(Some(24_000)).score(0.2, 3.0, ms(400));
    assert!((0.0..=100.0).contains(&s.r_factor) && (1.0..=4.5).contains(&s.mos_cq));
    // G.723.1 at 5.3 kbit/s: Table I.1's Ie 19.
    assert_eq!(
        EModel::for_codec_rate("G723", Plc::Standard, Some(5_300)),
        Some(EModel::codec(19.0, 16.1))
    );
}

/// G.107 (06/2015) §7.4 Table 1 and G.107.2 (03/2023) §7.4 Table 1: the delay sensitivity
/// classes' `Idd` (Eqs. 7-27, 7-28; G.107.2 Eq. 7-8b scales it by 1.48). Expected values
/// computed from the equations independently of the code.
#[test]
fn emodel_delay_sensitivity_classes() {
    use DelaySensitivity::{Default, Low, VeryLow};
    // Idd alone: the absolute-delay part of the fullband Id,FB, divided by 1.48.
    let idd = |class, t| {
        EModel::fullband(0.0, 4.3)
            .with_delay_sensitivity(class)
            .scaled_delay_impairment(ms(t))
            / 1.48
    };
    for (class, t, want) in [
        (Default, 150, 0.163_531),
        (Default, 300, 14.760_695),
        (Default, 600, 35.246_848),
        (Low, 120, 0.0),
        (Low, 200, 2.253_017),
        (Low, 300, 10.094_228),
        (Low, 400, 16.894_546),
        (VeryLow, 150, 0.0),
        (VeryLow, 200, 0.949_825),
        (VeryLow, 300, 6.178_555),
        (VeryLow, 600, 18.031_092),
    ] {
        assert!(
            (idd(class, t) - want).abs() < 1e-5,
            "{class:?} {t}: {}",
            idd(class, t)
        );
    }
    // Narrowband: Id = Idte + Idle + Idd, so the classes differ by Idd alone.
    let nb = |class| {
        EModel::default()
            .with_delay_sensitivity(class)
            .scaled_delay_impairment(ms(300))
    };
    assert!((nb(Default) - nb(Low) - (14.760_695 - 10.094_228)).abs() < 1e-5);
    assert!((nb(Default) - EModel::delay_impairment(ms(300))).abs() < 1e-12);
    let r = |class| {
        EModel::default()
            .with_delay_sensitivity(class)
            .score(0.0, 1.0, ms(300))
            .r_factor
    };
    assert!(r(VeryLow) > r(Low) && r(Low) > r(Default));
    // G.107.1 has no classes: a wideband model keeps the default.
    let wb = EModel::wideband(5.0, 7.1).with_delay_sensitivity(VeryLow);
    assert_eq!(wb.delay_sensitivity(), Default);
    assert_eq!(
        wb.scaled_delay_impairment(ms(300)),
        EModel::wideband(5.0, 7.1).scaled_delay_impairment(ms(300))
    );
    assert_eq!(EModel::default().delay_sensitivity(), Default);
}

/// G.107 Table 3's room noise and G.107.2 (03/2023) Eqs. 7-2 to 7-6. Expected values
/// computed from the equations independently of the code.
#[test]
fn emodel_room_noise() {
    // Narrowband: 35 dB(A) is G.107's default (Ro - Is = 93.355); louder rooms lower it.
    let nb = |p| EModel::default().with_room_noise(p, p).max_rating();
    assert!((nb(35.0) - EModel::default().max_rating()).abs() < 1e-12);
    assert!((nb(35.0) - 93.355_253).abs() < 1e-5, "{}", nb(35.0));
    assert!((nb(50.0) - 86.491_735).abs() < 1e-5, "{}", nb(50.0));
    assert!((nb(60.0) - 70.416_448).abs() < 1e-5, "{}", nb(60.0));
    // Fullband: 148 without room noise given; from the noise with it.
    let fb = |p: Option<f64>| {
        let m = EModel::fullband(0.0, 4.3);
        p.map_or(m, |p| m.with_room_noise(p, p)).max_rating()
    };
    assert_eq!(fb(None), 148.0);
    assert!(
        (fb(Some(35.0)) - 121.484_910).abs() < 1e-5,
        "{}",
        fb(Some(35.0))
    );
    assert!(
        (fb(Some(0.0)) - 147.285_866).abs() < 1e-5,
        "{}",
        fb(Some(0.0))
    );
    assert!(
        (fb(Some(50.0)) - 96.294_341).abs() < 1e-5,
        "{}",
        fb(Some(50.0))
    );
    let s = EModel::fullband(0.0, 4.3)
        .with_room_noise(35.0, 35.0)
        .score(0.0, 1.0, Duration::ZERO);
    assert!((s.r_factor - 121.484_910 / 1.48).abs() < 1e-5, "{s:?}");
    // Wideband: not used by G.107.1.
    assert_eq!(
        EModel::wideband(0.0, 4.3)
            .with_room_noise(60.0, 60.0)
            .max_rating(),
        129.0
    );
    // Out of range and non-finite levels.
    assert_eq!(nb(200.0), nb(85.0));
    assert_eq!(
        EModel::default()
            .with_room_noise(f64::NAN, 35.0)
            .max_rating(),
        nb(35.0)
    );
}

/// G.113 Table IV.1 (monotic) and the published Opus NB / WB values.
#[test]
fn emodel_monotic_and_opus_bands() {
    let mono = |n, r| EModel::for_codec_monotic(n, Plc::Enhanced, r).expect("table");
    // G.722 13 / 20 / 31; with Appendix III concealment the diotic Bpl,wb 7.1 at 64.
    assert_eq!(mono("G722", None), EModel::wideband(13.0, 7.1));
    assert_eq!(mono("g722", Some(56_000)), EModel::wideband(20.0, 4.3));
    assert_eq!(mono("g722", Some(48_000)), EModel::wideband(31.0, 4.3));
    // AMR-WB by mode, Bpl,wb from the diotic Table IV.4.
    assert_eq!(mono("AMR-WB", None), EModel::wideband(13.0, 4.3));
    assert_eq!(mono("amr-wb", Some(23_050)), EModel::wideband(1.0, 4.6));
    assert_eq!(mono("amr-wb", Some(23_850)), EModel::wideband(8.0, 4.9));
    assert_eq!(mono("amr-wb", Some(19_850)), EModel::wideband(3.0, 4.3));
    assert_eq!(mono("amr-wb", Some(6_600)), EModel::wideband(41.0, 4.3));
    // Others as diotic.
    assert_eq!(
        mono("PCMU", None),
        EModel::for_codec("PCMU", Plc::Enhanced).expect("table")
    );
    assert!(EModel::for_codec_monotic("vp8", Plc::Enhanced, None).is_none());
    // Opus: narrowband (Ie, Bpl) 23 / 24.6 at 6 .. 11.7 / 18.9 at 9 kbit/s; wideband 28.4 /
    // 23.9 at 11 .. 20 / 19.5 at 13; held beyond.
    assert_eq!(
        EModel::opus(OpusBand::Narrowband, 6_000),
        EModel::codec(23.0, 24.6)
    );
    assert_eq!(
        EModel::opus(OpusBand::Narrowband, 8_500),
        EModel::codec(16.0, 20.2)
    );
    assert_eq!(
        EModel::opus(OpusBand::Narrowband, 32_000),
        EModel::codec(11.7, 18.9)
    );
    assert_eq!(
        EModel::opus(OpusBand::Wideband, 5_000),
        EModel::wideband(28.4, 23.9)
    );
    assert_eq!(
        EModel::opus(OpusBand::Wideband, 12_000),
        EModel::wideband(23.3, 22.2)
    );
    assert_eq!(
        EModel::opus(OpusBand::Fullband, 32_000),
        EModel::for_codec_rate("opus", Plc::Enhanced, Some(32_000)).expect("table")
    );
    // NB Opus at 9 kbit/s, 2 % random loss: Ie,eff = 11.7 + 83.3 x 2 / 20.9 = 19.6713.
    let nb = EModel::opus(OpusBand::Narrowband, 9_000);
    assert!((nb.equipment_impairment(0.02, 1.0) - 19.671_29).abs() < 1e-4);
}

/// The burst and gap durations follow the packet duration given.
#[test]
fn voip_durations_follow_packet_duration() {
    let mut m = BurstLossModel::new(16);
    // 100 received, a burst of 4 losses among 6 packets, 100 received, a loss, 99 received.
    for _ in 0..100 {
        m.on_packet(false, false);
    }
    for lost in [true, false, true, true, false, true] {
        m.on_packet(lost, false);
    }
    // The burst is counted when the next loss after a gap comes.
    for i in 0..200 {
        m.on_packet(i == 100, false);
    }
    let at = |p| m.metrics(1, p);
    let (m20, m60) = (at(20), at(60));
    assert!(m20.burst_duration > 0);
    assert_eq!(
        u32::from(m60.burst_duration),
        3 * u32::from(m20.burst_duration)
    );
    assert_eq!(u32::from(m60.gap_duration), 3 * u32::from(m20.gap_duration));
}

/// A packet reported lost that later arrives and is discarded becomes a discard.
#[test]
fn voip_late_discard_moves_a_loss() {
    let mut m = BurstLossModel::new(16);
    for i in 0..100 {
        m.on_packet(i == 50, false);
    }
    let before = m.metrics(1, 20);
    assert!(before.loss_rate > 0 && before.discard_rate == 0);
    let ratio = m.burst_ratio();
    let loss = m.loss_fraction();
    assert!(m.on_late_discard());
    let after = m.metrics(1, 20);
    assert_eq!((after.loss_rate, after.discard_rate), (0, before.loss_rate));
    // Both are losses to the burst model and the E-model.
    assert_eq!(m.burst_ratio(), ratio);
    assert_eq!(m.loss_fraction(), loss);
    assert_eq!(
        (
            after.burst_density,
            after.gap_density,
            after.burst_duration,
            after.gap_duration
        ),
        (
            before.burst_density,
            before.gap_density,
            before.burst_duration,
            before.gap_duration
        )
    );
    // No loss left to move.
    assert!(!m.on_late_discard());
}
