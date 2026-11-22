//! ADR-058 in simulated time: RTCP on ICE component 2 (no rtcp-mux) with DTLS-SRTP and
//! SDES-SRTP, the mux policies, RTCP XR receipt blocks and VoIP metrics, SDES items, ULPFEC
//! levels.

use super::*;
use crate::SdpChanges;
use only_rtp::SdesItem;

/// A lossy network between sides with several addresses; logs what crossed it.
struct Net {
    rng: u64,
    loss: u32,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>)>,
    /// (from, to, first byte, an RTCP packet) of every datagram sent.
    log: Vec<(SocketAddr, SocketAddr, u8, bool)>,
}

impl Net {
    fn new(seed: u64) -> Net {
        Net {
            rng: seed,
            loss: 0,
            queue: Vec::new(),
            log: Vec::new(),
        }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn send(&mut self, now: Instant, from: SocketAddr, to: SocketAddr, d: Vec<u8>) {
        let b = d.first().copied().unwrap_or(0);
        let rtcp = (128..=191).contains(&b) && only_rtp::is_rtcp(&d);
        self.log.push((from, to, b, rtcp));
        // Only media is lost: the handshakes and RTCP get through.
        if (128..=191).contains(&b) && !rtcp && (self.rand() % 100) < u64::from(self.loss) {
            return;
        }
        let delay = 10 + self.rand() % 6;
        self.queue
            .push((now + Duration::from_millis(delay), from, to, d));
    }
}

struct Side {
    rtc: Rtc,
    addrs: Vec<SocketAddr>,
    events: Vec<RtcEvent>,
    wake: Instant,
}

fn drain(s: &mut Side, now: Instant, net: &mut Net) {
    loop {
        match s.rtc.poll_output(now) {
            Output::Timeout(t) => {
                s.wake = t;
                break;
            }
            Output::Transmit(from, to, d, _) => {
                assert!(s.addrs.contains(&from), "sent from {from}");
                net.send(now, from, to, d);
            }
            Output::Event(e) => s.events.push(e),
        }
    }
}

fn step(a: &mut Side, b: &mut Side, now: Instant, net: &mut Net) {
    let (due, keep): (Vec<_>, Vec<_>) = net.queue.drain(..).partition(|x| x.0 <= now);
    net.queue = keep;
    for (_, from, to, d) in due {
        let s = if a.addrs.contains(&to) {
            &mut *a
        } else {
            &mut *b
        };
        s.rtc.handle_receive(now, from, to, &d);
    }
    for s in [&mut *a, &mut *b] {
        if s.wake <= now {
            s.rtc.handle_timeout(now);
        }
        drain(s, now, net);
    }
}

const A1: &str = "10.0.0.1:1000";
const A2: &str = "10.0.0.1:1001";
const B1: &str = "10.0.0.2:2000";
const B2: &str = "10.0.0.2:2001";

/// A peer with a component-1 candidate at `c1` and, if any, a component-2 one at `c2`.
fn peer(cfg: ConfigInner, c1: &str, c2: Option<&str>, now: Instant) -> (Rtc, Vec<SocketAddr>) {
    let mut r = Rtc::new(cfg, false, now).unwrap();
    let mut addrs = vec![c1.parse().unwrap()];
    r.add_local_candidate(IceCandidate::host(addrs[0]));
    if let Some(c2) = c2 {
        addrs.push(c2.parse().unwrap());
        r.add_local_candidate(IceCandidate::host(addrs[1]).with_component(2));
    }
    (r, addrs)
}

fn side(rtc: Rtc, addrs: Vec<SocketAddr>, now: Instant) -> Side {
    Side {
        rtc,
        addrs,
        events: Vec::new(),
        wake: now,
    }
}

/// `a` (with `ca`) offers `kinds` to `b` (with `cb`), both with RTCP candidates; the offer
/// and the answer go through `munge`.
fn negotiate(
    ca: ConfigInner,
    cb: ConfigInner,
    kinds: &[MediaKind],
    munge_offer: fn(&str) -> String,
    munge_answer: fn(&str) -> String,
) -> (Side, Side, Vec<Mid>, String, String, Instant) {
    let now = Instant::now();
    let (mut a, aa) = peer(ca, A1, Some(A2), now);
    let (mut b, ba) = peer(cb, B1, Some(B2), now);
    let mut ch = a.changes();
    let mids = {
        let mut api = SdpChanges(&mut ch);
        kinds
            .iter()
            .map(|k| api.add_media(*k, Direction::SendRecv, None, None))
            .collect()
    };
    let offer = munge_offer(&a.apply(now, ch).unwrap().unwrap());
    let answer = munge_answer(&b.accept_offer(now, &offer).unwrap());
    a.accept_answer(now, &answer).unwrap();
    (side(a, aa, now), side(b, ba, now), mids, offer, answer, now)
}

fn same(s: &str) -> String {
    s.to_owned()
}

fn unmux(s: &str) -> String {
    s.replace("a=rtcp-mux\r\n", "")
}

fn off() -> ConfigInner {
    ConfigInner {
        rtcp_mux: RtcpMuxPolicy::Off,
        ..ConfigInner::default()
    }
}

fn connect(a: &mut Side, b: &mut Side, net: &mut Net, mut now: Instant) -> Instant {
    let start = now;
    while !(a.rtc.is_connected() && b.rtc.is_connected()) {
        now += Duration::from_millis(5);
        step(a, b, now, net);
        assert!(now - start < Duration::from_secs(30), "no connection");
    }
    now
}

/// Opus from both sides on `mid` for `n` 20 ms packets.
fn talk(a: &mut Side, b: &mut Side, net: &mut Net, mid: Mid, n: u64, mut now: Instant) -> Instant {
    let pt = a.rtc.payload_type(mid, Codec::Opus).unwrap();
    for i in 0..n {
        let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        a.rtc
            .write_media(now, mid, None, pt, t, &[0xfc, i as u8, 1, 2])
            .unwrap();
        b.rtc
            .write_media(now, mid, None, pt, t, &[0xfc, i as u8, 3, 4])
            .unwrap();
        for _ in 0..4 {
            now += Duration::from_millis(5);
            step(a, b, now, net);
        }
    }
    for _ in 0..300 {
        now += Duration::from_millis(5);
        step(a, b, now, net);
    }
    now
}

fn audio_frames(s: &Side, mid: Mid) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::MediaData(d) if d.mid == mid))
        .count()
}

fn sender_reports(s: &Side) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::Other(Other::SenderReport { .. })))
        .count()
}

/// The port pairs RTP, RTCP and DTLS crossed.
fn ports(net: &Net, pick: impl Fn(u8, bool) -> bool) -> Vec<(u16, u16)> {
    let mut v: Vec<(u16, u16)> = net
        .log
        .iter()
        .filter(|(_, _, b, rtcp)| pick(*b, *rtcp))
        .map(|(f, t, _, _)| (f.port(), t.port()))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn is_rtp(b: u8, rtcp: bool) -> bool {
    (128..=191).contains(&b) && !rtcp
}

fn is_dtls(b: u8, _: bool) -> bool {
    (20..=63).contains(&b)
}

#[test]
fn rtcp_on_component_two_with_dtls_srtp() {
    let (mut a, mut b, mids, offer, answer, now) = negotiate(
        off(),
        ConfigInner::default(),
        &[MediaKind::Audio],
        same,
        same,
    );
    for sdp in [&offer, &answer] {
        assert!(!sdp.contains("a=rtcp-mux"), "{sdp}");
        assert!(sdp.contains("a=rtcp:9 IN IP4 0.0.0.0\r\n"), "{sdp}");
        assert!(!sdp.contains("a=group:BUNDLE"), "{sdp}");
        // RTP and RTCP host candidates, one foundation (component 2: priority one less).
        let cands: Vec<Vec<&str>> = sdp
            .lines()
            .filter_map(|l| l.strip_prefix("a=candidate:"))
            .map(|l| l.split(' ').collect())
            .collect();
        assert_eq!(cands.len(), 2, "{sdp}");
        assert_eq!((cands[0][1], cands[1][1]), ("1", "2"));
        assert_eq!(cands[0][0], cands[1][0]);
        let prio = |c: &Vec<&str>| c[3].parse::<u32>().unwrap();
        assert_eq!(prio(&cands[0]), prio(&cands[1]) + 1);
    }
    assert_eq!((a.rtc.ice.components(), b.rtc.ice.components()), (2, 2));
    let mut net = Net::new(3);
    let now = connect(&mut a, &mut b, &mut net, now);
    // One DTLS handshake per component (RFC 5764 §4.1), each keying its own direction.
    assert!(a.rtc.rtcp.dtls_up && b.rtc.rtcp.dtls_up);
    assert!(a.rtc.rtcp.srtcp_tx.is_some() && b.rtc.rtcp.srtcp_rx.is_some());
    assert_eq!(
        a.events
            .iter()
            .filter(|e| matches!(e, RtcEvent::Connected))
            .count(),
        1
    );
    let now = talk(&mut a, &mut b, &mut net, mids[0], 250, now);
    assert!(audio_frames(&b, mids[0]) >= 240);
    assert!(audio_frames(&a, mids[0]) >= 240);
    // Sender reports went over component 2 and were decrypted with its keys; the reports
    // about them gave each sender its RTT.
    assert!(sender_reports(&a) >= 3 && sender_reports(&b) >= 3);
    assert!(a.rtc.media[0].rtt().is_some() && b.rtc.media[0].rtt().is_some());
    assert_eq!(ports(&net, is_rtp), vec![(1000, 2000), (2000, 1000)]);
    assert_eq!(
        ports(&net, |_, rtcp| rtcp),
        vec![(1001, 2001), (2001, 1001)]
    );
    assert_eq!(
        ports(&net, is_dtls),
        vec![(1000, 2000), (1001, 2001), (2000, 1000), (2001, 1001)]
    );
    // A sender report protected with component 1's keys is not taken on component 2; with
    // component 2's it is.
    let ssrc = b.rtc.media[0].send.ssrc();
    let info = b.rtc.media[0]
        .send
        .sender_report(now, b.rtc.ntp(now))
        .unwrap();
    let raw = only_rtp::write_compound(&[Rtcp::SenderReport {
        ssrc,
        info,
        reports: Vec::new(),
    }]);
    let (from, to) = (B2.parse().unwrap(), A2.parse().unwrap());
    let n = sender_reports(&a);
    let wrong = b.rtc.srtp_tx.as_mut().unwrap().protect_rtcp(&raw).unwrap();
    a.rtc.handle_receive(now, from, to, &wrong);
    drain(&mut a, now, &mut net);
    assert_eq!(sender_reports(&a), n);
    let right = b
        .rtc
        .rtcp
        .srtcp_tx
        .as_mut()
        .unwrap()
        .protect_rtcp(&raw)
        .unwrap();
    a.rtc.handle_receive(now, from, to, &right);
    drain(&mut a, now, &mut net);
    assert_eq!(sender_reports(&a), n + 1);
}

#[test]
fn negotiate_policy() {
    let neg = ConfigInner {
        rtcp_mux: RtcpMuxPolicy::Negotiate,
        ..ConfigInner::default()
    };
    // Answered by a peer that muxes: one component, BUNDLE, no `a=rtcp` in the answer.
    let (mut a, mut b, mids, offer, answer, now) = negotiate(
        neg.clone(),
        ConfigInner::default(),
        &[MediaKind::Audio, MediaKind::Video],
        same,
        same,
    );
    assert!(offer.contains("a=rtcp-mux\r\n") && offer.contains("a=rtcp:9 IN IP4"));
    assert!(offer.contains(" 2 udp ") && offer.contains("a=group:BUNDLE 0 1"));
    assert!(answer.contains("a=rtcp-mux\r\n") && !answer.contains("a=rtcp:"));
    assert!(!answer.contains(" 2 udp "), "{answer}");
    assert_eq!((a.rtc.ice.components(), b.rtc.ice.components()), (1, 1));
    let mut net = Net::new(5);
    let now = connect(&mut a, &mut b, &mut net, now);
    talk(&mut a, &mut b, &mut net, mids[0], 100, now);
    assert!(sender_reports(&a) >= 1 && audio_frames(&b, mids[0]) >= 90);
    assert!(net.log.iter().all(|(f, _, _, _)| f.port() % 1000 == 0));
    // A re-offer keeps rtcp-mux and leaves component 2 out.
    let reoffer = a.rtc.write_sdp(true);
    assert!(!reoffer.contains("a=rtcp:") && !reoffer.contains(" 2 udp "));
    // Answered by a peer that does not mux (one section): two components.
    let (mut a, mut b, mids, _, answer, now) = negotiate(
        neg,
        ConfigInner::default(),
        &[MediaKind::Audio],
        unmux,
        same,
    );
    assert!(!answer.contains("a=rtcp-mux") && answer.contains("a=rtcp:9"));
    assert_eq!((a.rtc.ice.components(), b.rtc.ice.components()), (2, 2));
    let mut net = Net::new(6);
    let now = connect(&mut a, &mut b, &mut net, now);
    talk(&mut a, &mut b, &mut net, mids[0], 100, now);
    assert!(sender_reports(&a) >= 1 && sender_reports(&b) >= 1);
    assert_eq!(
        ports(&net, |_, rtcp| rtcp),
        vec![(1001, 2001), (2001, 1001)]
    );
}

#[test]
fn sdes_without_rtcp_mux() {
    let sdes = ConfigInner {
        sdes: true,
        ..ConfigInner::default()
    };
    let (mut a, mut b, mids, offer, answer, now) = negotiate(
        ConfigInner {
            rtcp_mux: RtcpMuxPolicy::Off,
            ..sdes.clone()
        },
        sdes,
        &[MediaKind::Audio],
        same,
        same,
    );
    assert!(offer.contains("a=crypto:") && !offer.contains("a=rtcp-mux"));
    assert!(answer.contains("a=crypto:") && answer.contains("a=rtcp:9"));
    let mut net = Net::new(9);
    let now = connect(&mut a, &mut b, &mut net, now);
    talk(&mut a, &mut b, &mut net, mids[0], 150, now);
    assert!(audio_frames(&a, mids[0]) >= 140 && audio_frames(&b, mids[0]) >= 140);
    assert!(sender_reports(&a) >= 2 && sender_reports(&b) >= 2);
    assert_eq!(
        ports(&net, |_, rtcp| rtcp),
        vec![(1001, 2001), (2001, 1001)]
    );
    assert!(ports(&net, is_dtls).is_empty(), "no DTLS with SDES");
}

#[test]
fn rtcp_mux_stays_the_default() {
    let now = Instant::now();
    // The default policy offers rtcp-mux alone, even with an RTCP socket.
    let (mut a, _) = peer(ConfigInner::default(), A1, Some(A2), now);
    let mut ch = a.changes();
    SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    let offer = a.apply(now, ch).unwrap().unwrap();
    assert!(offer.contains("a=rtcp-mux\r\n") && offer.contains("a=group:BUNDLE"));
    assert!(
        !offer.contains("a=rtcp:") && !offer.contains(" 2 udp "),
        "{offer}"
    );
    // An offer with rtcp-mux (every browser's) is answered with it.
    let (mut b, _) = peer(ConfigInner::default(), B1, Some(B2), now);
    let answer = b.accept_offer(now, &offer).unwrap();
    assert!(answer.contains("a=rtcp-mux\r\n") && !answer.contains("a=rtcp:"));
    assert_eq!(b.ice.components(), 1);
    // Without an RTCP socket an offer without rtcp-mux is answered as before (with it).
    let (mut c, _) = peer(ConfigInner::default(), B1, None, now);
    let answer = c.accept_offer(now, &unmux(&offer)).unwrap();
    assert!(answer.contains("a=rtcp-mux\r\n"));
    assert_eq!(c.ice.components(), 1);
    // Several sections without rtcp-mux (no BUNDLE) are refused with an RTCP socket.
    let (mut a, _) = peer(ConfigInner::default(), A1, None, now);
    let mut ch = a.changes();
    {
        let mut api = SdpChanges(&mut ch);
        api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        api.add_media(MediaKind::Video, Direction::SendRecv, None, None);
    }
    let two = unmux(&a.apply(now, ch).unwrap().unwrap());
    let (mut b, _) = peer(ConfigInner::default(), B1, Some(B2), now);
    assert!(b.accept_offer(now, &two).is_err());
    // `Off` needs component-2 candidates and one section.
    let (mut a, _) = peer(off(), A1, None, now);
    let mut ch = a.changes();
    SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    assert!(a.apply(now, ch).is_err());
    let (mut a, _) = peer(off(), A1, Some(A2), now);
    let mut ch = a.changes();
    {
        let mut api = SdpChanges(&mut ch);
        api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        api.add_channel("x");
    }
    assert!(a.apply(now, ch).is_err());
    // Browsers' offers (rtcp-mux, BUNDLE) are answered exactly as before.
    let (mut b, _) = peer(ConfigInner::default(), B1, Some(B2), now);
    let answer = b.accept_offer(now, tests::BROWSER_OFFER).unwrap();
    assert!(answer.contains("a=group:BUNDLE") && answer.contains("a=rtcp-mux"));
    assert!(!answer.contains("a=rtcp:") && !answer.contains(" 2 udp "));
}

fn xr_cfg(blocks: XrBlocks) -> ConfigInner {
    ConfigInner {
        xr_blocks: blocks,
        ..ConfigInner::default()
    }
}

#[test]
fn xr_receipt_blocks_negotiation() {
    let (a, b, _, offer, answer, _) = negotiate(
        xr_cfg(XrBlocks::ALL),
        xr_cfg(XrBlocks::ALL),
        &[MediaKind::Audio, MediaKind::Video],
        same,
        same,
    );
    // VoIP metrics on audio only.
    let audio = "a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times voip-metrics\r\n";
    let video = "a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times\r\n";
    for sdp in [&offer, &answer] {
        assert!(sdp.contains(audio) && sdp.contains(video), "{sdp}");
    }
    assert_eq!(a.rtc.media[0].xr_blocks, XrBlocks::ALL);
    assert_eq!(
        b.rtc.media[1].xr_blocks,
        XrBlocks::LOSS_RLE | XrBlocks::DUPLICATE_RLE | XrBlocks::RECEIPT_TIMES
    );
    // Both sides must list a block; with receiver reference times on one line.
    let (a, b, _, _, answer, _) = negotiate(
        ConfigInner {
            xr: true,
            ..xr_cfg(XrBlocks::LOSS_RLE | XrBlocks::VOIP_METRICS)
        },
        ConfigInner {
            xr: true,
            ..xr_cfg(XrBlocks::LOSS_RLE | XrBlocks::RECEIPT_TIMES)
        },
        &[MediaKind::Audio],
        same,
        same,
    );
    assert!(
        answer.contains("a=rtcp-xr:rcvr-rtt=all pkt-loss-rle\r\n"),
        "{answer}"
    );
    assert_eq!(a.rtc.media[0].xr_blocks, XrBlocks::LOSS_RLE);
    assert_eq!(b.rtc.media[0].xr_blocks, XrBlocks::LOSS_RLE);
    assert!(a.rtc.media[0].xr && b.rtc.media[0].xr);
    // Formats with parameters count; unknown ones do not.
    assert_eq!(
        XrBlocks::from_sdp(["pkt-loss-rle=400 stat-summary=loss,dup foo"].into_iter()),
        XrBlocks::LOSS_RLE
    );
    // Off by default: no `a=rtcp-xr`.
    let (_, _, _, offer, _, _) = negotiate(
        ConfigInner::default(),
        xr_cfg(XrBlocks::ALL),
        &[MediaKind::Audio],
        same,
        same,
    );
    assert!(!offer.contains("a=rtcp-xr"));
}

#[test]
fn xr_receipt_blocks_and_voip_metrics_round_trip() {
    let (mut a, mut b, mids, _, _, now) = negotiate(
        xr_cfg(XrBlocks::ALL),
        xr_cfg(XrBlocks::ALL),
        &[MediaKind::Audio],
        same,
        same,
    );
    let mut net = Net::new(17);
    let now = connect(&mut a, &mut b, &mut net, now);
    net.loss = 10;
    talk(&mut a, &mut b, &mut net, mids[0], 400, now);
    let sent_a = a.rtc.media[0].send.ssrc();
    let (mut received, mut lost, mut times) = (0, 0, 0);
    let mut voip = None;
    for e in &a.events {
        match e {
            RtcEvent::Other(Other::XrReceipts {
                mid,
                ssrc,
                received: r,
                lost: l,
                receipt_times: t,
                ..
            }) => {
                assert_eq!((*mid, *ssrc), (mids[0], sent_a));
                received += r;
                lost += l;
                times += t;
            }
            RtcEvent::Other(Other::VoipMetrics { mid, metrics, .. }) => {
                assert_eq!((*mid, metrics.ssrc), (mids[0], sent_a));
                voip = Some(*metrics);
            }
            _ => {}
        }
    }
    // About 10 % of 400 packets lost; the blocks cover what arrived up to the last report.
    assert!(received > 250 && received <= 400, "{received}");
    assert!(lost > 15 && lost < 80, "{lost}");
    assert!(times > 30, "{times}");
    let st = a.rtc.stats;
    assert_eq!((st.xr_received, st.xr_lost), (received, lost));
    let m = voip.expect("VoIP metrics");
    // Loss rate in 1/256 (10 % = 26), the round trip from the reports (~30 ms).
    assert!(m.loss_rate > 8 && m.loss_rate < 60, "{m:?}");
    assert!(m.round_trip_delay > 10 && m.round_trip_delay < 80, "{m:?}");
    assert_eq!(m.gmin, 16);
    // The E-model for Opus (wideband, G.107.1) at ~10 % loss: R about 70, MOS about 3.6.
    assert!(m.r_factor > 50 && m.r_factor < 85, "{m:?}");
    assert!(
        m.mos_lq >= 28 && m.mos_lq <= 43 && m.mos_cq <= m.mos_lq,
        "{m:?}"
    );
    // Opus conceals losses itself: enhanced PLC; jitter buffer unknown. What only the
    // application knows is unavailable.
    let q = m.quality();
    assert_eq!((q.plc, q.jitter_buffer), (only_rtp::Plc::Enhanced, None));
    assert_eq!(m.rx_config, 0b1000_0000);
    assert_eq!(
        (q.signal_level, q.noise_level, q.rerl, q.ext_r_factor),
        (None, None, None, None)
    );
    // Without negotiation nothing is sent.
    let (mut a, mut b, mids, _, _, now) = negotiate(
        xr_cfg(XrBlocks::ALL),
        ConfigInner::default(),
        &[MediaKind::Audio],
        same,
        same,
    );
    let mut net = Net::new(18);
    let now = connect(&mut a, &mut b, &mut net, now);
    talk(&mut a, &mut b, &mut net, mids[0], 100, now);
    assert!(!a.events.iter().chain(&b.events).any(|e| matches!(
        e,
        RtcEvent::Other(Other::XrReceipts { .. } | Other::VoipMetrics { .. })
    )));
}

#[test]
fn xr_voip_metrics_application_fields() {
    use only_rtp::{EModel, JitterBufferConfig, Plc, VoipQuality};
    let (mut a, mut b, mids, _, _, now) = negotiate(
        xr_cfg(XrBlocks::VOIP_METRICS),
        xr_cfg(XrBlocks::VOIP_METRICS),
        &[MediaKind::Audio],
        same,
        same,
    );
    // What b's application knows of the audio it plays.
    let jb = JitterBufferConfig {
        adaptive: true,
        rate: 4,
        nominal: Duration::from_millis(60),
        maximum: Duration::from_millis(120),
        abs_max: Duration::from_millis(500),
    };
    let app = VoipQuality {
        signal_level: Some(-19),
        noise_level: Some(-62),
        rerl: Some(40),
        ext_r_factor: Some(88),
        plc: Plc::Standard,
        jitter_buffer: Some(jb),
        ..VoipQuality::default()
    };
    // As if it were G.711 without concealment: the worse codec model.
    assert!(
        b.rtc
            .set_voip_quality(mids[0], app, Some(EModel::codec(0.0, 4.3)))
    );
    assert!(!b.rtc.set_voip_quality(Mid::new("nope"), app, None));
    let mut net = Net::new(19);
    let now = connect(&mut a, &mut b, &mut net, now);
    net.loss = 5;
    talk(&mut a, &mut b, &mut net, mids[0], 300, now);
    let last = |s: &Side| {
        s.events.iter().rev().find_map(|e| match e {
            RtcEvent::Other(Other::VoipMetrics { metrics, .. }) => Some(*metrics),
            _ => None,
        })
    };
    let m = last(&a).expect("VoIP metrics from b");
    let q = m.quality();
    assert_eq!(
        (q.signal_level, q.noise_level, q.rerl, q.ext_r_factor),
        (Some(-19), Some(-62), Some(40), Some(88))
    );
    assert_eq!((q.plc, q.jitter_buffer), (Plc::Standard, Some(jb)));
    assert_eq!((m.jb_nominal, m.jb_maximum, m.jb_abs_max), (60, 120, 500));
    // G.711 without concealment at ~5 % loss: Ie,eff about 51, R about 40.
    assert!(m.r_factor > 20 && m.r_factor < 60, "{m:?}");
    // a set nothing: its reports about b's Opus stream use Opus's planning values.
    let o = last(&b).expect("VoIP metrics from a");
    assert!(o.r_factor > m.r_factor + 10, "{o:?} vs {m:?}");
    assert_eq!(o.quality().signal_level, None);
    // The application's own scores replace the estimate.
    let own = VoipQuality {
        r_factor: Some(77),
        mos_lq: Some(39),
        mos_cq: Some(38),
        ..app
    };
    assert!(b.rtc.set_voip_quality(mids[0], own, None));
    let now = talk(
        &mut a,
        &mut b,
        &mut net,
        mids[0],
        150,
        now + Duration::from_secs(5),
    );
    let _ = now;
    let m = last(&a).expect("VoIP metrics from b");
    assert_eq!((m.r_factor, m.mos_lq, m.mos_cq), (77, 39, 38));
}

#[test]
fn random_cname_and_sdes_items() {
    let (mut a, mut b, mids, offer, _, now) = negotiate(
        ConfigInner::default(),
        ConfigInner::default(),
        &[MediaKind::Audio],
        same,
        same,
    );
    // RFC 7022: 96 random bits in base64, new per peer connection.
    assert_eq!(a.rtc.cname.len(), 16);
    assert!(
        a.rtc
            .cname
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    );
    assert_ne!(a.rtc.cname, b.rtc.cname);
    assert!(offer.contains(&format!("cname:{}", a.rtc.cname)));
    let mut net = Net::new(23);
    let now = connect(&mut a, &mut b, &mut net, now);
    talk(&mut a, &mut b, &mut net, mids[0], 150, now);
    let items: Vec<_> = b
        .events
        .iter()
        .filter_map(|e| match e {
            RtcEvent::Other(Other::SourceDescription { ssrc, items }) => Some((*ssrc, items)),
            _ => None,
        })
        .collect();
    // Reported once (the items do not change), as typed items.
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].0, a.rtc.media[0].send.ssrc());
    assert_eq!(items[0].1, &vec![SdesItem::cname(a.rtc.cname.clone())]);
}

fn ulp(l0: Option<usize>) -> ConfigInner {
    ConfigInner {
        fec: Some(FecMechanism::Ulpfec),
        fec_min: 200,
        fec_max: 255,
        ulpfec_level0: l0,
        ..ConfigInner::default()
    }
}

/// `a` sends VP8 frames of 3 packets over a link losing `loss` % of media (no NACK);
/// returns the frames `b` got whole, `b`'s statistics and the bytes `a` sent.
fn ulp_run(l0: Option<usize>, loss: u32, seed: u64) -> (usize, Stats, u64) {
    let no_nack = |s: &str| {
        s.split("\r\n")
            .filter(|l| !(l.starts_with("a=rtcp-fb:") && l.ends_with(" nack")))
            .collect::<Vec<_>>()
            .join("\r\n")
    };
    let (mut a, mut b, mids, _, _, now) =
        negotiate(ulp(l0), ulp(None), &[MediaKind::Video], no_nack, no_nack);
    let video = mids[0];
    let mut net = Net::new(seed);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    net.loss = loss;
    let bytes0 = a.rtc.stats.bytes_sent;
    let vp8 = a.rtc.payload_type(video, Codec::Vp8).unwrap();
    let frame: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    for i in 0..200u64 {
        let mut f = frame.clone();
        f[0] = if i == 0 { 0x10 } else { 0x11 };
        f[1] = i as u8;
        let t = MediaTime::new(i * 3600, Frequency::NINETY_KHZ);
        a.rtc.write_media(now, video, None, vp8, t, &f).unwrap();
        for _ in 0..8 {
            now += Duration::from_millis(5);
            step(&mut a, &mut b, now, &mut net);
        }
    }
    for _ in 0..400 {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
    }
    let whole = b
        .events
        .iter()
        .filter(
            |e| matches!(e, RtcEvent::MediaData(d) if d.mid == video && d.data[2..] == frame[2..]),
        )
        .count();
    (whole, b.rtc.stats, a.rtc.stats.bytes_sent - bytes0)
}

#[test]
fn ulpfec_levels_repair_loss() {
    for seed in [31, 32] {
        let (plain, _, _) = ulp_run(None, 0, seed);
        assert_eq!(plain, 200);
        let (whole_fec, st_fec, bytes_fec) = ulp_run(None, 8, seed);
        let (whole_lvl, st_lvl, bytes_lvl) = ulp_run(Some(120), 8, seed);
        assert!(
            st_lvl.fec_received > 100 && st_lvl.fec_recovered > 10,
            "{st_lvl:?}"
        );
        // Frames with a single loss come back whole with levels too ... The loss pattern is
        // seeded, but SSRCs, initial sequence numbers and keys are random, so the FEC groups
        // fall differently on the frames from run to run: over 120 runs, levels gave 180-192
        // whole frames (without FEC about 156 survive 8 % loss) and 3 ± 3.4 fewer than
        // whole-packet FEC (at most 14). The bounds sit about five deviations out.
        assert!(
            whole_lvl >= 170 && whole_lvl + 20 >= whole_fec,
            "seed {seed}: {whole_lvl} whole frames with levels, {whole_fec} with whole-packet FEC ({st_fec:?})"
        );
        // ... for far fewer repair bytes.
        assert!(
            bytes_lvl * 100 < bytes_fec * 85,
            "{bytes_lvl} bytes with levels, {bytes_fec} without"
        );
    }
}
