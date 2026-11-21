//! ADR-073 in simulated time: the pacer (spread video, audio on time, retransmissions first),
//! probing on a raised maximum, ECN in RFC 8888 feedback, RED for PCMU, partially rebuilt
//! ULPFEC packets.

use super::pacing::{Class, Pacer, Queued, patch_ext};
use super::*;
use crate::SdpChanges;

/// A network with a fixed delay that can mark RTP datagrams with an ECN codepoint and logs
/// the media sent.
struct Net {
    rng: u64,
    loss: u32,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>, u8)>,
    /// The codepoint RTP datagrams arrive with, and CE on every `ce_every`-th one.
    ecn: u8,
    ce_every: u64,
    rtp_count: u64,
    /// (sent at, from, payload type) of every RTP datagram (not RTCP).
    log: Vec<(Instant, SocketAddr, u8)>,
}

impl Net {
    fn new(seed: u64) -> Net {
        Net {
            rng: seed,
            loss: 0,
            queue: Vec::new(),
            ecn: 0,
            ce_every: 0,
            rtp_count: 0,
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
        let rtp = (128..=191).contains(&b) && !only_rtp::is_rtcp(&d);
        let mut ecn = 0;
        if rtp {
            self.log.push((now, from, d[1] & 0x7f));
            self.rtp_count += 1;
            ecn = self.ecn;
            if self.ce_every > 0 && self.rtp_count % self.ce_every == 0 {
                ecn = 3;
            }
            // Only media is lost.
            if (self.rand() % 100) < u64::from(self.loss) {
                return;
            }
        }
        self.queue
            .push((now + Duration::from_millis(15), from, to, d, ecn));
    }
}

struct Side {
    rtc: Rtc,
    addr: SocketAddr,
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
            Output::Transmit(_, to, d) => net.send(now, s.addr, to, d),
            Output::Event(e) => s.events.push(e),
        }
    }
}

fn step(a: &mut Side, b: &mut Side, now: Instant, net: &mut Net) {
    let (due, keep): (Vec<_>, Vec<_>) = net.queue.drain(..).partition(|x| x.0 <= now);
    net.queue = keep;
    for (_, from, to, d, ecn) in due {
        let s = if to == a.addr { &mut *a } else { &mut *b };
        s.rtc.set_rx_ecn(ecn);
        s.rtc.handle_receive(now, from, to, &d);
    }
    for s in [&mut *a, &mut *b] {
        if s.wake <= now {
            s.rtc.handle_timeout(now);
        }
        drain(s, now, net);
    }
}

fn pair(ca: ConfigInner, cb: ConfigInner, kinds: &[MediaKind]) -> (Side, Side, Vec<Mid>, Instant) {
    let now = Instant::now();
    let mut a = Rtc::new(ca, false, now).unwrap();
    let mut b = Rtc::new(cb, false, now).unwrap();
    let (aa, ba): (SocketAddr, SocketAddr) = (
        "10.0.0.1:1000".parse().unwrap(),
        "10.0.0.2:2000".parse().unwrap(),
    );
    a.add_local_candidate(IceCandidate::host(aa));
    b.add_local_candidate(IceCandidate::host(ba));
    let mut ch = a.changes();
    let mids = {
        let mut api = SdpChanges(&mut ch);
        kinds
            .iter()
            .map(|k| api.add_media(*k, Direction::SendRecv, None, None))
            .collect()
    };
    let offer = a.apply(now, ch).unwrap().unwrap();
    let answer = b.accept_offer(now, &offer).unwrap();
    a.accept_answer(now, &answer).unwrap();
    let side = |rtc, addr| Side {
        rtc,
        addr,
        events: Vec::new(),
        wake: now,
    };
    (side(a, aa), side(b, ba), mids, now)
}

fn connect(a: &mut Side, b: &mut Side, net: &mut Net, mut now: Instant) -> Instant {
    let start = now;
    while !(a.rtc.is_connected() && b.rtc.is_connected()) {
        now += Duration::from_millis(5);
        step(a, b, now, net);
        assert!(now - start < Duration::from_secs(30), "no connection");
    }
    for _ in 0..20 {
        now += Duration::from_millis(5);
        step(a, b, now, net);
    }
    now
}

fn vp8_frame(i: u64, len: usize) -> Vec<u8> {
    let mut f: Vec<u8> = (0..len).map(|k| (k as u64 * 7 + i) as u8).collect();
    f[0] = if i == 0 { 0x10 } else { 0x11 };
    f
}

/// Sends a `len`-byte keyframe from `a` at `now` and steps 1 ms at a time for `ms`; returns
/// the send times (relative to `now`) of `a`'s VP8 packets and of its Opus packet, which goes
/// 5 ms after the frame.
fn keyframe_timing(cfg: ConfigInner, len: usize, ms: u64) -> (Vec<Duration>, Vec<Duration>, Side) {
    let (mut a, mut b, mids, now) = pair(cfg.clone(), cfg, &[MediaKind::Audio, MediaKind::Video]);
    let mut net = Net::new(1);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    let (audio, video) = (mids[0], mids[1]);
    let vp8 = a.rtc.payload_type(video, Codec::Vp8).unwrap();
    let opus = a.rtc.payload_type(audio, Codec::Opus).unwrap();
    // A small first frame starts the media and the probing; let it settle.
    a.rtc
        .write_media(
            now,
            video,
            None,
            vp8,
            MediaTime::new(0, Frequency::NINETY_KHZ),
            &vp8_frame(0, 500),
        )
        .unwrap();
    for _ in 0..300 {
        now += Duration::from_millis(1);
        step(&mut a, &mut b, now, &mut net);
    }
    let start = now;
    net.log.clear();
    a.rtc
        .write_media(
            now,
            video,
            None,
            vp8,
            MediaTime::new(3000, Frequency::NINETY_KHZ),
            &vp8_frame(0, len),
        )
        .unwrap();
    drain(&mut a, now, &mut net);
    for i in 1..=ms {
        now += Duration::from_millis(1);
        if i == 5 {
            let t = MediaTime::new(960, Frequency::FORTY_EIGHT_KHZ);
            a.rtc
                .write_media(now, audio, None, opus, t, &[0xfc, 1, 2, 3])
                .unwrap();
            drain(&mut a, now, &mut net);
        }
        step(&mut a, &mut b, now, &mut net);
    }
    let of = |pt: u8| {
        net.log
            .iter()
            .filter(|(_, from, p)| *from == a.addr && *p == pt)
            .map(|(t, _, _)| t.saturating_duration_since(start))
            .collect::<Vec<_>>()
    };
    (of(vp8.get()), of(opus.get()), a)
}

fn bwe_cfg(max: u64) -> ConfigInner {
    ConfigInner {
        bwe: Some(max),
        bwe_bounds: (30_000, max),
        ..ConfigInner::default()
    }
}

#[test]
fn pacer_spreads_a_keyframe() {
    // 1 Mbps estimate (the maximum): 2.5 Mbps pacing, 12.5 kB of burst. A 60 kB keyframe (50
    // packets): about 10 at once, the rest over (60 - 12.5) kB / 312.5 kB/s = 150 ms.
    let (video, audio, a) = keyframe_timing(bwe_cfg(1_000_000), 60_000, 400);
    let n = video.len();
    let at_once = video
        .iter()
        .filter(|t| **t < Duration::from_millis(1))
        .count();
    let last = *video.last().unwrap();
    println!(
        "paced: {n} packets, {at_once} at once, last after {last:?}, estimate {}",
        a.rtc.bwe.as_ref().unwrap().estimate()
    );
    assert!(n >= 50, "{n}");
    assert!((8..=13).contains(&at_once), "{at_once}");
    assert!(
        last >= Duration::from_millis(120) && last <= Duration::from_millis(220),
        "{last:?}"
    );
    // Evenly: no 10 ms window after the burst carries much more than 10 ms at the pacing
    // rate (3125 bytes, under 4 packets) plus one.
    for w in 1..15u64 {
        let (lo, hi) = (
            Duration::from_millis(w * 10),
            Duration::from_millis(w * 10 + 10),
        );
        let k = video.iter().filter(|t| **t >= lo && **t < hi).count();
        assert!(k <= 5, "{k} packets in {lo:?}..{hi:?}");
    }
    // The Opus packet written 5 ms in left at once, ahead of the queued video.
    assert_eq!(audio, [Duration::from_millis(5)]);
    assert!(a.rtc.pacer.is_empty());
    // Pacing off, or no estimator: the frame leaves at once.
    let cfg = ConfigInner {
        pacing: false,
        ..bwe_cfg(1_000_000)
    };
    let (video, _, _) = keyframe_timing(cfg, 60_000, 50);
    assert!(
        video.iter().all(|t| *t < Duration::from_millis(1)),
        "{video:?}"
    );
    let (video, _, _) = keyframe_timing(ConfigInner::default(), 60_000, 50);
    assert!(
        video.iter().all(|t| *t < Duration::from_millis(1)),
        "{video:?}"
    );
}

#[test]
fn pacer_queue_rules() {
    let t0 = Instant::now();
    let q = |n: u8, at: Instant| Queued {
        raw: vec![n; 1000],
        twcc: None,
        ast: None,
        fec: false,
        at,
    };
    let mut p = Pacer::default();
    p.set_rates(800_000, 0); // 250 kB/s, 10 kB of burst
    p.advance(t0);
    p.push(Class::Media, q(1, t0));
    p.push(Class::Media, q(2, t0));
    p.push(Class::Retransmission, q(3, t0));
    // Retransmissions first, then media in order.
    let order: Vec<u8> = std::iter::from_fn(|| p.pop().map(|x| x.raw[0])).collect();
    assert_eq!(order, [3, 1, 2]);
    // The burst allowance: 10 packets, then the next is due 4 ms per packet later.
    assert!(p.can_send(t0));
    for _ in 0..10 {
        p.on_sent(1000);
    }
    p.push(Class::Media, q(4, t0));
    // Exactly the allowance: still due.
    assert!(p.can_send(t0));
    let next = p.next_send(t0).unwrap();
    assert_eq!(next.duration_since(t0), Duration::from_millis(0));
    p.on_sent(1000);
    assert!(!p.can_send(t0));
    // 1000 bytes over (less the byte of slack) at 250 kB/s: 4 ms.
    let next = p.next_send(t0).unwrap();
    let wait = next.duration_since(t0);
    assert!(
        wait > Duration::from_micros(3990) && wait <= Duration::from_millis(4),
        "{wait:?}"
    );
    p.advance(next);
    assert!(p.can_send(next));
    // An old queue drains faster: 1 MB queued 1.9 s ago must leave within 0.1 s.
    let mut p = Pacer::default();
    p.set_rates(800_000, 0);
    p.advance(t0);
    for _ in 0..1000 {
        p.push(Class::Media, q(5, t0));
    }
    let late = t0 + Duration::from_millis(1900);
    p.advance(late);
    for _ in 0..200 {
        p.on_sent(1000);
    }
    let next = p.next_send(late).unwrap();
    assert!(
        next.duration_since(late) < Duration::from_millis(5),
        "{next:?}"
    );
    // Bounded: past 8192 packets the oldest media goes.
    let mut p = Pacer::default();
    for i in 0..9000u32 {
        p.push(Class::Media, q(i as u8, t0));
    }
    assert_eq!(p.dropped, 9000 - 8192);
    assert_eq!(p.pop().unwrap().raw[0], (9000u32 - 8192) as u8);
    // Padding: due while the queue is empty and the budgets allow.
    let mut p = Pacer::default();
    p.set_rates(1_000_000, 200_000);
    p.advance(t0);
    assert!(p.next_send(t0).is_some());
    p.on_padding(1000);
    // 1000 bytes at 25 kB/s of padding: due 40 ms later.
    let next = p.next_send(t0).unwrap();
    assert_eq!(next.duration_since(t0), Duration::from_millis(40));
    assert!(p.padding_due(t0).is_none());
    p.advance(next);
    assert_eq!(p.padding_due(next), Some(1000));
}

#[test]
fn send_time_extensions_are_patched() {
    let map = ExtensionMap::default_video();
    for two_byte in [false, true] {
        let ext = ExtensionValues {
            mid: Some(if two_byte { "x".repeat(20) } else { "0".into() }),
            transport_cc: Some(0),
            abs_send_time: Some(0),
            ..ExtensionValues::default()
        };
        let h = RtpHeader {
            sequence_number: 5,
            ext,
            ..RtpHeader::default()
        };
        let mut raw = h.write(&map, b"payload");
        let tw = map.id_of(Extension::TransportCc).unwrap();
        let ast = map.id_of(Extension::AbsSendTime).unwrap();
        assert!(patch_ext(&mut raw, tw, &0xabcdu16.to_be_bytes()));
        assert!(patch_ext(&mut raw, ast, &[1, 2, 3]));
        // Wrong length or absent: untouched.
        assert!(!patch_ext(&mut raw, tw, &[1, 2, 3]));
        assert!(!patch_ext(&mut raw, 13, &[1]));
        let p = RtpHeader::parse(&raw, &map).unwrap();
        assert_eq!(p.ext.transport_cc, Some(0xabcd), "two-byte {two_byte}");
        assert_eq!(p.ext.abs_send_time, Some(0x010203));
        assert_eq!(p.payload(&raw), b"payload");
    }
    assert!(!patch_ext(&mut [0x80; 12], 1, &[0]));
}

#[test]
fn raised_maximum_is_probed() {
    let cfg = bwe_cfg(500_000);
    let (mut a, mut b, mids, now) = pair(cfg.clone(), cfg, &[MediaKind::Video]);
    let mut net = Net::new(3);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    let vp8 = a.rtc.payload_type(mids[0], Codec::Vp8).unwrap();
    let send =
        |a: &mut Side, b: &mut Side, net: &mut Net, now: &mut Instant, frames: u64, len: usize| {
            for i in 0..frames {
                let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
                a.rtc
                    .write_media(*now, mids[0], None, vp8, t, &vp8_frame(i, len))
                    .unwrap();
                for _ in 0..33 {
                    *now += Duration::from_millis(1);
                    step(a, b, *now, net);
                }
            }
        };
    // 30 fps of 3 kB (720 kbps) against a 500 kbps maximum.
    send(&mut a, &mut b, &mut net, &mut now, 60, 3000);
    assert!(a.rtc.bwe.as_ref().unwrap().estimate() <= 500_000);
    let before = a.rtc.stats.packets_sent;
    a.rtc.set_bitrate_bounds(now, 30_000, 5_000_000);
    // A probe cluster at the new maximum goes out at once (paced at its rate: 15 ms).
    for _ in 0..20 {
        now += Duration::from_millis(1);
        step(&mut a, &mut b, now, &mut net);
    }
    let probes = a.rtc.stats.packets_sent - before;
    assert!(probes >= 5, "{probes}");
    send(&mut a, &mut b, &mut net, &mut now, 30, 3000);
    let e = a.rtc.bwe.as_ref().unwrap().estimate();
    assert!(e > 1_500_000, "estimate {e} 1 s after the raise");
}

#[test]
fn ecn_in_rfc8888_feedback() {
    for ccfb in [true, false] {
        let cfg = ConfigInner {
            ccfb,
            ..bwe_cfg(2_000_000)
        };
        let (mut a, mut b, mids, now) = pair(cfg.clone(), cfg, &[MediaKind::Video]);
        let mut net = Net::new(5);
        let mut now = connect(&mut a, &mut b, &mut net, now);
        net.ecn = 2; // ECT(0)
        net.ce_every = 10;
        let vp8 = a.rtc.payload_type(mids[0], Codec::Vp8).unwrap();
        for i in 0..60u64 {
            let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
            a.rtc
                .write_media(now, mids[0], None, vp8, t, &vp8_frame(i, 2500))
                .unwrap();
            for _ in 0..33 {
                now += Duration::from_millis(1);
                step(&mut a, &mut b, now, &mut net);
            }
        }
        let st = b.rtc.stats;
        assert!(st.ecn_ect_received > 100, "{st:?}");
        let ce = st.ecn_ce_received;
        assert!(
            ce * 12 > st.ecn_ect_received && ce * 8 < st.ecn_ect_received,
            "{st:?}"
        );
        let (ect, ce_fb) = a.rtc.bwe.as_ref().unwrap().ecn_counts();
        if ccfb {
            // RFC 8888 carries every codepoint back: the sender sees the marks.
            assert!(
                ect > 100 && ce_fb * 12 > ect && ce_fb * 8 < ect,
                "{ect} {ce_fb}"
            );
        } else {
            assert_eq!((ect, ce_fb), (0, 0), "transport-wide feedback has no ECN");
        }
    }
}

fn red_pcmu_cfg(n: Option<u8>) -> ConfigInner {
    ConfigInner {
        codecs: vec![Codec::Pcmu, Codec::Pcma],
        audio_red: n,
        ..ConfigInner::default()
    }
}

/// `a` sends 300 PCMU packets (20 ms) with `loss` % loss; the frames `b` got.
fn pcmu_red_run(n: Option<u8>, loss: u32, seed: u64) -> (usize, Side, Side) {
    let (mut a, mut b, mids, now) = pair(
        red_pcmu_cfg(n),
        red_pcmu_cfg(n.map(|_| 0)),
        &[MediaKind::Audio],
    );
    let mut net = Net::new(seed);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    net.loss = loss;
    let pcmu = a.rtc.payload_type(mids[0], Codec::Pcmu).unwrap();
    for i in 0..320u64 {
        let t = MediaTime::new(i * 160, Frequency::new(8000).unwrap());
        let f: Vec<u8> = (0..160).map(|k| (k as u8) ^ (i as u8)).collect();
        a.rtc.write_media(now, mids[0], None, pcmu, t, &f).unwrap();
        for _ in 0..4 {
            now += Duration::from_millis(5);
            step(&mut a, &mut b, now, &mut net);
        }
    }
    for _ in 0..100 {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
    }
    let got = b
        .events
        .iter()
        .filter(|e| {
            matches!(e, RtcEvent::MediaData(d) if d.mid == mids[0]
                && d.time.ticks() < 300 * 160
                && d.data[0] == (d.time.ticks() / 160) as u8)
        })
        .count();
    (got, a, b)
}

#[test]
fn red_for_pcmu() {
    let (a, _, _, _) = pair(
        red_pcmu_cfg(Some(1)),
        red_pcmu_cfg(Some(0)),
        &[MediaKind::Audio],
    );
    let offer = a.rtc.write_sdp(true);
    assert!(
        offer.contains("a=rtpmap:110 red/8000\r\na=fmtp:110 0/0\r\na=rtpmap:0 PCMU/8000"),
        "{offer}"
    );
    assert!(
        offer.contains("a=rtpmap:112 red/8000\r\na=fmtp:112 8/8"),
        "{offer}"
    );
    assert_eq!(a.rtc.media[0].red_other, [(110, 0), (112, 8)]);
    // Off on the answerer: none.
    let (a, b, _, _) = pair(
        red_pcmu_cfg(Some(1)),
        red_pcmu_cfg(None),
        &[MediaKind::Audio],
    );
    assert!(a.rtc.media[0].red_other.is_empty() && b.rtc.media[0].red_other.is_empty());
    // 10 % loss: one redundant packet brings most back.
    for seed in [3, 17] {
        let (plain, _, _) = pcmu_red_run(None, 10, seed);
        let (got, _, b) = pcmu_red_run(Some(1), 10, seed);
        println!("seed {seed}: {got} of 300 with RED, {plain} without");
        assert!(b.rtc.stats.red_recovered > 10, "{:?}", b.rtc.stats);
        assert!(
            got >= 290 && got > plain + 15,
            "seed {seed}: {got} with RED, {plain} without"
        );
    }
}

#[test]
fn partial_ulpfec_packets_reach_the_depacketizer() {
    // ULPFEC with a 40-byte level 0, no NACK, 3-packet frames, 15 % loss: double losses in a
    // group leave packets rebuilt in part, handed out as partial (not contiguous) frames.
    let cfg = ConfigInner {
        fec: Some(FecMechanism::Ulpfec),
        fec_min: 200,
        fec_max: 255,
        ulpfec_level0: Some(40),
        ..ConfigInner::default()
    };
    let (mut a, mut b, mids, now) = pair(cfg.clone(), cfg, &[MediaKind::Video]);
    // No NACK on the receiver: drop it from both lines.
    for s in [&mut a, &mut b] {
        for c in &mut s.rtc.media[0].codecs {
            c.fb.retain(|f| f != "nack");
        }
        for r in s.rtc.recv.values_mut() {
            r.stream = RecvStream::new(r.stream.ssrc(), 90_000, false);
        }
    }
    let mut net = Net::new(11);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    net.loss = 15;
    let vp8 = a.rtc.payload_type(mids[0], Codec::Vp8).unwrap();
    for i in 0..300u64 {
        let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
        a.rtc
            .write_media(now, mids[0], None, vp8, t, &vp8_frame(i + 1, 3000))
            .unwrap();
        for _ in 0..33 {
            now += Duration::from_millis(1);
            step(&mut a, &mut b, now, &mut net);
        }
    }
    let st = b.rtc.stats;
    let partial = b
        .events
        .iter()
        .filter(|e| matches!(e, RtcEvent::MediaData(d) if !d.contiguous && d.data.len() < 3000))
        .count();
    println!("{st:?}, {partial} partial frames");
    assert!(st.fec_partial > 0 && partial > 0, "{st:?}");
}
