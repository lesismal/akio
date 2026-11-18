//! Two peers over a simulated lossy, jittery link in simulated time: ICE, DTLS, SCTP and media
//! end to end; SDP negotiation details.

use super::*;
use crate::SdpChanges;

/// A deterministic lossy, jittery network between two peers.
struct Net {
    rng: u64,
    loss: u32,
    jitter_ms: u64,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>)>,
}

impl Net {
    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn send(&mut self, now: Instant, from: SocketAddr, to: SocketAddr, d: Vec<u8>) {
        if (self.rand() % 100) < u64::from(self.loss) {
            return;
        }
        let delay = 10 + self.rand() % (self.jitter_ms + 1);
        self.queue
            .push((now + Duration::from_millis(delay), from, to, d));
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
    for (_, from, to, d) in due {
        let s = if to == a.addr { &mut *a } else { &mut *b };
        s.rtc.handle_receive(now, from, to, &d);
    }
    for s in [&mut *a, &mut *b] {
        if s.wake <= now {
            s.rtc.handle_timeout(now);
        }
        drain(s, now, net);
    }
}

fn pair(lite_answerer: bool) -> (Side, Side, ChannelId, Mid, Mid, Instant) {
    let now = Instant::now();
    let mut a = Rtc::new(ConfigInner::default(), false, now).unwrap();
    let mut b = Rtc::new(ConfigInner::default(), lite_answerer, now).unwrap();
    let (aa, ba): (SocketAddr, SocketAddr) = (
        "10.0.0.1:1000".parse().unwrap(),
        "10.0.0.2:2000".parse().unwrap(),
    );
    a.add_local_candidate(IceCandidate::host(aa));
    b.add_local_candidate(IceCandidate::host(ba));
    let mut ch = a.changes();
    let (id, audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_channel("sim"),
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
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
    (side(a, aa), side(b, ba), id, audio, video, now)
}

fn run(lite: bool, loss: u32, seed: u64) {
    let (mut a, mut b, ch, audio, video, start) = pair(lite);
    let mut net = Net {
        rng: seed,
        loss,
        jitter_ms: 30,
        queue: Vec::new(),
    };
    let mut now = start;
    let tick = Duration::from_millis(5);
    // Connect (ICE + DTLS + SCTP).
    while !(a.rtc.is_connected()
        && b.rtc.is_connected()
        && b.events
            .iter()
            .any(|e| matches!(e, RtcEvent::ChannelOpen(..))))
    {
        now += tick;
        step(&mut a, &mut b, now, &mut net);
        assert!(now - start < Duration::from_secs(60), "no connection");
    }
    assert!(a.events.iter().any(|e| matches!(e, RtcEvent::Connected)));
    let opus = a.rtc.payload_type(audio, Codec::Opus).unwrap();
    let vp8 = a.rtc.payload_type(video, Codec::Vp8).unwrap();
    // Data, audio and video for a few seconds.
    let mut sent_msgs = 0u32;
    let frame: Vec<u8> = (0..4000u32).map(|i| (i * 13) as u8).collect();
    for i in 0..250u64 {
        for _ in 0..4 {
            let m = format!("msg {sent_msgs}");
            if a.rtc.send_channel(now, ch, m.as_bytes(), false).unwrap() == Some(true) {
                sent_msgs += 1;
            }
        }
        let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
        a.rtc
            .write_media(now, audio, None, opus, t, &[0xfc, i as u8, 7])
            .unwrap();
        if i % 2 == 0 {
            let mut f = frame.clone();
            f[0] = if i == 0 { 0x10 } else { 0x11 };
            f[1] = i as u8;
            let t = MediaTime::new(i * 1800, Frequency::NINETY_KHZ);
            a.rtc.write_media(now, video, None, vp8, t, &f).unwrap();
        }
        for _ in 0..4 {
            now += tick;
            step(&mut a, &mut b, now, &mut net);
        }
    }
    // Let retransmissions finish.
    for _ in 0..2000 {
        now += tick;
        step(&mut a, &mut b, now, &mut net);
    }
    let msgs: Vec<&Vec<u8>> = b
        .events
        .iter()
        .filter_map(|e| match e {
            RtcEvent::ChannelData(_, d, _) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(msgs.len() as u32, sent_msgs, "every message arrives");
    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(**m, format!("msg {i}").into_bytes(), "in order");
    }
    let (mut au, mut vi) = (0usize, 0usize);
    for e in &b.events {
        if let RtcEvent::MediaData(d) = e {
            if d.mid == audio {
                assert_eq!(&d.data[2..], &[7]);
                au += 1;
            } else {
                assert_eq!(d.data.len(), frame.len());
                assert_eq!(&d.data[2..], &frame[2..]);
                vi += 1;
            }
        }
    }
    // Audio is not retransmitted; video is repaired with NACK + RTX.
    // (The loss is random per datagram, and a packet that arrives after the reorder buffer gave
    // up on it is dropped: leave room.)
    let want_audio = 250 * (100 - 3 * loss as usize) / 100;
    assert!(au >= want_audio, "audio {au} < {want_audio}");
    assert!(vi >= 120, "video {vi}");
}

#[test]
fn lossless_full_ice() {
    run(false, 0, 1);
}

#[test]
fn lossy_full_ice() {
    for seed in [7, 99, 12345] {
        run(false, 10, seed);
    }
}

#[test]
fn lossy_ice_lite() {
    for seed in [3, 4242] {
        run(true, 10, seed);
    }
}

#[test]
fn sdp_negotiation() {
    let (a, b, _, audio, video, _) = pair(true);
    let offer = a.rtc.write_sdp(true);
    assert!(offer.contains("a=setup:actpass"));
    assert!(offer.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
    assert!(offer.contains("a=rtpmap:111 opus/48000/2"));
    assert!(offer.contains("a=group:BUNDLE 0 1 2"), "{offer}");
    let answer = b.rtc.write_sdp(false);
    assert!(answer.contains("a=ice-lite"));
    assert!(answer.contains("a=setup:active"));
    assert_eq!(a.rtc.dtls_role, Some(Role::Server));
    assert_eq!(b.rtc.dtls_role, Some(Role::Client));
    for c in [Codec::Opus, Codec::Pcmu] {
        assert!(b.rtc.payload_type(audio, c).is_some(), "{c:?}");
    }
    assert!(b.rtc.payload_type(video, Codec::Vp8).is_some());
    assert!(b.rtc.payload_type(video, Codec::H265).is_none());
    let l = &b.rtc.media[1];
    assert_eq!(
        l.codecs.iter().find(|c| c.codec == Codec::Vp8).unwrap().rtx,
        Some(97)
    );
    assert!(l.ext.id_of(Extension::TransportCc).is_some());
}

#[test]
fn answers_a_browser_offer() {
    // A Chrome-style offer: H.264 in two packetization modes, RTX, unknown extensions and an
    // mDNS candidate.
    let offer = "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=group:BUNDLE 0 1\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS s\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103 106\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n\
a=candidate:1 1 udp 2122260223 abc.local 50000 typ host generation 0\r\n\
a=candidate:2 1 udp 2122260223 192.0.2.9 50001 typ host generation 0\r\n\
a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\na=ice-options:trickle\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:actpass\r\na=mid:0\r\na=extmap:1 urn:ietf:params:rtp-hdrext:toffset\r\n\
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n\
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\na=extmap:9 http://example.com/unknown\r\n\
a=sendrecv\r\na=msid:s t\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\n\
a=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtcp-fb:96 transport-cc\r\na=rtpmap:97 rtx/90000\r\n\
a=fmtp:97 apt=96\r\na=rtpmap:102 H264/90000\r\n\
a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n\
a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\na=rtpmap:106 H264/90000\r\n\
a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
a=ssrc-group:FID 1111 2222\r\na=ssrc:1111 cname:x\r\na=ssrc:2222 cname:x\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\na=mid:1\r\na=sctp-port:5000\r\n\
a=max-message-size:262144\r\n";
    let now = Instant::now();
    let mut rtc = Rtc::new(ConfigInner::default(), true, now).unwrap();
    let answer = rtc.accept_offer(now, offer).unwrap();
    let sdp = Sdp::parse(&answer).unwrap();
    assert_eq!(sdp.media.len(), 2);
    let v = &sdp.media[0];
    assert_eq!(v.fmts, ["96", "97", "106"]);
    assert!(v.all("extmap").all(|e| !e.contains("unknown")));
    assert_eq!(v.get("mid"), Some("0"));
    assert_eq!(sdp.media[1].get("mid"), Some("1"));
    assert_eq!(sdp.get("group"), Some("BUNDLE 0 1"));
    assert_eq!(rtc.media[0].remote_rtx.get(&2222), Some(&1111));
    assert!(
        rtc.events
            .iter()
            .any(|e| matches!(e, RtcEvent::MediaAdded(_)))
    );
    // Renegotiation: the same offer again keeps the lines.
    let again = rtc.accept_offer(now, offer).unwrap();
    assert_eq!(Sdp::parse(&again).unwrap().media.len(), 2);
    // Garbage and an answer without a pending offer are errors.
    assert!(rtc.accept_offer(now, "v=0\r\n").is_err());
    assert!(rtc.accept_answer(now, offer).is_err());
}

/// A simulcast sender (three encodings) and a receiver of this stack: the answer accepts the
/// RIDs, each arrives as its own stream with its RID, survives loss through RTX (repaired RID),
/// and keyframe requests name the encoding.
fn simulcast(
    strip_answer: bool,
    loss: u32,
) -> (Vec<Option<String>>, Vec<RtcEvent>, Vec<Option<String>>) {
    let now = Instant::now();
    let mut a = Rtc::new(ConfigInner::default(), false, now).unwrap();
    let mut b = Rtc::new(ConfigInner::default(), false, now).unwrap();
    let (aa, ba): (SocketAddr, SocketAddr) = (
        "10.0.0.1:1000".parse().unwrap(),
        "10.0.0.2:2000".parse().unwrap(),
    );
    a.add_local_candidate(IceCandidate::host(aa));
    b.add_local_candidate(IceCandidate::host(ba));
    let mut ch = a.changes();
    let video = SdpChanges(&mut ch)
        .add_simulcast_media(
            MediaKind::Video,
            Direction::SendOnly,
            &["h", "m", "l"],
            None,
            None,
        )
        .unwrap();
    let offer = a.apply(now, ch).unwrap().unwrap();
    assert!(
        offer.contains("a=rid:h send\r\na=rid:m send\r\na=rid:l send\r\n"),
        "{offer}"
    );
    assert!(offer.contains("a=simulcast:send h;m;l"));
    assert!(offer.contains("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"));
    assert!(!offer.contains("a=ssrc:"));
    let mut answer = b.accept_offer(now, &offer).unwrap();
    assert!(answer.contains("a=rid:h recv"), "{answer}");
    assert!(answer.contains("a=simulcast:recv h;m;l"));
    if strip_answer {
        answer = answer
            .lines()
            .filter(|l| !l.starts_with("a=simulcast") && !l.starts_with("a=rid"))
            .map(|l| format!("{l}\r\n"))
            .collect();
    }
    a.accept_answer(now, &answer).unwrap();
    let side = |rtc, addr| Side {
        rtc,
        addr,
        events: Vec::new(),
        wake: now,
    };
    let (mut a, mut b) = (side(a, aa), side(b, ba));
    let mut net = Net {
        rng: 7,
        loss,
        jitter_ms: 20,
        queue: Vec::new(),
    };
    let mut t = now;
    while !(a.rtc.is_connected() && b.rtc.is_connected()) {
        t += Duration::from_millis(5);
        step(&mut a, &mut b, t, &mut net);
        assert!(t - now < Duration::from_secs(60), "no connection");
    }
    let vp8 = a.rtc.payload_type(video, Codec::Vp8).unwrap();
    for i in 0..100u64 {
        let ts = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
        for (rid, size) in [("h", 3000usize), ("m", 1500), ("l", 400)] {
            let frame: Vec<u8> = (0..size).map(|k| (k as u8) ^ (i as u8)).collect();
            assert!(
                a.rtc
                    .write_media(t, video, Some(rid), vp8, ts, &frame)
                    .unwrap()
            );
        }
        assert!(
            !a.rtc
                .write_media(t, video, Some("x"), vp8, ts, &[1])
                .unwrap()
        );
        for _ in 0..6 {
            t += Duration::from_millis(5);
            step(&mut a, &mut b, t, &mut net);
        }
    }
    assert!(b.rtc.request_keyframe(video, KeyframeRequestKind::Pli));
    for _ in 0..400 {
        t += Duration::from_millis(5);
        step(&mut a, &mut b, t, &mut net);
    }
    // A keyframe request for one layer reaches that encoding only.
    let mark = a.events.len();
    assert!(
        !b.rtc
            .request_keyframe_of(video, Some("x"), KeyframeRequestKind::Pli)
    );
    assert_eq!(
        b.rtc
            .request_keyframe_of(video, Some("m"), KeyframeRequestKind::Pli),
        !strip_answer
    );
    for _ in 0..400 {
        t += Duration::from_millis(5);
        step(&mut a, &mut b, t, &mut net);
    }
    let layer_kf = a.events[mark..]
        .iter()
        .filter_map(|e| match e {
            RtcEvent::Keyframe(k) => Some(k.rid.clone()),
            _ => None,
        })
        .collect();
    let rids = b
        .events
        .iter()
        .filter_map(|e| match e {
            RtcEvent::MediaData(d) => Some(d.rid.clone()),
            _ => None,
        })
        .collect();
    (rids, a.events, layer_kf)
}

#[test]
fn simulcast_three_encodings() {
    for loss in [0, 10] {
        let (rids, a_events, layer_kf) = simulcast(false, loss);
        assert!(!layer_kf.is_empty(), "no keyframe request for layer m");
        assert!(
            layer_kf.iter().all(|r| r.as_deref() == Some("m")),
            "{layer_kf:?}"
        );
        for r in ["h", "m", "l"] {
            let n = rids.iter().filter(|x| x.as_deref() == Some(r)).count();
            // Under loss NACK/RTX (with the repaired RID) fills the gaps.
            assert!(n >= 95, "rid {r}: {n} frames at {loss}% loss");
        }
        let mut kf: Vec<Option<String>> = a_events
            .iter()
            .filter_map(|e| match e {
                RtcEvent::Keyframe(k) => Some(k.rid.clone()),
                _ => None,
            })
            .collect();
        kf.sort();
        kf.dedup();
        assert_eq!(
            kf,
            vec![Some("h".into()), Some("l".into()), Some("m".into())]
        );
    }
}

#[test]
fn simulcast_without_answer_support_sends_the_first() {
    let (rids, _, _) = simulcast(true, 0);
    assert!(rids.len() >= 95);
    assert!(rids.iter().all(|r| r.as_deref() == Some("h")), "{rids:?}");
}

#[test]
fn simulcast_api_checks() {
    let now = Instant::now();
    let a = Rtc::new(ConfigInner::default(), false, now).unwrap();
    let mut ch = a.changes();
    let mut api = SdpChanges(&mut ch);
    let v = MediaKind::Video;
    assert!(
        api.add_simulcast_media(v, Direction::RecvOnly, &["a"], None, None)
            .is_err()
    );
    assert!(
        api.add_simulcast_media(v, Direction::SendOnly, &[], None, None)
            .is_err()
    );
    assert!(
        api.add_simulcast_media(v, Direction::SendOnly, &["a", "a"], None, None)
            .is_err()
    );
    assert!(
        api.add_simulcast_media(v, Direction::SendOnly, &["a b"], None, None)
            .is_err()
    );
    let nine = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];
    assert!(
        api.add_simulcast_media(v, Direction::SendOnly, &nine, None, None)
            .is_err()
    );
    assert!(
        api.add_simulcast_media(v, Direction::SendRecv, &nine[..8], None, None)
            .is_ok()
    );
}

// ---- FEC, RFC 8888, XR and TMMBR (ADR-039) ----

/// Two peers with configurations `ca` / `cb` and one video line `dir` (from the offerer `a`);
/// `munge` edits the offer and the answer in flight.
fn pair_with(
    ca: ConfigInner,
    cb: ConfigInner,
    dir: Direction,
    munge: fn(&str) -> String,
) -> (Side, Side, Mid, Instant) {
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
    let video = SdpChanges(&mut ch).add_media(MediaKind::Video, dir, None, None);
    let offer = munge(&a.apply(now, ch).unwrap().unwrap());
    let answer = munge(&b.accept_offer(now, &offer).unwrap());
    a.accept_answer(now, &answer).unwrap();
    let side = |rtc, addr| Side {
        rtc,
        addr,
        events: Vec::new(),
        wake: now,
    };
    (side(a, aa), side(b, ba), video, now)
}

fn same(s: &str) -> String {
    s.to_owned()
}

fn no_nack(s: &str) -> String {
    s.split("\r\n")
        .filter(|l| !(l.starts_with("a=rtcp-fb:") && l.ends_with(" nack")))
        .collect::<Vec<_>>()
        .join("\r\n")
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

/// `a` sends `frames` VP8 frames of ~3 packets at 25 fps; returns the frames `b` got whole
/// (`contiguous`) and the time.
fn send_video(
    a: &mut Side,
    b: &mut Side,
    net: &mut Net,
    video: Mid,
    frames: u64,
    mut now: Instant,
) -> (usize, Instant) {
    let vp8 = a.rtc.payload_type(video, Codec::Vp8).unwrap();
    let frame: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    for i in 0..frames {
        let mut f = frame.clone();
        f[0] = if i == 0 { 0x10 } else { 0x11 };
        f[1] = i as u8;
        let t = MediaTime::new(i * 3600, Frequency::NINETY_KHZ);
        a.rtc.write_media(now, video, None, vp8, t, &f).unwrap();
        for _ in 0..8 {
            now += Duration::from_millis(5);
            step(a, b, now, net);
        }
    }
    for _ in 0..400 {
        now += Duration::from_millis(5);
        step(a, b, now, net);
    }
    let whole = b
        .events
        .iter()
        .filter(|e| matches!(e, RtcEvent::MediaData(d) if d.mid == video && d.data.len() == frame.len() && d.data[2..] == frame[2..]))
        .count();
    (whole, now)
}

fn fec_cfg(m: Option<FecMechanism>) -> ConfigInner {
    ConfigInner {
        fec: m,
        fec_min: 80,
        ..ConfigInner::default()
    }
}

#[test]
fn fec_negotiation() {
    // Default configurations offer no FEC (browser interop unchanged).
    let (a, b, video, _) = pair_with(
        ConfigInner::default(),
        ConfigInner::default(),
        Direction::SendRecv,
        same,
    );
    let offer = a.rtc.write_sdp(true);
    assert!(!offer.contains("ulpfec") && !offer.contains("flexfec") && !offer.contains("red/"));
    assert!(!offer.contains("ccfb") && !offer.contains("tmmbr") && !offer.contains("rtcp-xr"));
    assert_eq!(b.rtc.media[0].fec_pts, FecPts::default());
    // ULPFEC both sides: red + its RTX + ulpfec.
    let (a, b, video2, _) = pair_with(
        fec_cfg(Some(FecMechanism::Ulpfec)),
        fec_cfg(Some(FecMechanism::Ulpfec)),
        Direction::SendRecv,
        same,
    );
    assert_eq!(video, video2);
    let offer = a.rtc.write_sdp(true);
    for l in [
        "a=rtpmap:116 red/90000",
        "a=rtpmap:117 rtx/90000",
        "a=fmtp:117 apt=116",
        "a=rtpmap:118 ulpfec/90000",
    ] {
        assert!(offer.contains(l), "{l}\n{offer}");
    }
    let want = FecPts {
        red: Some(116),
        red_rtx: Some(117),
        ulpfec: Some(118),
        flexfec: None,
    };
    assert_eq!(a.rtc.media[0].fec_pts, want);
    assert_eq!(b.rtc.media[0].fec_pts, want);
    assert_eq!(b.rtc.media[0].fec_send_scheme(), Some(FecScheme::Ulpfec));
    // FlexFEC against a peer without FEC: offered with FEC-FR, not negotiated.
    let (a, b, _, _) = pair_with(
        fec_cfg(Some(FecMechanism::FlexFec)),
        ConfigInner::default(),
        Direction::SendRecv,
        same,
    );
    let now = Instant::now();
    let mut o = Rtc::new(fec_cfg(Some(FecMechanism::FlexFec)), false, now).unwrap();
    let mut ch = o.changes();
    SdpChanges(&mut ch).add_media(MediaKind::Video, Direction::SendRecv, None, None);
    let offer = o.apply(now, ch).unwrap().unwrap();
    assert!(offer.contains("a=rtpmap:115 flexfec-03/90000"), "{offer}");
    assert!(offer.contains("a=fmtp:115 repair-window=10000000"));
    assert!(offer.contains("a=rtcp-fb:115 transport-cc"));
    let fec_fr = format!(
        "a=ssrc-group:FEC-FR {} {}",
        o.media[0].send.ssrc(),
        o.media[0].fec_send.ssrc()
    );
    assert!(offer.contains(&fec_fr), "{offer}");
    assert_eq!(b.rtc.media[0].fec_pts, FecPts::default());
    assert_eq!(a.rtc.media[0].fec_pts, FecPts::default());
    assert!(!b.rtc.write_sdp(false).contains("flexfec"));
    // FlexFEC both sides: the answerer learns the offerer's FEC stream.
    let (a, b, _, _) = pair_with(
        fec_cfg(Some(FecMechanism::FlexFec)),
        fec_cfg(Some(FecMechanism::FlexFec)),
        Direction::SendRecv,
        same,
    );
    assert_eq!(b.rtc.media[0].fec_pts.flexfec, Some(115));
    assert_eq!(
        b.rtc.media[0]
            .remote_fec
            .get(&a.rtc.media[0].fec_send.ssrc()),
        Some(&a.rtc.media[0].send.ssrc())
    );
    assert!(b.rtc.write_sdp(false).contains("FEC-FR"));
    // Mismatched mechanisms negotiate nothing.
    let (_, b, _, _) = pair_with(
        fec_cfg(Some(FecMechanism::FlexFec)),
        fec_cfg(Some(FecMechanism::Ulpfec)),
        Direction::SendRecv,
        same,
    );
    assert_eq!(b.rtc.media[0].fec_pts, FecPts::default());
}

#[test]
fn fec_rate_policy() {
    let cfg = ConfigInner::default();
    assert_eq!(fec_rate(&cfg, 0.0), 0);
    assert_eq!(fec_rate(&cfg, 0.005), 0);
    assert_eq!(fec_rate(&cfg, 0.05), 38);
    assert_eq!(fec_rate(&cfg, 0.5), 128);
    let cfg = ConfigInner {
        fec_min: 20,
        fec_max: 60,
        ..ConfigInner::default()
    };
    assert_eq!(fec_rate(&cfg, 0.0), 20);
    assert_eq!(fec_rate(&cfg, 0.3), 60);
}

/// Video over a link with 8 % loss and no NACK: FEC alone repairs it.
fn fec_run(m: Option<FecMechanism>, seed: u64) -> (usize, Stats) {
    let (mut a, mut b, video, now) =
        pair_with(fec_cfg(m), fec_cfg(m), Direction::SendRecv, no_nack);
    assert!(!b.rtc.media[0].codecs[0].fb.iter().any(|f| f == "nack"));
    let mut net = Net {
        rng: seed,
        loss: 0,
        jitter_ms: 5,
        queue: Vec::new(),
    };
    let now = connect(&mut a, &mut b, &mut net, now);
    net.loss = 8;
    let (whole, _) = send_video(&mut a, &mut b, &mut net, video, 200, now);
    (whole, b.rtc.stats)
}

#[test]
fn fec_repairs_loss_without_nack() {
    for seed in [5, 77] {
        let (plain, st) = fec_run(None, seed);
        assert_eq!(st.fec_received, 0);
        for m in [FecMechanism::Ulpfec, FecMechanism::FlexFec] {
            let (whole, st) = fec_run(Some(m), seed);
            assert!(st.fec_received > 50, "{m:?}: {st:?}");
            assert!(st.fec_recovered > 10, "{m:?}: {st:?}");
            assert!(
                whole > plain + 20 && whole >= 180,
                "{m:?} seed {seed}: {whole} whole frames with FEC, {plain} without"
            );
        }
    }
}

#[test]
fn fec_with_nack_and_rtx() {
    // NACK + RTX (of RED for ULPFEC) and FEC together over a lossy link: every frame.
    for m in [FecMechanism::Ulpfec, FecMechanism::FlexFec] {
        let (mut a, mut b, video, now) = pair_with(
            fec_cfg(Some(m)),
            fec_cfg(Some(m)),
            Direction::SendRecv,
            same,
        );
        let mut net = Net {
            rng: 9,
            loss: 0,
            jitter_ms: 20,
            queue: Vec::new(),
        };
        let now = connect(&mut a, &mut b, &mut net, now);
        net.loss = 12;
        let (whole, _) = send_video(&mut a, &mut b, &mut net, video, 150, now);
        assert!(whole >= 148, "{m:?}: {whole}");
        assert!(a.rtc.stats.fec_sent > 0 && b.rtc.stats.fec_recovered > 0);
        assert!(
            a.rtc.media[0].send.packets_resent() > 0,
            "{m:?}: NACK repaired some"
        );
    }
}

#[test]
fn fec_rate_follows_reported_loss() {
    let cfg = ConfigInner {
        fec: Some(FecMechanism::FlexFec),
        ..ConfigInner::default()
    };
    let (mut a, mut b, video, now) = pair_with(cfg.clone(), cfg, Direction::SendRecv, same);
    let mut net = Net {
        rng: 3,
        loss: 0,
        jitter_ms: 5,
        queue: Vec::new(),
    };
    let now = connect(&mut a, &mut b, &mut net, now);
    // Clean link: no FEC.
    let (_, now) = send_video(&mut a, &mut b, &mut net, video, 100, now);
    assert_eq!(a.rtc.stats.fec_sent, 0);
    // 15 % loss: the receiver reports it, FEC starts.
    net.loss = 15;
    send_video(&mut a, &mut b, &mut net, video, 150, now);
    let rate = a.rtc.media[0].fec_enc.as_ref().unwrap().rate();
    assert!(rate > 40, "rate {rate}");
    assert!(a.rtc.stats.fec_sent > 20);
}

#[test]
fn ccfb_replaces_transport_cc() {
    let cfg = ConfigInner {
        ccfb: true,
        bwe: Some(300_000),
        ..ConfigInner::default()
    };
    let (mut a, mut b, video, now) = pair_with(cfg.clone(), cfg, Direction::SendRecv, same);
    assert!(a.rtc.ccfb && b.rtc.ccfb);
    assert!(a.rtc.write_sdp(true).contains("a=rtcp-fb:96 ack ccfb"));
    // The answer picks RFC 8888: on every payload type, without transport-wide feedback.
    let ans = b.rtc.write_sdp(false);
    assert!(ans.contains("a=rtcp-fb:97 ack ccfb"), "{ans}");
    assert!(
        !ans.contains("transport-cc") && !ans.contains("transport-wide-cc"),
        "{ans}"
    );
    let mut net = Net {
        rng: 11,
        loss: 0,
        jitter_ms: 2,
        queue: Vec::new(),
    };
    let now = connect(&mut a, &mut b, &mut net, now);
    send_video(&mut a, &mut b, &mut net, video, 200, now);
    // The estimator ran on RFC 8888 feedback: it grew from 300 kbps.
    let est = a.rtc.bwe.as_ref().unwrap().estimate();
    assert!(est > 330_000, "estimate {est}");
    assert!(
        b.rtc.twcc_media_ssrc == 0,
        "no transport-wide feedback recorded"
    );
    // Against a peer without it: transport-wide feedback stays.
    let (a, _, _, _) = pair_with(
        ConfigInner {
            ccfb: true,
            ..ConfigInner::default()
        },
        ConfigInner::default(),
        Direction::SendRecv,
        same,
    );
    assert!(!a.rtc.ccfb);
}

#[test]
fn xr_gives_a_receiver_its_rtt() {
    let cfg = ConfigInner {
        xr: true,
        ..ConfigInner::default()
    };
    // `a` only sends: `b` only receives and sends no sender reports.
    let (mut a, mut b, video, now) = pair_with(cfg.clone(), cfg, Direction::SendOnly, same);
    assert!(a.rtc.write_sdp(true).contains("a=rtcp-xr:rcvr-rtt=all"));
    assert!(a.rtc.media[0].xr && b.rtc.media[0].xr);
    let mut net = Net {
        rng: 21,
        loss: 0,
        jitter_ms: 0,
        queue: Vec::new(),
    };
    let now = connect(&mut a, &mut b, &mut net, now);
    send_video(&mut a, &mut b, &mut net, video, 150, now);
    let rtt = b.rtc.xr_rtt.expect("an RTT from DLRR");
    // 10 ms each way in the simulated network, plus the 5 ms tick.
    assert!(
        rtt >= Duration::from_millis(18) && rtt <= Duration::from_millis(35),
        "{rtt:?}"
    );
    assert_eq!(a.rtc.xr_rtt, None);
    // Without XR negotiated nothing is measured.
    let (mut a, mut b, video, now) = pair_with(
        ConfigInner::default(),
        ConfigInner::default(),
        Direction::SendOnly,
        same,
    );
    let now = connect(&mut a, &mut b, &mut net, now);
    send_video(&mut a, &mut b, &mut net, video, 100, now);
    assert_eq!(b.rtc.xr_rtt, None);
}

#[test]
fn tmmbr_caps_the_sender() {
    let cfg = ConfigInner {
        tmmbr: true,
        bwe: Some(1_000_000),
        ..ConfigInner::default()
    };
    let (mut a, mut b, video, now) = pair_with(cfg.clone(), cfg, Direction::SendRecv, same);
    assert!(a.rtc.write_sdp(true).contains("a=rtcp-fb:96 ccm tmmbr"));
    let mut net = Net {
        rng: 31,
        loss: 0,
        jitter_ms: 2,
        queue: Vec::new(),
    };
    let now = connect(&mut a, &mut b, &mut net, now);
    let (_, now) = send_video(&mut a, &mut b, &mut net, video, 40, now);
    assert!(b.rtc.request_max_bitrate(video, Some(200_000)));
    assert!(!b.rtc.request_max_bitrate(Mid::new("nope"), Some(1)));
    let (_, now) = send_video(&mut a, &mut b, &mut net, video, 60, now);
    let req = a.rtc.media[0].send.ssrc();
    let bound = a.events.iter().rev().find_map(|e| match e {
        RtcEvent::Other(Other::MaxBitrateRequest { ssrc, bitrate, .. }) if *ssrc == req => {
            Some(*bitrate)
        }
        _ => None,
    });
    let bound = bound.flatten().expect("a bound");
    assert!(bound <= 200_000 && bound > 150_000, "{bound}");
    assert!(a.rtc.bwe.as_ref().unwrap().estimate() <= 200_000);
    assert!(b.events.iter().any(|e| matches!(
        e,
        RtcEvent::Other(Other::MaxBitrateNotification { entries, .. })
            if entries.first().is_some_and(|x| x.1 == 200_000)
    )));
    // Withdrawn: the bound goes, the estimate may grow again.
    assert!(b.rtc.request_max_bitrate(video, None));
    send_video(&mut a, &mut b, &mut net, video, 40, now);
    let last = a.events.iter().rev().find_map(|e| match e {
        RtcEvent::Other(Other::MaxBitrateRequest { bitrate, .. }) => Some(*bitrate),
        _ => None,
    });
    assert_eq!(last, Some(None));
    assert!(a.rtc.tmmbr.is_empty());
}
