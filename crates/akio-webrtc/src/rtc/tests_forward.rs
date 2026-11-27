//! An SFU in simulated time (ADR-187): publishers into RTP-mode peers, their packets written
//! as they are to a viewer's peer ([`Rtc::write_rtp`]), with loss on both legs; RTCP feedback
//! (NACK, PLI, REMB) along the way; the renumbering on its own; the ICE consent timeouts.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::SdpChanges;

const TICK: Duration = Duration::from_millis(5);

struct Node {
    rtc: Rtc,
    addr: SocketAddr,
    events: Vec<RtcEvent>,
    wake: Instant,
}

type DropFn = Box<dyn FnMut(SocketAddr, SocketAddr, &[u8]) -> bool>;

/// Peers on one simulated network: every datagram takes 10 ms unless `drop` takes it.
struct World {
    nodes: Vec<Node>,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>)>,
    now: Instant,
    drop: DropFn,
}

impl World {
    fn new() -> World {
        World {
            nodes: Vec::new(),
            queue: Vec::new(),
            now: Instant::now(),
            drop: Box::new(|_, _, _| false),
        }
    }

    fn add(&mut self, rtc: Rtc) -> usize {
        let n = self.nodes.len();
        let addr = SocketAddr::from(([10, 0, 0, n as u8 + 1], 1000));
        self.nodes.push(Node {
            rtc,
            addr,
            events: Vec::new(),
            wake: self.now,
        });
        n
    }

    /// An offerer (full ICE) with `off` and an ICE-lite answerer with `ans`; the offer made
    /// by `f` and edited by `edit`.
    fn link<R>(
        &mut self,
        off: ConfigInner,
        ans: ConfigInner,
        f: impl FnOnce(&mut SdpChanges<'_, '_>) -> R,
        edit: impl Fn(String) -> String,
    ) -> (usize, usize, R) {
        let now = self.now;
        let mut a = Rtc::new(off, false, now).unwrap();
        let mut b = Rtc::new(ans, true, now).unwrap();
        let (ia, ib) = (self.add_placeholder(), self.add_placeholder());
        a.add_local_candidate(IceCandidate::host(self.nodes[ia].addr));
        b.add_local_candidate(IceCandidate::host(self.nodes[ib].addr));
        let mut ch = a.changes();
        let r = f(&mut SdpChanges(&mut ch));
        let offer = edit(a.apply(now, ch).unwrap().unwrap());
        let answer = b.accept_offer(now, &offer).unwrap();
        a.accept_answer(now, &answer).unwrap();
        self.nodes[ia].rtc = a;
        self.nodes[ib].rtc = b;
        (ia, ib, r)
    }

    fn add_placeholder(&mut self) -> usize {
        let rtc = Rtc::new(ConfigInner::default(), true, self.now).unwrap();
        self.add(rtc)
    }

    fn step(&mut self) {
        self.now += TICK;
        let now = self.now;
        let (due, keep): (Vec<_>, Vec<_>) = self.queue.drain(..).partition(|x| x.0 <= now);
        self.queue = keep;
        for (_, from, to, d) in due {
            if let Some(n) = self.nodes.iter_mut().find(|n| n.addr == to) {
                n.rtc.handle_receive(now, from, to, &d);
            }
        }
        for i in 0..self.nodes.len() {
            if self.nodes[i].wake <= now {
                self.nodes[i].rtc.handle_timeout(now);
            }
            self.drain(i);
        }
    }

    fn drain(&mut self, i: usize) {
        let now = self.now;
        loop {
            let n = &mut self.nodes[i];
            match n.rtc.poll_output(now) {
                Output::Timeout(t) => {
                    n.wake = t;
                    break;
                }
                Output::Transmit(_, to, d, _) => {
                    let from = n.addr;
                    if !(self.drop)(from, to, &d) {
                        self.queue
                            .push((now + Duration::from_millis(10), from, to, d));
                    }
                }
                Output::Event(e) => n.events.push(e),
            }
        }
    }

    fn take(&mut self, i: usize) -> Vec<RtcEvent> {
        std::mem::take(&mut self.nodes[i].events)
    }

    fn until(&mut self, what: &str, mut f: impl FnMut(&World) -> bool) {
        let start = self.now;
        while !f(self) {
            self.step();
            assert!(self.now - start < Duration::from_secs(30), "{what}");
        }
    }
}

fn rtp_mode() -> ConfigInner {
    ConfigInner {
        rtp_mode: true,
        ..ConfigInner::default()
    }
}

/// An RTP packet (not RTCP) and its SSRC.
fn rtp_ssrc(d: &[u8]) -> Option<u32> {
    (d.len() >= 12 && d[0] >> 6 == 2 && !(192..=223).contains(&d[1]))
        .then(|| u32::from_be_bytes([d[8], d[9], d[10], d[11]]))
}

const FRAME: usize = 3000;

fn frame(publisher: u8, i: u64) -> Vec<u8> {
    let mut f: Vec<u8> = (0..FRAME as u32).map(|k| (k * 13) as u8).collect();
    f[0] = if i == 0 { 0x10 } else { 0x11 };
    f[1] = i as u8;
    f[2] = publisher;
    f
}

/// A publisher (sending audio and video) into an RTP-mode SFU peer: (publisher, SFU side,
/// audio mid, video mid).
fn publisher(w: &mut World) -> (usize, usize, Mid, Mid) {
    let (p, s, (a, v)) = w.link(
        ConfigInner::default(),
        rtp_mode(),
        |api| {
            (
                api.add_media(MediaKind::Audio, Direction::SendOnly, None, None),
                api.add_media(MediaKind::Video, Direction::SendOnly, None, None),
            )
        },
        |o| o,
    );
    (p, s, a, v)
}

#[derive(Default)]
struct Wire {
    /// Media packets from the SFU to the viewer, and how many were dropped.
    down: u64,
    down_dropped: u64,
    /// RTX packets from the SFU to the viewer.
    down_rtx: u64,
    /// Media packets from the publisher to the SFU, dropped, and RTX.
    up: u64,
    up_dropped: u64,
    up_rtx: u64,
}

#[test]
fn sfu_forwards_rtp_with_loss_on_both_legs() {
    let mut w = World::new();
    let (p, s1, p_audio, p_video) = publisher(&mut w);
    let (p2, s3, a2, v2) = publisher(&mut w);
    assert_eq!((a2, v2), (p_audio, p_video));
    // The viewer, frame mode, receiving what the SFU's peer `s2` sends.
    let (v, s2, (v_audio, v_video)) = w.link(
        ConfigInner::default(),
        ConfigInner::default(),
        |api| {
            (
                api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None),
                api.add_media(MediaKind::Video, Direction::RecvOnly, None, None),
            )
        },
        |o| o,
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });

    // A 10th of the video packets the SFU sends is lost on the way to the viewer, every 13th the
    // publisher sends on the way to the SFU (retransmissions get through).
    let wire = Rc::new(RefCell::new(Wire::default()));
    let line_ssrcs = |n: &Node, mid: Mid| {
        let l = n.rtc.media.iter().find(|l| l.mid == mid).unwrap();
        (l.send.ssrc(), l.send.rtx_ssrc())
    };
    let (down_ssrc, down_rtx) = line_ssrcs(&w.nodes[s2], v_video);
    let (up_ssrc, up_rtx) = line_ssrcs(&w.nodes[p], p_video);
    let (sfu_addr, viewer_addr, pub_addr) = (w.nodes[s2].addr, w.nodes[v].addr, w.nodes[p].addr);
    let wr = wire.clone();
    w.drop = Box::new(move |from, to, d| {
        let mut x = wr.borrow_mut();
        match rtp_ssrc(d) {
            Some(s) if from == sfu_addr && to == viewer_addr && s == down_ssrc => {
                x.down += 1;
                // Not the last packet: a lost tail has nothing after it to show the gap.
                let lose = x.down % 10 == 5;
                x.down_dropped += u64::from(lose);
                lose
            }
            Some(s) if from == sfu_addr && Some(s) == down_rtx => {
                x.down_rtx += 1;
                false
            }
            Some(s) if from == pub_addr && s == up_ssrc => {
                x.up += 1;
                let lose = x.up % 13 == 0;
                x.up_dropped += u64::from(lose);
                lose
            }
            Some(s) if from == pub_addr && Some(s) == up_rtx => {
                x.up_rtx += 1;
                false
            }
            _ => false,
        }
    });

    // The SFU caps the publisher at 400 kbit/s.
    w.nodes[s1].rtc.set_receive_bitrate_cap(Some(400_000));
    let opus = w.nodes[p].rtc.payload_type(p_audio, Codec::Opus).unwrap();
    let vp8 = w.nodes[p].rtc.payload_type(p_video, Codec::Vp8).unwrap();
    let mut got_frames: Vec<Vec<u8>> = Vec::new();
    let mut audio = 0usize;
    let mut sfu_keyframe_requests = 0;
    let mut pub_keyframe_requests = 0;
    let mut rembs = Vec::new();
    const FRAMES: u64 = 100;
    // Publisher 1 sends FRAMES frames, then publisher 2 replaces it (after a pause that lets
    // the first one's retransmissions finish).
    const SWITCH: u64 = FRAMES + 25;
    for i in 0..SWITCH + FRAMES + 200 {
        let now = w.now;
        let (src, src_audio, src_video) = if i < SWITCH {
            (p, p_audio, p_video)
        } else {
            (p2, p_audio, p_video)
        };
        let k = if i < SWITCH { i } else { i - SWITCH };
        if k < FRAMES {
            let t = MediaTime::new(k * 960, Frequency::FORTY_EIGHT_KHZ);
            w.nodes[src]
                .rtc
                .write_media(now, src_audio, None, opus, t, &[0xfc, k as u8, 7])
                .unwrap();
            let t = MediaTime::new(k * 1800, Frequency::NINETY_KHZ);
            w.nodes[src]
                .rtc
                .write_media(now, src_video, None, vp8, t, &frame(src as u8, k))
                .unwrap();
        }
        if i == 20 {
            // The viewer asks for a keyframe.
            assert!(
                w.nodes[v]
                    .rtc
                    .request_keyframe(now, v_video, KeyframeRequestKind::Pli)
            );
        }
        for _ in 0..4 {
            w.step();
            // Forward what the SFU's publisher sides received; only the current publisher's.
            for (side, current) in [(s1, src == p), (s3, src == p2)] {
                for e in w.take(side) {
                    if let (RtcEvent::Rtp(pkt), true) = (e, current) {
                        let mid = match pkt.codec.map(Codec::kind) {
                            Some(MediaKind::Audio) => v_audio,
                            _ => v_video,
                        };
                        assert_eq!(pkt.mid, if mid == v_audio { p_audio } else { p_video });
                        let now = w.now;
                        assert!(w.nodes[s2].rtc.write_rtp(now, mid, None, &pkt).unwrap());
                    }
                }
            }
            w.drain(s2);
            for e in w.take(s2) {
                if let RtcEvent::Keyframe(k) = e {
                    // A viewer's keyframe request goes to the current publisher.
                    assert_eq!(k.mid, v_video);
                    sfu_keyframe_requests += 1;
                    let now = w.now;
                    let side = if src == p { s1 } else { s3 };
                    assert!(w.nodes[side].rtc.request_keyframe(
                        now,
                        p_video,
                        KeyframeRequestKind::Pli
                    ));
                    w.drain(side);
                }
            }
            for e in w.take(src) {
                match e {
                    RtcEvent::Keyframe(_) => pub_keyframe_requests += 1,
                    RtcEvent::Other(Other::RemoteBitrateEstimate { bitrate, ssrcs }) => {
                        rembs.push((bitrate, ssrcs));
                    }
                    _ => {}
                }
            }
            for e in w.take(v) {
                if let RtcEvent::MediaData(d) = e {
                    if d.mid == v_video {
                        got_frames.push(d.data.to_vec());
                    } else {
                        assert_eq!(&d.data[..], &[0xfc, d.data[1], 7]);
                        audio += 1;
                    }
                }
            }
        }
    }
    let x = wire.borrow();
    assert!(
        x.down_dropped > 10 && x.up_dropped > 10,
        "losses: {:?}",
        (x.down_dropped, x.up_dropped)
    );
    // The SFU answered the viewer's NACKs from what it sent, the publisher the SFU's.
    assert!(
        x.down_rtx >= x.down_dropped,
        "SFU retransmissions {} for {}",
        x.down_rtx,
        x.down_dropped
    );
    assert!(
        x.up_rtx >= x.up_dropped,
        "publisher retransmissions {} for {}",
        x.up_rtx,
        x.up_dropped
    );
    // Every frame of both publishers arrives intact, in order, across the switch.
    let want: Vec<Vec<u8>> = (0..FRAMES)
        .map(|k| frame(p as u8, k))
        .chain((0..FRAMES).map(|k| frame(p2 as u8, k)))
        .collect();
    assert_eq!(got_frames.len(), want.len(), "frames");
    assert!(got_frames == want, "frames intact and in order");
    assert!(audio >= (FRAMES as usize * 2) * 95 / 100, "audio {audio}");
    // PLI: viewer -> SFU -> publisher.
    assert!(sfu_keyframe_requests >= 1 && pub_keyframe_requests >= 1);
    // REMB: the cap, once at once and then every second, about both streams.
    assert!(rembs.len() >= 3, "{rembs:?}");
    let (pa, pv) = (line_ssrcs(&w.nodes[p], p_audio).0, up_ssrc);
    for (b, ssrcs) in &rembs {
        assert_eq!(*b, 400_000);
        assert!(ssrcs.contains(&pa) && ssrcs.contains(&pv), "{ssrcs:?}");
    }
}

#[test]
fn forwarded_packets_keep_their_extensions_by_uri_and_are_renumbered() {
    let mut w = World::new();
    // The viewer, in RTP mode, numbers audio level 9 (the SFU's own offer would use 1).
    let (v, s, (v_audio, v_video)) = w.link(
        rtp_mode(),
        ConfigInner::default(),
        |api| {
            (
                api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None),
                api.add_media(MediaKind::Video, Direction::RecvOnly, None, None),
            )
        },
        |o| {
            o.replace(
                "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
                "a=extmap:9 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            )
        },
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });
    let start = w.now;
    let pkt = |ssrc: u32, seq: u64, ts: u32, at: Duration, level: u8| RtpPacket {
        seq_no: seq,
        ssrc,
        pt: Pt::from(111),
        marker: false,
        rtp_time: ts,
        time: MediaTime::new(u64::from(ts), Frequency::FORTY_EIGHT_KHZ),
        received: start + at,
        payload: Arc::from(&[0xfc, level, 1][..]),
        mid: Mid::new("x"),
        rid: None,
        codec: Some(Codec::Opus),
        extensions: ExtensionValues {
            audio_level: Some((true, level)),
            mid: Some("x".into()),
            ..ExtensionValues::default()
        },
    };
    // Source A: 1000, a gap (1001 lost upstream), 1002, then 1001 late; source B from 7.
    let ms = Duration::from_millis;
    let sent = [
        pkt(0xa, 1000, 5000, ms(0), 10),
        pkt(0xa, 1002, 5960, ms(20), 11),
        pkt(0xa, 1001, 5480, ms(25), 12),
        pkt(0xa, 900, 4000, ms(25), 13), // older than the numbering: dropped
        pkt(0xb, 7, 100, ms(120), 14),
        pkt(0xb, 8, 580, ms(130), 15),
        pkt(0xa, 1003, 6440, ms(140), 16), // the old source again: a switch back
    ];
    let mut got = Vec::new();
    for p in &sent {
        let now = w.now;
        assert!(w.nodes[s].rtc.write_rtp(now, v_audio, None, p).unwrap());
        for _ in 0..4 {
            w.step();
        }
        for e in w.take(v) {
            if let RtcEvent::Rtp(r) = e {
                got.push(r);
            }
        }
    }
    for _ in 0..10 {
        w.step();
    }
    for e in w.take(v) {
        if let RtcEvent::Rtp(r) = e {
            got.push(r);
        }
    }
    let line = w.nodes[s]
        .rtc
        .media
        .iter()
        .find(|l| l.mid == v_audio)
        .unwrap();
    let ssrc = line.send.ssrc();
    let opus = w.nodes[v].rtc.payload_type(v_audio, Codec::Opus).unwrap();
    let levels: Vec<u8> = got.iter().map(|r| r.payload[1]).collect();
    assert_eq!(levels, [10, 11, 12, 14, 15, 16]);
    for r in &got {
        assert_eq!(
            (r.ssrc, r.pt, r.mid, r.codec),
            (ssrc, opus, v_audio, Some(Codec::Opus))
        );
        assert_eq!(
            r.extensions.audio_level,
            Some((true, r.payload[1])),
            "by URI"
        );
    }
    let s0 = got[0].seq_no;
    let seqs: Vec<u64> = got.iter().map(|r| r.seq_no - s0).collect();
    // The gap stays and fills; each new source follows the last number sent.
    assert_eq!(seqs, [0, 2, 1, 3, 4, 5]);
    let t0 = got[0].rtp_time;
    let ts: Vec<u32> = got.iter().map(|r| r.rtp_time.wrapping_sub(t0)).collect();
    // Timestamps: shifted within a source; across a switch, by the time between arrivals
    // (100 ms = 4800 ticks after the last packet sent, which came at 20 ms; then 10 ms).
    assert_eq!(&ts[..3], &[0, 960, 480]);
    assert_eq!(ts[3], 960 + 4800);
    assert_eq!(ts[4], 960 + 4800 + 480);
    assert_eq!(ts[5], ts[4] + 480);
    // A video packet of a codec the line did not negotiate is refused.
    let mut h = pkt(0xc, 1, 1, ms(0), 1);
    h.codec = Some(Codec::H265);
    let now = w.now;
    assert!(w.nodes[s].rtc.write_rtp(now, v_video, None, &h).is_err());
}

#[test]
fn renumbering_skips_numbers_the_stream_took() {
    use forward::{MAX_LATE, Renumber};
    let t = Instant::now();
    let mut r = Renumber::default();
    let mut next = 100u16;
    let base = 100_000u64;
    let out = |r: &mut Renumber, seq: u64, next: &mut u16| {
        let (s, _) = r.map(1, base + seq, 0, t, *next, 90_000).unwrap();
        if s.wrapping_sub(*next) < 0x8000 {
            *next = s.wrapping_add(1);
        }
        s
    };
    assert_eq!(out(&mut r, 50, &mut next), 100);
    assert_eq!(out(&mut r, 51, &mut next), 101);
    // Two numbers taken by samples written in between.
    next += 2;
    assert_eq!(out(&mut r, 52, &mut next), 104);
    // A late packet of the earlier numbering is dropped.
    assert!(r.map(1, base + 49, 0, t, next, 90_000).is_none());
    assert_eq!(out(&mut r, 54, &mut next), 106, "gaps kept");
    assert_eq!(out(&mut r, 53, &mut next), 105, "late ones fill them");
    // Far behind the newest: dropped.
    assert_eq!(
        out(&mut r, 54 + MAX_LATE + 1, &mut next),
        106 + MAX_LATE as u16 + 1
    );
    assert!(r.map(1, base + 54, 0, t, next, 90_000).is_none());
}

fn consent_world(timeouts: Option<(Duration, Duration)>) -> (World, usize, usize) {
    let mut w = World::new();
    // Both sides: the full agent then checks consent often enough for the timeouts.
    let cfg = || ConfigInner {
        ice_timeouts: timeouts,
        ..ConfigInner::default()
    };
    let (a, b, ()) = w.link(
        cfg(),
        cfg(),
        |api| {
            api.add_channel("c");
        },
        |o| o,
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });
    w.take(b);
    (w, a, b)
}

fn ice_states(
    w: &mut World,
    b: usize,
    at: &mut Vec<(IceConnectionState, Duration)>,
    from: Instant,
) {
    for e in w.take(b) {
        if let RtcEvent::IceState(s) = e {
            at.push((s, w.now - from));
        }
    }
}

#[test]
fn consent_lost_is_disconnected_then_failed() {
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(5))));
    assert!(w.nodes[b].rtc.fails_after_disconnect());
    // The remote goes silent.
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    while w.now - cut < Duration::from_secs(8) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(
        kinds,
        [IceConnectionState::Disconnected, IceConnectionState::Failed]
    );
    // Disconnected 2 s after the last check (which came up to the full agent's interval
    // before the cut), Failed 3 s after that.
    assert!(states[0].1 <= Duration::from_secs(2) + TICK, "{states:?}");
    let wait = states[1].1.saturating_sub(states[0].1);
    assert!(
        wait >= Duration::from_secs(3) && wait <= Duration::from_secs(3) + TICK,
        "{states:?}"
    );
}

#[test]
fn consent_back_before_failed() {
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(20))));
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    w.until("disconnected", |w| {
        w.nodes[b]
            .events
            .iter()
            .any(|e| matches!(e, RtcEvent::IceState(IceConnectionState::Disconnected)))
    });
    ice_states(&mut w, b, &mut states, cut);
    w.drop = Box::new(|_, _, _| false);
    while w.now - cut < Duration::from_secs(25) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(kinds[0], IceConnectionState::Disconnected);
    assert!(
        kinds[1..].iter().all(|k| matches!(
            k,
            IceConnectionState::Connected | IceConnectionState::Completed
        )),
        "{kinds:?}"
    );
    assert!(kinds.len() >= 2);
}

#[test]
fn consent_without_failed_timeout_is_disconnected_only() {
    // A failed timeout not past the disconnected one: Disconnected, as without the setting.
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(2))));
    assert!(!w.nodes[b].rtc.fails_after_disconnect());
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    while w.now - cut < Duration::from_secs(6) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(kinds, [IceConnectionState::Disconnected]);
}

#[test]
fn receive_cap_told_as_remb() {
    let mut w = World::new();
    let (p, s, (audio, video)) = w.link(
        ConfigInner::default(),
        ConfigInner::default(),
        |api| {
            (
                api.add_media(MediaKind::Audio, Direction::SendOnly, None, None),
                api.add_media(MediaKind::Video, Direction::SendOnly, None, None),
            )
        },
        |o| o,
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });
    let ssrc = |mid: Mid| {
        w.nodes[p]
            .rtc
            .media
            .iter()
            .find(|l| l.mid == mid)
            .unwrap()
            .send
            .ssrc()
    };
    let (sa, sv) = (ssrc(audio), ssrc(video));
    let opus = w.nodes[p].rtc.payload_type(audio, Codec::Opus).unwrap();
    let vp8 = w.nodes[p].rtc.payload_type(video, Codec::Vp8).unwrap();
    let mut rembs: Vec<(Duration, u64, Vec<u32>)> = Vec::new();
    let start = w.now;
    let run = |w: &mut World, secs: u64, rembs: &mut Vec<(Duration, u64, Vec<u32>)>| {
        let until = w.now + Duration::from_secs(secs);
        let mut i = 0u64;
        while w.now < until {
            let now = w.now;
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            w.nodes[p]
                .rtc
                .write_media(now, audio, None, opus, t, &[0xfc, 1, 2])
                .unwrap();
            let t = MediaTime::new(i * 1800, Frequency::NINETY_KHZ);
            w.nodes[p]
                .rtc
                .write_media(now, video, None, vp8, t, &[0x10, 0, 0, 1])
                .unwrap();
            i += 1;
            for _ in 0..4 {
                w.step();
            }
            for e in w.take(p) {
                if let RtcEvent::Other(Other::RemoteBitrateEstimate { bitrate, ssrcs }) = e {
                    rembs.push((w.now - start, bitrate, ssrcs));
                }
            }
        }
    };
    run(&mut w, 1, &mut rembs);
    assert!(rembs.is_empty(), "no cap, no REMB: {rembs:?}");
    // The cap goes out at once, then once a second, about both streams received.
    w.nodes[s].rtc.set_receive_bitrate_cap(Some(250_000));
    let set = w.now - start;
    run(&mut w, 3, &mut rembs);
    assert!(rembs.len() >= 3, "{rembs:?}");
    assert!(
        rembs[0].0.saturating_sub(set) <= Duration::from_millis(30),
        "at once: {rembs:?}"
    );
    for (_, b, ssrcs) in &rembs {
        assert_eq!(*b, 250_000);
        assert_eq!(ssrcs, &{
            let mut v = vec![sa, sv];
            v.sort_unstable();
            v
        });
    }
    // None: no more.
    w.nodes[s].rtc.set_receive_bitrate_cap(None);
    rembs.clear();
    run(&mut w, 2, &mut rembs);
    assert!(
        rembs.len() <= 1,
        "at most one already on its way: {rembs:?}"
    );
}
