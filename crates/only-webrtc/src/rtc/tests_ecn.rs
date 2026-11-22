//! In simulated time (ADR-077): ECN-capable RTP over paths that keep, clear, re-mark or
//! CE-mark the codepoint; latching media without ICE behind a NAT (first packet, rebinding,
//! forged and replayed packets); congestion control across the transports of a session
//! without BUNDLE, with shared and per-transport numbering and with RFC 8888.

#![allow(clippy::field_reassign_with_default)]

use std::collections::HashSet;

use super::*;
use crate::SdpChanges;
use crate::types::{BundlePolicy, EcnMarking, Latching};

/// What the path does to ECN-capable packets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Path {
    Keep,
    /// Clears the codepoint (Not-ECT).
    Bleach,
    /// ECT(1) becomes ECT(0).
    Remark,
    /// One ECN-capable packet in `n` arrives CE.
    Ce(u64),
    /// ECN-capable packets that queue at the bottleneck for longer than this (and than two
    /// full-sized packets take) arrive CE (an L4S queue's step marking, RFC 9332).
    Step(Duration),
}

/// A datagram in flight: arrival, from, to, payload, codepoint.
type Flight = (Instant, SocketAddr, SocketAddr, Vec<u8>, u8);

struct Net {
    rng: u64,
    path: Path,
    queue: Vec<Flight>,
    /// (from, to, first byte, codepoint, RTCP) of every datagram sent, after NAT.
    log: Vec<(SocketAddr, SocketAddr, u8, u8, bool)>,
    /// NAT: (inside, outside) mappings. Datagrams from an inside address leave from its
    /// outside one; the outside one reaches the inside one; nothing from outside reaches an
    /// inside address directly.
    nat: Vec<(SocketAddr, SocketAddr)>,
    /// Datagrams that left a NAT'd side (for replays).
    captured: Vec<(SocketAddr, Vec<u8>)>,
    /// A bottleneck shared by everything sent: bytes per second, and when it is free
    /// again; datagrams queued for more than 300 ms are dropped.
    cap: Option<f64>,
    free: Option<Instant>,
    /// Queueing delay of every datagram through the bottleneck.
    queued: Vec<Duration>,
}

impl Net {
    fn new(path: Path) -> Net {
        Net {
            rng: 0x9e37_79b9_7f4a_7c15,
            path,
            queue: Vec::new(),
            log: Vec::new(),
            nat: Vec::new(),
            captured: Vec::new(),
            cap: None,
            free: None,
            queued: Vec::new(),
        }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn send(&mut self, now: Instant, from: SocketAddr, to: SocketAddr, d: Vec<u8>, ecn: u8) {
        let mut from = from;
        if let Some((_, out)) = self.nat.iter().find(|(i, _)| *i == from) {
            from = *out;
            self.captured.push((from, d.clone()));
        }
        let mut to = to;
        if self.nat.iter().any(|(i, _)| *i == to) {
            return; // a private address: unreachable from outside
        }
        if let Some((i, _)) = self.nat.iter().find(|(_, o)| *o == to) {
            to = *i;
        }
        let first = d.first().copied().unwrap_or(0);
        let rtcp = (128..=191).contains(&first) && only_rtp::is_rtcp(&d);
        self.log.push((from, to, first, ecn, rtcp));
        let mut ecn = match (self.path, ecn) {
            (_, 0) | (Path::Keep | Path::Step(_), _) => ecn,
            (Path::Bleach, _) => 0,
            (Path::Remark, 1) => 2,
            (Path::Remark, e) => e,
            (Path::Ce(n), e) => {
                if self.rand() % n == 0 {
                    3
                } else {
                    e
                }
            }
        };
        let mut at = now + Duration::from_millis(10 + self.rand() % 4);
        if let Some(cap) = self.cap {
            let start = self.free.map_or(now, |f| f.max(now));
            if start.saturating_duration_since(now) > Duration::from_millis(300) {
                return;
            }
            let done = start + Duration::from_secs_f64((d.len() + 28) as f64 / cap);
            self.free = Some(done);
            let q = start.saturating_duration_since(now);
            self.queued.push(q);
            if let Path::Step(t) = self.path {
                // At least two full-sized packets queued, as DualPI2 asks at low rates.
                let two = Duration::from_secs_f64(2.0 * 1228.0 / cap);
                if ecn != 0 && q > t.max(two) {
                    ecn = 3;
                }
            }
            at = done + Duration::from_millis(10);
        }
        self.queue.push((at, from, to, d, ecn));
    }
}

struct Side {
    rtc: Rtc,
    addrs: Vec<SocketAddr>,
    events: Vec<RtcEvent>,
    wake: Instant,
    /// Acts as the endpoint's hub: datagrams from unknown sources only reach the peer to be
    /// tried for latching (known: sent to, or reported by the peer).
    hub: bool,
    known: HashSet<SocketAddr>,
}

fn side(rtc: Rtc, addrs: Vec<SocketAddr>, now: Instant) -> Side {
    Side {
        rtc,
        addrs,
        events: Vec::new(),
        wake: now,
        hub: false,
        known: HashSet::new(),
    }
}

fn drain(s: &mut Side, now: Instant, net: &mut Net) {
    loop {
        match s.rtc.poll_output(now) {
            Output::Timeout(t) => {
                s.wake = t;
                break;
            }
            Output::Transmit(from, to, d, ecn) => {
                assert!(s.addrs.contains(&from), "sent from {from}");
                s.known.insert(to);
                net.send(now, from, to, d, ecn);
            }
            Output::Event(e) => s.events.push(e),
        }
    }
    for a in s.rtc.take_plain_remotes() {
        s.known.insert(a);
    }
    for a in s.rtc.take_gone_remotes() {
        s.known.remove(&a);
    }
}

fn deliver(s: &mut Side, now: Instant, from: SocketAddr, to: SocketAddr, d: &[u8], ecn: u8) {
    s.rtc.set_rx_ecn(ecn);
    if s.hub && !s.known.contains(&from) {
        s.rtc.latch_receive(now, from, to, d);
    } else {
        s.rtc.handle_receive(now, from, to, d);
    }
}

fn step(a: &mut Side, b: &mut Side, now: Instant, net: &mut Net) {
    let (due, keep): (Vec<_>, Vec<_>) = net.queue.drain(..).partition(|x| x.0 <= now);
    net.queue = keep;
    for (_, from, to, d, ecn) in due {
        if a.addrs.contains(&to) {
            deliver(a, now, from, to, &d, ecn);
        } else if b.addrs.contains(&to) {
            deliver(b, now, from, to, &d, ecn);
        }
    }
    for s in [&mut *a, &mut *b] {
        if s.wake <= now {
            s.rtc.handle_timeout(now);
        }
        drain(s, now, net);
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn peer(cfg: ConfigInner, c1: &[&str], c2: &[&str], now: Instant) -> Side {
    let mut r = Rtc::new(cfg, false, now).unwrap();
    let mut addrs = Vec::new();
    for c in c1 {
        addrs.push(addr(c));
        r.add_local_candidate(IceCandidate::host(addr(c)));
    }
    for c in c2 {
        addrs.push(addr(c));
        r.add_local_candidate(IceCandidate::host(addr(c)).with_component(2));
    }
    side(r, addrs, now)
}

/// Audio (and video) from `from` to `to` for `n` 20 ms ticks, both directions when `both`.
fn media(
    a: &mut Side,
    b: &mut Side,
    net: &mut Net,
    now: Instant,
    mids: (Option<Mid>, Option<Mid>),
    n: u64,
    both: bool,
) -> Instant {
    media_sized(a, b, net, now, mids, n, both, 2500)
}

/// [`media`] with video frames of `size` bytes.
#[allow(clippy::too_many_arguments)]
fn media_sized(
    a: &mut Side,
    b: &mut Side,
    net: &mut Net,
    mut now: Instant,
    mids: (Option<Mid>, Option<Mid>),
    n: u64,
    both: bool,
    size: usize,
) -> Instant {
    let frame: Vec<u8> = (0..size as u32).map(|i| (i * 7) as u8).collect();
    for i in 0..n {
        let sides: Vec<bool> = if both { vec![true, false] } else { vec![true] };
        for first in sides {
            let s = if first { &mut *a } else { &mut *b };
            if let Some(m) = mids.0 {
                if let Some(pt) = s.rtc.payload_type(m, Codec::Opus) {
                    let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
                    let _ = s.rtc.write_media(now, m, None, pt, t, &[0xfc, i as u8, 1]);
                }
            }
            if let Some(m) = mids.1 {
                if let Some(pt) = s.rtc.payload_type(m, Codec::Vp8) {
                    let t = MediaTime::new(i * 1800, Frequency::NINETY_KHZ);
                    let mut f = frame.clone();
                    f[0] = if i == 0 { 0x10 } else { 0x11 };
                    let _ = s.rtc.write_media(now, m, None, pt, t, &f);
                }
            }
        }
        for _ in 0..4 {
            now += Duration::from_millis(5);
            step(a, b, now, net);
        }
    }
    now
}

fn media_count(s: &Side, mid: Mid) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::MediaData(d) if d.mid == mid))
        .count()
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

// ---- ECN ----

fn ecn_cfg(marking: EcnMarking, ccfb: bool) -> ConfigInner {
    let mut c = ConfigInner::default();
    c.ccfb = ccfb;
    c.bwe = Some(1_000_000);
    c.ecn = marking;
    c
}

/// `a` (marking `marking`) sends audio and video to `b` over `path` for 4 s; returns the
/// sides and the network.
fn ecn_run(marking: EcnMarking, ccfb: bool, path: Path) -> (Side, Side, Net) {
    ecn_run_with(marking, EcnMarking::Off, ccfb, path).0
}

/// [`ecn_run`] with `b` configured to mark `b_marking` (RFC 6679 needs both sides to opt
/// in); also returns the offer and the answer.
fn ecn_run_with(
    marking: EcnMarking,
    b_marking: EcnMarking,
    ccfb: bool,
    path: Path,
) -> ((Side, Side, Net), String, String) {
    ecn_run_on(marking, b_marking, ccfb, path, false)
}

/// [`ecn_run_with`]; `tcp`: `a`'s candidate is one whose paths carry no codepoint (as the
/// endpoint says of TURN allocations over TCP or TLS).
fn ecn_run_on(
    marking: EcnMarking,
    b_marking: EcnMarking,
    ccfb: bool,
    path: Path,
    tcp: bool,
) -> ((Side, Side, Net), String, String) {
    let now = Instant::now();
    let mut a = peer(ecn_cfg(marking, ccfb), &["10.0.0.1:1000"], &[], now);
    if tcp {
        a.rtc.set_no_ecn(addr("10.0.0.1:1000"));
    }
    let mut b = peer(ecn_cfg(b_marking, ccfb), &["10.0.0.2:2000"], &[], now);
    let mut ch = a.rtc.changes();
    let (audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(path);
    let now = connect(&mut a, &mut b, &mut net, now);
    media(
        &mut a,
        &mut b,
        &mut net,
        now,
        (Some(audio), Some(video)),
        200,
        false,
    );
    assert!(media_count(&b, video) > 150, "{}", media_count(&b, video));
    ((a, b, net), offer, answer)
}

/// Codepoints of RTP (not RTCP) packets `a` sent, in order.
fn rtp_marks(net: &Net, from: SocketAddr) -> Vec<u8> {
    net.log
        .iter()
        .filter(|l| l.0 == from && (128..=191).contains(&l.2) && !l.4)
        .map(|l| l.3)
        .collect()
}

#[test]
fn ecn_marks_rtp_once_the_path_delivers_them() {
    let (a, b, net) = ecn_run(EcnMarking::Ect1, true, Path::Keep);
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    // Never RTCP, STUN or DTLS.
    for (from, _, first, ecn, rtcp) in &net.log {
        if *ecn != 0 {
            assert_eq!(*from, addr("10.0.0.1:1000"));
            assert!((128..=191).contains(first) && !rtcp, "marked {first}");
            assert_eq!(*ecn, 1);
        }
    }
    assert!(net.log.iter().any(|l| l.4 && l.0 == addr("10.0.0.1:1000")));
    let marks = rtp_marks(&net, addr("10.0.0.1:1000"));
    // Initiation marks a fraction.
    let head = &marks[..40];
    let n = head.iter().filter(|m| **m == 1).count();
    assert!((8..=12).contains(&n), "{head:?}");
    // Then every RTP packet.
    let tail = &marks[marks.len() - 200..];
    assert!(tail.iter().all(|m| *m == 1), "{tail:?}");
    assert!(b.rtc.stats.ecn_ect_received > 300);
    assert_eq!(b.rtc.stats.ecn_ce_received, 0);
    // b marks nothing (not asked to).
    assert!(
        rtp_marks(&net, addr("10.0.0.2:2000"))
            .iter()
            .all(|m| *m == 0)
    );
}

#[test]
fn ecn_falls_back_when_the_path_clears_or_changes_marks() {
    for path in [Path::Bleach, Path::Remark] {
        let (a, _, net) = ecn_run(EcnMarking::Ect1, true, path);
        assert_eq!(a.rtc.ecn.phase, ecn::Phase::Failed);
        assert_eq!(a.rtc.ecn.failures, 1);
        let marks = rtp_marks(&net, addr("10.0.0.1:1000"));
        let marked = marks.iter().filter(|m| **m != 0).count();
        // Probes until the first report (one RTP packet in four), none after.
        assert!((1..=40).contains(&marked), "{marked}");
        assert!(marks[marks.len() / 2..].iter().all(|m| *m == 0));
    }
}

#[test]
fn ce_marks_reach_the_estimator() {
    let (a, b, _) = ecn_run(EcnMarking::Ect0, true, Path::Ce(10));
    // CE is congestion, not a failure.
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    assert!(a.rtc.ecn.ce > 10, "{}", a.rtc.ecn.ce);
    let (_, ce_reported) = a.rtc.bwe.as_ref().unwrap().ecn_counts();
    assert!(ce_reported > 10, "{ce_reported}");
    assert!(b.rtc.stats.ecn_ce_received > 10);
    // ECT(0) is what goes out.
    assert!(a.rtc.ecn.marked_sent > 300);
}

#[test]
fn no_ecn_without_rfc8888_or_when_off() {
    for (marking, ccfb) in [(EcnMarking::Ect1, false), (EcnMarking::Off, true)] {
        let (a, _, net) = ecn_run(marking, ccfb, Path::Keep);
        assert_eq!(a.rtc.ecn.phase, ecn::Phase::Off);
        assert!(net.log.iter().all(|l| l.3 == 0));
    }
}

// ---- latching ----

fn sdes_plain(latching: Latching, mux: bool) -> ConfigInner {
    let mut c = ConfigInner::default();
    c.sdes = true;
    c.ice = false;
    c.latching = latching;
    if !mux {
        c.rtcp_mux = RtcpMuxPolicy::Off;
    }
    c
}

const GW: &str = "10.0.0.1:4000";
const GW_RTCP: &str = "10.0.0.1:4001";
const PHONE: &str = "192.168.1.10:5000";
const PHONE_RTCP: &str = "192.168.1.10:5001";
const NAT: &str = "203.0.113.9:40000";
const NAT_RTCP: &str = "203.0.113.9:40001";

/// A gateway `a` (latching as `latching`) offers audio without ICE to a phone `b` behind a
/// NAT whose description names its private address. Returns the sides, the audio mid and
/// the time once negotiated.
fn sip_call(latching: Latching, mux: bool) -> (Side, Side, Net, Mid, Instant) {
    let now = Instant::now();
    let (c1a, c2a): (&[&str], &[&str]) = if mux {
        (&[GW], &[])
    } else {
        (&[GW], &[GW_RTCP])
    };
    let (c1b, c2b): (&[&str], &[&str]) = if mux {
        (&[PHONE], &[])
    } else {
        (&[PHONE], &[PHONE_RTCP])
    };
    let mut a = peer(sdes_plain(latching, mux), c1a, c2a, now);
    let mut b = peer(sdes_plain(Latching::Off, mux), c1b, c2b, now);
    a.hub = true;
    let mut ch = a.rtc.changes();
    let audio = SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(answer.contains("c=IN IP4 192.168.1.10"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(Path::Keep);
    net.nat.push((addr(PHONE), addr(NAT)));
    net.nat.push((addr(PHONE_RTCP), addr(NAT_RTCP)));
    drain(&mut a, now, &mut net);
    drain(&mut b, now, &mut net);
    (a, b, net, audio, now)
}

#[test]
fn without_latching_a_natted_phone_is_unreachable() {
    let (mut a, mut b, mut net, audio, now) = sip_call(Latching::Off, true);
    media(&mut a, &mut b, &mut net, now, (Some(audio), None), 50, true);
    assert_eq!(media_count(&a, audio), 0);
    assert_eq!(media_count(&b, audio), 0);
    assert_eq!(a.rtc.latch_moves(), 0);
}

#[test]
fn latching_follows_the_first_authenticated_packet() {
    for mux in [true, false] {
        let (mut a, mut b, mut net, audio, now) = sip_call(Latching::Once, mux);
        // The phone speaks first (comedia); then both.
        let now = media(&mut a, &mut b, &mut net, now, (Some(audio), None), 5, false);
        let now = media(&mut b, &mut a, &mut net, now, (Some(audio), None), 50, true);
        assert!(media_count(&a, audio) >= 50, "mux {mux}");
        assert!(
            media_count(&b, audio) >= 45,
            "mux {mux}: {}",
            media_count(&b, audio)
        );
        assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr(NAT));
        // RTP to the NAT's mapping; without rtcp-mux RTCP latched on its own.
        let srtp: Vec<_> = net
            .log
            .iter()
            .filter(|l| l.0 == addr(GW) && l.2 >= 128 && !l.4)
            .map(|l| l.1)
            .collect();
        assert!(srtp.contains(&addr(PHONE)));
        if mux {
            assert_eq!(a.rtc.latch_moves(), 1);
        } else {
            let _ = media(
                &mut a,
                &mut b,
                &mut net,
                now,
                (Some(audio), None),
                300,
                true,
            );
            assert_eq!(a.rtc.ice.send_pair_of(2).unwrap().1, addr(NAT_RTCP));
            assert_eq!(a.rtc.latch_moves(), 2);
        }
        // Once latched, the endpoint stops offering unknown sources.
        assert!(!a.rtc.latch_wanted());
    }
}

#[test]
fn latching_ignores_forged_and_replayed_packets() {
    let (mut a, mut b, mut net, audio, now) = sip_call(Latching::Rebind(Duration::ZERO), true);
    let now = media(&mut b, &mut a, &mut net, now, (Some(audio), None), 20, true);
    assert_eq!(a.rtc.latch_moves(), 1);
    let evil = addr("198.51.100.7:1234");
    // A forged RTP packet (no valid tag).
    let mut forged = vec![0x80, 0x6f, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4];
    forged.extend_from_slice(&[0u8; 40]);
    assert!(!a.rtc.latch_receive(now, evil, addr(GW), &forged));
    // A replayed copy of a packet the phone sent (authentic, already received).
    let (_, old) = net
        .captured
        .iter()
        .rev()
        .find(|(_, d)| !only_rtp::is_rtcp(d) && d[0] >= 128)
        .cloned()
        .unwrap();
    assert!(!a.rtc.latch_receive(now, evil, addr(GW), &old));
    assert_eq!(a.rtc.latch_moves(), 1);
    assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr(NAT));
}

#[test]
fn rebinding_moves_only_when_allowed() {
    for (latching, moves) in [
        (Latching::Once, 1),
        (Latching::Rebind(Duration::from_millis(500)), 2),
        (Latching::Rebind(Duration::ZERO), 2),
    ] {
        let (mut a, mut b, mut net, audio, now) = sip_call(latching, true);
        let now = media(&mut b, &mut a, &mut net, now, (Some(audio), None), 20, true);
        // The NAT rebinds the phone to another port.
        net.nat[0].1 = addr("203.0.113.9:40007");
        let before = media_count(&b, audio);
        let _ = media(
            &mut b,
            &mut a,
            &mut net,
            now,
            (Some(audio), None),
            100,
            true,
        );
        assert_eq!(a.rtc.latch_moves(), moves, "{latching:?}");
        let got = media_count(&b, audio) - before;
        if moves == 2 {
            assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr("203.0.113.9:40007"));
            assert!(got > 60, "{latching:?}: {got}");
        } else {
            assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr(NAT));
            assert!(got < 5, "{got}");
        }
    }
}

// ---- congestion control without BUNDLE ----

fn split_peer(cfg: ConfigInner, primary: &str, others: &[&str], now: Instant) -> Side {
    let mut s = peer(cfg, &[primary], &[], now);
    for (k, a) in others.iter().enumerate() {
        s.rtc
            .add_transport_candidate(k + 1, IceCandidate::host(addr(a)));
        s.addrs.push(addr(a));
    }
    s
}

/// Audio and video both ways without BUNDLE, estimator on (`ccfb`: RFC 8888); `force_a`
/// makes `a` number transport-wide sequence numbers per transport from the start.
fn unbundled_run(ccfb: bool, force_a: bool, ecn: EcnMarking) -> (Side, Side, Net, Mid, Mid) {
    let now = Instant::now();
    let mut ca = ecn_cfg(ecn, ccfb);
    ca.bundle = BundlePolicy::Disabled;
    let mut a = split_peer(ca, "10.0.0.1:1000", &["10.0.0.1:1001"], now);
    let mut b = split_peer(
        ecn_cfg(EcnMarking::Off, ccfb),
        "10.0.0.2:2000",
        &["10.0.0.2:2001"],
        now,
    );
    let mut ch = a.rtc.changes();
    let (audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    assert!(!offer.contains("a=group:BUNDLE"));
    assert!(offer.contains(if ccfb { "ack ccfb" } else { "transport-cc" }));
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    a.rtc.accept_answer(now, &answer).unwrap();
    assert_eq!(a.rtc.ccfb, ccfb);
    if force_a {
        a.rtc.xt.cc.spaces = cc::Spaces::PerTransport;
    }
    let mut net = Net::new(Path::Keep);
    let now = connect(&mut a, &mut b, &mut net, now);
    assert!(a.rtc.unbundled() && b.rtc.unbundled());
    media(
        &mut a,
        &mut b,
        &mut net,
        now,
        (Some(audio), Some(video)),
        200,
        true,
    );
    for (s, n) in [(&a, "a"), (&b, "b")] {
        assert!(
            media_count(s, audio) > 180,
            "{n}: {}",
            media_count(s, audio)
        );
        assert!(
            media_count(s, video) > 150,
            "{n}: {}",
            media_count(s, video)
        );
        // Feedback of both transports reached the one estimator.
        let bwe = s.rtc.bwe.as_ref().unwrap();
        assert!(bwe.acknowledged_bitrate().is_some(), "{n}");
    }
    // Video RTP on the video transport's addresses only, audio on the primary's.
    let video_paths: HashSet<(SocketAddr, SocketAddr)> = net
        .log
        .iter()
        .filter(|l| l.2 >= 128 && l.0.port() % 1000 == 1)
        .map(|l| (l.0, l.1))
        .collect();
    assert!(
        video_paths
            .iter()
            .all(|(f, t)| t.port() % 1000 == 1 && f.port() % 1000 == 1)
    );
    (a, b, net, audio, video)
}

#[test]
fn unbundled_transport_cc_shared_numbering() {
    let (a, b, _, _, _) = unbundled_run(false, false, EcnMarking::Off);
    // Each side numbers in one space, which the other recognises.
    assert_eq!(a.rtc.xt.cc.spaces, cc::Spaces::Shared);
    assert_eq!(b.rtc.xt.cc.spaces, cc::Spaces::Shared);
}

#[test]
fn unbundled_transport_cc_per_transport_numbering() {
    let (mut a, b, _, _, _) = unbundled_run(false, true, EcnMarking::Off);
    // b reads a's numbering as per transport and numbers its own that way too.
    assert_eq!(b.rtc.xt.cc.spaces, cc::Spaces::PerTransport);
    assert_eq!(a.rtc.xt.cc.spaces, cc::Spaces::PerTransport);
    // Each transport sent with its own counter.
    assert!(a.rtc.twcc_tx.next_seq() > 100);
    assert!(a.rtc.xt.tps[0].1.twcc_tx_next() > 100);
}

#[test]
fn unbundled_rfc8888_with_ecn_per_path() {
    let (a, b, _, _, _) = unbundled_run(true, false, EcnMarking::Ect1);
    assert!(a.rtc.ccfb && b.rtc.ccfb);
    // Both transports' paths validated on their own.
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    assert_eq!(a.rtc.xt.tps[0].1.ecn.phase, ecn::Phase::Capable);
    assert!(b.rtc.stats.ecn_ect_received > 300);
}

/// The estimate `a` ends with after 8 s of audio and video (an encoder following the
/// estimate) through an 800 kbps bottleneck: bundled, or without BUNDLE with shared or
/// per-transport numbering.
fn bottleneck_estimate(bundle: bool, per_transport: bool) -> u64 {
    let now = Instant::now();
    let mut ca = ecn_cfg(EcnMarking::Off, false);
    ca.bwe = Some(300_000);
    if !bundle {
        ca.bundle = BundlePolicy::Disabled;
    }
    let mut a = split_peer(ca, "10.0.0.1:1000", &["10.0.0.1:1001"], now);
    let mut cb = ecn_cfg(EcnMarking::Off, false);
    cb.bwe = Some(300_000);
    let mut b = split_peer(cb, "10.0.0.2:2000", &["10.0.0.2:2001"], now);
    let mut ch = a.rtc.changes();
    let (audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    a.rtc.accept_answer(now, &answer).unwrap();
    if per_transport {
        a.rtc.xt.cc.spaces = cc::Spaces::PerTransport;
        b.rtc.xt.cc.spaces = cc::Spaces::PerTransport;
    }
    let mut net = Net::new(Path::Keep);
    let now = connect(&mut a, &mut b, &mut net, now);
    assert_eq!(a.rtc.unbundled(), !bundle);
    net.cap = Some(800_000.0 / 8.0);
    // The encoder follows the estimate (video at 80 % of it), as applications do.
    let mut now = now;
    let mut size = 2500;
    for _ in 0..40 {
        now = media_sized(
            &mut a,
            &mut b,
            &mut net,
            now,
            (Some(audio), Some(video)),
            10,
            false,
            size,
        );
        let est = a.rtc.bwe.as_ref().unwrap().estimate();
        size = ((est as f64 * 0.8 / 8.0 / 50.0) as usize).clamp(200, 20_000);
    }
    a.rtc.bwe.as_ref().unwrap().estimate()
}

#[test]
fn one_estimate_across_transports_follows_a_bottleneck() {
    let bundled = bottleneck_estimate(true, false);
    let shared = bottleneck_estimate(false, false);
    let split = bottleneck_estimate(false, true);
    for (n, e) in [
        ("bundled", bundled),
        ("shared", shared),
        ("per-transport", split),
    ] {
        assert!((400_000..=1_200_000).contains(&e), "{n}: {e}");
    }
    for e in [shared, split] {
        let r = e as f64 / bundled as f64;
        assert!((0.6..=1.4).contains(&r), "{bundled} {shared} {split}");
    }
}

// ---- scalable (L4S) response ----

const L4S_CAP: f64 = 6_000_000.0;

/// `a` sends audio and video (an encoder following the estimate) through a 6 Mbps
/// bottleneck that CE-marks ECN-capable packets queued for over 1 ms, marking `marking`:
/// the rate received and the mean queueing delay over the second half.
fn l4s_run(marking: EcnMarking) -> (Side, u64, Duration) {
    let now = Instant::now();
    let mut ca = ecn_cfg(marking, true);
    ca.bwe = Some(3_000_000);
    let mut a = peer(ca, &["10.0.0.1:1000"], &[], now);
    let mut b = peer(ecn_cfg(EcnMarking::Off, true), &["10.0.0.2:2000"], &[], now);
    let mut ch = a.rtc.changes();
    let (audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(Path::Step(Duration::from_millis(1)));
    let mut now = connect(&mut a, &mut b, &mut net, now);
    net.cap = Some(L4S_CAP / 8.0);
    let mut size = 2500;
    let (mut half, mut rx0, mut t0) = (0, 0, now);
    for i in 0..60 {
        if i == 30 {
            half = net.queued.len();
            rx0 = b.rtc.stats.bytes_received;
            t0 = now;
        }
        now = media_sized(
            &mut a,
            &mut b,
            &mut net,
            now,
            (Some(audio), Some(video)),
            10,
            false,
            size,
        );
        let est = a.rtc.bwe.as_ref().unwrap().estimate();
        size = ((est as f64 * 0.9 / 8.0 / 50.0) as usize).clamp(200, 20_000);
    }
    let q = &net.queued[half..];
    let mean = q.iter().sum::<Duration>() / q.len().max(1) as u32;
    let rate = (b.rtc.stats.bytes_received - rx0) as f64 * 8.0 / (now - t0).as_secs_f64();
    (a, rate as u64, mean)
}

#[test]
fn ect1_responds_to_ce_scalably() {
    let (a, l4s, lq) = l4s_run(EcnMarking::Ect1);
    let (c, classic, cq) = l4s_run(EcnMarking::Ect0);
    let (_, plain, pq) = l4s_run(EcnMarking::Off);
    println!(
        "6 Mbps step-marking queue: ECT(1) {l4s} bps, queue {lq:?}; ECT(0) {classic} bps, queue {cq:?}; off {plain} bps, queue {pq:?}"
    );
    let bwe = a.rtc.bwe.as_ref().unwrap();
    assert_eq!(bwe.ecn_response(), only_rtp::EcnResponse::Scalable);
    assert_eq!(
        c.rtc.bwe.as_ref().unwrap().ecn_response(),
        only_rtp::EcnResponse::Classic
    );
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    assert!(a.rtc.ecn.ce > 0 && bwe.ce_fraction().is_some());
    // Near the capacity (as without ECN), with a short queue; the classic response backs
    // off as for loss.
    assert!(l4s as f64 > 0.7 * L4S_CAP, "{l4s}");
    assert!(l4s as f64 > 0.85 * plain as f64, "{l4s} {plain}");
    assert!(
        lq < Duration::from_millis(3) && lq * 2 < pq,
        "{lq:?} {pq:?}"
    );
    assert!(l4s > 2 * classic, "{l4s} {classic}");
    let _ = cq;
}

// ---- RFC 6679 signalling (ADR-082) ----

#[test]
fn rfc6679_negotiates_and_validates_without_rfc8888() {
    let ((a, b, net), offer, answer) =
        ecn_run_with(EcnMarking::Ect1, EcnMarking::Ect0, false, Path::Keep);
    for (sdp, ect) in [(&offer, 1), (&answer, 0)] {
        assert!(
            sdp.contains(&format!("a=ecn-capable-rtp:rtp mode=setread; ect={ect}")),
            "{sdp}"
        );
        assert!(
            sdp.contains(" nack ecn\r\n") && sdp.contains("ecn-sum"),
            "{sdp}"
        );
        assert!(!sdp.contains("ack ccfb"));
    }
    assert!(a.rtc.ecn6679.tx && b.rtc.ecn6679.rx && !a.rtc.ccfb);
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    let marks = rtp_marks(&net, addr("10.0.0.1:1000"));
    let tail = &marks[marks.len() - 200..];
    assert!(tail.iter().all(|m| *m == 1), "{tail:?}");
    // RTCP stays unmarked; b's feedback reaches a.
    assert!(net.log.iter().filter(|l| l.4).all(|l| l.3 == 0));
    assert!(b.rtc.stats.ecn_ect_received > 300);
    let (ect, ce) = a.rtc.bwe.as_ref().unwrap().ecn_counts();
    assert!(ect > 200 && ce == 0, "{ect} {ce}");
}

#[test]
fn rfc6679_detects_cleared_and_remarked_codepoints() {
    for path in [Path::Bleach, Path::Remark] {
        let ((a, _, net), _, _) = ecn_run_with(EcnMarking::Ect1, EcnMarking::Ect1, false, path);
        assert_eq!(a.rtc.ecn.phase, ecn::Phase::Failed);
        let marks = rtp_marks(&net, addr("10.0.0.1:1000"));
        assert!(marks[marks.len() / 2..].iter().all(|m| *m == 0));
    }
}

#[test]
fn rfc6679_ce_reaches_the_estimator() {
    let ((a, _, _), _, _) = ecn_run_with(EcnMarking::Ect1, EcnMarking::Ect1, false, Path::Ce(10));
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Capable);
    let bwe = a.rtc.bwe.as_ref().unwrap();
    let (ect, ce) = bwe.ecn_counts();
    assert!(ce > 10 && ect > 5 * ce, "{ect} {ce}");
    assert!(bwe.ce_fraction().is_some());
}

#[test]
fn rfc6679_needs_the_remote() {
    // The answerer does not mark: no attribute in its answer, nothing marked.
    let ((a, _, net), offer, answer) =
        ecn_run_with(EcnMarking::Ect1, EcnMarking::Off, false, Path::Keep);
    assert!(offer.contains("a=ecn-capable-rtp:"));
    assert!(!answer.contains("ecn-capable-rtp") && !answer.contains("nack ecn"));
    assert!(!a.rtc.ecn6679.rx);
    assert_eq!(a.rtc.ecn.phase, ecn::Phase::Off);
    assert!(net.log.iter().all(|l| l.3 == 0));
}

// ---- paths without a codepoint (ADR-082) ----

#[test]
fn no_ecn_on_paths_over_tcp() {
    for ccfb in [true, false] {
        let ((a, _, net), _, _) =
            ecn_run_on(EcnMarking::Ect1, EcnMarking::Ect1, ccfb, Path::Keep, true);
        // Off, not failed: nothing marked, nothing given up on.
        assert_eq!(a.rtc.ecn.phase, ecn::Phase::Off);
        assert_eq!(a.rtc.ecn.failures, 0);
        assert!(
            rtp_marks(&net, addr("10.0.0.1:1000"))
                .iter()
                .all(|m| *m == 0)
        );
    }
    // ICE-TCP candidates are recognised by the peer itself.
    let now = Instant::now();
    let mut r = Rtc::new(ecn_cfg(EcnMarking::Ect1, true), false, now).unwrap();
    r.add_local_candidate(IceCandidate::host_tcp(
        addr("10.0.0.1:9"),
        only_ice::TcpType::Active,
    ));
    assert_eq!(r.no_ecn, [addr("10.0.0.1:9")]);
}

// ---- latching before DTLS-SRTP keys (ADR-082) ----

fn dtls_plain(latching: Latching) -> ConfigInner {
    let mut c = ConfigInner::default();
    c.ice = false;
    c.latching = latching;
    c
}

const ATTACKER: &str = "198.51.100.66:6000";

/// A gateway `a` (latching as `latching`) and a phone `b` behind a NAT with DTLS-SRTP and no
/// ICE: `gateway_offers` or the phone offers. Returns the sides, the network, the audio mid,
/// the offer and the answer.
fn dtls_call(latching: Latching, gateway_offers: bool) -> (Side, Side, Net, Mid, String, String) {
    let now = Instant::now();
    let mut a = peer(dtls_plain(latching), &[GW], &[], now);
    let mut b = peer(dtls_plain(Latching::Off), &[PHONE], &[], now);
    a.hub = true;
    let (offer, answer, audio);
    if gateway_offers {
        let mut ch = a.rtc.changes();
        audio = SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        offer = a.rtc.apply(now, ch).unwrap().unwrap();
        answer = b.rtc.accept_offer(now, &offer).unwrap();
        a.rtc.accept_answer(now, &answer).unwrap();
    } else {
        let mut ch = b.rtc.changes();
        audio = SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        offer = b.rtc.apply(now, ch).unwrap().unwrap();
        answer = a.rtc.accept_offer(now, &offer).unwrap();
        b.rtc.accept_answer(now, &answer).unwrap();
    }
    let mut net = Net::new(Path::Keep);
    net.nat.push((addr(PHONE), addr(NAT)));
    drain(&mut a, now, &mut net);
    drain(&mut b, now, &mut net);
    (a, b, net, audio, offer, answer)
}

/// Runs `a` and `b` until both are connected (or `limit` passes); the time then.
fn run_until_connected(a: &mut Side, b: &mut Side, net: &mut Net, limit: Duration) -> bool {
    let start = Instant::now();
    let mut now = start;
    while now - start < limit {
        now += Duration::from_millis(5);
        step(a, b, now, net);
        if a.rtc.is_connected() && b.rtc.is_connected() {
            return true;
        }
    }
    false
}

#[test]
fn dtls_handshake_latches_onto_a_natted_phone() {
    for gateway_offers in [true, false] {
        let (mut a, mut b, mut net, audio, offer, answer) =
            dtls_call(Latching::Once, gateway_offers);
        let ours = if gateway_offers { &offer } else { &answer };
        // The gateway is the DTLS server: the phone's ClientHello comes from the NAT.
        assert!(
            ours.contains(if gateway_offers {
                "a=setup:actpass"
            } else {
                "a=setup:passive"
            }),
            "{ours}"
        );
        assert!(
            run_until_connected(&mut a, &mut b, &mut net, Duration::from_secs(10)),
            "offers {gateway_offers}"
        );
        assert_eq!(a.rtc.latch_moves(), 1);
        assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr(NAT));
        // A cookie exchange first: the gateway's first DTLS datagram to the NAT is a
        // HelloVerifyRequest (or a DTLS 1.3 HelloRetryRequest), state-free.
        let first = net
            .log
            .iter()
            .find(|l| l.0 == addr(GW) && (20..=63).contains(&l.2))
            .unwrap();
        assert_eq!(first.1, addr(PHONE));
        let now = Instant::now() + Duration::from_secs(11);
        media(&mut a, &mut b, &mut net, now, (Some(audio), None), 50, true);
        assert!(media_count(&a, audio) >= 45 && media_count(&b, audio) >= 45);
    }
}

#[test]
fn no_dtls_latching_without_the_option() {
    let (mut a, mut b, mut net, _, _, _) = dtls_call(Latching::Off, true);
    assert!(!run_until_connected(
        &mut a,
        &mut b,
        &mut net,
        Duration::from_secs(5)
    ));
    assert_eq!(a.rtc.latch_moves(), 0);
    assert!(
        net.log
            .iter()
            .all(|l| l.0 != addr(GW) || l.1 != addr(PHONE))
    );
}

#[test]
fn a_foreign_handshake_does_not_latch() {
    // An attacker that read the offer starts a handshake with a certificate of its own from
    // its own address: the gateway tries it tentatively, the fingerprint does not match, the
    // pair goes back and the phone latches after.
    let (mut a, mut b, mut net, _, offer, _) = dtls_call(Latching::Once, true);
    let start = Instant::now();
    let mut x = peer(dtls_plain(Latching::Off), &[ATTACKER], &[], start);
    let _ = x.rtc.accept_offer(start, &offer).unwrap();
    let mut now = start;
    let mut tentative_seen = false;
    let mut connected = false;
    // The attacker gets going first: the phone's datagrams wait 300 ms.
    while now - start < Duration::from_secs(15) {
        now += Duration::from_millis(5);
        let (due, keep): (Vec<_>, Vec<_>) = net.queue.drain(..).partition(|q| q.0 <= now);
        net.queue = keep;
        for (_, from, to, d, ecn) in due {
            if to == addr(ATTACKER) {
                deliver(&mut x, now, from, to, &d, ecn);
            } else if a.addrs.contains(&to) {
                if from == addr(NAT) && now - start < Duration::from_millis(300) {
                    continue;
                }
                deliver(&mut a, now, from, to, &d, ecn);
            } else if b.addrs.contains(&to) {
                deliver(&mut b, now, from, to, &d, ecn);
            }
        }
        for s in [&mut a, &mut b, &mut x] {
            if s.wake <= now {
                s.rtc.handle_timeout(now);
            }
            drain(s, now, &mut net);
        }
        tentative_seen |= a
            .rtc
            .latch
            .tentative
            .is_some_and(|t| t.source == addr(ATTACKER));
        assert!(a.rtc.alive, "the gateway peer died");
        if a.rtc.is_connected() && b.rtc.is_connected() {
            connected = true;
            break;
        }
    }
    assert!(tentative_seen, "the attacker's handshake was never tried");
    assert!(connected, "the phone never latched");
    assert_eq!(a.rtc.ice.send_pair().unwrap().1, addr(NAT));
    assert_eq!(a.rtc.latch_moves(), 1);
    // (A DTLS 1.3 client counts itself connected once it sent its Finished: the attacker
    // may, though the gateway refused its certificate.)
    let _ = x;
}
