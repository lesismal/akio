//! In simulated time: data channel priorities and schedulers, several transports without
//! BUNDLE, SDES-SRTP variants (no ICE, MKIs, next to data channels) and component 2's
//! server-reflexive and relayed candidates.

use super::*;
use crate::SdpChanges;
use crate::types::{BundlePolicy, ChannelPriority, ChannelScheduler};

/// A network between sides with several addresses each (NATs and relays are modelled by the
/// tests that need them).
struct Net {
    rng: u64,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>)>,
    /// (from, to, first byte) of every datagram sent.
    log: Vec<(SocketAddr, SocketAddr, u8)>,
}

impl Net {
    fn new(seed: u64) -> Net {
        Net {
            rng: seed | 1,
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
        self.log.push((from, to, d.first().copied().unwrap_or(0)));
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

fn side(rtc: Rtc, addrs: Vec<SocketAddr>, now: Instant) -> Side {
    Side {
        rtc,
        addrs,
        events: Vec::new(),
        wake: now,
    }
}

fn drain(s: &mut Side, now: Instant, net: &mut Net) {
    loop {
        match s.rtc.poll_output(now) {
            Output::Timeout(t) => {
                s.wake = t;
                break;
            }
            Output::Transmit(from, to, d) => {
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
        } else if b.addrs.contains(&to) {
            &mut *b
        } else {
            continue;
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

fn connect(a: &mut Side, b: &mut Side, net: &mut Net, mut now: Instant) -> Instant {
    let start = now;
    while !(a.rtc.is_connected() && b.rtc.is_connected()) {
        now += Duration::from_millis(5);
        step(a, b, now, net);
        if now - start >= Duration::from_secs(30) {
            let mut p = paths(net, 0..=255);
            p.truncate(40);
            panic!(
                "no connection: a {:?} {}, b {:?} {}; {p:?}",
                a.rtc.xt,
                a.rtc.is_connected(),
                b.rtc.xt,
                b.rtc.is_connected()
            );
        }
    }
    now
}

fn run_for(a: &mut Side, b: &mut Side, net: &mut Net, mut now: Instant, d: Duration) -> Instant {
    let end = now + d;
    while now < end {
        now += Duration::from_millis(5);
        step(a, b, now, net);
    }
    now
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A peer with host candidates at `c1` (component 1) and `c2` (component 2).
fn peer(cfg: ConfigInner, c1: &[&str], c2: &[&str], now: Instant) -> (Rtc, Vec<SocketAddr>) {
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
    (r, addrs)
}

fn opened(s: &Side) -> Vec<(ChannelId, String)> {
    s.events
        .iter()
        .filter_map(|e| match e {
            RtcEvent::ChannelOpen(id, l) => Some((*id, l.clone())),
            _ => None,
        })
        .collect()
}

// ---- data channel priorities ----

/// `a` (scheduler `sched`) opens channels "low" and "high" with priorities `pl` / `ph` and,
/// once open, queues `n` messages of 16 KiB on "low" then on "high"; returns the labels of
/// the messages in the order `b` received them, and `b`'s view of the channels' priorities.
fn priority_run(
    sched: ChannelScheduler,
    pl: ChannelPriority,
    ph: ChannelPriority,
    raise: bool,
    n: usize,
) -> (Vec<&'static str>, Vec<(String, ChannelPriority)>) {
    let now = Instant::now();
    let mut ca = ConfigInner::default();
    ca.sctp_scheduler = sched;
    ca.sctp_max_buffered = 4 << 20;
    let (ra, aa) = peer(ca, &["10.0.0.1:1000"], &[], now);
    let (rb, ba) = peer(ConfigInner::default(), &["10.0.0.2:2000"], &[], now);
    let (mut a, mut b) = (side(ra, aa, now), side(rb, ba, now));
    let mut ch = a.rtc.changes();
    let (low, high) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_channel_with_config(&ChannelConfig::new("low").with_priority(pl)),
            api.add_channel_with_config(&ChannelConfig::new("high").with_priority(ph)),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(7);
    let mut now = connect(&mut a, &mut b, &mut net, now);
    while opened(&b).len() < 2 || opened(&a).len() < 2 {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
    }
    if raise {
        assert!(a.rtc.set_channel_priority(high, ChannelPriority::High));
        assert_eq!(a.rtc.channel_priority(high), Some(ChannelPriority::High));
    }
    let msg = vec![7u8; 16 * 1024];
    for _ in 0..n {
        assert_eq!(a.rtc.send_channel(now, low, &msg, true), Ok(Some(true)));
    }
    for _ in 0..n {
        assert_eq!(a.rtc.send_channel(now, high, &msg, true), Ok(Some(true)));
    }
    let names: HashMap<ChannelId, String> = opened(&b).into_iter().collect();
    let prios = names
        .iter()
        .map(|(id, l)| (l.clone(), b.rtc.channel_priority(*id).unwrap()))
        .collect();
    b.events.clear();
    let mut order = Vec::new();
    let start = now;
    while order.len() < 2 * n {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
        for e in b.events.drain(..) {
            if let RtcEvent::ChannelData(id, d, _) = e {
                assert_eq!(d.len(), msg.len());
                order.push(if names[&id] == "low" { "low" } else { "high" });
            }
        }
        assert!(now - start < Duration::from_secs(60), "stalled at {}", order.len());
    }
    (order, prios)
}

#[test]
fn channel_priorities_reach_the_peer() {
    let (_, prios) = priority_run(
        ChannelScheduler::WeightedFairQueueing,
        ChannelPriority::VeryLow,
        ChannelPriority::High,
        false,
        1,
    );
    let mut prios = prios;
    prios.sort();
    assert_eq!(
        prios,
        vec![
            ("high".to_owned(), ChannelPriority::High),
            ("low".to_owned(), ChannelPriority::VeryLow)
        ]
    );
}

#[test]
fn priority_scheduler_serves_the_high_channel_first() {
    let (order, _) = priority_run(
        ChannelScheduler::Priority,
        ChannelPriority::Low,
        ChannelPriority::High,
        false,
        24,
    );
    let last_high = order.iter().rposition(|l| *l == "high").unwrap();
    let first_low = order.iter().position(|l| *l == "low").unwrap();
    assert!(last_high < first_low, "{order:?}");
}

#[test]
fn raised_priority_takes_effect() {
    // Both opened low; "high" raised on the sending side before the data is queued.
    let (order, prios) = priority_run(
        ChannelScheduler::Priority,
        ChannelPriority::Low,
        ChannelPriority::Low,
        true,
        16,
    );
    let last_high = order.iter().rposition(|l| *l == "high").unwrap();
    let first_low = order.iter().position(|l| *l == "low").unwrap();
    assert!(last_high < first_low, "{order:?}");
    // The peer keeps what the open message said.
    assert!(prios.iter().all(|(_, p)| *p == ChannelPriority::Low));
}

#[test]
fn weighted_fair_queueing_shares_by_priority() {
    // 1024 against 256: about four bytes of "high" for one of "low".
    let (order, _) = priority_run(
        ChannelScheduler::WeightedFairQueueing,
        ChannelPriority::Low,
        ChannelPriority::High,
        false,
        24,
    );
    let last_high = order.iter().rposition(|l| *l == "high").unwrap();
    let low_before = order[..last_high].iter().filter(|l| **l == "low").count();
    assert!((2..=12).contains(&low_before), "{low_before}: {order:?}");
    // Round robin: about one for one.
    let (order, _) = priority_run(
        ChannelScheduler::RoundRobin,
        ChannelPriority::Low,
        ChannelPriority::High,
        false,
        24,
    );
    let last_high = order.iter().rposition(|l| *l == "high").unwrap();
    let low_before = order[..last_high].iter().filter(|l| **l == "low").count();
    assert!(low_before >= 18, "{low_before}: {order:?}");
}

#[test]
fn dcep_priority_values() {
    for p in [
        ChannelPriority::VeryLow,
        ChannelPriority::Low,
        ChannelPriority::Medium,
        ChannelPriority::High,
    ] {
        assert_eq!(ChannelPriority::from_dcep_value(p.dcep_value()), p);
    }
    assert_eq!(ChannelPriority::from_dcep_value(0), ChannelPriority::Low);
    assert_eq!(ChannelPriority::from_dcep_value(1), ChannelPriority::VeryLow);
    assert_eq!(ChannelPriority::from_dcep_value(300), ChannelPriority::Low);
    assert_eq!(ChannelPriority::from_dcep_value(700), ChannelPriority::Medium);
    assert_eq!(ChannelPriority::from_dcep_value(u16::MAX), ChannelPriority::High);
    assert_eq!(ChannelConfig::default().priority, ChannelPriority::Low);
}

// ---- media helpers ----

/// `from` sends `n` Opus packets on `audio` and `n` small VP8 frames on `video` (if any), and
/// sends `msgs` messages on channel `ch` (if any); returns the time after the run.
#[allow(clippy::too_many_arguments)]
fn exchange(
    from: &mut Side,
    to: &mut Side,
    net: &mut Net,
    mut now: Instant,
    audio: Option<Mid>,
    video: Option<Mid>,
    ch: Option<ChannelId>,
    n: u64,
) -> Instant {
    for i in 0..n {
        if let Some(a) = audio {
            let pt = from.rtc.payload_type(a, Codec::Opus).expect("opus");
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            assert!(from.rtc.write_media(now, a, None, pt, t, &[0xfc, i as u8, 1, 2]).unwrap());
        }
        if let Some(v) = video {
            let pt = from.rtc.payload_type(v, Codec::Vp8).expect("vp8");
            let t = MediaTime::new(i * 3600, Frequency::NINETY_KHZ);
            let f = [if i == 0 { 0x10 } else { 0x11 }, i as u8, 9, 9, 9, 9];
            assert!(from.rtc.write_media(now, v, None, pt, t, &f).unwrap());
        }
        if let Some(c) = ch {
            let _ = from.rtc.send_channel(now, c, &[i as u8; 64], true);
        }
        for _ in 0..4 {
            now += Duration::from_millis(5);
            step(from, to, now, net);
        }
    }
    run_for(from, to, net, now, Duration::from_millis(500))
}

fn media_count(s: &Side, mid: Mid) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::MediaData(d) if d.mid == mid))
        .count()
}

fn channel_data(s: &Side) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::ChannelData(..)))
        .count()
}

fn connected_events(s: &Side) -> usize {
    s.events
        .iter()
        .filter(|e| matches!(e, RtcEvent::Connected))
        .count()
}

/// The values of `a=<key>:` lines of each media section of an SDP.
fn per_section(sdp: &str, key: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for l in sdp.lines() {
        if l.starts_with("m=") {
            out.push(Vec::new());
        } else if let (Some(v), Some(cur)) = (l.strip_prefix(&format!("a={key}:")), out.last_mut()) {
            cur.push(v.to_owned());
        }
    }
    out
}

/// The (from, to) address pairs that carried datagrams whose first byte is in `range`.
fn paths(net: &Net, range: std::ops::RangeInclusive<u8>) -> Vec<(SocketAddr, SocketAddr)> {
    let mut v: Vec<_> = net
        .log
        .iter()
        .filter(|(_, _, b)| range.contains(b))
        .map(|(f, t, _)| (*f, *t))
        .collect();
    v.sort();
    v.dedup();
    v
}

// ---- several transports without BUNDLE ----

/// A peer with a host candidate at `primary` and, for the transports made later, one each
/// at `others` (a socket per transport, as an endpoint that does not bundle has).
fn split_peer(cfg: ConfigInner, primary: &str, others: &[&str], now: Instant) -> Side {
    let (mut r, mut addrs) = peer(cfg, &[primary], &[], now);
    for (k, a) in others.iter().enumerate() {
        r.add_transport_candidate(k + 1, IceCandidate::host(addr(a)));
        addrs.push(addr(a));
    }
    side(r, addrs, now)
}

#[test]
fn transports_per_section_without_bundle() {
    let now = Instant::now();
    let mut ca = ConfigInner::default();
    ca.bundle = BundlePolicy::Disabled;
    let mut a = split_peer(ca, "10.0.0.1:1000", &["10.0.0.1:1001", "10.0.0.1:1002"], now);
    let mut b = split_peer(
        ConfigInner::default(),
        "10.0.0.2:2000",
        &["10.0.0.2:2001", "10.0.0.2:2002"],
        now,
    );
    let mut ch = a.rtc.changes();
    let (audio, video, chan) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
            api.add_channel("data"),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    // No BUNDLE, credentials and candidates of its own in every section, no transport-wide
    // congestion control.
    assert!(!offer.contains("a=group:BUNDLE"), "{offer}");
    let ufrags = per_section(&offer, "ice-ufrag");
    assert_eq!(ufrags.len(), 3);
    let mut u: Vec<&String> = ufrags.iter().map(|v| &v[0]).collect();
    u.sort();
    u.dedup();
    assert_eq!(u.len(), 3, "{offer}");
    assert!(ufrags.iter().all(|v| v[0].starts_with(&ufrags[0][0][..8])));
    let cands = per_section(&offer, "candidate");
    assert!(cands[0][0].contains(" 1000 ") && cands[1][0].contains(" 1001 "), "{offer}");
    assert!(cands[2][0].contains(" 1002 "), "{offer}");
    assert!(!offer.contains("transport-cc"), "{offer}");
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(!answer.contains("a=group:BUNDLE"), "{answer}");
    assert_eq!(per_section(&answer, "ice-ufrag").len(), 3);
    assert!(!answer.contains("transport-cc"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(3);
    let now = connect(&mut a, &mut b, &mut net, now);
    assert!(a.rtc.unbundled() && b.rtc.unbundled());
    let mut now = now;
    let start = now;
    while opened(&b).is_empty() {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
        assert!(now - start < Duration::from_secs(30), "no channel");
    }
    let now = exchange(&mut a, &mut b, &mut net, now, Some(audio), Some(video), Some(chan), 50);
    assert!(media_count(&b, audio) >= 48, "{}", media_count(&b, audio));
    assert!(media_count(&b, video) >= 48, "{}", media_count(&b, video));
    assert_eq!(channel_data(&b), 50);
    // Media the other way too.
    let bmids: Vec<(Mid, MediaKind)> = b
        .events
        .iter()
        .filter_map(|e| match e {
            RtcEvent::MediaAdded(m) => Some((m.mid, m.kind)),
            _ => None,
        })
        .collect();
    assert_eq!(bmids.len(), 2);
    let _ = exchange(&mut b, &mut a, &mut net, now, Some(audio), Some(video), None, 20);
    assert!(media_count(&a, audio) >= 18 && media_count(&a, video) >= 18);
    // Each transport kept to its own pair of addresses: DTLS on three, RTP / RTCP on the
    // two media ones, ICE checks only within a transport.
    let pair = |x: &str, y: &str| (addr(x), addr(y));
    let dtls = paths(&net, 20..=63);
    for (x, y) in [
        ("10.0.0.1:1000", "10.0.0.2:2000"),
        ("10.0.0.1:1001", "10.0.0.2:2001"),
        ("10.0.0.1:1002", "10.0.0.2:2002"),
    ] {
        assert!(dtls.contains(&pair(x, y)) && dtls.contains(&pair(y, x)), "{dtls:?}");
    }
    assert_eq!(dtls.len(), 6, "{dtls:?}");
    let srtp = paths(&net, 128..=191);
    assert_eq!(srtp.len(), 4, "{srtp:?}");
    assert!(!srtp.iter().any(|(f, _)| f.port() == 1002 || f.port() == 2002));
    let stun = paths(&net, 0..=3);
    assert!(
        stun.iter().all(|(f, t)| f.port() % 1000 == t.port() % 1000),
        "{stun:?}"
    );
    // One Connected per side, once every transport was up.
    assert_eq!((connected_events(&a), connected_events(&b)), (1, 1));
}

#[test]
fn answer_refusing_bundle_splits_the_offerer() {
    // `a` offers BUNDLE (the default); `b` does not bundle and answers each section on its
    // own transport. `a` has one socket: its transports share it (and its credentials, as
    // its offer gave every section), told apart by `b`'s addresses.
    let now = Instant::now();
    let (ra, aa) = peer(ConfigInner::default(), &["10.0.0.1:1000"], &[], now);
    let mut a = side(ra, aa, now);
    let mut cb = ConfigInner::default();
    cb.bundle = BundlePolicy::Disabled;
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
    assert!(offer.contains("a=group:BUNDLE 0 1"));
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(!answer.contains("a=group:BUNDLE"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    assert!(a.rtc.unbundled());
    let mut net = Net::new(5);
    let now = connect(&mut a, &mut b, &mut net, now);
    let _ = exchange(&mut a, &mut b, &mut net, now, Some(audio), Some(video), None, 40);
    assert!(media_count(&b, audio) >= 38 && media_count(&b, video) >= 38);
    let srtp = paths(&net, 128..=191);
    assert!(srtp.contains(&(addr("10.0.0.1:1000"), addr("10.0.0.2:2001"))), "{srtp:?}");
    assert!(srtp.contains(&(addr("10.0.0.1:1000"), addr("10.0.0.2:2000"))), "{srtp:?}");
    assert_eq!((connected_events(&a), connected_events(&b)), (1, 1));
}

#[test]
fn transports_without_bundle_and_rtcp_mux() {
    // The SIP shape: audio and video, each on its own transport with RTCP on a port of its
    // own (four ICE components in all per side).
    let now = Instant::now();
    let mut ca = ConfigInner::default();
    ca.bundle = BundlePolicy::Disabled;
    ca.rtcp_mux = RtcpMuxPolicy::Off;
    let mk = |cfg: ConfigInner, h: &str, i: u16| {
        let (mut r, mut addrs) = peer(
            cfg,
            &[&format!("{h}:{}", i)],
            &[&format!("{h}:{}", i + 1)],
            now,
        );
        let (c1, c2) = (addr(&format!("{h}:{}", i + 2)), addr(&format!("{h}:{}", i + 3)));
        r.add_transport_candidate(1, IceCandidate::host(c1));
        r.add_transport_candidate(1, IceCandidate::host(c2).with_component(2));
        addrs.extend([c1, c2]);
        side(r, addrs, now)
    };
    let mut a = mk(ca, "10.0.0.1", 1000);
    let mut b = mk(ConfigInner::default(), "10.0.0.2", 2000);
    let mut ch = a.rtc.changes();
    let (audio, video) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_media(MediaKind::Video, Direction::SendRecv, None, None),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    assert!(!offer.contains("a=rtcp-mux") && !offer.contains("BUNDLE"), "{offer}");
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(!answer.contains("a=rtcp-mux") && answer.contains("a=rtcp:"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(9);
    let now = connect(&mut a, &mut b, &mut net, now);
    let _ = exchange(&mut a, &mut b, &mut net, now, Some(audio), Some(video), None, 60);
    assert!(media_count(&b, audio) >= 55 && media_count(&b, video) >= 55);
    // RTCP on each transport's component 2, RTP on its component 1.
    let rtcp: Vec<(SocketAddr, SocketAddr)> = net
        .log
        .iter()
        .filter(|(_, _, b)| (128..=191).contains(b))
        .map(|(f, t, _)| (*f, *t))
        .collect();
    for (f, t) in &rtcp {
        assert_eq!(f.port() % 2, t.port() % 2, "{f} -> {t}");
    }
    let ports: std::collections::HashSet<u16> = rtcp.iter().map(|(f, _)| f.port()).collect();
    for p in [1000, 1001, 1002, 1003] {
        assert!(ports.contains(&p), "{ports:?}");
    }
}

#[test]
fn bundled_rtcp_mux_off_still_refuses_two_sections() {
    let now = Instant::now();
    let mut ca = ConfigInner::default();
    ca.rtcp_mux = RtcpMuxPolicy::Off;
    let (mut a, _) = peer(ca, &["10.0.0.1:1000"], &["10.0.0.1:1001"], now);
    let mut ch = a.changes();
    {
        let mut api = SdpChanges(&mut ch);
        api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
        api.add_media(MediaKind::Video, Direction::SendRecv, None, None);
    }
    assert!(a.apply(now, ch).is_err());
}

// ---- SDES ----

fn sdes_cfg() -> ConfigInner {
    let mut c = ConfigInner::default();
    c.sdes = true;
    c
}

#[test]
fn sdes_without_ice() {
    // SIP style: no ICE attributes, media to the c= address and m= port; RTCP on its own
    // port.
    let now = Instant::now();
    let mut ca = sdes_cfg();
    ca.ice = false;
    ca.rtcp_mux = RtcpMuxPolicy::Off;
    let (ra, aa) = peer(ca, &["10.0.0.1:4000"], &["10.0.0.1:4001"], now);
    let (rb, ba) = peer(sdes_cfg(), &["10.0.0.2:5000"], &["10.0.0.2:5007"], now);
    let (mut a, mut b) = (side(ra, aa, now), side(rb, ba, now));
    let mut ch = a.rtc.changes();
    let audio = SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    assert!(!offer.contains("ice-ufrag") && !offer.contains("a=candidate"), "{offer}");
    assert!(offer.contains("m=audio 4000 RTP/SAVPF"), "{offer}");
    assert!(offer.contains("c=IN IP4 10.0.0.1\r\n"), "{offer}");
    assert!(offer.contains("a=rtcp:4001 IN IP4 10.0.0.1"), "{offer}");
    assert!(offer.contains("a=crypto:"), "{offer}");
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(!answer.contains("ice-ufrag"), "{answer}");
    assert!(answer.contains("m=audio 5000 RTP/SAVPF"), "{answer}");
    assert!(answer.contains("a=rtcp:5007 IN IP4 10.0.0.2"), "{answer}");
    // The answerer knows where to send at once.
    assert_eq!(
        b.rtc.take_plain_remotes(),
        vec![addr("10.0.0.1:4000"), addr("10.0.0.1:4001")]
    );
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(1);
    drain(&mut a, now, &mut net);
    drain(&mut b, now, &mut net);
    assert!(a.rtc.is_connected() && b.rtc.is_connected());
    assert_eq!((connected_events(&a), connected_events(&b)), (1, 1));
    let now = exchange(&mut a, &mut b, &mut net, now, Some(audio), None, None, 50);
    let _ = exchange(&mut b, &mut a, &mut net, now, Some(audio), None, None, 50);
    assert!(media_count(&b, audio) >= 50 && media_count(&a, audio) >= 50);
    // No STUN or DTLS; RTP between the media ports, RTCP between the RTCP ports.
    assert!(paths(&net, 0..=63).is_empty(), "{:?}", paths(&net, 0..=63));
    let srtp = paths(&net, 128..=191);
    for p in [
        ("10.0.0.1:4000", "10.0.0.2:5000"),
        ("10.0.0.2:5000", "10.0.0.1:4000"),
        ("10.0.0.1:4001", "10.0.0.2:5007"),
        ("10.0.0.2:5007", "10.0.0.1:4001"),
    ] {
        assert!(srtp.contains(&(addr(p.0), addr(p.1))), "{srtp:?}");
    }
    assert_eq!(srtp.len(), 4, "{srtp:?}");
}

#[test]
fn plain_offer_with_rtcp_mux() {
    // A SIP offer by hand: c=, port, a=rtcp-mux, an MKI'd key, no ICE.
    let now = Instant::now();
    let (rb, _) = peer(sdes_cfg(), &["10.0.0.2:5000"], &[], now);
    let mut b = rb;
    let key = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz";
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 7000 RTP/SAVP 0 111\r\na=rtpmap:111 opus/48000/2\r\na=rtcp-mux\r\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}|2^31|1:2\r\na=sendrecv\r\n"
    );
    let answer = b.accept_offer(now, &offer).unwrap();
    assert!(answer.contains("m=audio 5000 RTP/SAVP"), "{answer}");
    assert!(answer.contains("a=rtcp-mux") && !answer.contains("a=rtcp:"), "{answer}");
    // Our key has a 2-byte MKI too.
    let crypto = per_section(&answer, "crypto");
    assert!(crypto[0][0].ends_with("|1:2"), "{answer}");
    assert_eq!(b.take_plain_remotes(), vec![addr("192.0.2.1:7000")]);
    while !matches!(b.poll_output(now), Output::Timeout(_)) {}
    assert!(b.is_connected());
}

#[test]
fn sdes_with_mkis() {
    let now = Instant::now();
    let mut ca = sdes_cfg();
    ca.sdes_mki = 4;
    let (ra, aa) = peer(ca, &["10.0.0.1:1000"], &[], now);
    let (rb, ba) = peer(sdes_cfg(), &["10.0.0.2:2000"], &[], now);
    let (mut a, mut b) = (side(ra, aa, now), side(rb, ba, now));
    let mut ch = a.rtc.changes();
    let audio = SdpChanges(&mut ch).add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    let crypto = per_section(&offer, "crypto");
    assert!(crypto[0].iter().all(|c| c.ends_with("|1:4")), "{offer}");
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    assert!(per_section(&answer, "crypto")[0][0].ends_with("|1:4"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(2);
    let now = connect(&mut a, &mut b, &mut net, now);
    let now = exchange(&mut a, &mut b, &mut net, now, Some(audio), None, None, 30);
    let _ = exchange(&mut b, &mut a, &mut net, now, Some(audio), None, None, 30);
    assert!(media_count(&b, audio) >= 30 && media_count(&a, audio) >= 30);
}

#[test]
fn sdes_media_next_to_data_channels() {
    let now = Instant::now();
    let (ra, aa) = peer(sdes_cfg(), &["10.0.0.1:1000"], &[], now);
    let (rb, ba) = peer(sdes_cfg(), &["10.0.0.2:2000"], &[], now);
    let (mut a, mut b) = (side(ra, aa, now), side(rb, ba, now));
    let mut ch = a.rtc.changes();
    let (audio, chan) = {
        let mut api = SdpChanges(&mut ch);
        (
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None),
            api.add_channel("c"),
        )
    };
    let offer = a.rtc.apply(now, ch).unwrap().unwrap();
    // Keys in the media section, a fingerprint in the application section only.
    let fp = per_section(&offer, "fingerprint");
    let crypto = per_section(&offer, "crypto");
    assert!(fp[0].is_empty() && !crypto[0].is_empty(), "{offer}");
    assert!(fp[1].len() == 1 && crypto[1].is_empty(), "{offer}");
    assert_eq!(per_section(&offer, "setup")[1], vec!["actpass".to_owned()]);
    let answer = b.rtc.accept_offer(now, &offer).unwrap();
    let fp = per_section(&answer, "fingerprint");
    assert!(fp[0].is_empty() && fp[1].len() == 1, "{answer}");
    assert!(answer.contains("m=application 9 UDP/DTLS/SCTP"), "{answer}");
    a.rtc.accept_answer(now, &answer).unwrap();
    let mut net = Net::new(4);
    let start = now;
    let mut now = connect(&mut a, &mut b, &mut net, now);
    while opened(&b).is_empty() {
        now += Duration::from_millis(5);
        step(&mut a, &mut b, now, &mut net);
        assert!(now - start < Duration::from_secs(30), "no channel");
    }
    let _ = exchange(&mut a, &mut b, &mut net, now, Some(audio), None, Some(chan), 30);
    assert!(media_count(&b, audio) >= 30);
    assert_eq!(channel_data(&b), 30);
    // DTLS ran (for SCTP), and SRTP still uses the SDES keys: b decrypted the media.
    assert!(!paths(&net, 20..=63).is_empty());
}
