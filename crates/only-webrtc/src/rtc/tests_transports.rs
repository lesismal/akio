//! In simulated time: data channel priorities and schedulers, several transports without
//! BUNDLE, SDES-SRTP variants (no ICE, MKIs, next to data channels) and component 2's
//! server-reflexive and relayed candidates.

use super::*;
use crate::SdpChanges;
use crate::types::{ChannelPriority, ChannelScheduler};

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
        assert!(now - start < Duration::from_secs(30), "no connection");
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
