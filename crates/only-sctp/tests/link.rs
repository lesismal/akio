//! Two associations over a simulated link (loss, reordering, duplication, small MTU) in
//! simulated time. `Sim::pair` uses I-DATA (RFC 8260) for odd seeds and DATA for even ones,
//! so the seed loops cover both.

use std::time::{Duration, Instant};

use only_sctp::{Association, ChannelOptions, Config, Error, Event, Reliability, Scheduler};

/// Reproducible tags, initial TSNs and cookie keys; every third seed starts the TSNs just
/// below the 2^32 wrap.
fn ids(seed: u64, side: u8) -> [u8; 40] {
    let mut r = [side; 40];
    let mut g = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ u64::from(side) | 1);
    for b in &mut r {
        *b = g.next() as u8;
    }
    if seed % 3 == 0 {
        r[4..8].copy_from_slice(&(u32::MAX - 20 - u32::from(side)).to_be_bytes());
    }
    r
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// True with probability `permille` / 1000.
    fn chance(&mut self, permille: u64) -> bool {
        self.next() % 1000 < permille
    }
}

#[derive(Clone, Copy)]
struct Link {
    loss: u64,
    dup: u64,
    delay_ms: u64,
    jitter_ms: u64,
}

const CLEAN: Link = Link {
    loss: 0,
    dup: 0,
    delay_ms: 20,
    jitter_ms: 0,
};

const LOSSY: Link = Link {
    loss: 150,
    dup: 50,
    delay_ms: 20,
    jitter_ms: 40,
};

struct Sim {
    start: Instant,
    now: Instant,
    a: Association,
    b: Association,
    mtu: usize,
    link: Link,
    rng: Rng,
    /// (deliver at, sequence, to b, packet)
    queue: Vec<(Instant, u64, bool, Vec<u8>)>,
    seq: u64,
    ev_a: Vec<Event>,
    ev_b: Vec<Event>,
    /// Drop everything (the peer vanished).
    blackhole: bool,
    packets: u64,
    /// Chunk types seen in packets from `a`.
    seen: [bool; 256],
    /// Packets from `a` whose DATA / I-DATA chunks belong to more than one stream.
    mixed: usize,
    /// Packets from `a` with a zero checksum field (RFC 9653).
    zero_sums: usize,
}

impl Sim {
    fn new(ca: Config, cb: Config, link: Link, seed: u64) -> Sim {
        let now = Instant::now();
        let mtu = ca.mtu.min(cb.mtu);
        Sim {
            start: now,
            now,
            a: Association::with_random(ca, now, ids(seed, 1)),
            b: Association::with_random(cb, now, ids(seed, 2)),
            mtu,
            link,
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            queue: Vec::new(),
            seq: 0,
            ev_a: Vec::new(),
            ev_b: Vec::new(),
            blackhole: false,
            packets: 0,
            seen: [false; 256],
            mixed: 0,
            zero_sums: 0,
        }
    }

    fn pair(link: Link, seed: u64, mtu: usize) -> Sim {
        let idata = seed % 2 == 1;
        Sim::new(
            Config::new(true)
                .with_mtu(mtu)
                .with_message_interleaving(idata),
            Config::new(false)
                .with_mtu(mtu)
                .with_message_interleaving(idata),
            link,
            seed,
        )
    }

    /// Records the chunk types of a packet from `a` and whether its data chunks mix streams.
    fn inspect(&mut self, p: &[u8]) {
        let mut at = 12;
        let mut stream: Option<u16> = None;
        let mut mixed = false;
        while at + 4 <= p.len() {
            let typ = p[at];
            let len = usize::from(u16::from_be_bytes([p[at + 2], p[at + 3]]));
            self.seen[usize::from(typ)] = true;
            if (typ == 0 || typ == 64) && at + 10 <= p.len() {
                let s = u16::from_be_bytes([p[at + 8], p[at + 9]]);
                mixed |= stream.is_some_and(|x| x != s);
                stream = Some(s);
            }
            if len < 4 {
                break;
            }
            at += (len + 3) & !3;
        }
        self.mixed += usize::from(mixed);
    }

    fn elapsed(&self) -> Duration {
        self.now.duration_since(self.start)
    }

    fn enqueue(&mut self, to_b: bool, p: Vec<u8>) {
        assert!(
            p.len() <= self.mtu,
            "packet of {} > mtu {}",
            p.len(),
            self.mtu
        );
        self.packets += 1;
        if to_b {
            self.inspect(&p);
            self.zero_sums += usize::from(p[8..12] == [0; 4]);
        }
        if self.blackhole || self.rng.chance(self.link.loss) {
            return;
        }
        let copies = if self.rng.chance(self.link.dup) { 2 } else { 1 };
        for _ in 0..copies {
            let j = if self.link.jitter_ms > 0 {
                self.rng.next() % self.link.jitter_ms
            } else {
                0
            };
            let at = self.now + Duration::from_millis(self.link.delay_ms + j);
            self.seq += 1;
            self.queue.push((at, self.seq, to_b, p.clone()));
        }
    }

    fn flush(&mut self) {
        while let Some(p) = self.a.poll_transmit(self.now) {
            self.enqueue(true, p);
        }
        while let Some(p) = self.b.poll_transmit(self.now) {
            self.enqueue(false, p);
        }
        while let Some(e) = self.a.poll_event() {
            self.ev_a.push(e);
        }
        while let Some(e) = self.b.poll_event() {
            self.ev_b.push(e);
        }
    }

    /// One step: transmit, then move time to the next delivery or timer. `false` when
    /// nothing is left to happen.
    fn step(&mut self) -> bool {
        self.flush();
        let next_pkt = self.queue.iter().map(|q| (q.0, q.1)).min();
        let next_timer = [self.a.poll_timeout(), self.b.poll_timeout()]
            .into_iter()
            .flatten()
            .min();
        let next = match (next_pkt.map(|p| p.0), next_timer) {
            (Some(p), Some(t)) => p.min(t),
            (Some(p), None) => p,
            (None, Some(t)) => t,
            (None, None) => return false,
        };
        if next > self.now {
            self.now = next;
        }
        // Deliver everything due, in delivery-time order.
        let mut due: Vec<(Instant, u64, bool, Vec<u8>)> = Vec::new();
        let mut i = 0;
        while i < self.queue.len() {
            if self.queue[i].0 <= self.now {
                due.push(self.queue.swap_remove(i));
            } else {
                i += 1;
            }
        }
        due.sort_by_key(|d| (d.0, d.1));
        for (_, _, to_b, p) in due {
            if to_b {
                self.b.handle_packet(self.now, &p);
            } else {
                self.a.handle_packet(self.now, &p);
            }
            // Like a real event loop: answer each datagram before reading the next.
            self.flush();
        }
        if self.a.poll_timeout().is_some_and(|t| t <= self.now) {
            self.a.handle_timeout(self.now);
        }
        if self.b.poll_timeout().is_some_and(|t| t <= self.now) {
            self.b.handle_timeout(self.now);
        }
        self.flush();
        true
    }

    /// Steps until `done` or `limit` of simulated time; returns whether `done` held.
    fn run(&mut self, limit: Duration, mut done: impl FnMut(&Sim) -> bool) -> bool {
        let end = self.now + limit;
        loop {
            if done(self) {
                return true;
            }
            if self.now > end || !self.step() {
                return done(self);
            }
        }
    }

    fn connect(&mut self) {
        self.a.connect(self.now);
        assert!(self.run(Duration::from_secs(60), |s| s.a.is_established()
            && s.b.is_established()));
    }

    fn data_b(&self, stream: u16) -> Vec<Vec<u8>> {
        data_of(&self.ev_b, stream)
    }
}

/// Seeds `1..=default`, or `1..=$SCTP_SEEDS` for longer soak runs.
fn seeds(default: u64) -> std::ops::RangeInclusive<u64> {
    let n = std::env::var("SCTP_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    1..=n
}

fn data_of(ev: &[Event], stream: u16) -> Vec<Vec<u8>> {
    ev.iter()
        .filter_map(|e| match e {
            Event::ChannelData {
                stream: s, data, ..
            } if *s == stream => Some(data.clone()),
            _ => None,
        })
        .collect()
}

fn count(ev: &[Event], f: impl Fn(&Event) -> bool) -> usize {
    ev.iter().filter(|e| f(e)).count()
}

fn msg(i: usize, len: usize) -> Vec<u8> {
    let mut v = (i as u32).to_be_bytes().to_vec();
    v.extend((0..len.saturating_sub(4)).map(|j| (i + j) as u8));
    v.truncate(len.max(4));
    v
}

#[test]
fn ordered_reliable_over_lossy_link() {
    for seed in seeds(6) {
        let mut s = Sim::pair(LOSSY, seed, 300);
        s.connect();
        let ch =
            s.a.open_channel(s.now, ChannelOptions::new("chat"))
                .unwrap();
        let sent: Vec<Vec<u8>> = (0..400).map(|i| msg(i, 4 + (i * 37) % 900)).collect();
        for m in &sent {
            assert!(s.a.send(s.now, ch, m, true).unwrap());
        }
        assert!(
            s.run(Duration::from_secs(300), |s| s.data_b(ch).len()
                == sent.len()),
            "seed {seed}: {} of {} after {:?}",
            s.data_b(ch).len(),
            sent.len(),
            s.elapsed()
        );
        assert_eq!(s.data_b(ch), sent, "seed {seed}");
        assert!(s.run(Duration::from_secs(60), |s| s.a.buffered_amount(ch) == 0));
        assert!(!s.a.is_closed() && !s.b.is_closed());
        // The open went both ways.
        assert!(s.ev_b.iter().any(|e| matches!(e,
            Event::ChannelOpen { stream, label, .. } if *stream == ch && label == "chat")));
    }
}

#[test]
fn both_directions_lossy() {
    let mut s = Sim::pair(LOSSY, 99, 400);
    s.connect();
    let ca = s.a.open_channel(s.now, ChannelOptions::new("a")).unwrap();
    let cb = s.b.open_channel(s.now, ChannelOptions::new("b")).unwrap();
    assert_eq!((ca % 2, cb % 2), (0, 1), "stream id parity");
    let n = 200;
    for i in 0..n {
        s.a.send(s.now, ca, &msg(i, 100 + i), false).unwrap();
        s.b.send(s.now, cb, &msg(i, 50 + 3 * i), true).unwrap();
    }
    assert!(s.run(Duration::from_secs(300), |s| s.data_b(ca).len() == n
        && data_of(&s.ev_a, cb).len() == n));
    assert_eq!(data_of(&s.ev_a, cb)[n - 1], msg(n - 1, 50 + 3 * (n - 1)));
}

#[test]
fn large_messages_fragmented() {
    for (seed, link) in [(3, LOSSY), (4, CLEAN)] {
        let mut s = Sim::pair(link, seed, 1200);
        s.connect();
        let ch = s.a.open_channel(s.now, ChannelOptions::new("big")).unwrap();
        let sent = vec![msg(1, 60_000), msg(2, 200_000), msg(3, 262_144), msg(4, 10)];
        for m in &sent {
            s.a.send(s.now, ch, m, true).unwrap();
        }
        assert!(s.run(Duration::from_secs(300), |s| s.data_b(ch).len()
            == sent.len()));
        assert_eq!(s.data_b(ch), sent);
        assert_eq!(
            s.a.send(s.now, ch, &vec![0; 262_145], true),
            Err(Error::MessageTooLarge {
                size: 262_145,
                max: 262_144
            })
        );
    }
}

#[test]
fn unordered_all_arrive() {
    let mut s = Sim::pair(LOSSY, 7, 500);
    s.connect();
    let ch =
        s.a.open_channel(s.now, ChannelOptions::new("u").with_ordered(false))
            .unwrap();
    // Until the DCEP ACK arrives messages go ordered; let it arrive.
    s.run(Duration::from_secs(5), |_| false);
    let sent: Vec<Vec<u8>> = (0..300).map(|i| msg(i, 20 + i % 700)).collect();
    for m in &sent {
        s.a.send(s.now, ch, m, true).unwrap();
    }
    assert!(s.run(Duration::from_secs(300), |s| s.data_b(ch).len()
        == sent.len()));
    let mut got = s.data_b(ch);
    let in_order = got == sent;
    got.sort();
    let mut want = sent.clone();
    want.sort();
    assert_eq!(got, want);
    // With reordering on the link, unordered delivery shows.
    assert!(!in_order);
    assert_eq!(
        s.b.channel(ch).map(|c| (c.ordered, c.label)),
        Some((false, "u".to_owned()))
    );
}

fn partial_reliability(rel: Reliability, ordered: bool, seed: u64) {
    let link = Link {
        loss: 200,
        dup: 20,
        delay_ms: 20,
        jitter_ms: 20,
    };
    let mut s = Sim::pair(link, seed, 600);
    s.connect();
    let pr =
        s.a.open_channel(
            s.now,
            ChannelOptions::new("pr")
                .with_ordered(ordered)
                .with_reliability(rel),
        )
        .unwrap();
    let rel_ch = s.a.open_channel(s.now, ChannelOptions::new("rel")).unwrap();
    // Let the DCEP handshake finish so that unordered sending applies.
    assert!(
        s.run(Duration::from_secs(60), |s| s.data_b(rel_ch).is_empty()
            && count(&s.ev_b, |e| matches!(e, Event::ChannelOpen { .. }))
                == 2)
    );
    s.run(Duration::from_secs(5), |_| false);
    let n = 300;
    for i in 0..n {
        // Some single-fragment, some multi-fragment messages.
        s.a.send(
            s.now,
            pr,
            &msg(i, if i % 5 == 0 { 2000 } else { 100 }),
            true,
        )
        .unwrap();
        if i % 20 == 0 {
            // Spread over time so that lifetimes expire for some.
            s.run(Duration::from_millis(30), |_| false);
        }
    }
    s.a.send(s.now, rel_ch, b"after", false).unwrap();
    assert!(s.run(Duration::from_secs(120), |s| s.data_b(rel_ch).len() == 1));
    // Everything on the PR channel is acknowledged or abandoned.
    assert!(
        s.run(Duration::from_secs(120), |s| s.a.buffered_amount(pr) == 0),
        "buffered {}",
        s.a.buffered_amount(pr)
    );
    let got = s.data_b(pr);
    if rel == Reliability::MaxRetransmits(0) {
        assert!(got.len() < n, "{rel:?}: nothing was lost");
    }
    // Lifetimes below RTO.Min lose a lot; retransmission limits recover most.
    let min = if matches!(rel, Reliability::MaxLifetime(_)) {
        0
    } else {
        n / 3
    };
    assert!(got.len() > min, "{rel:?}: only {} arrived", got.len());
    let ids: Vec<u32> = got
        .iter()
        .map(|m| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
        .collect();
    for (m, &i) in got.iter().zip(&ids) {
        assert_eq!(*m, msg(i as usize, if i % 5 == 0 { 2000 } else { 100 }));
    }
    if ordered {
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
    }
    // Nothing is blocked: a later message on the PR channel over a clean link arrives
    // (possibly after complete messages a FORWARD TSN releases).
    s.link = CLEAN;
    s.a.send(s.now, pr, b"last", true).unwrap();
    assert!(
        s.run(Duration::from_secs(30), |s| s
            .data_b(pr)
            .last()
            .map(Vec::as_slice)
            == Some(&b"last"[..])),
        "{rel:?} ordered={ordered} seed={seed}"
    );
    if ordered {
        let ids: Vec<u32> = s.data_b(pr)[..s.data_b(pr).len() - 1]
            .iter()
            .map(|m| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
            .collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
    }
}

#[test]
fn max_retransmits_zero_with_forward_tsn() {
    for seed in seeds(2) {
        partial_reliability(Reliability::MaxRetransmits(0), true, 10 + seed);
        partial_reliability(Reliability::MaxRetransmits(0), false, 20 + seed);
        partial_reliability(Reliability::MaxRetransmits(2), true, 30 + seed);
    }
}

#[test]
fn max_lifetime_with_forward_tsn() {
    for seed in seeds(2) {
        partial_reliability(Reliability::MaxLifetime(100), true, 40 + seed);
        partial_reliability(Reliability::MaxLifetime(50), false, 50 + seed);
    }
}

#[test]
fn empty_messages() {
    let mut s = Sim::pair(CLEAN, 1, 1200);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("e")).unwrap();
    s.a.send(s.now, ch, b"", false).unwrap();
    s.a.send(s.now, ch, b"", true).unwrap();
    s.a.send(s.now, ch, b"x", false).unwrap();
    assert!(s.run(Duration::from_secs(5), |s| s.data_b(ch).len() == 3));
    let kinds: Vec<(Vec<u8>, bool)> = s
        .ev_b
        .iter()
        .filter_map(|e| match e {
            Event::ChannelData { data, binary, .. } => Some((data.clone(), *binary)),
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        vec![(vec![], false), (vec![], true), (b"x".to_vec(), false)]
    );
}

#[test]
fn buffered_amount_low_and_backpressure() {
    let mut ca = Config::new(true);
    ca.max_buffered_amount = 20_000;
    let mut s = Sim::new(ca, Config::new(false), CLEAN, 5);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("bp")).unwrap();
    s.a.set_buffered_amount_low_threshold(ch, 5_000);
    let mut queued = 0;
    while s.a.send(s.now, ch, &[7; 1000], true).unwrap() {
        queued += 1;
        assert!(queued < 100);
    }
    assert_eq!(queued, 21); // 21 000 > 20 000 refuses the 22nd
    assert_eq!(s.a.buffered_amount(ch), 21_000);
    assert!(
        s.run(Duration::from_secs(10), |s| count(&s.ev_a, |e| matches!(e,
        Event::BufferedAmountLow { stream } if *stream == ch))
            == 1)
    );
    assert!(s.a.buffered_amount(ch) <= 5_000);
    assert!(s.a.send(s.now, ch, &[7; 1000], true).unwrap());
    assert!(s.run(Duration::from_secs(10), |s| s.data_b(ch).len() == 22));
    assert!(s.run(Duration::from_secs(10), |s| s.a.buffered_amount(ch) == 0));
    // Fired once per crossing: 1 000 bytes never went above the threshold again.
    assert_eq!(
        count(&s.ev_a, |e| matches!(e, Event::BufferedAmountLow { .. })),
        1
    );
}

#[test]
fn channel_close_by_stream_reset() {
    for seed in seeds(3) {
        let mut s = Sim::pair(if seed == 1 { CLEAN } else { LOSSY }, seed, 1200);
        s.connect();
        let ch = s.a.open_channel(s.now, ChannelOptions::new("c")).unwrap();
        let other =
            s.a.open_channel(s.now, ChannelOptions::new("keep"))
                .unwrap();
        for i in 0..50 {
            s.a.send(s.now, ch, &msg(i, 500), true).unwrap();
        }
        // Close right away: queued data still goes out first.
        s.a.close_channel(s.now, ch);
        assert_eq!(
            s.a.send(s.now, ch, b"no", true),
            Err(Error::ChannelClosed(ch))
        );
        let closed = |ev: &[Event]| {
            count(
                ev,
                |e| matches!(e, Event::ChannelClose { stream } if *stream == ch),
            )
        };
        assert!(s.run(Duration::from_secs(120), |s| closed(&s.ev_a) == 1
            && closed(&s.ev_b) == 1));
        assert_eq!(s.data_b(ch).len(), 50);
        assert!(s.a.channel(ch).is_none() && s.b.channel(ch).is_none());
        // The stream id is reusable, with SSNs from 0.
        let again = s.a.open_channel(s.now, ChannelOptions::new("c2")).unwrap();
        assert_eq!(again, ch);
        s.a.send(s.now, again, b"second life", false).unwrap();
        s.a.send(s.now, other, b"other", false).unwrap();
        assert!(s.run(Duration::from_secs(60), |s| s.data_b(ch).len() == 51
            && s.data_b(other).len() == 1));
        assert_eq!(s.data_b(ch)[50], b"second life");
        assert_eq!(closed(&s.ev_a), 1);
    }
}

#[test]
fn remote_closes_channel() {
    let mut s = Sim::pair(CLEAN, 8, 1200);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("c")).unwrap();
    s.a.send(s.now, ch, b"hi", false).unwrap();
    assert!(s.run(Duration::from_secs(5), |s| s.data_b(ch).len() == 1));
    s.b.close_channel(s.now, ch);
    let closed = |ev: &[Event]| count(ev, |e| matches!(e, Event::ChannelClose { .. }));
    assert!(s.run(Duration::from_secs(10), |s| closed(&s.ev_a) == 1
        && closed(&s.ev_b) == 1));
    s.run(Duration::from_secs(5), |_| false);
    assert_eq!(closed(&s.ev_a), 1);
    assert_eq!(
        s.a.send(s.now, ch, b"x", false),
        Err(Error::UnknownChannel(ch))
    );
}

#[test]
fn simultaneous_init() {
    for seed in seeds(3) {
        let link = if seed == 1 { CLEAN } else { LOSSY };
        let mut s = Sim::pair(link, seed, 1200);
        s.a.connect(s.now);
        s.b.connect(s.now);
        let ca = s.a.open_channel(s.now, ChannelOptions::new("x")).unwrap();
        let cb = s.b.open_channel(s.now, ChannelOptions::new("y")).unwrap();
        s.a.send(s.now, ca, b"from a", false).unwrap();
        s.b.send(s.now, cb, b"from b", false).unwrap();
        assert!(s.run(Duration::from_secs(120), |s| s.data_b(ca).len() == 1
            && data_of(&s.ev_a, cb).len() == 1));
        assert_eq!(count(&s.ev_a, |e| *e == Event::Connected), 1);
        assert_eq!(count(&s.ev_b, |e| *e == Event::Connected), 1);
    }
}

#[test]
fn send_before_established() {
    let mut s = Sim::pair(LOSSY, 21, 1200);
    let ch =
        s.a.open_channel(s.now, ChannelOptions::new("early"))
            .unwrap();
    let neg_a =
        s.a.open_channel(s.now, ChannelOptions::new("neg").with_negotiated(100))
            .unwrap();
    let neg_b =
        s.b.open_channel(s.now, ChannelOptions::new("neg").with_negotiated(100))
            .unwrap();
    assert_eq!((neg_a, neg_b), (100, 100));
    assert_eq!(
        s.b.open_channel(s.now, ChannelOptions::new("dup").with_negotiated(100)),
        Err(Error::StreamInUse(100))
    );
    s.a.send(s.now, ch, b"early bird", false).unwrap();
    s.b.send(s.now, 100, b"neg data", true).unwrap();
    s.a.connect(s.now);
    assert!(s.run(Duration::from_secs(120), |s| s.data_b(ch).len() == 1
        && data_of(&s.ev_a, 100).len() == 1));
    // Connected comes first, then the channels.
    assert_eq!(s.ev_a[0], Event::Connected);
    assert!(matches!(&s.ev_a[1], Event::ChannelOpen { .. }));
    assert!(
        s.ev_b
            .iter()
            .any(|e| matches!(e, Event::ChannelOpen { stream: 100, .. }))
    );
    assert!(s.b.channel(100).unwrap().negotiated);
    assert!(!s.b.channel(ch).unwrap().negotiated);
}

#[test]
fn graceful_shutdown() {
    let mut s = Sim::pair(LOSSY, 31, 1200);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("s")).unwrap();
    for i in 0..30 {
        s.a.send(s.now, ch, &msg(i, 3000), true).unwrap();
    }
    s.a.shutdown(s.now);
    assert_eq!(
        s.a.send(s.now, ch, b"x", true),
        Err(Error::AssociationClosed)
    );
    assert!(s.run(Duration::from_secs(120), |s| s.a.is_closed()
        && s.b.is_closed()));
    assert_eq!(s.data_b(ch).len(), 30);
    assert_eq!(s.ev_a.last(), Some(&Event::Closed));
    assert_eq!(s.ev_b.last(), Some(&Event::Closed));
    assert!(
        s.ev_b
            .iter()
            .any(|e| matches!(e, Event::ChannelClose { .. }))
    );
    assert_eq!(s.a.poll_timeout(), None);
}

#[test]
fn abort_closes_peer() {
    let mut s = Sim::pair(CLEAN, 41, 1200);
    s.connect();
    s.b.abort();
    assert!(s.b.is_closed());
    assert!(s.run(Duration::from_secs(5), |s| s.a.is_closed()));
    assert_eq!(s.ev_a.last(), Some(&Event::Closed));
    assert_eq!(
        s.a.open_channel(s.now, ChannelOptions::new("x")),
        Err(Error::AssociationClosed)
    );
}

#[test]
fn failure_when_peer_disappears() {
    let mut s = Sim::pair(CLEAN, 51, 1200);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("f")).unwrap();
    s.run(Duration::from_secs(1), |_| false);
    s.blackhole = true;
    let t0 = s.now;
    s.a.send(s.now, ch, b"into the void", false).unwrap();
    assert!(s.run(Duration::from_secs(300), |s| s.a.is_closed()));
    let took = s.now.duration_since(t0);
    // 0.2..1 s, then doubling up to 10 s: 11 timeouts.
    assert!(
        took > Duration::from_secs(40) && took < Duration::from_secs(120),
        "{took:?}"
    );
    assert_eq!(s.ev_a.last(), Some(&Event::Closed));
    assert!(s.ev_a.contains(&Event::ChannelClose { stream: ch }));
}

#[test]
fn init_gives_up_without_peer() {
    let mut s = Sim::pair(CLEAN, 61, 1200);
    s.blackhole = true;
    s.a.connect(s.now);
    assert!(s.run(Duration::from_secs(300), |s| s.a.is_closed()));
    assert_eq!(s.ev_a, vec![Event::Closed]);
}

#[test]
fn ten_megabytes_lossless() {
    let mut s = Sim::pair(CLEAN, 71, 1200);
    s.connect();
    let ch =
        s.a.open_channel(s.now, ChannelOptions::new("bulk"))
            .unwrap();
    let chunk = vec![0x5a; 64 * 1024];
    let total = 10 * 1024 * 1024;
    let mut sent = 0;
    let mut received = 0;
    let t0 = s.now;
    let wall = Instant::now();
    while received < total {
        while sent < total && s.a.send(s.now, ch, &chunk, true).unwrap() {
            sent += chunk.len();
        }
        assert!(s.step());
        received = s
            .ev_b
            .iter()
            .map(|e| match e {
                Event::ChannelData { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert!(
            s.now.duration_since(t0) < Duration::from_secs(30),
            "stalled at {received}"
        );
    }
    let took = s.now.duration_since(t0);
    // 40 ms RTT with a 1 MiB window allows ~25 MB/s; slow start costs a little.
    assert!(
        took < Duration::from_secs(3),
        "10 MB took {took:?} of simulated time"
    );
    assert!(wall.elapsed() < Duration::from_secs(60));
}

#[test]
fn oversized_incoming_message_aborts() {
    let ca = Config::new(true);
    let cb = Config::new(false).with_max_receive_message_size(10_000);
    let mut s = Sim::new(ca, cb, CLEAN, 81);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("x")).unwrap();
    s.a.send(s.now, ch, &[1; 9_000], true).unwrap();
    s.a.send(s.now, ch, &vec![1; 20_000], true).unwrap();
    assert!(s.run(Duration::from_secs(10), |s| s.a.is_closed()
        && s.b.is_closed()));
    assert_eq!(s.data_b(ch).len(), 1);
}

#[test]
fn channel_info_and_protocol() {
    let mut s = Sim::pair(CLEAN, 91, 1200);
    s.connect();
    let ch =
        s.a.open_channel(
            s.now,
            ChannelOptions::new("lbl")
                .with_protocol("proto")
                .with_reliability(Reliability::MaxLifetime(500)),
        )
        .unwrap();
    assert!(s.run(Duration::from_secs(5), |s| s.b.channel(ch).is_some()));
    let info = s.b.channel(ch).unwrap();
    assert_eq!(info.label, "lbl");
    assert_eq!(info.protocol, "proto");
    assert_eq!(info.reliability, Reliability::MaxLifetime(500));
    assert!(s.ev_b.contains(&Event::ChannelOpen {
        stream: ch,
        label: "lbl".into(),
        protocol: "proto".into()
    }));
    assert_eq!(
        s.a.send(s.now, 77, b"x", false),
        Err(Error::UnknownChannel(77))
    );
}

#[test]
fn garbage_is_ignored() {
    let mut s = Sim::pair(CLEAN, 101, 1200);
    s.connect();
    let now = s.now;
    for len in 0..200 {
        let p: Vec<u8> = (0..len).map(|i| (i * 31 + len) as u8).collect();
        s.a.handle_packet(now, &p);
    }
    let ch = s.a.open_channel(s.now, ChannelOptions::new("ok")).unwrap();
    s.a.send(s.now, ch, b"still fine", false).unwrap();
    assert!(s.run(Duration::from_secs(5), |s| s.data_b(ch).len() == 1));
}

fn idata_config(client: bool, interleave: bool, scheduler: Scheduler) -> Config {
    Config::new(client)
        .with_message_interleaving(interleave)
        .with_scheduler(scheduler)
}

/// Opens channels from `a` and waits until `b` has them all and they are acknowledged.
fn open_all(s: &mut Sim, opts: &[ChannelOptions]) -> Vec<u16> {
    let ids: Vec<u16> = opts
        .iter()
        .map(|o| s.a.open_channel(s.now, o.clone()).unwrap())
        .collect();
    let n = ids.len();
    assert!(
        s.run(Duration::from_secs(60), |s| count(&s.ev_b, |e| matches!(
            e,
            Event::ChannelOpen { .. }
        )) == n)
    );
    s.run(Duration::from_secs(2), |_| false);
    ids
}

#[test]
fn message_interleaving_negotiation() {
    for (ia, ib, b_connects) in [
        (true, true, false),
        (true, true, true),
        (true, false, false),
        (false, true, true),
        (false, false, false),
    ] {
        let mut s = Sim::new(
            Config::new(true).with_message_interleaving(ia),
            Config::new(false).with_message_interleaving(ib),
            CLEAN,
            3,
        );
        assert!(!s.a.message_interleaving());
        if b_connects {
            s.b.connect(s.now);
            assert!(s.run(Duration::from_secs(60), |s| s.a.is_established()
                && s.b.is_established()));
        } else {
            s.connect();
        }
        let on = ia && ib;
        assert_eq!(
            (s.a.message_interleaving(), s.b.message_interleaving()),
            (on, on),
            "{ia} {ib}"
        );
        let ch = s.a.open_channel(s.now, ChannelOptions::new("x")).unwrap();
        let m = msg(1, 5000);
        s.a.send(s.now, ch, &m, true).unwrap();
        assert!(s.run(Duration::from_secs(5), |s| s.data_b(ch).len() == 1));
        assert_eq!(s.data_b(ch)[0], m);
        // RFC 8260 §2.2: I-DATA only, or DATA only, on the wire.
        assert_eq!((s.seen[64], s.seen[0]), (on, !on), "{ia} {ib}");
    }
}

/// Simulated time from queueing a 200 kB message on one channel and then 4 bytes on
/// another until each arrives: (small, big).
fn head_of_line(interleave: bool, scheduler: Scheduler) -> (Duration, Duration) {
    let mut s = Sim::new(
        idata_config(true, interleave, scheduler),
        idata_config(false, interleave, scheduler),
        CLEAN,
        11,
    );
    s.connect();
    let ids = open_all(
        &mut s,
        &[ChannelOptions::new("big"), ChannelOptions::new("small")],
    );
    let big = msg(7, 200_000);
    s.a.send(s.now, ids[0], &big, true).unwrap();
    s.a.send(s.now, ids[1], b"ping", false).unwrap();
    let t0 = s.now;
    assert!(s.run(Duration::from_secs(30), |s| s.data_b(ids[1]).len() == 1));
    let small = s.now - t0;
    assert!(s.run(Duration::from_secs(30), |s| s.data_b(ids[0]).len() == 1));
    assert_eq!(s.data_b(ids[0])[0], big);
    (small, s.now - t0)
}

#[test]
fn head_of_line_blocking() {
    // I-DATA with a scheduler that alternates: the small message overtakes the big one.
    for sched in [
        Scheduler::RoundRobin,
        Scheduler::RoundRobinPerPacket,
        Scheduler::FairCapacity,
        Scheduler::WeightedFairQueueing,
        Scheduler::Priority,
    ] {
        let (small, big) = head_of_line(true, sched);
        assert!(
            small < Duration::from_millis(60) && small * 4 < big,
            "{sched:?}: small {small:?} big {big:?}"
        );
    }
    // First come, first served keeps queueing order even with I-DATA, and without I-DATA a
    // started message always goes out whole.
    for (interleave, sched) in [
        (true, Scheduler::FirstComeFirstServed),
        (false, Scheduler::FirstComeFirstServed),
        (false, Scheduler::RoundRobin),
        (false, Scheduler::WeightedFairQueueing),
    ] {
        let (small, big) = head_of_line(interleave, sched);
        assert!(
            small >= big,
            "{interleave} {sched:?}: small {small:?} big {big:?}"
        );
    }
}

/// Queues 512 KiB in 8 KiB messages on each of two channels (all of the first, then all of
/// the second) and returns the bytes of each delivered once 256 KiB have arrived.
fn shares(interleave: bool, scheduler: Scheduler, prio: [u16; 2]) -> [usize; 2] {
    let mut s = Sim::new(
        idata_config(true, interleave, scheduler),
        idata_config(false, interleave, scheduler),
        CLEAN,
        13,
    );
    s.connect();
    let ids = open_all(
        &mut s,
        &[
            ChannelOptions::new("a").with_priority(prio[0]),
            ChannelOptions::new("b").with_priority(prio[1]),
        ],
    );
    for &c in &ids {
        for i in 0..64 {
            assert_eq!(s.a.send(s.now, c, &msg(i, 8192), true), Ok(true));
        }
    }
    let got = |s: &Sim, c: u16| s.data_b(c).iter().map(Vec::len).sum::<usize>();
    assert!(
        s.run(Duration::from_secs(60), |s| got(s, ids[0]) + got(s, ids[1])
            >= 256 << 10)
    );
    let r = [got(&s, ids[0]), got(&s, ids[1])];
    // Everything still arrives, in order.
    assert!(
        s.run(Duration::from_secs(60), |s| s.data_b(ids[0]).len() == 64
            && s.data_b(ids[1]).len() == 64)
    );
    for &c in &ids {
        assert!(
            s.data_b(c)
                .iter()
                .enumerate()
                .all(|(i, m)| *m == msg(i, 8192))
        );
    }
    r
}

#[test]
fn scheduler_fairness() {
    for interleave in [true, false] {
        // FCFS: the first channel's queue goes first.
        let [a, b] = shares(interleave, Scheduler::FirstComeFirstServed, [256, 256]);
        assert_eq!(b, 0, "fcfs {interleave}: {a} {b}");
        // Equal shares.
        for sched in [
            Scheduler::RoundRobin,
            Scheduler::RoundRobinPerPacket,
            Scheduler::FairCapacity,
            Scheduler::WeightedFairQueueing,
        ] {
            let [a, b] = shares(interleave, sched, [256, 256]);
            let r = b as f64 / a as f64;
            assert!(
                (0.75..=1.34).contains(&r),
                "{sched:?} {interleave}: {a} {b}"
            );
        }
        // Fair capacity ignores priorities.
        let [a, b] = shares(interleave, Scheduler::FairCapacity, [256, 1024]);
        let r = b as f64 / a as f64;
        assert!((0.75..=1.34).contains(&r), "fc {interleave}: {a} {b}");
        // Weighted fair queueing: 3:1.
        let [a, b] = shares(interleave, Scheduler::WeightedFairQueueing, [256, 768]);
        let r = b as f64 / a as f64;
        assert!((2.4..=3.6).contains(&r), "wfq {interleave}: {a} {b} ({r})");
        // Strict priority: the higher channel (the second one) first.
        let [a, b] = shares(interleave, Scheduler::Priority, [256, 1024]);
        assert_eq!(a, 0, "priority {interleave}: {a} {b}");
    }
}

#[test]
fn priority_changes_take_effect() {
    let mut s = Sim::new(
        idata_config(true, true, Scheduler::Priority),
        Config::new(false),
        CLEAN,
        17,
    );
    s.connect();
    let ids = open_all(
        &mut s,
        &[ChannelOptions::new("a"), ChannelOptions::new("b")],
    );
    assert_eq!(s.a.channel(ids[0]).map(|c| c.priority), Some(256));
    s.a.set_channel_priority(ids[1], 1024).unwrap();
    assert_eq!(s.a.channel(ids[1]).map(|c| c.priority), Some(1024));
    assert_eq!(
        s.a.set_channel_priority(99, 1),
        Err(Error::UnknownChannel(99))
    );
    for &c in &ids {
        for i in 0..16 {
            s.a.send(s.now, c, &msg(i, 4000), true).unwrap();
        }
    }
    assert!(
        s.run(Duration::from_secs(60), |s| s.data_b(ids[0]).len() == 16
            && s.data_b(ids[1]).len() == 16)
    );
    // Every message of the raised channel arrived before any of the other.
    let order: Vec<u16> = s
        .ev_b
        .iter()
        .filter_map(|e| match e {
            Event::ChannelData { stream, .. } => Some(*stream),
            _ => None,
        })
        .collect();
    assert_eq!(order[..16], [ids[1]; 16], "{order:?}");
}

#[test]
fn round_robin_per_packet_fills_packets_from_one_stream() {
    for (sched, per_packet) in [
        (Scheduler::RoundRobinPerPacket, true),
        (Scheduler::RoundRobin, false),
    ] {
        let mut s = Sim::new(
            idata_config(true, true, sched),
            Config::new(false),
            CLEAN,
            19,
        );
        s.connect();
        let ids = open_all(
            &mut s,
            &[ChannelOptions::new("a"), ChannelOptions::new("b")],
        );
        s.mixed = 0;
        for i in 0..300 {
            for &c in &ids {
                s.a.send(s.now, c, &msg(i, 100), true).unwrap();
            }
        }
        assert!(
            s.run(Duration::from_secs(60), |s| s.data_b(ids[0]).len() == 300
                && s.data_b(ids[1]).len() == 300)
        );
        if per_packet {
            assert!(s.mixed <= 2, "{sched:?}: {} mixed packets", s.mixed);
        } else {
            assert!(s.mixed > 20, "{sched:?}: {} mixed packets", s.mixed);
        }
    }
}

/// I-DATA over a lossy, reordering link with a reliable channel interleaved with partially
/// reliable ones: abandoned messages are skipped with I-FORWARD-TSN (ordered: by MID per
/// stream; unordered: by message), the reliable channel is intact and nothing stays blocked.
#[test]
fn interleaved_partial_reliability() {
    for seed in seeds(3) {
        let link = Link {
            loss: 150,
            dup: 30,
            delay_ms: 20,
            jitter_ms: 40,
        };
        let cfg = |c| idata_config(c, true, Scheduler::RoundRobin).with_mtu(500);
        let mut s = Sim::new(cfg(true), cfg(false), link, 200 + seed);
        s.connect();
        assert!(s.a.message_interleaving());
        let ids = open_all(
            &mut s,
            &[
                ChannelOptions::new("rel"),
                ChannelOptions::new("pr-o").with_reliability(Reliability::MaxRetransmits(1)),
                ChannelOptions::new("pr-u")
                    .with_ordered(false)
                    .with_reliability(Reliability::MaxLifetime(150)),
            ],
        );
        for i in 0..100 {
            if i % 5 == 0 {
                s.a.send(s.now, ids[0], &msg(i / 5, 3000), true).unwrap();
            }
            s.a.send(s.now, ids[1], &msg(i, 1500), true).unwrap();
            s.a.send(s.now, ids[2], &msg(i, 1500), true).unwrap();
            if i % 10 == 0 {
                s.run(Duration::from_millis(20), |_| false);
            }
        }
        assert!(
            s.run(Duration::from_secs(300), |s| s.data_b(ids[0]).len() == 20
                && ids.iter().all(|&c| s.a.buffered_amount(c) == 0)),
            "seed {seed}"
        );
        assert!(s.seen[194], "seed {seed}: no I-FORWARD-TSN");
        let rel = s.data_b(ids[0]);
        assert!(rel.iter().enumerate().all(|(i, m)| *m == msg(i, 3000)));
        let check = |got: Vec<Vec<u8>>, ordered: bool| {
            let ids: Vec<u32> = got
                .iter()
                .map(|m| u32::from_be_bytes([m[0], m[1], m[2], m[3]]))
                .collect();
            for (m, &i) in got.iter().zip(&ids) {
                assert_eq!(*m, msg(i as usize, 1500));
            }
            if ordered {
                assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
            }
            got.len()
        };
        let n = check(s.data_b(ids[1]), true) + check(s.data_b(ids[2]), false);
        assert!(n < 200, "seed {seed}: nothing was abandoned");
        // Nothing is blocked afterwards.
        s.link = CLEAN;
        s.a.send(s.now, ids[1], b"last", true).unwrap();
        s.a.send(s.now, ids[2], b"last", true).unwrap();
        assert!(
            s.run(Duration::from_secs(30), |s| [ids[1], ids[2]].iter().all(
                |&c| s.data_b(c).last().map(Vec::as_slice) == Some(&b"last"[..])
            )),
            "seed {seed}"
        );
    }
}

/// Many large messages queued on many channels at once: with I-DATA the sender must not
/// start more of them than the peer can hold, or the peer's window fills with messages none of
/// which can complete (each channel's message is only partly there) and nothing moves.
#[test]
fn many_concurrent_large_messages() {
    for (channels, size, window) in [
        (8, 250_000, 1 << 20),
        (40, 64_000, 1 << 20),
        (6, 200_000, 256 << 10),
    ] {
        for (interleave, sched) in [
            (true, Scheduler::WeightedFairQueueing),
            (true, Scheduler::RoundRobin),
            (false, Scheduler::WeightedFairQueueing),
        ] {
            let ca = idata_config(true, interleave, sched);
            let cb = idata_config(false, interleave, sched)
                .with_receive_window(window)
                .with_max_buffered_amount(4 << 20);
            let mut s = Sim::new(ca, cb, CLEAN, 23);
            s.connect();
            let opts: Vec<ChannelOptions> = (0..channels)
                .map(|i| ChannelOptions::new(&format!("c{i}")))
                .collect();
            let ids = open_all(&mut s, &opts);
            for (i, &c) in ids.iter().enumerate() {
                s.a.send(s.now, c, &msg(i, size), true).unwrap();
            }
            let t0 = s.now;
            assert!(
                s.run(Duration::from_secs(60), |s| ids
                    .iter()
                    .all(|&c| s.data_b(c).len() == 1)),
                "{channels} x {size} window {window} {interleave} {sched:?}: {} delivered",
                ids.iter().filter(|&&c| s.data_b(c).len() == 1).count()
            );
            let took = s.now - t0;
            assert!(
                took < Duration::from_secs(5),
                "{channels} x {size} window {window} {interleave} {sched:?}: {took:?}"
            );
            for (i, &c) in ids.iter().enumerate() {
                assert_eq!(s.data_b(c)[0], msg(i, size));
            }
        }
    }
}

/// RFC 9260 §8.3: an idle association sends HEARTBEATs, which measure the RTT; with data
/// flowing it does not need them.
#[test]
fn heartbeats_measure_rtt_when_idle() {
    let mut s = Sim::pair(CLEAN, 71, 1200);
    s.connect();
    assert_eq!(s.a.rtt(), None);
    s.run(Duration::from_secs(20), |_| false);
    assert!(!s.seen[4], "HEARTBEAT before HB.interval");
    s.run(Duration::from_secs(100), |_| false);
    assert!(s.seen[4], "no HEARTBEAT from a");
    let rtt = s.a.rtt().unwrap();
    // 20 ms each way.
    assert!(
        rtt >= Duration::from_millis(40) && rtt < Duration::from_millis(45),
        "{rtt:?}"
    );
    assert!(s.b.rtt().is_some());
    assert!(s.a.is_established() && s.b.is_established());
    // Both sides send one per 30 s + RTO (about 3 in 120 s), each answered, plus the
    // handshake.
    assert!(s.packets <= 24, "{} packets", s.packets);
}

/// An idle association notices a vanished peer through unanswered HEARTBEATs:
/// Path.Max.Retrans (= max_retransmissions) errors, then failure.
#[test]
fn heartbeats_detect_vanished_peer() {
    let mut s = Sim::pair(CLEAN, 72, 1200);
    s.connect();
    let ch =
        s.a.open_channel(s.now, ChannelOptions::new("idle"))
            .unwrap();
    s.run(Duration::from_secs(1), |_| false);
    s.blackhole = true;
    let t0 = s.now;
    assert!(s.run(Duration::from_secs(600), |s| s.a.is_closed()));
    let took = s.now.duration_since(t0);
    // 30 s + RTO of idleness, then 11 HEARTBEATs with a doubling RTO capped at 10 s.
    assert!(
        took > Duration::from_secs(60) && took < Duration::from_secs(150),
        "{took:?}"
    );
    assert_eq!(s.ev_a.last(), Some(&Event::Closed));
    assert!(s.ev_a.contains(&Event::ChannelClose { stream: ch }));

    // Without HEARTBEATs an idle association never notices.
    let cfg = |c| Config::new(c).with_heartbeat_interval(None);
    let mut s = Sim::new(cfg(true), cfg(false), CLEAN, 73);
    s.connect();
    s.blackhole = true;
    s.run(Duration::from_secs(600), |_| false);
    assert!(s.a.is_established() && !s.seen[4]);
}

/// A lost HEARTBEAT ACK costs one error, not the association: the next HEARTBEAT answered
/// clears the count.
#[test]
fn heartbeats_survive_loss() {
    for seed in seeds(4) {
        // 15 % each way: about 28 % of HEARTBEATs go unanswered.
        let link = Link {
            loss: 150,
            dup: 0,
            delay_ms: 20,
            jitter_ms: 10,
        };
        let mut s = Sim::pair(link, 80 + seed, 1200);
        s.connect();
        s.run(Duration::from_secs(1800), |_| false);
        assert!(s.a.is_established() && s.b.is_established(), "seed {seed}");
        assert!(s.a.rtt().is_some());
    }
}

/// RFC 9653: both sides announce SCTP over DTLS by default and send zero checksums after
/// the handshake; when one side does not, every packet carries the CRC-32C.
#[test]
fn zero_checksum_negotiation() {
    for (za, zb) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut s = Sim::new(
            Config::new(true).with_zero_checksum(za),
            Config::new(false).with_zero_checksum(zb),
            LOSSY,
            90,
        );
        assert!(!s.a.zero_checksum());
        s.connect();
        let on = za && zb;
        assert_eq!((s.a.zero_checksum(), s.b.zero_checksum()), (on, on));
        let ch = s.a.open_channel(s.now, ChannelOptions::new("z")).unwrap();
        for i in 0..50 {
            s.a.send(s.now, ch, &msg(i, 3000), true).unwrap();
        }
        assert!(s.run(Duration::from_secs(120), |s| s.data_b(ch).len() == 50));
        if on {
            // All but the INIT and COOKIE ECHO (and their retransmissions).
            assert!(s.zero_sums > 40, "{za} {zb}: {}", s.zero_sums);
        } else {
            assert_eq!(s.zero_sums, 0, "{za} {zb}");
        }
    }
}

/// RFC 9260 §5.2.2 / §5.2.4 case A: the peer restarts (a new association from the same
/// peer while established). Its channels are gone: ours close, `Restarted` follows, and the
/// association works again with new tags and TSNs.
#[test]
fn peer_restart() {
    for seed in seeds(4) {
        let link = if seed == 1 { CLEAN } else { LOSSY };
        let mut s = Sim::pair(link, 100 + seed, 1200);
        s.connect();
        let ch =
            s.a.open_channel(s.now, ChannelOptions::new("before"))
                .unwrap();
        for i in 0..20 {
            s.a.send(s.now, ch, &msg(i, 2000), true).unwrap();
        }
        assert!(s.run(Duration::from_secs(60), |s| s.data_b(ch).len() == 20));
        // b has data of its own queued when a restarts: it is dropped.
        let back =
            s.b.open_channel(s.now, ChannelOptions::new("back"))
                .unwrap();
        s.b.send(s.now, back, &msg(0, 50_000), true).unwrap();
        s.run(Duration::from_millis(30), |_| false);

        let idata = seed % 2 == 1;
        let cfg = Config::new(true).with_message_interleaving(idata);
        s.a = Association::with_random(cfg, s.now, ids(seed + 1000, 3));
        s.ev_a.clear();
        s.a.connect(s.now);
        assert!(s.run(Duration::from_secs(120), |s| s.a.is_established()
            && s.ev_b.contains(&Event::Restarted)));
        let i = s.ev_b.iter().position(|e| *e == Event::Restarted).unwrap();
        for stream in [ch, back] {
            let c = s.ev_b[..i]
                .iter()
                .position(|e| *e == Event::ChannelClose { stream });
            assert!(
                c.is_some(),
                "seed {seed}: no ChannelClose {stream} before Restarted"
            );
        }
        assert!(s.b.channel(ch).is_none() && s.b.channel(back).is_none());
        assert_eq!(s.b.buffered_amount(back), 0);
        assert_eq!(count(&s.ev_b, |e| *e == Event::Connected), 1);
        assert!(s.b.is_established());

        // Both directions work again, on reused stream ids.
        let a2 =
            s.a.open_channel(s.now, ChannelOptions::new("after"))
                .unwrap();
        let b2 =
            s.b.open_channel(s.now, ChannelOptions::new("after-b"))
                .unwrap();
        assert_eq!((a2, b2), (ch, back));
        let before = s.data_b(a2).len();
        for i in 0..20 {
            s.a.send(s.now, a2, &msg(i, 2000), true).unwrap();
            s.b.send(s.now, b2, &msg(i, 2000), true).unwrap();
        }
        assert!(s.run(Duration::from_secs(120), |s| s.data_b(a2).len()
            == before + 20
            && data_of(&s.ev_a, b2).len() == 20));
        assert_eq!(
            &s.data_b(a2)[before..],
            (0..20).map(|i| msg(i, 2000)).collect::<Vec<_>>()
        );
        assert_eq!(s.a.message_interleaving(), idata);
        // And it still shuts down cleanly.
        s.a.shutdown(s.now);
        assert!(s.run(Duration::from_secs(120), |s| s.a.is_closed()
            && s.b.is_closed()));
    }
}

/// A retransmitted INIT from the original handshake arriving late does not disturb the
/// association, and neither does an INIT from a peer that then goes away.
#[test]
fn stray_init_on_live_association() {
    let mut s = Sim::pair(CLEAN, 110, 1200);
    s.connect();
    let ch = s.a.open_channel(s.now, ChannelOptions::new("x")).unwrap();
    // A second association that sends INIT but never completes.
    let mut ghost = Association::with_random(Config::new(true), s.now, ids(111, 9));
    ghost.connect(s.now);
    let init = ghost.poll_transmit(s.now).unwrap();
    s.b.handle_packet(s.now, &init);
    s.flush();
    s.a.send(s.now, ch, b"still here", false).unwrap();
    assert!(s.run(Duration::from_secs(10), |s| s.data_b(ch).len() == 1));
    assert!(!s.ev_b.contains(&Event::Restarted));
}
