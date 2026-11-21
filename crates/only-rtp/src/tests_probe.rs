//! Bandwidth probing (ADR-050) on simulated links: ramp-up time to 90 % of the capacity and
//! overshoot with probing on and off, step changes, random loss and competing traffic. Every
//! run is deterministic (seeded xorshift; time is simulated).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::{BandwidthEstimator, ExtensionMap, ExtensionValues, Rtcp, RtpHeader, SendStream};
use crate::{TwccReceiver, TwccSender};

const PACKET: usize = 1200;
const ONE_WAY: Duration = Duration::from_millis(20);
/// Drop-tail limit of the bottleneck queue.
const MAX_QUEUE: Duration = Duration::from_millis(300);

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

struct Link<'a> {
    /// Capacity (bps) at a time since the start.
    capacity: &'a dyn Fn(Duration) -> f64,
    /// Competing traffic (bps) through the same queue, not under our control.
    cross: &'a dyn Fn(Duration) -> f64,
    loss_pct: u32,
    /// The application's own limit (an encoder at its top layer).
    app_max: f64,
    initial: u64,
    secs: u64,
    seed: u32,
    probing: bool,
    /// The estimator's maximum at a time since the start (`None`: the default bounds).
    max_at: Option<&'a dyn Fn(Duration) -> u64>,
    /// A network state estimate set from the start.
    nse: Option<u64>,
}

impl Default for Link<'_> {
    fn default() -> Self {
        Link {
            capacity: &|_| 10e6,
            cross: &|_| 0.0,
            loss_pct: 0,
            app_max: f64::INFINITY,
            initial: 300_000,
            secs: 30,
            seed: 1,
            probing: true,
            max_at: None,
            nse: None,
        }
    }
}

/// The estimate every 10 ms, the largest queueing delay seen, and the probe bytes sent.
struct Run {
    trace: Vec<(Duration, u64)>,
    max_queue: Duration,
    probe_bytes: usize,
    alr_seen: bool,
}

impl Run {
    /// The first time at or after `from` when the estimate reached `frac` of `cap`.
    fn reach(&self, from: Duration, cap: f64, frac: f64) -> Option<Duration> {
        self.trace
            .iter()
            .find(|&&(t, e)| t >= from && e as f64 >= frac * cap)
            .map(|&(t, _)| t.saturating_sub(from))
    }

    /// The first time at or after `from` when the estimate fell to `frac` of `cap`.
    fn fall(&self, from: Duration, cap: f64, frac: f64) -> Option<Duration> {
        self.trace
            .iter()
            .find(|&&(t, e)| t >= from && e as f64 <= frac * cap)
            .map(|&(t, _)| t.saturating_sub(from))
    }

    /// The largest estimate in `[from, to)` relative to `cap`.
    fn peak(&self, from: Duration, to: Duration, cap: f64) -> f64 {
        self.trace
            .iter()
            .filter(|&&(t, _)| t >= from && t < to)
            .map(|&(_, e)| e as f64 / cap)
            .fold(0.0, f64::max)
    }

    /// The mean estimate in `[from, to)` relative to `cap`.
    fn mean(&self, from: Duration, to: Duration, cap: f64) -> f64 {
        let v: Vec<f64> = self
            .trace
            .iter()
            .filter(|&&(t, _)| t >= from && t < to)
            .map(|&(_, e)| e as f64 / cap)
            .collect();
        v.iter().sum::<f64>() / v.len().max(1) as f64
    }
}

/// A sender with an encoder that follows the estimate (frames every 33 ms, sizes varying by
/// up to ±20 %, packets paced evenly over the frame interval), probe packets from
/// [`BandwidthEstimator::poll_probe`], a drop-tail FIFO bottleneck with 20 ms of propagation
/// each way, and transport-wide feedback every 100 ms coming back over the same delay.
fn run(link: &Link<'_>) -> Run {
    let t0 = Instant::now();
    let mut bwe = BandwidthEstimator::new(link.initial).with_probing(link.probing);
    if let Some(m) = link.max_at {
        bwe = bwe.with_bounds(crate::DEFAULT_MIN_BITRATE, m(Duration::ZERO));
    }
    bwe.set_network_state_estimate(link.nse);
    let mut tx = TwccSender::new();
    let mut rx = TwccReceiver::new();
    let mut rng = Rng(link.seed.max(1));
    let mut link_free = t0;
    let mut cross_credit = 0.0f64;
    let mut credit = 0.0f64;
    let mut frame_rate = 0.0f64;
    let mut arrivals: VecDeque<(Instant, u16)> = VecDeque::new();
    let mut feedback: VecDeque<(Instant, Rtcp)> = VecDeque::new();
    let mut out = Run {
        trace: Vec::new(),
        max_queue: Duration::ZERO,
        probe_bytes: 0,
        alr_seen: false,
    };
    // Enqueues `size` bytes at `now`: `Some(arrival)` unless dropped.
    let mut enqueue = |now: Instant, size: usize, rng: &mut Rng, max_queue: &mut Duration| {
        if rng.next() % 1000 < link.loss_pct * 10 {
            return None;
        }
        let start = link_free.max(now);
        let cap = (link.capacity)(start.saturating_duration_since(t0)).max(1.0);
        let end = start + Duration::from_secs_f64(size as f64 * 8.0 / cap);
        let queued = end.saturating_duration_since(now);
        if queued > MAX_QUEUE {
            return None;
        }
        *max_queue = (*max_queue).max(queued);
        link_free = end;
        Some(end + ONE_WAY)
    };
    for step in 0..link.secs * 1000 {
        let now = t0 + ms(step);
        let t = ms(step);
        if let Some(m) = link.max_at {
            let max = m(t);
            if max != bwe.bounds().1 {
                bwe.set_bounds(now, crate::DEFAULT_MIN_BITRATE, max);
            }
        }
        // Feedback arriving now.
        while feedback.front().is_some_and(|(at, _)| *at <= now) {
            let Some((_, Rtcp::TransportCc(fb))) = feedback.pop_front() else {
                continue;
            };
            let res = tx.on_feedback(now, &fb);
            bwe.on_packet_results(now, &res);
            out.alr_seen |= bwe.application_limited();
        }
        // Competing traffic shares the queue.
        cross_credit += (link.cross)(t) / 1000.0;
        while cross_credit >= (PACKET * 8) as f64 {
            cross_credit -= (PACKET * 8) as f64;
            let mut q = Duration::ZERO;
            let _ = enqueue(now, PACKET, &mut Rng(1), &mut q);
        }
        // Media: a new frame size every 33 ms.
        if step % 33 == 0 {
            let jitter = 0.8 + f64::from(rng.next() % 401) / 1000.0;
            frame_rate = (bwe.estimate() as f64).min(link.app_max) * jitter;
        }
        credit += frame_rate / 1000.0;
        while credit >= (PACKET * 8) as f64 {
            credit -= (PACKET * 8) as f64;
            let seq = tx.next_seq();
            tx.on_sent(seq, now, PACKET);
            if let Some(at) = enqueue(now, PACKET, &mut rng, &mut out.max_queue) {
                arrivals.push_back((at, seq));
            }
        }
        // Probes.
        while let Some(p) = bwe.poll_probe(now) {
            let size = p.size.min(PACKET);
            let seq = tx.next_seq();
            tx.on_sent_probe(seq, now, size, p.cluster);
            bwe.on_probe_sent(now, p.cluster, size);
            out.probe_bytes += size;
            if let Some(at) = enqueue(now, size, &mut rng, &mut out.max_queue) {
                arrivals.push_back((at, seq));
            }
        }
        // Arrivals (FIFO: in order) and feedback.
        while arrivals.front().is_some_and(|(at, _)| *at <= now) {
            if let Some((at, seq)) = arrivals.pop_front() {
                rx.on_received(seq, at);
            }
        }
        while let Some(fb) = rx.poll_feedback(now, 1, 2) {
            feedback.push_back((now + ONE_WAY, fb));
        }
        if step % 10 == 0 {
            out.trace.push((t, bwe.estimate()));
        }
    }
    out
}

fn secs(d: Option<Duration>) -> String {
    d.map_or_else(
        || "never".to_owned(),
        |d| format!("{:.2}s", d.as_secs_f64()),
    )
}

#[test]
fn probing_ramps_up_fixed_links() {
    for (cap, within, before_at_least) in [
        (0.5e6, ms(1500), ms(2000)),
        (2e6, ms(1500), ms(10_000)),
        (10e6, ms(2500), ms(30_000)),
    ] {
        let capacity = move |_| cap;
        let on = run(&Link {
            capacity: &capacity,
            ..Link::default()
        });
        let off = run(&Link {
            capacity: &capacity,
            probing: false,
            secs: 60,
            ..Link::default()
        });
        let (t_on, t_off) = (on.reach(ms(0), cap, 0.9), off.reach(ms(0), cap, 0.9));
        let end = ms(30_000);
        println!(
            "{:>5.1} Mbps: 90% after {} with probing, {} without; peak {:.2}x / {:.2}x, \
             mean (5-30 s) {:.2} / {:.2}, max queue {:?} / {:?}, probe bytes {}",
            cap / 1e6,
            secs(t_on),
            secs(t_off),
            on.peak(ms(0), end, cap),
            off.peak(ms(0), end, cap),
            on.mean(ms(5000), end, cap),
            off.mean(ms(5000), end, cap),
            on.max_queue,
            off.max_queue,
            on.probe_bytes,
        );
        let t_on = t_on.expect("probing reaches 90 %");
        assert!(t_on <= within, "{cap}: {t_on:?}");
        assert!(
            t_off.is_none_or(|t| t >= before_at_least),
            "{cap}: {t_off:?}"
        );
        // No runaway: the estimate stays near the capacity, the queue bounded.
        assert!(on.peak(ms(0), end, cap) < 1.5, "{cap}");
        assert!(on.mean(ms(5000), end, cap) > 0.75, "{cap}");
        assert!(on.max_queue < MAX_QUEUE, "{cap}");
        // Probing off is the estimator as before: no probe packets.
        assert_eq!(off.probe_bytes, 0);
    }
}

#[test]
fn probing_follows_step_changes() {
    // 10 Mbps, 2 Mbps from 20 s, 10 Mbps again from 40 s.
    let capacity = |t: Duration| {
        if t >= ms(20_000) && t < ms(40_000) {
            2e6
        } else {
            10e6
        }
    };
    let on = run(&Link {
        capacity: &capacity,
        secs: 70,
        ..Link::default()
    });
    let off = run(&Link {
        capacity: &capacity,
        secs: 70,
        probing: false,
        ..Link::default()
    });
    let down = |r: &Run| r.fall(ms(20_000), 2e6, 1.1);
    let up = |r: &Run| r.reach(ms(40_000), 10e6, 0.9);
    println!(
        "step 10->2->10 Mbps: down to 110% in {} / {}, back to 90% in {} / {}; \
         peak at 2 Mbps (25-40 s) {:.2}x / {:.2}x",
        secs(down(&on)),
        secs(down(&off)),
        secs(up(&on)),
        secs(up(&off)),
        on.peak(ms(25_000), ms(40_000), 2e6),
        off.peak(ms(25_000), ms(40_000), 2e6),
    );
    assert!(down(&on).expect("follows the drop") < ms(2000));
    let up_on = up(&on).expect("recovers");
    assert!(up_on < ms(5000), "{up_on:?}");
    assert!(up(&off).is_none_or(|t| t > 2 * up_on));
    // Recovery probes do not push the estimate far over the reduced capacity (the queue
    // overflows once when the capacity drops, probing or not).
    assert!(on.peak(ms(25_000), ms(40_000), 2e6) < 1.5);
}

#[test]
fn probing_under_loss_and_competition() {
    // 5 % random loss: the loss-based rate holds still, probing still finds the capacity.
    let capacity = |_| 4e6;
    let on = run(&Link {
        capacity: &capacity,
        loss_pct: 5,
        ..Link::default()
    });
    let off = run(&Link {
        capacity: &capacity,
        loss_pct: 5,
        probing: false,
        ..Link::default()
    });
    println!(
        "4 Mbps, 5% loss: 90% after {} / {}; peak {:.2}x / {:.2}x",
        secs(on.reach(ms(0), 4e6, 0.9)),
        secs(off.reach(ms(0), 4e6, 0.9)),
        on.peak(ms(0), ms(30_000), 4e6),
        off.peak(ms(0), ms(30_000), 4e6),
    );
    assert!(on.reach(ms(0), 4e6, 0.7).expect("ramps up") < ms(3000));
    assert!(on.peak(ms(0), ms(30_000), 4e6) < 1.5);
    // 15 % loss: the loss-based control wins over probing.
    let on = run(&Link {
        capacity: &capacity,
        loss_pct: 15,
        ..Link::default()
    });
    assert!(on.mean(ms(10_000), ms(30_000), 4e6) < 0.5);
    // 6 Mbps of competing traffic on 10 Mbps from 10 s: the estimate makes room.
    let cross = |t: Duration| if t >= ms(10_000) { 6e6 } else { 0.0 };
    let on = run(&Link {
        cross: &cross,
        ..Link::default()
    });
    let off = run(&Link {
        cross: &cross,
        probing: false,
        ..Link::default()
    });
    println!(
        "10 Mbps, 6 Mbps competing from 10 s: mean share (15-30 s) {:.2} / {:.2} of 4 Mbps, \
         peak {:.2}x / {:.2}x, max queue {:?} / {:?}",
        on.mean(ms(15_000), ms(30_000), 4e6),
        off.mean(ms(15_000), ms(30_000), 4e6),
        on.peak(ms(15_000), ms(30_000), 4e6),
        off.peak(ms(15_000), ms(30_000), 4e6),
        on.max_queue,
        off.max_queue,
    );
    assert!(on.mean(ms(15_000), ms(30_000), 4e6) < 1.3);
    assert!(on.max_queue < MAX_QUEUE);
}

#[test]
fn probing_when_application_limited() {
    // The encoder tops out at 1 Mbps on a 10 Mbps link: ALR probes keep the estimate ahead.
    let on = run(&Link {
        app_max: 1e6,
        initial: 1_000_000,
        ..Link::default()
    });
    let off = run(&Link {
        app_max: 1e6,
        initial: 1_000_000,
        probing: false,
        ..Link::default()
    });
    let (e_on, e_off) = (on.trace.last().unwrap().1, off.trace.last().unwrap().1);
    println!("app-limited at 1 Mbps on 10 Mbps: estimate after 30 s {e_on} / {e_off}");
    assert!(on.alr_seen);
    assert!(e_on as f64 > 3e6, "{e_on}");
    assert!((e_off as f64) < 2e6, "{e_off}");
    assert!(on.max_queue < MAX_QUEUE);
}

#[test]
fn probing_seeds_do_not_flake() {
    for seed in 1..=40 {
        let capacity = |_| 2e6;
        let r = run(&Link {
            capacity: &capacity,
            secs: 8,
            seed: seed * 7919,
            loss_pct: seed % 3,
            ..Link::default()
        });
        let t = r.reach(ms(0), 2e6, 0.9);
        assert!(t.is_some_and(|t| t < ms(2500)), "seed {seed}: {t:?}");
        assert!(r.peak(ms(0), ms(8000), 2e6) < 1.5, "seed {seed}");
    }
}

#[test]
fn probing_restarts_on_network_change() {
    let t0 = Instant::now();
    let mut b = BandwidthEstimator::new(500_000);
    let p = b.poll_probe(t0).expect("initial probe");
    // 3 x 500 kbps for 15 ms: 2812 bytes in about 10 packets of 281.
    assert_eq!(p.size, 281);
    assert!(b.probe_timeout().is_some());
    // Cancelled clusters are gone; new ones come with the next reason to probe.
    let mut c = BandwidthEstimator::new(500_000);
    assert!(c.poll_probe(t0).is_some());
    c.cancel_probes();
    assert_eq!(c.probe_timeout(), None);
    assert_eq!(c.poll_probe(t0), None);
    // Without sends, the clusters time out.
    assert_eq!(b.poll_probe(t0 + ms(1500)), None);
    assert_eq!(b.probe_timeout(), None);
    b.on_network_change(t0 + ms(2000));
    assert_eq!(b.estimate(), 500_000);
    let q = b.poll_probe(t0 + ms(2000)).expect("probes again");
    assert_ne!(q.cluster, p.cluster);
    // Off: nothing.
    let mut b = BandwidthEstimator::new(500_000).with_probing(false);
    assert_eq!(b.poll_probe(t0), None);
    b.on_network_change(t0);
    assert_eq!(b.poll_probe(t0), None);
    // The cap: no probe above the bounds or a REMB.
    let mut b = BandwidthEstimator::new(500_000).with_bounds(30_000, 600_000);
    let p = b.poll_probe(t0).unwrap();
    assert_eq!(p.size, 200); // 600 kbps for 15 ms: 1125 bytes, packets of at least 200
}

#[test]
fn probe_pacing_and_measurement() {
    // One cluster: packets leave at the cluster rate, and a clean result raises the estimate.
    let t0 = Instant::now();
    let mut b = BandwidthEstimator::new(1_000_000).with_bounds(30_000, 3_000_000);
    let mut tx = TwccSender::new();
    let mut rx = TwccReceiver::new();
    let mut now = t0;
    let mut sent = Vec::new();
    while now < t0 + ms(200) {
        while let Some(p) = b.poll_probe(now) {
            let seq = tx.next_seq();
            tx.on_sent_probe(seq, now, p.size, p.cluster);
            b.on_probe_sent(now, p.cluster, p.size);
            sent.push((now, p.cluster, p.size));
            rx.on_received(seq, now + ms(30));
        }
        now += Duration::from_micros(250);
    }
    // 3 Mbps (capped from 3 and 6 Mbps: one cluster) for 15 ms.
    let clusters: std::collections::BTreeSet<u32> = sent.iter().map(|s| s.1).collect();
    assert_eq!(clusters.len(), 1);
    let bytes: usize = sent.iter().map(|s| s.2).sum();
    let (first, last) = (sent[0].0, sent[sent.len() - 1].0);
    let rate = (bytes - sent[sent.len() - 1].2) as f64 * 8.0 / (last - first).as_secs_f64();
    assert!((2.8e6..3.2e6).contains(&rate), "{rate}");
    assert!(bytes >= 5625 && sent.len() >= 5);
    let at = now + ms(100);
    while let Some(Rtcp::TransportCc(fb)) = rx.poll_feedback(at, 1, 2) {
        let res = tx.on_feedback(at, &fb);
        assert!(res.iter().all(|r| r.probe == clusters.first().copied()));
        b.on_packet_results(at, &res);
    }
    assert!(b.estimate() > 2_700_000, "{}", b.estimate());
}

#[test]
fn padding_packets() {
    let map = ExtensionMap::default_video();
    let t0 = Instant::now();
    let mut s = SendStream::new(0x1111, 90_000, Some(0x2222), 100);
    assert!(s.padding(t0, 500, Some(97), &map, |_| {}).is_none());
    let ext = ExtensionValues {
        mid: Some("0".into()),
        ..Default::default()
    };
    s.write(t0, 96, false, 3000, &[1; 300], &ext, &map);
    s.write(t0, 96, true, 3000, &[2; 900], &ext, &map);
    // RTX of the newest packet that fits.
    let p = s
        .padding(t0, 500, Some(97), &map, |e| e.transport_cc = Some(7))
        .unwrap();
    let h = RtpHeader::parse(&p, &map).unwrap();
    assert_eq!((h.ssrc, h.payload_type), (0x2222, 97));
    assert_eq!(h.ext.transport_cc, Some(7));
    assert_eq!(h.ext.mid.as_deref(), Some("0"));
    assert_eq!(&h.payload(&p)[..2], &100u16.to_be_bytes());
    assert_eq!(h.payload(&p).len(), 302);
    // Nothing fits: the newest.
    let p = s.padding(t0, 100, Some(97), &map, |_| {}).unwrap();
    let h = RtpHeader::parse(&p, &map).unwrap();
    assert_eq!(&h.payload(&p)[..2], &101u16.to_be_bytes());
    assert!(h.marker);
    // Not counted, not in the history.
    assert_eq!((s.packets_sent(), s.packets_resent()), (2, 0));
    assert_eq!(s.next_seq(), 102);
    // Without RTX: padding only on the media stream, taking a sequence number.
    let p = s.padding(t0, 1000, None, &map, |_| {}).unwrap();
    let h = RtpHeader::parse(&p, &map).unwrap();
    assert_eq!(
        (h.ssrc, h.sequence_number, h.timestamp),
        (0x1111, 102, 3000)
    );
    assert_eq!((h.payload(&p).len(), h.padding_len), (0, 255));
    assert_eq!(s.next_seq(), 103);
    // After the history aged out: padding on the RTX stream.
    let p = s
        .padding(t0 + ms(5000), 50, Some(97), &map, |_| {})
        .unwrap();
    let h = RtpHeader::parse(&p, &map).unwrap();
    assert_eq!(
        (h.ssrc, h.payload(&p).len(), h.padding_len),
        (0x2222, 0, 50)
    );
}

#[test]
fn ccfb_carries_probe_clusters() {
    let t0 = Instant::now();
    let mut tx = crate::CcfbSender::new();
    let mut rx = crate::CcfbReceiver::new();
    tx.on_sent(5, 10, t0, 1200);
    tx.on_sent_probe(5, 11, t0, 300, 42);
    rx.on_received(5, 10, t0 + ms(10), 0);
    rx.on_received(5, 11, t0 + ms(10), 0);
    let at = t0 + ms(200);
    let Some(Rtcp::CongestionControl(fb)) = rx.poll_feedback(at, 1 << 32, 9) else {
        panic!("feedback")
    };
    let res = tx.on_feedback(at, &fb);
    let probes: Vec<_> = res.iter().map(|r| r.probe).collect();
    assert_eq!(probes, [None, Some(42)]);
}

#[test]
fn probing_when_the_maximum_is_raised() {
    // A 10 Mbps link, the application allowing 1 Mbps until 10 s, then 10 Mbps.
    let capacity = |_| 10e6;
    let max_at = |t: Duration| {
        if t < ms(10_000) {
            1_000_000
        } else {
            10_000_000
        }
    };
    let on = run(&Link {
        capacity: &capacity,
        max_at: Some(&max_at),
        ..Link::default()
    });
    let t = on.reach(ms(10_000), 10e6, 0.9);
    println!("max raised to 10 Mbps: 90 % after {}", secs(t));
    assert!(t.expect("reaches 90 %") <= ms(1500), "{t:?}");
    assert!(on.peak(ms(0), ms(10_000), 1e6) <= 1.0);
    assert!(on.peak(ms(10_000), ms(30_000), 10e6) < 1.5);
    let now = Instant::now();
    // Raising it during the initial probing leaves the initial probes alone.
    let mut b = BandwidthEstimator::new(300_000).with_bounds(30_000, 1_000_000);
    let first = b.poll_probe(now).expect("initial probe");
    b.set_bounds(now, 30_000, 5_000_000);
    assert_eq!(b.poll_probe(now).map(|p| p.cluster), Some(first.cluster));
    // A lowered maximum caps the estimate at once and probes nothing.
    let mut b = BandwidthEstimator::new(3_000_000).with_probing(false);
    b.set_bounds(now, 30_000, 1_000_000);
    assert_eq!(b.estimate(), 1_000_000);
    assert!(b.poll_probe(now).is_none());
}

#[test]
fn network_state_estimate_bounds_and_drives_probes() {
    let capacity = |_| 10e6;
    // An estimate of 4 Mbps set from outside: probes stay at or below it, so the estimate
    // stops there while the link carries 10 Mbps.
    let capped = run(&Link {
        capacity: &capacity,
        nse: Some(4_000_000),
        secs: 20,
        ..Link::default()
    });
    let free = run(&Link {
        capacity: &capacity,
        secs: 20,
        ..Link::default()
    });
    let reach_capped = capped.reach(ms(0), 4e6, 0.9);
    println!(
        "nse 4 Mbps: 90 % of it after {}, peak {:.2} of 10 Mbps (free: {:.2})",
        secs(reach_capped),
        capped.peak(ms(0), ms(20_000), 10e6),
        free.peak(ms(0), ms(20_000), 10e6),
    );
    assert!(reach_capped.expect("reaches the estimate") <= ms(1500));
    // Growth past the estimate is the AIMD's only (8 % per second at most).
    assert!(capped.peak(ms(0), ms(3000), 4e6) < 1.2);
    assert!(free.peak(ms(0), ms(3000), 10e6) > 0.9);
    // A link that drops to 2 Mbps for 10 s and comes back: with the estimate (10 Mbps) set,
    // the low-estimate probes bring it back as fast as the recovery probes or faster.
    let step = |t: Duration| {
        if t >= ms(10_000) && t < ms(20_000) {
            2e6
        } else {
            10e6
        }
    };
    let with = run(&Link {
        capacity: &step,
        nse: Some(10_000_000),
        secs: 40,
        ..Link::default()
    });
    let without = run(&Link {
        capacity: &step,
        secs: 40,
        ..Link::default()
    });
    let (a, b) = (
        with.reach(ms(20_000), 10e6, 0.8),
        without.reach(ms(20_000), 10e6, 0.8),
    );
    println!(
        "2 -> 10 Mbps: 80 % after {} with nse, {} without",
        secs(a),
        secs(b)
    );
    let a = a.expect("recovers with the estimate");
    assert!(a <= ms(8000), "{a:?}");
    assert!(b.is_none_or(|b| a <= b + ms(500)), "{a:?} {b:?}");
    // The estimator's own link capacity estimate is known after the drop.
    let mut bwe = BandwidthEstimator::new(300_000);
    assert!(bwe.link_capacity().is_none());
    bwe.set_network_state_estimate(Some(1_000_000));
    bwe.set_network_state_estimate(None);
}

#[test]
fn ecn_ce_marks_count_as_congestion() {
    use crate::PacketResult;
    let t0 = Instant::now();
    let feed = |ce_every: Option<u64>, ect: bool| {
        let mut bwe = BandwidthEstimator::new(2_000_000).with_probing(false);
        let mut seq = 0u64;
        for step in 0..100u64 {
            let now = t0 + ms(step * 50);
            let res: Vec<PacketResult> = (0..30)
                .map(|i| {
                    seq += 1;
                    let sent = now - ms(60) + Duration::from_micros(i * 1500);
                    PacketResult {
                        seq,
                        sent,
                        size: 1200,
                        received: Some(sent + ms(20)),
                        probe: None,
                        ecn: match (ce_every, ect) {
                            (Some(n), _) if seq % n == 0 => Some(3),
                            (_, true) => Some(2),
                            _ => None,
                        },
                    }
                })
                .collect();
            bwe.on_packet_results(now, &res);
        }
        (bwe.estimate(), bwe.ecn_counts())
    };
    let (clean, counts) = feed(None, true);
    assert_eq!(counts, (3000, 0));
    let (marked, counts) = feed(Some(5), true);
    assert_eq!(counts, (3000, 600));
    let (_, none) = feed(None, false);
    assert_eq!(none, (0, 0));
    // 20 % CE: the loss-based rate backs off as for 20 % loss.
    println!("estimate after 5 s: {clean} clean, {marked} with 20 % CE");
    assert!(marked < clean / 2, "{marked} vs {clean}");
}
