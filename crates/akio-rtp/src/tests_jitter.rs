//! The jitter buffer under simulated jitter, loss, reordering and duplicates.

use std::time::{Duration, Instant};

use crate::{
    JITTER_BUFFER_MAX_BYTES, JITTER_BUFFER_MAX_FRAMES, JitterBuffer, JitterFrame, JitterPush,
    PlayoutDelay,
};

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// xorshift64*: deterministic noise.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Uniform in 0..1.
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A packet on the simulated network: sequence number, RTP timestamp, marker, arrival.
#[derive(Debug, Clone, Copy)]
struct Pkt {
    seq: u64,
    ts: u32,
    marker: bool,
    at: Instant,
}

/// 20 ms Opus frames (960 ticks at 48 kHz) sent from `t0`, each delayed by `base` plus
/// `jitter(i)`, dropped when `lost(i)`; sorted by arrival.
fn stream(
    t0: Instant,
    n: u64,
    base: Duration,
    mut jitter: impl FnMut(u64) -> Duration,
    mut lost: impl FnMut(u64) -> bool,
) -> Vec<Pkt> {
    let mut v: Vec<Pkt> = (0..n)
        .filter(|&i| !lost(i))
        .map(|i| Pkt {
            seq: 1000 + i,
            ts: 7_000_000u32.wrapping_add(960 * i as u32),
            marker: i == 0,
            at: t0 + ms(20 * i) + base + jitter(i),
        })
        .collect();
    v.sort_by_key(|p| p.at);
    v
}

/// Runs the buffer over `pkts` as an event loop would: frames are taken when they are due
/// (checked to be handed out at their playout instant, in order) and packets pushed as they
/// arrive. Returns the frames and what each push gave.
fn run(
    jb: &mut JitterBuffer<u64>,
    pkts: &[Pkt],
) -> (Vec<JitterFrame<u64>>, Vec<(u64, JitterPush)>) {
    let mut out = Vec::new();
    let mut pushes = Vec::new();
    let take = |jb: &mut JitterBuffer<u64>, until: Instant, out: &mut Vec<JitterFrame<u64>>| {
        while let Some(due) = jb.poll_timeout().filter(|d| *d <= until) {
            let f = jb.pop(due).expect("due frame");
            assert_eq!(f.playout, due);
            out.push(f);
        }
    };
    for p in pkts {
        take(jb, p.at, &mut out);
        let r = jb.push(p.seq, p.ts, p.marker, p.at, p.seq, 80);
        pushes.push((p.seq, r));
        take(jb, p.at, &mut out);
    }
    take(
        jb,
        pkts.last().map_or_else(Instant::now, |p| p.at) + ms(5000),
        &mut out,
    );
    (out, pushes)
}

fn check_order(out: &[JitterFrame<u64>]) {
    for w in out.windows(2) {
        assert!(w[1].seq > w[0].seq, "{} after {}", w[1].seq, w[0].seq);
        assert!(w[1].playout >= w[0].playout);
        assert!(w[1].timestamp > w[0].timestamp);
    }
}

#[test]
fn no_jitter_plays_everything_in_order() {
    let t0 = Instant::now();
    let pkts = stream(t0, 200, ms(30), |_| Duration::ZERO, |_| false);
    let mut jb = JitterBuffer::new(48_000, PlayoutDelay::default());
    let (out, _) = run(&mut jb, &pkts);
    assert_eq!(out.len(), 200);
    check_order(&out);
    assert!(out.iter().all(|f| f.contiguous && f.data == f.seq));
    // Played at arrival: no delay beyond the transit time.
    assert!(out.iter().all(|f| f.playout == f.arrival), "{:?}", out[5]);
    let s = jb.stats();
    assert_eq!((s.received, s.played, s.lost, s.late), (200, 200, 0, 0));
    assert_eq!(s.delay, Duration::ZERO);
    assert_eq!(out[0].timestamp, 7_000_000);
    assert!(out[0].marker && !out[1].marker);
    assert!(jb.is_empty() && jb.poll_timeout().is_none());
}

#[test]
fn adapts_to_jitter_and_accounts_for_loss() {
    let t0 = Instant::now();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut drop = Rng(77);
    // Uniform jitter of 0..60 ms (reorders packets 20 ms apart), 3 % random loss.
    let jit: Vec<Duration> = (0..3000)
        .map(|_| Duration::from_micros((rng.unit() * 60_000.0) as u64))
        .collect();
    let lost: Vec<bool> = (0..3000).map(|_| drop.unit() < 0.03).collect();
    let pkts = stream(t0, 3000, ms(40), |i| jit[i as usize], |i| lost[i as usize]);
    let sent = pkts.len() as u64;
    let mut jb = JitterBuffer::new(48_000, PlayoutDelay::default());
    let (out, pushes) = run(&mut jb, &pkts);
    check_order(&out);
    let s = jb.stats();
    // Every packet is accounted for, once.
    assert_eq!(s.received + s.late, sent);
    assert_eq!(s.played, s.received);
    assert_eq!(out.len() as u64, s.played);
    assert!(s.reordered > 100, "{s:?}");
    // The delay settles near the 95th percentile of the jitter (57 ms).
    assert!(
        s.delay >= ms(45) && s.delay <= ms(65) && s.target >= ms(45) && s.target <= ms(65),
        "{s:?}"
    );
    // Late arrivals: well under the 5 % the percentile lets through (a frame late by less
    // than a packet interval still plays).
    assert!(s.late * 100 < sent * 2, "{s:?}");
    // Losses: the network's and the late ones (given up first, then discarded).
    let net_lost = lost.iter().filter(|l| **l).count() as u64;
    assert_eq!(s.lost, net_lost + s.late);
    // A frame after a gap is not contiguous.
    let gaps = out.windows(2).filter(|w| w[1].seq != w[0].seq + 1).count();
    assert_eq!(out.iter().filter(|f| !f.contiguous).count(), gaps);
    // The discarded sequence numbers are the late pushes.
    let late: Vec<u64> = pushes
        .iter()
        .filter(|(_, r)| *r == JitterPush::Late)
        .map(|(s, _)| *s)
        .collect();
    assert_eq!(jb.drain_discarded().collect::<Vec<_>>(), late);
    assert_eq!(jb.drain_discarded().count(), 0);
    // Only a frame that came after its own playout instant plays before it arrived.
    let early = out.iter().filter(|f| f.playout < f.arrival).count() as u64;
    assert!(early * 100 < sent * 5, "{early}");
    let xr = jb.xr_config();
    assert!(xr.adaptive && xr.nominal == s.delay && xr.abs_max == ms(500));
}

#[test]
fn duplicates_and_late_packets() {
    let t0 = Instant::now();
    let mut jb = JitterBuffer::new(8_000, PlayoutDelay::fixed(ms(40)));
    let ts = |i: u32| 160 * i;
    assert_eq!(jb.push(10, ts(0), true, t0, 0, 160), JitterPush::Buffered);
    assert_eq!(jb.push(10, ts(0), true, t0, 0, 160), JitterPush::Duplicate);
    // 11 is missing; 12 arrives in time.
    assert_eq!(
        jb.push(12, ts(2), false, t0 + ms(40), 2, 160),
        JitterPush::Buffered
    );
    assert_eq!(jb.poll_timeout(), Some(t0 + ms(40)));
    assert!(jb.pop(t0 + ms(39)).is_none());
    let f = jb.pop(t0 + ms(40)).expect("10");
    assert_eq!((f.seq, f.contiguous), (10, true));
    // 12 is due at 80 ms; 11 (due at 60) arrives at 70: late, but before 12 went out.
    assert_eq!(
        jb.push(11, ts(1), false, t0 + ms(70), 1, 160),
        JitterPush::Buffered
    );
    let f = jb.pop(t0 + ms(70)).expect("11 at once");
    assert_eq!((f.seq, f.playout), (11, t0 + ms(60)));
    let f = jb.pop(t0 + ms(80)).expect("12");
    assert_eq!((f.seq, f.contiguous), (12, true));
    // 14 plays before 13 comes: 13 is late, a copy of 14 a duplicate.
    jb.push(14, ts(4), false, t0 + ms(85), 4, 160);
    assert_eq!(
        jb.pop(t0 + ms(120)).map(|f| (f.seq, f.contiguous)),
        Some((14, false))
    );
    assert_eq!(
        jb.push(13, ts(3), false, t0 + ms(121), 3, 160),
        JitterPush::Late
    );
    assert_eq!(
        jb.push(14, ts(4), false, t0 + ms(122), 4, 160),
        JitterPush::Duplicate
    );
    assert_eq!(
        jb.push(12, ts(2), false, t0 + ms(122), 2, 160),
        JitterPush::Duplicate
    );
    let s = jb.stats();
    assert_eq!((s.duplicates, s.late, s.lost, s.played), (3, 1, 1, 4));
    assert_eq!(jb.drain_discarded().collect::<Vec<_>>(), [13]);
    // A fixed buffer reports its delay as nominal, maximum and absolute maximum.
    let xr = jb.xr_config();
    assert!(!xr.adaptive && xr.nominal == ms(40) && xr.abs_max == ms(40));
    assert_eq!(s.delay, ms(40));
}

#[test]
fn skipped_sequence_numbers_are_not_losses() {
    let t0 = Instant::now();
    let mut jb = JitterBuffer::new(48_000, PlayoutDelay::fixed(ms(20)));
    jb.push(1, 0, false, t0, 1, 10);
    jb.skip(2); // a FEC packet
    jb.push(3, 1920, false, t0 + ms(40), 3, 10);
    let out: Vec<_> = std::iter::from_fn(|| jb.pop(t0 + ms(100))).collect();
    assert_eq!(out.len(), 2);
    assert!(out[1].contiguous);
    assert_eq!(jb.stats().lost, 0);
}

#[test]
fn talkspurt_shortens_the_delay() {
    let t0 = Instant::now();
    let bounds = PlayoutDelay::adaptive(Duration::ZERO, ms(1000));
    let mut jb = JitterBuffer::new(48_000, bounds);
    let mut rng = Rng(5);
    let mut small = || Duration::from_micros((rng.unit() * 4000.0) as u64);
    // A talkspurt through 1.2 s of 600 ms extra delay, then 10 s of a quiet network: the
    // histogram forgets the spike, the delay comes down by a frame a second only.
    let mut pkts: Vec<Pkt> = (0..600u64)
        .map(|i| Pkt {
            seq: i,
            ts: 960 * i as u32,
            marker: i == 0,
            at: t0
                + ms(20 * i)
                + ms(10)
                + if (50..110).contains(&i) {
                    ms(600)
                } else {
                    small()
                },
        })
        .collect();
    pkts.sort_by_key(|p| p.at);
    run(&mut jb, &pkts);
    let s = jb.stats();
    assert!(s.delay >= ms(200) && s.target < ms(20), "{s:?}");
    // Silence (DTX: the timestamps jump, the sequence numbers do not), then a talkspurt: it
    // starts at the target.
    let mut later: Vec<Pkt> = (600..700u64)
        .map(|i| Pkt {
            seq: i,
            ts: 960 * (i + 100) as u32,
            marker: false,
            at: t0 + ms(20 * (i + 100)) + ms(10) + small(),
        })
        .collect();
    later.sort_by_key(|p| p.at);
    let (out, _) = run(&mut jb, &later);
    let s = jb.stats();
    assert!(s.delay < ms(15), "{s:?}");
    check_order(&out);
    assert_eq!(s.late, 0);
    // Played right after the silence, not 200 ms later.
    assert!(out[0].playout - out[0].arrival < ms(15));
}

#[test]
fn continuous_stream_shortens_one_frame_per_second() {
    let t0 = Instant::now();
    let bounds = PlayoutDelay::adaptive(Duration::ZERO, ms(300));
    // 0.8 s of 200 ms extra delay early, then a clean network for 19 s, no pause.
    let mut pkts: Vec<Pkt> = (0..1000u64)
        .map(|i| Pkt {
            seq: i,
            ts: 960 * i as u32,
            marker: i == 0,
            at: t0
                + ms(20 * i)
                + if (20..60).contains(&i) {
                    ms(200)
                } else {
                    Duration::ZERO
                },
        })
        .collect();
    pkts.sort_by_key(|p| p.at);
    let mut first = JitterBuffer::new(48_000, bounds);
    let n = pkts.iter().position(|p| p.seq == 150).expect("150");
    run(&mut first, &pkts[..n]);
    assert!(first.stats().delay >= ms(150), "{:?}", first.stats());
    let mut jb = JitterBuffer::new(48_000, bounds);
    let (out, _) = run(&mut jb, &pkts);
    // The delay never shrinks by more than a frame from one frame to the next.
    for w in out.windows(2) {
        let gap = w[1].playout.duration_since(w[0].playout);
        let media = Duration::from_micros((w[1].timestamp - w[0].timestamp) * 1_000_000 / 48_000);
        assert!(gap + ms(20) >= media, "{gap:?} for {media:?}");
    }
    let shrinks = out
        .windows(2)
        .filter(|w| w[1].playout.duration_since(w[0].playout) < ms(20))
        .count();
    assert!((5..=20).contains(&shrinks), "{shrinks}");
    assert!(jb.stats().delay < ms(20), "{:?}", jb.stats());
    assert_eq!(jb.stats().played, 1000);
    check_order(&out);
}

#[test]
fn bounded_by_frames_and_bytes() {
    let t0 = Instant::now();
    let mut jb = JitterBuffer::new(8_000, PlayoutDelay::fixed(ms(2000)));
    // Bytes: frames of 64 kB fill the buffer after 4.
    for i in 0..6u64 {
        let r = jb.push(i, 160 * i as u32, false, t0, i, 64 * 1024);
        assert_eq!(r == JitterPush::Overflow, i >= 4, "{i}");
    }
    assert_eq!(jb.len(), 4);
    assert_eq!(jb.stats().overflow, 2);
    let out = jb.drain();
    assert_eq!(out.iter().map(|f| f.seq).collect::<Vec<_>>(), [0, 1, 2, 3]);
    assert!(jb.is_empty());
    // A discarded slot is a gap, not a loss.
    jb.push(6, 160 * 6, false, t0, 6, 10);
    let f = jb.drain().remove(0);
    assert!(!f.contiguous);
    assert_eq!(jb.stats().lost, 0);
    // Frames: a sequence number past the window drops the oldest.
    let cap = JITTER_BUFFER_MAX_FRAMES as u64;
    jb.push(7, 160 * 7, false, t0, 7, 10);
    jb.push(7 + cap, 160 * (7 + cap) as u32, false, t0, 7 + cap, 10);
    assert_eq!(jb.len(), 1);
    assert_eq!(jb.stats().overflow, 3);
    // A jump of more than two windows starts over.
    jb.push(100_000, 0, false, t0, 1, 10);
    assert_eq!(jb.len(), 1);
    assert_eq!(jb.stats().overflow, 4);
    const { assert!(JITTER_BUFFER_MAX_BYTES >= 64 * 1024) };
    // Discards are remembered for the report, boundedly.
    assert_eq!(jb.drain_discarded().count(), 4);
}

#[test]
fn playout_delay_bounds() {
    let d = PlayoutDelay::adaptive(ms(900), ms(5000));
    assert_eq!((d.min(), d.max()), (ms(900), ms(2000)));
    assert!(!d.is_fixed());
    let d = PlayoutDelay::adaptive(ms(300), ms(100));
    assert_eq!((d.min(), d.max()), (ms(100), ms(100)));
    assert!(d.is_fixed() && PlayoutDelay::fixed(ms(60)).is_fixed());
    assert_eq!(PlayoutDelay::default().max(), ms(500));
    // The minimum holds even on a clean network.
    let t0 = Instant::now();
    let mut jb = JitterBuffer::new(48_000, PlayoutDelay::adaptive(ms(40), ms(200)));
    let pkts = stream(t0, 50, ms(5), |_| Duration::ZERO, |_| false);
    let (out, _) = run(&mut jb, &pkts);
    assert!(out.iter().all(|f| f.playout == f.arrival + ms(40)));
    assert_eq!(jb.stats().delay, ms(40));
    // Timestamps wrap.
    let mut jb = JitterBuffer::new(48_000, PlayoutDelay::fixed(ms(10)));
    jb.push(1, u32::MAX - 959, false, t0, 1, 1);
    jb.push(2, 0, false, t0 + ms(20), 2, 1);
    let out = jb.drain();
    assert_eq!(out[1].timestamp, out[0].timestamp + 960);
    assert_eq!(out[1].playout, out[0].playout + ms(20));
}
