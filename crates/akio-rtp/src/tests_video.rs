//! The video playout buffer (ADR-092) behind the frame assembler, under simulated jitter,
//! reordering, loss with NACK repair, large keyframes, overflow and clock jumps.

use std::time::{Duration, Instant};

use crate::codec::{CodecKind, FrameAssembler};
use crate::{
    PlayoutDelay, VIDEO_PLAYOUT_MAX_FRAMES, VideoFrameFlags, VideoPlayout, VideoPlayoutFrame,
};

pub(crate) fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

/// xorshift64*: deterministic noise.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Uniform in 0..1.
    pub(crate) fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A VP8 packet on the simulated network.
#[derive(Debug, Clone)]
pub(crate) struct Pkt {
    pub(crate) seq: u64,
    pub(crate) ts: u32,
    pub(crate) marker: bool,
    pub(crate) payload: Vec<u8>,
    pub(crate) at: Instant,
    /// A retransmission (RTX).
    pub(crate) rtx: bool,
}

/// The network: 30 frames/s of VP8 (3000 ticks at 90 kHz), a keyframe of `key_packets`
/// packets every `key_every` frames and 3 packets otherwise, sent paced at 1 ms per packet
/// from each frame's capture instant, each packet delayed by 20 ms plus `jitter` (uniform),
/// lost with probability `loss` and then (with `rtt`) retransmitted once, `rtt` after the
/// receiver could notice (the next packet's arrival).
pub(crate) struct Net {
    pub(crate) frames: u64,
    pub(crate) key_every: u64,
    pub(crate) key_packets: u64,
    pub(crate) jitter: u64,
    pub(crate) loss: f64,
    pub(crate) rtt: Option<Duration>,
}

pub(crate) fn packets(t0: Instant, n: &Net, rng: &mut Rng) -> Vec<Pkt> {
    let mut v = Vec::new();
    let mut seq = 5000u64;
    for i in 0..n.frames {
        let key = i % n.key_every == 0;
        let count = if key { n.key_packets } else { 3 };
        let capture = t0 + Duration::from_micros(i * 33_333);
        for k in 0..count {
            // VP8 descriptor: S on the first packet (PID 0); payload header P = 0 on a key.
            let mut payload = vec![if k == 0 { 0x10 } else { 0x00 }, 0, 0, 0];
            if k == 0 {
                payload[1] = u8::from(!key);
            }
            let sent = capture + ms(k);
            let delay = ms(20) + Duration::from_micros((rng.unit() * n.jitter as f64 * 1e3) as u64);
            let mut p = Pkt {
                seq,
                ts: (90_000u32 * 7).wrapping_add(3000 * i as u32),
                marker: k + 1 == count,
                payload,
                at: sent + delay,
                rtx: false,
            };
            if rng.unit() < n.loss {
                let Some(rtt) = n.rtt else {
                    seq += 1;
                    continue;
                };
                p.at = sent + delay + ms(2) + rtt;
                p.rtx = true;
            }
            v.push(p);
            seq += 1;
        }
    }
    v.sort_by_key(|p| p.at);
    v
}

/// The receive path as akio-webrtc runs it: packets into the assembler as they arrive, its
/// frames into the playout buffer (flagged repaired when a retransmission or a gap released
/// them), frames taken when due (checked to come out at their playout instant).
fn run(pkts: &[Pkt], pb: &mut VideoPlayout<u64>) -> Vec<VideoPlayoutFrame<u64>> {
    let mut asm = FrameAssembler::new(CodecKind::Vp8, 30);
    let mut out = Vec::new();
    let take = |pb: &mut VideoPlayout<u64>, until: Instant, out: &mut Vec<_>| {
        while let Some(due) = pb.poll_timeout().filter(|d| *d <= until) {
            let f = pb.pop(due).expect("due frame");
            assert_eq!(f.playout, due);
            out.push(f);
        }
    };
    for p in pkts {
        take(pb, p.at, &mut out);
        asm.push(p.seq, p.ts, p.marker, &p.payload, p.at);
        let mut repaired = p.rtx;
        while let Some(f) = asm.pop() {
            let mut flags = VideoFrameFlags::NONE;
            if f.keyframe {
                flags |= VideoFrameFlags::KEYFRAME;
            }
            if !f.contiguous {
                flags |= VideoFrameFlags::DISCONTINUOUS;
                repaired = true;
            }
            if repaired {
                flags |= VideoFrameFlags::REPAIRED;
            }
            pb.push(f.timestamp as u32, p.at, flags, f.timestamp, f.data.len());
        }
    }
    take(pb, pkts.last().unwrap().at + ms(3000), &mut out);
    out
}

/// `playout - media time` of each frame (ms), relative to the first frame's.
fn lateness(out: &[VideoPlayoutFrame<u64>]) -> Vec<f64> {
    let p0 = out[0].playout;
    let t0 = out[0].timestamp;
    out.iter()
        .map(|f| {
            let media = (f.timestamp - t0) as f64 / 90.0;
            f.playout.duration_since(p0).as_secs_f64() * 1e3 - media
        })
        .collect()
}

/// How many consecutive frames are not shown one frame interval apart (±2 ms).
pub(crate) fn uneven(out: &[VideoPlayoutFrame<u64>], from: usize) -> usize {
    out[from..]
        .windows(2)
        .filter(|w| {
            let gap = w[1].playout.duration_since(w[0].playout).as_secs_f64() * 1e3;
            let media = (w[1].timestamp - w[0].timestamp) as f64 / 90.0;
            (gap - media).abs() > 2.0
        })
        .count()
}

#[test]
fn jittered_frames_play_evenly() {
    let t0 = Instant::now();
    let net = Net {
        frames: 1800,
        key_every: 100_000,
        key_packets: 3,
        jitter: 40,
        loss: 0.0,
        rtt: None,
    };
    let pkts = packets(t0, &net, &mut Rng(7));
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    let out = run(&pkts, &mut pb);
    let s = pb.stats();
    // Every frame, in order, each played no earlier than complete.
    assert_eq!(out.len(), 1800, "{s:?}");
    assert!(out.windows(2).all(|w| w[0].timestamp < w[1].timestamp));
    assert!(out.windows(2).all(|w| w[0].playout <= w[1].playout));
    assert!(out.iter().all(|f| f.playout >= f.completed));
    // Completion times spread over 40 ms; after the first 5 s the buffer shows frames one
    // frame interval apart, nearly all of them.
    let spread = |v: &[f64]| {
        let lo = v.iter().copied().fold(f64::MAX, f64::min);
        let hi = v.iter().copied().fold(f64::MIN, f64::max);
        hi - lo
    };
    let completion: Vec<f64> = out
        .iter()
        .map(|f| {
            f.completed.duration_since(out[0].completed).as_secs_f64() * 1e3
                - (f.timestamp - out[0].timestamp) as f64 / 90.0
        })
        .collect();
    assert!(spread(&completion[150..]) > 30.0);
    let late = lateness(&out);
    assert!(spread(&late[150..]) < 25.0, "{}", spread(&late[150..]));
    let bad = uneven(&out, 150);
    assert!(bad < 1650 / 20, "{bad} of 1650 uneven {s:?}");
    assert!(s.late < 1800 / 15, "{s:?}");
    // The delay covers most of the 40 ms (plus the 2 ms of the three packets' pacing).
    assert!(s.delay >= ms(30) && s.delay <= ms(50), "{s:?}");
    assert_eq!(s.dropped, 0);
    assert_eq!(s.repaired, 0);
}

#[test]
fn lost_packets_repaired_by_nack_in_time() {
    let t0 = Instant::now();
    let rtt = ms(60);
    let net = Net {
        frames: 1800,
        key_every: 100_000,
        key_packets: 3,
        jitter: 20,
        loss: 0.01,
        rtt: Some(rtt),
    };
    let pkts = packets(t0, &net, &mut Rng(11));
    // Without room for a retransmission: every repaired frame is late.
    let mut plain = VideoPlayout::new(90_000, PlayoutDelay::default());
    let out_plain = run(&pkts, &mut plain);
    // With it.
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    pb.set_round_trip(Some(rtt));
    let out = run(&pkts, &mut pb);
    let (sp, s) = (plain.stats(), pb.stats());
    assert_eq!(out.len(), 1800);
    assert_eq!(out_plain.len(), 1800);
    assert!(out.iter().all(|f| f.contiguous), "every loss was repaired");
    assert!(s.repaired > 40, "{s:?}");
    // Repaired frames stay out of the histogram: without the round trip the target is the
    // jitter's; with it, the jitter's plus the round trip.
    assert!(sp.target < ms(30), "{sp:?}");
    assert!(s.target >= rtt && s.target < rtt + ms(30), "{s:?}");
    assert!(sp.late > 3 * s.late.max(1), "{sp:?} {s:?}");
    assert!(uneven(&out, 150) < uneven(&out_plain, 150) / 2);
}

#[test]
fn keyframes_are_covered() {
    let t0 = Instant::now();
    // A 40-packet keyframe every 2 s (40 ms of pacing) between 3-packet frames.
    let net = Net {
        frames: 1800,
        key_every: 60,
        key_packets: 40,
        jitter: 10,
        loss: 0.0,
        rtt: None,
    };
    let pkts = packets(t0, &net, &mut Rng(3));
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    let out = run(&pkts, &mut pb);
    let s = pb.stats();
    assert_eq!(out.len(), 1800);
    assert_eq!(out.iter().filter(|f| f.keyframe).count(), 30);
    // The keyframes take 40 ms longer than the rest: the target covers them, so after the
    // first ones they are in time (and so are the frames after them).
    assert!(s.target >= ms(40), "{s:?}");
    // A keyframe late without the cover would stall the picture for about 40 ms; with it,
    // by the 10 ms of jitter at most.
    for w in out.windows(2).skip(150).filter(|w| w[1].keyframe) {
        let gap = w[1].playout.duration_since(w[0].playout);
        assert!(gap <= Duration::from_micros(33_334) + ms(10), "{gap:?}");
    }
    assert!(s.late <= 30, "{s:?}");
    assert!(uneven(&out, 150) < 60, "{}", uneven(&out, 150));
}

#[test]
fn round_trip_allowance_expires() {
    let t0 = Instant::now();
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    pb.set_round_trip(Some(ms(100)));
    let mut now = t0;
    for i in 0..900u32 {
        now = t0 + Duration::from_micros(u64::from(i) * 33_333) + ms(20);
        let flags = if i == 30 {
            VideoFrameFlags::REPAIRED
        } else {
            VideoFrameFlags::NONE
        };
        pb.push(3000 * i, now, flags, i, 1000);
        while pb.pop(now).is_some() {}
        if i == 31 {
            assert!(pb.stats().target >= ms(100), "{:?}", pb.stats());
        }
    }
    // 30 s later, no repair for 29 s: the allowance is gone, the delay came back down.
    let s = pb.stats();
    assert!(s.target < ms(10), "{s:?}");
    assert!(s.delay < ms(10), "{s:?}");
    let _ = now;
}

#[test]
fn delay_shrinks_at_keyframes_at_once_else_slowly() {
    let t0 = Instant::now();
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    let mut out: Vec<VideoPlayoutFrame<u32>> = Vec::new();
    let mut push = |pb: &mut VideoPlayout<u32>, i: u32, extra: u64, key: bool| {
        let at = t0 + Duration::from_micros(u64::from(i) * 33_333) + ms(20 + extra);
        while let Some(f) = pb.pop(at) {
            out.push(f);
        }
        let flags = if key {
            VideoFrameFlags::KEYFRAME
        } else {
            VideoFrameFlags::NONE
        };
        pb.push(3000 * i, at, flags, i, 1000);
    };
    // 0.5 s of frames 150 ms late, then steady: the delay goes up to about 150 ms.
    for i in 0..15 {
        push(&mut pb, i, 0, i == 0);
    }
    for i in 15..30 {
        push(&mut pb, i, 150, false);
    }
    assert!(pb.stats().delay >= ms(140), "{:?}", pb.stats());
    // Once the histogram has forgotten them the target is back near 0, but between
    // keyframes the delay drops by at most a frame interval a second.
    let mut i = 30;
    while pb.stats().target > ms(10) {
        push(&mut pb, i, 0, false);
        i += 1;
        assert!(i < 3000);
    }
    let mut prev = pb.stats().delay;
    for _ in 0..60 {
        push(&mut pb, i, 0, false);
        let d = pb.stats().delay;
        assert!(prev.saturating_sub(d) <= ms(34), "{prev:?} -> {d:?} at {i}");
        prev = d;
        i += 1;
    }
    let before = pb.stats();
    assert!(before.delay > before.target + ms(30), "{before:?}");
    // A keyframe: down to the target at once.
    push(&mut pb, i, 0, true);
    let after = pb.stats();
    assert!(after.delay <= after.target + ms(2), "{before:?} {after:?}");
    // Through all of it, frames came out in order, never before they were complete.
    assert!(out.len() as u32 + 10 > i, "{} of {i}", out.len());
    assert!(out.windows(2).all(|w| w[0].data + 1 == w[1].data));
    assert!(out.windows(2).all(|w| w[0].playout <= w[1].playout));
    assert!(out.iter().all(|f| f.playout >= f.completed));
}

#[test]
fn bounded_and_keyframe_aware_when_full() {
    let t0 = Instant::now();
    // The sender's clock runs fast: every frame completes at once, media time ahead.
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::fixed(ms(2000)));
    for i in 0..300u32 {
        let flags = if i == 100 {
            VideoFrameFlags::KEYFRAME
        } else {
            VideoFrameFlags::NONE
        };
        pb.push(
            3000 * i,
            t0 + Duration::from_micros(u64::from(i)),
            flags,
            i,
            100,
        );
        assert!(pb.len() <= VIDEO_PLAYOUT_MAX_FRAMES);
    }
    // At 257 frames the keyframe at 100 let the 100 before it go; 300 is under the bound
    // again with no further keyframe: then the oldest go one by one.
    let s = pb.stats();
    assert_eq!(s.dropped, 100, "{s:?}");
    assert!(!pb.take_keyframe_request());
    let f = pb.drain();
    assert_eq!(f[0].data, 100);
    assert!(f[0].keyframe && !f[0].contiguous);
    assert!(f[1..].iter().all(|f| f.contiguous));
    // No keyframe to resume from: the oldest frame goes and a keyframe is asked for.
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::fixed(ms(2000)));
    for i in 0..=VIDEO_PLAYOUT_MAX_FRAMES as u32 {
        pb.push(3000 * i, t0, VideoFrameFlags::NONE, i, 100);
    }
    assert_eq!(pb.len(), VIDEO_PLAYOUT_MAX_FRAMES);
    assert_eq!(pb.stats().dropped, 1);
    assert!(pb.take_keyframe_request());
    assert!(!pb.take_keyframe_request());
    let f = pb.pop(t0 + ms(5000)).unwrap();
    assert_eq!(f.data, 1);
    assert!(!f.contiguous);
    // Bytes: frames of 5 MiB, at most three fit.
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    for i in 0..10u32 {
        pb.push(3000 * i, t0, VideoFrameFlags::KEYFRAME, i, 5 << 20);
        assert!(pb.len() <= 3);
    }
    assert_eq!(pb.stats().dropped, 7);
}

#[test]
fn never_held_longer_than_the_bound() {
    let t0 = Instant::now();
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::adaptive(ms(0), ms(200)));
    // Frames whose transit grows by 1 s each: the delay is capped, and every frame goes
    // out at most 200 ms after it was complete.
    for i in 0..5u32 {
        let at = t0 + Duration::from_millis(u64::from(i) * 1033);
        pb.push(3000 * i, at, VideoFrameFlags::NONE, i, 10);
        while let Some(due) = pb.poll_timeout() {
            let f = pb.pop(due).unwrap();
            assert!(f.playout <= f.completed + ms(200), "{f:?}");
        }
    }
    assert!(pb.stats().delay <= ms(200));
    assert!(pb.stats().late >= 3);
}

#[test]
fn clock_jump_starts_over() {
    let t0 = Instant::now();
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::fixed(ms(500)));
    for i in 0..30u32 {
        let at = t0 + Duration::from_micros(u64::from(i) * 33_333);
        pb.push(3000 * i, at, VideoFrameFlags::NONE, i, 10);
    }
    // 500 ms of delay: nothing out before 500 ms.
    assert!(pb.pop(t0 + ms(499)).is_none());
    assert_eq!(pb.len(), 30);
    // The sender restarts with a timestamp an hour back.
    let at = t0 + ms(1000);
    pb.push(
        3000u32.wrapping_mul(30).wrapping_sub(90_000 * 3600),
        at,
        VideoFrameFlags::KEYFRAME,
        99,
        10,
    );
    assert_eq!(pb.stats().resyncs, 1);
    // What was buffered goes out now, in order; the new frame after the fixed delay.
    let mut out = Vec::new();
    while let Some(f) = pb.pop(at) {
        out.push(f.data);
    }
    assert_eq!(out, (0..30).collect::<Vec<_>>());
    assert!(pb.pop(at + ms(499)).is_none());
    let f = pb.pop(at + ms(500)).unwrap();
    assert_eq!((f.data, f.playout), (99, at + ms(500)));
    // Timestamp wrap is not a jump.
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    for i in 0..60u32 {
        let at = t0 + Duration::from_micros(u64::from(i) * 33_333);
        pb.push(
            (u32::MAX - 90_000).wrapping_add(3000 * i),
            at,
            VideoFrameFlags::NONE,
            i,
            10,
        );
        while pb.pop(at + ms(5)).is_some() {}
    }
    assert_eq!(pb.stats().resyncs, 0);
    assert_eq!(pb.stats().played, 60);
}
