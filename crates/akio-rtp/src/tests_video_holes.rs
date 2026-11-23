//! The video playout buffer's second pass (ADR-092 update): missing packets given up at the
//! playout deadline of the frame waiting behind them, and frame-size-aware delay estimation,
//! under simulated loss, reordering, retransmission and jitter.

use std::time::{Duration, Instant};

use crate::codec::{CodecKind, FrameAssembler};
use crate::tests_video::{Net, Pkt, Rng, ms, packets, uneven};
use crate::{PlayoutDelay, VideoFrameFlags, VideoPlayout, VideoPlayoutFrame};

/// The frames the assembler has complete into the buffer at `at` (flagged as akio-webrtc
/// flags them).
fn drain(asm: &mut FrameAssembler, pb: &mut VideoPlayout<u64>, at: Instant, rtx: bool) {
    let mut repaired = rtx;
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
        pb.push(f.timestamp as u32, at, flags, f.timestamp, f.data.len());
    }
}

/// The receive path with an assembler that gives a gap up after `count` packets and, with
/// `deadlines`, at the playout deadline of the frame waiting behind it.
fn run(
    pkts: &[Pkt],
    pb: &mut VideoPlayout<u64>,
    count: usize,
    deadlines: bool,
) -> Vec<VideoPlayoutFrame<u64>> {
    let mut asm = FrameAssembler::new(CodecKind::Vp8, count);
    let mut out = Vec::new();
    let take = |pb: &mut VideoPlayout<u64>, until: Instant, out: &mut Vec<_>| {
        while let Some(due) = pb.poll_timeout().filter(|d| *d <= until) {
            let f = pb.pop(due).expect("due frame");
            assert_eq!(f.playout, due);
            out.push(f);
        }
    };
    let mut hole: Option<Instant> = None;
    let mut i = 0;
    loop {
        let next = pkts.get(i).map(|p| p.at);
        if let Some(h) = hole.filter(|h| next.is_none_or(|n| *h < n)) {
            take(pb, h, &mut out);
            assert!(asm.give_up_hole());
            pb.hole_given_up();
            drain(&mut asm, pb, h, false);
            hole = asm.blocked().map(|ts| pb.hole_deadline(ts as u32, h));
            continue;
        }
        let Some(p) = pkts.get(i) else { break };
        i += 1;
        take(pb, p.at, &mut out);
        asm.push(p.seq, p.ts, p.marker, &p.payload, p.at);
        drain(&mut asm, pb, p.at, p.rtx);
        hole = if deadlines {
            asm.blocked().map(|ts| pb.hole_deadline(ts as u32, p.at))
        } else {
            None
        };
    }
    take(pb, pkts.last().unwrap().at + ms(3000), &mut out);
    out
}

/// The longest pause between two frames shown (ms).
fn longest_pause(out: &[VideoPlayoutFrame<u64>]) -> f64 {
    out.windows(2)
        .map(|w| w[1].playout.duration_since(w[0].playout).as_secs_f64() * 1e3)
        .fold(0.0, f64::max)
}

#[test]
fn assembler_reports_and_gives_up_holes() {
    let t = Instant::now();
    let mut asm = FrameAssembler::new(CodecKind::Vp8, 1000);
    let vp8 = |start: bool| vec![if start { 0x10 } else { 0x00 }, 1, 0, 0];
    // Frame 1 (seq 10..12) complete; frame 2 (13..15) misses 14; frame 3 (16..18) complete.
    for (seq, ts, start, end) in [
        (10, 3000, true, false),
        (11, 3000, false, false),
        (12, 3000, false, true),
        (13, 6000, true, false),
        (15, 6000, false, true),
    ] {
        asm.push(seq, ts, end, &vp8(start), t);
    }
    assert!(asm.pop().is_some());
    assert!(asm.pop().is_none());
    // Frame 2 still arriving: nothing waits behind the hole.
    assert_eq!(asm.blocked(), None);
    assert!(!asm.give_up_hole());
    for (seq, start, end) in [(16, true, false), (17, false, false)] {
        asm.push(seq, 9000, end, &vp8(start), t);
    }
    assert!(asm.pop().is_none());
    // Frame 3 waits behind 14.
    assert_eq!(asm.blocked(), Some(9000));
    assert!(asm.accepts(14) && !asm.accepts(12) && !asm.accepts(15));
    asm.push(18, 9000, true, &vp8(false), t);
    assert!(asm.give_up_hole());
    let f = asm.pop().expect("frame 3");
    assert_eq!(f.timestamp, 9000);
    assert!(!f.contiguous);
    assert!(!asm.accepts(14), "given up");
    // A whole frame lost: 19..21 missing, frame 5 (22..23) behind it.
    for (seq, start, end) in [(22, true, false), (23, false, true)] {
        asm.push(seq, 15_000, end, &vp8(start), t);
    }
    assert!(asm.pop().is_none());
    assert_eq!(asm.blocked(), Some(15_000));
}

#[test]
fn holes_given_up_at_the_deadline_not_by_count() {
    let t0 = Instant::now();
    // 1 % loss, no retransmission, three packets a frame (about 90 packets/s): the count of
    // 30 packets stalls the picture for about 10 frames at each loss.
    let net = Net {
        frames: 1800,
        key_every: 100_000,
        key_packets: 3,
        jitter: 10,
        loss: 0.01,
        rtt: None,
    };
    let pkts = packets(t0, &net, &mut Rng(21));
    let mut counted = VideoPlayout::new(90_000, PlayoutDelay::default());
    let out_c = run(&pkts, &mut counted, 30, false);
    let mut timed = VideoPlayout::new(90_000, PlayoutDelay::default());
    let out_t = run(&pkts, &mut timed, 1000, true);
    let (sc, st) = (counted.stats(), timed.stats());
    // Each loss costs its frame either way; by count, a second loss before the count is
    // reached costs the frames between as well.
    assert!(out_t.len() >= out_c.len(), "{sc:?} {st:?}");
    assert!(out_t.len() > 1700 && out_t.len() < 1800);
    assert!(st.holes_given_up > 30, "{st:?}");
    assert_eq!(sc.holes_given_up, 0);
    // By count, a loss pauses the picture for about 360 ms; by deadline, for the lost
    // frame's interval and a little jitter (three intervals where two frames were lost).
    let (pc, pt) = (longest_pause(&out_c[150..]), longest_pause(&out_t[150..]));
    assert!(pc > 250.0, "{pc}");
    assert!(pt < 110.0, "{pt}");
    let single = out_t[150..]
        .windows(2)
        .filter(|w| w[1].timestamp - w[0].timestamp == 6000)
        .map(|w| w[1].playout.duration_since(w[0].playout))
        .max()
        .unwrap();
    assert!(single < ms(80), "{single:?}");
    // Frames released by count are late and flagged repaired; by deadline far fewer are.
    assert!(sc.late > 3 * st.late.max(1), "{sc:?} {st:?}");
    assert!(uneven(&out_t, 150) < uneven(&out_c, 150) / 2);
}

#[test]
fn retransmissions_beat_the_deadline() {
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
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    pb.set_round_trip(Some(rtt));
    let out = run(&pkts, &mut pb, 1000, true);
    let s = pb.stats();
    // The deadline waits at least a round trip: the retransmissions come in time, except
    // perhaps the first one (before any repair the target has no round trip in it).
    assert!(s.holes_given_up <= 2, "{s:?}");
    assert!(out.len() >= 1798, "{s:?}");
    assert!(out.iter().filter(|f| !f.contiguous).count() <= 2);
    assert!(s.repaired > 40, "{s:?}");
}

#[test]
fn reordered_packet_behind_late_frames_is_waited_for() {
    let t0 = Instant::now();
    let mut asm = FrameAssembler::new(CodecKind::Vp8, 1000);
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    let vp8 = |start: bool| vec![if start { 0x10 } else { 0x00 }, 1, 0, 0];
    // 60 frames of 2 packets at 20 ms transit.
    let mut seq = 100u64;
    for i in 0..60u32 {
        let at = t0 + Duration::from_micros(u64::from(i) * 33_333) + ms(20);
        asm.push(seq, 3000 * i, false, &vp8(true), at);
        asm.push(seq + 1, 3000 * i, true, &vp8(false), at);
        seq += 2;
        drain(&mut asm, &mut pb, at, false);
        while pb.pop(at).is_some() {}
    }
    // A 200 ms spike: frame 60's second packet comes 5 ms after frame 61, both long past
    // their playout instants.
    let spike = t0 + Duration::from_micros(60 * 33_333) + ms(220);
    asm.push(seq, 3000 * 60, false, &vp8(true), spike);
    asm.push(seq + 2, 3000 * 61, false, &vp8(true), spike);
    asm.push(seq + 3, 3000 * 61, true, &vp8(false), spike);
    assert!(asm.pop().is_none());
    let ts = asm.blocked().expect("frame 61 waits") as u32;
    let deadline = pb.hole_deadline(ts, spike);
    // Already late, yet the wait lasts the target delay (the jitter allowed for), 10 ms at
    // least.
    assert!(deadline >= spike + ms(10).max(pb.stats().target));
    let later = spike + ms(5);
    assert_eq!(
        pb.hole_deadline(ts, later),
        deadline,
        "the wait began at the first call"
    );
    asm.push(seq + 1, 3000 * 60, true, &vp8(false), later);
    drain(&mut asm, &mut pb, later, false);
    assert_eq!(asm.blocked(), None);
    let mut out = Vec::new();
    while let Some(f) = pb.pop(later + ms(100)) {
        out.push(f.timestamp);
    }
    assert_eq!(
        out[out.len() - 2..],
        [3000 * 60, 3000 * 61],
        "both frames played"
    );
    assert_eq!(pb.stats().holes_given_up, 0);
}

#[test]
fn rare_keyframes_are_covered_by_their_size() {
    let t0 = Instant::now();
    // A 40-packet keyframe every 15 s: longer than the 10 s the latest keyframe's delay is
    // remembered, so only the size estimate gives the next one room.
    let net = Net {
        frames: 3600,
        key_every: 450,
        key_packets: 40,
        jitter: 10,
        loss: 0.0,
        rtt: None,
    };
    let pkts = packets(t0, &net, &mut Rng(5));
    let mut pb = VideoPlayout::new(90_000, PlayoutDelay::default());
    let mut out = Vec::new();
    let mut asm = FrameAssembler::new(CodecKind::Vp8, 30);
    let mut sizes = Vec::new();
    for p in &pkts {
        while let Some(f) = pb.pop(p.at) {
            out.push(f);
        }
        asm.push(p.seq, p.ts, p.marker, &p.payload, p.at);
        let before = pb.stats().received;
        drain(&mut asm, &mut pb, p.at, false);
        if pb.stats().received > before {
            sizes.push(pb.stats().size_delay);
        }
    }
    out.extend(pb.drain());
    let s = pb.stats();
    assert_eq!(out.len(), 3600);
    // The keyframe is 37 packets (111 bytes) larger, 37 ms longer to arrive: the estimate
    // says about that once the first keyframes were seen, and keeps it between keyframes.
    assert!(s.size_delay >= ms(25) && s.size_delay <= ms(50), "{s:?}");
    assert!(
        sizes[1000..].iter().all(|d| *d >= ms(25)),
        "kept between keyframes"
    );
    // After the first two keyframes each one is shown in time: the picture pauses by at
    // most the jitter.
    for w in out.windows(2).skip(901).filter(|w| w[1].keyframe) {
        let gap = w[1].playout.duration_since(w[0].playout);
        assert!(gap <= Duration::from_micros(33_334) + ms(12), "{gap:?}");
    }
    // Without it, the target falls back to the jitter's 10 ms between keyframes.
    assert!(s.target >= ms(37), "{s:?}");
}
