//! A receive-side playout buffer for video frames (ADR-092): see [`VideoPlayout`].

use std::collections::VecDeque;
use std::ops::{BitOr, BitOrAssign};
use std::time::{Duration, Instant};

use crate::delay::{DelayEstimator, us};
use crate::jitter::PlayoutDelay;

/// Most frames a [`VideoPlayout`] holds.
pub const VIDEO_PLAYOUT_MAX_FRAMES: usize = 256;
/// Most payload bytes a [`VideoPlayout`] holds (four frames of the largest size the frame
/// assembler gives).
pub const VIDEO_PLAYOUT_MAX_BYTES: usize = 16 << 20;
/// At most one frame interval shorter per this long (µs), between keyframes.
const DECREASE_EVERY_US: i64 = 1_000_000;
/// The frame interval assumed before two consecutive frames tell it (µs, 30 frames/s).
const DEFAULT_FRAME_US: i64 = 33_333;
/// Keyframe delays kept (the newest ones).
const KEYFRAME_DELAYS: usize = 2;
/// How long a keyframe's delay and a repair count towards the target (µs).
const MEMORY_US: i64 = 10_000_000;
/// Media time and arrival time apart by more than this (µs) between two frames: the clock
/// starts over.
const RESYNC_US: i64 = 10_000_000;

/// What the frame assembler knows of a frame given to [`VideoPlayout::push`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct VideoFrameFlags(u8);

impl VideoFrameFlags {
    /// Nothing special: a delta frame, contiguous with the previous one, complete on its own.
    pub const NONE: VideoFrameFlags = VideoFrameFlags(0);
    /// A keyframe (decodable without the frames before it).
    pub const KEYFRAME: VideoFrameFlags = VideoFrameFlags(1);
    /// Packets are missing between the previous frame and this one.
    pub const DISCONTINUOUS: VideoFrameFlags = VideoFrameFlags(2);
    /// The frame was held up by loss repair: completed by a retransmission, or waiting
    /// behind a packet that was being repaired or given up. Its delay tells nothing of the
    /// network's jitter.
    pub const REPAIRED: VideoFrameFlags = VideoFrameFlags(4);

    /// Whether every flag of `other` is set.
    #[must_use]
    pub fn contains(self, other: VideoFrameFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for VideoFrameFlags {
    type Output = VideoFrameFlags;
    fn bitor(self, rhs: VideoFrameFlags) -> VideoFrameFlags {
        VideoFrameFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for VideoFrameFlags {
    fn bitor_assign(&mut self, rhs: VideoFrameFlags) {
        self.0 |= rhs.0;
    }
}

/// Counters and the current delay of a [`VideoPlayout`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VideoPlayoutStats {
    /// Frames pushed.
    pub received: u64,
    /// Frames handed out.
    pub played: u64,
    /// Frames completed after their playout instant (handed out at once, not discarded:
    /// later frames depend on them).
    pub late: u64,
    /// Frames flagged [`VideoFrameFlags::REPAIRED`] (left out of the jitter statistics).
    pub repaired: u64,
    /// Frames dropped because the buffer was full.
    pub dropped: u64,
    /// Times the media clock jumped and the playout clock started over.
    pub resyncs: u64,
    /// The current playout delay beyond the fastest frame's transit.
    pub delay: Duration,
    /// The delay the measured jitter, keyframes and repairs ask for.
    pub target: Duration,
}

/// A frame handed out by [`VideoPlayout::pop`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VideoPlayoutFrame<T> {
    /// Its extended RTP timestamp.
    pub timestamp: u64,
    /// It was pushed as a keyframe.
    pub keyframe: bool,
    /// No packet is missing and no frame was dropped since the previous frame.
    pub contiguous: bool,
    /// When it was complete (pushed).
    pub completed: Instant,
    /// When it is to be shown.
    pub playout: Instant,
    /// What was pushed.
    pub data: T,
}

#[derive(Debug)]
struct Entry<T> {
    ts: u64,
    /// Media time (µs on the playout clock); `None`: due at once (the clock started over).
    ts_us: Option<i64>,
    completed: Instant,
    completed_us: i64,
    keyframe: bool,
    contiguous: bool,
    bytes: usize,
    data: T,
}

/// A playout buffer for the complete frames of one video stream: frames go in as the frame
/// assembler completes them (in decoding order), and come out in that order at their playout
/// instants, so that frames completed unevenly are shown evenly.
///
/// - **Playout clock.** A frame of RTP time `ts` plays at `ts + offset`. The offset is the
///   smallest transit time seen lately (completion minus media time, the minimum over two
///   windows of 5 s) plus the target delay. A frame never plays before the previous one,
///   before it is complete, or later than the upper bound after it is complete.
/// - **Target delay.** The largest of:
///   - the 95th percentile of each frame's delay beyond that smallest transit, from a
///     histogram of 2 ms buckets forgetting by 0.997 per frame (about 11 s at 30 frames/s),
///     recomputed every 8 frames and at once for a frame later than it;
///   - **keyframes**: the delay of either of the two latest keyframes of the last 10 s.
///     Keyframes are many times larger than the frames between them, so they take longer to
///     arrive, yet are too few to move the percentile, and a late keyframe stalls every frame
///     behind it;
///
///   plus, **NACK**: while frames needed loss repair in the last 10 s, the round-trip time
///   ([`set_round_trip`](Self::set_round_trip)), room for one retransmission. Frames flagged
///   [`VideoFrameFlags::REPAIRED`] stay out of the histogram: their delay is the repair's,
///   not the network's jitter. All within [`PlayoutDelay`]'s bounds.
/// - **Adapting.** A longer delay applies at once (the frames still buffered play later: a
///   pause). A shorter one applies at once at a keyframe (the frames before it go out at
///   once: the player skips ahead where prediction starts over); between keyframes, by at
///   most one frame interval per second. A buffered frame a shorter delay makes due plays at
///   the moment of the change, not before.
/// - **Late frames** (completed after their playout instant) go out at once: a video frame
///   is not discarded for being late, since the frames after it are predicted from it. The
///   delay then grows as the percentile says.
/// - **Bounds.** At most [`VIDEO_PLAYOUT_MAX_FRAMES`] frames and [`VIDEO_PLAYOUT_MAX_BYTES`]
///   bytes. When full, the frames before the oldest buffered keyframe after the first are
///   dropped (the keyframe does not need them); with no such keyframe the oldest frame is
///   dropped and [`take_keyframe_request`](Self::take_keyframe_request) says a keyframe is
///   needed. The frame after a drop has `contiguous = false`.
/// - **Clock jumps.** Media time and completion time more than 10 s apart from one frame to
///   the next (a restarted sender, a new source behind the same SSRC): the frames buffered go
///   out at once and the playout clock starts over.
///
/// Time per frame is O(1) plus, every 8 frames, a histogram scan up to the percentile; memory
/// is the frames and at most 1002 histogram buckets.
///
/// Sans-IO: [`push`](Self::push) frames as they are complete, take them with
/// [`pop`](Self::pop) when [`poll_timeout`](Self::poll_timeout) comes.
#[derive(Debug)]
pub struct VideoPlayout<T> {
    clock: u32,
    bounds: PlayoutDelay,
    frames: VecDeque<Entry<T>>,
    bytes: usize,
    epoch: Option<Instant>,
    /// The extended timestamp of the latest frame pushed.
    last_ts: Option<u64>,
    base_ts: u64,
    /// `(media µs, completion µs)` of the latest frame pushed.
    last_push: Option<(i64, i64)>,
    est: DelayEstimator,
    target_us: i64,
    /// `(completion µs, delay µs)` of the latest keyframes.
    keys: [Option<(i64, i64)>; KEYFRAME_DELAYS],
    rtt_us: Option<i64>,
    last_repair_us: Option<i64>,
    offset_us: Option<i64>,
    last_decrease_us: i64,
    /// When the offset was last shortened.
    shortened_us: i64,
    frame_ticks: Option<u64>,
    last_out_us: Option<i64>,
    gap: bool,
    keyframe_needed: bool,
    stats: VideoPlayoutStats,
}

impl<T> VideoPlayout<T> {
    /// A buffer for a stream of RTP clock rate `clock` (Hz; 0 is taken as 90000) and playout
    /// delay `bounds`.
    #[must_use]
    pub fn new(clock: u32, bounds: PlayoutDelay) -> VideoPlayout<T> {
        VideoPlayout {
            clock: if clock == 0 { 90_000 } else { clock },
            bounds,
            frames: VecDeque::new(),
            bytes: 0,
            epoch: None,
            last_ts: None,
            base_ts: 0,
            last_push: None,
            est: DelayEstimator::new(bounds.max()),
            target_us: us(bounds.min()),
            keys: [None; KEYFRAME_DELAYS],
            rtt_us: None,
            last_repair_us: None,
            offset_us: None,
            last_decrease_us: 0,
            shortened_us: i64::MIN,
            frame_ticks: None,
            last_out_us: None,
            gap: false,
            keyframe_needed: false,
            stats: VideoPlayoutStats::default(),
        }
    }

    /// The clock rate.
    #[must_use]
    pub fn clock(&self) -> u32 {
        self.clock
    }

    /// The bounds of the delay.
    #[must_use]
    pub fn bounds(&self) -> PlayoutDelay {
        self.bounds
    }

    /// Frames buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The round-trip time a retransmission takes, `None` when the stream is not repaired
    /// by retransmission (no NACK): the target's room for one while repairs happen.
    pub fn set_round_trip(&mut self, rtt: Option<Duration>) {
        self.rtt_us = rtt.map(us);
    }

    fn since_epoch(&self, t: Instant) -> i64 {
        self.epoch
            .and_then(|e| t.checked_duration_since(e))
            .map_or(0, us)
    }

    fn at(&self, playout_us: i64) -> Instant {
        let e = self.epoch.unwrap_or_else(Instant::now);
        e + Duration::from_micros(playout_us.max(0) as u64)
    }

    fn extend_ts(&mut self, ts: u32) -> u64 {
        let ext = match self.last_ts {
            None => {
                self.base_ts = u64::from(ts);
                u64::from(ts)
            }
            Some(r) => {
                let v = r as i64 + i64::from(ts.wrapping_sub(r as u32) as i32);
                if v < 0 { u64::from(ts) } else { v as u64 }
            }
        };
        if let Some(prev) = self.last_ts.filter(|&p| ext > p) {
            let dt = ext - prev;
            if self.frame_ticks.is_none_or(|f| dt <= 2 * f) {
                self.frame_ticks = Some(dt);
            }
        }
        self.last_ts = Some(ext);
        ext
    }

    fn media_us(&self, ext_ts: u64) -> i64 {
        let d = i128::from(ext_ts) - i128::from(self.base_ts);
        (d * 1_000_000 / i128::from(self.clock)) as i64
    }

    fn frame_us(&self) -> i64 {
        self.frame_ticks.map_or(DEFAULT_FRAME_US, |f| {
            (u128::from(f) * 1_000_000 / u128::from(self.clock)) as i64
        })
    }

    /// The playout instant (µs) of `e`: its media time plus the offset, at most the upper
    /// bound after it was complete, not before that, before the previous frame's, nor before
    /// the offset was last shortened.
    fn due_us(&self, e: &Entry<T>) -> i64 {
        let ideal = match (e.ts_us, self.offset_us) {
            (Some(t), Some(off)) => t.saturating_add(off),
            _ => e.completed_us,
        };
        let capped = ideal.min(e.completed_us + us(self.bounds.max()));
        capped
            .max(e.completed_us)
            .max(self.shortened_us)
            .max(self.last_out_us.unwrap_or(i64::MIN))
    }

    /// Takes the frame of RTP timestamp `ts`, complete at `completed`; `bytes` counts against
    /// [`VIDEO_PLAYOUT_MAX_BYTES`]. Frames are pushed in decoding order (as the frame
    /// assembler gives them).
    pub fn push(
        &mut self,
        ts: u32,
        completed: Instant,
        flags: VideoFrameFlags,
        data: T,
        bytes: usize,
    ) {
        self.epoch.get_or_insert(completed);
        let now_us = self.since_epoch(completed);
        let ext = self.extend_ts(ts);
        let ts_us = self.media_us(ext);
        if let Some((m, c)) = self.last_push {
            if ((ts_us - m) - (now_us - c)).abs() > RESYNC_US {
                self.resync(now_us);
            }
        }
        self.last_push = Some((ts_us, now_us));
        let keyframe = flags.contains(VideoFrameFlags::KEYFRAME);
        self.stats.received += 1;
        if self
            .offset_us
            .is_some_and(|off| ts_us.saturating_add(off) < now_us)
        {
            self.stats.late += 1;
        }
        if flags.contains(VideoFrameFlags::REPAIRED) {
            self.stats.repaired += 1;
            self.last_repair_us = Some(now_us);
        } else {
            let (d, _) = self.est.sample(now_us, now_us - ts_us);
            if keyframe {
                self.keys.rotate_right(1);
                self.keys[0] = Some((now_us, d));
            }
        }
        self.retarget(now_us);
        self.adapt(now_us, ts_us, keyframe);
        self.frames.push_back(Entry {
            ts: ext,
            ts_us: Some(ts_us),
            completed,
            completed_us: now_us,
            keyframe,
            contiguous: !flags.contains(VideoFrameFlags::DISCONTINUOUS),
            bytes,
            data,
        });
        self.bytes += bytes;
        while self.frames.len() > VIDEO_PLAYOUT_MAX_FRAMES || self.bytes > VIDEO_PLAYOUT_MAX_BYTES {
            self.drop_for_room();
        }
    }

    /// The target from the percentile, the recent keyframes and repairs.
    fn retarget(&mut self, now_us: i64) {
        let recent = |t: i64| now_us - t <= MEMORY_US;
        let key = self
            .keys
            .iter()
            .flatten()
            .filter(|(t, _)| recent(*t))
            .map(|(_, d)| *d)
            .max()
            .unwrap_or(0);
        let repair = match (self.rtt_us, self.last_repair_us) {
            (Some(rtt), Some(t)) if recent(t) => rtt,
            _ => 0,
        };
        self.target_us = (self.est.quantile_us().max(key) + repair)
            .clamp(us(self.bounds.min()), us(self.bounds.max()));
    }

    /// Moves the playout offset towards the target as the type documentation says.
    fn adapt(&mut self, now_us: i64, ts_us: i64, keyframe: bool) {
        let min = match self.est.min_transit() {
            i64::MAX => now_us - ts_us,
            m => m,
        };
        let want = min + self.target_us;
        let Some(off) = self.offset_us else {
            self.offset_us = Some(want);
            self.last_decrease_us = now_us;
            return;
        };
        if want > off {
            self.offset_us = Some(want);
            self.last_decrease_us = now_us;
            return;
        }
        if keyframe && want < off {
            self.shorten(now_us, want);
            return;
        }
        let excess = off - want;
        let frame = self.frame_us();
        if excess >= frame / 2 && now_us - self.last_decrease_us >= DECREASE_EVERY_US {
            self.shorten(now_us, off - excess.min(frame));
        }
    }

    /// A shorter offset from `now_us` on: buffered frames it makes due play at `now_us`, not
    /// before.
    fn shorten(&mut self, now_us: i64, off: i64) {
        self.offset_us = Some(off);
        self.last_decrease_us = now_us;
        self.shortened_us = now_us;
    }

    /// Drops frames for room: those before the oldest keyframe after the first, else the
    /// first (a keyframe is then needed).
    fn drop_for_room(&mut self) {
        let n = match self.frames.iter().skip(1).position(|e| e.keyframe) {
            Some(i) => i + 1,
            None => {
                self.keyframe_needed = true;
                1
            }
        };
        for e in self.frames.drain(..n) {
            self.bytes -= e.bytes;
            self.stats.dropped += 1;
        }
        self.gap = true;
    }

    /// The media clock jumped: what is buffered goes out at once, the clock starts over.
    fn resync(&mut self, now_us: i64) {
        for e in &mut self.frames {
            e.ts_us = None;
        }
        self.est.reset_min(now_us);
        self.offset_us = None;
        self.keys = [None; KEYFRAME_DELAYS];
        self.stats.resyncs += 1;
    }

    /// Whether frames were dropped with no keyframe to resume from since the previous call:
    /// the sender should be asked for one (PLI).
    pub fn take_keyframe_request(&mut self) -> bool {
        std::mem::take(&mut self.keyframe_needed)
    }

    /// When the next frame is due (`None`: nothing buffered).
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.frames.front().map(|e| self.at(self.due_us(e)))
    }

    /// The next frame if its playout instant has come by `now`.
    pub fn pop(&mut self, now: Instant) -> Option<VideoPlayoutFrame<T>> {
        let due = self.poll_timeout()?;
        if due > now {
            return None;
        }
        self.pop_front()
    }

    fn pop_front(&mut self) -> Option<VideoPlayoutFrame<T>> {
        let p = self.frames.front().map(|e| self.due_us(e))?;
        let e = self.frames.pop_front()?;
        self.bytes -= e.bytes;
        self.last_out_us = Some(p);
        self.stats.played += 1;
        Some(VideoPlayoutFrame {
            timestamp: e.ts,
            keyframe: e.keyframe,
            contiguous: e.contiguous && !std::mem::take(&mut self.gap),
            completed: e.completed,
            playout: self.at(p),
            data: e.data,
        })
    }

    /// Every buffered frame at once, in order, whatever its playout instant (for example
    /// before the stream changes clock rate).
    pub fn drain(&mut self) -> Vec<VideoPlayoutFrame<T>> {
        let mut out = Vec::with_capacity(self.frames.len());
        while let Some(f) = self.pop_front() {
            out.push(f);
        }
        out
    }

    /// The current playout delay beyond the fastest frame's transit.
    #[must_use]
    pub fn delay(&self) -> Duration {
        let d = match self.offset_us {
            Some(off) if self.est.min_transit() != i64::MAX => off - self.est.min_transit(),
            _ => self.target_us,
        };
        Duration::from_micros(d.max(0) as u64)
    }

    /// The counters and the current delays.
    #[must_use]
    pub fn stats(&self) -> VideoPlayoutStats {
        VideoPlayoutStats {
            delay: self.delay(),
            target: Duration::from_micros(self.target_us.max(0) as u64),
            ..self.stats
        }
    }
}
