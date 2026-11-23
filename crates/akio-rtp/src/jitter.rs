//! A receive-side jitter buffer (playout buffer) for audio (ADR-087): see [`JitterBuffer`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::delay::{DelayEstimator, us};
use crate::xr::JitterBufferConfig;

/// The largest [`PlayoutDelay::max`] (2 s).
pub const MAX_PLAYOUT_DELAY: Duration = Duration::from_secs(2);
/// Most frames a [`JitterBuffer`] holds: sequence numbers from the next frame to play to the
/// newest one received.
pub const JITTER_BUFFER_MAX_FRAMES: usize = 1024;
/// Most payload bytes a [`JitterBuffer`] holds.
pub const JITTER_BUFFER_MAX_BYTES: usize = 256 * 1024;
/// Discarded sequence numbers kept until [`JitterBuffer::drain_discarded`].
const MAX_DISCARDED: usize = 4096;
/// At most one frame shorter per this long (µs) within a talkspurt.
const DECREASE_EVERY_US: i64 = 1_000_000;
/// The frame length assumed before two consecutive frames tell it (µs).
const DEFAULT_FRAME_US: i64 = 20_000;
/// Sequence numbers behind the next one to play whose fate is remembered (duplicate or late).
const HISTORY: u64 = 128;

/// The bounds of a [`JitterBuffer`]'s playout delay: the delay beyond the fastest packet's
/// transit time. Equal bounds make a fixed buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayoutDelay {
    min: Duration,
    max: Duration,
}

impl Default for PlayoutDelay {
    /// Adaptive between 0 and 500 ms.
    fn default() -> PlayoutDelay {
        PlayoutDelay::adaptive(Duration::ZERO, Duration::from_millis(500))
    }
}

impl PlayoutDelay {
    /// A delay that adapts to the measured jitter between `min` and `max` (at most
    /// [`MAX_PLAYOUT_DELAY`]; `min` at most `max`).
    #[must_use]
    pub fn adaptive(min: Duration, max: Duration) -> PlayoutDelay {
        let max = max.min(MAX_PLAYOUT_DELAY);
        PlayoutDelay {
            min: min.min(max),
            max,
        }
    }

    /// A fixed delay (at most [`MAX_PLAYOUT_DELAY`]).
    #[must_use]
    pub fn fixed(delay: Duration) -> PlayoutDelay {
        PlayoutDelay::adaptive(delay, delay)
    }

    /// The lower bound.
    #[must_use]
    pub fn min(&self) -> Duration {
        self.min
    }

    /// The upper bound.
    #[must_use]
    pub fn max(&self) -> Duration {
        self.max
    }

    /// Whether the delay is fixed (`min == max`).
    #[must_use]
    pub fn is_fixed(&self) -> bool {
        self.min == self.max
    }
}

/// What became of a frame given to [`JitterBuffer::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JitterPush {
    /// Buffered until its playout instant.
    Buffered,
    /// A copy of a frame buffered or played already: dropped.
    Duplicate,
    /// Arrived after a later frame went out (its own was given up as lost): discarded.
    Late,
    /// The buffer was full: discarded.
    Overflow,
}

/// Counters and the current delay of a [`JitterBuffer`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JitterBufferStats {
    /// Frames buffered.
    pub received: u64,
    /// Frames handed out.
    pub played: u64,
    /// Frames given up as missing.
    pub lost: u64,
    /// Frames discarded as late.
    pub late: u64,
    /// Frames discarded because the buffer was full (buffered frames among them when a jump
    /// in sequence numbers started the buffer over).
    pub overflow: u64,
    /// Copies dropped.
    pub duplicates: u64,
    /// Frames that arrived after a frame with a higher sequence number, in time.
    pub reordered: u64,
    /// The current playout delay beyond the fastest packet's transit (RFC 3611's nominal
    /// jitter buffer delay).
    pub delay: Duration,
    /// The delay the measured jitter asks for.
    pub target: Duration,
}

/// A frame handed out by [`JitterBuffer::pop`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JitterFrame<T> {
    /// Its extended sequence number.
    pub seq: u64,
    /// Its extended RTP timestamp.
    pub timestamp: u64,
    /// The RTP marker bit (for audio: the first packet of a talkspurt).
    pub marker: bool,
    /// When it arrived.
    pub arrival: Instant,
    /// When it is to be played.
    pub playout: Instant,
    /// No frame is missing or was discarded since the previous one.
    pub contiguous: bool,
    /// What was pushed.
    pub data: T,
}

#[derive(Debug)]
struct Entry<T> {
    ts: u64,
    ts_us: i64,
    arrival: Instant,
    marker: bool,
    bytes: usize,
    data: T,
}

#[derive(Debug)]
enum Slot<T> {
    /// Not received (yet).
    Empty,
    /// No media (FEC, padding): not a gap.
    Skipped,
    /// Received but discarded (overflow): a gap, not a loss.
    Dropped,
    Frame(Entry<T>),
}

/// A jitter buffer (playout buffer) for one RTP stream of single-packet frames (audio): frames
/// go in as their packets arrive, in any order, and come out in sequence order at their
/// playout instants.
///
/// - **Playout clock.** A frame of RTP time `ts` plays at `ts + offset`, both in local time.
///   The offset is the smallest transit time seen lately (arrival minus media time, the
///   minimum over two windows of 5 s, so a clock drift or a route change moves it) plus the
///   target delay.
/// - **Target delay.** The 95th percentile of each packet's delay beyond that smallest transit
///   (rounded up to 2 ms), from a histogram of 2 ms buckets that forgets with a factor of 0.997 per packet (about
///   7 s at 50 packets per second), clamped to [`PlayoutDelay`]'s bounds. It is recomputed
///   every 8 packets, and at once when a packet comes later than it.
/// - **Adapting.** A longer delay applies at once (the frames still buffered play later, and
///   the application conceals the pause). A shorter one applies at the start of a talkspurt
///   (the RTP marker bit, or a timestamp that jumps further than the sequence numbers do, as
///   after silence suppression or Opus DTX) while nothing is buffered; a stream that never
///   pauses shortens its delay by at most one frame per second, the frame after the change
///   then playing that much sooner than its predecessor's end (the application drops or
///   compresses that much).
/// - **Losses.** A missing frame is given up when a later frame's playout instant comes: that
///   frame goes out with `contiguous = false`. A packet arriving after that is *late* and
///   discarded, as is one arriving when the buffer is full (*overflow*: more than
///   [`JITTER_BUFFER_MAX_FRAMES`] frames or [`JITTER_BUFFER_MAX_BYTES`] bytes); both are the
///   discards of RTCP XR VoIP metrics ([`JitterBuffer::drain_discarded`]). A frame arriving
///   after its own playout instant but before a later frame went out still plays, at once.
///   Duplicates are dropped.
///
/// Memory is bounded (the slots, at most 1002 histogram buckets, at most 4096 discarded
/// sequence numbers between reports) and so is time: a packet costs O(1) plus, every 8
/// packets, a scan of the histogram up to the percentile.
///
/// Sans-IO: [`push`](Self::push) frames as their packets arrive (extended sequence number,
/// RTP timestamp, arrival instant), take frames with [`pop`](Self::pop) when
/// [`poll_timeout`](Self::poll_timeout) comes.
#[derive(Debug)]
pub struct JitterBuffer<T> {
    clock: u32,
    bounds: PlayoutDelay,
    slots: VecDeque<Slot<T>>,
    frames: usize,
    bytes: usize,
    /// The next sequence number to play.
    head: Option<u64>,
    highest: Option<u64>,
    /// Bit `i`: sequence number `head - 1 - i` was played (else lost or discarded).
    played: u128,
    gap: bool,
    epoch: Option<Instant>,
    /// `(ext seq, ext ts)` of the highest sequence number: the timestamp rollover reference.
    ts_ref: Option<(u64, u64)>,
    base_ts: u64,
    est: DelayEstimator,
    target_us: i64,
    offset_us: Option<i64>,
    last_decrease_us: i64,
    frame_ticks: Option<u64>,
    /// `(seq, ext ts)` of the highest sequence number pushed.
    last_pushed: Option<(u64, u64)>,
    /// `(seq, ext ts, playout µs)` of the last frame handed out.
    last_out: Option<(u64, u64, i64)>,
    stats: JitterBufferStats,
    discarded: Vec<u64>,
}

impl<T> JitterBuffer<T> {
    /// A buffer for a stream of RTP clock rate `clock` (Hz; 0 is taken as 8000) and playout
    /// delay `bounds`.
    #[must_use]
    pub fn new(clock: u32, bounds: PlayoutDelay) -> JitterBuffer<T> {
        JitterBuffer {
            clock: if clock == 0 { 8000 } else { clock },
            bounds,
            slots: VecDeque::new(),
            frames: 0,
            bytes: 0,
            head: None,
            highest: None,
            played: 0,
            gap: false,
            epoch: None,
            ts_ref: None,
            base_ts: 0,
            est: DelayEstimator::new(bounds.max),
            target_us: us(bounds.min),
            offset_us: None,
            last_decrease_us: 0,
            frame_ticks: None,
            last_pushed: None,
            last_out: None,
            stats: JitterBufferStats::default(),
            discarded: Vec::new(),
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
        self.frames
    }

    /// Whether no frame is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }

    fn extend_ts(&mut self, seq: u64, ts: u32) -> u64 {
        let ext = match self.ts_ref {
            None => {
                self.base_ts = u64::from(ts);
                u64::from(ts)
            }
            Some((_, r)) => {
                let v = r as i64 + i64::from(ts.wrapping_sub(r as u32) as i32);
                if v < 0 { u64::from(ts) } else { v as u64 }
            }
        };
        if self.ts_ref.is_none_or(|(s, _)| seq > s) {
            self.ts_ref = Some((seq, ext));
        }
        ext
    }

    fn media_us(&self, ext_ts: u64) -> i64 {
        let d = i128::from(ext_ts) - i128::from(self.base_ts);
        (d * 1_000_000 / i128::from(self.clock)) as i64
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

    fn frame_us(&self) -> i64 {
        self.frame_ticks.map_or(DEFAULT_FRAME_US, |f| {
            (u128::from(f) * 1_000_000 / u128::from(self.clock)) as i64
        })
    }

    fn record(&mut self, seq: u64) {
        if self.discarded.len() < MAX_DISCARDED {
            self.discarded.push(seq);
        }
    }

    fn min_transit(&self) -> i64 {
        self.est.min_transit()
    }

    /// Takes the frame of extended sequence number `seq`, RTP timestamp `ts` and marker bit
    /// `marker` that arrived at `arrival`; `bytes` counts against
    /// [`JITTER_BUFFER_MAX_BYTES`].
    pub fn push(
        &mut self,
        seq: u64,
        ts: u32,
        marker: bool,
        arrival: Instant,
        data: T,
        bytes: usize,
    ) -> JitterPush {
        self.epoch.get_or_insert(arrival);
        let head = *self.head.get_or_insert(seq);
        if seq < head {
            let back = head - seq;
            if back <= HISTORY && (self.played >> (back - 1)) & 1 == 1 {
                self.stats.duplicates += 1;
                return JitterPush::Duplicate;
            }
            self.stats.late += 1;
            self.record(seq);
            return JitterPush::Late;
        }
        let cap = JITTER_BUFFER_MAX_FRAMES as u64;
        if seq - head >= 2 * cap {
            self.restart(seq);
        } else {
            while seq - self.head.unwrap_or(seq) >= cap {
                self.drop_front();
            }
        }
        let idx = (seq - self.head.unwrap_or(seq)) as usize;
        if let Some(Slot::Frame(_)) = self.slots.get(idx) {
            self.stats.duplicates += 1;
            return JitterPush::Duplicate;
        }
        while self.slots.len() <= idx {
            self.slots.push_back(Slot::Empty);
        }
        if self.bytes + bytes > JITTER_BUFFER_MAX_BYTES {
            self.stats.overflow += 1;
            self.record(seq);
            self.slots[idx] = Slot::Dropped;
            return JitterPush::Overflow;
        }
        if self.highest.is_some_and(|h| seq < h) {
            self.stats.reordered += 1;
        }
        self.highest = Some(self.highest.map_or(seq, |h| h.max(seq)));
        let ext_ts = self.extend_ts(seq, ts);
        let ts_us = self.media_us(ext_ts);
        let now_us = self.since_epoch(arrival);
        self.estimate(now_us, ts_us);
        self.adapt(now_us, seq, ext_ts, marker);
        if let Some((s, t)) = self.last_pushed {
            if seq == s + 1 && ext_ts > t {
                let dt = ext_ts - t;
                if self.frame_ticks.is_none_or(|f| dt <= 2 * f) {
                    self.frame_ticks = Some(dt);
                }
            }
        }
        if self.last_pushed.is_none_or(|(s, _)| seq > s) {
            self.last_pushed = Some((seq, ext_ts));
        }
        self.slots[idx] = Slot::Frame(Entry {
            ts: ext_ts,
            ts_us,
            arrival,
            marker,
            bytes,
            data,
        });
        self.frames += 1;
        self.bytes += bytes;
        self.stats.received += 1;
        JitterPush::Buffered
    }

    /// Sequence number `seq` carried no media (FEC, padding): not a loss.
    pub fn skip(&mut self, seq: u64) {
        let Some(head) = self.head else { return };
        if seq < head || seq - head >= JITTER_BUFFER_MAX_FRAMES as u64 {
            return;
        }
        let idx = (seq - head) as usize;
        while self.slots.len() <= idx {
            self.slots.push_back(Slot::Empty);
        }
        if let Slot::Empty = self.slots[idx] {
            self.slots[idx] = Slot::Skipped;
        }
    }

    /// Transit time statistics and the target delay, from a packet of media time `ts_us`
    /// arriving at `now_us`.
    fn estimate(&mut self, now_us: i64, ts_us: i64) {
        if self.est.sample(now_us, now_us - ts_us).1 {
            self.target_us = self
                .est
                .quantile_us()
                .clamp(us(self.bounds.min), us(self.bounds.max));
        }
    }

    /// Moves the playout offset towards the target as the module documentation says.
    fn adapt(&mut self, now_us: i64, seq: u64, ext_ts: u64, marker: bool) {
        let want = self.min_transit() + self.target_us;
        let Some(off) = self.offset_us else {
            self.offset_us = Some(want);
            self.last_decrease_us = now_us;
            return;
        };
        let talkspurt = self.frames == 0
            && (marker
                || self.last_out.is_some_and(|(s, t, _)| {
                    seq > s
                        && ext_ts > t
                        && self
                            .frame_ticks
                            .is_some_and(|f| ext_ts - t > (seq - s).saturating_mul(f))
                }));
        if talkspurt || want > off {
            self.offset_us = Some(want);
            self.last_decrease_us = now_us;
            return;
        }
        let excess = off - want;
        let frame = self.frame_us();
        if excess >= frame / 2 && now_us - self.last_decrease_us >= DECREASE_EVERY_US {
            self.offset_us = Some(off - excess.min(frame));
            self.last_decrease_us = now_us;
        }
    }

    /// The playout instant (µs since the epoch) of a frame of media time `ts_us`: never
    /// before the previous frame's.
    fn playout_us(&self, ts_us: i64) -> i64 {
        let p = ts_us + self.offset_us.unwrap_or(0);
        self.last_out.map_or(p, |(_, _, last)| p.max(last))
    }

    /// Gives up the slot at the front: a missing frame is lost, a buffered one discarded.
    fn drop_front(&mut self) {
        let Some(head) = self.head else { return };
        match self.slots.pop_front() {
            Some(Slot::Frame(e)) => {
                self.frames -= 1;
                self.bytes -= e.bytes;
                self.stats.overflow += 1;
                self.record(head);
                self.gap = true;
            }
            Some(Slot::Dropped) => self.gap = true,
            Some(Slot::Skipped) => {}
            Some(Slot::Empty) | None => {
                self.stats.lost += 1;
                self.gap = true;
            }
        }
        self.played <<= 1;
        self.head = Some(head + 1);
    }

    /// Starts over at `seq` after a jump of the sequence numbers: what is buffered is
    /// discarded.
    fn restart(&mut self, seq: u64) {
        let head = self.head.unwrap_or(seq);
        let slots = std::mem::take(&mut self.slots);
        for (i, s) in slots.into_iter().enumerate() {
            if let Slot::Frame(_) = s {
                self.stats.overflow += 1;
                self.record(head + i as u64);
            }
        }
        self.frames = 0;
        self.bytes = 0;
        self.played = 0;
        self.head = Some(seq);
        self.highest = None;
        self.gap = true;
    }

    /// When the next frame is due (`None`: nothing buffered).
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.slots.iter().find_map(|s| match s {
            Slot::Frame(e) => Some(self.at(self.playout_us(e.ts_us))),
            _ => None,
        })
    }

    /// The next frame if its playout instant has come by `now`; missing frames before it
    /// are given up as lost.
    pub fn pop(&mut self, now: Instant) -> Option<JitterFrame<T>> {
        let due = self.poll_timeout()?;
        if due > now {
            return None;
        }
        self.pop_front_frame()
    }

    fn pop_front_frame(&mut self) -> Option<JitterFrame<T>> {
        let i = self
            .slots
            .iter()
            .position(|s| matches!(s, Slot::Frame(_)))?;
        for _ in 0..i {
            self.drop_front();
        }
        let head = self.head?;
        let Some(Slot::Frame(e)) = self.slots.pop_front() else {
            return None;
        };
        let p = self.playout_us(e.ts_us);
        self.frames -= 1;
        self.bytes -= e.bytes;
        self.head = Some(head + 1);
        self.played = self.played << 1 | 1;
        self.stats.played += 1;
        self.last_out = Some((head, e.ts, p));
        Some(JitterFrame {
            seq: head,
            timestamp: e.ts,
            marker: e.marker,
            arrival: e.arrival,
            playout: self.at(p),
            contiguous: !std::mem::take(&mut self.gap),
            data: e.data,
        })
    }

    /// Every buffered frame at once, in order, whatever its playout instant (for example
    /// before the stream changes clock rate).
    pub fn drain(&mut self) -> Vec<JitterFrame<T>> {
        let mut out = Vec::with_capacity(self.frames);
        while let Some(f) = self.pop_front_frame() {
            out.push(f);
        }
        out
    }

    /// The media length of a frame, once two consecutive frames told it.
    #[must_use]
    pub fn frame_duration(&self) -> Option<Duration> {
        self.frame_ticks.map(|f| {
            Duration::from_micros((u128::from(f) * 1_000_000 / u128::from(self.clock)) as u64)
        })
    }

    /// The counters and the current delays.
    #[must_use]
    pub fn stats(&self) -> JitterBufferStats {
        JitterBufferStats {
            delay: self.delay(),
            target: Duration::from_micros(self.target_us.max(0) as u64),
            ..self.stats
        }
    }

    /// The current playout delay beyond the fastest packet's transit.
    #[must_use]
    pub fn delay(&self) -> Duration {
        let d = match self.offset_us {
            Some(off) if self.min_transit() != i64::MAX => off - self.min_transit(),
            _ => self.target_us,
        };
        Duration::from_micros(d.max(0) as u64)
    }

    /// The buffer as RTCP XR VoIP metrics describe it (RFC 3611 §4.7.6, §4.7.7): adaptive
    /// unless fixed, adjustment rate 1 for an adaptive buffer (a longer delay applies at
    /// once), the current delay as the nominal one, and the upper bound as the maximum and
    /// absolute maximum (the earliest a packet may come without being discarded).
    #[must_use]
    pub fn xr_config(&self) -> JitterBufferConfig {
        if self.bounds.is_fixed() {
            return JitterBufferConfig {
                adaptive: false,
                rate: 0,
                nominal: self.bounds.max,
                maximum: self.bounds.max,
                abs_max: self.bounds.max,
            };
        }
        JitterBufferConfig {
            adaptive: true,
            rate: 1,
            nominal: self.delay(),
            maximum: self.bounds.max,
            abs_max: self.bounds.max,
        }
    }

    /// The extended sequence numbers discarded (late or overflow) since the previous call,
    /// at most 4096: what the discard fields of RTCP XR VoIP metrics count
    /// ([`BurstLossModel::on_packet`](crate::BurstLossModel::on_packet)).
    pub fn drain_discarded(&mut self) -> std::vec::Drain<'_, u64> {
        self.discarded.drain(..)
    }
}
