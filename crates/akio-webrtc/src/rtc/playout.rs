//! The audio jitter buffer (ADR-087): with
//! [`RtcConfig::set_audio_jitter_buffer`](crate::RtcConfig::set_audio_jitter_buffer), each
//! received audio stream goes through an [`akio_rtp::JitterBuffer`] instead of the frame
//! assembler, in frame mode: frames come out as [`MediaData`] in sequence order at their
//! playout instants ([`MediaData::playout_time`]), a frame after a gap marked
//! `contiguous = false`. Its late and overflow discards feed the discard fields of the RTCP
//! XR VoIP metrics about the stream and its delay their jitter buffer fields.
//!
//! The video playout buffer (ADR-092): with
//! [`RtcConfig::set_video_playout_buffer`](crate::RtcConfig::set_video_playout_buffer), the
//! frames of each received video stream go from the frame assembler into an
//! [`akio_rtp::VideoPlayout`] and come out at their playout instants. Frames completed by a
//! retransmission (RTX), or released with a frame after a gap, are flagged repaired; the
//! round-trip time is its room for a retransmission on a line with NACK.

use super::*;
use akio_rtp::{
    JitterBuffer, JitterBufferStats, JitterPush, PlayoutDelay, VideoFrameFlags, VideoPlayout,
    VideoPlayoutStats,
};

/// The playout buffer of one received video stream: frames of `(payload type, the
/// assembler's extended timestamp, first packet's arrival, data)`.
#[derive(Debug)]
pub(super) struct VideoJitter {
    pub(super) buf: VideoPlayout<(u8, u64, Instant, Arc<[u8]>)>,
    /// When to give up the missing packet a frame waits behind in the assembler.
    pub(super) hole_at: Option<Instant>,
}

/// The frame assembler's packet count with the video playout buffer on: a bound, missing
/// packets are given up at the deadline of the frame behind them first.
pub(super) const VIDEO_HOLE_PACKETS: usize = 1024;

/// Hands out the video frames of `r` due by `now` (all of them with `drain`).
fn release_video(
    r: &mut Recv,
    l: &MediaLine,
    now: Instant,
    drain: bool,
    events: &mut VecDeque<RtcEvent>,
) {
    let Some(v) = r.video.as_mut() else { return };
    let clock = v.buf.clock();
    let mut emit = |f: akio_rtp::VideoPlayoutFrame<(u8, u64, Instant, Arc<[u8]>)>| {
        let (pt, ts, first, data) = f.data;
        events.push_back(RtcEvent::MediaData(MediaData {
            mid: l.mid,
            pt: Pt::from(pt),
            rid: r.rid.clone(),
            codec: l.codec(pt).map(|c| c.codec),
            time: MediaTime::new(ts, Frequency::new(clock).unwrap_or(Frequency::NINETY_KHZ)),
            network_time: first,
            contiguous: f.contiguous,
            playout_time: Some(f.playout),
            data,
        }));
    };
    if drain {
        v.buf.drain().into_iter().for_each(&mut emit);
        return;
    }
    while let Some(f) = v.buf.pop(now) {
        emit(f);
    }
}

/// The jitter buffer of one received audio stream.
#[derive(Debug)]
pub(super) struct AudioJitter {
    /// The payload type of the latest frame (for the codec of the VoIP metrics).
    pub(super) pt: u8,
    pub(super) buf: JitterBuffer<(u8, Arc<[u8]>)>,
}

/// A frame out of the buffer as the application sees it.
fn media_data(
    mid: Mid,
    l: &MediaLine,
    rid: Option<&String>,
    clock: u32,
    f: akio_rtp::JitterFrame<(u8, Arc<[u8]>)>,
) -> MediaData {
    let (pt, data) = f.data;
    MediaData {
        mid,
        pt: Pt::from(pt),
        rid: rid.cloned(),
        codec: l.codec(pt).map(|c| c.codec),
        time: MediaTime::new(
            f.timestamp,
            Frequency::new(clock).unwrap_or(Frequency::NINETY_KHZ),
        ),
        network_time: f.arrival,
        contiguous: f.contiguous,
        playout_time: Some(f.playout),
        data,
    }
}

/// Hands out the frames of `r` due by `now` (all of them with `drain`).
fn release(
    r: &mut Recv,
    l: &MediaLine,
    now: Instant,
    drain: bool,
    events: &mut VecDeque<RtcEvent>,
) {
    let Some(j) = r.jitter.as_mut() else { return };
    let clock = j.buf.clock();
    if drain {
        for f in j.buf.drain() {
            events.push_back(RtcEvent::MediaData(media_data(
                l.mid,
                l,
                r.rid.as_ref(),
                clock,
                f,
            )));
        }
        return;
    }
    while let Some(f) = j.buf.pop(now) {
        events.push_back(RtcEvent::MediaData(media_data(
            l.mid,
            l,
            r.rid.as_ref(),
            clock,
            f,
        )));
    }
}

impl Rtc {
    /// An audio frame into the jitter buffer of stream `ssrc` (made on its first frame, made
    /// again when the clock rate changes, the frames still in the old one handed out first);
    /// then the frames due go out.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn jitter_push(
        &mut self,
        now: Instant,
        line: usize,
        ssrc: u32,
        ext_seq: u64,
        p: &Pkt<'_>,
        payload: &[u8],
        clock: u32,
        bounds: PlayoutDelay,
    ) -> Option<JitterPush> {
        let l = self.media.get(line)?;
        let r = self.recv.get_mut(&ssrc)?;
        if r.jitter.as_ref().is_some_and(|j| j.buf.clock() != clock) {
            release(r, l, now, true, &mut self.events);
            r.jitter = None;
        }
        let j = r.jitter.get_or_insert_with(|| {
            Box::new(AudioJitter {
                pt: p.pt,
                buf: JitterBuffer::new(clock, bounds),
            })
        });
        j.pt = p.pt;
        let data: Arc<[u8]> = Arc::from(payload);
        // Duplicates, late and overflowing frames are counted (and the discards reported)
        // by the buffer.
        let pushed = j
            .buf
            .push(ext_seq, p.ts, p.marker, now, (p.pt, data), payload.len());
        release(r, l, now, false, &mut self.events);
        Some(pushed)
    }

    /// The frames of every jitter buffer due by `now`.
    pub(super) fn jitter_release(&mut self, now: Instant) {
        for r in self.recv.values_mut() {
            if r.jitter.is_none() {
                continue;
            }
            if let Some(l) = self.media.get(r.line) {
                release(r, l, now, false, &mut self.events);
            }
        }
    }

    /// The frames the assembler of video stream `ssrc` (on `line`) has complete into its
    /// playout buffer (made on its first frame, made again when the clock rate changes, the
    /// frames still in the old one handed out first), flagged repaired after a
    /// retransmission (`rtx`) or a gap; then the frames due go out. Frames that cannot be
    /// decoded, or dropped without a keyframe to resume from, ask the sender for one
    /// (`keyframe.rs`).
    pub(super) fn video_push(&mut self, now: Instant, line: usize, ssrc: u32, rtx: bool) {
        let Some(bounds) = self.cfg.video_playout else {
            return;
        };
        let Some(l) = self.media.get(line) else {
            return;
        };
        let Some(r) = self.recv.get_mut(&ssrc) else {
            return;
        };
        let Some(clock) = r
            .assembler
            .as_ref()
            .and_then(|(pt, _)| l.codec(*pt))
            .map(|c| c.clock)
        else {
            return;
        };
        if r.video.as_ref().is_some_and(|v| v.buf.clock() != clock) {
            release_video(r, l, now, true, &mut self.events);
            r.video = None;
        }
        let nack = l.codecs.iter().any(|c| c.fb.iter().any(|f| f == "nack"));
        let rtt = nack.then(|| r.stream.rtt()).flatten();
        let krtt = Self::keyframe_rtt(r, l);
        let Recv {
            assembler,
            video,
            keyframe,
            ..
        } = r;
        let Some((pt, asm)) = assembler.as_mut() else {
            return;
        };
        let v = video.get_or_insert_with(|| {
            Box::new(VideoJitter {
                buf: VideoPlayout::new(clock, bounds),
                hole_at: None,
            })
        });
        v.buf.set_round_trip(rtt);
        let mut repaired = rtx;
        let mut ask = false;
        loop {
            while let Some(f) = asm.pop() {
                // After a given-up packet, frames up to a keyframe cannot be decoded.
                ask |= keyframe.on_frame(now, f.keyframe, f.contiguous && !f.partial, krtt);
                let mut flags = VideoFrameFlags::NONE;
                if f.keyframe {
                    flags |= VideoFrameFlags::KEYFRAME;
                }
                // A frame with a packet rebuilt in part may be corrupt.
                if !f.contiguous || f.partial {
                    flags |= VideoFrameFlags::DISCONTINUOUS;
                }
                // Frames after a gap waited for it to be given up.
                repaired |= !f.contiguous;
                if repaired {
                    flags |= VideoFrameFlags::REPAIRED;
                }
                let n = f.data.len();
                let data = (*pt, f.timestamp, f.first_arrival, Arc::from(f.data));
                v.buf.push(f.timestamp as u32, now, flags, data, n);
            }
            // A frame waiting behind a missing packet: give the packet up when that frame is
            // due (ADR-092 update).
            v.hole_at = None;
            let Some(ts) = asm.blocked() else { break };
            let at = v.buf.hole_deadline(ts as u32, now);
            if at > now {
                v.hole_at = Some(at);
                break;
            }
            if !asm.give_up_hole() {
                break;
            }
            v.buf.hole_given_up();
        }
        if v.buf.take_keyframe_request() {
            ask |= keyframe.on_drop(now, krtt);
        }
        release_video(r, l, now, false, &mut self.events);
        if ask {
            self.request_keyframe_on_loss(line, ssrc);
        }
    }

    /// The frames of every video playout buffer due by `now`, after giving up the missing
    /// packets whose deadline came.
    pub(super) fn video_release(&mut self, now: Instant) {
        let due: Vec<(usize, u32)> = self
            .recv
            .iter()
            .filter(|(_, r)| {
                r.video
                    .as_ref()
                    .is_some_and(|v| v.hole_at.is_some_and(|t| t <= now))
            })
            .map(|(s, r)| (r.line, *s))
            .collect();
        for (line, ssrc) in due {
            self.video_push(now, line, ssrc, false);
        }
        for r in self.recv.values_mut() {
            if r.video.is_none() {
                continue;
            }
            if let Some(l) = self.media.get(r.line) {
                release_video(r, l, now, false, &mut self.events);
            }
        }
    }

    /// The video playout buffers of the streams received on `mid`: `(SSRC, statistics)`;
    /// `None` when there is no such line.
    pub(crate) fn video_playout_stats(&self, mid: Mid) -> Option<Vec<(u32, VideoPlayoutStats)>> {
        let line = self.media.iter().position(|l| l.mid == mid)?;
        let mut v: Vec<_> = self
            .recv
            .iter()
            .filter(|(_, r)| r.line == line)
            .filter_map(|(s, r)| r.video.as_ref().map(|v| (*s, v.buf.stats())))
            .collect();
        v.sort_by_key(|x| x.0);
        Some(v)
    }

    /// The jitter buffers of the streams received on `mid`: `(SSRC, statistics)`; `None`
    /// when there is no such line.
    pub(crate) fn jitter_buffer_stats(&self, mid: Mid) -> Option<Vec<(u32, JitterBufferStats)>> {
        let line = self.media.iter().position(|l| l.mid == mid)?;
        let mut v: Vec<_> = self
            .recv
            .iter()
            .filter(|(_, r)| r.line == line)
            .filter_map(|(s, r)| r.jitter.as_ref().map(|j| (*s, j.buf.stats())))
            .collect();
        v.sort_by_key(|x| x.0);
        Some(v)
    }
}
