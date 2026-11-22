//! The audio jitter buffer (ADR-087): with
//! [`RtcConfig::set_audio_jitter_buffer`](crate::RtcConfig::set_audio_jitter_buffer), each
//! received audio stream goes through an [`akio_rtp::JitterBuffer`] instead of the frame
//! assembler, in frame mode: frames come out as [`MediaData`] in sequence order at their
//! playout instants ([`MediaData::playout_time`]), a frame after a gap marked
//! `contiguous = false`. Its late and overflow discards feed the discard fields of the RTCP
//! XR VoIP metrics about the stream and its delay their jitter buffer fields.

use super::*;
use akio_rtp::{JitterBuffer, JitterBufferStats, JitterPush, PlayoutDelay};

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
    ) {
        let Some(l) = self.media.get(line) else {
            return;
        };
        let Some(r) = self.recv.get_mut(&ssrc) else {
            return;
        };
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
        let _: JitterPush = j
            .buf
            .push(ext_seq, p.ts, p.marker, now, (p.pt, data), payload.len());
        release(r, l, now, false, &mut self.events);
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
