//! Keyframe requests on loss (ADR-092 update): a received video frame that cannot be decoded
//! (after a packet given up, or with a packet rebuilt only in part) and is not a keyframe asks
//! the sender for one, a PLI on a line with `nack pli`, otherwise a FIR on a line with
//! `ccm fir`. A request is outstanding until a keyframe comes out or `max(RTT, 200 ms)`
//! passes (libwebrtc's `VideoReceiveStream2` repeats no sooner than 200 ms); a later
//! undecodable frame then sends the next.

use super::*;

/// The least time between two requests about one stream, whatever the round trip.
pub(super) const KEYFRAME_RETRY: Duration = Duration::from_millis(200);

/// Whether a received video stream needs a keyframe, and when it last asked for one.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct KeyframeNeed {
    /// Frames out since a gap cannot be decoded until a keyframe comes out whole.
    broken: bool,
    /// The latest request about the stream (this module's or the application's).
    asked: Option<Instant>,
}

impl KeyframeNeed {
    /// A frame came out of the assembler: whether to ask for a keyframe now (`rtt`: the
    /// stream's round trip, when known).
    pub(super) fn on_frame(
        &mut self,
        now: Instant,
        keyframe: bool,
        decodable: bool,
        rtt: Option<Duration>,
    ) -> bool {
        if keyframe && decodable {
            self.broken = false;
            self.asked = None;
            return false;
        }
        if !decodable {
            self.broken = true;
        }
        self.due(now, rtt)
    }

    /// Frames were dropped without a keyframe to resume from (the playout buffer's
    /// overflow): whether to ask now.
    pub(super) fn on_drop(&mut self, now: Instant, rtt: Option<Duration>) -> bool {
        self.broken = true;
        self.due(now, rtt)
    }

    /// A request went out about the stream (the application's included).
    pub(super) fn asked(&mut self, now: Instant) {
        self.asked = Some(now);
    }

    /// Broken, and no request outstanding: notes the request about to go out.
    fn due(&mut self, now: Instant, rtt: Option<Duration>) -> bool {
        if !self.broken {
            return false;
        }
        let wait = rtt.unwrap_or(Duration::ZERO).max(KEYFRAME_RETRY);
        if self.asked.is_some_and(|t| now < t + wait) {
            return false;
        }
        self.asked = Some(now);
        true
    }
}

impl Rtc {
    /// The keyframe request about the received stream `ssrc` of `line` (PLI with `nack pli`,
    /// FIR with `ccm fir`), counted; nothing when neither is negotiated or the application
    /// opted out.
    pub(super) fn request_keyframe_on_loss(&mut self, line: usize, ssrc: u32) {
        if !self.cfg.keyframe_on_loss {
            return;
        }
        let Some(l) = self.media.get_mut(line) else {
            return;
        };
        let has = |fb: &str| l.codecs.iter().any(|c| c.fb.iter().any(|f| f == fb));
        let sender = l.send.ssrc();
        let pkt = if has("nack pli") {
            Rtcp::Pli {
                sender_ssrc: sender,
                media_ssrc: ssrc,
            }
        } else if has("ccm fir") {
            l.fir_seq = l.fir_seq.wrapping_add(1);
            Rtcp::Fir {
                sender_ssrc: sender,
                entries: vec![(ssrc, l.fir_seq)],
            }
        } else {
            return;
        };
        self.stats.keyframes_requested += 1;
        self.send_rtcp(&[pkt]);
    }

    /// The round trip of the received stream `r` on line `l`, as a receiver (XR DLRR) or
    /// as a sender on that line.
    pub(super) fn keyframe_rtt(r: &Recv, l: &MediaLine) -> Option<Duration> {
        r.stream.rtt().or_else(|| l.send.rtt())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn asks_once_per_gap_until_keyframe() {
        let t0 = Instant::now();
        let mut k = KeyframeNeed::default();
        // Contiguous delta frames need nothing.
        assert!(!k.on_frame(t0, false, true, None));
        // A gap followed by a keyframe needs nothing either.
        assert!(!k.on_frame(t0, true, true, None));
        // A gap followed by a delta frame asks once ...
        assert!(k.on_frame(t0, false, false, None));
        // ... and not again while it is outstanding, gap or not.
        for i in 1..10 {
            assert!(!k.on_frame(t0 + ms(i * 10), false, true, None));
            assert!(!k.on_frame(t0 + ms(i * 10 + 5), false, false, None));
        }
        // 200 ms later the stream is still broken: the next frame asks again.
        assert!(k.on_frame(t0 + ms(200), false, true, None));
        assert!(!k.on_frame(t0 + ms(399), false, true, None));
        // The keyframe ends it: no more requests, the next gap asks at once.
        assert!(!k.on_frame(t0 + ms(400), true, true, None));
        assert!(!k.on_frame(t0 + ms(405), false, true, None));
        assert!(k.on_frame(t0 + ms(410), false, false, None));
    }

    #[test]
    fn waits_a_round_trip_when_longer() {
        let t0 = Instant::now();
        let mut k = KeyframeNeed::default();
        let rtt = Some(ms(500));
        assert!(k.on_frame(t0, false, false, rtt));
        assert!(!k.on_frame(t0 + ms(300), false, false, rtt));
        assert!(!k.on_frame(t0 + ms(499), false, true, rtt));
        assert!(k.on_frame(t0 + ms(500), false, true, rtt));
        // A short round trip keeps the 200 ms floor.
        let mut k = KeyframeNeed::default();
        assert!(k.on_frame(t0, false, false, Some(ms(20))));
        assert!(!k.on_frame(t0 + ms(100), false, false, Some(ms(20))));
        assert!(k.on_frame(t0 + ms(200), false, false, Some(ms(20))));
    }

    #[test]
    fn partial_keyframe_is_not_a_keyframe_and_requests_are_shared() {
        let t0 = Instant::now();
        let mut k = KeyframeNeed::default();
        // A keyframe with a packet rebuilt in part does not repair the picture.
        assert!(k.on_frame(t0, true, false, None));
        // The application asked: none of ours for 200 ms.
        k.asked(t0 + ms(300));
        assert!(!k.on_frame(t0 + ms(400), false, true, None));
        assert!(k.on_frame(t0 + ms(500), false, true, None));
        // An overflow asks like a gap, under the same limit.
        let mut k = KeyframeNeed::default();
        assert!(k.on_drop(t0, None));
        assert!(!k.on_drop(t0 + ms(100), None));
        assert!(!k.on_frame(t0 + ms(150), false, true, None));
        assert!(k.on_drop(t0 + ms(200), None));
    }
}
