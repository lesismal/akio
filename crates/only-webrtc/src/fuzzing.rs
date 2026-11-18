//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::Instant;

use crate::rtc::Rtc;
use crate::types::ConfigInner;

fn fresh(lite: bool) -> Option<Rtc> {
    Rtc::new(ConfigInner::default(), lite, Instant::now()).ok()
}

/// `webrtc_sdp`: an SDP offer (or answer) from the signalling, as [`RtcServer::accept_offer`]
/// takes it: accepted by a fresh peer; the answer is parsed back by another peer as the answer
/// to an offer of its own.
///
/// [`RtcServer::accept_offer`]: crate::RtcServer::accept_offer
pub fn webrtc_sdp(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let now = Instant::now();
    let Some(mut rtc) = fresh(true) else { return };
    let _ = crate::sdp::Sdp::parse(s).map(|p| p.write());
    if let Ok(answer) = rtc.accept_offer(now, s) {
        assert!(crate::sdp::Sdp::parse(&answer).is_ok(), "{answer}");
    }
    // As an answer to an offer with media and a channel.
    let Some(mut offerer) = fresh(false) else {
        return;
    };
    let mut ch = offerer.changes();
    {
        let mut api = crate::SdpChanges(&mut ch);
        api.add_channel("fuzz");
        api.add_media(
            crate::MediaKind::Audio,
            crate::Direction::SendRecv,
            None,
            None,
        );
        api.add_media(
            crate::MediaKind::Video,
            crate::Direction::SendRecv,
            None,
            None,
        );
        // Simulcast: the answer's `a=simulcast:recv` picks the encodings.
        let _ = api.add_simulcast_media(
            crate::MediaKind::Video,
            crate::Direction::SendOnly,
            &["h", "m", "l"],
            None,
            None,
        );
    }
    if offerer.apply(now, ch).is_ok() {
        let _ = offerer.accept_answer(now, s);
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use std::time::Instant;

    use crate::rtc::Rtc;
    use crate::types::ConfigInner;
    use crate::{Direction, MediaKind, SdpChanges};

    /// Offers this stack makes (data only; audio + video + data) and the answers to them.
    pub(crate) fn webrtc_sdp() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = Instant::now();
        for media in [0, 1, 2] {
            let mut rtc = Rtc::new(ConfigInner::default(), false, now).expect("rtc");
            rtc.add_local_candidate(only_ice::Candidate::host(
                "192.0.2.1:5000".parse().expect("addr"),
            ));
            rtc.add_local_candidate(only_ice::Candidate::host_tcp(
                "192.0.2.1:5001".parse().expect("addr"),
                only_ice::TcpType::Passive,
            ));
            let mut ch = rtc.changes();
            {
                let mut api = SdpChanges(&mut ch);
                api.add_channel("seed");
                if media == 1 {
                    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
                    api.add_media(MediaKind::Video, Direction::SendOnly, None, None);
                }
                if media == 2 {
                    let _ = api.add_simulcast_media(
                        MediaKind::Video,
                        Direction::SendOnly,
                        &["q", "h", "f"],
                        None,
                        None,
                    );
                }
            }
            let offer = rtc.apply(now, ch).expect("apply").expect("offer");
            let mut answerer = Rtc::new(ConfigInner::default(), true, now).expect("rtc");
            let answer = answerer.accept_offer(now, &offer).expect("answer");
            out.push(offer.into_bytes());
            out.push(answer.into_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "webrtc_sdp", webrtc_sdp) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::webrtc_sdp() {
            webrtc_sdp(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-webrtc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "webrtc_sdp", &seeds::webrtc_sdp());
    }
}
