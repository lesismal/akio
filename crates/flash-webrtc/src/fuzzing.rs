//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::Instant;

use str0m::change::{SdpAnswer, SdpOffer};

/// `webrtc_sdp`: an SDP offer (or answer) from the signalling, as [`RtcServer::accept_offer`]
/// takes it: parsed, then accepted by a fresh `Rtc`; the answer is printed and parsed back.
///
/// [`RtcServer::accept_offer`]: crate::RtcServer::accept_offer
pub fn webrtc_sdp(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = SdpAnswer::from_sdp_string(s);
    let Ok(offer) = SdpOffer::from_sdp_string(s) else {
        return;
    };
    let mut rtc = crate::rtc_config().build(Instant::now());
    if let Ok(answer) = rtc.sdp_api().accept_offer(offer) {
        let text = answer.to_sdp_string();
        let _ = SdpAnswer::from_sdp_string(&text);
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use crate::{Direction, MediaKind};

    /// Offers str0m itself makes: data only, and audio + video + data.
    pub(crate) fn webrtc_sdp() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for media in [false, true] {
            let mut rtc = crate::rtc_config().build(std::time::Instant::now());
            let c = str0m::Candidate::host("192.0.2.1:5000".parse().expect("addr"), "udp")
                .expect("candidate");
            rtc.add_local_candidate(c);
            let mut api = rtc.sdp_api();
            api.add_channel("seed".into());
            if media {
                api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
                api.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            }
            let (offer, _) = api.apply().expect("offer");
            out.push(offer.to_sdp_string().into_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flash_core::fuzzing::{replay, write_target_seeds};

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

    /// Regenerates the seed files: `cargo test -p flash-webrtc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "webrtc_sdp", &seeds::webrtc_sdp());
    }
}
