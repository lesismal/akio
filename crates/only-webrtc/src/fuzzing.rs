//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::Instant;

use crate::rtc::Rtc;
use crate::types::ConfigInner;

fn fresh(lite: bool, cfg: ConfigInner) -> Option<Rtc> {
    Rtc::new(cfg, lite, Instant::now()).ok()
}

/// The configurations an SDP is tried with: the default, every ADR-039 and ADR-048 option
/// on (FEC as `fec`), SDES-SRTP on (ADR-054), RTCP without rtcp-mux offered with XR
/// receipt blocks and ULPFEC levels (ADR-058; its peers get component-2 candidates), SDES
/// without ICE and with MKIs, no BUNDLE with RTCP on component 2 negotiated (ADR-072), and
/// video RED without FEC with RED for the other audio codecs (ADR-073).
fn configs() -> [ConfigInner; 8] {
    let full = |fec| ConfigInner {
        fec: Some(fec),
        fec_min: 50,
        ccfb: true,
        xr: true,
        tmmbr: true,
        dtls13: true,
        cryptex: true,
        encrypt_ext: true,
        opus_red: Some(2),
        ecn: crate::EcnMarking::Ect1,
        bwe: Some(300_000),
        ..ConfigInner::default()
    };
    [
        ConfigInner::default(),
        full(crate::FecMechanism::FlexFec),
        full(crate::FecMechanism::Ulpfec),
        ConfigInner {
            sdes: true,
            ..ConfigInner::default()
        },
        ConfigInner {
            rtcp_mux: crate::RtcpMuxPolicy::Negotiate,
            xr: true,
            xr_blocks: crate::XrBlocks::ALL,
            ulpfec_level0: Some(64),
            ..full(crate::FecMechanism::Ulpfec)
        },
        ConfigInner {
            sdes: true,
            sdes_mki: 4,
            ice: false,
            latching: crate::Latching::Rebind(std::time::Duration::ZERO),
            // ADR-086: leap of faith offered first, the remote's ect= followed, keepalives.
            ecn: crate::EcnMarking::Ect0,
            ecn_init: crate::EcnInitiation::LeapOfFaith,
            bwe: Some(300_000),
            keepalive: std::time::Duration::from_secs(1),
            ..ConfigInner::default()
        },
        ConfigInner {
            bundle: crate::BundlePolicy::Disabled,
            rtcp_mux: crate::RtcpMuxPolicy::Negotiate,
            sdes: true,
            ccfb: true,
            bwe: Some(300_000),
            ..ConfigInner::default()
        },
        ConfigInner {
            audio_red: Some(2),
            ..full(crate::FecMechanism::Red)
        },
    ]
}

/// `webrtc_sdes`: an SDES `a=crypto` value (RFC 4568) as a remote description carries it: one
/// that is taken (suite, keys, lifetimes, MKIs, window size hint) writes back to the same
/// line and keys an SRTP context.
pub fn webrtc_sdes(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        crate::rtc::fuzz_crypto_line(s);
    }
}

/// Whether a section of `sdp` carries both `a=crypto` and `a=fingerprint`.
fn crypto_next_to_fingerprint(sdp: &str) -> bool {
    sdp.split("\r\nm=")
        .any(|sec| sec.contains("a=crypto:") && sec.contains("a=fingerprint:"))
}

/// Host candidates of both components for a peer whose configuration offers RTCP without
/// rtcp-mux.
fn rtcp_candidates(rtc: &mut Rtc, cfg: &ConfigInner) {
    if cfg.rtcp_mux != crate::RtcpMuxPolicy::Require {
        let a: std::net::SocketAddr = ([192, 0, 2, 1], 5000).into();
        rtc.add_local_candidate(only_ice::Candidate::host(a));
        rtc.add_local_candidate(
            only_ice::Candidate::host(([192, 0, 2, 1], 5001).into()).with_component(2),
        );
    }
}

/// `webrtc_turn_url`: a `turn:` / `turns:` URL as [`RelayServer::from_url`] takes it (the host
/// is not resolved: an IP address makes a server, a name is only checked).
///
/// [`RelayServer::from_url`]: crate::RelayServer::from_url
pub fn webrtc_turn_url(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(u) = crate::relay::parse_url(s) else {
        return;
    };
    assert!(!u.host.is_empty());
    if let Ok(ip) = u.host.parse::<std::net::IpAddr>() {
        let r = crate::RelayServer::from_parts(&u, (ip, u.port).into(), "u", "p");
        let t = r.transport();
        assert_eq!(
            t,
            if u.secure && u.tcp {
                "tls"
            } else if u.secure {
                "dtls"
            } else if u.tcp {
                "tcp"
            } else {
                "udp"
            }
        );
        assert_eq!(r.addr().port(), u.port);
    }
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
    let _ = crate::sdp::Sdp::parse(s).map(|p| p.write());
    for cfg in configs() {
        sdp_with(s, now, cfg);
    }
}

fn sdp_with(s: &str, now: Instant, cfg: ConfigInner) {
    let Some(mut rtc) = fresh(true, cfg.clone()) else {
        return;
    };
    rtcp_candidates(&mut rtc, &cfg);
    if let Ok(answer) = rtc.accept_offer(now, s) {
        assert!(crate::sdp::Sdp::parse(&answer).is_ok(), "{answer}");
        // Keys travel in SDP only when SDES is on, and never in a section with a DTLS
        // fingerprint (data channels next to SDES media have theirs in their own section).
        let crypto = answer.contains("a=crypto:");
        assert!(!crypto || cfg.sdes, "{answer}");
        assert!(!crypto_next_to_fingerprint(&answer), "{answer}");
        // No ICE in the answer to an offer without it; no BUNDLE when it is disabled.
        let offer_ice = s.contains("a=ice-ufrag");
        assert!(offer_ice || !answer.contains("a=ice-ufrag"), "{answer}");
        assert!(
            cfg.bundle != crate::BundlePolicy::Disabled || !answer.contains("a=group:BUNDLE"),
            "{answer}"
        );
        // RTCP on component 2 (`a=rtcp`) or muxed, never both, and BUNDLE only when muxed;
        // `a=rtcp` in every media section in use once the peer runs two components.
        // (per section: without BUNDLE each section has a transport of its own).
        let rtcp = answer.contains("a=rtcp:");
        assert!(
            !answer
                .split("\r\nm=")
                .any(|sec| sec.contains("a=rtcp-mux") && sec.contains("a=rtcp:")),
            "{answer}"
        );
        assert!(!rtcp || !answer.contains("a=group:BUNDLE"), "{answer}");
        assert!(!rtcp || rtc.two_components(), "{answer}");
        let in_use = answer.lines().any(|l| {
            (l.starts_with("m=audio ") || l.starts_with("m=video "))
                && l.split(' ').nth(1) != Some("0")
        });
        assert!(!(in_use && rtc.two_components()) || rtcp, "{answer}");
        // Driving the peer with what it would send itself does not panic.
        let _ = rtc.poll_output(now);
    }
    // As an answer to an offer with media and a channel.
    let Some(mut offerer) = fresh(false, cfg.clone()) else {
        return;
    };
    rtcp_candidates(&mut offerer, &cfg);
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

    /// Offers this stack makes (data only; audio + video + data; simulcast; with every
    /// ADR-039 / ADR-048 option, FlexFEC or ULPFEC; simulcast with them and ULPFEC) and the
    /// answers to them.
    pub(crate) fn webrtc_sdp() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = Instant::now();
        for media in [0, 1, 2, 3, 4, 5, 6, 7] {
            let cfg = match media {
                3 => super::configs()[1].clone(),
                4 | 5 => super::configs()[2].clone(),
                6 => super::configs()[3].clone(),
                // RTCP on component 2: one audio section, no data channel.
                7 => ConfigInner {
                    rtcp_mux: crate::RtcpMuxPolicy::Off,
                    ..super::configs()[4].clone()
                },
                _ => ConfigInner::default(),
            };
            let mut rtc = Rtc::new(cfg.clone(), false, now).expect("rtc");
            rtc.add_local_candidate(only_ice::Candidate::host(
                "192.0.2.1:5000".parse().expect("addr"),
            ));
            rtc.add_local_candidate(only_ice::Candidate::host_tcp(
                "192.0.2.1:5001".parse().expect("addr"),
                only_ice::TcpType::Passive,
            ));
            rtc.add_local_candidate(only_ice::Candidate::host_tcp(
                "192.0.2.1:9".parse().expect("addr"),
                only_ice::TcpType::Active,
            ));
            rtc.add_local_candidate(only_ice::Candidate::relayed_over_stream(
                "198.51.100.1:50000".parse().expect("addr"),
                "192.0.2.1:40000".parse().expect("addr"),
                true,
            ));
            super::rtcp_candidates(&mut rtc, &cfg);
            let mut ch = rtc.changes();
            {
                let mut api = SdpChanges(&mut ch);
                if media == 7 {
                    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
                } else if media != 6 {
                    api.add_channel("seed");
                }
                if media == 1 || (3..7).contains(&media) {
                    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
                    api.add_media(MediaKind::Video, Direction::SendOnly, None, None);
                }
                if media == 5 {
                    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
                }
                if media == 2 || media == 5 {
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
            let mut answerer = Rtc::new(cfg.clone(), true, now).expect("rtc");
            super::rtcp_candidates(&mut answerer, &cfg);
            let answer = answerer.accept_offer(now, &offer).expect("answer");
            out.push(offer.into_bytes());
            out.push(answer.into_bytes());
        }
        // ADR-072: SDES without ICE with MKIs (audio), SDES next to a data channel, and no
        // BUNDLE (audio, video, data) with RTCP on component 2 negotiated.
        for (cfg, channel, video) in [
            (super::configs()[5].clone(), false, false),
            (super::configs()[3].clone(), true, false),
            (super::configs()[6].clone(), true, true),
        ] {
            let mut rtc = Rtc::new(cfg.clone(), false, now).expect("rtc");
            rtc.add_local_candidate(only_ice::Candidate::host(
                "192.0.2.1:5000".parse().expect("addr"),
            ));
            super::rtcp_candidates(&mut rtc, &cfg);
            let mut ch = rtc.changes();
            {
                let mut api = SdpChanges(&mut ch);
                api.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
                if video {
                    api.add_media(MediaKind::Video, Direction::SendRecv, None, None);
                }
                if channel {
                    api.add_channel("seed");
                }
            }
            let offer = rtc.apply(now, ch).expect("apply").expect("offer");
            let mut answerer = Rtc::new(cfg.clone(), true, now).expect("rtc");
            answerer.add_local_candidate(only_ice::Candidate::host(
                "192.0.2.2:6000".parse().expect("addr"),
            ));
            super::rtcp_candidates(&mut answerer, &cfg);
            let answer = answerer.accept_offer(now, &offer).expect("answer");
            out.push(offer.into_bytes());
            out.push(answer.into_bytes());
        }
        // ADR-086: other RFC 6679 initiation lists, modes and ect= preferences, and an offer
        // that wants to be the DTLS server.
        let base = String::from_utf8(out[6].clone()).expect("utf-8");
        if let Some(line) = base
            .lines()
            .find(|l| l.starts_with("a=ecn-capable-rtp:"))
            .map(str::to_owned)
        {
            for v in [
                "leap",
                "ice",
                "leap,ice,rtp mode=readonly; ect=random",
                "ice,rtp mode=setonly; ect=1",
                "rtp ect=0; foo=bar",
                "zrtp,quux mode=setread",
            ] {
                out.push(
                    base.replace(&line, &format!("a=ecn-capable-rtp:{v}"))
                        .replace("a=setup:actpass", "a=setup:passive")
                        .into_bytes(),
                );
            }
        }
        out
    }

    /// `a=crypto` values: every offered suite, lifetimes, MKIs, several keys, a window size
    /// hint, and lines that are not taken.
    pub(crate) fn webrtc_sdes() -> Vec<Vec<u8>> {
        let k = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz";
        let k32 = "YUJjRGVGZ0hpSmtMbU5vUHFSc1R1VndYeVo1Njc4OTAxMjM0NTY3ODkwYWI";
        [
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}"),
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}|2^20|1:4"),
            format!("2 AES_CM_128_HMAC_SHA1_32 inline:{k}|1048576"),
            format!("3 AES_CM_128_HMAC_SHA1_80 inline:{k}|1:2;inline:{k}|2^31|2:2 WSH=128"),
            format!("4 AES_CM_128_HMAC_SHA1_80 inline:{k}|9:20"),
            format!("5 AES_256_CM_HMAC_SHA1_80 inline:{k32}"),
            format!("6 F8_128_HMAC_SHA1_80 inline:{k}"),
            format!("7 AES_CM_128_HMAC_SHA1_80 inline:{k} KDR=1"),
            format!("8 AES_CM_128_HMAC_SHA1_80 inline:{k};inline:{k}"),
            "9 AEAD_AES_128_GCM inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect()
    }

    /// TURN URLs of every form, and broken ones.
    pub(crate) fn webrtc_turn_url() -> Vec<Vec<u8>> {
        [
            "turn:192.0.2.1",
            "turn:192.0.2.1:3479?transport=udp",
            "turn:192.0.2.1?transport=tcp",
            "turns:192.0.2.1:443?transport=tcp",
            "turns:turn.example.com",
            "turn:[2001:db8::1]:3478",
            "turn:[2001:db8::1]",
            "turns:[2001:db8::1]?transport=udp",
            "turn:host:99999",
            "stun:192.0.2.1",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect()
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
        assert!(replay(DIR, "webrtc_turn_url", webrtc_turn_url) > 0);
        assert!(replay(DIR, "webrtc_sdes", webrtc_sdes) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::webrtc_sdp() {
            webrtc_sdp(s);
        }
        for s in &seeds::webrtc_turn_url() {
            webrtc_turn_url(s);
        }
        for s in &seeds::webrtc_sdes() {
            webrtc_sdes(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-webrtc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "webrtc_sdp", &seeds::webrtc_sdp());
        write_target_seeds(DIR, "webrtc_turn_url", &seeds::webrtc_turn_url());
        write_target_seeds(DIR, "webrtc_sdes", &seeds::webrtc_sdes());
    }
}
