//! RTSP, SDP and RTP fuzz entry points.

use only::{Acceptor, Handler};
use only_core::fuzzing::{conn, split};

use crate::{
    av::{Codec, Track},
    hub::Hub,
    rtp::Depacketizer,
    rtsp::{RtspConfig, RtspServer},
    sdp,
};

/// `rtsp_server`: an RTSP server session fed a byte stream (requests, interleaved frames).
/// `data[0]` splits the reads. Covers the message parser, DESCRIBE/ANNOUNCE/SETUP/RECORD and
/// the RTP ingest of interleaved frames into a hub.
pub fn rtsp_server(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let srv = RtspServer::new(Hub::default(), RtspConfig::default());
    let c = conn();
    let mut s = srv.on_open(&c);
    for p in split(data) {
        s.on_data(&c, p);
    }
    s.on_close(&c, None);
}

/// `rtsp_client`: an RTSP client session fed what a server sends (responses, interleaved
/// frames, server requests). `data[0]` bit 0 picks push (else pull), bit 1 UDP (else TCP);
/// `data[1]` splits the reads. Covers the response parser, Digest/Basic answers, SDP and
/// `Transport` handling, the RTP ingest of a pull and, for a push that gets to RECORD, the
/// packetizing sink.
pub fn rtsp_client(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    crate::rtsp::client::fuzz(mode & 1 != 0, mode & 2 != 0, &split(rest));
}

/// `sdp_parse`: the SDP parser and the media-to-track mapping.
pub fn sdp_parse(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(s) = sdp::Session::parse(text) {
        let _ = s.to_string();
        for m in &s.media {
            if let Some((t, pt)) = sdp::media_track(m) {
                let _ = sdp::track_media(&t, pt, "trackID=0");
            }
        }
    }
}

/// `rtp_depacketize`: RTP depacketizers. `data[0]` picks the codec; the rest is a sequence of
/// RTP packets, each prefixed by a one-byte length.
pub fn rtp_depacketize(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else {
        return;
    };
    let track = match sel % 5 {
        0 => Track::video(Codec::H264, vec![]),
        1 => Track::video(Codec::H265, vec![]),
        2 => Track::aac(vec![0x12, 0x10]),
        3 => Track::audio(Codec::Opus, vec![], 48000, 2),
        _ => Track::audio(Codec::Pcmu, vec![], 8000, 1),
    };
    let mut d = Depacketizer::new(&track);
    let mut out = Vec::new();
    while let Some((&n, r)) = rest.split_first() {
        let n = usize::from(n).min(r.len());
        let _ = d.push(&r[..n], &mut out);
        rest = &r[n..];
    }
    let _ = d.take_config();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::h264, rtp::Packetizer, rtsp::message::interleaved};
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=x\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QADazZQUH7ARAAAAMAEAAAAwMg8UKZYA==,aOvjyyLA\r\na=control:streamid=0\r\nm=audio 0 RTP/AVP 97\r\na=rtpmap:97 MPEG4-GENERIC/44100/2\r\na=fmtp:97 mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1210\r\na=control:streamid=1\r\n";

    fn rtp_stream(track: &Track) -> Vec<u8> {
        let mut p = Packetizer::new(track, 96).mtu(100);
        let mut wire = Vec::new();
        for i in 0..3i64 {
            let data = if track.is_video() {
                h264::to_avcc([
                    &[if i == 0 { 0x65 } else { 0x41 }, 1, 2, 3, 4][..],
                    &[0x41; 250][..],
                ])
            } else {
                vec![i as u8; 150]
            };
            let mut out = Vec::new();
            p.packetize(
                &crate::av::Packet::new(0, i * 40_000_000, i * 40_000_000, i == 0, data),
                &mut out,
            );
            for r in out {
                wire.push(r.len().min(255) as u8);
                wire.extend_from_slice(&r[..r.len().min(255)]);
            }
        }
        wire
    }

    fn server_seeds() -> Vec<Vec<u8>> {
        let mut rec = format!(
            "ANNOUNCE rtsp://h/live/s RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{SDP}",
            SDP.len()
        )
        .into_bytes();
        rec.extend_from_slice(b"SETUP rtsp://h/live/s/streamid=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=record\r\n\r\nRECORD rtsp://h/live/s RTSP/1.0\r\nCSeq: 3\r\nSession: 1\r\n\r\n");
        let track = Track::video(Codec::H264, vec![]);
        let mut p = Packetizer::new(&track, 96).mtu(200);
        let mut out = Vec::new();
        p.packetize(
            &crate::av::Packet::new(
                0,
                0,
                0,
                true,
                h264::to_avcc([&[0x67u8, 0x64, 0, 0x0d][..], &[0x68, 1], &[0x65; 500]]),
            ),
            &mut out,
        );
        for r in out {
            interleaved(0, &r, &mut rec);
        }
        let play = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\nDESCRIBE rtsp://h/live/s RTSP/1.0\r\nCSeq: 2\r\n\r\nSETUP rtsp://h/live/s/trackID=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=5000-5001\r\n\r\nPLAY rtsp://h/live/s RTSP/1.0\r\nCSeq: 4\r\n\r\nTEARDOWN rtsp://h/live/s RTSP/1.0\r\nCSeq: 5\r\n\r\n".to_vec();
        let mut v = Vec::new();
        for w in [rec, play, b"GARBAGE\r\n\r\n".to_vec()] {
            v.push([&[0u8][..], &w].concat());
            v.push([&[7u8][..], &w].concat());
        }
        v
    }

    /// What a server answers a client, in order: `(status line and headers, body)`.
    fn replies(rs: &[(&str, &str)]) -> Vec<u8> {
        let mut w = Vec::new();
        for (i, (head, body)) in rs.iter().enumerate() {
            w.extend_from_slice(
                format!(
                    "{head}\r\nCSeq: {}\r\nContent-Length: {}\r\n\r\n{body}",
                    i + 1,
                    body.len()
                )
                .as_bytes(),
            );
        }
        w
    }

    fn client_seeds() -> Vec<Vec<u8>> {
        let ok = "RTSP/1.0 200 OK";
        let setup_tcp0 = "RTSP/1.0 200 OK\r\nSession: 12345678;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1";
        let setup_tcp1 = "RTSP/1.0 200 OK\r\nSession: 12345678;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3";
        let setup_udp0 = "RTSP/1.0 200 OK\r\nSession: 12345678;timeout=60\r\nTransport: RTP/AVP;unicast;client_port=5000-5001;server_port=8000-8001";
        let setup_udp1 = "RTSP/1.0 200 OK\r\nSession: 12345678;timeout=60\r\nTransport: RTP/AVP;unicast;client_port=5002-5003;server_port=8000-8001";
        let describe = "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:8554/live/s/";
        let deny = "RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"only\", nonce=\"abc\", qop=\"auth\"";
        let public =
            "RTSP/1.0 200 OK\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN";
        let mut play_tcp = replies(&[
            (public, ""),
            (deny, ""),
            (describe, SDP),
            (setup_tcp0, ""),
            (setup_tcp1, ""),
            (ok, ""),
        ]);
        let track = Track::video(Codec::H264, vec![]);
        let mut p = Packetizer::new(&track, 96).mtu(200);
        let mut out = Vec::new();
        p.packetize(
            &crate::av::Packet::new(
                0,
                0,
                0,
                true,
                h264::to_avcc([&[0x67u8, 0x64, 0, 0x0d][..], &[0x68, 1], &[0x65; 500]]),
            ),
            &mut out,
        );
        for r in &out {
            interleaved(0, r, &mut play_tcp);
        }
        interleaved(1, &crate::rtp::sender_report(1, 2, 3, 4, 5), &mut play_tcp);
        let play_udp = replies(&[
            (ok, ""),
            (describe, SDP),
            (setup_udp0, ""),
            (setup_udp1, ""),
            (ok, ""),
        ]);
        let rec_tcp = replies(&[
            (ok, ""),
            (deny, ""),
            (ok, ""),
            (setup_tcp0, ""),
            (setup_tcp1, ""),
            (ok, ""),
        ]);
        let rec_udp = replies(&[
            (ok, ""),
            (ok, ""),
            (setup_udp0, ""),
            (setup_udp1, ""),
            (ok, ""),
        ]);
        let mut v = Vec::new();
        for (mode, w) in [(0u8, play_tcp), (2, play_udp), (1, rec_tcp), (3, rec_udp)] {
            v.push([&[mode, 0][..], &w].concat());
            v.push([&[mode, 9][..], &w].concat());
        }
        v.push(vec![0, 0, b'$', 0, 0xff]);
        v
    }

    fn sdp_seeds() -> Vec<Vec<u8>> {
        vec![
            SDP.as_bytes().to_vec(),
            b"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=rtpmap:111 opus/48000/2\r\n".to_vec(),
        ]
    }

    fn rtp_seeds() -> Vec<Vec<u8>> {
        let tracks = [
            Track::video(Codec::H264, vec![]),
            Track::video(Codec::H265, vec![]),
            Track::aac(vec![0x12, 0x10]),
            Track::audio(Codec::Opus, vec![], 48000, 2),
        ];
        tracks
            .iter()
            .enumerate()
            .map(|(i, t)| [&[i as u8][..], &rtp_stream(t)].concat())
            .collect()
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "rtsp_server", rtsp_server) > 0);
        assert!(replay(DIR, "rtsp_client", rtsp_client) > 0);
        assert!(replay(DIR, "sdp_parse", sdp_parse) > 0);
        assert!(replay(DIR, "rtp_depacketize", rtp_depacketize) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in server_seeds() {
            rtsp_server(&s);
        }
        for s in client_seeds() {
            rtsp_client(&s);
        }
        rtsp_client(&[]);
        rtsp_client(&[1]);
        for s in sdp_seeds() {
            sdp_parse(&s);
        }
        for s in rtp_seeds() {
            rtp_depacketize(&s);
        }
        rtsp_server(&[]);
        rtp_depacketize(&[]);
    }

    /// Regenerates the seed files: `cargo test -p only-media --lib write_rtsp_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_rtsp_fuzz_seeds() {
        write_target_seeds(DIR, "rtsp_server", &server_seeds());
        write_target_seeds(DIR, "sdp_parse", &sdp_seeds());
        write_target_seeds(DIR, "rtp_depacketize", &rtp_seeds());
    }

    /// Regenerates the `rtsp_client` seeds:
    /// `cargo test -p only-media --lib write_rtsp_client_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_rtsp_client_fuzz_seeds() {
        write_target_seeds(DIR, "rtsp_client", &client_seeds());
    }
}
