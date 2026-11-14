//! RTMP, FLV and AMF fuzz entry points.

use flash::{Acceptor, Handler};
use flash_core::fuzzing::{conn, split};

use crate::{
    amf,
    flv::{Decoder, Demuxer},
    hub::Hub,
    rtmp::{RtmpConfig, RtmpServer, handshake},
};

/// `rtmp_server`: an RTMP server session fed a valid simple handshake and then the fuzz
/// input as chunk stream (commands, publish, media messages into a hub). `data[0]` splits the
/// reads.
pub fn rtmp_server(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let srv = RtmpServer::new(Hub::default(), RtmpConfig::default());
    let c = conn();
    let mut s = srv.on_open(&c);
    s.on_data(&c, &handshake::client_hello(true));
    s.on_data(&c, &[0u8; handshake::SIZE]);
    for p in split(data) {
        s.on_data(&c, p);
    }
    s.on_close(&c, None);
}

/// `flv_demux`: the FLV file demuxer and the tag decoder (legacy and Enhanced RTMP headers,
/// script data, sequence headers).
pub fn flv_demux(data: &[u8]) {
    let mut d = Demuxer::new();
    let mut dec = Decoder::new();
    let mut body = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    body.extend_from_slice(data);
    if let Ok(tags) = d.feed(&body) {
        for t in tags {
            let _ = dec.write(t.tag_type, t.ts, &t.body);
        }
    }
}

/// `amf_decode`: AMF0 and AMF3 decoding, and AMF0 re-encoding of what decodes.
pub fn amf_decode(data: &[u8]) {
    if let Ok(v) = amf::decode_all(data) {
        let _ = amf::encode(&v);
    }
    let _ = amf::decode_amf3_all(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        amf::Value,
        rtmp::chunk::{self, Message},
    };
    use flash_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");
    const SAMPLE: &[u8] = include_bytes!("../../testdata/h264_aac.flv");

    fn cmd(vals: &[Value], sid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        chunk::write_message(&mut out, &Message::new(3, chunk::COMMAND_AMF0, sid, 0, amf::encode(vals)), 128);
        out
    }

    fn rtmp_seeds() -> Vec<Vec<u8>> {
        let mut publish = cmd(
            &[Value::from("connect"), Value::Number(1.0), Value::object([("app", Value::from("live"))])],
            0,
        );
        publish.extend(cmd(&[Value::from("createStream"), Value::Number(2.0), Value::Null], 0));
        publish.extend(cmd(&[Value::from("publish"), Value::Number(3.0), Value::Null, Value::from("s")], 1));
        let mut media = publish.clone();
        // A few tags of the sample (sequence headers and the first frames).
        let tags = Demuxer::new().feed(SAMPLE).unwrap_or_default();
        for t in tags.iter().take(6) {
            let mt = match t.tag_type {
                8 => chunk::AUDIO,
                9 => chunk::VIDEO,
                _ => chunk::DATA_AMF0,
            };
            chunk::write_message(&mut media, &Message::new(4, mt, 1, t.ts, t.body.clone()), 128);
        }
        let mut play = cmd(
            &[Value::from("connect"), Value::Number(1.0), Value::object([("app", Value::from("live"))])],
            0,
        );
        play.extend(cmd(&[Value::from("play"), Value::Number(2.0), Value::Null, Value::from("s")], 1));
        let mut v = Vec::new();
        for w in [publish, media, play] {
            v.push([&[0u8][..], &w].concat());
            v.push([&[5u8][..], &w].concat());
        }
        v
    }

    fn flv_seeds() -> Vec<Vec<u8>> {
        let body = &SAMPLE[13..];
        vec![body[..body.len().min(4096)].to_vec()]
    }

    fn amf_seeds() -> Vec<Vec<u8>> {
        vec![
            amf::encode(&[
                Value::from("onMetaData"),
                Value::EcmaArray(vec![("width".into(), Value::Number(320.0))]),
                Value::Array(vec![Value::Bool(true), Value::Null]),
            ]),
            vec![0x11, 0x0a, 0x0b, 0x01, 0x03, b'k', 0x04, 0x07, 0x01],
        ]
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "rtmp_server", rtmp_server) > 0);
        assert!(replay(DIR, "flv_demux", flv_demux) > 0);
        assert!(replay(DIR, "amf_decode", amf_decode) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in rtmp_seeds() {
            rtmp_server(&s);
        }
        for s in flv_seeds() {
            flv_demux(&s);
        }
        for s in amf_seeds() {
            amf_decode(&s);
        }
    }

    /// Regenerates the seed files: `cargo test -p flash-media --lib write_rtmp_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_rtmp_fuzz_seeds() {
        write_target_seeds(DIR, "rtmp_server", &rtmp_seeds());
        write_target_seeds(DIR, "flv_demux", &flv_seeds());
        write_target_seeds(DIR, "amf_decode", &amf_seeds());
    }
}
