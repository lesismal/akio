//! Ingest benchmarks of the RTMP and RTSP clients' pulls (ignored by default; run in release
//! with the `fuzzing` feature, whose entry points drive a client session over a detached
//! connection):
//!
//! ```text
//! cargo test -p only-media --release --features fuzzing --test client_bench -- --ignored --nocapture
//! ```
//!
//! Each prints `BENCH <name> <ns>`: the best of seven runs, in nanoseconds per media message
//! (RTMP) or RTP packet (RTSP), handshake and commands included (amortized over the sample
//! looped 40 times). Only public API, so the file runs on older trees too, for same-run A/B
//! comparisons between commits.
#![cfg(feature = "fuzzing")]

use std::time::Instant;

use only_media::{
    Packet, Tracks,
    amf::{self, Value},
    av::MILLISECOND,
    flv,
    rtmp::chunk::{self, Message},
    rtp::Packetizer,
    rtsp::{describe_sdp, message::interleaved},
};

const ROUNDS: i64 = 40;

fn sample() -> (Tracks, Vec<Packet>, Vec<flv::Tag>) {
    let data = include_bytes!("../testdata/h264_aac.flv");
    let tags = flv::Demuxer::new().feed(data).unwrap();
    let mut dec = flv::Decoder::new();
    let (mut tracks, mut pkts) = (None, Vec::new());
    for t in &tags {
        for e in dec.write(t.tag_type, t.ts, &t.body) {
            match e {
                flv::Event::Tracks(t) => tracks = Some(t),
                flv::Event::Packet(p) => pkts.push(p),
                _ => {}
            }
        }
    }
    (tracks.unwrap(), pkts, tags)
}

fn command(vals: Vec<Value>) -> Vec<u8> {
    let mut out = Vec::new();
    let m = Message::new(3, chunk::COMMAND_AMF0, 0, 0, amf::encode(&vals));
    chunk::write_message(&mut out, &m, 128);
    out
}

/// What an RTMP server sends a pulling client: the command answers, then the sample's tags
/// `ROUNDS` times (timestamps moved on each round); and the number of media messages.
fn rtmp_input(tags: &[flv::Tag]) -> (Vec<u8>, usize) {
    let mut w = vec![0u8]; // pull, one read
    w.extend(command(vec![
        Value::from("_result"),
        Value::Number(1.0),
        Value::object([("fmsVer", Value::from("FMS/3,0,1,123"))]),
        Value::object([("code", Value::from("NetConnection.Connect.Success"))]),
    ]));
    w.extend(command(vec![
        Value::from("_result"),
        Value::Number(2.0),
        Value::Null,
        Value::Number(1.0),
    ]));
    w.extend(command(vec![
        Value::from("onStatus"),
        Value::Number(0.0),
        Value::Null,
        Value::object([
            ("level", Value::from("status")),
            ("code", Value::from("NetStream.Play.Start")),
        ]),
    ]));
    let span = tags.last().map_or(0, |t| t.ts) + 40;
    let mut n = 0;
    for r in 0..ROUNDS as u32 {
        for t in tags {
            let mt = match t.tag_type {
                8 => chunk::AUDIO,
                9 => chunk::VIDEO,
                _ => chunk::DATA_AMF0,
            };
            if r > 0 && mt == chunk::DATA_AMF0 {
                continue;
            }
            let m = Message::new(4, mt, 1, t.ts + r * span, t.body.clone());
            chunk::write_message(&mut w, &m, 128);
            n += 1;
        }
    }
    (w, n)
}

/// What an RTSP server sends a pulling client over TCP: the answers to OPTIONS, DESCRIBE, two
/// SETUPs and PLAY, then the sample's RTP packets interleaved, `ROUNDS` times; and the number
/// of RTP packets.
fn rtsp_input(tracks: &Tracks, pkts: &[Packet]) -> (Vec<u8>, usize) {
    let sdp = describe_sdp(tracks).to_string();
    let replies = [
        (
            "RTSP/1.0 200 OK\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN",
            "",
        ),
        (
            "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:8554/live/s/",
            sdp.as_str(),
        ),
        (
            "RTSP/1.0 200 OK\r\nSession: 1234;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1",
            "",
        ),
        (
            "RTSP/1.0 200 OK\r\nSession: 1234;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3",
            "",
        ),
        ("RTSP/1.0 200 OK\r\nSession: 1234", ""),
    ];
    let mut w = vec![0u8, 0]; // pull over TCP, one read
    for (i, (head, body)) in replies.iter().enumerate() {
        w.extend_from_slice(
            format!(
                "{head}\r\nCSeq: {}\r\nContent-Length: {}\r\n\r\n{body}",
                i + 1,
                body.len()
            )
            .as_bytes(),
        );
    }
    let mut packers: Vec<Packetizer> = tracks
        .iter()
        .enumerate()
        .map(|(i, t)| Packetizer::new(t, 96 + i as u8))
        .collect();
    let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40 * MILLISECOND;
    let mut out = Vec::new();
    let mut n = 0;
    for r in 0..ROUNDS {
        for p in pkts {
            let q = Packet::new(
                p.track,
                p.dts + r * span,
                p.pts + r * span,
                p.keyframe,
                p.data.clone(),
            );
            out.clear();
            packers[p.track].packetize(&q, &mut out);
            for rtp in &out {
                interleaved(2 * p.track as u8, rtp, &mut w);
                n += 1;
            }
        }
    }
    (w, n)
}

fn best_of_seven(n: usize, f: impl Fn()) -> f64 {
    (0..7)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos() as f64 / n as f64
        })
        .fold(f64::INFINITY, f64::min)
}

#[test]
#[ignore]
fn bench_client_ingest() {
    let (tracks, pkts, tags) = sample();
    let (rtmp, n) = rtmp_input(&tags);
    let ns = best_of_seven(n, || only_media::fuzzing::rtmp::rtmp_client(&rtmp));
    println!("BENCH rtmp-pull {ns:.1}");
    let (rtsp, n) = rtsp_input(&tracks, &pkts);
    let ns = best_of_seven(n, || only_media::fuzzing::rtsp::rtsp_client(&rtsp));
    println!("BENCH rtsp-pull {ns:.1}");
}
