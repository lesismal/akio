//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::Arc;

use only_core::fuzzing::split;

use crate::{
    Values,
    coder::{self, Appender, Coder, FLAG_BIT_TRACING, Gzip},
    proto::{self, Decoder, FrameError, Message},
};

fn decode(max: usize, pieces: &[&[u8]]) -> (Vec<Message>, Option<FrameError>) {
    let mut d = Decoder::new(max);
    let mut out = Vec::new();
    for p in pieces {
        if let Err(e) = d.feed(p, &mut out) {
            return (out, Some(e));
        }
    }
    (out, None)
}

/// `arpc_decoder`: the arpc frame decoder. `data[0]` picks the body limit, `data[1]` splits the
/// reads; the messages and the error must not depend on the read boundaries.
pub fn arpc_decoder(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let max = usize::from(data[0]) * 64;
    let whole = decode(max, &[&data[2..]]);
    let parts = decode(max, &split(&data[1..]));
    assert_eq!(whole.1, parts.1);
    assert_eq!(whole.0.len(), parts.0.len());
    for (a, b) in whole.0.iter().zip(&parts.0) {
        assert_eq!(
            (a.seq, &a.method, &a.payload),
            (b.seq, &b.method, &b.payload)
        );
        assert!(a.payload.len() <= max);
    }
}

fn coders() -> Vec<Arc<dyn Coder>> {
    vec![
        Arc::new(Appender::new("trace", FLAG_BIT_TRACING)),
        Arc::new(Gzip::new(32)),
    ]
}

type Coded = (Vec<(Message, Values)>, Option<FrameError>);

/// The receive path of a connection with coders: frames, then the coder chain, then parsing.
fn decode_coded(max: usize, pieces: &[&[u8]]) -> Coded {
    let chain = coders();
    let mut d = Decoder::new(max);
    let mut out = Vec::new();
    for p in pieces {
        let r = d.feed_frames(p, |frame| {
            let mut values = Values::new();
            let mut buf = frame.to_vec();
            if !proto::is_heartbeat(frame) {
                coder::decode_frame(&chain, &mut buf, &mut values, max)
                    .map_err(|e| FrameError(e.0))?;
            }
            proto::decode_frame(&buf, &mut |m| out.push((m, std::mem::take(&mut values))))
        });
        if let Err(e) = r {
            return (out, Some(e));
        }
    }
    (out, None)
}

/// `arpc_coders`: the receive path with the gzip and appender coders (the frames of Go peers
/// using arpcex's coders). `data[0]` picks the body limit, `data[1]` splits the reads; the
/// result must not depend on the read boundaries, and no decoded body may pass the limit
/// however far its gzip data would inflate. The rest is also sent through the encoders and
/// must come back unchanged.
pub fn arpc_coders(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let max = usize::from(data[0]) * 256;
    let whole = decode_coded(max, &[&data[2..]]);
    let parts = decode_coded(max, &split(&data[1..]));
    assert_eq!(whole.1, parts.1);
    assert_eq!(whole.0.len(), parts.0.len());
    for ((a, av), (b, bv)) in whole.0.iter().zip(&parts.0) {
        assert_eq!((a, av), (b, bv));
        assert!(a.method.len() + a.payload.len() <= max);
    }
    // Encoding then decoding is the identity, with the value carried.
    let payload = &data[2..];
    let values = Values::new().with("trace", &payload[..payload.len().min(40)]);
    let plain = proto::encode(proto::Cmd::Notify, 0, false, false, "/f", 3, payload);
    let mut wire = plain.clone();
    coder::encode_frame(&coders(), &mut wire, &values);
    let mut back = wire;
    let mut got = Values::new();
    // The limit counts the appended value until the appender strips it.
    let max = plain.len() + 64;
    coder::decode_frame(&coders(), &mut back, &mut got, max).expect("own frame");
    assert_eq!(back, plain);
    assert_eq!(got, values);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Cmd, encode, ping, pong};
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn seeds() -> Vec<Vec<u8>> {
        let mut wire = Vec::new();
        wire.extend(encode(Cmd::Request, 0, false, false, "/echo", 1, b"hello"));
        wire.extend(encode(Cmd::Response, 1, false, false, "/echo", 1, b"err"));
        wire.extend(ping());
        wire.extend(encode(Cmd::Notify, 2, true, true, "/n", 7, &[0u8; 100]));
        wire.extend(pong());
        let mut v = Vec::new();
        for (m, s) in [(255u8, 0u8), (255, 3), (1, 0), (2, 17)] {
            v.push([&[m, s][..], &wire[..]].concat());
        }
        v
    }

    fn coded_seeds() -> Vec<Vec<u8>> {
        let chain = coders();
        let mut wire = Vec::new();
        let frames = [
            (
                encode(Cmd::Request, 0, false, false, "/echo", 1, b"hi"),
                "t-1",
            ),
            (
                encode(Cmd::Response, 2, false, false, "/echo", 1, &[b'a'; 300]),
                "",
            ),
            (
                encode(Cmd::Stream, 0, true, true, "/s", 5, &[b'b'; 100]),
                "t-2",
            ),
        ];
        for (mut f, t) in frames {
            let v = if t.is_empty() {
                Values::new()
            } else {
                Values::new().with("trace", t)
            };
            coder::encode_frame(&chain, &mut f, &v);
            wire.extend(f);
        }
        wire.extend(ping());
        let mut v = Vec::new();
        for (m, s) in [(255u8, 0u8), (255, 5), (1, 0), (2, 33)] {
            v.push([&[m, s][..], &wire[..]].concat());
        }
        v
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "arpc_decoder", arpc_decoder) > 0);
        assert!(replay(DIR, "arpc_coders", arpc_coders) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            arpc_decoder(s);
        }
        for s in &coded_seeds() {
            arpc_coders(s);
        }
        // The coded seeds really decode, values and all.
        let (msgs, err) = decode_coded(1 << 16, &[&coded_seeds()[0][2..]]);
        assert!(err.is_none());
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0].1.get("trace"), Some(&b"t-1"[..]));
        assert_eq!(msgs[1].0.payload, [b'a'; 300]);
    }

    /// Regenerates the seed files: `cargo test -p only-arpc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "arpc_decoder", &seeds());
        write_target_seeds(DIR, "arpc_coders", &coded_seeds());
    }
}
