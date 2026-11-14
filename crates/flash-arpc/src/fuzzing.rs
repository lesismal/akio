//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use flash_core::fuzzing::split;

use crate::proto::{Decoder, FrameError, Message};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Cmd, encode, ping, pong};
    use flash_core::fuzzing::{replay, write_target_seeds};

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

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "arpc_decoder", arpc_decoder) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            arpc_decoder(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p flash-arpc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "arpc_decoder", &seeds());
    }
}
