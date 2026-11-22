//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use akio_core::fuzzing::split;

use crate::client::check_response;
use crate::deflate::{Inflater, PmdOffer, negotiate};
use crate::protocol::{Decoder, Event, ProtocolError, Role};

/// The accept value for the RFC 6455 sample key `dGhlIHNhbXBsZSBub25jZQ==`.
pub const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn decode_all(cfg: u8, pieces: &[&[u8]]) -> (Vec<Event>, Option<ProtocolError>) {
    let role = if cfg & 1 == 0 {
        Role::Server
    } else {
        Role::Client
    };
    let inflater = (cfg & 2 != 0).then(|| Inflater::new(cfg & 4 != 0));
    let mut d = Decoder::new(role, 64 << 10, inflater);
    let mut out = Vec::new();
    for p in pieces {
        if let Err(e) = d.decode(p, &mut out) {
            return (out, Some(e));
        }
    }
    (out, None)
}

/// `ws_frames`: the frame decoder. `data[0]`: bit 0 client role (else server), bit 1
/// permessage-deflate, bit 2 no context takeover; `data[1]` splits the reads. Events and the
/// error must not depend on the read boundaries.
pub fn ws_frames(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let cfg = data[0];
    let whole = decode_all(cfg, &[&data[2..]]);
    let parts = decode_all(cfg, &split(&data[1..]));
    assert_eq!(whole, parts, "decoding depends on read boundaries");
}

/// `ws_client_handshake`: the client's check of the server's handshake response (status,
/// `Upgrade`/`Connection`, accept key, subprotocol, permessage-deflate answer) and the
/// server-side extension negotiation. `data[0]` picks the offer.
pub fn ws_client_handshake(data: &[u8]) {
    let Some((&cfg, resp)) = data.split_first() else {
        return;
    };
    let pmd = (cfg & 1 != 0).then_some(PmdOffer {
        client_no_context_takeover: cfg & 2 != 0,
        server_no_context_takeover: cfg & 4 != 0,
        server_max_window_bits: (cfg & 8 != 0).then_some(9 + (cfg >> 5)),
    });
    let protocols: Vec<String> = if cfg & 16 != 0 {
        vec!["chat".into(), "superchat".into()]
    } else {
        Vec::new()
    };
    if let Ok(Some(a)) = check_response(SAMPLE_ACCEPT, &protocols, pmd.as_ref(), resp) {
        assert!(a.head_len <= resp.len());
    }
    // The same bytes as a client's extension offers (server side).
    if let Ok(s) = std::str::from_utf8(resp) {
        if let Some((_, header)) = negotiate(s.lines()) {
            assert!(header.starts_with("permessage-deflate"));
        }
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use crate::deflate::Deflater;
    use crate::protocol::{Opcode, close_payload, encode_frame, encode_frame_masked};

    pub(crate) fn ws_frames() -> Vec<Vec<u8>> {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let mut v = Vec::new();
        // Server role: masked frames.
        let mut m = Vec::new();
        encode_frame_masked(Opcode::Text, true, false, b"Hello", key, &mut m);
        encode_frame_masked(Opcode::Text, false, false, b"Hel", key, &mut m);
        encode_frame_masked(Opcode::Ping, true, false, b"p", key, &mut m);
        encode_frame_masked(Opcode::Continue, true, false, b"lo", key, &mut m);
        encode_frame_masked(Opcode::Binary, true, false, &[7u8; 300], key, &mut m);
        encode_frame_masked(Opcode::Pong, true, false, b"", key, &mut m);
        encode_frame_masked(
            Opcode::Close,
            true,
            false,
            &close_payload(1000, "bye"),
            key,
            &mut m,
        );
        for s in [0u8, 1, 9] {
            let mut x = vec![0u8, s];
            x.extend_from_slice(&m);
            v.push(x);
        }
        let mut big = Vec::new();
        encode_frame_masked(
            Opcode::Binary,
            true,
            false,
            &vec![1u8; 70_000],
            key,
            &mut big,
        );
        v.push([&[0u8, 200][..], &big[..64]].concat());
        // Client role: unmasked frames.
        let mut c = Vec::new();
        encode_frame(Opcode::Text, true, false, "héllo wörld".as_bytes(), &mut c);
        encode_frame(Opcode::Binary, false, false, b"ab", &mut c);
        encode_frame(Opcode::Continue, true, false, b"cd", &mut c);
        encode_frame(Opcode::Close, true, false, &[0x03, 0xe8], &mut c);
        for s in [0u8, 3] {
            let mut x = vec![1u8, s];
            x.extend_from_slice(&c);
            v.push(x);
        }
        // permessage-deflate, with and without context takeover, both roles.
        for nct in [false, true] {
            let mut d = Deflater::new(nct, 15);
            let mut srv = Vec::new();
            let mut cli = Vec::new();
            for msg in [
                &b"compress me compress me compress me"[..],
                b"compress me again",
            ] {
                let z = d.deflate(msg);
                encode_frame_masked(Opcode::Text, true, true, &z, key, &mut srv);
                encode_frame(Opcode::Binary, true, true, &z, &mut cli);
            }
            let cfg = 2 | (u8::from(nct) << 2);
            v.push([&[cfg, 0][..], &srv[..]].concat());
            v.push([&[cfg, 5][..], &srv[..]].concat());
            v.push([&[cfg | 1, 0][..], &cli[..]].concat());
        }
        v
    }

    pub(crate) fn ws_client_handshake() -> Vec<Vec<u8>> {
        let base = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
        let mut v = Vec::new();
        v.push([&[0u8][..], format!("{base}\r\n").as_bytes()].concat());
        v.push(
            [
                &[16u8][..],
                format!("{base}Sec-WebSocket-Protocol: chat\r\n\r\nframes").as_bytes(),
            ]
            .concat(),
        );
        v.push(
            [
                &[1u8 | 4 | 8][..],
                format!("{base}Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; server_max_window_bits=9\r\n\r\n").as_bytes(),
            ]
            .concat(),
        );
        v.push(
            [
                &[1u8][..],
                format!("{base}Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=10\r\n\r\n").as_bytes(),
            ]
            .concat(),
        );
        v.push(
            [
                &[0u8][..],
                &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"[..],
            ]
            .concat(),
        );
        v.push(
            [
                &[0u8][..],
                &b"permessage-deflate; client_max_window_bits, permessage-deflate; server_max_window_bits=10; client_no_context_takeover\r\nx-webkit-deflate-frame"[..],
            ]
            .concat(),
        );
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use akio_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "ws_frames", ws_frames)
            + replay(DIR, "ws_client_handshake", ws_client_handshake);
        assert!(n > 0, "no corpus found under fuzz/corpus");
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::ws_frames() {
            ws_frames(s);
        }
        for s in &seeds::ws_client_handshake() {
            ws_client_handshake(s);
        }
        // The sample handshake is accepted.
        let ok = &seeds::ws_client_handshake()[0];
        assert!(matches!(
            check_response(SAMPLE_ACCEPT, &[], None, &ok[1..]),
            Ok(Some(_))
        ));
    }

    /// Regenerates the seed files: `cargo test -p akio-ws --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "ws_frames", &seeds::ws_frames());
        write_target_seeds(DIR, "ws_client_handshake", &seeds::ws_client_handshake());
    }
}
