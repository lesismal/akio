//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use flash_core::fuzzing::split;

use crate::{Code, Deframer, GrpcServer, Status, parse_timeout, pct_decode};

fn deframe(max: usize, gzip: bool, pieces: &[&[u8]]) -> Result<(Vec<Vec<u8>>, bool), Code> {
    let mut d = Deframer::new(max, gzip);
    let mut out = Vec::new();
    for p in pieces {
        d.feed(p, &mut out).map_err(|s| s.code)?;
    }
    for m in &out {
        assert!(m.len() <= max);
    }
    Ok((out, d.leftover()))
}

/// `grpc_framing`: the length-prefixed message deframer (with gzip), plus the `grpc-timeout`
/// and `grpc-message` header parsers on the same bytes. `data[0]`: bit 0 gzip accepted, the rest
/// the size limit; `data[1]` splits the reads, which must not change the outcome.
pub fn grpc_framing(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let gzip = data[0] & 1 == 1;
    let max = usize::from(data[0] >> 1) * 128;
    let whole = deframe(max, gzip, &[&data[2..]]);
    let parts = deframe(max, gzip, &split(&data[1..]));
    assert_eq!(whole, parts, "deframing depends on read boundaries");
    if let Ok(s) = std::str::from_utf8(&data[2..]) {
        let _ = parse_timeout(s);
        let _ = pct_decode(s);
    }
}

fn server() -> GrpcServer {
    GrpcServer::new()
        .max_message_bytes(16 << 10)
        .unary("/echo.Echo/Unary", |_md, m, sink| {
            sink.send(&m);
            sink.finish(Status::ok());
        })
        .client_stream("/echo.Echo/Collect", |_md, all, sink| {
            sink.send(&all.concat());
            sink.finish(Status::ok());
        })
        .bidi("/echo.Echo/Bidi", |_md, sink| {
            Box::new(move |m| match m {
                Some(m) => {
                    sink.send(&m);
                }
                None => sink.finish(Status::new(Code::Ok, "done")),
            })
        })
        .compress(true)
}

/// `grpc_server`: a gRPC server (unary, client-streaming and bidi methods, gzip, deadlines)
/// behind an HTTP/2 connection fed arbitrary frames after a valid preface. `data[0]` splits the
/// reads.
pub fn grpc_server(data: &[u8]) {
    flash_http::fuzzing::h2_server_with(server(), data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use flash_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn h2_frame(out: &mut Vec<u8>, ty: u8, flags: u8, sid: u32, p: &[u8]) {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes()[1..]);
        out.push(ty);
        out.push(flags);
        out.extend_from_slice(&sid.to_be_bytes());
        out.extend_from_slice(p);
    }

    /// A literal header field without indexing, new name (no Huffman).
    fn lit(out: &mut Vec<u8>, n: &str, v: &str) {
        out.push(0);
        out.push(n.len() as u8);
        out.extend_from_slice(n.as_bytes());
        out.push(v.len() as u8);
        out.extend_from_slice(v.as_bytes());
    }

    fn call(sid: u32, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut block = Vec::new();
        for (n, v) in [
            (":method", "POST"),
            (":scheme", "http"),
            (":path", path),
            (":authority", "h"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]
        .iter()
        .chain(extra)
        {
            lit(&mut block, n, v);
        }
        let mut out = Vec::new();
        h2_frame(&mut out, 1, 0x4, sid, &block);
        h2_frame(&mut out, 0, 0x1, sid, body);
        out
    }

    fn seeds_server() -> Vec<Vec<u8>> {
        let msg = crate::frame(b"hello", false);
        let gz = crate::frame(b"hello hello hello", true);
        let two = [crate::frame(b"a", false), crate::frame(b"bc", false)].concat();
        let mut v = vec![[&[0u8][..], &call(1, "/echo.Echo/Unary", &[], &msg)].concat()];
        v.push(
            [
                &[0u8][..],
                &call(
                    1,
                    "/echo.Echo/Unary",
                    &[("grpc-encoding", "gzip"), ("grpc-accept-encoding", "gzip")],
                    &gz,
                ),
            ]
            .concat(),
        );
        v.push([&[3u8][..], &call(3, "/echo.Echo/Collect", &[], &two)].concat());
        v.push(
            [
                &[0u8][..],
                &call(5, "/echo.Echo/Bidi", &[("grpc-timeout", "100m")], &two),
            ]
            .concat(),
        );
        v.push([&[0u8][..], &call(1, "/nope", &[], &msg)].concat());
        v.push([&[0u8][..], &call(1, "/echo.Echo/Unary", &[], &msg[..3])].concat());
        v
    }

    fn seeds_framing() -> Vec<Vec<u8>> {
        let mut wire = crate::frame(b"hello", false);
        wire.extend(crate::frame(&[9u8; 300], true));
        wire.extend(crate::frame(b"", false));
        let mut v = Vec::new();
        for (c, s) in [(0xffu8, 0u8), (0xff, 4), (0xfe, 0), (0x03, 0)] {
            v.push([&[c, s][..], &wire[..]].concat());
        }
        for t in [
            "100m",
            "1H",
            "99999999S",
            "5u",
            "18446744073709551615H",
            "x%41%zz",
        ] {
            v.push([&[0xffu8, 0][..], t.as_bytes()].concat());
        }
        v
    }

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "grpc_framing", grpc_framing) + replay(DIR, "grpc_server", grpc_server);
        assert!(n > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds_framing() {
            grpc_framing(s);
        }
        for s in &seeds_server() {
            grpc_server(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p flash-grpc --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "grpc_framing", &seeds_framing());
        write_target_seeds(DIR, "grpc_server", &seeds_server());
    }
}
