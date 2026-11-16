//! Fuzz entry points (feature `fuzzing`; not a public API). Each function takes one fuzz input
//! and must never panic, hang or allocate without bound, whatever the bytes. The `fuzz/`
//! cargo-fuzz project calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only_core::fuzzing::{conn, split};
use only_core::{Acceptor, Handler};

use crate::message::{Headers, Request, Response};
use crate::parse::{ChunkDecoder, parse_head};
use crate::ws::{Message, WsConfig, WsHandler, WsSender};
use crate::{BodyEvent, BodyMode, Context, H2Config, HttpConfig, Service, WsOptions};
use only_ws::http1::Resume;

/// `http1_request`: the request head parser. A complete head must parse to the same result
/// from exactly its own bytes, and never claim more bytes than it was given. Also, `data[1..]`
/// fed in growing prefixes cut as `data[0]` says (resumed parsing) must reach the same outcome
/// as in one go.
pub fn http1_request(data: &[u8]) {
    if let Ok(Some((head, n))) = parse_head(data, &mut Resume::default()) {
        assert!(n <= data.len());
        let (again, m) = parse_head(&data[..n], &mut Resume::default())
            .expect("a complete head parses alone")
            .expect("and is complete");
        assert_eq!(m, n);
        assert_eq!(again.target, head.target);
        assert_eq!(again.headers.len(), head.headers.len());
    }
    let stream = data.get(1..).unwrap_or_default();
    let once = parse_head(stream, &mut Resume::default());
    let mut resume = Resume::default();
    let mut end = 0;
    for piece in split(data) {
        end += piece.len();
        match parse_head(&stream[..end], &mut resume) {
            Ok(None) => {}
            Ok(Some((head, n))) => {
                let Ok(Some((h, m))) = &once else {
                    panic!("resumed parsing completed, one-shot did not")
                };
                assert_eq!(
                    (n, &head.target, head.headers.len()),
                    (*m, &h.target, h.headers.len())
                );
                return;
            }
            Err(e) => {
                assert_eq!(once.as_ref().err(), Some(&e), "resumed error differs");
                return;
            }
        }
    }
    // Still incomplete: one-shot must not have completed (it may have refused a byte of the
    // last, unfinished line, which resumed parsing only examines once the line ends).
    assert!(
        !matches!(once, Ok(Some(_))),
        "one-shot finished, resumed parsing did not"
    );
}

/// Splits a `regex_match` input: the pattern, then the subjects (NUL-separated, lossy UTF-8).
pub fn regex_input(data: &[u8]) -> (String, Vec<String>) {
    let mut parts = data.split(|&b| b == 0);
    let pattern = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let subjects = parts
        .take(16)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    (pattern, subjects)
}

/// `regex_match`: the route constraint engine (`crate::re`). Compiling must not panic, and for
/// small patterns the bit-parallel simulation must agree with the general one. (The cargo-fuzz
/// target also compares the outcome with the `regex` crate.)
pub fn regex_match(data: &[u8]) {
    if data.len() > 4096 {
        return;
    }
    let (pattern, subjects) = regex_input(data);
    let Ok(re) = crate::re::Regex::new(&pattern) else {
        return;
    };
    for s in std::iter::once("").chain(subjects.iter().map(String::as_str)) {
        assert_eq!(
            re.is_match(s),
            re.pike_match(s),
            "engines disagree on {pattern:?} / {s:?}"
        );
    }
}

/// `http1_chunked`: the chunked body decoder. `data[0]` picks the read boundaries and
/// `data[1]` the size limit; the outcome must not depend on the boundaries.
pub fn http1_chunked(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let max = match data[1] {
        0 => usize::MAX,
        b => usize::from(b) * 64,
    };
    let wire = &data[2..];
    let whole = decode_chunked(&[wire], max);
    let mut framed = vec![data[0]];
    framed.extend_from_slice(wire);
    let pieces = split(&framed);
    let parts = decode_chunked(&pieces, max);
    assert_eq!(whole, parts, "chunked decoding depends on read boundaries");
}

type Decoded = Result<(Vec<u8>, usize, bool, usize), ()>;

fn decode_chunked(pieces: &[&[u8]], max: usize) -> Decoded {
    let mut d = ChunkDecoder::new();
    let mut out = Vec::new();
    let mut used = 0;
    for p in pieces {
        if d.is_done() {
            break;
        }
        let n = d.feed(p, &mut out, max).map_err(|_| ())?;
        assert!(n <= p.len());
        assert!(out.len() <= max, "decoded past the limit");
        used += n;
    }
    let trailers = if d.is_done() { d.trailers().len() } else { 0 };
    Ok((out, used, d.is_done(), trailers))
}

/// `hpack`: the HPACK decoder as the HTTP/2 server configures it. `data[0]` splits the input
/// into two header blocks decoded in sequence (the dynamic table carries over). Whatever decodes
/// must survive a round trip through the encoder (with and without Huffman coding), and the
/// limited decoder must agree with the plain one.
pub fn hpack(data: &[u8]) {
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(cut).min(rest.len());
    let mut dec = crate::hpack::Decoder::new();
    let mut lim = crate::hpack::Decoder::new();
    let mut enc = [crate::hpack::Encoder::new(), crate::hpack::Encoder::new()];
    enc[1].set_huffman(false);
    let mut back = [crate::hpack::Decoder::new(), crate::hpack::Decoder::new()];
    for block in [&rest[..cut], &rest[cut..]] {
        let r = dec.decode(block);
        let limited = lim.decode_limited(block, 256);
        let Ok(list) = r else {
            assert!(limited.is_err(), "limited decoding accepted a bad block");
            return;
        };
        let (kept, size) = limited.expect("limited decoding refused a good block");
        assert_eq!(
            size,
            list.iter()
                .map(|(n, v)| n.len() + v.len() + 32)
                .sum::<usize>()
        );
        assert_eq!(kept[..], list[..kept.len()]);
        for (e, d) in enc.iter_mut().zip(&mut back) {
            let wire = e.encode(list.iter().map(|(n, v)| (&n[..], &v[..])));
            assert_eq!(d.decode(&wire).expect("own encoding decodes"), list);
        }
    }
}

/// `http1_client`: the HTTP/1 client's response parser (head, `Content-Length`, chunked and
/// close-delimited bodies, interim responses, keep-alive reuse). `data[0]` splits the reads;
/// the low bit of `data[1]` marks the requests as `HEAD`.
pub fn http1_client(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let head_only = data[1] & 1 == 1;
    let mut framed = vec![data[0]];
    framed.extend_from_slice(&data[2..]);
    crate::client::fuzz_responses(&split(&framed), head_only);
}

// ---- the server session ----------------------------------------------------------------------

struct Echo;

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
}

struct Raw;

impl crate::raw::RawHandler for Raw {
    fn on_data(&mut self, conn: &crate::raw::RawConn, data: &[u8]) {
        let _ = conn.send(data);
    }
}

/// What a real application might do with each request, chosen by the path.
struct Svc;

impl Service for Svc {
    fn body_mode(&self, req: &Request) -> BodyMode {
        if req.target.starts_with("/stream") {
            BodyMode::Stream
        } else {
            BodyMode::Buffered
        }
    }

    fn call(&self, ctx: &mut Context) {
        let path = ctx.path().to_owned();
        if path.starts_with("/ws") {
            let opts = WsOptions {
                config: {
                    let mut v = WsConfig::default();
                    v.max_message_bytes = 64 << 10;
                    v
                },
                protocols: vec!["chat".into()],
                origin_allowed: None,
            };
            ctx.upgrade_websocket(Echo, &opts);
        } else if path.starts_with("/raw") {
            ctx.upgrade_raw(Raw);
        } else if path.starts_with("/stream") {
            ctx.on_body(|ctx, ev| match ev {
                BodyEvent::Chunk(_) => {}
                BodyEvent::End(t) => {
                    let n = t.len();
                    ctx.text(200, format!("{n} trailers"));
                }
            });
        } else if path.starts_with("/sse") {
            if let Some(s) = ctx.stream_response(200, Headers::new()) {
                let _ = s.write(b"data: 1\n\n");
                s.finish();
            }
        } else if path.starts_with("/push") {
            ctx.push("/pushed");
            ctx.text(200, "pushed");
        } else if path.starts_with("/detach") {
            if let Some(d) = ctx.detach() {
                d.respond(Response::text(202, "later"));
            }
        } else {
            let body = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", body);
        }
    }
}

fn session_config() -> HttpConfig {
    HttpConfig {
        max_header_bytes: 8 << 10,
        max_body_bytes: 64 << 10,
        h2: Some(H2Config {
            max_concurrent_streams: 16,
            initial_window: 1 << 16,
            conn_window: 1 << 20,
            max_header_list: 16 << 10,
            max_body_bytes: 64 << 10,
            max_pending_bytes: 1 << 20,
            max_conn_pending_bytes: 4 << 20,
            max_resets: 100,
            max_control_frames: 1000,
            reset_window: std::time::Duration::from_secs(30),
        }),
        // No deadline thread in fuzz runs: every read is driven by the harness.
        head_timeout: None,
        keep_alive_timeout: None,
        body_timeout: None,
    }
}

fn run_session(pieces: &[&[u8]]) {
    run_session_with(Svc, pieces);
}

/// Drives one server connection of `service` with `pieces` as the reads, then shuts it down
/// and closes it (for fuzz targets of services built on `only-http`, such as gRPC).
pub fn run_session_with<S: Service>(service: S, pieces: &[&[u8]]) {
    let acceptor = crate::serve_with(session_config(), service);
    let c = conn();
    let mut s = acceptor.on_open(&c);
    for p in pieces {
        s.on_data(&c, p);
    }
    acceptor.on_shutdown(&c);
    s.on_close(&c, None);
}

/// `http1_server`: a whole server connection (HTTP/1 pipelining, bodies, `h2c` upgrades,
/// prior-knowledge HTTP/2, WebSocket and raw upgrades). `data[0]` splits the reads.
pub fn http1_server(data: &[u8]) {
    run_session(&split(data));
}

/// The client preface and an empty SETTINGS frame.
pub const H2_START: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// `h2_server`: an HTTP/2 server connection fed arbitrary frames after a valid preface and
/// SETTINGS. `data[0]` splits the reads.
pub fn h2_server(data: &[u8]) {
    h2_server_with(Svc, data);
}

/// [`h2_server`] with another service.
pub fn h2_server_with<S: Service>(service: S, data: &[u8]) {
    let mut pieces = vec![H2_START];
    pieces.extend(split(data));
    run_session_with(service, &pieces);
}

// ---- seeds -----------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod seeds {
    use crate::h2::frame;

    fn with(split: u8, wire: &[u8]) -> Vec<u8> {
        let mut v = vec![split];
        v.extend_from_slice(wire);
        v
    }

    pub(crate) fn requests() -> Vec<&'static [u8]> {
        vec![
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /a?b=c HTTP/1.0\r\nUser-Agent: x\r\nAccept: */*\r\n\r\n",
            b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody",
            b"POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
            b"POST /stream HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nbody\r\n0\r\nX-T: 1\r\n\r\n",
            b"POST /stream HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc",
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET /sse HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET /detach HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET /push HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET /raw HTTP/1.1\r\nHost: h\r\n\r\nraw bytes",
            b"POST / HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
            b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
            b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58\x89\x80\x37\xfa\x21\x3d",
            b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            b"GET http://example.com/abs HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        ]
    }

    pub(crate) fn http1_request() -> Vec<Vec<u8>> {
        requests().into_iter().map(<[u8]>::to_vec).collect()
    }

    pub(crate) fn http1_server() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for r in requests() {
            v.push(with(0, r));
            v.push(with(7, r));
        }
        // Prior-knowledge HTTP/2 through the HTTP/1 session.
        let mut h2 = super::H2_START.to_vec();
        h2.extend(h2_request(1));
        v.push(with(0, &h2));
        v
    }

    pub(crate) fn http1_chunked() -> Vec<Vec<u8>> {
        let bodies: [&[u8]; 6] = [
            b"4\r\nbody\r\n0\r\n\r\n",
            b"4;name=val\r\nbody\r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\nOther: y\r\n\r\n",
            b"0\r\n\r\nGET / HTTP/1.1\r\n\r\n",
            b"fffffffffffffffff\r\n",
            b"1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n",
            b"5\r\nab\r\n",
        ];
        let mut v = Vec::new();
        for b in bodies {
            for (s, m) in [(0u8, 0u8), (3, 0), (1, 1)] {
                let mut x = vec![s, m];
                x.extend_from_slice(b);
                v.push(x);
            }
        }
        v
    }

    /// RFC 7541 appendix C header blocks (with and without Huffman), split by `data[0]`.
    pub(crate) fn hpack() -> Vec<Vec<u8>> {
        let c2: &[u8] = &[
            0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let c3_2: &[u8] = &[
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, b'n', b'o', b'-', b'c', b'a', b'c', b'h', b'e',
        ];
        let c4: &[u8] = &[
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let custom: &[u8] = &[
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ];
        let mut v = Vec::new();
        let mut two = c2.to_vec();
        two.extend_from_slice(c3_2);
        v.push(with(c2.len() as u8, &two));
        v.push(with(c4.len() as u8, c4));
        v.push(with(0, custom));
        v.push(with(0, &[0x3f, 0xe1, 0x1f])); // table size update to 4096
        v.push(with(
            0,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ));
        v
    }

    fn h2_request(sid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = crate::hpack::Encoder::new();
        let block = enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (b":scheme", b"http"),
            (b":path", b"/stream"),
            (b":authority", b"h"),
            (b"content-length", b"4"),
        ]);
        frame(&mut out, 1, 0x4, sid, &block);
        frame(&mut out, 0, 0x1, sid, b"body");
        out
    }

    pub(crate) fn h2_server() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        let mut enc = crate::hpack::Encoder::new();
        let get = enc.encode([
            (&b":method"[..], &b"GET"[..]),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b":authority", b"localhost"),
        ]);
        let mut a = Vec::new();
        frame(&mut a, 1, 0x5, 1, &get);
        v.push(with(0, &a));
        v.push(with(5, &h2_request(3)));
        let mut b = Vec::new();
        frame(&mut b, 4, 0, 0, &[0, 4, 0, 0, 0x10, 0, 0, 3, 0, 0, 0, 1]);
        frame(&mut b, 4, 1, 0, &[]);
        frame(&mut b, 8, 0, 0, &(1u32 << 20).to_be_bytes());
        frame(&mut b, 6, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        frame(&mut b, 1, 0x1, 1, &get[..2]); // HEADERS without END_HEADERS
        frame(&mut b, 9, 0x4, 1, &get[2..]); // CONTINUATION
        frame(&mut b, 3, 0, 1, &[0, 0, 0, 8]);
        frame(&mut b, 2, 0, 5, &[0, 0, 0, 1, 16]);
        frame(&mut b, 7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        v.push(with(0, &b));
        let mut p = Vec::new();
        // PADDED + PRIORITY headers for /push, then trailers on a streamed body.
        let mut payload = vec![2u8, 0, 0, 0, 0, 16];
        payload.extend(enc.encode([
            (&b":method"[..], &b"GET"[..]),
            (b":scheme", b"http"),
            (b":path", b"/push"),
            (b":authority", b"h"),
        ]));
        payload.extend([0, 0]);
        frame(&mut p, 1, 0x4 | 0x8 | 0x20 | 0x1, 5, &payload);
        let st = enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (b":scheme", b"http"),
            (b":path", b"/stream"),
            (b":authority", b"h"),
        ]);
        frame(&mut p, 1, 0x4, 7, &st);
        frame(&mut p, 0, 0x8, 7, &[1, b'x', 0]);
        let tr = enc.encode([(&b"x-trailer"[..], &b"1"[..])]);
        frame(&mut p, 1, 0x5, 7, &tr);
        v.push(with(0, &p));
        v
    }

    /// Route-style patterns with matching and non-matching subjects.
    pub(crate) fn regex_match() -> Vec<Vec<u8>> {
        let cases: [&[u8]; 10] = [
            b"[0-9]+\x0042\x0042x\x00",
            b"\\d{4}-\\d{2}\x002026-11\x002026-1",
            b"0x[0-9a-f]+\x000x1f\x000x",
            b"(?:ab|a)(bc|c)*\x00abc\x00abcbc\x00ac",
            b"[^/]+\x00h\xc3\xa9llo\x00a/b",
            b"(a|aa)*b{0,3}c?\x00aaaaaaaaaaaaaaaaaaaaaaa\x00aabbbc",
            b"[\\w.-]+@[\\w-]+\\.[a-z]{2,6}\x00a.b@c-d.io\x00a@b",
            b"^v[0-9]+(\\.[0-9]+){0,2}$\x00v1.2.3\x00v1.2.3.4",
            b"[a-c]{70}|x{1,100}\x00xxxx\x00abc",
            b".*\\S\x00 x\x00 \n",
        ];
        cases.iter().map(|c| c.to_vec()).collect()
    }

    pub(crate) fn http1_client() -> Vec<Vec<u8>> {
        let resp: [&[u8]; 8] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: y\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            b"HTTP/1.0 200 OK\r\n\r\nuntil close",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 304 Not Modified\r\n\r\n",
            b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        ];
        let mut v = Vec::new();
        for r in resp {
            for (s, h) in [(0u8, 0u8), (4, 0), (0, 1)] {
                let mut x = vec![s, h];
                x.extend_from_slice(r);
                v.push(x);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let mut n = 0;
        n += replay(DIR, "http1_request", http1_request);
        n += replay(DIR, "http1_chunked", http1_chunked);
        n += replay(DIR, "hpack", hpack);
        n += replay(DIR, "http1_client", http1_client);
        n += replay(DIR, "http1_server", http1_server);
        n += replay(DIR, "h2_server", h2_server);
        n += replay(DIR, "regex_match", regex_match);
        assert!(n > 0, "no corpus found under fuzz/corpus");
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::http1_request() {
            http1_request(s);
        }
        for s in &seeds::http1_chunked() {
            http1_chunked(s);
        }
        for s in &seeds::hpack() {
            hpack(s);
        }
        for s in &seeds::http1_client() {
            http1_client(s);
        }
        for s in &seeds::http1_server() {
            http1_server(s);
        }
        for s in &seeds::h2_server() {
            h2_server(s);
        }
        for s in &seeds::regex_match() {
            regex_match(s);
        }
    }

    /// Regression: a handler that pushes from every request (including pushed ones) used to
    /// recurse without bound (stack overflow) and sent PUSH_PROMISE on server-initiated streams.
    #[test]
    fn push_from_a_pushed_stream_is_refused() {
        let mut enc = crate::hpack::Encoder::new();
        let block = enc.encode([
            (&b":method"[..], &b"GET"[..]),
            (b":scheme", b"http"),
            (b":path", b"/push"),
            (b":authority", b"h"),
        ]);
        let mut wire = vec![0u8];
        crate::h2::frame(&mut wire, 1, 0x5, 1, &block);
        h2_server(&wire);
    }

    /// Regression (found by fuzzing gRPC): closing an HTTP/2 connection dropped the parked
    /// context of a streamed request while holding the connection lock; a body sink that responds
    /// when dropped (as gRPC's does) then locked it again and the I/O thread deadlocked. The same
    /// happened when a RST_STREAM ended such a stream.
    #[test]
    fn dropping_a_streamed_request_does_not_deadlock() {
        struct RespondOnDrop(Option<crate::Detached>);
        impl Drop for RespondOnDrop {
            fn drop(&mut self) {
                if let Some(d) = self.0.take() {
                    d.respond(Response::text(500, "gone"));
                }
            }
        }
        let svc = crate::Streaming(|ctx: &mut Context| {
            let guard = RespondOnDrop(ctx.detach());
            ctx.on_body(move |_, _| {
                let _ = &guard;
            });
        });
        let mut enc = crate::hpack::Encoder::new();
        let block = enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (b":scheme", b"http"),
            (b":path", b"/"),
            (b":authority", b"h"),
        ]);
        let mut open = vec![0u8];
        crate::h2::frame(&mut open, 1, 0x4, 1, &block);
        let mut reset = open.clone();
        crate::h2::frame(&mut reset, 3, 0, 1, &[0, 0, 0, 8]);
        crate::h2::frame(&mut reset, 1, 0x4, 3, &block);
        h2_server_with(svc, &open); // dropped on close
        let svc = crate::Streaming(|ctx: &mut Context| {
            let guard = RespondOnDrop(ctx.detach());
            ctx.on_body(move |_, _| {
                let _ = &guard;
            });
        });
        h2_server_with(svc, &reset); // dropped by RST_STREAM
    }

    /// Regenerates the seed files: `cargo test -p only-http --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "http1_request", &seeds::http1_request());
        write_target_seeds(DIR, "http1_chunked", &seeds::http1_chunked());
        write_target_seeds(DIR, "hpack", &seeds::hpack());
        write_target_seeds(DIR, "http1_client", &seeds::http1_client());
        write_target_seeds(DIR, "http1_server", &seeds::http1_server());
        write_target_seeds(DIR, "h2_server", &seeds::h2_server());
        write_target_seeds(DIR, "regex_match", &seeds::regex_match());
    }
}
