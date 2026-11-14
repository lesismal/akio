//! HTTP/2 server at the frame level: a hand-driven peer sends crafted frames and checks the
//! server's answers (connection errors as GOAWAY, stream errors as RST_STREAM, PING, SETTINGS,
//! flow control, CONTINUATION, padding, trailers, malformed requests).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    thread,
    time::Duration,
};

use loona_hpack::{Decoder, Encoder};
use only::{Backend, Config, Engine, Listener, UringConfig};
use only_http::{BodyEvent, Context, H2Config, Headers, HttpConfig, Router, Streaming, serve_with};

// Frame types, flags and error codes (RFC 9113).
const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIO: u8 = 0x20;

const NO_ERROR: u32 = 0;
const PROTOCOL: u32 = 1;
const FLOW_CONTROL: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const FRAME_SIZE: u32 = 6;
const REFUSED_STREAM: u32 = 7;
const COMPRESSION: u32 = 9;
const ENHANCE: u32 = 11;

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn app() -> Router {
    Router::new()
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .get("/headers", |ctx: &mut Context| {
            let cookie = ctx.header("cookie").unwrap_or("-").to_owned();
            let host = ctx.header("host").unwrap_or("-").to_owned();
            ctx.text(200, format!("{cookie}|{host}"));
        })
        .get("/huge-header", |ctx: &mut Context| {
            // Bigger than one 16 KiB frame: the header block goes out as HEADERS + CONTINUATION.
            ctx.add_response_header("x-big", "v".repeat(40_000));
            ctx.text(200, "big header");
        })
        .get("/slow", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                d.respond(only_http::Response::text(200, "slow"));
            });
        })
        .get("/stream", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for _ in 0..4 {
                    let _ = s.write(&[b'x'; 1000]);
                }
                let mut tr = Headers::new();
                tr.append("x-done", "yes");
                s.finish_with_trailers(tr);
            });
        })
        .post(
            "/sum",
            Streaming(|ctx: &mut Context| {
                let mut sum = 0usize;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => sum += b.len(),
                    BodyEvent::End(tr) => {
                        let t = tr.get("x-trailer").unwrap_or("-").to_owned();
                        ctx.text(200, format!("{sum} {t}"));
                    }
                });
            }),
        )
}

fn start_with(h2: H2Config) -> Arc<Engine> {
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(h2);
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(500);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(1)
                    .serve(serve_with(cfg, app())),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

fn start() -> Arc<Engine> {
    start_with(H2Config::default())
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

type Fields = Vec<(String, String)>;
type Case = Box<dyn Fn(&mut Peer)>;

struct Frame {
    ty: u8,
    flags: u8,
    sid: u32,
    payload: Vec<u8>,
}

/// One HTTP/2 connection driven by hand.
struct Peer {
    s: TcpStream,
    enc: Encoder<'static>,
    dec: Decoder<'static>,
}

impl Peer {
    /// Connects, exchanges prefaces and SETTINGS (ours carry `settings`).
    fn open(e: &Engine, settings: &[(u16, u32)]) -> Peer {
        let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut p = Peer {
            s,
            enc: Encoder::new(),
            dec: Decoder::new(),
        };
        p.s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        let mut sp = Vec::new();
        for (id, v) in settings {
            sp.extend_from_slice(&id.to_be_bytes());
            sp.extend_from_slice(&v.to_be_bytes());
        }
        p.send(SETTINGS, 0, 0, &sp);
        // The server's SETTINGS comes first; ack it.
        let f = p.read();
        assert_eq!((f.ty, f.flags), (SETTINGS, 0));
        p.send(SETTINGS, ACK, 0, &[]);
        p
    }

    fn send(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        let mut b = len.to_be_bytes()[1..].to_vec();
        b.push(ty);
        b.push(flags);
        b.extend_from_slice(&sid.to_be_bytes());
        b.extend_from_slice(payload);
        self.s.write_all(&b).unwrap();
    }

    fn block(&mut self, headers: &[(&str, &str)]) -> Vec<u8> {
        self.enc
            .encode(headers.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())))
    }

    fn request(&mut self, sid: u32, method: &str, path: &str, end: bool) {
        let b = self.block(&[
            (":method", method),
            (":scheme", "http"),
            (":path", path),
            (":authority", "x"),
        ]);
        self.send(
            HEADERS,
            END_HEADERS | if end { END_STREAM } else { 0 },
            sid,
            &b,
        );
    }

    fn read(&mut self) -> Frame {
        let mut h = [0u8; 9];
        self.s.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let mut payload = vec![0; len];
        self.s.read_exact(&mut payload).unwrap();
        Frame {
            ty: h[3],
            flags: h[4],
            sid: u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
            payload,
        }
    }

    /// Reads until a frame matches.
    fn until(&mut self, mut pred: impl FnMut(&Frame) -> bool) -> Frame {
        loop {
            let f = self.read();
            if pred(&f) {
                return f;
            }
        }
    }

    /// The error code of the next GOAWAY.
    fn goaway(&mut self) -> u32 {
        let f = self.until(|f| f.ty == GOAWAY);
        u32::from_be_bytes(f.payload[4..8].try_into().unwrap())
    }

    /// The error code of the next RST_STREAM on `sid`.
    fn rst(&mut self, sid: u32) -> u32 {
        let f = self.until(|f| f.ty == RST_STREAM && f.sid == sid);
        u32::from_be_bytes(f.payload[..4].try_into().unwrap())
    }

    /// Reads the whole response on `sid`: (status, headers, body, trailers).
    fn response(&mut self, sid: u32) -> (u16, Fields, Vec<u8>, Fields) {
        let mut block = Vec::new();
        let mut heads: Vec<Fields> = Vec::new();
        let mut body = Vec::new();
        loop {
            let f = self.read();
            if f.sid != sid {
                continue;
            }
            match f.ty {
                HEADERS | CONTINUATION => {
                    block.extend_from_slice(&f.payload);
                    if f.flags & END_HEADERS != 0 {
                        let list = self.dec.decode(&block).unwrap();
                        block.clear();
                        heads.push(
                            list.into_iter()
                                .map(|(n, v)| {
                                    (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap())
                                })
                                .collect(),
                        );
                    }
                    if f.flags & END_STREAM != 0 {
                        break;
                    }
                }
                DATA => {
                    body.extend_from_slice(&f.payload);
                    if f.flags & END_STREAM != 0 {
                        break;
                    }
                }
                RST_STREAM => panic!("stream {sid} reset"),
                _ => {}
            }
        }
        let head = heads.remove(0);
        let status = head
            .iter()
            .find(|(n, _)| n == ":status")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let trailers = heads.pop().unwrap_or_default();
        (status, head, body, trailers)
    }
}

#[test]
fn ping_is_acked_and_bad_pings_are_connection_errors() {
    let e = start();
    let mut p = Peer::open(&e, &[]);
    p.send(PING, 0, 0, b"12345678");
    let f = p.until(|f| f.ty == PING);
    assert_eq!((f.flags, f.payload.as_slice()), (ACK, &b"12345678"[..]));
    // An ACK is not answered; the connection keeps working.
    p.send(PING, ACK, 0, b"abcdefgh");
    p.request(1, "GET", "/hello", true);
    assert_eq!(p.response(1).0, 200);
    p.send(PING, 0, 0, b"short");
    assert_eq!(p.goaway(), FRAME_SIZE);

    let mut p = Peer::open(&e, &[]);
    p.send(PING, 0, 1, b"12345678");
    assert_eq!(p.goaway(), PROTOCOL);
    stop(&e);
}

#[test]
fn goaway_rst_priority_and_push_promise_from_the_client() {
    let e = start();
    // A valid GOAWAY is accepted; a bad one is not.
    let mut p = Peer::open(&e, &[]);
    p.send(GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
    p.send(GOAWAY, 0, 0, &[0, 0, 0]);
    assert_eq!(p.goaway(), FRAME_SIZE);
    let mut p = Peer::open(&e, &[]);
    p.send(GOAWAY, 0, 3, &[0; 8]);
    assert_eq!(p.goaway(), PROTOCOL);

    // PRIORITY: stream 0 is a connection error, a bad length or self-dependency a stream error.
    let mut p = Peer::open(&e, &[]);
    p.send(PRIORITY, 0, 1, &[0, 0, 0, 0, 0]);
    p.send(PRIORITY, 0, 3, &[0, 0, 0]);
    assert_eq!(p.rst(3), FRAME_SIZE);
    p.send(PRIORITY, 0, 5, &[0, 0, 0, 5, 16]);
    assert_eq!(p.rst(5), PROTOCOL);
    p.send(PRIORITY, 0, 0, &[0, 0, 0, 1, 16]);
    assert_eq!(p.goaway(), PROTOCOL);

    // RST_STREAM: on stream 0, with a bad length, or for an idle stream.
    for (sid, payload, code) in [
        (0, &[0u8, 0, 0, 8][..], PROTOCOL),
        (1, &[0, 0, 8][..], FRAME_SIZE),
        (7, &[0, 0, 0, 8][..], PROTOCOL),
    ] {
        let mut p = Peer::open(&e, &[]);
        p.send(RST_STREAM, 0, sid, payload);
        assert_eq!(p.goaway(), code);
    }
    // Resetting an open stream is fine.
    let mut p = Peer::open(&e, &[]);
    p.request(1, "GET", "/slow", true);
    p.send(RST_STREAM, 0, 1, &8u32.to_be_bytes());
    p.request(3, "GET", "/hello", true);
    assert_eq!(p.response(3).0, 200);

    let mut p = Peer::open(&e, &[]);
    p.send(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2]);
    assert_eq!(p.goaway(), PROTOCOL);
    stop(&e);
}

#[test]
fn settings_are_validated() {
    let e = start();
    // Every known setting with a valid value, plus an unknown one: acked.
    let mut p = Peer::open(
        &e,
        &[
            (1, 0),
            (2, 0),
            (3, 10),
            (4, 1 << 16),
            (5, 1 << 15),
            (6, 1 << 16),
            (0x99, 7),
        ],
    );
    p.until(|f| f.ty == SETTINGS && f.flags == ACK);
    p.request(1, "GET", "/hello", true);
    assert_eq!(p.response(1).2, b"hello");
    // Raising the initial window applies to open streams too.
    p.request(3, "GET", "/slow", true);
    let mut sp = 4u16.to_be_bytes().to_vec();
    sp.extend_from_slice(&(1u32 << 20).to_be_bytes());
    p.send(SETTINGS, 0, 0, &sp);
    assert_eq!(p.response(3).2, b"slow");

    for (settings, code) in [
        (vec![(2u16, 2u32)], PROTOCOL),
        (vec![(4, 1 << 31)], FLOW_CONTROL),
        (vec![(5, 100)], PROTOCOL),
        (vec![(5, 1 << 24)], PROTOCOL),
    ] {
        let mut p = Peer::open(&e, &[]);
        let mut sp = Vec::new();
        for (id, v) in settings {
            sp.extend_from_slice(&id.to_be_bytes());
            sp.extend_from_slice(&v.to_be_bytes());
        }
        p.send(SETTINGS, 0, 0, &sp);
        assert_eq!(p.goaway(), code);
    }
    for (flags, sid, payload, code) in [
        (ACK, 0, &[0u8; 6][..], FRAME_SIZE),
        (0, 0, &[0u8; 5][..], FRAME_SIZE),
        (0, 1, &[][..], PROTOCOL),
    ] {
        let mut p = Peer::open(&e, &[]);
        p.send(SETTINGS, flags, sid, payload);
        assert_eq!(p.goaway(), code);
    }
    // The first frame must be SETTINGS.
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    s.write_all(&[0, 0, 8, PING, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    let mut p = Peer {
        s,
        enc: Encoder::new(),
        dec: Decoder::new(),
    };
    assert_eq!(p.goaway(), PROTOCOL);
    stop(&e);
}

#[test]
fn window_updates_are_validated() {
    let e = start();
    for (sid, inc, code) in [
        (0, 0u32, PROTOCOL),
        (0, 0x7fff_ffff, FLOW_CONTROL),
        (9, 1, PROTOCOL),
    ] {
        let mut p = Peer::open(&e, &[]);
        p.send(WINDOW_UPDATE, 0, sid, &inc.to_be_bytes());
        assert_eq!(p.goaway(), code);
    }
    let mut p = Peer::open(&e, &[]);
    p.send(WINDOW_UPDATE, 0, 0, &[0, 1]);
    assert_eq!(p.goaway(), FRAME_SIZE);
    // Stream level: a zero increment or an overflow resets the stream only.
    let mut p = Peer::open(&e, &[]);
    p.request(1, "GET", "/slow", true);
    p.send(WINDOW_UPDATE, 0, 1, &0u32.to_be_bytes());
    assert_eq!(p.rst(1), PROTOCOL);
    p.request(3, "GET", "/slow", true);
    p.send(WINDOW_UPDATE, 0, 3, &0x7fff_ffffu32.to_be_bytes());
    assert_eq!(p.rst(3), FLOW_CONTROL);
    // A late update for a closed stream is ignored.
    p.request(5, "GET", "/hello", true);
    assert_eq!(p.response(5).0, 200);
    p.send(WINDOW_UPDATE, 0, 5, &100u32.to_be_bytes());
    p.send(WINDOW_UPDATE, 0, 0, &100u32.to_be_bytes());
    p.request(7, "GET", "/hello", true);
    assert_eq!(p.response(7).0, 200);
    stop(&e);
}

#[test]
fn small_peer_window_stalls_the_response_until_updated() {
    let e = start();
    // Initial stream window of 100 bytes: the 4000-byte streamed body needs WINDOW_UPDATEs.
    let mut p = Peer::open(&e, &[(4, 100)]);
    p.request(1, "GET", "/stream", true);
    let mut got = 0;
    let mut trailers = false;
    while !trailers {
        let f = p.read();
        match f.ty {
            DATA if f.sid == 1 => {
                got += f.payload.len();
                if !f.payload.is_empty() {
                    let inc = (f.payload.len() as u32).to_be_bytes();
                    p.send(WINDOW_UPDATE, 0, 1, &inc);
                    p.send(WINDOW_UPDATE, 0, 0, &inc);
                }
            }
            HEADERS if f.sid == 1 && f.flags & END_STREAM != 0 => trailers = true,
            _ => {}
        }
    }
    assert_eq!(got, 4000);
    stop(&e);
}

#[test]
fn header_blocks_with_continuation_padding_and_priority() {
    let e = start();
    let mut p = Peer::open(&e, &[]);
    let b = p.block(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/headers"),
        (":authority", "example"),
        ("cookie", "a=1"),
        ("cookie", "b=2"),
    ]);
    let (a, rest) = b.split_at(3);
    let (m, z) = rest.split_at(3);
    p.send(HEADERS, END_STREAM, 1, a);
    p.send(CONTINUATION, 0, 1, m);
    p.send(CONTINUATION, END_HEADERS, 1, z);
    let (status, _, body, _) = p.response(1);
    assert_eq!((status, body.as_slice()), (200, &b"a=1; b=2|example"[..]));

    // PADDED + PRIORITY flags around the block.
    let b = p.block(&[(":method", "GET"), (":scheme", "http"), (":path", "/hello")]);
    let mut payload = vec![4u8]; // pad length
    payload.extend_from_slice(&[0, 0, 0, 0, 16]); // depends on 0, weight 16
    payload.extend_from_slice(&b);
    payload.extend_from_slice(&[0; 4]);
    p.send(
        HEADERS,
        END_HEADERS | END_STREAM | PADDED | PRIO,
        3,
        &payload,
    );
    assert_eq!(p.response(3).2, b"hello");

    // Self-dependency in HEADERS: the stream is reset, the connection lives on.
    let b = p.block(&[(":method", "GET"), (":scheme", "http"), (":path", "/hello")]);
    let mut payload = vec![0, 0, 0, 5, 16];
    payload.extend_from_slice(&b);
    p.send(HEADERS, END_HEADERS | END_STREAM | PRIO, 5, &payload);
    assert_eq!(p.rst(5), PROTOCOL);
    p.request(7, "GET", "/hello", true);
    assert_eq!(p.response(7).0, 200);

    // HEAD: headers only.
    p.request(9, "HEAD", "/hello", true);
    let (status, _, body, _) = p.response(9);
    assert_eq!((status, body.len()), (200, 0));

    // A response header block larger than a frame is split into CONTINUATION frames.
    p.request(11, "GET", "/huge-header", true);
    let (status, head, body, _) = p.response(11);
    assert_eq!((status, body.as_slice()), (200, &b"big header"[..]));
    assert!(head.iter().any(|(n, v)| n == "x-big" && v.len() == 40_000));
    stop(&e);
}

#[test]
fn broken_header_blocks_are_connection_errors() {
    let e = start();
    let cases: Vec<Case> = vec![
        // CONTINUATION without HEADERS.
        Box::new(|p| p.send(CONTINUATION, END_HEADERS, 1, &[0x82])),
        // Another frame in the middle of a header block.
        Box::new(|p| {
            p.send(HEADERS, 0, 1, &[0x82]);
            p.send(PING, 0, 0, &[0; 8]);
        }),
        // CONTINUATION on another stream.
        Box::new(|p| {
            p.send(HEADERS, 0, 1, &[0x82]);
            p.send(CONTINUATION, END_HEADERS, 3, &[0x84]);
        }),
        // Even (server-initiated) stream id, and stream 0.
        Box::new(|p| p.request(2, "GET", "/hello", true)),
        Box::new(|p| p.request(0, "GET", "/hello", true)),
        // Stream ids must increase.
        Box::new(|p| {
            p.request(5, "GET", "/hello", true);
            p.request(3, "GET", "/hello", true);
        }),
        // Padding longer than the payload.
        Box::new(|p| p.send(HEADERS, END_HEADERS | PADDED, 1, &[9, 0x82])),
        // PADDED with no pad length; PRIORITY too short.
        Box::new(|p| p.send(HEADERS, END_HEADERS | PADDED, 1, &[])),
        Box::new(|p| p.send(HEADERS, END_HEADERS | PRIO, 1, &[0, 0])),
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut p = Peer::open(&e, &[]);
        case(&mut p);
        let code = p.goaway();
        assert!(
            code == PROTOCOL || code == FRAME_SIZE || code == STREAM_CLOSED,
            "case {i}: code {code}"
        );
    }
    // Undecodable HPACK.
    let mut p = Peer::open(&e, &[]);
    p.send(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &[0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert_eq!(p.goaway(), COMPRESSION);
    // A frame larger than our max frame size.
    let mut p = Peer::open(&e, &[]);
    p.send(DATA, 0, 1, &vec![0; 20_000]);
    assert_eq!(p.goaway(), FRAME_SIZE);
    // An endless header block.
    let mut p = Peer::open(&e, &[]);
    p.send(HEADERS, 0, 1, &[0x82]);
    for _ in 0..12 {
        p.send(CONTINUATION, 0, 1, &[0; 16_000]);
    }
    assert_eq!(p.goaway(), ENHANCE);
    stop(&e);
}

#[test]
fn malformed_requests_are_reset() {
    let e = start();
    let mut p = Peer::open(&e, &[]);
    let bad: Vec<Vec<(&str, &str)>> = vec![
        vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            ("Upper", "x"),
        ],
        vec![
            (":method", "GET"),
            ("x", "y"),
            (":scheme", "http"),
            (":path", "/"),
        ],
        vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":bogus", "1"),
        ],
        vec![
            (":method", "GET"),
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
        ],
        vec![(":method", "GET"), (":scheme", "http")],
        vec![(":method", "GET"), (":path", "/")],
        vec![(":method", "GET"), (":scheme", "http"), (":path", "")],
        vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            ("connection", "x"),
        ],
        vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            ("te", "gzip"),
        ],
        vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            ("content-length", "abc"),
        ],
    ];
    let mut sid = 1;
    for h in &bad {
        let b = p.block(h);
        p.send(HEADERS, END_HEADERS | END_STREAM, sid, &b);
        assert_eq!(p.rst(sid), PROTOCOL, "headers {h:?}");
        sid += 2;
    }
    // END_STREAM on the headers but a non-zero content-length.
    let b = p.block(&[
        (":method", "POST"),
        (":scheme", "http"),
        (":path", "/echo"),
        ("content-length", "5"),
    ]);
    p.send(HEADERS, END_HEADERS | END_STREAM, sid, &b);
    assert_eq!(p.rst(sid), PROTOCOL);
    sid += 2;
    // Body longer, then shorter, than content-length.
    for (data, code) in [(&b"123456"[..], PROTOCOL), (&b"12"[..], PROTOCOL)] {
        let b = p.block(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/echo"),
            ("content-length", "5"),
        ]);
        p.send(HEADERS, END_HEADERS, sid, &b);
        p.send(DATA, END_STREAM, sid, data);
        assert_eq!(p.rst(sid), code);
        sid += 2;
    }
    // Still usable.
    p.request(sid, "GET", "/hello", true);
    assert_eq!(p.response(sid).0, 200);
    stop(&e);
}

#[test]
fn data_frames_padding_closed_streams_and_trailers() {
    let e = start();
    let mut p = Peer::open(&e, &[]);
    // Padded DATA: the padding is stripped.
    p.request(1, "POST", "/echo", false);
    let mut d = vec![3u8];
    d.extend_from_slice(b"abc");
    d.extend_from_slice(&[0; 3]);
    p.send(DATA, PADDED, 1, &d);
    p.send(DATA, END_STREAM, 1, b"def");
    assert_eq!(p.response(1).2, b"abcdef");
    // DATA on a half-closed (remote) stream, and on a stream already done.
    p.request(3, "GET", "/slow", true);
    p.send(DATA, 0, 3, b"late");
    assert_eq!(p.rst(3), STREAM_CLOSED);
    p.send(DATA, 0, 1, b"late");
    assert_eq!(p.rst(1), STREAM_CLOSED);

    // Trailers on a streamed request body.
    p.request(5, "POST", "/sum", false);
    p.send(DATA, 0, 5, &[1; 100]);
    let tr = p.block(&[("x-trailer", "t1")]);
    p.send(HEADERS, END_HEADERS | END_STREAM, 5, &tr);
    assert_eq!(p.response(5).2, b"100 t1");
    // Trailers on a buffered request body.
    p.request(7, "POST", "/echo", false);
    p.send(DATA, 0, 7, b"xyz");
    let tr = p.block(&[("x-trailer", "t2")]);
    p.send(HEADERS, END_HEADERS | END_STREAM, 7, &tr);
    assert_eq!(p.response(7).2, b"xyz");
    // Trailers without END_STREAM, or with a pseudo-header, reset the stream.
    p.request(9, "POST", "/echo", false);
    let tr = p.block(&[("x-trailer", "t3")]);
    p.send(HEADERS, END_HEADERS, 9, &tr);
    assert_eq!(p.rst(9), PROTOCOL);
    p.request(11, "POST", "/echo", false);
    let tr = p.block(&[(":status", "200")]);
    p.send(HEADERS, END_HEADERS | END_STREAM, 11, &tr);
    assert_eq!(p.rst(11), PROTOCOL);
    // A streamed response ends with trailers.
    p.request(13, "GET", "/stream", true);
    let (status, _, body, trailers) = p.response(13);
    assert_eq!((status, body.len()), (200, 4000));
    assert!(trailers.iter().any(|(n, v)| n == "x-done" && v == "yes"));

    // DATA on stream 0 or an idle stream is a connection error.
    p.send(DATA, 0, 0, b"x");
    assert_eq!(p.goaway(), PROTOCOL);
    let mut p = Peer::open(&e, &[]);
    p.send(DATA, 0, 99, b"x");
    assert_eq!(p.goaway(), PROTOCOL);
    let mut p = Peer::open(&e, &[]);
    p.request(1, "POST", "/echo", false);
    p.send(DATA, PADDED, 1, &[]);
    assert_eq!(p.goaway(), FRAME_SIZE);
    let mut p = Peer::open(&e, &[]);
    p.request(1, "POST", "/echo", false);
    p.send(DATA, PADDED, 1, &[5, 1]);
    assert_eq!(p.goaway(), PROTOCOL);
    stop(&e);
}

#[test]
fn limits_refuse_streams_and_oversized_bodies() {
    let e = start_with({
        let mut v = H2Config::default();
        v.max_concurrent_streams = 1;
        v.max_header_list = 200;
        v.max_body_bytes = 1000;
        v
    });
    let mut p = Peer::open(&e, &[]);
    p.request(1, "GET", "/slow", true);
    p.request(3, "GET", "/hello", true);
    assert_eq!(p.rst(3), REFUSED_STREAM);
    assert_eq!(p.response(1).2, b"slow");
    // A header list over the limit is refused.
    let big = "v".repeat(300);
    let b = p.block(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/hello"),
        ("x-big", &big),
    ]);
    p.send(HEADERS, END_HEADERS | END_STREAM, 5, &b);
    assert_eq!(p.rst(5), REFUSED_STREAM);
    // A buffered body over max_body_bytes gets 413.
    p.request(7, "POST", "/echo", false);
    p.send(DATA, 0, 7, &[0; 1500]);
    assert_eq!(p.response(7).0, 413);
    stop(&e);
}

#[test]
fn shutdown_sends_goaway_and_ignores_new_streams() {
    let e = start();
    let mut p = Peer::open(&e, &[]);
    p.request(1, "GET", "/slow", true);
    thread::sleep(Duration::from_millis(50));
    let t = thread::spawn(move || stop(&e));
    let f = p.until(|f| f.ty == GOAWAY);
    assert_eq!(
        u32::from_be_bytes(f.payload[4..8].try_into().unwrap()),
        NO_ERROR
    );
    // New streams after our GOAWAY are ignored; the in-flight one still finishes.
    p.request(3, "GET", "/hello", true);
    assert_eq!(p.response(1).2, b"slow");
    t.join().unwrap();
}
