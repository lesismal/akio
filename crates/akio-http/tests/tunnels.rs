//! Tunnels a proxy builds (ADR-113): the HTTP/1 client handing a connection over on `101
//! Switching Protocols` (`ResponseHandler::on_upgrade`), and an HTTP/2 extended CONNECT answered
//! with a streamed `2xx`, whose halves then close separately.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, H2Config, Headers, HttpConfig, Router, Streaming,
    client::{
        CancelToken, Client, ClientError, ClientRequest, ResponseBody, ResponseHandler,
        ResponseHead,
    },
    hpack::{Decoder, Encoder},
    raw::{RawConn, RawHandler},
    serve_with,
};

fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

const WAIT: Duration = Duration::from_secs(10);

/// The server side of an upgrade: answers `101`, then `hello`, then echoes; `bye` ends it.
struct Switch {
    /// Answer `101` whatever the request asked.
    ask: bool,
}

impl RawHandler for Switch {
    fn on_open(&mut self, conn: &RawConn) {
        if self.ask {
            let _ = conn.send(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nhello",
            );
        }
    }
    fn on_data(&mut self, conn: &RawConn, data: &[u8]) {
        if data == b"bye" {
            let _ = conn.send(b"bye");
            conn.close_after_send();
        } else {
            let _ = conn.send_owned([b"echo:".as_slice(), data].concat());
        }
    }
}

/// Holds an upgrade request without answering.
struct Mute;

impl RawHandler for Mute {
    fn on_data(&mut self, _conn: &RawConn, _data: &[u8]) {}
}

/// What the HTTP/2 tunnel handlers saw.
type Seen = Arc<Mutex<mpsc::Sender<String>>>;

fn app(seen: Seen) -> Router {
    let seen2 = seen.clone();
    Router::new()
        .fallback(Streaming(move |ctx: &mut Context| {
            // A CONNECT (RFC 9113 §8.5, A134): its target is the authority; answered with a
            // streamed `200` whose first bytes name it, then the stream's bytes echoed back.
            if *ctx.method() != akio_http::Method::Connect {
                return ctx.text(404, "no route");
            }
            let target = ctx.req().target.clone();
            let _ = seen2.lock().unwrap().send(format!("connect {target}"));
            let out = Arc::new(Mutex::new(ctx.stream_response(200, Headers::new())));
            if let Some(s) = out.lock().unwrap().as_ref() {
                let _ = s.write(format!("to {target};").as_bytes());
            }
            let seen = seen2.clone();
            ctx.on_body(move |_ctx, ev: BodyEvent<'_>| {
                let mut out = out.lock().unwrap();
                match ev {
                    BodyEvent::Chunk(b) => {
                        if let Some(s) = out.as_ref() {
                            let _ = s.write(b);
                        }
                    }
                    BodyEvent::End(_) => {
                        if let Some(s) = out.take() {
                            s.finish();
                        }
                        let _ = seen.lock().unwrap().send("end".into());
                    }
                    BodyEvent::TooLarge => {}
                }
            });
        }))
        .get("/up", |ctx: &mut Context| {
            let asked = ctx.header("upgrade") == Some("echo")
                && ctx
                    .header("connection")
                    .is_some_and(|v| v.eq_ignore_ascii_case("upgrade"));
            if asked {
                assert!(ctx.upgrade_raw(Switch { ask: true }));
            } else {
                ctx.text(400, "no upgrade asked");
            }
        })
        .get("/surprise", |ctx: &mut Context| {
            assert!(ctx.upgrade_raw(Switch { ask: true }));
        })
        .get("/mute", |ctx: &mut Context| {
            assert!(ctx.upgrade_raw(Mute));
        })
        .get("/refuse", |ctx: &mut Context| ctx.text(403, "no"))
        .get("/plain", |ctx: &mut Context| ctx.text(200, "plain"))
        .get(
            "/tunnel",
            Streaming(move |ctx: &mut Context| {
                // An extended CONNECT: answered with a streamed `200` (or a refusal), its
                // stream's bytes echoed back; `bye` ends our half.
                let status = if ctx.header("x-refuse").is_some() {
                    403
                } else {
                    200
                };
                let seen = seen.clone();
                let out = Arc::new(Mutex::new(ctx.stream_response(status, Headers::new())));
                ctx.on_body(move |_ctx, ev: BodyEvent<'_>| {
                    let mut out = out.lock().unwrap();
                    match ev {
                        BodyEvent::Chunk(b) if b == b"bye" => {
                            if let Some(s) = out.take() {
                                let _ = s.write(b"bye");
                                s.finish();
                            }
                        }
                        BodyEvent::Chunk(b) => match out.as_ref() {
                            Some(s) => {
                                let _ = s.write(&[b"echo:".as_slice(), b].concat());
                            }
                            None => {
                                let msg = format!("late {}", String::from_utf8_lossy(b));
                                let _ = seen.lock().unwrap().send(msg);
                            }
                        },
                        BodyEvent::End(_) => {
                            if let Some(s) = out.take() {
                                s.finish();
                            }
                            let _ = seen.lock().unwrap().send("end".into());
                        }
                        BodyEvent::TooLarge => {}
                    }
                });
            }),
        )
}

struct Server {
    e: Arc<Engine>,
    seen: mpsc::Receiver<String>,
}

fn start() -> Server {
    let (tx, seen) = mpsc::channel();
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(H2Config::default());
    let svc = serve_with(cfg, app(Arc::new(Mutex::new(tx))));
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
                    .serve(svc),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    Server { e, seen }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn url(e: &Engine, path: &str) -> String {
    format!("http://{}{path}", e.local_addrs()[0])
}

/// What the client's handlers saw.
enum Ev {
    Head(u16),
    Data(Vec<u8>),
    End,
    Error(ClientError),
    Upgraded(u16, Option<String>),
    Open(RawConn),
    Tunnel(Vec<u8>),
    Closed,
}

struct Up {
    tx: mpsc::Sender<Ev>,
    /// Take the connection over on `101`.
    take: bool,
}

impl ResponseHandler for Up {
    fn on_head(&mut self, head: ResponseHead, _body: ResponseBody) {
        let _ = self.tx.send(Ev::Head(head.status));
    }
    fn on_data(&mut self, chunk: &[u8]) {
        let _ = self.tx.send(Ev::Data(chunk.to_vec()));
    }
    fn on_end(&mut self, _trailers: &Headers) {
        let _ = self.tx.send(Ev::End);
    }
    fn on_error(&mut self, e: ClientError) {
        let _ = self.tx.send(Ev::Error(e));
    }
    fn on_upgrade(&mut self, head: &ResponseHead, _conn: &RawConn) -> Option<Box<dyn RawHandler>> {
        if !self.take {
            return None;
        }
        let up = head.headers.get("upgrade").map(str::to_owned);
        let _ = self.tx.send(Ev::Upgraded(head.status, up));
        Some(Box::new(Side(self.tx.clone())))
    }
}

/// The client's end of a tunnel.
struct Side(mpsc::Sender<Ev>);

impl RawHandler for Side {
    fn on_open(&mut self, conn: &RawConn) {
        let _ = self.0.send(Ev::Open(conn.clone()));
    }
    fn on_data(&mut self, _conn: &RawConn, data: &[u8]) {
        let _ = self.0.send(Ev::Tunnel(data.to_vec()));
    }
    fn on_close(&mut self) {
        let _ = self.0.send(Ev::Closed);
    }
}

fn next(rx: &mpsc::Receiver<Ev>) -> Ev {
    rx.recv_timeout(WAIT).expect("event in time")
}

/// Tunnel bytes until `want` came whole.
fn tunnel_bytes(rx: &mpsc::Receiver<Ev>, want: &[u8]) {
    let mut got = Vec::new();
    while got.len() < want.len() {
        match next(rx) {
            Ev::Tunnel(b) => got.extend(b),
            _ => panic!("expected tunnel bytes"),
        }
    }
    assert_eq!(got, want);
}

fn open(rx: &mpsc::Receiver<Ev>) -> RawConn {
    match next(rx) {
        Ev::Upgraded(101, Some(p)) => assert_eq!(p, "echo"),
        _ => panic!("expected the upgrade"),
    }
    match next(rx) {
        Ev::Open(c) => c,
        _ => panic!("expected the tunnel to open"),
    }
}

#[test]
fn a_101_hands_the_connection_over() {
    let srv = start();
    let client = Client::new(srv.e.clone());
    let (tx, rx) = mpsc::channel();
    // The request's timeout and token end with the switch: the tunnel outlives both.
    let token = CancelToken::new();
    let req = ClientRequest::get(&url(&srv.e, "/up"))
        .upgrade("echo")
        .timeout(Duration::from_millis(300))
        .cancel_with(&token);
    client.request_with(req, Up { tx, take: true });
    let conn = open(&rx);
    // The bytes the server sent right after its head.
    tunnel_bytes(&rx, b"hello");
    token.cancel();
    thread::sleep(Duration::from_millis(500));
    conn.send(b"ping").unwrap();
    tunnel_bytes(&rx, b"echo:ping");
    conn.send(b"bye").unwrap();
    tunnel_bytes(&rx, b"bye");
    assert!(matches!(next(&rx), Ev::Closed));
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    stop(&srv.e);
}

#[test]
fn answers_that_do_not_switch_are_responses() {
    let srv = start();
    let client = Client::new(srv.e.clone());

    // A refusal: an ordinary response.
    let (tx, rx) = mpsc::channel();
    let req = ClientRequest::get(&url(&srv.e, "/refuse")).upgrade("echo");
    client.request_with(req, Up { tx, take: true });
    assert!(matches!(next(&rx), Ev::Head(403)));
    assert!(matches!(next(&rx), Ev::Data(b) if b == b"no"));
    assert!(matches!(next(&rx), Ev::End));

    // A handler that does not take the connection: the 101 as a response without a body.
    let (tx, rx) = mpsc::channel();
    let req = ClientRequest::get(&url(&srv.e, "/up")).upgrade("echo");
    client.request_with(req, Up { tx, take: false });
    assert!(matches!(next(&rx), Ev::Head(101)));
    assert!(matches!(next(&rx), Ev::End));

    // A 101 to a request that asked for no upgrade fails it.
    let (tx, rx) = mpsc::channel();
    let req = ClientRequest::get(&url(&srv.e, "/surprise"));
    client.request_with(req, Up { tx, take: true });
    assert!(matches!(next(&rx), Ev::Error(ClientError::Protocol(_))));

    // A whole response: the 101 is returned and its connection closed, not pooled; the next
    // request goes out on another.
    let (tx, rx) = mpsc::channel();
    let req = ClientRequest::get(&url(&srv.e, "/up")).upgrade("echo");
    client.request(req, move |r| {
        let _ = tx.send(r.map(|r| r.status));
    });
    assert_eq!(rx.recv_timeout(WAIT).unwrap().unwrap(), 101);
    let (tx, rx) = mpsc::channel();
    client.request(ClientRequest::get(&url(&srv.e, "/plain")), move |r| {
        let _ = tx.send(r.map(|r| (r.status, r.body)));
    });
    assert_eq!(
        rx.recv_timeout(WAIT).unwrap().unwrap(),
        (200, b"plain".to_vec())
    );
    stop(&srv.e);
}

#[test]
fn an_unanswered_upgrade_times_out() {
    let srv = start();
    let client = Client::new(srv.e.clone());
    let (tx, rx) = mpsc::channel();
    let req = ClientRequest::get(&url(&srv.e, "/mute"))
        .upgrade("echo")
        .response_header_timeout(Duration::from_millis(200));
    client.request_with(req, Up { tx, take: true });
    assert!(matches!(next(&rx), Ev::Error(ClientError::HeaderTimeout)));
    stop(&srv.e);
}

// ---- HTTP/2: an extended CONNECT answered with a streamed `2xx` ------------------------------

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const NO_ERROR: u32 = 0;
const CANCEL: u32 = 8;
const PROTOCOL_ERROR: u32 = 1;

struct Frame {
    ty: u8,
    flags: u8,
    sid: u32,
    payload: Vec<u8>,
}

/// One HTTP/2 connection driven by hand.
struct Peer {
    s: TcpStream,
    enc: Encoder,
    dec: Decoder,
}

impl Peer {
    fn open(e: &Engine) -> Peer {
        let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.set_read_timeout(Some(WAIT)).unwrap();
        let mut p = Peer {
            s,
            enc: Encoder::new(),
            dec: Decoder::new(),
        };
        p.s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        p.send(SETTINGS, 0, 0, &[]);
        let f = p.read();
        assert_eq!((f.ty, f.flags), (SETTINGS, 0));
        assert!(
            f.payload.chunks_exact(6).any(|c| c == [0, 8, 0, 0, 0, 1]),
            "SETTINGS_ENABLE_CONNECT_PROTOCOL"
        );
        p.send(SETTINGS, ACK, 0, &[]);
        p
    }

    fn send(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        let mut b = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        b.push(ty);
        b.push(flags);
        b.extend_from_slice(&sid.to_be_bytes());
        b.extend_from_slice(payload);
        self.s.write_all(&b).unwrap();
    }

    fn headers(&mut self, sid: u32, fields: &[(&str, &str)], end: bool) {
        let b = self
            .enc
            .encode(fields.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
        let flags = END_HEADERS | if end { END_STREAM } else { 0 };
        self.send(HEADERS, flags, sid, &b);
    }

    /// An extended CONNECT for `/tunnel`, with `extra` fields.
    fn connect(&mut self, sid: u32, extra: &[(&str, &str)]) {
        let mut f = vec![
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", "/tunnel"),
            (":authority", "localhost"),
            ("sec-websocket-version", "13"),
        ];
        f.extend_from_slice(extra);
        self.headers(sid, &f, false);
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

    /// The next frame on `sid` that is HEADERS, DATA or RST_STREAM.
    fn on(&mut self, sid: u32) -> Frame {
        loop {
            let f = self.read();
            if f.sid == sid && matches!(f.ty, HEADERS | DATA | RST_STREAM) {
                return f;
            }
        }
    }

    /// The response status on `sid`.
    fn status(&mut self, sid: u32) -> String {
        let f = self.on(sid);
        assert_eq!(f.ty, HEADERS, "stream {sid}");
        assert_eq!(f.flags & END_STREAM, 0, "the head ends the stream");
        let list = self.dec.decode(&f.payload).unwrap();
        let (_, v) = list.into_iter().find(|(n, _)| n == b":status").unwrap();
        String::from_utf8(v).unwrap()
    }

    /// DATA on `sid` until `want` came; whether END_STREAM came with it.
    fn data(&mut self, sid: u32, want: &[u8]) -> bool {
        let mut got = Vec::new();
        loop {
            let f = self.on(sid);
            assert_eq!(f.ty, DATA, "stream {sid} reset");
            got.extend_from_slice(&f.payload);
            let end = f.flags & END_STREAM != 0;
            if got.len() >= want.len() || end {
                assert_eq!(got, want);
                return end;
            }
        }
    }

    /// END_STREAM on `sid` (an empty DATA frame unless it came already).
    fn ended(&mut self, sid: u32) {
        let f = self.on(sid);
        assert_eq!(
            (f.ty, f.flags & END_STREAM),
            (DATA, END_STREAM),
            "stream {sid}"
        );
    }

    fn rst(&mut self, sid: u32) -> u32 {
        let f = self.on(sid);
        assert_eq!(f.ty, RST_STREAM, "stream {sid}");
        u32::from_be_bytes(f.payload[..4].try_into().unwrap())
    }
}

fn seen(srv: &Server) -> String {
    srv.seen.recv_timeout(WAIT).unwrap()
}

#[test]
fn h2_a_streamed_2xx_to_an_extended_connect_is_a_tunnel() {
    let srv = start();
    let mut p = Peer::open(&srv.e);

    // The peer ends its half first: ours ends after, and nothing resets the stream.
    p.connect(1, &[]);
    assert_eq!(p.status(1), "200");
    p.send(DATA, 0, 1, b"abc");
    assert!(!p.data(1, b"echo:abc"));
    p.send(DATA, END_STREAM, 1, &[]);
    assert_eq!(seen(&srv), "end");
    p.ended(1);

    // Ours ends first: the peer's half stays open and its bytes still arrive, until it ends
    // its own; no reset.
    p.connect(3, &[]);
    assert_eq!(p.status(3), "200");
    p.send(DATA, 0, 3, b"bye");
    if !p.data(3, b"bye") {
        p.ended(3);
    }
    p.send(DATA, 0, 3, b"late");
    assert_eq!(seen(&srv), "late late");
    p.send(DATA, END_STREAM, 3, &[]);
    assert_eq!(seen(&srv), "end");
    // A request after it: no RST_STREAM for stream 3 comes before its answer.
    p.headers(
        5,
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/plain"),
            (":authority", "localhost"),
        ],
        true,
    );
    loop {
        let f = p.read();
        assert!(!(f.sid == 3 && f.ty == RST_STREAM), "stream 3 reset");
        if f.ty == HEADERS {
            // Decoded, to keep the HPACK table in step.
            p.dec.decode(&f.payload).unwrap();
        }
        if f.sid == 5 && f.ty == DATA && f.flags & END_STREAM != 0 {
            break;
        }
    }

    // A peer that never ends its half: the stream is reset (`CANCEL`) after the linger.
    p.connect(7, &[]);
    assert_eq!(p.status(7), "200");
    p.send(DATA, 0, 7, b"bye");
    if !p.data(7, b"bye") {
        p.ended(7);
    }
    assert_eq!(p.rst(7), CANCEL);

    // A refusal is no tunnel: answered before the peer ended, the stream is reset (`NO_ERROR`).
    p.connect(9, &[("x-refuse", "1")]);
    assert_eq!(p.status(9), "403");
    p.send(DATA, 0, 9, b"bye");
    if !p.data(9, b"bye") {
        p.ended(9);
    }
    assert_eq!(p.rst(9), NO_ERROR);
    stop(&srv.e);
}

/// A CONNECT on an HTTP/2 stream (RFC 9113 §8.5, A134): `:method` and `:authority` alone, the
/// target the authority; dispatched at once (before any DATA), its streamed `200` a tunnel
/// whose halves close separately. One with `:scheme` or `:path`, or without `:authority`, is
/// malformed.
#[test]
fn h2_a_connect_is_dispatched_at_once_and_a_streamed_2xx_is_a_tunnel() {
    let srv = start();
    let mut p = Peer::open(&srv.e);
    p.headers(
        1,
        &[(":method", "CONNECT"), (":authority", "example.com:443")],
        false,
    );
    assert_eq!(seen(&srv), "connect example.com:443");
    assert_eq!(p.status(1), "200");
    assert!(!p.data(1, b"to example.com:443;"));
    p.send(DATA, 0, 1, b"ping");
    assert!(!p.data(1, b"ping"));
    p.send(DATA, END_STREAM, 1, &[]);
    assert_eq!(seen(&srv), "end");
    p.ended(1);

    for (sid, bad) in [
        (
            3,
            &[
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":authority", "example.com:443"),
            ][..],
        ),
        (
            5,
            &[
                (":method", "CONNECT"),
                (":path", "/"),
                (":authority", "example.com:443"),
            ][..],
        ),
        (7, &[(":method", "CONNECT")][..]),
    ] {
        p.headers(sid, bad, false);
        assert_eq!(p.rst(sid), PROTOCOL_ERROR, "stream {sid}");
    }
    stop(&srv.e);
}
