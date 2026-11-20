//! WebSocket over HTTP/2 (RFC 8441): our client against our server (h2c and TLS, several
//! WebSockets and plain requests on one connection, flow control, backpressure, refusals,
//! shutdown), and a hand-driven peer for the frames (SETTINGS, the extended CONNECT, malformed
//! ones, permessage-deflate, close and RST_STREAM mapping).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use only::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use only_http::{
    Context, H2Config, HttpConfig, Router, WsOptions,
    client::{ClientError, ClientRequest},
    h2client::{H2Client, H2Options, H2WsOptions},
    hpack::{Decoder, Encoder},
    serve_with,
    ws::{Message, WsConfig, WsHandler, WsSender},
};

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

const WAIT: Duration = Duration::from_secs(10);

/// What a WebSocket handler saw.
#[derive(Debug, PartialEq)]
enum Ev {
    Msg(Message),
    Close(Option<u16>),
}

/// Echoes every message; reports its close.
struct Echo(mpsc::Sender<Ev>);

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.0.send(Ev::Close(code));
    }
}

/// Records what arrives (the client side).
struct Rec(mpsc::Sender<Ev>);

impl WsHandler for Rec {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        let _ = self.0.send(Ev::Msg(msg));
    }
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.0.send(Ev::Close(code));
    }
}

/// Sends until a send fails, then reports how many went, the error and what is queued.
struct Flood(mpsc::Sender<(usize, only::Error, usize)>);

impl WsHandler for Flood {
    fn on_open(&mut self, ws: &WsSender) {
        let chunk = vec![7u8; 64 << 10];
        let mut n = 0;
        let e = loop {
            match ws.send_binary(&chunk) {
                Ok(()) => n += 1,
                Err(e) => break e,
            }
            assert!(n <= 10_000, "never pushed back");
        };
        let _ = self.0.send((n, e, ws.queued_bytes()));
    }
    fn on_message(&mut self, _ws: &WsSender, _msg: Message) {}
}

/// Closes as soon as it opens.
struct Bye(mpsc::Sender<Ev>);

impl WsHandler for Bye {
    fn on_open(&mut self, ws: &WsSender) {
        ws.close(1001, "bye");
    }
    fn on_message(&mut self, _ws: &WsSender, _msg: Message) {}
    fn on_close(&mut self, code: Option<u16>, _reason: &str) {
        let _ = self.0.send(Ev::Close(code));
    }
}

struct Server {
    e: Arc<Engine>,
    /// Closes seen by the server's handlers.
    closed: mpsc::Receiver<Ev>,
    flood: mpsc::Receiver<(usize, only::Error, usize)>,
}

fn app(closed: mpsc::Sender<Ev>, flood: mpsc::Sender<(usize, only::Error, usize)>) -> Router {
    let (c1, c2) = (Mutex::new(closed.clone()), Mutex::new(closed));
    let flood = Mutex::new(flood);
    let opts = |deflate: bool| {
        let mut o = WsOptions::default();
        o.config = {
            let mut v = WsConfig::default();
            v.permessage_deflate = deflate;
            v
        };
        o.protocols = vec!["chat".into()];
        o.origin_allowed = Some(|o: &str| o != "https://evil.example");
        o
    };
    Router::new()
        .get("/ws", move |ctx: &mut Context| {
            let tx = c1.lock().unwrap().clone();
            ctx.upgrade_websocket(Echo(tx), &opts(true));
        })
        .get("/plain-ws", move |ctx: &mut Context| {
            let tx = c2.lock().unwrap().clone();
            ctx.upgrade_websocket(Bye(tx), &opts(false));
        })
        .get("/flood", move |ctx: &mut Context| {
            let tx = flood.lock().unwrap().clone();
            ctx.upgrade_websocket(Flood(tx), &opts(false));
        })
        .get("/forbidden", |ctx: &mut Context| ctx.text(403, "no"))
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello h2"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
}

fn start_with(h2: H2Config, tls: Option<only::tls::ServerConfig>) -> Server {
    let (ctx, closed) = mpsc::channel();
    let (ftx, flood) = mpsc::channel();
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some(h2);
    let svc = serve_with(cfg, app(ctx, ftx));
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(backend())
        .threads(2);
    let l = match tls {
        Some(t) => l.serve(Tls::server(t, svc)),
        None => l.serve(svc),
    };
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_secs(3);
                v
            })
            .listen(l)
            .client_threads(2)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    Server { e, closed, flood }
}

fn start() -> Server {
    start_with(H2Config::default(), None)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1] ^ seed)
        .collect()
}

fn next(rx: &mpsc::Receiver<Ev>) -> Ev {
    rx.recv_timeout(WAIT).expect("event in time")
}

fn ws_opts() -> H2WsOptions {
    let mut o = H2WsOptions::default();
    o.protocols = vec!["v2".into(), "chat".into()];
    o
}

/// Several WebSockets (compressed and not) and plain requests share one connection; each
/// echoes in order; each closes with its own handshake.
fn websockets_and_requests_on_one_connection(c: &H2Client, ws_base: &str, srv: &Server) {
    let base = &ws_base.replacen("ws", "http", 1);
    const N: usize = 4;
    let mut socks = Vec::new();
    for i in 0..N {
        let (tx, rx) = mpsc::channel();
        let mut o = ws_opts();
        o.config.permessage_deflate = i % 2 == 0;
        let ws = c
            .websocket_blocking(&format!("{ws_base}/ws"), &o, Rec(tx))
            .unwrap();
        assert_eq!(ws.subprotocol().as_deref(), Some("chat"));
        socks.push((ws, rx));
    }
    let plain = thread::scope(|s| {
        let h = s.spawn(|| {
            (0..20)
                .map(|i| {
                    let body = pattern(30_000 + i, i as u8);
                    let r = c
                        .send(ClientRequest::post(&format!("{base}/echo"), body.clone()))
                        .wait()
                        .unwrap();
                    usize::from(r.body == body)
                })
                .sum::<usize>()
        });
        for round in 0..5u8 {
            for (i, (ws, _)) in socks.iter().enumerate() {
                ws.send_text(&format!("m{i}-{round}")).unwrap();
                ws.send_binary(&pattern(100_000 + i, round)).unwrap();
            }
        }
        for (i, (_, rx)) in socks.iter().enumerate() {
            for round in 0..5u8 {
                assert_eq!(next(rx), Ev::Msg(Message::Text(format!("m{i}-{round}"))));
                assert_eq!(
                    next(rx),
                    Ev::Msg(Message::Binary(pattern(100_000 + i, round)))
                );
            }
        }
        h.join().unwrap()
    });
    assert_eq!(plain, 20, "plain requests answered alongside");
    for (ws, rx) in &socks {
        ws.close(1000, "done");
        assert_eq!(next(rx), Ev::Close(Some(1000)));
    }
    for _ in 0..N {
        assert_eq!(
            srv.closed.recv_timeout(WAIT).unwrap(),
            Ev::Close(Some(1000))
        );
    }
    // The connection still serves requests.
    let r = c
        .send(ClientRequest::get(&format!("{base}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello h2");
}

#[test]
fn h2c_websockets_share_a_connection_with_requests() {
    let srv = start();
    let addr = srv.e.local_addrs()[0];
    let c = H2Client::dial_blocking(&srv.e, addr, None, H2Options::default()).unwrap();
    websockets_and_requests_on_one_connection(&c, &format!("ws://{addr}"), &srv);
    stop(&srv.e);
}

#[test]
fn tls_h2_websockets_share_a_connection_with_requests() {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(cert.clone())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .alpn(["h2", "http/1.1"])
    .build()
    .unwrap();
    let srv = start_with(H2Config::default(), Some(scfg));
    let addr = srv.e.local_addrs()[0];
    let mut roots = only::tls::RootCerts::empty();
    roots.add(&only::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = only::tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["h2"])
        .build()
        .unwrap();
    let c = H2Client::dial_blocking(
        &srv.e,
        addr,
        Some((ccfg, "localhost")),
        H2Options::default(),
    )
    .unwrap();
    websockets_and_requests_on_one_connection(
        &c,
        &format!("wss://localhost:{}", addr.port()),
        &srv,
    );
    stop(&srv.e);
}

/// Small windows both ways: multi-megabyte messages cross in many window-sized pieces.
#[test]
fn flow_control_paces_large_messages_both_ways() {
    let mut h2 = H2Config::default();
    h2.initial_window = 16 << 10;
    h2.conn_window = 64 << 10;
    let srv = start_with(h2, None);
    let addr = srv.e.local_addrs()[0];
    let mut co = H2Options::default();
    co.initial_window = 16 << 10;
    co.conn_window = 65_535;
    let c = H2Client::dial_blocking(&srv.e, addr, None, co).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut o = ws_opts();
    o.config.permessage_deflate = false;
    let ws = c
        .websocket_blocking(&format!("http://{addr}/ws"), &o, Rec(tx))
        .unwrap();
    for i in 0..3u8 {
        let m = pattern((3 << 20) + i as usize, i);
        ws.send_binary(&m).unwrap();
        assert_eq!(next(&rx), Ev::Msg(Message::Binary(m)));
    }
    assert_eq!(ws.queued_bytes(), 0);
    ws.close(1000, "");
    assert_eq!(next(&rx), Ev::Close(Some(1000)));
    stop(&srv.e);
}

#[test]
fn refusals_and_disabled_extended_connect_reach_the_client() {
    let srv = start();
    let addr = srv.e.local_addrs()[0];
    let c = H2Client::dial_blocking(&srv.e, addr, None, H2Options::default()).unwrap();
    let base = format!("http://{addr}");
    let (tx, _rx) = mpsc::channel();
    for (path, status) in [("/forbidden", 403), ("/nowhere", 404)] {
        match c.websocket_blocking(&format!("{base}{path}"), &ws_opts(), Rec(tx.clone())) {
            Err(ClientError::Status(s)) => assert_eq!(s, status),
            other => panic!("{path}: {other:?}"),
        }
    }
    let mut o = ws_opts();
    o.origin = Some("https://evil.example".into());
    assert!(matches!(
        c.websocket_blocking(&format!("{base}/ws"), &o, Rec(tx.clone())),
        Err(ClientError::Status(403))
    ));
    stop(&srv.e);

    let mut h2 = H2Config::default();
    h2.enable_connect_protocol = false;
    let srv = start_with(h2, None);
    let addr = srv.e.local_addrs()[0];
    let c = H2Client::dial_blocking(&srv.e, addr, None, H2Options::default()).unwrap();
    assert!(matches!(
        c.websocket_blocking(&format!("http://{addr}/ws"), &ws_opts(), Rec(tx)),
        Err(ClientError::Protocol(_))
    ));
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello h2");
    stop(&srv.e);
}

/// The client cannot get ahead of a server that does not open its window: sends fail with
/// `Overloaded` past `max_queued_bytes`; closing then resets the stream (no close handshake is
/// possible), which the server reports as 1006.
#[test]
fn client_sends_push_back_and_close_resets_a_stuck_stream() {
    let mut h2 = H2Config::default();
    h2.initial_window = 0;
    let srv = start_with(h2, None);
    let addr = srv.e.local_addrs()[0];
    let c = H2Client::dial_blocking(&srv.e, addr, None, H2Options::default()).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut o = ws_opts();
    o.max_queued_bytes = 256 << 10;
    o.close_timeout = Duration::from_millis(200);
    o.config.permessage_deflate = false;
    let ws = c
        .websocket_blocking(&format!("http://{addr}/ws"), &o, Rec(tx))
        .unwrap();
    let chunk = vec![1u8; 32 << 10];
    let mut n = 0;
    let e = loop {
        match ws.send_binary(&chunk) {
            Ok(()) => n += 1,
            Err(e) => break e,
        }
        assert!(n < 1000, "never pushed back");
    };
    assert!(matches!(e, only::Error::Overloaded), "{e:?}");
    assert!(ws.queued_bytes() <= 256 << 10 && ws.queued_bytes() > 128 << 10);
    ws.close(1000, "");
    assert_eq!(next(&rx), Ev::Close(Some(1006)));
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1006))
    );
    // The connection is fine.
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello h2");
    stop(&srv.e);
}

#[test]
fn shutdown_closes_websockets_with_going_away() {
    let srv = start();
    let addr = srv.e.local_addrs()[0];
    // The client on an engine of its own: the server's shutdown must not stop it.
    let ce = Engine::builder().client_threads(1).build().unwrap();
    ce.start().unwrap();
    let c = H2Client::dial_blocking(&ce, addr, None, H2Options::default()).unwrap();
    let (tx, rx) = mpsc::channel();
    let ws = c
        .websocket_blocking(&format!("http://{addr}/ws"), &ws_opts(), Rec(tx))
        .unwrap();
    ws.send_text("before").unwrap();
    assert_eq!(next(&rx), Ev::Msg(Message::Text("before".into())));
    let e2 = srv.e.clone();
    let waiter = thread::spawn(move || e2.wait());
    srv.e.shutdown();
    assert_eq!(next(&rx), Ev::Close(Some(1001)));
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1001))
    );
    waiter.join().unwrap();
    stop(&ce);
}

// ---- frame level ---------------------------------------------------------------------------

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const WINDOW_UPDATE: u8 = 8;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PROTOCOL: u32 = 1;
const CANCEL: u32 = 8;

struct Frame {
    ty: u8,
    flags: u8,
    sid: u32,
    payload: Vec<u8>,
}

type Fields = Vec<(String, String)>;

/// One HTTP/2 connection driven by hand.
struct Peer {
    s: TcpStream,
    enc: Encoder,
    dec: Decoder,
    /// The server's SETTINGS.
    settings: Vec<(u16, u32)>,
}

impl Peer {
    fn open(e: &Engine, settings: &[(u16, u32)]) -> Peer {
        let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.set_read_timeout(Some(WAIT)).unwrap();
        let mut p = Peer {
            s,
            enc: Encoder::new(),
            dec: Decoder::new(),
            settings: Vec::new(),
        };
        p.s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        let mut sp = Vec::new();
        for (id, v) in settings {
            sp.extend_from_slice(&id.to_be_bytes());
            sp.extend_from_slice(&v.to_be_bytes());
        }
        p.send(SETTINGS, 0, 0, &sp);
        let f = p.read();
        assert_eq!((f.ty, f.flags), (SETTINGS, 0));
        p.settings = f
            .payload
            .chunks_exact(6)
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                )
            })
            .collect();
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

    /// An extended CONNECT for `path` with `extra` fields.
    fn connect(&mut self, sid: u32, path: &str, extra: &[(&str, &str)]) {
        let mut f = vec![
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", path),
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

    fn until(&mut self, mut pred: impl FnMut(&Frame) -> bool) -> Frame {
        loop {
            let f = self.read();
            if pred(&f) {
                return f;
            }
        }
    }

    /// The response head on `sid` (decoded), and whether it ended the stream.
    fn head(&mut self, sid: u32) -> (Fields, bool) {
        let f = self.until(|f| f.sid == sid && (f.ty == HEADERS || f.ty == RST_STREAM));
        assert_eq!(f.ty, HEADERS, "stream {sid} reset");
        assert!(f.flags & END_HEADERS != 0);
        let list = self.dec.decode(&f.payload).unwrap();
        let fields = list
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        (fields, f.flags & END_STREAM != 0)
    }

    fn rst(&mut self, sid: u32) -> u32 {
        let f = self.until(|f| f.ty == RST_STREAM && f.sid == sid);
        u32::from_be_bytes(f.payload[..4].try_into().unwrap())
    }

    /// WebSocket bytes on `sid` until `n` are there (or the stream ends): (bytes, ended).
    fn ws_bytes(&mut self, sid: u32, n: usize) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        while out.len() < n {
            let f = self.until(|f| f.sid == sid && matches!(f.ty, DATA | RST_STREAM));
            assert_eq!(f.ty, DATA, "stream {sid} reset");
            out.extend_from_slice(&f.payload);
            if f.flags & END_STREAM != 0 {
                return (out, true);
            }
        }
        (out, false)
    }
}

fn field<'a>(f: &'a Fields, name: &str) -> Option<&'a str> {
    f.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// A masked client frame.
fn masked(first: u8, payload: &[u8]) -> Vec<u8> {
    let key = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![first];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n < 65536 => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&key);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    f
}

/// Splits one unmasked server frame off `b`: (first byte, payload).
fn unframe(b: &mut Vec<u8>) -> (u8, Vec<u8>) {
    let first = b[0];
    let (len, at) = match b[1] & 0x7f {
        126 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
        127 => (
            u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize,
            10,
        ),
        n => (n as usize, 2),
    };
    assert_eq!(b[1] & 0x80, 0, "server frames are not masked");
    let p = b[at..at + len].to_vec();
    b.drain(..at + len);
    (first, p)
}

fn inflate(p: &[u8]) -> Vec<u8> {
    let mut data = p.to_vec();
    data.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out = Vec::with_capacity(1 << 16);
    flate2::Decompress::new(false)
        .decompress_vec(&data, &mut out, flate2::FlushDecompress::Sync)
        .unwrap();
    out
}

#[test]
fn frames_handshake_deflate_close_and_requests_alongside() {
    let srv = start();
    let mut p = Peer::open(&srv.e, &[]);
    assert!(
        p.settings.contains(&(8, 1)),
        "SETTINGS_ENABLE_CONNECT_PROTOCOL"
    );
    p.connect(
        1,
        "/ws",
        &[
            ("sec-websocket-protocol", "v1, chat"),
            (
                "sec-websocket-extensions",
                "permessage-deflate; client_max_window_bits",
            ),
        ],
    );
    let (head, ended) = p.head(1);
    assert!(!ended, "the stream stays open");
    assert_eq!(field(&head, ":status"), Some("200"));
    assert_eq!(field(&head, "sec-websocket-protocol"), Some("chat"));
    assert!(
        field(&head, "sec-websocket-extensions")
            .is_some_and(|v| v.starts_with("permessage-deflate"))
    );
    assert!(field(&head, "content-length").is_none());
    assert!(field(&head, "sec-websocket-accept").is_none());

    // A plain request on another stream while the WebSocket is open.
    p.headers(
        3,
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/hello"),
            (":authority", "localhost"),
        ],
        true,
    );
    let (h3, _) = p.head(3);
    assert_eq!(field(&h3, ":status"), Some("200"));

    // RFC 7692 §7.2.3.1: "Hello" compressed, sent split over two DATA frames.
    let f = masked(0xc1, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
    p.send(DATA, 0, 1, &f[..5]);
    p.send(DATA, 0, 1, &f[5..]);
    let (mut b, _) = p.ws_bytes(1, 7);
    assert_eq!(
        unframe(&mut b),
        (0x81, b"Hello".to_vec()),
        "short echo uncompressed"
    );
    // A long one comes back compressed.
    let long = "abc".repeat(200);
    p.send(DATA, 0, 1, &masked(0x81, long.as_bytes()));
    let (mut b, _) = p.ws_bytes(1, 4);
    let (first, payload) = unframe(&mut b);
    assert_eq!(first, 0xc1, "FIN | RSV1 | text");
    assert_eq!(inflate(&payload), long.as_bytes());

    // Client-initiated close: the echo, then END_STREAM; ending our half finishes it.
    p.send(DATA, 0, 1, &masked(0x88, &[0x03, 0xe8]));
    let (mut b, ended) = p.ws_bytes(1, 4);
    assert_eq!(unframe(&mut b), (0x88, vec![0x03, 0xe8]));
    let ended = ended || {
        let f = p.until(|f| f.sid == 1 && f.ty == DATA);
        f.flags & END_STREAM != 0
    };
    assert!(ended);
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1000))
    );
    p.send(DATA, END_STREAM, 1, &[]);

    // The connection goes on.
    p.headers(
        5,
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/hello"),
            (":authority", "localhost"),
        ],
        true,
    );
    let (h5, _) = p.head(5);
    assert_eq!(field(&h5, ":status"), Some("200"));
    stop(&srv.e);
}

#[test]
fn frames_reset_protocol_error_and_server_close_map_to_close_codes() {
    let srv = start();
    let mut p = Peer::open(&srv.e, &[]);

    // RST_STREAM from the peer: the server's handler hears 1006.
    p.connect(1, "/ws", &[]);
    assert_eq!(field(&p.head(1).0, ":status"), Some("200"));
    p.send(RST_STREAM, 0, 1, &CANCEL.to_be_bytes());
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1006))
    );

    // An unmasked frame is a protocol error: close 1002, then END_STREAM.
    p.connect(3, "/ws", &[]);
    assert_eq!(field(&p.head(3).0, ":status"), Some("200"));
    p.send(DATA, 0, 3, &[0x81, 0x02, b'h', b'i']);
    let (mut b, _) = p.ws_bytes(3, 4);
    let (first, payload) = unframe(&mut b);
    assert_eq!((first, &payload[..2]), (0x88, &[0x03, 0xea][..]));
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1002))
    );
    p.until(|f| f.sid == 3 && f.flags & END_STREAM != 0);
    p.send(DATA, END_STREAM, 3, &[]);

    // A server-initiated close: the close frame and END_STREAM; the peer's echo ends it.
    p.connect(5, "/plain-ws", &[]);
    assert_eq!(field(&p.head(5).0, ":status"), Some("200"));
    let (mut b, ended) = p.ws_bytes(5, 4);
    let (first, payload) = unframe(&mut b);
    assert_eq!((first, &payload[..2]), (0x88, &[0x03, 0xe9][..]));
    if !ended {
        p.until(|f| f.sid == 5 && f.flags & END_STREAM != 0);
    }
    p.send(DATA, END_STREAM, 5, &masked(0x88, &[0x03, 0xe9]));
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1001))
    );

    // END_STREAM from the peer without a close frame: 1006, and the server ends its half.
    p.connect(7, "/ws", &[]);
    assert_eq!(field(&p.head(7).0, ":status"), Some("200"));
    p.send(DATA, END_STREAM, 7, &[]);
    assert_eq!(
        srv.closed.recv_timeout(WAIT).unwrap(),
        Ev::Close(Some(1006))
    );
    p.until(|f| f.sid == 7 && f.flags & END_STREAM != 0);
    stop(&srv.e);
}

#[test]
fn frames_malformed_extended_connect_is_reset() {
    let srv = start();
    let mut p = Peer::open(&srv.e, &[]);
    let cases: [&[(&str, &str)]; 3] = [
        // :protocol on a GET.
        &[
            (":method", "GET"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", "/ws"),
            (":authority", "x"),
        ],
        // Without :authority.
        &[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", "/ws"),
        ],
        // Without :path.
        &[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":authority", "x"),
        ],
    ];
    let mut sid = 1;
    for c in cases {
        p.headers(sid, c, false);
        assert_eq!(p.rst(sid), PROTOCOL);
        sid += 2;
    }
    // Another protocol is a request the service answers (no route: 404).
    p.headers(
        sid,
        &[
            (":method", "CONNECT"),
            (":protocol", "something"),
            (":scheme", "http"),
            (":path", "/ws"),
            (":authority", "x"),
        ],
        false,
    );
    // (The path has a GET route only: 405.)
    assert_eq!(field(&p.head(sid).0, ":status"), Some("405"));
    // A version other than 13: 426.
    sid += 2;
    p.headers(
        sid,
        &[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", "/ws"),
            (":authority", "x"),
            ("sec-websocket-version", "8"),
        ],
        false,
    );
    let (h, ended) = p.head(sid);
    assert_eq!(field(&h, ":status"), Some("426"));
    let _ = ended;
    stop(&srv.e);

    // Disabled: not advertised, and :protocol is malformed.
    let mut h2 = H2Config::default();
    h2.enable_connect_protocol = false;
    let srv = start_with(h2, None);
    let mut p = Peer::open(&srv.e, &[]);
    assert!(!p.settings.iter().any(|(id, _)| *id == 8));
    p.connect(1, "/ws", &[]);
    assert_eq!(p.rst(1), PROTOCOL);
    stop(&srv.e);
}

/// A peer that does not open its window: the server's sends queue up to `max_pending_bytes`,
/// then fail with `Overloaded`; once the window opens, the queued bytes flow.
#[test]
fn frames_server_sends_push_back_until_the_window_opens() {
    let mut h2 = H2Config::default();
    h2.max_pending_bytes = 512 << 10;
    let srv = start_with(h2, None);
    let mut p = Peer::open(&srv.e, &[(4, 0)]);
    p.connect(1, "/flood", &[]);
    assert_eq!(field(&p.head(1).0, ":status"), Some("200"));
    let (n, e, queued) = srv.flood.recv_timeout(WAIT).unwrap();
    assert!(matches!(e, only::Error::Overloaded), "{e:?}");
    assert!((4..=8).contains(&n), "{n} sends before pushing back");
    assert!(queued <= 512 << 10 && queued >= n * (64 << 10), "{queued}");
    // Open the windows: everything queued arrives (64 KiB payloads take 10-byte headers).
    p.send(WINDOW_UPDATE, 0, 1, &(1u32 << 30).to_be_bytes());
    p.send(WINDOW_UPDATE, 0, 0, &(1u32 << 30).to_be_bytes());
    let want = n * ((64 << 10) + 10);
    let (b, _) = p.ws_bytes(1, want);
    assert_eq!(b.len(), want);
    p.send(RST_STREAM, 0, 1, &CANCEL.to_be_bytes());
    stop(&srv.e);
}
