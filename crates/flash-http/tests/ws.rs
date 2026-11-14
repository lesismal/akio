//! WebSocket over real sockets: handshake, framing, close, compression, broadcast.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use flash::{Backend, Config, Engine, Listener, UringConfig};
use flash_http::{
    Context, Router, WsOptions, serve,
    ws::{
        Message, PreparedMessage, WsConfig, WsHandler, WsSender,
        deflate::{Deflater, Inflater},
    },
};

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn start(router: Router) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve(router)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

// ---- a minimal blocking client ---------------------------------------------------------------

fn read_exact_retry(s: &mut TcpStream, buf: &mut [u8]) {
    let mut got = 0;
    while got < buf.len() {
        match s.read(&mut buf[got..]) {
            Ok(0) => panic!("eof after {got} of {} bytes", buf.len()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn handshake_request(extra: &str) -> String {
    format!(
        "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

/// Reads an HTTP response head; returns the status line and lowercase headers.
fn read_head(s: &mut TcpStream) -> (u16, Vec<(String, String)>) {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        read_exact_retry(s, &mut b);
        buf.push(b[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    (status, headers)
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Connects and completes the handshake; returns the stream and the 101 headers.
fn ws_connect(addr: SocketAddr, extra: &str) -> (TcpStream, Vec<(String, String)>) {
    let mut s = connect(addr);
    s.write_all(handshake_request(extra).as_bytes()).unwrap();
    let (status, h) = read_head(&mut s);
    assert_eq!(status, 101, "{h:?}");
    assert_eq!(
        header(&h, "sec-websocket-accept"),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    );
    (s, h)
}

fn frame_bytes(opcode: u8, fin: bool, rsv1: bool, payload: &[u8]) -> Vec<u8> {
    let mask = [0x12, 0x34, 0x56, 0x78];
    let mut f = vec![(u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n < 65_536 => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

fn send(s: &mut TcpStream, opcode: u8, fin: bool, payload: &[u8]) {
    s.write_all(&frame_bytes(opcode, fin, false, payload))
        .unwrap();
}

struct Frame {
    opcode: u8,
    rsv1: bool,
    payload: Vec<u8>,
}

fn recv(s: &mut TcpStream) -> Frame {
    let mut h = [0u8; 2];
    read_exact_retry(s, &mut h);
    assert_eq!(h[1] & 0x80, 0, "server frames are not masked");
    let len = match h[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            read_exact_retry(s, &mut b);
            u64::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            read_exact_retry(s, &mut b);
            u64::from_be_bytes(b)
        }
        n => u64::from(n),
    };
    let mut payload = vec![0; len as usize];
    read_exact_retry(s, &mut payload);
    assert!(h[0] & 0x80 != 0, "the server never fragments");
    Frame {
        opcode: h[0] & 0x0f,
        rsv1: h[0] & 0x40 != 0,
        payload,
    }
}

fn expect_eof(s: &mut TcpStream) {
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b) {
            Ok(0) => return,
            Ok(_) => panic!("unexpected data before EOF"),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("expected EOF: {e}"),
        }
    }
}

fn close_code(f: &Frame) -> u16 {
    assert_eq!(f.opcode, 8, "expected a close frame");
    u16::from_be_bytes([f.payload[0], f.payload[1]])
}

// ---- handlers --------------------------------------------------------------------------------

#[derive(Default)]
struct Seen {
    opened: Mutex<u32>,
    closed: Mutex<Vec<(Option<u16>, String)>>,
    pongs: Mutex<Vec<Vec<u8>>>,
    senders: Mutex<Vec<WsSender>>,
}

struct Echo(Arc<Seen>);

impl WsHandler for Echo {
    fn on_open(&mut self, ws: &WsSender) {
        *self.0.opened.lock().unwrap() += 1;
        self.0.senders.lock().unwrap().push(ws.clone());
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
    fn on_pong(&mut self, _ws: &WsSender, p: &[u8]) {
        self.0.pongs.lock().unwrap().push(p.to_vec());
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        self.0
            .closed
            .lock()
            .unwrap()
            .push((code, reason.to_owned()));
    }
}

fn echo_app(seen: Arc<Seen>, opts: WsOptions) -> Router {
    Router::new()
        .get("/ws", move |ctx: &mut Context| {
            ctx.upgrade_websocket(Echo(seen.clone()), &opts);
        })
        .get("/plain", |ctx: &mut Context| ctx.text(200, "plain http"))
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

// ---- tests -----------------------------------------------------------------------------------

#[test]
fn echo_text_and_binary_of_every_size_class() {
    let e = start(echo_app(Arc::default(), WsOptions::default()));
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 1 << 20] {
        let bin: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        send(&mut s, 2, true, &bin);
        let f = recv(&mut s);
        assert_eq!((f.opcode, f.payload.len()), (2, len));
        assert!(f.payload == bin, "binary {len}");
        let text = "é€".repeat(len / 5);
        send(&mut s, 1, true, text.as_bytes());
        let f = recv(&mut s);
        assert_eq!(f.opcode, 1);
        assert!(f.payload == text.as_bytes(), "text {len}");
    }
    stop(&e);
}

#[test]
fn ping_pong_fragmentation_and_data_right_behind_the_handshake() {
    let seen = Arc::new(Seen::default());
    let e = start(echo_app(seen.clone(), WsOptions::default()));
    let addr = e.local_addrs()[0];
    // A frame sent in the same write as the upgrade request must not be lost.
    let mut s = connect(addr);
    let mut first = handshake_request("").into_bytes();
    first.extend(frame_bytes(1, true, false, b"early"));
    s.write_all(&first).unwrap();
    let (status, _) = read_head(&mut s);
    assert_eq!(status, 101);
    let f = recv(&mut s);
    assert_eq!((f.opcode, f.payload.as_slice()), (1, &b"early"[..]));

    // Ping is answered with a pong carrying the same payload.
    send(&mut s, 9, true, b"are you there");
    let f = recv(&mut s);
    assert_eq!(
        (f.opcode, f.payload.as_slice()),
        (10, &b"are you there"[..])
    );
    // A fragmented message with a ping in the middle.
    send(&mut s, 1, false, b"Hel");
    send(&mut s, 9, true, b"mid");
    send(&mut s, 0, false, b"lo ");
    send(&mut s, 0, true, b"world");
    assert_eq!(recv(&mut s).opcode, 10);
    let f = recv(&mut s);
    assert_eq!(f.payload, b"Hello world");
    // Server-initiated ping reaches on_pong.
    seen.senders.lock().unwrap()[0].ping(b"s-ping").unwrap();
    let f = recv(&mut s);
    assert_eq!((f.opcode, f.payload.as_slice()), (9, &b"s-ping"[..]));
    send(&mut s, 10, true, b"s-ping");
    wait_for("pong", || !seen.pongs.lock().unwrap().is_empty());
    assert_eq!(seen.pongs.lock().unwrap()[0], b"s-ping");
    stop(&e);
}

#[test]
fn close_handshake_both_directions() {
    let seen = Arc::new(Seen::default());
    let e = start(echo_app(seen.clone(), WsOptions::default()));
    let addr = e.local_addrs()[0];
    // Client closes: the server echoes the code and ends the connection.
    let (mut s, _) = ws_connect(addr, "");
    let mut p = 1000u16.to_be_bytes().to_vec();
    p.extend_from_slice(b"bye");
    send(&mut s, 8, true, &p);
    let f = recv(&mut s);
    assert_eq!(close_code(&f), 1000);
    expect_eof(&mut s);
    wait_for("on_close", || !seen.closed.lock().unwrap().is_empty());
    assert_eq!(
        seen.closed.lock().unwrap()[0],
        (Some(1000), "bye".to_string())
    );

    // Server closes (from another thread).
    let (mut s2, _) = ws_connect(addr, "");
    wait_for("second open", || seen.senders.lock().unwrap().len() == 2);
    let sender = seen.senders.lock().unwrap()[1].clone();
    thread::spawn(move || sender.close(1001, "going away"));
    let f = recv(&mut s2);
    assert_eq!(close_code(&f), 1001);
    assert_eq!(&f.payload[2..], b"going away");
    expect_eof(&mut s2);

    // An abrupt TCP drop reports 1006.
    let (s3, _) = ws_connect(addr, "");
    drop(s3);
    wait_for("1006", || {
        seen.closed
            .lock()
            .unwrap()
            .iter()
            .any(|(c, _)| *c == Some(1006))
    });
    stop(&e);
}

#[test]
fn protocol_errors_close_with_the_right_status() {
    let opts = WsOptions {
        config: WsConfig {
            max_message_bytes: 1000,
            ..WsConfig::default()
        },
        ..WsOptions::default()
    };
    let e = start(echo_app(Arc::default(), opts));
    let addr = e.local_addrs()[0];
    let expect = |raw: Vec<u8>, code: u16| {
        let (mut s, _) = ws_connect(addr, "");
        s.write_all(&raw).unwrap();
        let f = recv(&mut s);
        assert_eq!(close_code(&f), code);
        expect_eof(&mut s);
    };
    // Unmasked client frame.
    expect(vec![0x81, 0x02, b'h', b'i'], 1002);
    // Reserved bit without negotiation, unknown opcode.
    expect(frame_bytes(1, true, true, b"x"), 1002);
    expect(frame_bytes(3, true, false, b"x"), 1002);
    // Invalid UTF-8 (fails on the first fragment, before the message ends).
    expect(frame_bytes(1, false, false, &[0x66, 0xff]), 1007);
    // Message too big.
    expect(frame_bytes(2, true, false, &[0; 1001]), 1009);
    // Oversized control frame.
    expect(frame_bytes(9, true, false, &[0; 126]), 1002);
    stop(&e);
}

#[test]
fn handshake_validation_and_subprotocols() {
    let seen = Arc::new(Seen::default());
    let opts = WsOptions {
        protocols: vec!["chat".into(), "v2.json".into()],
        origin_allowed: Some(|o| o == "https://good.example"),
        ..WsOptions::default()
    };
    let e = start(echo_app(seen, opts));
    let addr = e.local_addrs()[0];

    // Selected subprotocol, allowed origin.
    let (s, h) = ws_connect(
        addr,
        "Origin: https://good.example\r\nSec-WebSocket-Protocol: mqtt, v2.json, chat\r\n",
    );
    assert_eq!(header(&h, "sec-websocket-protocol"), Some("v2.json"));
    drop(s);
    // No Origin (non-browser client) is allowed.
    assert!(header(&ws_connect(addr, "").1, "sec-websocket-protocol").is_none());

    let bad = |raw: String, status: u16| -> (TcpStream, Vec<(String, String)>) {
        let mut s = connect(addr);
        s.write_all(raw.as_bytes()).unwrap();
        let (st, h) = read_head(&mut s);
        assert_eq!(st, status, "{raw:?}");
        let mut body = vec![0u8; header(&h, "content-length").map_or(0, |v| v.parse().unwrap())];
        read_exact_retry(&mut s, &mut body);
        (s, h)
    };
    // Wrong origin.
    bad(handshake_request("Origin: https://evil.example\r\n"), 403);
    // Wrong version: 426 with the supported one.
    let (_, h) = bad(
        handshake_request("").replace("Version: 13", "Version: 8"),
        426,
    );
    assert_eq!(header(&h, "sec-websocket-version"), Some("13"));
    // Missing / malformed key.
    bad(
        handshake_request("").replace("dGhlIHNhbXBsZSBub25jZQ==", "short"),
        400,
    );
    // Not an upgrade request at all.
    bad("GET /ws HTTP/1.1\r\nHost: x\r\n\r\n".into(), 400);
    // POST is not routed to the upgrade handler at all (405 from the router).
    bad(handshake_request("").replace("GET /ws", "POST /ws"), 405);
    // A refused handshake leaves the connection usable for HTTP.
    let (mut s, _) = bad(handshake_request("Origin: https://evil.example\r\n"), 403);
    s.write_all(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (st, _) = read_head(&mut s);
    assert_eq!(st, 200);
    stop(&e);
}

#[test]
fn permessage_deflate_roundtrip_with_context_takeover() {
    let e = start(echo_app(Arc::default(), WsOptions::default()));
    let addr = e.local_addrs()[0];
    let (mut s, h) = ws_connect(
        addr,
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
    );
    assert_eq!(
        header(&h, "sec-websocket-extensions"),
        Some("permessage-deflate")
    );
    let mut deflater = Deflater::new(false, 15);
    let mut inflater = Inflater::new(false);
    let msgs: Vec<String> = vec![
        "hello hello hello hello hello hello ".repeat(20),
        "x".repeat(50_000),
        "short".into(),
        "hello hello hello hello hello hello ".repeat(20),
    ];
    for m in &msgs {
        let payload = deflater.deflate(m.as_bytes());
        s.write_all(&frame_bytes(1, true, true, &payload)).unwrap();
        let f = recv(&mut s);
        assert_eq!(f.opcode, 1);
        let body = if f.rsv1 {
            inflater.inflate(&f.payload, 1 << 20).unwrap()
        } else {
            f.payload
        };
        assert_eq!(body, m.as_bytes());
        if m.len() >= 128 {
            assert!(f.rsv1, "large replies are compressed");
        } else {
            assert!(!f.rsv1, "below the threshold they are not");
        }
    }
    // Uncompressed client messages still work when compression is negotiated.
    send(&mut s, 1, true, b"plain");
    assert_eq!(recv(&mut s).payload, b"plain");
    stop(&e);
}

#[test]
fn permessage_deflate_is_only_used_when_asked_for_and_enabled() {
    let off = WsOptions {
        config: WsConfig {
            permessage_deflate: false,
            ..WsConfig::default()
        },
        ..WsOptions::default()
    };
    let e = start(echo_app(Arc::default(), off));
    let (_, h) = ws_connect(
        e.local_addrs()[0],
        "Sec-WebSocket-Extensions: permessage-deflate\r\n",
    );
    assert!(header(&h, "sec-websocket-extensions").is_none());
    stop(&e);
}

#[test]
fn broadcast_with_a_prepared_message() {
    let seen = Arc::new(Seen::default());
    let e = start(echo_app(seen.clone(), WsOptions::default()));
    let addr = e.local_addrs()[0];
    let mut clients: Vec<TcpStream> = (0..20).map(|_| ws_connect(addr, "").0).collect();
    wait_for("20 opened", || seen.senders.lock().unwrap().len() == 20);
    let msg = PreparedMessage::text("breaking news");
    for s in seen.senders.lock().unwrap().iter() {
        s.send_prepared(&msg).unwrap();
    }
    for c in &mut clients {
        let f = recv(c);
        assert_eq!((f.opcode, f.payload.as_slice()), (1, &b"breaking news"[..]));
    }
    stop(&e);
}

#[test]
fn sends_from_many_threads_never_interleave_frames() {
    let seen = Arc::new(Seen::default());
    let e = start(echo_app(seen.clone(), WsOptions::default()));
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    wait_for("open", || !seen.senders.lock().unwrap().is_empty());
    let sender = seen.senders.lock().unwrap()[0].clone();
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let sender = sender.clone();
            thread::spawn(move || {
                for i in 0..200u32 {
                    let body = vec![t; 100 + (i % 50) as usize];
                    sender.send_binary(&body).unwrap();
                }
            })
        })
        .collect();
    let mut per_thread = [0u32; 4];
    for _ in 0..800 {
        let f = recv(&mut s);
        let t = f.payload[0];
        assert!(
            f.payload.iter().all(|b| *b == t),
            "a frame mixed two senders"
        );
        per_thread[t as usize] += 1;
    }
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(per_thread, [200; 4]);
    stop(&e);
}
