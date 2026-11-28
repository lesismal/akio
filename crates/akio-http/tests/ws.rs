//! WebSocket over real sockets: handshake, framing, close, compression, broadcast.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Router, WsOptions, serve,
    ws::{
        Message, MessageRef, PreparedMessage, WsConfig, WsHandler, WsSender,
        deflate::{Deflater, Inflater},
    },
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

/// Echoes messages borrowed from the connection's buffers (`on_message_ref`), counting them.
struct RefEcho(Arc<Mutex<usize>>);

impl WsHandler for RefEcho {
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        *self.0.lock().unwrap() += 1;
        let _ = match msg {
            MessageRef::Text(t) => ws.send_text(t),
            MessageRef::Binary(b) => ws.send_binary(b),
        };
    }
}

// ---- tests -----------------------------------------------------------------------------------

#[test]
fn borrowed_handler_echoes_a_pipelined_batch_in_order() {
    let n = Arc::new(Mutex::new(0));
    let n2 = n.clone();
    let e = start(Router::new().get("/ws", move |ctx: &mut Context| {
        ctx.upgrade_websocket(RefEcho(n2.clone()), &WsOptions::default());
    }));
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    // Whole frames, a fragmented message with a ping inside and a large frame, in one write:
    // the whole-frame path and the general path take turns within one read.
    let mut batch = Vec::new();
    let mut want: Vec<(u8, Vec<u8>)> = Vec::new();
    for i in 0..64u32 {
        let t = format!("msg {i} \u{e9}");
        batch.extend(frame_bytes(1, true, false, t.as_bytes()));
        want.push((1, t.into_bytes()));
        if i % 16 == 5 {
            batch.extend(frame_bytes(1, false, false, b"frag"));
            batch.extend(frame_bytes(9, true, false, b"ping"));
            batch.extend(frame_bytes(0, true, false, b"mented"));
            want.push((10, b"ping".to_vec()));
            want.push((1, b"fragmented".to_vec()));
        }
        if i % 16 == 9 {
            let big: Vec<u8> = (0..70_000).map(|j| (j % 249) as u8).collect();
            batch.extend(frame_bytes(2, true, false, &big));
            want.push((2, big));
        }
    }
    s.write_all(&batch).unwrap();
    for (i, (op, payload)) in want.iter().enumerate() {
        let f = recv(&mut s);
        assert_eq!(f.opcode, *op, "frame {i}");
        assert!(f.payload == *payload, "frame {i}");
    }
    assert_eq!(*n.lock().unwrap(), 64 + 4 + 4);
    // Invalid UTF-8 in a whole frame still fails the connection with 1007.
    send(&mut s, 1, true, &[0xc3, 0x28]);
    assert_eq!(close_code(&recv(&mut s)), 1007);
    stop(&e);
}

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
    let mut opts = WsOptions::default();
    opts.config = {
        let mut v = WsConfig::default();
        v.max_message_bytes = 1000;
        v
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
    let mut opts = WsOptions::default();
    opts.protocols = vec!["chat".into(), "v2.json".into()];
    opts.origin_allowed = Some(|o| o == "https://good.example");
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
    let mut off = WsOptions::default();
    off.config = {
        let mut v = WsConfig::default();
        v.permessage_deflate = false;
        v
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

#[test]
fn nothing_follows_the_close_frame_when_other_threads_keep_sending() {
    // Senders on other threads race with a close from yet another thread: whatever they
    // manage to send comes whole and before the close frame, after which the stream ends.
    for round in 0..20 {
        let seen = Arc::new(Seen::default());
        let e = start(echo_app(seen.clone(), WsOptions::default()));
        let (mut s, _) = ws_connect(e.local_addrs()[0], "");
        wait_for("open", || !seen.senders.lock().unwrap().is_empty());
        let sender = seen.senders.lock().unwrap()[0].clone();
        let threads: Vec<_> = (0..3u8)
            .map(|t| {
                let sender = sender.clone();
                thread::spawn(move || {
                    let mut sent = 0u32;
                    while sender.send_binary(&[t; 40]).is_ok() {
                        sent += 1;
                    }
                    sent
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(1 + round % 3));
        sender.close(1000, "done");
        let mut got = 0u32;
        loop {
            let f = recv(&mut s);
            if f.opcode == 8 {
                assert_eq!(close_code(&f), 1000);
                break;
            }
            assert_eq!(f.opcode, 2);
            assert!(f.payload.len() == 40 && f.payload.iter().all(|b| *b == f.payload[0]));
            got += 1;
        }
        expect_eof(&mut s);
        let sent: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            got, sent,
            "round {round}: every accepted send arrived before the close"
        );
        assert!(sender.send_text("late").is_err());
        stop(&e);
    }
}

#[test]
fn compressed_messages_of_growing_size_echo_and_close_like_autobahn_12() {
    // Autobahn 12.x/13.x against the borrowed echo: per size class a fresh connection with
    // permessage-deflate, many compressible text messages (some pipelined, some one at a time,
    // some fragmented), then the close handshake.
    let n = Arc::new(Mutex::new(0));
    let n2 = n;
    let e = start(Router::new().get("/ws", move |ctx: &mut Context| {
        ctx.upgrade_websocket(RefEcho(n2.clone()), &WsOptions::default());
    }));
    let addr = e.local_addrs()[0];
    let words = [
        "alpha ",
        "beta ",
        "gamma ",
        "delta ",
        "\u{e9}t\u{e9} ",
        "\u{20ac} ",
    ];
    for (k, size) in [16usize, 64, 256, 1024, 4096, 16_384, 65_536, 131_072]
        .into_iter()
        .enumerate()
    {
        for takeover in [true, false] {
            let ext = if takeover {
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
            } else {
                "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; \
                 server_no_context_takeover\r\n"
            };
            let (mut s, _) = ws_connect(addr, ext);
            let mut deflater = Deflater::new(!takeover, 15);
            let mut inflater = Inflater::new(!takeover);
            let count = if size >= 65_536 { 20 } else { 100 };
            let msgs: Vec<String> = (0..count)
                .map(|i| {
                    let mut m = String::new();
                    let mut j = i + k;
                    while m.len() < size {
                        m.push_str(words[j % words.len()]);
                        j = (j * 7 + 3) % 1_000_003;
                    }
                    while m.len() > size {
                        m.pop();
                    }
                    m
                })
                .collect();
            // Half pipelined in one write, half one at a time; every fifth one fragmented.
            let (batch, single) = msgs.split_at(count / 2);
            let encode = |d: &mut Deflater, i: usize, m: &str| -> Vec<u8> {
                let z = d.deflate(m.as_bytes());
                if i % 5 == 3 && z.len() > 3 {
                    let mut w = frame_bytes(1, false, true, &z[..z.len() / 2]);
                    w.extend(frame_bytes(0, true, false, &z[z.len() / 2..]));
                    w
                } else {
                    frame_bytes(1, true, true, &z)
                }
            };
            let mut wire = Vec::new();
            for (i, m) in batch.iter().enumerate() {
                wire.extend(encode(&mut deflater, i, m));
            }
            s.write_all(&wire).unwrap();
            let mut check = |s: &mut TcpStream, m: &str, what: &str| {
                let f = recv(s);
                assert_eq!(f.opcode, 1, "{what}");
                let body = if f.rsv1 {
                    inflater.inflate(&f.payload, 1 << 20).unwrap()
                } else {
                    f.payload
                };
                assert!(body == m.as_bytes(), "{what}");
            };
            for (i, m) in batch.iter().enumerate() {
                check(
                    &mut s,
                    m,
                    &format!("size {size} takeover {takeover} batch {i}"),
                );
            }
            for (i, m) in single.iter().enumerate() {
                s.write_all(&encode(&mut deflater, i, m)).unwrap();
                check(
                    &mut s,
                    m,
                    &format!("size {size} takeover {takeover} single {i}"),
                );
            }
            send(&mut s, 8, true, &1000u16.to_be_bytes());
            assert_eq!(close_code(&recv(&mut s)), 1000);
            expect_eof(&mut s);
        }
    }
    stop(&e);
}

#[test]
fn compressed_messages_in_256_byte_fragments_like_autobahn_12_4_12() {
    // Autobahn 12.4.x: 1000 compressible text messages per case, compressed with context
    // takeover and split into 256-byte frames, written back to back while the echoes come back.
    let n = Arc::new(Mutex::new(0));
    let n2 = n;
    let e = start(Router::new().get("/ws", move |ctx: &mut Context| {
        ctx.upgrade_websocket(RefEcho(n2.clone()), &WsOptions::default());
    }));
    let addr = e.local_addrs()[0];
    let words = [
        "lorem ",
        "ipsum ",
        "dolor ",
        "sit ",
        "amet ",
        "consectetur ",
        "adipiscing ",
        "elit ",
        "sed ",
        "do ",
        "eiusmod ",
        "tempor ",
        "incididunt ",
        "ut ",
        "labore ",
        "et ",
    ];
    for size in [8192usize, 16_384, 32_768, 131_072] {
        let (mut s, _) = ws_connect(
            addr,
            "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
        );
        let count = 1000;
        let mut x = 0x2545_f491u32 ^ size as u32;
        let msgs: Vec<String> = (0..count)
            .map(|_| {
                let mut m = String::with_capacity(size + 16);
                while m.len() < size {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    m.push_str(words[(x % 16) as usize]);
                }
                m.truncate(size);
                m
            })
            .collect();
        let msgs = Arc::new(msgs);
        let mut w = s.try_clone().unwrap();
        let wm = msgs.clone();
        let writer = thread::spawn(move || {
            let mut deflater = Deflater::new(false, 15);
            for m in wm.iter() {
                let z = deflater.deflate(m.as_bytes());
                let pieces: Vec<&[u8]> = z.chunks(256).collect();
                let mut wire = Vec::new();
                for (k, p) in pieces.iter().enumerate() {
                    let op = u8::from(k == 0);
                    wire.extend(frame_bytes(op, k + 1 == pieces.len(), k == 0, p));
                }
                w.write_all(&wire).unwrap();
            }
        });
        let mut inflater = Inflater::new(false);
        let t0 = Instant::now();
        for (i, m) in msgs.iter().enumerate() {
            let f = recv(&mut s);
            let body = if f.rsv1 {
                inflater.inflate(&f.payload, 1 << 20).unwrap()
            } else {
                f.payload
            };
            assert!(body == m.as_bytes(), "size {size} message {i}");
        }
        writer.join().unwrap();
        eprintln!("size {size}: {:?}", t0.elapsed());
        send(&mut s, 8, true, &1000u16.to_be_bytes());
        assert_eq!(close_code(&recv(&mut s)), 1000);
    }
    stop(&e);
}

/// On "go": sends "A", has another thread send "B" (or close, on "close") and waits until that
/// returned, then sends "C". Everything happens inside one read's batch.
struct Relay;

impl WsHandler for Relay {
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        let MessageRef::Text(t) = msg else { return };
        ws.send_text("A").unwrap();
        let other = ws.clone();
        let close = t == "close";
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let r = if close {
                other.close(1000, "from another thread");
                Ok(())
            } else {
                other.send_text("B")
            };
            tx.send(r).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        let c = ws.send_text("C");
        assert_eq!(c.is_err(), close, "sends after a close fail");
    }
}

#[test]
fn another_threads_send_caused_by_the_handler_never_overtakes_it() {
    let e = start(Router::new().get("/ws", |ctx: &mut Context| {
        ctx.upgrade_websocket(Relay, &WsOptions::default());
    }));
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    for _ in 0..20 {
        send(&mut s, 1, true, b"go");
        let got: Vec<Vec<u8>> = (0..3).map(|_| recv(&mut s).payload).collect();
        // B was sent after A (the handler sent A before starting the thread): it comes after A.
        let a = got.iter().position(|p| p == b"A").unwrap();
        let b = got.iter().position(|p| p == b"B").unwrap();
        assert!(a < b, "{got:?}");
        assert!(got.iter().any(|p| p == b"C"));
    }
    // A close from another thread while the handler's output is collected: A, then the close
    // frame, then the end of the stream; C was refused.
    send(&mut s, 1, true, b"close");
    assert_eq!(recv(&mut s).payload, b"A");
    let f = recv(&mut s);
    assert_eq!(close_code(&f), 1000);
    expect_eof(&mut s);
    stop(&e);
}

// ---- akit A305: other threads' sends while the session's I/O thread is inside a read ---------

/// On "go" (and "go-close"), inside its read: hands its sender to the test and holds the read
/// until the test resumes it ("go-close" then closes from inside the read). Answers "fin" with
/// "fin".
#[derive(Clone)]
struct HoldRead {
    go: mpsc::Sender<WsSender>,
    resume: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl WsHandler for HoldRead {
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        match msg {
            MessageRef::Text(t @ ("go" | "go-close")) => {
                self.go.send(ws.clone()).unwrap();
                // A test that failed dropped the other end: the read ends then too.
                let _ = self.resume.lock().unwrap().recv();
                if t == "go-close" {
                    ws.close(1000, "bye");
                }
            }
            MessageRef::Text("fin") => {
                let _ = ws.send_text("fin");
            }
            _ => {}
        }
    }
}

/// A server whose sessions are [`HoldRead`]: their senders arrive on the receiver, and the
/// sender resumes a held read.
fn hold_read_server() -> (Engine, mpsc::Receiver<WsSender>, mpsc::Sender<()>) {
    let (go, went) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let h = HoldRead {
        go,
        resume: Arc::new(Mutex::new(resumed)),
    };
    let e = start(Router::new().get("/ws", move |ctx: &mut Context| {
        ctx.upgrade_websocket(h.clone(), &WsOptions::default());
    }));
    (e, went, resume)
}

/// Sends numbered binary messages of `len` bytes until one is refused; returns how many were
/// accepted and the refusal.
fn send_until_refused(ws: &WsSender, len: usize) -> (u32, akio::Error) {
    let mut body = vec![7u8; len];
    let mut n = 0u32;
    loop {
        body[..4].copy_from_slice(&n.to_be_bytes());
        match ws.send_binary(&body) {
            Ok(()) => n += 1,
            Err(e) => return (n, e),
        }
        assert!(n < 100_000, "never refused");
    }
}

/// Reads `n` numbered binary messages of `len` bytes, in order.
fn recv_numbered(s: &mut TcpStream, n: u32, len: usize) {
    for i in 0..n {
        let f = recv(s);
        assert_eq!(f.opcode, 2, "message {i}");
        assert_eq!(f.payload.len(), len, "message {i}");
        assert_eq!(f.payload[..4], i.to_be_bytes(), "message {i} of {n}");
    }
}

#[test]
fn late_sends_count_in_queued_bytes_and_are_bounded_by_the_connections_queue() {
    // akit A305: while the session's I/O thread is inside a read, another thread's sends wait
    // for it to end. They count in queued_bytes, on_drain waits for them to be written, they
    // are refused where the connection's max_queued_bytes is (not at a bound of their own),
    // and every accepted one arrives.
    const MAX: usize = 8 << 20;
    const LEN: usize = 60_000; // a 4-byte header
    let (e, went, resume) = hold_read_server();
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    send(&mut s, 1, true, b"go");
    let ws = went.recv_timeout(Duration::from_secs(5)).unwrap();
    ws.set_max_queued_bytes(Some(MAX)).unwrap();
    let base = ws.queued_bytes();
    let (n, refused) = send_until_refused(&ws, LEN);
    assert!(matches!(refused, akio::Error::Overloaded), "{refused:?}");
    let late = n as usize * (LEN + 4);
    assert_eq!(ws.queued_bytes(), base + late, "the late bytes count");
    // Refused only near the connection's bound: what was accepted, the next message and the
    // handler's batch (at most 64 KiB reserved) would pass it.
    assert!(late > 4 << 20, "refused at {late} bytes");
    assert!(
        base + late + (LEN + 14) + (64 << 10) > MAX,
        "refused at {late} bytes"
    );
    assert!(base + late <= MAX);
    let (drained, on_drain) = mpsc::channel();
    ws.on_drain(move || drained.send(()).unwrap());
    assert!(
        on_drain.try_recv().is_err(),
        "on_drain ran while the late bytes were held"
    );
    resume.send(()).unwrap();
    recv_numbered(&mut s, n, LEN);
    on_drain.recv_timeout(Duration::from_secs(5)).unwrap();
    send(&mut s, 1, true, b"fin");
    assert_eq!(recv(&mut s).payload, b"fin");
    assert_eq!(ws.queued_bytes(), 0);
    stop(&e);
}

#[test]
fn late_sends_go_before_a_close_from_inside_the_read() {
    // akit A305: a close from inside the read first sends what other threads sent meanwhile;
    // nothing accepted is dropped behind the close frame, and later sends are refused.
    let (e, went, resume) = hold_read_server();
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    send(&mut s, 1, true, b"go-close");
    let ws = went.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut body = vec![1u8; 1000];
    for i in 0..100u32 {
        body[..4].copy_from_slice(&i.to_be_bytes());
        ws.send_binary(&body).unwrap();
    }
    assert!(ws.queued_bytes() >= 100 * 1000);
    resume.send(()).unwrap();
    recv_numbered(&mut s, 100, 1000);
    assert_eq!(close_code(&recv(&mut s)), 1000);
    expect_eof(&mut s);
    assert!(matches!(ws.send_binary(b"x"), Err(akio::Error::Closed)));
    stop(&e);
}

/// Hands its sender over on open; echoes text.
struct OpenEcho(mpsc::Sender<WsSender>);

impl WsHandler for OpenEcho {
    fn on_open(&mut self, ws: &WsSender) {
        self.0.send(ws.clone()).unwrap();
    }
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) {
        if let MessageRef::Text(t) = msg {
            let _ = ws.send_text(t);
        }
    }
}

#[test]
fn a_sender_paced_on_queued_bytes_is_never_refused_while_the_handler_reads() {
    // akit A305 under load: another thread streams to the session, paced on queued_bytes and
    // on_drain, while the client keeps the session's I/O thread busy reading its messages and
    // echoing them. With a bound of 1 MiB and a high water of 256 KiB no send is refused, and
    // every message arrives, in order.
    const N: u32 = 2000;
    const LEN: usize = 16 << 10;
    const HIGH: usize = 256 << 10;
    let (opened, open) = mpsc::channel();
    let e = start(Router::new().get("/ws", move |ctx: &mut Context| {
        ctx.upgrade_websocket(OpenEcho(opened.clone()), &WsOptions::default());
    }));
    let (mut s, _) = ws_connect(e.local_addrs()[0], "");
    let ws = open.recv_timeout(Duration::from_secs(5)).unwrap();
    ws.set_max_queued_bytes(Some(1 << 20)).unwrap();
    let producer = thread::spawn(move || {
        let mut body = vec![3u8; LEN];
        for i in 0..N {
            while ws.queued_bytes() > HIGH {
                let (drained, on_drain) = mpsc::channel();
                ws.on_drain(move || {
                    let _ = drained.send(());
                });
                on_drain.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            body[..4].copy_from_slice(&i.to_be_bytes());
            if let Err(e) = ws.send_binary(&body) {
                let queued = ws.queued_bytes();
                // Ends the client's reads too.
                ws.abort();
                panic!("message {i} refused at {queued} queued: {e:?}");
            }
        }
    });
    let stop_writing = Arc::new(AtomicBool::new(false));
    let writer = {
        let mut w = s.try_clone().unwrap();
        let stop_writing = stop_writing.clone();
        thread::spawn(move || {
            // Many small messages per write, so that the server's reads are long ones.
            let mut burst = Vec::new();
            for _ in 0..200 {
                burst.extend(frame_bytes(1, true, false, &[b'x'; 64]));
            }
            while !stop_writing.load(Ordering::Relaxed) {
                if w.write_all(&burst).is_err() {
                    break;
                }
            }
        })
    };
    let mut next = 0u32;
    let began = Instant::now();
    while next < N {
        // The echoes keep coming when the last messages were lost: a bound, not a wait.
        assert!(
            began.elapsed() < Duration::from_secs(60),
            "messages lost: {next} of {N} arrived"
        );
        let f = recv(&mut s);
        if f.opcode == 2 {
            assert_eq!(f.payload.len(), LEN);
            assert_eq!(f.payload[..4], next.to_be_bytes(), "a message was lost");
            next += 1;
        }
    }
    stop_writing.store(true, Ordering::Relaxed);
    producer.join().unwrap();
    // The writer may be held by the server's backpressure: ending the connection frees it.
    stop(&e);
    drop(s);
    writer.join().unwrap();
}
