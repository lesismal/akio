//! HTTP/2 client against a scripted fake server: CONTINUATION and padding in responses, PING,
//! SETTINGS, RST_STREAM, GOAWAY, protocol errors and closing.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use loona_hpack::{Decoder, Encoder};
use only::{Config, Engine};
use only_http::{
    client::{ClientError, ClientRequest},
    h2client::{H2Client, H2Event, H2Options},
};

const DATA: u8 = 0;
const HEADERS: u8 = 1;
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

struct Frame {
    ty: u8,
    flags: u8,
    sid: u32,
    payload: Vec<u8>,
}

/// The fake server side of one connection.
struct Srv {
    s: TcpStream,
    enc: Encoder<'static>,
    dec: Decoder<'static>,
}

impl Srv {
    fn send(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        let mut b = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        b.push(ty);
        b.push(flags);
        b.extend_from_slice(&sid.to_be_bytes());
        b.extend_from_slice(payload);
        // The client may already have hung up after a protocol error.
        let _ = self.s.write_all(&b);
    }

    fn read(&mut self) -> Option<Frame> {
        let mut h = [0u8; 9];
        self.s.read_exact(&mut h).ok()?;
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let mut payload = vec![0; len];
        self.s.read_exact(&mut payload).ok()?;
        Some(Frame {
            ty: h[3],
            flags: h[4],
            sid: u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
            payload,
        })
    }

    fn until(&mut self, mut pred: impl FnMut(&Frame) -> bool) -> Option<Frame> {
        loop {
            let f = self.read()?;
            if pred(&f) {
                return Some(f);
            }
        }
    }

    /// Reads a whole request header block (HEADERS + CONTINUATION); returns (sid, fields).
    fn request(&mut self) -> (u32, Vec<(String, String)>) {
        let first = self.until(|f| f.ty == HEADERS).expect("request headers");
        let mut block = first.payload;
        let mut flags = first.flags;
        while flags & END_HEADERS == 0 {
            let f = self.read().unwrap();
            assert_eq!((f.ty, f.sid), (CONTINUATION, first.sid));
            block.extend_from_slice(&f.payload);
            flags = f.flags;
        }
        let fields = self
            .dec
            .decode(&block)
            .unwrap()
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        (first.sid, fields)
    }

    fn block(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
        self.enc
            .encode(fields.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())))
    }

    fn respond(&mut self, sid: u32, body: &[u8]) {
        let b = self.block(&[(":status", "200")]);
        self.send(HEADERS, END_HEADERS, sid, &b);
        self.send(DATA, END_STREAM, sid, body);
    }

    /// The error code of the next GOAWAY, if one comes before the connection closes.
    fn goaway(&mut self) -> Option<u32> {
        let f = self.until(|f| f.ty == GOAWAY)?;
        Some(u32::from_be_bytes(f.payload[4..8].try_into().unwrap()))
    }
}

/// Runs `script` as the server of one connection and returns a connected client.
fn setup(
    opts: H2Options,
    script: impl FnOnce(&mut Srv) + Send + 'static,
) -> (Arc<Engine>, H2Client, thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut srv = Srv {
            s,
            enc: Encoder::new(),
            dec: Decoder::new(),
        };
        let mut preface = [0u8; 24];
        srv.s.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let f = srv.read().unwrap();
        assert_eq!(f.ty, SETTINGS);
        // Header table size and max frame size: valid, and applied by the client.
        let mut sp = Vec::new();
        for (id, v) in [(1u16, 4096u32), (5, 1 << 15), (3, 100), (0x77, 1)] {
            sp.extend_from_slice(&id.to_be_bytes());
            sp.extend_from_slice(&v.to_be_bytes());
        }
        srv.send(SETTINGS, 0, 0, &sp);
        srv.send(SETTINGS, ACK, 0, &[]);
        script(&mut srv);
        // Keep the socket open (and read) until the client side goes away: closing with unread
        // bytes would reset the connection and could discard responses still in flight.
        while srv.read().is_some() {}
    });
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let c = H2Client::dial_blocking(&e, addr, None, opts).unwrap();
    (e, c, t)
}

fn stop(e: &Engine, t: thread::JoinHandle<()>) {
    e.shutdown();
    e.wait();
    t.join().unwrap();
}

fn get(path: &str) -> ClientRequest {
    ClientRequest::get(&format!("http://x{path}"))
}

#[test]
fn responses_with_continuation_padding_priority_and_ping() {
    let (e, c, t) = setup(H2Options::default(), |srv| {
        let (sid, req) = srv.request();
        assert!(req.iter().any(|(n, v)| n == ":path" && v == "/a"));
        // PING is answered.
        srv.send(PING, 0, 0, b"pingpong");
        let f = srv.until(|f| f.ty == PING).unwrap();
        assert_eq!((f.flags, f.payload.as_slice()), (ACK, &b"pingpong"[..]));
        // HEADERS (padded + priority) split with a CONTINUATION, then padded DATA.
        let b = srv.block(&[(":status", "200"), ("x-a", "1"), ("x-b", "2")]);
        let (h1, h2) = b.split_at(2);
        let mut p = vec![2u8, 0, 0, 0, 0, 16];
        p.extend_from_slice(h1);
        p.extend_from_slice(&[0, 0]);
        srv.send(HEADERS, PADDED | PRIO, sid, &p);
        srv.send(CONTINUATION, END_HEADERS, sid, h2);
        let mut d = vec![3u8];
        d.extend_from_slice(b"body");
        d.extend_from_slice(&[0; 3]);
        srv.send(DATA, PADDED, sid, &d);
        // An interim (1xx) head is skipped; trailers end the stream.
        let tr = srv.block(&[("x-trailer", "t")]);
        srv.send(HEADERS, END_HEADERS | END_STREAM, sid, &tr);
        // WINDOW_UPDATE and unknown frame types are accepted.
        srv.send(WINDOW_UPDATE, 0, 0, &100u32.to_be_bytes());
        srv.send(0xee, 0, 0, b"ignored");
        let (sid, _) = srv.request();
        let b = srv.block(&[(":status", "103")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        srv.respond(sid, b"second");
        srv.until(|f| f.ty == GOAWAY);
    });
    let r = c.send(get("/a")).wait().unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"body"[..]));
    assert_eq!(r.headers.get("x-b"), Some("2"));
    assert_eq!(r.trailers.get("x-trailer"), Some("t"));
    let r = c.send(get("/b")).wait().unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"second"[..]));
    assert!(c.is_open());
    c.close();
    stop(&e, t);
    assert!(!c.is_open());
    // Requests on a closed client fail at once.
    assert!(matches!(c.send(get("/c")).wait(), Err(ClientError::Closed)));
}

#[test]
fn rst_stream_and_goaway_fail_the_affected_requests() {
    let (got5, saw5) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (s1, _) = srv.request();
        srv.send(RST_STREAM, 0, s1, &7u32.to_be_bytes()); // REFUSED_STREAM
        let (s3, _) = srv.request();
        srv.send(RST_STREAM, 0, s3, &2u32.to_be_bytes()); // INTERNAL_ERROR
        let (s5, _) = srv.request();
        got5.send(()).unwrap();
        let (s7, _) = srv.request();
        // GOAWAY: stream 5 was processed, stream 7 was not.
        let mut p = s5.to_be_bytes().to_vec();
        p.extend_from_slice(&0u32.to_be_bytes());
        srv.send(GOAWAY, 0, 0, &p);
        srv.respond(s5, b"five");
        let _ = s7;
        thread::sleep(Duration::from_millis(100));
    });
    let r1 = c.send(get("/1"));
    let e1 = r1.wait().unwrap_err();
    assert!(e1.to_string().contains("refused"), "{e1}");
    let e3 = c.send(get("/3")).wait().unwrap_err();
    assert!(e3.to_string().contains("reset"), "{e3}");
    // Requests start in submission order only per round trip: wait until /5 is on the wire.
    let f5 = c.send(get("/5"));
    saw5.recv_timeout(Duration::from_secs(5)).unwrap();
    let f7 = c.send(get("/7"));
    let r7 = f7.wait();
    assert!(matches!(r7, Err(ClientError::Closed)), "{r7:?}");
    assert_eq!(f5.wait().unwrap().body, b"five");
    stop(&e, t);
}

#[test]
fn protocol_errors_close_the_connection() {
    type Script = Box<dyn FnOnce(&mut Srv, u32) + Send>;
    let cases: Vec<(&str, Script)> = vec![
        (
            "bad hpack",
            Box::new(|srv, sid| srv.send(HEADERS, END_HEADERS, sid, &[0xff; 6])),
        ),
        (
            "bad settings length",
            Box::new(|srv, _| srv.send(SETTINGS, 0, 0, &[0; 5])),
        ),
        (
            "window too large",
            Box::new(|srv, _| {
                let mut p = 4u16.to_be_bytes().to_vec();
                p.extend_from_slice(&(1u32 << 31).to_be_bytes());
                srv.send(SETTINGS, 0, 0, &p);
            }),
        ),
        (
            "bad window update",
            Box::new(|srv, _| srv.send(WINDOW_UPDATE, 0, 0, &[0; 3])),
        ),
        (
            "stray continuation",
            Box::new(|srv, sid| srv.send(CONTINUATION, END_HEADERS, sid, &[0x88])),
        ),
        (
            "short push promise",
            Box::new(|srv, sid| srv.send(PUSH_PROMISE, END_HEADERS, sid, &[0, 0])),
        ),
    ];
    for (name, script) in cases {
        let (tx, rx) = mpsc::channel();
        let (e, c, t) = setup(H2Options::default(), move |srv| {
            let (sid, _) = srv.request();
            script(srv, sid);
            let _ = tx.send(srv.goaway());
        });
        let r = c.send(get("/x")).wait();
        assert!(r.is_err(), "{name}: {r:?}");
        let code = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(code.is_some_and(|c| c != 0), "{name}: GOAWAY {code:?}");
        stop(&e, t);
    }
}

#[test]
fn push_promise_is_refused_when_push_is_disabled() {
    let (e, c, t) = setup(H2Options::default(), |srv| {
        let (sid, _) = srv.request();
        let mut p = 2u32.to_be_bytes().to_vec();
        p.extend(srv.block(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/pushed"),
            (":authority", "x"),
        ]));
        srv.send(PUSH_PROMISE, END_HEADERS, sid, &p);
        let f = srv.until(|f| f.ty == RST_STREAM).unwrap();
        assert_eq!(f.sid, 2);
        srv.respond(sid, b"ok");
    });
    let r = c.send(get("/x")).wait().unwrap();
    assert_eq!(r.body, b"ok");
    assert!(r.pushed.is_empty());
    stop(&e, t);
}

#[test]
fn push_promise_split_with_continuation_and_reset_push() {
    let mut opts = H2Options::default();
    opts.enable_push = true;
    let (e, c, t) = setup(opts, |srv| {
        let (sid, _) = srv.request();
        // A padded PUSH_PROMISE whose block continues in a CONTINUATION frame.
        let b = srv.block(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/pushed"),
            (":authority", "x"),
        ]);
        let (b1, b2) = b.split_at(3);
        let mut p = vec![1u8];
        p.extend_from_slice(&2u32.to_be_bytes());
        p.extend_from_slice(b1);
        p.push(0);
        srv.send(PUSH_PROMISE, PADDED, sid, &p);
        srv.send(CONTINUATION, END_HEADERS, sid, b2);
        // A second promise that is reset by the server before it completes.
        let b = srv.block(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/gone"),
            (":authority", "x"),
        ]);
        let mut p = 4u32.to_be_bytes().to_vec();
        p.extend_from_slice(&b);
        srv.send(PUSH_PROMISE, END_HEADERS, sid, &p);
        srv.send(RST_STREAM, 0, 4, &8u32.to_be_bytes());
        srv.respond(2, b"pushed body");
        srv.respond(sid, b"main");
    });
    let r = c.send(get("/x")).wait().unwrap();
    assert_eq!(r.body, b"main");
    assert_eq!(r.pushed.len(), 1);
    assert_eq!(r.pushed[0].0, "/pushed");
    assert_eq!(r.pushed[0].1.body, b"pushed body");
    stop(&e, t);
}

#[test]
fn large_request_headers_and_streamed_upload() {
    let (e, c, t) = setup(H2Options::default(), |srv| {
        // A header block bigger than the server's max frame size arrives in CONTINUATIONs.
        let (sid, req) = srv.request();
        assert!(req.iter().any(|(n, v)| n == "x-big" && v.len() == 70_000));
        srv.respond(sid, b"big ok");
        // Streamed upload: body pieces, then an empty DATA with END_STREAM.
        let (sid, _) = srv.request();
        let mut body = Vec::new();
        loop {
            let f = srv.until(|f| f.ty == DATA && f.sid == sid).unwrap();
            body.extend_from_slice(&f.payload);
            if f.flags & END_STREAM != 0 {
                break;
            }
        }
        assert_eq!(body, b"firstsecond");
        let b = srv.block(&[(":status", "200")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        srv.send(DATA, 0, sid, b"up");
        srv.send(DATA, END_STREAM, sid, b"loaded");
        // A reset during a streamed request is reported as an event.
        let (sid, _) = srv.request();
        srv.send(RST_STREAM, 0, sid, &8u32.to_be_bytes());
        thread::sleep(Duration::from_millis(100));
    });
    let big = "b".repeat(70_000);
    let r = c.send(get("/big").header("x-big", &big)).wait().unwrap();
    assert_eq!(r.body, b"big ok");

    let (tx, rx) = mpsc::channel();
    let up = c.open(
        ClientRequest::post("http://x/up", b"first".to_vec()),
        move |ev| {
            let s = match ev {
                H2Event::Head { status, .. } => format!("head {status}"),
                H2Event::Data(d) => format!("data {}", String::from_utf8_lossy(d)),
                H2Event::Trailers(_) => "trailers".to_owned(),
                H2Event::End => "end".to_owned(),
                H2Event::Error(e) => format!("error {e}"),
            };
            let _ = tx.send(s);
        },
    );
    assert!(up.write(b"second"));
    assert!(up.finish());
    let mut evs = Vec::new();
    while let Ok(ev) = rx.recv_timeout(Duration::from_secs(5)) {
        let end = ev == "end";
        evs.push(ev);
        if end {
            break;
        }
    }
    assert_eq!(evs, ["head 200", "data up", "data loaded", "end"]);

    let (tx, rx) = mpsc::channel();
    let _up = c.open(ClientRequest::post("http://x/rst", Vec::new()), move |ev| {
        if let H2Event::Error(e) = ev {
            let _ = tx.send(e.to_string());
        }
    });
    let err = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(err.contains("reset"), "{err}");
    stop(&e, t);
}

#[test]
fn server_hanging_up_fails_pending_requests() {
    let (e, c, t) = setup(H2Options::default(), |srv| {
        let _ = srv.request();
        srv.s.shutdown(std::net::Shutdown::Both).unwrap();
    });
    let r = c.send(get("/x")).wait();
    assert!(r.is_err());
    stop(&e, t);
}
