//! HTTP/2 client against a scripted fake server: CONTINUATION and padding in responses, PING,
//! SETTINGS, RST_STREAM, GOAWAY, protocol errors and closing; streamed requests cancelled, timed
//! out, ended with trailers, refused by a GOAWAY, their reads held and their bodies paced, and
//! the server's stream limit (ADR-110); header and idle timeouts and cancel tokens (ADR-111).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use akio::{Config, Engine};
use akio_http::hpack::{Decoder, Encoder};
use akio_http::{
    Headers,
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
    enc: Encoder,
    dec: Decoder,
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
    setup_with(
        opts,
        &[(1, 4096), (5, 1 << 15), (3, 100), (0x77, 1)],
        script,
    )
}

/// [`setup`], the server's SETTINGS as given.
fn setup_with(
    opts: H2Options,
    settings: &[(u16, u32)],
    script: impl FnOnce(&mut Srv) + Send + 'static,
) -> (Arc<Engine>, H2Client, thread::JoinHandle<()>) {
    let settings = settings.to_vec();
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
        for (id, v) in settings {
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
    assert!(matches!(e1, ClientError::Refused), "{e1}");
    let e3 = c.send(get("/3")).wait().unwrap_err();
    assert!(e3.to_string().contains("reset"), "{e3}");
    // Requests start in submission order only per round trip: wait until /5 is on the wire.
    let f5 = c.send(get("/5"));
    saw5.recv_timeout(Duration::from_secs(5)).unwrap();
    let f7 = c.send(get("/7"));
    let r7 = f7.wait();
    assert!(matches!(r7, Err(ClientError::Refused)), "{r7:?}");
    assert_eq!(f5.wait().unwrap().body, b"five");
    // After the GOAWAY the client takes no more requests: they were not processed (ADR-110).
    assert!(!c.is_open());
    let r = c.send(get("/9")).wait();
    assert!(matches!(r, Err(ClientError::Refused)), "{r:?}");
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

// ---- limits ----------------------------------------------------------------------------------

const CANCEL: u32 = 8;

/// The error code of the next RST_STREAM on `sid`.
fn rst_code(srv: &mut Srv, sid: u32) -> Option<u32> {
    let f = srv.until(|f| f.ty == RST_STREAM && f.sid == sid)?;
    Some(u32::from_be_bytes(f.payload[..4].try_into().unwrap()))
}

#[test]
fn h2_defaults_are_bounded() {
    let o = H2Options::default();
    assert_eq!(o.max_header_list, 64 << 10);
    assert_eq!(o.max_body_bytes, 64 << 20);
}

#[test]
fn header_block_and_frame_size_violations_end_the_connection() {
    type Script = Box<dyn FnOnce(&mut Srv, u32) + Send>;
    let cases: Vec<(&str, u32, Script)> = vec![
        (
            // An endless header block: bounded at 2 x max_header_list (at least 64 KiB).
            "continuation flood",
            11,
            Box::new(|srv, sid| {
                srv.send(HEADERS, 0, sid, &[0x88]);
                for _ in 0..200 {
                    srv.send(CONTINUATION, 0, sid, &[0x40; 1024]);
                }
            }),
        ),
        (
            "frame over SETTINGS_MAX_FRAME_SIZE",
            6,
            Box::new(|srv, sid| srv.send(DATA, 0, sid, &vec![0; 16_385])),
        ),
        (
            "frame inside a header block",
            1,
            Box::new(|srv, sid| {
                srv.send(HEADERS, 0, sid, &[0x88]);
                srv.send(PING, 0, 0, b"pingpong");
            }),
        ),
        (
            "continuation on another stream",
            1,
            Box::new(|srv, sid| {
                srv.send(HEADERS, 0, sid, &[0x88]);
                srv.send(CONTINUATION, END_HEADERS, sid + 2, &[]);
            }),
        ),
    ];
    for (name, want, script) in cases {
        let (tx, rx) = mpsc::channel();
        let (e, c, t) = setup(H2Options::default(), move |srv| {
            let (sid, _) = srv.request();
            script(srv, sid);
            let _ = tx.send(srv.goaway());
        });
        let r = c.send(get("/x")).wait();
        assert!(matches!(r, Err(ClientError::Protocol(_))), "{name}: {r:?}");
        let code = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(code, Some(want), "{name}");
        stop(&e, t);
    }
}

#[test]
fn header_list_and_body_limits_reset_the_stream_only() {
    let mut opts = H2Options::default();
    opts.max_header_list = 1024;
    opts.max_body_bytes = 1000;
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(opts, move |srv| {
        // A header list over the limit (one field of 2000 bytes).
        let (sid, _) = srv.request();
        let big = "v".repeat(2000);
        let b = srv.block(&[(":status", "200"), ("x-big", big.as_str())]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        let _ = tx.send(("headers", rst_code(srv, sid)));
        // A body just under, at and over the limit.
        for len in [999usize, 1000, 1001] {
            let (sid, _) = srv.request();
            let b = srv.block(&[(":status", "200")]);
            srv.send(HEADERS, END_HEADERS, sid, &b);
            srv.send(DATA, 0, sid, &vec![b'x'; len - 1]);
            srv.send(DATA, END_STREAM, sid, b"y");
            if len > 1000 {
                let _ = tx.send(("body", rst_code(srv, sid)));
            }
        }
        // The connection is still fine.
        let (sid, _) = srv.request();
        srv.respond(sid, b"after");
    });
    let r = c.send(get("/big-head")).wait();
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ("headers", Some(CANCEL))
    );
    for len in [999usize, 1000] {
        assert_eq!(c.send(get("/b")).wait().unwrap().body.len(), len);
    }
    let r = c.send(get("/b")).wait();
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ("body", Some(CANCEL))
    );
    assert_eq!(c.send(get("/after")).wait().unwrap().body, b"after");
    stop(&e, t);
}

#[test]
fn request_timeout_resets_an_unanswered_stream() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        // Never answered: the client resets it.
        let (sid, _) = srv.request();
        let _ = tx.send(rst_code(srv, sid));
        // A longer request still pending gets its answer after a shorter one timed out.
        let (long, _) = srv.request();
        let (short, _) = srv.request();
        let _ = tx.send(rst_code(srv, short));
        srv.respond(long, b"long");
    });
    let t0 = std::time::Instant::now();
    let r = c
        .send(get("/silent").timeout(Duration::from_millis(200)))
        .wait();
    assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    let long = c.send(get("/long").timeout(Duration::from_secs(10)));
    thread::sleep(Duration::from_millis(50));
    let r = c
        .send(get("/short").timeout(Duration::from_millis(200)))
        .wait();
    assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    assert_eq!(long.wait().unwrap().body, b"long");
    stop(&e, t);
}

// ---- streamed requests (ADR-110) ------------------------------------------------------------

/// A streamed request's events as text: `head 200`, `data <bytes>`, `trailers`, `end`,
/// `error <kind>`.
fn recorder() -> (
    impl FnMut(H2Event<'_>) + Send + 'static,
    mpsc::Receiver<String>,
) {
    let (tx, rx) = mpsc::channel();
    let on_event = move |ev: H2Event<'_>| {
        let s = match ev {
            H2Event::Head { status, .. } => format!("head {status}"),
            H2Event::Data(d) => format!("data {}", String::from_utf8_lossy(d)),
            H2Event::Trailers(_) => "trailers".to_owned(),
            H2Event::End => "end".to_owned(),
            H2Event::Error(e) => format!("error {e:?}"),
        };
        let _ = tx.send(s);
    };
    (on_event, rx)
}

/// The events up to the first `end` or `error`.
fn until_over(rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut evs = Vec::new();
    while let Ok(ev) = rx.recv_timeout(Duration::from_secs(5)) {
        let over = ev == "end" || ev.starts_with("error");
        evs.push(ev);
        if over {
            break;
        }
    }
    evs
}

/// Waits (5 s at most) for `f` to hold.
fn eventually(mut f: impl FnMut() -> bool) {
    let t0 = std::time::Instant::now();
    while !f() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "condition not reached"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn streamed_request_cancelled_resets_its_stream_once() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (sid, _) = srv.request();
        let _ = tx.send(rst_code(srv, sid));
        let (sid, _) = srv.request();
        srv.respond(sid, b"ok");
    });
    let (on_event, evs) = recorder();
    let up = c.open(ClientRequest::post("http://x/up", Vec::new()), on_event);
    assert!(up.write(b"part"));
    let s = up.stream();
    eventually(|| s.id() != 0);
    s.cancel();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    assert_eq!(until_over(&evs), ["error Cancelled"]);
    assert!(matches!(up.try_write(b"more"), Err(akio::Error::Closed)));
    assert!(!up.write(b"more"));
    assert!(!up.finish());
    // Once only.
    s.cancel();
    up.cancel();
    assert!(evs.recv_timeout(Duration::from_millis(200)).is_err());

    // A stream that ended: a cancel does nothing.
    let (on_event, evs) = recorder();
    let up = c.open(get("/b"), on_event);
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["head 200", "data ok", "end"]);
    up.cancel();
    assert!(evs.recv_timeout(Duration::from_millis(200)).is_err());
    assert_eq!(up.queued_bytes(), 0);
    stop(&e, t);
}

#[test]
fn streamed_request_cancelled_at_once_fails_once() {
    // The cancel may overtake the start (each goes to the I/O thread on its own): either the
    // request is never sent, or its stream is reset. It fails once either way.
    let (e, c, t) = setup(H2Options::default(), |srv| {
        loop {
            let (sid, req) = srv.request();
            if req.iter().any(|(n, v)| n == ":path" && v == "/cancelled") {
                assert_eq!(rst_code(srv, sid), Some(CANCEL));
                continue;
            }
            srv.respond(sid, b"after");
            break;
        }
    });
    let (on_event, evs) = recorder();
    let up = c.open(get("/cancelled"), on_event);
    up.cancel();
    assert_eq!(until_over(&evs), ["error Cancelled"]);
    assert!(evs.recv_timeout(Duration::from_millis(100)).is_err());
    let (on_event, evs) = recorder();
    let up = c.open(get("/after"), on_event);
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["head 200", "data after", "end"]);
    stop(&e, t);
}

#[test]
fn streamed_request_timeout_resets_its_stream() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (sid, _) = srv.request();
        let _ = tx.send(rst_code(srv, sid));
        // A request within its timeout is answered.
        let (sid, _) = srv.request();
        srv.respond(sid, b"in time");
    });
    let (on_event, evs) = recorder();
    let t0 = std::time::Instant::now();
    let up = c.open(get("/silent").timeout(Duration::from_millis(200)), on_event);
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["error Timeout"]);
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(150) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    assert!(!up.write(b"late"));

    let (on_event, evs) = recorder();
    let up = c.open(get("/quick").timeout(Duration::from_secs(10)), on_event);
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["head 200", "data in time", "end"]);
    stop(&e, t);
}

#[test]
fn request_trailers_end_the_stream() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (sid, _) = srv.request();
        let mut body = Vec::new();
        let trailers = loop {
            let f = srv
                .until(|f| f.sid == sid && (f.ty == DATA || f.ty == HEADERS))
                .unwrap();
            if f.ty == DATA {
                assert_eq!(f.flags & END_STREAM, 0, "the body does not end the stream");
                body.extend_from_slice(&f.payload);
            } else {
                assert_eq!(
                    f.flags & (END_STREAM | END_HEADERS),
                    END_STREAM | END_HEADERS
                );
                break srv.dec.decode(&f.payload).unwrap();
            }
        };
        let _ = tx.send((body, trailers));
        srv.respond(sid, b"done");
    });
    let (on_event, evs) = recorder();
    let up = c.open(ClientRequest::post("http://x/t", b"ab".to_vec()), on_event);
    assert!(up.write(b"cd"));
    let mut tr = Headers::new();
    tr.append("Grpc-Status", "0");
    tr.append("connection", "dropped");
    tr.append(":path", "/dropped");
    assert!(up.finish_with_trailers(tr));
    assert!(!up.finish(), "finished once");
    assert_eq!(until_over(&evs), ["head 200", "data done", "end"]);
    let (body, trailers) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(body, b"abcd");
    assert_eq!(trailers, [(b"grpc-status".to_vec(), b"0".to_vec())]);
    stop(&e, t);
}

#[test]
fn response_before_the_request_body_ends_resets_the_stream() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (sid, _) = srv.request();
        srv.respond(sid, b"early");
        let _ = tx.send(rst_code(srv, sid));
    });
    let (on_event, evs) = recorder();
    let up = c.open(
        ClientRequest::post("http://x/early", b"x".to_vec()),
        on_event,
    );
    assert_eq!(until_over(&evs), ["head 200", "data early", "end"]);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    assert!(matches!(up.try_write(b"y"), Err(akio::Error::Closed)));
    stop(&e, t);
}

#[test]
fn goaway_refuses_unprocessed_streamed_requests() {
    let (started, wait_started) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (s1, _) = srv.request();
        started.send(()).unwrap();
        let (s3, _) = srv.request();
        assert!(s3 > s1);
        let mut p = s1.to_be_bytes().to_vec();
        p.extend_from_slice(&0u32.to_be_bytes());
        srv.send(GOAWAY, 0, 0, &p);
        srv.respond(s1, b"one");
    });
    let (on_event, a) = recorder();
    let up_a = c.open(get("/a"), on_event);
    assert!(up_a.finish());
    wait_started.recv_timeout(Duration::from_secs(5)).unwrap();
    let (on_event, b) = recorder();
    let up_b = c.open(ClientRequest::post("http://x/b", Vec::new()), on_event);
    assert!(up_b.write(b"body"));
    assert_eq!(until_over(&b), ["error Refused"]);
    assert_eq!(until_over(&a), ["head 200", "data one", "end"]);
    assert!(!c.is_open());
    assert!(!up_b.write(b"more"));
    let (on_event, d) = recorder();
    let _up = c.open(get("/d"), on_event);
    assert_eq!(until_over(&d), ["error Refused"]);
    stop(&e, t);
}

#[test]
fn held_reads_keep_the_stream_window_closed() {
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let (checked_tx, checked_rx) = mpsc::channel::<()>();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let (sid, _) = srv.request();
        let b = srv.block(&[(":status", "200")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        srv.send(DATA, 0, sid, &[b'a'; 1000]);
        // The connection's window comes back at once, the stream's does not: it would come in
        // the same write, before the PING's answer.
        let f = srv.until(|f| f.ty == WINDOW_UPDATE).unwrap();
        assert_eq!(f.sid, 0, "the stream's window is held");
        srv.send(PING, 0, 0, b"heldheld");
        loop {
            let f = srv.read().unwrap();
            assert!(
                !(f.ty == WINDOW_UPDATE && f.sid == sid),
                "window given back while held"
            );
            if f.ty == PING && f.flags & ACK != 0 {
                break;
            }
        }
        checked_tx.send(()).unwrap();
        // Resumed: what was consumed comes back.
        let f = srv
            .until(|f| f.ty == WINDOW_UPDATE && f.sid == sid)
            .unwrap();
        assert_eq!(u32::from_be_bytes(f.payload[..4].try_into().unwrap()), 1000);
        srv.send(DATA, END_STREAM, sid, b"z");
    });
    let (tx, evs) = mpsc::channel();
    let up = c.open(get("/held"), move |ev| {
        let _ = tx.send(match ev {
            H2Event::Data(d) => format!("data {}", d.len()),
            H2Event::Head { status, .. } => format!("head {status}"),
            H2Event::End => "end".to_owned(),
            H2Event::Error(e) => format!("error {e:?}"),
            H2Event::Trailers(_) => "trailers".to_owned(),
        });
    });
    let s = up.stream();
    s.hold_reads(true);
    assert!(up.finish());
    held_tx.send(()).unwrap();
    // Held, the data in flight is still handed over.
    assert_eq!(
        evs.recv_timeout(Duration::from_secs(5)).unwrap(),
        "head 200"
    );
    assert_eq!(
        evs.recv_timeout(Duration::from_secs(5)).unwrap(),
        "data 1000"
    );
    checked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    s.hold_reads(false);
    assert_eq!(until_over(&evs), ["data 1", "end"]);
    stop(&e, t);
}

#[test]
fn upload_queue_is_bounded_and_drains() {
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (body_tx, body_rx) = mpsc::channel();
    let opts = {
        let mut o = H2Options::default();
        o.max_queued_bytes = 128;
        o
    };
    // The server's stream window is 10 bytes.
    let (e, c, t) = setup_with(opts, &[(4, 10), (3, 50)], move |srv| {
        let (sid, _) = srv.request();
        let f = srv.until(|f| f.ty == DATA && f.sid == sid).unwrap();
        let mut body = f.payload;
        assert_eq!(body.len(), 10);
        go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        srv.send(WINDOW_UPDATE, 0, sid, &1000u32.to_be_bytes());
        loop {
            let f = srv.until(|f| f.ty == DATA && f.sid == sid).unwrap();
            body.extend_from_slice(&f.payload);
            if f.flags & END_STREAM != 0 {
                break;
            }
        }
        body_tx.send(body).unwrap();
        srv.respond(sid, b"stored");
    });
    // The server's SETTINGS are in (one frame: the window too).
    eventually(|| c.max_concurrent_streams() == 50);
    let (on_event, evs) = recorder();
    let up = c.open(ClientRequest::post("http://x/u", Vec::new()), on_event);
    up.try_write(&[1; 100]).unwrap();
    eventually(|| up.queued_bytes() == 90);
    assert!(matches!(
        up.try_write(&[2; 50]),
        Err(akio::Error::Overloaded)
    ));
    assert!(!up.write(&[2; 50]));
    up.try_write(&[3; 30]).unwrap();
    assert_eq!(up.queued_bytes(), 120);
    let (dtx, drx) = mpsc::channel();
    up.on_drain(move || dtx.send(()).unwrap());
    assert!(drx.recv_timeout(Duration::from_millis(100)).is_err());
    go_tx.send(()).unwrap();
    drx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(up.queued_bytes(), 0);
    // Nothing queued: at once, on this thread.
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let r2 = ran.clone();
    up.on_drain(move || r2.store(true, std::sync::atomic::Ordering::SeqCst));
    assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["head 200", "data stored", "end"]);
    let body = body_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut want = vec![1u8; 100];
    want.extend_from_slice(&[3; 30]);
    assert_eq!(body, want);
    stop(&e, t);
}

#[test]
fn server_stream_limit_queues_requests_and_refuses_past_the_queue() {
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let opts = {
        let mut o = H2Options::default();
        o.max_pending_streams = 1;
        o
    };
    let (e, c, t) = setup_with(opts, &[(3, 1)], move |srv| {
        let (s1, _) = srv.request();
        go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // The waiting request is not sent while the first stream is open.
        srv.send(PING, 0, 0, b"limit-1!");
        loop {
            let f = srv.read().unwrap();
            assert_ne!(f.ty, HEADERS, "a second stream past the server's limit");
            if f.ty == PING && f.flags & ACK != 0 {
                break;
            }
        }
        srv.respond(s1, b"one");
        let (s3, req) = srv.request();
        assert!(
            req.iter().any(|(n, v)| n == ":path" && v == "/b"),
            "{req:?}"
        );
        srv.respond(s3, b"two");
    });
    eventually(|| c.max_concurrent_streams() == 1);
    let fa = c.send(get("/a"));
    eventually(|| c.open_streams() == 1);
    let fb = c.send(get("/b"));
    eventually(|| c.waiting_streams() == 1);
    let rc = c.send(get("/c")).wait();
    assert!(matches!(rc, Err(ClientError::Busy)), "{rc:?}");
    go_tx.send(()).unwrap();
    assert_eq!(fa.wait().unwrap().body, b"one");
    assert_eq!(fb.wait().unwrap().body, b"two");
    eventually(|| c.open_streams() == 0 && c.waiting_streams() == 0);
    stop(&e, t);
}

// ---- header and idle timeouts, cancel tokens (ADR-111) ----------------------------------------

/// The next `n` requests, by path.
fn requests(srv: &mut Srv, n: usize) -> std::collections::HashMap<String, u32> {
    (0..n)
        .map(|_| {
            let (sid, req) = srv.request();
            let path = req
                .into_iter()
                .find(|(n, _)| n == ":path")
                .map(|(_, v)| v)
                .unwrap();
            (path, sid)
        })
        .collect()
}

/// The next `n` RST_STREAMs: stream and error code.
fn resets(srv: &mut Srv, n: usize) -> Vec<(u32, u32)> {
    let mut v: Vec<(u32, u32)> = (0..n)
        .map(|_| {
            let f = srv.until(|f| f.ty == RST_STREAM).unwrap();
            (
                f.sid,
                u32::from_be_bytes(f.payload[..4].try_into().unwrap()),
            )
        })
        .collect();
    v.sort_unstable();
    v
}

#[test]
fn header_timeout_resets_the_stream_alone_from_the_requests_end() {
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let ids = requests(srv, 2);
        let _ = tx.send(rst_code(srv, ids["/silent"]));
        srv.respond(ids["/other"], b"other");
        // A request body still open: its wait for the head has not started.
        let (sid, _) = srv.request();
        srv.until(|f| f.ty == DATA && f.sid == sid && f.flags & END_STREAM != 0)
            .unwrap();
        srv.respond(sid, b"late ok");
    });
    let t0 = std::time::Instant::now();
    let silent = c.send(get("/silent").response_header_timeout(Duration::from_millis(200)));
    let other = c.send(get("/other"));
    let r = silent.wait();
    assert!(matches!(r, Err(ClientError::HeaderTimeout)), "{r:?}");
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(150) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );
    // The connection goes on with its other streams.
    assert_eq!(other.wait().unwrap().body, b"other");
    assert!(c.is_open());

    let (on_event, evs) = recorder();
    let up = c.open(
        ClientRequest::post("http://x/slow-up", Vec::new())
            .response_header_timeout(Duration::from_millis(200)),
        on_event,
    );
    assert!(up.write(b"x"));
    thread::sleep(Duration::from_millis(400));
    assert!(up.finish());
    assert_eq!(until_over(&evs), ["head 200", "data late ok", "end"]);
    stop(&e, t);
}

#[test]
fn idle_timeout_counts_the_gaps_between_data_frames_not_the_time_held() {
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        // Data every 100 ms for 400 ms: within an idle timeout of 300 ms.
        let (sid, _) = srv.request();
        let b = srv.block(&[(":status", "200")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        for _ in 0..4 {
            thread::sleep(Duration::from_millis(100));
            srv.send(DATA, 0, sid, b"t");
        }
        srv.send(DATA, END_STREAM, sid, b"");
        // A head, a piece, then silence.
        let (sid, _) = srv.request();
        let b = srv.block(&[(":status", "200")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        srv.send(DATA, 0, sid, b"x");
        let _ = tx.send(rst_code(srv, sid));
        // Silence while the client holds the reads.
        let (sid, _) = srv.request();
        let b = srv.block(&[(":status", "200")]);
        srv.send(HEADERS, END_HEADERS, sid, &b);
        srv.send(DATA, 0, sid, b"a");
        go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        srv.send(DATA, END_STREAM, sid, b"z");
    });
    let r = c
        .send(get("/trickle").response_idle_timeout(Duration::from_millis(300)))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"tttt");

    let (on_event, evs) = recorder();
    let t0 = std::time::Instant::now();
    let up = c.open(
        get("/stall").response_idle_timeout(Duration::from_millis(200)),
        on_event,
    );
    assert!(up.finish());
    assert_eq!(
        until_over(&evs),
        ["head 200", "data x", "error IdleTimeout"]
    );
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(150) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(CANCEL)
    );

    let (on_event, evs) = recorder();
    let up = c.open(
        get("/held").response_idle_timeout(Duration::from_millis(200)),
        on_event,
    );
    let s = up.stream();
    s.hold_reads(true);
    assert!(up.finish());
    assert_eq!(
        evs.recv_timeout(Duration::from_secs(5)).unwrap(),
        "head 200"
    );
    assert_eq!(evs.recv_timeout(Duration::from_secs(5)).unwrap(), "data a");
    // Held for twice the idle timeout: not given up.
    assert!(evs.recv_timeout(Duration::from_millis(500)).is_err());
    s.hold_reads(false);
    go_tx.send(()).unwrap();
    assert_eq!(until_over(&evs), ["data z", "end"]);
    stop(&e, t);
}

#[test]
fn cancel_token_resets_its_streams_and_fails_them_once() {
    use akio_http::client::CancelToken;
    let (tx, rx) = mpsc::channel();
    let (e, c, t) = setup(H2Options::default(), move |srv| {
        let ids = requests(srv, 2);
        let mut want = vec![(ids["/a"], CANCEL), (ids["/b"], CANCEL)];
        want.sort_unstable();
        let _ = tx.send(resets(srv, 2) == want);
        // Requests given a token cancelled already are never sent.
        let (sid, req) = srv.request();
        assert!(
            req.iter().any(|(n, v)| n == ":path" && v == "/after"),
            "{req:?}"
        );
        srv.respond(sid, b"after");
    });
    let token = CancelToken::new();
    let a = c.send(get("/a").cancel_with(&token));
    let (on_event, evs) = recorder();
    let b = c.open(get("/b").cancel_with(&token), on_event);
    assert!(b.finish());
    eventually(|| c.open_streams() == 2);
    token.cancel();
    assert!(matches!(a.wait(), Err(ClientError::Cancelled)));
    assert_eq!(until_over(&evs), ["error Cancelled"]);
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    assert!(evs.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(!b.write(b"late"));

    let r = c.send(get("/never").cancel_with(&token)).wait();
    assert!(matches!(r, Err(ClientError::Cancelled)), "{r:?}");
    let (on_event, evs) = recorder();
    let _up = c.open(get("/never").cancel_with(&token), on_event);
    assert_eq!(until_over(&evs), ["error Cancelled"]);
    assert_eq!(c.send(get("/after")).wait().unwrap().body, b"after");
    stop(&e, t);
}
