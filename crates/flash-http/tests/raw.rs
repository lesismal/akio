//! Raw connection takeover (`Context::upgrade_raw`) and HTTP/1 session edge cases: bad chunked
//! framing mid-stream, streamed handlers that never answer, header limits, non-HTTP preambles.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use flash::{Backend, Config, Engine, Listener, UringConfig};
use flash_http::{
    BodyEvent, Context, Router, Streaming,
    raw::{RawConn, RawHandler},
    serve,
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

type Log = Arc<Mutex<mpsc::Sender<String>>>;

/// Echoes lines with a prefix; `bye` closes after sending, `kill` closes at once.
struct Tunnel(Log);

impl RawHandler for Tunnel {
    fn on_open(&mut self, conn: &RawConn) {
        conn.hold_reads(false);
        let _ = conn.send(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = self.0.lock().unwrap().send(format!(
            "open {} queued={}",
            conn.is_open(),
            conn.queued_bytes() < 1 << 20
        ));
        let _ = conn.peer_addr();
        let log = self.0.clone();
        conn.on_drain(move || {
            let _ = log.lock().unwrap().send("drained".into());
        });
    }
    fn on_data(&mut self, conn: &RawConn, data: &[u8]) {
        match data {
            b"bye" => {
                let _ = conn.send_owned(b"see you".to_vec());
                conn.close_after_send();
            }
            b"kill" => conn.close(),
            _ => {
                let _ = conn.send_owned([b"echo:".as_slice(), data].concat());
            }
        }
    }
    fn on_close(&mut self) {
        let _ = self.0.lock().unwrap().send("closed".into());
    }
}

fn start(log: Log) -> Engine {
    let app = Router::new()
        .get("/tunnel", move |ctx: &mut Context| {
            assert!(ctx.upgrade_raw(Tunnel(log.clone())));
        })
        .post(
            "/silent",
            Streaming(|ctx: &mut Context| {
                // Reads the body, never answers: the session answers 500 for it.
                ctx.on_body(|_ctx, _ev: BodyEvent<'_>| {});
            }),
        )
        .post(
            "/count",
            Streaming(|ctx: &mut Context| {
                let mut n = 0;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => n += b.len(),
                    BodyEvent::End(_) => ctx.text(200, n.to_string()),
                });
            }),
        );
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve(app)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn read_some(s: &mut TcpStream) -> Vec<u8> {
    let mut b = vec![0; 4096];
    let n = s.read(&mut b).unwrap();
    b.truncate(n);
    b
}

fn read_to_end(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn next(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(5)).unwrap()
}

#[test]
fn raw_takeover_echo_and_close() {
    let (tx, rx) = mpsc::channel();
    let e = start(Arc::new(Mutex::new(tx)));

    let mut s = connect(&e);
    s.write_all(b"GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut got = Vec::new();
    while !got.ends_with(b"\r\n\r\n") {
        got.extend(read_some(&mut s));
    }
    assert!(got.starts_with(b"HTTP/1.1 200 Connection Established"));
    assert_eq!(next(&rx), "open true queued=true");
    s.write_all(b"hello").unwrap();
    assert_eq!(read_some(&mut s), b"echo:hello");
    s.write_all(b"bye").unwrap();
    assert_eq!(read_to_end(&mut s), "see you");
    let mut evs = vec![next(&rx), next(&rx)];
    evs.sort();
    assert_eq!(evs, ["closed", "drained"]);

    let mut s = connect(&e);
    s.write_all(b"GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut got = Vec::new();
    while !got.ends_with(b"\r\n\r\n") {
        got.extend(read_some(&mut s));
    }
    s.write_all(b"kill").unwrap();
    assert_eq!(read_to_end(&mut s), "");
    e.shutdown();
    e.wait();
}

#[test]
fn http1_session_edge_cases() {
    let (tx, _rx) = mpsc::channel();
    let e = start(Arc::new(Mutex::new(tx)));

    // A streamed handler that never answers gets a 500 once its body is in.
    let mut s = connect(&e);
    s.write_all(b"POST /silent HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc")
        .unwrap();
    let got = String::from_utf8(read_some(&mut s)).unwrap();
    assert!(got.starts_with("HTTP/1.1 500"), "{got}");

    // Broken chunked framing in a streamed body: the connection is dropped.
    let mut s = connect(&e);
    s.write_all(
        b"POST /count HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\nzz\r\n",
    )
    .unwrap();
    assert_eq!(read_to_end(&mut s), "");

    // Too many header fields: 431.
    let mut req = b"GET /x HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..200 {
        req.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    let mut s = connect(&e);
    s.write_all(&req).unwrap();
    let got = read_to_end(&mut s);
    assert!(got.starts_with("HTTP/1.1 431"), "{got}");

    // Neither HTTP/1 nor the HTTP/2 preface: answered with an HTTP/2 GOAWAY and closed.
    let mut s = connect(&e);
    s.write_all(b"\x16\x03\x01garbage-that-is-long-enough!!")
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert_eq!(&out[..9], &[0, 0, 8, 7, 0, 0, 0, 0, 0]);
    e.shutdown();
    e.wait();
}
