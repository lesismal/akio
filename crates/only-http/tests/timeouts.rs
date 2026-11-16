//! HTTP/1 server deadlines: head read (slowloris), keep-alive idle and body progress, on the
//! native backend (and io_uring with ONLY_TEST_BACKEND=uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};

use only::{Backend, Config, Engine, Listener, UringConfig};
use only_http::{BodyEvent, Context, HttpConfig, Response, Router, Streaming, serve_with};

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
        .get("/", |ctx: &mut Context| ctx.text(200, "ok"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "text/plain", b);
        })
        .post(
            "/sum",
            Streaming(|ctx: &mut Context| {
                let mut n = 0;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => n += b.len(),
                    BodyEvent::End(_) => ctx.text(200, n.to_string()),
                });
            }),
        )
        .get("/slow", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(600));
                d.respond(Response::text(200, "slow"));
            });
        })
}

/// A server whose three deadlines are `head`, `idle` and `body` milliseconds.
fn start(head: u64, idle: u64, body: u64) -> Engine {
    let mut cfg = HttpConfig::default();
    cfg.head_timeout = Some(Duration::from_millis(head));
    cfg.keep_alive_timeout = Some(Duration::from_millis(idle));
    cfg.body_timeout = Some(Duration::from_millis(body));
    let e = Engine::builder()
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
        .unwrap();
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Everything until the server closes the connection.
fn read_to_eof(s: &mut TcpStream) -> String {
    let mut all = Vec::new();
    s.read_to_end(&mut all).expect("the server closes the connection");
    String::from_utf8_lossy(&all).into_owned()
}

/// Reads one response with a `Content-Length` body; returns the status line and the body.
fn read_resp(s: &mut TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).unwrap(), 1, "closed before a response head");
        buf.push(b[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (
        head.lines().next().unwrap().to_owned(),
        String::from_utf8(body).unwrap(),
    )
}

#[test]
fn a_head_trickled_byte_by_byte_gets_408() {
    let e = start(400, 10_000, 10_000);
    let mut s = connect(&e);
    let t0 = Instant::now();
    // The reader stops the writer as soon as the server answers.
    let answered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut r = s.try_clone().unwrap();
    let flag = answered.clone();
    let reader = thread::spawn(move || {
        let mut all = Vec::new();
        let mut b = [0u8; 256];
        while let Ok(n @ 1..) = r.read(&mut b) {
            all.extend_from_slice(&b[..n]);
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        String::from_utf8_lossy(&all).into_owned()
    });
    // One byte every 50 ms never completes the head, but always makes "progress".
    let req = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for b in req {
        if answered.load(std::sync::atomic::Ordering::SeqCst) || s.write_all(&[*b]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let rest = reader.join().unwrap();
    assert!(rest.starts_with("HTTP/1.1 408"), "{rest:?}");
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(400), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    stop(&e);
}

#[test]
fn a_slow_but_complete_head_within_the_timeout_is_served() {
    let e = start(600, 10_000, 10_000);
    let mut s = connect(&e);
    s.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    thread::sleep(Duration::from_millis(200));
    s.write_all(b"Host: x\r\n").unwrap();
    thread::sleep(Duration::from_millis(200));
    s.write_all(b"\r\n").unwrap();
    assert_eq!(read_resp(&mut s).1, "ok");
    // Each head gets its own allowance: a second slow head on the same connection is fine.
    s.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    thread::sleep(Duration::from_millis(400));
    s.write_all(b"Host: x\r\n\r\n").unwrap();
    assert_eq!(read_resp(&mut s).1, "ok");
    stop(&e);
}

#[test]
fn a_connection_that_never_sends_is_closed() {
    let e = start(300, 10_000, 10_000);
    let mut s = connect(&e);
    let t0 = Instant::now();
    read_to_eof(&mut s);
    assert!(t0.elapsed() >= Duration::from_millis(300));
    stop(&e);
}

#[test]
fn keep_alive_connections_close_when_idle() {
    let e = start(10_000, 300, 10_000);
    let mut s = connect(&e);
    // Requests just under the idle timeout apart keep the connection.
    for _ in 0..3 {
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(read_resp(&mut s).1, "ok");
        thread::sleep(Duration::from_millis(150));
    }
    let t0 = Instant::now();
    assert_eq!(read_to_eof(&mut s), "");
    assert!(t0.elapsed() >= Duration::from_millis(100), "{:?}", t0.elapsed());
    stop(&e);
}

#[test]
fn a_response_slower_than_the_idle_timeout_is_still_sent() {
    let e = start(10_000, 200, 10_000);
    let mut s = connect(&e);
    s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_resp(&mut s).1, "slow");
    assert_eq!(read_to_eof(&mut s), "");
    stop(&e);
}

#[test]
fn a_stalled_body_gets_408_and_a_moving_one_completes() {
    let e = start(10_000, 10_000, 300);
    let mut s = connect(&e);
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhalf.")
        .unwrap();
    let t0 = Instant::now();
    let rest = read_to_eof(&mut s);
    assert!(rest.starts_with("HTTP/1.1 408"), "{rest:?}");
    assert!(t0.elapsed() >= Duration::from_millis(300));

    // One byte every 100 ms: slower in total than the timeout, but never stalled for it.
    let mut s = connect(&e);
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\n")
        .unwrap();
    for b in b"abcdef" {
        thread::sleep(Duration::from_millis(100));
        s.write_all(&[*b]).unwrap();
    }
    assert_eq!(read_resp(&mut s).1, "abcdef");

    // Chunked, streamed to the service: a stall cuts the connection.
    let mut s = connect(&e);
    s.write_all(b"POST /sum HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
        .unwrap();
    let t0 = Instant::now();
    read_to_eof(&mut s);
    assert!(t0.elapsed() >= Duration::from_millis(300));
    stop(&e);
}

#[test]
fn a_connection_cut_midway_through_a_head_is_cleaned_up() {
    let e = start(300, 300, 300);
    for _ in 0..20 {
        let mut s = connect(&e);
        s.write_all(b"GET / HTTP/1.1\r\nHo").unwrap();
        drop(s);
    }
    // The server keeps serving, and the deadlines of the closed connections fire harmlessly.
    thread::sleep(Duration::from_millis(500));
    let mut s = connect(&e);
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_resp(&mut s).1, "ok");
    stop(&e);
}
