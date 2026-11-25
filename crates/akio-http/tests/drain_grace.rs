//! Idle HTTP/1 connections drained after a grace (`HttpConfig::idle_drain_grace`, akit A54): a
//! request that arrives in the grace is answered with `Connection: close`, one partly received
//! when the drain starts too, an idle connection closes at the end of the grace (capped by the
//! drain's deadline), and a grace of zero closes it at once, as before.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{Context, HttpConfig, Router, serve_with};

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

fn start(grace: Duration) -> Arc<Engine> {
    let app = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hi"));
    let mut cfg = HttpConfig::default();
    cfg.idle_drain_grace = grace;
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_secs(5);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(cfg, app)),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    Arc::new(e)
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads one response: its status, its `Connection` header (lowercase) and its body.
fn read_resp(s: &mut TcpStream) -> (u16, Option<String>, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = loop {
            match s.read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                r => break r.expect("read response head"),
            }
        };
        assert!(
            n > 0,
            "closed mid-head: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status = head[9..12].parse().unwrap();
    let mut len = 0;
    let mut conn = None;
    for l in head.split("\r\n").skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap();
            } else if k.eq_ignore_ascii_case("connection") {
                conn = Some(v.trim().to_ascii_lowercase());
            }
        }
    }
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (status, conn, String::from_utf8(body).unwrap())
}

/// Whether the peer closed the connection (EOF or reset) within the read timeout.
fn closed(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(0) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return true,
            _ => return false,
        }
    }
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// A keep-alive connection that already served a request: idle now.
fn idle_conn(addr: SocketAddr) -> TcpStream {
    let mut s = connect(addr);
    s.write_all(GET).unwrap();
    let (status, conn, _) = read_resp(&mut s);
    assert_eq!((status, conn), (200, None));
    s
}

/// Drains the engine's listener on another thread (`shutdown_listener` waits for its threads to
/// stop listening) and returns when it started.
fn drain(e: &Arc<Engine>, deadline: Duration) -> thread::JoinHandle<()> {
    let id = e.listeners()[0].id;
    let e2 = e.clone();
    let h = thread::spawn(move || e2.shutdown_listener(id, deadline).unwrap());
    // `on_shutdown` reaches the connection's loop right away; give it the time to.
    thread::sleep(Duration::from_millis(50));
    h
}

#[test]
fn a_request_sent_just_after_the_drain_starts_is_answered_with_connection_close() {
    let e = start(Duration::from_secs(2));
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    let h = drain(&e, Duration::from_secs(5));
    s.write_all(GET).unwrap();
    let (status, conn, body) = read_resp(&mut s);
    assert_eq!(
        (status, conn.as_deref(), body.as_str()),
        (200, Some("close"), "hi")
    );
    assert!(closed(&mut s), "closed after the response");
    h.join().unwrap();
    e.shutdown();
    e.wait();
}

#[test]
fn a_request_partly_received_when_the_drain_starts_is_answered() {
    let e = start(Duration::from_millis(100));
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    s.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    thread::sleep(Duration::from_millis(20));
    let h = drain(&e, Duration::from_secs(5));
    // Past the grace: the half-received request made the connection busy.
    thread::sleep(Duration::from_millis(300));
    s.write_all(b"Host: x\r\n\r\n").unwrap();
    let (status, conn, _) = read_resp(&mut s);
    assert_eq!((status, conn.as_deref()), (200, Some("close")));
    assert!(closed(&mut s));
    h.join().unwrap();
    e.shutdown();
    e.wait();
}

#[test]
fn requests_already_received_when_the_drain_starts_are_answered() {
    let e = start(Duration::from_millis(300));
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    let id = e.listeners()[0].id;
    // The request and the drain race: whichever comes first, the request is answered.
    s.write_all(GET).unwrap();
    e.shutdown_listener(id, Duration::from_secs(5)).unwrap();
    let (status, _, body) = read_resp(&mut s);
    assert_eq!((status, body.as_str()), (200, "hi"));
    assert!(closed(&mut s));
    e.shutdown();
    e.wait();
}

#[test]
fn an_idle_connection_closes_at_the_end_of_the_grace() {
    let grace = Duration::from_millis(400);
    let e = start(grace);
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    // A connection that never sent anything is idle too.
    let mut fresh = connect(a);
    let t = Instant::now();
    let h = drain(&e, Duration::from_secs(5));
    assert!(closed(&mut s), "closed at the end of the grace");
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(350),
        "not before the grace: {took:?}"
    );
    assert!(
        took < Duration::from_secs(3),
        "long before the deadline: {took:?}"
    );
    assert!(closed(&mut fresh));
    h.join().unwrap();
    e.shutdown();
    e.wait();
}

#[test]
fn the_drain_deadline_caps_the_grace() {
    let e = start(Duration::from_secs(30));
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    let t = Instant::now();
    let h = drain(&e, Duration::from_millis(300));
    assert!(closed(&mut s));
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    h.join().unwrap();
    e.shutdown();
    e.wait();
}

#[test]
fn a_grace_of_zero_closes_an_idle_connection_at_once() {
    let e = start(Duration::ZERO);
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    let t = Instant::now();
    let h = drain(&e, Duration::from_secs(10));
    assert!(closed(&mut s));
    // Long before the drain's deadline: closed when the drain began.
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    h.join().unwrap();
    e.shutdown();
    e.wait();
}

#[test]
fn an_engine_shutdown_drains_with_the_grace_too() {
    let e = start(Duration::from_secs(2));
    let a = e.local_addrs()[0];
    let mut s = idle_conn(a);
    e.shutdown();
    thread::sleep(Duration::from_millis(50));
    s.write_all(GET).unwrap();
    let (status, conn, _) = read_resp(&mut s);
    assert_eq!((status, conn.as_deref()), (200, Some("close")));
    assert!(closed(&mut s));
    e.wait();
}
