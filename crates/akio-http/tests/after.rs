//! `Context::after` (ADR-099): delayed answers from the connection's own I/O thread. HTTP/1.1 and
//! h2c over real sockets, on the native backend (and io_uring with AKIO_TEST_BACKEND=uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Response, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve,
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

struct Counts {
    same: AtomicUsize,
    other: AtomicUsize,
    refused: AtomicUsize,
}

fn start() -> (Engine, Arc<Counts>) {
    let n = Arc::new(Counts {
        same: AtomicUsize::new(0),
        other: AtomicUsize::new(0),
        refused: AtomicUsize::new(0),
    });
    let (n1, n2) = (n.clone(), n.clone());
    let router = Router::new()
        .get("/delay/:ms", move |ctx: &mut Context| {
            let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
            let on = thread::current().id();
            let n = n1.clone();
            assert!(ctx.after(Duration::from_millis(ms), move |d| {
                let c = if thread::current().id() == on {
                    &n.same
                } else {
                    &n.other
                };
                c.fetch_add(1, Ordering::Relaxed);
                let body = d.param("ms").unwrap().to_owned();
                d.respond(Response::text(200, body));
            }));
        })
        .get("/twice", move |ctx: &mut Context| {
            ctx.text(200, "now");
            if !ctx.after(Duration::ZERO, |d| d.respond(Response::text(200, "late"))) {
                n2.refused.fetch_add(1, Ordering::Relaxed);
            }
        });
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
    (e, n)
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads `n` Content-Length framed responses; returns their bodies.
fn read_bodies(s: &mut TcpStream, n: usize) -> Vec<String> {
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    while out.len() < n {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            if buf.len() >= end + 4 + len {
                assert!(head.starts_with("http/1.1 200"), "{head}");
                out.push(String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).into_owned());
                buf.drain(..end + 4 + len);
                continue;
            }
        }
        let k = s.read(&mut b).unwrap();
        assert!(k > 0, "closed early");
        buf.extend_from_slice(&b[..k]);
    }
    out
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")
}

#[test]
fn delayed_answers_keep_pipelined_order() {
    let (e, n) = start();
    let mut s = connect(e.local_addrs()[0]);
    let t0 = Instant::now();
    let req = [get("/delay/40"), get("/delay/0"), get("/delay/10")].concat();
    s.write_all(req.as_bytes()).unwrap();
    assert_eq!(read_bodies(&mut s, 3), ["40", "0", "10"]);
    assert!(t0.elapsed() >= Duration::from_millis(40));
    assert_eq!(n.same.load(Ordering::Relaxed), 3);
    assert_eq!(n.other.load(Ordering::Relaxed), 0);
    e.shutdown();
    e.wait();
}

#[test]
fn many_connections_wait_at_once() {
    let (e, n) = start();
    let addr = e.local_addrs()[0];
    let t0 = Instant::now();
    let conns: Vec<_> = (0..64)
        .map(|_| {
            let mut s = connect(addr);
            s.write_all(get("/delay/50").as_bytes()).unwrap();
            s
        })
        .collect();
    for mut s in conns {
        assert_eq!(read_bodies(&mut s, 1), ["50"]);
    }
    // All 64 waited concurrently, not one after another.
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert_eq!(n.same.load(Ordering::Relaxed), 64);
    e.shutdown();
    e.wait();
}

#[test]
fn after_a_response_was_sent_is_refused() {
    let (e, n) = start();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all([get("/twice"), get("/delay/1")].concat().as_bytes())
        .unwrap();
    assert_eq!(read_bodies(&mut s, 2), ["now", "1"]);
    assert_eq!(n.refused.load(Ordering::Relaxed), 1);
    e.shutdown();
    e.wait();
}

#[test]
fn client_gone_before_the_answer() {
    let (e, n) = start();
    let addr = e.local_addrs()[0];
    for _ in 0..8 {
        let mut s = connect(addr);
        s.write_all(get("/delay/30").as_bytes()).unwrap();
    }
    thread::sleep(Duration::from_millis(100));
    let mut s = connect(addr);
    s.write_all(get("/delay/1").as_bytes()).unwrap();
    assert_eq!(read_bodies(&mut s, 1), ["1"]);
    assert_eq!(n.same.load(Ordering::Relaxed), 9);
    e.shutdown();
    e.wait();
}

#[test]
fn h2c_streams_are_answered_later_too() {
    let (e, n) = start();
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let t0 = Instant::now();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/delay/30")))
        .wait()
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"30");
    assert!(t0.elapsed() >= Duration::from_millis(30));
    assert_eq!(n.same.load(Ordering::Relaxed), 1);
    e.shutdown();
    e.wait();
}
