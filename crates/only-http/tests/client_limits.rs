//! The HTTP/1 client's limits against scripted (malicious or broken) servers: response head and
//! body caps, request timeouts, slow trickles, servers that never answer, and the idle pool.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::Engine;
use only_http::client::{Client, ClientError, ClientOptions, ClientRequest};

fn engine() -> Arc<Engine> {
    let e = Engine::builder().client_threads(2).build().unwrap();
    e.start().unwrap();
    Arc::new(e)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// A server that runs `script` on every accepted connection (each on its own thread) and counts
/// connections.
struct Server {
    addr: String,
    conns: Arc<AtomicUsize>,
    /// Connections whose script returned.
    done: Arc<AtomicUsize>,
}

impl Server {
    fn wait_done(&self, n: usize) -> usize {
        let t0 = Instant::now();
        while self.done.load(Ordering::SeqCst) < n && t0.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }
        self.done.load(Ordering::SeqCst)
    }
}

fn server(script: impl Fn(TcpStream) + Send + Sync + 'static) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", l.local_addr().unwrap());
    let conns = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let (n, d, script) = (conns.clone(), done.clone(), Arc::new(script));
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            n.fetch_add(1, Ordering::SeqCst);
            let (script, d) = (script.clone(), d.clone());
            thread::spawn(move || {
                script(s);
                d.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Server { addr, conns, done }
}

/// Reads one request head; false once the client hung up.
fn read_head(s: &mut TcpStream) -> bool {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => got.push(b[0]),
            _ => return false,
        }
    }
    true
}

/// Waits until the client closes the connection (read returns EOF or an error).
fn wait_closed(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) => return e.kind() != std::io::ErrorKind::WouldBlock,
        }
    }
}

fn client(e: &Arc<Engine>, f: impl FnOnce(&mut ClientOptions)) -> Client {
    let mut o = ClientOptions::default();
    f(&mut o);
    Client::new(e.clone()).with_options(o)
}

fn get(c: &Client, url: &str) -> Result<only_http::client::ClientResponse, ClientError> {
    c.send(ClientRequest::get(url))
        .wait_timeout(Duration::from_secs(10))
        .expect("the client must answer by itself")
}

#[test]
fn defaults_are_bounded() {
    let o = ClientOptions::default();
    assert_eq!(o.max_head_bytes, 64 << 10);
    assert_eq!(o.max_body_bytes, 64 << 20);
    assert_eq!(o.request_timeout, Some(Duration::from_secs(30)));
    assert_eq!(o.idle_timeout, Some(Duration::from_secs(90)));
    assert_eq!((o.max_idle_per_host, o.max_idle), (32, 256));
}

/// A head of exactly `len` bytes (status line, one padding field, empty line).
fn head_of(len: usize) -> Vec<u8> {
    let fixed = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: \r\n\r\n".len();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(len - fixed)
    )
    .into_bytes()
}

#[test]
fn response_head_limit_under_at_and_over() {
    const MAX: usize = 1024;
    for (len, ok) in [(MAX - 1, true), (MAX, true), (MAX + 1, false)] {
        let srv = server(move |mut s| {
            if read_head(&mut s) {
                let _ = s.write_all(&head_of(len));
            }
            wait_closed(&mut s);
        });
        let e = engine();
        let c = client(&e, |o| o.max_head_bytes = MAX);
        let r = get(&c, &format!("{}/", srv.addr));
        if ok {
            assert_eq!(r.unwrap().status, 200, "len {len}");
        } else {
            assert!(
                matches!(r, Err(ClientError::TooLarge(_))),
                "len {len}: {r:?}"
            );
        }
        stop(&e);
    }
}

#[test]
fn endless_head_and_endless_interim_responses_end() {
    // Header fields that never end.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nX-Flood: ");
            while s.write_all(&[b'a'; 1024]).is_ok() {}
        }
    });
    let e = engine();
    let c = client(&e, |_| {});
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    // 100 Continue, forever: every interim head counts toward the limit.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            while s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_ok() {}
        }
    });
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    stop(&e);
}

#[test]
fn body_limit_for_every_framing() {
    const MAX: usize = 4096;
    let e = engine();
    let c = client(&e, |o| o.max_body_bytes = MAX);
    // Content-Length: just under, at, over (refused before the body arrives).
    for (len, ok) in [(MAX - 1, true), (MAX, true), (MAX + 1, false)] {
        let srv = server(move |mut s| {
            if read_head(&mut s) {
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").as_bytes(),
                );
                let _ = s.write_all(&vec![b'x'; len]);
            }
            wait_closed(&mut s);
        });
        let r = get(&c, &format!("{}/", srv.addr));
        if ok {
            assert_eq!(r.unwrap().body.len(), len);
        } else {
            assert!(matches!(r, Err(ClientError::TooLarge(_))), "{len}: {r:?}");
        }
    }
    // A huge declared length fails at once, without waiting for (or buffering) the body.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n");
        }
        wait_closed(&mut s);
    });
    let t0 = Instant::now();
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    assert!(t0.elapsed() < Duration::from_secs(2));
    // Chunked: at the limit, then an endless chunked body.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let _ = s.write_all(format!("{MAX:x}\r\n").as_bytes());
            let _ = s.write_all(&[b'y'; MAX]);
            let _ = s.write_all(b"\r\n0\r\n\r\n");
        }
        wait_closed(&mut s);
    });
    assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body.len(), MAX);
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            while s.write_all(b"400\r\n").is_ok() && s.write_all(&[b'z'; 0x400]).is_ok() {
                if s.write_all(b"\r\n").is_err() {
                    break;
                }
            }
        }
    });
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TooLarge(_))), "{r:?}");
    // Close-delimited: at the limit, then over it.
    for (len, ok) in [(MAX, true), (MAX + 1, false)] {
        let srv = server(move |mut s| {
            if read_head(&mut s) {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(&vec![b'w'; len]);
            }
        });
        let r = get(&c, &format!("{}/", srv.addr));
        if ok {
            assert_eq!(r.unwrap().body.len(), len);
        } else {
            assert!(matches!(r, Err(ClientError::TooLarge(_))), "{len}: {r:?}");
        }
    }
    stop(&e);
}

#[test]
fn request_timeout_ends_silent_and_trickling_servers() {
    // Never answers: the request fails with TimedOut and the connection is closed.
    let closed = Arc::new(AtomicUsize::new(0));
    let cl = closed.clone();
    let srv = server(move |mut s| {
        if read_head(&mut s) && wait_closed(&mut s) {
            cl.fetch_add(1, Ordering::SeqCst);
        }
    });
    let e = engine();
    let c = client(&e, |o| o.request_timeout = Some(Duration::from_millis(300)));
    let t0 = Instant::now();
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TimedOut)), "{r:?}");
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "{took:?}"
    );
    let t0 = Instant::now();
    while closed.load(Ordering::SeqCst) == 0 && t0.elapsed() < Duration::from_secs(3) {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        closed.load(Ordering::SeqCst),
        1,
        "the timed-out connection is closed"
    );

    // A slow trickle (one head byte every 20 ms) cannot keep a request alive past its timeout.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            for b in b"HTTP/1.1 200 OK\r\nX-Slow: "
                .iter()
                .chain([b'a'; 1000].iter())
            {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    });
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::TimedOut)), "{r:?}");

    // The per-request timeout overrides the client's (here: none at all on the client).
    let srv = server(|mut s| {
        if read_head(&mut s) {
            wait_closed(&mut s);
        }
    });
    let c = client(&e, |o| o.request_timeout = None);
    let t0 = Instant::now();
    let r = c
        .send(ClientRequest::get(&format!("{}/", srv.addr)).timeout(Duration::from_millis(150)))
        .wait_timeout(Duration::from_secs(10))
        .unwrap();
    assert!(matches!(r, Err(ClientError::TimedOut)), "{r:?}");
    assert!(t0.elapsed() < Duration::from_secs(3));

    // A response that arrives in time is not affected, and its connection is reused (the
    // finished request's deadline does not fire on the next one).
    let srv = server(|mut s| {
        while read_head(&mut s) {
            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .is_err()
            {
                return;
            }
        }
    });
    let c = client(&e, |o| o.request_timeout = Some(Duration::from_millis(200)));
    for _ in 0..3 {
        assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
        thread::sleep(Duration::from_millis(120));
    }
    assert_eq!(srv.conns.load(Ordering::SeqCst), 1);
    stop(&e);
}

fn keep_alive_server(delay: Duration) -> Server {
    server(move |mut s| {
        while read_head(&mut s) {
            thread::sleep(delay);
            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .is_err()
            {
                return;
            }
        }
    })
}

#[test]
fn idle_pool_is_capped_per_host_and_expires() {
    let e = engine();
    // One idle connection per host: of 4 parallel requests' connections, 1 is kept.
    let srv = keep_alive_server(Duration::from_millis(100));
    let c = client(&e, |o| o.max_idle_per_host = 1);
    let futs: Vec<_> = (0..4)
        .map(|_| c.send(ClientRequest::get(&format!("{}/", srv.addr))))
        .collect();
    for f in futs {
        assert_eq!(f.wait().unwrap().body, b"ok");
    }
    assert_eq!(srv.conns.load(Ordering::SeqCst), 4);
    assert_eq!(
        srv.wait_done(3),
        3,
        "the 3 connections over the cap were closed"
    );
    for _ in 0..3 {
        assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    }
    assert_eq!(
        srv.conns.load(Ordering::SeqCst),
        4,
        "the kept one was reused"
    );

    // max_idle_per_host 0: no reuse at all.
    let srv = keep_alive_server(Duration::ZERO);
    let c = client(&e, |o| o.max_idle_per_host = 0);
    for _ in 0..3 {
        assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    }
    assert_eq!(srv.conns.load(Ordering::SeqCst), 3);

    // The total cap applies across hosts.
    let (a, b) = (
        keep_alive_server(Duration::ZERO),
        keep_alive_server(Duration::ZERO),
    );
    let c = client(&e, |o| o.max_idle = 1);
    for _ in 0..2 {
        assert_eq!(get(&c, &format!("{}/", a.addr)).unwrap().body, b"ok");
        assert_eq!(get(&c, &format!("{}/", b.addr)).unwrap().body, b"ok");
    }
    assert_eq!(
        a.conns.load(Ordering::SeqCst) + b.conns.load(Ordering::SeqCst),
        3,
        "only a's first connection stays pooled"
    );

    // Idle connections are closed after idle_timeout, even if the client is never used again.
    let closed = Arc::new(AtomicUsize::new(0));
    let cl = closed.clone();
    let srv = server(move |mut s| {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        while read_head(&mut s) {
            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .is_err()
            {
                return;
            }
        }
        cl.fetch_add(1, Ordering::SeqCst);
    });
    let c = client(&e, |o| o.idle_timeout = Some(Duration::from_millis(200)));
    assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    let t0 = Instant::now();
    while closed.load(Ordering::SeqCst) == 0 && t0.elapsed() < Duration::from_secs(4) {
        thread::sleep(Duration::from_millis(10));
    }
    let took = t0.elapsed();
    assert_eq!(
        closed.load(Ordering::SeqCst),
        1,
        "the idle connection was closed"
    );
    assert!(took >= Duration::from_millis(150), "{took:?}");
    // The next request dials anew.
    assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    assert_eq!(srv.conns.load(Ordering::SeqCst), 2);
    stop(&e);
}

#[test]
fn connection_cut_midway_and_closed_idle_connections() {
    let e = engine();
    let c = client(&e, |_| {});
    // Cut in the middle of a Content-Length body: Closed.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhalf");
        }
    });
    let r = get(&c, &format!("{}/", srv.addr));
    assert!(matches!(r, Err(ClientError::Closed)), "{r:?}");
    // The server closes a pooled connection: it leaves the pool, the next request dials anew.
    let srv = server(|mut s| {
        if read_head(&mut s) {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
        // closes right after the first response
    });
    assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(get(&c, &format!("{}/", srv.addr)).unwrap().body, b"ok");
    assert_eq!(srv.conns.load(Ordering::SeqCst), 2);
    stop(&e);
}
