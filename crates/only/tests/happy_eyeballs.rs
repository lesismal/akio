//! Happy Eyeballs v2 (RFC 8305, ADR-059): racing addresses on the engine, with an IPv6
//! "black hole" (a listener whose accept queue is full drops SYNs: the connect hangs).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use only::{Conn, Engine, Handler, dns::HappyEyeballs, fn_acceptor};

struct Nop;
impl Handler for Nop {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

/// A listening socket nobody accepts from, with its queue full, so that further connects
/// hang. `None` when the system answers them anyway (or `addr` is not available).
fn black_hole(addr: &str) -> Option<(TcpListener, Vec<TcpStream>, SocketAddr)> {
    let l = only_sys::listen(addr.parse().ok()?, false, 1).ok()?;
    let at = l.local_addr().ok()?;
    let mut held = Vec::new();
    for _ in 0..16 {
        if let Ok(s) = only_sys::connect_nonblocking(at) {
            held.push(s);
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    match TcpStream::connect_timeout(&at, Duration::from_millis(400)) {
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Some((l, held, at)),
        _ => None,
    }
}

type Seen = mpsc::Receiver<Result<SocketAddr, std::io::Error>>;

fn race(engine: &Arc<Engine>, he: HappyEyeballs, addrs: Vec<SocketAddr>) -> (Seen, Instant) {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let t2 = tx.clone();
    let start = Instant::now();
    he.dial(
        engine,
        addrs,
        fn_acceptor(move |c: &Conn<Nop>| {
            let _ = tx.lock().unwrap().send(Ok(c.peer_addr()));
            c.close();
            Nop
        }),
        move |e| {
            let _ = t2.lock().unwrap().send(Err(e));
        },
    );
    (rx, start)
}

/// A real black hole where the system makes one (Linux), else the racer's simulated one
/// (macOS answers a full accept queue).
fn ipv6_black_hole() -> (Option<(TcpListener, Vec<TcpStream>)>, SocketAddr) {
    if let Some((l, held, at)) = black_hole("[::1]:0") {
        return (Some((l, held)), at);
    }
    let at: SocketAddr = "[::1]:9".parse().unwrap();
    only::dns::black_hole(at);
    (None, at)
}

#[test]
fn falls_back_from_an_ipv6_black_hole() {
    let (real, hole) = ipv6_black_hole();
    eprintln!("black hole at {hole} (real: {})", real.is_some());
    let good = TcpListener::bind("127.0.0.1:0").unwrap();
    let good_addr = good.local_addr().unwrap();
    let e = engine();
    let (rx, start) = race(&e, HappyEyeballs::default(), vec![hole, good_addr]);
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    let took = start.elapsed();
    assert_eq!(got, good_addr);
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_millis(1500),
        "IPv4 went after the attempt delay: {took:?}"
    );
    // Only the winner reached the server.
    let (_s, from) = good.accept().unwrap();
    assert!(from.is_ipv4());
    // A shorter delay goes sooner.
    let mut he = HappyEyeballs::default();
    he.attempt_delay = Duration::from_millis(50);
    let (rx, start) = race(&e, he, vec![hole, good_addr]);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        good_addr
    );
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "{:?}",
        start.elapsed()
    );
    // Every address a black hole: each attempt times out, then the error.
    let mut he = HappyEyeballs::default();
    he.attempt_delay = Duration::from_millis(20);
    he.connect_timeout = Duration::from_millis(300);
    let (rx, start) = race(&e, he, vec![hole, hole]);
    let err = rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() >= Duration::from_millis(300));
}

#[test]
fn a_refused_address_moves_on_at_once() {
    // A port nobody listens on (bound, then closed).
    let closed = {
        let l = TcpListener::bind("[::1]:0")
            .or_else(|_| TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        l.local_addr().unwrap()
    };
    let good = TcpListener::bind("127.0.0.1:0").unwrap();
    let good_addr = good.local_addr().unwrap();
    let e = engine();
    let (rx, start) = race(&e, HappyEyeballs::default(), vec![closed, good_addr]);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        good_addr
    );
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "no attempt delay after a refusal: {:?}",
        start.elapsed()
    );
    // All refused: the last error.
    let (rx, _) = race(&e, HappyEyeballs::default(), vec![closed, closed]);
    let err = rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    // None at all.
    let (rx, _) = race(&e, HappyEyeballs::default(), Vec::new());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn many_races_at_once() {
    let good = TcpListener::bind("127.0.0.1:0").unwrap();
    let good_addr = good.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in good.incoming() {
            drop(s);
        }
    });
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let e = engine();
    // More than the racer takes at once: the rest are dialed in turn by the engine.
    let n = only::dns::MAX_RACES + 64;
    let rxs: Vec<_> = (0..n)
        .map(|_| race(&e, HappyEyeballs::default(), vec![closed, good_addr]).0)
        .collect();
    for rx in rxs {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(20)).unwrap().unwrap(),
            good_addr
        );
    }
}

#[test]
fn connect_resolves_then_races() {
    let good = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = good.local_addr().unwrap().port();
    let e = engine();
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let t2 = tx.clone();
    HappyEyeballs::default().connect(
        &e,
        "localhost",
        port,
        fn_acceptor(move |c: &Conn<Nop>| {
            let _ = tx.lock().unwrap().send(Ok(c.peer_addr()));
            Nop
        }),
        move |err| {
            let _ = t2.lock().unwrap().send(Err(err));
        },
    );
    let got = rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
    assert_eq!(got, SocketAddr::new([127, 0, 0, 1].into(), port));
}
