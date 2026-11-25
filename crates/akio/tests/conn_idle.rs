//! An idle timeout per connection (ADR-155, akit A78): `Conn::set_idle_timeout` and
//! `Conn::set_idle_counts_writes`, for TCP connections (on the backend under test: epoll/kqueue,
//! io_uring with `AKIO_TEST_BACKEND=uring`, rounds with `AKIO_DEFAULT_SCHEDULING=rounds`) and UDP
//! peers (the UDP loop: listener peers and dialed connections).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn cfg(idle: Option<Duration>) -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v.idle_timeout = idle;
    v
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(10), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// What the connections of a test did: opened (in order) and closed (id, error kind).
#[derive(Default)]
struct Rec {
    conns: Mutex<Vec<Conn<H>>>,
    closed: Mutex<Vec<(u64, Option<ErrorKind>)>>,
}

impl Rec {
    fn conn(&self, i: usize) -> Conn<H> {
        self.conns.lock().unwrap()[i].clone()
    }
    fn opened(&self) -> usize {
        self.conns.lock().unwrap().len()
    }
    /// How connection `id` closed: `None` while open, `Some(kind)` once closed.
    fn closed(&self, id: u64) -> Option<Option<ErrorKind>> {
        self.closed
            .lock()
            .unwrap()
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, k)| *k)
    }
}

struct H(Arc<Rec>);

impl Handler for H {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
    fn on_close(&mut self, c: &Conn<Self>, err: Option<Error>) {
        let kind = match err {
            Some(Error::Io(e)) => Some(e.kind()),
            _ => None,
        };
        self.0.closed.lock().unwrap().push((c.id(), kind));
    }
}

/// A TCP engine on the backend under test whose acceptor records its connections and runs
/// `setup` on each in `on_open`.
fn tcp_engine(
    idle: Option<Duration>,
    rec: &Arc<Rec>,
    setup: impl Fn(usize, &Conn<H>) + Send + Sync + 'static,
) -> Engine {
    let r = rec.clone();
    let e = Engine::builder()
        .config(cfg(idle))
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(move |c: &Conn<H>| {
                    let i = {
                        let mut v = r.conns.lock().unwrap();
                        v.push(c.clone());
                        v.len() - 1
                    };
                    setup(i, c);
                    H(r.clone())
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn own_idle_timeout_shorter_than_the_engines_closes() {
    let rec = Arc::new(Rec::default());
    // The engine's is long; the connection's own (set in `on_open`, on its I/O thread) short.
    let e = tcp_engine(Some(Duration::from_secs(30)), &rec, |_, c| {
        c.set_idle_timeout(Some(Duration::from_millis(200)))
            .unwrap();
    });
    let t0 = Instant::now();
    let mut s = connect(e.local_addrs()[0]);
    // Some traffic first: the timeout counts from the last of it.
    s.write_all(b"hi").unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(
        common::read_retry(&mut s, &mut b).unwrap(),
        0,
        "closed by the idle timeout"
    );
    assert!(
        t0.elapsed() >= Duration::from_millis(180),
        "{:?}",
        t0.elapsed()
    );
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    let id = rec.conn(0).id();
    wait_for("on_close", || rec.closed(id).is_some());
    assert_eq!(rec.closed(id), Some(Some(ErrorKind::TimedOut)));
    // A closed connection says so.
    assert!(matches!(
        rec.conn(0).set_idle_timeout(None),
        Err(Error::Closed)
    ));
    stop(&e);
}

#[test]
fn none_keeps_an_idle_connection_open_against_the_engines_timeout() {
    let rec = Arc::new(Rec::default());
    // Connection 0 turns the engine's 200 ms off; connection 1 keeps it.
    let e = tcp_engine(Some(Duration::from_millis(200)), &rec, |i, c| {
        if i == 0 {
            c.set_idle_timeout(None).unwrap();
        }
    });
    let addr = e.local_addrs()[0];
    let mut kept = connect(addr);
    wait_for("first open", || rec.opened() == 1);
    let mut timed = connect(addr);
    wait_for("second open", || rec.opened() == 2);
    let mut b = [0u8; 1];
    assert_eq!(common::read_retry(&mut timed, &mut b).unwrap(), 0);
    let timed_id = rec.conn(1).id();
    wait_for("on_close", || rec.closed(timed_id).is_some());
    assert_eq!(rec.closed(timed_id), Some(Some(ErrorKind::TimedOut)));
    thread::sleep(Duration::from_millis(600));
    // Still served, three timeouts later.
    kept.write_all(b"k").unwrap();
    kept.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"k");
    assert_eq!(rec.closed(rec.conn(0).id()), None);
    stop(&e);
}

#[test]
fn counting_writes_keeps_a_connection_that_only_sends_open() {
    let rec = Arc::new(Rec::default());
    let e = tcp_engine(None, &rec, |_, _| {});
    let addr = e.local_addrs()[0];
    let mut counted = connect(addr);
    wait_for("first open", || rec.opened() == 1);
    let mut uncounted = connect(addr);
    wait_for("second open", || rec.opened() == 2);
    let (a, b) = (rec.conn(0), rec.conn(1));
    // Set from another thread than the connections' own.
    for c in [&a, &b] {
        c.set_idle_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    a.set_idle_counts_writes(true).unwrap();
    // The server sends every 40 ms; the clients never do.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(1200) {
        let _ = a.send(b".");
        let _ = b.send(b".");
        thread::sleep(Duration::from_millis(40));
    }
    assert_eq!(rec.closed(a.id()), None, "writes count as activity");
    assert_eq!(
        rec.closed(b.id()),
        Some(Some(ErrorKind::TimedOut)),
        "writes alone are not activity by default"
    );
    // Once it stops sending, it is idle: closed after the timeout (and at most an eighth more).
    let stopped = Instant::now();
    wait_for("idle after the last write", || rec.closed(a.id()).is_some());
    assert_eq!(rec.closed(a.id()), Some(Some(ErrorKind::TimedOut)));
    assert!(
        stopped.elapsed() >= Duration::from_millis(250),
        "{:?}",
        stopped.elapsed()
    );
    // What the clients got: dots, then the close.
    let mut buf = [0u8; 256];
    let mut got = 0;
    loop {
        match common::read_retry(&mut counted, &mut buf) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(got >= 20, "{got}");
    drop(uncounted.write_all(b"x"));
    stop(&e);
}

#[test]
fn counting_writes_applies_to_the_engines_timeout_too() {
    let rec = Arc::new(Rec::default());
    let e = tcp_engine(Some(Duration::from_millis(300)), &rec, |_, c| {
        c.set_idle_counts_writes(true).unwrap();
    });
    let _client = connect(e.local_addrs()[0]);
    wait_for("open", || rec.opened() == 1);
    let a = rec.conn(0);
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(900) {
        let _ = a.send(b".");
        thread::sleep(Duration::from_millis(40));
    }
    assert_eq!(rec.closed(a.id()), None);
    wait_for("idle", || rec.closed(a.id()).is_some());
    assert_eq!(rec.closed(a.id()), Some(Some(ErrorKind::TimedOut)));
    stop(&e);
}

// ---- UDP peers -------------------------------------------------------------------------------

fn udp_client(server: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn udp_engine(
    udp_idle: Duration,
    rec: &Arc<Rec>,
    setup: impl Fn(usize, &Conn<H>) + Send + Sync + 'static,
) -> Engine {
    let r = rec.clone();
    let e = Engine::builder()
        .config({
            let mut v = cfg(None);
            v.udp_idle_timeout = udp_idle;
            v
        })
        .udp_client_threads(1)
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(move |c: &Conn<H>| {
                    let i = {
                        let mut v = r.conns.lock().unwrap();
                        v.push(c.clone());
                        v.len() - 1
                    };
                    setup(i, c);
                    H(r.clone())
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn udp_peers_have_idle_timeouts_of_their_own() {
    let rec = Arc::new(Rec::default());
    // Engine: 400 ms. Peer 0: 100 ms of its own; peer 1: none; peer 2: the engine's.
    let e = udp_engine(Duration::from_millis(400), &rec, |i, c| match i {
        0 => c
            .set_idle_timeout(Some(Duration::from_millis(100)))
            .unwrap(),
        1 => c.set_idle_timeout(None).unwrap(),
        _ => {}
    });
    let addr = e.local_addrs()[0];
    let clients: Vec<UdpSocket> = (0..3).map(|_| udp_client(addr)).collect();
    let mut b = [0u8; 16];
    for (i, c) in clients.iter().enumerate() {
        c.send(b"hi").unwrap();
        assert_eq!(c.recv(&mut b).unwrap(), 2);
        wait_for("peer open", || rec.opened() == i + 1);
    }
    let t0 = Instant::now();
    let id0 = rec.conn(0).id();
    wait_for("own timeout", || rec.closed(id0).is_some());
    assert_eq!(rec.closed(id0), Some(Some(ErrorKind::TimedOut)));
    assert!(
        t0.elapsed() < Duration::from_millis(350),
        "{:?}",
        t0.elapsed()
    );
    let id2 = rec.conn(2).id();
    wait_for("engine's timeout", || rec.closed(id2).is_some());
    thread::sleep(Duration::from_millis(500));
    // Peer 1 outlived the engine's timeout and still answers on the same connection.
    let id1 = rec.conn(1).id();
    assert_eq!(rec.closed(id1), None);
    clients[1].send(b"again").unwrap();
    assert_eq!(clients[1].recv(&mut b).unwrap(), 5);
    assert_eq!(rec.opened(), 3, "no new peer: the old one answered");
    stop(&e);
}

#[test]
fn udp_peer_counting_writes_stays_open_while_it_sends() {
    let rec = Arc::new(Rec::default());
    let e = udp_engine(Duration::from_secs(30), &rec, |_, c| {
        c.set_idle_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        c.set_idle_counts_writes(true).unwrap();
    });
    let client = udp_client(e.local_addrs()[0]);
    client.send(b"hi").unwrap();
    let mut b = [0u8; 16];
    assert_eq!(client.recv(&mut b).unwrap(), 2);
    wait_for("open", || rec.opened() == 1);
    let a = rec.conn(0);
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(900) {
        a.send(b".").unwrap();
        thread::sleep(Duration::from_millis(40));
    }
    assert_eq!(rec.closed(a.id()), None);
    wait_for("idle", || rec.closed(a.id()).is_some());
    assert_eq!(rec.closed(a.id()), Some(Some(ErrorKind::TimedOut)));
    stop(&e);
}

#[test]
fn dialed_udp_connection_has_an_idle_timeout_of_its_own() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap(); // receives, never answers
    let rec = Arc::new(Rec::default());
    // The engine's UDP idle timeout is long; the dialed connection's own short.
    let e = udp_engine(Duration::from_secs(30), &rec, |_, _| {});
    let r = rec.clone();
    let t0 = Instant::now();
    e.dial_udp(
        silent.local_addr().unwrap(),
        fn_acceptor(move |c: &Conn<H>| {
            r.conns.lock().unwrap().push(c.clone());
            c.set_idle_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let _ = c.send(b"hello?");
            H(r.clone())
        }),
        |e| panic!("{e}"),
    );
    wait_for("dialed", || rec.opened() == 1);
    let id = rec.conn(0).id();
    wait_for("idle", || rec.closed(id).is_some());
    assert_eq!(rec.closed(id), Some(Some(ErrorKind::TimedOut)));
    assert!(t0.elapsed() < Duration::from_secs(5));
    stop(&e);
}
