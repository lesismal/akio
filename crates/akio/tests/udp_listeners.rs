//! Per-peer UDP listeners added, removed and drained on a running engine, and bound UDP
//! sockets drained (ADR-155, akit A22). Per-peer UDP runs on the epoll/kqueue UDP loop whatever
//! the backend under test.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Acceptor, Config, Conn, Engine, Error, Handler, Listener};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
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

fn client(server: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(server).unwrap();
    s
}

/// The next datagram within `wait`, if one comes.
fn recv_within(s: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut b = vec![0u8; 2048];
    loop {
        match s.recv(&mut b) {
            Ok(n) => {
                b.truncate(n);
                return Some(b);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return None;
            }
            // An ICMP "port unreachable" from a closed socket.
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => return None,
            Err(e) => panic!("{e}"),
        }
    }
}

fn recv(s: &UdpSocket) -> Vec<u8> {
    recv_within(s, Duration::from_secs(5)).expect("an answer")
}

/// Echoes; `on_shutdown` sends "bye" and counts, leaving the peer open (the drain deadline
/// closes it).
#[derive(Clone, Default)]
struct Peers {
    conns: Arc<Mutex<Vec<Conn<P>>>>,
    shutdowns: Arc<AtomicUsize>,
    closed: Arc<Mutex<Vec<Option<ErrorKind>>>>,
}

struct P(Arc<Mutex<Vec<Option<ErrorKind>>>>);

impl Handler for P {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        let kind = match err {
            Some(Error::Io(e)) => Some(e.kind()),
            _ => None,
        };
        self.0.lock().unwrap().push(kind);
    }
}

impl Acceptor for Peers {
    type Handler = P;
    fn on_open(&self, c: &Conn<P>) -> P {
        self.conns.lock().unwrap().push(c.clone());
        P(self.closed.clone())
    }
    fn on_shutdown(&self, c: &Conn<P>) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        let _ = c.send(b"bye");
    }
}

impl Peers {
    fn opened(&self) -> usize {
        self.conns.lock().unwrap().len()
    }
    fn closed(&self) -> usize {
        self.closed.lock().unwrap().len()
    }
}

/// An engine with one UDP listener of `threads` threads, and UDP client threads of its own
/// unless `client_threads` is false (then the listener's threads serve `dial_udp` and
/// `bind_udp` too).
fn engine(peers: &Peers, threads: usize, client_threads: bool) -> Engine {
    let mut b = Engine::builder().config(quick()).listen(
        Listener::udp(localhost())
            .threads(threads)
            .serve(peers.clone()),
    );
    if client_threads {
        b = b.udp_client_threads(1);
    }
    let e = b.build().unwrap();
    e.start().unwrap();
    e
}

#[test]
fn shutdown_listener_drains_udp_peers_and_takes_no_new_ones() {
    let peers = Peers::default();
    let e = engine(&peers, 2, true);
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let a = client(addr);
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    let t0 = Instant::now();
    e.shutdown_listener(id, Duration::from_millis(700)).unwrap();
    assert!(e.listeners().iter().all(|l| l.id != id));
    // The peer was told (an HTTP/3 server would send GOAWAY here) and is still served.
    assert_eq!(recv(&a), b"bye");
    assert_eq!(peers.shutdowns.load(Ordering::SeqCst), 1);
    a.send(b"x").unwrap();
    assert_eq!(recv(&a), b"x");
    // A new peer is not.
    let b = client(addr);
    b.send(b"hi").unwrap();
    assert_eq!(recv_within(&b, Duration::from_millis(200)), None);
    assert_eq!(peers.opened(), 1);
    // At the deadline the peer is closed, the sockets and the threads go.
    wait_for("drain deadline", || peers.closed() == 1);
    assert!(
        t0.elapsed() >= Duration::from_millis(600),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(*peers.closed.lock().unwrap(), vec![None]);
    a.send(b"y").unwrap();
    assert_eq!(recv_within(&a, Duration::from_millis(200)), None);
    wait_for("threads exit", || e.threads()[0] == 0);
    // Removing it again: not found.
    assert_eq!(
        e.remove_listener(id).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    stop(&e);
}

#[test]
fn a_drained_listener_closes_as_soon_as_its_peers_are_gone() {
    let peers = Peers::default();
    let e = engine(&peers, 2, true);
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let a = client(addr);
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    e.shutdown_listener(id, Duration::from_secs(30)).unwrap();
    assert_eq!(recv(&a), b"bye");
    // The application closes its peer (an HTTP/3 connection done with its requests): long
    // before the deadline, the listener is gone.
    let t0 = Instant::now();
    peers.conns.lock().unwrap()[0].close();
    wait_for("threads exit", || e.threads()[0] == 0);
    assert!(t0.elapsed() < Duration::from_secs(5));
    stop(&e);
}

#[test]
fn remove_listener_keeps_udp_peers_until_they_close() {
    let peers = Peers::default();
    let e = engine(&peers, 1, true);
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let a = client(addr);
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    e.remove_listener(id).unwrap();
    // No drain: no `on_shutdown`, the peer keeps being served; a new one is not.
    a.send(b"x").unwrap();
    assert_eq!(recv(&a), b"x");
    assert_eq!(peers.shutdowns.load(Ordering::SeqCst), 0);
    let b = client(addr);
    b.send(b"hi").unwrap();
    assert_eq!(recv_within(&b, Duration::from_millis(200)), None);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(e.threads()[0], 1, "still serving its peer");
    // Its idle timeout (here: its own, A78) ends it, and the thread with it.
    peers.conns.lock().unwrap()[0]
        .set_idle_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    wait_for("idle close", || peers.closed() == 1);
    assert_eq!(
        *peers.closed.lock().unwrap(),
        vec![Some(ErrorKind::TimedOut)]
    );
    wait_for("threads exit", || e.threads()[0] == 0);
    stop(&e);
}

#[test]
fn a_removed_listener_that_serves_dial_udp_keeps_its_threads() {
    let peers = Peers::default();
    // No UDP client threads: the listener's serve `bind_udp`.
    let e = engine(&peers, 1, false);
    let id = e.listeners()[0].id;
    e.shutdown_listener(id, Duration::ZERO).unwrap();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(e.threads()[0], 1);
    let bound = e.bind_udp(localhost(), peers.clone()).unwrap();
    let c = client(bound.local_addr());
    c.send(b"still").unwrap();
    assert_eq!(recv(&c), b"still");
    stop(&e);
}

#[test]
fn a_udp_listener_added_at_run_time_serves_and_is_removed() {
    let e = Engine::builder().config(quick()).build().unwrap();
    e.start().unwrap();
    let peers = Peers::default();
    let id = e
        .add_listener(Listener::udp(localhost()).threads(2).serve(peers.clone()))
        .unwrap();
    let info = e.listeners().into_iter().find(|l| l.id == id).unwrap();
    assert!(info.udp);
    let a = client(info.local_addr);
    a.send(b"hello").unwrap();
    assert_eq!(recv(&a), b"hello");
    assert_eq!(peers.opened(), 1);
    e.shutdown_listener(id, Duration::from_millis(200)).unwrap();
    assert_eq!(recv(&a), b"bye");
    wait_for("drain deadline", || peers.closed() == 1);
    // Its threads exit and the engine lets go of the group.
    wait_for("reaped", || e.listeners().is_empty());
    let b = client(info.local_addr);
    b.send(b"hi").unwrap();
    assert_eq!(recv_within(&b, Duration::from_millis(200)), None);
    stop(&e);
}

#[test]
fn a_udp_listener_added_before_start_is_served_from_start() {
    let e = Engine::builder().config(quick()).build().unwrap();
    let peers = Peers::default();
    let id = e
        .add_listener(Listener::udp(localhost()).serve(peers.clone()))
        .unwrap();
    let addr = e.listeners()[0].local_addr;
    e.start().unwrap();
    let a = client(addr);
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    e.remove_listener(id).unwrap();
    stop(&e);
}

#[test]
fn udp_binding_shutdown_drains_its_peers() {
    let e = Engine::builder()
        .config(quick())
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let peers = Peers::default();
    let bound = e.bind_udp(localhost(), peers.clone()).unwrap();
    let addr = bound.local_addr();
    let a = client(addr);
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    let t0 = Instant::now();
    bound.shutdown(Duration::from_millis(500));
    assert_eq!(recv(&a), b"bye");
    a.send(b"x").unwrap();
    assert_eq!(recv(&a), b"x");
    let b = client(addr);
    b.send(b"hi").unwrap();
    assert_eq!(recv_within(&b, Duration::from_millis(200)), None);
    assert_eq!(peers.opened(), 1);
    // A second shutdown changes nothing.
    bound.shutdown(Duration::ZERO);
    wait_for("drain deadline", || peers.closed() == 1);
    assert!(
        t0.elapsed() >= Duration::from_millis(400),
        "{:?}",
        t0.elapsed()
    );
    a.send(b"y").unwrap();
    assert_eq!(recv_within(&a, Duration::from_millis(200)), None);
    stop(&e);
}

#[test]
fn udp_binding_close_ends_a_drain_early() {
    let e = Engine::builder()
        .config(quick())
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let peers = Peers::default();
    let bound = e.bind_udp(localhost(), peers.clone()).unwrap();
    let a = client(bound.local_addr());
    a.send(b"hi").unwrap();
    assert_eq!(recv(&a), b"hi");
    bound.shutdown(Duration::from_secs(30));
    assert_eq!(recv(&a), b"bye");
    let t0 = Instant::now();
    bound.close();
    wait_for("closed", || peers.closed() == 1);
    assert!(t0.elapsed() < Duration::from_secs(5));
    stop(&e);
}
