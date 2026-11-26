//! The accept filter on UDP listeners, bound UDP sockets and datagram listeners (ADR-178, akit
//! A220): a refused peer's datagrams are dropped before anything is made for it, counted in
//! `filtered`; the filter is swapped and cleared while the engine runs. Per-peer UDP runs on the
//! epoll/kqueue UDP loop whatever the backend or scheduling asked for; datagram listeners run on
//! the backend under test (`AKIO_TEST_BACKEND=uring`: io_uring, strict).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    collections::HashSet,
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{
    Acceptor, Config, Conn, DatagramSender, Datagrams, DatagramsHandler, Engine, Handler, Listener,
    Replies, Scheduling, WorkStealingConfig,
};

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
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => return None,
            Err(e) => panic!("{e}"),
        }
    }
}

fn recv(s: &UdpSocket) -> Vec<u8> {
    recv_within(s, Duration::from_secs(5)).expect("an answer")
}

/// Sends `msg` and expects it echoed.
fn echoed(s: &UdpSocket, msg: &[u8]) {
    s.send(msg).unwrap();
    assert_eq!(recv(s), msg);
}

/// Sends `n` datagrams and expects no answer.
fn ignored(s: &UdpSocket, n: usize) {
    for _ in 0..n {
        s.send(b"knock").unwrap();
    }
    assert_eq!(recv_within(s, Duration::from_millis(200)), None);
}

/// Echoes; counts the peers opened.
#[derive(Clone, Default)]
struct Peers(Arc<AtomicUsize>);

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

impl Acceptor for Peers {
    type Handler = Echo;
    fn on_open(&self, _c: &Conn<Echo>) -> Echo {
        self.0.fetch_add(1, Ordering::SeqCst);
        Echo
    }
}

impl Peers {
    fn opened(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// The peers a filter allows, changed while it is installed.
#[derive(Clone, Default)]
struct Allowed(Arc<Mutex<HashSet<SocketAddr>>>);

impl Allowed {
    fn add(&self, s: &UdpSocket) {
        self.0.lock().unwrap().insert(s.local_addr().unwrap());
    }
    fn filter(&self) -> impl Fn(&SocketAddr) -> bool + Send + Sync + 'static {
        let set = self.0.clone();
        move |peer| set.lock().unwrap().contains(peer)
    }
}

fn filtered(e: &Engine) -> u64 {
    e.metrics().total.filtered
}

#[test]
fn a_udp_listener_drops_refused_peers_without_making_them() {
    let peers = Peers::default();
    let allowed = Allowed::default();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .threads(2)
                .filter(allowed.filter())
                .serve(peers.clone()),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let (a, b) = (client(addr), client(addr));
    allowed.add(&a);
    echoed(&a, b"hi");
    // Every datagram of a refused peer is asked about and dropped; nothing is kept of it.
    ignored(&b, 5);
    wait_for("refusals counted", || filtered(&e) == 5);
    assert_eq!(peers.opened(), 1);
    assert_eq!(e.udp_stats().peers, 1);
    // Allowed later: its next datagram opens it.
    allowed.add(&b);
    echoed(&b, b"now");
    assert_eq!(peers.opened(), 2);
    assert_eq!(filtered(&e), 5);
    assert!(
        e.metrics()
            .to_prometheus()
            .contains("akio_connections_filtered_total")
    );
    stop(&e);
}

#[test]
fn the_filter_is_swapped_and_cleared_on_a_running_udp_listener() {
    let peers = Peers::default();
    let e = Engine::builder()
        .config(quick())
        .listen(Listener::udp(localhost()).serve(peers.clone()))
        .build()
        .unwrap();
    e.start().unwrap();
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let a = client(addr);
    echoed(&a, b"before");
    e.set_listener_filter(id, |_| false).unwrap();
    // A peer that already has a connection is not asked again (as an accepted TCP
    // connection); a new one is refused from the call's return on.
    echoed(&a, b"still");
    let b = client(addr);
    ignored(&b, 3);
    assert_eq!(filtered(&e), 3);
    e.set_listener_filter(id, |peer| peer.ip().is_loopback())
        .unwrap();
    echoed(&b, b"loopback");
    e.set_listener_filter(id, |_| false).unwrap();
    let c = client(addr);
    ignored(&c, 1);
    e.clear_listener_filter(id).unwrap();
    echoed(&c, b"cleared");
    assert_eq!(peers.opened(), 3);
    assert_eq!(filtered(&e), 4);
    stop(&e);
}

#[test]
fn refused_peers_take_no_room_under_udp_max_peers() {
    let peers = Peers::default();
    let allowed = Allowed::default();
    let mut cfg = quick();
    cfg.udp_max_peers = Some(2);
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .filter(allowed.filter())
                .serve(peers.clone()),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    // Many refused peers: none counts against the limit, none is rejected by it.
    let refused: Vec<UdpSocket> = (0..8).map(|_| client(addr)).collect();
    for s in &refused {
        ignored(s, 1);
    }
    assert_eq!(filtered(&e), 8);
    // Just under and at the limit: served; over it: rejected by the limit, not the filter.
    let ok: Vec<UdpSocket> = (0..3).map(|_| client(addr)).collect();
    for s in &ok {
        allowed.add(s);
    }
    echoed(&ok[0], b"1");
    echoed(&ok[1], b"2");
    ignored(&ok[2], 1);
    let stats = e.udp_stats();
    assert_eq!((stats.peers, stats.rejected), (2, 1));
    assert_eq!(filtered(&e), 8);
    assert_eq!(peers.opened(), 2);
    stop(&e);
}

#[test]
fn a_panicking_filter_refuses_the_peer_and_the_loop_survives() {
    let peers = Peers::default();
    let n = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .filter(move |peer| {
                    let k = n.fetch_add(1, Ordering::SeqCst);
                    assert!(k % 2 != 0, "filter panic for {peer} (expected by the test)");
                    true
                })
                .serve(peers.clone()),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let a = client(addr);
    // First call panics: refused. Second: allowed.
    ignored(&a, 1);
    echoed(&a, b"second");
    assert_eq!(filtered(&e), 1);
    assert_eq!(peers.opened(), 1);
    stop(&e);
}

#[test]
fn a_udp_listener_asking_for_work_stealing_filters_on_its_event_loops() {
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .scheduling(Scheduling::WorkStealing(WorkStealingConfig::default()))
                .filter(|_| false)
                .serve(Peers::default()),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let id = e.listeners()[0].id;
    let a = client(e.local_addrs()[0]);
    ignored(&a, 2);
    assert_eq!(filtered(&e), 2);
    e.clear_listener_filter(id).unwrap();
    echoed(&a, b"served");
    stop(&e);
}

#[test]
fn a_bound_socket_filters_from_its_first_datagram_and_swaps_it() {
    let peers = Peers::default();
    let e = Engine::builder()
        .config(quick())
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let allowed = Allowed::default();
    let bound = e
        .bind_udp_filtered(localhost(), peers.clone(), allowed.filter())
        .unwrap();
    let addr = bound.local_addr();
    let (a, b) = (client(addr), client(addr));
    allowed.add(&a);
    echoed(&a, b"a");
    ignored(&b, 2);
    assert_eq!(filtered(&e), 2);
    // Swapped on the binding.
    bound.set_filter(|_| true).unwrap();
    echoed(&b, b"b");
    bound.set_filter(|_| false).unwrap();
    let c = client(addr);
    ignored(&c, 1);
    echoed(&a, b"kept");
    bound.clear_filter().unwrap();
    echoed(&c, b"c");
    assert_eq!(peers.opened(), 3);
    assert_eq!(filtered(&e), 3);
    // A plain binding takes one too.
    let plain = e.bind_udp(localhost(), peers).unwrap();
    plain.set_filter(|_| false).unwrap();
    let d = client(plain.local_addr());
    ignored(&d, 1);
    plain.clear_filter().unwrap();
    echoed(&d, b"d");
    assert_eq!(filtered(&e), 4);
    bound.close();
    plain.close();
    stop(&e);
}

/// Echoes each datagram and counts those it saw.
struct Count(Arc<AtomicUsize>);

impl DatagramsHandler for Count {
    fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
        for (peer, data) in batch {
            self.0.fetch_add(1, Ordering::SeqCst);
            out.send_to(data, peer).unwrap();
        }
    }
}

#[test]
fn a_datagram_listener_drops_refused_datagrams_before_the_handler() {
    let seen = Arc::new(AtomicUsize::new(0));
    let s = seen.clone();
    let allowed = Allowed::default();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::udp(localhost())
                .backend(common::backend())
                .threads(2)
                .filter(allowed.filter())
                .serve_datagrams(move |_tx: &DatagramSender| Count(s.clone())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let (a, b) = (client(addr), client(addr));
    allowed.add(&a);
    echoed(&a, b"a");
    // Every datagram is asked about (there are no connections to remember a peer by).
    ignored(&b, 4);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    wait_for("refusals counted", || filtered(&e) == 4);
    allowed.add(&b);
    echoed(&b, b"b");
    // Swapped and cleared while it runs.
    e.set_listener_filter(id, |_| false).unwrap();
    ignored(&a, 2);
    e.clear_listener_filter(id).unwrap();
    echoed(&a, b"again");
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    assert_eq!(filtered(&e), 6);
    stop(&e);
}
