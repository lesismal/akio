//! UDP: one connection per peer, datagram boundaries, cross-thread sends, eviction.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{Acceptor, Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn cfg() -> Config {
    {
        let mut v = Config::default();
        v.shutdown_timeout = Duration::from_millis(500);
        v
    }
}

fn client(server: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn recv(s: &UdpSocket) -> Vec<u8> {
    let mut b = vec![0u8; 70_000];
    let n = s.recv(&mut b).unwrap();
    b.truncate(n);
    b
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

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn echo_engine(threads: usize) -> Engine {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(localhost())
                .threads(threads)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn echo_keeps_datagram_boundaries() {
    let e = echo_engine(2);
    let c = client(e.local_addrs()[0]);
    // macOS caps a datagram at 9216 bytes by default (net.inet.udp.maxdgram).
    let big = if cfg!(target_os = "linux") {
        60_000
    } else {
        9000
    };
    for size in [1usize, 2, 100, 1400, 9000, big] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        c.send(&msg).unwrap();
        assert_eq!(recv(&c), msg, "datagram of {size} bytes");
    }
    // Back-to-back datagrams stay separate messages, not one merged stream.
    for i in 0..5u8 {
        c.send(&[i; 10]).unwrap();
    }
    for i in 0..5u8 {
        assert_eq!(recv(&c), vec![i; 10]);
    }
    stop(&e);
}

#[test]
fn every_peer_has_its_own_connection_and_state() {
    struct Count(u32);
    impl Handler for Count {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            self.0 += 1;
            let _ = c.send(format!("{}@{}", self.0, c.peer_addr().port()).as_bytes());
        }
    }
    let opened = Arc::new(AtomicUsize::new(0));
    let o = opened.clone();
    let e = Engine::builder()
        .config(cfg())
        .listen(Listener::udp(localhost()).threads(3).serve(fn_acceptor(
            move |_c: &Conn<Count>| {
                o.fetch_add(1, Ordering::SeqCst);
                Count(0)
            },
        )))
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cs: Vec<UdpSocket> = (0..6).map(|_| client(addr)).collect();
    for round in 1..=3 {
        for c in &cs {
            c.send(b"x").unwrap();
        }
        for c in &cs {
            let port = c.local_addr().unwrap().port();
            assert_eq!(recv(c), format!("{round}@{port}").into_bytes());
        }
    }
    assert_eq!(opened.load(Ordering::SeqCst), 6, "one connection per peer");
    stop(&e);
}

#[test]
fn send_from_another_thread_reaches_the_peer() {
    struct Keep(Arc<Mutex<Vec<Conn<Keep>>>>);
    impl Handler for Keep {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            self.0.lock().unwrap().push(c.clone());
        }
    }
    let store = Arc::new(Mutex::new(Vec::new()));
    let s = store.clone();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(localhost())
                .threads(2)
                .serve(fn_acceptor(move |_c: &Conn<Keep>| Keep(s.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let c = client(e.local_addrs()[0]);
    c.send(b"hi").unwrap();
    wait_for("conn handle", || !store.lock().unwrap().is_empty());
    let conn = store.lock().unwrap()[0].clone();
    let t = thread::spawn(move || {
        for i in 0..20u8 {
            conn.send(&[i; 3]).unwrap();
        }
    });
    t.join().unwrap();
    let mut got = Vec::new();
    for _ in 0..20 {
        got.push(recv(&c));
    }
    let want: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 3]).collect();
    assert_eq!(got, want, "ordered, one datagram per send");
    stop(&e);
}

#[test]
fn silent_peers_are_evicted_and_come_back_fresh() {
    struct H {
        n: u32,
        closed: Arc<Mutex<Vec<std::io::ErrorKind>>>,
    }
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            self.n += 1;
            let _ = c.send(&[self.n as u8]);
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            if let Some(Error::Io(e)) = err {
                self.closed.lock().unwrap().push(e.kind());
            }
        }
    }
    let closed = Arc::new(Mutex::new(Vec::new()));
    let cl = closed.clone();
    let e =
        Engine::builder()
            .config({
                let mut v = cfg();
                v.udp_idle_timeout = Duration::from_millis(250);
                v
            })
            .listen(Listener::udp(localhost()).threads(1).serve(fn_acceptor(
                move |_c: &Conn<H>| H {
                    n: 0,
                    closed: cl.clone(),
                },
            )))
            .build()
            .unwrap();
    e.start().unwrap();
    let c = client(e.local_addrs()[0]);
    c.send(b"a").unwrap();
    assert_eq!(recv(&c), [1]);
    c.send(b"a").unwrap();
    assert_eq!(recv(&c), [2]);
    wait_for("idle eviction", || !closed.lock().unwrap().is_empty());
    assert_eq!(*closed.lock().unwrap(), vec![std::io::ErrorKind::TimedOut]);
    // The same address again is a new connection with fresh state.
    c.send(b"a").unwrap();
    assert_eq!(recv(&c), [1]);
    stop(&e);
}

#[test]
fn blocking_work_and_close_after_send_over_udp() {
    struct H(Arc<AtomicUsize>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
            let req = d.to_vec();
            c.spawn_blocking(
                move || {
                    thread::sleep(Duration::from_millis(50));
                    req.iter().rev().copied().collect::<Vec<u8>>()
                },
                |_me: &mut H, c, rev| {
                    let _ = c.send(&rev);
                    c.close_after_send();
                },
            )
            .unwrap();
        }
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            assert!(err.is_none());
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let closes = Arc::new(AtomicUsize::new(0));
    let cl = closes.clone();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(cl.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let c = client(e.local_addrs()[0]);
    c.send(b"abc").unwrap();
    assert_eq!(recv(&c), b"cba");
    wait_for("on_close", || closes.load(Ordering::SeqCst) == 1);
    // Still usable afterwards: the peer simply gets a new connection.
    c.send(b"xyz").unwrap();
    assert_eq!(recv(&c), b"zyx");
    wait_for("second on_close", || closes.load(Ordering::SeqCst) == 2);
    stop(&e);
}

#[test]
fn graceful_shutdown_notifies_peers_and_returns_promptly() {
    struct Bye;
    impl Handler for Bye {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let _ = c.send(b"hello");
        }
    }
    struct A(Arc<AtomicUsize>);
    impl Acceptor for A {
        type Handler = Bye;
        fn on_open(&self, _c: &Conn<Bye>) -> Bye {
            Bye
        }
        fn on_shutdown(&self, c: &Conn<Bye>) {
            self.0.fetch_add(1, Ordering::SeqCst);
            let _ = c.send(b"bye");
        }
    }
    let notified = Arc::new(AtomicUsize::new(0));
    let e = Engine::builder()
        .config({
            let mut v = cfg();
            v.shutdown_timeout = Duration::from_secs(10);
            v
        })
        .listen(
            Listener::udp(localhost())
                .threads(2)
                .serve(A(notified.clone())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cs: Vec<UdpSocket> = (0..4).map(|_| client(addr)).collect();
    for c in &cs {
        c.send(b"x").unwrap();
        assert_eq!(recv(c), b"hello");
    }
    let t = Instant::now();
    e.shutdown();
    e.wait();
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "UDP has nothing to drain; took {:?}",
        t.elapsed()
    );
    assert_eq!(notified.load(Ordering::SeqCst), 4);
    for c in &cs {
        assert_eq!(recv(c), b"bye");
    }
}

// ---- client side ------------------------------------------------------------------------

/// Records everything a dialed connection receives and how it ended.
#[derive(Default)]
struct Log {
    got: Mutex<Vec<Vec<u8>>>,
    closed: Mutex<Vec<Option<std::io::ErrorKind>>>,
    conns: Mutex<Vec<Conn<Cli>>>,
}

struct Cli(Arc<Log>);

impl Handler for Cli {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.0.got.lock().unwrap().push(data.to_vec());
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        let kind = match err {
            Some(Error::Io(e)) => Some(e.kind()),
            Some(_) => Some(std::io::ErrorKind::Other),
            None => None,
        };
        self.0.closed.lock().unwrap().push(kind);
    }
}

/// Sends its message once the connection opens.
struct CliAcceptor(Arc<Log>, std::borrow::Cow<'static, [u8]>);

impl Acceptor for CliAcceptor {
    type Handler = Cli;
    fn on_open(&self, c: &Conn<Cli>) -> Cli {
        self.0.conns.lock().unwrap().push(c.clone());
        if !self.1.is_empty() {
            c.send(&self.1).unwrap();
        }
        Cli(self.0.clone())
    }
}

fn client_engine(threads: usize) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = cfg();
            v.udp_idle_timeout = Duration::from_millis(400);
            v
        })
        .udp_client_threads(threads)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn dialed_udp_connections_talk_to_a_only_server_from_their_own_ports() {
    struct Seen;
    impl Handler for Seen {
        fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
            let _ = c.send(d);
        }
    }
    let peers = Arc::new(Mutex::new(Vec::new()));
    let p = peers.clone();
    let server =
        Engine::builder()
            .config(cfg())
            .listen(Listener::udp(localhost()).threads(2).serve(fn_acceptor(
                move |c: &Conn<Seen>| {
                    p.lock().unwrap().push(c.peer_addr());
                    Seen
                },
            )))
            .build()
            .unwrap();
    server.start().unwrap();
    let addr = server.local_addrs()[0];

    let client = client_engine(2);
    let logs: Vec<Arc<Log>> = (0..30).map(|_| Arc::new(Log::default())).collect();
    for (i, log) in logs.iter().enumerate() {
        let msg = format!("ping-{i}").into_bytes();
        client.dial_udp(addr, CliAcceptor(log.clone(), msg.into()), |e| {
            panic!("dial: {e}")
        });
    }
    for (i, log) in logs.iter().enumerate() {
        wait_for("echo", || !log.got.lock().unwrap().is_empty());
        assert_eq!(log.got.lock().unwrap()[0], format!("ping-{i}").into_bytes());
    }
    // 30 dials to one server address are 30 distinct peers (distinct local ports).
    let mut ports: Vec<u16> = peers.lock().unwrap().iter().map(|a| a.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 30);
    stop(&client);
    stop(&server);
}

#[test]
fn dialing_a_closed_port_ends_with_connection_refused() {
    let dead = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    }; // socket dropped: nobody listens, the kernel answers with ICMP port unreachable
    let client = client_engine(1);
    let log = Arc::new(Log::default());
    client.dial_udp(dead, CliAcceptor(log.clone(), b"anyone?"[..].into()), |e| {
        panic!("{e}")
    });
    wait_for("refused", || !log.closed.lock().unwrap().is_empty());
    assert_eq!(
        *log.closed.lock().unwrap(),
        vec![Some(std::io::ErrorKind::ConnectionRefused)]
    );
    stop(&client);
}

#[test]
fn silent_server_means_idle_timeout_for_the_client() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap(); // receives, never answers
    let client = client_engine(1);
    let log = Arc::new(Log::default());
    client.dial_udp(
        silent.local_addr().unwrap(),
        CliAcceptor(log.clone(), b"hello?"[..].into()),
        |e| panic!("{e}"),
    );
    wait_for("idle", || !log.closed.lock().unwrap().is_empty());
    assert_eq!(
        *log.closed.lock().unwrap(),
        vec![Some(std::io::ErrorKind::TimedOut)]
    );
    stop(&client);
}

#[test]
fn dialed_connection_can_send_from_another_thread_and_closes_cleanly() {
    let server = echo_engine(1);
    let addr = server.local_addrs()[0];
    let client = client_engine(1);
    let log = Arc::new(Log::default());
    client.dial_udp(addr, CliAcceptor(log.clone(), b""[..].into()), |e| {
        panic!("{e}")
    });
    wait_for("conn", || !log.conns.lock().unwrap().is_empty());
    let conn = log.conns.lock().unwrap()[0].clone();
    let t = thread::spawn({
        let conn = conn.clone();
        move || {
            for i in 0..10u8 {
                conn.send(&[i; 4]).unwrap();
            }
        }
    });
    t.join().unwrap();
    wait_for("10 echoes", || log.got.lock().unwrap().len() == 10);
    let want: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 4]).collect();
    assert_eq!(*log.got.lock().unwrap(), want);
    conn.close();
    wait_for("closed", || !log.closed.lock().unwrap().is_empty());
    assert_eq!(*log.closed.lock().unwrap(), vec![None]);
    assert!(matches!(conn.send(b"x"), Err(Error::Closed)));
    stop(&client);
    stop(&server);
}

#[test]
fn dial_udp_without_udp_threads_is_an_error() {
    let e = Engine::builder().build().unwrap();
    let failed = Arc::new(AtomicUsize::new(0));
    let f = failed.clone();
    e.dial_udp(
        "127.0.0.1:9".parse().unwrap(),
        CliAcceptor(Arc::new(Log::default()), b""[..].into()),
        move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );
    assert_eq!(failed.load(Ordering::SeqCst), 1);
}

#[test]
fn bursts_from_many_peers_are_echoed_intact() {
    // Many peers, many datagrams each: replies are batched across peers (sendmmsg on Linux).
    let e = echo_engine(2);
    let addr = e.local_addrs()[0];
    let clients: Vec<UdpSocket> = (0..20).map(|_| client(addr)).collect();
    for round in 0..5u8 {
        for (i, c) in clients.iter().enumerate() {
            for k in 0..8u8 {
                c.send(&[i as u8, round, k, 7, 7, 7]).unwrap();
            }
        }
        for (i, c) in clients.iter().enumerate() {
            let mut got: Vec<Vec<u8>> = (0..8).map(|_| recv(c)).collect();
            got.sort();
            let want: Vec<Vec<u8>> = (0..8u8).map(|k| vec![i as u8, round, k, 7, 7, 7]).collect();
            assert_eq!(got, want);
        }
    }
    stop(&e);
}

/// Replies to any datagram with `send_segments`: 5 datagrams of 1000 bytes and one of 300.
struct Segs;
impl Handler for Segs {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        let mut out = Vec::new();
        for i in 0..6u8 {
            let len = if i == 5 { 300 } else { 1000 };
            out.extend(std::iter::repeat_n(d[0].wrapping_add(i), len));
        }
        c.send_segments(out, 1000).unwrap();
    }
}

fn segs_server() -> Engine {
    let e = Engine::builder()
        .config(cfg())
        .listen(Listener::udp(localhost()).serve(fn_acceptor(|_c: &Conn<Segs>| Segs)))
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn check_segs(got: &[Vec<u8>], base: u8) {
    assert_eq!(got.len(), 6, "datagram count");
    for (i, d) in got.iter().enumerate() {
        let len = if i == 5 { 300 } else { 1000 };
        assert_eq!(d.len(), len);
        assert!(d.iter().all(|&b| b == base.wrapping_add(i as u8)));
    }
}

#[test]
fn send_segments_delivers_separate_datagrams() {
    let e = segs_server();
    let c = client(e.local_addrs()[0]);
    c.send(&[10]).unwrap();
    let got: Vec<Vec<u8>> = (0..6).map(|_| recv(&c)).collect();
    check_segs(&got, 10);
    stop(&e);
}

#[test]
fn dialed_connection_splits_coalesced_receives() {
    // The server sends with GSO; the dialed socket has GRO on (Linux): the kernel may hand the
    // client one coalesced buffer, which must still arrive as six `on_data` calls.
    struct Collect(Arc<Mutex<Vec<Vec<u8>>>>);
    impl Handler for Collect {
        fn on_data(&mut self, _c: &Conn<Self>, d: &[u8]) {
            self.0.lock().unwrap().push(d.to_vec());
        }
    }
    struct Dial(Arc<Mutex<Vec<Vec<u8>>>>);
    impl Acceptor for Dial {
        type Handler = Collect;
        fn on_open(&self, c: &Conn<Collect>) -> Collect {
            c.send(&[40]).unwrap();
            Collect(self.0.clone())
        }
    }
    let server = segs_server();
    let client = Engine::builder()
        .config({
            let mut v = cfg();
            v.udp_gro = true;
            v
        })
        .udp_client_threads(1)
        .build()
        .unwrap();
    client.start().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    client.dial_udp(server.local_addrs()[0], Dial(got.clone()), |e| {
        panic!("{e}")
    });
    wait_for("six datagrams", || got.lock().unwrap().len() >= 6);
    thread::sleep(Duration::from_millis(50));
    check_segs(&got.lock().unwrap(), 40);
    stop(&client);
    stop(&server);
}

#[test]
fn peer_cap_drops_new_peers_and_counts_them() {
    let e = Engine::builder()
        .config({
            let mut v = cfg();
            v.udp_max_peers = Some(2);
            v
        })
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let (a, b, c) = (client(addr), client(addr), client(addr));
    for s in [&a, &b] {
        s.send(b"in").unwrap();
        assert_eq!(recv(s), b"in");
    }
    c.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    c.send(b"out").unwrap();
    c.send(b"out").unwrap();
    let mut buf = [0u8; 16];
    assert!(c.recv(&mut buf).is_err(), "a third peer must be refused");
    // Known peers still work.
    a.send(b"again").unwrap();
    assert_eq!(recv(&a), b"again");
    let st = e.udp_stats();
    assert_eq!(st.peers, 2);
    assert_eq!(st.rejected, 2);
    stop(&e);
}

#[test]
fn bound_socket_talks_to_many_peers_from_one_port() {
    // Replies come back through per-peer connections of the bound socket's acceptor.
    type Got = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;
    struct Rx(Got, Arc<AtomicUsize>);
    impl Handler for Rx {
        fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
            self.0.lock().unwrap().push((c.peer_addr(), d.to_vec()));
            let _ = c.send(b"ack");
        }
        fn on_close(&mut self, _c: &Conn<Self>, _e: Option<Error>) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
    let got: Got = Arc::default();
    let closed = Arc::new(AtomicUsize::new(0));
    let e = client_engine(1);
    let (g, cl) = (got.clone(), closed.clone());
    let b = e
        .bind_udp(
            localhost(),
            fn_acceptor(move |_c: &Conn<Rx>| Rx(g.clone(), cl.clone())),
        )
        .unwrap();
    assert_ne!(b.local_addr().port(), 0);
    // Three plain sockets: the bound socket sends first (no datagram from them yet).
    let peers: Vec<UdpSocket> = (0..3).map(|_| client(b.local_addr())).collect();
    for (i, p) in peers.iter().enumerate() {
        b.send_to(format!("hi-{i}").as_bytes(), p.local_addr().unwrap())
            .unwrap();
    }
    for (i, p) in peers.iter().enumerate() {
        assert_eq!(recv(p), format!("hi-{i}").into_bytes());
        p.send(format!("re-{i}").as_bytes()).unwrap();
        assert_eq!(recv(p), b"ack");
    }
    wait_for("three peers", || got.lock().unwrap().len() == 3);
    for (i, p) in peers.iter().enumerate() {
        let g = got.lock().unwrap();
        let me = p.local_addr().unwrap();
        let (_, d) = g.iter().find(|(a, _)| *a == me).unwrap();
        assert_eq!(*d, format!("re-{i}").into_bytes());
    }
    b.close();
    wait_for("peers closed", || closed.load(Ordering::SeqCst) == 3);
    // Closed: nothing is received any more (the socket is unregistered).
    peers[0].send(b"late").unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(got.lock().unwrap().len(), 3);
    stop(&e);
}

#[test]
fn bind_udp_without_udp_threads_is_an_error() {
    let e = Engine::builder().build().unwrap();
    e.start().unwrap();
    let err = e
        .bind_udp(localhost(), fn_acceptor(|_c: &Conn<Echo>| Echo))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn dial_udp_from_sends_from_the_listener_port() {
    let engine = echo_engine(2);
    let local = engine.local_addrs()[0];
    // A peer that has never written to the listener.
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let opened = Arc::new(AtomicUsize::new(0));
    let o = opened.clone();
    engine.dial_udp_from(
        local,
        peer.local_addr().unwrap(),
        fn_acceptor(move |c: &Conn<Echo>| {
            c.send(b"hello from the listener port").unwrap();
            o.fetch_add(1, Ordering::Relaxed);
            Echo
        }),
        |e| panic!("dial_udp_from: {e}"),
    );
    let mut b = [0u8; 64];
    let (n, from) = peer.recv_from(&mut b).unwrap();
    assert_eq!(&b[..n], b"hello from the listener port");
    assert_eq!(from, local, "the datagram leaves from the listener's port");
    // Answers reach a connection of the listener (the echo handler), from the same port.
    peer.send_to(b"ping", local).unwrap();
    let (n, from) = peer.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from), (&b"ping"[..], local));
    // No UDP listener at that address.
    let (tx, rx) = std::sync::mpsc::channel();
    engine.dial_udp_from(
        "127.0.0.1:1".parse().unwrap(),
        peer.local_addr().unwrap(),
        fn_acceptor(|_c: &Conn<Echo>| Echo),
        move |e| tx.send(e.kind()).unwrap(),
    );
    let k = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(k, std::io::ErrorKind::InvalidInput);
    assert_eq!(opened.load(Ordering::Relaxed), 1);
    stop(&engine);
}

#[test]
fn tcp_dial_works_when_the_last_group_is_udp() {
    // A TCP listener, then a UDP listener and UDP client threads: `dial` must use a TCP group.
    let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let to = srv.local_addr().unwrap();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e.dial(to, fn_acceptor(|_c: &Conn<Echo>| Echo), |err| {
        panic!("dial: {err}")
    });
    srv.set_nonblocking(false).unwrap();
    let (_s, _) = srv.accept().unwrap();
    stop(&e);
}

#[test]
fn dial_udp_from_refuses_a_peer_that_has_a_connection() {
    let engine = echo_engine(1);
    let local = engine.local_addrs()[0];
    let peer = client(local);
    peer.send(b"first").unwrap();
    assert_eq!(recv(&peer), b"first");
    let (tx, rx) = std::sync::mpsc::channel();
    engine.dial_udp_from(
        local,
        peer.local_addr().unwrap(),
        fn_acceptor(|_c: &Conn<Echo>| Echo),
        move |e| tx.send(e.kind()).unwrap(),
    );
    let k = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(k, std::io::ErrorKind::AlreadyExists);
    stop(&engine);
}
