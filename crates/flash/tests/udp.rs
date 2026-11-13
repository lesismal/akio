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

use flash::{Acceptor, Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn cfg() -> Config {
    Config {
        shutdown_timeout: Duration::from_millis(500),
        ..Config::default()
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
            .config(Config {
                udp_idle_timeout: Duration::from_millis(250),
                ..cfg()
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
        .config(Config {
            shutdown_timeout: Duration::from_secs(10),
            ..cfg()
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

struct CliAcceptor(Arc<Log>, &'static [u8]);

impl Acceptor for CliAcceptor {
    type Handler = Cli;
    fn on_open(&self, c: &Conn<Cli>) -> Cli {
        self.0.conns.lock().unwrap().push(c.clone());
        if !self.1.is_empty() {
            c.send(self.1).unwrap();
        }
        Cli(self.0.clone())
    }
}

fn client_engine(threads: usize) -> Engine {
    let e = Engine::builder()
        .config(Config {
            udp_idle_timeout: Duration::from_millis(400),
            ..cfg()
        })
        .udp_client_threads(threads)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn dialed_udp_connections_talk_to_a_flash_server_from_their_own_ports() {
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
        let msg: &'static [u8] = Box::leak(format!("ping-{i}").into_bytes().into_boxed_slice());
        client.dial_udp(addr, CliAcceptor(log.clone(), msg), |e| panic!("dial: {e}"));
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
    client.dial_udp(dead, CliAcceptor(log.clone(), b"anyone?"), |e| {
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
        CliAcceptor(log.clone(), b"hello?"),
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
    client.dial_udp(addr, CliAcceptor(log.clone(), b""), |e| panic!("{e}"));
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
        CliAcceptor(Arc::new(Log::default()), b""),
        move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        },
    );
    assert_eq!(failed.load(Ordering::SeqCst), 1);
}
