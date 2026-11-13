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
