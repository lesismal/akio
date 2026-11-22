//! Connectionless UDP listeners (`Listener::serve_datagrams`, ADR-065): batches, replies sent
//! together per batch, cross-thread sends, no per-peer state, shutdown, panics, misuse.
//! `AKIO_TEST_BACKEND=uring` runs them on io_uring (strict).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{
    Config, Conn, DatagramSender, Datagrams, DatagramsHandler, Engine, Handler, Listener, Replies,
    fn_acceptor,
};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn cfg() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(500);
    v
}

fn client(server: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn recv(s: &UdpSocket) -> Vec<u8> {
    let mut b = vec![0u8; 70_000];
    let n = loop {
        match s.recv(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            r => break r.unwrap(),
        }
    };
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

fn engine(threads: usize, l: Listener) -> Engine {
    let e = Engine::builder()
        .config(cfg())
        .listen(l.backend(common::backend()).threads(threads))
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// Echoes every datagram; on `hold` sleeps first (so the next batch piles up in the socket), on
/// `boom` panics, on `burst` answers with ten equal-size datagrams. Records each batch's size.
struct Echo {
    batches: Arc<Mutex<Vec<usize>>>,
}

impl DatagramsHandler for Echo {
    fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
        self.batches.lock().unwrap().push(batch.len());
        assert_eq!(batch.iter().len(), batch.len());
        for (peer, data) in batch {
            match data {
                b"hold" => thread::sleep(Duration::from_millis(300)),
                b"boom" => panic!("boom (expected by the test)"),
                b"burst" => {
                    for i in 0..10u8 {
                        out.send_to(&[i; 100], peer).unwrap();
                    }
                    continue;
                }
                _ => {}
            }
            out.send_to(data, peer).unwrap();
        }
    }
}

fn echo(threads: usize) -> (Engine, Arc<Mutex<Vec<usize>>>) {
    let batches = Arc::new(Mutex::new(Vec::new()));
    let b = batches.clone();
    let e = engine(
        threads,
        Listener::udp(localhost())
            .serve_datagrams(move |_tx: &DatagramSender| Echo { batches: b.clone() }),
    );
    (e, batches)
}

#[test]
fn echo_keeps_boundaries_across_peers() {
    let (e, _) = echo(2);
    let addr = e.local_addrs()[0];
    let clients: Vec<UdpSocket> = (0..8).map(|_| client(addr)).collect();
    for round in 0..20u32 {
        for (i, c) in clients.iter().enumerate() {
            let msg = format!("{i}:{round}:{}", "x".repeat(round as usize * 50));
            c.send(msg.as_bytes()).unwrap();
            assert_eq!(recv(c), msg.as_bytes());
        }
    }
    // Empty datagrams are datagrams too.
    clients[0].send(b"").unwrap();
    assert_eq!(recv(&clients[0]), b"");
    // No connection, no peer.
    assert_eq!(e.udp_stats().peers, 0);
    assert!(e.connections(Duration::from_secs(1)).is_empty());
    assert_eq!(e.metrics().open_connections, 0);
    stop(&e);
}

#[test]
fn replies_leave_together_per_batch() {
    let (e, batches) = echo(1);
    let addr = e.local_addrs()[0];
    let hold = client(addr);
    hold.send(b"hold").unwrap();
    // While the handler sleeps, 20 peers send: their datagrams wait in the socket and arrive
    // as one batch.
    thread::sleep(Duration::from_millis(50));
    let peers: Vec<UdpSocket> = (0..20).map(|_| client(addr)).collect();
    for (i, p) in peers.iter().enumerate() {
        p.send(format!("p{i}").as_bytes()).unwrap();
    }
    assert_eq!(recv(&hold), b"hold");
    for (i, p) in peers.iter().enumerate() {
        assert_eq!(recv(p), format!("p{i}").as_bytes());
    }
    // One peer, a burst of ten equal-size replies (one GSO message where the kernel has it).
    hold.send(b"burst").unwrap();
    for i in 0..10u8 {
        assert_eq!(recv(&hold), vec![i; 100]);
    }
    let b = batches.lock().unwrap().clone();
    assert!(b.iter().any(|&n| n >= 2), "no multi-datagram batch: {b:?}");
    assert_eq!(b.iter().sum::<usize>(), 22, "{b:?}");
    // The loop counts after `sendmmsg` returns, which may be after the client got the replies.
    wait_for("counters", || e.metrics().total.datagrams_out == 31);
    let m = e.metrics().total;
    assert_eq!(m.datagrams_in, 22);
    if cfg!(target_os = "linux") {
        // Every batch's replies (at most 32 messages) went out in a single sendmmsg.
        assert_eq!(m.writes, b.len() as u64, "batches {b:?}");
    } else {
        assert_eq!(m.writes, 31);
    }
    stop(&e);
}

#[test]
fn senders_work_from_any_thread() {
    // The factory hands out the sender; the handler forwards work to another thread, which
    // answers through `Replies::sender`.
    let from_factory: Arc<Mutex<Option<DatagramSender>>> = Arc::default();
    struct Offload;
    impl DatagramsHandler for Offload {
        fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
            for (peer, data) in batch {
                let (tx, data) = (out.sender().clone(), data.to_vec());
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(20));
                    let mut reply = b"late:".to_vec();
                    reply.extend_from_slice(&data);
                    tx.send_to(&reply, peer).unwrap();
                });
            }
        }
    }
    let f = from_factory.clone();
    let e = engine(
        1,
        Listener::udp(localhost()).serve_datagrams(move |tx: &DatagramSender| {
            *f.lock().unwrap() = Some(tx.clone());
            Offload
        }),
    );
    let addr = e.local_addrs()[0];
    let c = client(addr);
    c.send(b"a").unwrap();
    assert_eq!(recv(&c), b"late:a");
    // Unprompted sends to any address, from other threads: the factory's sender and the
    // engine's.
    let tx = from_factory.lock().unwrap().clone().unwrap();
    assert_eq!(tx.local_addr(), addr);
    let to = c.local_addr().unwrap();
    let tx2 = e.datagram_sender(addr).unwrap();
    let h = thread::spawn(move || {
        tx.send_to(b"push1", to).unwrap();
        tx2.send_to(b"push2", to).unwrap();
    });
    h.join().unwrap();
    let mut got = vec![recv(&c), recv(&c)];
    got.sort();
    assert_eq!(got, vec![b"push1".to_vec(), b"push2".to_vec()]);
    // Datagrams from the listener's port.
    let mut b = [0u8; 16];
    c.send(b"b").unwrap();
    let (n, from) = c.recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from), (&b"late:b"[..], addr));
    wait_for("counters", || e.metrics().total.datagrams_out >= 4);
    stop(&e);
}

/// Resident set size in bytes (Linux).
#[cfg(target_os = "linux")]
fn rss() -> usize {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: usize = s.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

#[test]
fn many_peers_keep_no_state() {
    let seen = Arc::new(AtomicUsize::new(0));
    struct Count(Arc<AtomicUsize>);
    impl DatagramsHandler for Count {
        fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
            self.0.fetch_add(batch.len(), Ordering::Relaxed);
            for (peer, data) in batch {
                let _ = out.send_to(data, peer);
            }
        }
    }
    let s = seen.clone();
    let e = engine(
        2,
        Listener::udp(localhost()).serve_datagrams(move |_: &DatagramSender| Count(s.clone())),
    );
    let addr = e.local_addrs()[0];
    // Each round: `n` peers that are never seen again, each sending one datagram and waiting
    // for its answer (so nothing is lost to a full socket).
    let round = |n: usize| {
        for i in 0..n {
            let c = client(addr);
            c.send(&(i as u32).to_le_bytes()).unwrap();
            assert_eq!(recv(&c), (i as u32).to_le_bytes());
        }
    };
    round(1_000);
    #[cfg(target_os = "linux")]
    let before = rss();
    round(10_000);
    assert_eq!(seen.load(Ordering::Relaxed), 11_000);
    assert_eq!(e.udp_stats().peers, 0);
    assert_eq!(e.udp_stats().rejected, 0);
    assert!(e.connections(Duration::from_secs(1)).is_empty());
    assert_eq!(e.metrics().total.accepted, 0);
    #[cfg(target_os = "linux")]
    {
        // A peer table would hold 10,000 entries (with handlers and timers) here.
        let grown = rss().saturating_sub(before);
        assert!(
            grown < 4 << 20,
            "RSS grew by {grown} bytes over 10,000 peers"
        );
    }
    stop(&e);
}

#[test]
fn per_peer_udp_is_unchanged_next_to_a_datagram_listener() {
    struct PerPeer;
    impl Handler for PerPeer {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = c.send(data);
        }
    }
    let b: Arc<Mutex<Vec<usize>>> = Arc::default();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<PerPeer>| PerPeer)),
        )
        .listen(
            Listener::udp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve_datagrams(move |_: &DatagramSender| Echo { batches: b.clone() }),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let (a, d) = (e.local_addrs()[0], e.local_addrs()[1]);
    let (ca, cd) = (client(a), client(d));
    ca.send(b"conn").unwrap();
    cd.send(b"dgram").unwrap();
    assert_eq!(recv(&ca), b"conn");
    assert_eq!(recv(&cd), b"dgram");
    assert_eq!(e.udp_stats().peers, 1); // the per-peer listener's one connection
    // `bind_udp` and `dial_udp` go to the per-peer listener's threads, never the datagram one.
    let bound = e
        .bind_udp(localhost(), fn_acceptor(|_c: &Conn<PerPeer>| PerPeer))
        .unwrap();
    let cb = client(bound.local_addr());
    cb.send(b"bound").unwrap();
    assert_eq!(recv(&cb), b"bound");
    // Thread counts of UDP listeners are fixed.
    assert_eq!(
        e.set_threads(1, 2).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
    stop(&e);
}

#[test]
fn shutdown_lets_the_handler_send_last_datagrams() {
    struct Bye {
        last: Option<SocketAddr>,
    }
    impl DatagramsHandler for Bye {
        fn on_datagrams(&mut self, batch: &Datagrams<'_>, _out: &mut Replies) {
            self.last = batch.iter().last().map(|(p, _)| p);
        }
        fn on_shutdown(&mut self, out: &mut Replies) {
            if let Some(p) = self.last {
                out.send_to(b"bye", p).unwrap();
            }
        }
    }
    let e = engine(
        1,
        Listener::udp(localhost()).serve_datagrams(|_: &DatagramSender| Bye { last: None }),
    );
    let c = client(e.local_addrs()[0]);
    c.send(b"hi").unwrap();
    wait_for("datagram seen", || e.metrics().total.datagrams_in == 1);
    let t = Instant::now();
    stop(&e);
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(recv(&c), b"bye");
}

#[test]
fn a_panicking_handler_keeps_serving() {
    let (e, _) = echo(1);
    let c = client(e.local_addrs()[0]);
    c.send(b"boom").unwrap();
    wait_for("panic batch", || e.metrics().total.datagrams_in == 1);
    c.send(b"after").unwrap();
    assert_eq!(recv(&c), b"after");
    stop(&e);
}

#[test]
fn datagram_size_limits() {
    use std::io::ErrorKind::{InvalidInput, Other};
    let res: Arc<Mutex<Vec<std::io::ErrorKind>>> = Arc::default();
    struct Sizes(Arc<Mutex<Vec<std::io::ErrorKind>>>);
    impl DatagramsHandler for Sizes {
        fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
            for (peer, _) in batch {
                // Below and at the largest IPv4 UDP payload, then past what UDP can carry.
                for n in [65_506, 65_507, 65_536] {
                    let r = out.send_to(&vec![7u8; n], peer);
                    let k = r.err().map_or(Other, |e| e.kind());
                    self.0.lock().unwrap().push(k);
                }
            }
        }
    }
    let r = res.clone();
    let e = engine(
        1,
        Listener::udp(localhost()).serve_datagrams(move |_: &DatagramSender| Sizes(r.clone())),
    );
    let c = client(e.local_addrs()[0]);
    c.send(b"go").unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!(recv(&c).len(), 65_506);
        assert_eq!(recv(&c).len(), 65_507);
    } else {
        // macOS caps datagrams at `net.inet.udp.maxdgram` (9,216 by default): the kernel
        // refuses them at send time and they are dropped, as UDP does.
        wait_for("three sends", || res.lock().unwrap().len() == 3);
    }
    assert_eq!(*res.lock().unwrap(), vec![Other, Other, InvalidInput]);
    stop(&e);
}

#[test]
fn misuse_is_refused() {
    let tcp = Engine::builder()
        .listen(
            Listener::tcp(localhost()).serve_datagrams(|_: &DatagramSender| Echo {
                batches: Arc::default(),
            }),
        )
        .build();
    assert_eq!(
        tcp.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "TCP listener"
    );
    struct PerPeer;
    impl Handler for PerPeer {
        fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
    }
    let both = Engine::builder()
        .listen(
            Listener::udp(localhost())
                .serve(fn_acceptor(|_c: &Conn<PerPeer>| PerPeer))
                .serve_datagrams(|_: &DatagramSender| Echo {
                    batches: Arc::default(),
                }),
        )
        .build();
    assert_eq!(both.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    let (e, _) = echo(1);
    assert_eq!(
        e.datagram_sender(localhost()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    // No UDP threads for runtime binds or dials: the datagram listener is not one.
    assert!(
        e.bind_udp(localhost(), fn_acceptor(|_c: &Conn<PerPeer>| PerPeer))
            .is_err()
    );
    stop(&e);
}

#[cfg(target_os = "linux")]
#[test]
fn io_uring_backend_serves_datagrams() {
    // Explicitly io_uring (falls back to epoll, with a warning, on kernels without it).
    let b: Arc<Mutex<Vec<usize>>> = Arc::default();
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(localhost())
                .backend(akio::Backend::IoUring(akio::UringConfig::default()))
                .threads(2)
                .serve_datagrams(move |_: &DatagramSender| Echo { batches: b.clone() }),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cs: Vec<UdpSocket> = (0..16).map(|_| client(addr)).collect();
    for (i, c) in cs.iter().enumerate() {
        c.send(format!("u{i}").as_bytes()).unwrap();
    }
    for (i, c) in cs.iter().enumerate() {
        assert_eq!(recv(c), format!("u{i}").as_bytes());
    }
    let tx = e.datagram_sender(addr).unwrap();
    tx.send_to(b"x", cs[0].local_addr().unwrap()).unwrap();
    assert_eq!(recv(&cs[0]), b"x");
    stop(&e);
}
