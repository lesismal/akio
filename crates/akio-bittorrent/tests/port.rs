//! uTP and plain datagrams over real `akio` UDP listeners: two ports on loopback.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_bittorrent::port::{StreamHandler, UdpPort, UtpStream};

fn port() -> (UdpPort, Arc<Engine>, SocketAddr) {
    let p = UdpPort::new();
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(2)
                    .serve(p.acceptor()),
            )
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    p.attach(&engine, addr);
    (p, engine, addr)
}

struct Sink {
    got: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Sender<&'static str>,
    want: usize,
    echo: bool,
}

impl StreamHandler for Sink {
    fn on_connect(&mut self, _s: &UtpStream) {
        let _ = self.done.send("connect");
    }
    fn on_data(&mut self, s: &UtpStream, data: &[u8]) {
        if self.echo {
            s.write(data).unwrap();
        }
        let mut g = self.got.lock().unwrap();
        g.extend_from_slice(data);
        if g.len() == self.want {
            let _ = self.done.send("all");
        }
    }
    fn on_close(&mut self, _s: &UtpStream, err: Option<std::io::ErrorKind>) {
        let _ = self
            .done
            .send(if err.is_none() { "closed" } else { "error" });
    }
}

#[test]
fn utp_echo_over_only_udp() {
    let (a, _ea, _) = port();
    let (b, _eb, baddr) = port();
    let n = 3 << 20;
    let data: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
    let (btx, brx) = mpsc::channel();
    let bgot = Arc::new(Mutex::new(Vec::new()));
    let bg = bgot.clone();
    b.on_accept(move |_s| {
        Some(Box::new(Sink {
            got: bg.clone(),
            done: btx.clone(),
            want: n,
            echo: true,
        }))
    });
    let (atx, arx) = mpsc::channel();
    let agot = Arc::new(Mutex::new(Vec::new()));
    let s = a.connect(
        baddr,
        Sink {
            got: agot.clone(),
            done: atx,
            want: n,
            echo: false,
        },
    );
    assert_eq!(arx.recv_timeout(Duration::from_secs(5)).unwrap(), "connect");
    assert_eq!(brx.recv_timeout(Duration::from_secs(5)).unwrap(), "connect");
    for c in data.chunks(100_000) {
        s.write(c).unwrap();
    }
    assert_eq!(brx.recv_timeout(Duration::from_secs(30)).unwrap(), "all");
    assert_eq!(arx.recv_timeout(Duration::from_secs(30)).unwrap(), "all");
    assert!(*bgot.lock().unwrap() == data);
    assert!(*agot.lock().unwrap() == data);
    s.close();
    // B sees EOF and closes its side (default on_eof); both end in an orderly close.
    assert_eq!(arx.recv_timeout(Duration::from_secs(10)).unwrap(), "closed");
    assert_eq!(brx.recv_timeout(Duration::from_secs(10)).unwrap(), "closed");
    assert_eq!(a.utp_connections() + b.utp_connections(), 0);
}

#[test]
fn datagrams_leave_from_the_listener_port() {
    let (a, _ea, aaddr) = port();
    let (b, _eb, baddr) = port();
    let (tx, rx) = mpsc::channel();
    b.on_datagram(move |from, data| {
        let _ = tx.send((from, data.to_vec()));
    });
    // A writes first: B has never heard of A, yet the datagram comes from A's listener port.
    a.send_to(baddr, b"d1:ai1ee".to_vec());
    let (from, d) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(from, aaddr);
    assert_eq!(d, b"d1:ai1ee");
    // And B answers the same way.
    let (tx2, rx2) = mpsc::channel();
    a.on_datagram(move |from, data| {
        let _ = tx2.send((from, data.to_vec()));
    });
    b.send_to(aaddr, b"d1:bi2ee".to_vec());
    let (from, _) = rx2.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(from, baddr);
}

#[test]
fn utp_connect_to_nobody_times_out() {
    let (a, _ea, _) = port();
    let dead: SocketAddr = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let (tx, rx) = mpsc::channel();
    let _s = a.connect(
        dead,
        Sink {
            got: Arc::default(),
            done: tx,
            want: 0,
            echo: false,
        },
    );
    // The closed port answers with ICMP or nothing: the SYN times out (3 tries, backing off).
    let r = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(r, "error");
}

/// A raw uTP SYN (BEP 29 header: type 4, version 1) for connection id `id`.
fn syn(id: u16) -> Vec<u8> {
    let mut b = vec![0x41, 0];
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes()); // timestamp
    b.extend_from_slice(&0u32.to_be_bytes()); // timestamp difference
    b.extend_from_slice(&(1u32 << 20).to_be_bytes()); // window
    b.extend_from_slice(&1u16.to_be_bytes()); // seq
    b.extend_from_slice(&0u16.to_be_bytes()); // ack
    b
}

/// A SYN flood (the sender may be spoofed and never answers) fills the inbound table only up to
/// its cap; SYNs beyond it are dropped unanswered, and the cap can be raised.
#[test]
fn utp_inbound_table_is_capped() {
    let (b, _eb, baddr) = port();
    b.set_max_inbound(4);
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let acc = accepted.clone();
    let (tx, _rx) = mpsc::channel();
    b.on_accept(move |_s| {
        acc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(Box::new(Sink {
            got: Arc::default(),
            done: tx.clone(),
            want: usize::MAX,
            echo: false,
        }))
    });
    let flood = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    flood
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    for id in 0..20u16 {
        flood.send_to(&syn(id * 2), baddr).unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(b.utp_connections(), 4);
    assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 4);
    // Only the accepted ones were answered (one STATE each).
    let mut answers = 0;
    let mut buf = [0u8; 1500];
    while flood.recv_from(&mut buf).is_ok() {
        answers += 1;
    }
    assert_eq!(answers, 4);
    // A retransmitted SYN of an accepted connection is still handled (no new entry).
    flood.send_to(&syn(0), baddr).unwrap();
    // Raising the cap admits more.
    b.set_max_inbound(6);
    for id in 100..110u16 {
        flood.send_to(&syn(id * 2), baddr).unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(b.utp_connections(), 6);
}
