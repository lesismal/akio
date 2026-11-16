//! QUIC resource limits through the public API: the server's connection cap (refused with
//! CONNECTION_REFUSED), and stream send buffers (`Overloaded`, `on_stream_writable`) with a
//! producer that follows them, a peer that is cut midway, and work moved to the pool.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use only::{Engine, Listener};
use only_quic::{
    Bytes, Connection, ConnectionError, Error, QuicHandler, QuicServer, StreamId, TransportConfig,
};

fn tls() -> (Vec<only::tls::Certificate>, only::tls::PrivateKey) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    (
        vec![only::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
}

fn serve(server: QuicServer) -> (Engine, SocketAddr) {
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr)
}

fn client_engine() -> Engine {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    e
}

struct Quiet;
impl QuicHandler for Quiet {
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: Bytes, _fin: bool) {}
}

/// Reports the handshake (`Ok`) or the close reason (`Err`).
struct Watch(mpsc::Sender<Result<(), ConnectionError>>);
impl QuicHandler for Watch {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(Ok(()));
    }
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: Bytes, _fin: bool) {}
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        let _ = self.0.send(Err(r));
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn defaults_are_bounded() {
    let t = TransportConfig::default();
    assert_eq!(t.receive_window, Some(8 * t.stream_receive_window));
    assert_eq!(t.stream_send_buffer, 4 << 20);
    assert_eq!(t.send_buffer, 16 << 20);
    assert!(t.send_buffer > t.send_window);
    assert_eq!(only_quic::DEFAULT_MAX_CONNECTIONS, 10_000);
    assert_eq!(Error::Overloaded.to_string(), "quic: overloaded");
}

#[test]
fn connections_beyond_the_limit_are_refused() {
    let (certs, key) = tls();
    let cfg = only_quic::server_config(certs, key, &[b"lim"])
        .unwrap()
        .max_connections(2);
    let server = QuicServer::new(cfg, |_c: &Connection| Quiet);
    let (_s, addr) = serve(server.clone());
    let e = client_engine();
    let ccfg = only_quic::client_config_insecure(&[b"lim"]).unwrap();
    let dial = || {
        let (tx, rx) = mpsc::channel();
        let c = only_quic::dial(&e, addr, "localhost", ccfg.clone(), Watch(tx)).unwrap();
        (c, rx)
    };
    // Under and at the limit: accepted.
    let (c1, r1) = dial();
    assert_eq!(r1.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    let (_c2, r2) = dial();
    assert_eq!(r2.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    assert_eq!(server.connections(), 2);
    // Over it: refused at once, with no state kept on the server.
    let (_c3, r3) = dial();
    match r3.recv_timeout(Duration::from_secs(5)).unwrap() {
        Err(ConnectionError::ConnectionClosed { code, .. }) => assert_eq!(code, 0x2),
        other => panic!("expected CONNECTION_REFUSED, got {other:?}"),
    }
    assert_eq!(server.connections(), 2);
    assert_eq!(server.refused_connections(), 1);
    // A connection that goes away makes room again.
    c1.close(0, b"");
    wait_for("the closed connection to drain", || {
        server.connections() < 2
    });
    let (_c4, r4) = dial();
    assert_eq!(r4.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
}

/// Answers a stream's request with `total` bytes, written in `chunk`-byte pieces as the send
/// buffer allows, every other piece produced on the logical pool; counts what was accepted.
struct Producer {
    total: usize,
    chunk: usize,
    jobs: Arc<Mutex<Vec<Job>>>,
    accepted: Arc<AtomicU64>,
    refused: Arc<AtomicUsize>,
}

struct Job {
    id: StreamId,
    at: usize,
}

fn piece(at: usize, n: usize) -> Vec<u8> {
    (at..at + n).map(|i| (i % 251) as u8).collect()
}

impl Producer {
    /// Writes until the buffer refuses; `true` once the stream is finished.
    fn pump(&self, c: &Connection, id: StreamId) {
        let mut jobs = self.jobs.lock().unwrap();
        let Some(j) = jobs.iter_mut().find(|j| j.id == id) else {
            return;
        };
        loop {
            if j.at >= self.total {
                let _ = c.finish(id);
                jobs.retain(|j| j.id != id);
                return;
            }
            let n = self.chunk.min(self.total - j.at);
            if j.at / self.chunk % 2 == 1 {
                // Room first, then the piece is made off the I/O thread and sent from there.
                if c.send_capacity(id).unwrap_or(0) == 0 {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let (c2, at, acc) = (c.clone(), j.at, self.accepted.clone());
                j.at += n;
                let (tx, rx) = mpsc::channel();
                c.spawn_blocking(move || {
                    // The buffer had room: the write is accepted.
                    c2.send(id, piece(at, n)).expect("room was reported");
                    acc.fetch_add(n as u64, Ordering::Relaxed);
                    let _ = tx.send(());
                })
                .expect("pool");
                // Keep the order of the pieces: wait for the pool (a test, not a server).
                rx.recv_timeout(Duration::from_secs(5)).expect("pool ran");
                continue;
            }
            match c.send(id, piece(j.at, n)) {
                Ok(()) => {
                    self.accepted.fetch_add(n as u64, Ordering::Relaxed);
                    j.at += n;
                }
                Err(Error::Overloaded) => {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(e) => panic!("send: {e}"),
            }
        }
    }
}

impl QuicHandler for Producer {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, _d: Bytes, fin: bool) {
        if fin {
            self.jobs.lock().unwrap().push(Job { id, at: 0 });
            self.pump(c, id);
        }
    }
    fn on_stream_writable(&mut self, c: &Connection, id: StreamId) {
        self.pump(c, id);
    }
}

/// Checks what arrives on a stream against `piece` and counts it.
struct Reader {
    got: Arc<AtomicU64>,
    done: mpsc::Sender<()>,
}
impl QuicHandler for Reader {
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, d: Bytes, fin: bool) {
        let at = self.got.load(Ordering::Relaxed) as usize;
        assert_eq!(&d[..], &piece(at, d.len())[..], "bytes at {at}");
        self.got.fetch_add(d.len() as u64, Ordering::Relaxed);
        if fin {
            let _ = self.done.send(());
        }
    }
}

fn producer_server(
    total: usize,
    chunk: usize,
    t: &TransportConfig,
) -> (Engine, SocketAddr, Arc<AtomicU64>, Arc<AtomicUsize>) {
    let (certs, key) = tls();
    let cfg = only_quic::server_config(certs, key, &[b"lim"])
        .unwrap()
        .transport(t);
    let accepted = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let (a, r) = (accepted.clone(), refused.clone());
    let server = QuicServer::new(cfg, move |_c: &Connection| Producer {
        total,
        chunk,
        jobs: Arc::new(Mutex::new(Vec::new())),
        accepted: a.clone(),
        refused: r.clone(),
    });
    let (e, addr) = serve(server);
    (e, addr, accepted, refused)
}

#[test]
fn producer_follows_the_send_buffer() {
    let mut t = TransportConfig::default();
    t.stream_send_buffer = 256 << 10;
    let total = 8 << 20;
    let (_s, addr, accepted, refused) = producer_server(total, 64 << 10, &t);
    let e = client_engine();
    let got = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel();
    let c = only_quic::dial(
        &e,
        addr,
        "localhost",
        only_quic::client_config_insecure(&[b"lim"]).unwrap(),
        Reader {
            got: got.clone(),
            done: tx,
        },
    )
    .unwrap();
    wait_for("the handshake", || {
        c.open_bi().is_some_and(|id| {
            c.send(id, b"go".to_vec()).unwrap();
            c.finish(id).unwrap();
            true
        })
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the whole body");
    assert_eq!(got.load(Ordering::Relaxed), total as u64);
    assert_eq!(accepted.load(Ordering::Relaxed), total as u64);
    assert!(
        refused.load(Ordering::Relaxed) > 0,
        "the buffer never filled"
    );
}

#[test]
fn peer_cut_midway_leaves_the_buffer_bounded() {
    let mut t = TransportConfig::default();
    t.stream_send_buffer = 512 << 10;
    t.max_idle_timeout = Some(Duration::from_secs(1));
    // Far more than the buffer: the producer stops when the peer does.
    let (_s, addr, accepted, refused) = producer_server(1 << 30, 64 << 10, &t);
    let e = client_engine();
    let got = Arc::new(AtomicU64::new(0));
    let (tx, _rx) = mpsc::channel();
    let c = only_quic::dial(
        &e,
        addr,
        "localhost",
        only_quic::client_config_insecure(&[b"lim"]).unwrap(),
        Reader {
            got: got.clone(),
            done: tx,
        },
    )
    .unwrap();
    wait_for("the handshake", || {
        c.open_bi().is_some_and(|id| {
            c.send(id, b"go".to_vec()).unwrap();
            c.finish(id).unwrap();
            true
        })
    });
    wait_for("some data", || got.load(Ordering::Relaxed) > 1 << 20);
    // The client goes away without a word: nothing more is acknowledged.
    e.shutdown();
    e.wait();
    let received = got.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(1500));
    let acc = accepted.load(Ordering::Relaxed);
    assert!(refused.load(Ordering::Relaxed) > 0);
    // Accepted = acknowledged (at most what the client got) + held (the limit plus one piece).
    assert!(
        acc <= received + (512 << 10) + (64 << 10),
        "accepted {acc}, client received {received}"
    );
}
