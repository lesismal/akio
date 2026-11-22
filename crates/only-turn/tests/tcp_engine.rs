//! The engine-driven TCP allocation client ([`TcpAllocation`]) against an only-turn server on
//! real TCP and TLS listeners, peers as plain TCP sockets; and the server's own Connect
//! timeout (`TurnConfig::tcp_connect_timeout`), apart from the engine's `connect_timeout`.
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::tls::{self, Tls};
use only::{Acceptor, Config, Conn, Engine, Handler, Listener};
use only_turn::client::{
    AllocationEvent, ClientConfig, ClientError, ClientState, ServerTransport, TcpAllocation,
};
use only_turn::{TurnConfig, TurnServer, static_auth};

const WAIT: Duration = Duration::from_secs(10);

struct Server {
    _engine: Arc<Engine>,
    turn: TurnServer,
    tcp: SocketAddr,
    tls: SocketAddr,
}

fn server(engine_cfg: Config, f: impl FnOnce(&mut TurnConfig)) -> Server {
    let auth = static_auth("only", [("alice", "wonderland")]);
    let mut cfg =
        TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    f(&mut cfg);
    let turn = TurnServer::new(cfg);
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let scfg = tls::ServerConfig::builder(
        vec![tls::Certificate::from_der(ck.0.as_der().to_vec())],
        tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let engine = Arc::new(
        Engine::builder()
            .config(engine_cfg)
            .listen(Listener::tcp(any).threads(2).serve(turn.stream()))
            .listen(
                Listener::tcp(any)
                    .threads(1)
                    .serve(Tls::server(scfg, turn.stream())),
            )
            .client_threads(2)
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let a = engine.local_addrs();
    Server {
        _engine: engine,
        turn,
        tcp: a[0],
        tls: a[1],
    }
}

fn client_engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().client_threads(2).build().unwrap());
    e.start().unwrap();
    e
}

fn tls_transport() -> ServerTransport {
    let cfg = tls::ClientConfig::builder()
        .insecure_skip_verify()
        .build()
        .unwrap();
    ServerTransport::Tls(cfg, "localhost".into())
}

/// Opens an allocation whose events arrive on the receiver.
fn open(
    engine: &Arc<Engine>,
    server: SocketAddr,
    pass: &str,
    t: ServerTransport,
) -> (TcpAllocation, Receiver<AllocationEvent>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let cfg = ClientConfig::new(server, "alice", pass);
    let a = TcpAllocation::open(engine, cfg, t, move |_, e| {
        let _ = tx.lock().unwrap().send(e);
    });
    (a, rx)
}

fn allocated(rx: &Receiver<AllocationEvent>) -> SocketAddr {
    match rx.recv_timeout(WAIT).expect("no event") {
        AllocationEvent::Allocated { relayed, .. } => relayed,
        e => panic!("{e:?}"),
    }
}

/// What a data connection's handler saw.
#[derive(Debug)]
enum Seen {
    Open(Conn<Data>),
    Bytes(Vec<u8>),
    Closed(Option<String>),
}

/// Serves data connections: sends `greeting` from `on_open` (before the bind completes) and
/// reports everything on a channel.
struct DataAcceptor {
    tx: Mutex<Sender<Seen>>,
    greeting: &'static [u8],
}

struct Data {
    tx: Sender<Seen>,
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Data")
    }
}

impl Acceptor for DataAcceptor {
    type Handler = Data;
    fn on_open(&self, c: &Conn<Data>) -> Data {
        if !self.greeting.is_empty() {
            c.send(self.greeting).unwrap();
        }
        let tx = self.tx.lock().unwrap().clone();
        let _ = tx.send(Seen::Open(c.clone()));
        Data { tx }
    }
}

impl Handler for Data {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.tx.send(Seen::Bytes(data.to_vec()));
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        let _ = self.tx.send(Seen::Closed(err.map(|e| e.to_string())));
    }
}

fn data_acceptor(greeting: &'static [u8]) -> (DataAcceptor, Receiver<Seen>) {
    let (tx, rx) = mpsc::channel();
    (
        DataAcceptor {
            tx: Mutex::new(tx),
            greeting,
        },
        rx,
    )
}

fn opened(rx: &Receiver<Seen>) -> Conn<Data> {
    match rx.recv_timeout(WAIT).expect("no open") {
        Seen::Open(c) => c,
        e => panic!("{e:?}"),
    }
}

/// Collects `n` bytes the handler received.
fn bytes(rx: &Receiver<Seen>, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < n {
        match rx.recv_timeout(WAIT) {
            Ok(Seen::Bytes(b)) => out.extend_from_slice(&b),
            e => panic!("after {} of {n}: {e:?}", out.len()),
        }
    }
    out
}

fn closed(rx: &Receiver<Seen>) -> Option<String> {
    loop {
        match rx.recv_timeout(WAIT).expect("no close") {
            Seen::Closed(e) => return e,
            Seen::Bytes(_) => {}
            e => panic!("{e:?}"),
        }
    }
}

fn read_exact(s: &mut TcpStream, n: usize) -> Vec<u8> {
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut out = vec![0; n];
    s.read_exact(&mut out).unwrap();
    out
}

fn eof(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return true,
            Err(_) => return false,
        }
    }
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn pattern(n: usize, k: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(k) >> 3) as u8)
        .collect()
}

/// Connect and accept, over TCP and TLS: the handler's early bytes wait for the bind, the
/// peer's early bytes arrive first, 256 KiB each way, closing either side closes the other,
/// and `close` deletes the allocation.
#[test]
fn connect_and_accept_on_an_engine() {
    let srv = server(Config::default(), |_| {});
    let engine = client_engine();
    for (addr, t) in [(srv.tcp, ServerTransport::Tcp), (srv.tls, tls_transport())] {
        let (alloc, events) = open(&engine, addr, "wonderland", t);
        let relayed = allocated(&events);
        assert_eq!(alloc.relayed_addr(), Some(relayed));
        assert_eq!(alloc.state(), ClientState::Allocated);

        // Connect: the server dials the peer from the relayed address.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let pa = l.local_addr().unwrap();
        let (acc, seen) = data_acceptor(b"hello before the bind");
        let (etx, erx) = mpsc::channel::<ClientError>();
        assert!(alloc.connect(pa, acc, move |e| {
            let _ = etx.send(e);
        }));
        let (mut peer, from) = l.accept().unwrap();
        assert_eq!(from, relayed);
        let c = opened(&seen);
        assert_eq!(read_exact(&mut peer, 21), b"hello before the bind");
        let big = pattern(256 * 1024, 7);
        peer.write_all(&big).unwrap();
        assert_eq!(bytes(&seen, big.len()), big);
        let back = pattern(256 * 1024, 13);
        c.send(&back).unwrap();
        assert_eq!(read_exact(&mut peer, back.len()), back);
        // Closing the data connection closes the peer's.
        c.close();
        assert!(eof(&mut peer));
        assert!(erx.try_recv().is_err());

        // A peer with a permission connects; it sends before anyone accepted.
        assert!(alloc.create_permission("127.0.0.1:1".parse().unwrap()));
        std::thread::sleep(Duration::from_millis(200));
        let mut peer = TcpStream::connect(relayed).unwrap();
        peer.write_all(b"early bytes").unwrap();
        let id = match events.recv_timeout(WAIT).expect("no attempt") {
            AllocationEvent::ConnectionAttempt { peer: p, id } => {
                assert_eq!(p, peer.local_addr().unwrap());
                id
            }
            e => panic!("{e:?}"),
        };
        let (acc, seen) = data_acceptor(b"");
        alloc.accept(id, acc, |e| panic!("accept: {e}"));
        let c = opened(&seen);
        assert_eq!(bytes(&seen, 11), b"early bytes");
        c.send(b"welcome").unwrap();
        assert_eq!(read_exact(&mut peer, 7), b"welcome");
        // Closing the peer closes the data connection.
        drop(peer);
        let _ = closed(&seen);

        // Close: the allocation is deleted.
        alloc.close();
        match events.recv_timeout(WAIT).expect("no close") {
            AllocationEvent::Closed => {}
            e => panic!("{e:?}"),
        }
        assert_eq!(alloc.state(), ClientState::Closed);
        wait_for("no allocation", || srv.turn.stats().allocations == 0);
        wait_for("no connection", || srv.turn.stats().tcp_connections == 0);
    }
}

/// Failures: a peer that refuses (447 to `on_error`), a bind of an unknown id (the data
/// connection closes with the error), wrong credentials (`Failed`), and the last handle
/// dropped (the server loses the allocation).
#[test]
fn failures_on_an_engine() {
    let srv = server(Config::default(), |_| {});
    let engine = client_engine();

    let (_bad, events) = open(&engine, srv.tcp, "wrong", ServerTransport::Tcp);
    match events.recv_timeout(WAIT).expect("no event") {
        AllocationEvent::Failed(ClientError::Rejected(401, _)) => {}
        e => panic!("{e:?}"),
    }

    let (alloc, events) = open(&engine, srv.tcp, "wonderland", ServerTransport::Tcp);
    allocated(&events);
    // Nobody listens there: 447.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (acc, _seen) = data_acceptor(b"");
    let (etx, erx) = mpsc::channel();
    assert!(alloc.connect(dead, acc, move |e| {
        let _ = etx.send(e);
    }));
    match erx.recv_timeout(WAIT).expect("no error") {
        ClientError::Rejected(447, _) => {}
        e => panic!("{e:?}"),
    }
    // An id the server never gave: the bind is refused and the connection closes with it.
    let (acc, seen) = data_acceptor(b"never sent");
    let (etx, erx) = mpsc::channel();
    alloc.accept(0x5eed, acc, move |e| {
        let _ = etx.send(e);
    });
    let _ = opened(&seen);
    match erx.recv_timeout(WAIT).expect("no error") {
        ClientError::Rejected(400, _) => {}
        e => panic!("{e:?}"),
    }
    let _ = closed(&seen);
    assert!(
        erx.recv_timeout(Duration::from_millis(200)).is_err(),
        "reported twice"
    );
    // A server that is gone: the dial fails.
    let gone = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (_lost, events) = open(&engine, gone, "wonderland", ServerTransport::Tcp);
    match events.recv_timeout(WAIT).expect("no event") {
        AllocationEvent::Failed(ClientError::Io(..)) => {}
        e => panic!("{e:?}"),
    }

    // Dropping the last handle closes the control connection: the server forgets it all.
    assert_eq!(srv.turn.stats().allocations, 1);
    drop(alloc);
    wait_for("no allocation", || srv.turn.stats().allocations == 0);
}

/// A listener that never completes a handshake: its accept queue is full and nobody accepts
/// (SYNs are dropped). `None` where the platform completes them anyway.
fn black_hole() -> Option<(SocketAddr, Vec<TcpStream>, TcpListener)> {
    let l = only_sys::listen("127.0.0.1:0".parse().unwrap(), false, 1).ok()?;
    let a = l.local_addr().ok()?;
    let mut held = Vec::new();
    for _ in 0..16 {
        match TcpStream::connect_timeout(&a, Duration::from_millis(300)) {
            Ok(s) => held.push(s),
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Some((a, held, l));
            }
            Err(_) => return None, // reset (macOS): no black hole
        }
    }
    None
}

/// The server's Connect timeout is its own: with the engine's `connect_timeout` at 200 ms and
/// `tcp_connect_timeout` at 1.5 s, a peer that never answers gets 447 after 1.5 s, not 200 ms.
#[test]
fn connect_timeout_is_not_the_engines() {
    let Some((hole, _held, _l)) = black_hole() else {
        eprintln!("skipped: this platform completes handshakes past the backlog");
        return;
    };
    let mut ecfg = Config::default();
    ecfg.connect_timeout = Some(Duration::from_millis(200));
    let srv = server(ecfg, |c| {
        c.tcp_connect_timeout = Duration::from_millis(1500);
    });
    let engine = client_engine();
    let (alloc, events) = open(&engine, srv.tcp, "wonderland", ServerTransport::Tcp);
    allocated(&events);
    let (acc, _seen) = data_acceptor(b"");
    let (etx, erx) = mpsc::channel();
    let start = Instant::now();
    assert!(alloc.connect(hole, acc, move |e| {
        let _ = etx.send(e);
    }));
    match erx.recv_timeout(WAIT).expect("no answer") {
        ClientError::Rejected(447, _) => {}
        e => panic!("{e:?}"),
    }
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1400) && took < Duration::from_secs(4),
        "447 after {took:?}"
    );
    wait_for("no connection", || srv.turn.stats().tcp_connections == 0);
}
