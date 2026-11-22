//! TCP allocations (RFC 6062) end to end: an akio-turn server on TCP and TLS listeners, the
//! crate's sans-io client on blocking sockets, peers as plain TCP sockets.
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use akio::tls::{self, Tls};
use akio::{Engine, Listener};
use akio_turn::client::{
    Client, ClientConfig, ClientError, ClientEvent, ClientState, DataConnection, DataState,
};
use akio_turn::framing::FrameReader;
use akio_turn::stun::{
    Class, Message, MessageBuilder, Method, attr, long_term_key, transaction_id,
};
use akio_turn::{TurnConfig, TurnServer, static_auth};

const WAIT: Duration = Duration::from_secs(10);

struct Server {
    _engine: Arc<Engine>,
    turn: TurnServer,
    tcp: SocketAddr,
    tls: SocketAddr,
}

fn server(f: impl FnOnce(&mut TurnConfig)) -> Server {
    let auth = static_auth("akio", [("alice", "wonderland"), ("bob", "builder")]);
    let mut cfg =
        TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    f(&mut cfg);
    let turn = TurnServer::new(cfg);
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let scfg = tls::ServerConfig::builder(
        vec![tls::Certificate::from_der(ck.0.as_der().to_vec())],
        tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let engine = Arc::new(
        Engine::builder()
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

trait Wire: Read + Write {}
impl<T: Read + Write> Wire for T {}

fn tcp(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn tls_client(addr: SocketAddr) -> Box<dyn Wire> {
    let cfg = tls::ClientConfig::builder()
        .insecure_skip_verify()
        .build()
        .unwrap();
    Box::new(tls::stream::Stream::client(&cfg, "localhost", tcp(addr)).unwrap())
}

fn read_some(s: &mut dyn Read, buf: &mut [u8]) -> Option<usize> {
    match s.read(buf) {
        Ok(n) => Some(n),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => None,
        Err(e) if e.kind() == ErrorKind::ConnectionReset => Some(0),
        Err(e) => panic!("{e}"),
    }
}

/// A TCP allocation's control connection.
struct Control {
    s: Box<dyn Wire>,
    c: Client,
    reader: FrameReader,
    events: Vec<ClientEvent>,
}

impl Control {
    fn new(s: Box<dyn Wire>, server: SocketAddr, user: (&str, &str)) -> Control {
        let cfg = ClientConfig::new(server, user.0, user.1).tcp_allocation(true);
        Control {
            s,
            c: Client::new(cfg, Instant::now()),
            reader: FrameReader::new(),
            events: Vec::new(),
        }
    }

    fn run(&mut self, t: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let end = Instant::now() + t;
        let mut buf = vec![0u8; 65536];
        while Instant::now() < end {
            while let Some(m) = self.c.poll_transmit() {
                self.s.write_all(&m).unwrap();
            }
            let _ = self.s.flush();
            if done(self) {
                return true;
            }
            if let Some(n) = read_some(&mut self.s, &mut buf) {
                if n == 0 {
                    return done(self);
                }
                let c = &mut self.c;
                self.reader
                    .push(&buf[..n], |m| {
                        assert!(c.handle_input(Instant::now(), m).is_none());
                    })
                    .unwrap();
            }
            self.c.handle_timeout(Instant::now());
            self.events
                .extend(std::iter::from_fn(|| self.c.poll_event()));
        }
        done(self)
    }

    fn allocate(&mut self) -> SocketAddr {
        assert!(self.run(WAIT, |s| s.c.state() != ClientState::Allocating));
        match self.events.remove(0) {
            ClientEvent::Allocated { relayed, .. } => relayed,
            e => panic!("{e:?}"),
        }
    }

    /// Waits for the next event.
    fn event(&mut self) -> ClientEvent {
        assert!(self.run(WAIT, |s| !s.events.is_empty()), "no event");
        self.events.remove(0)
    }

    fn connect(&mut self, peer: SocketAddr) -> u32 {
        assert!(self.c.connect(Instant::now(), peer));
        match self.event() {
            ClientEvent::Connected { peer: p, id } if p == peer => id,
            e => panic!("{e:?}"),
        }
    }

    fn permit(&mut self, peer: SocketAddr) {
        assert!(self.c.create_permission(Instant::now(), peer));
        // Let the CreatePermission be answered.
        self.run(Duration::from_millis(300), |_| false);
    }
}

/// Binds a new connection to `id`; returns it with the peer's first bytes.
fn bind_data(ctl: &Control, s: &mut dyn Wire, id: u32) -> Result<Vec<u8>, ClientError> {
    let mut d: DataConnection = ctl.c.data_connection(Instant::now(), id).unwrap();
    let mut buf = vec![0u8; 65536];
    let end = Instant::now() + WAIT;
    loop {
        while let Some(m) = d.poll_transmit() {
            s.write_all(&m).unwrap();
        }
        let _ = s.flush();
        match d.state() {
            DataState::Binding => {}
            DataState::Bound => unreachable!(),
            DataState::Failed(e) => return Err(e.clone()),
        }
        assert!(Instant::now() < end, "bind timed out");
        if let Some(n) = read_some(s, &mut buf) {
            if n == 0 {
                return Err(ClientError::Protocol("closed"));
            }
            let used = d.handle_input(&buf[..n]);
            if *d.state() == DataState::Bound {
                return Ok(buf[used..n].to_vec());
            }
        }
        d.handle_timeout(Instant::now());
    }
}

fn read_exact(s: &mut dyn Read, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let end = Instant::now() + WAIT;
    while out.len() < n {
        assert!(Instant::now() < end, "read {} of {n}", out.len());
        match read_some(s, &mut buf) {
            Some(0) => panic!("closed after {} of {n}", out.len()),
            Some(k) => out.extend_from_slice(&buf[..k]),
            None => {}
        }
    }
    out
}

/// Waits for EOF (or a reset) on `s`.
fn closed(s: &mut dyn Read) -> bool {
    let mut buf = [0u8; 1024];
    let end = Instant::now() + WAIT;
    while Instant::now() < end {
        if read_some(s, &mut buf) == Some(0) {
            return true;
        }
    }
    false
}

/// A peer listening on TCP; echoes when asked.
fn peer_listener() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

fn accept(l: &TcpListener) -> TcpStream {
    let (s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    s
}

fn wait_stats(turn: &TurnServer, conns: usize) {
    let end = Instant::now() + WAIT;
    while turn.stats().tcp_connections != conns {
        assert!(Instant::now() < end, "{:?}", turn.stats());
        thread::sleep(Duration::from_millis(10));
    }
}

/// Connect: the server connects from the relayed address; data both ways; closing the data
/// connection closes the peer's.
#[test]
fn connect_relays_both_ways() {
    let srv = server(|_| {});
    let mut ctl = Control::new(Box::new(tcp(srv.tcp)), srv.tcp, ("alice", "wonderland"));
    let relayed = ctl.allocate();
    let (l, pa) = peer_listener();
    let id = ctl.connect(pa);
    let mut peer = accept(&l);
    // The connection comes from the relayed transport address (RFC 6062 section 5.2).
    assert_eq!(peer.peer_addr().unwrap(), relayed);
    // The peer talks first: held until the bind, then delivered.
    peer.write_all(b"early bytes").unwrap();
    thread::sleep(Duration::from_millis(50));
    let mut data = tcp(srv.tcp);
    let first = bind_data(&ctl, &mut data, id).unwrap();
    let rest = read_exact(&mut data, b"early bytes".len() - first.len());
    assert_eq!([first, rest].concat(), b"early bytes");
    data.write_all(b"to the peer").unwrap();
    assert_eq!(read_exact(&mut peer, 11), b"to the peer");
    // 1 MiB each way, interleaved.
    let big: Vec<u8> = (0..1 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
    let mut pw = peer.try_clone().unwrap();
    let b2 = big.clone();
    let w = thread::spawn(move || pw.write_all(&b2).unwrap());
    data.write_all(&big).unwrap();
    assert_eq!(read_exact(&mut peer, big.len()), big);
    assert_eq!(read_exact(&mut data, big.len()), big);
    w.join().unwrap();
    wait_stats(&srv.turn, 1);
    drop(data);
    assert!(closed(&mut peer));
    wait_stats(&srv.turn, 0);
    // Another Connect works once the first is gone (to another peer port: the same 4-tuple
    // sits in TIME_WAIT on the server for a while, and clients wait 10 s before retrying the
    // same peer, RFC 6062 section 4.3).
    let (l2, pa2) = peer_listener();
    let _id2 = ctl.connect(pa2);
    let peer2 = accept(&l2);
    drop(l);
    // The peer closing closes the client's data connection.
    let mut data2 = tcp(srv.tcp);
    bind_data(&ctl, &mut data2, _id2).unwrap();
    peer2.shutdown(Shutdown::Both).unwrap();
    assert!(closed(&mut data2));
    wait_stats(&srv.turn, 0);
}

/// A peer connecting to the relayed address: refused without a permission, a
/// ConnectionAttempt with one.
#[test]
fn peer_initiated_connections() {
    let srv = server(|_| {});
    let mut ctl = Control::new(Box::new(tcp(srv.tcp)), srv.tcp, ("alice", "wonderland"));
    let relayed = ctl.allocate();
    // No permission: accepted, then closed at once; the client hears nothing.
    let mut p = tcp(relayed);
    assert!(closed(&mut p));
    assert!(!ctl.run(Duration::from_millis(200), |s| !s.events.is_empty()));
    ctl.permit("127.0.0.1:9".parse().unwrap()); // any port: permissions are per IP
    let mut p = tcp(relayed);
    let pa = p.local_addr().unwrap();
    p.write_all(b"hello from the peer").unwrap();
    let id = match ctl.event() {
        ClientEvent::ConnectionAttempt { peer, id } => {
            assert_eq!(peer, pa);
            id
        }
        e => panic!("{e:?}"),
    };
    // Over TLS this time.
    let mut data = tls_client(srv.tls);
    let first = bind_data(&ctl, &mut *data, id).unwrap();
    let rest = read_exact(&mut *data, 19 - first.len());
    assert_eq!([first, rest].concat(), b"hello from the peer");
    data.write_all(b"and back").unwrap();
    data.flush().unwrap();
    assert_eq!(read_exact(&mut p, 8), b"and back");
    // A second ConnectionBind for the same id is refused (it is bound already).
    let mut again = tcp(srv.tcp);
    assert!(matches!(
        bind_data(&ctl, &mut again, id),
        Err(ClientError::Rejected(400, _))
    ));
    // The control connection going takes the allocation and its connections.
    drop(ctl);
    assert!(closed(&mut p));
    assert!(closed(&mut *data));
    wait_stats(&srv.turn, 0);
    assert_eq!(srv.turn.stats().allocations, 0);
}

/// Error cases of Connect and ConnectionBind.
#[test]
fn connect_and_bind_errors() {
    let srv = server(|c| c.max_tcp_connections = 2);
    let mut ctl = Control::new(Box::new(tcp(srv.tcp)), srv.tcp, ("alice", "wonderland"));
    ctl.allocate();
    // Nobody listening: 447.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    assert!(ctl.c.connect(Instant::now(), dead));
    match ctl.event() {
        ClientEvent::ConnectFailed(p, ClientError::Rejected(447, _)) => assert_eq!(p, dead),
        e => panic!("{e:?}"),
    }
    // A second Connect to a peer with a connection: 446.
    let (l, pa) = peer_listener();
    let id = ctl.connect(pa);
    let _peer = accept(&l);
    assert!(ctl.c.connect(Instant::now(), pa));
    match ctl.event() {
        ClientEvent::ConnectFailed(_, ClientError::Rejected(446, _)) => {}
        e => panic!("{e:?}"),
    }
    // The per-allocation limit: 508.
    let (l2, pa2) = peer_listener();
    let _id2 = ctl.connect(pa2);
    let _peer2 = accept(&l2);
    let (_l3, pa3) = peer_listener();
    assert!(ctl.c.connect(Instant::now(), pa3));
    match ctl.event() {
        ClientEvent::ConnectFailed(_, ClientError::Rejected(508, _)) => {}
        e => panic!("{e:?}"),
    }
    // ConnectionBind on the control connection itself: 400, and the allocation stays.
    let mut own = ctl.c.data_connection(Instant::now(), id).unwrap();
    while let Some(m) = own.poll_transmit() {
        ctl.s.write_all(&m).unwrap();
    }
    let mut buf = vec![0u8; 4096];
    let mut r = FrameReader::new();
    let mut got = None;
    let end = Instant::now() + WAIT;
    while got.is_none() && Instant::now() < end {
        if let Some(n) = read_some(&mut ctl.s, &mut buf) {
            r.push(&buf[..n], |m| {
                let msg = Message::parse(m).unwrap();
                if msg.method() == Method::CONNECTION_BIND {
                    got = msg.error_code().map(|e| e.0);
                }
            })
            .unwrap();
        }
    }
    assert_eq!(got, Some(400));
    assert_eq!(srv.turn.stats().allocations, 1);
    // ConnectionBind: an unknown id, and another user's connection, are 400.
    let mut d = tcp(srv.tcp);
    assert!(matches!(
        bind_data(&ctl, &mut d, id ^ 0x5555_5555),
        Err(ClientError::Rejected(400, _))
    ));
    let mut bob = Control::new(Box::new(tcp(srv.tcp)), srv.tcp, ("bob", "builder"));
    bob.allocate();
    let mut d = tcp(srv.tcp);
    assert!(matches!(
        bind_data(&bob, &mut d, id),
        Err(ClientError::Rejected(400, _))
    ));
    // Still bindable by its owner.
    let mut d = tcp(srv.tcp);
    bind_data(&ctl, &mut d, id).unwrap();
}

/// What a raw client gets for TCP allocations the server must refuse.
#[test]
fn tcp_allocate_refusals() {
    fn allocate_raw(s: &mut TcpStream, extra: &[(u16, &[u8])]) -> u16 {
        // First the challenge, then the authenticated request.
        let tid = transaction_id();
        let req = MessageBuilder::new(Method::ALLOCATE, Class::Request, tid)
            .u32(attr::REQUESTED_TRANSPORT, 6 << 24)
            .build();
        s.write_all(&req).unwrap();
        let ch = read_msg(s);
        let m = Message::parse(&ch).unwrap();
        let nonce = m.get_str(attr::NONCE).unwrap().to_owned();
        let mut b = MessageBuilder::new(Method::ALLOCATE, Class::Request, transaction_id())
            .u32(attr::REQUESTED_TRANSPORT, 6 << 24);
        for (t, v) in extra {
            b = b.attr(*t, v);
        }
        let req = b
            .attr(attr::USERNAME, b"alice")
            .attr(attr::REALM, b"akio")
            .attr(attr::NONCE, nonce.as_bytes())
            .integrity(&long_term_key("alice", "akio", "wonderland"))
            .build();
        s.write_all(&req).unwrap();
        let r = read_msg(s);
        let m = Message::parse(&r).unwrap();
        if m.class() == Class::Success {
            return 200;
        }
        m.error_code().unwrap().0
    }
    fn read_msg(s: &mut TcpStream) -> Vec<u8> {
        let mut r = FrameReader::new();
        let mut out = None;
        let mut buf = [0u8; 4096];
        let end = Instant::now() + WAIT;
        while out.is_none() {
            assert!(Instant::now() < end);
            if let Some(n) = read_some(s, &mut buf) {
                assert!(n > 0);
                r.push(&buf[..n], |m| out = Some(m.to_vec())).unwrap();
            }
        }
        out.unwrap()
    }
    let srv = server(|_| {});
    assert_eq!(
        allocate_raw(&mut tcp(srv.tcp), &[(attr::EVEN_PORT, &[0])]),
        400
    );
    assert_eq!(
        allocate_raw(&mut tcp(srv.tcp), &[(attr::DONT_FRAGMENT, &[])]),
        400
    );
    assert_eq!(allocate_raw(&mut tcp(srv.tcp), &[]), 200);
    let off = server(|c| c.tcp_relays = false);
    assert_eq!(allocate_raw(&mut tcp(off.tcp), &[]), 442);
}

/// A data connection that does not read: the server stops reading the peer (its writes stall)
/// instead of queueing; nothing is lost once the client reads again.
#[test]
fn backpressure_from_a_slow_data_connection() {
    let srv = server(|c| c.tcp_relay_buffer = 16 * 1024);
    let mut ctl = Control::new(Box::new(tcp(srv.tcp)), srv.tcp, ("alice", "wonderland"));
    ctl.allocate();
    let (l, pa) = peer_listener();
    let id = ctl.connect(pa);
    let peer = accept(&l);
    let mut data = tcp(srv.tcp);
    let first = bind_data(&ctl, &mut data, id).unwrap();
    assert!(first.is_empty());
    let total = 64 << 20;
    let mut pw = peer.try_clone().unwrap();
    pw.set_nonblocking(true).unwrap();
    let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wn = written.clone();
    let w = thread::spawn(move || {
        let chunk: Vec<u8> = (0..65536).map(|i| (i % 253) as u8).collect();
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(chunk.len());
            let off = sent % chunk.len();
            let m = n.min(chunk.len() - off);
            match pw.write(&chunk[off..off + m]) {
                Ok(k) => {
                    sent += k;
                    wn.store(sent, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    // The client does not read: the peer's writes stall well short of the total (socket
    // buffers on both hops plus the relay's mark, never 64 MiB).
    thread::sleep(Duration::from_millis(800));
    let stalled = written.load(std::sync::atomic::Ordering::Relaxed);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        stalled,
        written.load(std::sync::atomic::Ordering::Relaxed),
        "writes did not stall"
    );
    assert!(stalled < total / 2, "{stalled}");
    // Now read everything, in order.
    let got = read_exact(&mut data, total);
    w.join().unwrap();
    assert!(
        got.iter()
            .enumerate()
            .all(|(i, b)| *b == ((i % 65536) % 253) as u8)
    );
    drop(peer);
}
