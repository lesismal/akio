//! TCP allocations (RFC 6062) across implementations (`tools/interop/webrtc/turn-tcp.sh`).
//!
//! ```text
//! turn-tcp-interop server <tcp-addr> <tls-addr> <user> <pass>
//!     an only-turn server (realm "only") on a TCP and a TLS listener (self-signed), relaying
//!     from 127.0.0.1 and allowing loopback peers
//! turn-tcp-interop client <tcp|tls> <server> <user> <pass>
//!     the only_turn client: a TCP allocation; Connect to a local TCP echo peer and a
//!     ConnectionBind on a new connection, then a permission and a local peer connecting to
//!     the relayed address (ConnectionAttempt, ConnectionBind); 20 messages and 1 MiB echoed
//!     on each
//! turn-tcp-interop engine-client <tcp|tls> <server> <user> <pass>
//!     the same with the engine-driven client (`TcpAllocation`): data connections are engine
//!     connections served by a handler, nothing blocks
//! ```
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::tls::{self, Tls};
use only::{Acceptor, Conn, Engine, Handler, Listener};
use only_turn::client::{
    AllocationEvent, Client, ClientConfig, ClientEvent, ClientState, DataState, ServerTransport,
    TcpAllocation,
};
use only_turn::framing::FrameReader;
use only_turn::{TurnConfig, TurnServer, static_auth};

trait Wire: Read + Write + Send {}
impl<T: Read + Write + Send> Wire for T {}

fn connect(transport: &str, addr: SocketAddr) -> Box<dyn Wire> {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(20)))
        .expect("timeout");
    s.set_nodelay(true).expect("nodelay");
    if transport == "tls" {
        let cfg = tls::ClientConfig::builder()
            .insecure_skip_verify()
            .build()
            .expect("tls config");
        Box::new(tls::stream::Stream::client(&cfg, "localhost", s).expect("tls"))
    } else {
        Box::new(s)
    }
}

fn read_some(s: &mut dyn Read, buf: &mut [u8]) -> Option<usize> {
    match s.read(buf) {
        Ok(n) => Some(n),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => None,
        Err(e) => panic!("read: {e}"),
    }
}

struct Control {
    s: Box<dyn Wire>,
    c: Client,
    reader: FrameReader,
}

impl Control {
    /// Runs the control connection until an event arrives.
    fn event(&mut self) -> ClientEvent {
        let end = Instant::now() + Duration::from_secs(20);
        let mut buf = vec![0u8; 65536];
        loop {
            while let Some(m) = self.c.poll_transmit() {
                self.s.write_all(&m).expect("write");
            }
            self.s.flush().expect("flush");
            if let Some(e) = self.c.poll_event() {
                return e;
            }
            assert!(Instant::now() < end, "no event: {:?}", self.c);
            if let Some(n) = read_some(&mut self.s, &mut buf) {
                assert!(n > 0, "the server closed the control connection");
                let c = &mut self.c;
                self.reader
                    .push(&buf[..n], |m| {
                        c.handle_input(Instant::now(), m);
                    })
                    .expect("framing");
            }
            self.c.handle_timeout(Instant::now());
        }
    }
}

/// A new connection to the server bound to `id`; returns it and the peer's first bytes.
fn bind(ctl: &Control, transport: &str, id: u32) -> (Box<dyn Wire>, Vec<u8>) {
    let mut s = connect(transport, ctl.c.config().server);
    let mut d = ctl
        .c
        .data_connection(Instant::now(), id)
        .expect("credentials");
    let mut buf = vec![0u8; 65536];
    loop {
        while let Some(m) = d.poll_transmit() {
            s.write_all(&m).expect("write");
        }
        s.flush().expect("flush");
        match d.state() {
            DataState::Binding => {}
            DataState::Bound => unreachable!(),
            DataState::Failed(e) => panic!("ConnectionBind: {e}"),
        }
        if let Some(n) = read_some(&mut s, &mut buf) {
            assert!(n > 0, "the server closed the data connection");
            let used = d.handle_input(&buf[..n]);
            if *d.state() == DataState::Bound {
                return (s, buf[used..n].to_vec());
            }
        }
        d.handle_timeout(Instant::now());
    }
}

fn read_n(s: &mut dyn Read, mut have: Vec<u8>, n: usize) -> Vec<u8> {
    let end = Instant::now() + Duration::from_secs(20);
    let mut buf = vec![0u8; 65536];
    while have.len() < n {
        assert!(Instant::now() < end, "read {} of {n}", have.len());
        if let Some(k) = read_some(s, &mut buf) {
            assert!(k > 0, "closed after {} of {n}", have.len());
            have.extend_from_slice(&buf[..k]);
        }
    }
    have
}

/// 20 messages, then 1 MiB, echoed by the peer.
fn echo(s: &mut dyn Wire, first: Vec<u8>, what: &str) {
    let mut first = Some(first);
    for i in 0..20 {
        let msg = format!("through the tcp relay {i}");
        s.write_all(msg.as_bytes()).expect("write");
        s.flush().expect("flush");
        let got = read_n(s, first.take().unwrap_or_default(), msg.len());
        assert_eq!(got, msg.as_bytes(), "{what} echo {i}");
    }
    // Reads keep up with writes (at most 256 KiB in flight): nothing waits on buffer sizes.
    let big: Vec<u8> = (0..1u32 << 20).map(|i| (i * 7) as u8).collect();
    let mut got = Vec::new();
    for (i, chunk) in big.chunks(64 * 1024).enumerate() {
        s.write_all(chunk).expect("write");
        s.flush().expect("flush");
        let behind = ((i + 1) * 64 * 1024).saturating_sub(256 * 1024);
        got = read_n(s, got, behind);
    }
    assert!(read_n(s, got, big.len()) == big, "{what}: 1 MiB differs");
}

fn client(transport: &str, server: &str, user: &str, pass: &str) {
    let addr: SocketAddr = server.parse().expect("server");
    let cfg = ClientConfig::new(addr, user, pass).tcp_allocation(true);
    let mut ctl = Control {
        s: connect(transport, addr),
        c: Client::new(cfg, Instant::now()),
        reader: FrameReader::new(),
    };
    let relayed = match ctl.event() {
        ClientEvent::Allocated { relayed, .. } => relayed,
        e => panic!("{e:?}"),
    };
    eprintln!("turn-tcp: TCP allocation {relayed} over {transport}");
    // A TCP echo peer.
    let l = TcpListener::bind("127.0.0.1:0").expect("peer");
    let pa = l.local_addr().expect("peer addr");
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().expect("clone");
                let _ = std::io::copy(&mut r, &mut s);
            });
        }
    });
    // Connect, then bind.
    assert!(ctl.c.connect(Instant::now(), pa));
    let id = match ctl.event() {
        ClientEvent::Connected { peer, id } if peer == pa => id,
        e => panic!("{e:?}"),
    };
    let (mut data, first) = bind(&ctl, transport, id);
    echo(&mut *data, first, "connect");
    drop(data);
    // A peer connecting to the relayed address, with a permission.
    assert!(ctl.c.create_permission(Instant::now(), pa));
    let probe = std::thread::spawn(move || {
        // Give the permission a moment, then connect and echo.
        std::thread::sleep(Duration::from_millis(300));
        let mut p = TcpStream::connect(relayed).expect("connect to the relayed address");
        let mut r = p.try_clone().expect("clone");
        let _ = std::io::copy(&mut r, &mut p);
    });
    let id = match ctl.event() {
        ClientEvent::ConnectionAttempt { peer, id } => {
            assert_eq!(peer.ip(), pa.ip());
            id
        }
        e => panic!("{e:?}"),
    };
    let (mut data, first) = bind(&ctl, transport, id);
    echo(&mut *data, first, "connection attempt");
    drop(data);
    let _ = probe.join();
    ctl.c.close(Instant::now());
    while ctl.c.state() == ClientState::Closing {
        if matches!(ctl.event(), ClientEvent::Closed) {
            break;
        }
    }
    println!(
        "ok: only_turn TCP allocation {relayed} over {transport}: Connect and ConnectionAttempt, ConnectionBind, 20 messages and 1 MiB echoed on each"
    );
}

/// A TCP echo peer; returns its address.
fn echo_peer() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("peer");
    let pa = l.local_addr().expect("peer addr");
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().expect("clone");
                let _ = std::io::copy(&mut r, &mut s);
            });
        }
    });
    pa
}

/// A data connection's handler: what it reads goes to a channel (`None`: closed).
struct Sink(Sender<Option<Vec<u8>>>);

impl Handler for Sink {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(Some(data.to_vec()));
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        let _ = self.0.send(None);
    }
}

type Opened = (Conn<Sink>, Receiver<Option<Vec<u8>>>);

struct SinkAcceptor(Mutex<Sender<Opened>>);

impl Acceptor for SinkAcceptor {
    type Handler = Sink;
    fn on_open(&self, c: &Conn<Sink>) -> Sink {
        let (tx, rx) = mpsc::channel();
        let _ = self.0.lock().expect("lock").send((c.clone(), rx));
        Sink(tx)
    }
}

fn sink() -> (SinkAcceptor, Receiver<Opened>) {
    let (tx, rx) = mpsc::channel();
    (SinkAcceptor(Mutex::new(tx)), rx)
}

fn take(rx: &Receiver<Option<Vec<u8>>>, have: &mut Vec<u8>, n: usize, what: &str) {
    while have.len() < n {
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Some(b)) => have.extend_from_slice(&b),
            Ok(None) => panic!("{what}: closed after {} of {n}", have.len()),
            Err(_) => panic!("{what}: read {} of {n}", have.len()),
        }
    }
}

/// 20 messages, then 1 MiB, echoed by the peer, over an engine connection.
fn echo_engine((c, rx): Opened, what: &str) {
    for i in 0..20 {
        let msg = format!("through the tcp relay {i}");
        c.send(msg.as_bytes()).expect("send");
        let mut got = Vec::new();
        take(&rx, &mut got, msg.len(), what);
        assert_eq!(got, msg.as_bytes(), "{what} echo {i}");
    }
    let big: Vec<u8> = (0..1u32 << 20).map(|i| (i * 7) as u8).collect();
    let mut got = Vec::new();
    for (i, chunk) in big.chunks(64 * 1024).enumerate() {
        c.send(chunk).expect("send");
        let behind = ((i + 1) * 64 * 1024).saturating_sub(256 * 1024);
        take(&rx, &mut got, behind, what);
    }
    take(&rx, &mut got, big.len(), what);
    assert!(got == big, "{what}: 1 MiB differs");
    c.close();
}

fn engine_client(transport: &str, server: &str, user: &str, pass: &str) {
    let addr: SocketAddr = server.parse().expect("server");
    let engine = Arc::new(Engine::builder().client_threads(2).build().expect("engine"));
    engine.start().expect("start");
    let t = if transport == "tls" {
        let cfg = tls::ClientConfig::builder()
            .insecure_skip_verify()
            .build()
            .expect("tls config");
        ServerTransport::Tls(cfg, "localhost".into())
    } else {
        ServerTransport::Tcp
    };
    let (etx, events) = mpsc::channel();
    let etx = Mutex::new(etx);
    let alloc = TcpAllocation::open(
        &engine,
        ClientConfig::new(addr, user, pass),
        t,
        move |_, e| {
            let _ = etx.lock().expect("lock").send(e);
        },
    );
    let event = || {
        events
            .recv_timeout(Duration::from_secs(20))
            .expect("no event")
    };
    let relayed = match event() {
        AllocationEvent::Allocated { relayed, .. } => relayed,
        e => panic!("{e:?}"),
    };
    eprintln!("turn-tcp: engine TCP allocation {relayed} over {transport}");
    let pa = echo_peer();
    // Connect: bound and served by the handler without a blocking call.
    let (acc, opened) = sink();
    assert!(alloc.connect(pa, acc, |e| panic!("connect: {e}")));
    let o = opened
        .recv_timeout(Duration::from_secs(20))
        .expect("no data connection");
    echo_engine(o, "engine connect");
    // A peer connecting with a permission, taken with accept.
    assert!(alloc.create_permission(pa));
    let probe = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let mut p = TcpStream::connect(relayed).expect("connect to the relayed address");
        let mut r = p.try_clone().expect("clone");
        let _ = std::io::copy(&mut r, &mut p);
    });
    let id = match event() {
        AllocationEvent::ConnectionAttempt { peer, id } => {
            assert_eq!(peer.ip(), pa.ip());
            id
        }
        e => panic!("{e:?}"),
    };
    let (acc, opened) = sink();
    alloc.accept(id, acc, |e| panic!("accept: {e}"));
    let o = opened
        .recv_timeout(Duration::from_secs(20))
        .expect("no data connection");
    echo_engine(o, "engine connection attempt");
    let _ = probe.join();
    alloc.close();
    match event() {
        AllocationEvent::Closed => {}
        e => panic!("{e:?}"),
    }
    println!(
        "ok: engine TcpAllocation {relayed} over {transport}: Connect and ConnectionAttempt, ConnectionBind as a transport, 20 messages and 1 MiB echoed on each"
    );
}

fn server(tcp: &str, tls_addr: &str, user: &str, pass: &str) {
    let auth = static_auth("only", [(user, pass)]);
    let cfg =
        TurnConfig::new("only", auth, "127.0.0.1".parse().expect("ip")).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let ck = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    let scfg = tls::ServerConfig::builder(
        vec![tls::Certificate::from_der(ck.0.as_der().to_vec())],
        tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .expect("tls");
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp(tcp.parse().expect("tcp addr")).serve(turn.stream()))
            .listen(
                Listener::tcp(tls_addr.parse().expect("tls addr"))
                    .serve(Tls::server(scfg, turn.stream())),
            )
            .client_threads(1)
            .build()
            .expect("engine"),
    );
    turn.set_engine(&engine);
    eprintln!("only-turn: TCP {tcp}, TLS {tls_addr} (TCP relays)");
    engine.run().expect("run");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") if a.len() == 6 => server(&a[2], &a[3], &a[4], &a[5]),
        Some("client") if a.len() == 6 => client(&a[2], &a[3], &a[4], &a[5]),
        Some("engine-client") if a.len() == 6 => engine_client(&a[2], &a[3], &a[4], &a[5]),
        _ => {
            eprintln!(
                "usage: turn-tcp-interop server <tcp> <tls> <user> <pass> | [engine-]client <tcp|tls> <server> <user> <pass>"
            );
            std::process::exit(2);
        }
    }
}
