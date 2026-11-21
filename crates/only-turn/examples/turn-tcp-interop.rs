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
//! ```
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only::tls::{self, Tls};
use only::{Engine, Listener};
use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState, DataState};
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
    let id = loop {
        match ctl.event() {
            ClientEvent::ConnectionAttempt { peer, id } => {
                assert_eq!(peer.ip(), pa.ip());
                break id;
            }
            e => panic!("{e:?}"),
        }
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
        _ => {
            eprintln!(
                "usage: turn-tcp-interop server <tcp> <tls> <user> <pass> | client <tcp|tls> <server> <user> <pass>"
            );
            std::process::exit(2);
        }
    }
}
