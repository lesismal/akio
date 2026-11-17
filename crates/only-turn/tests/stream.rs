//! TURN over TCP and TLS listeners, driven by the crate's sans-io client over blocking sockets.
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use only::tls::{self, Tls};
use only::{Engine, Listener};
use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState};
use only_turn::framing::FrameReader;
use only_turn::{TurnConfig, TurnServer, static_auth};

struct Server {
    engine: Arc<Engine>,
    turn: TurnServer,
    tcp: SocketAddr,
    tls: SocketAddr,
    cert: Vec<u8>,
}

fn server(f: impl FnOnce(&mut TurnConfig)) -> Server {
    let auth = static_auth("only", [("alice", "wonderland")]);
    let mut cfg =
        TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    f(&mut cfg);
    let turn = TurnServer::new(cfg);
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = tls::ServerConfig::builder(
        vec![tls::Certificate::from_der(cert.clone())],
        tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp(any).threads(1).serve(turn.stream()))
            .listen(
                Listener::tcp(any)
                    .threads(1)
                    .serve(Tls::server(scfg, turn.stream())),
            )
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let a = engine.local_addrs();
    Server {
        engine,
        turn,
        tcp: a[0],
        tls: a[1],
        cert,
    }
}

/// A TURN client on a blocking stream (TCP or TLS).
struct StreamClient<S> {
    s: S,
    c: Client,
    reader: FrameReader,
    got: Vec<(SocketAddr, Vec<u8>)>,
    events: Vec<ClientEvent>,
}

impl<S: Read + Write> StreamClient<S> {
    fn new(s: S, server: SocketAddr) -> Self {
        let cfg = ClientConfig::new(server, "alice", "wonderland").stream(true);
        StreamClient {
            s,
            c: Client::new(cfg, Instant::now()),
            reader: FrameReader::new(),
            got: Vec::new(),
            events: Vec::new(),
        }
    }

    fn flush(&mut self) {
        while let Some(m) = self.c.poll_transmit() {
            self.s.write_all(&m).unwrap();
        }
        let _ = self.s.flush();
    }

    /// Runs until `done` or `t` passes; false on timeout. Read timeouts must be short.
    fn run(&mut self, t: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let end = Instant::now() + t;
        let mut buf = vec![0u8; 65536];
        while Instant::now() < end {
            self.flush();
            if done(self) {
                return true;
            }
            match self.s.read(&mut buf) {
                Ok(0) => return done(self),
                Ok(n) => {
                    let (c, got) = (&mut self.c, &mut self.got);
                    self.reader
                        .push(&buf[..n], |m| {
                            if let Some((p, d)) = c.handle_input(Instant::now(), m) {
                                got.push((p, d.to_vec()));
                            }
                        })
                        .unwrap();
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("{e}"),
            }
            self.c.handle_timeout(Instant::now());
            self.events
                .extend(std::iter::from_fn(|| self.c.poll_event()));
        }
        done(self)
    }

    fn allocate(&mut self) -> SocketAddr {
        assert!(self.run(Duration::from_secs(5), |s| s.c.state()
            != ClientState::Allocating));
        match self.events.first() {
            Some(ClientEvent::Allocated { relayed, .. }) => *relayed,
            e => panic!("{e:?}"),
        }
    }
}

fn tcp(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn peer() -> UdpSocket {
    let p = UdpSocket::bind("127.0.0.1:0").unwrap();
    p.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    p
}

/// Data both ways through a stream client's allocation, with odd sizes (padding).
fn relay_both_ways<S: Read + Write>(c: &mut StreamClient<S>, relayed: SocketAddr) {
    let p = peer();
    let pa = p.local_addr().unwrap();
    for (i, n) in [1usize, 2, 3, 4, 5, 1199, 1200].into_iter().enumerate() {
        let data = vec![i as u8; n];
        assert!(c.c.send_to(Instant::now(), pa, &data));
        c.flush();
        if i == 0 {
            // The first datagram waits for the channel.
            assert!(c.run(Duration::from_secs(5), |s| s.c.pending_bytes() == 0));
        }
        let mut b = [0u8; 2048];
        let (k, from) = p.recv_from(&mut b).unwrap();
        assert_eq!((&b[..k], from), (&data[..], relayed));
        p.send_to(&data, relayed).unwrap();
        assert!(c.run(Duration::from_secs(5), |s| !s.got.is_empty()));
        assert_eq!(c.got.remove(0), (pa, data));
    }
}

#[test]
fn turn_over_tcp() {
    let srv = server(|_| {});
    let mut c = StreamClient::new(tcp(srv.tcp), srv.tcp);
    let relayed = c.allocate();
    let local = c.s.local_addr().unwrap();
    assert_eq!(srv.turn.stream_relay_of(local), Some(relayed));
    assert_eq!(srv.turn.relay_of(local), None); // not a UDP client
    relay_both_ways(&mut c, relayed);
    // Closing the connection frees the allocation (RFC 8656 section 3.1).
    drop(c);
    let t = Instant::now();
    while srv.turn.stream_relay_of(local).is_some() {
        assert!(t.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(srv.turn.stats().allocations, 0);
    srv.engine.shutdown();
}

#[test]
fn turn_over_tls() {
    let srv = server(|_| {});
    let mut roots = tls::RootCerts::empty();
    roots
        .add(&tls::Certificate::from_der(srv.cert.clone()))
        .unwrap();
    let ccfg = tls::ClientConfig::builder().roots(roots).build().unwrap();
    let s = tls::stream::Stream::client(&ccfg, "localhost", tcp(srv.tls)).unwrap();
    let mut c = StreamClient::new(s, srv.tls);
    let relayed = c.allocate();
    relay_both_ways(&mut c, relayed);
    // A deletion over TLS.
    c.c.close(Instant::now());
    assert!(c.run(Duration::from_secs(5), |s| s.c.state()
        == ClientState::Closed));
    assert_eq!(c.events.last(), Some(&ClientEvent::Closed));
    assert_eq!(srv.turn.stats().allocations, 0);
    srv.engine.shutdown();
}

#[test]
fn garbage_and_idle_connections_are_closed() {
    let srv = server(|c| c.stream_allocate_timeout = Duration::from_secs(1));
    // Not STUN or ChannelData.
    let mut s = tcp(srv.tcp);
    s.write_all(b"\x80\x00\x00\x00 not turn").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(s.read(&mut [0u8; 16]).unwrap_or(0), 0);
    // Connected, never allocating: closed by the sweep.
    let mut s = tcp(srv.tcp);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = Instant::now();
    assert_eq!(s.read(&mut [0u8; 16]).unwrap_or(0), 0);
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "{:?}",
        t.elapsed()
    );
    // A connection with an allocation outlives the timeout.
    let mut c = StreamClient::new(tcp(srv.tcp), srv.tcp);
    let relayed = c.allocate();
    thread::sleep(Duration::from_millis(2000));
    relay_both_ways(&mut c, relayed);
    srv.engine.shutdown();
}

/// A client that stops reading: relayed data past `max_stream_queue` is dropped instead of
/// queued, and the connection keeps working once it reads again.
#[test]
fn slow_reader_drops_relayed_data() {
    let srv = server(|c| c.max_stream_queue = 8 * 1024);
    let mut c = StreamClient::new(tcp(srv.tcp), srv.tcp);
    let relayed = c.allocate();
    let p = peer();
    let pa = p.local_addr().unwrap();
    assert!(c.c.send_to(Instant::now(), pa, b"hi"));
    assert!(c.run(Duration::from_secs(5), |s| s.c.pending_bytes() == 0));
    let _ = p.recv_from(&mut [0u8; 64]).unwrap();
    const N: usize = 4000;
    for _ in 0..N {
        p.send_to(&[7u8; 1000], relayed).unwrap();
    }
    thread::sleep(Duration::from_millis(500));
    c.run(Duration::from_secs(2), |_| false);
    let got = c.got.len();
    assert!(got > 0 && got < N, "{got}");
    // Still alive.
    c.got.clear();
    p.send_to(b"again", relayed).unwrap();
    assert!(c.run(Duration::from_secs(5), |s| !s.got.is_empty()));
    srv.engine.shutdown();
}
