//! TURN over DTLS (RFC 7350): a `TurnServer::dtls` UDP listener, driven by the crate's sans-io
//! client inside an `only-dtls` client connection over a blocking UDP socket.
#![allow(missing_docs)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use only::tls;
use only::{Engine, Listener};
use only_dtls::{Config, Connection, Event, Fingerprint, FingerprintAlgorithm, PeerVerifier};
use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState};
use only_turn::{TurnConfig, TurnServer, static_auth};

struct Server {
    engine: Arc<Engine>,
    turn: TurnServer,
    addr: SocketAddr,
    cert: Vec<u8>,
}

fn server() -> Server {
    let auth = static_auth("only", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
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
            .listen(
                Listener::udp(any)
                    .threads(1)
                    .serve(turn.dtls(&scfg).unwrap()),
            )
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    Server {
        engine,
        turn,
        addr,
        cert,
    }
}

fn pinned(cert: &[u8]) -> PeerVerifier {
    PeerVerifier::Fingerprints(vec![Fingerprint::of(FingerprintAlgorithm::Sha256, cert)])
}

/// A TURN client in a DTLS client connection on a blocking UDP socket.
struct DtlsClient {
    s: UdpSocket,
    d: Connection,
    c: Client,
    got: Vec<(SocketAddr, Vec<u8>)>,
    events: Vec<ClientEvent>,
    closed: bool,
}

impl DtlsClient {
    fn new(s: UdpSocket, server: SocketAddr, dtls: Config) -> Self {
        s.connect(server).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let cfg = ClientConfig::new(server, "alice", "wonderland");
        DtlsClient {
            s,
            d: Connection::client(Arc::new(dtls), Instant::now()).unwrap(),
            c: Client::new(cfg, Instant::now()),
            got: Vec::new(),
            events: Vec::new(),
            closed: false,
        }
    }

    fn flush(&mut self) {
        if self.d.is_connected() {
            while let Some(m) = self.c.poll_transmit() {
                self.d.send_application_data(&m).unwrap();
            }
        }
        while let Some(d) = self.d.poll_transmit() {
            let _ = self.s.send(&d);
        }
    }

    /// Runs until `done` or `t` passes; false on timeout or a DTLS failure.
    fn run(&mut self, t: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let end = Instant::now() + t;
        let mut buf = vec![0u8; 65536];
        while Instant::now() < end {
            self.flush();
            if done(self) {
                return true;
            }
            let now = Instant::now();
            let r = match self.s.recv(&mut buf) {
                Ok(n) => self.d.handle_datagram(now, &buf[..n]),
                Err(_) => self.d.handle_timeout(now),
            };
            if r.is_err() {
                return false;
            }
            while let Some(e) = self.d.poll_event() {
                match e {
                    Event::ApplicationData(m) => {
                        if let Some((p, d)) = self.c.handle_input(now, &m) {
                            self.got.push((p, d.to_vec()));
                        }
                    }
                    Event::Closed => self.closed = true,
                    _ => {}
                }
            }
            if self.d.is_connected() {
                self.c.handle_timeout(now);
            }
            self.events.extend(std::iter::from_fn(|| self.c.poll_event()));
        }
        done(self)
    }

    fn allocate(&mut self) -> SocketAddr {
        assert!(self.run(Duration::from_secs(10), |s| s.c.state()
            != ClientState::Allocating));
        match self.events.first() {
            Some(ClientEvent::Allocated { relayed, .. }) => *relayed,
            e => panic!("{e:?}"),
        }
    }
}

fn udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn peer() -> UdpSocket {
    let p = UdpSocket::bind("127.0.0.1:0").unwrap();
    p.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    p
}

/// Data both ways through the allocation, with odd sizes (no padding over DTLS).
fn relay_both_ways(c: &mut DtlsClient, relayed: SocketAddr) {
    let p = peer();
    let pa = p.local_addr().unwrap();
    for (i, n) in [1usize, 3, 5, 1199].into_iter().enumerate() {
        let data = vec![i as u8; n];
        assert!(c.c.send_to(Instant::now(), pa, &data));
        c.flush();
        if i == 0 {
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

fn wait_until(f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn turn_over_dtls() {
    let srv = server();
    // DTLS 1.3 (the server offers both).
    let cfg = Config::without_identity()
        .with_versions(vec![only_dtls::Version::Dtls13, only_dtls::Version::Dtls12])
        .with_verifier(pinned(&srv.cert));
    let mut c = DtlsClient::new(udp(), srv.addr, cfg);
    let relayed = c.allocate();
    assert_eq!(c.d.version(), only_dtls::Version::Dtls13);
    let local = c.s.local_addr().unwrap();
    assert_eq!(srv.turn.dtls_relay_of(local), Some(relayed));
    assert_eq!(srv.turn.relay_of(local), None); // not a plain UDP client
    relay_both_ways(&mut c, relayed);
    // close_notify frees the allocation.
    c.d.close();
    c.flush();
    wait_until(|| srv.turn.dtls_relay_of(local).is_none());
    assert_eq!(srv.turn.stats().allocations, 0);
    srv.engine.shutdown();
}

#[test]
fn turn_over_dtls12() {
    let srv = server();
    let cfg = Config::without_identity().with_verifier(pinned(&srv.cert));
    let mut c = DtlsClient::new(udp(), srv.addr, cfg);
    let relayed = c.allocate();
    assert_eq!(c.d.version(), only_dtls::Version::Dtls12);
    relay_both_ways(&mut c, relayed);
    // A deletion over DTLS.
    c.c.close(Instant::now());
    assert!(c.run(Duration::from_secs(5), |s| s.c.state()
        == ClientState::Closed));
    assert_eq!(srv.turn.stats().allocations, 0);
    srv.engine.shutdown();
}

#[test]
fn wrong_certificate_is_refused() {
    let srv = server();
    let other = only_dtls::Identity::generate_self_signed().unwrap();
    let cfg = Config::without_identity().with_verifier(pinned(other.certificate()));
    let mut c = DtlsClient::new(udp(), srv.addr, cfg);
    assert!(!c.run(Duration::from_secs(5), |s| s.d.is_connected()));
    assert_eq!(srv.turn.stats().allocations, 0);
    srv.engine.shutdown();
}

/// A client that restarts (a new handshake from the same address) loses its old allocation
/// and can make a new one: no 437 Allocation Mismatch.
#[test]
fn new_handshake_replaces_the_association() {
    let srv = server();
    let cfg = || Config::without_identity().with_verifier(pinned(&srv.cert));
    let s = udp();
    let local = s.local_addr().unwrap();
    let mut c = DtlsClient::new(s.try_clone().unwrap(), srv.addr, cfg());
    let first = c.allocate();
    assert_eq!(srv.turn.dtls_relay_of(local), Some(first));
    drop(c);
    let mut c = DtlsClient::new(s, srv.addr, cfg());
    let second = c.allocate();
    assert_ne!(first, second);
    assert_eq!(srv.turn.dtls_relay_of(local), Some(second));
    assert_eq!(srv.turn.stats().allocations, 1);
    relay_both_ways(&mut c, second);
    srv.engine.shutdown();
}

/// Plain STUN or junk on the DTLS port gets no answer and opens nothing.
#[test]
fn non_dtls_datagrams_are_dropped() {
    let srv = server();
    let s = udp();
    s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let req = only_turn::stun::MessageBuilder::new(
        only_turn::stun::Method::BINDING,
        only_turn::stun::Class::Request,
        [7; 12],
    )
    .build();
    s.send_to(&req, srv.addr).unwrap();
    s.send_to(b"\x17\xfe\xfd\x00\x01junk", srv.addr).unwrap();
    assert!(s.recv(&mut [0u8; 64]).is_err());
    srv.engine.shutdown();
}
