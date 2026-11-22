//! Relayed candidates allocated over TCP and TLS (`Endpoint::gather_relay_via`): peers reach
//! each other through an `akio` TURN server whose control connection is a stream, and an
//! allocation lost with its connection is made again.
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::tls::{self, Tls};
use akio::{Engine, Listener};
use akio_turn::{TurnConfig, TurnServer, static_auth};
use akio_webrtc::{ChannelId, Endpoint, Error, Peer, PeerHandler, RelayServer};

const T: Duration = Duration::from_secs(10);

struct Turn {
    engine: Arc<Engine>,
    turn: TurnServer,
    udp: SocketAddr,
    tcp: SocketAddr,
    tls: SocketAddr,
    cert: Vec<u8>,
}

fn turn() -> Turn {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
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
            .listen(Listener::udp(any).threads(1).serve(turn.clone()))
            .listen(Listener::tcp(any).threads(1).serve(turn.stream()))
            .listen(
                Listener::tcp(any)
                    .threads(1)
                    .serve(Tls::server(scfg, turn.stream())),
            )
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let a = engine.local_addrs();
    Turn {
        engine,
        turn,
        udp: a[0],
        tcp: a[1],
        tls: a[2],
        cert,
    }
}

fn engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

fn tls_config(cert: &[u8]) -> tls::ClientConfig {
    let mut roots = tls::RootCerts::empty();
    roots
        .add(&tls::Certificate::from_der(cert.to_vec()))
        .unwrap();
    tls::ClientConfig::builder().roots(roots).build().unwrap()
}

struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
}

#[derive(Debug)]
enum Got {
    Open,
    Data(Vec<u8>),
}

struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.0.lock().unwrap().send(Got::Open);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _binary: bool) {
        let _ = self.0.lock().unwrap().send(Got::Data(data.to_vec()));
    }
}

fn wait(rx: &Receiver<Got>, what: &str, f: impl Fn(&Got) -> bool) -> Got {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let g = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&g) {
            return g;
        }
    }
}

fn relay_only(sdp: &str) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=candidate") || l.contains(" typ relay"))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

/// `a` offers a data channel to `b`, both signalling relayed candidates only; 20 echoes.
fn echo_through_relays(a: &Endpoint, b: &Endpoint) -> Peer {
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let (_pb, answer) = b.accept_offer(&relay_only(&offer), Echo).unwrap();
    pa.accept_answer(&relay_only(&answer)).unwrap();
    wait(&rx, "open", |g| matches!(g, Got::Open));
    for i in 0..20u8 {
        pa.send(ch.unwrap(), &[i; 300], true).unwrap();
        let Got::Data(d) = wait(&rx, "echo", |g| matches!(g, Got::Data(_))) else {
            unreachable!()
        };
        assert_eq!(d, vec![i; 300]);
    }
    pa
}

fn priority_of(ep: &Endpoint, addr: SocketAddr) -> u32 {
    let c = ep.candidates();
    let line = c
        .iter()
        .find(|c| c.addr() == addr)
        .unwrap_or_else(|| panic!("no candidate {addr}"))
        .to_sdp();
    line.split_whitespace().nth(3).unwrap().parse().unwrap()
}

#[test]
fn data_channel_through_tcp_and_tls_allocations() {
    let srv = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let ra = a
        .gather_relay_via(&e, &RelayServer::tcp(srv.tcp, "alice", "wonderland"), T)
        .expect("allocation over TCP");
    let tls_server = RelayServer::tls(
        srv.tls,
        "localhost",
        tls_config(&srv.cert),
        "alice",
        "wonderland",
    );
    assert_eq!(tls_server.transport(), "tls");
    let rb = b
        .gather_relay_via(&e, &tls_server, T)
        .expect("allocation over TLS");
    assert_ne!(ra, rb);
    assert_eq!(srv.turn.stats().allocations, 2);
    // No server-reflexive candidate from a stream allocation: host + relayed.
    assert_eq!(a.candidates().len(), 2, "{:?}", a.candidates());
    // The same server and transport again is refused; another transport is not.
    assert!(matches!(
        a.gather_relay_via(&e, &RelayServer::tcp(srv.tcp, "alice", "wonderland"), T),
        Err(Error::Turn(_))
    ));
    let ru = a.gather_relay(srv.udp, "alice", "wonderland", T).unwrap();
    // UDP-allocated relays rank above TCP ones, TCP above TLS.
    let rb2 = a.gather_relay_via(&e, &tls_server, T).unwrap();
    let (pu, pt, ps) = (
        priority_of(&a, ru),
        priority_of(&a, ra),
        priority_of(&a, rb2),
    );
    assert!(pu > pt && pt > ps, "{pu} {pt} {ps}");
    a.close();

    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    a.gather_relay_via(&e, &RelayServer::tcp(srv.tcp, "alice", "wonderland"), T)
        .unwrap();
    let _p = echo_through_relays(&a, &b);
    let st = srv.turn.stats();
    assert!(st.to_peer > 0 && st.to_client > 0, "{st:?}");
    a.close();
    b.close();
    let t = Instant::now();
    while srv.turn.stats().allocations != 0 {
        assert!(t.elapsed() < T, "{:?}", srv.turn.stats());
        std::thread::sleep(Duration::from_millis(10));
    }
    e.shutdown();
    srv.engine.shutdown();
}

#[test]
fn stream_allocation_errors() {
    let srv = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    match a.gather_relay_via(&e, &RelayServer::tcp(srv.tcp, "alice", "nope"), T) {
        Err(Error::Turn(s)) => assert!(s.contains("401"), "{s}"),
        r => panic!("{r:?}"),
    }
    // Nothing listens.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = l.local_addr().unwrap();
    drop(l);
    match a.gather_relay_via(&e, &RelayServer::tcp(closed, "alice", "wonderland"), T) {
        Err(Error::Turn(s)) => assert!(s.contains("connect"), "{s}"),
        r => panic!("{r:?}"),
    }
    // A certificate that does not verify.
    let other = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let bad = RelayServer::tls(
        srv.tls,
        "localhost",
        tls_config(other.0.as_der()),
        "alice",
        "wonderland",
    );
    assert!(matches!(
        a.gather_relay_via(&e, &bad, T),
        Err(Error::Turn(_))
    ));
    // A turns: URL without a TLS configuration.
    let u = RelayServer::from_url(&format!("turns:{}", srv.tls), "alice", "wonderland").unwrap();
    assert!(matches!(a.gather_relay_via(&e, &u, T), Err(Error::Turn(_))));
    // The URL forms.
    let u = RelayServer::from_url("turn:127.0.0.1?transport=tcp", "u", "p").unwrap();
    assert_eq!((u.addr().port(), u.transport()), (3478, "tcp"));
    let u = RelayServer::from_url("turn:[::1]:3479", "u", "p").unwrap();
    assert_eq!(
        (u.addr(), u.transport()),
        ("[::1]:3479".parse().unwrap(), "udp")
    );
    let u = RelayServer::from_url("turns:localhost", "u", "p").unwrap();
    assert_eq!((u.addr().port(), u.transport()), (5349, "tls"));
    // turns: over UDP is DTLS (RFC 7350).
    let u = RelayServer::from_url("turns:127.0.0.1?transport=udp", "u", "p").unwrap();
    assert_eq!((u.addr().port(), u.transport()), (5349, "dtls"));
    assert_eq!(u.tls_config(tls_config(&srv.cert)).transport(), "dtls");
    for bad in [
        "stun:1.2.3.4",
        "turn:",
        "turn:1.2.3.4:x",
        "turns:1.2.3.4?transport=sctp",
        "turn:1.2.3.4?transport=sctp",
    ] {
        assert!(
            matches!(RelayServer::from_url(bad, "u", "p"), Err(Error::Turn(_))),
            "{bad}"
        );
    }
    // Only the host candidate.
    assert_eq!(a.candidates().len(), 1, "{:?}", a.candidates());
    e.shutdown();
    srv.engine.shutdown();
}

/// A TCP forwarder whose connections can be cut.
struct Cutter {
    addr: SocketAddr,
    conns: Arc<Mutex<Vec<TcpStream>>>,
}

impl Cutter {
    fn new(upstream: SocketAddr) -> Cutter {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let conns = Arc::new(Mutex::new(Vec::new()));
        let cs = conns.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(down) = s else { return };
                let Ok(up) = TcpStream::connect(upstream) else {
                    continue;
                };
                let pipe = |mut from: TcpStream, mut to: TcpStream| {
                    std::thread::spawn(move || {
                        let mut b = [0u8; 16384];
                        while let Ok(n) = from.read(&mut b) {
                            if n == 0 || to.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                        let _ = to.shutdown(Shutdown::Both);
                        let _ = from.shutdown(Shutdown::Both);
                    });
                };
                cs.lock()
                    .unwrap()
                    .extend([down.try_clone().unwrap(), up.try_clone().unwrap()]);
                pipe(down.try_clone().unwrap(), up.try_clone().unwrap());
                pipe(up, down);
            }
        });
        Cutter { addr, conns }
    }

    fn cut(&self) {
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
    }
}

#[test]
fn lost_stream_allocation_is_made_again() {
    let srv = turn();
    let cutter = Cutter::new(srv.tcp);
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .close_on_disconnect(false);
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let r1 = a
        .gather_relay_via(&e, &RelayServer::tcp(cutter.addr, "alice", "wonderland"), T)
        .unwrap();
    // `a` offers its relayed candidate only; `b` answers with its host candidate: the pair
    // is a's relay to b's host.
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let (_pb, answer) = b.accept_offer(&relay_only(&offer), Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    wait(&rx, "first open", |g| matches!(g, Got::Open));
    let ch = ch.unwrap();
    pa.send(ch, b"before", true).unwrap();
    wait(&rx, "echo", |g| matches!(g, Got::Data(_)));

    cutter.cut();
    // The allocation is made again (after about a second) on a new relayed address, which
    // replaces the old candidate.
    let t = Instant::now();
    let r2 = loop {
        let relays: Vec<SocketAddr> = a
            .candidates()
            .iter()
            .filter(|c| c.to_sdp().contains("typ relay"))
            .map(|c| c.addr())
            .collect();
        if let [r] = relays[..] {
            if r != r1 {
                break r;
            }
        }
        assert!(t.elapsed() < T, "not allocated again: {relays:?}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(r1, r2);
    let t = Instant::now();
    while srv.turn.stats().allocations != 1 {
        assert!(t.elapsed() < T, "{:?}", srv.turn.stats());
        std::thread::sleep(Duration::from_millis(10));
    }
    // The open peer checks the new relayed candidate and its data flows again.
    let t = Instant::now();
    let mut n = 0u32;
    loop {
        let _ = pa.send(ch, format!("after {n}").as_bytes(), true);
        n += 1;
        if let Ok(Got::Data(d)) = rx.recv_timeout(Duration::from_millis(200)) {
            if d.starts_with(b"after") {
                break;
            }
        }
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "no data after the loss"
        );
    }
    // A new peer gets the new candidate (towards another endpoint: two peers of `a` talking
    // to one socket of `b` would share a 5-tuple).
    let c = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa2, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let offer = relay_only(&offer);
    assert!(
        offer.contains(&format!(" {} {} typ relay", r2.ip(), r2.port())),
        "{offer}"
    );
    let (_pc, answer) = c.accept_offer(&offer, Echo).unwrap();
    pa2.accept_answer(&answer).unwrap();
    wait(&rx, "open", |g| matches!(g, Got::Open));
    pa2.send(ch.unwrap(), b"new", true).unwrap();
    wait(&rx, "echo", |g| matches!(g, Got::Data(_)));
    a.close();
    b.close();
    c.close();
    e.shutdown();
    srv.engine.shutdown();
}
