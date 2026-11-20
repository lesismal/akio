//! Relayed candidates allocated over DTLS (TURN over DTLS, RFC 7350): peers reach each other
//! through an `only` TURN server whose control channel is a DTLS association on the
//! endpoint's own UDP socket.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::tls;
use only::{Engine, Listener};
use only_turn::{TurnConfig, TurnServer, static_auth};
use only_webrtc::{ChannelId, Endpoint, Error, Peer, PeerHandler, RelayServer};

const T: Duration = Duration::from_secs(10);

struct Turn {
    engine: Arc<Engine>,
    turn: TurnServer,
    udp: SocketAddr,
    dtls: SocketAddr,
    cert: Vec<u8>,
}

fn turn() -> Turn {
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
            .listen(Listener::udp(any).threads(1).serve(turn.clone()))
            .listen(
                Listener::udp(any)
                    .threads(1)
                    .serve(turn.dtls(&scfg).unwrap()),
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
        dtls: a[1],
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

fn dtls_server(srv: &Turn) -> RelayServer {
    RelayServer::dtls(
        srv.dtls,
        "localhost",
        tls_config(&srv.cert),
        "alice",
        "wonderland",
    )
}

#[test]
fn data_channel_through_dtls_allocations() {
    let srv = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server = dtls_server(&srv);
    assert_eq!(server.transport(), "dtls");
    let ra = a
        .gather_relay_via(&e, &server, T)
        .expect("allocation over DTLS");
    let rb = b
        .gather_relay_via(&e, &server, T)
        .expect("allocation over DTLS");
    assert_ne!(ra, rb);
    assert_eq!(srv.turn.stats().allocations, 2);
    let (la, lb) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    assert_eq!(srv.turn.dtls_relay_of(la), Some(ra));
    assert_eq!(srv.turn.dtls_relay_of(lb), Some(rb));
    // A UDP relayed candidate (the mapped address is the host one on loopback).
    let c = a.candidates();
    assert_eq!(c.len(), 2, "{c:?}");
    assert!(
        c[1].to_sdp().contains(" udp ") || c[1].to_sdp().contains(" UDP "),
        "{}",
        c[1].to_sdp()
    );
    // The same server again over DTLS, or over plain UDP, is refused (one datagram relay per
    // server address); a plain UDP allocation on the other port is not.
    assert!(matches!(
        a.gather_relay_via(&e, &server, T),
        Err(Error::Turn(_))
    ));
    assert!(matches!(
        a.gather_relay_via(&e, &RelayServer::udp(srv.dtls, "alice", "wonderland"), T),
        Err(Error::Turn(_))
    ));
    a.gather_relay(srv.udp, "alice", "wonderland", T).unwrap();
    a.close();
    // Closing the endpoint ends the association, which frees its allocation.
    let t = Instant::now();
    while srv.turn.dtls_relay_of(la).is_some() || srv.turn.relay_of(la).is_some() {
        assert!(t.elapsed() < T, "{:?}", srv.turn.stats());
        std::thread::sleep(Duration::from_millis(10));
    }

    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    a.gather_relay_via(&e, &server, T).unwrap();
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
fn dtls_allocation_errors() {
    let srv = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    // Wrong credentials.
    let wrong = RelayServer::dtls(
        srv.dtls,
        "localhost",
        tls_config(&srv.cert),
        "alice",
        "nope",
    );
    match a.gather_relay_via(&e, &wrong, T) {
        Err(Error::Turn(s)) => assert!(s.contains("401"), "{s}"),
        r => panic!("{r:?}"),
    }
    // A certificate that does not verify: refused at the handshake, quickly.
    let other = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let bad = RelayServer::dtls(
        srv.dtls,
        "localhost",
        tls_config(other.0.as_der()),
        "alice",
        "wonderland",
    );
    let t = Instant::now();
    match a.gather_relay_via(&e, &bad, T) {
        Err(Error::Turn(s)) => assert!(s.contains("dtls"), "{s}"),
        r => panic!("{r:?}"),
    }
    assert!(t.elapsed() < Duration::from_secs(5));
    // The wrong name.
    let bad = RelayServer::dtls(
        srv.dtls,
        "example.org",
        tls_config(&srv.cert),
        "alice",
        "wonderland",
    );
    assert!(matches!(
        a.gather_relay_via(&e, &bad, T),
        Err(Error::Turn(_))
    ));
    // A turns: URL over UDP without a TLS configuration.
    let u = RelayServer::from_url(
        &format!("turns:{}?transport=udp", srv.dtls),
        "alice",
        "wonderland",
    )
    .unwrap();
    assert!(matches!(a.gather_relay_via(&e, &u, T), Err(Error::Turn(_))));
    // With one, from the URL (an IP address: verified with insecure_skip_verify here).
    let insecure = tls::ClientConfig::builder()
        .insecure_skip_verify()
        .build()
        .unwrap();
    let r = a.gather_relay_via(&e, &u.tls_config(insecure), T).unwrap();
    assert_eq!(srv.turn.dtls_relay_of(a.local_addr().unwrap()), Some(r));
    a.close();
    e.shutdown();
    srv.engine.shutdown();
}
