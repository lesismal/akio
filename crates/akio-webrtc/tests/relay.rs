//! Relayed candidates: two `Endpoint`s that signal only TURN-relayed candidates reach each other
//! through an `akio` TURN server.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_turn::{TurnConfig, TurnServer, static_auth};
use akio_webrtc::{ChannelId, Endpoint, Error, Peer, PeerHandler};

const T: Duration = Duration::from_secs(10);

fn turn() -> (Arc<Engine>, TurnServer, SocketAddr) {
    turn_with(|c| c)
}

fn turn_with(f: impl FnOnce(TurnConfig) -> TurnConfig) -> (Arc<Engine>, TurnServer, SocketAddr) {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    let t = TurnServer::new(f(cfg));
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(t.clone()),
            )
            .build()
            .unwrap(),
    );
    t.set_engine(&e);
    e.start().unwrap();
    let a = e.local_addrs()[0];
    (e, t, a)
}

fn engine() -> Arc<Engine> {
    let e = Arc::new(Engine::builder().udp_client_threads(1).build().unwrap());
    e.start().unwrap();
    e
}

struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        p.send(id, data, binary).unwrap();
    }
}

#[derive(Debug)]
enum Got {
    Open,
    Data(Vec<u8>),
}

struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_channel_open(&mut self, _p: &Peer, id: ChannelId, _label: &str) {
        let _ = (id, self.0.lock().unwrap().send(Got::Open));
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

/// Keeps only the relayed candidates of an SDP.
fn relay_only(sdp: &str) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=candidate") || l.contains(" typ relay"))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

#[test]
fn data_channel_through_relayed_candidates() {
    let (te, turn, server) = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let ra = a
        .gather_relay(server, "alice", "wonderland", T)
        .expect("allocation");
    let rb = b.gather_relay(server, "alice", "wonderland", T).unwrap();
    assert_ne!(ra, rb);
    assert_eq!(turn.stats().allocations, 2);
    assert!(a.candidates().iter().any(|c| c.addr() == ra));
    // A second allocation on the same server is refused.
    assert!(matches!(
        a.gather_relay(server, "alice", "wonderland", T),
        Err(Error::Turn(_))
    ));

    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let offer = relay_only(&offer);
    assert!(
        offer.contains(&format!("{} {} typ relay", ra.ip(), ra.port())),
        "{offer}"
    );
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&relay_only(&answer)).unwrap();
    wait(&rx, "open", |g| matches!(g, Got::Open));
    for i in 0..20u8 {
        pa.send(ch.unwrap(), &[i; 100], true).unwrap();
        let Got::Data(d) = wait(&rx, "echo", |g| matches!(g, Got::Data(_))) else {
            unreachable!()
        };
        assert_eq!(d, vec![i; 100]);
    }
    let st = turn.stats();
    assert!(st.to_peer > 0 && st.to_client > 0, "{st:?}");
    // Closing the endpoints deletes their allocations.
    a.close();
    b.close();
    let t = Instant::now();
    while turn.stats().allocations != 0 {
        assert!(t.elapsed() < T, "{:?}", turn.stats());
        std::thread::sleep(Duration::from_millis(10));
    }
    e.shutdown();
    te.shutdown();
}

#[test]
fn allocation_errors() {
    let (te, _turn, server) = turn();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    match a.gather_relay(server, "alice", "nope", T) {
        Err(Error::Turn(s)) => assert!(s.contains("401"), "{s}"),
        r => panic!("{r:?}"),
    }
    // Nobody answers.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let r = a.gather_relay(
        silent.local_addr().unwrap(),
        "alice",
        "wonderland",
        Duration::from_millis(300),
    );
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    // Only the host candidate.
    assert_eq!(a.candidates().len(), 1);
    e.shutdown();
    te.shutdown();
}

/// A dual allocation (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`): an endpoint on IPv4 gets relayed
/// candidates of both families, and reaches an IPv6-only endpoint through the server's IPv6
/// relay.
#[test]
fn dual_allocation_reaches_an_ipv6_peer() {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap())
        .additional_relay_ip("::1".parse().unwrap())
        .allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let te = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(turn.clone()),
            )
            .build()
            .unwrap(),
    );
    turn.set_engine(&te);
    te.start().unwrap();
    let server = te.local_addrs()[0];
    let e = engine();
    let Ok(b) = Endpoint::bind(&e, "[::1]:0".parse().unwrap()) else {
        eprintln!("no IPv6 loopback: skipped");
        return;
    };
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let rs = akio_webrtc::RelayServer::udp(server, "alice", "wonderland").dual_allocation(true);
    let ra = a.gather_relay_via(&e, &rs, T).expect("allocation");
    assert!(ra.is_ipv4());
    let relayed: Vec<SocketAddr> = a
        .candidates()
        .iter()
        .filter(|c| c.kind() == "relay")
        .map(|c| c.addr())
        .collect();
    assert_eq!(turn.relays_of(a.local_addr().unwrap()), relayed);
    assert!(relayed.iter().any(SocketAddr::is_ipv6));
    assert_eq!(turn.stats().allocations, 1);

    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let offer = relay_only(&offer);
    assert!(offer.contains(" ::1 "), "{offer}");
    // B answers with its IPv6 host candidate: only A's IPv6 relayed one pairs with it.
    let (_pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    wait(&rx, "open", |g| matches!(g, Got::Open));
    pa.send(ch.unwrap(), b"over the v6 relay", true).unwrap();
    let Got::Data(d) = wait(&rx, "echo", |g| matches!(g, Got::Data(_))) else {
        unreachable!()
    };
    assert_eq!(d, b"over the v6 relay");
    let st = turn.stats();
    assert!(st.to_peer > 0 && st.to_client > 0, "{st:?}");
    a.close();
    b.close();
    e.shutdown();
    te.shutdown();
}

/// RFC 8656 section 11.6 through to ICE: the only remote candidate is a closed port, the
/// server relays the ICMP port unreachable that the first check through the relayed candidate
/// draws, and the agent fails that pair at once (RFC 8445 section 7.2.5.2.2): the relay
/// carries that one check, where without ICMP the check is sent again and again (seven sends
/// over about six seconds; three within the first two). (The host candidate's pair fails on
/// the ICMP its own socket hears, `loopback.rs`.) Linux and macOS (where the server reads
/// ICMP).
#[test]
fn icmp_through_the_relay_fails_the_check() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    for relay_icmp in [true, false] {
        let (te, turn, server) = turn_with(|c| c.relay_icmp(relay_icmp));
        let e = engine();
        let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        a.gather_relay(server, "alice", "wonderland", T).unwrap();
        let (pa, offer) = a
            .create_offer(Echo, |api| {
                api.add_channel("c");
            })
            .unwrap();
        let (_pb, answer) = b.accept_offer(&relay_only(&offer), Echo).unwrap();
        // B's answer, its candidates replaced by one on a closed port.
        let closed = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut answer: String = answer
            .lines()
            .filter(|l| !l.starts_with("a=candidate") && !l.starts_with("a=end-of-candidates"))
            .map(|l| format!("{l}\r\n"))
            .collect();
        answer.push_str(&format!(
            "a=candidate:1 1 udp 2130706431 127.0.0.1 {} typ host\r\n",
            closed.port()
        ));
        pa.accept_answer(&answer).unwrap();
        std::thread::sleep(Duration::from_millis(2500));
        let st = turn.stats();
        if relay_icmp {
            assert_eq!((st.to_peer, st.icmp), (1, 1), "{st:?}");
        } else {
            assert!(st.to_peer >= 3 && st.icmp == 0, "{st:?}");
        }
        a.close();
        b.close();
        e.shutdown();
        te.shutdown();
    }
}
