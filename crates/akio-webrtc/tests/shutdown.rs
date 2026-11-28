//! Endpoints and servers at their engine's graceful shutdown (a follow-up of akit's A301): they
//! close as `Endpoint::close` does, so the remote peer hears the goodbye at once rather than at
//! its consent timeout, and their TCP connections (ICE-TCP, TURN over TCP) do not hold
//! `Engine::wait` until the shutdown timeout.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Config, Engine, Listener};
use akio_turn::{TurnConfig, TurnServer, static_auth};
use akio_webrtc::{ChannelId, Endpoint, Peer, PeerHandler, RelayServer, RtcServer};

const T: Duration = Duration::from_secs(10);
/// Well under the consent timeout (30 s) a remote would otherwise wait for, and under the
/// 20 s shutdown timeout of the engines below.
const BOUND: Duration = Duration::from_secs(8);

/// An engine whose graceful shutdown waits up to 20 s for its connections.
fn engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_secs(20);
                v
            })
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

#[derive(Debug)]
enum Got {
    Open,
    Data(Vec<u8>),
    Closed,
}

/// Echoes channel data and reports its close.
struct Echo(Mutex<Sender<Got>>);
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
    fn on_close(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Closed);
    }
}

/// Reports what the peer sees.
struct Probe(Mutex<Sender<Got>>);
impl PeerHandler for Probe {
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.0.lock().unwrap().send(Got::Open);
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _binary: bool) {
        let _ = self.0.lock().unwrap().send(Got::Data(data.to_vec()));
    }
    fn on_close(&mut self, _p: &Peer) {
        let _ = self.0.lock().unwrap().send(Got::Closed);
    }
}

fn wait(rx: &Receiver<Got>, within: Duration, what: &str, f: impl Fn(&Got) -> bool) {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let g = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&g) {
            return;
        }
    }
}

/// Only the candidate lines with `keep`.
fn only(sdp: &str, keep: &str) -> String {
    sdp.lines()
        .filter(|l| !l.starts_with("a=candidate") || l.contains(keep))
        .map(|l| format!("{l}\r\n"))
        .collect()
}

/// `a` offers a data channel to `answer` (`keep` filters both sides' candidates) and gets one
/// echo back. Returns what `a`'s peer sees.
fn connect(a: &Endpoint, keep: &str, answer: impl FnOnce(&str) -> String) -> (Peer, Receiver<Got>) {
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    pa.accept_answer(&only(&answer(&only(&offer, keep)), keep))
        .unwrap();
    wait(&rx, T, "open", |g| matches!(g, Got::Open));
    pa.send(ch.unwrap(), b"ping", true).unwrap();
    wait(
        &rx,
        T,
        "echo",
        |g| matches!(g, Got::Data(d) if d == b"ping"),
    );
    (pa, rx)
}

/// Shuts `e` down and waits for it, within [`BOUND`].
fn stop(e: &Engine) {
    let t0 = Instant::now();
    e.shutdown();
    e.wait();
    assert!(t0.elapsed() < BOUND, "{:?}", t0.elapsed());
}

/// Over UDP: the engine's shutdown closes the endpoint's peers, whose remote hears it.
#[test]
fn an_endpoint_peer_closes_at_the_engine_shutdown() {
    let (ea, eb) = (engine(), engine());
    let a = Endpoint::bind(&ea, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&eb, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (btx, brx) = channel();
    let (_pa, arx) = connect(&a, " udp ", |offer| {
        b.accept_offer(offer, Echo(Mutex::new(btx))).unwrap().1
    });
    stop(&ea);
    wait(&arx, T, "a's close", |g| matches!(g, Got::Closed));
    wait(&brx, BOUND, "b's close", |g| matches!(g, Got::Closed));
    b.close();
    eb.shutdown();
}

/// Over ICE-TCP, `a` dialing: its connection does not hold the engine's `wait`, and the
/// passive side's peer hears the close.
#[test]
fn an_ice_tcp_endpoint_does_not_hold_the_engine_shutdown() {
    let (ea, eb) = (engine(), engine());
    let a = Endpoint::bind(&ea, "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Endpoint::bind(&eb, "127.0.0.1:0".parse().unwrap()).unwrap();
    a.dial_tcp(&ea).unwrap();
    b.listen_tcp(&eb, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (btx, brx) = channel();
    let (_pa, arx) = connect(&a, " tcp ", |offer| {
        b.accept_offer(offer, Echo(Mutex::new(btx))).unwrap().1
    });
    stop(&ea);
    wait(&arx, T, "a's close", |g| matches!(g, Got::Closed));
    wait(&brx, BOUND, "b's close", |g| matches!(g, Got::Closed));
    b.close();
    eb.shutdown();
}

/// An ICE-lite server whose only connection with its peer is ICE-TCP: its listener's
/// connection does not hold the server engine's `wait`, and the client's peer hears the
/// close.
#[test]
fn a_server_reached_over_tcp_does_not_hold_the_engine_shutdown() {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (udp, tcp) = loop {
        let t = std::net::TcpListener::bind(any)
            .unwrap()
            .local_addr()
            .unwrap();
        if std::net::UdpSocket::bind(t).is_ok() {
            break (t, t);
        }
    };
    let server = RtcServer::new(vec![udp]).tcp_candidates(vec![tcp]);
    let se = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_secs(20);
            v
        })
        .listen(Listener::udp(udp).threads(1).serve(server.clone()))
        .listen(Listener::tcp(tcp).threads(1).serve(server.tcp()))
        .build()
        .unwrap();
    se.start().unwrap();
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    a.dial_tcp(&e).unwrap();
    let (stx, srx) = channel();
    let (_pa, arx) = connect(&a, " tcp ", |offer| {
        server.accept_offer(offer, Echo(Mutex::new(stx))).unwrap().1
    });
    stop(&se);
    wait(&srx, T, "the server's close", |g| matches!(g, Got::Closed));
    wait(&arx, BOUND, "a's close", |g| matches!(g, Got::Closed));
    a.close();
    e.shutdown();
}

/// A TURN allocation over TCP: its control connection does not hold the engine's `wait`.
#[test]
fn a_tcp_allocation_does_not_hold_the_engine_shutdown() {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let te = Arc::new(
        Engine::builder()
            .listen(Listener::udp(any).threads(1).serve(turn.clone()))
            .listen(Listener::tcp(any).threads(1).serve(turn.stream()))
            .build()
            .unwrap(),
    );
    turn.set_engine(&te);
    te.start().unwrap();
    let tcp = te.local_addrs()[1];
    let e = engine();
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    a.gather_relay_via(&e, &RelayServer::tcp(tcp, "alice", "wonderland"), T)
        .expect("allocation over TCP");
    assert_eq!(turn.stats().allocations, 1);
    stop(&e);
    te.shutdown();
}
