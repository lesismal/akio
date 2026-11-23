//! The TTL / hop limit across the relay (RFC 5766 section 12, RFC 8656 section 13: one less
//! than it came in) and `DONT-FRAGMENT` (RFC 8656 sections 11.2 and 14), on real sockets: the
//! server relays from 127.0.0.1 and ::1, the sans-io client talks to it from an engine socket
//! with a TTL of its own, and peers of both families answer with theirs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use akio_turn::client::{Client, ClientConfig, ClientEvent};
use akio_turn::stun::{Class, MessageBuilder, Method, attr, transaction_id};
use akio_turn::{TurnConfig, TurnServer, static_auth};

/// What a socket received: from, data, TTL / hop limit.
type Got = (SocketAddr, Vec<u8>, u8);

#[derive(Clone)]
struct Rec(Sender<Got>);

impl Acceptor for Rec {
    type Handler = RecConn;
    fn on_open(&self, _c: &Conn<RecConn>) -> RecConn {
        RecConn(self.0.clone())
    }
}

struct RecConn(Sender<Got>);

impl Handler for RecConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send((c.peer_addr(), data.to_vec(), c.rx_ttl()));
    }
}

/// An engine socket at `addr` that reports TTLs and sends with `ttl`.
fn bind(engine: &Engine, addr: &str, ttl: u32) -> Option<(UdpBinding, Receiver<Got>)> {
    let (tx, rx) = channel();
    let b = engine.bind_udp(addr.parse().unwrap(), Rec(tx)).ok()?;
    assert!(b.enable_rx_ttl());
    b.set_unicast_hops(ttl).unwrap();
    Some((b, rx))
}

fn start(cfg: TurnConfig) -> (TurnServer, Arc<Engine>, SocketAddr) {
    let turn = TurnServer::new(cfg);
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(turn.clone()),
            )
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let server = engine.local_addrs()[0];
    (turn, engine, server)
}

fn server_cfg() -> TurnConfig {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap())
        .additional_relay_ip("::1".parse().unwrap())
        .allow_private_peers(true)
}

struct Session {
    client: Client,
    sock: UdpBinding,
    rx: Receiver<Got>,
    server: SocketAddr,
    /// Relayed data the client got: peer, data, TTL of the server's datagram.
    got: Vec<Got>,
}

impl Session {
    fn pump(&mut self, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            while let Some(m) = self.client.poll_transmit() {
                self.sock.send_to(&m, self.server).unwrap();
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Ok((_, d, ttl)) = self.rx.recv_timeout(left.min(Duration::from_millis(20))) {
                if let Some((p, payload)) = self.client.handle_input(Instant::now(), &d) {
                    self.got.push((p, payload.to_vec(), ttl));
                }
            }
            self.client.handle_timeout(Instant::now());
        }
    }

    fn allocated(&mut self) -> Vec<SocketAddr> {
        for _ in 0..100 {
            if let Some(e) = self.client.poll_event() {
                assert!(matches!(e, ClientEvent::Allocated { .. }), "{e:?}");
                return self.client.relayed_addrs().to_vec();
            }
            self.pump(Duration::from_millis(20));
        }
        panic!("not allocated");
    }

    fn next_got(&mut self) -> Option<Got> {
        let t = Instant::now() + Duration::from_millis(500);
        while self.got.is_empty() && Instant::now() < t {
            self.pump(Duration::from_millis(20));
        }
        (!self.got.is_empty()).then(|| self.got.remove(0))
    }
}

fn session(engine: &Engine, server: SocketAddr, ttl: u32) -> Session {
    let (sock, rx) = bind(engine, "127.0.0.1:0", ttl).unwrap();
    let ccfg = ClientConfig::new(server, "alice", "wonderland").dual_allocation(true);
    Session {
        client: Client::new(ccfg, Instant::now()),
        sock,
        rx,
        server,
        got: Vec::new(),
    }
}

/// The TTL a datagram the server sends on `family` with `ttl` arrives with on loopback: `ttl`
/// itself, except where the platform cannot set it per datagram (macOS IPv4: the default 64).
fn sent(v6: bool, ttl: u8) -> u8 {
    if cfg!(target_os = "macos") && !v6 {
        64
    } else {
        ttl
    }
}

/// TTL 40 from the client reaches the peers as 39, TTL 50 from the peers reaches the client as
/// 49, on both families, through channels; with `copy_ttl` off everything arrives with the
/// default (64). A datagram that reaches the server with TTL 1 goes no further.
#[test]
fn ttl_is_decremented_across_the_relay() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    for copy in [true, false] {
        let (turn, engine, server) = start(server_cfg().copy_ttl(copy));
        let Some((p6, p6rx)) = bind(&engine, "[::1]:0", 50) else {
            eprintln!("no IPv6 loopback: skipped");
            return;
        };
        let (p4, p4rx) = bind(&engine, "127.0.0.1:0", 50).unwrap();
        let mut s = session(&engine, server, 40);
        let relays = s.allocated();
        assert_eq!(relays.len(), 2);
        for (peer, prx) in [(&p4, &p4rx), (&p6, &p6rx)] {
            let to = peer.local_addr();
            let v6 = to.is_ipv6();
            for i in 0..3u8 {
                assert!(s.client.send_to(Instant::now(), to, &[i; 8]));
                s.pump(Duration::from_millis(30));
                let (from, d, ttl) = prx.recv_timeout(Duration::from_secs(5)).expect("to peer");
                assert_eq!(d, [i; 8]);
                assert_eq!(ttl, if copy { sent(v6, 39) } else { 64 }, "to {to}");
                peer.send_to(&[i; 4], from).unwrap();
                let (p, d, ttl) = s.next_got().expect("to client");
                assert_eq!((p, d), (to, vec![i; 4]));
                assert_eq!(ttl, if copy { sent(false, 49) } else { 64 }, "from {to}");
            }
        }
        // TTL 1: the server drops it (copying), or relays it with the default (not).
        p4.set_unicast_hops(1).unwrap();
        let (_, from4) = (p4.local_addr(), relays[0]);
        p4.send_to(b"last hop", from4).unwrap();
        let got = s.next_got();
        if copy {
            assert_eq!(got, None);
            assert_eq!(turn.stats().ttl_expired, 1);
        } else {
            assert_eq!(got.map(|g| g.2), Some(64));
            assert_eq!(turn.stats().ttl_expired, 0);
        }
        engine.shutdown();
    }
}

/// `DONT-FRAGMENT` in Send indications on real sockets: datagrams with and without it, to an
/// IPv4 peer (DF set and cleared on the relay socket as they alternate) and an IPv6 one (the
/// attribute ignored from a UDP client, RFC 8656 section 13), all arrive: loopback needs no
/// fragmenting. That a datagram too big for the path is refused with DF and fragmented
/// without is shown on a 1500-byte link by `tools/interop/webrtc/turn-ttl-df.sh`.
#[test]
fn dont_fragment_in_send_indications() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let (turn, engine, server) = start(server_cfg());
    let (p4, p4rx) = bind(&engine, "127.0.0.1:0", 64).unwrap();
    let p6 = bind(&engine, "[::1]:0", 64);
    let mut s = session(&engine, server, 64);
    s.allocated();
    let mut peers = vec![(p4, p4rx)];
    peers.extend(p6);
    for (peer, prx) in &peers {
        let to = peer.local_addr();
        assert!(s.client.create_permission(Instant::now(), to));
        s.pump(Duration::from_millis(100));
        for (i, df) in [true, false, true, true, false].into_iter().enumerate() {
            let data = vec![i as u8; 1000];
            let mut b = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
                .xor_addr(attr::XOR_PEER_ADDRESS, to)
                .attr(attr::DATA, &data);
            if df {
                b = b.attr(attr::DONT_FRAGMENT, &[]);
            }
            s.sock.send_to(&b.build(), server).unwrap();
            let (_, d, _) = prx.recv_timeout(Duration::from_secs(5)).expect("relayed");
            assert_eq!(d, data, "{to} df={df}");
        }
    }
    assert_eq!(turn.stats().to_peer, 5 * peers.len() as u64);
    engine.shutdown();
}
