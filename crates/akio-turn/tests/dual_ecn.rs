//! Dual allocations (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`), the traffic class (DSCP and ECN)
//! across the relay (RFC 8656 section 14) and ICMP relaying (section 11.5), on real sockets:
//! the server relays from 127.0.0.1 and ::1, the sans-io client talks to it from an engine
//! socket, and peers of both families answer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use akio_turn::client::{Client, ClientConfig, ClientEvent};
use akio_turn::{TurnConfig, TurnServer, static_auth};

/// What a socket received: from, data, traffic class byte (DSCP and ECN).
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
        let _ = self.0.send((c.peer_addr(), data.to_vec(), c.rx_tos()));
    }
}

fn bind(engine: &Engine, addr: &str) -> Option<(UdpBinding, Receiver<Got>)> {
    let (tx, rx) = channel();
    let b = engine.bind_udp(addr.parse().unwrap(), Rec(tx)).ok()?;
    Some((b, rx))
}

/// Whether this platform reports and sets ECN codepoints on UDP sockets.
fn ecn() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        akio_sys::ecn_available()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

struct Session {
    client: Client,
    sock: UdpBinding,
    rx: Receiver<Got>,
    server: SocketAddr,
    /// Relayed data the client got: peer, data, traffic class of the server's datagram.
    got: Vec<Got>,
}

impl Session {
    /// Sends what the client has (relayed data with traffic class `tos`), then reads for
    /// `wait`.
    fn pump(&mut self, tos: u8, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            while let Some(m) = self.client.poll_transmit() {
                if tos != 0 && !akio_turn::stun::is_stun(&m) {
                    self.sock.send_to_tos(&m, self.server, tos).unwrap();
                } else {
                    self.sock.send_to(&m, self.server).unwrap();
                }
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Ok((_, d, e)) = self.rx.recv_timeout(left.min(Duration::from_millis(20))) {
                let now = Instant::now();
                if let Some((p, payload)) = self.client.handle_input(now, &d) {
                    self.got.push((p, payload.to_vec(), e));
                }
            }
            self.client.handle_timeout(Instant::now());
        }
    }

    fn event(&mut self) -> Option<ClientEvent> {
        for _ in 0..100 {
            if let Some(e) = self.client.poll_event() {
                return Some(e);
            }
            self.pump(0, Duration::from_millis(20));
        }
        None
    }
}

fn recv(rx: &Receiver<Got>) -> Got {
    rx.recv_timeout(Duration::from_secs(5)).expect("datagram")
}

fn server_cfg() -> TurnConfig {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap())
        .additional_relay_ip("::1".parse().unwrap())
        .allow_private_peers(true)
}

/// A TURN server on an engine (one UDP listener thread, relays bound through the engine).
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

#[test]
fn dual_allocation_relays_both_families_with_ecn() {
    traffic_class_across_the_relay(true);
}

#[test]
fn dscp_cleared_when_not_copied() {
    traffic_class_across_the_relay(false);
}

fn traffic_class_across_the_relay(copy_dscp: bool) {
    let (turn, engine, server) = start(server_cfg().copy_dscp(copy_dscp));
    let Some((p6, p6rx)) = bind(&engine, "[::1]:0") else {
        eprintln!("no IPv6 loopback: skipped");
        return;
    };
    let (p4, p4rx) = bind(&engine, "127.0.0.1:0").unwrap();
    let (sock, rx) = bind(&engine, "127.0.0.1:0").unwrap();
    let ccfg = ClientConfig::new(server, "alice", "wonderland").dual_allocation(true);
    let mut s = Session {
        client: Client::new(ccfg, Instant::now()),
        sock,
        rx,
        server,
        got: Vec::new(),
    };
    let Some(ClientEvent::Allocated { relayed, .. }) = s.event() else {
        panic!("not allocated");
    };
    let relays = s.client.relayed_addrs().to_vec();
    assert_eq!(relays.len(), 2, "{relays:?}");
    assert_eq!(relays[0], relayed);
    assert!(relays[0].is_ipv4() && relays[1].is_ipv6());
    assert_eq!(turn.relays_of(s.sock.local_addr()), relays);

    let marks = ecn();
    for (i, (peer, prx)) in [(&p4, &p4rx), (&p6, &p6rx)].into_iter().enumerate() {
        let to = peer.local_addr();
        // The first datagram waits for the channel; then marked ones (ECT(1), ECT(0), CE).
        assert!(s.client.send_to(Instant::now(), to, b"first"));
        s.pump(0, Duration::from_millis(100));
        let (from, d, _) = recv(prx);
        assert_eq!(d, b"first");
        assert_eq!(from, relays[i], "the relay of the peer's family");
        // DSCP EF, AF41, CS1 (with DSCP copied: section 14's preferred behaviour), then CS6
        // alone, not ECN-capable.
        for tos in [46u8 << 2 | 1, 34 << 2 | 2, 8 << 2 | 3, 48 << 2] {
            let want = if copy_dscp { tos } else { tos & 3 };
            assert!(s.client.send_to(Instant::now(), to, &[tos; 8]));
            s.pump(tos, Duration::ZERO);
            let (_, d, got) = recv(prx);
            assert_eq!(d, [tos; 8]);
            if marks {
                assert_eq!(got, want, "client to peer {to}");
            }
            // And back: the peer's traffic class reaches the client.
            peer.send_to_tos(&[tos ^ 1; 4], from, tos).unwrap();
            let t = Instant::now() + Duration::from_secs(5);
            while s.got.is_empty() && Instant::now() < t {
                s.pump(0, Duration::from_millis(20));
            }
            let (p, d, got) = s.got.remove(0);
            assert_eq!((p, d), (to, vec![tos ^ 1; 4]));
            if marks {
                assert_eq!(got, want, "peer {to} to client");
            }
        }
        // Unmarked stays unmarked.
        assert!(s.client.send_to(Instant::now(), to, b"plain"));
        s.pump(0, Duration::ZERO);
        assert_eq!(recv(prx).2, 0);
    }
    assert!(turn.stats().to_peer >= 12);
    assert!(turn.stats().to_client >= 8);
    s.client.close(Instant::now());
    let _ = s.event();
    assert!(turn.relays_of(s.sock.local_addr()).is_empty());
    engine.shutdown();
}

/// Datagrams relayed to a closed port draw ICMP port unreachable on loopback: the client hears
/// of it (a Data indication with `ICMP`, RFC 8656 section 11.5) on both families, and the relay
/// goes on relaying. Linux only (`IP_RECVERR`); elsewhere the server cannot see ICMP.
#[cfg(target_os = "linux")]
#[test]
fn icmp_reaches_the_client() {
    let (turn, engine, server) = start(server_cfg());
    let v6 = bind(&engine, "[::1]:0");
    let (sock, rx) = bind(&engine, "127.0.0.1:0").unwrap();
    let ccfg = ClientConfig::new(server, "alice", "wonderland").dual_allocation(v6.is_some());
    let mut s = Session {
        client: Client::new(ccfg, Instant::now()),
        sock,
        rx,
        server,
        got: Vec::new(),
    };
    assert!(matches!(s.event(), Some(ClientEvent::Allocated { .. })));
    let mut peers = vec![(bind(&engine, "127.0.0.1:0").unwrap(), "127.0.0.1:0")];
    if let Some(p) = v6 {
        peers.push((p, "[::1]:0"));
    }
    let mut icmp = 0;
    for ((peer, prx), any) in peers {
        // A port nobody listens on (bound, then closed).
        let closed = std::net::UdpSocket::bind(any)
            .unwrap()
            .local_addr()
            .unwrap();
        for i in 0..3 {
            // The permission comes with the first; ICMP is rate-limited: a few tries.
            assert!(s.client.send_to(Instant::now(), closed, b"anyone?"));
            s.pump(0, Duration::from_millis(100 * (i + 1)));
            if let Some(e) = s.client.poll_event() {
                let ClientEvent::Icmp {
                    peer: p,
                    icmp_type,
                    code,
                    mtu,
                } = e
                else {
                    panic!("{e:?}");
                };
                assert_eq!(p, closed);
                // Port unreachable: ICMPv4 3/3, ICMPv6 1/4.
                let want = if closed.is_ipv6() { (1, 4) } else { (3, 3) };
                assert_eq!((icmp_type, code, mtu), (want.0, want.1, 0));
                icmp += 1;
                break;
            }
        }
        // The relay still works both ways.
        let to = peer.local_addr();
        assert!(s.client.send_to(Instant::now(), to, b"still there"));
        s.pump(0, Duration::from_millis(100));
        let (from, d, _) = recv(&prx);
        assert_eq!(d, b"still there");
        peer.send_to(b"yes", from).unwrap();
        let t = Instant::now() + Duration::from_secs(5);
        while s.got.is_empty() && Instant::now() < t {
            s.pump(0, Duration::from_millis(20));
        }
        assert_eq!(s.got.remove(0), (to, b"yes".to_vec(), 0));
    }
    assert!(icmp >= 1, "no ICMP error relayed");
    assert_eq!(turn.stats().icmp, icmp);
    engine.shutdown();
}
