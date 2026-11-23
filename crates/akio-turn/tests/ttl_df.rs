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

impl Session {
    /// The next `ClientEvent::Icmp` within `wait`: peer, type, code, MTU.
    fn icmp(&mut self, wait: Duration) -> Option<(SocketAddr, u8, u8, u32)> {
        let end = Instant::now() + wait;
        while Instant::now() < end {
            while let Some(e) = self.client.poll_event() {
                if let ClientEvent::Icmp {
                    peer,
                    icmp_type,
                    code,
                    mtu,
                    ..
                } = e
                {
                    return Some((peer, icmp_type, code, mtu));
                }
            }
            self.pump(Duration::from_millis(20));
        }
        None
    }

    /// A Send indication to `to` with `len` bytes, with `DONT-FRAGMENT` or not.
    fn send_ind(&self, to: SocketAddr, len: usize, df: bool) {
        let data = vec![0x5a; len];
        let mut b = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
            .xor_addr(attr::XOR_PEER_ADDRESS, to)
            .attr(attr::DATA, &data);
        if df {
            b = b.attr(attr::DONT_FRAGMENT, &[]);
        }
        self.sock.send_to(&b.build(), self.server).unwrap();
    }
}

/// A client datagram that reaches the server with TTL 1 is dropped, and the client hears of it
/// as from a router (RFC 8656 section 13.2): ICMP time exceeded (11/0) for the peer, once per
/// 100 ms however many it sends; with `relay_icmp(false)` it hears nothing.
#[test]
fn ttl_1_from_the_client_draws_time_exceeded() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    for relay_icmp in [true, false] {
        let (turn, engine, server) = start(server_cfg().relay_icmp(relay_icmp));
        let (p4, p4rx) = bind(&engine, "127.0.0.1:0", 64).unwrap();
        // Every datagram of the client leaves with TTL 1 and reaches the server with it
        // (loopback): its requests are answered all the same.
        let mut s = session(&engine, server, 1);
        s.allocated();
        let to = p4.local_addr();
        assert!(s.client.create_permission(Instant::now(), to));
        s.pump(Duration::from_millis(100));
        for _ in 0..5 {
            s.send_ind(to, 100, false);
        }
        let got = s.icmp(Duration::from_millis(400));
        assert!(p4rx.try_recv().is_err(), "relayed");
        assert_eq!(turn.stats().ttl_expired, 5);
        if relay_icmp {
            assert_eq!(got, Some((to, 11, 0, 0)));
            assert_eq!(turn.stats().icmp, 1);
        } else {
            assert_eq!(got, None);
            assert_eq!(turn.stats().icmp, 0);
        }
        engine.shutdown();
    }
}

/// A Send indication with `DONT-FRAGMENT` one byte too large for the path to an IPv4 peer is
/// refused by the kernel (`EMSGSIZE`), and the client gets "fragmentation needed" (3/4) with
/// the path MTU, as a router would have told it (RFC 8656 section 14, RFC 1122); the next one
/// that fits goes through, as does the large one without `DONT-FRAGMENT` (fragmented). It
/// needs a path MTU small enough to exceed with a datagram every socket can send: loopback
/// lowered to 1500 bytes or so (Linux in a container with `NET_ADMIN`:
/// `ip link set lo mtu 1500`); with loopback's usual MTU (Linux 65536, macOS 16384, over
/// macOS's 9216-byte UDP send limit) it is skipped.
#[test]
fn too_big_for_the_path_draws_fragmentation_needed() {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return;
    }
    let mtu = akio_sys::path_mtu("127.0.0.1:9".parse().unwrap()).unwrap() as usize;
    if mtu + 100 > 9000 {
        eprintln!("loopback MTU {mtu}: skipped (lower it to run this test)");
        return;
    }
    let (turn, engine, server) = start(server_cfg());
    let (p4, p4rx) = bind(&engine, "127.0.0.1:0", 64).unwrap();
    let mut s = session(&engine, server, 64);
    s.allocated();
    let to = p4.local_addr();
    assert!(s.client.create_permission(Instant::now(), to));
    s.pump(Duration::from_millis(100));
    let fits = mtu - 28;
    s.send_ind(to, fits + 1, true);
    assert_eq!(s.icmp(Duration::from_secs(2)), Some((to, 3, 4, mtu as u32)));
    assert!(p4rx.recv_timeout(Duration::from_millis(100)).is_err());
    assert_eq!(turn.stats().icmp, 1);
    for (len, df) in [(fits, true), (fits + 1, false)] {
        s.send_ind(to, len, df);
        let (_, d, _) = p4rx.recv_timeout(Duration::from_secs(5)).expect("relayed");
        assert_eq!(d.len(), len, "df={df}");
    }
    assert_eq!(s.icmp(Duration::from_millis(200)), None);
    engine.shutdown();
}
