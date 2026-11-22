//! Dual allocations (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`) and ECN across the relay
//! (RFC 8656 section 14), on real sockets: the server relays from 127.0.0.1 and ::1, the
//! sans-io client talks to it from an engine socket, and peers of both families answer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use only_turn::client::{Client, ClientConfig, ClientEvent};
use only_turn::{TurnConfig, TurnServer, static_auth};

/// What a socket received: from, data, ECN codepoint.
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
        let _ = self.0.send((c.peer_addr(), data.to_vec(), c.rx_ecn()));
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
        only_sys::ecn_available()
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
    /// Relayed data the client got: peer, data, ECN of the server's datagram.
    got: Vec<Got>,
}

impl Session {
    /// Sends what the client has (relayed data with codepoint `ecn`), then reads for `wait`.
    fn pump(&mut self, ecn: u8, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            while let Some(m) = self.client.poll_transmit() {
                if ecn != 0 && !only_turn::stun::is_stun(&m) {
                    self.sock.send_to_ecn(&m, self.server, ecn).unwrap();
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

#[test]
fn dual_allocation_relays_both_families_with_ecn() {
    let auth = static_auth("only", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap())
        .additional_relay_ip("::1".parse().unwrap())
        .allow_private_peers(true);
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
        for ecn in [1u8, 2, 3] {
            assert!(s.client.send_to(Instant::now(), to, &[ecn; 8]));
            s.pump(ecn, Duration::ZERO);
            let (_, d, got) = recv(prx);
            assert_eq!(d, [ecn; 8]);
            if marks {
                assert_eq!(got, ecn, "client to peer {to}");
            }
            // And back: the peer's codepoint reaches the client.
            peer.send_to_ecn(&[0xa0 | ecn; 4], from, ecn).unwrap();
            let t = Instant::now() + Duration::from_secs(5);
            while s.got.is_empty() && Instant::now() < t {
                s.pump(0, Duration::from_millis(20));
            }
            let (p, d, got) = s.got.remove(0);
            assert_eq!((p, d), (to, vec![0xa0 | ecn; 4]));
            if marks {
                assert_eq!(got, ecn, "peer {to} to client");
            }
        }
        // Unmarked stays unmarked.
        assert!(s.client.send_to(Instant::now(), to, b"plain"));
        s.pump(0, Duration::ZERO);
        assert_eq!(recv(prx).2, 0);
    }
    assert!(turn.stats().to_peer >= 10);
    assert!(turn.stats().to_client >= 6);
    s.client.close(Instant::now());
    let _ = s.event();
    assert!(turn.relays_of(s.sock.local_addr()).is_empty());
    engine.shutdown();
}
