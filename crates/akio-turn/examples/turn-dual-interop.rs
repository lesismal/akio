//! Dual allocations (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`), the traffic class (DSCP and ECN)
//! across the relay, ICMP relaying and deleting one family against other TURN servers and
//! clients (`tools/interop/webrtc/turn-dual.sh`).
//!
//! ```text
//! turn-dual-interop server <udp-addr> <user> <pass>
//!     akio-turn relaying from 127.0.0.1 and ::1 (dual allocations), realm "akio"
//! turn-dual-interop client <server> <user> <pass> <relays> [ecn,dscp,icmp,release]
//!     the akio_turn client asks for a dual allocation over UDP and checks it got <relays>
//!     relayed addresses (1 or 2); per family, a peer on 127.0.0.1 or ::1 echoes 20 datagrams;
//!     the client marks its datagrams DSCP EF + ECT(0), the peer its echoes AF41 + ECT(1); then
//!     the client sends to a closed port through the relay and waits for the ICMP error
//!     (RFC 8656 section 11.5). With two relays, it then gives back the IPv6 one
//!     (`Client::release_family`) and checks the server stopped relaying it while the IPv4
//!     one goes on. What was seen is printed; each word of the last argument makes it a
//!     requirement: ECN copied both ways, DSCP copied both ways, ICMP relayed, the IPv6
//!     family deleted alone.
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use akio_turn::client::{Client, ClientConfig, ClientEvent};
use akio_turn::{TurnConfig, TurnServer, static_auth};

type Got = (SocketAddr, Vec<u8>, u8);

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

fn fail(why: String) -> ! {
    eprintln!("FAIL: {why}");
    std::process::exit(1);
}

fn engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .build()
            .expect("engine"),
    );
    e.start().expect("start");
    e
}

fn bind(e: &Engine, addr: &str) -> (UdpBinding, Receiver<Got>) {
    let (tx, rx) = channel();
    let b = e
        .bind_udp(addr.parse().expect("addr"), Rec(tx))
        .unwrap_or_else(|err| fail(format!("bind {addr}: {err}")));
    (b, rx)
}

fn server(addr: &str, user: &str, pass: &str) {
    let auth = static_auth("akio", [(user, pass)]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().expect("ip"))
        .additional_relay_ip("::1".parse().expect("ip"))
        .allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let e = Arc::new(
        Engine::builder()
            .listen(Listener::udp(addr.parse().expect("addr")).serve(turn.clone()))
            .build()
            .expect("engine"),
    );
    turn.set_engine(&e);
    eprintln!("akio-turn (dual: 127.0.0.1 and ::1) on udp {addr}");
    e.run().expect("run");
}

struct Session {
    c: Client,
    sock: UdpBinding,
    rx: Receiver<Got>,
    server: SocketAddr,
    got: Vec<Got>,
    /// Datagrams from the server, relayed data or not.
    raw: usize,
    /// ICMP errors relayed: peer, type, code.
    icmp: Vec<(SocketAddr, u8, u8)>,
}

impl Session {
    fn pump(&mut self, tos: u8, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            while let Some(m) = self.c.poll_transmit() {
                let r = if tos != 0 && !akio_turn::stun::is_stun(&m) {
                    self.sock.send_to_tos(&m, self.server, tos)
                } else {
                    self.sock.send_to(&m, self.server)
                };
                r.unwrap_or_else(|e| fail(format!("send: {e}")));
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Ok((_, d, e)) = self.rx.recv_timeout(left.min(Duration::from_millis(20))) {
                self.raw += 1;
                // What the server answers to Refreshes (the family release among them).
                if let Ok(m) = akio_turn::stun::Message::parse(&d) {
                    if m.method() == akio_turn::stun::Method::REFRESH
                        && m.class() != akio_turn::stun::Class::Request
                    {
                        println!(
                            "  Refresh answered: {:?} {:?}",
                            m.class(),
                            m.error_code().map(|(c, r)| format!("{c} {r}"))
                        );
                    }
                }
                if let Some((p, payload)) = self.c.handle_input(Instant::now(), &d) {
                    self.got.push((p, payload.to_vec(), e));
                }
            }
            self.c.handle_timeout(Instant::now());
            while let Some(ev) = self.c.poll_event() {
                match ev {
                    ClientEvent::Icmp {
                        peer,
                        icmp_type,
                        code,
                        ..
                    } => self.icmp.push((peer, icmp_type, code)),
                    ev => println!("  event {ev:?}"),
                }
            }
        }
    }
}

/// Client to peer: DSCP EF, ECT(0). Peer to client: AF41, ECT(1).
const TOS_OUT: u8 = 46 << 2 | 2;
const TOS_BACK: u8 = 34 << 2 | 1;

fn client(server: &str, user: &str, pass: &str, want: usize, need: &str) {
    let need = |w: &str| need.split(',').any(|x| x == w);
    let server: SocketAddr = server.parse().expect("server");
    let e = engine();
    let (sock, rx) = bind(&e, "127.0.0.1:0");
    let cfg = ClientConfig::new(server, user, pass).dual_allocation(true);
    let mut s = Session {
        c: Client::new(cfg, Instant::now()),
        sock,
        rx,
        server,
        got: Vec::new(),
        raw: 0,
        icmp: Vec::new(),
    };
    let t = Instant::now() + Duration::from_secs(10);
    let ev = loop {
        if let Some(ev) = s.c.poll_event() {
            break ev;
        }
        if Instant::now() > t {
            fail("no answer to the Allocate".into());
        }
        s.c.handle_timeout(Instant::now());
        while let Some(m) = s.c.poll_transmit() {
            let _ = s.sock.send_to(&m, s.server);
        }
        if let Ok((_, d, _)) = s.rx.recv_timeout(Duration::from_millis(20)) {
            let _ = s.c.handle_input(Instant::now(), &d);
        }
    };
    if !matches!(ev, ClientEvent::Allocated { .. }) {
        fail(format!("allocate: {ev:?}"));
    }
    let relays = s.c.relayed_addrs().to_vec();
    println!(
        "  relayed {relays:?}, ADDRESS-ERROR-CODE {:?}",
        s.c.address_error()
    );
    if relays.len() != want {
        fail(format!("{} relayed addresses, want {want}", relays.len()));
    }
    let mut peers = Vec::new();
    for relay in &relays {
        let (peer, prx) = bind(
            &e,
            if relay.is_ipv6() {
                "[::1]:0"
            } else {
                "127.0.0.1:0"
            },
        );
        let to = peer.local_addr();
        let (mut out_ecn, mut back_ecn) = (Vec::new(), Vec::new());
        for i in 0..20u8 {
            let msg = [i; 64];
            if !s.c.send_to(Instant::now(), to, &msg) {
                fail(format!("send_to {to} refused"));
            }
            s.pump(TOS_OUT, Duration::ZERO);
            let t = Instant::now() + Duration::from_secs(5);
            let (from, d, got) = loop {
                match prx.recv_timeout(Duration::from_millis(20)) {
                    Ok(g) => break g,
                    Err(_) if Instant::now() < t => s.pump(TOS_OUT, Duration::from_millis(1)),
                    Err(_) => fail(format!("peer {to}: nothing from the relay")),
                }
            };
            if d != msg || from != *relay {
                fail(format!(
                    "peer {to}: {} bytes from {from}, want the relay {relay}",
                    d.len()
                ));
            }
            out_ecn.push(got);
            peer.send_to_tos(&d, from, TOS_BACK)
                .unwrap_or_else(|e| fail(format!("echo: {e}")));
            let t = Instant::now() + Duration::from_secs(5);
            while s.got.is_empty() {
                if Instant::now() > t {
                    fail(format!("no echo from {to}"));
                }
                s.pump(0, Duration::from_millis(5));
            }
            let (p, d, got) = s.got.remove(0);
            if p != to || d != msg {
                fail(format!("echo from {p}, {} bytes", d.len()));
            }
            back_ecn.push(got);
        }
        // The first datagram waited for the channel binding (a request): skip it.
        let ecn_out = out_ecn[1..].iter().all(|&x| x & 3 == TOS_OUT & 3);
        let ecn_back = back_ecn.iter().all(|&x| x & 3 == TOS_BACK & 3);
        let dscp_out = out_ecn[1..].iter().all(|&x| x >> 2 == TOS_OUT >> 2);
        let dscp_back = back_ecn.iter().all(|&x| x >> 2 == TOS_BACK >> 2);
        let word = |b| if b { "copied" } else { "not copied" };
        println!(
            "  {} relay {relay}: 20 datagrams echoed; traffic class client->peer {:02x?}, peer->client {:02x?}",
            if relay.is_ipv6() { "IPv6" } else { "IPv4" },
            &out_ecn[1..3],
            &back_ecn[..2],
        );
        println!(
            "    ECN {} / {}, DSCP {} / {}",
            word(ecn_out),
            word(ecn_back),
            word(dscp_out),
            word(dscp_back)
        );
        if need("ecn") && !(ecn_out && ecn_back) {
            fail("ECN codepoints were not copied across the relay".into());
        }
        if need("dscp") && !(dscp_out && dscp_back) {
            fail("DSCP was not copied across the relay".into());
        }
        // ICMP: a closed port of the peer's address, through the relay.
        let closed = std::net::UdpSocket::bind(SocketAddr::new(to.ip(), 0))
            .and_then(|x| x.local_addr())
            .unwrap_or_else(|e| fail(format!("closed port: {e}")));
        s.icmp.clear();
        for _ in 0..5 {
            s.c.send_to(Instant::now(), closed, b"anyone?");
            s.pump(0, Duration::from_millis(200));
            if !s.icmp.is_empty() {
                break;
            }
        }
        match s.icmp.first() {
            Some((p, t, c)) => println!("    ICMP relayed: {p} type {t} code {c}"),
            None => println!("    ICMP not relayed"),
        }
        if need("icmp") {
            let want = if to.is_ipv6() { (1, 4) } else { (3, 3) };
            match s.icmp.first() {
                Some(&(p, t, c)) if p.ip() == closed.ip() && (t, c) == want => {}
                x => fail(format!("ICMP port unreachable for {closed}: got {x:?}")),
            }
        }
        peers.push((relay, to, peer, prx));
    }
    if relays.len() == 2 {
        // Give back the IPv6 relay (RFC 8656 section 8: Refresh with REQUESTED-ADDRESS-FAMILY).
        if !s.c.release_family(Instant::now(), true) {
            fail("release_family refused".into());
        }
        // Long enough for a server that frees relays on a timer (coturn's is per second).
        s.pump(0, Duration::from_millis(2500));
        let (r6, _, p6, _) = &peers[1];
        let before = s.raw;
        for _ in 0..5 {
            let _ = p6.send_to(b"still relayed?", **r6);
        }
        s.pump(0, Duration::from_millis(500));
        let still = s.raw - before;
        // The IPv4 relay goes on.
        let (r4, to4, p4, prx4) = &peers[0];
        s.c.send_to(Instant::now(), *to4, b"v4 after");
        s.pump(0, Duration::from_millis(100));
        let v4_ok = prx4
            .recv_timeout(Duration::from_secs(5))
            .is_ok_and(|(from, d, _)| from == **r4 && d == b"v4 after");
        let _ = p4;
        println!(
            "  IPv6 family released: {} ({still} datagrams relayed after), IPv4 relay {}",
            if still == 0 {
                "deleted"
            } else {
                "still relaying"
            },
            if v4_ok { "still works" } else { "BROKEN" }
        );
        if !v4_ok {
            fail("the IPv4 relay stopped with the IPv6 one".into());
        }
        if need("release") && still != 0 {
            fail("the server kept relaying the released IPv6 family".into());
        }
    }
    s.c.close(Instant::now());
    s.pump(0, Duration::from_millis(200));
    println!("ok: akio_turn dual allocation against {server}");
    e.shutdown();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") if a.len() >= 5 => server(&a[2], &a[3], &a[4]),
        Some("client") if a.len() >= 6 => client(
            &a[2],
            &a[3],
            &a[4],
            a[5].parse().expect("relays"),
            a.get(6).map_or("", String::as_str),
        ),
        _ => fail("usage: turn-dual-interop server|client ...".into()),
    }
}
