//! Dual allocations (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`) and ECN across the relay against
//! other TURN servers and clients (`tools/interop/webrtc/turn-dual.sh`).
//!
//! ```text
//! turn-dual-interop server <udp-addr> <user> <pass>
//!     only-turn relaying from 127.0.0.1 and ::1 (dual allocations), realm "only"
//! turn-dual-interop client <server> <user> <pass> <relays> [ecn]
//!     the only_turn client asks for a dual allocation over UDP and checks it got <relays>
//!     relayed addresses (1 or 2); per family, a peer on 127.0.0.1 or ::1 echoes 20 datagrams;
//!     the client marks its datagrams ECT(0), the peer its echoes ECT(1). The codepoints seen
//!     are printed; with `ecn` they must have been copied both ways.
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use only_turn::client::{Client, ClientConfig, ClientEvent};
use only_turn::{TurnConfig, TurnServer, static_auth};

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
        let _ = self.0.send((c.peer_addr(), data.to_vec(), c.rx_ecn()));
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
    let auth = static_auth("only", [(user, pass)]);
    let cfg = TurnConfig::new("only", auth, "127.0.0.1".parse().expect("ip"))
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
    eprintln!("only-turn (dual: 127.0.0.1 and ::1) on udp {addr}");
    e.run().expect("run");
}

struct Session {
    c: Client,
    sock: UdpBinding,
    rx: Receiver<Got>,
    server: SocketAddr,
    got: Vec<Got>,
}

impl Session {
    fn pump(&mut self, ecn: u8, wait: Duration) {
        let end = Instant::now() + wait;
        loop {
            while let Some(m) = self.c.poll_transmit() {
                let r = if ecn != 0 && !only_turn::stun::is_stun(&m) {
                    self.sock.send_to_ecn(&m, self.server, ecn)
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
                if let Some((p, payload)) = self.c.handle_input(Instant::now(), &d) {
                    self.got.push((p, payload.to_vec(), e));
                }
            }
            self.c.handle_timeout(Instant::now());
        }
    }
}

fn client(server: &str, user: &str, pass: &str, want: usize, ecn: bool) {
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
    };
    let t = Instant::now() + Duration::from_secs(10);
    let ev = loop {
        if let Some(ev) = s.c.poll_event() {
            break ev;
        }
        if Instant::now() > t {
            fail("no answer to the Allocate".into());
        }
        s.pump(0, Duration::from_millis(20));
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
            s.pump(2, Duration::ZERO);
            let t = Instant::now() + Duration::from_secs(5);
            let (from, d, got) = loop {
                match prx.recv_timeout(Duration::from_millis(20)) {
                    Ok(g) => break g,
                    Err(_) if Instant::now() < t => s.pump(2, Duration::from_millis(1)),
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
            peer.send_to_ecn(&d, from, 1)
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
        let copied_out = out_ecn[1..].iter().all(|&x| x == 2);
        let copied_back = back_ecn.iter().all(|&x| x == 1);
        println!(
            "  {} relay {relay}: 20 datagrams echoed; ECN client->peer {:?} ({}), peer->client {:?} ({})",
            if relay.is_ipv6() { "IPv6" } else { "IPv4" },
            &out_ecn[1..4],
            if copied_out { "copied" } else { "not copied" },
            &back_ecn[..3],
            if copied_back { "copied" } else { "not copied" },
        );
        if ecn && !(copied_out && copied_back) {
            fail("ECN codepoints were not copied across the relay".into());
        }
    }
    s.c.close(Instant::now());
    s.pump(0, Duration::from_millis(200));
    println!("ok: only_turn dual allocation against {server}");
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
            a.get(6).is_some_and(|x| x == "ecn"),
        ),
        _ => fail("usage: turn-dual-interop server|client ...".into()),
    }
}
