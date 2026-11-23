//! The TTL across the relay and `DONT-FRAGMENT` against other TURN servers
//! (`tools/interop/webrtc/turn-ttl-df.sh`): the client and the servers share a host, the peer is
//! on another one behind a 1500-byte link.
//!
//! ```text
//! turn-ttl-df-interop server <udp-addr> <relay-ip> <user> <pass>
//!     akio-turn relaying from <relay-ip>, realm "akio"
//! turn-ttl-df-interop peer <udp-addr>
//!     answers every datagram with what it saw ("ttl=<n> len=<n>"), sending with TTL 50
//! turn-ttl-df-interop client <server> <peer> <user> <pass> [ttl,df]
//!     the akio_turn client, sending with TTL 40, allocates, binds a channel to <peer> and
//!     sends (1) ChannelData, (2) a small Send indication with DONT-FRAGMENT, (3) a 2000-byte
//!     one without, (4) the same with DONT-FRAGMENT, (5) a small one with it again. It prints the TTL the peer saw and
//!     the TTL of the answers, and which datagrams arrived; each word of the last argument
//!     makes it a requirement: the TTL one less both ways (39 and 49), the 2000-byte datagram
//!     relayed without DONT-FRAGMENT and refused with it.
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, Listener, UdpBinding};
use akio_turn::client::{Client, ClientConfig, ClientEvent};
use akio_turn::stun::{Class, MessageBuilder, Method, attr, transaction_id};
use akio_turn::{TurnConfig, TurnServer, static_auth};

/// From, data, TTL.
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
        let _ = self.0.send((c.peer_addr(), data.to_vec(), c.rx_ttl()));
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

/// An engine socket at `addr` that reports TTLs and sends with `ttl`.
fn bind(e: &Engine, addr: &str, ttl: u32) -> (UdpBinding, Receiver<Got>) {
    let (tx, rx) = channel();
    let b = e
        .bind_udp(addr.parse().expect("addr"), Rec(tx))
        .unwrap_or_else(|err| fail(format!("bind {addr}: {err}")));
    b.enable_rx_ttl();
    b.set_unicast_hops(ttl).expect("ttl");
    (b, rx)
}

fn server(addr: &str, relay: &str, user: &str, pass: &str) {
    let auth = static_auth("akio", [(user, pass)]);
    let cfg = TurnConfig::new("akio", auth, relay.parse().expect("ip")).allow_private_peers(true);
    let turn = TurnServer::new(cfg);
    let e = Arc::new(
        Engine::builder()
            .listen(Listener::udp(addr.parse().expect("addr")).serve(turn.clone()))
            .build()
            .expect("engine"),
    );
    turn.set_engine(&e);
    eprintln!("akio-turn (relay {relay}) on udp {addr}");
    e.run().expect("run");
}

fn peer(addr: &str) {
    let e = engine();
    let (b, rx) = bind(&e, addr, 50);
    eprintln!("peer on {addr}");
    while let Ok((from, d, ttl)) = rx.recv() {
        let _ = b.send_to(format!("ttl={ttl} len={}", d.len()).as_bytes(), from);
    }
}

struct Session {
    c: Client,
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
            while let Some(m) = self.c.poll_transmit() {
                self.sock
                    .send_to(&m, self.server)
                    .unwrap_or_else(|e| fail(format!("send: {e}")));
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            if let Ok((_, d, ttl)) = self.rx.recv_timeout(left.min(Duration::from_millis(20))) {
                if let Some((p, payload)) = self.c.handle_input(Instant::now(), &d) {
                    self.got.push((p, payload.to_vec(), ttl));
                }
            }
            self.c.handle_timeout(Instant::now());
        }
    }

    /// The peer's next answer within a second: what it saw, and the TTL the answer reached
    /// the client with.
    fn answer(&mut self) -> Option<(String, u8)> {
        let end = Instant::now() + Duration::from_secs(1);
        while self.got.is_empty() && Instant::now() < end {
            self.pump(Duration::from_millis(20));
        }
        (!self.got.is_empty()).then(|| {
            let (_, d, ttl) = self.got.remove(0);
            (String::from_utf8_lossy(&d).into_owned(), ttl)
        })
    }

    fn send_indication(&self, to: SocketAddr, len: usize, df: bool) {
        let mut b = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
            .xor_addr(attr::XOR_PEER_ADDRESS, to)
            .attr(attr::DATA, &vec![7u8; len]);
        if df {
            b = b.attr(attr::DONT_FRAGMENT, &[]);
        }
        self.sock
            .send_to(&b.build(), self.server)
            .unwrap_or_else(|e| fail(format!("send: {e}")));
    }
}

fn client(server: &str, to: &str, user: &str, pass: &str, require: &str) {
    let e = engine();
    let server: SocketAddr = server.parse().expect("server");
    let to: SocketAddr = to.parse().expect("peer");
    let (sock, rx) = bind(&e, "127.0.0.1:0", 40);
    let mut s = Session {
        c: Client::new(ClientConfig::new(server, user, pass), Instant::now()),
        sock,
        rx,
        server,
        got: Vec::new(),
    };
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        s.pump(Duration::from_millis(20));
        match s.c.poll_event() {
            Some(ClientEvent::Allocated { relayed, .. }) => {
                println!("  allocated {relayed}");
                break;
            }
            Some(ev) => fail(format!("{ev:?}")),
            None if Instant::now() > end => fail("no allocation".into()),
            None => {}
        }
    }
    // (1) ChannelData (the first datagram waits for the channel).
    if !s.c.send_to(Instant::now(), to, b"hello") {
        fail("send_to".into());
    }
    let Some((seen, back)) = s.answer() else {
        fail("no answer to ChannelData".into());
    };
    println!("  client TTL 40 -> peer saw {seen}; peer TTL 50 -> client saw ttl={back}");
    // (2), (3), (4).
    let mut arrived = Vec::new();
    for (len, df) in [(100, true), (2000, false), (2000, true), (100, true)] {
        s.send_indication(to, len, df);
        let a = s.answer();
        println!(
            "  Send indication, {len} bytes{}: {}",
            if df { ", DONT-FRAGMENT" } else { "" },
            a.as_ref().map_or_else(
                || "not relayed".to_owned(),
                |(seen, _)| format!("peer saw {seen}")
            )
        );
        arrived.push(a.is_some());
    }
    for word in require.split(',').filter(|w| !w.is_empty()) {
        match word {
            "ttl" => {
                if !seen.starts_with("ttl=39 ") || back != 49 {
                    fail(format!(
                        "TTL not decremented: peer saw {seen}, client ttl={back}"
                    ));
                }
            }
            "df" => {
                if arrived != [true, true, false, true] {
                    fail(format!("DONT-FRAGMENT not honoured: {arrived:?}"));
                }
            }
            w => fail(format!("unknown requirement {w}")),
        }
    }
    s.c.close(Instant::now());
    s.pump(Duration::from_millis(100));
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    match a.get(1..) {
        Some(["server", addr, relay, user, pass]) => server(addr, relay, user, pass),
        Some(["peer", addr]) => peer(addr),
        Some(["client", server, to, user, pass]) => client(server, to, user, pass, ""),
        Some(["client", server, to, user, pass, req]) => client(server, to, user, pass, req),
        _ => fail("usage: see the module documentation".into()),
    }
}
