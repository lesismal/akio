//! What an embedding server sets and hears (akit's A256 and A257) over real `akio` sockets:
//! the relay port range, the shared nonce secret, the stream message bound, `on_relay`,
//! `on_event` and `holds_relay`.
#![allow(missing_docs)]

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_turn::framing::FrameReader;
use akio_turn::stun::{
    Class, Message, MessageBuilder, Method, attr, long_term_key, transaction_id,
};
use akio_turn::{FreeReason, TurnConfig, TurnEventKind, TurnServer, static_auth};

const WAIT: Duration = Duration::from_secs(5);

fn sock() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    s
}

fn recv(s: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut b = vec![0u8; 2048];
    let (n, from) = s.recv_from(&mut b).unwrap();
    b.truncate(n);
    (b, from)
}

fn config() -> TurnConfig {
    let auth = static_auth("akio", [("alice", "wonderland"), ("bob", "builder")]);
    TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true)
}

struct Server {
    engine: Arc<Engine>,
    turn: TurnServer,
    udp: SocketAddr,
    tcp: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.engine.shutdown();
        self.engine.wait();
    }
}

fn serve(cfg: TurnConfig) -> Server {
    let turn = TurnServer::new(cfg);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::udp(any).threads(1).serve(turn.clone()))
            .listen(Listener::tcp(any).threads(1).serve(turn.stream()))
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let a = engine.local_addrs();
    Server {
        engine,
        turn,
        udp: a[0],
        tcp: a[1],
    }
}

/// How a test client reaches the server.
enum Wire {
    Udp(UdpSocket, SocketAddr),
    Tcp(TcpStream, FrameReader, VecDeque<Vec<u8>>),
}

impl Wire {
    fn send(&mut self, b: &[u8]) {
        match self {
            Wire::Udp(s, to) => {
                s.send_to(b, *to).unwrap();
            }
            Wire::Tcp(s, ..) => s.write_all(b).unwrap(),
        }
    }

    /// The next message, or `None` when a TCP server closed the connection.
    fn recv(&mut self) -> Option<Vec<u8>> {
        match self {
            Wire::Udp(s, _) => Some(recv(s).0),
            Wire::Tcp(s, r, q) => loop {
                if let Some(m) = q.pop_front() {
                    return Some(m);
                }
                let mut b = [0u8; 4096];
                let n = match s.read(&mut b) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::ConnectionReset => 0,
                    Err(e) => panic!("{e}"),
                };
                if n == 0 {
                    return None;
                }
                r.push(&b[..n], |m| q.push_back(m.to_vec())).unwrap();
            },
        }
    }
}

struct Client {
    w: Wire,
    user: &'static str,
    nonce: String,
    key: [u8; 16],
}

impl Client {
    fn udp(server: SocketAddr, user: (&'static str, &str)) -> Client {
        Client {
            w: Wire::Udp(sock(), server),
            user: user.0,
            nonce: String::new(),
            key: long_term_key(user.0, "akio", user.1),
        }
    }

    fn tcp(server: SocketAddr, user: (&'static str, &str)) -> Client {
        let s = TcpStream::connect(server).unwrap();
        s.set_read_timeout(Some(WAIT)).unwrap();
        Client {
            w: Wire::Tcp(s, FrameReader::new(), VecDeque::new()),
            ..Client::udp(server, user)
        }
    }

    fn addr(&self) -> SocketAddr {
        match &self.w {
            Wire::Udp(s, _) => s.local_addr().unwrap(),
            Wire::Tcp(s, ..) => s.local_addr().unwrap(),
        }
    }

    /// Sends a request, again after a 401/438 challenge; the answer, parsed into its class,
    /// error code and message bytes.
    fn request(&mut self, m: Method, f: impl Fn(MessageBuilder) -> MessageBuilder) -> Vec<u8> {
        for _ in 0..2 {
            let tid = transaction_id();
            let mut b = f(MessageBuilder::new(m, Class::Request, tid));
            if !self.nonce.is_empty() {
                b = b
                    .attr(attr::USERNAME, self.user.as_bytes())
                    .attr(attr::REALM, b"akio")
                    .attr(attr::NONCE, self.nonce.as_bytes())
                    .integrity(&self.key);
            }
            self.w.send(&b.build());
            let resp = loop {
                let r = self.w.recv().expect("an answer");
                if Message::parse(&r).is_ok_and(|m| m.transaction_id() == tid) {
                    break r;
                }
            };
            let msg = Message::parse(&resp).unwrap();
            match msg.error_code() {
                Some((401, _)) if self.nonce.is_empty() => {}
                Some((438, _)) => {}
                _ => return resp,
            }
            self.nonce = msg.get_str(attr::NONCE).unwrap().to_owned();
        }
        panic!("still challenged");
    }

    /// Allocates a relayed address (UDP, or TCP with `tcp`): it, or the error code.
    fn allocate(&mut self, tcp: bool) -> Result<SocketAddr, u16> {
        let t = if tcp { 6 } else { 17 };
        let r = self.request(Method::ALLOCATE, |b| {
            b.u32(attr::REQUESTED_TRANSPORT, t << 24)
        });
        let m = Message::parse(&r).unwrap();
        match m.error_code() {
            Some((code, _)) => Err(code),
            None => Ok(m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap()),
        }
    }

    fn code(&mut self, m: Method, f: impl Fn(MessageBuilder) -> MessageBuilder) -> Option<u16> {
        let r = self.request(m, f);
        Message::parse(&r).unwrap().error_code().map(|e| e.0)
    }

    fn permit(&mut self, peer: SocketAddr) -> Option<u16> {
        self.code(Method::CREATE_PERMISSION, |b| {
            b.xor_addr(attr::XOR_PEER_ADDRESS, peer)
        })
    }

    fn send_to(&mut self, peer: SocketAddr, data: &[u8]) {
        let ind = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
            .xor_addr(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::DATA, data)
            .build();
        self.w.send(&ind);
    }

    /// The next Data indication: its peer and data.
    fn data(&mut self) -> (SocketAddr, Vec<u8>) {
        let r = self.w.recv().expect("data");
        let m = Message::parse(&r).unwrap();
        assert_eq!((m.method(), m.class()), (Method::DATA, Class::Indication));
        (
            m.get_xor_addr(attr::XOR_PEER_ADDRESS).unwrap(),
            m.get(attr::DATA).unwrap().to_vec(),
        )
    }

    fn delete(&mut self) {
        assert_eq!(
            self.code(Method::REFRESH, |b| b.u32(attr::LIFETIME, 0)),
            None
        );
    }
}

/// `n` consecutive ports free for UDP and TCP on 127.0.0.1 now.
fn free_range(n: u16) -> u16 {
    let seed = u64::from(std::process::id())
        ^ u64::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        );
    for i in 0..1000u64 {
        let base = 20000 + ((seed.wrapping_mul(2654435761).wrapping_add(i * 7919)) % 30000) as u16;
        let held: Vec<_> = (base..base + n)
            .map_while(|p| {
                let u = UdpSocket::bind(("127.0.0.1", p)).ok()?;
                let t = TcpListener::bind(("127.0.0.1", p)).ok()?;
                Some((u, t))
            })
            .collect();
        if held.len() == usize::from(n) {
            return base;
        }
    }
    panic!("no free range");
}

/// Relayed addresses take ports of the range alone, skipping one another socket holds; a
/// range used up refuses with 508 until a port is freed. TCP allocations' listeners too.
#[test]
fn relay_port_range() {
    let p = free_range(4);
    let taken = UdpSocket::bind(("127.0.0.1", p + 1)).unwrap();
    let srv = serve(config().relay_ports(p + 3, p));
    let mut clients: Vec<Client> = (0..3)
        .map(|_| Client::udp(srv.udp, ("alice", "wonderland")))
        .collect();
    let ports: Vec<u16> = clients
        .iter_mut()
        .map(|c| c.allocate(false).unwrap().port())
        .collect();
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, [p, p + 2, p + 3]);
    let mut late = Client::udp(srv.udp, ("bob", "builder"));
    assert_eq!(late.allocate(false), Err(508));
    clients[1].delete();
    let r = late.allocate(false).unwrap();
    assert_eq!(r.port(), ports[1]);
    assert!(srv.turn.holds_relay(r));
    // Relays work on a port of the range.
    let peer = sock();
    assert_eq!(late.permit(peer.local_addr().unwrap()), None);
    late.send_to(peer.local_addr().unwrap(), b"in range");
    assert_eq!(recv(&peer), (b"in range".to_vec(), r));
    drop(taken);

    // A TCP allocation's listener: the port another socket holds is skipped.
    let q = free_range(2);
    let tcp_taken = TcpListener::bind(("127.0.0.1", q)).unwrap();
    let srv = serve(config().relay_ports(q, q + 1));
    let mut c = Client::tcp(srv.tcp, ("alice", "wonderland"));
    let r = c.allocate(true).unwrap();
    assert_eq!(r.port(), q + 1);
    assert!(srv.turn.holds_relay(r));
    let mut c2 = Client::tcp(srv.tcp, ("alice", "wonderland"));
    assert_eq!(c2.allocate(true), Err(508));
    drop(tcp_taken);
}

/// `on_relay` hears each datagram both ways with the username and drops what it refuses;
/// `on_event` runs once the answer went and the shard is unlocked (it calls `stats`, which
/// locks every shard); a peer filter asking `holds_relay` lets two clients of the server relay
/// to each other while the server's other ports stay closed to the relay.
#[test]
fn hooks_on_a_running_server() {
    let me: Arc<OnceLock<TurnServer>> = Arc::default();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let calls = AtomicUsize::new(0);
    let heard: Arc<Mutex<Vec<(String, bool, usize)>>> = Arc::default();
    let (m1, m2, h1) = (me.clone(), me.clone(), heard.clone());
    let cfg = TurnConfig::new(
        "akio",
        static_auth("akio", [("alice", "wonderland"), ("bob", "builder")]),
        "127.0.0.1".parse().unwrap(),
    )
    // Loopback peers on the server's relayed ports alone (a permission asks with port 0).
    .peer_allowed(move |p| p.port() == 0 || m1.get().is_some_and(|t| t.holds_relay(p)))
    .on_relay(move |user, to_peer, n| {
        h1.lock().unwrap().push((user.to_owned(), to_peer, n));
        // The second datagram toward a peer is refused.
        !(to_peer && calls.fetch_add(1, Ordering::Relaxed) == 1)
    })
    .on_event(move |e| {
        let t = m2.get().expect("server");
        let st = t.stats(); // locks every shard: not called under one
        let _ = tx
            .lock()
            .unwrap()
            .send((e.clone(), st.allocations, t.allocations()));
    });
    let srv = serve(cfg);
    let _ = me.set(srv.turn.clone());

    let mut a = Client::udp(srv.udp, ("alice", "wonderland"));
    let mut b = Client::udp(srv.udp, ("bob", "builder"));
    let ra = a.allocate(false).unwrap();
    let (e, n, live) = rx.recv_timeout(WAIT).unwrap();
    assert_eq!(e.kind, TurnEventKind::Allocated);
    assert_eq!(
        (e.user.as_str(), e.client, e.relay),
        ("alice", a.addr(), Some(ra))
    );
    assert_eq!((n, live), (1, 1));
    let rb = b.allocate(false).unwrap();
    assert_eq!(rx.recv_timeout(WAIT).unwrap().0.relay, Some(rb));
    assert!(srv.turn.holds_relay(ra) && srv.turn.holds_relay(rb));
    assert!(!srv.turn.holds_relay(srv.udp) && !srv.turn.holds_relay(srv.tcp));

    // Each lets the other in (one IP: one permission each), and they relay to each other.
    assert_eq!(a.permit(rb), None);
    assert_eq!(b.permit(ra), None);
    a.send_to(rb, b"one");
    assert_eq!(b.data(), (ra, b"one".to_vec()));
    a.send_to(rb, b"two"); // refused by on_relay
    a.send_to(rb, b"three");
    assert_eq!(b.data(), (ra, b"three".to_vec()));
    // Toward the server's listener: refused by the peer filter, and a channel to it too.
    a.send_to(srv.udp, b"no");
    let bind = a.code(Method::CHANNEL_BIND, |x| {
        x.u32(attr::CHANNEL_NUMBER, 0x4001 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, srv.udp)
    });
    assert_eq!(bind, Some(403));
    let (e, ..) = rx.recv_timeout(WAIT).unwrap();
    assert_eq!(
        e.kind,
        TurnEventKind::Refused {
            method: Method::CHANNEL_BIND,
            code: 403
        }
    );
    let st = srv.turn.stats();
    assert_eq!((st.to_peer, st.to_peer_bytes), (2, 8));
    assert_eq!((st.to_client, st.to_client_bytes), (2, 8));
    assert_eq!(st.dropped, 2);
    assert_eq!((st.permissions, st.refused, st.pending), (2, 1, 0));
    // Bob's side: two from the peer's side, toward him. Alice's: three toward peers.
    let h = heard.lock().unwrap().clone();
    assert_eq!(h.iter().filter(|x| x.0 == "alice" && x.1).count(), 3);
    assert_eq!(h.iter().filter(|x| x.0 == "bob" && !x.1).count(), 2);

    a.delete();
    let (e, n, live) = rx.recv_timeout(WAIT).unwrap();
    assert_eq!(
        e.kind,
        TurnEventKind::Freed {
            reason: FreeReason::Deleted,
            to_peer: e_traffic(2, 8),
            to_client: e_traffic(0, 0),
        }
    );
    assert_eq!((n, live), (1, 1), "counted out before the hook runs");
    assert!(!srv.turn.holds_relay(ra));
    srv.turn.close_all();
    let (e, ..) = rx.recv_timeout(WAIT).unwrap();
    assert!(matches!(
        e.kind,
        TurnEventKind::Freed {
            reason: FreeReason::Closed,
            ..
        }
    ));
    assert_eq!(srv.turn.allocations(), 0);
}

fn e_traffic(datagrams: u64, bytes: u64) -> akio_turn::Traffic {
    let mut t = akio_turn::Traffic::default();
    t.datagrams = datagrams;
    t.bytes = bytes;
    t
}

/// Servers sharing a nonce secret take each other's nonces.
#[test]
fn nonce_secret_shared() {
    let one = serve(config().nonce_secret(b"behind one balancer"));
    let two = serve(config().nonce_secret(b"behind one balancer"));
    let other = serve(config());
    let mut c = Client::udp(one.udp, ("alice", "wonderland"));
    assert_eq!(c.code(Method::REFRESH, |x| x), Some(437)); // a nonce of one's, no allocation
    // The same 5-tuple's requests now reach two, with one's nonce: no 438.
    let s = match &c.w {
        Wire::Udp(s, _) => s.try_clone().unwrap(),
        Wire::Tcp(..) => unreachable!(),
    };
    let mut c2 = Client {
        w: Wire::Udp(s, two.udp),
        user: "alice",
        nonce: c.nonce.clone(),
        key: c.key,
    };
    let nonce = c2.nonce.clone();
    let r = c2.allocate(false);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(c2.nonce, nonce, "never challenged");
    // A server with a key of its own challenges it.
    let s = match &c.w {
        Wire::Udp(s, _) => s.try_clone().unwrap(),
        Wire::Tcp(..) => unreachable!(),
    };
    let mut c3 = Client {
        w: Wire::Udp(s, other.udp),
        user: "alice",
        nonce: nonce.clone(),
        key: c.key,
    };
    c3.allocate(false).unwrap();
    assert_ne!(c3.nonce, nonce, "challenged with a fresh one");
}

/// A TCP client whose next message claims more than `max_stream_message` is cut off; smaller
/// ones are served.
#[test]
fn stream_message_bound() {
    let srv = serve(config().max_stream_message(600));
    let mut c = Client::tcp(srv.tcp, ("alice", "wonderland"));
    c.allocate(false).unwrap();
    // A Binding request padded to 596 bytes: served.
    let ok = MessageBuilder::new(Method::BINDING, Class::Request, transaction_id())
        .attr(attr::SOFTWARE, &[b'x'; 572])
        .build();
    assert_eq!(ok.len(), 596);
    c.w.send(&ok);
    let r = c.w.recv().expect("served");
    assert_eq!(Message::parse(&r).unwrap().class(), Class::Success);
    // ChannelData claiming 600 bytes of data: the header alone ends the connection.
    c.w.send(&[0x40, 0x00, 0x02, 0x58]);
    assert_eq!(c.w.recv(), None);
}
