//! The client against the server state machine, over simulated links.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::*;
use crate::core::{TurnConfig, TurnCore, TurnEnv};
use crate::framing::FrameReader;
use crate::static_auth;

const CLIENT: &str = "198.51.100.7:40000";
const SERVER: &str = "192.0.2.1:3478";
const PEER: &str = "203.0.113.9:7000";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[derive(Default)]
struct Env {
    to_client: Vec<Vec<u8>>,
    to_peer: Vec<(SocketAddr, Vec<u8>)>,
    relays: u16,
    pad: bool,
    /// TCP allocations: connections asked for (peer, id), connections bound.
    dials: Vec<(SocketAddr, u32)>,
    bound: Vec<u32>,
}

impl TurnEnv for Env {
    fn send_to_client(&mut self, _client: SocketAddr, data: &[u8]) {
        self.to_client.push(data.to_vec());
    }
    fn send_to_peer(&mut self, _relay: SocketAddr, peer: SocketAddr, data: &[u8]) {
        self.to_peer.push((peer, data.to_vec()));
    }
    fn open_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.relays += 1;
        Ok(SocketAddr::new(addr.ip(), 50000 + self.relays))
    }
    fn close_relay(&mut self, _relay: SocketAddr) {}
    fn pads_channel_data(&self, _client: SocketAddr) -> bool {
        self.pad
    }
    fn open_tcp_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.relays += 1;
        Ok(SocketAddr::new(addr.ip(), 50000 + self.relays))
    }
    fn connect_peer(&mut self, _client: SocketAddr, _relay: SocketAddr, peer: SocketAddr, id: u32) {
        self.dials.push((peer, id));
    }
    fn connection_bound(&mut self, _data_client: SocketAddr, id: u32) {
        self.bound.push(id);
    }
}

struct Net {
    core: TurnCore,
    env: Env,
    client: Client,
    now: Instant,
    /// Drops every n-th message in each direction (0: none).
    drop_every: usize,
    sent: usize,
    reader: FrameReader,
    got: Vec<(SocketAddr, Vec<u8>)>,
}

impl Net {
    fn new(cfg: TurnConfig, ccfg: ClientConfig) -> Net {
        let now = Instant::now();
        let stream = ccfg.stream;
        Net {
            core: TurnCore::new(cfg),
            env: Env {
                pad: stream,
                ..Env::default()
            },
            client: Client::new(ccfg, now),
            now,
            drop_every: 0,
            sent: 0,
            reader: FrameReader::new(),
            got: Vec::new(),
        }
    }

    fn lost(&mut self) -> bool {
        self.sent += 1;
        self.drop_every != 0 && self.sent % self.drop_every == 0
    }

    /// Moves messages both ways until nothing is left.
    fn pump(&mut self) {
        for _ in 0..100 {
            let mut moved = false;
            while let Some(m) = self.client.poll_transmit() {
                moved = true;
                if self.lost() {
                    continue;
                }
                if self.client.config().stream {
                    // Whole messages are framed on the stream: the server reads them back.
                    let mut msgs = Vec::new();
                    let mut r = FrameReader::new();
                    r.push(&m, |x| msgs.push(x.to_vec())).unwrap();
                    assert_eq!(msgs.len(), 1, "a stream message must be framed");
                }
                self.core
                    .handle_client(self.now, a(CLIENT), &m, &mut self.env);
            }
            for m in std::mem::take(&mut self.env.to_client) {
                moved = true;
                if self.lost() {
                    continue;
                }
                let stream = self.client.config().stream;
                let mut frames = Vec::new();
                if stream {
                    self.reader.push(&m, |x| frames.push(x.to_vec())).unwrap();
                } else {
                    frames.push(m);
                }
                for f in frames {
                    if let Some((p, d)) = self.client.handle_input(self.now, &f) {
                        self.got.push((p, d.to_vec()));
                    }
                }
            }
            if !moved {
                return;
            }
        }
        panic!("no quiescence");
    }

    fn advance(&mut self, d: Duration) {
        let end = self.now + d;
        loop {
            let next = self.client.poll_timeout().filter(|t| *t <= end);
            match next {
                Some(t) => {
                    self.now = t.max(self.now);
                    self.client.handle_timeout(self.now);
                    self.core.handle_timeout(self.now, &mut self.env);
                    self.pump();
                }
                None => break,
            }
        }
        self.now = end;
        self.client.handle_timeout(self.now);
        self.core.handle_timeout(self.now, &mut self.env);
        self.pump();
    }

    fn events(&mut self) -> Vec<ClientEvent> {
        std::iter::from_fn(|| self.client.poll_event()).collect()
    }
}

fn server_cfg() -> TurnConfig {
    TurnConfig::new(
        "realm",
        static_auth("realm", [("alice", "pw")]),
        "192.0.2.1".parse().unwrap(),
    )
}

fn client_cfg() -> ClientConfig {
    ClientConfig::new(a(SERVER), "alice", "pw")
}

fn allocated(n: &mut Net) -> SocketAddr {
    n.pump();
    let ev = n.events();
    let Some(ClientEvent::Allocated {
        relayed,
        mapped,
        lifetime,
    }) = ev.first().cloned()
    else {
        panic!("{ev:?}");
    };
    assert_eq!(mapped, Some(a(CLIENT)));
    assert_eq!(lifetime, Duration::from_secs(600));
    assert_eq!(n.client.state(), ClientState::Allocated);
    assert_eq!(n.client.relayed_addr(), Some(relayed));
    assert_eq!(n.core.relay_of(a(CLIENT)), Some(relayed));
    relayed
}

fn exchange(n: &mut Net, relayed: SocketAddr) {
    assert!(n.client.send_to(n.now, a(PEER), b"one"));
    assert!(n.client.send_to(n.now, a(PEER), b"two"));
    n.pump();
    let to_peer: Vec<Vec<u8>> = n.env.to_peer.drain(..).map(|x| x.1).collect();
    assert_eq!(to_peer, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(n.client.pending_bytes(), 0);
    n.core
        .handle_peer(n.now, a("192.0.2.1:50001"), a(PEER), b"back", &mut n.env);
    let _ = relayed;
    n.pump();
    assert_eq!(
        std::mem::take(&mut n.got),
        vec![(a(PEER), b"back".to_vec())]
    );
}

#[test]
fn allocate_channel_and_data() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    let mut n = Net::new(cfg, client_cfg());
    let relayed = allocated(&mut n);
    exchange(&mut n, relayed);
    // Data goes as ChannelData once the channel is bound.
    assert!(n.client.send_to(n.now, a(PEER), b"three"));
    let m = n.client.poll_transmit().unwrap();
    assert!(is_channel_data(&m));
    assert_eq!(m.len(), 4 + 5); // not padded over UDP
}

#[test]
fn stream_framing_and_padding() {
    let mut n = Net::new(server_cfg(), client_cfg().stream(true));
    let relayed = allocated(&mut n);
    exchange(&mut n, relayed);
    assert!(n.client.send_to(n.now, a(PEER), b"three"));
    let m = n.client.poll_transmit().unwrap();
    assert_eq!(m.len(), 12); // padded on a stream
    // Over a stream nothing is retransmitted.
    n.client.close(n.now);
    let _ = n.client.poll_transmit().unwrap();
    n.client.handle_timeout(n.now + Duration::from_secs(5));
    assert!(n.client.poll_transmit().is_none());
    n.client.handle_timeout(n.now + Duration::from_secs(40));
    assert_eq!(n.events(), vec![ClientEvent::Closed]);
}

#[test]
fn permissions_and_send_indications() {
    let mut n = Net::new(server_cfg(), client_cfg().use_channels(false));
    let relayed = allocated(&mut n);
    exchange(&mut n, relayed);
    assert!(n.client.send_to(n.now, a(PEER), b"x"));
    let m = n.client.poll_transmit().unwrap();
    assert!(is_stun(&m));
}

#[test]
fn wrong_password_fails() {
    let mut n = Net::new(server_cfg(), ClientConfig::new(a(SERVER), "alice", "nope"));
    n.pump();
    assert_eq!(
        n.events(),
        vec![ClientEvent::Failed(ClientError::Rejected(
            401,
            "Unauthorized".into()
        ))]
    );
    assert_eq!(n.client.state(), ClientState::Failed);
    assert!(!n.client.send_to(n.now, a(PEER), b"x"));
}

#[test]
fn timeout_without_server() {
    let now = Instant::now();
    let mut c = Client::new(client_cfg(), now);
    let mut sends = 0;
    let mut t = now;
    while let Some(next) = c.poll_timeout() {
        while c.poll_transmit().is_some() {
            sends += 1;
        }
        t = next;
        c.handle_timeout(t);
        if c.state() == ClientState::Failed {
            break;
        }
    }
    assert_eq!(sends, 7);
    assert_eq!(t - now, Duration::from_millis(39_500));
    assert_eq!(
        std::iter::from_fn(|| c.poll_event()).collect::<Vec<_>>(),
        vec![ClientEvent::Failed(ClientError::Timeout)]
    );
}

#[test]
fn refresh_keeps_allocation_and_bindings() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    let mut n = Net::new(cfg, client_cfg());
    let relayed = allocated(&mut n);
    exchange(&mut n, relayed);
    // Keep the peer in use for 30 minutes: past the allocation's 10, the channel's 10 and the
    // permission's 5.
    for _ in 0..30 {
        n.advance(Duration::from_secs(60));
        assert!(n.client.send_to(n.now, a(PEER), b"tick"));
        n.pump();
        assert_eq!(n.env.to_peer.drain(..).count(), 1, "at {:?}", n.now);
    }
    assert_eq!(n.core.relay_of(a(CLIENT)), Some(relayed));
    assert!(n.events().is_empty());
    // An idle peer is forgotten; the allocation stays.
    n.advance(Duration::from_secs(900));
    assert_eq!(n.core.relay_of(a(CLIENT)), Some(relayed));
}

#[test]
fn close_deletes_allocation() {
    let mut n = Net::new(server_cfg(), client_cfg());
    allocated(&mut n);
    n.client.close(n.now);
    assert_eq!(n.client.state(), ClientState::Closing);
    n.pump();
    assert_eq!(n.events(), vec![ClientEvent::Closed]);
    assert_eq!(n.core.relay_of(a(CLIENT)), None);
    assert_eq!(n.client.poll_timeout(), None);
}

#[test]
fn refused_peer() {
    // The default policy refuses private peers: the channel fails, then the permission.
    let mut n = Net::new(server_cfg(), client_cfg());
    allocated(&mut n);
    let private = a("10.0.0.1:9");
    assert!(n.client.send_to(n.now, private, b"x"));
    n.pump();
    assert_eq!(
        n.events(),
        vec![ClientEvent::PeerFailed(
            private,
            ClientError::Rejected(403, "Forbidden".into())
        )]
    );
    assert_eq!(n.client.pending_bytes(), 0);
    assert!(!n.client.send_to(n.now, private, b"x")); // for a while
    n.advance(Duration::from_secs(31));
    assert!(n.client.send_to(n.now, private, b"x"));
}

#[test]
fn stale_nonce_is_renewed() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    cfg.nonce_lifetime = Duration::from_secs(30);
    let mut n = Net::new(cfg, client_cfg());
    let relayed = allocated(&mut n);
    n.advance(Duration::from_secs(120));
    exchange(&mut n, relayed);
    assert!(n.events().is_empty());
}

#[test]
fn bounds() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    let mut cc = client_cfg();
    cc.max_peers = 2;
    cc.max_pending = 100;
    let mut n = Net::new(cfg, cc);
    allocated(&mut n);
    assert!(n.client.send_to(n.now, a("203.0.113.1:1"), &[0; 60]));
    assert!(!n.client.send_to(n.now, a("203.0.113.1:1"), &[0; 60])); // pending bytes
    assert!(n.client.send_to(n.now, a("203.0.113.2:1"), &[0; 10]));
    assert!(!n.client.send_to(n.now, a("203.0.113.3:1"), &[0; 10])); // peers
    for _ in 0..20 {
        let _ = n.client.send_to(n.now, a("203.0.113.2:1"), &[0; 1]);
    }
    assert!(n.client.pending_bytes() <= 100);
    n.pump();
    assert_eq!(n.client.pending_bytes(), 0);
    assert!(!n.client.send_to(n.now, a(PEER), &vec![0; 70_000]));
}

/// A link losing every third message each way: retransmissions get everything through.
#[test]
fn lossy_link() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    let mut n = Net::new(cfg, client_cfg());
    n.drop_every = 3;
    n.pump();
    n.advance(Duration::from_secs(10));
    assert!(matches!(
        n.events().first(),
        Some(ClientEvent::Allocated { .. })
    ));
    // Relayed data itself is not retransmitted: some of it is lost.
    for _ in 0..6 {
        assert!(n.client.send_to(n.now, a(PEER), b"x"));
        n.pump();
        n.advance(Duration::from_secs(2));
    }
    assert_eq!(n.client.pending_bytes(), 0);
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    assert!(n.env.to_peer.iter().any(|(p, d)| p.ip() == ip && d == b"x"));
}

/// Binds connection `id` from a new client connection at `data` against the core; the
/// response is delivered one byte at a time, followed by the peer's first bytes.
fn bind(n: &mut Net, data: SocketAddr, id: u32) -> DataConnection {
    let mut d = n.client.data_connection(n.now, id).unwrap();
    assert_eq!(d.id(), id);
    for _ in 0..4 {
        let Some(m) = d.poll_transmit() else { break };
        n.core.handle_client(n.now, data, &m, &mut n.env);
        let mut out = std::mem::take(&mut n.env.to_client).concat();
        out.extend_from_slice(b"PEER");
        let mut i = 0;
        while i < out.len() && *d.state() == DataState::Binding {
            i += d.handle_input(&out[i..=i]);
        }
        if *d.state() == DataState::Bound {
            assert_eq!(&out[i..], b"PEER");
        }
    }
    d
}

#[test]
fn tcp_allocation_connect_and_attempts() {
    let mut n = Net::new(
        server_cfg().allow_private_peers(true),
        client_cfg().tcp_allocation(true),
    );
    assert!(n.client.config().stream);
    let relayed = allocated(&mut n);
    // No UDP data on a TCP allocation.
    assert!(!n.client.send_to(n.now, a(PEER), b"x"));
    // Connect: the event follows the server's answer.
    assert!(n.client.connect(n.now, a(PEER)));
    assert!(
        !n.client.connect(n.now, a(PEER)),
        "one Connect per peer at a time"
    );
    n.pump();
    let (peer, id) = n.env.dials[0];
    assert_eq!(peer, a(PEER));
    assert!(n.events().is_empty());
    assert!(n.core.tcp_connected(n.now, a(CLIENT), id, true, &mut n.env));
    n.pump();
    assert_eq!(n.events(), vec![ClientEvent::Connected { peer, id }]);
    let d = bind(&mut n, a("198.51.100.7:40001"), id);
    assert_eq!(*d.state(), DataState::Bound);
    assert_eq!(d.poll_timeout(), None);
    assert_eq!(n.env.bound, vec![id]);
    // A failed one.
    let other = a("203.0.113.10:80");
    assert!(n.client.connect(n.now, other));
    n.pump();
    let id2 = n.env.dials[1].1;
    assert!(
        !n.core
            .tcp_connected(n.now, a(CLIENT), id2, false, &mut n.env)
    );
    n.pump();
    assert!(matches!(
        n.events()[..],
        [ClientEvent::ConnectFailed(p, ClientError::Rejected(447, _))] if p == other
    ));
    // A peer connecting: needs the permission, which stays installed while unused.
    let p3 = a("203.0.113.11:5000");
    assert_eq!(
        n.core
            .tcp_incoming(n.now, relayed_local(relayed), p3, &mut n.env),
        None
    );
    assert!(n.client.create_permission(n.now, p3));
    n.pump();
    n.advance(Duration::from_secs(900));
    assert_eq!(n.client.state(), ClientState::Allocated);
    let id3 = n
        .core
        .tcp_incoming(n.now, relayed_local(relayed), p3, &mut n.env)
        .unwrap();
    n.pump();
    assert_eq!(
        n.events(),
        vec![ClientEvent::ConnectionAttempt { peer: p3, id: id3 }]
    );
    // A binding the server refuses (bound already): failed, not retried.
    let d = bind(&mut n, a("198.51.100.7:40002"), id);
    assert!(matches!(
        d.state(),
        DataState::Failed(ClientError::Rejected(400, _))
    ));
    // A stale nonce is renewed once (the data connection's own).
    n.advance(Duration::from_secs(10));
    let p4 = a("203.0.113.11:5001");
    let id4 = n
        .core
        .tcp_incoming(n.now, relayed_local(relayed), p4, &mut n.env)
        .unwrap();
    n.now += Duration::from_secs(700); // past the nonce lifetime, not the bind deadline...
    let mut d = n.client.data_connection(n.now, id4).unwrap();
    let m = d.poll_transmit().unwrap();
    n.core
        .handle_client(n.now, a("198.51.100.7:40003"), &m, &mut n.env);
    let out = std::mem::take(&mut n.env.to_client).concat();
    assert_eq!(d.handle_input(&out), out.len());
    assert_eq!(
        *d.state(),
        DataState::Binding,
        "retrying with the new nonce"
    );
    assert!(d.poll_transmit().is_some());
    // Garbage instead of STUN fails it; so does the deadline.
    let mut d = n.client.data_connection(n.now, id4).unwrap();
    assert!(d.handle_input(b"\x80junk") > 0);
    assert!(matches!(
        d.state(),
        DataState::Failed(ClientError::Protocol(_))
    ));
    let mut d = n.client.data_connection(n.now, id4).unwrap();
    let t = d.poll_timeout().unwrap();
    d.handle_timeout(t);
    assert_eq!(*d.state(), DataState::Failed(ClientError::Timeout));
}

/// The relay's own address: the core keys TCP relays by the listener's bound address, which
/// the test environment makes equal to the relayed one.
fn relayed_local(relayed: SocketAddr) -> SocketAddr {
    relayed
}

#[test]
fn udp_clients_cannot_connect() {
    let mut n = Net::new(server_cfg(), client_cfg());
    allocated(&mut n);
    assert!(!n.client.connect(n.now, a(PEER)));
    assert!(n.client.data_connection(n.now, 1).is_some());
}

/// A dual allocation (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`): both relayed addresses, peers of
/// both families, refreshes keeping both for half an hour, and the close deleting both.
#[test]
fn dual_allocation_both_families() {
    let cfg = server_cfg()
        .additional_relay_ip("2001:db8::1".parse().unwrap())
        .allow_private_peers(true);
    let mut n = Net::new(cfg, client_cfg().dual_allocation(true));
    let relayed = allocated(&mut n);
    let all = n.client.relayed_addrs().to_vec();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], relayed);
    assert!(all[0].is_ipv4() && all[1].is_ipv6());
    assert_eq!(n.core.relays_of(a(CLIENT)), all);
    assert_eq!(n.client.address_error(), None);
    let peer6 = a("[2001:db8:9::9]:7000");
    assert_eq!(n.client.relayed_addr_for(peer6), Some(all[1]));
    assert_eq!(n.client.relayed_addr_for(a(PEER)), Some(all[0]));
    for _ in 0..30 {
        n.advance(Duration::from_secs(60));
        assert!(n.client.send_to(n.now, a(PEER), b"four"));
        assert!(n.client.send_to(n.now, peer6, b"six"));
        n.pump();
        let peers: Vec<SocketAddr> = n.env.to_peer.drain(..).map(|x| x.0).collect();
        assert_eq!(peers, [a(PEER), peer6], "at {:?}", n.now);
    }
    assert_eq!(n.core.relays_of(a(CLIENT)), all);
    // The IPv6 peer's datagrams come back through the IPv6 relay.
    let r6 = SocketAddr::new(all[1].ip(), all[1].port());
    n.core.handle_peer(n.now, r6, peer6, b"back6", &mut n.env);
    n.pump();
    assert_eq!(std::mem::take(&mut n.got), vec![(peer6, b"back6".to_vec())]);
    assert!(n.events().is_empty());
    n.client.close(n.now);
    n.pump();
    assert_eq!(n.events(), vec![ClientEvent::Closed]);
    assert!(n.core.relays_of(a(CLIENT)).is_empty());
}

/// A server that relays IPv4 only meets a dual request partially: the client keeps one relayed
/// address and the reason for the other.
#[test]
fn dual_allocation_partial() {
    let mut cfg = server_cfg();
    cfg.allow_private_peers = true;
    let mut n = Net::new(cfg, client_cfg().dual_allocation(true));
    allocated(&mut n);
    assert_eq!(n.client.relayed_addrs().len(), 1);
    assert_eq!(
        n.client.address_error(),
        Some((2, 440, "Address Family not Supported"))
    );
    // An IPv6 peer is refused by the server (443).
    let peer6 = a("[2001:db8:9::9]:7000");
    assert!(n.client.send_to(n.now, peer6, b"x"));
    n.pump();
    assert!(matches!(
        n.events().as_slice(),
        [ClientEvent::PeerFailed(p, ClientError::Rejected(443, _))] if *p == peer6
    ));
}
