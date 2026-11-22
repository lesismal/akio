//! TURN and STUN servers over real `akio` sockets, driven by a small client written with the
//! codec.
#![allow(missing_docs)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use akio::{Engine, Listener};
use akio_turn::stun::{
    Class, Message, MessageBuilder, Method, attr, binding_request, long_term_key,
    parse_binding_response, transaction_id,
};
use akio_turn::{StunServer, TurnConfig, TurnServer, static_auth};

fn sock() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn recv(s: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut b = vec![0u8; 2048];
    let (n, from) = s.recv_from(&mut b).unwrap();
    b.truncate(n);
    (b, from)
}

fn server() -> (Arc<Engine>, TurnServer, SocketAddr) {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
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
    let addr = engine.local_addrs()[0];
    (engine, turn, addr)
}

struct Client {
    s: UdpSocket,
    server: SocketAddr,
    nonce: String,
    key: [u8; 16],
}

impl Client {
    fn new(server: SocketAddr, password: &str) -> Client {
        Client {
            s: sock(),
            server,
            nonce: String::new(),
            key: long_term_key("alice", "akio", password),
        }
    }

    /// Sends a request, retrying once after a 401/438 challenge; returns the response bytes.
    fn request(&mut self, m: Method, f: impl Fn(MessageBuilder) -> MessageBuilder) -> Vec<u8> {
        for _ in 0..2 {
            let tid = transaction_id();
            let mut b = f(MessageBuilder::new(m, Class::Request, tid));
            if !self.nonce.is_empty() {
                b = b
                    .attr(attr::USERNAME, b"alice")
                    .attr(attr::REALM, b"akio")
                    .attr(attr::NONCE, self.nonce.as_bytes())
                    .integrity(&self.key);
            }
            self.s
                .send_to(&b.fingerprint().build(), self.server)
                .unwrap();
            let (resp, _) = recv(&self.s);
            let msg = Message::parse(&resp).unwrap();
            assert_eq!(msg.transaction_id(), tid);
            assert!(msg.check_fingerprint());
            match msg.error_code() {
                Some((401 | 438, _))
                    if self.nonce.is_empty() || msg.error_code().unwrap().0 == 438 =>
                {
                    self.nonce = msg.get_str(attr::NONCE).unwrap().to_owned();
                    assert_eq!(msg.get_str(attr::REALM), Some("akio"));
                }
                _ => return resp,
            }
        }
        panic!("still challenged");
    }
}

#[test]
fn allocate_permission_send_data_channel_refresh() {
    let (engine, turn, addr) = server();
    let mut c = Client::new(addr, "wonderland");
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
    });
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.class(), Class::Success, "{:?}", m.error_code());
    assert!(m.check_integrity(&c.key));
    let relay = m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap();
    assert_eq!(
        m.get_xor_addr(attr::XOR_MAPPED_ADDRESS),
        Some(c.s.local_addr().unwrap())
    );
    assert_eq!(m.get_u32(attr::LIFETIME), Some(600));
    assert_eq!(turn.stats().allocations, 1);
    assert_eq!(turn.relay_of(c.s.local_addr().unwrap()), Some(relay));

    // A second Allocate on the same 5-tuple is a mismatch.
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 437);

    // Without a permission the peer's datagrams are dropped.
    let peer = sock();
    peer.send_to(b"too early", relay).unwrap();
    // Let the relay socket's thread see (and drop) it before the permission exists: one
    // that arrives after CreatePermission is relayed, as RFC 8656 says.
    std::thread::sleep(Duration::from_millis(100));

    let pa = peer.local_addr().unwrap();
    let resp = c.request(Method::CREATE_PERMISSION, |b| {
        b.xor_addr(attr::XOR_PEER_ADDRESS, pa)
    });
    assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);

    // Send indication -> peer.
    let ind = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
        .xor_addr(attr::XOR_PEER_ADDRESS, pa)
        .attr(attr::DATA, b"hello peer")
        .build();
    c.s.send_to(&ind, addr).unwrap();
    let (got, from) = recv(&peer);
    assert_eq!(got, b"hello peer");
    assert_eq!(from, relay);

    // Peer -> Data indication.
    peer.send_to(b"hello client", relay).unwrap();
    let (got, _) = recv(&c.s);
    let m = Message::parse(&got).unwrap();
    assert_eq!((m.method(), m.class()), (Method::DATA, Class::Indication));
    assert_eq!(m.get(attr::DATA), Some(&b"hello client"[..]));
    assert_eq!(m.get_xor_addr(attr::XOR_PEER_ADDRESS), Some(pa));

    // ChannelBind, then ChannelData both ways.
    let resp = c.request(Method::CHANNEL_BIND, |b| {
        b.u32(attr::CHANNEL_NUMBER, 0x4001 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, pa)
    });
    assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);
    c.s.send_to(&[0x40, 0x01, 0, 4, b'p', b'i', b'n', b'g'], addr)
        .unwrap();
    assert_eq!(recv(&peer).0, b"ping");
    peer.send_to(b"pong", relay).unwrap();
    assert_eq!(recv(&c.s).0, [0x40, 0x01, 0, 4, b'p', b'o', b'n', b'g']);

    // A channel number out of range is refused.
    let resp = c.request(Method::CHANNEL_BIND, |b| {
        b.u32(attr::CHANNEL_NUMBER, 0x3fff << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, pa)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 400);

    // Refresh with lifetime 0 deletes the allocation and closes the relay.
    let resp = c.request(Method::REFRESH, |b| b.u32(attr::LIFETIME, 0));
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.class(), Class::Success);
    assert_eq!(turn.stats().allocations, 0);
    assert!(turn.stats().to_peer >= 2 && turn.stats().to_client >= 2);
    engine.shutdown();
    engine.wait();
}

#[test]
fn even_port_with_reservation_token() {
    let (engine, turn, addr) = server();
    let mut rtp = Client::new(addr, "wonderland");
    let resp = rtp.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
            .attr(attr::EVEN_PORT, &[0x80])
    });
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.class(), Class::Success, "{:?}", m.error_code());
    let relay = m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap();
    assert_eq!(relay.port() % 2, 0);
    let token = m.get(attr::RESERVATION_TOKEN).unwrap().to_vec();
    assert_eq!(token.len(), 8);

    // Another client claims the reserved odd port with the token.
    let mut rtcp = Client::new(addr, "wonderland");
    let resp = rtcp.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
            .attr(attr::RESERVATION_TOKEN, &token)
    });
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.class(), Class::Success, "{:?}", m.error_code());
    assert_eq!(
        m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap().port(),
        relay.port() + 1
    );
    // The token is spent.
    let mut third = Client::new(addr, "wonderland");
    let resp = third.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
            .attr(attr::RESERVATION_TOKEN, &token)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 508);
    assert_eq!(turn.stats().allocations, 2);
    engine.shutdown();
    engine.wait();
}

#[test]
fn wrong_password_and_unsupported_transport() {
    let (engine, turn, addr) = server();
    let mut c = Client::new(addr, "wrong");
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
    });
    let m = Message::parse(&resp).unwrap();
    assert_eq!(m.error_code().unwrap().0, 401);
    assert!(turn.stats().auth_failures >= 2);

    let mut c = Client::new(addr, "wonderland");
    // TCP allocations are for TCP and TLS clients only (RFC 6062 section 5.1).
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 6 << 24)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 400);
    // Neither UDP nor TCP (SCTP).
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 132 << 24)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 442);
    let resp = c.request(Method::REFRESH, |b| b);
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 437);
    engine.shutdown();
    engine.wait();
}

#[test]
fn default_policy_refuses_loopback_peers() {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let turn = TurnServer::new(TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()));
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(turn.clone()))
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let mut c = Client::new(engine.local_addrs()[0], "wonderland");
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
    });
    assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);
    let resp = c.request(Method::CREATE_PERMISSION, |b| {
        b.xor_addr(attr::XOR_PEER_ADDRESS, "127.0.0.1:9".parse().unwrap())
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 403);
    engine.shutdown();
    engine.wait();
}

#[test]
fn stun_binding_on_both_servers() {
    let stun = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(StunServer::new().software("t")),
        )
        .build()
        .unwrap();
    stun.start().unwrap();
    let (engine, _turn, turn_addr) = server();
    for server in [stun.local_addrs()[0], turn_addr] {
        let s = sock();
        let tid = transaction_id();
        s.send_to(&binding_request(tid), server).unwrap();
        let (resp, _) = recv(&s);
        assert_eq!(
            parse_binding_response(&resp, &tid),
            Some(s.local_addr().unwrap())
        );
    }
    stun.shutdown();
    stun.wait();
    engine.shutdown();
    engine.wait();
}

fn server_with(cfg: TurnConfig, threads: usize) -> (Arc<Engine>, TurnServer, SocketAddr) {
    let turn = TurnServer::new(cfg);
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(threads)
                    .serve(turn.clone()),
            )
            .build()
            .unwrap(),
    );
    turn.set_engine(&engine);
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    (engine, turn, addr)
}

fn allocate(c: &mut Client) -> Result<SocketAddr, u16> {
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
    });
    let m = Message::parse(&resp).unwrap();
    match m.error_code() {
        Some((code, _)) => Err(code),
        None => Ok(m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap()),
    }
}

/// The allocation quotas hold for the whole server although allocations live in shards (one per
/// client address hash): at, then over, the per-user and the total limit; freeing one makes room.
#[test]
fn quotas_span_shards() {
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let mut cfg =
        TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    cfg.max_allocations_per_user = 5;
    let (engine, turn, addr) = server_with(cfg, 1);
    // 12 clients spread over the shards: 5 succeed, the rest hit the per-user quota.
    let mut clients: Vec<Client> = (0..12).map(|_| Client::new(addr, "wonderland")).collect();
    let mut ok = Vec::new();
    for (i, c) in clients.iter_mut().enumerate() {
        match allocate(c) {
            Ok(_) => ok.push(i),
            Err(code) => assert_eq!(code, 486),
        }
    }
    assert_eq!(ok.len(), 5);
    assert_eq!(turn.stats().allocations, 5);
    // Freeing one (Refresh with lifetime 0) gives its slot back.
    let freed = ok[0];
    let resp = clients[freed].request(Method::REFRESH, |b| b.u32(attr::LIFETIME, 0));
    assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);
    assert_eq!(turn.stats().allocations, 4);
    let next = (0..12).find(|i| !ok.contains(i)).unwrap();
    assert!(allocate(&mut clients[next]).is_ok());
    assert_eq!(turn.stats().allocations, 5);
    engine.shutdown();
    engine.wait();

    // The total: two users, 3 allocations in all.
    let auth = static_auth("akio", [("alice", "wonderland")]);
    let mut cfg =
        TurnConfig::new("akio", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
    cfg.max_allocations = 3;
    let (engine, turn, addr) = server_with(cfg, 1);
    let codes: Vec<Result<SocketAddr, u16>> = (0..8)
        .map(|_| allocate(&mut Client::new(addr, "wonderland")))
        .collect();
    assert_eq!(codes.iter().filter(|r| r.is_ok()).count(), 3);
    assert!(codes.iter().all(|r| r.is_ok() || *r == Err(508)));
    assert_eq!(turn.stats().allocations, 3);
    turn.close_all();
    assert_eq!(turn.stats().allocations, 0);
    assert!(allocate(&mut Client::new(addr, "wonderland")).is_ok());
    engine.shutdown();
    engine.wait();
}

/// A token set aside by one client is claimed by another, whatever shard each lands in: the
/// claimed relay's peer data reaches the claiming client.
#[test]
fn reservation_claimed_across_shards() {
    let (engine, turn, addr) = server_with(
        TurnConfig::new(
            "akio",
            static_auth("akio", [("alice", "wonderland")]),
            "127.0.0.1".parse().unwrap(),
        )
        .allow_private_peers(true),
        1,
    );
    for _ in 0..6 {
        let mut rtp = Client::new(addr, "wonderland");
        let resp = rtp.request(Method::ALLOCATE, |b| {
            b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
                .attr(attr::EVEN_PORT, &[0x80])
        });
        let m = Message::parse(&resp).unwrap();
        if m.error_code().is_some() {
            continue; // no even/odd port pair free right now
        }
        let token = m.get(attr::RESERVATION_TOKEN).unwrap().to_vec();
        let mut rtcp = Client::new(addr, "wonderland");
        let resp = rtcp.request(Method::ALLOCATE, |b| {
            b.u32(attr::REQUESTED_TRANSPORT, 17 << 24)
                .attr(attr::RESERVATION_TOKEN, &token)
        });
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.class(), Class::Success, "{:?}", m.error_code());
        let relay = m.get_xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap();
        let peer = sock();
        let pa = peer.local_addr().unwrap();
        let resp = rtcp.request(Method::CREATE_PERMISSION, |b| {
            b.xor_addr(attr::XOR_PEER_ADDRESS, pa)
        });
        assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);
        peer.send_to(b"to rtcp", relay).unwrap();
        let (d, _) = recv(&rtcp.s);
        let m = Message::parse(&d).unwrap();
        assert_eq!(m.method(), Method::DATA);
        assert_eq!(m.get(attr::DATA), Some(&b"to rtcp"[..]));
        assert_eq!(m.get_xor_addr(attr::XOR_PEER_ADDRESS), Some(pa));
    }
    assert!(turn.stats().allocations >= 2);
    engine.shutdown();
    engine.wait();
}

/// Many allocations relaying at once from several listener threads (each in some shard) keep
/// their traffic apart.
#[test]
fn concurrent_relays() {
    let (engine, turn, addr) = server_with(
        TurnConfig::new(
            "akio",
            static_auth("akio", [("alice", "wonderland")]),
            "127.0.0.1".parse().unwrap(),
        )
        .allow_private_peers(true),
        2,
    );
    let mut setups = Vec::new();
    for i in 0..8u16 {
        let mut c = Client::new(addr, "wonderland");
        let relay = allocate(&mut c).unwrap();
        let peer = sock();
        let pa = peer.local_addr().unwrap();
        let ch = 0x4000 + i;
        let resp = c.request(Method::CHANNEL_BIND, |b| {
            b.attr(attr::CHANNEL_NUMBER, &[(ch >> 8) as u8, ch as u8, 0, 0])
                .xor_addr(attr::XOR_PEER_ADDRESS, pa)
        });
        assert_eq!(Message::parse(&resp).unwrap().class(), Class::Success);
        setups.push((c, peer, relay, ch, i));
    }
    let threads: Vec<_> = setups
        .into_iter()
        .map(|(c, peer, relay, ch, i)| {
            std::thread::spawn(move || {
                for k in 0..20u8 {
                    let payload = [i as u8, k];
                    let mut d = ch.to_be_bytes().to_vec();
                    d.extend_from_slice(&2u16.to_be_bytes());
                    d.extend_from_slice(&payload);
                    c.s.send_to(&d, c.server).unwrap();
                    let (got, from) = recv(&peer);
                    assert_eq!((got.as_slice(), from), (&payload[..], relay));
                    peer.send_to(&[k, i as u8], relay).unwrap();
                    let (back, _) = recv(&c.s);
                    assert_eq!(&back[..2], &ch.to_be_bytes());
                    assert_eq!(&back[4..6], &[k, i as u8]);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let st = turn.stats();
    assert_eq!((st.allocations, st.to_peer, st.to_client), (8, 160, 160));
    engine.shutdown();
    engine.wait();
}
