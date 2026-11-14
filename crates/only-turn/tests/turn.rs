//! TURN and STUN servers over real `only` sockets, driven by a small client written with the
//! codec.
#![allow(missing_docs)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use only::{Engine, Listener};
use only_turn::stun::{
    Class, Message, MessageBuilder, Method, attr, binding_request, long_term_key,
    parse_binding_response, transaction_id,
};
use only_turn::{StunServer, TurnConfig, TurnServer, static_auth};

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
    let auth = static_auth("only", [("alice", "wonderland")]);
    let cfg = TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap()).allow_private_peers(true);
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
            key: long_term_key("alice", "only", password),
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
                    .attr(attr::REALM, b"only")
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
                    assert_eq!(msg.get_str(attr::REALM), Some("only"));
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
    let resp = c.request(Method::ALLOCATE, |b| {
        b.u32(attr::REQUESTED_TRANSPORT, 6 << 24)
    });
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 442);
    let resp = c.request(Method::REFRESH, |b| b);
    assert_eq!(Message::parse(&resp).unwrap().error_code().unwrap().0, 437);
    engine.shutdown();
    engine.wait();
}

#[test]
fn default_policy_refuses_loopback_peers() {
    let auth = static_auth("only", [("alice", "wonderland")]);
    let turn = TurnServer::new(TurnConfig::new("only", auth, "127.0.0.1".parse().unwrap()));
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
