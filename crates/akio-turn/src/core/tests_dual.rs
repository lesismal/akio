//! Dual allocations (RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`), ECN and DSCP across the relay and
//! ICMP relaying, on the state machine.

use super::*;
use crate::fuzzing::{CLIENT, REALM, USER};
use crate::stun::{long_term_key, transaction_id};

const V4: &str = "192.0.2.1";
const V6: &str = "2001:db8::1";

/// What the UDP side of the core asks of its environment.
#[derive(Default)]
struct Env {
    /// To the client: data, ECN codepoint.
    sent: Vec<(Vec<u8>, u8)>,
    /// To peers: relay, peer, data, ECN codepoint.
    to_peer: Vec<(SocketAddr, SocketAddr, Vec<u8>, u8)>,
    /// Relays open.
    open: Vec<SocketAddr>,
    next: u16,
    /// Binding IPv6 relays fails.
    no_v6: bool,
}

impl TurnEnv for Env {
    fn send_to_client(&mut self, _: SocketAddr, data: &[u8]) {
        self.sent.push((data.to_vec(), 0));
    }
    fn send_to_client_ecn(&mut self, _: SocketAddr, data: &[u8], ecn: u8) {
        self.sent.push((data.to_vec(), ecn));
    }
    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]) {
        self.to_peer.push((relay, peer, data.to_vec(), 0));
    }
    fn send_to_peer_ecn(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8], ecn: u8) {
        self.to_peer.push((relay, peer, data.to_vec(), ecn));
    }
    fn open_relay(&mut self, _: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        if self.no_v6 && addr.is_ipv6() {
            return Err(io::Error::other("no ports"));
        }
        self.next += 1;
        let r = SocketAddr::new(addr.ip(), 50000 + self.next);
        self.open.push(r);
        Ok(r)
    }
    fn close_relay(&mut self, relay: SocketAddr) {
        self.open.retain(|r| *r != relay);
    }
}

impl Env {
    fn last(&self) -> Message<'_> {
        Message::parse(&self.sent.last().expect("sent").0).expect("stun")
    }
    fn code(&self) -> Option<u16> {
        self.last().error_code().map(|e| e.0)
    }
}

fn core_with(cfg: TurnConfig, now: Instant) -> TurnCore {
    let mut c = TurnCore::new(cfg.allow_private_peers(true));
    c.fuzz_reset(now);
    c
}

fn cfg(relay: &str) -> TurnConfig {
    TurnConfig::new(
        REALM,
        crate::static_auth(REALM, [USER]),
        relay.parse().unwrap(),
    )
}

fn dual(now: Instant) -> TurnCore {
    core_with(cfg(V4).additional_relay_ip(V6.parse().unwrap()), now)
}

fn req(m: Method) -> MessageBuilder {
    MessageBuilder::new(m, Class::Request, transaction_id())
}

fn authed(core: &TurnCore, now: Instant, b: MessageBuilder) -> Vec<u8> {
    b.attr(attr::USERNAME, USER.0.as_bytes())
        .attr(attr::REALM, REALM.as_bytes())
        .attr(attr::NONCE, core.fuzz_nonce(now, CLIENT).as_bytes())
        .integrity(&long_term_key(USER.0, REALM, USER.1))
        .fingerprint()
        .build()
}

fn udp() -> MessageBuilder {
    req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 17 << 24)
}

fn family(v6: bool) -> [u8; 4] {
    [if v6 { 2 } else { 1 }, 0, 0, 0]
}

/// Sends `b` authenticated from `CLIENT`.
fn send(core: &mut TurnCore, env: &mut Env, now: Instant, b: MessageBuilder) {
    let m = authed(core, now, b);
    core.handle_client(now, CLIENT, &m, env);
}

fn relayed(env: &Env) -> Vec<SocketAddr> {
    env.last()
        .get_xor_addrs(attr::XOR_RELAYED_ADDRESS)
        .into_iter()
        .flatten()
        .collect()
}

fn peer4() -> SocketAddr {
    "198.51.100.7:7000".parse().unwrap()
}

fn peer6() -> SocketAddr {
    "[2001:db8:1::7]:7000".parse().unwrap()
}

/// A dual allocation: two XOR-RELAYED-ADDRESS, IPv4 first; a retransmission gets both again.
#[test]
fn dual_allocation_gets_both_families() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    let m = authed(
        &core,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    core.handle_client(now, CLIENT, &m, &mut env);
    assert_eq!(env.last().class(), Class::Success);
    let r = relayed(&env);
    assert_eq!(r.len(), 2);
    assert!(r[0].is_ipv4() && r[1].is_ipv6());
    assert!(env.last().address_error_code().is_none());
    assert_eq!(core.relays_of(CLIENT), r);
    assert_eq!(core.relay_of(CLIENT), Some(r[0]));
    assert_eq!(env.open.len(), 2);
    assert_eq!(core.stats().allocations, 1);
    // The same request again (a UDP retransmission).
    core.handle_client(now, CLIENT, &m, &mut env);
    assert_eq!(relayed(&env), r);
    // Public addresses per family.
    let mut core = core_with(
        cfg(V4)
            .additional_relay_ip(V6.parse().unwrap())
            .public_ip("203.0.113.1".parse().unwrap())
            .additional_public_ip("2001:db8:ff::1".parse().unwrap()),
        now,
    );
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    let r = relayed(&env);
    assert_eq!(r[0].ip(), "203.0.113.1".parse::<IpAddr>().unwrap());
    assert_eq!(r[1].ip(), "2001:db8:ff::1".parse::<IpAddr>().unwrap());
}

/// RFC 8656 section 7.2: 400 for both family attributes, an IPv4 additional family, a token
/// with either, EVEN-PORT with R and a dual request; 440 for a family the server lacks.
#[test]
fn family_errors() {
    let now = Instant::now();
    let cases: Vec<(MessageBuilder, u16)> = vec![
        (
            udp()
                .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true))
                .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
            400,
        ),
        (
            udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(false)),
            400,
        ),
        (
            udp()
                .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true))
                .attr(attr::RESERVATION_TOKEN, &[1; 8]),
            400,
        ),
        (
            udp()
                .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true))
                .attr(attr::EVEN_PORT, &[0x80]),
            400,
        ),
        (
            udp().attr(attr::REQUESTED_ADDRESS_FAMILY, &[3, 0, 0, 0]),
            440,
        ),
    ];
    for (b, code) in cases {
        let mut core = dual(now);
        let mut env = Env::default();
        send(&mut core, &mut env, now, b);
        assert_eq!(env.code(), Some(code));
        assert!(env.open.is_empty());
        assert_eq!(core.stats().allocations, 0);
    }
    // An IPv4-only server: IPv6 asked for alone is 440; a dual request is met partially.
    let mut core = core_with(cfg(V4), now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true)),
    );
    assert_eq!(env.code(), Some(440));
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    assert_eq!(env.last().class(), Class::Success);
    assert_eq!(relayed(&env).len(), 1);
    assert_eq!(
        env.last().address_error_code(),
        Some((2, 440, "Address Family not Supported"))
    );
    // An IPv6-only server: no family named is IPv6 (as before); a dual request needs IPv4.
    let mut core = core_with(cfg(V6), now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    assert_eq!(env.code(), Some(440));
    send(&mut core, &mut env, now, udp());
    assert!(relayed(&env)[0].is_ipv6());
    // An IPv6 relay first, IPv4 additional: no family named is IPv4 (RFC 8656 section 7.2).
    let mut core = core_with(cfg(V6).additional_relay_ip(V4.parse().unwrap()), now);
    let mut env = Env::default();
    send(&mut core, &mut env, now, udp());
    assert!(relayed(&env)[0].is_ipv4());
    let mut core = core_with(cfg(V6).additional_relay_ip(V4.parse().unwrap()), now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true)),
    );
    assert!(relayed(&env)[0].is_ipv6());
}

/// No IPv6 port free: the IPv4 one with ADDRESS-ERROR-CODE 508, and the retransmission says
/// the same. No IPv4 port: 508 for the whole request.
#[test]
fn partial_dual_allocation() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env {
        no_v6: true,
        ..Env::default()
    };
    let m = authed(
        &core,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    core.handle_client(now, CLIENT, &m, &mut env);
    assert_eq!(relayed(&env).len(), 1);
    assert_eq!(
        env.last().address_error_code(),
        Some((2, 508, "Insufficient Capacity"))
    );
    core.handle_client(now, CLIENT, &m, &mut env);
    assert_eq!(env.last().address_error_code().map(|e| e.1), Some(508));
    // Data to an IPv6 peer has nowhere to go: 443 for its permission.
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer6()),
    );
    assert_eq!(env.code(), Some(443));
}

/// Permissions and channels go to the relayed address of the peer's family, both ways, and
/// each family's datagrams leave from its own relay.
#[test]
fn permissions_and_channels_per_family() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    let (r4, r6) = (env.open[0], env.open[1]);
    // One CreatePermission with both families (RFC 8656 section 10.1).
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CREATE_PERMISSION)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4())
            .xor_addr(attr::XOR_PEER_ADDRESS, peer6()),
    );
    assert_eq!(env.last().class(), Class::Success);
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4001 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer6()),
    );
    assert_eq!(env.last().class(), Class::Success);
    // Send indications, ChannelData.
    for p in [peer4(), peer6()] {
        let ind = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
            .xor_addr(attr::XOR_PEER_ADDRESS, p)
            .attr(attr::DATA, b"ind")
            .build();
        core.handle_client(now, CLIENT, &ind, &mut env);
    }
    core.handle_client(now, CLIENT, &[0x40, 0x01, 0, 2, b'c', b'd'], &mut env);
    let routes: Vec<(SocketAddr, SocketAddr)> = env.to_peer.iter().map(|t| (t.0, t.1)).collect();
    assert_eq!(routes, [(r4, peer4()), (r6, peer6()), (r6, peer6())]);
    // From the peers: each on its own relay; a peer on the other family's relay is dropped.
    let n = env.sent.len();
    core.handle_peer(now, r4, peer4(), b"x", &mut env);
    core.handle_peer(now, r6, peer6(), b"y", &mut env);
    core.handle_peer(now, r4, peer6(), b"z", &mut env);
    assert_eq!(env.sent.len(), n + 2);
    assert!(is_channel_data(&env.sent[n + 1].0));
}

/// Refresh: REQUESTED-ADDRESS-FAMILY refreshes or deletes one family; without it, all. A
/// deleted family takes its permissions and channels with it, the other keeps its own.
#[test]
fn refresh_per_family() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    let (r4, r6) = (env.open[0], env.open[1]);
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4()),
    );
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4001 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer6()),
    );
    // An unknown family value: 400.
    send(
        &mut core,
        &mut env,
        now,
        req(Method::REFRESH).attr(attr::REQUESTED_ADDRESS_FAMILY, &[9, 0, 0, 0]),
    );
    assert_eq!(env.code(), Some(400));
    // Only IPv6 is refreshed: past the default lifetime, IPv4 alone expires.
    let later = now + Duration::from_secs(500);
    send(
        &mut core,
        &mut env,
        later,
        req(Method::REFRESH)
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true))
            .u32(attr::LIFETIME, 600),
    );
    assert_eq!(env.last().get_u32(attr::LIFETIME), Some(600));
    // Channels and permissions keep their own lifetimes: refresh both channels.
    for (ch, p) in [(0x4000u32, peer4()), (0x4001, peer6())] {
        send(
            &mut core,
            &mut env,
            later,
            req(Method::CHANNEL_BIND)
                .u32(attr::CHANNEL_NUMBER, ch << 16)
                .xor_addr(attr::XOR_PEER_ADDRESS, p),
        );
    }
    let t = now + Duration::from_secs(700);
    core.handle_timeout(t, &mut env);
    assert_eq!(env.open, [r6]);
    assert_eq!(core.relays_of(CLIENT).len(), 1);
    assert_eq!(core.stats().allocations, 1);
    // The IPv6 channel still relays; the IPv4 one is gone.
    let n = env.to_peer.len();
    core.handle_client(t, CLIENT, &[0x40, 0x01, 0, 1, b'a'], &mut env);
    core.handle_client(t, CLIENT, &[0x40, 0x00, 0, 1, b'b'], &mut env);
    assert_eq!(env.to_peer.len(), n + 1);
    assert_eq!(env.to_peer[n].1, peer6());
    // IPv4 is no longer in the allocation: 443 to refresh it or to permit an IPv4 peer.
    send(
        &mut core,
        &mut env,
        t,
        req(Method::REFRESH).attr(attr::REQUESTED_ADDRESS_FAMILY, &family(false)),
    );
    assert_eq!(env.code(), Some(443));
    send(
        &mut core,
        &mut env,
        t,
        req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer4()),
    );
    assert_eq!(env.code(), Some(443));
    // Deleting the last family deletes the allocation (and gives back the quota).
    send(
        &mut core,
        &mut env,
        t,
        req(Method::REFRESH)
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true))
            .u32(attr::LIFETIME, 0),
    );
    assert_eq!(env.last().class(), Class::Success);
    assert!(env.open.is_empty());
    assert_eq!(core.stats().allocations, 0);
    assert_eq!(core.shared.allocations.load(Ordering::Relaxed), 0);
    let _ = r4;

    // Without REQUESTED-ADDRESS-FAMILY a refresh and a deletion apply to both.
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    send(
        &mut core,
        &mut env,
        later,
        req(Method::REFRESH).u32(attr::LIFETIME, 600),
    );
    core.handle_timeout(now + Duration::from_secs(700), &mut env);
    assert_eq!(env.open.len(), 2);
    send(
        &mut core,
        &mut env,
        later,
        req(Method::REFRESH)
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(false))
            .u32(attr::LIFETIME, 0),
    );
    assert_eq!(env.open.len(), 1);
    assert!(env.open[0].is_ipv6());
    send(
        &mut core,
        &mut env,
        later,
        req(Method::REFRESH).u32(attr::LIFETIME, 0),
    );
    assert!(env.open.is_empty());
    assert_eq!(core.stats().allocations, 0);
}

/// A TCP allocation knows one relayed address: a dual request gets IPv4 and 440 for IPv6.
#[test]
fn tcp_allocation_is_single_family() {
    struct Tcp(Env);
    impl TurnEnv for Tcp {
        fn send_to_client(&mut self, c: SocketAddr, d: &[u8]) {
            self.0.send_to_client(c, d);
        }
        fn send_to_peer(&mut self, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
        fn open_relay(&mut self, _: SocketAddr, _: SocketAddr) -> io::Result<SocketAddr> {
            Err(io::Error::other("udp"))
        }
        fn close_relay(&mut self, _: SocketAddr) {}
        fn pads_channel_data(&self, _: SocketAddr) -> bool {
            true
        }
        fn open_tcp_relay(&mut self, c: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
            self.0.open_relay(c, addr)
        }
    }
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Tcp(Env::default());
    let m = authed(
        &core,
        now,
        req(Method::ALLOCATE)
            .u32(attr::REQUESTED_TRANSPORT, 6 << 24)
            .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    core.handle_client(now, CLIENT, &m, &mut env);
    assert_eq!(relayed(&env.0).len(), 1);
    assert!(relayed(&env.0)[0].is_ipv4());
    assert_eq!(env.0.last().address_error_code().map(|e| e.1), Some(440));
}

/// Relayed data keeps the codepoint it arrived with, both ways; requests and responses
/// carry none.
#[test]
fn ecn_is_copied_both_ways() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    send(&mut core, &mut env, now, udp());
    let r4 = env.open[0];
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4()),
    );
    let p2: SocketAddr = "198.51.100.8:9".parse().unwrap();
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, p2),
    );
    assert!(env.sent.iter().all(|s| s.1 == 0));
    for ecn in [1, 2, 3, 0] {
        core.handle_client_ecn(now, CLIENT, &[0x40, 0, 0, 1, b'a'], ecn, &mut env);
        let ind = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
            .xor_addr(attr::XOR_PEER_ADDRESS, p2)
            .attr(attr::DATA, b"i")
            .build();
        core.handle_client_ecn(now, CLIENT, &ind, ecn, &mut env);
        let n = env.to_peer.len();
        assert_eq!(env.to_peer[n - 2].3, ecn);
        assert_eq!(env.to_peer[n - 1].3, ecn);
        core.handle_peer_ecn(now, r4, peer4(), b"cd", ecn, &mut env);
        core.handle_peer_ecn(now, r4, p2, b"di", ecn, &mut env);
        let n = env.sent.len();
        assert!(is_channel_data(&env.sent[n - 2].0));
        assert_eq!(env.sent[n - 2].1, ecn);
        assert_eq!(env.last().method(), Method::DATA);
        assert_eq!(env.sent[n - 1].1, ecn);
    }
}

/// Prebinding follows the families: one address, both for a dual request the server can
/// meet, none for a malformed one.
#[test]
fn prebind_per_family() {
    let now = Instant::now();
    let core = dual(now);
    let ips = |b: MessageBuilder| core.shared.prebind_ips(now, CLIENT, &authed(&core, now, b));
    let v4: IpAddr = V4.parse().unwrap();
    let v6: IpAddr = V6.parse().unwrap();
    assert_eq!(ips(udp()), [v4]);
    assert_eq!(
        ips(udp().attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true))),
        [v6]
    );
    assert_eq!(
        ips(udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true))),
        [v4, v6]
    );
    assert!(
        ips(udp()
            .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true))
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(false)))
        .is_empty()
    );
    let single = core_with(cfg(V4), now);
    let m = authed(
        &single,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    assert_eq!(single.shared.prebind_ips(now, CLIENT, &m), [v4]);
}

/// coturn 4.6 numbers `ADDITIONAL-ADDRESS-FAMILY` as draft-ietf-tram-turnbis did (0x8032), and
/// reads `ADDRESS-ERROR-CODE` at 0x8033: both are understood, and answered in kind.
#[test]
fn draft_codepoints() {
    let draft = attr::ADDITIONAL_ADDRESS_FAMILY_DRAFT;
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(draft, &family(true)).attr(attr::EVEN_PORT, &[0]),
    );
    assert_eq!(relayed(&env).len(), 2);
    // Both codepoints at once (the akio_turn client sends both) are one request.
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp()
            .attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true))
            .attr(draft, &family(true)),
    );
    assert_eq!(relayed(&env).len(), 2);
    // The same rules: with REQUESTED-ADDRESS-FAMILY, 400.
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp()
            .attr(draft, &family(true))
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(false)),
    );
    assert_eq!(env.code(), Some(400));
    // A partial success answers at both codepoints.
    let mut core = core_with(cfg(V4), now);
    let mut env = Env::default();
    send(&mut core, &mut env, now, udp().attr(draft, &family(true)));
    let m = env.last();
    assert!(m.has(attr::ADDRESS_ERROR_CODE));
    assert!(m.has(attr::ADDRESS_ERROR_CODE_DRAFT));
    assert_eq!(m.address_error_code().map(|e| e.1), Some(440));
    // An RFC 8656 request gets the RFC codepoint only.
    let mut core = core_with(cfg(V4), now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    assert!(!env.last().has(attr::ADDRESS_ERROR_CODE_DRAFT));
}

/// An environment that sees the whole traffic class byte (`send_to_*_tos`).
#[derive(Default)]
struct TosEnv(Env);

impl TurnEnv for TosEnv {
    fn send_to_client(&mut self, c: SocketAddr, data: &[u8]) {
        self.0.send_to_client(c, data);
    }
    fn send_to_client_tos(&mut self, _: SocketAddr, data: &[u8], tos: u8) {
        self.0.sent.push((data.to_vec(), tos));
    }
    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]) {
        self.0.send_to_peer(relay, peer, data);
    }
    fn send_to_peer_tos(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8], tos: u8) {
        self.0.to_peer.push((relay, peer, data.to_vec(), tos));
    }
    fn open_relay(&mut self, c: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.0.open_relay(c, addr)
    }
    fn close_relay(&mut self, relay: SocketAddr) {
        self.0.close_relay(relay);
    }
}

/// DSCP goes with the ECN codepoint both ways (RFC 8656 section 14), unless `copy_dscp` is
/// off; an environment that only knows ECN gets the low two bits.
#[test]
fn dscp_is_copied_unless_off() {
    for copy in [true, false] {
        let now = Instant::now();
        let mut core = core_with(
            cfg(V4)
                .additional_relay_ip(V6.parse().unwrap())
                .copy_dscp(copy),
            now,
        );
        let mut env = TosEnv::default();
        let m = authed(
            &core,
            now,
            udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
        );
        core.handle_client(now, CLIENT, &m, &mut env);
        let (r4, r6) = (env.0.open[0], env.0.open[1]);
        let b = req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4());
        let m = authed(&core, now, b);
        core.handle_client(now, CLIENT, &m, &mut env);
        let b = req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer6());
        let m = authed(&core, now, b);
        core.handle_client(now, CLIENT, &m, &mut env);
        assert!(env.0.sent.iter().all(|s| s.1 == 0), "responses unmarked");
        // EF + ECT(1), AF41 + ECT(0), CS1 + CE, CS6 not ECN-capable, unmarked.
        for tos in [0xb9u8, 0x8a, 0x23, 0xc0, 0] {
            let want = if copy { tos } else { tos & 3 };
            core.handle_client_tos(now, CLIENT, &[0x40, 0, 0, 1, b'a'], tos, &mut env);
            let ind = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
                .xor_addr(attr::XOR_PEER_ADDRESS, peer6())
                .attr(attr::DATA, b"i")
                .build();
            core.handle_client_tos(now, CLIENT, &ind, tos, &mut env);
            let n = env.0.to_peer.len();
            assert_eq!(env.0.to_peer[n - 2].0, r4);
            assert_eq!(env.0.to_peer[n - 2].3, want, "ChannelData {tos:#x}");
            assert_eq!(env.0.to_peer[n - 1].0, r6);
            assert_eq!(env.0.to_peer[n - 1].3, want, "Send {tos:#x}");
            core.handle_peer_tos(now, r4, peer4(), b"cd", tos, &mut env);
            core.handle_peer_tos(now, r6, peer6(), b"di", tos, &mut env);
            let n = env.0.sent.len();
            assert!(is_channel_data(&env.0.sent[n - 2].0));
            assert_eq!(env.0.sent[n - 2].1, want);
            assert_eq!(env.0.last().method(), Method::DATA);
            assert_eq!(env.0.sent[n - 1].1, want);
        }
        // The ECN-only entry points and environments see no DSCP.
        let mut plain = Env::default();
        core.handle_peer_tos(now, r4, peer4(), b"cd", 0xb9, &mut plain);
        assert_eq!(plain.sent.last().map(|s| s.1), Some(1));
        core.handle_client_ecn(now, CLIENT, &[0x40, 0, 0, 1, b'a'], 0xb9, &mut env);
        assert_eq!(env.0.to_peer.last().map(|t| t.3), Some(1));
    }
}

/// The ICMP Data indication of `env`'s last message to the client: peer, ICMP fields, and
/// whether it carried DATA.
fn icmp_of(env: &Env) -> (SocketAddr, (u8, u8, u32), bool) {
    let m = env.last();
    assert_eq!((m.method(), m.class()), (Method::DATA, Class::Indication));
    (
        m.get_xor_addr(attr::XOR_PEER_ADDRESS).expect("peer"),
        m.icmp().expect("ICMP"),
        m.has(attr::DATA),
    )
}

/// ICMP errors go to the client as Data indications with `ICMP` and without `DATA` (RFC 8656
/// section 11.5): destination unreachable and time exceeded only, the MTU for "fragmentation
/// needed" and "packet too big", a permission for the peer's address (any port) and a live
/// relayed address of its family needed.
#[test]
fn icmp_is_relayed() {
    let now = Instant::now();
    let mut core = dual(now);
    let mut env = Env::default();
    send(
        &mut core,
        &mut env,
        now,
        udp().attr(attr::ADDITIONAL_ADDRESS_FAMILY, &family(true)),
    );
    let (r4, r6) = (env.open[0], env.open[1]);
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CREATE_PERMISSION)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4())
            .xor_addr(attr::XOR_PEER_ADDRESS, peer6()),
    );
    // A channel does not matter: ICMP always comes as a Data indication.
    send(
        &mut core,
        &mut env,
        now,
        req(Method::CHANNEL_BIND)
            .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer4()),
    );
    let relayed = [
        // Port unreachable; fragmentation needed with its MTU; time exceeded.
        (r4, peer4(), 3, 3, 9, (3, 3, 0)),
        (r4, peer4(), 3, 4, 1400, (3, 4, 1400)),
        (r4, peer4(), 11, 0, 0, (11, 0, 0)),
        // ICMPv6: unreachable (no MTU), packet too big, time exceeded.
        (r6, peer6(), 1, 4, 1280, (1, 4, 0)),
        (r6, peer6(), 2, 0, 1280, (2, 0, 1280)),
        (r6, peer6(), 3, 1, 0, (3, 1, 0)),
    ];
    for (i, (relay, peer, ty, code, mtu, want)) in relayed.into_iter().enumerate() {
        core.handle_icmp(now, relay, peer, ty, code, mtu, &mut env);
        assert_eq!(icmp_of(&env), (peer, want, false), "case {i}");
        assert_eq!(core.stats().icmp, i as u64 + 1);
    }
    // Port 0: the platform did not tell the destination port.
    let p0 = SocketAddr::new(peer4().ip(), 0);
    core.handle_icmp(now, r4, p0, 3, 1, 0, &mut env);
    assert_eq!(icmp_of(&env), (p0, (3, 1, 0), false));
    let n = env.sent.len();
    let other: SocketAddr = "198.51.100.99:7000".parse().unwrap();
    let dropped = [
        // ICMPv4 parameter problem, echo reply; ICMPv6 parameter problem, echo reply.
        (r4, peer4(), 12, 0),
        (r4, peer4(), 0, 0),
        (r6, peer6(), 4, 0),
        (r6, peer6(), 129, 0),
        // No permission; the other family's relay; no such relay.
        (r4, other, 3, 3),
        (r4, peer6(), 1, 4),
        ("192.0.2.1:1".parse().unwrap(), peer4(), 3, 3),
    ];
    for (relay, peer, ty, code) in dropped {
        core.handle_icmp(now, relay, peer, ty, code, 0, &mut env);
    }
    assert_eq!(env.sent.len(), n);
    // Off: nothing relayed.
    let mut off = core_with(
        cfg(V4)
            .additional_relay_ip(V6.parse().unwrap())
            .relay_icmp(false),
        now,
    );
    let mut env2 = Env::default();
    send(&mut off, &mut env2, now, udp());
    let r = env2.open[0];
    send(
        &mut off,
        &mut env2,
        now,
        req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer4()),
    );
    let n = env2.sent.len();
    off.handle_icmp(now, r, peer4(), 3, 3, 0, &mut env2);
    assert_eq!(env2.sent.len(), n);
    // A family deleted alone takes its ICMP with it.
    send(
        &mut core,
        &mut env,
        now,
        req(Method::REFRESH)
            .u32(attr::LIFETIME, 0)
            .attr(attr::REQUESTED_ADDRESS_FAMILY, &family(true)),
    );
    let n = env.sent.len();
    core.handle_icmp(now, r6, peer6(), 1, 4, 0, &mut env);
    assert_eq!(env.sent.len(), n);
    core.handle_icmp(now, r4, peer4(), 3, 3, 0, &mut env);
    assert_eq!(env.sent.len(), n + 1);
}
