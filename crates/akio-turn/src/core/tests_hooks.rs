//! The hooks of an embedding server (`on_relay`, `on_event`, `holds_relay`), the limits and
//! credentials changed in place, the drain and the shared nonce key, on the state machine.

use super::*;
use crate::fuzzing::{CLIENT, REALM, USER};
use crate::stun::{long_term_key, transaction_id};

const PEER: &str = "10.1.1.1:7000";

#[derive(Default)]
struct Env {
    sent: Vec<Vec<u8>>,
    to_peer: Vec<Vec<u8>>,
    next: u16,
}

impl TurnEnv for Env {
    fn send_to_client(&mut self, _: SocketAddr, data: &[u8]) {
        self.sent.push(data.to_vec());
    }
    fn send_to_peer(&mut self, _: SocketAddr, _: SocketAddr, data: &[u8]) {
        self.to_peer.push(data.to_vec());
    }
    fn open_relay(&mut self, _: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.next += 1;
        Ok(SocketAddr::new(addr.ip(), 50000 + self.next))
    }
    fn close_relay(&mut self, _: SocketAddr) {}
}

impl Env {
    fn last(&self) -> Message<'_> {
        Message::parse(self.sent.last().expect("sent")).expect("stun")
    }
    fn code(&self) -> Option<u16> {
        self.last().error_code().map(|e| e.0)
    }
}

type Seen = Arc<Mutex<Vec<TurnEvent>>>;
type Relayed = Arc<Mutex<Vec<(String, bool, usize)>>>;

/// A core whose events go to the returned list, whose `on_relay` refuses while `refuse`, and
/// whose peer filter refuses multicast peers alone.
fn core(now: Instant, refuse: Arc<AtomicBool>) -> (TurnCore, Seen, Relayed) {
    let seen: Seen = Arc::default();
    let relayed: Relayed = Arc::default();
    let (s, r) = (seen.clone(), relayed.clone());
    let cfg = TurnConfig::new(
        REALM,
        crate::static_auth(REALM, [USER, ("v", "w")]),
        "192.0.2.1".parse().unwrap(),
    )
    .public_ip("203.0.113.9".parse().unwrap())
    .peer_allowed(|p| !p.ip().is_multicast())
    .on_event(move |e| lock(&s).push(e.clone()))
    .on_relay(move |user, to_peer, n| {
        lock(&r).push((user.to_owned(), to_peer, n));
        !refuse.load(Ordering::Relaxed)
    });
    let mut c = TurnCore::new(cfg);
    c.fuzz_reset(now);
    (c, seen, relayed)
}

fn req(m: Method) -> MessageBuilder {
    MessageBuilder::new(m, Class::Request, transaction_id())
}

fn authed_as(
    core: &TurnCore,
    now: Instant,
    from: SocketAddr,
    (user, pass): (&str, &str),
    b: MessageBuilder,
) -> Vec<u8> {
    b.attr(attr::USERNAME, user.as_bytes())
        .attr(attr::REALM, REALM.as_bytes())
        .attr(attr::NONCE, core.fuzz_nonce(now, from).as_bytes())
        .integrity(&long_term_key(user, REALM, pass))
        .build()
}

fn authed(core: &TurnCore, now: Instant, from: SocketAddr, b: MessageBuilder) -> Vec<u8> {
    authed_as(core, now, from, USER, b)
}

fn allocate(core: &TurnCore, now: Instant, from: SocketAddr) -> Vec<u8> {
    authed(
        core,
        now,
        from,
        req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 17 << 24),
    )
}

fn kinds(seen: &Seen) -> Vec<TurnEventKind> {
    std::mem::take(&mut *lock(seen))
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

/// Events are kept until `flush_events`, then told with the username, client and relayed
/// address; `on_relay` sees each datagram both ways and drops what it refuses; freed
/// allocations tell what they relayed and why they went.
#[test]
fn events_and_relay_hook() {
    let now = Instant::now();
    let refuse = Arc::new(AtomicBool::new(false));
    let (mut core, seen, relayed) = core(now, refuse.clone());
    let mut env = Env::default();
    // Without credentials, and with a stale nonce: challenges, not failures.
    core.handle_client(now, CLIENT, &req(Method::ALLOCATE).build(), &mut env);
    assert_eq!(env.code(), Some(401));
    let stale = req(Method::ALLOCATE)
        .u32(attr::REQUESTED_TRANSPORT, 17 << 24)
        .attr(attr::USERNAME, USER.0.as_bytes())
        .attr(attr::REALM, REALM.as_bytes())
        .attr(attr::NONCE, "0".repeat(32).as_bytes())
        .integrity(&long_term_key(USER.0, REALM, USER.1))
        .build();
    core.handle_client(now, CLIENT, &stale, &mut env);
    assert_eq!(env.code(), Some(438));
    // A wrong password: a failure, under the name it claimed.
    let wrong = authed_as(
        &core,
        now,
        CLIENT,
        (USER.0, "nope"),
        req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 17 << 24),
    );
    core.handle_client(now, CLIENT, &wrong, &mut env);
    assert_eq!(env.code(), Some(401));
    core.flush_events();
    let e = lock(&seen).pop().expect("auth failed");
    assert_eq!(
        e.kind,
        TurnEventKind::AuthFailed {
            method: Method::ALLOCATE,
            code: 401
        }
    );
    assert_eq!((e.user.as_str(), e.client, e.relay), (USER.0, CLIENT, None));
    assert!(lock(&seen).is_empty());

    core.handle_client(now, CLIENT, &allocate(&core, now, CLIENT), &mut env);
    assert_eq!(env.last().class(), Class::Success);
    assert!(lock(&seen).is_empty(), "kept until flushed");
    core.flush_events();
    let e = lock(&seen).pop().expect("allocated");
    let relay: SocketAddr = "203.0.113.9:50001".parse().unwrap();
    assert_eq!(e.kind, TurnEventKind::Allocated);
    assert_eq!(e.relay, Some(relay), "as clients are told of it");
    assert_eq!(e.lifetime, Duration::from_secs(600));
    assert!(core.holds_relay(relay) && core.holds_relay("192.0.2.1:50001".parse().unwrap()));
    assert!(!core.holds_relay("203.0.113.9:50002".parse().unwrap()));

    // A peer the policy refuses: 403, refused.
    let peer: SocketAddr = PEER.parse().unwrap();
    let bad: SocketAddr = "224.0.0.1:1".parse().unwrap();
    let cp = |core: &TurnCore, p: SocketAddr| {
        authed(
            core,
            now,
            CLIENT,
            req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, p),
        )
    };
    core.handle_client(now, CLIENT, &cp(&core, bad), &mut env);
    assert_eq!(env.code(), Some(403));
    core.handle_client(now, CLIENT, &cp(&core, peer), &mut env);
    assert_eq!(env.last().class(), Class::Success);
    core.flush_events();
    assert_eq!(
        kinds(&seen),
        [TurnEventKind::Refused {
            method: Method::CREATE_PERMISSION,
            code: 403
        }]
    );
    assert_eq!(core.stats().refused, 1);
    assert_eq!(core.stats().permissions, 1);

    // Datagrams both ways go through on_relay with the username and the payload's length.
    let send = MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
        .xor_addr(attr::XOR_PEER_ADDRESS, peer)
        .attr(attr::DATA, b"12345")
        .build();
    core.handle_client(now, CLIENT, &send, &mut env);
    let bound: SocketAddr = "192.0.2.1:50001".parse().unwrap();
    core.handle_peer(now, bound, peer, b"abc", &mut env);
    assert_eq!(env.to_peer, [b"12345".to_vec()]);
    assert_eq!(
        *lock(&relayed),
        [(USER.0.to_owned(), true, 5), (USER.0.to_owned(), false, 3)]
    );
    // Refused: dropped, and counted so.
    refuse.store(true, Ordering::Relaxed);
    core.handle_client(now, CLIENT, &send, &mut env);
    let n = env.sent.len();
    core.handle_peer(now, bound, peer, b"abc", &mut env);
    assert_eq!((env.to_peer.len(), env.sent.len()), (1, n));
    refuse.store(false, Ordering::Relaxed);
    // Not relayed for want of a permission: dropped before the hook hears of it.
    let calls = lock(&relayed).len();
    core.handle_peer(now, bound, "10.9.9.9:1".parse().unwrap(), b"x", &mut env);
    core.handle_client(now, CLIENT, b"\xff\xff", &mut env);
    assert_eq!(lock(&relayed).len(), calls);
    let st = core.stats();
    assert_eq!((st.to_peer, st.to_peer_bytes), (1, 5));
    assert_eq!((st.to_client, st.to_client_bytes), (1, 3));
    assert_eq!(st.dropped, 4);

    // Refresh, then delete: refreshed, freed (deleted) with what it relayed.
    let r = authed(
        &core,
        now,
        CLIENT,
        req(Method::REFRESH).u32(attr::LIFETIME, 1200),
    );
    core.handle_client(now, CLIENT, &r, &mut env);
    let r0 = authed(
        &core,
        now,
        CLIENT,
        req(Method::REFRESH).u32(attr::LIFETIME, 0),
    );
    core.handle_client(now, CLIENT, &r0, &mut env);
    core.flush_events();
    let evs = std::mem::take(&mut *lock(&seen));
    assert_eq!(evs[0].kind, TurnEventKind::Refreshed);
    assert_eq!(evs[0].lifetime, Duration::from_secs(1200));
    assert_eq!(
        evs[1].kind,
        TurnEventKind::Freed {
            reason: FreeReason::Deleted,
            to_peer: Traffic {
                datagrams: 1,
                bytes: 5
            },
            to_client: Traffic {
                datagrams: 1,
                bytes: 3
            },
        }
    );
    assert_eq!(evs[1].relay, Some(relay));
    assert!(!core.holds_relay(relay));

    // Expired by the sweep; closed with the server.
    core.handle_client(now, CLIENT, &allocate(&core, now, CLIENT), &mut env);
    let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    core.handle_client(now, other, &allocate(&core, now, other), &mut env);
    core.handle_timeout(now + Duration::from_secs(601), &mut env);
    let again = now + Duration::from_secs(601);
    core.handle_client(again, other, &allocate(&core, again, other), &mut env);
    core.close_all(&mut env);
    core.flush_events();
    let freed: Vec<FreeReason> = kinds(&seen)
        .into_iter()
        .filter_map(|k| match k {
            TurnEventKind::Freed { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        freed,
        [FreeReason::Expired, FreeReason::Expired, FreeReason::Closed]
    );
}

/// Quotas, caps and lifetimes change in place: the next request goes by them, what is held is
/// kept.
#[test]
fn limits_change_in_place() {
    let now = Instant::now();
    let (mut core, _, _) = core(now, Arc::default());
    let mut env = Env::default();
    let mut l = core.limits();
    assert_eq!(l, core.config().limits());
    l.max_allocations_per_user = 1;
    l.default_lifetime = Duration::from_secs(900);
    l.max_lifetime = Duration::from_secs(60); // taken as the default lifetime
    core.set_limits(l);
    assert_eq!(core.limits().max_lifetime, Duration::from_secs(900));
    core.handle_client(now, CLIENT, &allocate(&core, now, CLIENT), &mut env);
    assert_eq!(env.last().get_u32(attr::LIFETIME), Some(900));
    let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    core.handle_client(now, other, &allocate(&core, now, other), &mut env);
    assert_eq!(env.code(), Some(486));
    l.max_allocations_per_user = 2;
    core.set_limits(l);
    core.handle_client(now, other, &allocate(&core, now, other), &mut env);
    assert_eq!(env.last().class(), Class::Success);
    // Lowered caps keep what is held and refuse more.
    let cp = |core: &TurnCore, p: &str| {
        authed(
            core,
            now,
            CLIENT,
            req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, p.parse().unwrap()),
        )
    };
    core.handle_client(now, CLIENT, &cp(&core, "10.1.1.1:1"), &mut env);
    core.handle_client(now, CLIENT, &cp(&core, "10.1.1.2:1"), &mut env);
    l.max_permissions = 1;
    l.permission_lifetime = Duration::from_secs(30);
    core.set_limits(l);
    core.handle_client(now, CLIENT, &cp(&core, "10.1.1.3:1"), &mut env);
    assert_eq!(env.code(), Some(508));
    assert_eq!(core.stats().permissions, 2);
    // Over the cap even one held is not refreshed: what is held runs out.
    core.handle_client(now, CLIENT, &cp(&core, "10.1.1.1:1"), &mut env);
    assert_eq!(env.code(), Some(508), "two held, one allowed");
    core.handle_timeout(now + Duration::from_secs(301), &mut env);
    let later = now + Duration::from_secs(301);
    let cp_later = authed(
        &core,
        later,
        CLIENT,
        req(Method::CREATE_PERMISSION)
            .xor_addr(attr::XOR_PEER_ADDRESS, "10.1.1.3:1".parse().unwrap()),
    );
    core.handle_client(later, CLIENT, &cp_later, &mut env);
    assert_eq!(env.last().class(), Class::Success);
    core.handle_timeout(later + Duration::from_secs(31), &mut env);
    assert_eq!(core.stats().permissions, 0, "the new permission lifetime");
    // The nonce lifetime.
    l.nonce_lifetime = Duration::from_secs(5);
    core.set_limits(l);
    let n = core.fuzz_nonce(now, CLIENT);
    assert!(
        core.shared
            .nonce_valid(now + Duration::from_secs(5), CLIENT, &n)
    );
    assert!(
        !core
            .shared
            .nonce_valid(now + Duration::from_secs(6), CLIENT, &n)
    );
}

/// A draining core refuses new allocations (508, and no relay bound ahead of the lock) and
/// serves those it holds, a retransmission of their Allocate included.
#[test]
fn drain() {
    let now = Instant::now();
    let (mut core, seen, _) = core(now, Arc::default());
    let mut env = Env::default();
    let first = allocate(&core, now, CLIENT);
    core.handle_client(now, CLIENT, &first, &mut env);
    assert!(!core.draining());
    core.drain();
    assert!(core.draining());
    let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    let a = allocate(&core, now, other);
    assert!(core.shared.prebind_ips(now, other, &a).is_empty());
    core.handle_client(now, other, &a, &mut env);
    assert_eq!(env.code(), Some(508));
    core.handle_client(now, CLIENT, &first, &mut env);
    assert_eq!(env.last().class(), Class::Success, "a retransmission");
    let r = authed(&core, now, CLIENT, req(Method::REFRESH));
    core.handle_client(now, CLIENT, &r, &mut env);
    assert_eq!(env.last().class(), Class::Success);
    let cp = authed(
        &core,
        now,
        CLIENT,
        req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, PEER.parse().unwrap()),
    );
    core.handle_client(now, CLIENT, &cp, &mut env);
    assert_eq!(env.last().class(), Class::Success);
    core.flush_events();
    let k = kinds(&seen);
    assert!(k.contains(&TurnEventKind::Refused {
        method: Method::ALLOCATE,
        code: 508
    }));
    assert_eq!(core.shared.allocations(), 1);
}

/// New credentials apply from the next request on, those of allocations held included.
#[test]
fn auth_changes_in_place() {
    let now = Instant::now();
    let (mut core, _, _) = core(now, Arc::default());
    let mut env = Env::default();
    core.handle_client(now, CLIENT, &allocate(&core, now, CLIENT), &mut env);
    core.set_auth(crate::static_auth(REALM, [(USER.0, "new")]));
    let r = authed(&core, now, CLIENT, req(Method::REFRESH));
    core.handle_client(now, CLIENT, &r, &mut env);
    assert_eq!(env.code(), Some(401));
    let r = authed_as(&core, now, CLIENT, (USER.0, "new"), req(Method::REFRESH));
    core.handle_client(now, CLIENT, &r, &mut env);
    assert_eq!(env.last().class(), Class::Success);
    // And for the Allocates bound ahead of the lock.
    let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    assert!(
        core.shared
            .prebind_ips(now, other, &allocate(&core, now, other))
            .is_empty()
    );
}

/// Servers sharing a nonce secret take each other's nonces, whenever each started; others
/// do not.
#[test]
fn shared_nonce_secret() {
    let cfg = |secret: Option<&[u8]>| {
        let c = TurnConfig::new(
            REALM,
            crate::static_auth(REALM, [USER]),
            "192.0.2.1".parse().unwrap(),
        );
        match secret {
            Some(s) => c.nonce_secret(s),
            None => c,
        }
    };
    let a = Shared::new(cfg(Some(b"s3cret")));
    let now = Instant::now();
    let n = a.nonce(now, CLIENT);
    let b = Shared::new(cfg(Some(b"s3cret")));
    let later = Instant::now();
    assert!(b.nonce_valid(later, CLIENT, &n));
    assert!(!b.nonce_valid(later, "10.0.0.9:1".parse().unwrap(), &n));
    assert!(!Shared::new(cfg(Some(b"other"))).nonce_valid(later, CLIENT, &n));
    assert!(!Shared::new(cfg(None)).nonce_valid(later, CLIENT, &n));
    // Expiries are UNIX seconds.
    let exp = u64::from_str_radix(&n[..16], 16).unwrap();
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(exp.abs_diff(unix + 600) <= 2, "{exp} {unix}");
    assert!(!format!("{:?}", cfg(Some(b"s3cret"))).contains("s3cret"));
}
