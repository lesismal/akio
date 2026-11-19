//! DTLS 1.3 after and before the main handshake (ADR-045): connection ID management
//! (RFC 9147 §9 NewConnectionId / RequestConnectionId), post-handshake client authentication
//! (RFC 8446 §4.6.2) and early data (0-RTT) with anti-replay, over the simulated link.

use std::sync::Arc;
use std::time::Duration;

use only_dtls::{
    AlertDescription, AntiReplayStore, Config, Connection, Error, Event, Identity,
    MemoryAntiReplay, PeerVerifier, Session, TicketKey, Version,
};

mod common;

use common::*;

fn cfg13(id: &Identity) -> Config {
    Config::new(id.clone()).with_versions(vec![Version::Dtls13])
}

fn handshake(cc: Config, sc: Config, seed: u64, link: Link) -> (Connection, Connection, Sim) {
    let mut sim = Sim::new(seed, link);
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(30), connected);
    assert!(
        connected(&c, &s),
        "{:?} {:?}",
        sim.client_errors,
        sim.server_errors
    );
    (c, s, sim)
}

/// Runs until neither side has a timer left (all flights acknowledged).
fn settle(c: &mut Connection, s: &mut Connection, sim: &mut Sim) {
    sim.run(c, s, Duration::from_secs(60), |c, s| {
        c.poll_timeout().is_none() && s.poll_timeout().is_none()
    });
}

fn lossy() -> Link {
    Link {
        loss: 20,
        dup: 10,
        jitter: 200,
    }
}

fn cid_sets(evs: &[Event]) -> Vec<Vec<Vec<u8>>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::LocalConnectionIds(v) => Some(v.clone()),
            _ => None,
        })
        .collect()
}

/// Sends one record each way and checks it arrives; returns the server's received datagram
/// and its events.
fn exchange_events(
    c: &mut Connection,
    s: &mut Connection,
    sim: &Sim,
    tag: &[u8],
) -> (Vec<u8>, Vec<Event>) {
    c.send_application_data(tag).unwrap();
    let d = c.poll_transmit().unwrap();
    s.handle_datagram(sim.now, &d).unwrap();
    let evs = events(s);
    assert!(
        evs.iter()
            .any(|e| matches!(e, Event::ApplicationData(x) if x == tag))
    );
    s.send_application_data(tag).unwrap();
    let back = s.poll_transmit().unwrap();
    c.handle_datagram(sim.now, &back).unwrap();
    assert!(
        events(c)
            .iter()
            .any(|e| matches!(e, Event::ApplicationData(x) if x == tag))
    );
    (d, evs)
}

fn exchange(c: &mut Connection, s: &mut Connection, sim: &Sim, tag: &[u8]) -> Vec<u8> {
    exchange_events(c, s, sim, tag).0
}

#[test]
fn new_connection_ids_and_rotation() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    for (seed, link) in [(1, PERFECT), (2, lossy()), (3, lossy())] {
        let cc = cfg13(&ci).with_connection_id(Some(4));
        let sc = cfg13(&si).with_connection_id(Some(6));
        let (mut c, mut s, mut sim) = handshake(cc, sc, seed, link);
        settle(&mut c, &mut s, &mut sim);
        events(&mut c);
        events(&mut s);
        let first = s.local_connection_id().unwrap().to_vec();
        assert_eq!(s.local_connection_ids(), std::slice::from_ref(&first));
        assert_eq!(c.peer_connection_id(), Some(&first[..]));
        // The server issues two spares: it accepts three now.
        s.new_connection_ids(2, false).unwrap();
        let sets = cid_sets(&events(&mut s));
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].len(), 3);
        assert_eq!(sets[0][0], first);
        assert!(sets[0].iter().all(|x| x.len() == 6));
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(c.spare_connection_ids(), 2, "seed {seed}");
        // Still the first CID until the client rotates.
        sim.link = PERFECT;
        let d = exchange(&mut c, &mut s, &sim, b"before");
        assert_eq!(only_dtls::connection_id(&d, 6), Some(&first[..]));
        assert!(c.rotate_connection_id().unwrap());
        assert_eq!(c.peer_connection_id(), Some(&sets[0][1][..]));
        let (d, evs) = exchange_events(&mut c, &mut s, &sim, b"after");
        assert_eq!(only_dtls::connection_id(&d, 6), Some(&sets[0][1][..]));
        // The peer moved past the first CID: retired.
        let retired = cid_sets(&evs);
        assert_eq!(retired, vec![sets[0][1..].to_vec()]);
        assert_eq!(s.local_connection_ids(), &sets[0][1..]);
        // A record with the retired CID is no longer routed to this connection.
        let mut stale = d;
        stale[1..7].copy_from_slice(&first);
        s.handle_datagram(sim.now, &stale).unwrap();
        assert!(events(&mut s).is_empty());
        assert!(c.poll_transmit().is_none());
        // Immediate: the client switches without being asked.
        s.new_connection_ids(1, true).unwrap();
        let now_set = cid_sets(&events(&mut s)).pop().unwrap();
        let newest = now_set.last().unwrap().clone();
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(c.peer_connection_id(), Some(&newest[..]));
        assert_eq!(
            c.spare_connection_ids(),
            0,
            "spares dropped on cid_immediate"
        );
        let d = exchange(&mut c, &mut s, &sim, b"immediate");
        assert_eq!(only_dtls::connection_id(&d, 6), Some(&newest[..]));
        assert_eq!(s.local_connection_ids(), [newest]);
        check_connected(&mut c, &mut s, &mut sim);
    }
}

#[test]
fn request_connection_ids() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    for (seed, link) in [(4, PERFECT), (5, lossy())] {
        let cc = cfg13(&ci).with_connection_id(Some(5));
        let sc = cfg13(&si).with_connection_id(Some(3));
        let (mut c, mut s, mut sim) = handshake(cc, sc, seed, link);
        settle(&mut c, &mut s, &mut sim);
        // Both directions: the client asks the server, the server asks the client.
        c.request_connection_ids(3).unwrap();
        assert!(matches!(
            c.request_connection_ids(1),
            Err(Error::NotAvailable(_))
        ));
        s.request_connection_ids(2).unwrap();
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(c.spare_connection_ids(), 3, "seed {seed}");
        assert_eq!(s.spare_connection_ids(), 2);
        assert_eq!(s.local_connection_ids().len(), 4);
        assert_eq!(c.local_connection_ids().len(), 3);
        assert_eq!(cid_sets(&events(&mut s)).last().unwrap().len(), 4);
        // Answered: another request is allowed; the server stops at 8 CIDs.
        c.request_connection_ids(200).unwrap();
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(s.local_connection_ids().len(), 8);
        assert_eq!(c.spare_connection_ids(), 7);
        c.request_connection_ids(1).unwrap();
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(c.spare_connection_ids(), 7, "none left to give");
        assert!(matches!(
            s.new_connection_ids(1, false),
            Err(Error::NotAvailable(_))
        ));
        // Rotate through every spare; each record reaches the server.
        sim.link = PERFECT;
        let mut seen = Vec::new();
        while c.rotate_connection_id().unwrap() {
            let d = exchange(&mut c, &mut s, &sim, b"r");
            seen.push(only_dtls::connection_id(&d, 3).unwrap().to_vec());
        }
        assert_eq!(seen.len(), 7);
        assert_eq!(s.local_connection_ids(), [seen.last().unwrap().clone()]);
        // Room again: new spares.
        c.request_connection_ids(2).unwrap();
        settle(&mut c, &mut s, &mut sim);
        assert_eq!(c.spare_connection_ids(), 2);
        check_connected(&mut c, &mut s, &mut sim);
    }
}

#[test]
fn connection_id_management_errors() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    // No CIDs; zero-length CID on the client (it receives none, sends the server's).
    let (mut c, mut s, _) = handshake(cfg13(&ci), cfg13(&si), 6, PERFECT);
    assert!(matches!(
        c.new_connection_ids(1, false),
        Err(Error::NotAvailable(_))
    ));
    assert!(matches!(
        c.request_connection_ids(1),
        Err(Error::NotAvailable(_))
    ));
    assert!(!c.rotate_connection_id().unwrap());
    assert!(c.local_connection_ids().is_empty() && c.peer_connection_id().is_none());
    assert!(matches!(
        s.new_connection_ids(0, false),
        Err(Error::NotAvailable(_))
    ));
    let (mut c, mut s, _) = handshake(
        cfg13(&ci).with_connection_id(Some(0)),
        cfg13(&si).with_connection_id(Some(4)),
        7,
        PERFECT,
    );
    assert!(matches!(
        c.new_connection_ids(1, false),
        Err(Error::NotAvailable(_))
    ));
    assert!(matches!(
        s.request_connection_ids(1),
        Err(Error::NotAvailable(_))
    ));
    c.request_connection_ids(1).unwrap();
    s.new_connection_ids(1, false).unwrap();
    // DTLS 1.2: RFC 9146 has no CID updates.
    let v12 = |id: &Identity| Config::new(id.clone()).with_connection_id(Some(4));
    let (mut c, s, _) = handshake(v12(&ci), v12(&si), 8, PERFECT);
    assert_eq!(c.local_connection_ids().len(), 1);
    assert_eq!(c.peer_connection_id(), s.local_connection_id());
    assert!(matches!(
        c.new_connection_ids(1, false),
        Err(Error::NotAvailable(_))
    ));
    assert!(matches!(
        c.request_connection_ids(1),
        Err(Error::NotAvailable(_))
    ));
    assert!(matches!(
        c.rotate_connection_id(),
        Err(Error::NotAvailable(_))
    ));
    // Before the handshake completes.
    let sim = Sim::new(9, PERFECT);
    let (mut c, _) = pair(
        cfg13(&ci).with_connection_id(Some(4)),
        cfg13(&si).with_connection_id(Some(4)),
        &sim,
    );
    assert!(matches!(
        c.new_connection_ids(1, false),
        Err(Error::NotConnected)
    ));
}

fn client_certs(evs: &[Event]) -> Vec<Vec<Vec<u8>>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::ClientCertificate(v) => Some(v.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn post_handshake_client_authentication() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let rsa = rsa_identity();
    for (seed, link, client_id) in [
        (10, PERFECT, ci.clone()),
        (11, lossy(), ci),
        (12, lossy(), rsa),
    ] {
        let cc = cfg13(&client_id)
            .with_post_handshake_auth(true)
            .with_verifier(PeerVerifier::Fingerprints(vec![si.fingerprint()]));
        let sc = cfg13(&si)
            .with_require_client_certificate(false)
            .with_verifier(PeerVerifier::Fingerprints(vec![client_id.fingerprint()]));
        let (mut c, mut s, mut sim) = handshake(cc, sc, seed, link);
        assert!(s.handshake_info().unwrap().peer_certificates.is_empty());
        settle(&mut c, &mut s, &mut sim);
        events(&mut s);
        // Twice, with a KeyUpdate of each side in between (the Finished key follows it).
        for round in 0..2 {
            s.request_client_certificate().unwrap();
            assert!(matches!(
                s.request_client_certificate(),
                Err(Error::NotAvailable(_))
            ));
            settle(&mut c, &mut s, &mut sim);
            let got = client_certs(&events(&mut s));
            assert_eq!(
                got.len(),
                1,
                "seed {seed} round {round} {:?}",
                sim.server_errors
            );
            assert_eq!(got[0], client_id.chain());
            let info = s.handshake_info().unwrap();
            assert_eq!(info.peer_fingerprint, Some(client_id.fingerprint()));
            assert_eq!(info.peer_certificates, client_id.chain());
            c.update_keys(true).unwrap();
            settle(&mut c, &mut s, &mut sim);
        }
        assert!(sim.server_errors.is_empty() && sim.client_errors.is_empty());
        check_connected(&mut c, &mut s, &mut sim);
    }
}

#[test]
fn post_handshake_authentication_declined_refused_and_unavailable() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let sc = cfg13(&si).with_require_client_certificate(false);
    // A client without a certificate declines: an empty chain.
    let cc = Config::without_identity()
        .with_versions(vec![Version::Dtls13])
        .with_post_handshake_auth(true);
    let (mut c, mut s, mut sim) = handshake(cc, sc.clone(), 13, PERFECT);
    events(&mut s);
    s.request_client_certificate().unwrap();
    settle(&mut c, &mut s, &mut sim);
    assert_eq!(client_certs(&events(&mut s)), vec![Vec::<Vec<u8>>::new()]);
    assert!(s.handshake_info().unwrap().peer_certificates.is_empty());
    check_connected(&mut c, &mut s, &mut sim);
    // The verifier refuses the certificate: the server fails the connection.
    let picky = sc
        .clone()
        .with_verifier(PeerVerifier::Fingerprints(vec![si.fingerprint()]));
    let cc = cfg13(&ci).with_post_handshake_auth(true);
    let (mut c, mut s, mut sim) = handshake(cc, picky, 14, PERFECT);
    s.request_client_certificate().unwrap();
    settle(&mut c, &mut s, &mut sim);
    assert!(matches!(
        sim.server_errors.first(),
        Some(Error::Certificate(_))
    ));
    assert!(s.is_closed());
    assert!(matches!(
        sim.client_errors.first(),
        Some(Error::PeerAlert(AlertDescription::BadCertificate))
    ));
    // Not offered by the client; asked by a client; DTLS 1.2.
    let (mut c, mut s, _) = handshake(cfg13(&ci), sc, 15, PERFECT);
    assert!(matches!(
        s.request_client_certificate(),
        Err(Error::NotAvailable(_))
    ));
    assert!(matches!(
        c.request_client_certificate(),
        Err(Error::NotAvailable(_))
    ));
    let (_, mut s, _) = handshake(
        Config::new(ci).with_post_handshake_auth(true),
        Config::new(si),
        16,
        PERFECT,
    );
    assert!(matches!(
        s.request_client_certificate(),
        Err(Error::NotAvailable(_))
    ));
}

fn sessions(evs: &[Event]) -> Vec<Session> {
    evs.iter()
        .filter_map(|e| match e {
            Event::NewSession(s) => Some((**s).clone()),
            _ => None,
        })
        .collect()
}

fn early_events(evs: &[Event]) -> Vec<Vec<u8>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::EarlyData(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

/// A ticket from a full handshake between these configurations.
fn ticket(cc: &Config, sc: &Config, seed: u64) -> Session {
    let (mut c, mut s, mut sim) = handshake(cc.clone(), sc.clone(), seed, PERFECT);
    settle(&mut c, &mut s, &mut sim);
    let got = sessions(&events(&mut c));
    assert_eq!(got.len(), 1);
    got[0].clone()
}

fn early_configs(ci: &Identity, si: &Identity, key: &TicketKey) -> (Config, Config) {
    let cc = cfg13(ci).with_session_resumption(true).with_early_data(1);
    let sc = cfg13(si)
        .with_session_resumption(true)
        .with_ticket_key(key.clone())
        .with_early_data(1000);
    (cc, sc)
}

#[test]
fn early_data_accepted_once() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let key = TicketKey::from_secret(&[5; 32]).unwrap();
    let (cc, sc) = early_configs(&ci, &si, &key);
    let session = ticket(&cc, &sc, 20);
    assert_eq!(session.max_early_data(), 1000);
    let sc = Arc::new(sc);
    for (seed, link) in [(21, PERFECT), (22, lossy())] {
        let mut sim = Sim::new(seed, link);
        let mut c = Connection::client_resume(Arc::new(cc.clone()), sim.now, &session).unwrap();
        let hello: Vec<Vec<u8>> = std::iter::from_fn(|| c.poll_transmit()).collect();
        c.send_early_data(b"GET /a").unwrap();
        c.send_early_data(&[7; 994]).unwrap();
        assert!(matches!(c.send_early_data(b"x"), Err(Error::TooLarge)));
        let early: Vec<Vec<u8>> = std::iter::from_fn(|| c.poll_transmit()).collect();
        let mut s = Connection::server(sc.clone(), sim.now, b"10.0.0.2:1").unwrap();
        for d in hello.iter().chain(&early) {
            sim.push(true, d.clone());
        }
        sim.run(&mut c, &mut s, Duration::from_secs(30), connected);
        assert!(connected(&c, &s), "{:?}", sim.server_errors);
        let ci_ = c.handshake_info().unwrap().clone();
        let si_ = s.handshake_info().unwrap().clone();
        assert!(ci_.resumed && ci_.early_data && si_.early_data);
        let evs = events(&mut s);
        let got = early_events(&evs);
        if link.loss == 0 {
            assert_eq!(got, vec![b"GET /a".to_vec(), vec![7; 994]]);
        }
        // Early data comes before Connected.
        let connected_at = evs
            .iter()
            .position(|e| matches!(e, Event::Connected(_)))
            .unwrap();
        assert!(
            evs.iter()
                .skip(connected_at)
                .all(|e| !matches!(e, Event::EarlyData(_)))
        );
        assert!(matches!(
            c.send_early_data(b"late"),
            Err(Error::NotAvailable(_))
        ));
        check_connected(&mut c, &mut s, &mut sim);
        // The same ClientHello again (a replay to the same server): resumed, no early data.
        let mut sim = Sim::new(seed + 100, PERFECT);
        let mut s = Connection::server(sc.clone(), sim.now, b"10.0.0.3:1").unwrap();
        for d in hello.iter().chain(&early) {
            let _ = s.handle_datagram(sim.now, d);
        }
        assert!(early_events(&events(&mut s)).is_empty());
        let answer: Vec<Vec<u8>> = std::iter::from_fn(|| s.poll_transmit()).collect();
        assert!(!answer.is_empty(), "answered like any resumption");
        sim.now += Duration::from_millis(1);
    }
}

#[test]
fn early_data_rejected() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let key = TicketKey::from_secret(&[6; 32]).unwrap();
    let (cc, sc) = early_configs(&ci, &si, &key);
    let session = ticket(&cc, &sc, 30);
    let resume = |cc: &Config, sc: &Config, seed: u64, age: Duration| {
        let mut sim = Sim::new(seed, PERFECT);
        let mut c =
            Connection::client_resume(Arc::new(cc.clone()), sim.now + age, &session).unwrap();
        let r = c.send_early_data(b"early");
        let mut s = Connection::server(Arc::new(sc.clone()), sim.now, b"10.0.0.4:1").unwrap();
        sim.run(&mut c, &mut s, Duration::from_secs(30), connected);
        assert!(
            connected(&c, &s),
            "{:?} {:?}",
            sim.client_errors,
            sim.server_errors
        );
        let got = early_events(&events(&mut s));
        assert!(got.is_empty());
        assert!(!c.handshake_info().unwrap().early_data);
        assert!(!s.handshake_info().unwrap().early_data);
        assert!(matches!(
            c.send_early_data(b"x"),
            Err(Error::NotAvailable(_))
        ));
        // The data goes again as application data.
        check_connected(&mut c, &mut s, &mut sim);
        (r, c.handshake_info().unwrap().resumed)
    };
    // Server with early data off (and resumption on): resumed, early data skipped.
    let off = cfg13(&si)
        .with_session_resumption(true)
        .with_ticket_key(key);
    assert_eq!(resume(&cc, &off, 31, Duration::ZERO), (Ok(()), true));
    // Ticket age 60 s off: not fresh.
    assert_eq!(
        resume(&cc, &sc, 32, Duration::from_secs(60)),
        (Ok(()), true)
    );
    // Another ticket key: full handshake after a HelloRetryRequest (cookies on).
    let other = cfg13(&si)
        .with_session_resumption(true)
        .with_early_data(1000);
    assert_eq!(resume(&cc, &other, 33, Duration::ZERO), (Ok(()), false));
    // A client with early data off does not offer it.
    let plain = cfg13(&ci).with_session_resumption(true);
    let (r, resumed) = resume(&plain, &sc, 34, Duration::ZERO);
    assert!(matches!(r, Err(Error::NotAvailable(_))) && resumed);
    // A ticket issued without early data.
    let no_early = ticket(&cc, &off, 35);
    assert_eq!(no_early.max_early_data(), 0);
    let mut c =
        Connection::client_resume(Arc::new(cc.clone()), Sim::new(1, PERFECT).now, &no_early)
            .unwrap();
    assert!(matches!(
        c.send_early_data(b"x"),
        Err(Error::NotAvailable(_))
    ));
    // A shared store that is full or failing: rejected (fail closed).
    struct Never;
    impl AntiReplayStore for Never {
        fn check_and_insert(&self, _: &[u8], _: Duration) -> std::io::Result<bool> {
            Err(std::io::Error::other("store down"))
        }
    }
    let failing = sc.clone().with_anti_replay(Arc::new(Never));
    assert_eq!(resume(&cc, &failing, 36, Duration::ZERO), (Ok(()), true));
    let full = sc.with_anti_replay(Arc::new(MemoryAntiReplay::new(0)));
    assert_eq!(resume(&cc, &full, 37, Duration::ZERO), (Ok(()), true));
}

/// Two servers sharing a ticket key and an anti-replay store: a ClientHello replayed to the
/// second one gets no early data accepted there either.
#[test]
fn early_data_shared_anti_replay() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let key = TicketKey::from_secret(&[8; 32]).unwrap();
    let store: Arc<dyn AntiReplayStore> = Arc::new(MemoryAntiReplay::new(100));
    let (cc, sc) = early_configs(&ci, &si, &key);
    let sc = sc.with_anti_replay(store);
    let session = ticket(&cc, &sc, 40);
    let sim = Sim::new(41, PERFECT);
    let mut c = Connection::client_resume(Arc::new(cc), sim.now, &session).unwrap();
    c.send_early_data(b"once").unwrap();
    let flight: Vec<Vec<u8>> = std::iter::from_fn(|| c.poll_transmit()).collect();
    let mut accepted = 0;
    for server in 0..2 {
        // Separate configurations (separate servers), one store.
        let cfg = Arc::new(sc.clone());
        let mut s = Connection::server(cfg, sim.now, format!("s{server}").as_bytes()).unwrap();
        for d in &flight {
            s.handle_datagram(sim.now, d).unwrap();
        }
        accepted += early_events(&events(&mut s)).len();
    }
    assert_eq!(accepted, 1);
}
