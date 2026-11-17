//! DTLS 1.3 (RFC 9147), version negotiation, connection IDs (RFC 9146), PSKs and session
//! resumption, over the simulated link: loss, reordering, duplication, small MTUs, ACKs and
//! partial-flight retransmission, KeyUpdate.

use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PrivateKey;
use only_dtls::{
    AlertDescription, CipherSuite, Config, Connection, Error, Event, HelloCheck, HelloVerifier,
    Identity, PeerVerifier, Psk, Session, SrtpProfile, TicketKey, Version,
};

mod common;

use common::*;

const V13: [Version; 1] = [Version::Dtls13];
const BOTH: [Version; 2] = [Version::Dtls13, Version::Dtls12];

fn cfg13(id: &Identity) -> Config {
    Config::new(id.clone()).with_versions(V13.to_vec())
}

fn handshake(cc: Config, sc: Config, seed: u64, link: Link) -> (Connection, Connection, Sim) {
    let mut sim = Sim::new(seed, link);
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(30), connected);
    (c, s, sim)
}

fn version(c: &Connection) -> Option<Version> {
    c.handshake_info().map(|i| i.version)
}

fn sessions(evs: &[Event]) -> Vec<Session> {
    evs.iter()
        .filter_map(|e| match e {
            Event::NewSession(s) => Some((**s).clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn every_suite_and_key_type() {
    let p384 = identity_with(PrivateKey::P384(
        only_crypto::p384::SecretKey::generate().unwrap(),
    ));
    let ed = identity_with(PrivateKey::Ed25519(
        only_crypto::ed25519::SigningKey::generate().unwrap(),
    ));
    let p256 = Identity::generate_self_signed().unwrap();
    let rsa = rsa_identity();
    for suite in CipherSuite::TLS13 {
        for sid in [&p256, &p384, &ed, &rsa] {
            for cid in [&p256, &rsa] {
                let cc = cfg13(cid)
                    .with_cipher_suites(vec![suite])
                    .with_srtp_profiles(vec![SrtpProfile::AeadAes128Gcm])
                    .with_verifier(PeerVerifier::Fingerprints(vec![sid.fingerprint()]));
                let sc = cfg13(sid)
                    .with_srtp_profiles(SrtpProfile::ALL.to_vec())
                    .with_verifier(PeerVerifier::Fingerprints(vec![cid.fingerprint()]));
                let (mut c, mut s, mut sim) = handshake(cc, sc, 3, PERFECT);
                assert_eq!(version(&c), Some(Version::Dtls13));
                let info = c.handshake_info().unwrap().clone();
                assert_eq!(info.cipher_suite, suite);
                assert_eq!(info.srtp_profile, Some(SrtpProfile::AeadAes128Gcm));
                assert_eq!(info.peer_fingerprint, Some(sid.fingerprint()));
                assert_eq!(
                    s.handshake_info().unwrap().peer_fingerprint,
                    Some(cid.fingerprint())
                );
                assert!(!info.resumed);
                check_connected(&mut c, &mut s, &mut sim);
            }
        }
    }
}

#[test]
fn version_negotiation() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let cases: [(&[Version], &[Version], Option<Version>); 6] = [
        (&BOTH, &BOTH, Some(Version::Dtls13)),
        (&BOTH, &[Version::Dtls12], Some(Version::Dtls12)),
        (&[Version::Dtls12], &BOTH, Some(Version::Dtls12)),
        (&V13, &BOTH, Some(Version::Dtls13)),
        (&V13, &[Version::Dtls12], None),
        (&[Version::Dtls12], &V13, None),
    ];
    for (i, (cv, sv, want)) in cases.into_iter().enumerate() {
        for cookies in [false, true] {
            let cc = Config::new(ci.clone()).with_versions(cv.to_vec());
            let sc = Config::new(si.clone())
                .with_versions(sv.to_vec())
                .with_hello_verify(cookies)
                .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80]);
            let cc = cc.with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80]);
            let (mut c, mut s, mut sim) = handshake(cc, sc, i as u64, PERFECT);
            match want {
                Some(v) => {
                    assert_eq!(version(&c), Some(v), "case {i} cookies {cookies}");
                    assert_eq!(version(&s), Some(v));
                    assert_eq!(c.version(), v);
                    check_connected(&mut c, &mut s, &mut sim);
                }
                None => {
                    assert!(!c.is_connected() && !s.is_connected(), "case {i}");
                    let errs: Vec<_> = sim.client_errors.iter().chain(&sim.server_errors).collect();
                    assert!(
                        errs.iter().any(|e| matches!(
                            e,
                            Error::Protocol {
                                alert: AlertDescription::ProtocolVersion
                                    | AlertDescription::HandshakeFailure,
                                ..
                            } | Error::PeerAlert(
                                AlertDescription::ProtocolVersion
                                    | AlertDescription::HandshakeFailure
                            )
                        )),
                        "case {i}: {errs:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn lossy_reordering_small_mtu() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = rsa_identity(); // a large certificate: many fragments at MTU 256
    let link = Link {
        loss: 25,
        dup: 10,
        jitter: 400,
    };
    for seed in 0..32 {
        let cc = cfg13(&ci)
            .with_mtu(256)
            .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80])
            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2))
            .with_verifier(PeerVerifier::Fingerprints(vec![si.fingerprint()]))
            .with_connection_id((seed % 3 == 0).then_some(4));
        let sc = cfg13(&si)
            .with_mtu(256)
            .with_hello_verify(seed % 2 == 0)
            .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80])
            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2))
            .with_verifier(PeerVerifier::Fingerprints(vec![ci.fingerprint()]))
            .with_session_resumption(seed % 4 == 1)
            .with_connection_id((seed % 3 == 0).then_some(8));
        let (mut c, mut s, mut sim) = handshake(cc, sc, seed, link);
        assert!(
            connected(&c, &s),
            "seed {seed}: client {:?} server {:?}",
            sim.client_errors,
            sim.server_errors
        );
        check_connected(&mut c, &mut s, &mut sim);
        // KeyUpdates both ways over the lossy link, data flowing between them.
        sim.link = link;
        for round in 0..3u8 {
            c.update_keys(round == 1).unwrap();
            s.update_keys(false).unwrap();
            sim.run(&mut c, &mut s, Duration::from_secs(10), |c, s| {
                c.poll_timeout().is_none() && s.poll_timeout().is_none()
            });
        }
        sim.link = PERFECT;
        events(&mut c);
        events(&mut s);
        c.send_application_data(b"after updates").unwrap();
        s.send_application_data(b"back").unwrap();
        sim.run(&mut c, &mut s, Duration::from_secs(1), |_, _| false);
        let got = |c: &mut Connection| {
            events(c)
                .into_iter()
                .filter_map(|e| match e {
                    Event::ApplicationData(d) => Some(d),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(got(&mut s), vec![b"after updates".to_vec()], "seed {seed}");
        assert_eq!(got(&mut c), vec![b"back".to_vec()], "seed {seed}");
    }
}

/// One lost datagram in the middle of the server's flight: the client ACKs what it has and
/// the server resends only the missing fragments, not the whole flight.
#[test]
fn partial_flight_retransmission() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = rsa_identity();
    let now = Instant::now();
    let cc = cfg13(&ci).with_mtu(256);
    let sc = cfg13(&si).with_mtu(256).with_hello_verify(false);
    let mut c = Connection::client(Arc::new(cc), now).unwrap();
    let mut s = Connection::server(Arc::new(sc), now, b"peer").unwrap();
    while let Some(d) = c.poll_transmit() {
        s.handle_datagram(now, &d).unwrap();
    }
    let flight: Vec<Vec<u8>> = std::iter::from_fn(|| s.poll_transmit()).collect();
    assert!(flight.len() >= 6, "{} datagrams", flight.len());
    let lost = flight.len() / 2;
    for (i, d) in flight.iter().enumerate() {
        if i != lost {
            c.handle_datagram(now, d).unwrap();
        }
    }
    // The client saw a gap and ACKs at once, one ACK for all it received.
    assert!(c.poll_transmit().is_none());
    assert_eq!(c.poll_timeout(), Some(now));
    c.handle_timeout(now).unwrap();
    let acks: Vec<Vec<u8>> = std::iter::from_fn(|| c.poll_transmit()).collect();
    assert_eq!(acks.len(), 1, "one ACK");
    for d in &acks {
        s.handle_datagram(now, d).unwrap();
    }
    assert!(!c.is_connected());
    // At the retransmission timeout the server resends only what was not acknowledged.
    let t = s.poll_timeout().unwrap();
    s.handle_timeout(t).unwrap();
    let resent: Vec<Vec<u8>> = std::iter::from_fn(|| s.poll_transmit()).collect();
    assert!(
        !resent.is_empty() && resent.len() < 3,
        "resent {} of {}",
        resent.len(),
        flight.len()
    );
    for d in &resent {
        c.handle_datagram(t, d).unwrap();
    }
    assert!(c.is_connected(), "the resent fragment completed the flight");
    // The client's final flight; the server ACKs it and is done.
    for d in std::iter::from_fn(|| c.poll_transmit()).collect::<Vec<_>>() {
        s.handle_datagram(t, &d).unwrap();
    }
    assert!(s.is_connected());
    for d in std::iter::from_fn(|| s.poll_transmit()).collect::<Vec<_>>() {
        c.handle_datagram(t, &d).unwrap();
    }
    assert_eq!(c.poll_timeout(), None, "final flight acknowledged");
    assert_eq!(s.poll_timeout(), None);
}

/// The client's final flight is lost: the server never connects until it is resent, and the
/// lost ACK makes the client resend it too.
#[test]
fn final_flight_and_ack_loss() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let mut now = Instant::now();
    let mut c = Connection::client(Arc::new(cfg13(&ci)), now).unwrap();
    let mut s =
        Connection::server(Arc::new(cfg13(&si).with_hello_verify(false)), now, b"p").unwrap();
    let pump = |from: &mut Connection, to: &mut Connection, now: Instant, drop: bool| {
        for d in std::iter::from_fn(|| from.poll_transmit()).collect::<Vec<_>>() {
            if !drop {
                to.handle_datagram(now, &d).unwrap();
            }
        }
    };
    pump(&mut c, &mut s, now, false);
    pump(&mut s, &mut c, now, false);
    assert!(c.is_connected());
    pump(&mut c, &mut s, now, true); // final flight lost
    assert!(!s.is_connected());
    now = c.poll_timeout().unwrap();
    c.handle_timeout(now).unwrap();
    pump(&mut c, &mut s, now, false);
    assert!(s.is_connected());
    pump(&mut s, &mut c, now, true); // the ACK lost
    now = c.poll_timeout().unwrap();
    c.handle_timeout(now).unwrap();
    pump(&mut c, &mut s, now, false); // a repeat: the server ACKs again
    pump(&mut s, &mut c, now, false);
    assert_eq!(c.poll_timeout(), None);
}

#[test]
fn hello_retry_request_cookies() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let now = Instant::now();
    // In the connection.
    let (mut c, mut s, mut sim) =
        handshake(cfg13(&ci), cfg13(&si).with_hello_verify(true), 7, PERFECT);
    check_connected(&mut c, &mut s, &mut sim);
    // Stateless, in front of the connection.
    let v = HelloVerifier::new(now).unwrap();
    let mut c = Connection::client(Arc::new(cfg13(&ci)), now).unwrap();
    let ch1 = c.poll_transmit().unwrap();
    let HelloCheck::Respond(hrr) = v.check(now, b"10.0.0.9:9", &ch1) else {
        panic!("no HelloRetryRequest")
    };
    assert!(matches!(
        v.check(now, b"10.0.0.9:9", &ch1),
        HelloCheck::Respond(_)
    ));
    c.handle_datagram(now, &hrr).unwrap();
    let ch2 = c.poll_transmit().unwrap();
    assert_eq!(v.check(now, b"10.0.0.9:9", &ch2), HelloCheck::Accept);
    assert_eq!(
        v.check(now, b"10.0.0.8:9", &ch2),
        HelloCheck::Drop,
        "other address"
    );
    let later = now + Duration::from_secs(200);
    assert_eq!(
        v.check(later, b"10.0.0.9:9", &ch2),
        HelloCheck::Drop,
        "expired"
    );
    let mut s = Connection::server(
        Arc::new(cfg13(&si).with_hello_verify(false)),
        now,
        b"10.0.0.9:9",
    )
    .unwrap();
    s.handle_datagram(now, &ch2).unwrap();
    let mut sim = Sim::new(1, PERFECT);
    sim.now = now;
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    check_connected(&mut c, &mut s, &mut sim);
}

#[test]
fn resumption_dtls13() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let key = TicketKey::from_secret(&[9; 32]).unwrap();
    let cc = cfg13(&ci)
        .with_session_resumption(true)
        .with_verifier(PeerVerifier::Fingerprints(vec![si.fingerprint()]));
    let sc = cfg13(&si)
        .with_session_resumption(true)
        .with_ticket_key(key);
    let (mut c, mut s, mut sim) = handshake(cc.clone(), sc.clone(), 1, PERFECT);
    sim.run(&mut c, &mut s, Duration::from_secs(2), |c, s| {
        c.poll_timeout().is_none() && s.poll_timeout().is_none()
    });
    let got = sessions(&events(&mut c));
    assert_eq!(got.len(), 1, "one NewSessionTicket");
    let session = &got[0];
    assert_eq!(session.version(), Version::Dtls13);
    assert!(session.has_ticket());
    // Resumed: no certificates on the wire, same peer identity reported.
    let full = sim.sent;
    let mut sim = Sim::new(2, PERFECT);
    let mut c = Connection::client_resume(Arc::new(cc.clone()), sim.now, session).unwrap();
    let mut s = Connection::server(Arc::new(sc.clone()), sim.now, b"x").unwrap();
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    let info = c.handshake_info().unwrap().clone();
    assert!(info.resumed && s.handshake_info().unwrap().resumed);
    assert_eq!(info.peer_fingerprint, Some(si.fingerprint()));
    assert_eq!(
        s.handshake_info().unwrap().peer_fingerprint,
        Some(ci.fingerprint())
    );
    assert!(sim.sent[0] <= full[0] && sim.sent[1] <= full[1]);
    check_connected(&mut c, &mut s, &mut sim);
    // Another ticket key: a full handshake instead.
    let other = cfg13(&si)
        .with_session_resumption(true)
        .with_ticket_key(TicketKey::generate().unwrap());
    let mut sim = Sim::new(3, PERFECT);
    let mut c = Connection::client_resume(Arc::new(cc), sim.now, session).unwrap();
    let mut s = Connection::server(Arc::new(other), sim.now, b"x").unwrap();
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert!(!c.handshake_info().unwrap().resumed);
    check_connected(&mut c, &mut s, &mut sim);
    // A pinned fingerprint that no longer matches refuses the resumed session too.
    let pinned = cfg13(&ci)
        .with_session_resumption(true)
        .with_verifier(PeerVerifier::Fingerprints(vec![ci.fingerprint()]));
    let mut sim = Sim::new(4, PERFECT);
    let mut c = Connection::client_resume(Arc::new(pinned), sim.now, session).unwrap();
    let mut s = Connection::server(Arc::new(sc), sim.now, b"x").unwrap();
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert!(!c.is_connected());
    assert!(matches!(
        sim.client_errors.first(),
        Some(Error::Certificate(_))
    ));
}

#[test]
fn external_psk_dtls13() {
    let psk = Psk::new("device-7", vec![0x42; 32]).unwrap();
    let cc = Config::without_identity()
        .with_versions(V13.to_vec())
        .with_psks(vec![psk.clone()]);
    let sc = Config::without_identity()
        .with_versions(V13.to_vec())
        .with_psks(vec![Psk::new("other", vec![1; 32]).unwrap(), psk]);
    let (mut c, mut s, mut sim) = handshake(cc, sc.clone(), 5, PERFECT);
    let info = s.handshake_info().unwrap().clone();
    assert_eq!(info.psk_identity.as_deref(), Some(&b"device-7"[..]));
    assert!(info.peer_certificates.is_empty());
    check_connected(&mut c, &mut s, &mut sim);
    // The wrong key: the binder does not verify.
    let bad = Config::without_identity()
        .with_versions(V13.to_vec())
        .with_psks(vec![Psk::new("device-7", vec![0x43; 32]).unwrap()]);
    let (c, s, sim) = handshake(bad, sc, 6, PERFECT);
    assert!(!c.is_connected() && !s.is_connected());
    assert!(
        sim.server_errors.iter().any(|e| matches!(
            e,
            Error::Protocol {
                alert: AlertDescription::DecryptError,
                ..
            }
        )),
        "{:?}",
        sim.server_errors
    );
}

#[test]
fn psk_suites_dtls12() {
    let psk = Psk::new(b"sensor".to_vec(), vec![7; 16]).unwrap();
    for suite in CipherSuite::PSK {
        let cc = Config::without_identity()
            .with_psks(vec![psk.clone()])
            .with_cipher_suites(vec![suite]);
        let sc = Config::without_identity().with_psks(vec![psk.clone()]);
        let (mut c, mut s, mut sim) = handshake(cc, sc, 8, PERFECT);
        let info = c.handshake_info().unwrap().clone();
        assert_eq!(info.cipher_suite, suite);
        assert_eq!(info.version, Version::Dtls12);
        assert_eq!(
            s.handshake_info().unwrap().psk_identity.as_deref(),
            Some(&b"sensor"[..])
        );
        check_connected(&mut c, &mut s, &mut sim);
    }
    // Unknown identity.
    let cc = Config::without_identity().with_psks(vec![Psk::new("who", vec![7; 16]).unwrap()]);
    let sc = Config::without_identity().with_psks(vec![psk]);
    let (c, _s, sim) = handshake(cc, sc, 9, PERFECT);
    assert!(!c.is_connected());
    assert!(sim.server_errors.iter().any(|e| matches!(
        e,
        Error::Protocol {
            alert: AlertDescription::UnknownPskIdentity,
            ..
        }
    )));
}

#[test]
fn resumption_dtls12_tickets_and_ids() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    for tickets in [true, false] {
        let cc = Config::new(ci.clone()).with_session_resumption(tickets);
        // Without tickets the client offers none and the server falls back to session IDs.
        let cc = if tickets {
            cc
        } else {
            cc.with_session_resumption(false)
        };
        let sc = Config::new(si.clone()).with_session_resumption(true);
        let (mut c, mut s, _) = handshake(cc.clone(), sc.clone(), 10, PERFECT);
        let got = sessions(&events(&mut c));
        events(&mut s);
        if !tickets {
            // A client without resumption reports no sessions.
            assert!(got.is_empty());
            continue;
        }
        assert_eq!(got.len(), 1);
        assert!(got[0].has_ticket());
        assert_eq!(got[0].version(), Version::Dtls12);
        for link in [
            PERFECT,
            Link {
                loss: 20,
                dup: 10,
                jitter: 300,
            },
        ] {
            for seed in 0..8 {
                let mut sim = Sim::new(seed, link);
                let mut c = Connection::client_resume(
                    Arc::new(
                        cc.clone()
                            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2)),
                    ),
                    sim.now,
                    &got[0],
                )
                .unwrap();
                let mut s = Connection::server(
                    Arc::new(
                        sc.clone()
                            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2)),
                    ),
                    sim.now,
                    b"y",
                )
                .unwrap();
                sim.run(&mut c, &mut s, Duration::from_secs(20), connected);
                assert!(
                    connected(&c, &s),
                    "seed {seed}: {:?} {:?}",
                    sim.client_errors,
                    sim.server_errors
                );
                assert!(c.handshake_info().unwrap().resumed);
                assert!(s.handshake_info().unwrap().resumed);
                assert_eq!(
                    s.handshake_info().unwrap().peer_fingerprint,
                    Some(ci.fingerprint())
                );
                check_connected(&mut c, &mut s, &mut sim);
            }
        }
    }
    // Session IDs: a client that does not offer the ticket extension.
    let cc = Config::new(ci).with_session_resumption(true);
    let sc = Config::new(si)
        .with_session_resumption(true)
        .with_ticket_key(TicketKey::generate().unwrap());
    let mut sim = Sim::new(11, PERFECT);
    let mut c = Connection::client(Arc::new(cc.clone()), sim.now).unwrap();
    let mut s = Connection::server(Arc::new(sc.clone()), sim.now, b"z").unwrap();
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    let got = sessions(&events(&mut c));
    assert_eq!(got.len(), 1);
    let mut sim = Sim::new(12, PERFECT);
    let mut c = Connection::client_resume(Arc::new(cc), sim.now, &got[0]).unwrap();
    let mut s = Connection::server(Arc::new(sc), sim.now, b"z").unwrap();
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert!(c.handshake_info().unwrap().resumed);
    check_connected(&mut c, &mut s, &mut sim);
}

#[test]
fn connection_ids() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    for versions in [vec![Version::Dtls12], V13.to_vec()] {
        for (clen, slen) in [
            (Some(4), Some(8)),
            (Some(0), Some(6)),
            (Some(5), None),
            (None, Some(3)),
        ] {
            let cc = Config::new(ci.clone())
                .with_versions(versions.clone())
                .with_connection_id(clen);
            let sc = Config::new(si.clone())
                .with_versions(versions.clone())
                .with_connection_id(slen);
            let (mut c, mut s, mut sim) = handshake(cc, sc, 13, PERFECT);
            let negotiated = clen.is_some() && slen.is_some();
            let ci_ = c.handshake_info().unwrap().clone();
            let si_ = s.handshake_info().unwrap().clone();
            if negotiated {
                assert_eq!(
                    ci_.peer_connection_id, si_.local_connection_id,
                    "{versions:?}"
                );
                assert_eq!(si_.peer_connection_id, ci_.local_connection_id);
                assert_eq!(
                    s.local_connection_id().map(<[u8]>::len),
                    slen.map(usize::from)
                );
            } else {
                assert_eq!(ci_.peer_connection_id, None);
                assert_eq!(s.local_connection_id(), None);
            }
            // Records to the server carry its CID; a listener can route them by it.
            events(&mut c);
            c.send_application_data(b"routed").unwrap();
            let d = c.poll_transmit().unwrap();
            let len = slen.map_or(0, usize::from);
            let want = s.local_connection_id().filter(|c| !c.is_empty());
            assert_eq!(
                only_dtls::connection_id(&d, len),
                want,
                "{versions:?} {clen:?} {slen:?}"
            );
            s.handle_datagram(sim.now, &d).unwrap();
            assert!(
                matches!(events(&mut s).last(), Some(Event::ApplicationData(x)) if x == b"routed")
            );
            check_connected(&mut c, &mut s, &mut sim);
        }
    }
}

#[test]
fn replayed_tampered_and_misrouted_records() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let (mut c, mut s, sim) = handshake(
        cfg13(&ci).with_connection_id(Some(4)),
        cfg13(&si).with_connection_id(Some(4)),
        14,
        PERFECT,
    );
    events(&mut s);
    c.send_application_data(b"once").unwrap();
    let d = c.poll_transmit().unwrap();
    s.handle_datagram(sim.now, &d).unwrap();
    s.handle_datagram(sim.now, &d).unwrap();
    let data: Vec<_> = events(&mut s)
        .into_iter()
        .filter(|e| matches!(e, Event::ApplicationData(_)))
        .collect();
    assert_eq!(data.len(), 1, "the replay is dropped");
    for i in [0, 1, 6, d.len() - 1] {
        let mut t = d.clone();
        t[i] ^= 0x40;
        s.handle_datagram(sim.now, &t).unwrap();
    }
    assert!(events(&mut s).is_empty(), "tampered records are dropped");
    assert!(s.is_connected());
}

#[test]
fn wrong_fingerprint_and_close() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let cc = cfg13(&ci).with_verifier(PeerVerifier::Fingerprints(vec![ci.fingerprint()]));
    let (c, s, sim) = handshake(cc, cfg13(&si), 15, PERFECT);
    assert!(!c.is_connected() && !s.is_connected());
    assert!(matches!(
        sim.client_errors.first(),
        Some(Error::Certificate(_))
    ));
    assert!(matches!(
        sim.server_errors.first(),
        Some(Error::PeerAlert(AlertDescription::BadCertificate))
    ));
    let (mut c, mut s, mut sim) = handshake(cfg13(&ci), cfg13(&si), 16, PERFECT);
    events(&mut s);
    c.close();
    sim.run(&mut c, &mut s, Duration::from_secs(1), |_, _| false);
    assert!(matches!(events(&mut s).last(), Some(Event::Closed)));
    assert!(c.is_closed() && s.is_closed());
    assert!(matches!(c.send_application_data(b"x"), Err(Error::Closed)));
}

#[test]
fn handshake_timeout() {
    let ci = Identity::generate_self_signed().unwrap();
    let now = Instant::now();
    let mut c = Connection::client(
        Arc::new(cfg13(&ci).with_handshake_timeout(Duration::from_secs(3))),
        now,
    )
    .unwrap();
    let mut t = now;
    let mut sent = 0;
    let mut result = Ok(());
    while let Some(next) = c.poll_timeout() {
        t = next;
        result = c.handle_timeout(t);
        while c.poll_transmit().is_some() {
            sent += 1;
        }
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(Error::Timeout));
    assert!(t >= now + Duration::from_secs(3));
    assert!((2..=4).contains(&sent), "{sent} retransmissions");
    assert!(c.update_keys(false).is_err());
}
