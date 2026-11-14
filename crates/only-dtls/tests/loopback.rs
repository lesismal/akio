//! Handshakes between two `Connection`s over a simulated link: loss, reordering, duplication,
//! small MTUs; negative cases (fingerprints, replays, cookies, timeouts, alerts).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PrivateKey;
use only_dtls::{
    AlertDescription, CipherSuite, Config, Connection, Error, Event, HelloCheck, HelloVerifier,
    Identity, PeerVerifier, Role, SrtpProfile,
};

/// A deterministic xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[derive(Clone, Copy)]
struct Link {
    loss: u64,
    dup: u64,
    /// Maximum extra delay in ms (reordering).
    jitter: u64,
}

const PERFECT: Link = Link {
    loss: 0,
    dup: 0,
    jitter: 0,
};

struct Sim {
    now: Instant,
    rng: Rng,
    link: Link,
    /// (delivery time, tiebreak) -> (to_server, datagram)
    queue: BTreeMap<(Instant, u64), (bool, Vec<u8>)>,
    n: u64,
    sent: [usize; 2],
    client_errors: Vec<Error>,
    server_errors: Vec<Error>,
}

impl Sim {
    fn new(seed: u64, link: Link) -> Sim {
        Sim {
            now: Instant::now(),
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            link,
            queue: BTreeMap::new(),
            n: 0,
            sent: [0; 2],
            client_errors: Vec::new(),
            server_errors: Vec::new(),
        }
    }

    fn push(&mut self, to_server: bool, d: Vec<u8>) {
        self.sent[usize::from(to_server)] += 1;
        if self.rng.chance(self.link.loss) {
            return;
        }
        let copies = if self.rng.chance(self.link.dup) { 2 } else { 1 };
        for _ in 0..copies {
            let delay = 5 + if self.link.jitter > 0 {
                self.rng.next() % self.link.jitter
            } else {
                0
            };
            self.n += 1;
            self.queue.insert(
                (self.now + Duration::from_millis(delay), self.n),
                (to_server, d.clone()),
            );
        }
    }

    fn flush(&mut self, c: &mut Connection, s: &mut Connection) {
        while let Some(d) = c.poll_transmit() {
            self.push(true, d);
        }
        while let Some(d) = s.poll_transmit() {
            self.push(false, d);
        }
    }

    /// Runs until `done` or the deadline (virtual time).
    fn run(
        &mut self,
        c: &mut Connection,
        s: &mut Connection,
        limit: Duration,
        mut done: impl FnMut(&Connection, &Connection) -> bool,
    ) {
        let end = self.now + limit;
        self.flush(c, s);
        while self.now < end && !done(c, s) {
            let next_packet = self.queue.keys().next().map(|k| k.0);
            let next = [next_packet, c.poll_timeout(), s.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else { break };
            self.now = self.now.max(next);
            while let Some((&k, _)) = self.queue.iter().next() {
                if k.0 > self.now {
                    break;
                }
                let Some((to_server, d)) = self.queue.remove(&k) else {
                    break;
                };
                let r = if to_server {
                    s.handle_datagram(self.now, &d)
                } else {
                    c.handle_datagram(self.now, &d)
                };
                if let Err(e) = r {
                    if to_server {
                        self.server_errors.push(e);
                    } else {
                        self.client_errors.push(e);
                    }
                }
            }
            if c.poll_timeout().is_some_and(|t| t <= self.now) {
                if let Err(e) = c.handle_timeout(self.now) {
                    self.client_errors.push(e);
                }
            }
            if s.poll_timeout().is_some_and(|t| t <= self.now) {
                if let Err(e) = s.handle_timeout(self.now) {
                    self.server_errors.push(e);
                }
            }
            self.flush(c, s);
        }
    }
}

fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

fn rsa_identity() -> Identity {
    let key = PrivateKey::from_pem(include_bytes!("data/rsa2048.pem")).unwrap();
    let cert = only_x509::CertificateParams::new(["rsa.test"])
        .self_signed(&key)
        .unwrap();
    Identity::new(vec![cert.as_der().to_vec()], key).unwrap()
}

fn identity_with(key: PrivateKey) -> Identity {
    let cert = only_x509::CertificateParams::new(["peer.test"])
        .self_signed(&key)
        .unwrap();
    Identity::new(vec![cert.as_der().to_vec()], key).unwrap()
}

fn pair(client: Config, server: Config, sim: &Sim) -> (Connection, Connection) {
    let c = Connection::client(Arc::new(client), sim.now).unwrap();
    let s = Connection::server(Arc::new(server), sim.now, b"10.0.0.1:1234").unwrap();
    (c, s)
}

fn connected(c: &Connection, s: &Connection) -> bool {
    c.is_connected() && s.is_connected()
}

/// Handshake, SRTP keys and exporter agreement, application data both ways.
fn check_connected(c: &mut Connection, s: &mut Connection, sim: &mut Sim) {
    assert!(
        connected(c, s),
        "client {:?} server {:?}",
        sim.client_errors,
        sim.server_errors
    );
    let ci = c.handshake_info().unwrap().clone();
    let si = s.handshake_info().unwrap().clone();
    assert_eq!(ci.cipher_suite, si.cipher_suite);
    assert_eq!(ci.srtp_profile, si.srtp_profile);
    assert_eq!(ci.srtp_keys, si.srtp_keys);
    assert!(ci.extended_master_secret && si.extended_master_secret);
    let a = c
        .export_keying_material("EXPERIMENTAL-test", Some(b"ctx"), 40)
        .unwrap();
    let b = s
        .export_keying_material("EXPERIMENTAL-test", Some(b"ctx"), 40)
        .unwrap();
    assert_eq!(a, b);
    assert_ne!(
        a,
        c.export_keying_material("EXPERIMENTAL-test", None, 40)
            .unwrap()
    );
    assert!(matches!(
        c.export_keying_material("master secret", None, 8),
        Err(Error::Exporter(_))
    ));
    events(c);
    events(s);
    c.send_application_data(b"ping").unwrap();
    s.send_application_data(&vec![7u8; 5000]).unwrap();
    let mut got_c = Vec::new();
    let mut got_s = Vec::new();
    sim.link = PERFECT;
    sim.run(c, s, Duration::from_secs(1), |_, _| false);
    for e in events(s) {
        if let Event::ApplicationData(d) = e {
            got_s.push(d);
        }
    }
    for e in events(c) {
        if let Event::ApplicationData(d) = e {
            got_c.push(d);
        }
    }
    assert_eq!(got_s, vec![b"ping".to_vec()]);
    assert_eq!(got_c, vec![vec![7u8; 5000]]);
}

#[test]
fn webrtc_handshake_all_srtp_profiles() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    for p in SrtpProfile::ALL {
        let mut sim = Sim::new(1, PERFECT);
        let cc = Config::webrtc(
            ci.clone(),
            PeerVerifier::Fingerprints(vec![si.fingerprint()]),
        )
        .with_srtp_profiles(vec![p]);
        let sc = Config::webrtc(
            si.clone(),
            PeerVerifier::Fingerprints(vec![ci.fingerprint()]),
        )
        .with_srtp_profiles(SrtpProfile::ALL.to_vec());
        let (mut c, mut s) = pair(cc, sc, &sim);
        sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
        let ev = events(&mut c);
        let Some(Event::Connected(info)) = ev.first() else {
            panic!("{ev:?}")
        };
        assert_eq!(info.srtp_profile, Some(p));
        assert_eq!(info.peer_fingerprint.as_ref(), Some(&si.fingerprint()));
        assert_eq!(info.peer_certificates, vec![si.certificate().to_vec()]);
        let keys = info.srtp_keys.clone().unwrap();
        assert_eq!(keys.client_master_key.len(), p.master_key_len());
        assert_eq!(keys.server_master_salt.len(), p.master_salt_len());
        // The keys are the exporter output.
        let m = c
            .export_keying_material(
                only_dtls::SRTP_EXPORTER_LABEL,
                None,
                2 * (p.master_key_len() + p.master_salt_len()),
            )
            .unwrap();
        assert_eq!(keys.local(Role::Client).0, &m[..p.master_key_len()]);
        check_connected(&mut c, &mut s, &mut sim);
    }
}

#[test]
fn every_cipher_suite_and_key_type() {
    let p384 = identity_with(PrivateKey::P384(
        only_crypto::p384::SecretKey::generate().unwrap(),
    ));
    let ed = identity_with(PrivateKey::Ed25519(
        only_crypto::ed25519::SigningKey::generate().unwrap(),
    ));
    let p256 = Identity::generate_self_signed().unwrap();
    let rsa = rsa_identity();
    let client_id = Identity::generate_self_signed().unwrap();
    for suite in CipherSuite::ALL {
        let servers: Vec<&Identity> = if suite.is_ecdsa() {
            vec![&p256, &p384, &ed]
        } else {
            vec![&rsa]
        };
        for sid in servers {
            // Client certificates of every kind, too.
            for cid in [&client_id, &rsa, &ed] {
                let mut sim = Sim::new(2, PERFECT);
                let cc = Config::new(cid.clone()).with_cipher_suites(vec![suite]);
                let sc = Config::new(sid.clone()).with_hello_verify(false);
                let (mut c, mut s) = pair(cc, sc, &sim);
                sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
                assert_eq!(c.handshake_info().map(|i| i.cipher_suite), Some(suite));
                assert_eq!(
                    s.handshake_info().and_then(|i| i.peer_fingerprint.clone()),
                    Some(cid.fingerprint())
                );
                check_connected(&mut c, &mut s, &mut sim);
            }
        }
    }
}

#[test]
fn lossy_reordering_small_mtu() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = rsa_identity(); // a large certificate: several fragments at MTU 256
    let link = Link {
        loss: 25,
        dup: 10,
        jitter: 400,
    };
    let mut retransmitted = false;
    for seed in 0..24 {
        let mut sim = Sim::new(seed, link);
        let cc = Config::new(ci.clone())
            .with_mtu(256)
            .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80])
            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2))
            .with_verifier(PeerVerifier::Fingerprints(vec![si.fingerprint()]));
        let sc = Config::new(si.clone())
            .with_mtu(256)
            .with_hello_verify(seed % 2 == 0)
            .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80])
            .with_retransmit(Duration::from_millis(100), Duration::from_secs(2))
            .with_verifier(PeerVerifier::Fingerprints(vec![ci.fingerprint()]));
        let (mut c, mut s) = pair(cc, sc, &sim);
        sim.run(&mut c, &mut s, Duration::from_secs(25), connected);
        assert!(
            connected(&c, &s),
            "seed {seed}: client {:?} server {:?}",
            sim.client_errors,
            sim.server_errors
        );
        retransmitted |= sim.sent[1] > 6;
        check_connected(&mut c, &mut s, &mut sim);
    }
    assert!(
        retransmitted,
        "the lossy link never forced a retransmission"
    );
}

#[test]
fn fragments_fit_the_mtu() {
    let si = rsa_identity();
    let mut sim = Sim::new(3, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap()).with_mtu(256);
    let sc = Config::new(si).with_mtu(256).with_hello_verify(false);
    let (mut c, mut s) = pair(cc, sc, &sim);
    let mut max = 0;
    let mut count = 0;
    for _ in 0..6 {
        while let Some(d) = c.poll_transmit() {
            max = max.max(d.len());
            count += 1;
            s.handle_datagram(sim.now, &d).unwrap();
        }
        while let Some(d) = s.poll_transmit() {
            max = max.max(d.len());
            count += 1;
            c.handle_datagram(sim.now, &d).unwrap();
        }
    }
    assert!(connected(&c, &s));
    assert!(max <= 256, "datagram of {max} bytes");
    assert!(count > 6, "the RSA certificate was not fragmented");
    check_connected(&mut c, &mut s, &mut sim);
}

#[test]
fn wrong_fingerprint_fails_both_sides() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let other = Identity::generate_self_signed().unwrap();
    let mut sim = Sim::new(4, PERFECT);
    let cc = Config::webrtc(
        ci.clone(),
        PeerVerifier::Fingerprints(vec![other.fingerprint()]),
    );
    let sc = Config::webrtc(si, PeerVerifier::Fingerprints(vec![ci.fingerprint()]));
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), |c, s| {
        c.is_closed() && s.is_closed()
    });
    assert!(
        matches!(sim.client_errors.as_slice(), [Error::Certificate(_)]),
        "{:?}",
        sim.client_errors
    );
    assert_eq!(
        sim.server_errors,
        vec![Error::PeerAlert(AlertDescription::BadCertificate)]
    );
    assert!(c.handshake_info().is_none());

    // And the server rejecting the client's certificate.
    let mut sim = Sim::new(5, PERFECT);
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let cc = Config::webrtc(ci, PeerVerifier::Fingerprints(vec![si.fingerprint()]));
    let sc = Config::webrtc(si, PeerVerifier::Fingerprints(vec![other.fingerprint()]));
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), |c, s| {
        c.is_closed() && s.is_closed()
    });
    assert!(matches!(
        sim.server_errors.as_slice(),
        [Error::Certificate(_)]
    ));
    assert_eq!(
        sim.client_errors,
        vec![Error::PeerAlert(AlertDescription::BadCertificate)]
    );
}

#[test]
fn custom_verifier_sees_the_chain() {
    let ci = Identity::generate_self_signed().unwrap();
    let si = Identity::generate_self_signed().unwrap();
    let expect = si.certificate().to_vec();
    let verify: Arc<only_dtls::VerifyFn> = Arc::new(move |chain: &[Vec<u8>]| {
        if chain[0] == expect {
            Ok(())
        } else {
            Err("unknown".into())
        }
    });
    let mut sim = Sim::new(6, PERFECT);
    let cc = Config::new(ci).with_verifier(PeerVerifier::Custom(verify.clone()));
    let sc = Config::new(si);
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    check_connected(&mut c, &mut s, &mut sim);
    // The same callback refuses another server.
    let mut sim = Sim::new(7, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap())
        .with_verifier(PeerVerifier::Custom(verify));
    let sc = Config::new(Identity::generate_self_signed().unwrap());
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), |c, _| c.is_closed());
    assert_eq!(
        sim.client_errors,
        vec![Error::Certificate("unknown".into())]
    );
}

#[test]
fn replayed_and_tampered_records_are_dropped() {
    let mut sim = Sim::new(8, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap());
    let sc = Config::new(Identity::generate_self_signed().unwrap());
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert!(connected(&c, &s));
    events(&mut s);
    c.send_application_data(b"once").unwrap();
    let d = c.poll_transmit().unwrap();
    s.handle_datagram(sim.now, &d).unwrap();
    s.handle_datagram(sim.now, &d).unwrap(); // replay
    let mut bad = d.clone();
    *bad.last_mut().unwrap() ^= 1;
    s.handle_datagram(sim.now, &bad).unwrap(); // bad tag: dropped silently
    s.handle_datagram(sim.now, &d[..d.len() - 3]).unwrap(); // truncated
    let got: Vec<Event> = events(&mut s);
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(matches!(&got[0], Event::ApplicationData(x) if x == b"once"));
    // Out of order within the window is fine, once.
    let mut ds = Vec::new();
    for i in 0..5u8 {
        c.send_application_data(&[i]).unwrap();
        ds.push(c.poll_transmit().unwrap());
    }
    for d in ds.iter().rev().chain(ds.iter()) {
        s.handle_datagram(sim.now, d).unwrap();
    }
    let got: Vec<Vec<u8>> = events(&mut s)
        .into_iter()
        .filter_map(|e| match e {
            Event::ApplicationData(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(got, vec![vec![4], vec![3], vec![2], vec![1], vec![0]]);
    // An unauthenticated epoch-0 alert after the handshake is ignored.
    let alert = [21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 99, 0, 2, 2, 40];
    s.handle_datagram(sim.now, &alert).unwrap();
    assert!(s.is_connected());
}

#[test]
fn hello_verify_cookies() {
    let mut sim = Sim::new(9, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap());
    let sc = Config::new(Identity::generate_self_signed().unwrap()).with_hello_verify(true);
    let (mut c, mut s) = pair(cc, sc, &sim);
    let ch1 = c.poll_transmit().unwrap();
    s.handle_datagram(sim.now, &ch1).unwrap();
    let hvr = s.poll_transmit().unwrap();
    assert_eq!(hvr[13], 3, "HelloVerifyRequest");
    assert!(s.poll_transmit().is_none());
    c.handle_datagram(sim.now, &hvr).unwrap();
    let ch2 = c.poll_transmit().unwrap();
    // A corrupted cookie is answered with another HelloVerifyRequest, not a ServerHello.
    let mut bad = ch2.clone();
    // record(13) + handshake header(12) + version(2) + random(32) + session id len(1) +
    // cookie length(1): the cookie starts at 61.
    bad[61] ^= 0xff;
    s.handle_datagram(sim.now, &bad).unwrap();
    let again = s.poll_transmit().unwrap();
    assert_eq!(again[13], 3);
    assert!(!s.is_connected());
    // The genuine one proceeds.
    s.handle_datagram(sim.now, &ch2).unwrap();
    let flight4 = s.poll_transmit().unwrap();
    assert_eq!(flight4[13], 2, "ServerHello");
    sim.push(false, flight4);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    check_connected(&mut c, &mut s, &mut sim);
}

#[test]
fn stateless_hello_verifier() {
    let now = Instant::now();
    let v = HelloVerifier::new(now).unwrap();
    let cc = Arc::new(Config::new(Identity::generate_self_signed().unwrap()));
    let mut c = Connection::client(cc, now).unwrap();
    let ch1 = c.poll_transmit().unwrap();
    let HelloCheck::Respond(hvr) = v.check(now, b"peer-a", &ch1) else {
        panic!("expected a HelloVerifyRequest")
    };
    c.handle_datagram(now, &hvr).unwrap();
    let ch2 = c.poll_transmit().unwrap();
    assert_eq!(v.check(now, b"peer-a", &ch2), HelloCheck::Accept);
    // Another address, a later time, garbage.
    assert!(matches!(
        v.check(now, b"peer-b", &ch2),
        HelloCheck::Respond(_)
    ));
    assert_eq!(
        v.check(now + Duration::from_secs(90), b"peer-a", &ch2),
        HelloCheck::Accept
    );
    assert!(matches!(
        v.check(now + Duration::from_secs(200), b"peer-a", &ch2),
        HelloCheck::Respond(_)
    ));
    assert_eq!(v.check(now, b"peer-a", b"garbage"), HelloCheck::Drop);
    assert_eq!(v.check(now, b"peer-a", &hvr), HelloCheck::Drop);
    // A server created after the check (cookies off) completes the handshake from CH2.
    let sc =
        Arc::new(Config::new(Identity::generate_self_signed().unwrap()).with_hello_verify(false));
    let mut s = Connection::server(sc, now, b"peer-a").unwrap();
    s.handle_datagram(now, &ch2).unwrap();
    let mut sim = Sim::new(10, PERFECT);
    sim.now = now;
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    check_connected(&mut c, &mut s, &mut sim);
}

#[test]
fn handshake_timeout_and_backoff() {
    let now = Instant::now();
    let cfg = Config::new(Identity::generate_self_signed().unwrap())
        .with_retransmit(Duration::from_millis(100), Duration::from_millis(800))
        .with_handshake_timeout(Duration::from_secs(5));
    let mut c = Connection::client(Arc::new(cfg), now).unwrap();
    assert!(c.poll_transmit().is_some());
    let mut t = now;
    let mut intervals = Vec::new();
    loop {
        let next = c.poll_timeout().unwrap();
        intervals.push(next - t);
        t = next;
        match c.handle_timeout(t) {
            Ok(()) => assert!(c.poll_transmit().is_some(), "retransmission"),
            Err(e) => {
                assert_eq!(e, Error::Timeout);
                break;
            }
        }
    }
    let ms: Vec<u128> = intervals.iter().map(Duration::as_millis).collect();
    assert_eq!(&ms[..6], &[100, 200, 400, 800, 800, 800], "{ms:?}");
    assert_eq!(t - now, Duration::from_secs(5));
    assert!(c.is_closed());
    assert_eq!(c.poll_timeout(), None);
}

#[test]
fn close_notify() {
    let mut sim = Sim::new(11, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap());
    let sc = Config::new(Identity::generate_self_signed().unwrap());
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    events(&mut s);
    c.close();
    assert!(c.is_closed());
    assert_eq!(c.send_application_data(b"x"), Err(Error::Closed));
    let d = c.poll_transmit().unwrap();
    s.handle_datagram(sim.now, &d).unwrap();
    assert!(matches!(events(&mut s).as_slice(), [Event::Closed]));
    assert!(s.is_closed());
    assert!(s.poll_transmit().is_some(), "close_notify in reply");
    assert_eq!(s.handle_datagram(sim.now, &d), Err(Error::Closed));
}

#[test]
fn negotiation_failures() {
    // No shared cipher suite: the client offers only RSA suites to an ECDSA server.
    let mut sim = Sim::new(12, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap())
        .with_cipher_suites(vec![CipherSuite::EcdheRsaAes128GcmSha256]);
    let sc = Config::new(Identity::generate_self_signed().unwrap());
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), |c, _| c.is_closed());
    assert!(matches!(
        sim.server_errors.as_slice(),
        [Error::Protocol {
            alert: AlertDescription::HandshakeFailure,
            ..
        }]
    ));
    assert_eq!(
        sim.client_errors,
        vec![Error::PeerAlert(AlertDescription::HandshakeFailure)]
    );

    // A client without a certificate against a server that requires one.
    let mut sim = Sim::new(13, PERFECT);
    let cc = Config::without_identity();
    let sc = Config::new(Identity::generate_self_signed().unwrap());
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), |c, _| c.is_closed());
    assert!(matches!(
        sim.server_errors.as_slice(),
        [Error::Certificate(_)]
    ));
    assert_eq!(
        sim.client_errors,
        vec![Error::PeerAlert(AlertDescription::BadCertificate)]
    );

    // ... which works when the server does not require it.
    let mut sim = Sim::new(14, PERFECT);
    let cc = Config::without_identity();
    let sc = Config::new(Identity::generate_self_signed().unwrap())
        .with_require_client_certificate(false);
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert!(s.handshake_info().unwrap().peer_fingerprint.is_none());
    check_connected(&mut c, &mut s, &mut sim);

    // SRTP offered but not accepted: connected without a profile.
    let mut sim = Sim::new(15, PERFECT);
    let cc = Config::new(Identity::generate_self_signed().unwrap())
        .with_srtp_profiles(vec![SrtpProfile::AeadAes256Gcm]);
    let sc = Config::new(Identity::generate_self_signed().unwrap())
        .with_srtp_profiles(vec![SrtpProfile::Aes128CmHmacSha1_80]);
    let (mut c, mut s) = pair(cc, sc, &sim);
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert_eq!(c.handshake_info().unwrap().srtp_profile, None);
    check_connected(&mut c, &mut s, &mut sim);

    // Configuration errors.
    assert!(matches!(
        Connection::server(Arc::new(Config::without_identity()), Instant::now(), b""),
        Err(Error::Config(_))
    ));
    let rsa_only = Config::new(Identity::generate_self_signed().unwrap())
        .with_cipher_suites(vec![CipherSuite::EcdheRsaAes128GcmSha256]);
    assert!(Connection::server(Arc::new(rsa_only), Instant::now(), b"").is_err());
}

#[test]
fn api_misuse() {
    let now = Instant::now();
    let cfg = Arc::new(Config::new(Identity::generate_self_signed().unwrap()));
    let mut c = Connection::client(cfg, now).unwrap();
    assert_eq!(c.role(), Role::Client);
    assert_eq!(c.send_application_data(b"x"), Err(Error::NotConnected));
    assert!(c.export_keying_material("EXPERIMENTAL", None, 8).is_err());
    let mut sim = Sim::new(16, PERFECT);
    let mut s = Connection::server(
        Arc::new(Config::new(Identity::generate_self_signed().unwrap())),
        now,
        b"",
    )
    .unwrap();
    sim.now = now;
    sim.run(&mut c, &mut s, Duration::from_secs(5), connected);
    assert_eq!(
        c.send_application_data(&vec![0; 16385]),
        Err(Error::TooLarge)
    );
    c.send_application_data(&vec![0; 16384]).unwrap();
    // Garbage after the handshake changes nothing.
    for g in [&b""[..], b"\x16\xfe\xfd", &[0u8; 100]] {
        c.handle_datagram(now, g).unwrap();
    }
    assert!(c.is_connected());
}
