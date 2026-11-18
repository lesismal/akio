//! The simulated link shared by the integration tests: loss, duplication, reordering in
//! virtual time.
#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_crypto::pkey::PrivateKey;
use only_dtls::{Config, Connection, Error, Event, Identity};

/// A deterministic xorshift generator.
pub struct Rng(u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[derive(Clone, Copy)]
pub struct Link {
    pub loss: u64,
    pub dup: u64,
    /// Maximum extra delay in ms (reordering).
    pub jitter: u64,
}

pub const PERFECT: Link = Link {
    loss: 0,
    dup: 0,
    jitter: 0,
};

pub struct Sim {
    pub now: Instant,
    pub rng: Rng,
    pub link: Link,
    /// (delivery time, tiebreak) -> (to_server, datagram)
    pub queue: BTreeMap<(Instant, u64), (bool, Vec<u8>)>,
    pub n: u64,
    pub sent: [usize; 2],
    pub client_errors: Vec<Error>,
    pub server_errors: Vec<Error>,
}

impl Sim {
    pub fn new(seed: u64, link: Link) -> Sim {
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

    pub fn push(&mut self, to_server: bool, d: Vec<u8>) {
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

    pub fn flush(&mut self, c: &mut Connection, s: &mut Connection) {
        while let Some(d) = c.poll_transmit() {
            self.push(true, d);
        }
        while let Some(d) = s.poll_transmit() {
            self.push(false, d);
        }
    }

    /// Runs until `done` or the deadline (virtual time).
    pub fn run(
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

pub fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

pub fn rsa_identity() -> Identity {
    let key = PrivateKey::from_pem(include_bytes!("../data/rsa2048.pem")).unwrap();
    let cert = only_x509::CertificateParams::new(["rsa.test"])
        .self_signed(&key)
        .unwrap();
    Identity::new(vec![cert.as_der().to_vec()], key).unwrap()
}

pub fn identity_with(key: PrivateKey) -> Identity {
    let cert = only_x509::CertificateParams::new(["peer.test"])
        .self_signed(&key)
        .unwrap();
    Identity::new(vec![cert.as_der().to_vec()], key).unwrap()
}

pub fn pair(client: Config, server: Config, sim: &Sim) -> (Connection, Connection) {
    let c = Connection::client(Arc::new(client), sim.now).unwrap();
    let s = Connection::server(Arc::new(server), sim.now, b"10.0.0.1:1234").unwrap();
    (c, s)
}

pub fn connected(c: &Connection, s: &Connection) -> bool {
    c.is_connected() && s.is_connected()
}

/// Handshake, SRTP keys and exporter agreement, application data both ways.
pub fn check_connected(c: &mut Connection, s: &mut Connection, sim: &mut Sim) {
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
    assert_eq!(ci.srtp_mki, si.srtp_mki);
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
    if ci.version == only_dtls::Version::Dtls12 {
        assert!(matches!(
            c.export_keying_material("master secret", None, 8),
            Err(Error::Exporter(_))
        ));
    }
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
