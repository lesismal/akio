//! Handshakes per second (DTLS 1.2 and DTLS 1.3 full handshakes, DTLS 1.3 resumption) and
//! DTLS 1.3 record throughput, in memory.
//!
//! ```text
//! dtls-hs-bench [handshakes] [records] [rounds]   # defaults 300 200000 5
//! ```
//!
//! Prints the best round of each. Uses only API from ADR-021 (DTLS 1.3, resumption), so the
//! same file measures the revisions before ADR-045 (same-run A/B).

use std::sync::Arc;
use std::time::Instant;

use akio_dtls::{CipherSuite, Config, Connection, Event, Identity, Session, TicketKey, Version};

fn run(c: &mut Connection, s: &mut Connection, now: Instant) {
    for _ in 0..10 {
        while let Some(d) = c.poll_transmit() {
            s.handle_datagram(now, &d).expect("server");
        }
        while let Some(d) = s.poll_transmit() {
            c.handle_datagram(now, &d).expect("client");
        }
        if c.is_connected() && s.is_connected() && c.poll_timeout().is_none() {
            break;
        }
    }
    assert!(c.is_connected() && s.is_connected());
}

/// One handshake (resuming `resume`), returning the client's new session.
fn handshake(cc: &Arc<Config>, sc: &Arc<Config>, resume: Option<&Session>) -> Option<Session> {
    let now = Instant::now();
    let mut c = match resume {
        Some(r) => Connection::client_resume(cc.clone(), now, r),
        None => Connection::client(cc.clone(), now),
    }
    .expect("client");
    let mut s = Connection::server(sc.clone(), now, b"bench").expect("server");
    run(&mut c, &mut s, now);
    let mut session = None;
    while let Some(e) = c.poll_event() {
        if let Event::NewSession(x) = e {
            session = Some(*x);
        }
    }
    session
}

fn best(rounds: usize, n: usize, mut f: impl FnMut()) -> f64 {
    let mut best = 0f64;
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        best = best.max(n as f64 / t.elapsed().as_secs_f64());
    }
    best
}

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("number"))
        .collect();
    let hs = args.first().copied().unwrap_or(300);
    let records = args.get(1).copied().unwrap_or(200_000);
    let rounds = args.get(2).copied().unwrap_or(5);
    let ci = Identity::generate_self_signed().expect("identity");
    let si = Identity::generate_self_signed().expect("identity");
    let key = TicketKey::from_secret(&[7; 32]).expect("ticket key");
    let cfg = |id: &Identity, v: Vec<Version>| {
        Config::new(id.clone())
            .with_versions(v)
            .with_hello_verify(false)
            .with_session_resumption(true)
            .with_ticket_key(key.clone())
    };
    for (name, v) in [
        ("dtls1.2", vec![Version::Dtls12]),
        ("dtls1.3", vec![Version::Dtls13]),
    ] {
        let cc = Arc::new(cfg(&ci, v.clone()));
        let sc = Arc::new(cfg(&si, v));
        let full = best(rounds, hs, || {
            handshake(&cc, &sc, None);
        });
        println!("{name} full handshakes/s {full:.0}");
        if name == "dtls1.3" {
            let session = handshake(&cc, &sc, None).expect("ticket");
            let resumed = best(rounds, hs, || {
                handshake(&cc, &sc, Some(&session));
            });
            println!("{name} resumed handshakes/s {resumed:.0}");
        }
    }
    for suite in [
        CipherSuite::Tls13Aes128GcmSha256,
        CipherSuite::Tls13Chacha20Poly1305Sha256,
    ] {
        for size in [64usize, 1024] {
            let cc = Arc::new(cfg(&ci, vec![Version::Dtls13]).with_cipher_suites(vec![suite]));
            let sc = Arc::new(cfg(&si, vec![Version::Dtls13]));
            let now = Instant::now();
            let mut c = Connection::client(cc, now).expect("client");
            let mut s = Connection::server(sc, now, b"bench").expect("server");
            run(&mut c, &mut s, now);
            while c.poll_event().is_some() {}
            while s.poll_event().is_some() {}
            let payload = vec![0x5au8; size];
            let rate = best(rounds, records, || {
                c.send_application_data(&payload).expect("send");
                let d = c.poll_transmit().expect("record");
                s.handle_datagram(now, &d).expect("open");
                let _ = s.poll_event();
            });
            println!(
                "{suite:?} {size} B records/s {rate:.0} MB/s {:.1}",
                rate * size as f64 / 1e6
            );
        }
    }
}
