//! Record-layer throughput of an established DTLS connection, in memory: the client seals
//! application data records and the server opens them (the WebRTC data channel path).
//!
//! ```text
//! dtls-bench [payload bytes] [records] [rounds]   # defaults 1024 200000 5
//! ```
//!
//! Prints the best round as `records/s` and `MB/s` per cipher suite. Uses only API that
//! existed before DTLS 1.3 so the same file measures older revisions (same-run A/B).

use std::sync::Arc;
use std::time::Instant;

use akio_dtls::{CipherSuite, Config, Connection, Event, Identity};

fn pair(suite: CipherSuite) -> (Connection, Connection) {
    let ci = Identity::generate_self_signed().expect("identity");
    let si = Identity::generate_self_signed().expect("identity");
    let now = Instant::now();
    let cc = Config::new(ci).with_cipher_suites(vec![suite]);
    let sc = Config::new(si).with_hello_verify(false);
    let mut c = Connection::client(Arc::new(cc), now).expect("client");
    let mut s = Connection::server(Arc::new(sc), now, b"bench").expect("server");
    for _ in 0..10 {
        while let Some(d) = c.poll_transmit() {
            s.handle_datagram(now, &d).expect("server");
        }
        while let Some(d) = s.poll_transmit() {
            c.handle_datagram(now, &d).expect("client");
        }
    }
    assert!(c.is_connected() && s.is_connected());
    while c.poll_event().is_some() {}
    while s.poll_event().is_some() {}
    (c, s)
}

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("number"))
        .collect();
    let size = args.first().copied().unwrap_or(1024);
    let n = args.get(1).copied().unwrap_or(200_000);
    let rounds = args.get(2).copied().unwrap_or(5);
    let payload = vec![0x5au8; size];
    for suite in [
        CipherSuite::EcdheEcdsaAes128GcmSha256,
        CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
    ] {
        let (mut c, mut s) = pair(suite);
        let now = Instant::now();
        let mut best = f64::MAX;
        for _ in 0..rounds {
            let t = Instant::now();
            for _ in 0..n {
                c.send_application_data(&payload).expect("send");
                let d = c.poll_transmit().expect("datagram");
                s.handle_datagram(now, &d).expect("open");
                match s.poll_event() {
                    Some(Event::ApplicationData(x)) => assert_eq!(x.len(), size),
                    other => panic!("{other:?}"),
                }
            }
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!(
            "{suite} payload={size}: {:.0} records/s, {:.1} MB/s",
            n as f64 / best,
            (n * size) as f64 / best / 1e6
        );
    }
}
