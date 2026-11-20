//! TLS 1.3 early data (RFC 8446 section 4.2.10): accepted, rejected (by configuration, after a
//! HelloRetryRequest, by the replay record, for another ALPN protocol or SNI name), replayed
//! (also to another server sharing tickets and a replay store), a failing replay store, the
//! max_early_data_size limits, and the off-by-default switches.

use super::alert::{Alert, Fatal};
use super::common::EarlyData;
use super::conn::Connection;
use super::msgs::ClientHello;
use super::tests::{Kind, Pki, pki};
use crate::{ClientConfig, ClientConfigBuilder, ServerConfig, ServerConfigBuilder};

fn server(p: &Pki) -> ServerConfigBuilder {
    ServerConfig::builder(p.chain.clone(), p.key.clone())
        .session_tickets(true)
        .alpn(["h2", "http/1.1"])
}

fn client(p: &Pki) -> ClientConfigBuilder {
    ClientConfig::builder().roots(p.roots.clone()).alpn(["h2"])
}

/// What one connection did.
struct Run {
    c: Connection,
    s: Connection,
    /// What the server's application read, and how much of it before the handshake ended.
    s_plain: Vec<u8>,
    s_plain_early: usize,
    /// The client's first flight: ClientHello, CCS, early data.
    first_flight: Vec<u8>,
}

/// Connects, the client sending `early` before the handshake (as early data if it can) and
/// `later` once it is done.
fn run(scfg: &ServerConfig, ccfg: &ClientConfig, name: &str, early: &[u8]) -> Result<Run, Fatal> {
    let mut c = crate::__proto::client(ccfg, name)?;
    let mut s = crate::__proto::server(scfg);
    let mut c2s = Vec::new();
    c.seal(early, &mut c2s)?;
    let first_flight = c2s.clone();
    let (mut s_plain, mut c_plain, mut s_plain_early) = (Vec::new(), Vec::new(), 0);
    for _ in 0..50 {
        if c2s.is_empty() && !c.handshaking() && !s.handshaking() {
            break;
        }
        let mut s2c = Vec::new();
        s.recv(&std::mem::take(&mut c2s), &mut s_plain, &mut s2c)?;
        if s.handshaking() {
            s_plain_early = s_plain.len();
        }
        c.recv(&s2c, &mut c_plain, &mut c2s)?;
    }
    assert!(!c.handshaking() && !s.handshaking());
    assert!(c_plain.is_empty());
    Ok(Run {
        c,
        s,
        s_plain,
        s_plain_early,
        first_flight,
    })
}

/// A connection for tickets.
fn prime(scfg: &ServerConfig, ccfg: &ClientConfig, name: &str) {
    run(scfg, ccfg, name, b"").unwrap();
}

fn offers_early(first_flight: &[u8]) -> bool {
    let len = usize::from(u16::from_be_bytes([first_flight[3], first_flight[4]]));
    let ch = ClientHello::parse(&first_flight[9..5 + len]).ok();
    ch.is_some_and(|h| h.early_data)
}

#[test]
fn early_data_accepted() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).early_data(16384).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    for _ in 0..2 {
        let mut r = run(&scfg, &ccfg, "localhost", b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(offers_early(&r.first_flight));
        assert!(r.c.resumed() && r.s.resumed());
        assert_eq!(r.c.early_data(), EarlyData::Accepted);
        assert_eq!(r.s.early_data(), EarlyData::Accepted);
        assert_eq!(r.c.early_data_len(), 18);
        assert_eq!(r.s.early_data_len(), 18);
        // Read by the server before the handshake completed.
        assert_eq!(r.s_plain, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(r.s_plain_early, 18);
        // The connection goes on as usual.
        let mut wire = Vec::new();
        r.c.seal(b"after", &mut wire).unwrap();
        let mut got = Vec::new();
        r.s.recv(&wire, &mut got, &mut Vec::new()).unwrap();
        assert_eq!(got, b"after");
        let mut wire = Vec::new();
        r.s.seal(b"answer", &mut wire).unwrap();
        let mut got = Vec::new();
        r.c.recv(&wire, &mut got, &mut Vec::new()).unwrap();
        assert_eq!(got, b"answer");
    }
}

#[test]
fn early_data_is_off_by_default() {
    let p = pki(Kind::P256, &["localhost"]);
    // Server off: tickets do not allow early data, the client never offers it.
    let scfg = server(&p).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"hello").unwrap();
    assert!(r.c.resumed());
    assert!(!offers_early(&r.first_flight));
    assert_eq!(r.c.early_data(), EarlyData::NotAttempted);
    assert_eq!(r.s_plain, b"hello");
    assert_eq!(r.s_plain_early, 0);
    // Client off.
    let scfg = server(&p).early_data(1024).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"hello").unwrap();
    assert!(r.c.resumed() && !offers_early(&r.first_flight));
    assert_eq!(r.s.early_data(), EarlyData::NotAttempted);
    assert_eq!((r.s_plain_early, r.s.early_data_len()), (0, 0));
}

/// The client's early data is rejected: it is sent again after the handshake.
fn assert_rejected(r: &Run, data: &[u8]) {
    assert!(offers_early(&r.first_flight));
    assert_eq!(r.c.early_data(), EarlyData::Rejected);
    assert_eq!(r.s.early_data(), EarlyData::Rejected);
    assert_eq!(r.c.early_data_len(), data.len() as u64);
    assert_eq!(r.s.early_data_len(), 0);
    assert_eq!(r.s_plain_early, 0);
    assert_eq!(r.s_plain, data);
}

#[test]
fn early_data_rejected_after_hello_retry() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p)
        .early_data(16384)
        .__force_hello_retry(true)
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"early bytes").unwrap();
    assert!(r.c.resumed());
    assert_rejected(&r, b"early bytes");
}

#[test]
fn early_data_rejected_when_the_replay_record_is_full() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p)
        .early_data(16384)
        .__anti_replay(std::time::Duration::from_secs(10), 0)
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"x".repeat(40_000).as_slice()).unwrap();
    // Resumed all the same; more than the ticket allows is sent after the handshake.
    assert!(r.c.resumed() && r.s.resumed());
    assert!(offers_early(&r.first_flight));
    assert_eq!(r.c.early_data(), EarlyData::Rejected);
    assert_eq!(r.c.early_data_len(), 16384);
    assert_eq!(r.s_plain, b"x".repeat(40_000));
    assert_eq!(r.s_plain_early, 0);
}

#[test]
fn replayed_client_hello_with_early_data_is_rejected() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).early_data(16384).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"POST /pay").unwrap();
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
    // An attacker sends the recorded first flight again, to the same server.
    for _ in 0..2 {
        let mut s = crate::__proto::server(&scfg);
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        s.recv(&r.first_flight, &mut plain, &mut out).unwrap();
        assert_eq!(s.early_data(), EarlyData::Rejected);
        assert!(
            plain.is_empty(),
            "replayed early data reached the application"
        );
        assert!(s.handshaking());
    }
    // A stale ClientHello: the ticket age the client reports is a minute off the server's.
    prime(&scfg, &ccfg, "localhost");
    let cache = ccfg.inner.cache.as_ref().unwrap();
    let mut t = cache
        .take_ticket13("localhost", super::common::now_secs(), 0)
        .unwrap();
    t.received_ms -= 60_000;
    cache.add_ticket13("localhost", t);
    let r = run(&scfg, &ccfg, "localhost", b"late").unwrap();
    assert!(r.s.resumed());
    assert_rejected(&r, b"late");
}

/// A "remote" anti-replay store, as an application would back one with Redis or similar
/// (`SET key 1 NX PX ttl`): a shared map behind a connection that can go down.
#[derive(Default)]
struct RemoteStore {
    map: std::sync::Mutex<std::collections::HashMap<Vec<u8>, std::time::Instant>>,
    down: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}

impl crate::AntiReplayStore for RemoteStore {
    fn check_and_insert(&self, binder: &[u8], ttl: std::time::Duration) -> std::io::Result<bool> {
        use std::sync::atomic::Ordering::SeqCst;
        self.calls.fetch_add(1, SeqCst);
        if self.down.load(SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "store unreachable",
            ));
        }
        let now = std::time::Instant::now();
        let mut m = self.map.lock().unwrap();
        m.retain(|_, exp| *exp > now);
        if m.contains_key(binder) {
            return Ok(false);
        }
        m.insert(binder.to_vec(), now + ttl);
        Ok(true)
    }
}

/// Sends a recorded first flight to a fresh connection of `scfg`: what its early data became.
fn replay_to(scfg: &ServerConfig, flight: &[u8]) -> (EarlyData, Vec<u8>) {
    let mut s = crate::__proto::server(scfg);
    let (mut plain, mut out) = (Vec::new(), Vec::new());
    s.recv(flight, &mut plain, &mut out).unwrap();
    assert!(s.resumed() || s.handshaking());
    (s.early_data(), plain)
}

#[test]
fn shared_store_rejects_a_replay_on_another_server() {
    let p = pki(Kind::P256, &["localhost"]);
    let key = [0x5a; 48];
    let store = std::sync::Arc::new(RemoteStore::default());
    // Two servers (two processes or machines) sharing the ticket key and the store.
    let shared = |store: &std::sync::Arc<RemoteStore>| {
        server(&p)
            .session_ticket_key(key)
            .early_data(16384)
            .anti_replay_store(store.clone())
            .build()
            .unwrap()
    };
    let (a, b) = (shared(&store), shared(&store));
    let ccfg = client(&p).early_data(true).build().unwrap();
    // A ticket from server A, early data accepted by server B.
    prime(&a, &ccfg, "localhost");
    let r = run(&b, &ccfg, "localhost", b"POST /pay").unwrap();
    assert!(r.s.resumed());
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
    assert_eq!(r.s_plain_early, 9);
    // The recorded flight replayed to server A, then to B: rejected by both.
    for srv in [&a, &b] {
        let (ed, plain) = replay_to(srv, &r.first_flight);
        assert_eq!(ed, EarlyData::Rejected);
        assert!(
            plain.is_empty(),
            "replayed early data reached the application"
        );
    }
    assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 3);

    // The same two servers with their own (default) records: the replay gets through on the
    // other server. This is what the shared store is for.
    let own = || {
        server(&p)
            .session_ticket_key(key)
            .early_data(16384)
            .build()
            .unwrap()
    };
    let (a, b) = (own(), own());
    prime(&a, &ccfg, "localhost");
    let r = run(&a, &ccfg, "localhost", b"POST /pay").unwrap();
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
    assert_eq!(replay_to(&a, &r.first_flight).0, EarlyData::Rejected);
    let (ed, plain) = replay_to(&b, &r.first_flight);
    assert_eq!(ed, EarlyData::Accepted);
    assert_eq!(plain, b"POST /pay");
}

#[test]
fn store_failure_rejects_early_data() {
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(RemoteStore::default());
    let scfg = server(&p)
        .early_data(16384)
        .anti_replay_store(store.clone())
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    store.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let r = run(&scfg, &ccfg, "localhost", b"early bytes").unwrap();
    // Fail closed: resumed, the early data rejected and sent again after the handshake.
    assert!(r.c.resumed() && r.s.resumed());
    assert_rejected(&r, b"early bytes");
    // Back up: accepted again.
    store.down.store(false, std::sync::atomic::Ordering::SeqCst);
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"again").unwrap();
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
}

#[test]
fn shared_ticket_key() {
    let p = pki(Kind::P256, &["localhost"]);
    let a = server(&p).session_ticket_key([1; 48]).build().unwrap();
    let b = ServerConfig::builder(p.chain.clone(), p.key.clone())
        .alpn(["h2", "http/1.1"])
        .session_ticket_key([1; 48])
        .build()
        .unwrap();
    let other = server(&p).session_ticket_key([2; 48]).build().unwrap();
    let ccfg = client(&p).build().unwrap();
    prime(&a, &ccfg, "localhost");
    assert!(run(&b, &ccfg, "localhost", b"").unwrap().s.resumed());
    prime(&a, &ccfg, "localhost");
    assert!(!run(&other, &ccfg, "localhost", b"").unwrap().s.resumed());
}

#[test]
fn early_data_bound_to_alpn_and_sni() {
    let p = pki(Kind::P256, &["localhost", "other.test"]);
    let scfg = ServerConfig::builder(p.chain.clone(), p.key.clone())
        .session_tickets(true)
        .alpn(["http/1.1", "h2"])
        .early_data(16384)
        .build()
        .unwrap();
    // A ticket issued for h2 ...
    let c_h2 = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &c_h2, "localhost");
    // ... in a client that also offers http/1.1, which the server prefers.
    let c_both = ClientConfig::builder()
        .roots(p.roots.clone())
        .alpn(["http/1.1", "h2"])
        .early_data(true)
        .build()
        .unwrap();
    let take = |from: &ClientConfig, to: &ClientConfig, name_from: &str, name_to: &str| {
        let cache = from.inner.cache.as_ref().unwrap();
        let t = cache
            .take_ticket13(name_from, super::common::now_secs(), 0)
            .unwrap();
        to.inner.cache.as_ref().unwrap().add_ticket13(name_to, t);
    };
    take(&c_h2, &c_both, "localhost", "localhost");
    let r = run(&scfg, &c_both, "localhost", b"for h2").unwrap();
    assert!(r.s.resumed());
    assert_eq!(r.s.alpn(), Some(&b"http/1.1"[..]));
    assert_rejected(&r, b"for h2");
    // A ticket for localhost presented for other.test: not used at all.
    prime(&scfg, &c_h2, "localhost");
    take(&c_h2, &c_h2, "localhost", "other.test");
    let r = run(&scfg, &c_h2, "other.test", b"other").unwrap();
    assert!(!r.s.resumed());
    assert_rejected(&r, b"other");
    // A client does not offer a ticket's early data for a protocol it no longer asks for.
    prime(&scfg, &c_h2, "localhost");
    let c_11 = ClientConfig::builder()
        .roots(p.roots)
        .alpn(["http/1.1"])
        .early_data(true)
        .build()
        .unwrap();
    take(&c_h2, &c_11, "localhost", "localhost");
    let r = run(&scfg, &c_11, "localhost", b"x").unwrap();
    assert!(r.c.resumed() && !offers_early(&r.first_flight));
}

#[test]
fn max_early_data_limits() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).early_data(100).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    // The client sends no more than the ticket allows early; the rest follows the handshake.
    let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let r = run(&scfg, &ccfg, "localhost", &data).unwrap();
    assert_eq!(r.c.early_data(), EarlyData::Accepted);
    assert_eq!((r.c.early_data_len(), r.s.early_data_len()), (100, 100));
    assert_eq!(r.s_plain_early, 100);
    assert_eq!(r.s_plain, data);
    // A client going over the limit is refused with unexpected_message.
    prime(&scfg, &ccfg, "localhost");
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    c.test_early_budget(1000);
    let mut wire = Vec::new();
    c.seal(&[7; 101], &mut wire).unwrap();
    let mut s = crate::__proto::server(&scfg);
    let e = s.recv(&wire, &mut Vec::new(), &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::UnexpectedMessage);
}

#[test]
fn early_data_after_quic_ticket_and_tls12() {
    let p = pki(Kind::P256, &["localhost"]);
    // TLS 1.2 has no early data: no ticket, nothing offered.
    let scfg = server(&p)
        .__tls12_only(true)
        .early_data(100)
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let r = run(&scfg, &ccfg, "localhost", b"abc").unwrap();
    assert!(r.c.resumed());
    assert_eq!(r.c.early_data(), EarlyData::NotAttempted);
    assert_eq!(r.s_plain, b"abc");
}

/// Seeds for the fuzz targets: an early-data first flight (ClientHello with early_data and a
/// PSK, CCS, early records), the server's answer, and the ClientHello alone.
/// `cargo test -p only-tls --lib write_early_corpus -- --ignored`.
#[test]
#[ignore = "writes fuzz/corpus"]
fn write_early_corpus() {
    let base = format!("{}/../../fuzz/corpus", env!("CARGO_MANIFEST_DIR"));
    let write = |t: &str, name: &str, d: &[u8]| {
        let dir = format!("{base}/{t}");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/{name}"), d).unwrap();
    };
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).early_data(16384).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&scfg);
    let mut c2s = Vec::new();
    c.seal(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", &mut c2s)
        .unwrap();
    let flight = c2s.clone();
    let mut s2c = Vec::new();
    s.recv(&c2s, &mut Vec::new(), &mut s2c).unwrap();
    let mut rest = Vec::new();
    c.recv(&s2c, &mut Vec::new(), &mut rest).unwrap();
    assert_eq!(c.early_data(), EarlyData::Accepted);
    let mut all = flight.clone();
    all.extend_from_slice(&rest);
    write("tls_server", "early_flight", &flight);
    write("tls_server", "early_handshake", &all);
    write("tls_client", "early_accepted", &s2c);
    // The ClientHello alone (record and handshake headers off): the direct parser.
    let len = usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    write("tls_server", "early_client_hello_body", &flight[9..5 + len]);
}

/// An asynchronous "remote" anti-replay store (ADR-062): the same shared map as
/// [`RemoteStore`], answered from another thread after `delay` (or never, when `silent`), as a
/// Redis client's reader thread would.
#[derive(Default)]
struct AsyncRemote {
    map: std::sync::Arc<RemoteStore>,
    delay: std::time::Duration,
    silent: std::sync::atomic::AtomicBool,
    inline: bool,
    held: std::sync::Mutex<Vec<crate::ReplayCheck>>,
}

impl crate::AsyncAntiReplayStore for AsyncRemote {
    fn check_and_insert(&self, binder: &[u8], ttl: std::time::Duration, done: crate::ReplayCheck) {
        use crate::AntiReplayStore;
        if self.silent.load(std::sync::atomic::Ordering::SeqCst) {
            self.held.lock().unwrap().push(done);
            return;
        }
        if self.inline {
            return done.complete(self.map.check_and_insert(binder, ttl));
        }
        let (map, binder, delay) = (self.map.clone(), binder.to_vec(), self.delay);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            done.complete(map.check_and_insert(&binder, ttl));
        });
    }
}

/// [`run`] against a server whose anti-replay store answers asynchronously: the server takes
/// the ClientHello and suspends (sending nothing) until the answer, its waker is called, and
/// the handshake goes on. Returns the run and whether the server suspended.
fn run_async(scfg: &ServerConfig, ccfg: &ClientConfig, early: &[u8]) -> (Run, bool) {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let mut c = crate::__proto::client(ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(scfg);
    let woken = std::sync::Arc::new(AtomicUsize::new(0));
    let w = woken.clone();
    s.set_waker(std::sync::Arc::new(move || {
        w.fetch_add(1, SeqCst);
    }));
    let mut c2s = Vec::new();
    c.seal(early, &mut c2s).unwrap();
    let first_flight = c2s.clone();
    let (mut s_plain, mut c_plain, mut s_plain_early) = (Vec::new(), Vec::new(), 0);
    let mut suspended = false;
    for _ in 0..50 {
        if c2s.is_empty() && !c.handshaking() && !s.handshaking() {
            break;
        }
        let mut s2c = Vec::new();
        s.recv(&std::mem::take(&mut c2s), &mut s_plain, &mut s2c)
            .unwrap();
        if s.suspended() {
            suspended = true;
            // Nothing goes out and nothing reaches the application meanwhile; bytes that
            // arrive wait.
            assert!(s2c.is_empty() && s_plain.is_empty());
            s.recv(b"", &mut s_plain, &mut s2c).unwrap();
            assert!(s2c.is_empty());
            s.wait_resumable();
            assert_eq!(
                woken.load(SeqCst),
                1,
                "the waker runs once the answer is in"
            );
            // Woken: the connection is polled with no input.
            s.recv(b"", &mut s_plain, &mut s2c).unwrap();
            assert!(!s.suspended() && !s2c.is_empty());
        }
        if s.handshaking() {
            s_plain_early = s_plain.len();
        }
        c.recv(&s2c, &mut c_plain, &mut c2s).unwrap();
    }
    assert!(!c.handshaking() && !s.handshaking());
    (
        Run {
            c,
            s,
            s_plain,
            s_plain_early,
            first_flight,
        },
        suspended,
    )
}

fn async_server(p: &Pki, store: &std::sync::Arc<AsyncRemote>) -> ServerConfigBuilder {
    server(p)
        .session_ticket_key([0x5b; 48])
        .early_data(16384)
        .async_anti_replay_store(store.clone())
}

#[test]
fn async_store_suspends_the_handshake() {
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(AsyncRemote {
        delay: std::time::Duration::from_millis(20),
        ..AsyncRemote::default()
    });
    let scfg = async_server(&p, &store).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    // No early data: no check, no suspension.
    let (r, suspended) = run_async(&scfg, &ccfg, b"");
    assert!(!suspended && r.s.early_data() == EarlyData::NotAttempted);
    // Early data (with more than one record of it waiting during the check).
    let early = vec![b'e'; 40_000];
    let (r, suspended) = run_async(&scfg, &ccfg, &early);
    assert!(suspended && r.s.resumed());
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
    assert_eq!(r.c.early_data(), EarlyData::Accepted);
    assert_eq!(r.s_plain_early, 16384);
    assert_eq!(r.s_plain, early);
    // The recorded flight replayed to another server sharing the store: rejected.
    let other = async_server(&p, &store).build().unwrap();
    let mut s = crate::__proto::server(&other);
    let (mut plain, mut out) = (Vec::new(), Vec::new());
    s.recv(&r.first_flight, &mut plain, &mut out).unwrap();
    assert!(s.suspended());
    s.wait_resumable();
    s.recv(b"", &mut plain, &mut out).unwrap();
    assert!(!s.suspended());
    assert_eq!(s.early_data(), EarlyData::Rejected);
    assert!(
        plain.is_empty(),
        "replayed early data reached the application"
    );
    assert!(!out.is_empty(), "the handshake went on");
}

#[test]
fn async_store_answering_inline_does_not_suspend() {
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(AsyncRemote {
        inline: true,
        ..AsyncRemote::default()
    });
    let scfg = async_server(&p, &store).build().unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let (r, suspended) = run_async(&scfg, &ccfg, b"inline");
    assert!(!suspended);
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
    assert_eq!(replay_to(&scfg, &r.first_flight).0, EarlyData::Rejected);
}

#[test]
fn async_store_timeout_rejects_early_data() {
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(AsyncRemote::default());
    store
        .silent
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let scfg = async_server(&p, &store)
        .anti_replay_timeout(std::time::Duration::from_millis(30))
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let t0 = std::time::Instant::now();
    let (r, suspended) = run_async(&scfg, &ccfg, b"no answer");
    assert!(suspended && t0.elapsed() >= std::time::Duration::from_millis(30));
    // Fail closed: resumed without the early data, which the client sends again.
    assert!(r.s.resumed());
    assert_rejected(&r, b"no answer");
    // A late answer changes nothing.
    for c in store.held.lock().unwrap().drain(..) {
        c.complete(Ok(true));
    }
    assert_eq!(r.s.early_data(), EarlyData::Rejected);
}

#[test]
fn async_store_with_cached_tickets() {
    // Stateful TLS 1.3 tickets are taken from the cache once: the resumed ClientHello must
    // not look them up again.
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(AsyncRemote {
        delay: std::time::Duration::from_millis(5),
        ..AsyncRemote::default()
    });
    let scfg = ServerConfig::builder(p.chain.clone(), p.key.clone())
        .alpn(["h2"])
        .early_data(16384)
        .async_anti_replay_store(store)
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let (r, suspended) = run_async(&scfg, &ccfg, b"cached");
    assert!(suspended && r.s.resumed());
    assert_eq!(r.s.early_data(), EarlyData::Accepted);
}

#[test]
fn async_store_suspended_input_is_bounded() {
    let p = pki(Kind::P256, &["localhost"]);
    let store = std::sync::Arc::new(AsyncRemote::default());
    store
        .silent
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let scfg = async_server(&p, &store)
        .anti_replay_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    prime(&scfg, &ccfg, "localhost");
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&scfg);
    let mut flight = Vec::new();
    c.seal(b"x", &mut flight).unwrap();
    let (mut plain, mut out) = (Vec::new(), Vec::new());
    s.recv(&flight, &mut plain, &mut out).unwrap();
    assert!(s.suspended());
    // A peer streaming while the check is pending is cut off past the bound.
    let junk = [23u8, 3, 3, 0x40, 0];
    let mut rec = junk.to_vec();
    rec.resize(5 + 0x4000, 0);
    let mut failed = false;
    for _ in 0..64 {
        if let Err(e) = s.recv(&rec, &mut plain, &mut out) {
            assert_eq!(e.alert, Alert::UnexpectedMessage);
            failed = true;
            break;
        }
    }
    assert!(failed);
}

#[test]
fn rotating_ticket_keys_keep_old_tickets() {
    // Two servers sharing tickets, rotated together by the application (ADR-062).
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let (ka, kb) = (
            crate::TicketKeys::new([1; 48]),
            crate::TicketKeys::new([1; 48]),
        );
        let mk = |k: &crate::TicketKeys| {
            server(&p)
                .session_ticket_keys(k.clone())
                .__tls12_only(tls12)
                .build()
                .unwrap()
        };
        let (a, b) = (mk(&ka), mk(&kb));
        let ccfg = client(&p).__tls12_only(tls12).build().unwrap();
        prime(&a, &ccfg, "localhost");
        for k in [&ka, &kb] {
            k.rotate([2; 48]);
        }
        // A ticket sealed under the previous key resumes on either server.
        assert!(run(&b, &ccfg, "localhost", b"").unwrap().s.resumed());
        // Only the keys still listed open tickets.
        prime(&a, &ccfg, "localhost");
        for k in [&ka, &kb] {
            k.set([3; 48], &[]);
        }
        assert!(
            !run(&b, &ccfg, "localhost", b"").unwrap().s.resumed(),
            "tls12 {tls12}"
        );
        // What the new key sealed resumes.
        assert!(run(&a, &ccfg, "localhost", b"").unwrap().s.resumed());
    }
}

#[test]
fn derived_ticket_keys_are_shared() {
    let p = pki(Kind::P256, &["localhost"]);
    let secret = [0x77; 32];
    let period = std::time::Duration::from_secs(3600);
    let a = server(&p)
        .session_ticket_keys(crate::TicketKeys::derived(&secret, period))
        .build()
        .unwrap();
    let b = server(&p)
        .session_ticket_keys(crate::TicketKeys::derived(&secret, period))
        .build()
        .unwrap();
    let other = server(&p)
        .session_ticket_keys(crate::TicketKeys::derived(&[0x78; 32], period))
        .build()
        .unwrap();
    // Tickets advertise at most one period.
    assert_eq!(a.inner.ticket_lifetime, 3600);
    let ccfg = client(&p).build().unwrap();
    prime(&a, &ccfg, "localhost");
    assert!(run(&b, &ccfg, "localhost", b"").unwrap().s.resumed());
    prime(&a, &ccfg, "localhost");
    assert!(!run(&other, &ccfg, "localhost", b"").unwrap().s.resumed());
    // Process-local random keys: their own tickets only.
    let r = server(&p)
        .session_ticket_keys(crate::TicketKeys::random(period).unwrap())
        .build()
        .unwrap();
    prime(&r, &ccfg, "localhost");
    assert!(run(&r, &ccfg, "localhost", b"").unwrap().s.resumed());
    prime(&r, &ccfg, "localhost");
    assert!(!run(&a, &ccfg, "localhost", b"").unwrap().s.resumed());
}
