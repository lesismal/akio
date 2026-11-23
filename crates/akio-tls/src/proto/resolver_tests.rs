//! Certificates chosen per handshake by a resolver (ADR-093): answered inline and later from
//! another thread, TLS 1.3 and 1.2, HelloRetryRequest, resumption not asking, `use_default`
//! with and without a default chain, alerts, a dropped answer, the timeout, the bound on
//! waiting handshakes, a connection dropped while waiting, and `CertStore`.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::alert::Alert;
use super::conn::Connection;
use super::tests::{Kind, Pki, Side, pki};
use crate::{
    CertAlert, CertDone, CertResolver, CertStore, CertifiedKey, ClientConfig, ClientHelloInfo,
    ServerConfig,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// Answers from the store inside the call.
    Inline,
    /// Answers from the store on another thread after the delay.
    Thread(Duration),
    /// Keeps the answer (tests answer or drop it).
    Hold,
    /// `use_default`.
    Default,
    /// `fail` with this alert.
    Fail(CertAlert),
    /// Drops the answer.
    Drop,
}

/// What a resolver saw of one ClientHello.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    pub(crate) name: Option<String>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) version: &'static str,
    pub(crate) quic: bool,
    pub(crate) schemes: usize,
    pub(crate) suites: usize,
}

pub(crate) struct TestResolver {
    pub(crate) store: CertStore,
    pub(crate) mode: Mutex<Mode>,
    pub(crate) calls: AtomicUsize,
    pub(crate) seen: Mutex<Vec<Seen>>,
    pub(crate) held: Mutex<Vec<CertDone>>,
}

impl TestResolver {
    pub(crate) fn new(mode: Mode) -> Arc<TestResolver> {
        Arc::new(TestResolver {
            store: CertStore::new(),
            mode: Mutex::new(mode),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(SeqCst)
    }
}

impl CertResolver for TestResolver {
    fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone) {
        self.calls.fetch_add(1, SeqCst);
        self.seen.lock().unwrap().push(Seen {
            name: hello.server_name().map(str::to_owned),
            alpn: hello.alpn().iter().map(|p| p.to_vec()).collect(),
            version: hello.version(),
            quic: hello.is_quic(),
            schemes: hello.signature_schemes().len(),
            suites: hello.cipher_suites().len(),
        });
        assert!(!done.is_abandoned());
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Inline => self.store.resolve(hello, done),
            Mode::Thread(delay) => {
                let key = self.store.get(hello.server_name());
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    match key {
                        Some(k) => done.complete(k),
                        None => done.use_default(),
                    }
                });
            }
            Mode::Hold => self.held.lock().unwrap().push(done),
            Mode::Default => done.use_default(),
            Mode::Fail(a) => done.fail(a),
            Mode::Drop => drop(done),
        }
    }
}

fn certified(p: &Pki) -> CertifiedKey {
    CertifiedKey::new(p.chain.clone(), p.key.clone()).unwrap()
}

/// A configuration whose default chain is `default`, resolving with `r`.
fn server(default: &Pki, r: &Arc<TestResolver>) -> crate::ServerConfigBuilder {
    ServerConfig::builder(default.chain.clone(), default.key.clone())
        .cert_resolver(r.clone())
        .alpn(["h2", "http/1.1"])
}

fn client(p: &Pki, tls12: bool) -> ClientConfig {
    ClientConfig::builder()
        .roots(p.roots.clone())
        .alpn(["h2"])
        .__tls12_only(tls12)
        .build()
        .unwrap()
}

/// Runs a handshake, the server suspending while the resolver has not answered: it sends
/// nothing meanwhile, its waker is called once the answer is in, and the handshake goes on
/// when polled with no input. Returns the two sides and whether the server suspended.
fn drive(
    scfg: &ServerConfig,
    ccfg: &ClientConfig,
    name: &str,
) -> Result<(Connection, Connection, bool), Side> {
    let mut c = crate::__proto::client(ccfg, name).map_err(Side::Client)?;
    let mut s = crate::__proto::server(scfg);
    let woken = Arc::new(AtomicUsize::new(0));
    let w = woken.clone();
    s.set_waker(Arc::new(move || {
        w.fetch_add(1, SeqCst);
    }));
    let (mut c2s, mut plain) = (Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut c2s).map_err(Side::Client)?;
    let mut suspended = false;
    for _ in 0..50 {
        if c2s.is_empty() && !c.handshaking() && !s.handshaking() {
            break;
        }
        let mut s2c = Vec::new();
        let mut r = s.recv(&std::mem::take(&mut c2s), &mut plain, &mut s2c);
        if r.is_ok() && s.suspended() {
            suspended = true;
            assert!(s2c.is_empty(), "nothing goes out while waiting");
            // A poll before the answer changes nothing.
            s.recv(b"", &mut plain, &mut s2c).map_err(Side::Server)?;
            assert!(s2c.is_empty() && s.suspended());
            s.wait_resumable();
            let until = Instant::now() + Duration::from_secs(5);
            while woken.load(SeqCst) == 0 && Instant::now() < until {
                std::thread::yield_now();
            }
            assert_eq!(woken.load(SeqCst), 1, "the waker runs once");
            woken.store(0, SeqCst);
            r = s.recv(b"", &mut plain, &mut s2c);
            assert!(!s.suspended());
        }
        if let Err(e) = r {
            let _ = c.recv(&s2c, &mut plain, &mut Vec::new());
            return Err(Side::Server(e));
        }
        c.recv(&s2c, &mut plain, &mut c2s).map_err(Side::Client)?;
    }
    assert!(!c.handshaking() && !s.handshaking());
    assert!(plain.is_empty());
    Ok((c, s, suspended))
}

fn leaf(c: &Connection) -> Vec<u8> {
    c.peer_certificates()[0].clone()
}

fn server_alert(r: Result<(Connection, Connection, bool), Side>) -> Alert {
    match r {
        Err(Side::Server(f)) => f.alert,
        Err(Side::Client(f)) => panic!("client failed: {f}"),
        Ok(_) => panic!("the handshake succeeded"),
    }
}

#[test]
fn inline_answer_does_not_suspend() {
    let default = pki(Kind::P256, &["localhost"]);
    let a = pki(Kind::P256, &["a.test"]);
    let r = TestResolver::new(Mode::Inline);
    r.store.insert("a.test", certified(&a));
    let scfg = server(&default, &r).build().unwrap();
    for tls12 in [false, true] {
        let (c, s, suspended) = drive(&scfg, &client(&a, tls12), "a.test").unwrap();
        assert!(!suspended, "tls12={tls12}");
        assert_eq!(leaf(&c), a.chain[0].as_der());
        assert_eq!(s.server_name(), Some("a.test"));
        assert_eq!(
            c.version_name(),
            Some(if tls12 { "TLSv1_2" } else { "TLSv1_3" })
        );
    }
    assert_eq!(r.calls(), 2);
    let seen = r.seen.lock().unwrap().clone();
    assert_eq!(seen[0].name.as_deref(), Some("a.test"));
    assert_eq!(seen[0].alpn, vec![b"h2".to_vec()]);
    assert_eq!((seen[0].version, seen[1].version), ("TLSv1_3", "TLSv1_2"));
    assert!(!seen[0].quic && seen[0].schemes > 0 && seen[0].suites > 0);
    // A name the store does not have: the configuration's own chain.
    let (c, _, _) = drive(&scfg, &client(&default, false), "localhost").unwrap();
    assert_eq!(leaf(&c), default.chain[0].as_der());
}

#[test]
fn answer_from_another_thread() {
    let default = pki(Kind::P256, &["localhost"]);
    // An RSA certificate from the resolver: TLS 1.2 picks an ECDHE_RSA suite for it.
    for kind in [Kind::P256, Kind::Rsa, Kind::Ed25519] {
        let a = pki(kind, &["a.test"]);
        let r = TestResolver::new(Mode::Thread(Duration::from_millis(10)));
        r.store.insert("a.test", certified(&a));
        let scfg = server(&default, &r).build().unwrap();
        for tls12 in [false, true] {
            if tls12 && kind == Kind::Ed25519 {
                continue;
            }
            let (mut c, mut s, suspended) = drive(&scfg, &client(&a, tls12), "a.test").unwrap();
            assert!(suspended, "{kind:?} tls12={tls12}");
            assert_eq!(leaf(&c), a.chain[0].as_der());
            super::tests::exchange(&mut c, &mut s);
        }
    }
}

#[test]
fn hello_retry_asks_once() {
    let default = pki(Kind::P256, &["localhost"]);
    let a = pki(Kind::P256, &["a.test"]);
    let r = TestResolver::new(Mode::Thread(Duration::from_millis(5)));
    r.store.insert("a.test", certified(&a));
    let scfg = server(&default, &r)
        .__force_hello_retry(true)
        .build()
        .unwrap();
    let (c, _, suspended) = drive(&scfg, &client(&a, false), "a.test").unwrap();
    assert!(suspended);
    assert_eq!(leaf(&c), a.chain[0].as_der());
    assert_eq!(r.calls(), 1, "asked for the second ClientHello only");
}

#[test]
fn resumption_does_not_ask() {
    let default = pki(Kind::P256, &["localhost"]);
    let a = pki(Kind::P256, &["a.test"]);
    for tickets in [false, true] {
        for tls12 in [false, true] {
            let r = TestResolver::new(Mode::Thread(Duration::from_millis(5)));
            r.store.insert("a.test", certified(&a));
            let scfg = server(&default, &r)
                .session_tickets(tickets)
                .build()
                .unwrap();
            let ccfg = client(&a, tls12);
            let (c, _, suspended) = drive(&scfg, &ccfg, "a.test").unwrap();
            assert!(suspended && !c.resumed());
            let (c, s, suspended) = drive(&scfg, &ccfg, "a.test").unwrap();
            assert!(
                c.resumed() && s.resumed(),
                "tickets={tickets} tls12={tls12}"
            );
            assert!(!suspended);
            assert_eq!(r.calls(), 1, "tickets={tickets} tls12={tls12}");
        }
    }
}

#[test]
fn use_default_serves_the_configuration_chains() {
    let default = pki(Kind::P256, &["localhost"]);
    let b = pki(Kind::P384, &["b.test"]);
    let r = TestResolver::new(Mode::Default);
    let scfg = server(&default, &r)
        .sni_cert("b.test", b.chain.clone(), b.key.clone())
        .build()
        .unwrap();
    let (c, _, _) = drive(&scfg, &client(&b, false), "b.test").unwrap();
    assert_eq!(leaf(&c), b.chain[0].as_der());
    let (c, _, _) = drive(&scfg, &client(&default, true), "localhost").unwrap();
    assert_eq!(leaf(&c), default.chain[0].as_der());
    // No default chain: names without an sni_cert are refused.
    let scfg = ServerConfig::builder_with_resolver(r)
        .sni_cert("b.test", b.chain.clone(), b.key.clone())
        .build()
        .unwrap();
    let (c, _, _) = drive(&scfg, &client(&b, false), "b.test").unwrap();
    assert_eq!(leaf(&c), b.chain[0].as_der());
    for tls12 in [false, true] {
        let alert = server_alert(drive(&scfg, &client(&default, tls12), "localhost"));
        assert_eq!(alert, Alert::UnrecognizedName);
    }
}

#[test]
fn alerts_and_dropped_answers() {
    let default = pki(Kind::P256, &["localhost"]);
    for (mode, want) in [
        (Mode::Fail(CertAlert::AccessDenied), Alert::AccessDenied),
        (
            Mode::Fail(CertAlert::UnrecognizedName),
            Alert::UnrecognizedName,
        ),
        (
            Mode::Fail(CertAlert::HandshakeFailure),
            Alert::HandshakeFailure,
        ),
        (Mode::Fail(CertAlert::InternalError), Alert::InternalError),
        (Mode::Drop, Alert::InternalError),
    ] {
        let r = TestResolver::new(mode);
        let scfg = server(&default, &r).build().unwrap();
        for tls12 in [false, true] {
            let mut c = crate::__proto::client(&client(&default, tls12), "localhost").unwrap();
            let mut s = crate::__proto::server(&scfg);
            match super::tests::shuttle(&mut c, &mut s, usize::MAX) {
                Err(Side::Server(f)) => assert_eq!(f.alert, want, "{mode:?}"),
                other => panic!("{mode:?}: {other:?}"),
            }
            // The client got the alert.
            assert!(c.handshaking());
        }
    }
    // Answered later from another thread with an alert.
    let r = TestResolver::new(Mode::Hold);
    let scfg = server(&default, &r).build().unwrap();
    let h = r;
    std::thread::spawn(move || {
        while h.held.lock().unwrap().is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
        h.held
            .lock()
            .unwrap()
            .pop()
            .unwrap()
            .fail(CertAlert::AccessDenied);
    });
    let alert = server_alert(drive(&scfg, &client(&default, false), "localhost"));
    assert_eq!(alert, Alert::AccessDenied);
}

/// Sends a ClientHello to a fresh server connection.
fn hello(scfg: &ServerConfig, ccfg: &ClientConfig) -> (Connection, Result<(), super::Fatal>) {
    let mut c = crate::__proto::client(ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(scfg);
    let (mut flight, mut plain, mut out) = (Vec::new(), Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut flight).unwrap();
    let r = s.recv(&flight, &mut plain, &mut out);
    assert!(
        !s.suspended() || out.is_empty(),
        "nothing goes out while waiting"
    );
    (s, r)
}

#[test]
fn timeout_fails_the_handshake() {
    let default = pki(Kind::P256, &["localhost"]);
    let r = TestResolver::new(Mode::Hold);
    let scfg = server(&default, &r)
        .cert_resolver_timeout(Duration::from_millis(30))
        .build()
        .unwrap();
    let ccfg = client(&default, false);
    let t0 = Instant::now();
    let (mut s, res) = hello(&scfg, &ccfg);
    res.unwrap();
    assert!(s.suspended());
    s.wait_resumable();
    assert!(t0.elapsed() >= Duration::from_millis(30));
    let e = s.recv(b"", &mut Vec::new(), &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::InternalError);
    // The answer is abandoned; answering late is harmless.
    let done = r.held.lock().unwrap().pop().unwrap();
    assert!(done.is_abandoned());
    done.complete(certified(&default));
}

#[test]
fn pending_handshakes_are_bounded() {
    let default = pki(Kind::P256, &["localhost"]);
    let r = TestResolver::new(Mode::Hold);
    let scfg = server(&default, &r)
        .max_pending_cert_resolutions(2)
        .build()
        .unwrap();
    let ccfg = client(&default, false);
    let (s1, res) = hello(&scfg, &ccfg);
    res.unwrap();
    let (s2, res) = hello(&scfg, &ccfg);
    res.unwrap();
    assert!(s1.suspended() && s2.suspended());
    // A third that would wait is refused, its answer abandoned.
    let (_, res) = hello(&scfg, &ccfg);
    assert_eq!(res.unwrap_err().alert, Alert::InternalError);
    assert_eq!(r.calls(), 3);
    assert!(r.held.lock().unwrap().pop().unwrap().is_abandoned());
    // A connection closed while waiting gives its place back; its answer is abandoned.
    drop(s1);
    assert!(r.held.lock().unwrap()[0].is_abandoned());
    assert!(!r.held.lock().unwrap()[1].is_abandoned());
    let (s3, res) = hello(&scfg, &ccfg);
    res.unwrap();
    assert!(s3.suspended() && r.calls() == 4);
    // Answering the closed connection's handshake from another thread is harmless.
    let d = r.held.lock().unwrap().remove(0);
    std::thread::spawn(move || d.complete(CertifiedKey::new(default.chain, default.key).unwrap()))
        .join()
        .unwrap();
    // At the limit, answers given inside the call are still served.
    *r.mode.lock().unwrap() = Mode::Default;
    for _ in 0..5 {
        let (s, res) = hello(&scfg, &ccfg);
        res.unwrap();
        assert!(!s.suspended());
    }
    drop((s2, s3));
}

#[test]
fn input_while_waiting_is_bounded() {
    let default = pki(Kind::P256, &["localhost"]);
    let r = TestResolver::new(Mode::Hold);
    let scfg = server(&default, &r).build().unwrap();
    let (mut s, res) = hello(&scfg, &client(&default, false));
    res.unwrap();
    let mut rec = vec![23u8, 3, 3, 0x40, 0];
    rec.resize(5 + 0x4000, 0);
    let mut failed = false;
    for _ in 0..64 {
        if let Err(e) = s.recv(&rec, &mut Vec::new(), &mut Vec::new()) {
            assert_eq!(e.alert, Alert::UnexpectedMessage);
            failed = true;
            break;
        }
    }
    assert!(failed, "unbounded input while waiting");
}

#[test]
fn cert_store() {
    let a = pki(Kind::P256, &["a.test"]);
    let w = pki(Kind::P256, &["*.w.test"]);
    let d = pki(Kind::P256, &["d.test"]);
    let s = CertStore::new();
    assert!(s.is_empty() && s.get(Some("a.test")).is_none());
    assert!(s.insert("A.Test.", certified(&a)).is_none());
    s.insert("*.w.test", certified(&w));
    let der = |k: Option<CertifiedKey>| k.map(|k| k.chain_der().next().unwrap().to_vec());
    assert_eq!(
        der(s.get(Some("a.test"))),
        Some(a.chain[0].as_der().to_vec())
    );
    assert_eq!(
        der(s.get(Some("x.w.test"))),
        Some(w.chain[0].as_der().to_vec())
    );
    assert!(s.get(Some("x.y.w.test")).is_none());
    assert!(s.get(Some("w.test")).is_none());
    assert!(s.get(None).is_none());
    s.set_default(Some(certified(&d)));
    assert_eq!(der(s.get(None)), Some(d.chain[0].as_der().to_vec()));
    assert_eq!(
        der(s.get(Some("other"))),
        Some(d.chain[0].as_der().to_vec())
    );
    // Replaced while serving: the next handshake gets the new chain.
    let a2 = pki(Kind::P384, &["a.test"]);
    let r = TestResolver::new(Mode::Inline);
    r.store.insert("a.test", certified(&a));
    let scfg = ServerConfig::builder_with_resolver(Arc::new(r.store.clone()))
        .build()
        .unwrap();
    let (c, _, _) = drive(&scfg, &client(&a, false), "a.test").unwrap();
    assert_eq!(leaf(&c), a.chain[0].as_der());
    assert!(r.store.insert("a.test", certified(&a2)).is_some());
    let (c, _, _) = drive(&scfg, &client(&a2, false), "a.test").unwrap();
    assert_eq!(leaf(&c), a2.chain[0].as_der());
    assert!(r.store.remove("a.test").is_some());
    assert_eq!(
        server_alert(drive(&scfg, &client(&a2, false), "a.test")),
        Alert::UnrecognizedName
    );
    assert_eq!(s.len(), 2);
    assert!(format!("{s:?}").contains("CertStore"));
}

#[test]
fn certified_key_checks() {
    let a = pki(Kind::P256, &["a.test"]);
    let b = pki(Kind::P256, &["b.test"]);
    assert!(CertifiedKey::new(a.chain.clone(), b.key).is_err());
    assert!(CertifiedKey::new(Vec::new(), a.key.clone()).is_err());
    let k = certified(&a);
    assert!(k.clone().with_ocsp_response(b"not ocsp".to_vec()).is_err());
    assert_eq!(k.chain_der().count(), 1);
    assert!(format!("{k:?}").contains("CertifiedKey"));
    // An OCSP response for the default chain needs a default chain.
    let r = TestResolver::new(Mode::Inline);
    let e = ServerConfig::builder_with_resolver(r.clone())
        .ocsp_response(vec![0x30, 0])
        .build();
    assert!(e.is_err());
    let b = ServerConfig::builder_with_resolver(r)
        .cert_resolver_timeout(Duration::ZERO)
        .max_pending_cert_resolutions(0);
    let dbg = format!("{b:?}");
    assert!(dbg.contains("cert_resolver: true") && dbg.contains("max_pending_cert_resolutions: 1"));
    assert!(dbg.contains("cert_resolver_timeout: 1ms"));
}
