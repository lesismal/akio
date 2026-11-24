//! 0-RTT end to end over loopback: a resumed client sends its request before the handshake,
//! the server sees it as early data (and can refuse it), the client learns the outcome.
//! Also a handshake waiting for a server certificate resolver that answers later (ADR-098),
//! which suspends the handshake the same way an asynchronous anti-replay store does.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use akio::tls::EarlyData;
use akio::{Engine, Listener};
use akio_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

/// Echoes streams, prefixed with whether they came in 0-RTT.
#[derive(Default)]
struct Echo(HashMap<StreamId, Vec<u8>>);
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let b = self.0.entry(id).or_default();
        b.extend_from_slice(&data);
        if fin {
            let tag: &[u8] = if c.is_early(id) { b"early:" } else { b"late:" };
            let mut out = tag.to_vec();
            out.extend_from_slice(&self.0.remove(&id).unwrap_or_default());
            let _ = c.send(id, out);
            let _ = c.finish(id);
        }
    }
}

struct Client {
    tx: mpsc::Sender<(StreamId, Vec<u8>)>,
    bufs: HashMap<StreamId, Vec<u8>>,
    done: mpsc::Sender<()>,
}
impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.done.send(());
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let b = self.bufs.entry(id).or_default();
        b.extend_from_slice(&data);
        if fin {
            let b = self.bufs.remove(&id).unwrap_or_default();
            let _ = self.tx.send((id, b));
        }
    }
}

fn setup(zero_rtt: bool) -> (Arc<Engine>, SocketAddr) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = akio_quic::server_config(vec![cert], key, &[b"echo"])
        .unwrap()
        .zero_rtt(zero_rtt);
    let server = QuicServer::new(cfg, |_c: &Connection| Echo::default());
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

/// Dials, sends `req` on a stream opened right away (or after the handshake if that fails),
/// returns the answer and the connection.
fn request(
    e: &Engine,
    addr: SocketAddr,
    cfg: &akio_quic::ClientConfig,
    req: &[u8],
) -> (Vec<u8>, Connection) {
    let (tx, rx) = mpsc::channel();
    let (dtx, drx) = mpsc::channel();
    let c = akio_quic::dial(
        e,
        addr,
        "localhost",
        cfg.clone(),
        Client {
            tx,
            bufs: HashMap::new(),
            done: dtx,
        },
    )
    .unwrap();
    let id = match c.open_bi() {
        Some(id) => id,
        None => {
            drx.recv_timeout(Duration::from_secs(5)).expect("connected");
            c.open_bi().expect("stream")
        }
    };
    c.send(id, req.to_vec()).unwrap();
    c.finish(id).unwrap();
    let (got, b) = rx.recv_timeout(Duration::from_secs(10)).expect("answer");
    assert_eq!(got, id);
    (b, c)
}

#[test]
fn zero_rtt_end_to_end() {
    let (e, addr) = setup(true);
    let cfg = akio_quic::client_config_insecure(&[b"echo"])
        .unwrap()
        .zero_rtt(true);
    // First connection: no ticket yet, the stream waits for the handshake.
    let (b, c) = request(&e, addr, &cfg, b"one");
    assert_eq!(b, b"late:one");
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
    // Let the ticket arrive, then close.
    std::thread::sleep(Duration::from_millis(200));
    c.close(0, b"");
    // Resumed: the request goes in 0-RTT and the server sees it as early.
    for _ in 0..3 {
        let (b, c) = request(&e, addr, &cfg, b"GET /");
        assert_eq!(b, b"early:GET /");
        assert_eq!(c.early_data(), EarlyData::Accepted);
        std::thread::sleep(Duration::from_millis(100));
        c.close(0, b"");
    }
    // A client without 0-RTT waits for the handshake even with a ticket.
    let plain = akio_quic::client_config_insecure(&[b"echo"]).unwrap();
    let (b, c) = request(&e, addr, &plain, b"x");
    assert_eq!(b, b"late:x");
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
    c.close(0, b"");
}

#[test]
fn zero_rtt_off_on_the_server() {
    let (e, addr) = setup(false);
    let cfg = akio_quic::client_config_insecure(&[b"echo"])
        .unwrap()
        .zero_rtt(true);
    let (_, c) = request(&e, addr, &cfg, b"one");
    std::thread::sleep(Duration::from_millis(200));
    c.close(0, b"");
    let (b, c) = request(&e, addr, &cfg, b"two");
    assert_eq!(b, b"late:two");
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
}

/// A remote anti-replay store answered from another thread after a delay (ADR-062): the
/// suspended handshake is driven again from that thread.
struct SlowStore(std::sync::Mutex<std::collections::HashSet<Vec<u8>>>);

impl akio::tls::AsyncAntiReplayStore for SlowStore {
    fn check_and_insert(&self, binder: &[u8], _ttl: Duration, done: akio::tls::ReplayCheck) {
        let fresh = self.0.lock().unwrap().insert(binder.to_vec());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            done.complete(Ok(fresh));
        });
    }
}

#[test]
fn zero_rtt_with_an_async_anti_replay_store() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let tls = akio::tls::ServerConfig::builder(vec![cert], key)
        .alpn(["echo"])
        .async_anti_replay_store(Arc::new(SlowStore(Default::default())))
        .build()
        .unwrap();
    let cfg = akio_quic::server_config_from(&tls).unwrap().zero_rtt(true);
    let server = QuicServer::new(cfg, |_c: &Connection| Echo::default());
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cfg = akio_quic::client_config_insecure(&[b"echo"])
        .unwrap()
        .zero_rtt(true);
    let (_, c) = request(&e, addr, &cfg, b"one");
    std::thread::sleep(Duration::from_millis(200));
    c.close(0, b"");
    for _ in 0..2 {
        let (b, c) = request(&e, addr, &cfg, b"GET /");
        assert_eq!(b, b"early:GET /");
        assert_eq!(c.early_data(), EarlyData::Accepted);
        std::thread::sleep(Duration::from_millis(100));
        c.close(0, b"");
    }
}

/// A certificate resolver answering from another thread (ADR-098): the QUIC handshake waits
/// for it and is driven again from that thread. The client trusts only the resolver's
/// certificate, not the configuration's default one.
struct LaterCert(akio::tls::CertifiedKey);

impl akio::tls::CertResolver for LaterCert {
    fn resolve(&self, hello: &akio::tls::ClientHelloInfo<'_>, done: akio::tls::CertDone) {
        assert!(hello.is_quic() && hello.server_name() == Some("localhost"));
        let key = self.0.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            done.complete(key);
        });
    }
}

#[test]
fn certificate_from_a_resolver_answering_later() {
    let default = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let served = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let served_cert = akio::tls::Certificate::from_der(served.0.as_der().to_vec());
    let key = akio::tls::CertifiedKey::new(
        vec![served_cert.clone()],
        akio::tls::PrivateKey::from_pkcs8_der(served.1.to_pkcs8_der()),
    )
    .unwrap();
    let tls = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(
            default.0.as_der().to_vec(),
        )],
        akio::tls::PrivateKey::from_pkcs8_der(default.1.to_pkcs8_der()),
    )
    .alpn(["echo"])
    .cert_resolver(Arc::new(LaterCert(key)))
    .build()
    .unwrap();
    let cfg = akio_quic::server_config_from(&tls).unwrap();
    let server = QuicServer::new(cfg, |_c: &Connection| Echo::default());
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&served_cert).unwrap();
    let cfg = akio_quic::client_config(roots, &[b"echo"]).unwrap();
    for _ in 0..2 {
        let (b, c) = request(&e, addr, &cfg, b"resolved");
        assert_eq!(b, b"late:resolved");
        c.close(0, b"");
    }
}
