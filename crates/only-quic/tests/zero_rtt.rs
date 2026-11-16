//! 0-RTT end to end over loopback: a resumed client sends its request before the handshake,
//! the server sees it as early data (and can refuse it), the client learns the outcome.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use only::tls::EarlyData;
use only::{Engine, Listener};
use only_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

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
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = only::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = only_quic::server_config(vec![cert], key, &[b"echo"])
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
    cfg: &only_quic::ClientConfig,
    req: &[u8],
) -> (Vec<u8>, Connection) {
    let (tx, rx) = mpsc::channel();
    let (dtx, drx) = mpsc::channel();
    let c = only_quic::dial(
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
    let cfg = only_quic::client_config_insecure(&[b"echo"])
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
    let plain = only_quic::client_config_insecure(&[b"echo"]).unwrap();
    let (b, c) = request(&e, addr, &plain, b"x");
    assert_eq!(b, b"late:x");
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
    c.close(0, b"");
}

#[test]
fn zero_rtt_off_on_the_server() {
    let (e, addr) = setup(false);
    let cfg = only_quic::client_config_insecure(&[b"echo"])
        .unwrap()
        .zero_rtt(true);
    let (_, c) = request(&e, addr, &cfg, b"one");
    std::thread::sleep(Duration::from_millis(200));
    c.close(0, b"");
    let (b, c) = request(&e, addr, &cfg, b"two");
    assert_eq!(b, b"late:two");
    assert_eq!(c.early_data(), EarlyData::NotAttempted);
}
