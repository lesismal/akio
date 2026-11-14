//! QUIC end to end over loopback: streams, a large transfer, datagrams, close.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use bytes::Bytes;
use flash::{Engine, Listener};
use flash_quic::{Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
    fn on_datagram(&mut self, c: &Connection, data: Bytes) {
        let _ = c.send_datagram(data);
    }
}

enum Got {
    Connected,
    Stream(StreamId, Vec<u8>),
    Datagram(Bytes),
    Closed(ConnectionError),
}

struct Client {
    tx: mpsc::Sender<Got>,
    bufs: HashMap<StreamId, Vec<u8>>,
}
impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.tx.send(Got::Connected);
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let b = self.bufs.entry(id).or_default();
        b.extend_from_slice(&data);
        if fin {
            let b = self.bufs.remove(&id).unwrap_or_default();
            let _ = self.tx.send(Got::Stream(id, b));
        }
    }
    fn on_datagram(&mut self, _c: &Connection, data: Bytes) {
        let _ = self.tx.send(Got::Datagram(data));
    }
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        let _ = self.tx.send(Got::Closed(r));
    }
}

fn setup() -> (Arc<Engine>, SocketAddr) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let cfg = flash_quic::server_config(vec![cert], key, &[b"echo"]).unwrap();
    let server = QuicServer::new(cfg, |_c: &Connection| Echo);
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve(server),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

#[test]
fn streams_datagrams_and_close() {
    let (e, addr) = setup();
    let (tx, rx) = mpsc::channel();
    let cfg = flash_quic::client_config_insecure(&[b"echo"]).unwrap();
    let c = flash_quic::dial(
        &e,
        addr,
        "localhost",
        cfg,
        Client {
            tx,
            bufs: HashMap::new(),
        },
    )
    .unwrap();
    assert!(
        c.open_bi().is_none(),
        "no stream credit before the handshake"
    );
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Got::Connected
    ));
    let mut want = HashMap::new();
    for i in 0..20usize {
        let id = c.open_bi().expect("stream");
        let body: Vec<u8> = (0..1 + i * 5000).map(|j| (i + j) as u8).collect();
        c.send(id, body.clone()).unwrap();
        c.finish(id).unwrap();
        want.insert(id, body);
    }
    let big = c.open_bi().unwrap();
    let body: Vec<u8> = (0..8usize << 20).map(|j| ((j * 13) >> 3) as u8).collect();
    c.send(big, body.clone()).unwrap();
    c.finish(big).unwrap();
    want.insert(big, body);
    while !want.is_empty() {
        match rx.recv_timeout(Duration::from_secs(20)).expect("event") {
            Got::Connected => panic!("connected twice"),
            Got::Stream(id, b) => {
                let w = want.remove(&id).expect("known stream");
                assert_eq!(b.len(), w.len());
                assert!(b == w, "stream {id} differs");
            }
            Got::Datagram(_) => {}
            Got::Closed(r) => panic!("closed: {r}"),
        }
    }
    assert_eq!(c.alpn().as_deref(), Some(&b"echo"[..]));
    c.send_datagram(Bytes::from_static(b"ping")).unwrap();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).expect("datagram") {
            Got::Datagram(d) => {
                assert_eq!(&d[..], b"ping");
                break;
            }
            _ => continue,
        }
    }
    c.close(0, b"bye");
    loop {
        if let Got::Closed(r) = rx.recv_timeout(Duration::from_secs(5)).expect("close") {
            assert_eq!(r, ConnectionError::LocallyClosed);
            break;
        }
    }
    assert!(
        c.send(c.open_bi().unwrap_or(big), Bytes::from_static(b"x"))
            .is_err()
    );
    e.shutdown();
}

#[test]
fn bad_certificate_fails_the_handshake() {
    let (e, addr) = setup();
    let (tx, rx) = mpsc::channel();
    let cfg = flash_quic::client_config(rustls::RootCertStore::empty(), &[b"echo"]).unwrap();
    let _c = flash_quic::dial(
        &e,
        addr,
        "localhost",
        cfg,
        Client {
            tx,
            bufs: HashMap::new(),
        },
    )
    .unwrap();
    loop {
        match rx.recv_timeout(Duration::from_secs(10)).expect("close") {
            Got::Closed(ConnectionError::TransportError(_)) => break,
            Got::Closed(r) => panic!("unexpected {r}"),
            _ => {}
        }
    }
    e.shutdown();
}
