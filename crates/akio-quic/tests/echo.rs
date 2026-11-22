//! QUIC end to end over loopback: streams, a large transfer, datagrams, close.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_quic::Bytes;
use akio_quic::{Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

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
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = akio_quic::server_config(vec![cert], key, &[b"echo"]).unwrap();
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
    let cfg = akio_quic::client_config_insecure(&[b"echo"]).unwrap();
    let c = akio_quic::dial(
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
        let body: Vec<u8> = (0..=(i * 5000)).map(|j| (i + j) as u8).collect();
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
    // Loopback carries ECN codepoints on Linux and macOS: the path passed ECN validation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(c.stats().ecn_capable, "{:?}", c.stats());
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
    let cfg = akio_quic::client_config(akio::tls::RootCerts::empty(), &[b"echo"]).unwrap();
    let _c = akio_quic::dial(
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
            Got::Closed(ConnectionError::TransportError { .. }) => break,
            Got::Closed(r) => panic!("unexpected {r}"),
            _ => {}
        }
    }
    e.shutdown();
}

#[test]
fn version_2() {
    let (e, addr) = setup();
    for version in [akio_quic::Version::V2, akio_quic::Version::V1] {
        let (tx, rx) = mpsc::channel();
        let cfg = akio_quic::client_config_insecure(&[b"echo"])
            .unwrap()
            .version(version);
        let c = akio_quic::dial(
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
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Got::Connected
        ));
        assert_eq!(c.version(), version);
        let id = c.open_bi().unwrap();
        c.send(id, vec![7u8; 50_000]).unwrap();
        c.finish(id).unwrap();
        loop {
            if let Got::Stream(_, b) = rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                assert_eq!(b, vec![7u8; 50_000]);
                break;
            }
        }
        c.close(0, b"");
    }
    e.shutdown();
}

/// ADR-015: `QuicServer` is a collector whose totals survive closed connections.
#[test]
fn server_collector_reports_connections() {
    use akio::metrics::{Families, Value};

    fn value(f: &Families, name: &str, label: Option<(&str, &str)>) -> f64 {
        let fam = f.get(name).unwrap_or_else(|| panic!("no {name}"));
        let s = fam
            .samples
            .iter()
            .find(|s| label.is_none_or(|(k, v)| s.label(k) == Some(v)))
            .unwrap();
        match s.value {
            Value::Counter(v) | Value::Gauge(v) => v,
            _ => panic!("{name} is a histogram"),
        }
    }

    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = akio_quic::server_config(vec![cert], key, &[b"echo"]).unwrap();
    let server = QuicServer::new(cfg, |_c: &Connection| Echo);
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(server.clone()),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let tel = e.telemetry().clone();
    tel.register_collector(Arc::new(server), &[("server", "echo")]);
    let addr = e.local_addrs()[0];

    let (tx, rx) = mpsc::channel();
    let ccfg = akio_quic::client_config_insecure(&[b"echo"]).unwrap();
    let c = akio_quic::dial(
        &e,
        addr,
        "localhost",
        ccfg,
        Client {
            tx,
            bufs: HashMap::new(),
        },
    )
    .unwrap();
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Got::Connected
    ));
    let id = c.open_bi().unwrap();
    c.send(id, vec![7u8; 100_000]).unwrap();
    c.finish(id).unwrap();
    loop {
        if let Got::Stream(_, b) = rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            assert_eq!(b.len(), 100_000);
            break;
        }
    }
    let f = tel.collect();
    assert_eq!(value(&f, "akio_quic_connections_open", None), 1.0);
    assert_eq!(value(&f, "akio_quic_connections_accepted_total", None), 1.0);
    assert_eq!(value(&f, "akio_quic_connections_closed_total", None), 0.0);
    let rx_bytes = value(&f, "akio_quic_bytes_total", Some(("dir", "rx")));
    let tx_pkts = value(&f, "akio_quic_packets_sent_total", None);
    assert!(rx_bytes >= 100_000.0, "{rx_bytes}");
    assert!(tx_pkts > 0.0);
    assert!(
        f.get("akio_quic_connections_open").unwrap().samples[0].label("server") == Some("echo")
    );

    c.close(0, b"bye");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let f = loop {
        let f = tel.collect();
        if value(&f, "akio_quic_connections_open", None) == 0.0 {
            break f;
        }
        assert!(std::time::Instant::now() < deadline, "server never drained");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(value(&f, "akio_quic_connections_closed_total", None), 1.0);
    assert!(value(&f, "akio_quic_bytes_total", Some(("dir", "rx"))) >= rx_bytes);
    assert!(value(&f, "akio_quic_packets_sent_total", None) >= tx_pkts);
    let text = tel.render_prometheus();
    assert!(text.contains("akio_quic_connections_closed_total{server=\"echo\"} 1\n"));
}
