//! QUIC stream control: RESET_STREAM and STOP_SENDING in both directions, sending on finished or
//! stopped streams, connection introspection, and error formatting.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use only_quic::Bytes;
use only::{Engine, Listener};
use only_quic::{Connection, Error, QuicHandler, QuicServer, StreamId};

/// Server: `reset` resets the stream, `stop` stops it, anything else is echoed with FIN.
struct Ctl {
    names: Arc<Mutex<mpsc::Sender<String>>>,
}

impl QuicHandler for Ctl {
    fn on_connected(&mut self, c: &Connection) {
        let info = format!(
            "{:?} {:?} rtt>0:{} sent>0:{}",
            c.server_name(),
            c.alpn().map(|a| String::from_utf8(a).unwrap()),
            c.rtt() > Duration::ZERO,
            c.stats().udp_tx.datagrams > 0,
        );
        let _ = self.names.lock().unwrap().send(info);
    }
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        match &data[..] {
            b"reset" => c.reset(id, 7).unwrap(),
            b"stop" => c.stop(id, 9).unwrap(),
            _ => {
                let _ = c.send(id, data);
                if fin {
                    let _ = c.finish(id);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum Got {
    Connected,
    Data(StreamId, Vec<u8>, bool),
    Reset(StreamId, u64),
    Stopped(StreamId, u64),
    Opened(StreamId),
}

struct Client(mpsc::Sender<Got>);

impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(Got::Connected);
    }
    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
        let _ = self.0.send(Got::Opened(id));
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = self.0.send(Got::Data(id, data.to_vec(), fin));
    }
    fn on_stream_reset(&mut self, _c: &Connection, id: StreamId, code: u64) {
        let _ = self.0.send(Got::Reset(id, code));
    }
    fn on_stream_stopped(&mut self, _c: &Connection, id: StreamId, code: u64) {
        let _ = self.0.send(Got::Stopped(id, code));
    }
}

fn setup() -> (Arc<Engine>, SocketAddr, mpsc::Receiver<String>) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = only::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = only_quic::server_config(vec![cert], key, &[b"ctl"]).unwrap();
    let (tx, rx) = mpsc::channel();
    let names = Arc::new(Mutex::new(tx));
    let server = QuicServer::new(cfg, move |_c: &Connection| Ctl {
        names: names.clone(),
    });
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(server),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr, rx)
}

fn next(rx: &mpsc::Receiver<Got>, mut pred: impl FnMut(&Got) -> bool) -> Got {
    loop {
        let g = rx.recv_timeout(Duration::from_secs(5)).expect("event");
        if pred(&g) {
            return g;
        }
    }
}

#[test]
fn reset_stop_and_introspection() {
    let (e, addr, names) = setup();
    let (tx, rx) = mpsc::channel();
    let cfg = only_quic::client_config_insecure(&[b"ctl"]).unwrap();
    let c = only_quic::dial(&e, addr, "localhost", cfg, Client(tx)).unwrap();
    assert_eq!(next(&rx, |g| *g == Got::Connected), Got::Connected);
    assert!(format!("{c:?}").contains("Connection"));
    let info = names.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        info.starts_with("Some(\"localhost\") Some(\"ctl\")"),
        "{info}"
    );

    // The server resets its side of the stream.
    let id = c.open_bi().unwrap();
    c.send(id, Bytes::from_static(b"reset")).unwrap();
    assert_eq!(
        next(&rx, |g| matches!(g, Got::Reset(..))),
        Got::Reset(id, 7)
    );

    // The server asks us to stop sending: we are told, and further sends fail.
    let id = c.open_bi().unwrap();
    c.send(id, Bytes::from_static(b"stop")).unwrap();
    assert_eq!(
        next(&rx, |g| matches!(g, Got::Stopped(..))),
        Got::Stopped(id, 9)
    );
    let r = c.send(id, Bytes::from_static(b"more"));
    assert!(matches!(r, Err(Error::Stopped(9))), "{r:?}");
    assert_eq!(c.queued_bytes(id), 0);

    // A finished stream takes no more data; resetting or stopping an unknown stream fails.
    let id = c.open_uni().unwrap();
    c.send(id, Bytes::from_static(b"uni")).unwrap();
    c.finish(id).unwrap();
    assert!(matches!(
        c.send(id, Bytes::from_static(b"x")),
        Err(Error::UnknownStream)
    ));
    let bogus = c.open_bi().unwrap();
    c.reset(bogus, 1).unwrap();
    assert!(
        c.stop(id, 1).is_err(),
        "uni stream we opened has no receive side"
    );

    // Our own reset reaches the server, which keeps serving other streams.
    let id = c.open_bi().unwrap();
    c.send(id, Bytes::from_static(b"echo me")).unwrap();
    c.finish(id).unwrap();
    let mut echoed = Vec::new();
    next(&rx, |g| match g {
        Got::Data(i, d, fin) if *i == id => {
            echoed.extend_from_slice(d);
            *fin
        }
        _ => false,
    });
    assert_eq!(echoed, b"echo me");

    c.close(0, b"done");
    assert!(matches!(
        c.send(id, Bytes::from_static(b"x")),
        Err(Error::Closed)
    ));
    e.shutdown();
    e.wait();
}

#[test]
fn errors_format_and_idle_server_handle() {
    for (e, want) in [
        (Error::Closed, "quic: connection closed"),
        (Error::UnknownStream, "quic: unknown stream"),
        (Error::Stopped(3), "quic: stream stopped by peer (code 3)"),
        (Error::Datagram("too big".into()), "quic: datagram: too big"),
        (Error::Config("bad".into()), "quic: config: bad"),
    ] {
        assert_eq!(e.to_string(), want);
    }
    let e = Error::Connect("endpoint stopping".into());
    assert!(e.to_string().starts_with("quic: connect: "), "{e}");
    // Bad key material is a config error.
    let r = only_quic::server_config(
        vec![only::tls::Certificate::from_der(vec![1, 2, 3])],
        only::tls::PrivateKey::from_pkcs8_der(vec![4, 5, 6]),
        &[b"x"],
    );
    assert!(matches!(r, Err(Error::Config(_))));
    // A server that is not serving yet has no connections; closing all is a no-op.
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = only_quic::server_config(
        vec![only::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        key,
        &[b"x"],
    )
    .unwrap();
    let s = QuicServer::new(cfg, |_c: &Connection| Ctl {
        names: Arc::new(Mutex::new(mpsc::channel().0)),
    });
    assert_eq!(s.connections(), 0);
    s.close_all(0, b"");
}

/// Configurations built from `only::tls` configs, with transport settings, verifying the
/// server certificate against real roots.
#[test]
fn configs_from_tls_with_transport_settings() {
    use only::tls;
    use only_quic::{Congestion, Dir, Side, TransportConfig};

    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let stls = tls::ServerConfig::builder(vec![cert.clone()], key)
        .alpn(["ctl"])
        .build()
        .unwrap();
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams = 2;
    t.keep_alive_interval = Some(Duration::from_millis(500));
    t.congestion = Congestion::NewReno;
    let scfg = only_quic::server_config_from(&stls)
        .unwrap()
        .transport(&t)
        .migration(false);
    assert!(format!("{scfg:?}").contains("ServerConfig"));
    let (tx, _rx) = mpsc::channel();
    let names = Arc::new(Mutex::new(tx));
    let server = QuicServer::new(scfg, move |_c: &Connection| Ctl {
        names: names.clone(),
    });
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];

    let mut roots = tls::RootCerts::empty();
    roots.add(&cert).unwrap();
    let ctls = tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["ctl"])
        .build()
        .unwrap();
    let ccfg = only_quic::client_config_from(&ctls)
        .unwrap()
        .transport(&TransportConfig::default());
    assert!(format!("{ccfg:?}").contains("ClientConfig"));
    let (tx, rx) = mpsc::channel();
    let c = only_quic::dial(&e, addr, "localhost", ccfg, Client(tx)).unwrap();
    assert_eq!(next(&rx, |g| *g == Got::Connected), Got::Connected);
    // The server allows two bidirectional streams at once.
    let a = c.open_bi().unwrap();
    let b = c.open_bi().unwrap();
    assert!(c.open_bi().is_none());
    assert_eq!(
        (a.initiator(), a.dir(), a.index(), b.index()),
        (Side::Client, Dir::Bi, 0, 1)
    );
    assert_eq!(StreamId::new(Side::Client, Dir::Bi, 1), b);
    assert!(c.stats().sent_packets > 0);
    c.close(0, b"");

    // A name the certificate does not cover fails the handshake.
    let mut roots = tls::RootCerts::empty();
    roots.add(&cert).unwrap();
    let cfg = only_quic::client_config(roots, &[b"ctl"]).unwrap();
    let (tx, rx) = mpsc::channel();
    struct Closed(mpsc::Sender<only_quic::ConnectionError>);
    impl QuicHandler for Closed {
        fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: Bytes, _fin: bool) {}
        fn on_close(&mut self, _c: &Connection, r: only_quic::ConnectionError) {
            let _ = self.0.send(r);
        }
    }
    let _c = only_quic::dial(&e, addr, "other.test", cfg, Closed(tx)).unwrap();
    let r = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        matches!(r, only_quic::ConnectionError::TransportError { .. }),
        "{r}"
    );
    e.shutdown();
    e.wait();
}
