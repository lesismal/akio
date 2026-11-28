//! A follow-up of akit's A301: a client connection's handler hears of its engine's shutdown
//! (`QuicHandler::on_shutdown`) while its socket can still carry a `CONNECTION_CLOSE`, so the
//! server learns of it at once instead of at its idle timeout.
#![allow(missing_docs)]

use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use akio::{Config, Engine, Listener};
use akio_quic::Bytes;
use akio_quic::{Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

/// Well under the 30 s idle timeout, after which the server would end the connection anyway.
const T: Duration = Duration::from_secs(10);

struct Server(mpsc::Sender<ConnectionError>);

impl QuicHandler for Server {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        let _ = self.0.send(reason);
    }
}

#[derive(Debug, PartialEq)]
enum Got {
    Connected,
    Data(Vec<u8>),
    Shutdown,
    Closed,
}

struct Client(mpsc::Sender<Got>);

impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(Got::Connected);
    }
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, data: Bytes, _fin: bool) {
        let _ = self.0.send(Got::Data(data.to_vec()));
    }
    fn on_shutdown(&mut self, c: &Connection) {
        let _ = self.0.send(Got::Shutdown);
        c.close(7, b"engine down");
    }
    fn on_close(&mut self, _c: &Connection, _reason: ConnectionError) {
        let _ = self.0.send(Got::Closed);
    }
}

#[test]
fn a_clients_engine_shutdown_closes_its_connection_at_once() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let cfg = akio_quic::server_config(vec![cert], key, &[b"bye"]).unwrap();
    let (stx, srx) = mpsc::channel();
    let stx = Mutex::new(stx);
    let server = QuicServer::new(cfg, move |_c: &Connection| {
        Server(stx.lock().unwrap().clone())
    });
    let se = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server.clone()))
        .build()
        .unwrap();
    se.start().unwrap();
    let addr = se.local_addrs()[0];

    let ce = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_secs(20);
            v
        })
        .udp_client_threads(1)
        .build()
        .unwrap();
    ce.start().unwrap();
    let (tx, rx) = mpsc::channel();
    let ccfg = akio_quic::client_config_insecure(&[b"bye"]).unwrap();
    let c = akio_quic::dial(&ce, addr, "localhost", ccfg, Client(tx)).unwrap();
    assert_eq!(rx.recv_timeout(T).unwrap(), Got::Connected);
    let s = c.open_bi().unwrap();
    c.send(s, &b"ping"[..]).unwrap();
    assert_eq!(rx.recv_timeout(T).unwrap(), Got::Data(b"ping".to_vec()));
    assert_eq!(server.connections(), 1);

    let t0 = Instant::now();
    ce.shutdown();
    ce.wait();
    assert!(t0.elapsed() < T, "{:?}", t0.elapsed());
    assert_eq!(rx.recv_timeout(T).unwrap(), Got::Shutdown);
    assert_eq!(rx.recv_timeout(T).unwrap(), Got::Closed);
    // The server heard the client's CONNECTION_CLOSE, long before its idle timeout.
    match srx.recv_timeout(T).unwrap() {
        ConnectionError::ApplicationClosed { code, reason } => {
            assert_eq!((code, &reason[..]), (7, &b"engine down"[..]));
        }
        other => panic!("{other:?}"),
    }
    se.shutdown();
    se.wait();
}
