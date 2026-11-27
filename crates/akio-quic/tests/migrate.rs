//! Client migration over loopback: to a new local port, and to the server's preferred address
//! (served by a second listener sharing the same `QuicServer`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_quic::Bytes;
use akio_quic::{Connection, QuicHandler, QuicServer, StreamId};

/// Echoes streams and records the client address of each request.
struct Echo(Arc<Mutex<Vec<SocketAddr>>>);
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            self.0.lock().unwrap().push(c.remote_addr());
            let _ = c.finish(id);
        }
    }
}

struct Client {
    tx: mpsc::Sender<Option<(StreamId, Vec<u8>)>>,
    bufs: HashMap<StreamId, Vec<u8>>,
}
impl QuicHandler for Client {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.tx.send(None);
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        self.bufs.entry(id).or_default().extend_from_slice(&data);
        if fin {
            let b = self.bufs.remove(&id).unwrap_or_default();
            let _ = self.tx.send(Some((id, b)));
        }
    }
}

fn echo(c: &Connection, rx: &mpsc::Receiver<Option<(StreamId, Vec<u8>)>>, n: usize) {
    let id = c.open_bi().expect("stream");
    let body: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
    c.send(id, body.clone()).unwrap();
    c.finish(id).unwrap();
    loop {
        if let Some((got, b)) = rx.recv_timeout(Duration::from_secs(10)).expect("echo") {
            assert_eq!(got, id);
            assert!(b == body);
            return;
        }
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn migrate_to_a_new_port_and_to_the_preferred_address() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    // The preferred address needs a fixed port: take a free one.
    let preferred = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let cfg = akio_quic::server_config(vec![cert], key, &[b"echo"])
        .unwrap()
        .preferred_address(preferred);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let server = QuicServer::new(cfg, move |_c: &Connection| Echo(s2.clone()));
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(server.clone()),
            )
            .listen(Listener::udp(preferred).threads(1).serve(server))
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = *e.local_addrs().iter().find(|a| **a != preferred).unwrap();
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
    assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().is_none());
    echo(&c, &rx, 10_000);
    // The server offered its preferred address: the first migration goes there.
    wait_for("the preferred address", || c.preferred_address().is_some());
    assert_eq!(c.preferred_address(), Some(preferred));
    let first = seen.lock().unwrap()[0];
    c.migrate(&e).unwrap();
    wait_for("the move", || c.remote_addr() == preferred);
    echo(&c, &rx, 200_000);
    let second = *seen.lock().unwrap().last().unwrap();
    assert_ne!(second.port(), first.port(), "a new local socket");
    assert_eq!(c.preferred_address(), None);
    // Then a new local port on the same server address, one migration at a time: a call
    // while one probes is refused. A test thread held up until the probe was answered (a
    // loaded host) finds the migration done, and its call starts another: call again.
    c.migrate(&e).unwrap();
    assert!(
        (0..10).any(|_| c.migrate(&e).is_err()),
        "one migration at a time"
    );
    let before = seen.lock().unwrap().len();
    wait_for("the second move", || {
        echo(&c, &rx, 1000);
        seen.lock().unwrap()[before..]
            .iter()
            .any(|a| a.port() != second.port())
    });
    assert_eq!(c.remote_addr(), preferred);
    echo(&c, &rx, 100_000);
    assert!(!c.is_closed());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(c.stats().ecn_capable, "{:?}", c.stats());
    e.shutdown();
}
