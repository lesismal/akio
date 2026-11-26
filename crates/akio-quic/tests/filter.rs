//! The listener's accept filter in front of a QUIC server (ADR-178, akit A220): a refused
//! client's Initial packets never make a connection (no TLS work, nothing sent back), on a UDP
//! listener and on a bound socket; the filter is swapped while the server runs; and the server
//! asks it again for each new QUIC connection, from a UDP peer it already serves too.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_quic::{Bytes, Connection, ConnectionError, QuicHandler, QuicServer, StreamId};

fn tls() -> (Vec<akio::tls::Certificate>, akio::tls::PrivateKey) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    (
        vec![akio::tls::Certificate::from_der(ck.0.as_der().to_vec())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
}

struct Quiet;
impl QuicHandler for Quiet {
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: Bytes, _fin: bool) {}
}

/// Reports the handshake (`Ok`) or the close reason (`Err`).
struct Watch(mpsc::Sender<Result<(), ConnectionError>>);
impl QuicHandler for Watch {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(Ok(()));
    }
    fn on_stream_data(&mut self, _c: &Connection, _id: StreamId, _d: Bytes, _fin: bool) {}
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        let _ = self.0.send(Err(r));
    }
}

fn server() -> QuicServer {
    let (certs, key) = tls();
    let cfg = akio_quic::server_config(certs, key, &[b"flt"]).unwrap();
    QuicServer::new(cfg, |_c: &Connection| Quiet)
}

fn client_engine() -> Engine {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    e
}

/// Dials `addr`; the receiver reports the handshake or the close.
fn dial(e: &Engine, addr: SocketAddr) -> (Connection, mpsc::Receiver<Result<(), ConnectionError>>) {
    let ccfg = akio_quic::client_config_insecure(&[b"flt"]).unwrap();
    let (tx, rx) = mpsc::channel();
    let c = akio_quic::dial(e, addr, "localhost", ccfg, Watch(tx)).unwrap();
    (c, rx)
}

fn filtered(e: &Engine) -> u64 {
    e.metrics().total.filtered
}

#[test]
fn a_refused_client_gets_no_connection_until_the_filter_is_swapped() {
    let srv = server();
    let s = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .filter(|_| false)
                .serve(srv.clone()),
        )
        .build()
        .unwrap();
    s.start().unwrap();
    let (id, addr) = (s.listeners()[0].id, s.local_addrs()[0]);
    let first = client_engine();
    let (_c, rx) = dial(&first, addr);
    // Dropped before any QUIC state: no handshake, nothing sent back.
    assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    assert_eq!(srv.connections(), 0);
    assert_eq!(s.udp_stats().peers, 0);
    assert!(filtered(&s) >= 1);
    // That client gives up (its socket closes, so its retransmissions stop).
    first.shutdown();
    first.wait();
    let e = client_engine();
    // Swapped without binding anew: a new client is served.
    s.set_listener_filter(id, |peer| peer.ip().is_loopback())
        .unwrap();
    let (_c2, rx2) = dial(&e, addr);
    assert_eq!(rx2.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    assert_eq!(srv.connections(), 1);
    e.shutdown();
    s.shutdown();
}

#[test]
fn a_new_quic_connection_from_a_known_udp_peer_asks_the_filter_again() {
    // Allows each address once: the UDP peer is made (first ask), its QUIC connection is not
    // (second ask, on the Initial), as when the filter changes between the two.
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let srv = server();
    let s = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .filter(move |_| n.fetch_add(1, Ordering::SeqCst) == 0)
                .serve(srv.clone()),
        )
        .build()
        .unwrap();
    s.start().unwrap();
    let (id, addr) = (s.listeners()[0].id, s.local_addrs()[0]);
    let e = client_engine();
    let (_c, rx) = dial(&e, addr);
    assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    // The UDP peer exists; no QUIC connection was made for it.
    assert_eq!(s.udp_stats().peers, 1);
    assert_eq!(srv.connections(), 0);
    assert!(calls.load(Ordering::SeqCst) >= 2);
    assert!(filtered(&s) >= 1);
    // Allowed now: the client's next Initial (a retransmission) on the same UDP peer is served.
    s.set_listener_filter(id, |_| true).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    assert_eq!(srv.connections(), 1);
    e.shutdown();
    s.shutdown();
}

#[test]
fn a_quic_server_on_a_bound_socket_takes_the_bindings_filter() {
    let srv = server();
    let s = Engine::builder().udp_client_threads(1).build().unwrap();
    s.start().unwrap();
    let bound = s
        .bind_udp_filtered("127.0.0.1:0".parse().unwrap(), srv.clone(), |_| false)
        .unwrap();
    let e = client_engine();
    let (_c, rx) = dial(&e, bound.local_addr());
    assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    assert_eq!(srv.connections(), 0);
    assert!(filtered(&s) >= 1);
    bound.clear_filter().unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    assert_eq!(srv.connections(), 1);
    bound.close();
    e.shutdown();
    s.shutdown();
}
