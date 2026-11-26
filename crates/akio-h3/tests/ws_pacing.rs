//! A WebSocket over HTTP/3 paced from outside (ADR-183, akit A236): `WsSender::hold_reads`
//! holds the request stream (what arrives stays in the QUIC stream's buffer), `on_drain` runs
//! once the stream's send buffer has room, `peer_addr` is the QUIC connection's peer; both
//! ends, from a thread other than the connection's.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3WsOptions};
use akio_http::ws::{MessageRef, WsHandler, WsSender};
use akio_http::{Context, Router, WsOptions};

const T: Duration = Duration::from_secs(20);
const MSG: usize = 16 << 10;

/// A server's end as it opened: its sender and the bytes it got.
type Opened = (WsSender, Arc<AtomicUsize>);

/// Counts the bytes of the messages it gets; the server's hands its sender over on open.
struct Count {
    got: Arc<AtomicUsize>,
    open: Option<Arc<Mutex<mpsc::Sender<Opened>>>>,
}

impl WsHandler for Count {
    fn on_open(&mut self, ws: &WsSender) {
        if let Some(tx) = &self.open {
            let _ = tx.lock().unwrap().send((ws.clone(), self.got.clone()));
        }
    }
    fn on_message_ref(&mut self, _ws: &WsSender, msg: MessageRef<'_>) {
        self.got.fetch_add(msg.as_bytes().len(), Ordering::AcqRel);
    }
}

fn server() -> (Arc<Engine>, SocketAddr, mpsc::Receiver<Opened>) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let app = Router::new().get("/ws", move |ctx: &mut Context| {
        let mut o = WsOptions::default();
        o.config.permessage_deflate = false;
        ctx.upgrade_websocket(
            Count {
                got: Arc::default(),
                open: Some(tx.clone()),
            },
            &o,
        );
    });
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve_with(
                quic,
                H3Config::default(),
                app,
            )),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr, rx)
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < T, "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

/// `to` holds its reads; `from` sends 4 MiB; nothing reaches `to`'s handler until it resumes,
/// then all of it does, and a drain waiter of `from` runs.
fn held_then_resumed(from: &WsSender, to: &WsSender, to_got: &AtomicUsize) {
    let base = to_got.load(Ordering::Acquire);
    to.hold_reads(true);
    let msg = vec![0x3c; MSG];
    let mut sent = 0;
    while sent < 4 << 20 {
        match from.send_binary(&msg) {
            Ok(()) => sent += MSG,
            Err(akio::Error::Overloaded) => break,
            Err(e) => panic!("send: {e:?}"),
        }
    }
    thread::sleep(Duration::from_millis(300));
    assert_eq!(to_got.load(Ordering::Acquire), base, "delivered while held");
    to.hold_reads(false);
    wait_for("everything after the reads resumed", || {
        to_got.load(Ordering::Acquire) - base == sent
    });
    let (dtx, drx) = mpsc::channel();
    from.on_drain(move || {
        let _ = dtx.send(());
    });
    drx.recv_timeout(T).expect("the drain waiter ran");
}

#[test]
fn http3_websocket_paced_both_ways() {
    let (e, addr, opened) = server();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial_with(&e, addr, "localhost", cc, H3ClientOptions::default()).unwrap();
    let got = Arc::new(AtomicUsize::new(0));
    let mut o = H3WsOptions::default();
    o.config.permessage_deflate = false;
    let client = c
        .websocket_blocking(
            "/ws",
            &o,
            Count {
                got: got.clone(),
                open: None,
            },
            T,
        )
        .unwrap();
    let (server, server_got) = opened.recv_timeout(T).unwrap();
    assert_eq!(client.peer_addr(), Some(addr));
    let p = server.peer_addr().expect("the client's address");
    assert!(p.ip().is_loopback() && p.port() != addr.port(), "{p}");
    held_then_resumed(&client, &server, &server_got);
    held_then_resumed(&server, &client, &got);
    // The stream's queue is bounded by QUIC's send buffers; relaying is the stream's already.
    assert!(server.set_max_queued_bytes(Some(1 << 20)).is_err());
    server.set_relayed(true);
    // A waiter set after the stream is gone runs at once.
    client.close(1000, "");
    wait_for("closed", || !server.is_open());
    let (dtx, drx) = mpsc::channel();
    server.on_drain(move || {
        let _ = dtx.send(());
    });
    drx.recv_timeout(T).expect("the drain waiter ran");
    e.shutdown();
}
