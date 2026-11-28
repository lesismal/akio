//! A follow-up of akit's A301: an `H3Client` connection is closed (`H3_NO_ERROR`) at its
//! engine's graceful shutdown, so the server hears of it at once instead of at its idle
//! timeout, and the client's requests fail with a reason saying so.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use akio::{Config, Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3Error};
use akio_http::message::{Headers, Method};
use akio_http::{Context, Router};

/// Well under the 30 s QUIC idle timeout, after which the server would end the connection
/// anyway.
const T: Duration = Duration::from_secs(10);

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < T, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn a_clients_engine_shutdown_closes_its_connection_at_once() {
    // `/hang` is never answered: its responder is kept (and the test told) until the end.
    let (htx, hrx) = mpsc::channel();
    let htx = Mutex::new(htx);
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
        .post("/hang", move |ctx: &mut Context| {
            let _ = htx.lock().unwrap().send(ctx.detach());
        });
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let server = akio_h3::serve_with(quic, H3Config::default(), app);
    let se = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(server.clone()))
        .build()
        .unwrap();
    se.start().unwrap();
    let addr = se.local_addrs()[0];

    let ce = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_secs(20);
                v
            })
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    ce.start().unwrap();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial_with(&ce, addr, "localhost", cc, H3ClientOptions::default()).unwrap();
    assert_eq!(c.get("/", T).unwrap().body, b"hello h3");
    let (tx, rx) = mpsc::channel();
    c.request(
        Method::Post,
        "/hang",
        &Headers::new(),
        b"x".to_vec(),
        move |r| {
            let _ = tx.send(r);
        },
    );
    // The request reached the server, which holds it.
    let held = hrx.recv_timeout(T).unwrap();
    assert!(held.is_some());
    assert!(rx.try_recv().is_err());
    assert_eq!(server.connections(), 1);

    let t0 = Instant::now();
    ce.shutdown();
    ce.wait();
    assert!(t0.elapsed() < T, "{:?}", t0.elapsed());
    let shutting_down = H3Error::Closed("the engine is shutting down".into());
    assert_eq!(rx.recv_timeout(T).unwrap().unwrap_err(), shutting_down);
    // New requests are refused, with the same reason.
    assert_eq!(c.get("/", T).unwrap_err(), shutting_down);
    // The server heard the client's CONNECTION_CLOSE, long before its idle timeout.
    wait_until("the server's connection closed", || {
        server.connections() == 0
    });
    drop(held);
    se.shutdown();
    se.wait();
}
