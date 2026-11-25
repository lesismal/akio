//! An HTTP/3 server whose UDP listener is removed with a drain, or whose bound socket drains
//! (ADR-155, akit A22): `GOAWAY`, the requests in flight answered, later ones refused.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

fn app(started: Arc<AtomicBool>) -> Router {
    Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
        .get("/slow", move |ctx: &mut Context| {
            started.store(true, Ordering::SeqCst);
            let d = ctx.detach().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(500));
                d.respond(akio_http::Response::text(200, "slow"));
            });
        })
}

fn quic() -> akio_quic::ServerConfig {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    akio_h3::server_config(vec![cert], key).unwrap()
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < T, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Sends a slow request, waits until the server has it, then runs `drain`; checks that a new
/// request on the connection is refused and the slow one is answered.
fn drains(e: &Engine, client: &H3Client, started: &Arc<AtomicBool>, drain: impl FnOnce()) {
    let r = client.get("/", T).unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello h3"[..]));
    let c2 = client.clone();
    let slow = std::thread::spawn(move || c2.get("/slow", T));
    wait_for("slow request", || started.load(Ordering::SeqCst));
    drain();
    // After GOAWAY the connection takes no new request.
    assert!(
        client.get("/", T).is_err(),
        "a request after GOAWAY is refused"
    );
    // The one in flight is answered.
    let r = slow.join().unwrap().unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"slow"[..]));
    e.shutdown();
    e.wait();
}

#[test]
fn a_drained_listener_sends_goaway_and_answers_requests_in_flight() {
    let started = Arc::new(AtomicBool::new(false));
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(akio_h3::serve(quic(), app(started.clone()))),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let id = e.listeners()[0].id;
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    drains(&e, &client, &started, || {
        e.shutdown_listener(id, Duration::from_secs(5)).unwrap();
    });
}

#[test]
fn a_drained_binding_sends_goaway_and_answers_requests_in_flight() {
    let started = Arc::new(AtomicBool::new(false));
    let e = Engine::builder().udp_client_threads(2).build().unwrap();
    e.start().unwrap();
    let bound = e
        .bind_udp(
            "127.0.0.1:0".parse().unwrap(),
            akio_h3::serve(quic(), app(started.clone())),
        )
        .unwrap();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial(&e, bound.local_addr(), "localhost", cc).unwrap();
    drains(&e, &client, &started, || {
        bound.shutdown(Duration::from_secs(5));
        // `shutdown` returns at once: the drain begins on the socket's I/O thread.
        std::thread::sleep(Duration::from_millis(100));
    });
}
