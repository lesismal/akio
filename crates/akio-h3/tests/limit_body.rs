//! HTTP/3: a request body bounded by a middleware (`Context::limit_body`, akit A49), and the
//! address a request came to (`Context::local_addr`, akit A148).
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{BodyEvent, Context, Router, Service, Streaming};

const T: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Seen {
    called: AtomicUsize,
    too_large: AtomicUsize,
}

fn app(seen: &Arc<Seen>) -> Router {
    let seen = seen.clone();
    Router::new()
        .post(
            "/sum",
            Streaming(move |ctx: &mut Context| {
                seen.called.fetch_add(1, Ordering::SeqCst);
                let seen = seen.clone();
                let mut n = 0usize;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => n += b.len(),
                    BodyEvent::End(_) => ctx.text(200, n.to_string()),
                    BodyEvent::TooLarge => {
                        seen.too_large.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }),
        )
        .layer(|ctx: &mut Context, next: &dyn Service| {
            if ctx.limit_body(1000) {
                next.call(ctx);
            }
        })
        .get("/local", |ctx: &mut Context| {
            let a = ctx.local_addr().to_string();
            ctx.text(200, a);
        })
}

fn server(seen: &Arc<Seen>) -> (Arc<Engine>, SocketAddr) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app(seen))),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

fn client(e: &Engine, addr: SocketAddr) -> H3Client {
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    H3Client::dial(e, addr, "localhost", cc).unwrap()
}

fn post(c: &H3Client, headers: &Headers, n: usize) -> (u16, String) {
    let r = c
        .request_blocking(Method::Post, "/sum", headers, vec![b'x'; n], T)
        .unwrap();
    (r.status, String::from_utf8(r.body).unwrap())
}

/// Under and at the limit, through; a declared length over it, refused before the handler; an
/// upload that grows past it, refused as it does, the sink told, and stopped (`STOP_SENDING`);
/// the connection serves on.
#[test]
fn limit_body_http3() {
    let seen = Arc::new(Seen::default());
    let (e, addr) = server(&seen);
    let c = client(&e, addr);
    let none = Headers::new();
    assert_eq!(post(&c, &none, 999), (200, "999".into()));
    assert_eq!(post(&c, &none, 1000), (200, "1000".into()));
    assert_eq!(seen.called.load(Ordering::SeqCst), 2);

    // The client declares the length of a body sent whole: refused before the handler runs.
    assert_eq!(post(&c, &none, 1001).0, 413);
    assert_eq!(
        seen.called.load(Ordering::SeqCst),
        2,
        "refused before the handler"
    );
    assert_eq!(seen.too_large.load(Ordering::SeqCst), 0);

    // An upload of no declared length that writes on past the limit: refused as it grows, the
    // sink told, answered, and its stream stopped.
    let (tx, rx) = mpsc::channel();
    let up = c.upload(Method::Post, "/sum", &none, move |r| {
        let _ = tx.send(r);
    });
    let piece = vec![b'y'; 16 << 10];
    let r = loop {
        let _ = up.write(&piece);
        if let Ok(r) = rx.recv_timeout(Duration::from_millis(5)) {
            break r.unwrap();
        }
    };
    assert_eq!(r.status, 413);
    assert_eq!(seen.called.load(Ordering::SeqCst), 3);
    assert_eq!(seen.too_large.load(Ordering::SeqCst), 1);
    // The stream is stopped: writing fails before long.
    let deadline = std::time::Instant::now() + T;
    while up.write(&piece) {
        assert!(
            std::time::Instant::now() < deadline,
            "the upload is stopped"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(post(&c, &none, 10), (200, "10".into()));
    e.shutdown();
}

/// The address a request came to: the UDP socket's.
#[test]
fn local_address_http3() {
    let seen = Arc::new(Seen::default());
    let (e, addr) = server(&seen);
    let c = client(&e, addr);
    let r = c.get("/local", T).unwrap();
    assert_eq!(String::from_utf8(r.body).unwrap(), addr.to_string());
    e.shutdown();
}
