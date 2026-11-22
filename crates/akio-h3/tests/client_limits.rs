//! The HTTP/3 client's limits: response body and field section caps, the request timeout.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3ClientOptions, H3Config, H3Error};
use akio_http::message::{Headers, Method};
use akio_http::{Context, Response, Router};

const T: Duration = Duration::from_secs(10);

fn setup(opts: H3ClientOptions) -> (Arc<Engine>, H3Client) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    // Detached responses that are never answered (kept so they are not answered on drop).
    let parked = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .get("/size/:n", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            ctx.bytes(200, "application/octet-stream", vec![b'x'; n]);
        })
        .get("/head/:n", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            ctx.respond(Response::text(200, "h").header("x-big", "v".repeat(n)));
        })
        .get("/never", move |ctx: &mut Context| {
            parked.lock().unwrap().push(ctx.detach().unwrap());
        });
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let mut scfg = H3Config::default();
    scfg.max_field_section_bytes = 1 << 20;
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(akio_h3::serve_with(quic, scfg, app)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial_with(&e, addr, "localhost", cc, opts).unwrap();
    (Arc::new(e), client)
}

#[test]
fn h3_client_defaults_match_the_server_limits() {
    let (o, s) = (H3ClientOptions::default(), H3Config::default());
    assert_eq!(o.max_body_bytes, s.max_body_bytes);
    assert_eq!(o.max_field_section_bytes, s.max_field_section_bytes);
    assert_eq!(o.request_timeout, Some(Duration::from_secs(30)));
}

#[test]
fn body_and_field_section_limits() {
    let mut o = H3ClientOptions::default();
    o.max_body_bytes = 100_000;
    o.max_field_section_bytes = 4096;
    let (e, c) = setup(o);
    for (n, ok) in [(99_999, true), (100_000, true), (100_001, false)] {
        let r = c.get(&format!("/size/{n}"), T);
        match r {
            Ok(r) if ok => assert_eq!(r.body.len(), n),
            Err(H3Error::TooLarge(_)) if !ok => {}
            r => panic!("{n}: {r:?}"),
        }
    }
    // Far over: the stream is stopped, not read to the end.
    let r = c.get("/size/5000000", T);
    assert!(matches!(r, Err(H3Error::TooLarge(_))), "{r:?}");
    let r = c.get("/head/100", T).unwrap();
    assert_eq!(r.headers.get("x-big").map(str::len), Some(100));
    let r = c.get("/head/8000", T);
    assert!(matches!(r, Err(H3Error::TooLarge(_))), "{r:?}");
    // The connection still works.
    assert_eq!(c.get("/size/3", T).unwrap().body, b"xxx");
    e.shutdown();
}

#[test]
fn request_timeout_fails_unanswered_requests() {
    let mut o = H3ClientOptions::default();
    o.request_timeout = Some(Duration::from_millis(300));
    let (e, c) = setup(o);
    let (tx, rx) = std::sync::mpsc::channel();
    let t0 = Instant::now();
    c.request(
        Method::Get,
        "/never",
        &Headers::new(),
        Vec::new(),
        move |r| {
            let _ = tx.send(r);
        },
    );
    let r = rx.recv_timeout(T).unwrap();
    assert_eq!(r.unwrap_err(), H3Error::Timeout);
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "{took:?}"
    );
    // Answered requests are unaffected, also past the timeout of earlier ones.
    for _ in 0..3 {
        assert_eq!(c.get("/size/2", T).unwrap().body, b"xx");
        std::thread::sleep(Duration::from_millis(150));
    }
    e.shutdown();
}
