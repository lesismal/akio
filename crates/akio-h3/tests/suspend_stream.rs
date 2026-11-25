//! HTTP/3: a request whose body streams, suspended (`Context::suspend`, ADR-159, akit A75): its
//! stream held while suspended, what arrived kept for the resumed handler, which gets the whole
//! body in order; dropped unresumed, answered 500.
#![allow(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{BodyEvent, Context, Router, Streaming};

const T: Duration = Duration::from_secs(30);

fn pat(i: usize) -> u8 {
    (i * 7 % 251) as u8
}

fn later(ctx: &mut Context, first: &Arc<AtomicUsize>) {
    let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
    let s = ctx.suspend().expect("a streamed body suspends");
    let first = first.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(ms));
        s.resume(|ctx| {
            let (mut off, mut bad, mut n) = (0usize, None, 0);
            ctx.on_body(move |ctx, ev| match ev {
                BodyEvent::Chunk(b) => {
                    n += 1;
                    if n == 1 {
                        first.store(b.len(), Ordering::Relaxed);
                    }
                    for (i, &x) in b.iter().enumerate() {
                        if bad.is_none() && x != pat(off + i) {
                            bad = Some(off + i);
                        }
                    }
                    off += b.len();
                }
                BodyEvent::TooLarge => {}
                BodyEvent::End(_) => {
                    let r = match bad {
                        None => format!("ok {off}"),
                        Some(at) => format!("bad at {at}"),
                    };
                    ctx.text(200, r);
                }
            });
        });
    });
}

#[test]
fn h3_a_suspended_streamed_body_reaches_the_resumed_handler() {
    let first = Arc::new(AtomicUsize::new(0));
    let f2 = first.clone();
    let app = Router::new()
        .route(
            Method::Post,
            "/later/:ms",
            Streaming(move |ctx: &mut Context| later(ctx, &f2)),
        )
        .route(
            Method::Post,
            "/dropped",
            Streaming(|ctx: &mut Context| drop(ctx.suspend().unwrap())),
        );
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    let post = |path: &str, n: usize| {
        let body = (0..n).map(pat).collect();
        let r = c
            .request_blocking(Method::Post, path, &Headers::new(), body, T)
            .unwrap_or_else(|e| panic!("{path} {n}: {e:?}"));
        (r.status, String::from_utf8(r.body).unwrap())
    };
    assert_eq!(post("/later/0", 5), (200, "ok 5".to_owned()));
    let n = 3 << 20;
    assert_eq!(post("/later/200", n), (200, format!("ok {n}")));
    // What the stream's window let in while suspended, no more.
    let kept = first.load(Ordering::Relaxed);
    assert!(kept < n, "kept while suspended: {kept}");
    assert_eq!(post("/dropped", 100_000).0, 500);
    e.shutdown();
    e.wait();
}
