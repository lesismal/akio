//! HTTP/3 under linked backpressure (ADR-101): a streamed request body whose reads the handler
//! holds (`Context::body_reads`), and a streamed response paced by its drain notices
//! (`BodyStream::on_drain`) instead of retrying refused writes.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{BodyEvent, Context, Router, Streaming};

const T: Duration = Duration::from_secs(30);

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 251) as u8).collect()
}

/// Holds the body's reads at its first chunk for `ms`, then answers `total,taken-while-held`.
fn held(ctx: &mut Context) {
    let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
    let reads = ctx.body_reads().expect("a streamed body");
    let total = Arc::new(AtomicUsize::new(0));
    let at_release = Arc::new(AtomicUsize::new(usize::MAX));
    let mut first = true;
    ctx.on_body(move |ctx, ev| match ev {
        BodyEvent::Chunk(b) => {
            total.fetch_add(b.len(), Ordering::Relaxed);
            if std::mem::take(&mut first) {
                reads.hold(true);
                let (reads, total, at) = (reads.clone(), total.clone(), at_release.clone());
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(ms));
                    at.store(total.load(Ordering::Relaxed), Ordering::Relaxed);
                    reads.hold(false);
                });
            }
        }
        BodyEvent::End(_) => {
            let t = total.load(Ordering::Relaxed);
            ctx.text(200, format!("{t},{}", at_release.load(Ordering::Relaxed)));
        }
    });
}

#[test]
fn held_body_reads_and_responses_paced_by_drains() {
    let drains = Arc::new(AtomicUsize::new(0));
    let d2 = drains.clone();
    let app = Router::new()
        .route(Method::Post, "/held/:ms", Streaming(held))
        .get("/paced/:n", move |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            let drains = d2.clone();
            thread::spawn(move || {
                let data = pattern(n);
                let (tx, rx) = mpsc::channel::<()>();
                for piece in data.chunks(64 << 10) {
                    // Refused: wait for the drain notice rather than retry in a loop.
                    while let Err(akio::Error::Overloaded) = s.write(piece) {
                        let (tx, drains) = (tx.clone(), drains.clone());
                        s.on_drain(move || {
                            drains.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(());
                        });
                        rx.recv_timeout(T).expect("the stream drains");
                    }
                }
                s.finish();
            });
        });
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let mut t = akio_quic::TransportConfig::default();
    t.stream_send_buffer = 256 << 10;
    t.send_buffer = 1 << 20;
    t.stream_receive_window = 256 << 10;
    let quic = akio_h3::server_config(vec![cert], key)
        .unwrap()
        .transport(&t);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut ct = akio_quic::TransportConfig::default();
    ct.stream_receive_window = 64 << 10;
    ct.receive_window = Some(256 << 10);
    let cc = akio_quic::client_config_insecure(&[b"h3"])
        .unwrap()
        .transport(&ct);
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();

    // Held: the stream's window (256 KiB) bounds what the client sends meanwhile.
    let n = 4 << 20;
    let (tx, rx) = mpsc::channel();
    c.request(
        Method::Post,
        "/held/400",
        &Headers::new(),
        pattern(n),
        move |r| {
            let _ = tx.send(r);
        },
    );
    let r = rx.recv_timeout(T).unwrap().unwrap();
    let text = String::from_utf8(r.body).unwrap();
    let (total, at) = text.split_once(',').unwrap();
    let (total, at): (usize, usize) = (total.parse().unwrap(), at.parse().unwrap());
    assert_eq!(total, n);
    assert!(at <= 1 << 20, "held: {at} of {n} taken meanwhile");

    // Paced by drains through a slow client: arrives whole, and the drains were waited for.
    let m = 6 << 20;
    let r = c.get(&format!("/paced/{m}"), T).unwrap();
    assert!(r.body == pattern(m), "paced body differs");
    assert!(
        drains.load(Ordering::Relaxed) > 0,
        "no drain was waited for"
    );
    c.close();
    e.shutdown();
    e.wait();
}
