//! HTTP/3 requests that hear their client go before their response is finished
//! (`Detached::on_gone`, `ConnSink::on_gone`, ADR-108): a detached request and an unfinished
//! streamed response when the client closes the connection; answered and finished ones hear
//! nothing.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{Context, Detached, Response, Router};

const T: Duration = Duration::from_secs(10);

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    f()
}

#[test]
fn requests_hear_their_client_go() {
    let gone = Arc::new(Mutex::new(Vec::<String>::new()));
    let (tx, arrived) = mpsc::channel::<String>();
    let tx = Arc::new(Mutex::new(tx));
    let held = Arc::new(Mutex::new(Vec::<Detached>::new()));
    let streams = Arc::new(Mutex::new(Vec::new()));
    let cb = |gone: &Arc<Mutex<Vec<String>>>, p: &str| {
        let (g, p) = (gone.clone(), p.to_owned());
        move || g.lock().unwrap().push(p)
    };
    let (g1, g2, g3) = (gone.clone(), gone.clone(), gone.clone());
    let (t1, t2, t3) = (tx.clone(), tx.clone(), tx);
    let app = Router::new()
        .get("/wait", move |ctx: &mut Context| {
            let mut d = ctx.detach().unwrap();
            d.on_gone(cb(&g1, "/wait"));
            held.lock().unwrap().push(d);
            let _ = t1.lock().unwrap().send("/wait".into());
        })
        .get("/answered", move |ctx: &mut Context| {
            ctx.on_gone(cb(&g2, "/answered"));
            let d = ctx.detach().unwrap();
            d.respond(Response::text(200, "done"));
            let _ = t2.lock().unwrap().send("/answered".into());
        })
        .get("/stream/:finish", move |ctx: &mut Context| {
            let finish = ctx.param("finish") == Some("1");
            let path = format!("/stream/{}", u8::from(finish));
            ctx.on_gone(cb(&g3, &path));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"part").unwrap();
            if finish {
                s.finish();
            } else {
                streams.lock().unwrap().push(s);
            }
            let _ = t3.lock().unwrap().send(path);
        });
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

    assert_eq!(c.get("/answered", T).unwrap().body, b"done");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/answered");
    assert_eq!(c.get("/stream/1", T).unwrap().body, b"part");
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/stream/1");
    for path in ["/wait", "/stream/0"] {
        c.request(Method::Get, path, &Headers::new(), Vec::new(), |_| {});
        assert_eq!(arrived.recv_timeout(T).unwrap(), path);
    }
    thread::sleep(Duration::from_millis(100));
    assert!(gone.lock().unwrap().is_empty());
    c.close();
    assert!(wait_until(T, || gone.lock().unwrap().len() == 2));
    thread::sleep(Duration::from_millis(200));
    let mut g = gone.lock().unwrap().clone();
    g.sort();
    assert_eq!(g, ["/stream/0", "/wait"]);
    e.shutdown();
    e.wait();
}
