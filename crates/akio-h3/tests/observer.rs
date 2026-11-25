//! HTTP/3: a listener's response observer (`akio_h3::serve_with_observer`,
//! `Context::set_observed`, ADR-158, akit A29): told once of each observed request's response,
//! inline, detached or streamed, with its words; not of a request that did not ask.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Config};
use akio_http::message::Headers;
use akio_http::{Context, Request, Response, ResponseObserver, Router};

const T: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Log(Mutex<Vec<(String, u16, [u64; 2])>>);

impl ResponseObserver for Log {
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant) {
        assert!(started.elapsed() < T);
        self.0
            .lock()
            .unwrap()
            .push((req.path().to_owned(), resp.status, words));
    }
}

impl Log {
    fn of(&self, path: &str) -> Vec<(u16, [u64; 2])> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.0 == path)
            .map(|s| (s.1, s.2))
            .collect()
    }
}

fn app() -> Router {
    Router::new()
        .get("/inline", |ctx: &mut Context| {
            assert!(ctx.set_observed([1, 2]));
            ctx.text(200, "inline");
        })
        .get("/unobserved", |ctx: &mut Context| {
            ctx.text(200, "unobserved");
        })
        .get("/detached", |ctx: &mut Context| {
            ctx.set_observed([3, 4]);
            let d = ctx.detach().unwrap();
            thread::spawn(move || d.respond(Response::text(201, "detached")));
        })
        .get("/streamed", |ctx: &mut Context| {
            ctx.set_observed([5, 6]);
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                s.write(b"streamed").unwrap();
                s.finish();
            });
        })
}

#[test]
fn h3_responses_are_observed() {
    let log = Arc::new(Log::default());
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e =
        Engine::builder()
            .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(
                akio_h3::serve_with_observer(quic, H3Config::default(), app(), log.clone()),
            ))
            .udp_client_threads(1)
            .build()
            .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    for (path, status) in [
        ("/inline", 200),
        ("/unobserved", 200),
        ("/detached", 201),
        ("/streamed", 200),
    ] {
        assert_eq!(c.get(path, T).unwrap().status, status, "{path}");
    }
    let t0 = Instant::now();
    while t0.elapsed() < T && log.0.lock().unwrap().len() < 3 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(log.of("/inline"), [(200, [1, 2])]);
    assert_eq!(log.of("/detached"), [(201, [3, 4])]);
    assert_eq!(log.of("/streamed"), [(200, [5, 6])]);
    assert!(log.of("/unobserved").is_empty());
    e.shutdown();
    e.wait();
}
