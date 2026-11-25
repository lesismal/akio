//! HTTP/3 requests: their end heard (`Context::on_end`, `Detached::on_end`, ADR-127): a
//! response sent whole, a streamed one once finished, a detached one whose client goes, a
//! detached one dropped unanswered; and a request changed by a middleware (`Context::req_mut`,
//! ADR-126) before its handler.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{Context, Detached, End, Request, Response, Router, Service};

const T: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }

    fn end(&self, path: &str) -> impl FnOnce(End) + Send + 'static {
        let (l, p) = (self.clone(), path.to_owned());
        move |e| l.push(format!("{p} {e:?}"))
    }

    fn of(&self, path: &str) -> Vec<String> {
        let pre = format!("{path} ");
        let v = self.0.lock().unwrap();
        v.iter().filter(|s| s.starts_with(&pre)).cloned().collect()
    }

    fn wait(&self, path: &str, want: &[&str]) {
        let t0 = Instant::now();
        while t0.elapsed() < T && self.of(path) != want {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(self.of(path), want, "{path}");
    }
}

/// Rewrites `/old/...` to `/new/...` and edits fields, in front of the router.
struct Front(Router);

impl Service for Front {
    fn call(&self, ctx: &mut Context) {
        if ctx.path().starts_with("/old/") {
            let r = ctx.req_mut().expect("owned before the handler");
            r.target = r.target.replacen("/old/", "/new/", 1);
            r.headers.set("x-set", "1");
            r.headers.remove("x-drop");
        }
        self.0.call(ctx);
    }
}

#[test]
fn requests_end_and_are_changed() {
    let log = Log::default();
    let (tx, arrived) = mpsc::channel::<String>();
    let tx = Arc::new(Mutex::new(tx));
    let held = Arc::new(Mutex::new(Vec::<Detached>::new()));
    let (l1, l2, l3, l4, l5) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    let (t1, t2) = (tx.clone(), tx);
    let app = Router::new()
        .get("/now", move |ctx: &mut Context| {
            ctx.on_end(l1.end("/now"));
            ctx.text(200, "now");
        })
        .get("/stream", move |ctx: &mut Context| {
            ctx.on_end(l2.end("/stream"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"part").unwrap();
            let l = l2.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                l.push("/stream finishing".into());
                s.finish();
            });
        })
        .get("/wait", move |ctx: &mut Context| {
            ctx.on_end(l3.end("/wait"));
            held.lock().unwrap().push(ctx.detach().unwrap());
            let _ = t1.lock().unwrap().send("/wait".into());
        })
        .get("/dropped", move |ctx: &mut Context| {
            let mut d = ctx.detach().unwrap();
            d.on_end(l4.end("/dropped"));
            drop(d);
            let _ = t2.lock().unwrap().send("/dropped".into());
        })
        .get("/new/:id", move |ctx: &mut Context| {
            l5.push(format!(
                "/new path={} id={} set={:?} drop={:?}",
                ctx.path(),
                ctx.param("id").unwrap_or("-"),
                ctx.header("x-set"),
                ctx.header("x-drop"),
            ));
            ctx.add_response_filter(|resp: &mut Response, req: &Request| {
                resp.headers.set("x-target", req.target.as_str());
            });
            ctx.text(200, "new");
        });
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, Front(app))),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();

    assert_eq!(c.get("/now", T).unwrap().body, b"now");
    log.wait("/now", &["/now Sent"]);
    assert_eq!(c.get("/stream", T).unwrap().body, b"part");
    log.wait("/stream", &["/stream finishing", "/stream Sent"]);

    let mut h = Headers::new();
    h.append("x-drop", "yes");
    let (rtx, rrx) = mpsc::channel();
    c.request(Method::Get, "/old/7?q=1", &h, Vec::new(), move |r| {
        let _ = rtx.send(r.map(|r| r.headers.get("x-target").map(str::to_owned)));
    });
    let target = rrx.recv_timeout(T).unwrap().unwrap();
    assert_eq!(target.as_deref(), Some("/new/7?q=1"));
    assert_eq!(
        log.of("/new"),
        ["/new path=/new/7 id=7 set=Some(\"1\") drop=None"]
    );

    c.request(Method::Get, "/dropped", &Headers::new(), Vec::new(), |_| {});
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/dropped");
    log.wait("/dropped", &["/dropped Gone"]);
    c.request(Method::Get, "/wait", &Headers::new(), Vec::new(), |_| {});
    assert_eq!(arrived.recv_timeout(T).unwrap(), "/wait");
    thread::sleep(Duration::from_millis(100));
    assert!(log.of("/wait").is_empty());
    c.close();
    log.wait("/wait", &["/wait Gone"]);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(log.of("/now"), ["/now Sent"]);
    assert_eq!(log.of("/wait"), ["/wait Gone"]);
    e.shutdown();
    e.wait();
}
