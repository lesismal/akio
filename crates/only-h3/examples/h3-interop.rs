//! HTTP/3 interop peer for tools/interop/h3 (quic-go):
//!
//! ```text
//! h3-interop server 127.0.0.1:9401   serves /, /user/:id, /echo, /stream (with trailers)
//! h3-interop client 127.0.0.1:9400   checks a quic-go server
//! h3-interop client-fib 127.0.0.1:9402   checks a fib server (/ and /echo only)
//! ```

use std::time::Duration;

use only::{Engine, Listener};
use only_h3::H3Client;
use only_http::message::{Headers, Method};
use only_http::{Context, Router};

fn fail(msg: String) -> ! {
    println!("FAIL: {msg}");
    std::process::exit(1)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + (i >> 9)) as u8).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a[2].parse().expect("addr");
    if a[1] == "server" {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let cert = only::tls::Certificate::from_der(ck.cert.der().to_vec());
        let key = only::tls::PrivateKey::from_pkcs8_der(ck.key_pair.serialize_der());
        let app = Router::new()
            .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
            .get("/user/:id", |ctx: &mut Context| {
                let id = ctx.param("id").unwrap_or("?").to_owned();
                ctx.text(200, format!("user {id} {:?}", ctx.req().version));
            })
            .post("/echo", |ctx: &mut Context| {
                let body = ctx.req().body.clone();
                ctx.bytes(200, "application/octet-stream", body);
            })
            .get("/stream", |ctx: &mut Context| {
                let mut h = Headers::new();
                h.set("trailer", "x-checksum");
                let s = ctx.stream_response(200, h).expect("stream");
                for i in 0..50 {
                    let _ = s.write(format!("line {i}\n").as_bytes());
                }
                let mut t = Headers::new();
                t.set("x-checksum", "abc");
                s.finish_with_trailers(t);
            });
        let quic = only_h3::server_config(vec![cert], key).expect("config");
        let e = Engine::builder()
            .listen(Listener::udp(addr).serve(only_h3::serve(quic, app)))
            .build()
            .expect("engine");
        e.start().expect("start");
        println!("ready");
        e.wait();
        return;
    }
    let e = Engine::builder()
        .udp_client_threads(1)
        .build()
        .expect("engine");
    e.start().expect("start");
    let cc = only_quic::client_config_insecure(&[b"h3"]).expect("client config");
    let c = H3Client::dial(&e, addr, "localhost", cc).expect("connect");
    let t = Duration::from_secs(20);
    let r = c.get("/", t).unwrap_or_else(|e| fail(e.to_string()));
    let body = String::from_utf8_lossy(&r.body).into_owned();
    let fib = a[1] == "client-fib";
    let want = if fib {
        "hello from fib HTTP/3"
    } else {
        "hello from quic-go HTTP/3.0 localhost"
    };
    if r.status != 200 || !body.starts_with(want) {
        fail(format!("GET /: {} {body:?}", r.status));
    }
    let mut h = Headers::new();
    h.set("x-test", "yes");
    let big = pattern(3 << 20);
    let r = c
        .request_blocking(Method::Post, "/echo", &h, big.clone(), t)
        .unwrap_or_else(|e| fail(e.to_string()));
    if r.body != big || (!fib && r.headers.get("x-req-header") != Some("yes")) {
        fail(format!("POST /echo: {} bytes", r.body.len()));
    }
    if fib {
        parallel(&c, t);
        c.close();
        println!("ok: only-h3 client -> fib server");
        return;
    }
    let r = c
        .get("/trailers", t)
        .unwrap_or_else(|e| fail(e.to_string()));
    let sum = r
        .trailers
        .as_ref()
        .and_then(|t| t.get("x-sum").map(str::to_owned));
    if r.body != b"body" || sum.as_deref() != Some("42") {
        fail(format!("trailers: {:?} {sum:?}", r.body));
    }
    let r = c.get("/big", t).unwrap_or_else(|e| fail(e.to_string()));
    if r.body != pattern(4 << 20) {
        fail(format!("GET /big: {} bytes", r.body.len()));
    }
    parallel(&c, t);
    c.close();
    println!("ok: only-h3 client -> quic-go server");
}

fn parallel(c: &H3Client, t: Duration) {
    let (tx, rx) = std::sync::mpsc::channel();
    for i in 0..200 {
        let tx = tx.clone();
        c.request(Method::Get, "/", &Headers::new(), Vec::new(), move |r| {
            let _ = tx.send((i, r));
        });
    }
    for _ in 0..200 {
        let (i, r) = rx
            .recv_timeout(t)
            .unwrap_or_else(|_| fail("parallel: timeout".into()));
        if r.map(|r| r.status) != Ok(200) {
            fail(format!("parallel {i}"));
        }
    }
}
