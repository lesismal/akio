//! HTTP/3 end to end over loopback with a flash-http Router.

use std::sync::Arc;
use std::time::Duration;

use flash::{Engine, Listener};
use flash_h3::{H3Client, H3Config};
use flash_http::message::{Headers, Method};
use flash_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

fn setup(cfg: H3Config) -> (Arc<Engine>, H3Client) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key =
        flash_quic::rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
        .get("/user/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap_or("?").to_owned();
            let v = format!("{:?}", ctx.req().version);
            ctx.text(
                200,
                format!("user {id} {v} {}", ctx.header("host").unwrap_or("")),
            );
        })
        .post("/echo", |ctx: &mut Context| {
            let body = ctx.req().body.clone();
            ctx.bytes(200, "application/octet-stream", body);
        })
        .get("/later", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                d.respond(flash_http::Response::text(202, "later"));
            });
        })
        .get("/stream", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            std::thread::spawn(move || {
                for i in 0..50 {
                    s.write(format!("chunk {i}\n").as_bytes()).unwrap();
                }
                let mut t = Headers::new();
                t.set("x-checksum", "abc");
                s.finish_with_trailers(t);
            });
        });
    let quic = flash_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(flash_h3::serve_with(quic, cfg, app)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = flash_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    (Arc::new(e), client)
}

#[test]
fn requests_over_h3() {
    let (e, c) = setup(H3Config::default());
    let r = c.get("/", T).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"hello h3");
    assert_eq!(r.headers.get("content-length"), Some("8"));
    assert!(r.headers.get("date").is_some());
    let r = c.get("/user/42", T).unwrap();
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!("user 42 Http3 localhost:{}", e.local_addrs()[0].port())
    );
    assert_eq!(c.get("/nope", T).unwrap().status, 404);
    let r = c
        .request_blocking(Method::Head, "/", &Headers::new(), Vec::new(), T)
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.headers.get("content-length"), Some("8"));
    let big: Vec<u8> = (0..3 << 20).map(|i| (i % 253) as u8).collect();
    let r = c
        .request_blocking(Method::Post, "/echo", &Headers::new(), big.clone(), T)
        .unwrap();
    assert_eq!(r.status, 200);
    assert!(r.body == big);
    assert_eq!(c.get("/later", T).unwrap().status, 202);
    let r = c.get("/stream", T).unwrap();
    assert_eq!(r.body.iter().filter(|&&b| b == b'\n').count(), 50);
    assert_eq!(r.trailers.unwrap().get("x-checksum"), Some("abc"));
    // Many requests at once, on parallel streams.
    let (tx, rx) = std::sync::mpsc::channel();
    for i in 0..300 {
        let tx = tx.clone();
        c.request(
            Method::Get,
            &format!("/user/{i}"),
            &Headers::new(),
            Vec::new(),
            move |r| {
                let _ = tx.send((i, r));
            },
        );
    }
    for _ in 0..300 {
        let (i, r) = rx.recv_timeout(T).unwrap();
        let body = String::from_utf8(r.unwrap().body).unwrap();
        assert!(body.starts_with(&format!("user {i} ")), "{body}");
    }
    c.close();
    std::thread::sleep(Duration::from_millis(50));
    assert!(c.get("/", T).is_err());
    e.shutdown();
}

#[test]
fn limits() {
    let (e, c) = setup({
        let mut v = H3Config::default();
        v.max_body_bytes = 1000;
        v.max_field_section_bytes = 400;
        v
    });
    let r = c
        .request_blocking(Method::Post, "/echo", &Headers::new(), vec![1; 5000], T)
        .unwrap();
    assert_eq!(r.status, 413);
    let mut h = Headers::new();
    h.set("x-big", "v".repeat(1000));
    let r = c
        .request_blocking(Method::Get, "/", &h, Vec::new(), T)
        .unwrap();
    assert_eq!(r.status, 431);
    assert_eq!(
        c.get("/", T).unwrap().status,
        200,
        "the connection survives"
    );
    e.shutdown();
}
