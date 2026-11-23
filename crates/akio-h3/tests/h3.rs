//! HTTP/3 end to end over loopback with a akio-http Router.

use std::sync::Arc;
use std::time::Duration;

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Config};
use akio_http::message::{Headers, Method};
use akio_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

fn setup(cfg: H3Config) -> (Arc<Engine>, H3Client) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h3"))
        .get("/t/*rest", |ctx: &mut Context| {
            let t = ctx.req().target.clone();
            ctx.text(200, t);
        })
        .get("/d/*rest", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            std::thread::spawn(move || {
                let t = d.req().target.clone();
                d.respond(akio_http::Response::text(200, t));
            });
        })
        .get("/h/:n", echo_fields)
        .get("/hd/:n", echo_fields)
        .get("/s/:len", |ctx: &mut Context| {
            let len: usize = ctx.param("len").unwrap().parse().unwrap();
            ctx.text(200, text_of(len));
        })
        .get("/sd/:len", |ctx: &mut Context| {
            let len: usize = ctx.param("len").unwrap().parse().unwrap();
            let d = ctx.detach().unwrap();
            std::thread::spawn(move || d.respond(akio_http::Response::text(200, text_of(len))));
        })
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
                d.respond(akio_http::Response::text(202, "later"));
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
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(akio_h3::serve_with(quic, cfg, app)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    (Arc::new(e), client)
}

/// Requests on one connection reuse a finished request's target buffer and answer through the
/// connection's shared sink (ADR-025): each still sees exactly its own target, and HEAD still
/// gets no body.
#[test]
fn targets_reuse_the_buffer_and_stay_exact() {
    let (_e, c) = setup(H3Config::default());
    let long = format!("/t/{}", "w".repeat(1500));
    for t in [
        "/t/a-fairly-long-first-target?q=1",
        "/t/b",
        "/d/detached",
        "/t/c?q",
        &long,
        "/t/d",
    ] {
        let r = c.get(t, T).unwrap();
        assert_eq!(
            (r.status, String::from_utf8(r.body).unwrap().as_str()),
            (200, t)
        );
    }
    let r = c
        .request_blocking(Method::Head, "/t/head", &Headers::new(), Vec::new(), T)
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.headers.get("content-length"), Some("7"));
    let r = c.get("/t/after-head", T).unwrap();
    assert_eq!(r.body, b"/t/after-head");
}

/// Echoes the request's `x-` fields in order and answers with `:n` extra fields `r-0`, `r-1`...
/// (from another thread when the path starts with `/hd/`).
fn echo_fields(ctx: &mut Context) {
    let n: usize = ctx.param("n").unwrap().parse().unwrap();
    let body: String = ctx
        .req()
        .headers
        .iter()
        .filter(|(k, _)| k.starts_with("x-"))
        .map(|(k, v)| format!("{k}={v};"))
        .collect();
    let mut r = akio_http::Response::text(200, body);
    for i in 0..n {
        r = r.header(&format!("r-{i}"), format!("v{i}"));
    }
    if ctx.path().starts_with("/hd/") {
        let d = ctx.detach().unwrap();
        std::thread::spawn(move || d.respond(r));
    } else {
        ctx.respond(r);
    }
}

/// Request and response heads of every size, one after another on a connection, as the
/// per-thread spare header storage sees them (ADR-081): `(path, request x- fields)`.
fn field_cases() -> Vec<(String, Vec<(String, String)>)> {
    let f = |n: &str, v: &str| (n.to_owned(), v.to_owned());
    vec![
        (
            "/h/5".into(),
            (0..10)
                .map(|i| f(&format!("x-f{i}"), &"v".repeat(i)))
                .collect(),
        ),
        ("/h/0".into(), vec![f("x-one", "1")]),
        ("/h/3".into(), vec![f("x-big", &"b".repeat(5000))]),
        ("/h/0".into(), vec![]),
        (
            "/hd/4".into(),
            vec![f("x-d1", "a"), f("x-d2", "b"), f("x-d3", "c")],
        ),
        ("/h/1".into(), vec![f("x-two", "2")]),
        (
            "/h/2".into(),
            vec![f("x-m", "m"), f("x-n", ""), f("x-o", "o")],
        ),
    ]
}

/// The fields `echo_fields` should answer `path` with: `(body, r- fields)`.
fn expected(path: &str, fs: &[(String, String)]) -> (String, usize) {
    let body = fs.iter().map(|(n, v)| format!("{n}={v};")).collect();
    (body, path.rsplit('/').next().unwrap().parse().unwrap())
}

/// Each request sees exactly its own fields and each response carries exactly its own,
/// whatever the heads before them on the connection held (ADR-081).
#[test]
fn heads_reuse_header_storage_and_stay_exact() {
    let (_e, c) = setup(H3Config::default());
    for _ in 0..2 {
        for (p, fs) in field_cases() {
            let mut h = Headers::new();
            for (n, v) in &fs {
                h.append(n, v);
            }
            let r = c
                .request_blocking(Method::Get, &p, &h, Vec::new(), T)
                .unwrap();
            let (body, n) = expected(&p, &fs);
            assert_eq!(String::from_utf8(r.body).unwrap(), body, "{p}");
            for i in 0..8 {
                let v = format!("v{i}");
                let got = r.headers.get(&format!("r-{i}"));
                assert_eq!(got, (i < n).then_some(v.as_str()), "{p}");
            }
            assert_eq!(r.headers.get_all("content-type").count(), 1, "{p}");
        }
    }
}

/// A `&'static str` of `len` bytes (a repeating pattern, so a byte out of place shows).
fn text_of(len: usize) -> &'static str {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    &S.get_or_init(|| {
        (0..400_000)
            .map(|i| char::from(b'a' + (i % 23) as u8))
            .collect()
    })[..len]
}

/// Body lengths around the pool's size classes, for `text(200, &str)` bodies (ADR-081).
const TEXT_LENS: [usize; 9] = [13, 0, 511, 512, 513, 5000, 300_000, 1, 16384];

/// `text(200, &str)` bodies in pool buffers (ADR-081): every size, sent here or from another
/// thread, arrives exactly, one request after another on a connection.
#[test]
fn text_bodies_reuse_pool_buffers_and_stay_exact() {
    let (_e, c) = setup(H3Config::default());
    for round in 0..3 {
        for len in TEXT_LENS {
            let p = format!("/{}/{len}", if round == 1 { "sd" } else { "s" });
            let r = c
                .request_blocking(Method::Get, &p, &Headers::new(), Vec::new(), T)
                .unwrap();
            assert_eq!(r.status, 200, "{p}");
            assert!(r.body == text_of(len).as_bytes(), "{p}: body differs");
        }
    }
}

/// The client builds a response's headers in the storage of a response dropped on its thread
/// before (ADR-081): responses checked and dropped in the callback (on the client's thread),
/// one after another with heads of every size, each carry exactly their own fields.
#[test]
fn client_response_heads_reuse_storage_and_stay_exact() {
    let (_e, c) = setup(H3Config::default());
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    for _ in 0..3 {
        for (p, fs) in field_cases() {
            let mut h = Headers::new();
            for (n, v) in &fs {
                h.append(n, v);
            }
            let (body, n) = expected(&p, &fs);
            let tx = tx.clone();
            let path = p.clone();
            c.request(Method::Get, &path, &h, Vec::new(), move |r| {
                let check = || -> Result<(), String> {
                    let r = r.map_err(|e| format!("{p}: {e:?}"))?;
                    if r.body != body.as_bytes() {
                        return Err(format!("{p}: body"));
                    }
                    for i in 0..8 {
                        let v = format!("v{i}");
                        if r.headers.get(&format!("r-{i}")) != (i < n).then_some(v.as_str()) {
                            return Err(format!("{p}: r-{i}"));
                        }
                    }
                    if r.headers.get_all("content-type").count() != 1 {
                        return Err(format!("{p}: content-type"));
                    }
                    Ok(())
                };
                let _ = tx.send(check());
            });
            rx.recv_timeout(T).unwrap().unwrap();
        }
    }
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
