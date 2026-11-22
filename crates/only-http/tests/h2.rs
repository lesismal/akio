//! HTTP/2 end to end: our client against our server, h2c upgrade, TLS with ALPN, push, streams.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use only::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use only_http::{
    BodyEvent, Context, Headers, Router, Streaming,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve,
};

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn app() -> Router {
    Router::new()
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello h2"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .get("/big/:n", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            ctx.bytes(200, "application/octet-stream", pattern(n));
        })
        .get("/sse", |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for i in 0..5 {
                    s.write(format!("event {i};").as_bytes()).unwrap();
                    thread::sleep(Duration::from_millis(10));
                }
                s.finish();
            });
        })
        .post(
            "/sum",
            Streaming(|ctx: &mut Context| {
                let mut sum = 0usize;
                ctx.on_body(move |ctx, ev| match ev {
                    BodyEvent::Chunk(b) => sum += b.len(),
                    BodyEvent::End(_) => ctx.text(200, sum.to_string()),
                });
            }),
        )
        .get("/page", |ctx: &mut Context| {
            let pushed = ctx.push("/style.css");
            ctx.text(200, format!("page pushed={pushed}"));
        })
        .get("/style.css", |ctx: &mut Context| {
            ctx.bytes(200, "text/css", b"body{}".to_vec());
        })
        .get("/slow", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150));
                d.respond(only_http::Response::text(200, "slow done"));
            });
        })
        .get("/headers", |ctx: &mut Context| {
            let ua = ctx.header("x-custom").unwrap_or("-").to_owned();
            let cookie = ctx.header("cookie").unwrap_or("-").to_owned();
            ctx.text(
                200,
                format!("{ua}|{cookie}|{}", ctx.header("host").unwrap_or("?")),
            );
        })
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 % 251) as u8).collect()
}

fn start(acceptor: impl only::Acceptor) -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(800);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .serve(acceptor),
            )
            .client_threads(2)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(e: &Engine, opts: H2Options) -> (H2Client, String) {
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(e, addr, None, opts).unwrap();
    (c, format!("http://{addr}"))
}

/// Requests on one HTTP/2 connection reuse a finished request's target buffer (ADR-025):
/// each still sees exactly its own target, long or short, detached or not.
#[test]
fn targets_reuse_the_buffer_and_stay_exact() {
    let app = Router::new()
        .get("/t/*rest", |ctx: &mut Context| {
            let t = ctx.req().target.clone();
            ctx.text(200, t);
        })
        .get("/d/*rest", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                let t = d.req().target.clone();
                d.respond(only_http::Response::text(200, t));
            });
        });
    let e = start(serve(app));
    let (c, base) = connect(&e, H2Options::default());
    let long = format!("/t/{}", "y".repeat(1500));
    for t in [
        "/t/a-fairly-long-first-target?q=1",
        "/t/b",
        "/d/detached",
        "/t/c?q",
        &long,
        "/t/d",
    ] {
        let r = c
            .send(ClientRequest::get(&format!("{base}{t}")))
            .wait()
            .unwrap();
        assert_eq!(String::from_utf8(r.body).unwrap(), t);
    }
    stop(&e);
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
    let mut r = only_http::Response::text(200, body);
    for i in 0..n {
        r = r.header(&format!("r-{i}"), format!("v{i}"));
    }
    if ctx.path().starts_with("/hd/") {
        let d = ctx.detach().unwrap();
        thread::spawn(move || d.respond(r));
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
    let app = Router::new()
        .get("/h/:n", echo_fields)
        .get("/hd/:n", echo_fields);
    let e = start(serve(app));
    let (c, base) = connect(&e, H2Options::default());
    for _ in 0..2 {
        for (p, fs) in field_cases() {
            let mut req = ClientRequest::get(&format!("{base}{p}"));
            for (n, v) in &fs {
                req = req.header(n, v);
            }
            let r = c.send(req).wait().unwrap();
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
    stop(&e);
}

#[test]
fn basic_requests_headers_and_bodies() {
    let e = start(serve(app()));
    let (c, base) = connect(&e, H2Options::default());
    let r = c
        .send(ClientRequest::get(&format!("{base}/hello")))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello h2"[..]));
    assert!(r.headers.get("date").is_some());
    assert_eq!(
        r.headers.get("content-type"),
        Some("text/plain; charset=utf-8")
    );
    let r = c
        .send(ClientRequest::get(&format!("{base}/headers")).header("X-Custom", "v1"))
        .wait()
        .unwrap();
    let host = base.trim_start_matches("http://");
    assert_eq!(r.body, format!("v1|-|{host}").as_bytes());
    assert_eq!(
        c.send(ClientRequest::get(&format!("{base}/nope")))
            .wait()
            .unwrap()
            .status,
        404
    );
    // HEAD has no body but the length.
    let mut head = ClientRequest::get(&format!("{base}/hello"));
    head.method = only_http::Method::Head;
    let r = c.send(head).wait().unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.headers.get("content-length"), Some("8"));
    stop(&e);
}

#[test]
fn large_bodies_cross_small_flow_control_windows_both_ways() {
    let e = start(serve(app()));
    // 16 KiB windows on the client force WINDOW_UPDATE round trips for the download, and the
    // server's own windows (1 MiB) for the 3 MiB upload.
    let (c, base) = connect(&e, {
        let mut v = H2Options::default();
        v.initial_window = 16 << 10;
        v.conn_window = 64 << 10;
        v
    });
    let r = c
        .send(ClientRequest::get(&format!("{base}/big/3000000")))
        .wait()
        .unwrap();
    assert_eq!(r.body.len(), 3_000_000);
    assert!(r.body == pattern(3_000_000), "download corrupted");
    let up = pattern(3 << 20);
    let r = c
        .send(ClientRequest::post(&format!("{base}/echo"), up))
        .wait()
        .unwrap();
    // The server buffers uploads up to its limit (1 MiB default): bigger ones get a 413.
    assert_eq!(r.status, 413);
    let up = pattern(900_000);
    let r = c
        .send(ClientRequest::post(&format!("{base}/echo"), up.clone()))
        .wait()
        .unwrap();
    assert!(r.body == up, "upload echoed byte for byte");
    stop(&e);
}

#[test]
fn many_concurrent_streams_on_one_connection() {
    let e = start(serve(app()));
    let (c, base) = connect(&e, H2Options::default());
    let futs: Vec<_> = (0..200)
        .map(|i| {
            let body = format!("message-{i}").into_bytes();
            (
                body.clone(),
                c.send(ClientRequest::post(&format!("{base}/echo"), body)),
            )
        })
        .collect();
    for (body, f) in futs {
        assert_eq!(f.wait().unwrap().body, body);
    }
    // Concurrent slow requests overlap instead of queueing behind each other.
    let t = std::time::Instant::now();
    let futs: Vec<_> = (0..20)
        .map(|_| c.send(ClientRequest::get(&format!("{base}/slow"))))
        .collect();
    for f in futs {
        assert_eq!(f.wait().unwrap().body, b"slow done");
    }
    assert!(
        t.elapsed() < Duration::from_millis(1200),
        "multiplexed: {:?}",
        t.elapsed()
    );
    stop(&e);
}

#[test]
fn streamed_responses_and_streamed_request_bodies() {
    let e = start(serve(app()));
    let (c, base) = connect(&e, H2Options::default());
    let r = c
        .send(ClientRequest::get(&format!("{base}/sse")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"event 0;event 1;event 2;event 3;event 4;");
    // A 4 MiB upload to a streaming handler: no 1 MiB buffering limit applies.
    let up = pattern(4 << 20);
    let r = c
        .send(ClientRequest::post(&format!("{base}/sum"), up))
        .wait()
        .unwrap();
    assert_eq!(r.body, (4usize << 20).to_string().as_bytes());
    stop(&e);
}

#[test]
fn server_push() {
    let e = start(serve(app()));
    let (c, base) = connect(&e, {
        let mut v = H2Options::default();
        v.enable_push = true;
        v
    });
    let r = c
        .send(ClientRequest::get(&format!("{base}/page")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"page pushed=true");
    assert_eq!(r.pushed.len(), 1);
    assert_eq!(r.pushed[0].0, "/style.css");
    assert_eq!(r.pushed[0].1.body, b"body{}");
    assert_eq!(r.pushed[0].1.headers.get("content-type"), Some("text/css"));
    // A client that disabled push is never pushed to (`push` reports false).
    let (c2, base2) = connect(&e, H2Options::default());
    let r = c2
        .send(ClientRequest::get(&format!("{base2}/page")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"page pushed=false");
    assert!(r.pushed.is_empty());
    stop(&e);
}

/// Reads one frame from a blocking socket.
fn read_frame(s: &mut TcpStream) -> (u8, u8, u32, Vec<u8>) {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).unwrap();
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    let mut p = vec![0; len];
    s.read_exact(&mut p).unwrap();
    (
        h[3],
        h[4],
        u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
        p,
    )
}

#[test]
fn h2c_upgrade_from_http1() {
    let e = start(serve(app()));
    let addr: SocketAddr = e.local_addrs()[0];
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // HTTP2-Settings: an empty SETTINGS payload, base64url ("" is valid).
    s.write_all(
        b"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n",
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
    // Now HTTP/2: our preface and SETTINGS; the response to the upgrade request is stream 1.
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // empty SETTINGS
    s.write_all(&out).unwrap();
    let mut got_status = false;
    let mut body = Vec::new();
    loop {
        let (ty, flags, sid, p) = read_frame(&mut s);
        match ty {
            4 => {
                if flags & 1 == 0 {
                    s.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).unwrap(); // ack the server's
                }
            }
            1 if sid == 1 => got_status = true,
            0 if sid == 1 => {
                body.extend_from_slice(&p);
                if flags & 1 != 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(got_status);
    assert_eq!(body, b"hello h2");
    stop(&e);
}

#[test]
fn tls_with_alpn_h2_and_http1_on_the_same_listener() {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(cert.clone())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .alpn(["h2", "http/1.1"])
    .build()
    .unwrap();
    let e = start(Tls::server(scfg, serve(app())));
    let addr = e.local_addrs()[0];
    let mut roots = only::tls::RootCerts::empty();
    roots.add(&only::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = only::tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["h2"])
        .build()
        .unwrap();
    let c =
        H2Client::dial_blocking(&e, addr, Some((ccfg, "localhost")), H2Options::default()).unwrap();
    let url = format!("https://localhost:{}", addr.port());
    let r = c
        .send(ClientRequest::get(&format!("{url}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.body, b"hello h2");
    let r = c
        .send(ClientRequest::get(&format!("{url}/big/500000")))
        .wait()
        .unwrap();
    assert!(r.body == pattern(500_000));
    stop(&e);
}

#[test]
fn graceful_shutdown_sends_goaway_and_lets_streams_finish() {
    let e = start(serve(app()));
    let (c, base) = connect(&e, H2Options::default());
    let slow = c.send(ClientRequest::get(&format!("{base}/slow")));
    thread::sleep(Duration::from_millis(30));
    let e2 = e.clone();
    let waiter = thread::spawn(move || e2.wait());
    e.shutdown();
    assert_eq!(
        slow.wait().unwrap().body,
        b"slow done",
        "in-flight stream completes"
    );
    waiter.join().unwrap();
    assert!(
        c.send(ClientRequest::get(&format!("{base}/hello")))
            .wait()
            .is_err(),
        "no new streams after GOAWAY"
    );
}
