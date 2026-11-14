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

use flash::{
    Backend, Config, Engine, Listener, UringConfig,
    tls::{Tls, rustls},
};
use flash_http::{
    BodyEvent, Context, Headers, Router, Streaming,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve,
};

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring(UringConfig {
            strict: true,
            ..Default::default()
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
                d.respond(flash_http::Response::text(200, "slow done"));
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

fn start(acceptor: impl flash::Acceptor) -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .config(Config {
                shutdown_timeout: Duration::from_millis(800),
                ..Config::default()
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
    let c = H2Client::connect_blocking(e, addr, None, opts).unwrap();
    (c, format!("http://{addr}"))
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
    head.method = flash_http::Method::Head;
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
    let (c, base) = connect(
        &e,
        H2Options {
            initial_window: 16 << 10,
            conn_window: 64 << 10,
            ..H2Options::default()
        },
    );
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
    let (c, base) = connect(
        &e,
        H2Options {
            enable_push: true,
            ..H2Options::default()
        },
    );
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
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let mut scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    scfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let e = start(Tls::server(Arc::new(scfg), serve(app())));
    let addr = e.local_addrs()[0];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"h2".to_vec()];
    let c = H2Client::connect_blocking(
        &e,
        addr,
        Some((Arc::new(ccfg), "localhost")),
        H2Options::default(),
    )
    .unwrap();
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
