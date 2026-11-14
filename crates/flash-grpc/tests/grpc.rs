//! gRPC between flash peers over HTTP/2.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use flash::{Config, Engine, Listener};
use flash_grpc::{CallOptions, Code, GrpcClient, GrpcServer, Status};
use flash_http::h2client::{H2Client, H2Options};

fn server() -> GrpcServer {
    GrpcServer::new()
        .unary("/test.Echo/Unary", |_md, req, sink| {
            sink.send(&req);
            sink.finish(Status::ok());
        })
        .unary("/test.Echo/Fail", |_md, _req, sink| {
            sink.finish(Status::new(Code::InvalidArgument, "bad input: é\n%"));
        })
        .unary("/test.Echo/Meta", |md, _req, sink| {
            let who = md.get("x-user").unwrap_or("nobody").to_owned();
            sink.set_header("x-greeting", "hi");
            sink.set_trailer("x-served-by", "flash");
            sink.send(who.as_bytes());
            sink.finish(Status::ok());
        })
        .unary("/test.Echo/Slow", |_md, req, sink| {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(500));
                sink.send(&req);
                sink.finish(Status::ok());
            });
        })
        .server_stream("/test.Echo/Count", |_md, req, sink| {
            let n: usize = String::from_utf8_lossy(&req).parse().unwrap();
            thread::spawn(move || {
                for i in 0..n {
                    sink.send(i.to_string().as_bytes());
                }
                sink.finish(Status::ok());
            });
        })
        .client_stream("/test.Echo/Sum", |_md, msgs, sink| {
            let total: usize = msgs.iter().map(|m| m.len()).sum();
            sink.send(total.to_string().as_bytes());
            sink.finish(Status::ok());
        })
        .bidi("/test.Echo/Chat", |_md, sink| {
            Box::new(move |m| match m {
                Some(m) => {
                    sink.send(&[b"re:".as_slice(), &m].concat());
                }
                None => sink.finish(Status::ok()),
            })
        })
        .interceptor(|md| {
            if md.method == "/test.Echo/Secret" && md.get("authorization") != Some("Bearer t0k3n") {
                return Err(Status::new(Code::Unauthenticated, "no token"));
            }
            Ok(())
        })
        .unary("/test.Echo/Secret", |_md, _r, sink| {
            sink.send(b"the secret");
            sink.finish(Status::ok());
        })
        .max_message_bytes(4 << 20)
        .compress(true)
}

fn setup() -> (Arc<Engine>, GrpcClient) {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .threads(2)
                    .serve(flash_http::serve(server())),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let h2 = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    (e, GrpcClient::new(h2, &format!("http://{addr}")))
}

#[test]
fn unary_errors_metadata_and_unknown_methods() {
    let (e, c) = setup();
    let o = CallOptions::default;
    assert_eq!(
        c.unary("/test.Echo/Unary", b"hello", o()).unwrap(),
        b"hello"
    );
    assert_eq!(
        c.unary("/test.Echo/Unary", b"", o()).unwrap(),
        b"",
        "empty message"
    );
    let err = c.unary("/test.Echo/Fail", b"x", o()).unwrap_err();
    assert_eq!(
        (err.code, err.message.as_str()),
        (Code::InvalidArgument, "bad input: é\n%")
    );
    assert_eq!(
        c.unary("/test.Echo/Nope", b"x", o()).unwrap_err().code,
        Code::Unimplemented
    );
    let mut opts = CallOptions::default();
    opts.metadata = vec![("x-user".into(), "ada".into())];
    assert_eq!(c.unary("/test.Echo/Meta", b"", opts).unwrap(), b"ada");
    // Trailers come back through bidi's completion.
    let (tx, rx) = std::sync::mpsc::channel();
    let s = c.bidi(
        "/test.Echo/Meta",
        CallOptions::default(),
        |_m| {},
        move |st, tr| {
            let _ = tx.send((st, tr.get("x-served-by").map(str::to_owned)));
        },
    );
    s.send(b"");
    s.close_send();
    let (st, by) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!((st.code, by.as_deref()), (Code::Ok, Some("flash")));
    e.shutdown();
    e.wait();
}

#[test]
fn streaming_calls() {
    let (e, c) = setup();
    let (msgs, st) = c.collect(
        "/test.Echo/Count",
        vec![b"500".to_vec()],
        CallOptions::default(),
    );
    assert_eq!(st.code, Code::Ok);
    assert_eq!(msgs.len(), 500);
    assert_eq!(msgs[499], b"499");
    let reqs: Vec<Vec<u8>> = (0..100).map(|i| vec![1u8; i]).collect();
    let (msgs, st) = c.collect("/test.Echo/Sum", reqs, CallOptions::default());
    assert_eq!(
        (st.code, msgs[0].as_slice()),
        (Code::Ok, b"4950".as_slice())
    );
    // Bidi: a reply per message, interleaved.
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let sink = c.bidi(
        "/test.Echo/Chat",
        CallOptions::default(),
        move |m| g.lock().unwrap().push(String::from_utf8(m).unwrap()),
        move |st, _| {
            let _ = tx.send(st);
        },
    );
    for w in ["a", "b", "c"] {
        sink.send(w.as_bytes());
    }
    sink.close_send();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().code,
        Code::Ok
    );
    assert_eq!(*got.lock().unwrap(), ["re:a", "re:b", "re:c"]);
    e.shutdown();
    e.wait();
}

#[test]
fn deadlines_interceptors_compression_and_limits() {
    let (e, c) = setup();
    let mut short = CallOptions::default();
    short.timeout = Some(Duration::from_millis(100));
    assert_eq!(
        c.unary("/test.Echo/Slow", b"x", short).unwrap_err().code,
        Code::DeadlineExceeded
    );
    let mut long = CallOptions::default();
    long.timeout = Some(Duration::from_secs(5));
    assert_eq!(c.unary("/test.Echo/Slow", b"x", long).unwrap(), b"x");
    assert_eq!(
        c.unary("/test.Echo/Secret", b"", CallOptions::default())
            .unwrap_err()
            .code,
        Code::Unauthenticated
    );
    let mut auth = CallOptions::default();
    auth.metadata = vec![("authorization".into(), "Bearer t0k3n".into())];
    assert_eq!(
        c.unary("/test.Echo/Secret", b"", auth).unwrap(),
        b"the secret"
    );
    // gzip both ways (the server compresses because the client accepts it).
    let gz = c.clone().compress(true);
    let big = vec![b'z'; 3 << 20];
    assert_eq!(
        gz.unary("/test.Echo/Unary", &big, CallOptions::default())
            .unwrap(),
        big
    );
    // Over the server's 4 MiB limit.
    let huge = vec![1u8; 5 << 20];
    assert_eq!(
        c.unary("/test.Echo/Unary", &huge, CallOptions::default())
            .unwrap_err()
            .code,
        Code::ResourceExhausted
    );
    e.shutdown();
    e.wait();
}
