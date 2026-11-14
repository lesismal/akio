//! Companion of the book's "gRPC" chapter: a server sharing its port with plain HTTP routes, and
//! a client making unary and streaming calls.
//!
//! `cargo run -p flash-grpc --example guide-grpc`

use std::{sync::Arc, time::Duration};

use flash::{Engine, Listener};
use flash_grpc::{CallOptions, Code, GrpcClient, GrpcServer, Status};
use flash_http::{
    Context, Router,
    h2client::{H2Client, H2Options},
    serve,
};

fn main() -> std::io::Result<()> {
    // ANCHOR: server
    let grpc = GrpcServer::new()
        .unary("/demo.Greeter/Hello", |md, req, sink| {
            let who = md.get("x-user").unwrap_or("anonymous").to_owned();
            sink.set_trailer("x-served-by", "flash");
            sink.send(format!("hello {who}: {}", String::from_utf8_lossy(&req)).as_bytes());
            sink.finish(Status::ok());
        })
        .unary("/demo.Greeter/Fail", |_md, _req, sink| {
            sink.finish(Status::new(Code::InvalidArgument, "no thanks"));
        })
        .server_stream("/demo.Greeter/Count", |_md, req, sink| {
            // `sink` is usable from any thread: move slow producers off the I/O thread.
            let n: u32 = String::from_utf8_lossy(&req).parse().unwrap_or(0);
            std::thread::spawn(move || {
                for i in 0..n {
                    sink.send(i.to_string().as_bytes());
                }
                sink.finish(Status::ok());
            });
        })
        .bidi("/demo.Greeter/Chat", |_md, sink| {
            Box::new(move |msg| match msg {
                Some(m) => {
                    sink.send(&[b"re: ".as_slice(), &m].concat());
                }
                None => sink.finish(Status::ok()), // client closed its side
            })
        })
        .interceptor(|md| match md.get("x-user") {
            Some("mallory") => Err(Status::new(Code::PermissionDenied, "go away")),
            _ => Ok(()),
        })
        .max_message_bytes(4 << 20)
        .compress(true); // gzip responses when the client accepts it
    // Plain HTTP routes and gRPC on one port: gRPC requests go to `grpc`.
    let app = Router::new()
        .get("/healthz", |ctx: &mut Context| ctx.text(200, "ok"))
        .fallback(grpc);
    // ANCHOR_END: server
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    let addr = engine.local_addrs()[0];

    // ANCHOR: client
    let h2 = H2Client::dial_blocking(&engine, addr, None, H2Options::default())?;
    let client = GrpcClient::new(h2, &format!("http://{addr}"));
    let opts = || {
        let mut o = CallOptions::default();
        o.timeout = Some(Duration::from_secs(5)); // sent as grpc-timeout
        o
    };
    let mut with_user = opts();
    with_user.metadata = vec![("x-user".into(), "ada".into())];
    let reply = client
        .unary("/demo.Greeter/Hello", b"world", with_user)
        .expect("unary");
    println!("{}", String::from_utf8_lossy(&reply));
    let err = client.unary("/demo.Greeter/Fail", b"", opts()).unwrap_err();
    println!("status {:?}: {}", err.code, err.message);
    let (msgs, status) = client.collect("/demo.Greeter/Count", vec![b"3".to_vec()], opts());
    println!("{} messages, {:?}", msgs.len(), status.code);
    let (msgs, _) = client.collect(
        "/demo.Greeter/Chat",
        vec![b"a".to_vec(), b"b".to_vec()],
        opts(),
    );
    println!(
        "{:?}",
        msgs.iter()
            .map(|m| String::from_utf8_lossy(m))
            .collect::<Vec<_>>()
    );
    // ANCHOR_END: client

    engine.shutdown();
    engine.wait();
    Ok(())
}
