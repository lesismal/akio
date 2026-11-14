//! The generated only-grpc stubs end to end: an `only` server registered with
//! `route_guide_server::register` / `greeter_server::register`, called through the generated
//! clients (unary, both streaming directions, bidirectional, errors, metadata, unknown fields).

use std::sync::Arc;

use only::{Engine, Listener};
use only_http::h2client::{H2Client, H2Options};
use protobuf_test::service;

#[test]
fn generated_stubs_against_an_only_server() {
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .serve(only_http::serve(service::server("only"))),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    let h2 = H2Client::dial_blocking(&engine, addr, None, H2Options::default()).unwrap();
    let grpc = only_grpc::GrpcClient::new(h2, &format!("http://{addr}"));
    service::check_server(&grpc, "only").unwrap();
    // Gzip-compressed requests too.
    service::check_server(&grpc.clone().compress(true), "only").unwrap();
    // A request that is not a valid encoding is INVALID_ARGUMENT.
    let err = grpc
        .unary(
            "/routeguide.RouteGuide/GetFeature",
            &[0x0a, 0xff],
            Default::default(),
        )
        .unwrap_err();
    assert_eq!(err.code, only_grpc::Code::InvalidArgument);
    engine.shutdown();
    engine.wait();
}
