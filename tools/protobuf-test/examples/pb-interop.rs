//! The `akio` side of the protobuf half of the grpc-go interop check
//! (tools/interop/grpc/run.sh): route_guide and helloworld through the stubs akio-protobuf-build
//! generates, and well-known types, against grpc-go's own generated code.
//!
//! `pb-interop server <addr>` / `pb-interop client <addr>`.

use std::sync::Arc;

use akio::{Engine, Listener};
use akio_http::h2client::{H2Client, H2Options};
use protobuf_test::service;

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let addr = a[1].parse().expect("address");
    if a[0] == "server" {
        let e = Engine::builder()
            .listen(Listener::tcp(addr).serve(akio_http::serve(service::server("akio"))))
            .build()?;
        println!("ready");
        return e.run();
    }
    let e = Arc::new(Engine::builder().client_threads(1).build()?);
    e.start()?;
    let h2 = H2Client::dial_blocking(&e, addr, None, H2Options::default())?;
    let grpc = akio_grpc::GrpcClient::new(h2, &format!("http://{addr}"));
    if let Err(m) = service::check_server(&grpc, "go") {
        println!("FAIL {m}");
        std::process::exit(1);
    }
    println!("OK");
    Ok(())
}
