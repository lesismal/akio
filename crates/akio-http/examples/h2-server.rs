//! HTTP/1.1 + HTTP/2 (prior knowledge and h2c upgrade) test server, the target of h2spec:
//! `cargo run --release -p akio-http --example h2-server -- 0.0.0.0:8082`

use akio::{Engine, Listener};
use akio_http::{Context, Router, serve};

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8082".into())
        .parse()
        .expect("address");
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello h2\n"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
        .fallback(|ctx: &mut Context| {
            // h2spec requests arbitrary paths and bodies; answer them all.
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        });
    let engine = Engine::builder()
        .listen(Listener::tcp(addr).serve(serve(app)))
        .build()?;
    println!("h2 on {:?}", engine.local_addrs());
    engine.run()
}
