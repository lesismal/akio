//! `cargo run --release -p only-http --example hello`, then `curl -i localhost:8080/users/7`.

use std::time::Duration;

use only::{Engine, Listener};
use only_http::{Context, Response, Router, middleware, serve};

fn main() -> std::io::Result<()> {
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hello from only\n"))
        .get("/users/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap_or("?").to_owned();
            ctx.text(200, format!("user {id}\n"));
        })
        // Slow work off the I/O thread: detach, finish from any thread.
        .get("/slow", |ctx: &mut Context| {
            let Some(d) = ctx.detach() else { return };
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(500));
                d.respond(Response::text(200, "slow, but the I/O thread was free\n"));
            });
        })
        .layer(middleware::request_id())
        .layer(middleware::recover())
        .layer(middleware::logger(|r| {
            println!("{} {} {:?} {:?}", r.method, r.target, r.status, r.elapsed);
        }));
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:8080".parse().expect("address")).serve(serve(app)))
        .build()?;
    println!("http on {:?}", engine.local_addrs());
    engine.run()
}
