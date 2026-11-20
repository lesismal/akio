//! HTTP/1 client throughput (ADR-059 A/B): `client-bench [seconds] [concurrency] [threads]`.
//!
//! Serves `GET /plaintext` on loopback and drives it with [`Client`]: `concurrency` request
//! loops, each sending the next keep-alive request from the previous one's callback, for
//! `seconds`; prints requests per second. Defaults: 5 s, 64 loops, 2 client and 2 server
//! threads.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_http::{
    Context, Router,
    client::{Client, ClientRequest},
    serve,
};

fn run(client: Client, url: Arc<str>, done: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let c2 = client.clone();
    client.request(ClientRequest::get(&url), move |r| {
        if r.is_ok_and(|r| r.status == 200) {
            done.fetch_add(1, Ordering::Relaxed);
        }
        if !stop.load(Ordering::Relaxed) {
            run(c2, url, done, stop);
        }
    });
}

fn main() {
    let mut args = std::env::args().skip(1);
    let secs: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(5);
    let conc: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(64);
    let threads: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(2);
    let router = Router::new().get("/plaintext", |ctx: &mut Context| {
        ctx.text(200, "Hello, World!");
    });
    let server = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                .threads(threads)
                .serve(serve(router)),
        )
        .build()
        .expect("server");
    server.start().expect("start");
    let port = server.local_addrs()[0].port();
    let ce = Arc::new(
        Engine::builder()
            .client_threads(threads)
            .build()
            .expect("client engine"),
    );
    ce.start().expect("start");
    let client = Client::new(ce.clone());
    let url: Arc<str> = format!("http://127.0.0.1:{port}/plaintext").into();
    // Warm up the keep-alive pool.
    client
        .send(ClientRequest::get(&url))
        .wait()
        .expect("warm-up");
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    for _ in 0..conc {
        run(client.clone(), url.clone(), done.clone(), stop.clone());
    }
    std::thread::sleep(Duration::from_secs(secs));
    let n = done.load(Ordering::Relaxed);
    let took = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    println!("client-bench: {:.0} req/s ({n} in {took:.2} s, {conc} loops)", n as f64 / took);
    std::thread::sleep(Duration::from_millis(200));
    std::process::exit(0);
}
