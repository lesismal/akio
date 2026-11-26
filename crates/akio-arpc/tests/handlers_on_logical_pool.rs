//! `Routes::handlers_on_logical_pool`: middleware and handlers on the logical pool, the requests
//! of one connection served at the same time.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Engine, Listener, PoolConfig};
use akio_arpc::{CallError, Routes, SERVER_BUSY, Server, dial_blocking};

fn on_pool_thread() -> bool {
    thread::current().name() == Some("akio-pool")
}

fn engine(routes: Routes, pool: Option<PoolConfig>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .client_threads(1)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(Server::new(Arc::new(routes))),
        );
    if let Some(p) = pool {
        b = b.pool(p);
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn routes(on: bool) -> Routes {
    Routes::new()
        .middleware(|ctx, next| {
            let pooled = on_pool_thread();
            ctx.values_mut()
                .set("mw-pool", if pooled { "1" } else { "0" });
            next.run(ctx);
        })
        .handle("/block", |ctx| {
            // Blocks where it runs: only fine on the pool.
            let ms: u64 = String::from_utf8_lossy(ctx.body()).parse().unwrap();
            thread::sleep(Duration::from_millis(ms));
            let mw =
                String::from_utf8_lossy(ctx.values().get("mw-pool").unwrap_or(b"?")).into_owned();
            let body = format!("{ms} pool={} mw={mw}", on_pool_thread());
            ctx.write(body.as_bytes());
        })
        .handlers_on_logical_pool(on)
}

#[test]
fn requests_of_one_connection_run_at_once_on_the_pool() {
    for on in [true, false] {
        let e = engine(routes(on), None);
        let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();
        let t = Instant::now();
        // Slowest first: on the pool the answers come back as they are ready.
        let futs: Vec<_> = [300u64, 250, 200, 150, 100, 50]
            .iter()
            .map(|ms| (*ms, peer.call("/block", ms.to_string().as_bytes(), None)))
            .collect();
        let flag = u8::from(on);
        for (ms, f) in futs {
            assert_eq!(
                f.wait().unwrap(),
                format!("{ms} pool={on} mw={flag}").into_bytes()
            );
        }
        let took = t.elapsed();
        if on {
            // On the I/O thread they take 1050 ms one after another.
            assert!(took < Duration::from_millis(700), "took {took:?}");
        } else {
            assert!(took >= Duration::from_millis(1000), "took {took:?}");
        }
        e.shutdown();
        e.wait();
    }
}

#[test]
fn a_full_pool_answers_server_busy() {
    let mut pool = PoolConfig::default();
    pool.min_threads = 1;
    pool.max_threads = 1;
    pool.queue_capacity = 1;
    let e = engine(routes(true), Some(pool));
    let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();
    let futs: Vec<_> = (0..4).map(|_| peer.call("/block", b"200", None)).collect();
    let results: Vec<_> = futs.into_iter().map(|f| f.wait()).collect();
    assert!(results[0].is_ok(), "{results:?}");
    let busy = results
        .iter()
        .filter(|r| **r == Err(CallError::Remote(SERVER_BUSY.into())))
        .count();
    assert!(busy >= 2, "{results:?}");
    // Once there is room again, calls are served.
    assert_eq!(
        peer.call("/block", b"0", None).wait().unwrap(),
        b"0 pool=true mw=1"
    );
    e.shutdown();
    e.wait();
}
