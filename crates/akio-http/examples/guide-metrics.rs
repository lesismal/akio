//! Companion of the book's "Observability" chapter, section "Your own metrics": application
//! counters, gauges and histograms (and any `Collector`, such as `HttpMetrics`, a `QuicServer`
//! or `Tls::stats()`) served on the engine's `/metrics` endpoint (ADR-015).
//!
//! `cargo run -p akio-http --example guide-metrics`

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{
    Config, Engine, Listener,
    metrics::{DEFAULT_BUCKETS, Families, Registry, fn_collector},
};
use akio_http::{
    Context, Router,
    client::{Client, ClientRequest},
    observe, serve,
};

fn main() -> std::io::Result<()> {
    // ANCHOR: collectors
    let cfg = Config::default();
    let tel = cfg.telemetry.clone();

    // Application instruments: cheap clones, relaxed atomics, no lock per update.
    let reg = Registry::new();
    let orders = reg.counter("shop_orders_total", "Orders placed.", &[("channel", "web")]);
    let basket = reg.histogram(
        "shop_checkout_seconds",
        "Checkout time.",
        &[],
        &DEFAULT_BUCKETS,
    );
    tel.register_collector(Arc::new(reg), &[("service", "shop")]);

    // Request counts per status class and HTTP version, latency histogram, in-flight.
    let http = observe::HttpMetrics::new();
    tel.register_collector(Arc::new(http.clone()), &[]);

    // Anything else: a closure run on every scrape.
    let started = Instant::now();
    tel.register_collector(
        Arc::new(fn_collector(move |out: &mut Families| {
            out.gauge(
                "shop_build_info",
                "Build information.",
                &[("version", env!("CARGO_PKG_VERSION"))],
                1.0,
            );
            out.gauge(
                "shop_warm_seconds",
                "Time since the caches were filled.",
                &[],
                started.elapsed().as_secs_f64(),
            );
        })),
        &[],
    );

    let app = Router::new()
        .post("/order", move |ctx: &mut Context| {
            let t0 = Instant::now();
            orders.inc();
            basket.observe_duration(t0.elapsed() + Duration::from_millis(12));
            ctx.text(201, "ordered\n");
        })
        // Engine series, then every registered collector (`http` is one, so not passed again).
        .get("/metrics", observe::metrics_handler(tel.clone(), None))
        .layer(http.middleware());
    // ANCHOR_END: collectors

    let engine = Arc::new(
        Engine::builder()
            .config(cfg)
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    let base = format!("http://{}", engine.local_addrs()[0]);
    let client = Client::new(engine.clone());
    for _ in 0..3 {
        let r = client
            .send(ClientRequest::post(&format!("{base}/order"), Vec::new()))
            .wait()
            .expect("order");
        assert_eq!(r.status, 201);
    }
    let m = client
        .send(ClientRequest::get(&format!("{base}/metrics")))
        .wait()
        .expect("metrics");
    let text = String::from_utf8_lossy(&m.body);
    for line in text
        .lines()
        .filter(|l| l.starts_with("shop_") || l.starts_with("akio_http_requests_by_version"))
    {
        println!("{line}");
    }
    assert!(text.contains("shop_orders_total{service=\"shop\",channel=\"web\"} 3\n"));

    // ANCHOR: snapshot
    // The same collectors as a snapshot: JSON, or walk the families yourself.
    let snap = tel.collect();
    for fam in snap.iter() {
        println!(
            "{} ({}): {} samples",
            fam.name,
            fam.kind.as_str(),
            fam.samples.len()
        );
    }
    let json = snap.to_json();
    // ANCHOR_END: snapshot
    assert!(json.contains("\"name\":\"shop_orders_total\""));

    engine.shutdown();
    engine.wait();
    Ok(())
}
