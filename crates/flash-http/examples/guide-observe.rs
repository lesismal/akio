//! Companion of the book's "Observability" chapter: a Prometheus endpoint with engine and HTTP
//! metrics, the token-protected debug endpoint, the structured access log and a hot-reload
//! admin route.
//!
//! `cargo run -p flash-http --example guide-observe`

use std::{sync::Arc, time::Duration};

use flash::{Config, Engine, EngineRef, Listener};
use flash_http::{
    Context, Router,
    client::{Client, ClientRequest},
    middleware, observe, serve,
};

fn main() -> std::io::Result<()> {
    // ANCHOR: endpoints
    let cfg = Config::default();
    let tel = cfg.telemetry.clone(); // the engine built with `cfg` reports here
    let http = observe::HttpMetrics::new();
    let engine_ref = EngineRef::new(); // set once the engine exists
    let admin = {
        let engine_ref = engine_ref.clone();
        let base = cfg.clone();
        move |ctx: &mut Context| {
            // e.g. POST /admin/reload?idle_secs=30
            let Some(engine) = engine_ref.get() else {
                return ctx.text(503, "starting");
            };
            let mut next = base.clone();
            next.idle_timeout = ctx
                .req()
                .query_param("idle_secs")
                .and_then(|s| s.parse().ok())
                .map(Duration::from_secs);
            let r = engine.reload(&next);
            ctx.text(
                200,
                format!("applied {:?} ignored {:?}\n", r.applied, r.ignored),
            );
        }
    };
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "hi\n"))
        .get(
            "/metrics",
            observe::metrics_handler(tel.clone(), Some(http.clone())),
        )
        .get(
            "/debug/flash/*view",
            observe::debug_handler(tel, Some("s3cret".into())),
        )
        .post("/admin/reload", admin)
        .layer(http.middleware()) // request counts, latency histogram, in-flight
        .layer(observe::access_log()) // one `log` record per response (target flash_http::access)
        .layer(middleware::request_id());
    let engine = Arc::new(
        Engine::builder()
            .config(cfg)
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .client_threads(1)
            .build()?,
    );
    engine_ref.set(&engine);
    engine.start()?;
    // ANCHOR_END: endpoints

    let base = format!("http://{}", engine.local_addrs()[0]);
    let client = Client::new(engine.clone());
    let get = |path: &str, token: Option<&str>| {
        let mut req = ClientRequest::get(&format!("{base}{path}"));
        if let Some(t) = token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        client.send(req).wait().expect("response")
    };
    get("/", None);
    let m = get("/metrics", None);
    let text = String::from_utf8_lossy(&m.body);
    for line in text
        .lines()
        .filter(|l| l.starts_with("flash_http_requests_total"))
    {
        println!("{line}");
    }
    assert_eq!(get("/debug/flash/live", None).status, 401);
    let live = get("/debug/flash/live", Some("s3cret"));
    println!("live: {}", String::from_utf8_lossy(&live.body));
    let conns = get("/debug/flash/conns", Some("s3cret"));
    println!("conns: {}", String::from_utf8_lossy(&conns.body));
    let r = client
        .send(ClientRequest::post(
            &format!("{base}/admin/reload?idle_secs=30"),
            Vec::new(),
        ))
        .wait()
        .expect("reload");
    print!("reload: {}", String::from_utf8_lossy(&r.body));

    engine.shutdown();
    engine.wait();
    Ok(())
}
