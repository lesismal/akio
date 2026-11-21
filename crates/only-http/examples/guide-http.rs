//! Companion of the book's HTTP chapters: routing, middleware, static files, detached and
//! streamed responses, streamed request bodies, HTTP/2 settings, and the HTTP/1 + HTTP/2
//! clients talking to that server.
//!
//! `cargo run -p only-http --example guide-http`

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use only::{Engine, Listener};
use only_http::{
    BodyEvent, Context, H2Config, Headers, HttpConfig, Response, Router, Service, Streaming,
    client::{Client, ClientRequest},
    files::Files,
    h2client::{H2Client, H2Options},
    middleware::{self, Compress, Cors, StreamCompress},
    serve_with,
};

// ANCHOR: handlers
fn hello(ctx: &mut Context) {
    ctx.text(200, "hello\n");
}

fn user(ctx: &mut Context) {
    // Route parameters are percent-decoded once; `param_raw` gives the text as sent.
    let id = ctx.param("id").unwrap_or("?").to_owned();
    let verbose = ctx.req().query_param("verbose").is_some();
    ctx.text(200, format!("user {id} verbose={verbose}\n"));
}

fn slow(ctx: &mut Context) {
    // Handlers run on the I/O thread: never block here. Detach, then answer from anywhere.
    let Some(d) = ctx.detach() else { return };
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(20)); // a database call, say
        d.respond(Response::text(200, "slow but the I/O thread stayed free\n"));
    });
}

fn events(ctx: &mut Context) {
    let mut h = Headers::new();
    h.set("Content-Type", "text/event-stream");
    // Chunked on keep-alive HTTP/1.1, DATA frames on HTTP/2. Write from any thread.
    let Some(body) = ctx.stream_response(200, h) else {
        return;
    };
    thread::spawn(move || {
        for i in 0..3 {
            if body
                .write(format!("data: tick {i}\n\n").as_bytes())
                .is_err()
            {
                return; // client went away
            }
        }
        body.finish();
    });
}

fn upload(ctx: &mut Context) {
    // With `Streaming(..)` the handler runs once the head is parsed and gets the body in pieces.
    let mut total = 0usize;
    ctx.on_body(move |ctx, ev| match ev {
        BodyEvent::Chunk(b) => total += b.len(),
        BodyEvent::End(_trailers) => ctx.text(200, format!("received {total} bytes\n")),
    });
}
// ANCHOR_END: handlers

// ANCHOR: middleware
/// A middleware: continue with `next.call(ctx)`, or answer without calling it.
fn auth(ctx: &mut Context, next: &dyn Service) {
    match ctx.header("authorization") {
        Some("Bearer let-me-in") => next.call(ctx),
        _ => ctx.text(401, "unauthorized\n"),
    }
}
// ANCHOR_END: middleware

// ANCHOR: compression
/// gzip / deflate for every client that accepts them, zstd for those that accept it, and
/// streamed responses too (ADR-074): each write is compressed and flushed, so a server-sent
/// event still reaches the client as soon as it is written.
fn compression() -> Compress {
    let mut c = Compress::default();
    c.zstd = Some(3);
    c.stream = Some(StreamCompress::default()); // gzip 1, zstd 1, br 4, small windows
    c
}
// ANCHOR_END: compression

// ANCHOR: state
/// Application state shared by handlers: capture an `Arc` in the closure (the counterpart of
/// axum's `State` extractor).
struct AppState {
    hits: AtomicU64,
}

fn hits(state: Arc<AppState>) -> impl Fn(&mut Context) + Send + Sync + 'static {
    move |ctx: &mut Context| {
        let n = state.hits.fetch_add(1, Ordering::Relaxed) + 1;
        let body = format!("{{\"hits\":{n}}}").into_bytes();
        ctx.bytes(200, "application/json", body);
    }
}
// ANCHOR_END: state

// ANCHOR: router
fn app(static_dir: &str, state: Arc<AppState>) -> Router {
    let api = Router::new()
        .get("/users/:id", user) // plain parameter
        .get("/orders/{id:[0-9]+}", user) // regexp parameter
        .post("/upload", Streaming(upload)); // streamed request body
    let admin = Router::new().get("/stats", hello).layer(auth); // only admin routes need auth
    Router::new()
        .get("/", hello)
        .get("/slow", slow)
        .get("/events", events)
        .get("/hits", hits(state))
        .get(
            "/static/*path",
            Files::new(static_dir).cache_control("max-age=60"),
        )
        .nest("/api", api)
        .nest("/admin", admin) // a nested router keeps its own layers
        .fallback(|ctx: &mut Context| ctx.text(404, "nothing here\n"))
        // Layers wrap everything registered on this router; the last added runs first.
        .layer(middleware::compress(compression()))
        .layer(middleware::etag())
        .layer(middleware::cors(Cors::default()))
        .layer(middleware::limiter(1000.0, 200))
        .layer(middleware::response_time())
        .layer(middleware::request_id())
        .layer(middleware::recover())
}
// ANCHOR_END: router

fn main() -> std::io::Result<()> {
    let dir = std::env::temp_dir().join("only-guide-http");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("hello.txt"), "a static file\n")?;

    // ANCHOR: serve
    let mut h2 = H2Config::default();
    h2.max_concurrent_streams = 256;
    let mut http = HttpConfig::default();
    http.max_header_bytes = 64 << 10;
    http.max_body_bytes = 1 << 20; // buffered bodies; streamed ones are unlimited
    http.h2 = Some(h2); // None = HTTP/1 only
    let engine = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve_with(
                    http,
                    app(
                        dir.to_str().unwrap(),
                        Arc::new(AppState {
                            hits: AtomicU64::new(0),
                        }),
                    ),
                )),
            )
            .client_threads(1) // for the clients below
            .build()?,
    );
    engine.start()?;
    // ANCHOR_END: serve
    let addr = engine.local_addrs()[0];
    let base = format!("http://{addr}");

    // ANCHOR: client
    let client = Client::new(engine.clone());
    let r = client
        .send(ClientRequest::get(&format!("{base}/api/users/7?verbose")))
        .wait()
        .expect("response");
    println!("{} {}", r.status, String::from_utf8_lossy(&r.body).trim());
    // Callback style: runs on an I/O thread, must not block.
    client.request(ClientRequest::get(&format!("{base}/slow")), |res| {
        if let Ok(r) = res {
            println!("callback: {}", String::from_utf8_lossy(&r.body).trim());
        }
    });
    // ANCHOR_END: client

    for path in [
        "/static/hello.txt",
        "/events",
        "/api/orders/42",
        "/api/orders/x",
        "/admin/stats",
        "/hits",
    ] {
        let r = client
            .send(ClientRequest::get(&format!("{base}{path}")))
            .wait_timeout(Duration::from_secs(5))
            .expect("in time")
            .expect("response");
        println!(
            "{path}: {} {:?}",
            r.status,
            String::from_utf8_lossy(&r.body)
        );
    }
    // The event stream again, compressed: the client hands the body over as it came.
    let r = client
        .send(ClientRequest::get(&format!("{base}/events")).header("accept-encoding", "gzip"))
        .wait()
        .expect("events");
    assert_eq!(r.headers.get("content-encoding"), Some("gzip"));
    let events = only_deflate::decompress(only_deflate::Format::Gzip, &r.body, 1 << 20)
        .expect("a gzip stream");
    println!("/events (gzip): {:?}", String::from_utf8_lossy(&events));
    let r = client
        .send(ClientRequest::post(
            &format!("{base}/api/upload"),
            vec![0; 100_000],
        ))
        .wait()
        .expect("upload");
    println!("upload: {}", String::from_utf8_lossy(&r.body).trim());

    // ANCHOR: h2client
    // HTTP/2 with prior knowledge on the same port; many requests share one connection.
    let h2 = H2Client::dial_blocking(&engine, addr, None, H2Options::default())?;
    let futures: Vec<_> = (0..4)
        .map(|i| h2.send(ClientRequest::get(&format!("{base}/api/users/{i}"))))
        .collect();
    for f in futures {
        let r = f.wait().expect("h2 response");
        println!("h2: {}", String::from_utf8_lossy(&r.body).trim());
    }
    // ANCHOR_END: h2client

    thread::sleep(Duration::from_millis(50)); // let the callback above print
    engine.shutdown();
    engine.wait();
    Ok(())
}
