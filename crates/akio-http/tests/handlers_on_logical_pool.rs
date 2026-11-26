//! Requests on the logical pool: `HttpConfig::handlers_on_logical_pool` (HTTP/1.1),
//! `H2Config::handlers_on_logical_pool` (HTTP/2) and `Context::detach_to_pool`, and HTTP/1.1
//! response order however inline and pooled requests interleave.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, PoolConfig, UringConfig};
use akio_http::{
    Context, H2Config, HttpConfig, Response, Router, WsOptions,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    serve_with,
    ws::{Message, WsHandler, WsSender},
};

fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn start(app: Router, cfg: HttpConfig, pool: Option<PoolConfig>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(cfg, app)),
        )
        .client_threads(1);
    if let Some(p) = pool {
        b = b.pool(p);
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn pooled_h1() -> HttpConfig {
    let mut c = HttpConfig::default();
    c.handlers_on_logical_pool = true;
    c
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

/// Reads one Content-Length framed response: its status and body.
fn read_resp(s: &mut TcpStream) -> (u16, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = loop {
            match s.read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                r => break r.expect("read response head"),
            }
        };
        assert!(
            n > 0,
            "closed mid-head: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let len: usize = head
        .split("\r\n")
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (status, String::from_utf8(body).unwrap())
}

fn on_pool_thread() -> bool {
    thread::current().name() == Some("akio-pool")
}

fn ms(ctx: &Context) -> u64 {
    ctx.param("ms").unwrap().parse().unwrap()
}

/// Inline answers, `detach_to_pool`, and a detach answered from a thread of its own.
fn mixed_app() -> Router {
    Router::new()
        .get("/inline/:ms", |ctx: &mut Context| {
            let body = format!("inline {}", ms(ctx));
            ctx.text(200, body);
        })
        .get("/pool/:ms", |ctx: &mut Context| {
            let ms = ms(ctx);
            assert!(ctx.detach_to_pool(move |d| {
                assert!(on_pool_thread());
                thread::sleep(Duration::from_millis(ms));
                d.respond(Response::text(200, format!("pool {ms}")));
            }));
        })
        .get("/thread/:ms", |ctx: &mut Context| {
            let ms = ms(ctx);
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(ms));
                d.respond(Response::text(200, format!("thread {ms}")));
            });
        })
        .get("/block/:ms", |ctx: &mut Context| {
            // Blocks where it runs: only fine on the pool.
            let ms = ms(ctx);
            thread::sleep(Duration::from_millis(ms));
            let body = format!("block {ms} pool={}", on_pool_thread());
            ctx.text(200, body);
        })
}

/// Pipelines `paths` on one connection in one write, and returns the bodies in arrival order.
fn pipeline(addr: SocketAddr, paths: &[&str]) -> Vec<String> {
    let mut s = connect(addr);
    let raw: String = paths
        .iter()
        .map(|p| format!("GET {p} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    paths
        .iter()
        .map(|_| {
            let (status, body) = read_resp(&mut s);
            assert_eq!(status, 200, "{body}");
            body
        })
        .collect()
}

#[test]
fn http1_inline_pooled_and_detached_answers_go_out_in_request_order() {
    // Later requests finish first, and inline ones finish at once behind slow pooled ones.
    let paths = [
        "/pool/200",
        "/inline/1",
        "/thread/120",
        "/inline/2",
        "/pool/60",
        "/thread/0",
        "/inline/3",
        "/pool/0",
    ];
    let want: Vec<String> = paths.iter().map(|p| p[1..].replacen('/', " ", 1)).collect();
    for cfg in [HttpConfig::default(), pooled_h1()] {
        let handlers_on_logical_pool = cfg.handlers_on_logical_pool;
        let e = start(mixed_app(), cfg, None);
        let a = e.local_addrs()[0];
        for _ in 0..3 {
            assert_eq!(
                pipeline(a, &paths),
                want,
                "handlers_on_logical_pool={handlers_on_logical_pool}"
            );
        }
        stop(&e);
    }
}

#[test]
fn http1_handlers_on_logical_pool_serves_pipelined_blocking_handlers_at_once_and_in_order() {
    let e = start(mixed_app(), pooled_h1(), None);
    let a = e.local_addrs()[0];
    let paths = ["/block/300", "/block/200", "/block/100", "/block/0"];
    let t = Instant::now();
    let got = pipeline(a, &paths);
    let took = t.elapsed();
    assert_eq!(
        got,
        ["300", "200", "100", "0"].map(|m| format!("block {m} pool=true"))
    );
    // One after another they would take 600 ms.
    assert!(took < Duration::from_millis(500), "took {took:?}");
    stop(&e);

    // Off by default: the handler runs on the I/O thread.
    let e = start(mixed_app(), HttpConfig::default(), None);
    assert_eq!(
        pipeline(e.local_addrs()[0], &["/block/0"]),
        ["block 0 pool=false"]
    );
    stop(&e);
}

struct Silent;

impl WsHandler for Silent {
    fn on_message(&mut self, _ws: &WsSender, _msg: Message) {}
}

#[test]
fn http1_handlers_on_logical_pool_keeps_upgrades_on_the_io_thread() {
    let ran_on_pool = Arc::new(Mutex::new(Vec::new()));
    let seen = ran_on_pool.clone();
    let app = Router::new().get("/ws", move |ctx: &mut Context| {
        seen.lock().unwrap().push(on_pool_thread());
        ctx.upgrade_websocket(Silent, &WsOptions::default());
    });
    let e = start(app, pooled_h1(), None);
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).unwrap(), 1);
        head.push(b[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    assert_eq!(*ran_on_pool.lock().unwrap(), [false]);
    stop(&e);
}

#[test]
fn http1_handlers_on_logical_pool_answers_503_in_order_when_the_pool_is_full() {
    let mut pool = PoolConfig::default();
    pool.min_threads = 1;
    pool.max_threads = 1;
    pool.queue_capacity = 1;
    let e = start(mixed_app(), pooled_h1(), Some(pool));
    let a = e.local_addrs()[0];
    let mut s = connect(a);
    // One thread and one queue place: the first is served, and at most one of the rest finds
    // room (none, while the first still waits in the queue for the thread to start).
    let raw: String = ["/block/300", "/block/1", "/block/2", "/block/3"]
        .iter()
        .map(|p| format!("GET {p} HTTP/1.1\r\nHost: x\r\n\r\n"))
        .collect();
    s.write_all(raw.as_bytes()).unwrap();
    let got: Vec<(u16, String)> = (0..4).map(|_| read_resp(&mut s)).collect();
    assert_eq!(got[0], (200, "block 300 pool=true".to_owned()));
    // Each answer in its request's place: a served request's body names it.
    for (i, (status, body)) in got.iter().enumerate().skip(1) {
        match status {
            200 => assert_eq!(*body, format!("block {i} pool=true")),
            503 => assert_eq!(body, "server busy"),
            s => panic!("status {s}"),
        }
    }
    let refused = got.iter().filter(|(s, _)| *s == 503).count();
    assert!(refused >= 2, "{got:?}");
    // The connection goes on.
    s.write_all(b"GET /inline/9 HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(read_resp(&mut s), (200, "inline 9".to_owned()));
    stop(&e);
}

#[test]
fn h2_handlers_on_logical_pool_serves_one_connections_blocking_streams_at_once() {
    for on in [true, false] {
        let mut cfg = HttpConfig::default();
        let mut h2 = H2Config::default();
        h2.handlers_on_logical_pool = on;
        cfg.h2 = Some(h2);
        let e = start(mixed_app(), cfg, None);
        let addr = e.local_addrs()[0];
        let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
        let t = Instant::now();
        let futs: Vec<_> = (0..8)
            .map(|_| c.send(ClientRequest::get(&format!("http://{addr}/block/150"))))
            .collect();
        for f in futs {
            let r = f.wait().unwrap();
            assert_eq!(
                String::from_utf8(r.body).unwrap(),
                format!("block 150 pool={on}")
            );
        }
        let took = t.elapsed();
        if on {
            // On the I/O thread they take 8 x 150 ms.
            assert!(took < Duration::from_millis(800), "took {took:?}");
        } else {
            assert!(took >= Duration::from_millis(1200), "took {took:?}");
        }
        stop(&e);
    }
}

/// Pooled HTTP/2 handlers answer on the pool thread, and their responses go back to the
/// connection's thread to be written together (`h2::Deferred`); work they post to the pool
/// themselves, or answer from threads of their own, writes by itself. Many streams of one
/// connection at once, every kind mixed, a body larger than the stream window among them.
#[test]
fn h2_pooled_responses_of_one_connection_all_arrive_whoever_writes_them() {
    let big = "x".repeat(200 << 10);
    let big2 = big.clone();
    let app = mixed_app().get("/big", move |ctx: &mut Context| {
        assert!(on_pool_thread());
        ctx.text(200, big2.clone());
    });
    let mut cfg = HttpConfig::default();
    let mut h2 = H2Config::default();
    h2.handlers_on_logical_pool = true;
    cfg.h2 = Some(h2);
    let e = start(app, cfg, None);
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    for round in 0..5 {
        // Within the server's 128 concurrent streams.
        let paths: Vec<String> = (0..120)
            .map(|i| match i % 5 {
                0 => format!("/inline/{i}"),
                1 => format!("/pool/{}", i % 3),
                2 => format!("/thread/{}", i % 3),
                3 => "/block/0".to_owned(),
                _ => "/big".to_owned(),
            })
            .collect();
        let futs: Vec<_> = paths
            .iter()
            .map(|p| c.send(ClientRequest::get(&format!("http://{addr}{p}"))))
            .collect();
        for (p, f) in paths.iter().zip(futs) {
            let r = f.wait().unwrap();
            assert_eq!(r.status, 200, "{p} in round {round}");
            let body = String::from_utf8(r.body).unwrap();
            let want = match p.split('/').nth(1).unwrap() {
                "inline" => format!("inline {}", &p[8..]),
                "pool" => format!("pool {}", &p[6..]),
                "thread" => format!("thread {}", &p[8..]),
                "block" => "block 0 pool=true".to_owned(),
                _ => big.clone(),
            };
            assert!(body == want, "{p} in round {round}: {} bytes", body.len());
        }
    }
    stop(&e);
}

/// A handler on a full pool (here its only thread) that calls a client and waits: the client
/// reaches its connection's loop directly, so it never needs a pool thread of its own (rules
/// §1; it used to queue a no-op job on the pool and wait for it, which deadlocked).
#[test]
fn clients_called_from_a_full_pool_do_not_wait_for_it() {
    use akio_http::client::Client;
    use std::sync::OnceLock;

    // The leaf answers inline on both versions, so it needs no pool thread either.
    let leaf = Router::new().get("/leaf", |ctx: &mut Context| ctx.text(200, "leaf"));
    let mut inline = HttpConfig::default();
    inline.h2.as_mut().unwrap().handlers_on_logical_pool = false;
    let mut pooled = HttpConfig::default();
    pooled.h2.as_mut().unwrap().handlers_on_logical_pool = true;
    type Clients = (H2Client, Client, SocketAddr);
    let clients: Arc<OnceLock<Clients>> = Arc::new(OnceLock::new());
    let cl = clients.clone();
    // The proxy's HTTP/2 streams run on the pool.
    let proxy = Router::new().get("/proxy", move |ctx: &mut Context| {
        let (h2, h1, leaf) = cl.get().unwrap();
        let url = format!("http://{leaf}/leaf");
        let mut got = Vec::new();
        for r in [
            h2.send(ClientRequest::get(&url)),
            h1.send(ClientRequest::get(&url)),
        ] {
            got.push(match r.wait_timeout(Duration::from_secs(3)) {
                Some(Ok(r)) => r.status.to_string(),
                Some(Err(e)) => format!("{e}"),
                None => "stuck".to_owned(),
            });
        }
        ctx.text(200, got.join("/"));
    });
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(500);
                v
            })
            .pool({
                let mut v = PoolConfig::default();
                v.max_threads = 1;
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(1)
                    .serve(serve_with(inline, leaf)),
            )
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(1)
                    .serve(serve_with(pooled, proxy)),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let (leaf_addr, proxy_addr) = (e.local_addrs()[0], e.local_addrs()[1]);
    let h2 = H2Client::dial_blocking(&e, leaf_addr, None, H2Options::default()).unwrap();
    let h1 = Client::new(e.clone());
    // Leave a keep-alive connection idle, so the handler's HTTP/1.1 request reuses it (the
    // path that hands the request to that connection's loop).
    let warm = h1
        .send(ClientRequest::get(&format!("http://{leaf_addr}/leaf")))
        .wait()
        .unwrap();
    assert_eq!(warm.status, 200);
    thread::sleep(Duration::from_millis(50));
    assert!(clients.set((h2, h1, leaf_addr)).is_ok());

    let front = H2Client::dial_blocking(&e, proxy_addr, None, H2Options::default()).unwrap();
    let t = Instant::now();
    let r = front
        .send(ClientRequest::get(&format!("http://{proxy_addr}/proxy")))
        .wait_timeout(Duration::from_secs(10))
        .expect("the proxy answered")
        .unwrap();
    assert_eq!(String::from_utf8(r.body).unwrap(), "200/200");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    stop(&e);
}
