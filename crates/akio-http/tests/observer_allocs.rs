//! An observed request costs no allocation (ADR-158, akit A29): with a counting global
//! allocator, HTTP/1.1 keep-alive requests that call `Context::set_observed` under a listener
//! observer allocate nothing in the steady state, where a boxed response filter costs one each.
//! A binary of its own: the allocator counts every thread of the process.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{Context, HttpConfig, Request, Response, ResponseObserver, Router, serve_with};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

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

#[derive(Default)]
struct Count(AtomicU64);

impl ResponseObserver for Count {
    fn on_response(&self, resp: &Response, _: &Request, words: [u64; 2], started: Instant) {
        if resp.status == 200 && words == [7, 9] && started.elapsed() < Duration::from_secs(60) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Serves `app` with observer `obs`, sends `n` requests on one keep-alive connection after a
/// warm-up, and returns the allocations per request (the whole process's, client included,
/// which reads and writes with fixed buffers).
fn allocs_per_request(app: Router, obs: Arc<Count>, n: u64) -> f64 {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve_with(HttpConfig::default(), app).observer(obs)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    let mut buf = [0u8; 512];
    let mut one = |s: &mut TcpStream| {
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut have = 0;
        // The response ends with its two-byte body.
        while !buf[..have].ends_with(b"\r\n\r\nhi") {
            let k = s.read(&mut buf[have..]).unwrap();
            assert!(k > 0, "closed");
            have += k;
        }
    };
    for _ in 0..200 {
        one(&mut s);
    }
    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..n {
        one(&mut s);
    }
    let used = ALLOCS.load(Ordering::Relaxed) - before;
    drop(s);
    e.shutdown();
    e.wait();
    used as f64 / n as f64
}

#[test]
fn an_observed_request_allocates_nothing_where_a_boxed_filter_allocates() {
    let n = 2000;
    let obs = Arc::new(Count::default());
    let observed = Router::new().get("/", |ctx: &mut Context| {
        ctx.set_observed([7, 9]);
        ctx.text(200, "hi");
    });
    let per = allocs_per_request(observed, obs.clone(), n);
    assert_eq!(obs.0.load(Ordering::Relaxed), n + 200, "each one observed");
    // The control: a response filter that carries something is a box per request.
    let filtered = Router::new().get("/", |ctx: &mut Context| {
        let started = Instant::now();
        ctx.add_response_filter(move |resp: &mut Response, _: &Request| {
            assert!(resp.status == 200 && started.elapsed() < Duration::from_secs(60));
        });
        ctx.text(200, "hi");
    });
    let boxed = allocs_per_request(filtered, Arc::new(Count::default()), n);
    assert!(boxed >= 0.9, "the control allocates: {boxed}");
    // The baseline: the same request not observed, on the same scheduler. Background threads
    // (the deadline sweeper, the engine's, work-stealing scheduling's workers) allocate now and
    // then, the same with or without the observer, so the observed request is held to the
    // baseline.
    let plain = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hi"));
    let base = allocs_per_request(plain, Arc::new(Count::default()), n);
    assert!(
        per < base + 0.05,
        "an observed request allocates: {per} per request, {base} without the observer"
    );
}
