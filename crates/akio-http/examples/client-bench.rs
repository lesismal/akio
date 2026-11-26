//! HTTP client throughput (ADR-059 A/B, A171 A/B):
//! `client-bench [seconds] [concurrency] [threads] [epoll|uring] [h1|h2] [timeout-ms]`.
//!
//! Serves `GET /plaintext` on loopback and drives it with [`Client`] (`h1`) or with one
//! [`H2Client`] connection per client thread (`h2`, prior knowledge): `concurrency` request
//! loops, each sending the next request from the previous one's callback, for `seconds`; prints
//! requests per second. A `timeout-ms` above 0 sets [`ClientRequest::timeout`] on every
//! request. Defaults: 5 s, 64 loops, 2 client and 2 server threads, epoll, `h1`, no timeout.
//! With `uring` both the server and the client connections run on io_uring (the client engine
//! dials from the threads of an io_uring listener of its own, since `client_threads` are
//! epoll).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{Backend, Engine, Listener};
use akio_http::{
    Context, Router,
    client::{Client, ClientError, ClientRequest, ClientResponse},
    h2client::{H2Client, H2Options},
    serve,
};

#[derive(Clone)]
enum Driver {
    H1(Client),
    H2(Arc<Vec<H2Client>>, Arc<AtomicUsize>),
}

impl Driver {
    fn send(
        &self,
        req: ClientRequest,
        done: impl FnOnce(Result<ClientResponse, ClientError>) + Send + 'static,
    ) {
        match self {
            Driver::H1(c) => c.request(req, done),
            Driver::H2(cs, next) => {
                let i = next.fetch_add(1, Ordering::Relaxed) % cs.len();
                cs[i].request(req, done);
            }
        }
    }
}

struct Loop {
    driver: Driver,
    url: Arc<str>,
    timeout: Option<Duration>,
    done: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

fn run(l: Arc<Loop>) {
    let mut req = ClientRequest::get(&l.url);
    if let Some(t) = l.timeout {
        req = req.timeout(t);
    }
    let l2 = l.clone();
    l.driver.send(req, move |r| {
        if r.is_ok_and(|r| r.status == 200) {
            l2.done.fetch_add(1, Ordering::Relaxed);
        }
        if !l2.stop.load(Ordering::Relaxed) {
            run(l2);
        }
    });
}

fn main() {
    let mut args = std::env::args().skip(1);
    let secs: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(5);
    let conc: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(64);
    let threads: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(2);
    let uring = args.next().as_deref() == Some("uring");
    let h2 = args.next().as_deref() == Some("h2");
    let timeout = match args.next().and_then(|a| a.parse::<u64>().ok()).unwrap_or(0) {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    };
    let backend = || {
        if uring {
            Backend::IoUring(Default::default())
        } else {
            Backend::Epoll
        }
    };
    let router = Router::new().get("/plaintext", |ctx: &mut Context| {
        ctx.text(200, "Hello, World!");
    });
    let server = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                .backend(backend())
                .threads(threads)
                .serve(serve(router)),
        )
        .build()
        .expect("server");
    server.start().expect("start");
    let addr = server.local_addrs()[0];
    let ce = if uring {
        // Dials go to the last TCP listener's threads: an io_uring one that serves nothing.
        Engine::builder().listen(
            Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                .backend(backend())
                .threads(threads)
                .serve(serve(Router::new())),
        )
    } else {
        Engine::builder().client_threads(threads)
    };
    let ce = Arc::new(ce.build().expect("client engine"));
    ce.start().expect("start");
    let url: Arc<str> = format!("http://{addr}/plaintext").into();
    let driver = if h2 {
        let conns = (0..threads)
            .map(|_| H2Client::dial_blocking(&ce, addr, None, H2Options::default()))
            .collect::<std::io::Result<Vec<_>>>()
            .expect("h2 connect");
        Driver::H2(Arc::new(conns), Arc::new(AtomicUsize::new(0)))
    } else {
        Driver::H1(Client::new(ce))
    };
    // Warm up the keep-alive pool (or the HTTP/2 connections).
    let (tx, rx) = std::sync::mpsc::channel();
    driver.send(ClientRequest::get(&url), move |r| {
        let _ = tx.send(r.map(|r| r.status));
    });
    let warm = rx.recv_timeout(Duration::from_secs(10)).expect("warm-up");
    assert_eq!(warm.expect("warm-up"), 200);
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    for _ in 0..conc {
        run(Arc::new(Loop {
            driver: driver.clone(),
            url: url.clone(),
            timeout,
            done: done.clone(),
            stop: stop.clone(),
        }));
    }
    std::thread::sleep(Duration::from_secs(secs));
    let n = done.load(Ordering::Relaxed);
    let took = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    println!(
        "client-bench: {:.0} req/s ({n} in {took:.2} s, {conc} loops, {}, {}, timeout {:?})",
        n as f64 / took,
        if uring { "uring" } else { "epoll" },
        if h2 { "h2" } else { "h1" },
        timeout,
    );
    std::thread::sleep(Duration::from_millis(200));
    std::process::exit(0);
}
