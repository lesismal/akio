//! End-to-end tests of the supervisor with real worker processes: this test binary re-executes
//! itself as the workers (it has its own `main`, `harness = false`), each serving only-http.
//!
//! `cargo test -p only-prefork --test prefork [-- <name filter>]`. `ONLY_TEST_BACKEND=uring`
//! serves the workers on io_uring, as for the other tests.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashSet,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{Backend, Config, Engine, UringConfig};
use only_http::{Context, Response, Router, serve};
use only_prefork::{ListenMode, Prefork, Status, Supervisor, Worker};

// ---- the worker -------------------------------------------------------------------------------

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn worker(w: Worker) -> io::Result<()> {
    let info = format!("{} {} {}", w.index(), w.workers(), w.generation());
    let app = Router::new()
        .get("/pid", |ctx: &mut Context| {
            ctx.text(200, std::process::id().to_string());
        })
        .get("/info", move |ctx: &mut Context| {
            ctx.text(200, info.clone());
        })
        .get("/slow/:ms", |ctx: &mut Context| {
            let ms: u64 = ctx.param("ms").and_then(|v| v.parse().ok()).unwrap_or(500);
            let Some(d) = ctx.detach() else { return };
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(ms));
                d.respond(Response::text(200, std::process::id().to_string()));
            });
        })
        .get("/crash", |_ctx: &mut Context| std::process::exit(3));
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_secs(5);
    let engine = Engine::builder()
        .config(cfg)
        .listen(
            w.listener(0)?
                .backend(backend())
                .threads(2)
                .serve(serve(app)),
        )
        .build()?;
    w.serve(&engine)
}

// ---- helpers ----------------------------------------------------------------------------------

/// One `GET` on a fresh connection; the body of a 200 response.
fn get(addr: SocketAddr, path: &str) -> io::Result<String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )?;
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("no response to {path}: {text:?}"),
        ));
    };
    if !head.starts_with("HTTP/1.1 200") {
        return Err(io::Error::other(format!("{path}: {head}")));
    }
    Ok(body.to_owned())
}

fn prefork(workers: usize, mode: ListenMode) -> Prefork {
    Prefork::new()
        .workers(workers)
        .listen("127.0.0.1:0".parse().unwrap())
        .mode(mode)
        .shutdown_timeout(Duration::from_secs(10))
        .ready_timeout(Duration::from_secs(20))
        .restart_backoff(Duration::from_millis(50), Duration::from_secs(1))
}

/// Polls the supervisor until `ok(status)` or panics after `secs`.
fn wait_until(sup: &Supervisor, secs: u64, what: &str, ok: impl Fn(&Status) -> bool) -> Status {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let st = sup.status();
        if ok(&st) {
            return st;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {st:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Every worker slot has a ready, current-generation worker and nothing else is running.
fn settled(n: usize) -> impl Fn(&Status) -> bool {
    move |st: &Status| st.serving().len() == n && st.workers.len() == n
}

fn pids(st: &Status) -> HashSet<u32> {
    st.workers.iter().map(|w| w.pid).collect()
}

/// `n` requests from `threads` concurrent clients; the answering pids.
fn spread(addr: SocketAddr, threads: usize, n: usize) -> HashSet<u32> {
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            thread::spawn(move || {
                (0..n / threads)
                    .map(|_| get(addr, "/pid").unwrap().parse::<u32>().unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect()
}

// ---- scenarios --------------------------------------------------------------------------------

fn served_by_several_workers(mode: ListenMode) {
    let sup = prefork(4, mode).spawn().unwrap();
    let addr = sup.addrs()[0];
    let st = wait_until(&sup, 20, "4 ready workers", settled(4));
    let workers = pids(&st);
    assert_eq!(workers.len(), 4);
    assert!(!workers.contains(&std::process::id()));
    // io_uring workers sharing one inherited socket: the multishot accept of whichever ring
    // armed first tends to take every connection (documented; ReusePort balances).
    let lopsided = mode == ListenMode::Inherit && matches!(backend(), Backend::IoUring(_));
    let mut infos = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(if lopsided { 2 } else { 20 });
    while infos.len() < 2 && Instant::now() < deadline {
        infos.extend(spread(addr, 8, 64));
    }
    assert!(
        lopsided || infos.len() >= 2,
        "{mode:?}: every request answered by one process: {infos:?}"
    );
    assert!(infos.is_subset(&workers), "{infos:?} not in {workers:?}");
    // Every worker knows its index and that there are 4.
    for _ in 0..16 {
        let info = get(addr, "/info").unwrap();
        let v: Vec<u64> = info.split(' ').map(|x| x.parse().unwrap()).collect();
        assert!(v[0] < 4 && v[1] == 4 && v[2] == 0, "{info}");
    }
    println!(
        "    {mode:?}: requests answered by {} of 4 worker pids",
        infos.len()
    );
    sup.shutdown();
    sup.wait().unwrap();
}

fn crashed_worker_is_restarted(mode: ListenMode) {
    let sup = prefork(2, mode).spawn().unwrap();
    let addr = sup.addrs()[0];
    let before = pids(&wait_until(&sup, 20, "2 ready workers", settled(2)));
    // The worker answering this exits without a response.
    assert!(get(addr, "/crash").is_err());
    let st = wait_until(&sup, 20, "a restart", |st| {
        st.restarts >= 1 && settled(2)(st)
    });
    let after = pids(&st);
    assert_eq!(after.len(), 2);
    assert_eq!(
        before.intersection(&after).count(),
        1,
        "{before:?} -> {after:?}"
    );
    // Every index is still served: one survivor, one replacement with the crashed one's index.
    let mut idx: Vec<usize> = st.workers.iter().map(|w| w.index).collect();
    idx.sort_unstable();
    assert_eq!(idx, vec![0, 1]);
    for _ in 0..20 {
        let pid: u32 = get(addr, "/pid").unwrap().parse().unwrap();
        assert!(after.contains(&pid));
    }
    // A second crash of the same slot backs off longer but still restarts.
    let _ = get(addr, "/crash");
    wait_until(&sup, 20, "a second restart", |st| {
        st.restarts >= 2 && settled(2)(st)
    });
    sup.shutdown();
    sup.wait().unwrap();
}

fn shutdown_drains_in_flight_requests(mode: ListenMode) {
    let sup = prefork(2, mode).spawn().unwrap();
    let addr = sup.addrs()[0];
    wait_until(&sup, 20, "2 ready workers", settled(2));
    let clients: Vec<_> = (0..6)
        .map(|_| thread::spawn(move || get(addr, "/slow/800")))
        .collect();
    // Let every request reach a worker, then stop while they are in flight.
    thread::sleep(Duration::from_millis(250));
    let t0 = Instant::now();
    sup.shutdown();
    let st = sup.status();
    for c in clients {
        let body = c
            .join()
            .unwrap()
            .expect("in-flight request completed during the drain");
        assert!(body.parse::<u32>().is_ok(), "{body}");
    }
    sup.wait().unwrap();
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(300),
        "returned before the drain: {took:?}"
    );
    assert!(took < Duration::from_secs(8), "drain took {took:?}: {st:?}");
    // The supervisor released the port with the last worker.
    assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err());
}

/// Requests that failed while a reload swapped the workers.
#[derive(Debug, Default)]
struct Failures {
    /// The connection was refused or reset by the kernel (a dropped accept queue).
    lost: usize,
    /// A worker accepted the connection and closed it without answering: it was draining and
    /// its HTTP server closed a connection whose request it had not read yet.
    unanswered: usize,
    /// Requests answered.
    ok: usize,
}

fn reload_swaps_workers(mode: ListenMode) -> Failures {
    let sup = prefork(3, mode).spawn().unwrap();
    let addr = sup.addrs()[0];
    let old = pids(&wait_until(&sup, 20, "3 ready workers", settled(3)));
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(AtomicUsize::new(0));
    let lost = Arc::new(AtomicUsize::new(0));
    let unanswered = Arc::new(AtomicUsize::new(0));
    let clients: Vec<_> = (0..6)
        .map(|_| {
            let (stop, ok) = (stop.clone(), ok.clone());
            let (lost, unanswered) = (lost.clone(), unanswered.clone());
            thread::spawn(move || {
                let mut seen = HashSet::new();
                while !stop.load(Ordering::Relaxed) {
                    match get(addr, "/pid") {
                        Ok(b) => {
                            seen.insert(b.parse::<u32>().unwrap());
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        // An old worker that drains closes a connection it accepted before
                        // the request was read: the client sees EOF, or a reset / broken pipe
                        // when the request bytes had already arrived (seen under load). Same
                        // race, so counted together and bounded below; a refused connect is not.
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::BrokenPipe
                            ) =>
                        {
                            unanswered.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("    request failed during reload: {e}");
                            lost.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                seen
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(200));
    sup.reload();
    let st = wait_until(&sup, 30, "the reload", |st| {
        st.generation == 1 && settled(3)(st)
    });
    let new = pids(&st);
    assert!(old.is_disjoint(&new), "{old:?} / {new:?}");
    assert_eq!(st.reloads, 1);
    // Traffic after the reload goes to the new generation only.
    let ok_at_reload = ok.load(Ordering::Relaxed);
    thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    let seen: HashSet<u32> = clients
        .into_iter()
        .flat_map(|c| c.join().unwrap())
        .collect();
    let mut late = HashSet::new();
    for _ in 0..30 {
        late.insert(get(addr, "/pid").unwrap().parse::<u32>().unwrap());
    }
    assert!(late.is_subset(&new), "{late:?} not in {new:?}");
    assert!(seen.iter().any(|p| old.contains(p)) && seen.iter().any(|p| new.contains(p)));
    let f = Failures {
        lost: lost.load(Ordering::Relaxed),
        unanswered: unanswered.load(Ordering::Relaxed),
        ok: ok.load(Ordering::Relaxed),
    };
    println!(
        "    {mode:?}: {} requests answered during the reload ({} after it), {} refused/reset, \
         {} closed unanswered by a draining worker",
        f.ok,
        f.ok - ok_at_reload,
        f.lost,
        f.unanswered
    );
    sup.shutdown();
    sup.wait().unwrap();
    f
}

fn bad_program_fails_spawn() {
    let err = prefork(2, ListenMode::Inherit)
        .program("/nonexistent/only-prefork-worker")
        .spawn()
        .unwrap_err();
    assert!(err.to_string().contains("starting worker 0"), "{err}");
}

fn second_shutdown_kills() {
    // Workers that ignore their stop request (a long in-flight request, a long drain budget)
    // are killed by a second shutdown.
    let sup = prefork(1, ListenMode::Inherit).spawn().unwrap();
    let addr = sup.addrs()[0];
    wait_until(&sup, 20, "1 ready worker", settled(1));
    let client = thread::spawn(move || get(addr, "/slow/4000"));
    thread::sleep(Duration::from_millis(200));
    let t0 = Instant::now();
    sup.shutdown();
    thread::sleep(Duration::from_millis(200));
    sup.shutdown();
    sup.wait().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert!(client.join().unwrap().is_err());
}

// ---- main -------------------------------------------------------------------------------------

type Test = Box<dyn Fn()>;

fn main() {
    if only_prefork::is_worker() {
        // Re-executed by a supervisor below: serve until asked to stop.
        if let Err(e) = Prefork::new().run(worker) {
            eprintln!("worker failed: {e}");
            std::process::exit(1);
        }
        return;
    }
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let mut tests: Vec<(&str, Test)> = vec![
        ("bad_program_fails_spawn", Box::new(bad_program_fails_spawn)),
        (
            "served_by_several_workers_inherit",
            Box::new(|| served_by_several_workers(ListenMode::Inherit)),
        ),
        (
            "crashed_worker_is_restarted",
            Box::new(|| crashed_worker_is_restarted(ListenMode::Auto)),
        ),
        (
            "shutdown_drains_in_flight_requests_inherit",
            Box::new(|| shutdown_drains_in_flight_requests(ListenMode::Inherit)),
        ),
        (
            "reload_swaps_workers_inherit_no_refused",
            Box::new(|| {
                let f = reload_swaps_workers(ListenMode::Inherit);
                // The listening socket never stops listening: nothing is refused.
                assert_eq!(f.lost, 0, "{f:?}");
                // A connection an old worker accepted just before its drain, whose request it
                // had not read yet, is closed by only-http's shutdown (it closes connections
                // with no request in flight): rare, bounded here.
                assert!(f.unanswered * 1000 <= f.ok, "{f:?}");
            }),
        ),
        ("second_shutdown_kills", Box::new(second_shutdown_kills)),
    ];
    if cfg!(target_os = "linux") {
        tests.push((
            "served_by_several_workers_reuseport",
            Box::new(|| served_by_several_workers(ListenMode::ReusePort)),
        ));
        tests.push((
            "shutdown_drains_in_flight_requests_reuseport",
            Box::new(|| shutdown_drains_in_flight_requests(ListenMode::ReusePort)),
        ));
        // SO_REUSEPORT drops what an old worker's sockets had queued unless the kernel
        // migrates it (net.ipv4.tcp_migrate_req): reported, not asserted.
        tests.push((
            "reload_swaps_workers_reuseport",
            Box::new(|| {
                reload_swaps_workers(ListenMode::ReusePort);
            }),
        ));
    }
    let selected: Vec<_> = tests
        .iter()
        .filter(|(name, _)| filter.is_empty() || filter.iter().any(|f| name.contains(f.as_str())))
        .collect();
    println!("\nrunning {} tests", selected.len());
    let mut failed = Vec::new();
    for (name, test) in selected {
        let t0 = Instant::now();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let verdict = if r.is_ok() { "ok" } else { "FAILED" };
        println!("test {name} ... {verdict} ({:.2?})", t0.elapsed());
        if r.is_err() {
            failed.push(*name);
        }
    }
    if failed.is_empty() {
        println!("\ntest result: ok.");
    } else {
        println!("\ntest result: FAILED. {failed:?}");
        std::process::exit(101);
    }
}
