//! The logical pool: `spawn_blocking`, ordered responses, overload, slow-callback detection.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, Engine, Error, Handler, Listener, PoolConfig, SlowHook, fn_acceptor};

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn quick() -> Config {
    {
        let mut v = Config::default();
        v.shutdown_timeout = Duration::from_millis(300);
        v
    }
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    s.read_exact(&mut v).unwrap();
    v
}

/// Line-less protocol: every byte received is a request; "blocking work" takes `byte` ms.
struct Slow {
    done_count: u32,
    on_io_thread: Arc<AtomicBool>,
}

impl Handler for Slow {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if data == b"echo" {
            let _ = c.send(data);
            return;
        }
        let ms = u64::from(data[0]);
        c.spawn_blocking(
            move || {
                thread::sleep(Duration::from_millis(ms * 10));
                ms
            },
            |me: &mut Slow, c, ms| {
                me.done_count += 1;
                // Completion runs on an I/O thread, with the handler state we mutated.
                let name = thread::current().name().unwrap_or("").to_string();
                me.on_io_thread
                    .store(name.starts_with("akio-io"), Ordering::SeqCst);
                let _ = c.send(format!("{}:{}", ms, me.done_count).as_bytes());
            },
        )
        .unwrap();
    }
}

#[test]
fn blocking_work_does_not_stall_the_io_thread_and_completes_on_it() {
    let on_io = Arc::new(AtomicBool::new(false));
    let o = on_io.clone();
    // One I/O thread: if blocking work ran inline, `other` below would have to wait for it.
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Slow>| Slow {
                    done_count: 0,
                    on_io_thread: o.clone(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let mut worker = connect(addr);
    let mut other = connect(addr);
    worker.write_all(&[50]).unwrap(); // 500 ms of "blocking" work
    thread::sleep(Duration::from_millis(50));
    let t = Instant::now();
    other.write_all(b"echo").unwrap();
    assert_eq!(read_n(&mut other, 4), b"echo");
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "I/O thread was blocked for {:?}",
        t.elapsed()
    );
    assert_eq!(read_n(&mut worker, 4), b"50:1");
    assert!(
        on_io.load(Ordering::SeqCst),
        "completion must run on an I/O thread"
    );
    // A second job sees the state the first one left behind.
    worker.write_all(&[1]).unwrap();
    assert_eq!(read_n(&mut worker, 3), b"1:2");
    stop(&e);
}

#[test]
fn completion_is_skipped_when_the_connection_closed_meanwhile() {
    let ran = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    struct H(Arc<AtomicUsize>, Arc<AtomicUsize>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let fin = self.1.clone();
            c.spawn_blocking(
                move || {
                    thread::sleep(Duration::from_millis(200));
                    fin.fetch_add(1, Ordering::SeqCst);
                },
                |me: &mut H, _c, ()| {
                    me.0.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();
        }
    }
    let (r, f) = (ran.clone(), finished.clone());
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(r.clone(), f.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"x").unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(s); // gone before the work finishes
    let t = Instant::now();
    while finished.load(Ordering::SeqCst) == 0 {
        assert!(t.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        0,
        "completion must not run after close"
    );
    stop(&e);
}

#[test]
fn pool_overload_is_reported_to_the_caller() {
    let results = Arc::new(Mutex::new(Vec::new()));
    struct H(Arc<Mutex<Vec<bool>>>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            // Long enough that job 1 still runs when submission 4 arrives on a slow runner.
            let r = c.spawn_blocking(|| thread::sleep(Duration::from_secs(3)), |_, _, ()| {});
            self.0
                .lock()
                .unwrap()
                .push(matches!(r, Err(Error::Overloaded)));
            let _ = c.send(b"k");
        }
    }
    let res = results.clone();
    let e = Engine::builder()
        .config(quick())
        // One worker, room for one waiting job: the 3rd and 4th submissions must be refused.
        .pool({
            let mut v = PoolConfig::default();
            v.min_threads = 0;
            v.max_threads = 1;
            v.queue_capacity = 1;
            v.keep_alive = Duration::from_secs(1);
            v
        })
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(res.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    for _ in 0..4 {
        s.write_all(b"x").unwrap();
        read_n(&mut s, 1);
        thread::sleep(Duration::from_millis(30)); // let the worker pick up job 1
    }
    let r = results.lock().unwrap().clone();
    assert_eq!(
        r,
        vec![false, false, true, true],
        "submissions 3 and 4 overflow"
    );
    assert!(e.pool_stats().rejected >= 2);
    stop(&e);
}

#[test]
fn ordered_slots_keep_pipelined_responses_in_request_order() {
    struct H;
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            // One request per byte, pipelined in a single segment. Later requests finish first.
            for &b in data {
                let slot = c.reserve_response().unwrap();
                let delay = (20 - u64::from(b)) * 5;
                c.spawn_blocking(
                    move || {
                        thread::sleep(Duration::from_millis(delay));
                        slot.fill(vec![b'a' + b]);
                    },
                    |_, _, ()| {},
                )
                .unwrap();
            }
        }
    }
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(2)
                .serve(fn_acceptor(|_c: &Conn<H>| H)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    let reqs: Vec<u8> = (0..20).collect();
    s.write_all(&reqs).unwrap();
    let want: Vec<u8> = (0..20).map(|b| b'a' + b).collect();
    assert_eq!(read_n(&mut s, 20), want);
    stop(&e);
}

#[test]
fn dropping_an_unfilled_slot_closes_the_connection() {
    struct H;
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let slot = c.reserve_response().unwrap();
            drop(slot);
        }
    }
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<H>| H)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"x").unwrap();
    let mut b = [0u8; 1];
    assert_eq!(common::read_retry(&mut s, &mut b).unwrap(), 0);
    stop(&e);
}

#[test]
fn slow_callbacks_are_reported_and_fast_ones_are_not() {
    struct H;
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            if data == b"slow" {
                thread::sleep(Duration::from_millis(120));
            }
            let _ = c.send(b"k");
        }
    }
    let hits = Arc::new(Mutex::new(Vec::new()));
    let h = hits.clone();
    let e = Engine::builder()
        .config({
            let mut v = quick();
            v.slow_callback_threshold = Some(Duration::from_millis(50));
            v.slow_hook = Some(SlowHook(Arc::new(move |r| {
                h.lock().unwrap().push((r.kind, r.elapsed));
            })));
            v
        })
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<H>| H)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"fast").unwrap();
    read_n(&mut s, 1);
    assert!(hits.lock().unwrap().is_empty());
    s.write_all(b"slow").unwrap();
    read_n(&mut s, 1);
    let got = hits.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "on_data");
    assert!(got[0].1 >= Duration::from_millis(100));
    stop(&e);
}

/// `Conn::run_on_loop` reaches the handler without a pool thread: a pool job holding the only
/// pool thread hands work to the loop and waits for it.
#[test]
fn run_on_loop_needs_no_pool_thread() {
    struct H;
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let c2 = c.clone();
            c.execute(move || {
                let (tx, rx) = std::sync::mpsc::channel();
                c2.run_on_loop(move |_h: &mut H, c| {
                    let _ = c.send(b"L");
                    let _ = tx.send(());
                })
                .unwrap();
                let ok = rx.recv_timeout(Duration::from_secs(5)).is_ok();
                let _ = c2.send(if ok { b"Y" } else { b"N" });
            })
            .unwrap();
        }
    }
    let e = Engine::builder()
        .config(quick())
        .pool({
            let mut v = PoolConfig::default();
            v.max_threads = 1;
            v
        })
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<H>| H)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"x").unwrap();
    assert_eq!(read_n(&mut s, 2), b"LY");
    stop(&e);
}

/// Work handed to `run_on_loop` that never runs is dropped, so a guard it owns can answer its
/// waiter: refused at once on a closed connection, and dropped unrun when the connection
/// closes after it was queued but before the loop got to it (here the handler panics right
/// after posting, which closes the connection within the same batch).
#[test]
fn run_on_loop_work_that_cannot_run_is_dropped() {
    /// Counts whether the work it rides in ran or was dropped unrun.
    struct Guard {
        ran: bool,
        counts: Arc<(AtomicUsize, AtomicUsize)>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let c = if self.ran {
                &self.counts.0
            } else {
                &self.counts.1
            };
            c.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct H(Arc<(AtomicUsize, AtomicUsize)>, Arc<AtomicUsize>);
    impl Handler for H {
        fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
            let g = Guard {
                ran: false,
                counts: self.0.clone(),
            };
            // Posted from the loop's own thread, so it would run after this batch.
            c.run_on_loop(move |_h: &mut H, _c| {
                let mut g = g; // the whole guard rides in the work, not just its field
                g.ran = true;
            })
            .unwrap();
            self.1.fetch_add(1, Ordering::SeqCst);
            panic!("closes the connection before the posted work runs");
        }
        fn on_close(&mut self, c: &Conn<Self>, _e: Option<Error>) {
            let g = Guard {
                ran: false,
                counts: self.0.clone(),
            };
            let r = c.run_on_loop(move |_h: &mut H, _c| drop(g));
            assert!(matches!(r, Err(Error::Closed)), "{r:?}");
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
    let counts = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
    let posted = Arc::new(AtomicUsize::new(0));
    let (c2, p2) = (counts.clone(), posted.clone());
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp(localhost())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H(c2.clone(), p2.clone()))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    for _ in 0..50 {
        let mut s = connect(addr);
        s.write_all(b"x").unwrap();
        drop(s);
    }
    // 50 posts in `on_data`, dropped when the panic closed the connection, and 50 refused
    // posts in `on_close`.
    let t = Instant::now();
    while counts.0.load(Ordering::SeqCst) + counts.1.load(Ordering::SeqCst) < 100 {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "work neither ran nor was dropped"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(posted.load(Ordering::SeqCst), 100);
    assert_eq!(
        counts.0.load(Ordering::SeqCst),
        0,
        "no work ran on a closed connection"
    );
    assert_eq!(counts.1.load(Ordering::SeqCst), 100);
    stop(&e);
}
