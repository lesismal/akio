//! Accept-time balancing of TCP connections over a listener's I/O threads (ADR-100), on the
//! backend under test (`AKIO_TEST_BACKEND=uring` for io_uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Balance, Config, Conn, Engine, Handler, Listener, fn_acceptor};

fn cfg() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// Echoes, and records a mismatch if a callback ever runs on another thread than `on_open`.
struct Pinned {
    opened_on: Option<String>,
    moved: Arc<Mutex<u32>>,
}

impl Handler for Pinned {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if thread::current().name().map(str::to_owned) != self.opened_on {
            *self.moved.lock().unwrap() += 1;
        }
        let _ = c.send(data);
    }
}

fn engine(threads: usize, balance: Balance, moved: Arc<Mutex<u32>>) -> Engine {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(threads)
                .balance(balance)
                .serve(fn_acceptor(move |_c: &Conn<Pinned>| Pinned {
                    opened_on: thread::current().name().map(str::to_owned),
                    moved: moved.clone(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn echo(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).unwrap();
    let mut buf = vec![0; msg.len()];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, msg);
}

/// Open connections per I/O thread, once `n` are open in all.
fn open_per_thread(e: &Engine, n: u64) -> Vec<u64> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let loads: Vec<u64> = e.metrics().loops.iter().map(|l| l.open()).collect();
        if loads.iter().sum::<u64>() == n || Instant::now() > deadline {
            return loads;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn connections_are_spread_evenly() {
    if common::rounds() {
        return; // per-thread connection balance is a loops matter (ADR-100, ADR-104)
    }
    let moved = Arc::new(Mutex::new(0));
    let e = engine(4, Balance::LeastConnections, moved.clone());
    let addr = e.local_addrs()[0];
    // From several client threads at once, so accepts race on every I/O thread.
    let clients: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                (0..32)
                    .map(|j| {
                        let mut s = connect(addr);
                        echo(&mut s, format!("{i}/{j}").as_bytes());
                        s
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut conns: Vec<TcpStream> = clients
        .into_iter()
        .flat_map(|c| c.join().unwrap())
        .collect();
    let loads = open_per_thread(&e, 256);
    assert_eq!(loads.iter().sum::<u64>(), 256, "{loads:?}");
    let (min, max) = (*loads.iter().min().unwrap(), *loads.iter().max().unwrap());
    // Each thread keeps a connection while it holds at most `2 + min / 32` above the least
    // loaded; racing accepts can each add one more.
    assert!(max - min <= 2 + min / 32 + 4, "uneven: {loads:?}");
    // Every connection still works, and none ever ran a callback off its `on_open` thread.
    for (k, s) in conns.iter_mut().enumerate() {
        echo(s, format!("again {k}").as_bytes());
    }
    assert_eq!(*moved.lock().unwrap(), 0);
    e.shutdown();
    e.wait();
}

/// Connections close and reopen: the counts follow (closed ones leave the load).
#[test]
fn closed_connections_leave_the_count() {
    if common::rounds() {
        return; // per-thread connection balance is a loops matter (ADR-100, ADR-104)
    }
    let moved = Arc::new(Mutex::new(0));
    let e = engine(3, Balance::LeastConnections, moved.clone());
    let addr = e.local_addrs()[0];
    for round in 0..3 {
        let mut conns: Vec<_> = (0..60).map(|_| connect(addr)).collect();
        for s in &mut conns {
            echo(s, b"x");
        }
        let loads = open_per_thread(&e, 60);
        let (min, max) = (*loads.iter().min().unwrap(), *loads.iter().max().unwrap());
        assert!(max - min <= 3, "round {round}: {loads:?}");
        drop(conns);
        assert_eq!(open_per_thread(&e, 0).iter().sum::<u64>(), 0);
    }
    assert_eq!(*moved.lock().unwrap(), 0);
    e.shutdown();
    e.wait();
}

/// `Balance::Kernel` serves as before (each thread keeps what its socket accepts).
#[test]
fn kernel_balance_serves() {
    if common::rounds() {
        return; // per-thread connection balance is a loops matter (ADR-100, ADR-104)
    }
    let moved = Arc::new(Mutex::new(0));
    let e = engine(2, Balance::Kernel, moved.clone());
    let addr = e.local_addrs()[0];
    let mut conns: Vec<_> = (0..32).map(|_| connect(addr)).collect();
    for s in &mut conns {
        echo(s, b"kernel");
    }
    assert_eq!(open_per_thread(&e, 32).iter().sum::<u64>(), 32);
    assert_eq!(*moved.lock().unwrap(), 0);
    e.shutdown();
    e.wait();
}

/// Shrinking and growing the thread count while connections arrive: every connection is
/// served (handed-over ones that reach a retiring thread are passed on, not lost).
#[test]
fn balancing_survives_resizing() {
    if common::rounds() {
        return; // per-thread connection balance is a loops matter (ADR-100, ADR-104)
    }
    let moved = Arc::new(Mutex::new(0));
    let e = Arc::new(engine(4, Balance::LeastConnections, moved.clone()));
    let addr = e.local_addrs()[0];
    let resizer = {
        let e = e.clone();
        thread::spawn(move || {
            for n in [2, 3, 1, 4] {
                thread::sleep(Duration::from_millis(15));
                e.set_threads(0, n).unwrap();
            }
        })
    };
    let clients: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                for j in 0..60 {
                    let mut s = connect(addr);
                    echo(&mut s, format!("{i}:{j}").as_bytes());
                }
            })
        })
        .collect();
    for c in clients {
        c.join().unwrap();
    }
    resizer.join().unwrap();
    assert_eq!(*moved.lock().unwrap(), 0);
    e.shutdown();
    e.wait();
}
