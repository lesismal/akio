//! Loop timers (`akio::timer`, ADR-103): set from a callback, run later on the same I/O thread.
//! TCP on the native backend (and io_uring with AKIO_TEST_BACKEND=uring), and UDP.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

use akio::{
    Backend, Config, Conn, Engine, Error, Handler, Listener, UringConfig, fn_acceptor, timer,
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

fn cfg() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(500);
    v
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// Each line `<ms>\n` is answered with `<ms>\n` after `ms` milliseconds, from a loop timer.
/// Records whether the timer ran on the thread that set it.
struct Delay {
    same_thread: Arc<AtomicUsize>,
    other_thread: Arc<AtomicUsize>,
    buf: Vec<u8>,
}

impl Handler for Delay {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        assert!(timer::on_loop());
        self.buf.extend_from_slice(data);
        while let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            let ms: u64 = std::str::from_utf8(&line).unwrap().trim().parse().unwrap();
            let set_on: ThreadId = thread::current().id();
            let (c, same, other) = (
                c.clone(),
                self.same_thread.clone(),
                self.other_thread.clone(),
            );
            let _ = timer::after(Duration::from_millis(ms), move || {
                if thread::current().id() == set_on {
                    same.fetch_add(1, Ordering::Relaxed);
                } else {
                    other.fetch_add(1, Ordering::Relaxed);
                }
                let _ = c.send(&line);
            })
            .unwrap();
        }
    }
}

fn delay_engine() -> (Engine, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let same = Arc::new(AtomicUsize::new(0));
    let other = Arc::new(AtomicUsize::new(0));
    let (s, o) = (same.clone(), other.clone());
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(fn_acceptor(move |_c: &Conn<Delay>| Delay {
                    same_thread: s.clone(),
                    other_thread: o.clone(),
                    buf: Vec::new(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    (e, same, other)
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_nodelay(true).unwrap();
    s
}

fn read_lines(s: &mut TcpStream, n: usize) -> Vec<String> {
    let mut got = Vec::new();
    let mut b = [0u8; 256];
    while got.iter().filter(|&&c| c == b'\n').count() < n {
        let k = s.read(&mut b).unwrap();
        assert!(k > 0, "closed early");
        got.extend_from_slice(&b[..k]);
    }
    String::from_utf8(got)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn not_on_a_loop_off_the_io_threads() {
    assert!(!timer::on_loop());
    assert!(matches!(
        timer::after(Duration::ZERO, || {}),
        Err(Error::Closed)
    ));
}

#[test]
fn fires_after_the_delay_on_the_owning_thread() {
    let (e, same, other) = delay_engine();
    let mut s = connect(e.local_addrs()[0]);
    let t0 = Instant::now();
    s.write_all(b"40\n").unwrap();
    assert_eq!(read_lines(&mut s, 1), ["40"]);
    assert!(
        t0.elapsed() >= Duration::from_millis(40),
        "{:?}",
        t0.elapsed()
    );
    // Shorter delays overtake longer ones set earlier.
    s.write_all(b"60\n0\n20\n").unwrap();
    assert_eq!(read_lines(&mut s, 3), ["0", "20", "60"]);
    assert_eq!(same.load(Ordering::Relaxed), 4);
    assert_eq!(other.load(Ordering::Relaxed), 0);
    stop(&e);
}

#[test]
fn many_connections_and_timers() {
    let (e, same, other) = delay_engine();
    let addr = e.local_addrs()[0];
    let clients: Vec<_> = (0..32)
        .map(|i| {
            thread::spawn(move || {
                let mut s = connect(addr);
                let mut want = Vec::new();
                let mut req = String::new();
                for j in 0..20u64 {
                    let ms = (i * 7 + j * 3) % 25;
                    req.push_str(&format!("{ms}\n"));
                    want.push(ms);
                }
                s.write_all(req.as_bytes()).unwrap();
                let mut got: Vec<u64> = read_lines(&mut s, 20)
                    .iter()
                    .map(|l| l.parse().unwrap())
                    .collect();
                got.sort_unstable();
                want.sort_unstable();
                assert_eq!(got, want);
            })
        })
        .collect();
    for c in clients {
        c.join().unwrap();
    }
    assert_eq!(same.load(Ordering::Relaxed), 32 * 20);
    assert_eq!(other.load(Ordering::Relaxed), 0);
    stop(&e);
}

#[test]
fn connection_closed_while_a_timer_is_pending() {
    let (e, same, _) = delay_engine();
    let addr = e.local_addrs()[0];
    for _ in 0..10 {
        let mut s = connect(addr);
        s.write_all(b"30\n").unwrap();
        drop(s); // gone before the reply: the timer's send fails quietly
    }
    thread::sleep(Duration::from_millis(80));
    let mut s = connect(addr);
    s.write_all(b"1\n").unwrap();
    assert_eq!(read_lines(&mut s, 1), ["1"]);
    assert_eq!(same.load(Ordering::Relaxed), 11);
    stop(&e);
}

#[test]
fn shutdown_drops_pending_timers() {
    let (e, _, _) = delay_engine();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"600000\n").unwrap();
    thread::sleep(Duration::from_millis(50));
    let t0 = Instant::now();
    stop(&e); // does not wait for the ten-minute timer
    assert!(t0.elapsed() < Duration::from_secs(5));
}

/// UDP: each datagram `<ms>` comes back after `ms` milliseconds; one timer is cancelled.
struct UdpDelay;
impl Handler for UdpDelay {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let ms: u64 = std::str::from_utf8(data).unwrap().parse().unwrap();
        let (c1, c2, d) = (c.clone(), c.clone(), data.to_vec());
        let cancelled = timer::after(Duration::from_millis(ms), move || {
            let _ = c1.send(b"cancelled");
        })
        .unwrap();
        assert!(cancelled.cancel());
        let _ = timer::after(Duration::from_millis(ms), move || {
            let _ = c2.send(&d);
        })
        .unwrap();
    }
}

#[test]
fn udp_loops_have_timers_too() {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<UdpDelay>| UdpDelay)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t0 = Instant::now();
    s.send(b"30").unwrap();
    let mut b = [0u8; 64];
    let n = s.recv(&mut b).unwrap();
    assert_eq!(&b[..n], b"30");
    assert!(t0.elapsed() >= Duration::from_millis(30));
    stop(&e);
}

/// `timer::after_send` (ADR-154, akit A45): set from a thread that is not an I/O thread, run
/// once on the process-wide timer thread, never early; cancelled from yet another thread.
#[test]
fn after_send_from_any_thread() {
    assert!(!timer::on_loop());
    let (tx, rx) = std::sync::mpsc::channel();
    let t0 = Instant::now();
    let t = timer::after_send(Duration::from_millis(40), move || {
        let _ = tx.send((t0.elapsed(), thread::current().name().map(str::to_owned)));
    })
    .unwrap();
    let (took, name) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(took >= Duration::from_millis(40), "{took:?}");
    assert_eq!(name.as_deref(), Some("akio-timer"));
    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "runs once"
    );
    assert!(!t.cancel(), "it already ran");

    // Cancelled before it is due (from another thread): never runs.
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let t = timer::after_send(Duration::from_millis(50), move || {
        h.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(thread::spawn(move || t.cancel()).join().unwrap());
    thread::sleep(Duration::from_millis(150));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// `timer::after_send` from an I/O thread's callback: the job runs on the timer thread and
/// reaches the connection back with `Conn::run_on_loop`.
#[test]
fn after_send_from_an_io_thread_comes_back_with_run_on_loop() {
    struct Later;
    impl Handler for Later {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let (c, data) = (c.clone(), data.to_vec());
            let _ = timer::after_send(Duration::from_millis(10), move || {
                assert!(!timer::on_loop());
                let _ = c.run_on_loop(move |_h, c| {
                    let _ = c.send(&data);
                });
            })
            .unwrap();
        }
    }
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Later>| Later)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = connect(e.local_addrs()[0]);
    s.write_all(b"back\n").unwrap();
    assert_eq!(read_lines(&mut s, 1), ["back"]);
    stop(&e);
}
