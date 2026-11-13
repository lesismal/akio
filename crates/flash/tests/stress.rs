//! Many-connection stability and descriptor-leak tests.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use flash::{Acceptor, Config, Conn, Engine, Handler, Listener};

/// Raises the soft fd limit to what the hard limit allows (capped), returns the new soft limit.
fn raise_nofile() -> u64 {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of both calls.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = lim.rlim_max.min(65_536);
        libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
    }
    lim.rlim_cur
}

/// Connects with `SO_LINGER = 0`, so closing sends RST and leaves no TIME_WAIT behind: thousands
/// of loopback connections would otherwise exhaust the ephemeral port range.
fn connect_rst_on_close(addr: std::net::SocketAddr) -> TcpStream {
    use std::os::fd::AsRawFd;
    let s = TcpStream::connect(addr).unwrap();
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: valid fd, and `l` outlives the call with the size passed.
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
    s
}

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).unwrap().count()
}

#[derive(Default)]
struct Counters {
    opened: AtomicUsize,
    closed: AtomicUsize,
}

struct Echo(Arc<Counters>);

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        self.0.closed.fetch_add(1, Ordering::SeqCst);
    }
}

struct EchoAcceptor(Arc<Counters>);

impl Acceptor for EchoAcceptor {
    type Handler = Echo;
    fn on_open(&self, _c: &Conn<Echo>) -> Echo {
        self.0.opened.fetch_add(1, Ordering::SeqCst);
        Echo(self.0.clone())
    }
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(t.elapsed() < Duration::from_secs(30), "timed out: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Opens `n` simultaneous connections, round-trips a byte on each, closes them all, and checks
/// every `on_close` ran and every descriptor was released.
/// The fd baseline is process-wide, so these tests must not overlap.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn churn(n: usize, rounds: usize) {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let limit = raise_nofile();
    assert!(
        limit as usize > n * 2 + 256,
        "fd limit {limit} too low for {n} connections"
    );
    let counters = Arc::new(Counters::default());
    let engine = Engine::builder()
        .config(Config {
            shutdown_timeout: Duration::from_secs(5),
            ..Config::default()
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(4)
                .serve(EchoAcceptor(counters.clone())),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    // Let the loops settle before taking the baseline.
    thread::sleep(Duration::from_millis(100));
    let baseline = open_fds();

    for round in 0..rounds {
        let mut socks = Vec::with_capacity(n);
        for _ in 0..n {
            socks.push(connect_rst_on_close(addr));
        }
        for (i, s) in socks.iter_mut().enumerate() {
            let b = [(i % 251) as u8];
            s.write_all(&b).unwrap();
        }
        for (i, s) in socks.iter_mut().enumerate() {
            s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).unwrap();
            assert_eq!(b[0], (i % 251) as u8, "echo mismatch on connection {i}");
        }
        assert_eq!(
            counters.opened.load(Ordering::SeqCst),
            (round + 1) * n,
            "every connection opened exactly once"
        );
        drop(socks);
        let want = (round + 1) * n;
        wait_for("all on_close", || {
            counters.closed.load(Ordering::SeqCst) >= want
        });
    }

    // Closed connections must give their descriptors back (the handler Conn handles are gone).
    wait_for("fds released", || open_fds() <= baseline + 2);
    engine.shutdown();
    engine.wait();
    assert_eq!(
        counters.closed.load(Ordering::SeqCst),
        rounds * n,
        "on_close exactly once"
    );
}

#[test]
fn five_thousand_connections_then_no_fd_leak() {
    churn(5_000, 1);
}

#[test]
fn repeated_connect_close_cycles_do_not_leak() {
    churn(500, 20);
}
