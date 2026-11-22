//! Chaos: descriptor exhaustion. The process's fd limit is lowered so `accept` fails with EMFILE
//! while clients keep connecting; the engine must neither crash nor spin, and must resume
//! accepting (and serve every waiting client) once descriptors are freed.
//!
//! Its own test binary because `setrlimit` is process-wide. Run alone with
//! `cargo test -p akio --test chaos_fd` (and `AKIO_TEST_BACKEND=uring`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    os::fd::FromRawFd,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Acceptor, Config, Conn, Engine, Handler, Listener};

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
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
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

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    // The directory handle itself is one of the entries.
    std::fs::read_dir(dir).unwrap().count() - 1
}

fn nofile() -> libc::rlimit {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is valid and writable.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) };
    lim
}

fn set_nofile(lim: libc::rlimit) {
    // SAFETY: `lim` is a valid rlimit.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) };
    assert_eq!(rc, 0, "setrlimit: {}", io::Error::last_os_error());
}

/// User + system CPU time of the whole process.
fn cpu_time() -> Duration {
    // SAFETY: `ru` is plain old data, fully written by getrusage.
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &raw mut ru);
        ru
    };
    let tv = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
    };
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

/// A TCP socket created now (while descriptors are plentiful), connected later.
struct Pending(libc::c_int);

impl Pending {
    fn new() -> Pending {
        // SAFETY: plain socket(2) call.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        Pending(fd)
    }

    fn connect(self, addr: std::net::SocketAddrV4) -> TcpStream {
        let sa = libc::sockaddr_in {
            #[cfg(target_os = "macos")]
            sin_len: size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*addr.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sa` is a valid sockaddr_in of the size passed; the fd is ours.
        let rc = unsafe {
            libc::connect(
                self.0,
                (&raw const sa).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "connect: {}", io::Error::last_os_error());
        // SAFETY: we own the connected descriptor and hand it to the TcpStream.
        unsafe { TcpStream::from_raw_fd(self.0) }
    }
}

#[test]
fn accept_survives_fd_exhaustion_and_resumes() {
    const CLIENTS: usize = 96;
    const HEADROOM: usize = 12;
    let counters = Arc::new(Counters::default());
    let engine = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_secs(2);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(2)
                .serve(EchoAcceptor(counters.clone())),
        )
        .build()
        .unwrap();
    let std::net::SocketAddr::V4(addr) = engine.local_addrs()[0] else {
        unreachable!()
    };

    // Client sockets are made up front: they live in this same process.
    let pending: Vec<Pending> = (0..CLIENTS).map(|_| Pending::new()).collect();
    let saved = nofile();
    let used = open_fds();
    set_nofile(libc::rlimit {
        rlim_cur: (used + HEADROOM) as libc::rlim_t,
        rlim_max: saved.rlim_max,
    });
    // Started only now: io_uring applies the limit in force when its accept was armed.
    engine.start().unwrap();

    // Every client connects (the kernel completes the handshake into the backlog) and sends a
    // byte; the server can only accept about HEADROOM of them.
    let mut clients: Vec<Option<TcpStream>> = pending
        .into_iter()
        .map(|p| {
            let mut s = p.connect(addr);
            s.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
            s.write_all(b"x").unwrap();
            Some(s)
        })
        .collect();
    let t = Instant::now();
    let mut last = usize::MAX;
    // Wait for accepting to stall at the limit.
    loop {
        let n = counters.opened.load(Ordering::SeqCst);
        if n == last && t.elapsed() > Duration::from_millis(300) {
            break;
        }
        last = n;
        thread::sleep(Duration::from_millis(100));
    }
    let stalled_at = counters.opened.load(Ordering::SeqCst);
    assert!(
        stalled_at < CLIENTS,
        "the fd limit was not hit ({stalled_at} accepted)"
    );

    // While stuck at EMFILE the engine must not spin on the listener.
    let (c0, w0) = (cpu_time(), Instant::now());
    thread::sleep(Duration::from_secs(1));
    let (cpu, wall) = (cpu_time().checked_sub(c0).unwrap(), w0.elapsed());
    eprintln!("fd exhaustion: {stalled_at} accepted at the limit, cpu {cpu:?} over {wall:?}");

    // Free descriptors by finishing served clients: the engine must resume accepting.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut done = 0;
    // macOS (XNU) dequeues the connection before failing `accept` with EMFILE and resets it;
    // Linux leaves it queued, so there every client must eventually be served.
    let mut resets = 0;
    let mut b = [0u8; 1];
    while done < CLIENTS {
        assert!(
            Instant::now() < deadline,
            "only {done} of {CLIENTS} clients served (accepted {})",
            counters.opened.load(Ordering::SeqCst)
        );
        for slot in &mut clients {
            let Some(s) = slot else { continue };
            match s.read(&mut b) {
                Ok(1) => {
                    assert_eq!(b[0], b'x');
                    *slot = None; // closes it
                    done += 1;
                }
                Ok(_) => panic!("server closed a client without answering"),
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionReset && cfg!(target_os = "macos") =>
                {
                    *slot = None;
                    done += 1;
                    resets += 1;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => panic!("client read: {e}"),
            }
        }
    }
    set_nofile(saved);
    let t = Instant::now();
    let served = CLIENTS - resets;
    eprintln!("fd exhaustion: {served} served, {resets} reset by the kernel");
    while counters.closed.load(Ordering::SeqCst) < served {
        assert!(t.elapsed() < Duration::from_secs(20), "on_close missing");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(counters.opened.load(Ordering::SeqCst), served);

    // Still serving normally.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"ok").unwrap();
    let mut got = [0u8; 2];
    s.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ok");
    drop(s);
    engine.shutdown();
    engine.wait();

    // A loop spinning on the still-readable listener burns a whole core per I/O thread.
    assert!(
        cpu < wall / 2,
        "engine spun while accept failed with EMFILE: {cpu:?} CPU in {wall:?}"
    );
}
