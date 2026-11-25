//! Shared by the integration tests.
#![allow(dead_code)]

use akio::{Backend, UringConfig};

/// The backend under test: epoll/kqueue by default, io_uring with `AKIO_TEST_BACKEND=uring`
/// (strict: a kernel without io_uring fails the run instead of silently testing epoll).
pub(crate) fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

/// Listeners default to rounds scheduling (`AKIO_DEFAULT_SCHEDULING=rounds`, ADR-104): tests
/// of what only per-thread loops do (thread resizing, one metrics row per I/O thread) skip.
pub(crate) fn rounds() -> bool {
    std::env::var("AKIO_DEFAULT_SCHEDULING").as_deref() == Ok("rounds")
}

/// `read` that retries `EINTR`: with an io_uring ring in the same process, a blocking std read
/// can be interrupted (`read_exact` already retries; a single `read` does not).
pub(crate) fn read_retry(s: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match s.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

/// An address whose connects hang (their SYNs go unanswered), held open while this lives.
pub(crate) struct BlackHole {
    pub(crate) addr: std::net::SocketAddr,
    _listener: Option<std::net::TcpListener>,
    _held: Vec<std::net::TcpStream>,
}

/// Whether a blocking connect to `at` is still pending after 400 ms.
fn hangs(at: std::net::SocketAddr) -> bool {
    matches!(
        std::net::TcpStream::connect_timeout(&at, std::time::Duration::from_millis(400)),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
    )
}

/// A black hole for connect-timeout tests: a loopback listener whose accept queue is full
/// (Linux drops the SYNs past it), else a documentation address (TEST-NET, RFC 5737) the
/// network drops (macOS answers a full queue with a reset). `None`, with a message, where
/// every candidate answers at once (no route, a refusing gateway): the caller skips.
pub(crate) fn black_hole() -> Option<BlackHole> {
    if let Ok(l) = akio_sys::listen("127.0.0.1:0".parse().unwrap(), false, 1) {
        if let Ok(at) = l.local_addr() {
            let held: Vec<_> = (0..16)
                .filter_map(|_| akio_sys::connect_nonblocking(at).ok())
                .collect();
            std::thread::sleep(std::time::Duration::from_millis(100));
            if hangs(at) {
                return Some(BlackHole {
                    addr: at,
                    _listener: Some(l),
                    _held: held,
                });
            }
        }
    }
    for at in ["192.0.2.1:81", "198.51.100.1:81", "203.0.113.1:81"] {
        let at: std::net::SocketAddr = at.parse().unwrap();
        if hangs(at) {
            return Some(BlackHole {
                addr: at,
                _listener: None,
                _held: Vec::new(),
            });
        }
    }
    eprintln!("skipped: no black hole here (every candidate answers a connect at once)");
    None
}
