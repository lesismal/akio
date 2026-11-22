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
