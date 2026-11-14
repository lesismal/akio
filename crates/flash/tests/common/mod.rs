//! Shared by the integration tests.
#![allow(dead_code)]

use flash::{Backend, UringConfig};

/// The backend under test: epoll/kqueue by default, io_uring with `FLASH_TEST_BACKEND=uring`
/// (strict: a kernel without io_uring fails the run instead of silently testing epoll).
pub(crate) fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring(UringConfig {
            strict: true,
            ..UringConfig::default()
        }),
        _ => Backend::Epoll,
    }
}
