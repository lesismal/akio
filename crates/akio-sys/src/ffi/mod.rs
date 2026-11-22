//! The workspace's own bindings to the operating system: C types, constants, `#[repr(C)]`
//! structures and function declarations, replacing the `libc` crate.
//!
//! * Linux (x86_64 and aarch64; riscv64 and loongarch64 share the generic layouts): the C
//!   library's functions are declared here (`extern "C"`), linked from the libc that `std`
//!   already links (glibc or musl). Calling the C library rather than issuing raw `syscall`
//!   instructions keeps `errno`, `EINTR` and `std::io::Error::last_os_error` semantics exactly
//!   as they were with the `libc` crate. System calls without a C wrapper (`bpf`,
//!   `io_uring_*`) go through the C library's `syscall(2)`, with per-architecture numbers.
//! * macOS: the stable ABI is libSystem; its functions are declared the same way.
//!
//! Every structure layout and constant is checked against the `libc` crate in the test-only
//! module `layout` (`libc` is a dev-dependency only), and the layouts that matter most also carry
//! compile-time size and alignment assertions here.
//!
//! This is an internal module of an internal crate: it is `#[doc(hidden)]` and outside the
//! semver promise; it exists so that akio-uring, akio-ebpf and akio-dpdk share one set of
//! declarations.
#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    missing_docs,
    clippy::upper_case_acronyms
)]

pub use core::ffi::{c_char, c_int, c_long, c_short, c_uint, c_ulong, c_ushort, c_void};

/// `size_t`.
pub type size_t = usize;
/// `ssize_t`.
pub type ssize_t = isize;
/// `socklen_t`.
pub type socklen_t = u32;
/// `pid_t`.
pub type pid_t = i32;
/// `off_t` (64-bit on every supported target).
pub type off_t = i64;
/// `time_t`.
pub type time_t = i64;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

/// `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

/// `struct in_addr` (network byte order).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct in_addr {
    pub s_addr: u32,
}

/// `struct in6_addr`.
#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy, Debug, Default)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

/// `struct sockaddr` (only ever used behind a pointer).
#[repr(C)]
#[derive(Debug)]
pub struct sockaddr {
    _opaque: [u8; 16],
}

const _: () = assert!(size_of::<iovec>() == 16 && align_of::<iovec>() == 8);
const _: () = assert!(size_of::<in6_addr>() == 16 && align_of::<in6_addr>() == 4);
const _: () = assert!(size_of::<timespec>() == 16);
const _: () = assert!(size_of::<sockaddr_in>() == 16);
const _: () = assert!(size_of::<sockaddr_in6>() == 28 && align_of::<sockaddr_in6>() == 4);
const _: () = assert!(size_of::<sockaddr_storage>() == 128 && align_of::<sockaddr_storage>() == 8);

/// The calling thread's `errno` location.
///
/// # Safety
///
/// The pointer is valid only on the calling thread; it must not be sent to another thread.
pub unsafe fn errno_location() -> *mut c_int {
    #[cfg(target_os = "linux")]
    // SAFETY: always valid for the calling thread.
    unsafe {
        __errno_location()
    }
    #[cfg(target_os = "macos")]
    // SAFETY: always valid for the calling thread.
    unsafe {
        __error()
    }
}

#[cfg(test)]
mod layout;
