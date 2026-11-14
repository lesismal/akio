//! macOS (aarch64 and x86_64): constants, structures and libSystem functions (the stable ABI;
//! macOS has no stable system call interface).

use super::{
    c_char, c_int, c_void, in_addr, in6_addr, off_t, pid_t, size_t, sockaddr, socklen_t, ssize_t,
    timespec,
};

/// `sa_family_t`.
pub type sa_family_t = u8;

// ---- errno -------------------------------------------------------------------------------
pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const ESRCH: c_int = 3;
pub const EINTR: c_int = 4;
pub const EBADF: c_int = 9;
pub const EINVAL: c_int = 22;
pub const EAGAIN: c_int = 35;
pub const EINPROGRESS: c_int = 36;
pub const ENOSYS: c_int = 78;

// ---- files and fcntl -----------------------------------------------------------------------
pub const O_NONBLOCK: c_int = 0x4;
pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const FD_CLOEXEC: c_int = 1;

// ---- sockets -------------------------------------------------------------------------------
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 30;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOL_SOCKET: c_int = 0xffff;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_REUSEPORT: c_int = 0x0200;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPV6_V6ONLY: c_int = 27;

// ---- kqueue --------------------------------------------------------------------------------
pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;
pub const EV_ADD: u16 = 0x1;
pub const EV_DELETE: u16 = 0x2;
pub const EV_ENABLE: u16 = 0x4;
pub const EV_DISABLE: u16 = 0x8;
pub const EV_ERROR: u16 = 0x4000;
pub const EV_EOF: u16 = 0x8000;

// ---- signals -------------------------------------------------------------------------------
pub const SIGHUP: c_int = 1;
pub const SIGINT: c_int = 2;
pub const SIGQUIT: c_int = 3;
pub const SIGTERM: c_int = 15;
pub const SIGUSR1: c_int = 30;
pub const SIGUSR2: c_int = 31;
pub const SA_RESTART: c_int = 0x0002;

// ---- structures ----------------------------------------------------------------------------

/// `struct sockaddr_in` (BSD: with a length byte).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sockaddr_in {
    pub sin_len: u8,
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [c_char; 8],
}

/// `struct sockaddr_in6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sockaddr_in6 {
    pub sin6_len: u8,
    pub sin6_family: sa_family_t,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

/// `struct sockaddr_storage`: 128 bytes, 8-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sockaddr_storage {
    pub ss_len: u8,
    pub ss_family: sa_family_t,
    _pad1: [u8; 6],
    _align: i64,
    _pad2: [u8; 112],
}

/// `struct kevent` (`#pragma pack(4)` in `<sys/event.h>`).
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug)]
pub struct kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut c_void,
}

/// `sigset_t`.
pub type sigset_t = u32;

/// `sighandler_t`.
pub type sighandler_t = size_t;

/// `struct sigaction` (the user-space one, without `sa_tramp`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sigaction {
    pub sa_sigaction: sighandler_t,
    pub sa_mask: sigset_t,
    pub sa_flags: c_int,
}

const _: () = assert!(size_of::<kevent>() == 32 && align_of::<kevent>() == 4);
const _: () = assert!(size_of::<sigaction>() == 16);

// ---- libSystem functions -------------------------------------------------------------------

// Soundness of the declarations: each matches the prototype in the macOS SDK headers (types as laid out
// above); `fcntl` is variadic in C and declared variadic, which matters on arm64, where variadic
// arguments go on the stack.
unsafe extern "C" {
    pub fn __error() -> *mut c_int;

    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn listen(fd: c_int, backlog: c_int) -> c_int;
    pub fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        len: socklen_t,
    ) -> c_int;
    pub fn sendfile(
        fd: c_int,
        s: c_int,
        offset: off_t,
        len: *mut off_t,
        hdtr: *mut c_void,
        flags: c_int,
    ) -> c_int;

    pub fn kqueue() -> c_int;
    pub fn kevent(
        kq: c_int,
        changelist: *const kevent,
        nchanges: c_int,
        eventlist: *mut kevent,
        nevents: c_int,
        timeout: *const timespec,
    ) -> c_int;
    pub fn pipe(fds: *mut c_int) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;
    pub fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;

    pub fn getentropy(buf: *mut c_void, len: size_t) -> c_int;

    pub fn kill(pid: pid_t, sig: c_int) -> c_int;
    pub fn sigemptyset(set: *mut sigset_t) -> c_int;
    pub fn sigaction(sig: c_int, act: *const sigaction, old: *mut sigaction) -> c_int;
}
