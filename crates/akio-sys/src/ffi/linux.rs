//! Linux (glibc / musl, 64-bit little-endian): constants, structures and C library functions.
//!
//! Values are those of the kernel UAPI headers (`asm-generic` unless noted); x86_64 differs from
//! the generic table only in `struct epoll_event` (packed) and in system call numbers.

use super::{
    c_char, c_int, c_long, c_short, c_uint, c_ulong, c_ushort, c_void, ifaddrs, in_addr, in6_addr,
    iovec, off_t, pid_t, size_t, sockaddr, socklen_t, ssize_t, timespec, uid_t,
};

#[cfg(not(all(
    target_pointer_width = "64",
    target_endian = "little",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )
)))]
compile_error!(
    "akio-sys supports Linux on x86_64 and aarch64 (and riscv64 / loongarch64, which share the \
     generic layouts); other architectures need their constants and layouts in src/ffi/linux.rs"
);

/// `sa_family_t`.
pub type sa_family_t = u16;

// ---- errno -------------------------------------------------------------------------------
pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const EINTR: c_int = 4;
pub const EIO: c_int = 5;
pub const EBADF: c_int = 9;
pub const EAGAIN: c_int = 11;
pub const EBUSY: c_int = 16;
pub const EINVAL: c_int = 22;
pub const ENOSYS: c_int = 38;
pub const ENOPROTOOPT: c_int = 92;
pub const EOPNOTSUPP: c_int = 95;
pub const ETIME: c_int = 62;
pub const ENOBUFS: c_int = 105;
pub const EPROTO: c_int = 71;
pub const EMSGSIZE: c_int = 90;
pub const ENETDOWN: c_int = 100;
pub const ENETUNREACH: c_int = 101;
pub const ECONNREFUSED: c_int = 111;
pub const EHOSTDOWN: c_int = 112;
pub const EHOSTUNREACH: c_int = 113;
pub const EINPROGRESS: c_int = 115;
pub const ECANCELED: c_int = 125;

// ---- files and fcntl -----------------------------------------------------------------------
pub const O_RDWR: c_int = 2;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_CLOEXEC: c_int = 0o2_000_000;
pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const FD_CLOEXEC: c_int = 1;

// ---- sockets -------------------------------------------------------------------------------
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;
pub const AF_UNIX: c_int = 1;
pub const AF_PACKET: c_int = 17;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_NONBLOCK: c_int = O_NONBLOCK;
pub const SOCK_CLOEXEC: c_int = O_CLOEXEC;
pub const SOL_SOCKET: c_int = 1;
pub const SO_REUSEADDR: c_int = 2;
pub const SO_LINGER: c_int = 13;
pub const SO_RCVBUF: c_int = 8;
pub const SO_REUSEPORT: c_int = 15;
pub const SHUT_RD: c_int = 0;
pub const SO_RCVBUFFORCE: c_int = 33;
pub const SO_INCOMING_CPU: c_int = 49;
pub const SO_ATTACH_REUSEPORT_CBPF: c_int = 51;
pub const SO_ATTACH_REUSEPORT_EBPF: c_int = 52;
pub const SO_COOKIE: c_int = 57;
pub const IPPROTO_IP: c_int = 0;
pub const IP_TOS: c_int = 1;
pub const IP_RECVTOS: c_int = 13;
pub const IP_RECVERR: c_int = 11;
pub const IP_TTL: c_int = 2;
pub const IP_RECVTTL: c_int = 12;
pub const IP_MTU_DISCOVER: c_int = 10;
pub const IP_MTU: c_int = 14;
pub const IPV6_MTU: c_int = 24;
pub const IP_PMTUDISC_DONT: c_int = 0;
pub const IP_PMTUDISC_DO: c_int = 2;
pub const IPV6_HOPLIMIT: c_int = 52;
pub const IPV6_RECVHOPLIMIT: c_int = 51;
pub const IPV6_DONTFRAG: c_int = 62;
pub const IPV6_RECVERR: c_int = 25;
pub const MSG_ERRQUEUE: c_int = 0x2000;
pub const SO_EE_ORIGIN_ICMP: u8 = 2;
pub const SO_EE_ORIGIN_ICMP6: u8 = 3;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPV6_RECVTCLASS: c_int = 66;
pub const IPV6_TCLASS: c_int = 67;
pub const IPV6_V6ONLY: c_int = 26;
pub const IPV6_MULTICAST_HOPS: c_int = 18;
pub const IPV6_UNICAST_HOPS: c_int = 16;
pub const IP_PKTINFO: c_int = 8;
pub const IPV6_PKTINFO: c_int = 50;
pub const IPV6_RECVPKTINFO: c_int = 49;
pub const IFF_UP: c_int = 0x1;
pub const IFF_LOOPBACK: c_int = 0x8;
pub const IFF_POINTOPOINT: c_int = 0x10;
pub const IFF_RUNNING: c_int = 0x40;
pub const IFF_MULTICAST: c_int = 0x1000;
pub const SOL_UDP: c_int = 17;
pub const UDP_SEGMENT: c_int = 103;
pub const UDP_GRO: c_int = 104;
pub const MSG_TRUNC: c_int = 0x20;
pub const MSG_DONTWAIT: c_int = 0x40;
pub const IFNAMSIZ: usize = 16;
pub const IPPROTO_TCP: c_int = 6;
pub const TCP_INFO: c_int = 11;
pub const TCP_ULP: c_int = 31;

// ---- kernel TLS (linux/tls.h) --------------------------------------------------------------
pub const SOL_TLS: c_int = 282;
pub const TLS_TX: c_int = 1;
pub const TLS_RX: c_int = 2;
pub const TLS_SET_RECORD_TYPE: c_int = 1;
pub const TLS_GET_RECORD_TYPE: c_int = 2;
pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;
pub const TLS_TX_ZEROCOPY_RO: c_int = 3;
pub const TLS_RX_EXPECT_NO_PAD: c_int = 4;

// ---- ethtool (linux/ethtool.h, linux/sockios.h) ---------------------------------------------
pub const SIOCETHTOOL: c_ulong = 0x8946;
pub const ETHTOOL_GSTRINGS: u32 = 0x1b;
pub const ETHTOOL_GSSET_INFO: u32 = 0x37;
pub const ETHTOOL_GFEATURES: u32 = 0x3a;
pub const ETH_SS_FEATURES: u32 = 4;
pub const ETH_GSTRING_LEN: usize = 32;

// ---- epoll, eventfd, poll ------------------------------------------------------------------
pub const EPOLLIN: c_int = 0x1;
pub const EPOLLOUT: c_int = 0x4;
pub const EPOLLERR: c_int = 0x8;
pub const EPOLLHUP: c_int = 0x10;
pub const EPOLLRDHUP: c_int = 0x2000;
pub const EPOLLET: c_int = 0x8000_0000_u32 as c_int;
pub const EPOLL_CTL_ADD: c_int = 1;
pub const EPOLL_CTL_DEL: c_int = 2;
pub const EPOLL_CTL_MOD: c_int = 3;
pub const EPOLL_CLOEXEC: c_int = O_CLOEXEC;
pub const EFD_NONBLOCK: c_int = O_NONBLOCK;
pub const EFD_CLOEXEC: c_int = O_CLOEXEC;
pub const POLLIN: c_short = 0x1;

// ---- inotify -------------------------------------------------------------------------------
pub const IN_NONBLOCK: c_int = O_NONBLOCK;
pub const IN_CLOEXEC: c_int = O_CLOEXEC;
pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_MOVE_SELF: u32 = 0x800;
pub const IN_UNMOUNT: u32 = 0x2000;
pub const IN_Q_OVERFLOW: u32 = 0x4000;
pub const IN_IGNORED: u32 = 0x8000;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;
pub const POLLOUT: c_short = 0x4;
pub const POLLERR: c_short = 0x8;
pub const POLLRDHUP: c_short = 0x2000;

// ---- signals and processes -----------------------------------------------------------------
pub const SIGHUP: c_int = 1;
pub const SIGINT: c_int = 2;
pub const SIGKILL: c_int = 9;
pub const SIGUSR2: c_int = 12;
pub const SIGTERM: c_int = 15;
pub const SA_RESTART: c_int = 0x1000_0000;

// ---- memory mapping (io_uring rings) -------------------------------------------------------
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const MAP_SHARED: c_int = 0x01;
pub const MAP_POPULATE: c_int = 0x8000;
pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

// ---- system call numbers (for `syscall`) ---------------------------------------------------
#[cfg(target_arch = "x86_64")]
pub const SYS_bpf: c_long = 321;
#[cfg(not(target_arch = "x86_64"))]
pub const SYS_bpf: c_long = 280;
// The io_uring calls were added after the tables were unified: the same on every architecture.
pub const SYS_io_uring_setup: c_long = 425;
pub const SYS_io_uring_enter: c_long = 426;
pub const SYS_io_uring_register: c_long = 427;

// ---- structures ----------------------------------------------------------------------------

/// `struct sockaddr_in`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

/// `struct sockaddr_in6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

/// `struct sockaddr_un`: a Unix-domain socket's path, at most 107 bytes and a NUL.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [c_char; 108],
}

/// `struct sockaddr_storage`: 128 bytes, 8-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    _pad: [u8; 6],
    _align: [u64; 15],
}

/// `struct sockaddr_ll` (AF_PACKET).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sockaddr_ll {
    pub sll_family: c_ushort,
    pub sll_protocol: c_ushort,
    pub sll_ifindex: c_int,
    pub sll_hatype: c_ushort,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

/// `struct msghdr` (glibc spelling; musl's padded `int` fields are layout-identical on 64-bit
/// little-endian targets when the padding is zero, which the kernel's own `size_t` view needs).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: size_t,
    pub msg_control: *mut c_void,
    pub msg_controllen: size_t,
    pub msg_flags: c_int,
}

/// `struct mmsghdr`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct mmsghdr {
    pub msg_hdr: msghdr,
    pub msg_len: c_uint,
}

/// `struct cmsghdr`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

/// `struct tls_crypto_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tls_crypto_info {
    pub version: u16,
    pub cipher_type: u16,
}

/// `struct tls12_crypto_info_aes_gcm_128`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tls12_crypto_info_aes_gcm_128 {
    pub info: tls_crypto_info,
    pub iv: [u8; 8],
    pub key: [u8; 16],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

/// `struct tls12_crypto_info_aes_gcm_256`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tls12_crypto_info_aes_gcm_256 {
    pub info: tls_crypto_info,
    pub iv: [u8; 8],
    pub key: [u8; 32],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

/// `struct tls12_crypto_info_chacha20_poly1305` (its `salt` is zero-length).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tls12_crypto_info_chacha20_poly1305 {
    pub info: tls_crypto_info,
    pub iv: [u8; 12],
    pub key: [u8; 32],
    pub rec_seq: [u8; 8],
}

const _: () = assert!(size_of::<tls12_crypto_info_aes_gcm_128>() == 40);
const _: () = assert!(size_of::<tls12_crypto_info_aes_gcm_256>() == 56);
const _: () = assert!(size_of::<tls12_crypto_info_chacha20_poly1305>() == 56);
const _: () = assert!(align_of::<tls12_crypto_info_aes_gcm_128>() == 2);

/// `struct epoll_event`: packed on x86_64 (12 bytes), naturally aligned elsewhere (16 bytes).
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy, Debug)]
pub struct epoll_event {
    pub events: u32,
    pub u64: u64,
}

/// `struct pollfd`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct pollfd {
    pub fd: c_int,
    pub events: c_short,
    pub revents: c_short,
}

/// `cpu_set_t`: 1024 CPUs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cpu_set_t {
    bits: [u64; 16],
}

impl cpu_set_t {
    /// The empty set.
    pub const fn new() -> cpu_set_t {
        cpu_set_t { bits: [0; 16] }
    }

    /// How many CPUs the set can name.
    pub const CAPACITY: usize = 1024;

    /// `CPU_SET(cpu, self)`; CPUs at or beyond [`CAPACITY`](Self::CAPACITY) are ignored.
    pub fn set(&mut self, cpu: usize) {
        if let Some(w) = self.bits.get_mut(cpu / 64) {
            *w |= 1 << (cpu % 64);
        }
    }

    /// `CPU_ISSET(cpu, self)`.
    pub fn is_set(&self, cpu: usize) -> bool {
        self.bits
            .get(cpu / 64)
            .is_some_and(|w| w & (1 << (cpu % 64)) != 0)
    }
}

impl Default for cpu_set_t {
    fn default() -> Self {
        Self::new()
    }
}

/// `sigset_t` of the C library (1024 bits; the kernel's own is 64).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sigset_t {
    _bits: [u64; 16],
}

/// `sighandler_t`.
pub type sighandler_t = size_t;

/// `struct sigaction` of the C library (not the kernel's `struct k_sigaction`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sigaction {
    pub sa_sigaction: sighandler_t,
    pub sa_mask: sigset_t,
    pub sa_flags: c_int,
    pub sa_restorer: Option<extern "C" fn()>,
}

/// `struct utsname`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct utsname {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

/// `struct ifreq` with the `ifr_data` member of its union (`SIOCETHTOOL`), padded to the
/// union's 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ifreq_data {
    pub ifr_name: [c_char; IFNAMSIZ],
    pub ifr_data: *mut c_void,
    pub _pad: [u8; 16],
}

/// `struct ethtool_get_features_block`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ethtool_get_features_block {
    pub available: u32,
    pub requested: u32,
    pub active: u32,
    pub never_changed: u32,
}

const _: () = assert!(size_of::<ifreq_data>() == 40);
const _: () = assert!(size_of::<sockaddr_ll>() == 20);
const _: () = assert!(size_of::<msghdr>() == 56 && align_of::<msghdr>() == 8);
const _: () = assert!(size_of::<mmsghdr>() == 64);
const _: () = assert!(size_of::<cmsghdr>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<epoll_event>() == 12 && align_of::<epoll_event>() == 1);
#[cfg(not(target_arch = "x86_64"))]
const _: () = assert!(size_of::<epoll_event>() == 16 && align_of::<epoll_event>() == 8);
const _: () = assert!(size_of::<pollfd>() == 8);
const _: () = assert!(size_of::<cpu_set_t>() == 128);
const _: () = assert!(size_of::<sigaction>() == 152);
const _: () = assert!(size_of::<utsname>() == 390);

// ---- terminals (termios) --------------------------------------------------------------------

/// `tcflag_t`.
pub type tcflag_t = c_uint;
/// `cc_t`.
pub type cc_t = u8;
/// `speed_t`.
pub type speed_t = c_uint;
/// Control characters in `termios::c_cc`.
pub const NCCS: usize = 32;

/// `struct termios` of the C library (glibc and musl share it; not the kernel's `termios2`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; NCCS],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}

const _: () = assert!(size_of::<termios>() == 60);

pub const IGNBRK: tcflag_t = 0o1;
pub const BRKINT: tcflag_t = 0o2;
pub const PARMRK: tcflag_t = 0o10;
pub const ISTRIP: tcflag_t = 0o40;
pub const INLCR: tcflag_t = 0o100;
pub const IGNCR: tcflag_t = 0o200;
pub const ICRNL: tcflag_t = 0o400;
pub const IXON: tcflag_t = 0o2000;
pub const OPOST: tcflag_t = 0o1;
pub const CSIZE: tcflag_t = 0o60;
pub const CS8: tcflag_t = 0o60;
pub const PARENB: tcflag_t = 0o400;
pub const ISIG: tcflag_t = 0o1;
pub const ICANON: tcflag_t = 0o2;
pub const ECHO: tcflag_t = 0o10;
pub const ECHONL: tcflag_t = 0o100;
pub const IEXTEN: tcflag_t = 0o100000;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const TCSANOW: c_int = 0;

// ---- file systems (statvfs) -----------------------------------------------------------------

/// `struct statvfs` of the C library (glibc and musl, 64-bit: `fsblkcnt_t` and `fsfilcnt_t` are
/// 64-bit; glibc's `f_type` and the spare words of both are `__f_spare` here).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct statvfs {
    pub f_bsize: c_ulong,
    pub f_frsize: c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: c_ulong,
    pub f_flag: c_ulong,
    pub f_namemax: c_ulong,
    pub __f_spare: [c_int; 6],
}

const _: () = assert!(size_of::<statvfs>() == 112 && align_of::<statvfs>() == 8);

// ---- ancillary data (the CMSG_* macros) -----------------------------------------------------

const fn cmsg_align(len: usize) -> usize {
    (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// `CMSG_SPACE(len)`.
pub const fn cmsg_space(len: usize) -> usize {
    cmsg_align(len) + cmsg_align(size_of::<cmsghdr>())
}

/// `CMSG_LEN(len)`.
pub const fn cmsg_len(len: usize) -> usize {
    cmsg_align(size_of::<cmsghdr>()) + len
}

/// `CMSG_FIRSTHDR(mhdr)`.
///
/// # Safety
///
/// `mhdr` must point to a valid `msghdr`.
pub unsafe fn cmsg_firsthdr(mhdr: *const msghdr) -> *mut cmsghdr {
    // SAFETY: `mhdr` is valid for reads (caller).
    let h = unsafe { &*mhdr };
    if h.msg_controllen >= size_of::<cmsghdr>() {
        h.msg_control.cast()
    } else {
        std::ptr::null_mut()
    }
}

/// `CMSG_DATA(cmsg)`.
///
/// Pure address arithmetic: the result is only meaningful for a header inside a control buffer.
pub fn cmsg_data(cmsg: *const cmsghdr) -> *mut u8 {
    cmsg.cast::<u8>()
        .wrapping_add(cmsg_align(size_of::<cmsghdr>()))
        .cast_mut()
}

/// `CMSG_NXTHDR(mhdr, cmsg)`, with glibc's bounds: the next header *and* the payload its
/// `cmsg_len` claims must end inside `msg_control[..msg_controllen]`, else null.
///
/// # Safety
///
/// `mhdr` must point to a valid `msghdr` whose control buffer is readable for `msg_controllen`
/// bytes, and `cmsg` to a header inside that buffer (one returned by [`cmsg_firsthdr`] or by
/// this function).
pub unsafe fn cmsg_nxthdr(mhdr: *const msghdr, cmsg: *const cmsghdr) -> *mut cmsghdr {
    // SAFETY: both pointers are valid for reads (caller).
    let (h, len) = unsafe { (&*mhdr, (*cmsg).cmsg_len) };
    if len < size_of::<cmsghdr>() {
        return std::ptr::null_mut();
    }
    let next = (cmsg as usize).wrapping_add(cmsg_align(len));
    let max = (h.msg_control as usize).wrapping_add(h.msg_controllen);
    if next < cmsg as usize || next.wrapping_add(size_of::<cmsghdr>()) > max {
        return std::ptr::null_mut();
    }
    let next = cmsg
        .cast::<u8>()
        .wrapping_add(next - cmsg as usize)
        .cast::<cmsghdr>();
    // SAFETY: the next header lies inside the control buffer (checked above), which is
    // readable (caller).
    let next_len = unsafe { (*next).cmsg_len };
    if (next as usize).wrapping_add(cmsg_align(next_len)) > max {
        return std::ptr::null_mut();
    }
    next.cast_mut()
}

// ---- C library functions ---------------------------------------------------------------------

// Soundness of the declarations: each matches the C prototype in the glibc / musl headers for 64-bit
// Linux (argument and return types as laid out above); the variadic ones (`fcntl`, `ioctl`,
// `open`, `syscall`) are declared variadic, as C callers see them.
unsafe extern "C" {
    pub fn __errno_location() -> *mut c_int;

    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn listen(fd: c_int, backlog: c_int) -> c_int;
    pub fn accept4(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t, flags: c_int) -> c_int;
    pub fn shutdown(fd: c_int, how: c_int) -> c_int;
    pub fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        len: socklen_t,
    ) -> c_int;
    pub fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        len: *mut socklen_t,
    ) -> c_int;
    pub fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
    ) -> ssize_t;
    pub fn recvmmsg(
        fd: c_int,
        msgs: *mut mmsghdr,
        vlen: c_uint,
        flags: c_int,
        timeout: *mut timespec,
    ) -> c_int;
    pub fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t;
    pub fn sendmmsg(fd: c_int, msgs: *mut mmsghdr, vlen: c_uint, flags: c_int) -> c_int;
    pub fn sendfile(out: c_int, file: c_int, offset: *mut off_t, count: size_t) -> ssize_t;
    pub fn if_nametoindex(name: *const c_char) -> c_uint;
    pub fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int;
    pub fn freeifaddrs(ifa: *mut ifaddrs);

    pub fn epoll_create1(flags: c_int) -> c_int;
    pub fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut epoll_event) -> c_int;
    pub fn epoll_wait(epfd: c_int, events: *mut epoll_event, max: c_int, timeout: c_int) -> c_int;
    pub fn eventfd(initval: c_uint, flags: c_int) -> c_int;
    pub fn inotify_init1(flags: c_int) -> c_int;
    pub fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int;
    pub fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int;
    pub fn ppoll(
        fds: *mut pollfd,
        nfds: c_ulong,
        timeout: *const timespec,
        sigmask: *const sigset_t,
    ) -> c_int;

    pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;
    pub fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub fn close(fd: c_int) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    pub fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, len: size_t) -> c_int;

    pub fn getrandom(buf: *mut c_void, len: size_t, flags: c_uint) -> ssize_t;
    pub fn uname(buf: *mut utsname) -> c_int;
    pub fn syscall(num: c_long, ...) -> c_long;

    pub fn kill(pid: pid_t, sig: c_int) -> c_int;
    pub fn killpg(pgrp: pid_t, sig: c_int) -> c_int;
    pub fn geteuid() -> uid_t;
    pub fn sched_setaffinity(pid: pid_t, size: size_t, set: *const cpu_set_t) -> c_int;
    pub fn sched_getaffinity(pid: pid_t, size: size_t, set: *mut cpu_set_t) -> c_int;
    pub fn sigemptyset(set: *mut sigset_t) -> c_int;
    pub fn sigaction(sig: c_int, act: *const sigaction, old: *mut sigaction) -> c_int;

    pub fn tcgetattr(fd: c_int, t: *mut termios) -> c_int;
    pub fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int;

    pub fn statvfs(path: *const c_char, buf: *mut statvfs) -> c_int;
}
