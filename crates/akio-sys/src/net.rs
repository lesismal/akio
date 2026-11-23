use crate::ffi;
use std::io;
use std::mem;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

fn cvt(r: ffi::c_int) -> io::Result<ffi::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub(crate) fn sockaddr(addr: &SocketAddr) -> (ffi::sockaddr_storage, ffi::socklen_t) {
    // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
    let mut ss: ffi::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_in fits in sockaddr_storage and shares its alignment.
            let sin = unsafe { &mut *(&raw mut ss).cast::<ffi::sockaddr_in>() };
            sin.sin_family = ffi::AF_INET as ffi::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = ffi::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()),
            };
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = size_of::<ffi::sockaddr_in>() as u8;
            }
            size_of::<ffi::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: as above for sockaddr_in6.
            let sin6 = unsafe { &mut *(&raw mut ss).cast::<ffi::sockaddr_in6>() };
            sin6.sin6_family = ffi::AF_INET6 as ffi::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_addr = ffi::in6_addr {
                s6_addr: a.ip().octets(),
            };
            sin6.sin6_scope_id = a.scope_id();
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = size_of::<ffi::sockaddr_in6>() as u8;
            }
            size_of::<ffi::sockaddr_in6>()
        }
    };
    (ss, len as ffi::socklen_t)
}

/// The address the kernel stored in `ss`, IPv4-mapped IPv6 reported as IPv4.
pub(crate) fn parse_addr(ss: &ffi::sockaddr_storage) -> Option<SocketAddr> {
    match ffi::c_int::from(ss.ss_family) {
        ffi::AF_INET => {
            // SAFETY: the family says the kernel stored a sockaddr_in here.
            let a = unsafe { &*std::ptr::from_ref(ss).cast::<ffi::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(a.sin_port),
            )))
        }
        ffi::AF_INET6 => {
            // SAFETY: the family says the kernel stored a sockaddr_in6 here.
            let a = unsafe { &*std::ptr::from_ref(ss).cast::<ffi::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
    .map(|a| match a.ip() {
        // Report IPv4-mapped IPv6 peers as plain IPv4 so they match `SocketAddr`s users compare.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        _ => a,
    })
}

/// Creates a non-blocking, close-on-exec TCP socket of the family of `addr`.
fn socket(addr: &SocketAddr) -> io::Result<OwnedFd> {
    socket_of(addr, ffi::SOCK_STREAM)
}

/// As [`socket`], with an explicit socket type (`SOCK_STREAM` / `SOCK_DGRAM`).
fn socket_of(addr: &SocketAddr, ty: ffi::c_int) -> io::Result<OwnedFd> {
    let domain = if addr.is_ipv4() {
        ffi::AF_INET
    } else {
        ffi::AF_INET6
    };
    #[cfg(target_os = "linux")]
    let fd = {
        // SAFETY: plain syscall with valid constant arguments.
        let fd =
            cvt(unsafe { ffi::socket(domain, ty | ffi::SOCK_NONBLOCK | ffi::SOCK_CLOEXEC, 0) })?;
        // SAFETY: `fd` was just created by socket(2) and is owned by no one else.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    #[cfg(not(target_os = "linux"))]
    let fd = {
        // SAFETY: plain syscall with valid constant arguments.
        let fd = cvt(unsafe { ffi::socket(domain, ty, 0) })?;
        // SAFETY: `fd` was just created by socket(2) and is owned by no one else. Owning it
        // before the fcntl calls closes it if they fail.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        crate::poller::set_nonblock_cloexec(std::os::fd::AsRawFd::as_raw_fd(&fd))?;
        fd
    };
    Ok(fd)
}

pub(crate) fn setsockopt_int(
    fd: RawFd,
    level: ffi::c_int,
    name: ffi::c_int,
    v: ffi::c_int,
) -> io::Result<()> {
    // SAFETY: `v` outlives the call and the length matches its type.
    cvt(unsafe {
        ffi::setsockopt(
            fd,
            level,
            name,
            (&raw const v).cast::<ffi::c_void>(),
            size_of::<ffi::c_int>() as ffi::socklen_t,
        )
    })
    .map(drop)
}

/// Binds and listens on `addr` with `SO_REUSEADDR`, and `SO_REUSEPORT` when `reuseport` is set.
/// The returned listener is non-blocking.
pub fn listen(addr: SocketAddr, reuseport: bool, backlog: i32) -> io::Result<TcpListener> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEADDR, 1)?;
    if reuseport {
        setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEPORT, 1)?;
    }
    if let SocketAddr::V6(_) = addr {
        setsockopt_int(raw, ffi::IPPROTO_IPV6, ffi::IPV6_V6ONLY, 0).ok();
    }
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    cvt(unsafe { ffi::bind(raw, (&raw const ss).cast::<ffi::sockaddr>(), len) })?;
    // SAFETY: plain syscall on an owned fd.
    cvt(unsafe { ffi::listen(raw, backlog) })?;
    Ok(TcpListener::from(fd))
}

/// Calls `listen(2)` again on a listening socket with a new `backlog`: Linux and macOS update
/// the queue limit of the live socket in place (connections already queued stay queued). The
/// kernel caps the value (`net.core.somaxconn`, `kern.ipc.somaxconn`).
pub fn set_backlog(listener: &TcpListener, backlog: i32) -> io::Result<()> {
    let raw = std::os::fd::AsRawFd::as_raw_fd(listener);
    // SAFETY: plain syscall on a descriptor `listener` keeps open.
    cvt(unsafe { ffi::listen(raw, backlog) }).map(drop)
}

/// The accept-queue limit the kernel applies to a listening socket (Linux: `tcpi_sacked` of
/// `TCP_INFO`, which holds `sk_max_ack_backlog` for listeners). For tests.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn listen_backlog(listener: &TcpListener) -> io::Result<u32> {
    let raw = std::os::fd::AsRawFd::as_raw_fd(listener);
    // `struct tcp_info`: 8 bytes of u8 fields, then u32s: rto, ato, snd_mss, rcv_mss, unacked,
    // sacked, ...; 104 bytes cover every kernel since 2.6.
    let mut buf = [0u8; 104];
    let mut len = buf.len() as ffi::socklen_t;
    // SAFETY: `buf` is valid for `len` bytes of writes; the kernel writes at most `len`.
    cvt(unsafe {
        ffi::getsockopt(
            raw,
            ffi::IPPROTO_TCP,
            ffi::TCP_INFO,
            buf.as_mut_ptr().cast(),
            &raw mut len,
        )
    })?;
    if (len as usize) < 32 {
        return Err(io::Error::other("short tcp_info"));
    }
    Ok(u32::from_ne_bytes([buf[28], buf[29], buf[30], buf[31]]))
}

/// Binds a TCP socket on `addr` with `SO_REUSEADDR` and `SO_REUSEPORT`, without listening.
pub(crate) fn bind_reuseport(addr: SocketAddr) -> io::Result<TcpListener> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEADDR, 1)?;
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEPORT, 1)?;
    if let SocketAddr::V6(_) = addr {
        setsockopt_int(raw, ffi::IPPROTO_IPV6, ffi::IPV6_V6ONLY, 0).ok();
    }
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    cvt(unsafe { ffi::bind(raw, (&raw const ss).cast::<ffi::sockaddr>(), len) })?;
    Ok(TcpListener::from(fd))
}

/// Binds a non-blocking UDP socket on `addr` with `SO_REUSEADDR`, and `SO_REUSEPORT` when
/// `reuseport` is set (on Linux the kernel then spreads peers over the sockets by 4-tuple hash).
pub fn listen_udp(addr: SocketAddr, reuseport: bool) -> io::Result<std::net::UdpSocket> {
    let fd = socket_of(&addr, ffi::SOCK_DGRAM)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEADDR, 1)?;
    if reuseport {
        setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEPORT, 1)?;
    }
    if let SocketAddr::V6(_) = addr {
        setsockopt_int(raw, ffi::IPPROTO_IPV6, ffi::IPV6_V6ONLY, 0).ok();
    }
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    cvt(unsafe { ffi::bind(raw, (&raw const ss).cast::<ffi::sockaddr>(), len) })?;
    Ok(std::net::UdpSocket::from(fd))
}

/// Sets the hop limit of the IPv6 multicast datagrams `socket` sends (`IPV6_MULTICAST_HOPS`):
/// the IPv6 counterpart of `UdpSocket::set_multicast_ttl_v4`, which std lacks. 0 to 255; the
/// kernel's default is 1 (the link). mDNS sends with 255 (RFC 6762 §11), as some responders
/// check it on reception.
pub fn set_multicast_hops_v6(socket: &std::net::UdpSocket, hops: u32) -> io::Result<()> {
    set_hops_v6(socket, ffi::IPV6_MULTICAST_HOPS, hops)
}

/// The hop limit of the IPv6 multicast datagrams `socket` sends (see
/// [`set_multicast_hops_v6`]).
pub fn multicast_hops_v6(socket: &std::net::UdpSocket) -> io::Result<u32> {
    hops_v6(socket, ffi::IPV6_MULTICAST_HOPS)
}

/// Sets the hop limit of the IPv6 unicast datagrams `socket` sends (`IPV6_UNICAST_HOPS`):
/// the IPv6 counterpart of `UdpSocket::set_ttl`, which std lacks. 0 to 255; the kernel's
/// default is the route's (usually 64). mDNS sends its unicast responses with 255 too (RFC
/// 6762 §11).
pub fn set_unicast_hops_v6(socket: &std::net::UdpSocket, hops: u32) -> io::Result<()> {
    set_hops_v6(socket, ffi::IPV6_UNICAST_HOPS, hops)
}

/// Sets the boolean socket options `v4` and `v6` (level, name) to 1 on `fd`: an IPv4 socket
/// refuses the IPv6 one; an IPv6 one takes both (the IPv4 one covers IPv4-mapped peers).
/// Whether either was set.
pub(crate) fn set_both(
    fd: RawFd,
    v4: (ffi::c_int, ffi::c_int),
    v6: (ffi::c_int, ffi::c_int),
) -> bool {
    let a = setsockopt_int(fd, v4.0, v4.1, 1).is_ok();
    let b = setsockopt_int(fd, v6.0, v6.1, 1).is_ok();
    a || b
}

/// What the kernel reported about a received datagram besides its data and sender, each 0
/// when not reported: the traffic class byte (IPv4 TOS / IPv6 traffic class: DSCP and ECN), the
/// TTL / hop limit (asked for with `enable_recv_ttl`), and the index of the interface it
/// arrived on (asked for with [`enable_recv_interface`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecvInfo {
    /// The traffic class byte (DSCP in the upper six bits, ECN in the low two).
    pub tos: u8,
    /// The TTL (IPv4) or hop limit (IPv6).
    pub ttl: u8,
    /// The index of the interface the datagram arrived on (as [`interfaces`](crate::interfaces)
    /// lists them).
    pub interface: u32,
}

impl RecvInfo {
    /// The fields of a datagram (for tests and userspace stacks).
    pub fn new(tos: u8, ttl: u8, interface: u32) -> RecvInfo {
        RecvInfo {
            tos,
            ttl,
            interface,
        }
    }
}

/// Asks the kernel to report (`on`), or to stop reporting, the interface every datagram `fd`
/// (a UDP socket) receives arrived on: Linux `IP_PKTINFO`, macOS `IP_RECVPKTINFO`, and
/// `IPV6_RECVPKTINFO` (an IPv4 socket refuses the IPv6 option; an IPv6 one takes both, the
/// IPv4 one covering IPv4-mapped peers). The `in_pktinfo` / `in6_pktinfo` control message then
/// comes with each datagram ([`RecvInfo::interface`]). Whether either option was accepted.
/// Off by default: only a socket that must tell links apart (an mDNS responder) wants the
/// extra control message on every datagram.
pub fn enable_recv_interface(fd: RawFd, on: bool) -> bool {
    #[cfg(target_os = "linux")]
    let v4 = ffi::IP_PKTINFO;
    #[cfg(target_os = "macos")]
    let v4 = ffi::IP_RECVPKTINFO;
    let v = ffi::c_int::from(on);
    let a = setsockopt_int(fd, ffi::IPPROTO_IP, v4, v).is_ok();
    let b = setsockopt_int(fd, ffi::IPPROTO_IPV6, ffi::IPV6_RECVPKTINFO, v).is_ok();
    a || b
}

/// Sets the "don't fragment" bit of the IPv4 datagrams `fd` (a UDP socket) sends, or clears it
/// (`IP_MTU_DISCOVER` with `IP_PMTUDISC_DO` / `IP_PMTUDISC_DONT` on Linux, `IP_DONTFRAG` on
/// macOS). With it set, a datagram larger than the path MTU the kernel knows is refused with
/// `EMSGSIZE` instead of being fragmented; cleared, it is fragmented and the routers on the
/// way may fragment it further. On an IPv6 socket it also sets `IPV6_DONTFRAG` (IPv6 routers
/// never fragment; the option keeps the sender from doing it). Linux's default (no call) is
/// path MTU discovery: DF set while the datagram fits the known path MTU.
pub fn set_dont_fragment(fd: RawFd, v6_socket: bool, on: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let r4 = setsockopt_int(
        fd,
        ffi::IPPROTO_IP,
        ffi::IP_MTU_DISCOVER,
        if on {
            ffi::IP_PMTUDISC_DO
        } else {
            ffi::IP_PMTUDISC_DONT
        },
    );
    #[cfg(target_os = "macos")]
    let r4 = setsockopt_int(fd, ffi::IPPROTO_IP, ffi::IP_DONTFRAG, ffi::c_int::from(on));
    if !v6_socket {
        return r4;
    }
    let r6 = setsockopt_int(
        fd,
        ffi::IPPROTO_IPV6,
        ffi::IPV6_DONTFRAG,
        ffi::c_int::from(on),
    );
    // An IPv6-only socket may refuse the IPv4 option.
    r6.or(r4)
}

/// Whether `fd` (an IPv4 UDP socket) sets the "don't fragment" bit on every datagram it sends
/// ([`set_dont_fragment`]).
pub fn dont_fragment(fd: RawFd) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    let (name, on) = (ffi::IP_MTU_DISCOVER, ffi::IP_PMTUDISC_DO);
    #[cfg(target_os = "macos")]
    let (name, on) = (ffi::IP_DONTFRAG, 1);
    let mut v: ffi::c_int = 0;
    let mut len = size_of::<ffi::c_int>() as ffi::socklen_t;
    // SAFETY: `v` is valid for `len` bytes of writes; the kernel writes at most `len`.
    cvt(unsafe {
        ffi::getsockopt(
            fd,
            ffi::IPPROTO_IP,
            name,
            (&raw mut v).cast::<ffi::c_void>(),
            &raw mut len,
        )
    })?;
    Ok(v == on)
}

/// The MTU of the path to `dest` as this host knows it: what a datagram to `dest` with the
/// "don't fragment" bit set (see [`set_dont_fragment`]) may carry, IP header included, before
/// the kernel refuses it with `EMSGSIZE`. A UDP socket is connected to `dest` (no packet is
/// sent) and asked: Linux `IP_MTU` / `IPV6_MTU` (the route's MTU, lowered by what path MTU
/// discovery learnt); macOS the MTU of the interface holding the socket's local address
/// (`SIOCGIFMTU`). An error when there is no route to `dest`, or elsewhere. Three or four
/// system calls and a file descriptor: for error paths, not per datagram.
pub fn path_mtu(dest: SocketAddr) -> io::Result<u32> {
    let any: SocketAddr = if dest.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let s = std::net::UdpSocket::bind(any)?;
    s.connect(dest)?;
    path_mtu_of(&s, dest)
}

#[cfg(target_os = "linux")]
fn path_mtu_of(s: &std::net::UdpSocket, dest: SocketAddr) -> io::Result<u32> {
    let (level, name) = if dest.is_ipv6() {
        (ffi::IPPROTO_IPV6, ffi::IPV6_MTU)
    } else {
        (ffi::IPPROTO_IP, ffi::IP_MTU)
    };
    let raw = std::os::fd::AsRawFd::as_raw_fd(s);
    let mut v: ffi::c_int = 0;
    let mut len = size_of::<ffi::c_int>() as ffi::socklen_t;
    // SAFETY: `v` is valid for `len` bytes of writes; the kernel writes at most `len`.
    cvt(unsafe {
        ffi::getsockopt(
            raw,
            level,
            name,
            (&raw mut v).cast::<ffi::c_void>(),
            &raw mut len,
        )
    })?;
    u32::try_from(v).map_err(|_| io::Error::other("negative MTU"))
}

#[cfg(target_os = "macos")]
fn path_mtu_of(s: &std::net::UdpSocket, _dest: SocketAddr) -> io::Result<u32> {
    let local = s.local_addr()?.ip();
    let ifs = crate::interfaces()?;
    let name = ifs
        .iter()
        .find(|i| i.has_addr(local))
        .map(|i| i.name.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no interface holds the local address",
            )
        })?;
    let mut req = ffi::ifreq_mtu {
        ifr_name: [0; ffi::IFNAMSIZ],
        ifr_mtu: 0,
        _pad: [0; 12],
    };
    if name.len() >= ffi::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (d, b) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *d = b as ffi::c_char;
    }
    let raw = std::os::fd::AsRawFd::as_raw_fd(s);
    // SAFETY: `req` is a NUL-terminated `ifreq` of the size `SIOCGIFMTU` encodes (32 bytes,
    // checked against `libc` in the layout tests); the kernel writes `ifru_mtu` only.
    cvt(unsafe { ffi::ioctl(raw, ffi::SIOCGIFMTU, (&raw mut req).cast::<ffi::c_void>()) })?;
    u32::try_from(req.ifr_mtu).map_err(|_| io::Error::other("negative MTU"))
}

/// The hop limit of the IPv6 unicast datagrams `socket` sends (see [`set_unicast_hops_v6`]);
/// 0 where the kernel reports the default as unset (macOS: -1).
pub fn unicast_hops_v6(socket: &std::net::UdpSocket) -> io::Result<u32> {
    hops_v6(socket, ffi::IPV6_UNICAST_HOPS)
}

fn set_hops_v6(socket: &std::net::UdpSocket, opt: ffi::c_int, hops: u32) -> io::Result<()> {
    let hops = ffi::c_int::try_from(hops)
        .ok()
        .filter(|h| *h <= 255)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hop limit above 255"))?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(socket);
    setsockopt_int(raw, ffi::IPPROTO_IPV6, opt, hops)
}

fn hops_v6(socket: &std::net::UdpSocket, opt: ffi::c_int) -> io::Result<u32> {
    let raw = std::os::fd::AsRawFd::as_raw_fd(socket);
    let mut v: ffi::c_int = 0;
    let mut len = size_of::<ffi::c_int>() as ffi::socklen_t;
    // SAFETY: `v` is valid for `len` bytes of writes; the kernel writes at most `len`.
    cvt(unsafe {
        ffi::getsockopt(
            raw,
            ffi::IPPROTO_IPV6,
            opt,
            (&raw mut v).cast::<ffi::c_void>(),
            &raw mut len,
        )
    })?;
    Ok(u32::try_from(v).unwrap_or(0))
}

/// Starts a non-blocking connect. The stream becomes writable when the connect finished; check
/// `TcpStream::take_error` then.
pub fn connect_nonblocking(addr: SocketAddr) -> io::Result<TcpStream> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    let r = unsafe { ffi::connect(raw, (&raw const ss).cast::<ffi::sockaddr>(), len) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ffi::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(TcpStream::from(fd))
}

/// Starts a non-blocking connect to `addr` from `local`, bound with `SO_REUSEADDR` and
/// `SO_REUSEPORT` first: several sockets (connections to different peers, a listener) may
/// share the local port, which TCP simultaneous open needs (ICE-TCP `so` candidates, RFC
/// 6544). As [`connect_nonblocking`], the stream becomes writable when the connect finished.
pub fn connect_nonblocking_from(local: SocketAddr, addr: SocketAddr) -> io::Result<TcpStream> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEADDR, 1)?;
    setsockopt_int(raw, ffi::SOL_SOCKET, ffi::SO_REUSEPORT, 1)?;
    let (ls, llen) = sockaddr(&local);
    // SAFETY: `ls` is a valid sockaddr of `llen` bytes.
    cvt(unsafe { ffi::bind(raw, (&raw const ls).cast::<ffi::sockaddr>(), llen) })?;
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    let r = unsafe { ffi::connect(raw, (&raw const ss).cast::<ffi::sockaddr>(), len) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ffi::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(TcpStream::from(fd))
}

/// Sends up to `count` bytes of `file` starting at `offset` to the socket `out` without copying
/// through user space. `Ok(n)` bytes were sent; `WouldBlock` when the socket is full.
pub fn sendfile(out: RawFd, file: RawFd, offset: u64, count: usize) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        let mut off = offset as ffi::off_t;
        // SAFETY: plain syscall; `off` outlives the call and is the only pointer passed.
        let n = unsafe { ffi::sendfile(out, file, &raw mut off, count) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    #[cfg(target_os = "macos")]
    {
        let mut len = count as ffi::off_t;
        // SAFETY: plain syscall; `len` is read and written by the kernel and outlives the call.
        let r = unsafe {
            ffi::sendfile(
                file,
                out,
                offset as ffi::off_t,
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            // A full socket with part of the data already sent reports the progress in `len`.
            if len > 0 && e.kind() == io::ErrorKind::WouldBlock {
                return Ok(len as usize);
            }
            return Err(e);
        }
        Ok(len as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_mtu_of_loopback() {
        // Linux: lo's 65536 (lower when a test container lowered it); macOS: lo0's 16384.
        let v4 = path_mtu("127.0.0.1:9".parse().unwrap()).unwrap();
        assert!((1280..=65536).contains(&v4), "{v4}");
        if cfg!(target_os = "macos") {
            assert_eq!(v4, 16384);
        }
        if let Ok(v6) = path_mtu("[::1]:9".parse().unwrap()) {
            assert!((1280..=65536).contains(&v6), "{v6}");
        }
        // macOS refuses to connect to the unspecified address (Linux takes it for loopback).
        if cfg!(target_os = "macos") {
            assert!(path_mtu("0.0.0.0:0".parse().unwrap()).is_err());
        }
    }

    #[test]
    fn multicast_hops_v6_round_trip() {
        let Ok(s) = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
            return; // no IPv6 on this host
        };
        assert_eq!(multicast_hops_v6(&s).unwrap(), 1, "kernel default");
        set_multicast_hops_v6(&s, 255).unwrap();
        assert_eq!(multicast_hops_v6(&s).unwrap(), 255);
        set_multicast_hops_v6(&s, 0).unwrap();
        assert_eq!(multicast_hops_v6(&s).unwrap(), 0);
        let e = set_multicast_hops_v6(&s, 256).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            multicast_hops_v6(&s).unwrap(),
            0,
            "unchanged by the refused value"
        );
    }

    #[test]
    fn unicast_hops_v6_round_trip() {
        let Ok(s) = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
            return; // no IPv6 on this host
        };
        // The default reads as the route's limit on Linux, as 0 (unset, -1) on macOS.
        assert!(unicast_hops_v6(&s).unwrap() <= 255);
        set_unicast_hops_v6(&s, 255).unwrap();
        assert_eq!(unicast_hops_v6(&s).unwrap(), 255);
        assert_eq!(
            multicast_hops_v6(&s).unwrap(),
            1,
            "the multicast limit is apart"
        );
        let e = set_unicast_hops_v6(&s, 256).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(unicast_hops_v6(&s).unwrap(), 255);
    }
}
