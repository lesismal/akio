//! The host's network interfaces (`getifaddrs(3)`) and sending a datagram out of a given one
//! (`IP_PKTINFO` / `IPV6_PKTINFO` control message).
//!
//! The `getifaddrs` list is read entry by entry and copied into owned values before
//! `freeifaddrs`; socket addresses are copied out byte-wise (never referenced in place: the list
//! packs them without alignment guarantees, and macOS shortens netmasks to their `sa_len`).

use std::ffi::CStr;
use std::io;
use std::mem::offset_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use crate::ffi;

/// A network interface of the host: its name, index, flags and addresses
/// ([`interfaces`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interface {
    /// The interface name (`eth0`, `en0`, `lo0`...).
    pub name: String,
    /// The interface index (`if_nametoindex`): the scope id of its IPv6 link-local addresses,
    /// what [`send_to_on`] and IPv6 multicast joins take. 0 if the interface vanished while
    /// it was being listed.
    pub index: u32,
    /// Its flags (up, running, loopback, point-to-point, multicast).
    pub flags: InterfaceFlags,
    /// Its IPv4 and IPv6 addresses, in the order the system lists them (IPv6 link-local ones
    /// without a scope id: it is [`index`](Self::index)).
    pub addrs: Vec<InterfaceAddr>,
}

impl Interface {
    /// Whether one of the interface's subnets contains `ip` (an address of a host on its link,
    /// or one of its own addresses).
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.addrs.iter().any(|a| a.contains(ip))
    }

    /// Whether `ip` is one of the interface's own addresses.
    pub fn has_addr(&self, ip: IpAddr) -> bool {
        self.addrs.iter().any(|a| a.ip == ip)
    }

    /// The interface's first IPv4 address, if it has one.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addrs.iter().find_map(|a| match a.ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
    }
}

/// An address of an [`Interface`] and the length of its subnet prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct InterfaceAddr {
    /// The address.
    pub ip: IpAddr,
    /// The prefix length of its subnet (from the netmask; 32 / 128 when the system gives no
    /// netmask).
    pub prefix_len: u8,
}

impl InterfaceAddr {
    /// Whether `ip` is in this address's subnet (same family, same first
    /// [`prefix_len`](Self::prefix_len) bits).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len.min(32)))
                    .unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len.min(128)))
                    .unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}

/// The flags of an [`Interface`] (`ifa_flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceFlags(u32);

impl InterfaceFlags {
    fn has(self, flag: ffi::c_int) -> bool {
        self.0 & flag as u32 != 0
    }
    /// Administratively up (`IFF_UP`).
    pub fn is_up(self) -> bool {
        self.has(ffi::IFF_UP)
    }
    /// Resources allocated, link usable (`IFF_RUNNING`).
    pub fn is_running(self) -> bool {
        self.has(ffi::IFF_RUNNING)
    }
    /// A loopback interface (`IFF_LOOPBACK`).
    pub fn is_loopback(self) -> bool {
        self.has(ffi::IFF_LOOPBACK)
    }
    /// A point-to-point link, such as a tunnel (`IFF_POINTOPOINT`).
    pub fn is_point_to_point(self) -> bool {
        self.has(ffi::IFF_POINTOPOINT)
    }
    /// Supports multicast (`IFF_MULTICAST`).
    pub fn is_multicast(self) -> bool {
        self.has(ffi::IFF_MULTICAST)
    }
    /// The raw `ifa_flags` (the `IFF_*` values are the system's).
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// The host's network interfaces with their addresses (`getifaddrs(3)`), sorted by index.
/// Interfaces without an IPv4 or IPv6 address are listed too, with no addresses.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut head: *mut ffi::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is valid for writes; on success it holds a list freed below, once.
    if unsafe { ffi::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out: Vec<Interface> = Vec::new();
    let mut p = head;
    while !p.is_null() {
        // SAFETY: `p` is an entry of the list `getifaddrs` returned, alive until `freeifaddrs`
        // below; nothing else references it. Its name is null or a NUL-terminated string, its
        // address and netmask null or socket addresses (copied by `read_addr` within their size).
        let (name, flags, addr) = unsafe {
            let e = &*p;
            p = e.ifa_next;
            if e.ifa_name.is_null() {
                continue;
            }
            let name = CStr::from_ptr(e.ifa_name);
            (name, e.ifa_flags, read_addr(e.ifa_addr, e.ifa_netmask))
        };
        let i = match out
            .iter()
            .position(|i| i.name.as_bytes() == name.to_bytes())
        {
            Some(i) => i,
            None => {
                // SAFETY: `name` is a NUL-terminated string from the live list.
                let index = unsafe { ffi::if_nametoindex(name.as_ptr()) };
                out.push(Interface {
                    name: name.to_string_lossy().into_owned(),
                    index,
                    flags: InterfaceFlags(flags),
                    addrs: Vec::new(),
                });
                out.len() - 1
            }
        };
        if let Some(a) = addr {
            if !out[i].addrs.contains(&a) {
                out[i].addrs.push(a);
            }
        }
    }
    // SAFETY: `head` came from a successful `getifaddrs`, is freed once, and nothing read
    // from it (`name` above) outlives this point.
    unsafe { ffi::freeifaddrs(head) };
    out.sort_by_key(|i| i.index);
    Ok(out)
}

/// The IPv4 or IPv6 address at `addr` with the prefix length of `mask`.
///
/// # Safety
///
/// `addr` and `mask` are null or point to socket addresses of a live `getifaddrs` list.
unsafe fn read_addr(
    addr: *const ffi::sockaddr,
    mask: *const ffi::sockaddr,
) -> Option<InterfaceAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: (caller) `addr` points to a socket address, at least its family's bytes long.
    let family = unsafe {
        std::ptr::read_unaligned(
            addr.cast::<u8>()
                .add(offset_of!(ffi::sockaddr_in, sin_family))
                .cast::<ffi::sa_family_t>(),
        )
    };
    match ffi::c_int::from(family) {
        ffi::AF_INET => {
            // SAFETY: (caller) an AF_INET address is a whole `sockaddr_in`; the netmask is
            // null or a (maybe shortened) one of the same family.
            let (a, m) = unsafe {
                (
                    copy::<ffi::sockaddr_in>(addr),
                    copy::<ffi::sockaddr_in>(mask),
                )
            };
            let ip = Ipv4Addr::from(u32::from_be(a?.sin_addr.s_addr));
            let prefix = m.map_or(32, |m| u32::from_be(m.sin_addr.s_addr).leading_ones() as u8);
            Some(InterfaceAddr {
                ip: IpAddr::V4(ip),
                prefix_len: prefix,
            })
        }
        ffi::AF_INET6 => {
            // SAFETY: as above, for `sockaddr_in6`.
            let (a, m) = unsafe {
                (
                    copy::<ffi::sockaddr_in6>(addr),
                    copy::<ffi::sockaddr_in6>(mask),
                )
            };
            let mut b = a?.sin6_addr.s6_addr;
            // The BSD kernels embed the scope id of a link-scoped address in its second 16-bit
            // word (KAME); the scope is the interface's index.
            if cfg!(target_os = "macos")
                && (b[0] == 0xfe && b[1] & 0xc0 == 0x80 || b[0] == 0xff && b[1] & 0x0f == 2)
            {
                b[2] = 0;
                b[3] = 0;
            }
            let prefix = m.map_or(128, |m| {
                u128::from_be_bytes(m.sin6_addr.s6_addr).leading_ones() as u8
            });
            Some(InterfaceAddr {
                ip: IpAddr::V6(Ipv6Addr::from(b)),
                prefix_len: prefix,
            })
        }
        _ => None,
    }
}

/// Copies the socket address at `p` into a `T` (`None` if `p` is null). On macOS it may be
/// shorter than `T` (netmasks are cut to their `sa_len`): only its `sa_len` bytes are read, the
/// rest stays zero.
///
/// # Safety
///
/// `p` is null or points to a socket address of type `T` (on macOS: of at least its `sa_len`
/// bytes).
unsafe fn copy<T: Default>(p: *const ffi::sockaddr) -> Option<T> {
    if p.is_null() {
        return None;
    }
    let mut len = size_of::<T>();
    if cfg!(target_os = "macos") {
        // SAFETY: (caller) a BSD socket address starts with its length byte.
        len = len.min(usize::from(unsafe { p.cast::<u8>().read() }));
    }
    let mut out = T::default();
    // SAFETY: (caller) `p` is readable for `len` bytes; `out` is a distinct local `T`, at
    // least `len` bytes, of plain-old-data whose every bit pattern is valid.
    unsafe {
        std::ptr::copy_nonoverlapping(p.cast::<u8>(), (&raw mut out).cast::<u8>(), len);
    }
    Some(out)
}

/// A control message with its data, laid out as `CMSG_FIRSTHDR` / `CMSG_DATA` place them: the
/// data right after the header rounded up to the control message alignment (8 bytes on Linux,
/// where `cmsghdr` is 16 bytes; 4 on macOS, where it is 12), the whole `CMSG_SPACE` long.
#[repr(C)]
struct Cmsg<T> {
    hdr: ffi::cmsghdr,
    data: T,
}

/// Sends one datagram to `addr` out of interface `interface` (an [`Interface::index`]; 0: the
/// system's choice, a plain `send_to`), from the calling thread: the interface goes with the
/// datagram in an `IP_PKTINFO` / `IPV6_PKTINFO` control message (`ipi_ifindex`), which for a
/// multicast destination picks the link it is sent on, as `IP_MULTICAST_IF` would for the whole
/// socket. The source address is the system's choice for that interface. The family of the
/// control message is the socket's (an IPv4 destination on an IPv6 socket is sent mapped).
/// macOS, IPv4 multicast from an IPv4 socket: `IP_MULTICAST_IFINDEX` is set for the send
/// instead (and put back), since there `IP_PKTINFO` fails on an interface without a multicast
/// route (`lo0`, or every interface but the primary one).
pub fn send_to_on(
    socket: &UdpSocket,
    data: &[u8],
    addr: SocketAddr,
    interface: u32,
) -> io::Result<usize> {
    if interface == 0 {
        return socket.send_to(data, addr);
    }
    let v6 = socket.local_addr()?.is_ipv6();
    let dest = match (v6, addr) {
        (true, SocketAddr::V4(a)) => SocketAddr::new(a.ip().to_ipv6_mapped().into(), a.port()),
        _ => addr,
    };
    #[cfg(target_os = "macos")]
    if let (false, SocketAddr::V4(a)) = (v6, dest)
        && a.ip().is_multicast()
    {
        return send_multicast_v4_on(socket, data, dest, interface);
    }
    if v6 {
        let info = ffi::in6_pktinfo {
            ipi6_addr: ffi::in6_addr::default(),
            ipi6_ifindex: interface,
        };
        send_cmsg(
            socket,
            data,
            &dest,
            ffi::IPPROTO_IPV6,
            ffi::IPV6_PKTINFO,
            info,
        )
    } else {
        let info = ffi::in_pktinfo {
            ipi_ifindex: interface,
            ..ffi::in_pktinfo::default()
        };
        send_cmsg(socket, data, &dest, ffi::IPPROTO_IP, ffi::IP_PKTINFO, info)
    }
}

/// Serializes the sends of IPv4 multicast on macOS while [`send_to_on`] switches a socket's
/// multicast interface (see [`send_multicast_v4_on`]).
#[cfg(target_os = "macos")]
static MULTICAST_V4: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// (internal) For a send to `addr` that does not name an interface: on macOS, when `addr` is an
/// IPv4 multicast group, the lock [`send_to_on`] holds while it switches the socket's multicast
/// interface, so this send does not leave on the interface another one named; elsewhere, and
/// for other destinations, `None`. Hold it across the send.
#[doc(hidden)]
pub fn multicast_send_guard(addr: &SocketAddr) -> Option<std::sync::MutexGuard<'static, ()>> {
    #[cfg(target_os = "macos")]
    if let SocketAddr::V4(a) = addr
        && a.ip().is_multicast()
    {
        return Some(MULTICAST_V4.lock().unwrap_or_else(|p| p.into_inner()));
    }
    let _ = addr;
    None
}

/// macOS, an IPv4 multicast destination: the interface named in `IP_PKTINFO` scopes the route
/// lookup to that interface there, and an interface without a route for 224.0.0.0/4 (`lo0`, or
/// any but the one the multicast route names) fails with `ENETUNREACH`, where Linux sends out of
/// it. `IP_MULTICAST_IFINDEX` picks the interface without a route, so it is set on the socket
/// for this send and put back after, under [`MULTICAST_V4`] (which the socket's other IPv4
/// multicast sends take too, [`multicast_send_guard`]).
#[cfg(target_os = "macos")]
fn send_multicast_v4_on(
    socket: &UdpSocket,
    data: &[u8],
    dest: SocketAddr,
    interface: u32,
) -> io::Result<usize> {
    let _g = MULTICAST_V4.lock().unwrap_or_else(|p| p.into_inner());
    let fd = socket.as_raw_fd();
    let mut old: u32 = 0;
    let mut len = size_of::<u32>() as ffi::socklen_t;
    // SAFETY: `old` is valid for `len` bytes of writes; the kernel writes at most `len`.
    crate::net::cvt(unsafe {
        ffi::getsockopt(
            fd,
            ffi::IPPROTO_IP,
            ffi::IP_MULTICAST_IFINDEX,
            (&raw mut old).cast(),
            &raw mut len,
        )
    })?;
    let set = |index: u32| {
        // SAFETY: `index` outlives the call and the length matches its type.
        crate::net::cvt(unsafe {
            ffi::setsockopt(
                fd,
                ffi::IPPROTO_IP,
                ffi::IP_MULTICAST_IFINDEX,
                (&raw const index).cast(),
                size_of::<u32>() as ffi::socklen_t,
            )
        })
        .map(drop)
    };
    set(interface)?;
    let sent = socket.send_to(data, dest);
    // Put back before the lock goes, whatever the send did.
    set(old)?;
    sent
}

fn send_cmsg<T: Copy>(
    socket: &UdpSocket,
    data: &[u8],
    dest: &SocketAddr,
    level: ffi::c_int,
    ty: ffi::c_int,
    info: T,
) -> io::Result<usize> {
    let (mut ss, slen) = crate::net::sockaddr(dest);
    let mut iov = ffi::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut ctrl = Cmsg {
        hdr: ffi::cmsghdr {
            cmsg_len: (offset_of!(Cmsg<T>, data) + size_of::<T>()) as _,
            cmsg_level: level,
            cmsg_type: ty,
        },
        data: info,
    };
    let h = ffi::msghdr {
        msg_name: (&raw mut ss).cast(),
        msg_namelen: slen,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: (&raw mut ctrl).cast(),
        msg_controllen: size_of::<Cmsg<T>>() as _,
        msg_flags: 0,
    };
    loop {
        // SAFETY: every pointer in `h` points into a live local (`ss` with its length,
        // `iov` -> `data`, `ctrl`: one control message of `CMSG_SPACE` bytes whose header
        // gives its `CMSG_LEN`); sendmsg only reads them.
        let n = unsafe { ffi::sendmsg(socket.as_raw_fd(), &raw const h, 0) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmsg_layout_matches_libc() {
        // SAFETY: CMSG_* only compute sizes.
        unsafe {
            for (len, space, data) in [
                (
                    offset_of!(Cmsg<ffi::in_pktinfo>, data) + size_of::<ffi::in_pktinfo>(),
                    size_of::<Cmsg<ffi::in_pktinfo>>(),
                    size_of::<ffi::in_pktinfo>(),
                ),
                (
                    offset_of!(Cmsg<ffi::in6_pktinfo>, data) + size_of::<ffi::in6_pktinfo>(),
                    size_of::<Cmsg<ffi::in6_pktinfo>>(),
                    size_of::<ffi::in6_pktinfo>(),
                ),
            ] {
                assert_eq!(len, libc::CMSG_LEN(data as u32) as usize);
                assert_eq!(space, libc::CMSG_SPACE(data as u32) as usize);
            }
        }
    }

    #[test]
    fn subnets() {
        let a = InterfaceAddr {
            ip: "192.168.1.7".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(a.contains("192.168.1.200".parse().unwrap()));
        assert!(!a.contains("192.168.2.7".parse().unwrap()));
        assert!(!a.contains("::1".parse().unwrap()));
        let all = InterfaceAddr { prefix_len: 0, ..a };
        assert!(all.contains("10.0.0.1".parse().unwrap()));
        let b = InterfaceAddr {
            ip: "fd00:6::1".parse().unwrap(),
            prefix_len: 64,
        };
        assert!(b.contains("fd00:6::2".parse().unwrap()));
        assert!(!b.contains("fd00:7::1".parse().unwrap()));
        let host = InterfaceAddr {
            prefix_len: 128,
            ..b
        };
        assert!(!host.contains("fd00:6::2".parse().unwrap()));
        assert!(host.contains("fd00:6::1".parse().unwrap()));
    }

    #[test]
    fn lists_the_loopback_interface() {
        let all = interfaces().unwrap();
        assert!(!all.is_empty());
        let lo = all
            .iter()
            .find(|i| i.flags.is_loopback())
            .expect("a loopback interface");
        assert!(lo.index > 0 && lo.flags.is_up());
        assert!(
            lo.addrs
                .iter()
                .any(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST) && a.prefix_len == 8),
            "{lo:?}"
        );
        assert!(lo.contains("127.0.0.53".parse().unwrap()));
        let mut idx: Vec<u32> = all.iter().map(|i| i.index).collect();
        idx.dedup();
        assert_eq!(idx.len(), all.len(), "indexes unique and sorted: {all:?}");
        for i in &all {
            for a in &i.addrs {
                if let IpAddr::V6(v6) = a.ip {
                    let s = v6.segments();
                    if s[0] & 0xffc0 == 0xfe80 {
                        assert_eq!(s[1], 0, "no embedded scope id in {v6} on {}", i.name);
                    }
                }
                assert!(a.prefix_len <= if a.ip.is_ipv4() { 32 } else { 128 });
            }
        }
    }

    /// macOS: IPv4 multicast out of `lo0`, which has no route for 224.0.0.0/4 (the multicast
    /// route names the primary interface): `IP_PKTINFO` failed with `ENETUNREACH` there; the
    /// socket's `IP_MULTICAST_IFINDEX` is switched for the send and put back after.
    #[cfg(target_os = "macos")]
    #[test]
    fn ipv4_multicast_leaves_on_an_interface_without_the_multicast_route() {
        let lo = interfaces()
            .unwrap()
            .into_iter()
            .find(|i| i.flags.is_loopback() && i.flags.is_multicast())
            .unwrap();
        let rx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let group = Ipv4Addr::new(239, 255, 42, 91);
        rx.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let dest = SocketAddr::new(group.into(), rx.local_addr().unwrap().port());
        assert_eq!(send_to_on(&tx, b"via lo0", dest, lo.index).unwrap(), 7);
        let mut buf = [0u8; 16];
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"via lo0");
        assert_eq!(from.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // The socket's own multicast interface is back to the system's choice.
        let mut v: u32 = u32::MAX;
        let mut len = size_of::<u32>() as ffi::socklen_t;
        // SAFETY: `v` is valid for `len` bytes of writes.
        let r = unsafe {
            ffi::getsockopt(
                tx.as_raw_fd(),
                ffi::IPPROTO_IP,
                ffi::IP_MULTICAST_IFINDEX,
                (&raw mut v).cast(),
                &raw mut len,
            )
        };
        assert_eq!((r, v), (0, 0));
    }

    #[test]
    fn send_to_on_names_the_interface() {
        let all = interfaces().unwrap();
        let lo = all.iter().find(|i| i.flags.is_loopback()).unwrap();
        for (bind, ip) in [("127.0.0.1:0", "127.0.0.1"), ("[::1]:0", "::1")] {
            let Ok(rx) = UdpSocket::bind(bind) else {
                continue; // no IPv6 loopback
            };
            if !lo.has_addr(ip.parse().unwrap()) {
                continue;
            }
            rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let tx = UdpSocket::bind(bind).unwrap();
            let dest = rx.local_addr().unwrap();
            assert_eq!(send_to_on(&tx, b"via lo", dest, lo.index).unwrap(), 6);
            assert_eq!(send_to_on(&tx, b"default", dest, 0).unwrap(), 7);
            let mut buf = [0u8; 16];
            let (n, from) = rx.recv_from(&mut buf).unwrap();
            assert_eq!(
                (&buf[..n], from),
                (&b"via lo"[..], tx.local_addr().unwrap())
            );
            let (n, _) = rx.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"default");
            // An interface that does not exist is refused.
            assert!(send_to_on(&tx, b"x", dest, 0x7fff_fff0).is_err());
        }
    }
}
