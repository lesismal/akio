//! TUN devices (layer-3 virtual interfaces: one IP packet per read and per write) and the
//! interface settings a TUN needs: MTU, addresses, up / down (ADR-096).
//!
//! * Linux: `/dev/net/tun` with `TUNSETIFF` and `IFF_TUN | IFF_NO_PI` (optionally
//!   `IFF_MULTI_QUEUE`: one descriptor per queue, the kernel spreads flows over them). The
//!   interface lives while a queue's descriptor is open (not persistent). Settings are the classic
//!   `SIOCSIF*` ioctls on a datagram socket (IPv6 addresses through `struct in6_ifreq`), which need
//!   `CAP_NET_ADMIN` like the device itself.
//! * macOS: a `utun` interface from the `com.apple.net.utun_control` kernel control (a
//!   `PF_SYSTEM` socket, root only). Every packet carries a 4-byte address family in front
//!   (network byte order); [`read_packet`] reports where the packet starts and [`write_packet`]
//!   prepends the header with `writev`, so no packet is copied. Addresses by `SIOCAIFADDR` /
//!   `SIOCAIFADDR_IN6` (point-to-point: the destination is the address itself), MTU and flags by
//!   `SIOCSIFMTU` / `SIOCSIFFLAGS`.
//!
//! Every structure handed to the kernel is a byte array of the C layout's size and alignment,
//! filled field by field with `to_ne_bytes` / `to_be_bytes`: the `unsafe` here is only the calls.

#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::ffi;

fn cvt(r: ffi::c_int) -> io::Result<ffi::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_size(r: ffi::ssize_t) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

/// Interface name bytes, NUL-padded to `IFNAMSIZ` (16 on both systems).
fn name_bytes(name: &str) -> io::Result<[u8; 16]> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= 16 || b.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {name:?}"),
        ));
    }
    let mut out = [0u8; 16];
    out[..b.len()].copy_from_slice(b);
    Ok(out)
}

fn name_from(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A `struct ifreq`: the name, then the union (40 bytes on Linux, 32 on macOS; 8-aligned for
/// its pointer member).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct IfReq {
    name: [u8; 16],
    #[cfg(target_os = "linux")]
    u: [u8; 24],
    #[cfg(target_os = "macos")]
    u: [u8; 16],
}

#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<IfReq>() == 40 && align_of::<IfReq>() == 8);
#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<IfReq>() == 32 && align_of::<IfReq>() == 8);

impl IfReq {
    fn new(name: &str) -> io::Result<IfReq> {
        Ok(IfReq {
            name: name_bytes(name)?,
            u: [0; size_of::<IfReq>() - 16],
        })
    }
    fn short(&self) -> i16 {
        i16::from_ne_bytes([self.u[0], self.u[1]])
    }
    fn set_short(&mut self, v: i16) {
        self.u[..2].copy_from_slice(&v.to_ne_bytes());
    }
    fn int(&self) -> i32 {
        i32::from_ne_bytes([self.u[0], self.u[1], self.u[2], self.u[3]])
    }
    fn set_int(&mut self, v: i32) {
        self.u[..4].copy_from_slice(&v.to_ne_bytes());
    }
}

/// A datagram socket of `family` to issue interface ioctls on.
fn ctl_socket(family: ffi::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain integer arguments.
    let fd = cvt(unsafe { ffi::socket(family, ffi::SOCK_DGRAM, 0) })?;
    // SAFETY: `fd` was just created and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `ioctl(fd, req, &mut ifreq)`.
fn ioctl_ifreq(fd: &OwnedFd, req: ffi::c_ulong, ifr: &mut IfReq) -> io::Result<()> {
    // SAFETY: every request passed here reads and/or writes one `struct ifreq`, which `ifr` is
    // (layout and size checked above), alive and exclusively borrowed across the call.
    cvt(unsafe { ffi::ioctl(fd.as_raw_fd(), req, std::ptr::from_mut(ifr)) }).map(drop)
}

/// The interface's MTU.
pub fn if_mtu(name: &str) -> io::Result<u32> {
    let s = ctl_socket(ffi::AF_INET)?;
    let mut ifr = IfReq::new(name)?;
    ioctl_ifreq(&s, SIOCGIFMTU, &mut ifr)?;
    Ok(ifr.int() as u32)
}

/// Sets the interface's MTU.
pub fn if_set_mtu(name: &str, mtu: u32) -> io::Result<()> {
    let s = ctl_socket(ffi::AF_INET)?;
    let mut ifr = IfReq::new(name)?;
    ifr.set_int(i32::try_from(mtu).map_err(|_| io::ErrorKind::InvalidInput)?);
    ioctl_ifreq(&s, SIOCSIFMTU, &mut ifr)
}

/// Whether the interface is administratively up (`IFF_UP`).
pub fn if_is_up(name: &str) -> io::Result<bool> {
    let s = ctl_socket(ffi::AF_INET)?;
    let mut ifr = IfReq::new(name)?;
    ioctl_ifreq(&s, SIOCGIFFLAGS, &mut ifr)?;
    Ok(i32::from(ifr.short()) & ffi::IFF_UP != 0)
}

/// Brings the interface up or down (`IFF_UP`).
pub fn if_set_up(name: &str, up: bool) -> io::Result<()> {
    let s = ctl_socket(ffi::AF_INET)?;
    let mut ifr = IfReq::new(name)?;
    ioctl_ifreq(&s, SIOCGIFFLAGS, &mut ifr)?;
    let mut flags = i32::from(ifr.short());
    if up {
        flags |= ffi::IFF_UP;
    } else {
        flags &= !ffi::IFF_UP;
    }
    ifr.set_short(flags as i16);
    ioctl_ifreq(&s, SIOCSIFFLAGS, &mut ifr)
}

/// The IPv4 netmask of a `prefix`-bit prefix, in network byte order bytes.
fn mask4(prefix: u8) -> [u8; 4] {
    u32::MAX
        .checked_shl(32 - u32::from(prefix.min(32)))
        .unwrap_or(0)
        .to_be_bytes()
}

#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux takes a prefix length
fn mask6(prefix: u8) -> [u8; 16] {
    u128::MAX
        .checked_shl(128 - u32::from(prefix.min(128)))
        .unwrap_or(0)
        .to_be_bytes()
}

/// Validates a prefix length for `ip`'s family.
fn check_prefix(ip: IpAddr, prefix: u8) -> io::Result<()> {
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("prefix length {prefix} too long for {ip}"),
        ));
    }
    Ok(())
}

// ---- Linux -------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const TUNSETIFF: ffi::c_ulong = 0x4004_54ca;
#[cfg(target_os = "linux")]
const TUNGETIFF: ffi::c_ulong = 0x8004_54d2;
#[cfg(target_os = "linux")]
const IFF_TUN: i16 = 0x0001;
#[cfg(target_os = "linux")]
const IFF_MULTI_QUEUE: i16 = 0x0100;
#[cfg(target_os = "linux")]
const IFF_NO_PI: i16 = 0x1000;
#[cfg(target_os = "linux")]
const SIOCGIFFLAGS: ffi::c_ulong = 0x8913;
#[cfg(target_os = "linux")]
const SIOCSIFFLAGS: ffi::c_ulong = 0x8914;
#[cfg(target_os = "linux")]
const SIOCSIFADDR: ffi::c_ulong = 0x8916;
#[cfg(target_os = "linux")]
const SIOCSIFNETMASK: ffi::c_ulong = 0x891c;
#[cfg(target_os = "linux")]
const SIOCGIFMTU: ffi::c_ulong = 0x8921;
#[cfg(target_os = "linux")]
const SIOCSIFMTU: ffi::c_ulong = 0x8922;
#[cfg(target_os = "linux")]
const SIOCGIFINDEX: ffi::c_ulong = 0x8933;
#[cfg(target_os = "linux")]
const SIOCDIFADDR: ffi::c_ulong = 0x8936;
/// `EBADFD`: the descriptor's interface was deleted (`ip link del`).
#[cfg(target_os = "linux")]
const EBADFD: i32 = 77;

/// Opens a queue of TUN interface `name` (created if it does not exist; `None`: the kernel
/// names it `tunN`) with `IFF_TUN | IFF_NO_PI`, and `IFF_MULTI_QUEUE` when `multi_queue`
/// (every queue of a multi-queue interface must be opened with it, by calling this again with
/// the name returned). Non-blocking, close-on-exec. Returns the descriptor and the interface's
/// name. Needs `CAP_NET_ADMIN` (or ownership of a persistent device).
#[cfg(target_os = "linux")]
pub fn tun_open(name: Option<&str>, multi_queue: bool) -> io::Result<(OwnedFd, String)> {
    let mut ifr = match name {
        Some(n) => IfReq::new(n)?,
        None => IfReq {
            name: [0; 16],
            u: [0; 24],
        },
    };
    let mut flags = IFF_TUN | IFF_NO_PI;
    if multi_queue {
        flags |= IFF_MULTI_QUEUE;
    }
    ifr.set_short(flags);
    let path = c"/dev/net/tun";
    // SAFETY: `path` is a valid NUL-terminated string; the flags are plain integers.
    let raw = cvt(unsafe {
        ffi::open(
            path.as_ptr(),
            ffi::O_RDWR | ffi::O_NONBLOCK | ffi::O_CLOEXEC,
        )
    })?;
    // SAFETY: `raw` was just opened and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    ioctl_ifreq(&fd, TUNSETIFF, &mut ifr)?;
    Ok((fd, name_from(&ifr.name)))
}

/// The flags a TUN descriptor was opened with (`TUNGETIFF`): whether it is multi-queue.
#[cfg(target_os = "linux")]
pub fn tun_is_multi_queue(fd: &OwnedFd) -> io::Result<bool> {
    let mut ifr = IfReq {
        name: [0; 16],
        u: [0; 24],
    };
    ioctl_ifreq(fd, TUNGETIFF, &mut ifr)?;
    Ok(ifr.short() & IFF_MULTI_QUEUE != 0)
}

/// The interface's index.
#[cfg(target_os = "linux")]
pub fn if_index(name: &str) -> io::Result<u32> {
    let s = ctl_socket(ffi::AF_INET)?;
    let mut ifr = IfReq::new(name)?;
    ioctl_ifreq(&s, SIOCGIFINDEX, &mut ifr)?;
    Ok(ifr.int() as u32)
}

/// `struct in6_ifreq` (`linux/ipv6.h`): address, prefix length, interface index.
#[cfg(target_os = "linux")]
#[repr(C, align(4))]
struct In6IfReq([u8; 24]);

#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<In6IfReq>() == 24);

#[cfg(target_os = "linux")]
fn in6_ifreq(name: &str, ip: std::net::Ipv6Addr, prefix: u8) -> io::Result<In6IfReq> {
    let mut r = [0u8; 24];
    r[..16].copy_from_slice(&ip.octets());
    r[16..20].copy_from_slice(&u32::from(prefix).to_ne_bytes());
    r[20..24].copy_from_slice(&(if_index(name)? as i32).to_ne_bytes());
    Ok(In6IfReq(r))
}

/// A `struct sockaddr_in` with `ip` (port 0) in an `ifreq` union.
#[cfg(target_os = "linux")]
fn put_sin(ifr: &mut IfReq, ip: [u8; 4]) {
    ifr.u = [0; 24];
    ifr.u[..2].copy_from_slice(&(ffi::AF_INET as u16).to_ne_bytes());
    ifr.u[4..8].copy_from_slice(&ip);
}

/// Adds `ip/prefix` to the interface. IPv4: sets the interface's (one) IPv4 address and its
/// netmask, replacing an earlier one; IPv6: adds an address (several may be set). The kernel
/// routes the prefix to the interface once it is up.
#[cfg(target_os = "linux")]
pub fn if_add_addr(name: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    check_prefix(ip, prefix)?;
    match ip {
        IpAddr::V4(v4) => {
            let s = ctl_socket(ffi::AF_INET)?;
            let mut ifr = IfReq::new(name)?;
            put_sin(&mut ifr, v4.octets());
            ioctl_ifreq(&s, SIOCSIFADDR, &mut ifr)?;
            put_sin(&mut ifr, mask4(prefix));
            ioctl_ifreq(&s, SIOCSIFNETMASK, &mut ifr)
        }
        IpAddr::V6(v6) => {
            let s = ctl_socket(ffi::AF_INET6)?;
            let mut r = in6_ifreq(name, v6, prefix)?;
            // SAFETY: SIOCSIFADDR on an AF_INET6 socket reads one `struct in6_ifreq`, which
            // `r` is (24 bytes, 4-aligned), alive across the call.
            cvt(unsafe { ffi::ioctl(s.as_raw_fd(), SIOCSIFADDR, &raw mut r) }).map(drop)
        }
    }
}

/// Removes `ip/prefix` from the interface.
#[cfg(target_os = "linux")]
pub fn if_del_addr(name: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    check_prefix(ip, prefix)?;
    match ip {
        IpAddr::V4(v4) => {
            let s = ctl_socket(ffi::AF_INET)?;
            let mut ifr = IfReq::new(name)?;
            put_sin(&mut ifr, v4.octets());
            ioctl_ifreq(&s, SIOCDIFADDR, &mut ifr)
        }
        IpAddr::V6(v6) => {
            let s = ctl_socket(ffi::AF_INET6)?;
            let mut r = in6_ifreq(name, v6, prefix)?;
            // SAFETY: SIOCDIFADDR on an AF_INET6 socket reads one `struct in6_ifreq`, which
            // `r` is, alive across the call.
            cvt(unsafe { ffi::ioctl(s.as_raw_fd(), SIOCDIFADDR, &raw mut r) }).map(drop)
        }
    }
}

/// Reads one packet into `buf`. Returns the range of `buf` it occupies (Linux: from 0; macOS:
/// behind the 4-byte family header). A packet larger than `buf` is truncated by the kernel.
#[cfg(target_os = "linux")]
pub fn read_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let n = cvt_size(unsafe { ffi::read(fd, buf.as_mut_ptr().cast(), buf.len()) })?;
    Ok(0..n)
}

/// Writes one IP packet.
#[cfg(target_os = "linux")]
pub fn write_packet(fd: RawFd, pkt: &[u8]) -> io::Result<usize> {
    // SAFETY: `pkt` is valid for reads of `pkt.len()` bytes.
    cvt_size(unsafe { ffi::write(fd, pkt.as_ptr().cast(), pkt.len()) })
}

/// Whether a read or write error means the device is gone (deleted underneath, or the
/// descriptor no longer refers to it), rather than a packet refused.
pub fn tun_gone(e: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(e.raw_os_error(), Some(EBADFD | ffi::EBADF))
    }
    #[cfg(target_os = "macos")]
    {
        // ENXIO: the interface was detached; EBADF / ENOTCONN: the control socket is dead.
        matches!(e.raw_os_error(), Some(6 | ffi::EBADF | 57))
    }
}

// ---- macOS -------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const SIOCSIFFLAGS: ffi::c_ulong = 0x8020_6910;
#[cfg(target_os = "macos")]
const SIOCGIFFLAGS: ffi::c_ulong = 0xc020_6911;
#[cfg(target_os = "macos")]
const SIOCGIFMTU: ffi::c_ulong = 0xc020_6933;
#[cfg(target_os = "macos")]
const SIOCSIFMTU: ffi::c_ulong = 0x8020_6934;
#[cfg(target_os = "macos")]
const SIOCAIFADDR: ffi::c_ulong = 0x8040_691a;
#[cfg(target_os = "macos")]
const SIOCDIFADDR: ffi::c_ulong = 0x8020_6919;
#[cfg(target_os = "macos")]
const SIOCAIFADDR_IN6: ffi::c_ulong = 0x8080_691a;
#[cfg(target_os = "macos")]
const SIOCDIFADDR_IN6: ffi::c_ulong = 0x8120_6919;
#[cfg(target_os = "macos")]
const PF_SYSTEM: ffi::c_int = 32;
#[cfg(target_os = "macos")]
const AF_SYS_CONTROL: u16 = 2;
#[cfg(target_os = "macos")]
const SYSPROTO_CONTROL: ffi::c_int = 2;
#[cfg(target_os = "macos")]
const CTLIOCGINFO: ffi::c_ulong = 0xc064_4e03;
#[cfg(target_os = "macos")]
const UTUN_OPT_IFNAME: ffi::c_int = 2;
#[cfg(target_os = "macos")]
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;

/// `struct ctl_info`: control id, control name.
#[cfg(target_os = "macos")]
#[repr(C, align(4))]
struct CtlInfo([u8; 100]);

/// `struct sockaddr_ctl`.
#[cfg(target_os = "macos")]
#[repr(C, align(4))]
struct SockaddrCtl([u8; 32]);

/// `struct ifaliasreq`: name, address, destination (broadcast), mask.
#[cfg(target_os = "macos")]
#[repr(C, align(4))]
struct IfAliasReq([u8; 64]);

/// `struct in6_aliasreq`: name, address, destination, prefix mask, flags, lifetimes.
#[cfg(target_os = "macos")]
#[repr(C, align(8))]
struct In6AliasReq([u8; 128]);

/// `struct in6_ifreq` (macOS): name, then a union whose largest member is 272 bytes.
#[cfg(target_os = "macos")]
#[repr(C, align(8))]
struct In6IfReq([u8; 288]);

#[cfg(target_os = "macos")]
const _: () = assert!(
    size_of::<CtlInfo>() == 100
        && size_of::<SockaddrCtl>() == 32
        && size_of::<IfAliasReq>() == 64
        && size_of::<In6AliasReq>() == 128
        && size_of::<In6IfReq>() == 288
);

/// Opens a `utun` interface: `utun{unit}` when `unit` is given, else the first free one.
/// Non-blocking, close-on-exec. Returns the control socket and the interface's name. Needs
/// root. The interface is destroyed when the socket closes.
#[cfg(target_os = "macos")]
pub fn utun_open(unit: Option<u32>) -> io::Result<OwnedFd> {
    // SAFETY: plain integer arguments.
    let raw = cvt(unsafe { ffi::socket(PF_SYSTEM, ffi::SOCK_DGRAM, SYSPROTO_CONTROL) })?;
    // SAFETY: `raw` was just created and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info = CtlInfo([0; 100]);
    let ctl = b"com.apple.net.utun_control";
    info.0[4..4 + ctl.len()].copy_from_slice(ctl);
    // SAFETY: CTLIOCGINFO reads and writes one `struct ctl_info`, which `info` is (100 bytes,
    // 4-aligned), alive across the call.
    cvt(unsafe { ffi::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &raw mut info) })?;
    let id = u32::from_ne_bytes([info.0[0], info.0[1], info.0[2], info.0[3]]);
    let mut sc = SockaddrCtl([0; 32]);
    sc.0[0] = 32; // sc_len
    sc.0[1] = PF_SYSTEM as u8; // sc_family: AF_SYSTEM
    sc.0[2..4].copy_from_slice(&AF_SYS_CONTROL.to_ne_bytes());
    sc.0[4..8].copy_from_slice(&id.to_ne_bytes());
    // sc_unit: utunN is unit N + 1; 0 lets the kernel pick.
    let sc_unit = unit.map_or(Ok(0), |u| {
        u.checked_add(1).ok_or(io::ErrorKind::InvalidInput)
    })?;
    sc.0[8..12].copy_from_slice(&sc_unit.to_ne_bytes());
    // SAFETY: `sc` is a valid `struct sockaddr_ctl` of the length passed.
    cvt(unsafe {
        ffi::connect(
            fd.as_raw_fd(),
            (&raw const sc).cast::<ffi::sockaddr>(),
            size_of::<SockaddrCtl>() as ffi::socklen_t,
        )
    })?;
    set_nonblock_cloexec(fd.as_raw_fd())?;
    Ok(fd)
}

/// The interface name of a utun control socket (`UTUN_OPT_IFNAME`).
#[cfg(target_os = "macos")]
pub fn utun_name(fd: &OwnedFd) -> io::Result<String> {
    let mut name = [0u8; 16];
    let mut len = name.len() as ffi::socklen_t;
    // SAFETY: `name` is writable for `len` bytes, `len` is a valid `socklen_t`.
    cvt(unsafe {
        ffi::getsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &raw mut len,
        )
    })?;
    Ok(name_from(&name[..(len as usize).min(16)]))
}

#[cfg(target_os = "macos")]
fn set_nonblock_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFL / F_SETFL / F_SETFD takes and returns plain integers.
    unsafe {
        let fl = cvt(ffi::fcntl(fd, ffi::F_GETFL))?;
        cvt(ffi::fcntl(fd, ffi::F_SETFL, fl | ffi::O_NONBLOCK))?;
        cvt(ffi::fcntl(fd, ffi::F_SETFD, ffi::FD_CLOEXEC))?;
    }
    Ok(())
}

/// A BSD `sockaddr_in` (with its length byte) at `out[..16]`.
#[cfg(target_os = "macos")]
fn put_sin_bsd(out: &mut [u8], ip: [u8; 4]) {
    out[0] = 16;
    out[1] = ffi::AF_INET as u8;
    out[4..8].copy_from_slice(&ip);
}

/// A BSD `sockaddr_in6` at `out[..28]`.
#[cfg(target_os = "macos")]
fn put_sin6_bsd(out: &mut [u8], ip: [u8; 16]) {
    out[0] = 28;
    out[1] = ffi::AF_INET6 as u8;
    out[8..24].copy_from_slice(&ip);
}

/// Adds `ip/prefix` to the interface. The interface is point-to-point: the destination is the
/// address itself, and routes for the prefix are the application's (`route add -net ...
/// -interface utunN`), as with any utun.
#[cfg(target_os = "macos")]
pub fn if_add_addr(name: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    check_prefix(ip, prefix)?;
    let n = name_bytes(name)?;
    match ip {
        IpAddr::V4(v4) => {
            let s = ctl_socket(ffi::AF_INET)?;
            let mut r = IfAliasReq([0; 64]);
            r.0[..16].copy_from_slice(&n);
            put_sin_bsd(&mut r.0[16..32], v4.octets());
            put_sin_bsd(&mut r.0[32..48], v4.octets());
            put_sin_bsd(&mut r.0[48..64], mask4(prefix));
            // SAFETY: SIOCAIFADDR reads one `struct ifaliasreq`, which `r` is, alive across
            // the call.
            cvt(unsafe { ffi::ioctl(s.as_raw_fd(), SIOCAIFADDR, &raw mut r) }).map(drop)
        }
        IpAddr::V6(v6) => {
            let s = ctl_socket(ffi::AF_INET6)?;
            let mut r = In6AliasReq([0; 128]);
            r.0[..16].copy_from_slice(&n);
            put_sin6_bsd(&mut r.0[16..44], v6.octets());
            // No destination for IPv6 (left zero, as ifconfig does with a prefix length).
            put_sin6_bsd(&mut r.0[72..100], mask6(prefix));
            // ifra_flags at 100 stays 0; lifetimes at 104: expire, preferred (time_t), then
            // valid and preferred lifetimes: infinite.
            r.0[120..124].copy_from_slice(&ND6_INFINITE_LIFETIME.to_ne_bytes());
            r.0[124..128].copy_from_slice(&ND6_INFINITE_LIFETIME.to_ne_bytes());
            // SAFETY: SIOCAIFADDR_IN6 reads one `struct in6_aliasreq`, which `r` is (128
            // bytes, 8-aligned), alive across the call.
            cvt(unsafe { ffi::ioctl(s.as_raw_fd(), SIOCAIFADDR_IN6, &raw mut r) }).map(drop)
        }
    }
}

/// Removes `ip` from the interface.
#[cfg(target_os = "macos")]
pub fn if_del_addr(name: &str, ip: IpAddr, prefix: u8) -> io::Result<()> {
    check_prefix(ip, prefix)?;
    let n = name_bytes(name)?;
    match ip {
        IpAddr::V4(v4) => {
            let s = ctl_socket(ffi::AF_INET)?;
            let mut ifr = IfReq::new(name)?;
            put_sin_bsd(&mut ifr.u, v4.octets());
            ioctl_ifreq(&s, SIOCDIFADDR, &mut ifr)
        }
        IpAddr::V6(v6) => {
            let s = ctl_socket(ffi::AF_INET6)?;
            let mut r = In6IfReq([0; 288]);
            r.0[..16].copy_from_slice(&n);
            put_sin6_bsd(&mut r.0[16..44], v6.octets());
            // SAFETY: SIOCDIFADDR_IN6 reads one `struct in6_ifreq`, which `r` is (288 bytes,
            // 8-aligned), alive across the call.
            cvt(unsafe { ffi::ioctl(s.as_raw_fd(), SIOCDIFADDR_IN6, &raw mut r) }).map(drop)
        }
    }
}

/// The interface's index.
#[cfg(target_os = "macos")]
pub fn if_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c` is a valid NUL-terminated string.
    match unsafe { ffi::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}

/// Reads one packet into `buf`. Returns the range of `buf` it occupies: behind the 4-byte
/// address family header utun puts in front of every packet.
#[cfg(target_os = "macos")]
pub fn read_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let n = cvt_size(unsafe { ffi::read(fd, buf.as_mut_ptr().cast(), buf.len()) })?;
    Ok(4.min(n)..n)
}

/// Writes one IP packet, behind the 4-byte family header taken from its version nibble, with
/// one `writev` (the packet is not copied).
#[cfg(target_os = "macos")]
pub fn write_packet(fd: RawFd, pkt: &[u8]) -> io::Result<usize> {
    let family: u32 = match pkt.first().map(|b| b >> 4) {
        Some(6) => ffi::AF_INET6 as u32,
        _ => ffi::AF_INET as u32,
    };
    let hdr = family.to_be_bytes();
    let iov = [
        ffi::iovec {
            iov_base: hdr.as_ptr().cast_mut().cast(),
            iov_len: 4,
        },
        ffi::iovec {
            iov_base: pkt.as_ptr().cast_mut().cast(),
            iov_len: pkt.len(),
        },
    ];
    // SAFETY: both iovecs point to live buffers of the lengths given; writev only reads them.
    let n = cvt_size(unsafe { ffi::writev(fd, iov.as_ptr(), 2) })?;
    Ok(n.saturating_sub(4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(mask4(24), [255, 255, 255, 0]);
        assert_eq!(mask4(0), [0; 4]);
        assert_eq!(mask4(32), [255; 4]);
        assert_eq!(mask6(64)[..8], [255; 8]);
        assert_eq!(mask6(64)[8..], [0; 8]);
        assert_eq!(mask6(128), [255; 16]);
    }

    #[test]
    fn names() {
        assert!(name_bytes("").is_err());
        assert!(name_bytes("0123456789abcdef").is_err());
        assert!(name_bytes("a\0b").is_err());
        assert_eq!(name_from(&name_bytes("tun7").unwrap()), "tun7");
        assert!(check_prefix("10.0.0.1".parse().unwrap(), 33).is_err());
        assert!(check_prefix("::1".parse().unwrap(), 128).is_ok());
    }

    #[test]
    fn missing_interface_is_an_error() {
        assert!(if_mtu("akio-nope0").is_err());
        assert!(if_set_up("akio-nope0", true).is_err());
    }

    #[test]
    fn ifreq_fields() {
        let mut r = IfReq::new("x").unwrap();
        r.set_int(1280);
        assert_eq!(r.int(), 1280);
        r.set_short(0x1001);
        assert_eq!(r.short(), 0x1001);
    }
}
