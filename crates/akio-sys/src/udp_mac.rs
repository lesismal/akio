//! Datagram I/O with ECN codepoints (macOS): one datagram per `sendmsg` / `recvmsg`, the
//! codepoint (RFC 3168) carried in an `IP_TOS` / `IPV6_TCLASS` control message each way, and the
//! TTL / hop limit received when asked for ([`enable_recv_ttl`]) and, on IPv6 sockets, sent
//! (`IPV6_HOPLIMIT`: XNU ignores an `IP_TTL` control message on send); the arrival interface
//! received when asked for ([`enable_recv_interface`](crate::enable_recv_interface),
//! [`recv_from_info`]).
//!
//! The control messages are built and parsed as plain bytes (no pointer walking): only the two
//! system calls are `unsafe`. `AKIO_UDP_ECN=0` disables ECN, as on Linux.

use std::{
    io,
    net::SocketAddr,
    os::fd::RawFd,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::ffi::{
    self, IP_PKTINFO, IP_RECVTOS, IP_RECVTTL, IP_TOS, IP_TTL, IPPROTO_IP, IPPROTO_IPV6,
    IPV6_HOPLIMIT, IPV6_PKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS, IPV6_TCLASS,
};
use crate::net::{RecvInfo, parse_addr, sockaddr};

/// `CMSG_LEN(0)`: a `cmsghdr` rounded up to the 4-byte control message alignment.
pub(crate) const CMSG_HDR: usize = (size_of::<ffi::cmsghdr>() + 3) & !3;

/// Control buffer: room for a few control messages, 8-aligned (on receive: the traffic class
/// 16 bytes, the TTL 16 and an `in6_pktinfo` 32, with room to spare).
#[repr(C, align(8))]
struct Ctrl([u8; 128]);

const UNKNOWN: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;
static ECN: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Whether datagrams may carry ECN codepoints (not disabled with `AKIO_UDP_ECN=0`).
pub fn ecn_available() -> bool {
    match ECN.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !std::env::var("AKIO_UDP_ECN")
                .is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("off"));
            ECN.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}

/// Asks the kernel to report the ECN codepoint of every received datagram (`IP_RECVTOS`, and
/// `IPV6_RECVTCLASS` on an IPv6 socket); [`recv_from_ecn`] reads it. Returns whether it was
/// enabled.
pub fn enable_ecn(fd: RawFd) -> bool {
    if !ecn_available() {
        return false;
    }
    let one: ffi::c_int = 1;
    let set = |level, opt| {
        // SAFETY: `one` is a valid int for the duration of the call.
        unsafe {
            ffi::setsockopt(
                fd,
                level,
                opt,
                (&raw const one).cast(),
                size_of::<ffi::c_int>() as ffi::socklen_t,
            ) == 0
        }
    };
    let v4 = set(IPPROTO_IP, IP_RECVTOS);
    let v6 = set(IPPROTO_IPV6, IPV6_RECVTCLASS);
    v4 || v6
}

/// Asks the kernel to report the TTL (IPv4) or hop limit (IPv6) of every received datagram
/// (`IP_RECVTTL`, and `IPV6_RECVHOPLIMIT` on an IPv6 socket); [`recv_from_ip`] reads it.
/// Returns whether it was enabled.
pub fn enable_recv_ttl(fd: RawFd) -> bool {
    crate::net::set_both(
        fd,
        (IPPROTO_IP, IP_RECVTTL),
        (IPPROTO_IPV6, IPV6_RECVHOPLIMIT),
    )
}

/// Receives one datagram into `buf`: its length, sender and ECN codepoint (the low two bits of
/// the traffic class; 0 when not ECN-capable or not reported, see [`enable_ecn`]). A datagram
/// longer than `buf` is truncated, as `recv_from` does.
pub fn recv_from_ecn(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
    recv_from_tos(fd, buf).map(|(n, a, tos)| (n, a, tos & 3))
}

/// [`recv_from_ecn`] with the whole traffic class byte (DSCP in the upper six bits, ECN in the
/// low two; 0 when not reported).
pub fn recv_from_tos(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
    recv_from_ip(fd, buf).map(|(n, a, tos, _)| (n, a, tos))
}

/// [`recv_from_tos`] with the TTL (IPv4) or hop limit (IPv6) the datagram arrived with (0 when
/// not reported, see [`enable_recv_ttl`]): length, sender, traffic class byte, TTL.
pub fn recv_from_ip(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8, u8)> {
    recv_from_info(fd, buf).map(|(n, a, r)| (n, a, r.tos, r.ttl))
}

/// Receives one datagram into `buf`: its length, sender, and what the kernel reported with it
/// (traffic class, TTL, arrival interface: see [`RecvInfo`]). A datagram longer than `buf` is
/// truncated, as `recv_from` does.
pub fn recv_from_info(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, RecvInfo)> {
    // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
    let mut ss: ffi::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut ctrl = Ctrl([0; 128]);
    let mut iov = ffi::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg = ffi::msghdr {
        msg_name: (&raw mut ss).cast(),
        msg_namelen: size_of::<ffi::sockaddr_storage>() as ffi::socklen_t,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: ctrl.0.as_mut_ptr().cast(),
        msg_controllen: ctrl.0.len() as ffi::socklen_t,
        msg_flags: 0,
    };
    // SAFETY: every pointer in `msg` points into a live local (`ss`, `iov` -> `buf`, `ctrl`)
    // with the length given next to it; the kernel writes only within those lengths.
    let n = unsafe { ffi::recvmsg(fd, &raw mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let addr = parse_addr(&ss).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let clen = (msg.msg_controllen as usize).min(ctrl.0.len());
    let ctrl = &ctrl.0[..clen];
    Ok((n as usize, addr, info_of(ctrl)))
}

/// Everything [`RecvInfo`] holds, from received control data.
pub(crate) fn info_of(ctrl: &[u8]) -> RecvInfo {
    RecvInfo::new(tos_of(ctrl), ttl_of(ctrl), interface_of(ctrl))
}

/// The arrival interface in received control data: the `ipi_ifindex` of an `IP_PKTINFO`
/// message (`in_pktinfo`, 12 bytes, the index first) or the `ipi6_ifindex` of an
/// `IPV6_PKTINFO` one (`in6_pktinfo`, 20 bytes, the index last); 0 when there is none.
pub(crate) fn interface_of(ctrl: &[u8]) -> u32 {
    let word = |d: &[u8], at: usize| u32::from_ne_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    if let Some(d) = find_data(ctrl, |level, ty| level == IPPROTO_IP && ty == IP_PKTINFO) {
        if d.len() >= size_of::<ffi::in_pktinfo>() {
            return word(d, 0);
        }
    }
    if let Some(d) = find_data(ctrl, |level, ty| {
        level == IPPROTO_IPV6 && ty == IPV6_PKTINFO
    }) {
        if d.len() >= size_of::<ffi::in6_pktinfo>() {
            return word(d, 16);
        }
    }
    0
}

/// The ECN codepoint in received control data (see [`tos_of`]).
#[cfg(test)]
pub(crate) fn ecn_of(ctrl: &[u8]) -> u8 {
    tos_of(ctrl) & 3
}

/// The traffic class byte in received control data: an `IP_TOS` / `IP_RECVTOS` message (one
/// byte, or an int) or an `IPV6_TCLASS` message (an int); 0 when there is none.
pub(crate) fn tos_of(ctrl: &[u8]) -> u8 {
    find_byte(ctrl, |level, ty| {
        (level == IPPROTO_IP && (ty == IP_TOS || ty == IP_RECVTOS))
            || (level == IPPROTO_IPV6 && ty == IPV6_TCLASS)
    })
}

/// The TTL / hop limit in received control data: an `IP_RECVTTL` message (one byte; `IP_TTL`
/// accepted too) or an `IPV6_HOPLIMIT` message (an int); 0 when there is none.
pub(crate) fn ttl_of(ctrl: &[u8]) -> u8 {
    find_byte(ctrl, |level, ty| {
        (level == IPPROTO_IP && (ty == IP_RECVTTL || ty == IP_TTL))
            || (level == IPPROTO_IPV6 && ty == IPV6_HOPLIMIT)
    })
}

/// The first payload byte of the first control message `want(level, type)` accepts: a
/// one-byte payload is the value itself, an int's low byte comes first (both targets are
/// little-endian); 0 when there is none.
fn find_byte(ctrl: &[u8], want: impl Fn(ffi::c_int, ffi::c_int) -> bool) -> u8 {
    find_data(ctrl, want)
        .and_then(|d| d.first().copied())
        .unwrap_or(0)
}

/// The payload of the first control message `want(level, type)` accepts.
fn find_data(ctrl: &[u8], want: impl Fn(ffi::c_int, ffi::c_int) -> bool) -> Option<&[u8]> {
    let mut off = 0;
    while off + CMSG_HDR <= ctrl.len() {
        let word = |i: usize| {
            let b = &ctrl[off + i..off + i + 4];
            u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
        };
        let len = word(0) as usize;
        let (level, ty) = (word(4) as ffi::c_int, word(8) as ffi::c_int);
        if len < CMSG_HDR || off + len > ctrl.len() {
            break;
        }
        let data = &ctrl[off + CMSG_HDR..off + len];
        if want(level, ty) && !data.is_empty() {
            return Some(data);
        }
        off += (len + 3) & !3;
    }
    None
}

/// Sends `data` as one datagram to `dest` (`None`: the connected peer) with ECN codepoint `ecn`
/// (its low two bits; 0 sends no control message), through `IPV6_TCLASS` when `v6_socket` (the
/// socket is IPv6), else `IP_TOS`.
pub fn send_to_ecn(
    fd: RawFd,
    data: &[u8],
    dest: Option<&SocketAddr>,
    ecn: u8,
    v6_socket: bool,
) -> io::Result<usize> {
    send_to_tos(fd, data, dest, ecn & 3, v6_socket)
}

/// [`send_to_ecn`] with the whole traffic class byte `tos` (DSCP in the upper six bits, ECN in
/// the low two; 0 sends no control message).
pub fn send_to_tos(
    fd: RawFd,
    data: &[u8],
    dest: Option<&SocketAddr>,
    tos: u8,
    v6_socket: bool,
) -> io::Result<usize> {
    send_to_ip(fd, data, dest, tos, 0, v6_socket)
}

/// [`send_to_tos`] with the hop limit `ttl` on an IPv6 socket (`IPV6_HOPLIMIT` control
/// message; 0 sends none: the socket's). On an IPv4 socket `ttl` is not sent: XNU ignores an
/// `IP_TTL` control message, so the datagram has the socket's TTL either way.
pub fn send_to_ip(
    fd: RawFd,
    data: &[u8],
    dest: Option<&SocketAddr>,
    tos: u8,
    ttl: u8,
    v6_socket: bool,
) -> io::Result<usize> {
    let (mut ss, slen) = match dest {
        Some(d) => {
            // An IPv6 socket reaches an IPv4 peer at its IPv4-mapped address.
            let d = match (v6_socket, d) {
                (true, SocketAddr::V4(a)) => {
                    SocketAddr::new(a.ip().to_ipv6_mapped().into(), a.port())
                }
                _ => *d,
            };
            let (ss, len) = sockaddr(&d);
            (ss, len)
        }
        // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
        None => (unsafe { std::mem::zeroed() }, 0),
    };
    let mut ctrl = Ctrl([0; 128]);
    let level = if v6_socket { IPPROTO_IPV6 } else { IPPROTO_IP };
    let msgs = [
        (tos, if v6_socket { IPV6_TCLASS } else { IP_TOS }),
        (if v6_socket { ttl } else { 0 }, IPV6_HOPLIMIT),
    ];
    let mut clen = 0;
    for (v, ty) in msgs {
        if v == 0 {
            continue;
        }
        // Each message: header, an int, padded to 4 bytes (it already is).
        let len = CMSG_HDR + size_of::<ffi::c_int>();
        let c = &mut ctrl.0[clen..clen + len];
        c[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        c[4..8].copy_from_slice(&level.to_ne_bytes());
        c[8..12].copy_from_slice(&ty.to_ne_bytes());
        c[CMSG_HDR..len].copy_from_slice(&ffi::c_int::from(v).to_ne_bytes());
        clen += len;
    }
    let mut iov = ffi::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let msg = ffi::msghdr {
        msg_name: if slen == 0 {
            std::ptr::null_mut()
        } else {
            (&raw mut ss).cast()
        },
        msg_namelen: slen,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: if clen == 0 {
            std::ptr::null_mut()
        } else {
            ctrl.0.as_mut_ptr().cast()
        },
        msg_controllen: clen as ffi::socklen_t,
        msg_flags: 0,
    };
    // SAFETY: every pointer in `msg` points into a live local (`ss`, `iov` -> `data`, `ctrl`)
    // with the length given next to it, or is null with length 0; sendmsg only reads them.
    let n = unsafe { ffi::sendmsg(fd, &raw const msg, 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    fn pair(v6: bool) -> (UdpSocket, UdpSocket) {
        let ip = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        let rx = UdpSocket::bind(ip).expect("bind");
        let tx = UdpSocket::bind(ip).expect("bind");
        rx.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        (rx, tx)
    }

    #[test]
    fn ecn_codepoints_both_ways() {
        for v6 in [false, true] {
            let (rx, tx) = pair(v6);
            assert!(enable_ecn(rx.as_raw_fd()));
            let dest = rx.local_addr().expect("addr");
            for (i, ecn) in [2u8, 1, 3, 0].into_iter().enumerate() {
                let n = send_to_ecn(tx.as_raw_fd(), &[i as u8; 40], Some(&dest), ecn, v6)
                    .expect("send");
                assert_eq!(n, 40);
            }
            let mut buf = [0u8; 64];
            for (i, ecn) in [2u8, 1, 3, 0].into_iter().enumerate() {
                // Blocking read (the timeout bounds it).
                let (n, from, got) = recv_from_ecn(rx.as_raw_fd(), &mut buf).expect("recv");
                assert_eq!((n, buf[0]), (40, i as u8));
                assert_eq!(from, tx.local_addr().expect("addr"));
                assert_eq!(got, ecn, "v6={v6} datagram {i}");
            }
        }
    }

    #[test]
    fn connected_send_and_no_report_without_enable() {
        let (rx, tx) = pair(false);
        tx.connect(rx.local_addr().expect("addr")).expect("connect");
        assert_eq!(
            send_to_ecn(tx.as_raw_fd(), b"hi", None, 2, false).expect("send"),
            2
        );
        let mut buf = [0u8; 8];
        let (n, _, ecn) = recv_from_ecn(rx.as_raw_fd(), &mut buf).expect("recv");
        assert_eq!((n, ecn), (2, 0));
    }

    #[test]
    fn dual_stack_socket_to_ipv4_peer() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind");
        rx.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        assert!(enable_ecn(rx.as_raw_fd()));
        let Ok(tx) = UdpSocket::bind("[::]:0") else {
            return; // no IPv6
        };
        let dest = rx.local_addr().expect("addr");
        send_to_ecn(tx.as_raw_fd(), b"x", Some(&dest), 2, true).expect("send");
        let mut buf = [0u8; 8];
        let (n, from, ecn) = recv_from_ecn(rx.as_raw_fd(), &mut buf).expect("recv");
        assert_eq!((n, ecn), (1, 2));
        assert!(from.is_ipv4());
    }

    #[test]
    fn dual_stack_socket_from_ipv4_peer() {
        let Ok(rx) = UdpSocket::bind("[::]:0") else {
            return; // no IPv6
        };
        rx.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        assert!(enable_ecn(rx.as_raw_fd()));
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = rx.local_addr().expect("addr").port();
        let dest: SocketAddr = ([127, 0, 0, 1], port).into();
        send_to_ecn(tx.as_raw_fd(), b"y", Some(&dest), 2, false).expect("send");
        let mut buf = [0u8; 8];
        let (n, from, ecn) = recv_from_ecn(rx.as_raw_fd(), &mut buf).expect("recv");
        assert_eq!((n, ecn), (1, 2));
        assert_eq!(from, tx.local_addr().expect("addr"));
    }

    /// The TTL / hop limit read back once asked for; the hop limit sent on IPv6 (XNU ignores
    /// an IPv4 `IP_TTL` control message: the socket's 64 arrives).
    #[test]
    fn ttl_both_ways() {
        for v6 in [false, true] {
            let (rx, tx) = pair(v6);
            let dest = rx.local_addr().expect("addr");
            let mut buf = [0u8; 16];
            send_to_ip(tx.as_raw_fd(), b"a", Some(&dest), 0, 33, v6).expect("send");
            let (_, _, _, ttl) = recv_from_ip(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!(ttl, 0, "not asked for");
            assert!(enable_recv_ttl(rx.as_raw_fd()) && enable_ecn(rx.as_raw_fd()));
            send_to_ip(tx.as_raw_fd(), b"b", Some(&dest), 0xb8, 33, v6).expect("send");
            send_to_ip(tx.as_raw_fd(), b"c", Some(&dest), 0, 0, v6).expect("send");
            let (_, _, tos, ttl) = recv_from_ip(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!((tos, ttl), (0xb8, if v6 { 33 } else { 64 }), "v6={v6}");
            let (_, _, tos, ttl) = recv_from_ip(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!((tos, ttl), (0, 64), "v6={v6}");
        }
    }

    /// The loopback interface's index.
    fn lo_index() -> u32 {
        crate::interfaces()
            .expect("interfaces")
            .iter()
            .find(|i| i.flags.is_loopback())
            .expect("a loopback interface")
            .index
    }

    /// The arrival interface: 0 until asked for, then lo0 for both families and for an IPv4
    /// datagram on a dual-stack socket, next to the traffic class and TTL (the control buffer
    /// holds all three); 0 again once turned off.
    #[test]
    fn arrival_interface() {
        let lo = lo_index();
        for v6 in [false, true] {
            let (rx, tx) = pair(v6);
            let dest = rx.local_addr().expect("addr");
            let mut buf = [0u8; 16];
            send_to_ip(tx.as_raw_fd(), b"a", Some(&dest), 0, 0, v6).expect("send");
            let (_, _, r) = recv_from_info(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!(r.interface, 0, "v6={v6}: not asked for");
            assert!(crate::enable_recv_interface(rx.as_raw_fd(), true));
            assert!(enable_recv_ttl(rx.as_raw_fd()) && enable_ecn(rx.as_raw_fd()));
            send_to_ip(tx.as_raw_fd(), b"b", Some(&dest), 0xb8, 0, v6).expect("send");
            let (n, from, r) = recv_from_info(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!((n, from), (1, tx.local_addr().expect("addr")));
            assert_eq!(r, RecvInfo::new(0xb8, 64, lo), "v6={v6}");
            assert!(crate::enable_recv_interface(rx.as_raw_fd(), false));
            send_to_ip(tx.as_raw_fd(), b"c", Some(&dest), 0, 0, v6).expect("send");
            let (_, _, r) = recv_from_info(rx.as_raw_fd(), &mut buf).expect("recv");
            assert_eq!(r.interface, 0, "v6={v6}: turned off");
        }
        let Ok(rx) = UdpSocket::bind("[::]:0") else {
            return; // no IPv6
        };
        rx.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        assert!(crate::enable_recv_interface(rx.as_raw_fd(), true));
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dest: SocketAddr = ([127, 0, 0, 1], rx.local_addr().expect("addr").port()).into();
        tx.send_to(b"d", dest).expect("send");
        let mut buf = [0u8; 16];
        let (_, _, r) = recv_from_info(rx.as_raw_fd(), &mut buf).expect("recv");
        assert_eq!(r.interface, lo, "IPv4 on a dual-stack socket");
    }

    #[test]
    fn dont_fragment_toggles() {
        for v6 in [false, true] {
            let (_, tx) = pair(v6);
            let fd = tx.as_raw_fd();
            crate::set_dont_fragment(fd, v6, true).expect("on");
            if !v6 {
                assert!(crate::dont_fragment(fd).expect("get"));
            }
            crate::set_dont_fragment(fd, v6, false).expect("off");
            if !v6 {
                assert!(!crate::dont_fragment(fd).expect("get"));
            }
        }
    }

    #[test]
    fn control_parsing_is_bounded() {
        assert_eq!(ecn_of(&[]), 0);
        assert_eq!(ecn_of(&[0xff; 11]), 0);
        // A length past the end, and one shorter than a header.
        let mut c = [0u8; 16];
        c[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert_eq!(ecn_of(&c), 0);
        c[0..4].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(ecn_of(&c), 0);
        // An unrelated message, then an IP_RECVTOS byte.
        let mut c = [0u8; 32];
        c[0..4].copy_from_slice(&16u32.to_ne_bytes());
        c[4..8].copy_from_slice(&0xffffi32.to_ne_bytes());
        c[16..20].copy_from_slice(&13u32.to_ne_bytes());
        c[20..24].copy_from_slice(&IPPROTO_IP.to_ne_bytes());
        c[24..28].copy_from_slice(&IP_RECVTOS.to_ne_bytes());
        c[28] = 0b1011_1011;
        assert_eq!(ecn_of(&c), 3);
        assert_eq!(ttl_of(&c), 0);
        c[24..28].copy_from_slice(&IP_RECVTTL.to_ne_bytes());
        assert_eq!((ttl_of(&c), tos_of(&c)), (0b1011_1011, 0));
        assert_eq!(interface_of(&c), 0);
        // Packet info: too short is ignored; IPv4 has the index first, IPv6 last.
        let mut c = [0u8; 48];
        c[0..4].copy_from_slice(&(12u32 + 8).to_ne_bytes());
        c[4..8].copy_from_slice(&IPPROTO_IP.to_ne_bytes());
        c[8..12].copy_from_slice(&IP_PKTINFO.to_ne_bytes());
        c[12..16].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(interface_of(&c), 0, "8 bytes, not an in_pktinfo");
        c[0..4].copy_from_slice(&(12u32 + 12).to_ne_bytes());
        assert_eq!(interface_of(&c), 7);
        c[0..4].copy_from_slice(&(12u32 + 20).to_ne_bytes());
        c[4..8].copy_from_slice(&IPPROTO_IPV6.to_ne_bytes());
        c[8..12].copy_from_slice(&IPV6_PKTINFO.to_ne_bytes());
        c[28..32].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(interface_of(&c), 9);
        assert_eq!(info_of(&c), RecvInfo::new(0, 0, 9));
        c[0..4].copy_from_slice(&(12u32 + 60).to_ne_bytes());
        assert_eq!(interface_of(&c), 0, "past the end");
    }
}
