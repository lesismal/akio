//! Datagram I/O with ECN codepoints (macOS): one datagram per `sendmsg` / `recvmsg`, the
//! codepoint (RFC 3168) carried in an `IP_TOS` / `IPV6_TCLASS` control message each way.
//!
//! The control messages are built and parsed as plain bytes (no pointer walking): only the two
//! system calls are `unsafe`. `ONLY_UDP_ECN=0` disables ECN, as on Linux.

use std::{
    io,
    net::SocketAddr,
    os::fd::RawFd,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::ffi::{
    self, IP_RECVTOS, IP_TOS, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVTCLASS, IPV6_TCLASS,
};
use crate::net::{parse_addr, sockaddr};

/// `CMSG_LEN(0)`: a `cmsghdr` rounded up to the 4-byte control message alignment.
pub(crate) const CMSG_HDR: usize = (size_of::<ffi::cmsghdr>() + 3) & !3;

/// Control buffer: room for a few control messages, 8-aligned.
#[repr(C, align(8))]
struct Ctrl([u8; 64]);

const UNKNOWN: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;
static ECN: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Whether datagrams may carry ECN codepoints (not disabled with `ONLY_UDP_ECN=0`).
pub fn ecn_available() -> bool {
    match ECN.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !std::env::var("ONLY_UDP_ECN")
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

/// Receives one datagram into `buf`: its length, sender and ECN codepoint (the low two bits of
/// the traffic class; 0 when not ECN-capable or not reported, see [`enable_ecn`]). A datagram
/// longer than `buf` is truncated, as `recv_from` does.
pub fn recv_from_ecn(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
    // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
    let mut ss: ffi::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut ctrl = Ctrl([0; 64]);
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
    Ok((n as usize, addr, ecn_of(&ctrl.0[..clen])))
}

/// The ECN codepoint in received control data: an `IP_TOS` / `IP_RECVTOS` message (one byte, or
/// an int) or an `IPV6_TCLASS` message (an int); 0 when there is none.
pub(crate) fn ecn_of(ctrl: &[u8]) -> u8 {
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
        let tos = (level == IPPROTO_IP && (ty == IP_TOS || ty == IP_RECVTOS))
            || (level == IPPROTO_IPV6 && ty == IPV6_TCLASS);
        if tos && !data.is_empty() {
            // A one-byte payload is the TOS byte itself; an int's low byte comes first (both
            // targets are little-endian).
            return data[0] & 3;
        }
        off += (len + 3) & !3;
    }
    0
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
    let mut ctrl = Ctrl([0; 64]);
    let clen = if ecn & 3 != 0 {
        let (level, ty) = if v6_socket {
            (IPPROTO_IPV6, IPV6_TCLASS)
        } else {
            (IPPROTO_IP, IP_TOS)
        };
        let len = CMSG_HDR + size_of::<ffi::c_int>();
        let c = &mut ctrl.0;
        c[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        c[4..8].copy_from_slice(&level.to_ne_bytes());
        c[8..12].copy_from_slice(&ty.to_ne_bytes());
        c[CMSG_HDR..len].copy_from_slice(&ffi::c_int::from(ecn & 3).to_ne_bytes());
        len
    } else {
        0
    };
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
    }
}
