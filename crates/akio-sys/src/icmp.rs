//! ICMP errors of unconnected UDP sockets (Linux `IP_RECVERR` / `IPV6_RECVERR`).
//!
//! Without `IP_RECVERR` Linux drops the ICMP errors (port unreachable, time exceeded, ...) that
//! answer datagrams an unconnected socket sent. With it, each one is queued on the socket's
//! error queue, read with `recvmsg(MSG_ERRQUEUE)`: the address the datagram was sent to (port
//! included, no privileges needed), the ICMP type and code, and who sent the error. Two side
//! effects the caller has to live with:
//!
//! - the socket polls readable-with-error (`EPOLLERR`, level-triggered) until its error queue
//!   is drained: [`recv_icmp`] until it returns `Ok(None)`;
//! - the error is also left as the socket's pending error, which the next `recvmsg` or
//!   `sendmsg` on it returns once (`ECONNREFUSED`, `EHOSTUNREACH`, ...) instead of doing its
//!   work: see [`is_icmp_error`].

use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::RawFd,
};

use crate::ffi::{
    self, IP_RECVERR, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVERR, MSG_DONTWAIT, MSG_ERRQUEUE,
    SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6,
};
use crate::net::parse_addr;

/// An ICMP error about a datagram a UDP socket sent (see [`enable_recverr`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IcmpReport {
    /// Where the datagram that drew the error was going (address and port).
    pub dest: SocketAddr,
    /// Who sent the ICMP message (a router on the way, or `dest`'s host), when known.
    pub from: Option<IpAddr>,
    /// An ICMPv6 message (else ICMPv4).
    pub v6: bool,
    /// The ICMP type.
    pub icmp_type: u8,
    /// The ICMP code.
    pub code: u8,
    /// The kernel's `ee_info`: the next-hop MTU of an ICMPv4 "fragmentation needed" or ICMPv6
    /// "packet too big", else 0.
    pub info: u32,
}

/// Asks the kernel to queue the ICMP errors of datagrams `fd` (a UDP socket) sends
/// (`IP_RECVERR`, and `IPV6_RECVERR` on an IPv6 socket); [`recv_icmp`] reads them. Returns
/// whether it was enabled.
pub fn enable_recverr(fd: RawFd) -> bool {
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
    // An IPv4 socket refuses the IPv6 option; an IPv6 one takes both (the IPv4 one covers
    // IPv4-mapped peers).
    let v4 = set(IPPROTO_IP, IP_RECVERR);
    let v6 = set(IPPROTO_IPV6, IPV6_RECVERR);
    v4 || v6
}

/// Whether `e` is what a socket with `IP_RECVERR` returns once from a `recvmsg` or `sendmsg`
/// after an ICMP error arrived (its pending error): the call did nothing and may be retried.
pub fn is_icmp_error(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            ffi::ECONNREFUSED
                | ffi::EHOSTUNREACH
                | ffi::ENETUNREACH
                | ffi::EHOSTDOWN
                | ffi::ENETDOWN
                | ffi::EPROTO
                | ffi::EMSGSIZE
                | ffi::ENOPROTOOPT
                | ffi::EOPNOTSUPP
        )
    )
}

/// Control buffer for one `IP_RECVERR` message: a `cmsghdr`, a `sock_extended_err` and the
/// offender's `sockaddr_in6`, 8-aligned.
type Ctrl = [u64; 16];

/// `struct sock_extended_err`: errno (4), origin, type, code, pad (1 each), info (4), data (4).
const EE_LEN: usize = 16;

/// Reads the next ICMP error from `fd`'s error queue, skipping errors of local origin. `Ok(None)`
/// once the queue is empty.
pub fn recv_icmp(fd: RawFd) -> io::Result<Option<IcmpReport>> {
    loop {
        // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
        let mut ss: ffi::sockaddr_storage = unsafe { mem::zeroed() };
        let mut ctrl: Ctrl = [0; 16];
        // The original datagram's payload is not wanted: a few bytes, truncated.
        let mut buf = [0u8; 8];
        let mut iov = ffi::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: a zeroed msghdr is a valid empty one; its fields are filled in below.
        let mut h: ffi::msghdr = unsafe { mem::zeroed() };
        h.msg_name = (&raw mut ss).cast();
        h.msg_namelen = size_of::<ffi::sockaddr_storage>() as ffi::socklen_t;
        h.msg_iov = &raw mut iov;
        h.msg_iovlen = 1;
        h.msg_control = (&raw mut ctrl).cast();
        h.msg_controllen = size_of::<Ctrl>() as _;
        // SAFETY: every pointer in `h` points into a live local (`ss`, `iov` -> `buf`, `ctrl`)
        // with the length given next to it; the kernel writes only within those lengths.
        let n = unsafe { ffi::recvmsg(fd, &raw mut h, MSG_ERRQUEUE | MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(None),
                _ => return Err(e),
            }
        }
        let Some(dest) = parse_addr(&ss) else {
            continue;
        };
        // SAFETY: `h` is a header the kernel filled in; the CMSG_* helpers only walk within
        // `msg_control[..msg_controllen]`, which points into `ctrl`, and a payload is read only
        // within the `cmsg_len` the kernel wrote.
        let ee = unsafe {
            let mut c = ffi::cmsg_firsthdr(&raw const h);
            let mut found = None;
            while !c.is_null() {
                let (level, ty) = ((*c).cmsg_level, (*c).cmsg_type);
                if (level == IPPROTO_IP && ty == IP_RECVERR)
                    || (level == IPPROTO_IPV6 && ty == IPV6_RECVERR)
                {
                    let len = ((*c).cmsg_len as usize).saturating_sub(ffi::cmsg_len(0));
                    let data = std::slice::from_raw_parts(ffi::cmsg_data(c), len);
                    found = Some(data.to_vec());
                    break;
                }
                c = ffi::cmsg_nxthdr(&raw const h, c);
            }
            found
        };
        let Some(ee) = ee.filter(|e| e.len() >= EE_LEN) else {
            continue;
        };
        let origin = ee[4];
        if origin != SO_EE_ORIGIN_ICMP && origin != SO_EE_ORIGIN_ICMP6 {
            continue;
        }
        return Ok(Some(IcmpReport {
            dest,
            from: offender(&ee[EE_LEN..]),
            v6: origin == SO_EE_ORIGIN_ICMP6,
            icmp_type: ee[5],
            code: ee[6],
            info: u32::from_ne_bytes([ee[8], ee[9], ee[10], ee[11]]),
        }));
    }
}

/// The `SO_EE_OFFENDER` address after a `sock_extended_err`: a `sockaddr_in` or `sockaddr_in6`
/// (family `AF_UNSPEC` when unknown).
fn offender(sa: &[u8]) -> Option<IpAddr> {
    let family = ffi::c_int::from(u16::from_ne_bytes([*sa.first()?, *sa.get(1)?]));
    let ip = match family {
        ffi::AF_INET => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(sa.get(4..8)?).ok()?)),
        ffi::AF_INET6 => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(sa.get(8..24)?).ok()?);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};

    /// A port nobody listens on, answered on loopback with ICMP port unreachable.
    fn closed_port(ip: IpAddr) -> SocketAddr {
        let s = UdpSocket::bind(SocketAddr::new(ip, 0)).expect("bind");
        s.local_addr().expect("addr")
    }

    fn wait_icmp(fd: RawFd) -> IcmpReport {
        for _ in 0..200 {
            if let Some(r) = recv_icmp(fd).expect("recv_icmp") {
                return r;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("no ICMP error queued");
    }

    #[test]
    fn port_unreachable_is_queued() {
        for ip in [
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from(Ipv6Addr::LOCALHOST),
        ] {
            let Ok(s) = UdpSocket::bind(SocketAddr::new(ip, 0)) else {
                continue; // no IPv6 here
            };
            s.set_nonblocking(true).expect("nonblocking");
            assert!(enable_recverr(s.as_raw_fd()));
            assert_eq!(recv_icmp(s.as_raw_fd()).expect("empty"), None);
            let dest = closed_port(ip);
            s.send_to(b"x", dest).expect("send");
            let r = wait_icmp(s.as_raw_fd());
            assert_eq!(r.dest, dest);
            assert_eq!(r.from, Some(ip));
            assert_eq!(r.v6, ip.is_ipv6());
            // Destination unreachable, port unreachable (ICMPv4 3/3, ICMPv6 1/4).
            assert_eq!((r.icmp_type, r.code), if r.v6 { (1, 4) } else { (3, 3) });
            assert_eq!(recv_icmp(s.as_raw_fd()).expect("drained"), None);
            // The pending error goes with the first call that reports it.
            let mut b = [0u8; 4];
            match s.recv_from(&mut b) {
                Err(e) if is_icmp_error(&e) => {}
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
                Ok(_) => panic!("unexpected datagram"),
            }
            assert_eq!(
                s.recv_from(&mut b).map_err(|e| e.kind()).err(),
                Some(io::ErrorKind::WouldBlock)
            );
        }
    }
}
