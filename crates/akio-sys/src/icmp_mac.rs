//! ICMP errors of unconnected UDP sockets on macOS, which has no `IP_RECVERR`: an unprivileged
//! ICMP socket (`SOCK_DGRAM`, `IPPROTO_ICMP` / `IPPROTO_ICMPV6`, what `ping` uses) receives a
//! copy of every ICMP message the host gets, errors about other sockets' datagrams included.
//! The caller matches each one to its own sockets by the quoted datagram's source address and
//! port ([`IcmpPacket::source`]).
//!
//! Every such socket gets every message, so a process opens as few as it can (one per address
//! family and event loop) and drops what is not about its sockets. Anyone who can reach the
//! host can send ICMP errors naming any address and port: the quoted datagram is the only
//! check, as it is for the kernel's own matching on Linux.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use crate::ffi::{self, AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, SOCK_DGRAM};
use crate::icmp_packet::{IcmpPacket, parse_icmp_error};
use crate::net::parse_addr;

/// A non-blocking ICMP (or ICMPv6) socket reading the ICMP errors of the host's UDP datagrams.
#[derive(Debug)]
pub struct IcmpListener {
    fd: OwnedFd,
    v6: bool,
}

impl IcmpListener {
    /// Opens one for ICMPv6 (`v6`) or ICMPv4. Needs no privileges.
    pub fn open(v6: bool) -> io::Result<IcmpListener> {
        let (domain, proto) = if v6 {
            (AF_INET6, IPPROTO_ICMPV6)
        } else {
            (AF_INET, IPPROTO_ICMP)
        };
        // SAFETY: plain syscall with valid constant arguments.
        let fd = unsafe { ffi::socket(domain, SOCK_DGRAM, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created by socket(2) and is owned by no one else. Owning it
        // before the fcntl calls closes it if they fail.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        crate::poller::set_nonblock_cloexec(fd.as_raw_fd())?;
        Ok(IcmpListener { fd, v6 })
    }

    /// For ICMPv6 (else ICMPv4).
    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// The next ICMP error about a UDP datagram, and who sent it; other ICMP messages are
    /// skipped. `Ok(None)` once nothing is left to read.
    pub fn recv(&self) -> io::Result<Option<(IcmpPacket, IpAddr)>> {
        let mut buf = [0u8; 576];
        loop {
            // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
            let mut ss: ffi::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut iov = ffi::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut msg = ffi::msghdr {
                msg_name: (&raw mut ss).cast(),
                msg_namelen: size_of::<ffi::sockaddr_storage>() as ffi::socklen_t,
                msg_iov: &raw mut iov,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            // SAFETY: every pointer in `msg` points into a live local (`ss`, `iov` -> `buf`)
            // with the length given next to it; the kernel writes only within those lengths.
            let n = unsafe { ffi::recvmsg(self.fd.as_raw_fd(), &raw mut msg, 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(None),
                    _ => return Err(e),
                }
            }
            let data = &buf[..(n as usize).min(buf.len())];
            let (Some(p), Some(from)) = (parse_icmp_error(data, self.v6), parse_addr(&ss)) else {
                continue;
            };
            return Ok(Some((p, from.ip())));
        }
    }
}

impl AsRawFd for IcmpListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Whether `source` (an [`IcmpPacket::source`]) is a datagram of the socket bound at `local`:
/// the same port and family, and the same address unless the socket is bound to the
/// unspecified one.
pub fn icmp_source_matches(local: SocketAddr, source: SocketAddr) -> bool {
    local.port() == source.port()
        && local.is_ipv6() == source.is_ipv6()
        && (local.ip().is_unspecified() || local.ip() == source.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    /// Port unreachable for a datagram to a closed loopback port, read from the ICMP socket
    /// and matched to the sender by its quoted address.
    #[test]
    fn port_unreachable_on_loopback() {
        for (v6, ip) in [(false, "127.0.0.1"), (true, "::1")] {
            let l = IcmpListener::open(v6).expect("icmp socket");
            let Ok(u) = UdpSocket::bind(SocketAddr::new(ip.parse().expect("ip"), 0)) else {
                continue;
            };
            // A closed port: bind one, note it, close it.
            let closed = UdpSocket::bind(SocketAddr::new(ip.parse().expect("ip"), 0))
                .expect("bind")
                .local_addr()
                .expect("addr");
            u.send_to(b"ping", closed).expect("send");
            let local = u.local_addr().expect("addr");
            let end = Instant::now() + Duration::from_secs(3);
            let got = loop {
                match l.recv().expect("recv") {
                    Some((p, _)) if icmp_source_matches(local, p.source) => break Some(p),
                    Some(_) => {}
                    None if Instant::now() > end => break None,
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            };
            let p = got.expect("no ICMP error read");
            assert_eq!(p.dest, closed);
            assert_eq!((p.v6, p.icmp_type), (v6, if v6 { 1 } else { 3 }));
            assert_eq!(p.code, if v6 { 4 } else { 3 });
        }
    }

    #[test]
    fn source_matching() {
        let a = |s: &str| s.parse::<SocketAddr>().expect("addr");
        assert!(icmp_source_matches(a("0.0.0.0:5000"), a("10.0.0.1:5000")));
        assert!(icmp_source_matches(a("10.0.0.1:5000"), a("10.0.0.1:5000")));
        assert!(!icmp_source_matches(a("10.0.0.2:5000"), a("10.0.0.1:5000")));
        assert!(!icmp_source_matches(a("0.0.0.0:5001"), a("10.0.0.1:5000")));
        assert!(!icmp_source_matches(a("[::]:5000"), a("10.0.0.1:5000")));
        assert!(icmp_source_matches(a("[::]:5000"), a("[::1]:5000")));
    }
}
