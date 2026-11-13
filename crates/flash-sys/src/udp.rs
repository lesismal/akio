//! Batched datagram receive (`recvmmsg`, Linux).

use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
};

/// Receives up to `slots` datagrams per syscall into pre-allocated buffers.
pub struct RecvBatch {
    bufs: Vec<u8>,
    size: usize,
    iov: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    msgs: Vec<libc::mmsghdr>,
    got: usize,
}

// SAFETY: the raw pointers inside `iov`/`msgs` point into the heap buffers owned by this same
// struct, which move with it; nothing is shared with another thread.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    /// `slots` datagrams of up to `size` bytes each (longer ones are truncated).
    pub fn new(slots: usize, size: usize) -> RecvBatch {
        let mut b = RecvBatch {
            bufs: vec![0; slots * size],
            size,
            iov: Vec::with_capacity(slots),
            // SAFETY: sockaddr_storage and mmsghdr are plain-old-data; all-zero is valid.
            names: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            // SAFETY: as above.
            msgs: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            got: 0,
        };
        for i in 0..slots {
            b.iov.push(libc::iovec {
                iov_base: b.bufs[i * size..].as_mut_ptr().cast(),
                iov_len: size,
            });
        }
        b
    }

    fn reset(&mut self) {
        for i in 0..self.msgs.len() {
            let h = &mut self.msgs[i].msg_hdr;
            h.msg_name = (&raw mut self.names[i]).cast();
            h.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &raw mut self.iov[i];
            h.msg_iovlen = 1;
            h.msg_control = std::ptr::null_mut();
            h.msg_controllen = 0;
            h.msg_flags = 0;
            self.msgs[i].msg_len = 0;
        }
    }

    /// One `recvmmsg` call. Returns how many datagrams arrived (0 = nothing ready).
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.reset();
        // SAFETY: `msgs` holds `msgs.len()` initialised headers whose name/iov pointers refer to
        // buffers owned by `self` that are live for the duration of the call.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(e)
            };
        }
        self.got = n as usize;
        Ok(self.got)
    }

    /// Datagram `i` of the last `recv`, and its sender.
    pub fn get(&self, i: usize) -> Option<(&[u8], SocketAddr)> {
        if i >= self.got {
            return None;
        }
        let len = (self.msgs[i].msg_len as usize).min(self.size);
        let data = &self.bufs[i * self.size..i * self.size + len];
        Some((data, parse_addr(&self.names[i])?))
    }
}

fn parse_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: the family says the kernel stored a sockaddr_in here.
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the kernel stored a sockaddr_in6 here.
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
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
