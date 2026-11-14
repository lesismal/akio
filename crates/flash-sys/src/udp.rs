//! Batched datagram I/O (Linux): `recvmmsg` with optional UDP GRO, `sendmmsg` with optional UDP
//! GSO (`UDP_SEGMENT`).
//!
//! GSO is detected once per process and turned off for good when the kernel or a device refuses
//! it (`EIO`/`EINVAL`, as quinn does); `FLASH_UDP_GSO=0` / `FLASH_UDP_GRO=0` disable either.

use std::{
    io,
    marker::PhantomData,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
    sync::atomic::{AtomicU8, Ordering},
};

const SOL_UDP: libc::c_int = 17;
const UDP_SEGMENT: libc::c_int = 103;
const UDP_GRO: libc::c_int = 104;

/// Most datagrams one GSO send may carry (the kernel's `UDP_MAX_SEGMENTS` is 64 before 6.x).
pub const MAX_GSO_SEGMENTS: usize = 64;
/// Most payload bytes one GSO send may carry (a UDP datagram's length field, minus headers).
pub const MAX_GSO_BYTES: usize = 65000;
/// Messages per `sendmmsg` call.
pub const SEND_BATCH: usize = 64;
const MAX_IOV: usize = 1024;

/// Space for one `cmsghdr` carrying an `int` (u16 for UDP_SEGMENT, int for UDP_GRO), 8-aligned.
type Ctrl = [u64; 4];

const UNKNOWN: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;
static GSO: AtomicU8 = AtomicU8::new(UNKNOWN);
static GRO: AtomicU8 = AtomicU8::new(UNKNOWN);

fn env_off(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("off"))
}

fn probe(opt: libc::c_int) -> bool {
    // SAFETY: plain syscalls on a socket we create and close here.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let mut v: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        let r = libc::getsockopt(fd, SOL_UDP, opt, (&raw mut v).cast(), &raw mut len);
        libc::close(fd);
        r == 0
    }
}

/// Whether sends may use UDP GSO (`UDP_SEGMENT`, Linux 4.18+).
pub fn gso_enabled() -> bool {
    match GSO.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !env_off("FLASH_UDP_GSO") && probe(UDP_SEGMENT);
            GSO.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}

/// Stops using GSO for the rest of the process (the kernel or a device refused it).
pub fn disable_gso() {
    GSO.store(OFF, Ordering::Relaxed);
}

/// Whether UDP GRO is available (Linux 5.0+) and not disabled with `FLASH_UDP_GRO=0`.
pub fn gro_available() -> bool {
    match GRO.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !env_off("FLASH_UDP_GRO") && probe(UDP_GRO);
            GRO.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}

/// Asks the kernel to coalesce received datagrams of one flow (UDP GRO, Linux 5.0+). A
/// [`RecvBatch`] made `with_gro` splits them again. Returns whether it was enabled.
pub fn enable_gro(fd: RawFd) -> bool {
    if !gro_available() {
        return false;
    }
    let one: libc::c_int = 1;
    // SAFETY: `one` is a valid int for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            (&raw const one).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    r == 0
}

/// Receives up to `slots` datagrams per syscall into pre-allocated buffers.
pub struct RecvBatch {
    bufs: Vec<u8>,
    size: usize,
    iov: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    ctrl: Vec<Ctrl>,
    gro: bool,
    msgs: Vec<libc::mmsghdr>,
    got: usize,
}

// SAFETY: the raw pointers inside `iov`/`msgs` point into the heap buffers owned by this same
// struct, which move with it; nothing is shared with another thread.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    /// `slots` datagrams of up to `size` bytes each (longer ones are truncated).
    pub fn new(slots: usize, size: usize) -> RecvBatch {
        Self::with_gro(slots, size, false)
    }

    /// As [`new`](Self::new); with `gro`, coalesced receives (see [`enable_gro`]) report their
    /// segment size through [`get`](Self::get). `size` should then be at least 64 KiB.
    pub fn with_gro(slots: usize, size: usize, gro: bool) -> RecvBatch {
        let mut b = RecvBatch {
            bufs: vec![0; slots * size],
            size,
            iov: Vec::with_capacity(slots),
            // SAFETY: sockaddr_storage and mmsghdr are plain-old-data; all-zero is valid.
            names: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            ctrl: vec![[0; 4]; if gro { slots } else { 0 }],
            gro,
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
            h.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &raw mut self.iov[i];
            h.msg_iovlen = 1;
            if self.gro {
                h.msg_control = (&raw mut self.ctrl[i]).cast();
                h.msg_controllen = size_of::<Ctrl>() as _;
            } else {
                h.msg_control = std::ptr::null_mut();
                h.msg_controllen = 0;
            }
            h.msg_flags = 0;
            self.msgs[i].msg_len = 0;
        }
    }

    /// One `recvmmsg` call. Returns how many datagrams arrived (0 = nothing ready).
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.reset();
        // SAFETY: `msgs` holds `msgs.len()` initialised headers whose name/iov/control pointers
        // refer to buffers owned by `self` that are live for the duration of the call.
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

    /// Datagram `i` of the last `recv` and its sender. The last element is the GRO segment size
    /// when the kernel coalesced several datagrams into this one (split it into pieces of that
    /// size, the last possibly shorter), else 0.
    pub fn get(&self, i: usize) -> Option<(&[u8], SocketAddr, usize)> {
        if i >= self.got {
            return None;
        }
        let len = (self.msgs[i].msg_len as usize).min(self.size);
        let data = &self.bufs[i * self.size..i * self.size + len];
        Some((data, parse_addr(&self.names[i])?, self.gro_size(i)))
    }

    fn gro_size(&self, i: usize) -> usize {
        if !self.gro {
            return 0;
        }
        let h = &self.msgs[i].msg_hdr;
        // SAFETY: `h` is a header the kernel filled in; the CMSG_* macros only walk within
        // `msg_control[..msg_controllen]`, which points into `self.ctrl[i]`.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(h);
            while !c.is_null() {
                if (*c).cmsg_level == SOL_UDP && (*c).cmsg_type == UDP_GRO {
                    let v = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>());
                    return v.max(0) as usize;
                }
                c = libc::CMSG_NXTHDR(h, c);
            }
        }
        0
    }
}

#[derive(Clone, Copy)]
struct Meta {
    iov_start: usize,
    iov_len: usize,
    namelen: libc::socklen_t,
    gso: u16,
}

/// Reusable storage for `sendmmsg` batches; fill one with [`SendBatch::batch`].
pub struct SendBatch {
    iov: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    ctrl: Vec<Ctrl>,
    meta: Vec<Meta>,
    msgs: Vec<libc::mmsghdr>,
}

// SAFETY: between batches the raw pointers are dangling but never dereferenced; a `Batch` (which
// borrows the data they point to) is needed to send.
unsafe impl Send for SendBatch {}

impl Default for SendBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl SendBatch {
    /// Room for [`SEND_BATCH`] messages.
    pub fn new() -> SendBatch {
        SendBatch {
            iov: Vec::with_capacity(MAX_IOV),
            // SAFETY: plain-old-data; all-zero is valid.
            names: (0..SEND_BATCH).map(|_| unsafe { mem::zeroed() }).collect(),
            ctrl: vec![[0; 4]; SEND_BATCH],
            meta: Vec::with_capacity(SEND_BATCH),
            // SAFETY: as above.
            msgs: (0..SEND_BATCH).map(|_| unsafe { mem::zeroed() }).collect(),
        }
    }

    /// Starts an empty batch borrowing data for `'d`.
    pub fn batch<'d>(&mut self) -> Batch<'_, 'd> {
        self.iov.clear();
        self.meta.clear();
        Batch {
            s: self,
            _d: PhantomData,
        }
    }
}

/// Messages being collected for one `sendmmsg` (see [`SendBatch::batch`]).
pub struct Batch<'s, 'd> {
    s: &'s mut SendBatch,
    _d: PhantomData<&'d [u8]>,
}

impl<'d> Batch<'_, 'd> {
    /// Messages collected so far.
    pub fn len(&self) -> usize {
        self.s.meta.len()
    }

    /// No message yet.
    pub fn is_empty(&self) -> bool {
        self.s.meta.is_empty()
    }

    /// Adds one message: the datagram made of `parts` to `dest` (`None` on a connected socket),
    /// or, with `gso = n > 0`, the datagrams of `n` bytes each (the last may be shorter) that
    /// `parts` concatenate. Returns `false` (adding nothing) when the batch is full.
    pub fn push(&mut self, dest: Option<&SocketAddr>, parts: &[&'d [u8]], gso: usize) -> bool {
        let s = &mut *self.s;
        let i = s.meta.len();
        if i == SEND_BATCH || s.iov.len() + parts.len() > MAX_IOV {
            return false;
        }
        let iov_start = s.iov.len();
        for p in parts {
            s.iov.push(libc::iovec {
                iov_base: p.as_ptr() as *mut libc::c_void,
                iov_len: p.len(),
            });
        }
        let namelen = match dest {
            Some(a) => {
                let (ss, len) = crate::net::sockaddr(a);
                s.names[i] = ss;
                len
            }
            None => 0,
        };
        s.meta.push(Meta {
            iov_start,
            iov_len: parts.len(),
            namelen,
            gso: gso.min(u16::MAX as usize) as u16,
        });
        true
    }

    /// Whether message `i` uses GSO.
    pub fn is_gso(&self, i: usize) -> bool {
        self.s.meta.get(i).is_some_and(|m| m.gso > 0)
    }

    /// One `sendmmsg` of the messages from `from` on. Returns how many were sent; an error
    /// concerns message `from` (it was not sent).
    pub fn send(&mut self, fd: RawFd, from: usize) -> io::Result<usize> {
        let s = &mut *self.s;
        let n = s.meta.len();
        if from >= n {
            return Ok(0);
        }
        for i in from..n {
            let m = s.meta[i];
            let h = &mut s.msgs[i].msg_hdr;
            // SAFETY: zeroing a plain-old-data header before filling it in.
            *h = unsafe { mem::zeroed() };
            if m.namelen > 0 {
                h.msg_name = (&raw mut s.names[i]).cast();
                h.msg_namelen = m.namelen;
            }
            h.msg_iov = s.iov[m.iov_start..].as_mut_ptr();
            h.msg_iovlen = m.iov_len as _;
            if m.gso > 0 {
                h.msg_control = (&raw mut s.ctrl[i]).cast();
                // SAFETY: CMSG_SPACE is a pure size computation.
                h.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as _;
                // SAFETY: `msg_control` points to `ctrl[i]` (32 bytes, 8-aligned), large enough
                // for one cmsghdr with a u16 payload as computed by CMSG_SPACE above.
                unsafe {
                    let c = libc::CMSG_FIRSTHDR(h);
                    (*c).cmsg_level = SOL_UDP;
                    (*c).cmsg_type = UDP_SEGMENT;
                    (*c).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as _;
                    std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<u16>(), m.gso);
                }
            }
            s.msgs[i].msg_len = 0;
        }
        // SAFETY: headers `from..n` are initialised; their name/iov/control pointers refer to
        // `s`'s buffers and to the data borrowed for `'d`, all live for the call.
        let r = unsafe {
            libc::sendmmsg(
                fd,
                s.msgs[from..].as_mut_ptr(),
                (n - from) as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }
}

fn parse_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(ss.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the kernel stored a sockaddr_in here.
            let a = unsafe { &*std::ptr::from_ref(ss).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the kernel stored a sockaddr_in6 here.
            let a = unsafe { &*std::ptr::from_ref(ss).cast::<libc::sockaddr_in6>() };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, os::fd::AsRawFd};

    #[test]
    fn sendmmsg_gso_then_gro_split() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let gro = enable_gro(rx.as_raw_fd());
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        let a = [1u8; 100];
        let b = [2u8; 100];
        let c = [3u8; 40];
        let mut sb = SendBatch::new();
        let mut batch = sb.batch();
        let gso = if gso_enabled() { 100 } else { 0 };
        if gso > 0 {
            assert!(batch.push(Some(&dest), &[&a, &b, &c], gso));
        } else {
            for p in [&a[..], &b[..], &c[..]] {
                assert!(batch.push(Some(&dest), &[p], 0));
            }
        }
        let n = batch.len();
        eprintln!("gso={gso} gro={gro} messages={n}");
        assert_eq!(batch.send(tx.as_raw_fd(), 0).unwrap(), n);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut rb = RecvBatch::with_gro(8, 65536, gro);
        let mut got = Vec::new();
        loop {
            let k = rb.recv(rx.as_raw_fd()).unwrap();
            if k == 0 {
                break;
            }
            for i in 0..k {
                let (d, from, seg) = rb.get(i).unwrap();
                assert_eq!(from, tx.local_addr().unwrap());
                if seg > 0 {
                    got.extend(d.chunks(seg).map(|x| x.to_vec()));
                } else {
                    got.push(d.to_vec());
                }
            }
        }
        assert_eq!(got, vec![a.to_vec(), b.to_vec(), c.to_vec()]);
    }
}
