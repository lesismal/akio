//! Batched datagram I/O (Linux): `recvmmsg` with optional UDP GRO, `sendmmsg` with optional UDP
//! GSO (`UDP_SEGMENT`), and the ECN codepoint of each datagram (RFC 3168) both ways: received
//! from the `IP_TOS` / `IPV6_TCLASS` control message ([`enable_ecn`]), sent as one per message.
//!
//! GSO is detected once per process and turned off for good when the kernel or a device refuses
//! it (`EIO`/`EINVAL`, as quinn does); `ONLY_UDP_GSO=0` / `ONLY_UDP_GRO=0` / `ONLY_UDP_ECN=0`
//! disable GSO, GRO or ECN.

use std::{
    io,
    marker::PhantomData,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::ffi::{
    self, IP_RECVTOS, IP_TOS, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVTCLASS, IPV6_TCLASS, SOL_UDP,
    UDP_GRO, UDP_SEGMENT,
};

/// Most datagrams one GSO send may carry (the kernel's `UDP_MAX_SEGMENTS` is 64 before 6.x).
pub const MAX_GSO_SEGMENTS: usize = 64;
/// Most payload bytes one GSO send may carry (a UDP datagram's length field, minus headers).
pub const MAX_GSO_BYTES: usize = 65000;
/// Messages per `sendmmsg` call.
pub const SEND_BATCH: usize = 64;
const MAX_IOV: usize = 1024;

/// Space for two `cmsghdr`s carrying an `int` each (u16 for UDP_SEGMENT, int for UDP_GRO, a byte
/// or an int for the traffic class), 8-aligned.
type Ctrl = [u64; 8];

const UNKNOWN: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;
static GSO: AtomicU8 = AtomicU8::new(UNKNOWN);
static GRO: AtomicU8 = AtomicU8::new(UNKNOWN);
static ECN: AtomicU8 = AtomicU8::new(UNKNOWN);

fn env_off(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("off"))
}

fn probe(opt: ffi::c_int) -> bool {
    // SAFETY: plain syscalls on a socket we create and close here.
    unsafe {
        let fd = ffi::socket(ffi::AF_INET, ffi::SOCK_DGRAM | ffi::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let mut v: ffi::c_int = 0;
        let mut len = size_of::<ffi::c_int>() as ffi::socklen_t;
        let r = ffi::getsockopt(fd, SOL_UDP, opt, (&raw mut v).cast(), &raw mut len);
        ffi::close(fd);
        r == 0
    }
}

/// Whether sends may use UDP GSO (`UDP_SEGMENT`, Linux 4.18+).
pub fn gso_enabled() -> bool {
    match GSO.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !env_off("ONLY_UDP_GSO") && probe(UDP_SEGMENT);
            GSO.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}

/// Stops using GSO for the rest of the process (the kernel or a device refused it).
pub fn disable_gso() {
    GSO.store(OFF, Ordering::Relaxed);
}

/// Whether UDP GRO is available (Linux 5.0+) and not disabled with `ONLY_UDP_GRO=0`.
pub fn gro_available() -> bool {
    match GRO.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !env_off("ONLY_UDP_GRO") && probe(UDP_GRO);
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
    let one: ffi::c_int = 1;
    // SAFETY: `one` is a valid int for the duration of the call.
    let r = unsafe {
        ffi::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            (&raw const one).cast(),
            size_of::<ffi::c_int>() as ffi::socklen_t,
        )
    };
    r == 0
}

/// Whether datagrams may carry ECN codepoints (not disabled with `ONLY_UDP_ECN=0`).
pub fn ecn_available() -> bool {
    match ECN.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            let on = !env_off("ONLY_UDP_ECN");
            ECN.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}

/// Asks the kernel to report the ECN codepoint of every received datagram (`IP_RECVTOS`, and
/// `IPV6_RECVTCLASS` on an IPv6 socket); [`RecvBatch::ecn`] reads it. Returns whether it was
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
    // An IPv4 socket refuses the IPv6 option; an IPv6 one takes both (the IPv4 one covers
    // IPv4-mapped peers).
    let v4 = set(IPPROTO_IP, IP_RECVTOS);
    let v6 = set(IPPROTO_IPV6, IPV6_RECVTCLASS);
    v4 || v6
}

/// Receives up to `slots` datagrams per syscall into pre-allocated buffers.
pub struct RecvBatch {
    bufs: Vec<u8>,
    size: usize,
    iov: Vec<ffi::iovec>,
    names: Vec<ffi::sockaddr_storage>,
    ctrl: Vec<Ctrl>,
    gro: bool,
    msgs: Vec<ffi::mmsghdr>,
    got: usize,
}

impl std::fmt::Debug for RecvBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvBatch").finish_non_exhaustive()
    }
}

// SAFETY: the raw pointers inside `iov`/`msgs` point into the heap buffers owned by this same
// struct, which move with it; nothing is shared with another thread.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    /// `slots` datagrams of up to `size` bytes each (longer ones are truncated).
    ///
    /// # Panics
    ///
    /// If `slots * size` overflows `usize` or `slots` exceeds `u32::MAX`.
    pub fn new(slots: usize, size: usize) -> RecvBatch {
        Self::with_gro(slots, size, false)
    }

    /// As [`new`](Self::new); with `gro`, coalesced receives (see [`enable_gro`]) report their
    /// segment size through [`get`](Self::get). `size` should then be at least 64 KiB.
    pub fn with_gro(slots: usize, size: usize, gro: bool) -> RecvBatch {
        // An unchecked product could wrap in release builds and leave iovecs that claim more
        // memory than `bufs` holds, letting the kernel write past the allocation.
        let total = slots
            .checked_mul(size)
            .expect("RecvBatch: slots * size overflows usize");
        assert!(
            u32::try_from(slots).is_ok(),
            "RecvBatch: too many slots for recvmmsg"
        );
        let mut b = RecvBatch {
            bufs: vec![0; total],
            size,
            iov: Vec::with_capacity(slots),
            // SAFETY: sockaddr_storage and mmsghdr are plain-old-data; all-zero is valid.
            names: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            ctrl: vec![[0; 8]; slots],
            gro,
            // SAFETY: as above.
            msgs: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            got: 0,
        };
        // One base pointer for all slots: re-borrowing `bufs` mutably per slot would, under
        // Rust's aliasing model, invalidate the pointers taken for the earlier slots.
        let base = b.bufs.as_mut_ptr();
        for i in 0..slots {
            b.iov.push(ffi::iovec {
                // SAFETY: `i * size + size <= total == bufs.len()` (checked above), so the slot
                // lies inside the allocation; `bufs` is never resized, so the pointer stays valid.
                iov_base: unsafe { base.add(i * size) }.cast(),
                iov_len: size,
            });
        }
        b
    }

    fn reset(&mut self) {
        for i in 0..self.msgs.len() {
            // A stale family from an earlier receive must not survive a header the kernel does
            // not fill in (`parse_addr` trusts it).
            self.names[i].ss_family = 0;
            let h = &mut self.msgs[i].msg_hdr;
            h.msg_name = (&raw mut self.names[i]).cast();
            h.msg_namelen = size_of::<ffi::sockaddr_storage>() as ffi::socklen_t;
            h.msg_iov = &raw mut self.iov[i];
            h.msg_iovlen = 1;
            // Control data: the GRO segment size and the traffic class (ECN), when enabled.
            h.msg_control = (&raw mut self.ctrl[i]).cast();
            h.msg_controllen = size_of::<Ctrl>() as _;
            h.msg_flags = 0;
            self.msgs[i].msg_len = 0;
        }
    }

    /// One `recvmmsg` call. Returns how many datagrams arrived (0 = nothing ready).
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.got = 0;
        self.reset();
        // SAFETY: `msgs` holds `msgs.len()` initialised headers whose name/iov/control pointers
        // refer to buffers owned by `self` that are live for the duration of the call.
        let n = unsafe {
            ffi::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.msgs.len() as ffi::c_uint,
                ffi::MSG_DONTWAIT,
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
        self.cmsg_int(i, |level, ty| level == SOL_UDP && ty == UDP_GRO)
            .map_or(0, |v| v.max(0) as usize)
    }

    /// The ECN codepoint (the low two bits of the traffic class) of datagram `i` of the last
    /// `recv`: 0 when not ECN-capable or not reported (see [`enable_ecn`]).
    pub fn ecn(&self, i: usize) -> u8 {
        if i >= self.got {
            return 0;
        }
        let tos = self.cmsg_int(i, |level, ty| {
            (level == IPPROTO_IP && ty == IP_TOS) || (level == IPPROTO_IPV6 && ty == IPV6_TCLASS)
        });
        tos.map_or(0, |v| (v & 3) as u8)
    }

    /// The payload of the first control message of datagram `i` that `want(level, type)`
    /// accepts, as an int (a one-byte payload, as `IP_TOS` has, is widened).
    fn cmsg_int(&self, i: usize, want: impl Fn(ffi::c_int, ffi::c_int) -> bool) -> Option<i32> {
        let h = &self.msgs[i].msg_hdr;
        // SAFETY: `h` is a header the kernel filled in; the CMSG_* helpers only walk within
        // `msg_control[..msg_controllen]`, which points into `self.ctrl[i]`, and a payload is
        // read only within the `cmsg_len` the kernel wrote (one int, else one byte).
        unsafe {
            let mut c = ffi::cmsg_firsthdr(h);
            while !c.is_null() {
                if want((*c).cmsg_level, (*c).cmsg_type) {
                    let data = ffi::cmsg_data(c);
                    let len = (*c).cmsg_len as usize;
                    return if len >= ffi::cmsg_len(size_of::<ffi::c_int>()) {
                        Some(std::ptr::read_unaligned(data.cast::<ffi::c_int>()))
                    } else if len >= ffi::cmsg_len(1) {
                        Some(i32::from(*data))
                    } else {
                        None
                    };
                }
                c = ffi::cmsg_nxthdr(h, c);
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
struct Meta {
    iov_start: usize,
    iov_len: usize,
    namelen: ffi::socklen_t,
    gso: u16,
    /// ECN codepoint to send with (0: none), and whether the socket is IPv6 (`IPV6_TCLASS`
    /// rather than `IP_TOS`).
    ecn: u8,
    v6: bool,
}

/// Reusable storage for `sendmmsg` batches; fill one with [`SendBatch::batch`].
pub struct SendBatch {
    iov: Vec<ffi::iovec>,
    names: Vec<ffi::sockaddr_storage>,
    ctrl: Vec<Ctrl>,
    meta: Vec<Meta>,
    msgs: Vec<ffi::mmsghdr>,
}

impl std::fmt::Debug for SendBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendBatch").finish_non_exhaustive()
    }
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
            ctrl: vec![[0; 8]; SEND_BATCH],
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

impl<'s, 'd> std::fmt::Debug for Batch<'s, 'd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batch").finish_non_exhaustive()
    }
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
        self.push_ecn(dest, parts, gso, 0, false)
    }

    /// As [`push`](Self::push), with the ECN codepoint `ecn` (its low two bits; 0 sends none)
    /// set on the message's datagrams, through `IPV6_TCLASS` when `v6_socket` (the socket is
    /// IPv6), else `IP_TOS`.
    pub fn push_ecn(
        &mut self,
        dest: Option<&SocketAddr>,
        parts: &[&'d [u8]],
        gso: usize,
        ecn: u8,
        v6_socket: bool,
    ) -> bool {
        let s = &mut *self.s;
        let i = s.meta.len();
        if i == SEND_BATCH || s.iov.len() + parts.len() > MAX_IOV {
            return false;
        }
        let iov_start = s.iov.len();
        for p in parts {
            s.iov.push(ffi::iovec {
                iov_base: p.as_ptr() as *mut ffi::c_void,
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
            ecn: ecn & 3,
            v6: v6_socket,
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
            let mut space = 0;
            if m.gso > 0 {
                space += ffi::cmsg_space(size_of::<u16>());
            }
            if m.ecn > 0 {
                space += ffi::cmsg_space(size_of::<ffi::c_int>());
            }
            if space > 0 {
                s.ctrl[i] = [0; 8];
                h.msg_control = (&raw mut s.ctrl[i]).cast();
                h.msg_controllen = space as _;
                // SAFETY: `msg_control` points to `ctrl[i]` (64 bytes, 8-aligned, zeroed above),
                // large enough for the (at most two) cmsghdrs CMSG_SPACE counted; each header
                // comes from CMSG_FIRSTHDR / CMSG_NXTHDR within that length, the next one only
                // after its predecessor's `cmsg_len` is set.
                unsafe {
                    let mut c = ffi::cmsg_firsthdr(h);
                    if m.gso > 0 && !c.is_null() {
                        (*c).cmsg_level = SOL_UDP;
                        (*c).cmsg_type = UDP_SEGMENT;
                        (*c).cmsg_len = ffi::cmsg_len(size_of::<u16>());
                        std::ptr::write_unaligned(ffi::cmsg_data(c).cast::<u16>(), m.gso);
                        c = ffi::cmsg_nxthdr(h, c);
                    }
                    if m.ecn > 0 && !c.is_null() {
                        (*c).cmsg_level = if m.v6 { IPPROTO_IPV6 } else { IPPROTO_IP };
                        (*c).cmsg_type = if m.v6 { IPV6_TCLASS } else { IP_TOS };
                        (*c).cmsg_len = ffi::cmsg_len(size_of::<ffi::c_int>());
                        let v = ffi::c_int::from(m.ecn);
                        std::ptr::write_unaligned(ffi::cmsg_data(c).cast::<ffi::c_int>(), v);
                    }
                }
            }
            s.msgs[i].msg_len = 0;
        }
        // SAFETY: headers `from..n` are initialised; their name/iov/control pointers refer to
        // `s`'s buffers and to the data borrowed for `'d`, all live for the call.
        let r = unsafe {
            ffi::sendmmsg(
                fd,
                s.msgs[from..].as_mut_ptr(),
                (n - from) as ffi::c_uint,
                ffi::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }
}

fn parse_addr(ss: &ffi::sockaddr_storage) -> Option<SocketAddr> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, os::fd::AsRawFd};

    #[test]
    #[should_panic(expected = "overflows")]
    fn recv_batch_rejects_overflowing_size() {
        // Unchecked, `2 * (usize::MAX / 2 + 1)` wraps to 0 in release builds: an empty buffer
        // behind iovecs that let the kernel write anywhere.
        let _ = RecvBatch::new(2, usize::MAX / 2 + 1);
    }

    #[test]
    fn recv_batch_forgets_previous_datagrams() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"hello", rx.local_addr().unwrap()).unwrap();
        let mut rb = RecvBatch::new(4, 2048);
        let mut n = 0;
        for _ in 0..100 {
            n = rb.recv(rx.as_raw_fd()).unwrap();
            if n > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(n, 1);
        assert_eq!(rb.get(0).unwrap().0, b"hello");
        // Nothing pending: the earlier datagram must not be reported again.
        assert_eq!(rb.recv(rx.as_raw_fd()).unwrap(), 0);
        assert!(rb.get(0).is_none());
        // A failing receive (bad fd) must not leave the old one visible either.
        assert!(rb.recv(-1).is_err());
        assert!(rb.get(0).is_none());
    }

    #[test]
    fn ecn_codepoints_both_ways() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        assert!(enable_ecn(rx.as_raw_fd()));
        let gro = enable_gro(rx.as_raw_fd());
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        let (a, b, c) = ([1u8; 100], [2u8; 100], [3u8; 60]);
        let mut sb = SendBatch::new();
        let mut batch = sb.batch();
        // ECT(0), ECT(1) with GSO when available, then CE.
        assert!(batch.push_ecn(Some(&dest), &[&a], 0, 2, false));
        let gso = if gso_enabled() { 100 } else { 0 };
        if gso > 0 {
            assert!(batch.push_ecn(Some(&dest), &[&b, &b], gso, 1, false));
        } else {
            assert!(batch.push_ecn(Some(&dest), &[&b], 0, 1, false));
            assert!(batch.push_ecn(Some(&dest), &[&b], 0, 1, false));
        }
        assert!(batch.push_ecn(Some(&dest), &[&c], 0, 3, false));
        let n = batch.len();
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
                let (d, _, seg) = rb.get(i).unwrap();
                let seg = if seg > 0 { seg } else { d.len() };
                for x in d.chunks(seg) {
                    got.push((x[0], rb.ecn(i)));
                }
            }
        }
        assert_eq!(got, vec![(1, 2), (2, 1), (2, 1), (3, 3)]);
    }

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
