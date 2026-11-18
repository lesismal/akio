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

/// Receives up to `slots` datagrams per syscall into pooled receive slabs (ADR-024).
///
/// Each slot receives into the free tail of its own slab (`only_buf::slab`, two slot sizes
/// long). A datagram is either read in place ([`get`](Self::get)) or cut off the slab and handed
/// out ([`take`](Self::take)), after which the slot goes on receiving into what is left of its
/// slab, and into a fresh (or freed) one once less than a slot size is left. Small datagrams
/// thus pack densely: a handed-out datagram keeps only its slab, not a whole batch, alive.
pub struct RecvBatch {
    /// The free tail of each slot's slab; at least `size` bytes at each `recv`.
    free: Vec<only_buf::slab::ChunkMut>,
    pool: only_buf::slab::SlabPool,
    /// Datagram `i` of the last `recv` was handed out with `take`.
    taken: Vec<bool>,
    size: usize,
    iov: Vec<ffi::iovec>,
    names: Vec<ffi::sockaddr_storage>,
    ctrl: Vec<Ctrl>,
    gro: bool,
    msgs: Vec<ffi::mmsghdr>,
    got: usize,
    /// Slots the last `recvmmsg` may have written (`got` plus the one it stopped at): only
    /// these need their header, iovec and slab looked at again before the next one.
    dirty: usize,
}

impl std::fmt::Debug for RecvBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvBatch").finish_non_exhaustive()
    }
}

// SAFETY: the raw pointers inside `iov`/`msgs` point into memory owned by this same struct (the
// `names`/`ctrl` vectors and the slabs of `free`), which moves with it; they are rewritten before
// every `recvmmsg` and nothing else reads them.
unsafe impl Send for RecvBatch {}

impl RecvBatch {
    /// `slots` datagrams of up to `size` bytes each (longer ones are truncated).
    ///
    /// # Panics
    ///
    /// If `slots * 2 * size` overflows `usize`, `2 * size` exceeds `u32::MAX` or `slots` exceeds
    /// `u32::MAX`.
    pub fn new(slots: usize, size: usize) -> RecvBatch {
        Self::with_gro(slots, size, false)
    }

    /// As [`new`](Self::new); with `gro`, coalesced receives (see [`enable_gro`]) report their
    /// segment size through [`get`](Self::get). `size` should then be at least 64 KiB.
    pub fn with_gro(slots: usize, size: usize, gro: bool) -> RecvBatch {
        let slab = size
            .checked_mul(2)
            .filter(|s| slots.checked_mul(*s).is_some())
            .expect("RecvBatch: slots * size overflows usize");
        assert!(
            u32::try_from(slots).is_ok(),
            "RecvBatch: too many slots for recvmmsg"
        );
        // One slab per slot, plus half as many again kept for reuse while datagrams cut from a
        // slot's previous slab are still held (zeroed pages cost no memory until written).
        let mut pool = only_buf::slab::SlabPool::new(slab, slots.saturating_add(slots.div_ceil(2)));
        RecvBatch {
            free: (0..slots).map(|_| pool.take()).collect(),
            pool,
            taken: vec![false; slots],
            size,
            iov: vec![
                ffi::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                slots
            ],
            // SAFETY: sockaddr_storage and mmsghdr are plain-old-data; all-zero is valid.
            names: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            ctrl: vec![[0; 8]; slots],
            gro,
            // SAFETY: as above.
            msgs: (0..slots).map(|_| unsafe { mem::zeroed() }).collect(),
            got: 0,
            dirty: slots,
        }
    }

    fn reset(&mut self) {
        // The kernel writes only the headers of the datagrams it returns, so the others still
        // hold what an earlier `reset` put there; a request/response peer that gets one or two
        // datagrams per call thus costs one or two slots here, not all of them.
        for i in 0..self.dirty.min(self.msgs.len()) {
            // A slot whose slab has less than a datagram's room left starts over: in the same
            // slab when the datagrams cut from it have dropped (still in cache), else in another.
            if self.free[i].len() < self.size {
                self.pool.renew(&mut self.free[i]);
            }
            self.taken[i] = false;
            self.iov[i] = ffi::iovec {
                iov_base: self.free[i].as_mut_ptr().cast(),
                iov_len: self.size,
            };
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
        // refer to buffers owned by `self` that are live for the duration of the call. Each iovec
        // covers the first `size` bytes of `free[i]`, an exclusive slab range (`ChunkMut`) at
        // least `size` long (`reset`), so the kernel's writes alias nothing else; `&mut self`
        // keeps every `free[i]` borrowed until the call returns.
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
                self.dirty = 1;
                Ok(0)
            } else {
                // Unknown how far the kernel got: start over on every slot.
                self.dirty = self.msgs.len();
                Err(e)
            };
        }
        self.got = n as usize;
        self.dirty = self.got + 1;
        Ok(self.got)
    }

    fn len_of(&self, i: usize) -> usize {
        (self.msgs[i].msg_len as usize).min(self.size)
    }

    /// Datagram `i` of the last `recv` and its sender. The last element is the GRO segment size
    /// when the kernel coalesced several datagrams into this one (split it into pieces of that
    /// size, the last possibly shorter), else 0. `None` past the last datagram, for one that has
    /// no readable sender, and for one already handed out by [`take`](Self::take).
    pub fn get(&self, i: usize) -> Option<(&[u8], SocketAddr, usize)> {
        if i >= self.got || self.taken[i] {
            return None;
        }
        let data = &self.free[i][..self.len_of(i)];
        Some((data, parse_addr(&self.names[i])?, self.gro_size(i)))
    }

    /// As [`get`](Self::get) without the sender (already read with [`addr`](Self::addr)):
    /// the datagram, read in place, and its GRO segment size. Backend-facing.
    #[doc(hidden)]
    pub fn data(&self, i: usize) -> Option<(&[u8], usize)> {
        if i >= self.got || self.taken[i] {
            return None;
        }
        Some((&self.free[i][..self.len_of(i)], self.gro_size(i)))
    }

    /// The sender of datagram `i` of the last `recv` (`None` as for [`get`](Self::get)).
    #[doc(hidden)]
    pub fn addr(&self, i: usize) -> Option<SocketAddr> {
        if i >= self.got || self.taken[i] {
            return None;
        }
        parse_addr(&self.names[i])
    }

    /// As [`get`](Self::get), but hands the datagram out as an owned, writable slab range
    /// (no copy); the slot goes on receiving into the rest of its slab. Backend-facing (the
    /// slab types are `#[doc(hidden)]`, ADR-024).
    #[doc(hidden)]
    pub fn take(&mut self, i: usize) -> Option<(only_buf::slab::ChunkMut, SocketAddr, usize)> {
        let addr = self.addr(i)?;
        let seg = self.gro_size(i);
        let len = self.len_of(i);
        self.taken[i] = true;
        Some((self.free[i].split_to(len), addr, seg))
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
                    let len: usize = (*c).cmsg_len;
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

    /// Receives until nothing more arrives (a few empty rounds), calling `f` per datagram index.
    fn drain(rb: &mut RecvBatch, fd: RawFd, mut f: impl FnMut(&mut RecvBatch, usize)) {
        let mut idle = 0;
        while idle < 20 {
            let k = rb.recv(fd).unwrap();
            if k == 0 {
                idle += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            idle = 0;
            for i in 0..k {
                f(rb, i);
            }
        }
    }

    #[test]
    fn take_hands_out_a_coalesced_batch_to_split() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let gro = enable_gro(rx.as_raw_fd());
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        let parts: Vec<Vec<u8>> = (0..5u8)
            .map(|i| vec![i + 1; if i == 4 { 40 } else { 100 }])
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        let mut sb = SendBatch::new();
        let mut batch = sb.batch();
        if gso_enabled() {
            assert!(batch.push(Some(&dest), &refs, 100));
        } else {
            for p in &refs {
                assert!(batch.push(Some(&dest), &[p], 0));
            }
        }
        let n = batch.len();
        assert_eq!(batch.send(tx.as_raw_fd(), 0).unwrap(), n);
        let mut rb = RecvBatch::with_gro(4, 65536, gro);
        let mut got = Vec::new();
        drain(&mut rb, rx.as_raw_fd(), |rb, i| {
            let (mut d, from, seg) = rb.take(i).unwrap();
            assert_eq!(from, tx.local_addr().unwrap());
            // Handed out once: neither readable in place nor takeable again.
            assert!(rb.get(i).is_none());
            assert!(rb.take(i).is_none());
            let seg = if seg > 0 { seg } else { d.len() };
            while !d.is_empty() {
                let mut x = d.split_to(seg.min(d.len()));
                // Owned and writable: as a decrypt in place would.
                x[0] ^= 0x80;
                got.push(x.freeze());
            }
        });
        let got: Vec<Vec<u8>> = got
            .iter()
            .map(|c| {
                let mut v = c.to_vec();
                v[0] ^= 0x80;
                v
            })
            .collect();
        assert_eq!(got, parts);
    }

    #[test]
    fn truncated_datagrams_are_cut_at_the_slot_size() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        tx.send_to(&big, dest).unwrap();
        tx.send_to(&[7; 100], dest).unwrap();
        tx.send_to(&big, dest).unwrap();
        let mut rb = RecvBatch::new(4, 512);
        let mut got = Vec::new();
        drain(&mut rb, rx.as_raw_fd(), |rb, i| {
            // Alternate the two ways out of the batch.
            if got.len() % 2 == 0 {
                got.push(rb.take(i).unwrap().0.to_vec());
            } else {
                got.push(rb.get(i).unwrap().0.to_vec());
            }
        });
        assert_eq!(
            got,
            vec![big[..512].to_vec(), vec![7; 100], big[..512].to_vec()]
        );
    }

    #[test]
    fn taken_datagrams_outlive_later_receives() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        // Two slots of 2 KiB: slabs of 4 KiB, so the slots move to new slabs every few
        // datagrams while the earlier ones are still held.
        let mut rb = RecvBatch::new(2, 2048);
        let pattern = |seq: u32, len: usize| -> Vec<u8> {
            (0..len).map(|i| (seq as usize * 31 + i) as u8).collect()
        };
        let mut kept = Vec::new();
        let mut seq = 0u32;
        for round in 0..300u32 {
            let len = 1 + (round as usize * 97) % 1500;
            tx.send_to(&pattern(round, len), dest).unwrap();
            if round % 3 == 2 {
                drain(&mut rb, rx.as_raw_fd(), |rb, i| {
                    let (d, _, _) = rb.take(i).unwrap();
                    kept.push((seq, d.freeze()));
                    seq += 1;
                });
                // Every other one dropped: the slabs they lived in come back once their
                // neighbours drop too.
                if round % 6 == 5 {
                    kept.retain(|(s, _)| s % 2 == 0);
                }
            }
        }
        assert!(kept.len() > 100, "{}", kept.len());
        for (s, c) in &kept {
            let len = 1 + (*s as usize * 97) % 1500;
            assert_eq!(&c[..], &pattern(*s, len)[..], "datagram {s}");
        }
        // Everything dropped: receiving goes on in reused slabs.
        drop(kept);
        assert!(rb.pool.kept() <= 3);
        tx.send_to(b"after", dest).unwrap();
        let mut last = Vec::new();
        drain(&mut rb, rx.as_raw_fd(), |rb, i| {
            last.push(rb.get(i).unwrap().0.to_vec());
        });
        assert_eq!(last, vec![b"after".to_vec()]);
    }
}
