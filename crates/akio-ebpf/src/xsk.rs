//! AF_XDP sockets (Linux 5.4+): a UMEM, its fill and completion rings, the RX and TX rings of
//! one socket per queue, and the XDP program that redirects a queue's frames to its socket
//! (ADR-063). The data path of akio-dpdk's `Device::AfXdp`; `#[doc(hidden)]`, unstable.
//!
//! Layout per queue: `frames` chunks of `frame_size` bytes in one page-aligned allocation.
//! Half of them start in the fill ring (the kernel writes received frames into them and hands
//! them back on the RX ring); the other half are the TX pool (written in place, handed to the
//! kernel on the TX ring, returned on the completion ring). Received frames are copied out
//! and their chunk goes straight back to the fill ring, so the caller never holds a reference
//! into the UMEM.
//!
//! With `shared_umem` the queues share one UMEM (`XDP_SHARED_UMEM`, Linux 5.10+ across
//! queues): the first socket registers it, the others bind to it with fill and completion rings
//! of their own, and each socket owns a fixed slice of its chunks (the kernel hands a socket
//! back only chunks it put on that socket's rings), so no chunk is ever touched by two threads.
//! With `multi_buffer` (`XDP_USE_SG`, Linux 6.6+) a frame larger than a chunk spans several
//! descriptors (`XDP_PKT_CONTD` on all but the last) both ways, and the redirect program is
//! loaded frags-aware (`BPF_F_XDP_HAS_FRAGS`), so jumbo MTUs work.
//!
//! Zero-copy (`XDP_ZEROCOPY`: the NIC DMAs into the UMEM) is tried first unless disabled; when
//! the driver does not support it on the queue the socket is bound in copy mode (`XDP_COPY`:
//! the kernel copies, but no skb is allocated and no syscall is made per frame). The program is
//! attached in native (driver) mode first, generic (skb) mode otherwise, as for the XDP rate
//! limiter.

use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use akio_sys::ffi;

use crate::xdp::{Attachment, ProgLink, XdpMode};

const AF_XDP: ffi::c_int = 44;
const SOL_XDP: ffi::c_int = 283;

const XDP_MMAP_OFFSETS: ffi::c_int = 1;
const XDP_RX_RING: ffi::c_int = 2;
const XDP_TX_RING: ffi::c_int = 3;
const XDP_UMEM_REG: ffi::c_int = 4;
const XDP_UMEM_FILL_RING: ffi::c_int = 5;
const XDP_UMEM_COMPLETION_RING: ffi::c_int = 6;
const XDP_STATISTICS: ffi::c_int = 7;
const XDP_OPTIONS: ffi::c_int = 8;

const XDP_SHARED_UMEM: u16 = 1 << 0;
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const XDP_USE_SG: u16 = 1 << 4;
/// `xdp_desc.options`: more descriptors of the same frame follow.
const XDP_PKT_CONTD: u32 = 1;
/// Most descriptors one frame may span (copy mode: `MAX_SKB_FRAGS + 1`).
const MAX_FRAGS: usize = 18;
/// Largest frame reassembled from descriptors.
const MAX_SG_FRAME: usize = 64 << 10;
const XDP_OPTIONS_ZEROCOPY: u32 = 1;
const XDP_RING_NEED_WAKEUP: u32 = 1;

const PGOFF_RX_RING: ffi::off_t = 0;
const PGOFF_TX_RING: ffi::off_t = 0x8000_0000;
const PGOFF_FILL_RING: ffi::off_t = 0x1_0000_0000;
const PGOFF_COMPLETION_RING: ffi::off_t = 0x1_8000_0000;

/// Whether to bind in zero-copy mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZeroCopy {
    /// Zero-copy where the driver supports it on the queue, copy mode otherwise.
    #[default]
    Auto,
    /// Zero-copy or fail.
    Required,
    /// Copy mode.
    Off,
}

/// Configuration of [`open`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct XskConfig {
    /// Queues `0..queues`, one socket each (default 1).
    pub queues: u32,
    /// UMEM chunks per socket (default 4096; half for receiving, half for sending); with
    /// `shared_umem`, in all (each socket gets `frames / queues`).
    pub frames: u32,
    /// One UMEM for every queue (`XDP_SHARED_UMEM`) instead of one per socket.
    pub shared_umem: bool,
    /// Frames larger than a chunk, over several descriptors (`XDP_USE_SG`).
    pub multi_buffer: bool,
    /// Bytes per chunk: a power of two from 2048 to 4096 (default 4096). The largest frame is
    /// `frame_size - 256` (the kernel's XDP headroom).
    pub frame_size: u32,
    /// Entries of each ring, a power of two (default 2048; at most `frames / 2`).
    pub ring_size: u32,
    /// How the redirect program is attached.
    pub mode: XdpMode,
    /// Zero-copy or copy mode.
    pub zero_copy: ZeroCopy,
}

impl Default for XskConfig {
    fn default() -> Self {
        XskConfig {
            queues: 1,
            frames: 4096,
            shared_umem: false,
            multi_buffer: false,
            frame_size: 4096,
            ring_size: 2048,
            mode: XdpMode::Auto,
            zero_copy: ZeroCopy::Auto,
        }
    }
}

impl XskConfig {
    fn check(&self) -> io::Result<()> {
        let bad = |m: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, m.to_owned()));
        if self.queues == 0 || self.queues > 256 {
            return bad("AF_XDP: queues must be 1 to 256");
        }
        if !matches!(self.frame_size, 2048 | 4096) {
            return bad("AF_XDP: frame_size must be 2048 or 4096");
        }
        if !self.ring_size.is_power_of_two() || self.ring_size < 64 {
            return bad("AF_XDP: ring_size must be a power of two of at least 64");
        }
        if self.frames < 2 * self.ring_size || self.frames > 1 << 20 {
            return bad("AF_XDP: frames must be 2 * ring_size to 2^20");
        }
        if self.shared_umem && self.per_socket() < 2 * self.ring_size {
            return bad("AF_XDP: a shared UMEM needs 2 * ring_size frames per queue");
        }
        Ok(())
    }

    /// Chunks each socket owns.
    fn per_socket(&self) -> u32 {
        if self.shared_umem {
            self.frames / self.queues.max(1)
        } else {
            self.frames
        }
    }
}

/// What [`open`] set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct XskInfo {
    /// The interface.
    pub ifindex: u32,
    /// How the redirect program is attached.
    pub mode: XdpMode,
    /// BPF link or netlink.
    pub attachment: Attachment,
    /// Every socket is bound in zero-copy mode.
    pub zero_copy: bool,
    /// Sockets (queues).
    pub queues: u32,
    /// The sockets share one UMEM.
    pub shared_umem: bool,
    /// Frames may span several chunks (`XDP_USE_SG`).
    pub multi_buffer: bool,
}

/// Counters of one socket (`XDP_STATISTICS`; fields the kernel does not report are 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct XskStats {
    /// Frames dropped for reasons other than a full ring or an empty fill ring.
    pub rx_dropped: u64,
    /// Invalid RX descriptors.
    pub rx_invalid_descs: u64,
    /// Invalid TX descriptors.
    pub tx_invalid_descs: u64,
    /// Frames dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Frames dropped because the fill ring was empty.
    pub rx_fill_ring_empty_descs: u64,
    /// Times the TX ring was empty when the kernel looked.
    pub tx_ring_empty_descs: u64,
}

fn cvt(r: ffi::c_int) -> io::Result<ffi::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn setsockopt<T>(fd: RawFd, name: ffi::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` is valid for reads of `size_of::<T>()` bytes for the duration of the call.
    cvt(unsafe {
        ffi::setsockopt(
            fd,
            SOL_XDP,
            name,
            std::ptr::from_ref::<T>(v).cast::<c_void>(),
            size_of::<T>() as ffi::socklen_t,
        )
    })
    .map(drop)
}

/// `getsockopt(SOL_XDP, name)` into `v`; returns the length the kernel wrote.
fn getsockopt<T>(fd: RawFd, name: ffi::c_int, v: &mut T) -> io::Result<usize> {
    let mut len = size_of::<T>() as ffi::socklen_t;
    // SAFETY: `v` is valid for writes of `len` bytes and `len` for a write of a socklen_t;
    // the kernel writes at most `len` bytes. `T` is plain integers (every bit pattern valid).
    cvt(unsafe {
        ffi::getsockopt(
            fd,
            SOL_XDP,
            name,
            std::ptr::from_mut::<T>(v).cast::<c_void>(),
            &raw mut len,
        )
    })?;
    Ok(len as usize)
}

#[repr(C)]
struct UmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct MmapOffsets {
    rx: RingOffset,
    tx: RingOffset,
    fr: RingOffset,
    cr: RingOffset,
}

#[repr(C)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

/// `struct xdp_desc`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    options: u32,
}

const _: () = assert!(size_of::<Desc>() == 16 && size_of::<SockaddrXdp>() == 16);
const _: () = assert!(size_of::<UmemReg>() == 32 && size_of::<MmapOffsets>() == 128);

const MAP_PRIVATE: ffi::c_int = 0x02;
const MAP_ANONYMOUS: ffi::c_int = 0x20;

/// The anonymous mapping a UMEM is registered over. Its own mapping (not the heap): when it is
/// unmapped the kernel's pins keep the pages alive until it releases the UMEM, and no later
/// allocation can be handed those pages meanwhile.
struct UmemMem {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is owned by this value and freed once (in `drop`, when the last socket
// sharing it is gone). Every chunk belongs to exactly one socket (its slice of the UMEM, see
// `XskSocket::new`), and a socket only dereferences the pointer for its own chunks, through
// its `&self`/`&mut self`: sockets on different threads never touch the same bytes.
unsafe impl Send for UmemMem {}
// SAFETY: as above: shared references to the mapping are only used for disjoint chunks.
unsafe impl Sync for UmemMem {}

impl UmemMem {
    fn new(len: usize) -> io::Result<UmemMem> {
        // SAFETY: a fresh private anonymous mapping (no file, no fixed address); checked below.
        let p = unsafe {
            ffi::mmap(
                std::ptr::null_mut(),
                len,
                ffi::PROT_READ | ffi::PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | ffi::MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == ffi::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = std::ptr::NonNull::new(p.cast::<u8>())
            .ok_or_else(|| io::Error::other("AF_XDP: mmap returned NULL"))?;
        Ok(UmemMem { ptr, len })
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Drop for UmemMem {
    fn drop(&mut self) {
        // SAFETY: unmaps the mapping made in `new`. The socket that registered it is closed
        // first (`XskSocket` field order) and no slice into it outlives the socket.
        unsafe { ffi::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// One mmap'ed ring of `size` entries of `E` (`u64` addresses or [`Desc`]s).
struct Ring<E> {
    map: *mut c_void,
    map_len: usize,
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    flags: *const AtomicU32,
    entries: *mut E,
    mask: u32,
    size: u32,
    cached_prod: u32,
    cached_cons: u32,
}

// SAFETY: the ring owns its mapping; the raw pointers point into it and are only dereferenced
// through `&self`/`&mut self` of the one thread that owns the socket. The kernel side of the
// ring synchronises through the atomic producer/consumer words.
unsafe impl<E> Send for Ring<E> {}

impl<E: Copy> Ring<E> {
    /// Maps the ring of `fd` at page offset `pgoff` with offsets `off`.
    fn map(fd: RawFd, pgoff: ffi::off_t, off: &RingOffset, size: u32) -> io::Result<Ring<E>> {
        let map_len = off.desc as usize + size as usize * size_of::<E>();
        // SAFETY: a fresh shared mapping of the ring the kernel created for `fd` (its length
        // covers the descriptors); no Rust object aliases it.
        let map = unsafe {
            ffi::mmap(
                std::ptr::null_mut(),
                map_len,
                ffi::PROT_READ | ffi::PROT_WRITE,
                ffi::MAP_SHARED | ffi::MAP_POPULATE,
                fd,
                pgoff,
            )
        };
        if map == ffi::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = map.cast::<u8>();
        // SAFETY: the offsets come from XDP_MMAP_OFFSETS and lie inside the mapping (the
        // kernel lays the ring out as producer, consumer, flags, then the descriptors); the
        // words are 4-byte and the descriptors 8-byte aligned (the mapping is page aligned and
        // the kernel aligns each field).
        let at = |o: u64| unsafe { base.add(o as usize) };
        Ok(Ring {
            map,
            map_len,
            producer: at(off.producer).cast(),
            consumer: at(off.consumer).cast(),
            flags: at(off.flags).cast(),
            entries: at(off.desc).cast(),
            mask: size - 1,
            size,
            cached_prod: 0,
            cached_cons: 0,
        })
    }

    fn producer(&self) -> &AtomicU32 {
        // SAFETY: points to an aligned u32 inside the live mapping (see `map`); `AtomicU32`
        // has the layout of `u32`, and the kernel accesses the word atomically too.
        unsafe { &*self.producer }
    }

    fn consumer(&self) -> &AtomicU32 {
        // SAFETY: as in `producer`.
        unsafe { &*self.consumer }
    }

    fn needs_wakeup(&self) -> bool {
        // SAFETY: as in `producer`.
        unsafe { &*self.flags }.load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0
    }

    // ---- as a producer (fill, TX) ----

    /// Writes entry `k` past the next one without publishing it (see [`submit`](Self::submit);
    /// `k` must be below [`free`](Self::free)).
    fn stage(&mut self, k: u32, e: E) {
        debug_assert!(self.size - self.cached_prod.wrapping_sub(self.cached_cons) > k);
        let i = (self.cached_prod.wrapping_add(k) & self.mask) as usize;
        // SAFETY: as in `produce`: `i < size` and the entry is free.
        unsafe { self.entries.add(i).write(e) };
    }

    /// Publishes `n` staged entries at once.
    fn submit(&mut self, n: u32) {
        self.cached_prod = self.cached_prod.wrapping_add(n);
        self.producer().store(self.cached_prod, Ordering::Release);
    }

    /// Free entries.
    fn free(&mut self) -> u32 {
        let free = self.size - self.cached_prod.wrapping_sub(self.cached_cons);
        if free > 0 {
            return free;
        }
        self.cached_cons = self.consumer().load(Ordering::Acquire);
        self.size - self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Writes the next entry (call [`free`](Self::free) first) and publishes it.
    fn produce(&mut self, e: E) {
        debug_assert!(self.size - self.cached_prod.wrapping_sub(self.cached_cons) > 0);
        let i = (self.cached_prod & self.mask) as usize;
        // SAFETY: `i < size`, and the mapping holds `size` entries of `E` from `entries`;
        // the entry is free (the kernel consumed it), so the kernel does not read it now.
        unsafe { self.entries.add(i).write(e) };
        self.cached_prod = self.cached_prod.wrapping_add(1);
        // Release: the entry is visible before the producer moves past it.
        self.producer().store(self.cached_prod, Ordering::Release);
    }

    // ---- as a consumer (RX, completion) ----

    /// Entries ready to read.
    fn available(&mut self) -> u32 {
        let n = self.cached_prod.wrapping_sub(self.cached_cons);
        if n > 0 {
            return n;
        }
        self.cached_prod = self.producer().load(Ordering::Acquire);
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Reads and releases the next entry (call [`available`](Self::available) first).
    fn consume(&mut self) -> E {
        debug_assert!(self.cached_prod != self.cached_cons);
        let i = (self.cached_cons & self.mask) as usize;
        // SAFETY: `i < size` (see `produce`); the kernel published this entry (acquire load
        // of the producer in `available`) and does not write it until we release it.
        let e = unsafe { self.entries.add(i).read() };
        self.cached_cons = self.cached_cons.wrapping_add(1);
        self.consumer().store(self.cached_cons, Ordering::Release);
        e
    }
}

impl<E> Drop for Ring<E> {
    fn drop(&mut self) {
        // SAFETY: unmaps the mapping made in `map`; no reference into it outlives the ring.
        unsafe { ffi::munmap(self.map, self.map_len) };
    }
}

/// The program and map shared by a device's sockets; detached when the last socket is gone.
struct Device {
    ifindex: u32,
    link: Option<ProgLink>,
    _map: crate::sys::Map<u32, u32>,
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(l) = self.link.take() {
            let _ = l.detach(self.ifindex);
        }
    }
}

/// One AF_XDP socket bound to one queue.
pub struct XskSocket {
    // Field order is drop order: the rings are unmapped and the socket closed before the
    // UMEM memory is freed, and the device (redirect program) goes last.
    fill: Ring<u64>,
    comp: Ring<u64>,
    rx: Ring<Desc>,
    tx: Ring<Desc>,
    fd: OwnedFd,
    mem: Arc<UmemMem>,
    device: Option<Arc<Device>>,
    frame_size: u32,
    /// Bound with `XDP_USE_SG`.
    sg: bool,
    /// A frame being reassembled from several RX descriptors, and whether it is being dropped
    /// (over `MAX_SG_FRAME`).
    partial: Vec<u8>,
    partial_drop: bool,
    /// Whether the UMEM is shared with other sockets.
    shared: bool,
    /// This socket's slice of the UMEM, in bytes: the only chunks it ever touches.
    lo: usize,
    hi: usize,
    /// TX chunks owned by userspace.
    tx_free: Vec<u64>,
    /// The chunk and length being written by `staged_mut`.
    staged: Option<(u64, usize)>,
    /// TX descriptors produced since the last kick.
    tx_pending: u32,
    zero_copy: bool,
    queue: u32,
}

impl std::fmt::Debug for XskSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XskSocket")
            .field("queue", &self.queue)
            .field("zero_copy", &self.zero_copy)
            .finish_non_exhaustive()
    }
}

/// Errors of a zero-copy bind that mean "not supported here": retry in copy mode.
fn zc_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(ffi::EOPNOTSUPP | ffi::EINVAL | ffi::ENOPROTOOPT | ffi::EBUSY)
    ) || e.raw_os_error() == Some(524) // ENOTSUPP (kernel-internal, seen from some drivers)
}

impl XskSocket {
    /// A socket on `queue` owning chunks `first..first + count` of `mem`. `owner`: the socket
    /// that registered `mem` (this one binds with `XDP_SHARED_UMEM` to it); `None`: this socket
    /// registers it.
    fn new(
        ifindex: u32,
        queue: u32,
        cfg: &XskConfig,
        zero_copy: bool,
        mem: Arc<UmemMem>,
        (first, count): (u32, u32),
        owner: Option<RawFd>,
    ) -> io::Result<XskSocket> {
        // SAFETY: socket(2) with constant arguments; the result is checked.
        let raw = cvt(unsafe { ffi::socket(AF_XDP, ffi::SOCK_RAW | ffi::SOCK_CLOEXEC, 0) })?;
        // SAFETY: `raw` was just returned by the kernel and is owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if owner.is_none() {
            let reg = UmemReg {
                addr: mem.ptr.as_ptr() as u64,
                len: mem.len() as u64,
                chunk_size: cfg.frame_size,
                headroom: 0,
                flags: 0,
                tx_metadata_len: 0,
            };
            // The kernel pins the pages of `mem`, which stays allocated until after `fd` (and
            // every socket sharing it) closes.
            setsockopt(fd.as_raw_fd(), XDP_UMEM_REG, &reg)?;
        }
        let n = cfg.ring_size;
        // A socket sharing the UMEM on another queue has fill and completion rings of its own.
        for opt in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            setsockopt(fd.as_raw_fd(), opt, &n)?;
        }
        let mut off = MmapOffsets::default();
        if getsockopt(fd.as_raw_fd(), XDP_MMAP_OFFSETS, &mut off)? < size_of::<MmapOffsets>() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AF_XDP: kernel without ring flags (Linux 5.4+ needed)",
            ));
        }
        let fill = Ring::<u64>::map(fd.as_raw_fd(), PGOFF_FILL_RING, &off.fr, n)?;
        let comp = Ring::<u64>::map(fd.as_raw_fd(), PGOFF_COMPLETION_RING, &off.cr, n)?;
        let rx = Ring::<Desc>::map(fd.as_raw_fd(), PGOFF_RX_RING, &off.rx, n)?;
        let tx = Ring::<Desc>::map(fd.as_raw_fd(), PGOFF_TX_RING, &off.tx, n)?;
        let mut s = XskSocket {
            fill,
            comp,
            rx,
            tx,
            fd,
            mem,
            device: None,
            frame_size: cfg.frame_size,
            sg: cfg.multi_buffer,
            partial: Vec::new(),
            partial_drop: false,
            shared: cfg.shared_umem,
            lo: first as usize * cfg.frame_size as usize,
            hi: (first + count) as usize * cfg.frame_size as usize,
            tx_free: Vec::with_capacity((count - n) as usize),
            staged: None,
            tx_pending: 0,
            zero_copy: false,
            queue,
        };
        let chunk = |i: u32| u64::from(first + i) * u64::from(cfg.frame_size);
        // The first `ring_size` chunks of our slice receive, the rest send.
        for i in 0..n {
            s.fill.produce(chunk(i));
        }
        s.tx_free.extend((n..count).rev().map(chunk));
        // Sockets sharing a UMEM take its owner's mode and flags (the kernel refuses any).
        let flags = match owner {
            Some(_) => XDP_SHARED_UMEM,
            None => {
                XDP_USE_NEED_WAKEUP
                    | if zero_copy { XDP_ZEROCOPY } else { XDP_COPY }
                    | if cfg.multi_buffer { XDP_USE_SG } else { 0 }
            }
        };
        let addr = SockaddrXdp {
            family: AF_XDP as u16,
            flags,
            ifindex,
            queue_id: queue,
            shared_umem_fd: owner.map_or(0, |f| f as u32),
        };
        // SAFETY: `addr` is a valid `sockaddr_xdp` and the length passed is its size.
        cvt(unsafe {
            ffi::bind(
                s.fd.as_raw_fd(),
                (&raw const addr).cast::<ffi::sockaddr>(),
                size_of::<SockaddrXdp>() as ffi::socklen_t,
            )
        })?;
        let mut opts = 0u32;
        if getsockopt(s.fd.as_raw_fd(), XDP_OPTIONS, &mut opts).is_ok() {
            s.zero_copy = opts & XDP_OPTIONS_ZEROCOPY != 0;
        } else {
            s.zero_copy = zero_copy;
        }
        Ok(s)
    }

    /// Opens a socket on `queue` with the UMEM it registers (`mem`, its chunks `range`),
    /// zero-copy first as `cfg` allows.
    fn open(
        ifindex: u32,
        queue: u32,
        cfg: &XskConfig,
        mem: &Arc<UmemMem>,
        range: (u32, u32),
    ) -> io::Result<XskSocket> {
        let new = |zc| Self::new(ifindex, queue, cfg, zc, mem.clone(), range, None);
        match cfg.zero_copy {
            ZeroCopy::Off => new(false),
            ZeroCopy::Required => new(true),
            _ => match new(true) {
                Err(e) if zc_unsupported(&e) => new(false),
                r => r,
            },
        }
    }

    /// The socket's descriptor (for `poll`).
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The queue it is bound to.
    pub fn queue(&self) -> u32 {
        self.queue
    }

    /// Bound in zero-copy mode.
    pub fn zero_copy(&self) -> bool {
        self.zero_copy
    }

    /// Largest frame [`alloc`](Self::alloc) takes (larger ones go through
    /// [`send_frags`](Self::send_frags) with `multi_buffer`).
    pub fn max_frame(&self) -> usize {
        self.frame_size as usize
    }

    /// Bound with `XDP_USE_SG`: frames may span several chunks.
    pub fn multi_buffer(&self) -> bool {
        self.sg
    }

    /// Shares its UMEM with the other queues' sockets.
    pub fn shared_umem(&self) -> bool {
        self.shared
    }

    /// Copies the next received frame into `buf` (resized to it) and gives its chunks back to
    /// the kernel. `None` when nothing (or only part of a multi-buffer frame) is pending.
    pub fn recv(&mut self, buf: &mut Vec<u8>) -> Option<()> {
        loop {
            if self.rx.available() == 0 {
                if self.fill.needs_wakeup() {
                    self.wake_rx();
                }
                return None;
            }
            let d = self.rx.consume();
            let (start, len) = (d.addr as usize, d.len as usize);
            let chunk = d.addr & !u64::from(self.frame_size - 1);
            let more = self.sg && d.options & XDP_PKT_CONTD != 0;
            let ours = start >= self.lo
                && start
                    .checked_add(len)
                    .is_some_and(|end| end <= self.hi && end <= self.mem.len());
            if !ours {
                // Not a chunk of ours (cannot happen with a sane kernel): never touch it.
                if !more {
                    self.partial.clear();
                    self.partial_drop = false;
                }
                continue;
            }
            let data: &[u8] = {
                // SAFETY: `start..start + len` lies inside this socket's slice of the UMEM
                // (checked above); the kernel handed this chunk to us on the RX ring and does
                // not write it until we put it back on the fill ring below, after the copy.
                unsafe { std::slice::from_raw_parts(self.mem.ptr.as_ptr().add(start), len) }
            };
            if !more && self.partial.is_empty() && !self.partial_drop {
                buf.clear();
                buf.extend_from_slice(data);
                self.recycle(chunk);
                return Some(());
            }
            // A frame over several descriptors.
            if self.partial.len() + data.len() > MAX_SG_FRAME {
                self.partial_drop = true;
                self.partial.clear();
            } else if !self.partial_drop {
                self.partial.extend_from_slice(data);
            }
            self.recycle(chunk);
            if more {
                continue;
            }
            if std::mem::take(&mut self.partial_drop) {
                continue;
            }
            buf.clear();
            buf.extend_from_slice(&self.partial);
            self.partial.clear();
            return Some(());
        }
    }

    /// Returns a received chunk to the fill ring (or, if it has no room, to the TX pool).
    fn recycle(&mut self, chunk: u64) {
        if self.fill.free() > 0 {
            self.fill.produce(chunk);
        } else {
            self.tx_free.push(chunk);
        }
    }

    fn wake_rx(&self) {
        // SAFETY: a zero-length, non-blocking recvfrom with no buffers or address: it only
        // makes the kernel look at the fill ring again.
        unsafe {
            ffi::recvfrom(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                0,
                ffi::MSG_DONTWAIT,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
    }

    fn kick_tx(&mut self) {
        // SAFETY: an all-zero `msghdr` (no address, no buffers, no control data) is valid;
        // AF_XDP's sendmsg only starts transmitting what is on the TX ring.
        let msg: ffi::msghdr = unsafe { std::mem::zeroed() };
        // SAFETY: `msg` is a valid msghdr that lives across the call.
        unsafe { ffi::sendmsg(self.fd.as_raw_fd(), &raw const msg, ffi::MSG_DONTWAIT) };
        self.tx_pending = 0;
    }

    /// Takes back TX chunks the kernel finished with.
    fn reap(&mut self) {
        let n = self.comp.available();
        for _ in 0..n {
            let a = self.comp.consume() & !u64::from(self.frame_size - 1);
            if (self.lo..self.hi).contains(&(a as usize)) {
                self.tx_free.push(a);
            }
        }
    }

    /// Reserves a TX chunk for a frame of `len` bytes; false when none is free (the frame is
    /// to be dropped, like on a full NIC ring).
    pub fn alloc(&mut self, len: usize) -> bool {
        if let Some((a, _)) = self.staged.take() {
            self.tx_free.push(a);
        }
        if len > self.frame_size as usize {
            return false;
        }
        if self.tx_free.is_empty() || self.tx.free() == 0 {
            if self.tx_pending > 0 {
                self.kick_tx();
            }
            self.reap();
        }
        if self.tx.free() == 0 {
            return false;
        }
        match self.tx_free.pop() {
            Some(a) => {
                self.staged = Some((a, len));
                true
            }
            None => false,
        }
    }

    /// The reserved chunk, `len` bytes, to write the frame into.
    pub fn staged_mut(&mut self) -> &mut [u8] {
        let Some((a, len)) = self.staged else {
            return &mut [];
        };
        debug_assert!(a as usize + len <= self.mem.len());
        // SAFETY: the chunk `a` came from this socket's TX pool, so this socket owns it (it is
        // on no ring, and in this socket's slice of a shared UMEM) and `a + len` is inside the
        // UMEM (`len <= frame_size`, chunks are frame aligned); the slice borrows `self`
        // mutably, so nothing else reads or writes the chunk meanwhile.
        unsafe { std::slice::from_raw_parts_mut(self.mem.ptr.as_ptr().add(a as usize), len) }
    }

    /// Queues the reserved frame on the TX ring (sent at the next [`flush`](Self::flush)).
    pub fn commit(&mut self) {
        if let Some((addr, len)) = self.staged.take() {
            // `alloc` checked there is room.
            self.tx.produce(Desc {
                addr,
                len: len as u32,
                options: 0,
            });
            self.tx_pending += 1;
        }
    }

    /// Queues `frame`, larger than a chunk, over several TX descriptors (`multi_buffer`);
    /// false when it cannot be sent now (the frame is to be dropped, like on a full NIC ring).
    pub fn send_frags(&mut self, frame: &[u8]) -> bool {
        if let Some((a, _)) = self.staged.take() {
            self.tx_free.push(a);
        }
        let size = self.frame_size as usize;
        let n = frame.len().div_ceil(size);
        if !self.sg || n == 0 || n > MAX_FRAGS {
            return false;
        }
        if self.tx_free.len() < n || (self.tx.free() as usize) < n {
            if self.tx_pending > 0 {
                self.kick_tx();
            }
            self.reap();
        }
        if self.tx_free.len() < n || (self.tx.free() as usize) < n {
            return false;
        }
        for (k, piece) in frame.chunks(size).enumerate() {
            let Some(a) = self.tx_free.pop() else {
                return false; // checked above
            };
            debug_assert!(a as usize + piece.len() <= self.mem.len());
            // SAFETY: the chunk `a` came from this socket's TX pool, so this socket owns it
            // (it is on no ring) and `a + piece.len()` is inside the UMEM (`piece.len() <=
            // frame_size`, chunks are frame aligned); nothing else reads or writes it until the
            // descriptor is submitted below.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    piece.as_ptr(),
                    self.mem.ptr.as_ptr().add(a as usize),
                    piece.len(),
                );
            }
            let last = k + 1 == n;
            self.tx.stage(
                k as u32,
                Desc {
                    addr: a,
                    len: piece.len() as u32,
                    options: if last { 0 } else { XDP_PKT_CONTD },
                },
            );
        }
        // Every descriptor of the frame becomes visible at once.
        self.tx.submit(n as u32);
        self.tx_pending += n as u32;
        true
    }

    /// Starts transmitting what was committed and takes back completed chunks.
    pub fn flush(&mut self) {
        if self.tx_pending > 0 && (!self.zero_copy || self.tx.needs_wakeup()) {
            self.kick_tx();
        }
        self.tx_pending = 0;
        self.reap();
    }

    /// Waits until a frame may have arrived, at most `timeout`.
    pub fn wait(&self, timeout: Duration) {
        let mut p = ffi::pollfd {
            fd: self.fd.as_raw_fd(),
            events: ffi::POLLIN,
            revents: 0,
        };
        let t = timeout.min(Duration::from_secs(1));
        let ts = ffi::timespec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: ffi::c_long::from(t.subsec_nanos() as i32),
        };
        // SAFETY: `p` is one valid `pollfd`, `ts` a valid timespec; no signal mask is passed.
        let _ = unsafe { ffi::ppoll(&raw mut p, 1, &raw const ts, std::ptr::null()) };
    }

    /// The kernel's counters for this socket.
    pub fn stats(&self) -> io::Result<XskStats> {
        let mut v = [0u64; 6];
        getsockopt(self.fd.as_raw_fd(), XDP_STATISTICS, &mut v)?;
        Ok(XskStats {
            rx_dropped: v[0],
            rx_invalid_descs: v[1],
            tx_invalid_descs: v[2],
            rx_ring_full: v[3],
            rx_fill_ring_empty_descs: v[4],
            tx_ring_empty_descs: v[5],
        })
    }
}

/// Opens one AF_XDP socket per queue `0..cfg.queues` of interface `ifindex`, puts them in an
/// `XSKMAP` and attaches the program redirecting each queue's frames to its socket (frames of
/// other queues go to the kernel). The program is detached when the last socket is dropped (or
/// when the process exits). Needs `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_BPF` (or root).
pub fn open(ifindex: u32, cfg: &XskConfig) -> io::Result<(Vec<XskSocket>, XskInfo)> {
    use crate::sys;
    cfg.check()?;
    let map = sys::Map::<u32, u32>::create(sys::MAP_XSKMAP, cfg.queues)?;
    let prog = sys::prog_load_flags(
        sys::PROG_XDP,
        0,
        &crate::ebpf::xdp_redirect_xsk(map.fd()),
        "akio_xsk_redir",
        if cfg.multi_buffer {
            sys::BPF_F_XDP_HAS_FRAGS
        } else {
            0
        },
    )?;
    let per = cfg.per_socket();
    let size = cfg.frame_size as usize;
    let mut socks: Vec<XskSocket> = Vec::with_capacity(cfg.queues as usize);
    let shared = if cfg.shared_umem {
        Some(Arc::new(UmemMem::new((per * cfg.queues) as usize * size)?))
    } else {
        None
    };
    for q in 0..cfg.queues {
        let s = match (&shared, socks.first()) {
            (Some(mem), Some(owner)) => XskSocket::new(
                ifindex,
                q,
                cfg,
                owner.zero_copy,
                mem.clone(),
                (q * per, per),
                Some(owner.fd()),
            )?,
            (Some(mem), None) => XskSocket::open(ifindex, q, cfg, mem, (0, per))?,
            (None, _) => {
                let mem = Arc::new(UmemMem::new(per as usize * size)?);
                XskSocket::open(ifindex, q, cfg, &mem, (0, per))?
            }
        };
        map.update(&q, &(s.fd() as u32))?;
        socks.push(s);
    }
    let (link, mode, attachment) = ProgLink::attach(ifindex, prog, cfg.mode, false)?;
    let device = Arc::new(Device {
        ifindex,
        link: Some(link),
        _map: map,
    });
    let zero_copy = socks.iter().all(XskSocket::zero_copy);
    for s in &mut socks {
        s.device = Some(device.clone());
    }
    Ok((
        socks,
        XskInfo {
            ifindex,
            mode,
            attachment,
            zero_copy,
            queues: cfg.queues,
            shared_umem: cfg.shared_umem,
            multi_buffer: cfg.multi_buffer,
        },
    ))
}

/// Interface index of `name`.
pub fn if_index(name: &str) -> io::Result<u32> {
    crate::sys::if_index(name)
}

/// Whether AF_XDP sockets, an `XSKMAP` and the redirect program can be created (privileged);
/// nothing is attached.
pub(crate) fn probe() -> io::Result<()> {
    use crate::sys;
    // SAFETY: socket(2) with constant arguments; the result is checked and closed.
    let raw = cvt(unsafe { ffi::socket(AF_XDP, ffi::SOCK_RAW | ffi::SOCK_CLOEXEC, 0) })?;
    // SAFETY: `raw` was just returned by the kernel and is owned by nobody else.
    drop(unsafe { OwnedFd::from_raw_fd(raw) });
    let map = sys::Map::<u32, u32>::create(sys::MAP_XSKMAP, 1)?;
    sys::prog_load(
        sys::PROG_XDP,
        0,
        &crate::ebpf::xdp_redirect_xsk(map.fd()),
        "akio_xsk_probe",
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_limits() {
        assert!(XskConfig::default().check().is_ok());
        let shared = XskConfig {
            queues: 2,
            frames: 8192,
            shared_umem: true,
            ..XskConfig::default()
        };
        assert!(shared.check().is_ok());
        assert_eq!(shared.per_socket(), 4096);
        for bad in [
            XskConfig {
                queues: 0,
                ..XskConfig::default()
            },
            XskConfig {
                frame_size: 1500,
                ..XskConfig::default()
            },
            XskConfig {
                ring_size: 1000,
                ..XskConfig::default()
            },
            XskConfig {
                frames: 1024,
                ..XskConfig::default()
            },
            XskConfig {
                queues: 4,
                shared_umem: true,
                ..XskConfig::default()
            },
        ] {
            assert_eq!(bad.check().unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }
}
