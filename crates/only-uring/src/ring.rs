//! Own io_uring bindings (replacing the `io-uring` crate): the `io_uring_setup` /
//! `io_uring_enter` / `io_uring_register` system calls, the shared SQ/CQ rings and SQE array
//! mapped from the ring fd, submission entries for the operations the reactor uses, completion
//! flags, and opcode / feature probing.
//!
//! Memory ordering follows the kernel's protocol (`io_uring(7)`): the application publishes the
//! SQ tail with `Release` and reads the kernel's SQ head with `Acquire`; it reads the kernel's CQ
//! tail with `Acquire` and publishes its CQ head with `Release` after copying the entries out.
//! With SQPOLL, a `SeqCst` fence orders the tail store before reading `IORING_SQ_NEED_WAKEUP`.
//! Structure layouts are those of `<linux/io_uring.h>`, checked by compile-time assertions.
//! Items marked `#[cfg(test)]` (`SEND`, `SEND_ZC`, direct accept and registered files,
//! `MSG_RING`) serve only the measurement harness in `eval.rs` and the unit tests: the engine
//! does not use them (docs/BENCHMARKS.md, "io_uring features evaluation").

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    sync::atomic::{AtomicU32, Ordering, fence},
    time::Duration,
};

use only_sys::ffi::{self, c_long, c_void};

// ---- UAPI constants ----------------------------------------------------------------------------

/// `IORING_SETUP_*`.
pub(crate) const SETUP_SQPOLL: u32 = 1 << 1;
pub(crate) const SETUP_CQSIZE: u32 = 1 << 3;
pub(crate) const SETUP_R_DISABLED: u32 = 1 << 6;
pub(crate) const SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub(crate) const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
pub(crate) const SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const SETUP_IOPOLL: u32 = 1 << 0;

/// `IORING_FEAT_*`.
const FEAT_SINGLE_MMAP: u32 = 1 << 0;
const FEAT_NODROP: u32 = 1 << 1;
pub(crate) const FEAT_EXT_ARG: u32 = 1 << 8;

/// `IORING_ENTER_*`.
const ENTER_GETEVENTS: u32 = 1 << 0;
const ENTER_SQ_WAKEUP: u32 = 1 << 1;
const ENTER_EXT_ARG: u32 = 1 << 3;

/// `IORING_SQ_*` (the SQ ring's `flags` word).
const SQ_NEED_WAKEUP: u32 = 1 << 0;
const SQ_CQ_OVERFLOW: u32 = 1 << 1;
const SQ_TASKRUN: u32 = 1 << 2;

/// mmap offsets of the ring fd.
const OFF_SQ_RING: i64 = 0;
const OFF_CQ_RING: i64 = 0x0800_0000;
const OFF_SQES: i64 = 0x1000_0000;

/// `IORING_REGISTER_*`.
#[cfg(test)]
const REGISTER_FILES: u32 = 2;
const REGISTER_PROBE: u32 = 8;
const REGISTER_ENABLE_RINGS: u32 = 12;
const REGISTER_PBUF_RING: u32 = 22;
const UNREGISTER_PBUF_RING: u32 = 23;
#[cfg(test)]
const REGISTER_SEND_MSG_RING: u32 = 31;

/// `IORING_OP_*`.
pub(crate) const OP_POLL_ADD: u8 = 6;
pub(crate) const OP_ACCEPT: u8 = 13;
pub(crate) const OP_ASYNC_CANCEL: u8 = 14;
pub(crate) const OP_READ: u8 = 22;
#[cfg(test)]
const OP_SEND: u8 = 26;
pub(crate) const OP_RECV: u8 = 27;
#[cfg(test)]
const OP_CLOSE: u8 = 19;
#[cfg(test)]
const OP_MSG_RING: u8 = 40;
#[cfg(test)]
const OP_SEND_ZC: u8 = 47;

/// `IOSQE_FIXED_FILE`: `fd` is an index into the registered file table.
#[cfg(test)]
const IOSQE_FIXED_FILE: u8 = 1 << 0;
/// `IORING_SEND_ZC_REPORT_USAGE` (in `ioprio`): the notification says whether data was copied.
#[cfg(test)]
const SEND_ZC_REPORT_USAGE: u16 = 1 << 3;
/// `IORING_FILE_INDEX_ALLOC`: let the kernel pick a free slot of the file table.
#[cfg(test)]
const FILE_INDEX_ALLOC: u32 = !0;
/// `MSG_NOSIGNAL` (a reset peer fails the send with `EPIPE` instead of raising `SIGPIPE`).
#[cfg(test)]
const MSG_NOSIGNAL: u32 = 0x4000;
/// `IORING_MSG_DATA` (the `MSG_RING` command in `addr`).
#[cfg(test)]
const MSG_DATA: u64 = 0;

/// `IOSQE_BUFFER_SELECT`.
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
/// `IORING_ACCEPT_MULTISHOT` (in `ioprio`).
const ACCEPT_MULTISHOT: u16 = 1 << 0;
/// `IORING_RECV_MULTISHOT` (in `ioprio`).
const RECV_MULTISHOT: u16 = 1 << 1;
/// `IORING_ASYNC_CANCEL_ANY`.
const ASYNC_CANCEL_ANY: u32 = 1 << 2;

/// `IORING_CQE_F_*`.
const CQE_F_BUFFER: u32 = 1 << 0;
const CQE_F_MORE: u32 = 1 << 1;
#[cfg(test)]
const CQE_F_NOTIF: u32 = 1 << 3;
/// `IORING_NOTIF_USAGE_ZC_COPIED`: in a `SEND_ZC` notification, the kernel copied the data.
#[cfg(test)]
const NOTIF_USAGE_ZC_COPIED: i32 = 1 << 31;
const CQE_BUFFER_SHIFT: u32 = 16;

/// `IO_URING_OP_SUPPORTED`.
const PROBE_OP_SUPPORTED: u16 = 1;

// ---- UAPI structures ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

/// `struct io_uring_params`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
}

/// `struct io_uring_sqe` (64 bytes), with each union spelled by the member the reactor uses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    /// `off` / `addr2`.
    off: u64,
    /// `addr` / `splice_off_in`.
    addr: u64,
    len: u32,
    /// `rw_flags` / `poll32_events` / `accept_flags` / `cancel_flags` / `msg_flags` ...
    op_flags: u32,
    user_data: u64,
    /// `buf_index` / `buf_group`.
    buf_group: u16,
    personality: u16,
    /// `splice_fd_in` / `file_index`.
    file_index: u32,
    addr3: u64,
    pad2: u64,
}

/// `struct io_uring_cqe` (without `IORING_SETUP_CQE32`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

/// `struct io_uring_getevents_arg`.
#[repr(C)]
struct GeteventsArg {
    sigmask: u64,
    sigmask_sz: u32,
    min_wait_usec: u32,
    ts: u64,
}

/// `struct __kernel_timespec`.
#[repr(C)]
struct KernelTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// `struct io_uring_buf_reg`.
#[repr(C)]
struct BufReg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

/// `struct io_uring_probe_op`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

const PROBE_OPS: usize = 256;

/// `struct io_uring_probe` with room for 256 opcodes.
#[repr(C)]
pub(crate) struct Probe {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
    ops: [ProbeOp; PROBE_OPS],
}

const _: () = assert!(size_of::<SqringOffsets>() == 40 && size_of::<CqringOffsets>() == 40);
const _: () = assert!(size_of::<Params>() == 120);
const _: () = assert!(size_of::<Sqe>() == 64 && align_of::<Sqe>() == 8);
const _: () = assert!(std::mem::offset_of!(Sqe, user_data) == 32);
const _: () = assert!(std::mem::offset_of!(Sqe, buf_group) == 40);
const _: () = assert!(std::mem::offset_of!(Sqe, file_index) == 44);
const _: () = assert!(std::mem::offset_of!(Sqe, addr3) == 48);
const _: () = assert!(size_of::<Cqe>() == 16);
const _: () = assert!(size_of::<GeteventsArg>() == 24);
const _: () = assert!(size_of::<KernelTimespec>() == 16);
const _: () = assert!(size_of::<BufReg>() == 40);
const _: () = assert!(size_of::<ProbeOp>() == 8);
const _: () = assert!(size_of::<Probe>() == 16 + 8 * PROBE_OPS);

// ---- submission entries ------------------------------------------------------------------------

impl Sqe {
    /// `IORING_OP_READ` of `len` bytes into `buf` (offset 0: a non-seekable fd).
    pub(crate) fn read(fd: RawFd, buf: *mut u8, len: u32) -> Sqe {
        Sqe {
            opcode: OP_READ,
            fd,
            addr: buf as u64,
            len,
            ..Sqe::default()
        }
    }

    /// Multishot `IORING_OP_ACCEPT` (5.19+): one completion per accepted connection, no peer
    /// address, no accept flags (the reactor configures each socket itself).
    pub(crate) fn accept_multi(fd: RawFd) -> Sqe {
        Sqe {
            opcode: OP_ACCEPT,
            fd,
            ioprio: ACCEPT_MULTISHOT,
            ..Sqe::default()
        }
    }

    /// Multishot `IORING_OP_RECV` (6.0+) with buffer selection from provided-buffer group
    /// `bgid`.
    pub(crate) fn recv_multi(fd: RawFd, bgid: u16) -> Sqe {
        Sqe {
            opcode: OP_RECV,
            flags: IOSQE_BUFFER_SELECT,
            ioprio: RECV_MULTISHOT,
            fd,
            buf_group: bgid,
            ..Sqe::default()
        }
    }

    /// One-shot `IORING_OP_POLL_ADD` for `events` (`POLL*` bits, 32-bit field, little-endian).
    pub(crate) fn poll_add(fd: RawFd, events: u32) -> Sqe {
        Sqe {
            opcode: OP_POLL_ADD,
            fd,
            op_flags: events,
            ..Sqe::default()
        }
    }

    /// `IORING_OP_ASYNC_CANCEL` of the request submitted with `user_data`.
    pub(crate) fn async_cancel(user_data: u64) -> Sqe {
        Sqe {
            opcode: OP_ASYNC_CANCEL,
            fd: -1,
            addr: user_data,
            ..Sqe::default()
        }
    }

    /// `IORING_OP_ASYNC_CANCEL` with `IORING_ASYNC_CANCEL_ANY` (5.19+): every request in flight.
    pub(crate) fn async_cancel_any() -> Sqe {
        Sqe {
            opcode: OP_ASYNC_CANCEL,
            fd: -1,
            op_flags: ASYNC_CANCEL_ANY,
            ..Sqe::default()
        }
    }

    #[cfg(test)]
    /// `IORING_OP_MSG_RING` / `IORING_MSG_DATA` (5.18+): posts a completion with `user_data`
    /// and result `res` to the ring `target` (a ring fd), without touching its submission queue.
    pub(crate) fn msg_ring(target: RawFd, res: u32, user_data: u64) -> Sqe {
        Sqe {
            opcode: OP_MSG_RING,
            fd: target,
            addr: MSG_DATA,
            off: user_data,
            len: res,
            ..Sqe::default()
        }
    }

    #[cfg(test)]
    /// `IORING_OP_SEND` of `len` bytes at `buf`.
    pub(crate) fn send(fd: RawFd, buf: *const u8, len: u32) -> Sqe {
        Sqe {
            opcode: OP_SEND,
            fd,
            addr: buf as u64,
            len,
            op_flags: MSG_NOSIGNAL,
            ..Sqe::default()
        }
    }

    #[cfg(test)]
    /// `IORING_OP_SEND_ZC` (6.0+) of `len` bytes at `buf`: completes once with the result
    /// (`F_MORE` set), then again with `F_NOTIF` when the kernel no longer uses the buffer.
    pub(crate) fn send_zc(fd: RawFd, buf: *const u8, len: u32) -> Sqe {
        Sqe {
            opcode: OP_SEND_ZC,
            ioprio: SEND_ZC_REPORT_USAGE,
            ..Sqe::send(fd, buf, len)
        }
    }

    #[cfg(test)]
    /// Multishot accept straight into the registered file table (`IORING_ACCEPT_DIRECT`, 5.19+):
    /// each completion's result is the slot the kernel picked, not a descriptor.
    pub(crate) fn accept_multi_direct(fd: RawFd) -> Sqe {
        Sqe {
            file_index: FILE_INDEX_ALLOC,
            ..Sqe::accept_multi(fd)
        }
    }

    #[cfg(test)]
    /// `IORING_OP_CLOSE` of registered-file slot `slot`.
    pub(crate) fn close_fixed(slot: u32) -> Sqe {
        Sqe {
            opcode: OP_CLOSE,
            file_index: slot + 1,
            ..Sqe::default()
        }
    }

    #[cfg(test)]
    /// Names the file by registered-table slot (`IOSQE_FIXED_FILE`) instead of descriptor.
    #[must_use]
    pub(crate) fn fixed(mut self) -> Sqe {
        self.flags |= IOSQE_FIXED_FILE;
        self
    }

    /// Sets the value the completion carries back.
    #[must_use]
    pub(crate) fn user_data(mut self, v: u64) -> Sqe {
        self.user_data = v;
        self
    }
}

// ---- completion flags --------------------------------------------------------------------------

/// `IORING_CQE_F_MORE`: the (multishot) request stays armed and will complete again.
pub(crate) fn cqe_more(flags: u32) -> bool {
    flags & CQE_F_MORE != 0
}

#[cfg(test)]
/// `IORING_CQE_F_NOTIF`: a `SEND_ZC` notification (the buffer is free again).
pub(crate) fn cqe_notif(flags: u32) -> bool {
    flags & CQE_F_NOTIF != 0
}

#[cfg(test)]
/// In a `SEND_ZC` notification's result: the kernel fell back to copying the data.
pub(crate) fn notif_copied(res: i32) -> bool {
    res & NOTIF_USAGE_ZC_COPIED != 0
}

/// `IORING_CQE_F_BUFFER`: the provided buffer the kernel selected for this completion.
pub(crate) fn cqe_buffer(flags: u32) -> Option<u16> {
    (flags & CQE_F_BUFFER != 0).then_some((flags >> CQE_BUFFER_SHIFT) as u16)
}

// ---- system calls ------------------------------------------------------------------------------

fn cvt(r: c_long) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

/// A shared mapping of part of the ring fd, unmapped on drop.
struct Mmap {
    addr: *mut c_void,
    len: usize,
}

impl Mmap {
    fn new(fd: RawFd, offset: i64, len: usize) -> io::Result<Mmap> {
        // SAFETY: a fresh shared mapping chosen by the kernel (no address hint), of a region the
        // ring fd exposes at `offset`; nothing else refers to it yet.
        let addr = unsafe {
            ffi::mmap(
                ptr::null_mut(),
                len,
                ffi::PROT_READ | ffi::PROT_WRITE,
                ffi::MAP_SHARED | ffi::MAP_POPULATE,
                fd,
                offset,
            )
        };
        if addr == ffi::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap { addr, len })
    }

    /// `offset` bytes into the mapping (checked to leave room for a `T`).
    fn at<T>(&self, offset: u32) -> *mut T {
        let off = offset as usize;
        assert!(
            off.checked_add(size_of::<T>())
                .is_some_and(|e| e <= self.len),
            "io_uring ring offset outside its mapping"
        );
        self.addr.cast::<u8>().wrapping_add(off).cast()
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: the mapping was created in `new` with this address and length, and every
        // pointer into it belongs to the `Ring` that is being dropped.
        unsafe { ffi::munmap(self.addr, self.len) };
    }
}

/// An io_uring instance: the ring fd and its mapped submission / completion rings.
pub(crate) struct Ring {
    // Pointers into `maps` (kernel-shared words and arrays).
    sq_head: *const AtomicU32,
    sq_ktail: *const AtomicU32,
    sq_flags: *const AtomicU32,
    sq_mask: u32,
    sq_entries: u32,
    sqes: *mut Sqe,
    /// Our copy of the SQ tail (we are its only writer).
    sq_tail: u32,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const Cqe,
    flags: u32,
    features: u32,
    _maps: Vec<Mmap>,
    fd: OwnedFd,
}

impl std::fmt::Debug for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ring").finish_non_exhaustive()
    }
}

impl Ring {
    /// `io_uring_setup(entries)` with setup `flags` (`SETUP_*`), a CQ of `cq_entries` when
    /// `SETUP_CQSIZE` is set and an SQPOLL idle time of `sq_thread_idle` ms, then maps the rings.
    pub(crate) fn new(
        entries: u32,
        flags: u32,
        cq_entries: u32,
        sq_thread_idle: u32,
    ) -> io::Result<Ring> {
        let mut p = Params {
            flags,
            cq_entries,
            sq_thread_idle,
            ..Params::default()
        };
        // SAFETY: `p` is a valid, zero-initialised `io_uring_params` the kernel reads and
        // writes during the call.
        let fd = cvt(unsafe {
            ffi::syscall(
                ffi::SYS_io_uring_setup,
                c_long::from(entries),
                (&raw mut p).cast::<c_void>(),
            )
        })?;
        // SAFETY: a fresh descriptor from the kernel that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        let raw = fd.as_raw_fd();
        let sq_len = p.sq_off.array as usize + p.sq_entries as usize * size_of::<u32>();
        let cq_len = p.cq_off.cqes as usize + p.cq_entries as usize * size_of::<Cqe>();
        let sqe_map = Mmap::new(raw, OFF_SQES, p.sq_entries as usize * size_of::<Sqe>())?;
        let (sq_map, cq_map) = if p.features & FEAT_SINGLE_MMAP != 0 {
            (Mmap::new(raw, OFF_SQ_RING, sq_len.max(cq_len))?, None)
        } else {
            (
                Mmap::new(raw, OFF_SQ_RING, sq_len)?,
                Some(Mmap::new(raw, OFF_CQ_RING, cq_len)?),
            )
        };
        let cq = cq_map.as_ref().unwrap_or(&sq_map);
        let sq_array = sq_map.at::<u32>(p.sq_off.array);
        // Bounds of the arrays (the scalar words are checked by `at`).
        let _ = sq_map.at::<u32>(p.sq_off.array + (p.sq_entries - 1) * 4);
        let _ = cq.at::<Cqe>(p.cq_off.cqes + (p.cq_entries - 1) * size_of::<Cqe>() as u32);
        // SAFETY: all offsets come from the kernel and lie inside the mappings (checked by `at`);
        // the ring masks are plain words the kernel wrote before io_uring_setup returned, and the
        // SQ index array has `sq_entries` slots that only we write.
        let (sq_mask, cq_mask) = unsafe {
            for i in 0..p.sq_entries {
                sq_array.add(i as usize).write(i);
            }
            (
                *sq_map.at::<u32>(p.sq_off.ring_mask),
                *cq.at::<u32>(p.cq_off.ring_mask),
            )
        };
        let ring = Ring {
            sq_head: sq_map.at(p.sq_off.head),
            sq_ktail: sq_map.at(p.sq_off.tail),
            sq_flags: sq_map.at(p.sq_off.flags),
            sq_mask,
            sq_entries: p.sq_entries,
            sqes: sqe_map.addr.cast(),
            // SAFETY: the tail is a 4-aligned word inside the mapping; only we write it.
            sq_tail: unsafe { (*sq_map.at::<AtomicU32>(p.sq_off.tail)).load(Ordering::Relaxed) },
            cq_head: cq.at(p.cq_off.head),
            cq_tail: cq.at(p.cq_off.tail),
            cq_mask,
            cqes: cq.at(p.cq_off.cqes),
            flags: p.flags,
            features: p.features,
            _maps: [Some(sqe_map), Some(sq_map), cq_map]
                .into_iter()
                .flatten()
                .collect(),
            fd,
        };
        Ok(ring)
    }

    /// The `IORING_FEAT_*` bits the kernel reported.
    pub(crate) fn features(&self) -> u32 {
        self.features
    }

    fn sq_head(&self) -> u32 {
        // SAFETY: `sq_head` points to a 4-aligned word of the live SQ mapping, written by the
        // kernel; reading it as an atomic is the protocol.
        unsafe { (*self.sq_head).load(Ordering::Acquire) }
    }

    fn sq_flags(&self) -> u32 {
        // SAFETY: as in `sq_head`, for the SQ flags word.
        unsafe { (*self.sq_flags).load(Ordering::Acquire) }
    }

    fn sq_len(&self) -> u32 {
        self.sq_tail.wrapping_sub(self.sq_head())
    }

    /// No entry is waiting for the kernel to consume it.
    pub(crate) fn sq_is_empty(&self) -> bool {
        self.sq_len() == 0
    }

    /// Queues `e`; `Err(())` when the submission queue is full (submit, then retry).
    ///
    /// # Safety
    ///
    /// Every buffer or pointer `e` refers to must stay valid, and not be accessed in a way that
    /// conflicts with the kernel's use, until the request's final completion is reaped.
    pub(crate) unsafe fn push(&mut self, e: &Sqe) -> Result<(), ()> {
        if self.sq_len() >= self.sq_entries {
            return Err(());
        }
        let idx = (self.sq_tail & self.sq_mask) as usize;
        // SAFETY: `idx < sq_entries` (the mask is `sq_entries - 1`); the slot is not owned by the
        // kernel (the queue is not full, so the slot at our tail was consumed already). The
        // tail store with `Release` publishes the entry to the kernel.
        unsafe {
            self.sqes.add(idx).write(*e);
            self.sq_tail = self.sq_tail.wrapping_add(1);
            (*self.sq_ktail).store(self.sq_tail, Ordering::Release);
        }
        Ok(())
    }

    /// Moves every available completion into `out` as `(user_data, res, flags)`.
    pub(crate) fn reap_into(&mut self, out: &mut Vec<(u64, i32, u32)>) {
        // SAFETY: `cq_head` / `cq_tail` are 4-aligned words of the live CQ mapping; we are the
        // only writer of the head. Entries between head and tail (Acquire) are written by the
        // kernel and ours to read until the head store (Release) hands their slots back.
        unsafe {
            let mut head = (*self.cq_head).load(Ordering::Relaxed);
            let tail = (*self.cq_tail).load(Ordering::Acquire);
            while head != tail {
                let c = self.cqes.add((head & self.cq_mask) as usize).read();
                out.push((c.user_data, c.res, c.flags));
                head = head.wrapping_add(1);
            }
            (*self.cq_head).store(head, Ordering::Release);
        }
    }

    /// `io_uring_enter`.
    fn enter(
        &self,
        min_complete: u32,
        flags: u32,
        arg: *const c_void,
        argsz: usize,
    ) -> io::Result<usize> {
        // SAFETY: the ring fd is live; `arg` is null or points to a live `GeteventsArg` of
        // `argsz` bytes (with `ENTER_EXT_ARG`).
        cvt(unsafe {
            ffi::syscall(
                ffi::SYS_io_uring_enter,
                c_long::from(self.fd.as_raw_fd()),
                c_long::from(self.sq_len()),
                c_long::from(min_complete),
                c_long::from(flags),
                arg,
                argsz,
            )
        })
    }

    /// The enter flags for a submission waiting for `want` completions, or `None` when no
    /// system call is needed (an awake SQPOLL thread picks the entries up).
    fn enter_flags(&self, want: u32, mut flags: u32) -> Option<u32> {
        let sqf = self.sq_flags();
        let overflow = sqf & SQ_CQ_OVERFLOW != 0;
        let taskrun = sqf & SQ_TASKRUN != 0;
        let need_syscall = (overflow && self.features & FEAT_NODROP != 0) || taskrun;
        // Deferred task work only runs in an enter carrying GETEVENTS.
        if want > 0 || self.flags & SETUP_IOPOLL != 0 || overflow || taskrun {
            flags |= ENTER_GETEVENTS;
        }
        if self.flags & SETUP_SQPOLL != 0 {
            // Orders our tail store before the read of NEED_WAKEUP (io_uring(7)).
            fence(Ordering::SeqCst);
            // SAFETY: as in `sq_flags`.
            let wakeup = unsafe { (*self.sq_flags).load(Ordering::Relaxed) } & SQ_NEED_WAKEUP;
            if wakeup != 0 {
                flags |= ENTER_SQ_WAKEUP;
            } else if want == 0 && !need_syscall {
                return None;
            }
        }
        Some(flags)
    }

    /// Submits the queued entries.
    pub(crate) fn submit(&self) -> io::Result<usize> {
        self.submit_and_wait(0)
    }

    /// Submits the queued entries and waits for `want` completions.
    pub(crate) fn submit_and_wait(&self, want: u32) -> io::Result<usize> {
        match self.enter_flags(want, 0) {
            Some(flags) => self.enter(want, flags, ptr::null(), 0),
            None => Ok(self.sq_len() as usize),
        }
    }

    /// Submits the queued entries and waits for `want` completions or `timeout`, whichever
    /// comes first (`ETIME` on timeout; `IORING_ENTER_EXT_ARG`, 5.11+).
    pub(crate) fn submit_with_timeout(&self, want: u32, timeout: Duration) -> io::Result<usize> {
        let Some(flags) = self.enter_flags(want, ENTER_EXT_ARG) else {
            return Ok(self.sq_len() as usize);
        };
        let ts = KernelTimespec {
            tv_sec: timeout.as_secs() as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        let arg = GeteventsArg {
            sigmask: 0,
            sigmask_sz: 0,
            min_wait_usec: 0,
            ts: (&raw const ts) as u64,
        };
        self.enter(
            want,
            flags,
            (&raw const arg).cast(),
            size_of::<GeteventsArg>(),
        )
    }

    /// `io_uring_register(opcode, arg, nr_args)`.
    ///
    /// # Safety
    ///
    /// `arg` must be what `opcode` expects, valid for the kernel's reads and writes during the
    /// call (and for longer when the registration keeps referring to it).
    unsafe fn register(&self, opcode: u32, arg: *const c_void, nr_args: u32) -> io::Result<usize> {
        // SAFETY: the ring fd is live; `arg` is valid for `opcode` (caller).
        cvt(unsafe {
            ffi::syscall(
                ffi::SYS_io_uring_register,
                c_long::from(self.fd.as_raw_fd()),
                c_long::from(opcode),
                arg,
                c_long::from(nr_args),
            )
        })
    }

    /// `IORING_REGISTER_ENABLE_RINGS`: starts a ring created with `SETUP_R_DISABLED` (the
    /// calling thread becomes a single-issuer ring's owner).
    pub(crate) fn enable_rings(&self) -> io::Result<()> {
        // SAFETY: this opcode takes no argument.
        unsafe { self.register(REGISTER_ENABLE_RINGS, ptr::null(), 0) }.map(drop)
    }

    #[cfg(test)]
    /// `IORING_REGISTER_FILES` with `n` empty slots (a sparse table for direct descriptors).
    pub(crate) fn register_files_sparse(&self, n: u32) -> io::Result<()> {
        let fds = vec![-1i32; n as usize];
        // SAFETY: `fds` holds `n` descriptors (all -1: empty), read during the call.
        unsafe { self.register(REGISTER_FILES, fds.as_ptr().cast(), n) }.map(drop)
    }

    /// `IORING_REGISTER_PROBE`: which opcodes this kernel supports.
    pub(crate) fn probe(&self) -> io::Result<Box<Probe>> {
        let mut p = Box::new(Probe {
            last_op: 0,
            ops_len: 0,
            resv: 0,
            resv2: [0; 3],
            ops: [ProbeOp::default(); PROBE_OPS],
        });
        // SAFETY: `p` is a zeroed `io_uring_probe` with room for `PROBE_OPS` entries, the count
        // passed; the kernel writes at most that many.
        unsafe {
            self.register(
                REGISTER_PROBE,
                (&raw mut *p).cast::<c_void>(),
                PROBE_OPS as u32,
            )
        }?;
        Ok(p)
    }

    /// `IORING_REGISTER_PBUF_RING`: registers a provided-buffer ring of `entries` (a power of
    /// two) `struct io_uring_buf`s at `addr` as buffer group `bgid`.
    ///
    /// # Safety
    ///
    /// `addr` must point to `entries * 16` page-aligned bytes that stay allocated, and are only
    /// accessed following the buffer-ring protocol, for as long as the ring lives.
    pub(crate) unsafe fn register_buf_ring(
        &self,
        addr: u64,
        entries: u16,
        bgid: u16,
    ) -> io::Result<()> {
        let reg = BufReg {
            ring_addr: addr,
            ring_entries: u32::from(entries),
            bgid,
            flags: 0,
            resv: [0; 3],
        };
        // SAFETY: `reg` is a valid `io_uring_buf_reg` read during the call; the memory it names
        // satisfies the registration's requirements (caller).
        unsafe { self.register(REGISTER_PBUF_RING, (&raw const reg).cast(), 1) }.map(drop)
    }

    /// `IORING_UNREGISTER_PBUF_RING`: removes buffer group `bgid`. Once it returns the kernel no
    /// longer refers to the ring's memory; buffers it handed out in completions stay the
    /// caller's.
    ///
    /// # Safety
    ///
    /// No operation that selects buffers from `bgid` may be in flight (it would complete with
    /// `ENOBUFS` at best).
    pub(crate) unsafe fn unregister_buf_ring(&self, bgid: u16) -> io::Result<()> {
        let reg = BufReg {
            ring_addr: 0,
            ring_entries: 0,
            bgid,
            flags: 0,
            resv: [0; 3],
        };
        // SAFETY: `reg` is a valid `io_uring_buf_reg` (only `bgid` is read), read during the
        // call.
        unsafe { self.register(UNREGISTER_PBUF_RING, (&raw const reg).cast(), 1) }.map(drop)
    }
}

#[cfg(test)]
/// `IORING_REGISTER_SEND_MSG_RING` (6.13+): sends the `MSG_RING` entry `e` (see
/// [`Sqe::msg_ring`]) from a thread that has no ring of its own, in one system call.
pub(crate) fn send_msg_ring(e: &Sqe) -> io::Result<()> {
    // SAFETY: `e` is a live 64-byte `io_uring_sqe`, read during the call; the ring fd it names
    // is the caller's business (an fd that is no ring fails with `EBADFD`/`EINVAL`).
    cvt(unsafe {
        ffi::syscall(
            ffi::SYS_io_uring_register,
            c_long::from(-1),
            c_long::from(REGISTER_SEND_MSG_RING),
            (&raw const *e).cast::<c_void>(),
            c_long::from(1),
        )
    })
    .map(drop)
}

impl Probe {
    /// Whether `opcode` is supported.
    pub(crate) fn is_supported(&self, opcode: u8) -> bool {
        opcode <= self.last_op && self.ops[usize::from(opcode)].flags & PROBE_OP_SUPPORTED != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entries the reactor submits, field by field (what the `io-uring` crate produced).
    #[test]
    fn sqe_builders() {
        let e = Sqe::recv_multi(7, 3).user_data(99);
        assert_eq!((e.opcode, e.flags, e.ioprio, e.fd), (OP_RECV, 1 << 5, 2, 7));
        assert_eq!((e.buf_group, e.len, e.op_flags, e.user_data), (3, 0, 0, 99));
        let e = Sqe::accept_multi(5);
        assert_eq!(
            (e.opcode, e.ioprio, e.fd, e.addr, e.off),
            (OP_ACCEPT, 1, 5, 0, 0)
        );
        let e = Sqe::poll_add(4, 0x2008);
        assert_eq!((e.opcode, e.op_flags, e.len), (OP_POLL_ADD, 0x2008, 0));
        let e = Sqe::async_cancel(42);
        assert_eq!(
            (e.opcode, e.fd, e.addr, e.op_flags),
            (OP_ASYNC_CANCEL, -1, 42, 0)
        );
        let e = Sqe::async_cancel_any();
        assert_eq!((e.fd, e.addr, e.op_flags), (-1, 0, 4));
        let mut b = [0u8; 8];
        let e = Sqe::read(9, b.as_mut_ptr(), 8);
        assert_eq!(
            (e.opcode, e.fd, e.addr, e.len),
            (OP_READ, 9, b.as_ptr() as u64, 8)
        );
        assert_eq!(cqe_buffer((5 << 16) | CQE_F_BUFFER | CQE_F_MORE), Some(5));
        assert_eq!(cqe_buffer(5 << 16), None);
        assert!(cqe_more(CQE_F_MORE) && !cqe_more(CQE_F_BUFFER));
        // `MSG_RING` / `IORING_MSG_DATA`: target ring in `fd`, result in `len`, the target's
        // `user_data` in `off` (`addr` = 0 is the command).
        let e = Sqe::msg_ring(11, 7, 0x1234);
        assert_eq!(
            (e.opcode, e.fd, e.addr, e.off, e.len, e.op_flags, e.flags),
            (OP_MSG_RING, 11, 0, 0x1234, 7, 0, 0)
        );
        // The evaluation-only entries (`eval.rs`).
        let e = Sqe::send_zc(3, b.as_ptr(), 8).fixed();
        assert_eq!(
            (e.opcode, e.flags, e.ioprio, e.op_flags, e.len),
            (OP_SEND_ZC, 1, 1 << 3, 0x4000, 8)
        );
        let e = Sqe::accept_multi_direct(5);
        assert_eq!((e.opcode, e.ioprio, e.file_index), (OP_ACCEPT, 1, !0));
        let e = Sqe::close_fixed(4);
        assert_eq!((e.opcode, e.fd, e.file_index), (OP_CLOSE, 0, 5));
        assert!(cqe_notif(CQE_F_NOTIF) && notif_copied(i32::MIN) && !notif_copied(0));
        let e = Sqe::send(3, b.as_ptr(), 8);
        assert_eq!(e.opcode, OP_SEND);
    }

    /// `MSG_RING` from a thread without a ring (`IORING_REGISTER_SEND_MSG_RING`, 6.13+) lands in
    /// the target's completion queue with the given `user_data` and result. Skipped where
    /// io_uring or that registration opcode is missing.
    #[test]
    fn msg_ring_without_a_source_ring() {
        let Ok(mut ring) = Ring::new(8, 0, 0, 0) else {
            return;
        };
        let e = Sqe::msg_ring(ring.fd.as_raw_fd(), 7, 0x1234);
        if send_msg_ring(&e).is_err() {
            return;
        }
        ring.submit_and_wait(1).unwrap();
        let mut out = Vec::new();
        ring.reap_into(&mut out);
        assert_eq!(out, vec![(0x1234, 7, 0)]);
        // A descriptor that is no ring is refused.
        let not_a_ring = std::fs::File::open("/dev/null").unwrap();
        assert!(send_msg_ring(&Sqe::msg_ring(not_a_ring.as_raw_fd(), 0, 1)).is_err());
    }
}
