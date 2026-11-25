use std::{
    cell::Cell,
    io,
    net::{TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{
    Config, ConnInfo, ConnInner, DatagramPort, DynAcceptor, DynHandler, Error, IdleCheck, IdleRule,
    LoopLink, LoopMeta, LoopStats, Pool, RING_IOV, RingSend, RingSent, Task,
    telemetry::{LoopCmd, log_or_stderr},
};
use akio_sys::EventFd;
use akio_sys::ffi;
use akio_timer::{TimerId, Wheel};

use crate::UringOptions;
use crate::ring::{self, Ring, Sqe, cqe_buffer, cqe_more};

// Operation kinds, packed into the low bits of `user_data` next to the connection id.
const OP_ACCEPT: u64 = 1;
const OP_RECV: u64 = 2;
const OP_POLL: u64 = 3;
const OP_WAKE: u64 = 4;
const OP_OTHER: u64 = 5;
/// One-shot poll for a socket error (a reset): see `arm_reset_watch`.
const OP_RESET: u64 = 6;
/// A multishot recv on buffer group 1 (`OP_RECV` is group 0): the group a completion's buffer
/// belongs to while a read-buffer reload swaps groups (`BufGroup`).
const OP_RECV1: u64 = 7;
/// A one-shot poll on a datagram listener socket (ADR-065); the id is its index in `dgrams`.
const OP_DGRAM: u64 = 8;
/// A connection's ring send (`IORING_OP_SEND` / `SENDMSG`, ADR-106).
const OP_SEND: u64 = 9;

/// Whether connections send their output through the ring (ADR-106, the default) or with
/// `write`/`writev` from the loop as before (`AKIO_URING_SENDS=write`).
fn ring_sends() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("AKIO_URING_SENDS").map_or(true, |v| v != "write"))
}

/// The `msghdr` and iovecs of a connection's ring send of several buffers. Boxed so that the
/// address in the entry stays valid while the connection moves in the slot map; the kernel
/// reads it when the entry is submitted.
struct SendMsg {
    hdr: ffi::msghdr,
    iov: [ffi::iovec; RING_IOV],
}

impl SendMsg {
    fn new() -> Box<SendMsg> {
        Box::new(SendMsg {
            hdr: ffi::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 0,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            iov: [ffi::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; RING_IOV],
        })
    }
}

/// A ring send still in flight when its connection closed: what it reads stays alive until its
/// completion (`Loop::orphans`).
struct Orphan {
    inner: Arc<ConnInner>,
    _msg: Option<Box<SendMsg>>,
}

/// The recv operation kind for buffer group `bgid`.
fn recv_op(bgid: u16) -> u64 {
    if bgid == 0 { OP_RECV } else { OP_RECV1 }
}

pub(crate) const BGID: u16 = 0;
/// Provided buffers per loop; a power of two (the buffer ring is indexed with a mask).
pub(crate) const BUF_COUNT: u16 = 1024;
const MAX_BUF: usize = 16 << 10;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(16);
static NEXT_LOOP_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static CURRENT_LOOP: Cell<usize> = const { Cell::new(0) };
}

/// Marks a wheel entry as a write-timeout check (connection ids never reach bit 63).
const WRITE_TIMER: u64 = 1 << 63;
/// Timer ids with this bit set are connect deadlines of pending dials (`Config::connect_timeout`).
const CONNECT_TIMER: u64 = 1 << 62;
/// Timer ids with this bit set are handshake deadlines (`Transport::handshake_timeout`).
const HANDSHAKE_TIMER: u64 = 1 << 61;
/// Command batches above this capacity are not kept for reuse after a burst.
const MAX_SPARE_CMDS: usize = 1024;

fn ud(id: u64, op: u64) -> u64 {
    (id << 4) | op
}

/// Runs `f` on a short-lived thread of its own and returns its result.
///
/// `io_uring_setup` (and enabling a ring) attaches the calling thread to the ring: when the ring
/// is torn down, the kernel's exit work sends every such thread a signal-like task_work
/// (`TIF_NOTIFY_SIGNAL`). A thread blocked in a call the kernel cannot restart then gets `EINTR`
/// (a socket read with `SO_RCVTIMEO`, for one), long after it built the engine. Rings are
/// therefore never created on the caller's thread: the scratch thread is detached from them when
/// it exits, and the I/O thread that drives a ring attaches itself when it enables it.
pub(crate) fn on_scratch_thread<T: Send>(f: impl FnOnce() -> T + Send) -> io::Result<T> {
    std::thread::scope(|s| {
        let h = std::thread::Builder::new()
            .name("akio-uring-setup".into())
            .spawn_scoped(s, f)?;
        Ok(h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
    })
}

/// Where a loop's ring is created and its SQPOLL thread runs ([`Group::pin_threads`]).
///
/// [`Group::pin_threads`]: akio_core::Group::pin_threads
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RingPlace {
    /// The loop's CPU set: the scratch thread that creates the ring is pinned to it first, so
    /// the kernel allocates the ring's memory on that node. Empty: anywhere (not pinned).
    pub(crate) cpus: Vec<usize>,
    /// With SQPOLL, the CPU its kernel thread is pinned to (`IORING_SETUP_SQ_AFF`).
    pub(crate) sq_cpu: Option<usize>,
}

/// A ring from [`make_ring_here`].
pub(crate) struct NewRing {
    pub(crate) ring: Ring,
    /// The ring starts disabled and must be enabled by the thread that will drive it.
    pub(crate) needs_enable: bool,
    /// The CPU its SQPOLL thread is pinned to (`IORING_SETUP_SQ_AFF` accepted).
    pub(crate) sq_cpu: Option<usize>,
}

/// Creates a ring on a scratch thread ([`on_scratch_thread`]) that is first pinned to
/// `place.cpus` (best effort; not pinned when empty), with its SQPOLL thread on `place.sq_cpu`.
pub(crate) fn make_ring_at(entries: u32, sqpoll: bool, place: &RingPlace) -> io::Result<NewRing> {
    on_scratch_thread(move || {
        if !place.cpus.is_empty() {
            // A thread that cannot be pinned creates the ring where it runs, as unplaced.
            let _ = akio_sys::process::pin_current_thread(&place.cpus);
        }
        make_ring_here(entries, sqpoll, place.sq_cpu)
    })?
}

/// Creates a ring with the cheapest setup the kernel accepts: cooperative task-run, a single
/// issuer and deferred task-run (6.1+); anything less if that is refused. The returned ring may
/// start disabled ([`NewRing::needs_enable`]): single-issuer rings belong to the thread that
/// enables them, and rings are built on another thread. With `sqpoll`, `sq_cpu` pins the polling
/// thread (`IORING_SETUP_SQ_AFF`; without it if the kernel refuses that CPU). Call it only on a
/// thread that exits soon (see [`on_scratch_thread`]).
pub(crate) fn make_ring_here(
    entries: u32,
    sqpoll: bool,
    sq_cpu: Option<usize>,
) -> io::Result<NewRing> {
    let cq = entries.saturating_mul(4);
    let plain = |ring| NewRing {
        ring,
        needs_enable: false,
        sq_cpu: None,
    };
    if sqpoll {
        let flags = ring::SETUP_CQSIZE | ring::SETUP_SQPOLL;
        if let Some(cpu) = sq_cpu.and_then(|c| u32::try_from(c).ok()) {
            // EINVAL when the CPU is offline or outside this task's cpuset.
            if let Ok(r) = Ring::with_sq_cpu(entries, flags | ring::SETUP_SQ_AFF, cq, 1000, cpu) {
                return Ok(NewRing {
                    ring: r,
                    needs_enable: false,
                    sq_cpu: Some(cpu as usize),
                });
            }
        }
        return Ring::new(entries, flags, cq, 1000).map(plain);
    }
    let fast = ring::SETUP_CQSIZE
        | ring::SETUP_COOP_TASKRUN
        | ring::SETUP_SINGLE_ISSUER
        | ring::SETUP_DEFER_TASKRUN
        | ring::SETUP_R_DISABLED;
    if let Ok(r) = Ring::new(entries, fast, cq, 0) {
        return Ok(NewRing {
            ring: r,
            needs_enable: true,
            sq_cpu: None,
        });
    }
    if let Ok(r) = Ring::new(
        entries,
        ring::SETUP_CQSIZE | ring::SETUP_COOP_TASKRUN,
        cq,
        0,
    ) {
        return Ok(plain(r));
    }
    Ring::new(entries, ring::SETUP_CQSIZE, cq, 0).map(plain)
}

/// One entry of a provided-buffer ring (`struct io_uring_buf`). Entries are written through raw
/// field pointers, never through a `&mut RawBuf`: a `&mut` to entry 0 would also cover the
/// ring's tail (which overlays entry 0's `resv`) while the kernel may read it.
#[repr(C)]
struct RawBuf {
    addr: u64,
    len: u32,
    bid: u16,
    /// In entry 0: the ring's tail, shared with the kernel.
    resv: u16,
}

const _: () = assert!(size_of::<RawBuf>() == 16 && std::mem::offset_of!(RawBuf, resv) == 14);

/// The provided-buffer ring: page-aligned memory shared with the kernel. Returning a buffer is a
/// plain memory write plus a tail bump, with no submission entry and no syscall.
pub(crate) struct BufRing {
    base: *mut RawBuf,
    tail: u16,
    /// Never free the ring (the kernel may still use it; see `Loop::drain_inflight`).
    leaked: bool,
}

const RING_BYTES: usize = BUF_COUNT as usize * size_of::<RawBuf>();

impl BufRing {
    fn layout() -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(RING_BYTES, 4096).expect("valid layout")
    }

    pub(crate) fn new() -> io::Result<BufRing> {
        // SAFETY: the layout has non-zero size.
        let base = unsafe { std::alloc::alloc_zeroed(Self::layout()) }.cast::<RawBuf>();
        if base.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(BufRing {
            base,
            tail: 0,
            leaked: false,
        })
    }

    /// Registers the ring with the kernel as buffer group `bgid`.
    pub(crate) fn register(&self, ring: &Ring, bgid: u16) -> io::Result<()> {
        // SAFETY: `base` points to `BUF_COUNT` zeroed, page-aligned entries that stay allocated
        // until `self` is dropped, which happens after the io_uring instance that holds the
        // registration (see field order in `Loop`) or after `BufGroup::release` unregistered it.
        unsafe { ring.register_buf_ring(self.base as u64, BUF_COUNT, bgid) }
    }

    /// Makes buffer `bid` (a `size`-byte slot at `area + bid * size`) available to the kernel.
    ///
    /// Each `bid` must be given at most once until the kernel hands it back in a completion, so
    /// at most `BUF_COUNT` entries are ever outstanding and the slot at `tail` is never one the
    /// kernel is reading.
    pub(crate) fn give(&mut self, area: &KernelBuf, size: usize, bid: u16) {
        assert!(
            bid < BUF_COUNT && (bid as usize + 1) * size <= area.len(),
            "buffer id out of range"
        );
        let idx = (self.tail & (BUF_COUNT - 1)) as usize;
        // SAFETY: `idx < BUF_COUNT`, so the entry is inside the allocation, and `bid`'s slot is
        // inside `area` (asserted above). Only this thread writes entries; the kernel reads an
        // entry only after the tail store in `publish` covers it, and never reads the slot at
        // `tail` (see above). Fields are written through raw pointers, never touching `resv`.
        unsafe {
            let e = self.base.add(idx);
            (&raw mut (*e).addr).write(area.as_ptr().add(bid as usize * size) as u64);
            (&raw mut (*e).len).write(size as u32);
            (&raw mut (*e).bid).write(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Publishes everything given since the last call.
    pub(crate) fn publish(&self) {
        // SAFETY: the tail is entry 0's `resv`, a 2-aligned `u16` inside the allocation shared
        // with the kernel, which the protocol says to store with release ordering. `AtomicU16`
        // has the size and alignment of `u16`, and this thread is its only writer.
        unsafe {
            let t = (&raw mut (*self.base).resv).cast::<std::sync::atomic::AtomicU16>();
            (*t).store(self.tail, Ordering::Release);
        }
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        if self.leaked {
            return;
        }
        // SAFETY: allocated in `new` with the same layout.
        unsafe { std::alloc::dealloc(self.base.cast(), Self::layout()) };
    }
}

/// Heap memory the kernel writes into asynchronously: the provided buffers and the eventfd read
/// buffer. Held as a raw pointer rather than a `Vec`/`Box`, which would assert exclusive access
/// for as long as they live while the kernel may fill any buffer it owns at any moment (from
/// task work or an io-wq worker). Rust code only borrows, with [`KernelBuf::slice`], a range the
/// kernel has handed back and is not using.
pub(crate) struct KernelBuf {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    /// Never free the memory (the kernel may still write it; see `Loop::drain_inflight`).
    leaked: bool,
}

impl KernelBuf {
    fn layout(len: usize) -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(len, 64).expect("valid layout")
    }

    /// `len` zeroed bytes (`len > 0`).
    pub(crate) fn new(len: usize) -> io::Result<KernelBuf> {
        assert!(len > 0, "KernelBuf::new(0)");
        // SAFETY: the layout has non-zero size.
        let p = unsafe { std::alloc::alloc_zeroed(Self::layout(len)) };
        let ptr = std::ptr::NonNull::new(p).ok_or(io::ErrorKind::OutOfMemory)?;
        Ok(KernelBuf {
            ptr,
            len,
            leaked: false,
        })
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Borrows `off..off + n`.
    ///
    /// # Safety
    ///
    /// The kernel must not write that range while the returned slice lives (it was handed back
    /// in a completion and has not been given to the kernel again).
    pub(crate) unsafe fn slice(&self, off: usize, n: usize) -> &[u8] {
        assert!(
            off.checked_add(n).is_some_and(|end| end <= self.len),
            "KernelBuf range out of bounds"
        );
        // SAFETY: the range is inside the allocation (asserted above), initialised (zeroed at
        // allocation, then written by the kernel), and not written while borrowed (caller).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(off), n) }
    }
}

impl Drop for KernelBuf {
    fn drop(&mut self) {
        if self.leaked {
            return;
        }
        // SAFETY: allocated in `new` with the same layout.
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), Self::layout(self.len)) };
    }
}

/// One provided-buffer group: the ring the kernel picks receive buffers from and the memory
/// they live in. A loop has one, and two while a read-buffer reload moves its connections from
/// the old group to the new one (each when its multishot recv is re-armed).
pub(crate) struct BufGroup {
    ring: BufRing,
    bufs: KernelBuf,
    size: usize,
    bgid: u16,
    /// Multishot recvs on this group whose final completion has not been reaped.
    armed: usize,
}

impl BufGroup {
    /// `BUF_COUNT` buffers of `size` bytes, for group `bgid` (not registered yet).
    fn alloc(size: usize, bgid: u16) -> io::Result<BufGroup> {
        Ok(BufGroup {
            ring: BufRing::new()?,
            bufs: KernelBuf::new(size * BUF_COUNT as usize)?,
            size,
            bgid,
            armed: 0,
        })
    }

    /// Hands the group to the kernel with every buffer in it. On the ring's own thread.
    fn install(&mut self, ring: &Ring) -> io::Result<()> {
        self.ring.register(ring, self.bgid)?;
        for bid in 0..BUF_COUNT {
            self.ring.give(&self.bufs, self.size, bid);
        }
        self.ring.publish();
        Ok(())
    }

    /// Returns buffer `bid` to the kernel (published with `publish`).
    fn give_back(&mut self, bid: u16) {
        self.ring.give(&self.bufs, self.size, bid);
    }

    /// Unregisters the group, once no recv uses it, and frees it; leaks it if the kernel
    /// refuses (it may then still refer to the memory).
    fn release(mut self, ring: &Ring) {
        debug_assert_eq!(self.armed, 0);
        // SAFETY: no operation selecting buffers from this group is in flight (`armed == 0`:
        // every multishot recv armed on it delivered its final completion).
        if let Err(e) = unsafe { ring.unregister_buf_ring(self.bgid) } {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!(
                    "io_uring: unregistering buffer group {}: {e}; leaking it",
                    self.bgid
                ),
            );
            self.leak();
        }
    }

    /// Never frees the memory (the kernel may still use it).
    fn leak(&mut self) {
        self.bufs.leaked = true;
        self.ring.leaked = true;
    }
}

pub(crate) enum Cmd {
    Wake(u64),
    /// The connection's own idle timeout changed (`LoopLink::retime_conn`, ADR-155).
    Retime(u64),
    Close(u64, Option<io::Error>),
    Task(u64, Task),
    Shutdown,
    /// From the engine's telemetry hub (connection table, live-settings reload).
    Core(LoopCmd),
    /// Accept-time balancing (ADR-105): a connection another loop of the group accepted, to be
    /// served here. Counted in this loop's `LoopStats::load` until it arrives.
    Adopt {
        stream: TcpStream,
        peer: std::net::SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        /// The listener it came from (ADR-130).
        lid: usize,
    },
    Dial {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
        /// A Unix-domain socket (ADR-120): its addresses are `UNIX_ADDR`.
        unix: bool,
    },
    /// A listener joins the group (ADR-130): what accepting on its sockets needs. Its sockets
    /// follow as `AddListener`.
    Listen {
        lid: usize,
        ear: Arc<Ear>,
    },
    /// Accept on listening socket `.0` from now on (a new listener's, one passed on by thread
    /// resizing, ADR-028, or given back to a loop the group grew again).
    AddListener(Sock, TcpListener),
    /// Thread resizing: if this loop holds socket `sock`, hand it to `to`.
    GiveListener {
        sock: Sock,
        to: Arc<LoopShared>,
    },
    /// Thread resizing: stop taking new connections, hand the `SO_REUSEPORT` listening sockets
    /// to the active loops (clones the others hold too are just closed), exit once the
    /// connections are gone.
    Retire,
    /// Thread resizing: a retiring loop becomes active again.
    Revive,
    /// A listener was removed (ADR-099; see the epoll backend): listener `lid`, or with `None`
    /// every one. `done` is dropped once the loop's listening sockets stopped listening
    /// (`Group::await_unlisted`).
    StopListening {
        lid: Option<usize>,
        drain: Option<Duration>,
        exit: bool,
        done: Option<akio_core::CountdownToken>,
    },
}

/// A listening socket of a group: socket `idx` of listener `lid` (ADR-130; see the epoll
/// backend).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sock {
    pub(crate) lid: usize,
    pub(crate) idx: usize,
}

impl Sock {
    /// Its id in an accept's `user_data`.
    fn id(self) -> u64 {
        ((self.lid as u64) << 32) | (self.idx as u64 & 0xffff_ffff)
    }

    fn of_id(id: u64) -> Sock {
        Sock {
            lid: (id >> 32) as usize,
            idx: (id & 0xffff_ffff) as usize,
        }
    }
}

/// One listener of a group (ADR-130): what a loop needs to accept on its sockets.
pub(crate) struct Ear {
    pub(crate) acceptor: Arc<dyn DynAcceptor>,
    pub(crate) filter: Arc<akio_core::FilterCell>,
    /// A Unix-domain listener (ADR-121): its connections get `UNIX_ADDR` for both addresses.
    pub(crate) unix: bool,
    /// One `SO_REUSEPORT` socket per loop index: each has a home loop and is handed on when its
    /// loop retires (and stops listening when the listener is removed). Otherwise the loops
    /// hold clones of one (inherited or Unix-domain) socket.
    pub(crate) reuseport: bool,
    /// Its address (`ConnInfo::owner.listener` of its connections).
    pub(crate) addr: std::net::SocketAddr,
}

/// No listener: a dialed connection's `LoopConn::lid`.
const NO_LISTENER: usize = usize::MAX;

/// A loop's view of one listener of its group.
struct LoopEar {
    ear: Arc<Ear>,
    filter: akio_core::FilterView,
    /// Removed (`Cmd::StopListening`): sockets handed here later are closed.
    unlisted: bool,
    /// Removed with a drain: connections its cancelled accept still delivers are shut down
    /// after their first data, as while draining.
    drain: bool,
    /// The drain deadline of its removal: its connections still open then are closed.
    kill: Option<Instant>,
}

impl LoopEar {
    fn new(ear: Arc<Ear>) -> LoopEar {
        LoopEar {
            filter: akio_core::FilterView::new(ear.filter.clone()),
            ear,
            unlisted: false,
            drain: false,
            kill: None,
        }
    }
}

/// `LoopShared::state`: taking new connections.
const ACTIVE: u8 = 0;
/// Retired by a smaller thread count; exits once its connections are gone.
const RETIRING: u8 = 1;
/// Exited (or committed to exit) after retiring.
const EXITED: u8 = 2;

/// The active loops of a group (ADR-028): where dials and handed-over listening sockets go.
/// Written only by `set_threads` (under the group's lock); read on the control path.
pub(crate) struct Roster {
    active: RwLock<Vec<Arc<LoopShared>>>,
    rr: AtomicUsize,
    /// Accept-time balancing (ADR-105, `Group::set_balance`).
    balance: AtomicBool,
}

impl Roster {
    pub(crate) fn new() -> Roster {
        Roster {
            active: RwLock::new(Vec::new()),
            rr: AtomicUsize::new(0),
            balance: AtomicBool::new(false),
        }
    }

    pub(crate) fn set(&self, v: Vec<Arc<LoopShared>>) {
        *self.active.write().unwrap_or_else(|p| p.into_inner()) = v;
    }

    /// Posts `cmd` to the next active loop in turn. The read lock is held while posting, so a
    /// loop that `set_threads` retires right after receives the command before its `Retire`.
    /// `Err(cmd)` when no loop is active.
    pub(crate) fn post_next(&self, cmd: Cmd) -> Result<(), Cmd> {
        let g = self.active.read().unwrap_or_else(|p| p.into_inner());
        if g.is_empty() {
            return Err(cmd);
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % g.len();
        g[i].post(cmd);
        Ok(())
    }

    /// Where `SO_REUSEPORT` socket `sock` belongs (its home is active loop `idx % active`), if
    /// that is not `me`: then it is posted there and `None` returned. A socket that went to the
    /// wrong loop while the group was being resized (handed on by a retiring loop after the
    /// group had grown again, say) thus ends up at home. Clones of one socket have no home.
    fn route(
        &self,
        sock: Sock,
        l: TcpListener,
        me: &LoopShared,
        reuseport: bool,
    ) -> Option<TcpListener> {
        if !reuseport {
            return Some(l);
        }
        let g = self.active.read().unwrap_or_else(|p| p.into_inner());
        match g.get(sock.idx % g.len().max(1)) {
            Some(home) if home.uid != me.uid => {
                home.post(Cmd::AddListener(sock, l));
                None
            }
            _ => Some(l),
        }
    }

    /// Hands listening socket `sock` to an active loop (spread by index).
    fn forward_listener(&self, sock: Sock, l: TcpListener) {
        let g = self.active.read().unwrap_or_else(|p| p.into_inner());
        if !g.is_empty() {
            g[sock.idx % g.len()].post(Cmd::AddListener(sock, l));
        }
    }

    pub(crate) fn set_balance(&self, on: bool) {
        self.balance.store(on, Ordering::Relaxed);
    }

    /// Accept-time balancing (ADR-105): the active loop a connection just accepted by `me`
    /// should go to instead, if `me` holds more than its share (`akio_core::balance`). The
    /// target's load already counts the connection when this returns.
    fn handoff_target(&self, me: &LoopShared) -> Option<Arc<LoopShared>> {
        if !self.balance.load(Ordering::Relaxed) {
            return None;
        }
        let g = self.active.read().unwrap_or_else(|p| p.into_inner());
        let t = akio_core::balance::pick(&me.stats, &g, |l| &l.stats)?.clone();
        t.stats.handoff_begin();
        Some(t)
    }

    /// Passes on a handed-over connection that reached a loop which is leaving: to the next
    /// active loop, or closes it when there is none.
    fn hand_on(&self, cmd: Cmd) {
        let g = self.active.read().unwrap_or_else(|p| p.into_inner());
        if g.is_empty() {
            return;
        }
        let t = &g[self.rr.fetch_add(1, Ordering::Relaxed) % g.len()];
        t.stats.handoff_begin();
        t.post(cmd);
    }
}

/// The part of a loop other threads can reach: its command queue and eventfd.
/// Whether the calling thread runs an I/O loop of this backend.
pub(crate) fn on_loop_thread() -> bool {
    CURRENT_LOOP.with(Cell::get) != 0
}

pub(crate) struct LoopShared {
    uid: usize,
    /// `ACTIVE`, `RETIRING` or `EXITED` (thread resizing).
    state: AtomicU8,
    waker: EventFd,
    cmds: Mutex<Vec<Cmd>>,
    wake_pending: AtomicBool,
    /// The loop posted to itself since its last drain (written and read on the loop's thread
    /// only): it drains again before it blocks.
    self_posted: AtomicBool,
    pool: Arc<Pool>,
    pub(crate) stats: Arc<LoopStats>,
}

impl LoopShared {
    /// A loop's shared half, registered with `cfg`'s telemetry hub.
    pub(crate) fn new(
        pool: Arc<Pool>,
        cfg: &Config,
        meta: LoopMeta,
    ) -> io::Result<Arc<LoopShared>> {
        Self::with_stats(pool, cfg, Arc::new(LoopStats::new(meta)))
    }

    /// As `new`, reusing the counters of a loop that exited (a group growing again).
    pub(crate) fn with_stats(
        pool: Arc<Pool>,
        cfg: &Config,
        stats: Arc<LoopStats>,
    ) -> io::Result<Arc<LoopShared>> {
        let sh = Arc::new(LoopShared {
            uid: NEXT_LOOP_UID.fetch_add(1, Ordering::Relaxed),
            state: AtomicU8::new(ACTIVE),
            waker: EventFd::new()?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
            self_posted: AtomicBool::new(false),
            pool,
            stats,
        });
        let weak = Arc::downgrade(&sh);
        cfg.telemetry.register_loop(
            sh.stats.clone(),
            Box::new(move |c| {
                if let Some(sh) = weak.upgrade() {
                    sh.post(Cmd::Core(c));
                }
            }),
        );
        Ok(sh)
    }

    pub(crate) fn post(&self, cmd: Cmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        if CURRENT_LOOP.with(Cell::get) == self.uid {
            // From the loop's own thread no wake-up is needed, but the post may come after the
            // loop's drain (a callback run from its timers posting for another connection):
            // the loop drains again before it blocks, or the command would wait for whatever
            // wakes it next, on an idle loop never.
            self.self_posted.store(true, Ordering::Relaxed);
        } else if !self.wake_pending.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// Group side: the loop is being retired (its `Retire` command follows).
    pub(crate) fn mark_retiring(&self) {
        self.state.store(RETIRING, Ordering::Release);
    }

    /// Group side: makes a retiring loop active again; false if it already exited (or
    /// committed to), in which case a new loop takes its place.
    pub(crate) fn try_revive(&self) -> bool {
        self.state
            .compare_exchange(RETIRING, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Loop side: commits a retiring loop to exiting; false if the group revived it meanwhile.
    fn try_exit(&self) -> bool {
        self.state
            .compare_exchange(RETIRING, EXITED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn take(&self) -> Vec<Cmd> {
        self.wake_pending.store(false, Ordering::Release);
        self.self_posted.store(false, Ordering::Relaxed);
        std::mem::take(&mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Swaps the queued commands into `batch` (which must be empty), leaving `batch`'s
    /// allocation behind for the next posts: the loop and its posters trade two vectors back
    /// and forth instead of allocating one after every drain.
    fn take_into(&self, batch: &mut Vec<Cmd>) {
        debug_assert!(batch.is_empty());
        self.wake_pending.store(false, Ordering::Release);
        self.self_posted.store(false, Ordering::Relaxed);
        std::mem::swap(
            &mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()),
            batch,
        );
    }

    /// Loop side: commands the loop posted to itself are queued since its last drain.
    pub(crate) fn self_posted(&self) -> bool {
        self.self_posted.load(Ordering::Relaxed)
    }
}

impl LoopLink for LoopShared {
    fn wake_conn(&self, id: u64) {
        self.post(Cmd::Wake(id));
    }
    fn close_conn(&self, id: u64, err: Option<io::Error>) {
        self.post(Cmd::Close(id, err));
    }
    fn post_task(&self, id: u64, task: Task) {
        self.post(Cmd::Task(id, task));
    }
    fn pool(&self) -> Option<&Pool> {
        Some(&self.pool)
    }
    fn stats(&self) -> Option<Arc<LoopStats>> {
        Some(self.stats.clone())
    }
    fn retime_conn(&self, id: u64) -> bool {
        self.post(Cmd::Retime(id));
        true
    }
}

struct LoopConn {
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    acceptor: Arc<dyn DynAcceptor>,
    /// The listener it was accepted on (ADR-130), or `NO_LISTENER` when dialed.
    lid: usize,
    /// A multishot recv is in flight (until a completion without `F_MORE` arrives).
    recv_armed: bool,
    /// The buffer group that recv takes its buffers from.
    recv_bgid: u16,
    /// A cancel for the recv was submitted.
    cancel_sent: bool,
    /// A `poll(POLLOUT)` is in flight.
    poll_armed: bool,
    /// Reads paused by backpressure.
    bp: bool,
    /// Peer sent EOF; we are only draining output.
    eof: bool,
    /// Input that arrived while reads were paused (backpressure, `hold_reads`): a multishot recv
    /// keeps completing until its cancel lands, so what it read waits here for `on_data` until
    /// reads resume (epoll simply stops reading instead).
    held_in: Vec<u8>,
    /// The peer's EOF arrived behind `held_in`: it takes effect once that is delivered.
    held_eof: bool,
    last_active: u64,
    idle_timer: Option<TimerId>,
    /// Its own idle timeout, if it set one (ADR-155); else the engine's.
    idle: IdleRule,
    /// Pending write-timeout check (`Config::write_timeout`), and the bytes written when it
    /// was armed.
    write_timer: Option<TimerId>,
    write_mark: u64,
    /// Pending handshake deadline of its transport (`Transport::handshake_timeout`).
    hs_timer: Option<TimerId>,
    /// Bytes queued as the last `uncork_flush` / `flush_queue` reported them, for the next
    /// `refresh` (saves it a lock); taken by it.
    q_hint: Option<usize>,
    /// Tick when it opened, and bytes read (connection table).
    opened: u64,
    bytes_in: u64,
    /// Accepted while draining: `on_shutdown` runs after its first data, so the request that
    /// is already on its way is served (see `on_accept`).
    shutdown_after_data: bool,
    /// Kernel TLS: reads are stopped so that the transport's receive direction can move into
    /// the kernel (`ConnInner::offload_rx_now`) at a point where no recv is in flight.
    rx_offload: bool,
    /// Attempts at that so far (a stream that never pauses on a record boundary gives up).
    rx_offload_tries: u8,
    /// A ring send is in flight (ADR-106): its completion flushes what was queued meanwhile.
    send_armed: bool,
    /// That send is described but still waits in `Loop::unsent` (not submitted: the kernel has
    /// not seen it).
    send_unsent: bool,
    /// Header of multi-buffer ring sends, allocated on first use.
    send_msg: Option<Box<SendMsg>>,
}

/// Turns the send described in `rs` into an entry for connection `id` and marks it in flight;
/// `None` (and nothing changed) when `rs` is empty.
fn prep_send(lc: &mut LoopConn, id: u64, rs: &mut RingSend) -> Option<Sqe> {
    let parts = rs.parts();
    if parts.is_empty() {
        return None;
    }
    let fd = lc.inner.stream().as_raw_fd();
    let e = if let [(addr, len)] = *parts {
        Sqe::send(fd, addr as *const u8, len as u32)
    } else {
        let m = lc.send_msg.get_or_insert_with(SendMsg::new);
        for (slot, &(addr, len)) in m.iov.iter_mut().zip(parts) {
            slot.iov_base = addr as *mut std::ffi::c_void;
            slot.iov_len = len;
        }
        m.hdr.msg_iov = m.iov.as_mut_ptr();
        m.hdr.msg_iovlen = parts.len();
        Sqe::sendmsg(fd, &raw const m.hdr)
    };
    rs.clear();
    lc.send_armed = true;
    Some(e.user_data(ud(id, OP_SEND)))
}

/// Attempts at moving a connection's receive direction into the kernel before giving up.
const RX_OFFLOAD_TRIES: u8 = 8;
/// Buffer for one kernel TLS record read with `recvmsg` (16 KiB of content and some room).
const KERNEL_RECORD_BUF: usize = (16 << 10) + 256;

enum Slot {
    Conn(LoopConn),
    Connecting {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
        unix: bool,
    },
}

/// A listening socket of a loop, by its index in the group. `l` is `None` once the socket was
/// handed on (or closed) while its multishot accept is still being cancelled: until that ends,
/// connections it accepts are served here.
struct Lsn {
    sock: Sock,
    l: Option<TcpListener>,
    armed: bool,
}

pub(crate) struct Loop {
    ring: Ring,
    /// Provided receive buffers (declared after `ring` so the kernel's registration is gone
    /// before the memory is freed), and, during a read-buffer reload, the group being left.
    bufs: BufGroup,
    old_bufs: Option<BufGroup>,
    needs_enable: bool,
    /// The CPU the ring's SQPOLL thread is pinned to (`RingPlace::sq_cpu`, accepted).
    sq_cpu: Option<usize>,
    shared: Arc<LoopShared>,
    listeners: Vec<Lsn>,
    /// The listeners of the group, by `lid` (ADR-130; none in a client-only group).
    ears: Vec<Option<LoopEar>>,
    /// The group's active loops (thread resizing).
    roster: Arc<Roster>,
    /// The backlog the listening sockets were last `listen`ed with.
    backlog: i32,
    /// Retired by a smaller thread count (see the epoll backend).
    retiring: bool,
    retire_at: Option<Instant>,
    retire_kill: Option<Instant>,
    /// After a failed accept (EMFILE...) do not re-arm before this instant.
    accept_retry_at: Option<Instant>,
    /// Every listener of the group was removed (`Cmd::StopListening` with no `lid`, see the
    /// epoll backend): with `unlisted_exit` the thread ends once nothing is left, and at
    /// `unlisted_kill` the connections still open are closed and the dials aborted. (One
    /// listener's removal keeps its state in its `LoopEar`.)
    unlisted_exit: bool,
    unlisted_kill: Option<Instant>,
    /// Target of the eventfd `Read` (never read by Rust).
    wake_buf: KernelBuf,
    wake_armed: bool,
    slots: akio_core::IdMap<Slot>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    /// Connections finalized since the last submit. Entries already in the submission queue
    /// name their socket by fd number, resolved by the kernel only at submit: the fd must not be
    /// closed (and reused by another connection, perhaps on another loop) before that.
    graveyard: Vec<Arc<ConnInner>>,
    wheel: Wheel<u64>,
    epoch: Instant,
    /// When the current batch of completions started, or the last timed callback ended: the
    /// start of the next callback and the "now" of idle accounting, so a request costs one clock
    /// read instead of three.
    clock: Instant,
    cqes: Vec<(u64, i32, u32)>,
    /// Submitted operations whose final completion (one without `F_MORE`) has not been reaped.
    /// Every entry this loop pushes ends with exactly one such completion.
    inflight: usize,
    /// The command vector traded with `shared` (see `LoopShared::take_into`).
    spare_cmds: Vec<Cmd>,
    /// Datagram listener sockets (ADR-065): readiness by a one-shot `POLL_ADD` each, I/O by the
    /// port's `recvmmsg` / `sendmmsg` (the batching the epoll loops use too).
    dgrams: Vec<Dgram>,
    /// Connections send through the ring (ADR-106, `ring_sends`).
    ring_sends: bool,
    /// The send the last flush described, turned into an entry right after it (`submit_send`).
    rs: RingSend,
    /// Ring sends of closed connections, by connection id, until their completions.
    orphans: akio_core::IdMap<Orphan>,
    /// Connections whose described ring send is not submitted yet: submitted together right
    /// before the loop enters the kernel (`submit_sends`), each described again then, so that
    /// everything the batch queued for a connection leaves in one send.
    unsent: Vec<u64>,
}

/// A datagram listener socket of a loop.
struct Dgram {
    port: DatagramPort,
    /// Its poll is in flight.
    armed: bool,
}

// SAFETY: a `Loop` is built on one thread and then moved to, and used only by, its I/O thread.
// The raw pointers inside submitted entries point into `bufs`/`old_bufs`/`wake_buf`, heap
// allocations that move with it without changing address and are freed only after `ring`, or
// into a connection's queued output and boxed `SendMsg` (ring sends), kept alive by the
// connection (or `orphans`) until the send's completion. `SendMsg` holds raw pointers, which
// only this thread uses.
unsafe impl Send for Loop {}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

enum Done {
    No,
    Eof,
    Err(io::Error),
    Panic,
}

/// Whether `on_data` must wait: the handler held reads, or (unless relayed) the output queue
/// reached `Config::write_high_watermark`, checked after every chunk as epoll does.
fn reads_paused(lc: &LoopConn, high: usize) -> bool {
    lc.bp
        || lc.rx_offload
        || lc.inner.read_held()
        || (lc.inner.write_backpressure()
            && lc.q_hint.unwrap_or_else(|| lc.inner.queued_bytes()) >= high)
}

/// Runs `on_data` with `data`, then flushes what it queued.
fn feed(
    lc: &mut LoopConn,
    data: &[u8],
    id: u64,
    cfg: &Config,
    st: &LoopStats,
    clock: &mut Instant,
    rs: &mut RingSend,
) -> Done {
    lc.inner.set_corked(true);
    let r = catch_unwind(AssertUnwindSafe(|| lc.handler.on_data(data)));
    if cfg.telemetry.timing_enabled() {
        *clock = cfg.telemetry.callback_done_at(st, "on_data", id, *clock);
    } else {
        st.callbacks.add_local(1);
    }
    if r.is_err() {
        return Done::Panic;
    }
    match lc.inner.uncork_flush_ring(rs) {
        Ok(q) => {
            lc.q_hint = Some(q);
            Done::No
        }
        Err(e) => Done::Err(e),
    }
}

/// The submission queue depth of a loop's ring.
fn ring_entries(opts: &UringOptions) -> u32 {
    if opts.entries == 0 {
        1024
    } else {
        opts.entries
    }
}

impl Loop {
    pub(crate) fn new(
        shared: Arc<LoopShared>,
        listeners: Vec<(Sock, TcpListener)>,
        ears: Vec<Option<Arc<Ear>>>,
        roster: Arc<Roster>,
        cfg: Arc<Config>,
        opts: &UringOptions,
        place: &RingPlace,
    ) -> io::Result<Loop> {
        let entries = ring_entries(opts);
        let NewRing {
            ring,
            needs_enable,
            sq_cpu,
        } = make_ring_at(entries, opts.sqpoll, place)?;
        for (_, l) in &listeners {
            l.set_nonblocking(true)?;
        }
        let live = cfg.telemetry.live();
        let buf_size = live.read_buffer().clamp(512, MAX_BUF);
        let backlog = live.backlog();
        Ok(Loop {
            ring,
            bufs: BufGroup::alloc(buf_size, BGID)?,
            old_bufs: None,
            needs_enable,
            sq_cpu,
            shared,
            listeners: listeners
                .into_iter()
                .map(|(sock, l)| Lsn {
                    sock,
                    l: Some(l),
                    armed: false,
                })
                .collect(),
            ears: ears.into_iter().map(|e| e.map(LoopEar::new)).collect(),
            roster,
            backlog,
            retiring: false,
            retire_at: None,
            retire_kill: None,
            accept_retry_at: None,
            unlisted_exit: false,
            unlisted_kill: None,
            wake_buf: KernelBuf::new(8)?,
            wake_armed: false,
            slots: Default::default(),
            cfg,
            draining: None,
            graveyard: Vec::new(),
            wheel: Wheel::new(0),
            epoch: Instant::now(),
            clock: Instant::now(),
            cqes: Vec::with_capacity(1024),
            inflight: 0,
            spare_cmds: Vec::new(),
            dgrams: Vec::new(),
            ring_sends: ring_sends(),
            rs: RingSend::default(),
            orphans: akio_core::IdMap::default(),
            unsent: Vec::new(),
        })
    }

    /// Replaces the ring of this loop (built, not started: nothing uses the ring yet) with one
    /// created at `place`. On error the loop keeps its ring.
    pub(crate) fn place_ring(&mut self, opts: &UringOptions, place: &RingPlace) -> io::Result<()> {
        let r = make_ring_at(ring_entries(opts), opts.sqpoll, place)?;
        self.ring = r.ring;
        self.needs_enable = r.needs_enable;
        self.sq_cpu = r.sq_cpu;
        Ok(())
    }

    /// The CPU this loop's SQPOLL thread is pinned to, if any.
    pub(crate) fn sq_cpu(&self) -> Option<usize> {
        self.sq_cpu
    }

    /// Serves the datagram listener socket of `port` on this loop (before it starts).
    pub(crate) fn add_port(&mut self, port: DatagramPort) {
        self.dgrams.push(Dgram { port, armed: false });
    }

    /// No datagram reply waits for socket space (draining may end).
    fn dgrams_idle(&self) -> bool {
        self.dgrams.iter().all(|d| !d.port.wants_write())
    }

    /// A datagram socket's poll completed with `res` (the ready events, or `-errno`).
    fn on_dgram(&mut self, i: usize, res: i32) {
        let Some(d) = self.dgrams.get_mut(i) else {
            return;
        };
        d.armed = false;
        if res <= 0 {
            return; // cancelled (shutdown) or an error: re-armed as needed
        }
        let ev = res as u32;
        if ev & ffi::POLLOUT as u32 != 0 {
            d.port.on_writable();
        }
        let rd = (ffi::POLLIN | ffi::POLLERR) as u32;
        if ev & rd != 0 && d.port.wants_read() {
            d.port.on_readable();
        }
    }

    /// Runs on the I/O thread before the first submission: takes ownership of the ring (when it
    /// was created disabled) and hands the buffer ring to the kernel.
    fn init(&mut self) -> io::Result<()> {
        if self.needs_enable {
            self.ring.enable_rings()?;
        }
        self.bufs.install(&self.ring)
    }

    /// Queues an entry, submitting first if the submission queue is full.
    fn push(&mut self, e: Sqe) {
        loop {
            // SAFETY: every entry pushed refers to memory that outlives its completion: the
            // provided-buffer area and the wake buffer are owned by `self` and never moved or
            // freed while the ring lives; a ring send's bytes stay in its connection's queue
            // (`ring_inflight`) and its boxed `msghdr` in the `LoopConn`, both kept (`orphans`)
            // until its completion; the other entries carry only integers (fds, ids).
            if unsafe { self.ring.push(&e) }.is_ok() {
                self.inflight += 1;
                return;
            }
            let _ = self.ring.submit();
        }
    }

    /// The buffer group `bgid`, current or being left.
    fn group(&mut self, bgid: u16) -> Option<&mut BufGroup> {
        if self.bufs.bgid == bgid {
            Some(&mut self.bufs)
        } else {
            self.old_bufs.as_mut().filter(|g| g.bgid == bgid)
        }
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn run(&mut self) {
        akio_core::timer::install();
        self.run_inner();
        akio_core::timer::uninstall();
        self.drain_inflight();
        self.shared.stats.set_running(false);
        self.shared.stats.set_retiring(false);
        // Pending telemetry requests are dropped, which answers them (as "nothing"). A loop
        // that retired passes on what must not be lost (see the epoll backend).
        for cmd in self.shared.take() {
            match cmd {
                Cmd::AddListener(sock, l) => self.roster.forward_listener(sock, l),
                c @ Cmd::Adopt { .. } => {
                    self.shared.stats.handoff_done();
                    self.roster.hand_on(c);
                }
                c @ Cmd::Dial { .. } => {
                    if let Err(Cmd::Dial { on_error, .. }) = self.roster.post_next(c) {
                        on_error(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "engine shutting down",
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    /// A multishot accept of some listening socket is in flight.
    fn accepts_armed(&self) -> bool {
        self.listeners.iter().any(|l| l.armed)
    }

    fn run_inner(&mut self) {
        CURRENT_LOOP.with(|c| c.set(self.shared.uid));
        if let Err(e) = self.init() {
            log_or_stderr(
                akio_log::Level::Error,
                format_args!("io_uring init failed: {e}"),
            );
            return;
        }
        loop {
            // Commands posted to itself after the last drain (by callbacks run from timers,
            // retiring or draining): handled before blocking, since nothing would wake it.
            if self.shared.self_posted() {
                self.drain_cmds();
            }
            self.submit_sends();
            self.arm_loop_ops();
            if !self.graveyard.is_empty() {
                // Submit before blocking: the kernel then holds its own references to the
                // sockets of finalized connections, whose descriptors may be closed.
                let _ = self.ring.submit();
                if self.ring.sq_is_empty() {
                    self.graveyard.clear();
                }
            }
            let mut timeout = (self.draining.is_some()
                || self.retire_at.is_some()
                || self.retire_kill.is_some()
                || self.unlisted_kill.is_some()
                || self.ears.iter().flatten().any(|e| e.kill.is_some()))
            .then_some(Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            if let Some(t) = self.accept_retry_at {
                let left = t.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
                timeout = Some(timeout.map_or(left, |x| x.min(left)));
            }
            let timeout = akio_core::timer::poll_timeout(timeout);
            let res = match timeout {
                Some(t) => self.ring.submit_with_timeout(1, t),
                None => self.ring.submit_and_wait(1),
            };
            match res {
                Ok(_) => {}
                Err(e)
                    if matches!(e.raw_os_error(), Some(ffi::ETIME | ffi::EINTR | ffi::EBUSY)) => {}
                Err(e) => {
                    log_or_stderr(akio_log::Level::Error, format_args!("io_uring_enter: {e}"));
                    break;
                }
            }
            self.shared.stats.iterations.add_local(1);
            let mut cqes = std::mem::take(&mut self.cqes);
            cqes.clear();
            self.ring.reap_into(&mut cqes);
            self.shared.stats.events.add_local(cqes.len() as u64);
            self.clock = Instant::now();
            for &(data, res, flags) in &cqes {
                self.on_cqe(data, res, flags);
            }
            self.cqes = cqes;
            // Loop timers (ADR-103) before the commands: what they send posts wakes here.
            akio_core::timer::fire();
            self.drain_cmds();
            self.fire_timers();
            if self.retiring && self.draining.is_none() && self.retire_step() {
                break;
            }
            if self.draining.is_none() && self.unlisting() && self.unlisted_step() {
                self.quiesce();
                break;
            }
            if let Some(deadline) = self.draining {
                // Done once every connection closed and the cancelled multishot accepts have
                // ended: until then they may still deliver connections, which are served.
                if self.slots.is_empty() && !self.accepts_armed() && self.dgrams_idle() {
                    self.quiesce();
                    break;
                }
                if Instant::now() >= deadline {
                    let ids: Vec<u64> = self.slots.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    self.quiesce();
                    break;
                }
            }
        }
    }

    /// Before the loop's memory is freed: cancels every operation still in flight and reaps
    /// completions until none is left, so the kernel no longer refers to the provided buffers,
    /// the buffer ring or the wake buffer when `Loop` drops them. If that does not finish in
    /// time (a kernel refusing `ASYNC_CANCEL_ANY`, say), that memory is leaked instead of freed.
    fn drain_inflight(&mut self) {
        if self.inflight == 0 {
            return;
        }
        let e = Sqe::async_cancel_any().user_data(ud(0, OP_OTHER));
        self.push(e);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.inflight > 0 && Instant::now() < deadline {
            let _ = self.ring.submit_with_timeout(1, Duration::from_millis(10));
            let mut cqes = Vec::new();
            self.ring.reap_into(&mut cqes);
            for (data, res, flags) in cqes {
                // Count only: no callbacks or re-arming during teardown.
                if !cqe_more(flags) {
                    self.inflight = self.inflight.saturating_sub(1);
                }
                if data & 0xf == OP_ACCEPT && res >= 0 {
                    // SAFETY: a fresh descriptor from the kernel that nothing else owns;
                    // dropping it closes it.
                    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(res) });
                }
            }
        }
        if self.inflight > 0 {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!(
                    "io_uring: {} operation(s) still in flight at exit; leaking their buffers",
                    self.inflight
                ),
            );
            self.bufs.leak();
            if let Some(g) = &mut self.old_bufs {
                g.leak();
            }
            self.wake_buf.leaked = true;
            // Ring sends the kernel may still read: keep their bytes forever.
            for (_, o) in self.orphans.drain() {
                std::mem::forget(o);
            }
            for slot in self.slots.values_mut() {
                if let Slot::Conn(lc) = slot {
                    if lc.send_armed && !lc.send_unsent {
                        std::mem::forget(lc.inner.clone());
                        std::mem::forget(lc.send_msg.take());
                    }
                }
            }
        }
    }

    /// Before the thread exits: let the cancelled multishot accept finish, so the listening
    /// socket is really closed when `Group::join` returns (the kernel keeps it alive while the
    /// accept is in flight).
    fn quiesce(&mut self) {
        // The drain is over: what the accept still delivers now is closed (`on_accept` finds
        // no listener).
        self.ears.clear();
        for _ in 0..200 {
            if !self.accepts_armed() {
                break;
            }
            let _ = self.ring.submit_with_timeout(1, Duration::from_millis(10));
            let mut cqes = Vec::new();
            self.ring.reap_into(&mut cqes);
            for (data, res, flags) in cqes {
                self.on_cqe(data, res, flags);
            }
        }
    }

    /// (Re-)arms the operations that belong to the loop itself: the wake-up read and accept.
    fn arm_loop_ops(&mut self) {
        if !self.wake_armed {
            let fd = self.shared.waker.as_raw_fd();
            let buf = self.wake_buf.as_ptr();
            let e = Sqe::read(fd, buf, 8).user_data(ud(0, OP_WAKE));
            self.push(e);
            self.wake_armed = true;
        }
        let backoff_over = self.accept_retry_at.is_none_or(|t| Instant::now() >= t);
        if self.draining.is_none() && !self.retiring && backoff_over {
            let mut arm = Vec::new();
            for ls in &mut self.listeners {
                let live = self
                    .ears
                    .get(ls.sock.lid)
                    .and_then(Option::as_ref)
                    .is_some_and(|e| !e.unlisted);
                if let (false, true, Some(l)) = (ls.armed, live, &ls.l) {
                    arm.push(
                        Sqe::accept_multi(l.as_raw_fd()).user_data(ud(ls.sock.id(), OP_ACCEPT)),
                    );
                    ls.armed = true;
                }
            }
            for e in arm {
                self.push(e);
            }
        }
        let draining = self.draining.is_some();
        for i in 0..self.dgrams.len() {
            let d = &self.dgrams[i];
            if d.armed {
                continue;
            }
            let mut mask = 0;
            if d.port.wants_read() && !draining {
                mask |= ffi::POLLIN as u32;
            }
            if d.port.wants_write() {
                mask |= ffi::POLLOUT as u32;
            }
            if mask != 0 {
                let e = Sqe::poll_add(d.port.fd(), mask).user_data(ud(i as u64, OP_DGRAM));
                self.dgrams[i].armed = true;
                self.push(e);
            }
        }
    }

    // ---- completions ----------------------------------------------------------------------

    fn on_cqe(&mut self, data: u64, res: i32, flags: u32) {
        if !cqe_more(flags) {
            self.inflight = self.inflight.saturating_sub(1);
        }
        let (id, op) = (data >> 4, data & 0xf);
        match op {
            OP_WAKE => self.wake_armed = false,
            OP_ACCEPT => self.on_accept(Sock::of_id(id), res, flags),
            OP_RECV => self.on_recv(id, 0, res, flags),
            OP_RECV1 => self.on_recv(id, 1, res, flags),
            OP_POLL => self.on_poll(id),
            OP_RESET => self.on_reset_watch(id),
            OP_DGRAM => self.on_dgram(id as usize, res),
            OP_SEND => self.on_send(id, res),
            _ => {} // buffer provisioning, cancels
        }
    }

    fn on_accept(&mut self, sock: Sock, res: i32, flags: u32) {
        if !cqe_more(flags) {
            if let Some(pos) = self
                .listeners
                .iter()
                .position(|l| l.sock == sock && l.armed)
            {
                self.listeners[pos].armed = false;
                if self.listeners[pos].l.is_none() {
                    self.listeners.swap_remove(pos);
                }
            }
        }
        let Some(ear) = self.ears.get_mut(sock.lid).and_then(Option::as_mut) else {
            // Not a listener of this group (any more): a fresh descriptor is closed.
            if res >= 0 {
                // SAFETY: the kernel just handed us this fresh descriptor; nothing else owns it.
                drop(unsafe { TcpStream::from_raw_fd(res) });
            }
            return;
        };
        if res < 0 {
            // `EINVAL`: the socket stopped listening (`stop_listening`).
            let ended = res == -ffi::EINVAL && ear.unlisted;
            if res != -ffi::ECANCELED && res != -ffi::EINTR && !ended {
                // e.g. EMFILE: retry in a moment instead of spinning.
                self.shared.stats.accept_errors.add_local(1);
                let e = io::Error::from_raw_os_error(-res);
                log_or_stderr(akio_log::Level::Warn, format_args!("accept: {e}"));
                self.accept_retry_at = Some(Instant::now() + Duration::from_millis(100));
            }
            return;
        }
        // SAFETY: the kernel just handed us this fresh descriptor; nothing else owns it.
        let stream = unsafe { TcpStream::from_raw_fd(res) };
        let unix = ear.ear.unix;
        let peer = if unix {
            akio_core::UNIX_ADDR
        } else {
            let Ok(peer) = stream.peer_addr() else {
                return;
            };
            peer
        };
        let unix_local = unix.then_some(akio_core::UNIX_ADDR);
        if !ear.filter.allows(&peer) {
            self.shared.stats.filtered.add_local(1);
            akio_log::debug!(target: "akio", peer:% = peer; "connection refused by the accept filter");
            return; // dropping the stream closes it
        }
        let acceptor = ear.ear.acceptor.clone();
        if self.draining.is_some() || ear.drain {
            // Accepted before the cancellation of the multishot accept took effect: the peer
            // already counts as connected (on a listening socket shared with other processes it
            // could have been served there). Resetting it would lose its first request, so serve
            // that, then shut the connection down like those open when the drain began; one
            // that sends nothing is closed at the drain deadline.
            if let Some(id) = self.open(stream, peer, acceptor, false, unix_local, sock.lid) {
                if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                    lc.shutdown_after_data = true;
                }
            }
            return;
        }
        // Also a connection accepted after the socket was handed on (before the cancellation
        // of this loop's accept took effect): it is served here.
        // Accept-time balancing (ADR-105): a loop holding more than its share hands the
        // connection over before reading from it. A Unix-domain connection (ADR-121) stays:
        // `Adopt` opens with TCP addresses.
        if !self.retiring && !unix {
            if let Some(to) = self.roster.handoff_target(&self.shared) {
                to.post(Cmd::Adopt {
                    stream,
                    peer,
                    acceptor,
                    lid: sock.lid,
                });
                return;
            }
        }
        self.open(stream, peer, acceptor, false, unix_local, sock.lid);
    }

    /// A connection another loop accepted and handed here (ADR-105).
    fn adopt_accepted(
        &mut self,
        stream: TcpStream,
        peer: std::net::SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        lid: usize,
    ) {
        if self.draining.is_some() {
            // As for one the cancelled multishot accept completes while draining (`on_accept`):
            // serve its first request, then shut it down.
            if let Some(id) = self.open(stream, peer, acceptor, false, None, lid) {
                if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                    lc.shutdown_after_data = true;
                }
            }
        } else if self.retiring {
            self.roster.hand_on(Cmd::Adopt {
                stream,
                peer,
                acceptor,
                lid,
            });
        } else {
            self.open(stream, peer, acceptor, false, None, lid);
        }
    }

    fn on_poll(&mut self, id: u64) {
        if matches!(self.slots.get(&id), Some(Slot::Connecting { .. })) {
            self.finish_connect(id);
            return;
        }
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            lc.poll_armed = false;
            self.on_wake(id);
        }
    }

    fn on_recv(&mut self, id: u64, bgid: u16, res: i32, flags: u32) {
        let bid = cqe_buffer(flags);
        let more = cqe_more(flags);
        if !more {
            if let Some(g) = self.group(bgid) {
                g.armed = g.armed.saturating_sub(1);
            }
        }
        let now = self.clock.saturating_duration_since(self.epoch).as_millis() as u64;
        let mut done = Done::No;
        let mut fed = false;
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            if !more {
                lc.recv_armed = false;
                lc.cancel_sent = false;
            }
            if res > 0 {
                let n = res as usize;
                if let Some(bid) = bid {
                    if !lc.eof && !lc.held_eof && lc.inner.is_open() {
                        let g = if self.bufs.bgid == bgid {
                            &self.bufs
                        } else if let Some(g) = self.old_bufs.as_ref().filter(|g| g.bgid == bgid) {
                            g
                        } else {
                            return; // cannot happen: a group lives while recvs use it
                        };
                        let off = bid as usize * g.size;
                        lc.last_active = now;
                        lc.bytes_in += n as u64;
                        let st = &self.shared.stats;
                        st.reads.add_local(1);
                        st.bytes_in.add_local(n as u64);
                        // SAFETY: the kernel handed buffer `bid` over in this completion; it is
                        // not in the ring again until `give_back` below, so nothing writes it
                        // while `data` lives. `slice` bounds-checks the range.
                        let data = unsafe { g.bufs.slice(off, n.min(g.size)) };
                        // `refresh` ran after the previous completion, so `bp` is current.
                        if !lc.held_in.is_empty() || lc.bp || lc.rx_offload || lc.inner.read_held()
                        {
                            // Reads are paused, but the multishot recv runs until its cancel
                            // lands (it can complete many more buffers first): keep the data,
                            // in order, for when they resume (`replay`).
                            lc.held_in.extend_from_slice(data);
                        } else {
                            done = feed(lc, data, id, &self.cfg, st, &mut self.clock, &mut self.rs);
                            fed = true;
                        }
                    }
                }
            } else if res == 0 {
                if !lc.eof && !lc.held_eof {
                    if lc.held_in.is_empty() {
                        lc.eof = true;
                        // Peer is done sending: finish writing what we owe, then close.
                        lc.inner.close_after_responses();
                        done = Done::Eof;
                    } else {
                        lc.held_eof = true; // after the held input (`replay`)
                    }
                }
            } else if res == -ffi::EIO && lc.inner.kernel_rx() && !lc.eof && !lc.held_eof {
                // Kernel TLS: a control record is next (an alert, a post-handshake message).
                // Read it with its content type; the multishot recv ended, `refresh` re-arms.
                let mut buf = vec![0u8; KERNEL_RECORD_BUF];
                match lc.inner.kernel_read_record(&mut buf) {
                    Ok(akio_core::KernelRead::Data(0)) => {
                        // close_notify: the end of the peer's stream.
                        if lc.held_in.is_empty() {
                            lc.eof = true;
                            lc.inner.close_after_responses();
                            done = Done::Eof;
                        } else {
                            lc.held_eof = true;
                        }
                    }
                    Ok(akio_core::KernelRead::Data(n)) => {
                        let st = &self.shared.stats;
                        if !lc.held_in.is_empty() || reads_paused(lc, usize::MAX) {
                            lc.held_in.extend_from_slice(&buf[..n]);
                        } else {
                            done = feed(
                                lc,
                                &buf[..n],
                                id,
                                &self.cfg,
                                st,
                                &mut self.clock,
                                &mut self.rs,
                            );
                            fed = true;
                        }
                    }
                    Ok(akio_core::KernelRead::Control) => {
                        match lc.inner.uncork_flush_ring(&mut self.rs) {
                            Ok(q) => lc.q_hint = Some(q),
                            Err(e) => done = Done::Err(e),
                        }
                    }
                    Err(e) => done = Done::Err(e),
                }
            } else if res != -ffi::ENOBUFS && res != -ffi::ECANCELED && res != -ffi::EINTR {
                done = Done::Err(io::Error::from_raw_os_error(-res));
            }
            // ENOBUFS/ECANCELED/EINTR end the multishot; `refresh` re-arms it if still wanted.
        }
        self.submit_send(id);
        if let Some(bid) = bid {
            if let Some(g) = self.group(bgid) {
                g.give_back(bid);
                g.ring.publish();
            }
        }
        if self.old_bufs.as_ref().is_some_and(|g| g.armed == 0) {
            self.release_old_bufs();
        }
        self.after_data(id, done, fed);
    }

    /// Delivers input held while reads were paused, until it is all out or they pause again.
    /// Called by `refresh` once reads may resume.
    fn replay(&mut self, id: u64) {
        let high = self.cfg.telemetry.live().write_high_watermark();
        let chunk = self.bufs.size;
        let mut done = Done::No;
        let mut fed = false;
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            let mut data = std::mem::take(&mut lc.held_in);
            let mut off = 0;
            while off < data.len() && lc.inner.is_open() && !reads_paused(lc, high) {
                let end = data.len().min(off + chunk);
                done = feed(
                    lc,
                    &data[off..end],
                    id,
                    &self.cfg,
                    &self.shared.stats,
                    &mut self.clock,
                    &mut self.rs,
                );
                fed = true;
                off = end;
                if !matches!(done, Done::No) {
                    break;
                }
            }
            data.drain(..off);
            lc.held_in = data;
            if matches!(done, Done::No) && lc.held_in.is_empty() && lc.held_eof {
                lc.held_eof = false;
                lc.eof = true;
                lc.inner.close_after_responses();
                done = Done::Eof;
            }
        }
        self.submit_send(id);
        self.after_data(id, done, fed);
    }

    /// After `on_data` ran (`fed`) or input was held: the drain's `on_shutdown` for a connection
    /// accepted while draining, then the follow-up for `done`.
    fn after_data(&mut self, id: u64, mut done: Done, fed: bool) {
        if matches!(done, Done::No) && fed {
            if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                if std::mem::take(&mut lc.shutdown_after_data) {
                    let (acc, inner) = (lc.acceptor.clone(), lc.inner.clone());
                    if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                        done = Done::Panic;
                    }
                }
            }
        }
        match done {
            Done::No => self.refresh(id),
            Done::Eof => self.on_wake(id),
            Done::Err(e) => self.finalize(id, Some(Error::Io(e))),
            Done::Panic => self.finalize(id, Some(panic_error())),
        }
    }

    // ---- connection management ------------------------------------------------------------

    fn open(
        &mut self,
        stream: TcpStream,
        peer: std::net::SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        dialed: bool,
        // The local address of a Unix-domain socket, which has none of its own (ADR-120).
        unix_local: Option<std::net::SocketAddr>,
        // The listener it was accepted on (`NO_LISTENER` when dialed).
        lid: usize,
    ) -> Option<u64> {
        if stream.set_nonblocking(true).is_err() {
            return None;
        }
        let local = match unix_local {
            Some(l) => l,
            None => {
                let _ = stream.set_nodelay(true);
                stream.local_addr().ok()?
            }
        };
        let tel = self.cfg.telemetry.clone();
        if !tel.conn_opened(!dialed) {
            self.shared.stats.rejected.add_local(1);
            akio_log::debug!(target: "akio", peer:% = peer; "connection refused: max_connections reached");
            return None; // dropping the stream closes it
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let fd = stream.as_raw_fd();
        let inner = ConnInner::new(
            id,
            stream,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        if self.ring_sends {
            inner.set_ring_sends(true);
        }
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) else {
            inner.mark_closed();
            tel.conn_closed();
            return None;
        };
        let st = &self.shared.stats;
        if dialed { &st.dialed } else { &st.accepted }.add_local(1);
        akio_log::trace!(target: "akio", conn_id = id, peer:% = peer, local:% = local, dialed = dialed; "connection opened");
        let now = self.tick();
        let idle = self.cfg.telemetry.live().idle_ms();
        let idle_timer = self.arm_idle(id, now + idle);
        self.slots.insert(
            id,
            Slot::Conn(LoopConn {
                inner,
                handler,
                acceptor,
                lid,
                recv_armed: false,
                recv_bgid: 0,
                cancel_sent: false,
                poll_armed: false,
                bp: false,
                eof: false,
                held_in: Vec::new(),
                held_eof: false,
                last_active: now,
                idle_timer,
                idle: IdleRule::ENGINE,
                write_timer: None,
                write_mark: 0,
                hs_timer: None,
                q_hint: None,
                opened: now,
                bytes_in: 0,
                shutdown_after_data: false,
                rx_offload: false,
                rx_offload_tries: 0,
                send_armed: false,
                send_unsent: false,
                send_msg: None,
            }),
        );
        self.arm_reset_watch(id, fd);
        self.arm_handshake(id);
        // `on_open` may already have queued output or closed the connection.
        self.on_wake(id);
        Some(id)
    }

    /// Watches the socket for a reset with a one-shot poll of its own. A multishot recv that
    /// has delivered data and is waiting for more does not always complete when an RST
    /// arrives next (observed on Linux 6.12: the socket holds ECONNRESET, no CQE ever comes),
    /// which would leave the connection open forever. `POLLRDHUP` also fires on a plain FIN,
    /// which the recv reports itself, so the completion only acts on a pending socket error.
    fn arm_reset_watch(&mut self, id: u64, fd: std::os::fd::RawFd) {
        let e =
            Sqe::poll_add(fd, (ffi::POLLRDHUP | ffi::POLLERR) as u32).user_data(ud(id, OP_RESET));
        self.push(e);
    }

    fn on_reset_watch(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get(&id) else {
            return;
        };
        if let Ok(Some(e)) = lc.inner.stream().take_error() {
            self.finalize(id, Some(Error::Io(e)));
        }
    }

    fn begin_dial(
        &mut self,
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
        unix: bool,
    ) {
        if self.draining.is_some() {
            return on_error(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "engine shutting down",
            ));
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let e = Sqe::poll_add(stream.as_raw_fd(), ffi::POLLOUT as u32).user_data(ud(id, OP_POLL));
        self.push(e);
        self.slots.insert(
            id,
            Slot::Connecting {
                stream,
                acceptor,
                on_error: Some(on_error),
                unix,
            },
        );
        self.arm_connect(id);
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Slot::Connecting {
            stream,
            acceptor,
            on_error,
            unix,
        }) = self.slots.remove(&id)
        else {
            return;
        };
        let result = match stream.take_error() {
            Ok(None) if unix => Ok(akio_core::UNIX_ADDR),
            Ok(None) => stream.peer_addr(),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok(peer) => {
                let unix_local = unix.then_some(akio_core::UNIX_ADDR);
                self.open(stream, peer, acceptor, true, unix_local, NO_LISTENER);
            }
            Err(e) => {
                if let Some(f) = on_error {
                    f(e);
                }
            }
        }
    }

    /// Flushes output, applies `close_after_send`, and refreshes interest.
    fn on_wake(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let r = lc.inner.flush_queue_ring(&mut self.rs);
        self.after_flush(id, r);
    }

    /// After a flush that returned `r` (`Ok(true)`: nothing left queued): submits the ring send
    /// it described, applies `close_after_send` and refreshes interest.
    fn after_flush(&mut self, id: u64, r: io::Result<bool>) {
        self.submit_send(id);
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        match r {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && lc.inner.close_after_send_requested() {
                    self.finalize(id, None);
                } else {
                    lc.q_hint = empty.then_some(0);
                    self.refresh(id);
                }
            }
        }
    }

    /// Takes the ring send the last flush of connection `id` described in `rs`, if any (ADR-106),
    /// for `submit_sends`. Called right after every such flush, before anything else uses `rs`.
    fn submit_send(&mut self, id: u64) {
        if self.rs.parts().is_empty() {
            return;
        }
        self.rs.clear();
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            lc.send_armed = true;
            lc.send_unsent = true;
            self.unsent.push(id);
        }
        // (Cannot be missing: a flush that describes a send leaves the connection open.)
    }

    /// Right before the loop enters the kernel: submits the ring sends taken by `submit_send`,
    /// each described again to carry what was queued after it.
    fn submit_sends(&mut self) {
        if self.unsent.is_empty() {
            return;
        }
        let mut ids = std::mem::take(&mut self.unsent);
        for &id in &ids {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                continue; // finalized meanwhile: `finalize` released it
            };
            if !std::mem::take(&mut lc.send_unsent) {
                continue;
            }
            let e = if lc.inner.ring_redescribe(&mut self.rs) > 0 {
                prep_send(lc, id, &mut self.rs)
            } else {
                None
            };
            match e {
                Some(e) => self.push(e),
                None => {
                    // Nothing to send after all (cannot happen): back to the plain flush path.
                    lc.send_armed = false;
                    lc.inner.ring_release();
                    self.rs.clear();
                    self.refresh(id);
                }
            }
        }
        ids.clear();
        if self.unsent.is_empty() {
            self.unsent = ids; // keep the allocation
        }
    }

    /// A ring send of connection `id` completed with `res` (bytes sent, or `-errno`).
    fn on_send(&mut self, id: u64, res: i32) {
        let r = match self.slots.get_mut(&id) {
            Some(Slot::Conn(lc)) if lc.send_armed => {
                lc.send_armed = false;
                lc.inner.ring_sent(res, &mut self.rs)
            }
            _ => {
                // The connection closed while its send was in flight: free what it read.
                if let Some(o) = self.orphans.remove(&id) {
                    o.inner.ring_release();
                }
                return;
            }
        };
        match r {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(RingSent::Drained { close: true }) => self.finalize(id, None),
            Ok(RingSent::Drained { close: false }) => {
                // The usual case: the answer is out. Interest changes only if reads were held
                // back for the queue, or kernel TLS waits to move its receive direction.
                if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                    if lc.bp || lc.inner.offload_rx_waiting() {
                        lc.q_hint = Some(0);
                        self.refresh(id);
                    }
                }
            }
            Ok(RingSent::Pending) => {
                self.submit_send(id);
                self.refresh(id);
            }
        }
    }

    /// Arms or cancels the connection's recv / writability poll to match its state.
    fn refresh(&mut self, id: u64) {
        let high = self.cfg.telemetry.live().write_high_watermark();
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        // The count the last flush on this thread reported, if nothing ran since: output
        // queued by another thread meanwhile either went out directly or woke the loop.
        let q = match lc.q_hint.take() {
            Some(q) => q,
            None => lc.inner.queued_bytes(),
        };
        let arm = q > 0 && lc.write_timer.is_none() && self.cfg.telemetry.live().write_ms() != 0;
        if q >= high && lc.inner.write_backpressure() {
            if !lc.bp {
                self.shared.stats.backpressure.add_local(1);
            }
            lc.bp = true;
        } else if q <= high / 4 || !lc.inner.write_backpressure() {
            lc.bp = false;
        }
        // Kernel TLS: the receive direction may follow the send direction into the kernel only
        // where no recv is in flight (it could hold records the transport has not seen): stop
        // reading, and once the multishot recv has ended with nothing held, move it.
        if lc.inner.offload_rx_waiting() && !lc.eof && lc.inner.is_open() {
            if !lc.rx_offload && lc.rx_offload_tries < RX_OFFLOAD_TRIES {
                lc.rx_offload = true;
            }
            if lc.rx_offload && !lc.recv_armed {
                lc.rx_offload = false;
                lc.rx_offload_tries += 1;
                if lc.held_in.is_empty() && !lc.held_eof {
                    if let Err(e) = lc.inner.offload_rx_now() {
                        return self.finalize(id, Some(Error::Io(e)));
                    }
                }
                if lc.rx_offload_tries >= RX_OFFLOAD_TRIES && lc.inner.offload_rx_waiting() {
                    lc.inner.offload_rx_give_up();
                }
            }
        }
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let want_read =
            !lc.inner.read_held() && !lc.bp && !lc.rx_offload && !lc.eof && lc.inner.is_open();
        if want_read && (!lc.held_in.is_empty() || lc.held_eof) {
            // Input held while paused goes first; `replay` comes back here (once it is out, or
            // paused again, so this does not loop).
            return self.replay(id);
        }
        let fd = lc.inner.stream().as_raw_fd();
        let mut entries: Vec<Sqe> = Vec::new();
        if want_read && !lc.recv_armed {
            lc.recv_armed = true;
            lc.recv_bgid = self.bufs.bgid;
            self.bufs.armed += 1;
            entries.push(
                Sqe::recv_multi(fd, self.bufs.bgid).user_data(ud(id, recv_op(self.bufs.bgid))),
            );
        } else if !want_read && lc.recv_armed && !lc.cancel_sent {
            lc.cancel_sent = true;
            entries
                .push(Sqe::async_cancel(ud(id, recv_op(lc.recv_bgid))).user_data(ud(id, OP_OTHER)));
        }
        if q > 0 && !lc.poll_armed && !lc.send_armed {
            // (A ring send in flight goes on with the rest when it completes.)
            lc.poll_armed = true;
            entries.push(Sqe::poll_add(fd, ffi::POLLOUT as u32).user_data(ud(id, OP_POLL)));
        }
        for e in entries {
            self.push(e);
        }
        if arm {
            self.arm_write(id);
        }
    }

    /// Removes a connection and runs `on_close` exactly once. In-flight operations complete
    /// (the shutdown below ends them) and are ignored: ids are never reused.
    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(Slot::Conn(mut lc)) = self.slots.remove(&id) else {
            return;
        };
        if let Some(t) = lc.idle_timer.take() {
            self.wheel.cancel(t);
        }
        if let Some(t) = lc.write_timer.take() {
            self.wheel.cancel(t);
        }
        if let Some(t) = lc.hs_timer.take() {
            self.wheel.cancel(t);
        }
        if lc.send_unsent {
            // Described but never submitted (a `close` right after a send, in the same batch):
            // write what is queued now, as the `writev` at the end of the callback would have,
            // before the shutdown below. The kernel never saw these bytes.
            lc.inner.ring_write_unsent();
        }
        lc.inner.mark_closed();
        if lc.send_armed && !lc.send_unsent {
            // The kernel still reads its queued bytes (kept by `mark_closed`) and maybe its
            // header: both live until the send completes (the shutdown below ends it).
            self.orphans.insert(
                id,
                Orphan {
                    inner: lc.inner.clone(),
                    _msg: lc.send_msg.take(),
                },
            );
        }
        self.graveyard.push(lc.inner.clone());
        let _ = lc.inner.stream().shutdown(std::net::Shutdown::Both);
        let t0 = self.timing();
        if akio_log::log_enabled!(target: "akio", akio_log::Level::Trace) {
            akio_log::trace!(target: "akio", conn_id = id, peer:% = lc.inner.peer_addr(), error:? = err; "connection closed");
        }
        let _ = catch_unwind(AssertUnwindSafe(|| lc.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
        self.shared.stats.closed.add_local(1);
        self.cfg.telemetry.conn_closed();
    }

    // ---- commands -------------------------------------------------------------------------

    fn drain_cmds(&mut self) {
        let mut batch = std::mem::take(&mut self.spare_cmds);
        loop {
            self.shared.take_into(&mut batch);
            if batch.is_empty() {
                break;
            }
            for cmd in batch.drain(..) {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Retime(id) => self.retime(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Task(id, task) => self.on_task(id, task),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Core(c) => self.on_core(c),
                    Cmd::Adopt {
                        stream,
                        peer,
                        acceptor,
                        lid,
                    } => {
                        self.shared.stats.handoff_done();
                        self.adopt_accepted(stream, peer, acceptor, lid);
                    }
                    Cmd::Dial {
                        stream,
                        acceptor,
                        on_error,
                        unix,
                    } => self.begin_dial(stream, acceptor, on_error, unix),
                    Cmd::Listen { lid, ear } => {
                        if self.ears.len() <= lid {
                            self.ears.resize_with(lid + 1, || None);
                        }
                        self.ears[lid] = Some(LoopEar::new(ear));
                    }
                    Cmd::AddListener(sock, l) => self.add_listener(sock, l),
                    Cmd::GiveListener { sock, to } => {
                        if let Some(l) = self.drop_listener(sock) {
                            to.post(Cmd::AddListener(sock, l));
                        }
                    }
                    Cmd::Retire => self.retire(),
                    Cmd::Revive => {
                        self.retiring = false;
                        self.retire_at = None;
                        self.retire_kill = None;
                        self.shared.stats.set_retiring(false);
                    }
                    Cmd::StopListening {
                        lid,
                        drain,
                        exit,
                        done,
                    } => {
                        self.stop_listening(lid, drain, exit);
                        drop(done);
                    }
                }
            }
        }
        if batch.capacity() <= MAX_SPARE_CMDS {
            self.spare_cmds = batch;
        }
    }

    fn on_core(&mut self, c: LoopCmd) {
        match c {
            LoopCmd::Inspect(reply) => {
                let now = self.tick();
                let infos = self
                    .slots
                    .iter()
                    .filter_map(|(id, s)| match s {
                        Slot::Conn(lc) => Some(self.info(*id, lc, now)),
                        Slot::Connecting { .. } => None,
                    })
                    .collect();
                reply(infos);
            }
            LoopCmd::Reload => self.on_reload(),
        }
    }

    fn info(&self, id: u64, lc: &LoopConn, now: u64) -> ConnInfo {
        let mut ci = ConnInfo::new(id, &lc.inner, self.shared.stats.meta().clone());
        // A shared group's threads serve several listeners (ADR-130): name the connection's.
        if let Some(e) = self.ears.get(lc.lid).and_then(Option::as_ref) {
            ci.owner.listener = Some(e.ear.addr);
        }
        ci.age = Duration::from_millis(now.saturating_sub(lc.opened));
        ci.idle = Duration::from_millis(now.saturating_sub(lc.last_active));
        ci.bytes_in = lc.bytes_in;
        ci.backpressure = lc.bp;
        ci
    }

    /// Live settings changed: re-arm idle timers for the new timeout and re-evaluate
    /// backpressure against the new watermark.
    fn on_reload(&mut self) {
        for d in &mut self.dgrams {
            d.port.on_reload();
        }
        self.apply_read_buffer();
        let backlog = self.cfg.telemetry.live().backlog();
        if backlog != self.backlog {
            self.backlog = backlog;
            for ls in &self.listeners {
                if let Some(l) = &ls.l {
                    if let Err(e) = akio_sys::set_backlog(l, backlog) {
                        log_or_stderr(
                            akio_log::Level::Warn,
                            format_args!("listen({backlog}) on a live socket: {e}"),
                        );
                    }
                }
            }
        }
        let idle = self.cfg.telemetry.live().idle_ms();
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        for &id in &ids {
            if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                if let Some(t) = lc.idle_timer.take() {
                    self.wheel.cancel(t);
                }
                if let Some(at) = lc.idle.first_check(idle, lc.last_active, now) {
                    lc.idle_timer = Some(self.wheel.schedule(at, id));
                }
            }
        }
        for id in ids {
            self.refresh(id);
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.telemetry.live().shutdown_timeout());
        // A multishot accept keeps its listening socket alive until it is cancelled; what it
        // still delivers is served by its listener's acceptor (`on_accept`).
        let socks: Vec<Sock> = self.listeners.iter().map(|l| l.sock).collect();
        for sock in socks {
            drop(self.drop_listener(sock));
        }
        // Datagram sockets stop reading: `on_shutdown`, then a poll only while replies wait.
        let mut cancels = Vec::new();
        for (i, d) in self.dgrams.iter_mut().enumerate() {
            d.port.shutdown();
            if d.armed {
                cancels.push(Sqe::async_cancel(ud(i as u64, OP_DGRAM)).user_data(ud(0, OP_OTHER)));
            }
        }
        for e in cancels {
            self.push(e);
        }
        self.notify_shutdown(None);
    }

    // ---- thread resizing (ADR-028) ----------------------------------------------------------

    /// Stops accepting on socket `sock` and returns it (if this loop holds it). An armed
    /// multishot accept is cancelled; until its final completion the entry stays (with no
    /// socket), and what it still accepts is served here.
    fn drop_listener(&mut self, sock: Sock) -> Option<TcpListener> {
        let pos = self
            .listeners
            .iter()
            .position(|l| l.sock == sock && l.l.is_some())?;
        let l = self.listeners[pos].l.take();
        if self.listeners[pos].armed {
            let e = Sqe::async_cancel(ud(sock.id(), OP_ACCEPT)).user_data(ud(0, OP_OTHER));
            self.push(e);
        } else {
            self.listeners.swap_remove(pos);
        }
        l
    }

    /// Whether listener `lid`'s sockets form a `SO_REUSEPORT` group (one per loop index).
    fn reuseport(&self, lid: usize) -> bool {
        self.ears
            .get(lid)
            .and_then(Option::as_ref)
            .is_some_and(|e| e.ear.reuseport)
    }

    /// Listener `lid` (with `None`, every listener of the group) was removed (ADR-099,
    /// ADR-130): its multishot accepts are cancelled and its listening sockets close once that
    /// is done; the connections stay.
    fn stop_listening(&mut self, lid: Option<usize>, drain: Option<Duration>, exit: bool) {
        if self.draining.is_some() {
            return; // the engine is shutting down anyway
        }
        let at = drain.map(|d| Instant::now() + d);
        for (i, e) in self.ears.iter_mut().enumerate() {
            if let Some(e) = e.as_mut().filter(|_| lid.is_none_or(|l| l == i)) {
                e.unlisted = true;
                if drain.is_some() {
                    e.drain = true;
                }
                if let (Some(at), Some(_)) = (at, lid) {
                    e.kill = Some(e.kill.map_or(at, |t| t.min(at)));
                }
            }
        }
        if lid.is_none() {
            self.unlisted_exit |= exit;
            if let Some(at) = at {
                self.unlisted_kill = Some(self.unlisted_kill.map_or(at, |t| t.min(at)));
            }
        }
        let socks: Vec<Sock> = self
            .listeners
            .iter()
            .map(|l| l.sock)
            .filter(|s| lid.is_none_or(|l| s.lid == l))
            .collect();
        for sock in socks {
            if let Some(l) = self.drop_listener(sock) {
                // The multishot accept holds the socket open until its cancellation completes,
                // and meanwhile the kernel would still queue connections on it (it is still in
                // the address's `SO_REUSEPORT` group), to be reset when it closes: a listener
                // replaced at its address would refuse some of the first connections after its
                // removal. Out of the group now. (Clones of an inherited socket are not ours to
                // shut: another process may share it.)
                if self.reuseport(sock.lid) {
                    let _ = akio_sys::stop_listening(&l);
                }
            }
        }
        if drain.is_some() {
            self.notify_shutdown(lid);
        }
    }

    /// Whether a removal is still at work here: a drain deadline to apply, or the thread to end
    /// once nothing is left.
    fn unlisting(&self) -> bool {
        self.unlisted_exit
            || self.unlisted_kill.is_some()
            || self.ears.iter().flatten().any(|e| e.kill.is_some())
    }

    /// Once per iteration while a removal is at work: closes what is left at a drain deadline,
    /// and ends the thread (true) once no connection and no accept is left, if it may.
    fn unlisted_step(&mut self) -> bool {
        let now = Instant::now();
        if self.unlisted_kill.is_some_and(|t| now >= t) {
            self.unlisted_kill = None;
            let ids: Vec<u64> = self.slots.keys().copied().collect();
            for id in ids {
                match self.slots.get(&id) {
                    Some(Slot::Conn(_)) => self.finalize(id, None),
                    _ => {
                        if let Some(Slot::Connecting {
                            on_error: Some(f), ..
                        }) = self.slots.remove(&id)
                        {
                            f(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "listener shut down",
                            ));
                        }
                    }
                }
            }
        }
        let due: Vec<usize> = self
            .ears
            .iter_mut()
            .enumerate()
            .filter_map(|(i, e)| {
                let e = e.as_mut()?;
                e.kill.is_some_and(|t| now >= t).then(|| {
                    e.kill = None;
                    i
                })
            })
            .collect();
        for lid in due {
            let ids: Vec<u64> = self
                .slots
                .iter()
                .filter_map(|(id, s)| matches!(s, Slot::Conn(lc) if lc.lid == lid).then_some(*id))
                .collect();
            for id in ids {
                self.finalize(id, None);
            }
        }
        self.unlisted_exit && self.slots.is_empty() && !self.accepts_armed() && self.dgrams_idle()
    }

    /// Starts accepting on socket `sock` (a new listener's, passed on by a retiring loop, or
    /// given back to a loop the group grew again), or passes it on if this loop is retiring.
    fn add_listener(&mut self, sock: Sock, l: TcpListener) {
        let reuseport = match self.ears.get(sock.lid).and_then(Option::as_ref) {
            Some(e) if !e.unlisted && self.draining.is_none() => e.ear.reuseport,
            _ => return, // shutting down, removed, or unknown: the socket closes
        };
        if self.retiring {
            if reuseport {
                self.roster.forward_listener(sock, l);
            }
            return;
        }
        let Some(l) = self.roster.route(sock, l, &self.shared, reuseport) else {
            return;
        };
        if l.set_nonblocking(true).is_err() {
            return;
        }
        let backlog = self.cfg.telemetry.live().backlog();
        if backlog != self.backlog {
            let _ = akio_sys::set_backlog(&l, backlog);
        }
        // An entry still cancelling the accept of this very socket (handed on and back) takes
        // it again; the accept is re-armed once the cancellation ended.
        match self
            .listeners
            .iter_mut()
            .find(|e| e.sock == sock && e.l.is_none())
        {
            Some(e) => e.l = Some(l),
            None => self.listeners.push(Lsn {
                sock,
                l: Some(l),
                armed: false,
            }),
        }
    }

    fn retire(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.retiring = true;
        self.shared.stats.set_retiring(true);
        let now = Instant::now();
        self.retire_at = self.cfg.telemetry.live().retire_timeout().map(|d| now + d);
        self.retire_kill = None;
        let socks: Vec<Sock> = self.listeners.iter().map(|l| l.sock).collect();
        for sock in socks {
            if let Some(l) = self.drop_listener(sock) {
                // `SO_REUSEPORT` sockets go to the active loops; clones of a shared socket the
                // others hold too just close.
                if self.reuseport(sock.lid) {
                    self.roster.forward_listener(sock, l);
                }
            }
        }
    }

    /// Once per iteration while retiring: applies `retire_timeout`, and exits (true) once no
    /// connection and no accept is left and the group did not revive the loop meanwhile.
    fn retire_step(&mut self) -> bool {
        let now = Instant::now();
        if self.retire_at.is_some_and(|t| now >= t) {
            self.retire_at = None;
            self.retire_kill = Some(now + self.cfg.telemetry.live().shutdown_timeout());
            self.notify_shutdown(None);
        }
        if self.retire_kill.is_some_and(|t| now >= t) {
            self.retire_kill = None;
            let ids: Vec<u64> = self.slots.keys().copied().collect();
            for id in ids {
                match self.slots.get(&id) {
                    Some(Slot::Conn(_)) => self.finalize(id, None),
                    _ => {
                        if let Some(Slot::Connecting {
                            on_error: Some(f), ..
                        }) = self.slots.remove(&id)
                        {
                            f(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "I/O thread retired",
                            ));
                        }
                    }
                }
            }
        }
        self.slots.is_empty() && !self.accepts_armed() && self.shared.try_exit()
    }

    /// Switches to a buffer group of the reloaded `read_buffer` size (clamped as at start):
    /// connections move to it when their multishot recv is next armed, which the cancellation
    /// here forces; the old group is released once no recv uses it. A further change waits
    /// until then.
    fn apply_read_buffer(&mut self) {
        let want = self.cfg.telemetry.live().read_buffer().clamp(512, MAX_BUF);
        if want == self.bufs.size || self.old_bufs.is_some() {
            return;
        }
        let mut g = match BufGroup::alloc(want, 1 - self.bufs.bgid) {
            Ok(g) => g,
            Err(e) => {
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!("io_uring: new read buffers ({want} bytes): {e}"),
                );
                return;
            }
        };
        if let Err(e) = g.install(&self.ring) {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!("io_uring: registering read buffers ({want} bytes): {e}"),
            );
            return;
        }
        let old = std::mem::replace(&mut self.bufs, g);
        let old_bgid = old.bgid;
        self.old_bufs = Some(old);
        let mut cancels = Vec::new();
        for (&id, slot) in &mut self.slots {
            if let Slot::Conn(lc) = slot {
                if lc.recv_armed && !lc.cancel_sent && lc.recv_bgid == old_bgid {
                    lc.cancel_sent = true;
                    cancels.push(
                        Sqe::async_cancel(ud(id, recv_op(old_bgid))).user_data(ud(id, OP_OTHER)),
                    );
                }
            }
        }
        for e in cancels {
            self.push(e);
        }
        if self.old_bufs.as_ref().is_some_and(|g| g.armed == 0) {
            self.release_old_bufs();
        }
    }

    /// Frees the group being left (no recv uses it any more), then applies a `read_buffer`
    /// changed again meanwhile.
    fn release_old_bufs(&mut self) {
        if let Some(g) = self.old_bufs.take() {
            g.release(&self.ring);
        }
        self.apply_read_buffer();
    }

    /// Runs `on_shutdown` for every connection and aborts pending dials.
    fn notify_shutdown(&mut self, only: Option<usize>) {
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        for id in ids {
            match self.slots.get_mut(&id) {
                Some(Slot::Conn(lc)) if only.is_none_or(|l| l == lc.lid) => {
                    let (acc, inner) = (lc.acceptor.clone(), lc.inner.clone());
                    if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                        self.finalize(id, Some(panic_error()));
                    }
                }
                Some(Slot::Connecting { .. }) if only.is_none() => {
                    if let Some(Slot::Connecting {
                        on_error: Some(f), ..
                    }) = self.slots.remove(&id)
                    {
                        f(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "engine shutting down",
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    /// Runs a `spawn_blocking` completion on the connection's handler.
    fn on_task(&mut self, id: u64, task: Task) {
        let t0 = self.timing();
        let mut failed = None;
        {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                return; // connection closed meanwhile: the completion is dropped
            };
            lc.inner.set_corked(true);
            if catch_unwind(AssertUnwindSafe(|| lc.handler.run_task(task))).is_err() {
                failed = Some(panic_error());
            } else {
                match lc.inner.uncork_flush_ring(&mut self.rs) {
                    Ok(q) => lc.q_hint = Some(q),
                    Err(e) => failed = Some(Error::Io(e)),
                }
            }
        }
        self.submit_send(id);
        self.check_slow("spawn_blocking completion", id, t0);
        match failed {
            Some(e) => self.finalize(id, Some(e)),
            None => self.refresh(id),
        }
    }

    // ---- slow callbacks / timers ----------------------------------------------------------

    fn timing(&self) -> Option<Instant> {
        self.cfg.telemetry.timing()
    }

    /// Accounts a callback (and reports it if it ran longer than the slow-callback threshold).
    fn check_slow(&self, kind: &'static str, id: u64, started: Option<Instant>) {
        self.cfg
            .telemetry
            .callback_done(&self.shared.stats, kind, id, started);
    }

    fn arm_idle(&mut self, id: u64, at: u64) -> Option<TimerId> {
        if self.cfg.telemetry.live().idle_ms() == 0 {
            return None;
        }
        if self.wheel.is_empty() {
            self.wheel.advance(self.tick(), drop);
        }
        Some(self.wheel.schedule(at, id))
    }

    /// Arms the write-timeout check of a connection that has output queued (if the timeout is
    /// set and no check is pending). `now` comes from the cached loop clock.
    fn arm_write(&mut self, id: u64) {
        let Some(wt) = self.cfg.telemetry.live().write_timeout() else {
            return;
        };
        let now = self.clock.saturating_duration_since(self.epoch).as_millis() as u64;
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        if lc.write_timer.is_some() {
            return;
        }
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        lc.write_mark = lc.inner.debug_state().0;
        let at = now + (wt.as_millis() as u64).max(1);
        lc.write_timer = Some(self.wheel.schedule(at, id | WRITE_TIMER));
    }

    /// Arms the connect deadline of a pending dial (if `connect_timeout` is set). The timer is
    /// not cancelled when the dial completes: the connection then lives under a new id, and a
    /// stale deadline finds no pending dial.
    fn arm_connect(&mut self, id: u64) {
        let Some(ct) = self.cfg.connect_timeout else {
            return;
        };
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let at = now + (ct.as_millis() as u64).max(1);
        self.wheel.schedule(at, id | CONNECT_TIMER);
    }

    /// Arms the handshake deadline of a connection whose transport is negotiating and has a
    /// `handshake_timeout`.
    fn arm_handshake(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get(&id) else {
            return;
        };
        let Some(d) = lc.inner.handshake_timeout() else {
            return;
        };
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let at = now + (d.as_millis() as u64).max(1);
        let t = self.wheel.schedule(at, id | HANDSHAKE_TIMER);
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            lc.hs_timer = Some(t);
        }
    }

    /// A handshake deadline is due: close the connection if its transport is still negotiating.
    fn on_handshake_timer(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        lc.hs_timer = None;
        if lc.inner.transport_handshaking() {
            lc.inner.note_transport_error();
            let e = io::Error::new(io::ErrorKind::TimedOut, "handshake timeout");
            self.finalize(id, Some(Error::Io(e)));
        }
    }

    /// A dial's connect deadline is due: abandon it if it is still pending.
    fn on_connect_timer(&mut self, id: u64) {
        if !matches!(self.slots.get(&id), Some(Slot::Connecting { .. })) {
            return;
        }
        let Some(Slot::Connecting {
            stream, on_error, ..
        }) = self.slots.remove(&id)
        else {
            return;
        };
        // Cancel the pending POLLOUT so the ring drops its reference and the socket closes.
        let e = Sqe::async_cancel(ud(id, OP_POLL)).user_data(ud(id, OP_OTHER));
        self.push(e);
        drop(stream);
        if let Some(f) = on_error {
            f(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
        }
    }

    /// A write-timeout check is due: close the connection if output is still queued and nothing
    /// was written since the last check, else check again later.
    fn on_write_timer(&mut self, id: u64, now: u64) {
        let wt = self.cfg.telemetry.live().write_timeout();
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        lc.write_timer = None;
        // Turned off at run time (`Live::set_write_timeout`): no more checks until it is set
        // again and a write arms one.
        let Some(wt) = wt else {
            return;
        };
        let (sent, pending, ..) = lc.inner.debug_state();
        if pending == 0 {
            return; // drained: the next blocked write arms a new check
        }
        if sent != lc.write_mark {
            lc.write_mark = sent;
            let at = now + (wt.as_millis() as u64).max(1);
            lc.write_timer = Some(self.wheel.schedule(at, id | WRITE_TIMER));
            return;
        }
        self.shared.stats.write_timeouts.add_local(1);
        let e = io::Error::new(io::ErrorKind::TimedOut, "write timeout");
        self.finalize(id, Some(Error::Io(e)));
    }

    fn fire_timers(&mut self) {
        let idle = self.cfg.telemetry.live().idle_ms();
        if self.wheel.is_empty() {
            return;
        }
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        for id in due {
            if id & CONNECT_TIMER != 0 {
                self.on_connect_timer(id & !CONNECT_TIMER);
                continue;
            }
            if id & HANDSHAKE_TIMER != 0 {
                self.on_handshake_timer(id & !HANDSHAKE_TIMER);
                continue;
            }
            if id & WRITE_TIMER != 0 {
                self.on_write_timer(id & !WRITE_TIMER, now);
                continue;
            }
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                continue;
            };
            lc.idle_timer = None;
            match lc.idle.check(idle, &mut lc.last_active, now, &lc.inner) {
                // Disabled at runtime (or for this connection): the timer is just dropped.
                IdleCheck::Off => {}
                IdleCheck::Expired => {
                    self.shared.stats.idle_timeouts.add_local(1);
                    let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                    self.finalize(id, Some(Error::Io(e)));
                }
                IdleCheck::At(at) => lc.idle_timer = Some(self.wheel.schedule(at, id)),
            }
        }
    }

    /// Connection `id` set an idle timeout of its own (ADR-155): re-arms its timer from its
    /// last activity.
    fn retime(&mut self, id: u64) {
        let engine = self.cfg.telemetry.live().idle_ms();
        let now = self.tick();
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        lc.idle = IdleRule::of(&lc.inner);
        if let Some(t) = lc.idle_timer.take() {
            self.wheel.cancel(t);
        }
        if let Some(at) = lc.idle.first_check(engine, lc.last_active, now) {
            if self.wheel.is_empty() {
                self.wheel.advance(now, drop);
            }
            lc.idle_timer = Some(self.wheel.schedule(at, id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel SQ polling threads of this process (`iou-sqp-*`): task id and allowed CPUs.
    fn sqp_threads() -> Vec<(String, Vec<usize>)> {
        let mut out = Vec::new();
        for t in std::fs::read_dir("/proc/self/task")
            .into_iter()
            .flatten()
            .flatten()
        {
            let comm = std::fs::read_to_string(t.path().join("comm")).unwrap_or_default();
            if !comm.starts_with("iou-sqp-") {
                continue;
            }
            let status = std::fs::read_to_string(t.path().join("status")).unwrap_or_default();
            let list = status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .unwrap_or("")
                .trim()
                .to_owned();
            let cpus = akio_sys::numa::parse_cpulist(&list).unwrap_or_default();
            out.push((t.file_name().to_string_lossy().into_owned(), cpus));
        }
        out
    }

    /// Placed rings (ADR-088, update): with SQPOLL and an SQ CPU, the kernel's polling thread
    /// runs on that CPU only; a CPU the kernel refuses falls back to an unpinned polling thread;
    /// without SQPOLL the setup is unchanged (single issuer, created disabled where supported).
    /// Skipped where io_uring or SQPOLL is unavailable.
    #[test]
    fn placed_ring_pins_the_sqpoll_thread() {
        let Some(&cpu) = akio_sys::process::allowed_cpus().unwrap_or_default().last() else {
            return;
        };
        let place = RingPlace {
            cpus: vec![cpu],
            sq_cpu: Some(cpu),
        };
        let before: Vec<String> = sqp_threads().into_iter().map(|(t, _)| t).collect();
        let r = match make_ring_at(8, true, &place) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipped: no SQPOLL ring here ({e})");
                return;
            }
        };
        assert_eq!(r.sq_cpu, Some(cpu));
        assert!(!r.needs_enable);
        let new: Vec<_> = sqp_threads()
            .into_iter()
            .filter(|(t, _)| !before.contains(t))
            .collect();
        assert_eq!(new.len(), 1, "{new:?}");
        assert_eq!(new[0].1, vec![cpu]);
        drop(r);

        // A CPU that does not exist: created without SQ_AFF.
        let off = RingPlace {
            cpus: vec![cpu],
            sq_cpu: Some(1 << 20),
        };
        let r = make_ring_at(8, true, &off).expect("SQPOLL ring without SQ_AFF");
        assert_eq!(r.sq_cpu, None);
        // Not placed: as before.
        let r = make_ring_at(8, true, &RingPlace::default()).expect("SQPOLL ring");
        assert_eq!(r.sq_cpu, None);
        // Without SQPOLL the SQ CPU is ignored and the setup is the unplaced one.
        let unplaced = make_ring_at(8, false, &RingPlace::default()).expect("ring");
        let placed = make_ring_at(8, false, &place).expect("placed ring");
        assert_eq!(placed.sq_cpu, None);
        assert_eq!(placed.needs_enable, unplaced.needs_enable);
    }

    /// Pure memory operations (no syscalls), so this also runs under Miri: the mirrored entry
    /// layout matches `struct io_uring_buf`, `give` wraps and `publish` lands on entry 0's `resv`.
    #[test]
    fn buf_ring_layout_give_and_publish() {
        let size = 512;
        let area = KernelBuf::new(size * BUF_COUNT as usize).unwrap();
        let mut ring = BufRing::new().unwrap();
        for bid in 0..BUF_COUNT {
            ring.give(&area, size, bid);
        }
        ring.publish();
        // Wraps: the slot of buffer 0 is reused once the kernel has handed a buffer back.
        ring.give(&area, size, 3);
        ring.publish();
        let base = ring.base;
        // SAFETY: `base` points to `BUF_COUNT` initialised entries owned by `ring`; the tail is
        // entry 0's `resv`, at byte 14 as in `struct io_uring_buf_ring`.
        let (e0, e5, tail) = unsafe {
            (
                &*base,
                &*base.add(5),
                base.cast::<u8>().add(14).cast::<u16>().read(),
            )
        };
        assert_eq!(e0.addr, area.as_ptr() as u64 + 3 * size as u64);
        assert_eq!((e0.len, e0.bid), (size as u32, 3));
        assert_eq!(e5.addr, area.as_ptr() as u64 + 5 * size as u64);
        assert_eq!(e5.bid, 5);
        assert_eq!(tail, BUF_COUNT.wrapping_add(1));
    }

    #[test]
    fn kernel_buf_slices_are_bounds_checked() {
        let b = KernelBuf::new(64).unwrap();
        // SAFETY: no kernel operation refers to `b`.
        assert_eq!(unsafe { b.slice(60, 4) }, &[0; 4]);
        let r = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: as above (and the range is rejected before any access).
            let _ = unsafe { b.slice(60, 5) };
        }));
        assert!(r.is_err());
    }

    #[test]
    #[should_panic(expected = "buffer id out of range")]
    fn buf_ring_rejects_foreign_buffer_ids() {
        let area = KernelBuf::new(512 * 4).unwrap();
        let mut ring = BufRing::new().unwrap();
        ring.give(&area, 512, 4);
    }
}
