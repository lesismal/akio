use std::{
    cell::Cell,
    io,
    net::{TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use only_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, LoopLink, LoopMeta, LoopStats,
    Pool, Task,
    telemetry::{LoopCmd, log_or_stderr},
};
use only_sys::EventFd;
use only_sys::ffi;
use only_timer::{TimerId, Wheel};

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

const BGID: u16 = 0;
/// Provided buffers per loop; a power of two (the buffer ring is indexed with a mask).
const BUF_COUNT: u16 = 1024;
const MAX_BUF: usize = 16 << 10;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(16);
static NEXT_LOOP_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static CURRENT_LOOP: Cell<usize> = const { Cell::new(0) };
}

/// Marks a wheel entry as a write-timeout check (connection ids never reach bit 63).
const WRITE_TIMER: u64 = 1 << 63;

fn ud(id: u64, op: u64) -> u64 {
    (id << 4) | op
}

/// Creates a ring with the cheapest setup the kernel accepts: cooperative task-run, a single
/// issuer and deferred task-run (6.1+); anything less if that is refused. The returned flag says
/// the ring starts disabled and must be enabled by the thread that will drive it (single-issuer
/// rings belong to the thread that enables them, and rings are built on another thread).
pub(crate) fn make_ring(entries: u32, sqpoll: bool) -> io::Result<(Ring, bool)> {
    let cq = entries.saturating_mul(4);
    if sqpoll {
        let r = Ring::new(entries, ring::SETUP_CQSIZE | ring::SETUP_SQPOLL, cq, 1000)?;
        return Ok((r, false));
    }
    let fast = ring::SETUP_CQSIZE
        | ring::SETUP_COOP_TASKRUN
        | ring::SETUP_SINGLE_ISSUER
        | ring::SETUP_DEFER_TASKRUN
        | ring::SETUP_R_DISABLED;
    if let Ok(r) = Ring::new(entries, fast, cq, 0) {
        return Ok((r, true));
    }
    if let Ok(r) = Ring::new(
        entries,
        ring::SETUP_CQSIZE | ring::SETUP_COOP_TASKRUN,
        cq,
        0,
    ) {
        return Ok((r, false));
    }
    Ok((Ring::new(entries, ring::SETUP_CQSIZE, cq, 0)?, false))
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

    /// Registers the ring with the kernel as buffer group `BGID`.
    pub(crate) fn register(&self, ring: &Ring) -> io::Result<()> {
        // SAFETY: `base` points to `BUF_COUNT` zeroed, page-aligned entries that stay allocated
        // until `self` is dropped, which happens after the io_uring instance that holds the
        // registration (see field order in `Loop`).
        unsafe { ring.register_buf_ring(self.base as u64, BUF_COUNT, BGID) }
    }

    /// Makes buffer `bid` (a `size`-byte slot at `area + bid * size`) available to the kernel.
    ///
    /// Each `bid` must be given at most once until the kernel hands it back in a completion, so
    /// at most `BUF_COUNT` entries are ever outstanding and the slot at `tail` is never one the
    /// kernel is reading.
    fn give(&mut self, area: &KernelBuf, size: usize, bid: u16) {
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
    fn publish(&self) {
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

pub(crate) enum Cmd {
    Wake(u64),
    Close(u64, Option<io::Error>),
    Task(u64, Task),
    Shutdown,
    /// From the engine's telemetry hub (connection table, live-settings reload).
    Core(LoopCmd),
    Dial {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
}

/// The part of a loop other threads can reach: its command queue and eventfd.
pub(crate) struct LoopShared {
    uid: usize,
    waker: EventFd,
    cmds: Mutex<Vec<Cmd>>,
    wake_pending: AtomicBool,
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
        let sh = Arc::new(LoopShared {
            uid: NEXT_LOOP_UID.fetch_add(1, Ordering::Relaxed),
            waker: EventFd::new()?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
            pool,
            stats: Arc::new(LoopStats::new(meta)),
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
        // The loop drains its queue after every batch of completions, so a post from the loop's
        // own thread needs no wake-up.
        if CURRENT_LOOP.with(Cell::get) != self.uid
            && !self.wake_pending.swap(true, Ordering::AcqRel)
        {
            self.waker.wake();
        }
    }

    fn take(&self) -> Vec<Cmd> {
        self.wake_pending.store(false, Ordering::Release);
        std::mem::take(&mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()))
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
}

struct LoopConn {
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    acceptor: Arc<dyn DynAcceptor>,
    /// A multishot recv is in flight (until a completion without `F_MORE` arrives).
    recv_armed: bool,
    /// A cancel for the recv was submitted.
    cancel_sent: bool,
    /// A `poll(POLLOUT)` is in flight.
    poll_armed: bool,
    /// Reads paused by backpressure.
    bp: bool,
    /// Peer sent EOF; we are only draining output.
    eof: bool,
    last_active: u64,
    idle_timer: Option<TimerId>,
    /// Pending write-timeout check (`Config::write_timeout`), and the bytes written when it
    /// was armed.
    write_timer: Option<TimerId>,
    write_mark: u64,
    /// Tick when it opened, and bytes read (connection table).
    opened: u64,
    bytes_in: u64,
    /// Accepted while draining: `on_shutdown` runs after its first data, so the request that
    /// is already on its way is served (see `on_accept`).
    shutdown_after_data: bool,
}

enum Slot {
    Conn(LoopConn),
    Connecting {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
    },
}

pub(crate) struct Loop {
    ring: Ring,
    /// Declared after `ring` so the kernel's registration is gone before the memory is freed.
    buf_ring: BufRing,
    needs_enable: bool,
    shared: Arc<LoopShared>,
    listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
    accept_armed: bool,
    /// After a failed accept (EMFILE...) do not re-arm before this instant.
    accept_retry_at: Option<Instant>,
    /// While draining: the listener's acceptor, for connections the multishot accept completed
    /// before its cancellation took effect.
    drain_acceptor: Option<Arc<dyn DynAcceptor>>,
    /// Target of the eventfd `Read` (never read by Rust).
    wake_buf: KernelBuf,
    wake_armed: bool,
    /// Provided buffers: `BUF_COUNT` slots of `buf_size` bytes. Never reallocated.
    bufs: KernelBuf,
    buf_size: usize,
    slots: only_core::IdMap<Slot>,
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
}

// SAFETY: a `Loop` is built on one thread and then moved to, and used only by, its I/O thread.
// The raw pointers inside submitted entries point into `bufs`/`wake_buf`/`buf_ring`, heap
// allocations that move with it without changing address and are freed only after `ring`.
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

impl Loop {
    pub(crate) fn new(
        shared: Arc<LoopShared>,
        listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
        cfg: Arc<Config>,
        opts: &UringOptions,
    ) -> io::Result<Loop> {
        let entries = if opts.entries == 0 {
            1024
        } else {
            opts.entries
        };
        let (ring, needs_enable) = make_ring(entries, opts.sqpoll)?;
        if let Some((l, _)) = &listener {
            l.set_nonblocking(true)?;
        }
        let buf_size = cfg.read_buffer.clamp(512, MAX_BUF);
        Ok(Loop {
            ring,
            buf_ring: BufRing::new()?,
            needs_enable,
            shared,
            listener,
            accept_armed: false,
            accept_retry_at: None,
            drain_acceptor: None,
            wake_buf: KernelBuf::new(8)?,
            wake_armed: false,
            bufs: KernelBuf::new(buf_size * BUF_COUNT as usize)?,
            buf_size,
            slots: Default::default(),
            cfg,
            draining: None,
            graveyard: Vec::new(),
            wheel: Wheel::new(0),
            epoch: Instant::now(),
            clock: Instant::now(),
            cqes: Vec::with_capacity(1024),
            inflight: 0,
        })
    }

    /// Runs on the I/O thread before the first submission: takes ownership of the ring (when it
    /// was created disabled) and hands the buffer ring to the kernel.
    fn init(&mut self) -> io::Result<()> {
        if self.needs_enable {
            self.ring.enable_rings()?;
        }
        self.buf_ring.register(&self.ring)?;
        for bid in 0..BUF_COUNT {
            self.buf_ring.give(&self.bufs, self.buf_size, bid);
        }
        self.buf_ring.publish();
        Ok(())
    }

    /// Queues an entry, submitting first if the submission queue is full.
    fn push(&mut self, e: Sqe) {
        loop {
            // SAFETY: every entry pushed refers to memory that outlives its completion: the
            // provided-buffer area and the wake buffer are owned by `self` and never moved or
            // freed while the ring lives; the other entries carry only integers (fds, ids).
            if unsafe { self.ring.push(&e) }.is_ok() {
                self.inflight += 1;
                return;
            }
            let _ = self.ring.submit();
        }
    }

    /// Returns a receive buffer to the kernel (no syscall; published with `publish`).
    fn give_back(&mut self, bid: u16) {
        self.buf_ring.give(&self.bufs, self.buf_size, bid);
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn run(&mut self) {
        self.run_inner();
        self.drain_inflight();
        self.shared.stats.set_running(false);
        // Pending telemetry requests are dropped, which answers them (as "nothing").
        drop(self.shared.take());
    }

    fn run_inner(&mut self) {
        CURRENT_LOOP.with(|c| c.set(self.shared.uid));
        if let Err(e) = self.init() {
            log_or_stderr(log::Level::Error, format_args!("io_uring init failed: {e}"));
            return;
        }
        loop {
            self.arm_loop_ops();
            if !self.graveyard.is_empty() {
                // Submit before blocking: the kernel then holds its own references to the
                // sockets of finalized connections, whose descriptors may be closed.
                let _ = self.ring.submit();
                if self.ring.sq_is_empty() {
                    self.graveyard.clear();
                }
            }
            let mut timeout = self.draining.map(|_| Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            if let Some(t) = self.accept_retry_at {
                let left = t.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
                timeout = Some(timeout.map_or(left, |x| x.min(left)));
            }
            let res = match timeout {
                Some(t) => self.ring.submit_with_timeout(1, t),
                None => self.ring.submit_and_wait(1),
            };
            match res {
                Ok(_) => {}
                Err(e)
                    if matches!(e.raw_os_error(), Some(ffi::ETIME | ffi::EINTR | ffi::EBUSY)) => {}
                Err(e) => {
                    log_or_stderr(log::Level::Error, format_args!("io_uring_enter: {e}"));
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
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                // Done once every connection closed and the cancelled multishot accept has
                // ended: until then it may still deliver connections, which are served.
                if self.slots.is_empty() && !self.accept_armed {
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
                log::Level::Warn,
                format_args!(
                    "io_uring: {} operation(s) still in flight at exit; leaking their buffers",
                    self.inflight
                ),
            );
            self.bufs.leaked = true;
            self.wake_buf.leaked = true;
            self.buf_ring.leaked = true;
        }
    }

    /// Before the thread exits: let the cancelled multishot accept finish, so the listening
    /// socket is really closed when `Group::join` returns (the kernel keeps it alive while the
    /// accept is in flight).
    fn quiesce(&mut self) {
        // The drain is over: what the accept still delivers now is closed.
        self.drain_acceptor = None;
        for _ in 0..200 {
            if !self.accept_armed {
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
        if !self.accept_armed && self.draining.is_none() && backoff_over {
            if let Some((l, _)) = &self.listener {
                let e = Sqe::accept_multi(l.as_raw_fd()).user_data(ud(0, OP_ACCEPT));
                self.push(e);
                self.accept_armed = true;
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
            OP_ACCEPT => self.on_accept(res, flags),
            OP_RECV => self.on_recv(id, res, flags),
            OP_POLL => self.on_poll(id),
            OP_RESET => self.on_reset_watch(id),
            _ => {} // buffer provisioning, cancels
        }
    }

    fn on_accept(&mut self, res: i32, flags: u32) {
        if !cqe_more(flags) {
            self.accept_armed = false;
        }
        if res < 0 {
            if res != -ffi::ECANCELED && res != -ffi::EINTR {
                // e.g. EMFILE: retry in a moment instead of spinning.
                self.shared.stats.accept_errors.add_local(1);
                let e = io::Error::from_raw_os_error(-res);
                log_or_stderr(log::Level::Warn, format_args!("accept: {e}"));
                self.accept_retry_at = Some(Instant::now() + Duration::from_millis(100));
            }
            return;
        }
        // SAFETY: the kernel just handed us this fresh descriptor; nothing else owns it.
        let stream = unsafe { TcpStream::from_raw_fd(res) };
        let Ok(peer) = stream.peer_addr() else {
            return;
        };
        if self.draining.is_some() {
            // Accepted before the cancellation of the multishot accept took effect: the peer
            // already counts as connected (on a listening socket shared with other processes it
            // could have been served there). Resetting it would lose its first request, so serve
            // that, then shut the connection down like those open when the drain began; one
            // that sends nothing is closed at the drain deadline.
            let Some(acceptor) = self.drain_acceptor.clone() else {
                return; // dropped: closes it
            };
            if let Some(id) = self.open(stream, peer, acceptor, false) {
                if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                    lc.shutdown_after_data = true;
                }
            }
            return;
        }
        let Some((_, acceptor)) = &self.listener else {
            return;
        };
        let acceptor = acceptor.clone();
        self.open(stream, peer, acceptor, false);
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

    fn on_recv(&mut self, id: u64, res: i32, flags: u32) {
        let bid = cqe_buffer(flags);
        let more = cqe_more(flags);
        let now = self.clock.saturating_duration_since(self.epoch).as_millis() as u64;
        let timed = self.cfg.telemetry.timing_enabled();
        let mut done = Done::No;
        if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
            if !more {
                lc.recv_armed = false;
                lc.cancel_sent = false;
            }
            if res > 0 {
                let n = res as usize;
                if let Some(bid) = bid {
                    if !lc.eof && lc.inner.is_open() {
                        let off = bid as usize * self.buf_size;
                        lc.last_active = now;
                        lc.bytes_in += n as u64;
                        let st = &self.shared.stats;
                        st.reads.add_local(1);
                        st.bytes_in.add_local(n as u64);
                        lc.inner.set_corked(true);
                        // SAFETY: the kernel handed buffer `bid` over in this completion; it is
                        // not in the ring again until `give_back` below, so nothing writes it
                        // while `data` lives. `slice` bounds-checks the range.
                        let data = unsafe { self.bufs.slice(off, n.min(self.buf_size)) };
                        let r = catch_unwind(AssertUnwindSafe(|| lc.handler.on_data(data)));
                        if timed {
                            self.clock = self
                                .cfg
                                .telemetry
                                .callback_done_at(st, "on_data", id, self.clock);
                        } else {
                            st.callbacks.add_local(1);
                        }
                        if r.is_err() {
                            done = Done::Panic;
                        } else if let Err(e) = lc.inner.uncork_flush() {
                            done = Done::Err(e);
                        }
                    }
                }
            } else if res == 0 {
                if !lc.eof {
                    lc.eof = true;
                    // Peer is done sending: finish writing what we owe, then close.
                    lc.inner.close_after_responses();
                    done = Done::Eof;
                }
            } else if res != -ffi::ENOBUFS && res != -ffi::ECANCELED && res != -ffi::EINTR {
                done = Done::Err(io::Error::from_raw_os_error(-res));
            }
            // ENOBUFS/ECANCELED/EINTR end the multishot; `refresh` re-arms it if still wanted.
        }
        if let Some(bid) = bid {
            self.give_back(bid);
            self.buf_ring.publish();
        }
        if matches!(done, Done::No) && res > 0 {
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
    ) -> Option<u64> {
        if stream.set_nonblocking(true).is_err() {
            return None;
        }
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return None;
        };
        let tel = self.cfg.telemetry.clone();
        if !tel.conn_opened(!dialed) {
            self.shared.stats.rejected.add_local(1);
            log::debug!(target: "only", peer:% = peer; "connection refused: max_connections reached");
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
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) else {
            inner.mark_closed();
            tel.conn_closed();
            return None;
        };
        let st = &self.shared.stats;
        if dialed { &st.dialed } else { &st.accepted }.add_local(1);
        log::trace!(target: "only", conn_id = id, peer:% = peer, local:% = local, dialed = dialed; "connection opened");
        let now = self.tick();
        let idle = self.cfg.telemetry.live().idle_ms();
        let idle_timer = self.arm_idle(id, now + idle);
        self.slots.insert(
            id,
            Slot::Conn(LoopConn {
                inner,
                handler,
                acceptor,
                recv_armed: false,
                cancel_sent: false,
                poll_armed: false,
                bp: false,
                eof: false,
                last_active: now,
                idle_timer,
                write_timer: None,
                write_mark: 0,
                opened: now,
                bytes_in: 0,
                shutdown_after_data: false,
            }),
        );
        self.arm_reset_watch(id, fd);
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
            },
        );
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Slot::Connecting {
            stream,
            acceptor,
            on_error,
        }) = self.slots.remove(&id)
        else {
            return;
        };
        let result = match stream.take_error() {
            Ok(None) => stream.peer_addr(),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok(peer) => {
                self.open(stream, peer, acceptor, true);
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
        match lc.inner.flush_queue() {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && lc.inner.close_after_send_requested() {
                    self.finalize(id, None);
                } else {
                    self.refresh(id);
                }
            }
        }
    }

    /// Arms or cancels the connection's recv / writability poll to match its state.
    fn refresh(&mut self, id: u64) {
        let high = self.cfg.telemetry.live().write_high_watermark();
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let q = lc.inner.queued_bytes();
        let arm = q > 0 && lc.write_timer.is_none() && self.cfg.write_timeout.is_some();
        if q >= high {
            if !lc.bp {
                self.shared.stats.backpressure.add_local(1);
            }
            lc.bp = true;
        } else if q <= high / 4 {
            lc.bp = false;
        }
        let want_read = !lc.inner.read_held() && !lc.bp && !lc.eof && lc.inner.is_open();
        let fd = lc.inner.stream().as_raw_fd();
        let mut entries: Vec<Sqe> = Vec::new();
        if want_read && !lc.recv_armed {
            lc.recv_armed = true;
            entries.push(Sqe::recv_multi(fd, BGID).user_data(ud(id, OP_RECV)));
        } else if !want_read && lc.recv_armed && !lc.cancel_sent {
            lc.cancel_sent = true;
            entries.push(Sqe::async_cancel(ud(id, OP_RECV)).user_data(ud(id, OP_OTHER)));
        }
        if q > 0 && !lc.poll_armed {
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
        lc.inner.mark_closed();
        self.graveyard.push(lc.inner.clone());
        let _ = lc.inner.stream().shutdown(std::net::Shutdown::Both);
        let t0 = self.timing();
        if log::log_enabled!(target: "only", log::Level::Trace) {
            log::trace!(target: "only", conn_id = id, peer:% = lc.inner.peer_addr(), error:? = err; "connection closed");
        }
        let _ = catch_unwind(AssertUnwindSafe(|| lc.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
        self.shared.stats.closed.add_local(1);
        self.cfg.telemetry.conn_closed();
    }

    // ---- commands -------------------------------------------------------------------------

    fn drain_cmds(&mut self) {
        loop {
            let cmds = self.shared.take();
            if cmds.is_empty() {
                return;
            }
            for cmd in cmds {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Task(id, task) => self.on_task(id, task),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Core(c) => self.on_core(c),
                    Cmd::Dial {
                        stream,
                        acceptor,
                        on_error,
                    } => self.begin_dial(stream, acceptor, on_error),
                }
            }
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
        ci.age = Duration::from_millis(now.saturating_sub(lc.opened));
        ci.idle = Duration::from_millis(now.saturating_sub(lc.last_active));
        ci.bytes_in = lc.bytes_in;
        ci.backpressure = lc.bp;
        ci
    }

    /// Live settings changed: re-arm idle timers for the new timeout and re-evaluate
    /// backpressure against the new watermark.
    fn on_reload(&mut self) {
        let idle = self.cfg.telemetry.live().idle_ms();
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        if self.wheel.is_empty() && idle != 0 {
            self.wheel.advance(self.tick(), drop);
        }
        for &id in &ids {
            if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                if let Some(t) = lc.idle_timer.take() {
                    self.wheel.cancel(t);
                }
                if idle != 0 {
                    lc.idle_timer = Some(self.wheel.schedule(lc.last_active + idle, id));
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
        let listener = self.listener.take();
        if self.accept_armed {
            self.drain_acceptor = listener.as_ref().map(|(_, a)| a.clone());
        }
        if listener.is_some() && self.accept_armed {
            // The multishot accept keeps the listening socket alive until it is cancelled.
            let e = Sqe::async_cancel(ud(0, OP_ACCEPT)).user_data(ud(0, OP_OTHER));
            self.push(e);
        }
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        for id in ids {
            match self.slots.get_mut(&id) {
                Some(Slot::Conn(lc)) => {
                    let (acc, inner) = (lc.acceptor.clone(), lc.inner.clone());
                    if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                        self.finalize(id, Some(panic_error()));
                    }
                }
                Some(Slot::Connecting { .. }) => {
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
                None => {}
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
            } else if let Err(e) = lc.inner.uncork_flush() {
                failed = Some(Error::Io(e));
            }
        }
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
        let Some(wt) = self.cfg.write_timeout else {
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

    /// A write-timeout check is due: close the connection if output is still queued and nothing
    /// was written since the last check, else check again later.
    fn on_write_timer(&mut self, id: u64, now: u64) {
        let Some(wt) = self.cfg.write_timeout else {
            return;
        };
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        lc.write_timer = None;
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
            if id & WRITE_TIMER != 0 {
                self.on_write_timer(id & !WRITE_TIMER, now);
                continue;
            }
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                continue;
            };
            lc.idle_timer = None;
            if idle == 0 {
                continue; // disabled at runtime: the timer is just dropped
            }
            let expires = lc.last_active + idle;
            if expires <= now {
                self.shared.stats.idle_timeouts.add_local(1);
                let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                self.finalize(id, Some(Error::Io(e)));
            } else {
                lc.idle_timer = Some(self.wheel.schedule(expires, id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
