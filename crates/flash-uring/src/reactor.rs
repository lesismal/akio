use std::{
    cell::Cell,
    collections::HashMap,
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

use flash_core::{
    Config, ConnInner, DynAcceptor, DynHandler, Error, LoopLink, Pool, SlowCallback, Task,
};
use flash_sys::EventFd;
use flash_timer::{TimerId, Wheel};
use io_uring::{IoUring, cqueue, opcode, squeue, types};

use crate::UringOptions;

// Operation kinds, packed into the low bits of `user_data` next to the connection id.
const OP_ACCEPT: u64 = 1;
const OP_RECV: u64 = 2;
const OP_POLL: u64 = 3;
const OP_WAKE: u64 = 4;
const OP_OTHER: u64 = 5;

const BGID: u16 = 0;
const BUF_COUNT: u16 = 1024;
const MAX_BUF: usize = 16 << 10;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(16);
static NEXT_LOOP_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static CURRENT_LOOP: Cell<usize> = const { Cell::new(0) };
}

fn ud(id: u64, op: u64) -> u64 {
    (id << 4) | op
}

pub(crate) enum Cmd {
    Wake(u64),
    Close(u64, Option<io::Error>),
    Task(u64, Task),
    Shutdown,
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
}

impl LoopShared {
    pub(crate) fn new(pool: Arc<Pool>) -> io::Result<Arc<LoopShared>> {
        Ok(Arc::new(LoopShared {
            uid: NEXT_LOOP_UID.fetch_add(1, Ordering::Relaxed),
            waker: EventFd::new()?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
            pool,
        }))
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
    ring: IoUring,
    shared: Arc<LoopShared>,
    listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
    accept_armed: bool,
    wake_buf: Box<[u8; 8]>,
    wake_armed: bool,
    /// Provided buffers: `BUF_COUNT` slots of `buf_size` bytes. Never reallocated.
    bufs: Vec<u8>,
    buf_size: usize,
    slots: HashMap<u64, Slot>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    wheel: Wheel<u64>,
    epoch: Instant,
    cqes: Vec<(u64, i32, u32)>,
}

// SAFETY: a `Loop` is built on one thread and then moved to, and used only by, its I/O thread.
// The raw pointers inside submitted entries point into `bufs`/`wake_buf`, which move with it
// (heap allocations that do not change address).
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
        let mut b = IoUring::builder();
        b.setup_cqsize(entries.saturating_mul(4));
        if opts.sqpoll {
            b.setup_sqpoll(1000);
        }
        let ring = b.build(entries)?;
        if let Some((l, _)) = &listener {
            l.set_nonblocking(true)?;
        }
        let buf_size = cfg.read_buffer.clamp(512, MAX_BUF);
        let mut lp = Loop {
            ring,
            shared,
            listener,
            accept_armed: false,
            wake_buf: Box::new([0; 8]),
            wake_armed: false,
            bufs: vec![0; buf_size * BUF_COUNT as usize],
            buf_size,
            slots: HashMap::new(),
            cfg,
            draining: None,
            wheel: Wheel::new(0),
            epoch: Instant::now(),
            cqes: Vec::with_capacity(1024),
        };
        // Hand the whole buffer area to the kernel in one request.
        let e =
            opcode::ProvideBuffers::new(lp.bufs.as_mut_ptr(), buf_size as i32, BUF_COUNT, BGID, 0)
                .build()
                .user_data(ud(0, OP_OTHER));
        lp.push(e);
        Ok(lp)
    }

    /// Queues an entry, submitting first if the submission queue is full.
    fn push(&mut self, e: squeue::Entry) {
        loop {
            // SAFETY: every entry pushed refers to memory that outlives its completion: the
            // provided-buffer area and the wake buffer are owned by `self` and never moved or
            // freed while the ring lives; the other entries carry only integers (fds, ids).
            if unsafe { self.ring.submission().push(&e) }.is_ok() {
                return;
            }
            let _ = self.ring.submit();
        }
    }

    fn provide(&mut self, bid: u16) {
        // SAFETY (pointer arithmetic): `bid < BUF_COUNT`, so the slot lies inside `bufs`.
        let ptr = self.bufs[bid as usize * self.buf_size..].as_mut_ptr();
        let e = opcode::ProvideBuffers::new(ptr, self.buf_size as i32, 1, BGID, bid)
            .build()
            .user_data(ud(0, OP_OTHER));
        self.push(e);
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn run(&mut self) {
        CURRENT_LOOP.with(|c| c.set(self.shared.uid));
        loop {
            self.arm_loop_ops();
            let mut timeout = self.draining.map(|_| Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            let res = match timeout {
                Some(t) => {
                    let ts = types::Timespec::new()
                        .sec(t.as_secs())
                        .nsec(t.subsec_nanos());
                    self.ring
                        .submitter()
                        .submit_with_args(1, &types::SubmitArgs::new().timespec(&ts))
                }
                None => self.ring.submit_and_wait(1),
            };
            match res {
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ETIME | libc::EINTR | libc::EBUSY)
                    ) => {}
                Err(e) => {
                    eprintln!("flash: io_uring_enter: {e}");
                    break;
                }
            }
            let mut cqes = std::mem::take(&mut self.cqes);
            cqes.clear();
            cqes.extend(
                self.ring
                    .completion()
                    .map(|c| (c.user_data(), c.result(), c.flags())),
            );
            for &(data, res, flags) in &cqes {
                self.on_cqe(data, res, flags);
            }
            self.cqes = cqes;
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                if self.slots.is_empty() {
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

    /// Before the thread exits: let the cancelled multishot accept finish, so the listening
    /// socket is really closed when `Group::join` returns (the kernel keeps it alive while the
    /// accept is in flight).
    fn quiesce(&mut self) {
        for _ in 0..200 {
            if !self.accept_armed {
                break;
            }
            let ts = types::Timespec::new().nsec(10_000_000);
            let _ = self
                .ring
                .submitter()
                .submit_with_args(1, &types::SubmitArgs::new().timespec(&ts));
            let cqes: Vec<_> = self
                .ring
                .completion()
                .map(|c| (c.user_data(), c.result(), c.flags()))
                .collect();
            for (data, res, flags) in cqes {
                self.on_cqe(data, res, flags);
            }
        }
    }

    /// (Re-)arms the operations that belong to the loop itself: the wake-up read and accept.
    fn arm_loop_ops(&mut self) {
        if !self.wake_armed {
            let fd = self.shared.waker.as_raw_fd();
            let buf = self.wake_buf.as_mut_ptr();
            let e = opcode::Read::new(types::Fd(fd), buf, 8)
                .build()
                .user_data(ud(0, OP_WAKE));
            self.push(e);
            self.wake_armed = true;
        }
        if !self.accept_armed && self.draining.is_none() {
            if let Some((l, _)) = &self.listener {
                let e = opcode::AcceptMulti::new(types::Fd(l.as_raw_fd()))
                    .build()
                    .user_data(ud(0, OP_ACCEPT));
                self.push(e);
                self.accept_armed = true;
            }
        }
    }

    // ---- completions ----------------------------------------------------------------------

    fn on_cqe(&mut self, data: u64, res: i32, flags: u32) {
        let (id, op) = (data >> 4, data & 0xf);
        match op {
            OP_WAKE => self.wake_armed = false,
            OP_ACCEPT => self.on_accept(res, flags),
            OP_RECV => self.on_recv(id, res, flags),
            OP_POLL => self.on_poll(id),
            _ => {} // buffer provisioning, cancels
        }
    }

    fn on_accept(&mut self, res: i32, flags: u32) {
        if !cqueue::more(flags) {
            self.accept_armed = false;
        }
        if res < 0 {
            if res != -libc::ECANCELED && res != -libc::EINTR {
                // e.g. EMFILE: avoid a hot loop by leaving it disarmed for one iteration.
                eprintln!("flash: accept: {}", io::Error::from_raw_os_error(-res));
            }
            return;
        }
        // SAFETY: the kernel just handed us this fresh descriptor; nothing else owns it.
        let stream = unsafe { TcpStream::from_raw_fd(res) };
        if self.draining.is_some() {
            return; // dropped: closes it
        }
        let Some((_, acceptor)) = &self.listener else {
            return;
        };
        let acceptor = acceptor.clone();
        let Ok(peer) = stream.peer_addr() else {
            return;
        };
        self.open(stream, peer, acceptor);
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
        let bid = cqueue::buffer_select(flags);
        let more = cqueue::more(flags);
        let now = self.tick();
        let slow = self.cfg.slow_callback_threshold.is_some();
        let mut slow_hits: Vec<Duration> = Vec::new();
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
                        lc.inner.set_corked(true);
                        let t0 = slow.then(Instant::now);
                        let data = &self.bufs[off..off + n];
                        let r = catch_unwind(AssertUnwindSafe(|| lc.handler.on_data(data)));
                        if let (Some(t0), Some(limit)) = (t0, self.cfg.slow_callback_threshold) {
                            let elapsed = t0.elapsed();
                            if elapsed >= limit {
                                slow_hits.push(elapsed);
                            }
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
                    lc.inner.close_after_send();
                    done = Done::Eof;
                }
            } else if res != -libc::ENOBUFS && res != -libc::ECANCELED && res != -libc::EINTR {
                done = Done::Err(io::Error::from_raw_os_error(-res));
            }
            // ENOBUFS/ECANCELED/EINTR end the multishot; `refresh` re-arms it if still wanted.
        }
        if let Some(bid) = bid {
            self.provide(bid);
        }
        for elapsed in slow_hits {
            self.report_slow("on_data", id, elapsed);
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
    ) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let inner = ConnInner::new(
            id,
            stream,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let handler = match catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) {
            Ok(h) => h,
            Err(_) => {
                inner.mark_closed();
                return;
            }
        };
        let now = self.tick();
        let idle = self
            .cfg
            .idle_timeout
            .map_or(0, |d| d.as_millis().max(1) as u64);
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
            }),
        );
        // `on_open` may already have queued output or closed the connection.
        self.on_wake(id);
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
        let e = opcode::PollAdd::new(types::Fd(stream.as_raw_fd()), libc::POLLOUT as u32)
            .build()
            .user_data(ud(id, OP_POLL));
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
            Ok(peer) => self.open(stream, peer, acceptor),
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
        let high = self.cfg.write_high_watermark;
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let q = lc.inner.queued_bytes();
        if q >= high {
            lc.bp = true;
        } else if q <= high / 4 {
            lc.bp = false;
        }
        let want_read = !lc.inner.read_held() && !lc.bp && !lc.eof && lc.inner.is_open();
        let fd = lc.inner.stream().as_raw_fd();
        let mut entries: Vec<squeue::Entry> = Vec::new();
        if want_read && !lc.recv_armed {
            lc.recv_armed = true;
            entries.push(
                opcode::RecvMulti::new(types::Fd(fd), BGID)
                    .build()
                    .user_data(ud(id, OP_RECV)),
            );
        } else if !want_read && lc.recv_armed && !lc.cancel_sent {
            lc.cancel_sent = true;
            entries.push(
                opcode::AsyncCancel::new(ud(id, OP_RECV))
                    .build()
                    .user_data(ud(id, OP_OTHER)),
            );
        }
        if q > 0 && !lc.poll_armed {
            lc.poll_armed = true;
            entries.push(
                opcode::PollAdd::new(types::Fd(fd), libc::POLLOUT as u32)
                    .build()
                    .user_data(ud(id, OP_POLL)),
            );
        }
        for e in entries {
            self.push(e);
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
        lc.inner.mark_closed();
        let _ = lc.inner.stream().shutdown(std::net::Shutdown::Both);
        let t0 = self.timing();
        let _ = catch_unwind(AssertUnwindSafe(|| lc.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
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
                    Cmd::Dial {
                        stream,
                        acceptor,
                        on_error,
                    } => self.begin_dial(stream, acceptor, on_error),
                }
            }
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.shutdown_timeout);
        if self.listener.take().is_some() && self.accept_armed {
            // The multishot accept keeps the listening socket alive until it is cancelled.
            let e = opcode::AsyncCancel::new(ud(0, OP_ACCEPT))
                .build()
                .user_data(ud(0, OP_OTHER));
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
        self.cfg.slow_callback_threshold.map(|_| Instant::now())
    }

    fn check_slow(&self, kind: &'static str, id: u64, started: Option<Instant>) {
        let (Some(t0), Some(limit)) = (started, self.cfg.slow_callback_threshold) else {
            return;
        };
        let elapsed = t0.elapsed();
        if elapsed >= limit {
            self.report_slow(kind, id, elapsed);
        }
    }

    fn report_slow(&self, kind: &'static str, id: u64, elapsed: Duration) {
        let limit = self.cfg.slow_callback_threshold.unwrap_or_default();
        let rep = SlowCallback {
            kind,
            conn_id: id,
            elapsed,
        };
        match &self.cfg.slow_hook {
            Some(h) => (h.0)(&rep),
            None => eprintln!(
                "flash: slow callback: {kind} on connection {id} blocked its I/O thread for \
                 {elapsed:?} (limit {limit:?}); move blocking work to Conn::spawn_blocking"
            ),
        }
    }

    fn arm_idle(&mut self, id: u64, at: u64) -> Option<TimerId> {
        self.cfg.idle_timeout?;
        if self.wheel.is_empty() {
            self.wheel.advance(self.tick(), drop);
        }
        Some(self.wheel.schedule(at, id))
    }

    fn fire_timers(&mut self) {
        let Some(idle) = self.cfg.idle_timeout else {
            return;
        };
        let idle = idle.as_millis().max(1) as u64;
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        for id in due {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                continue;
            };
            lc.idle_timer = None;
            let expires = lc.last_active + idle;
            if expires <= now {
                let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                self.finalize(id, Some(Error::Io(e)));
            } else {
                lc.idle_timer = Some(self.wheel.schedule(expires, id));
            }
        }
    }
}
