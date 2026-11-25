//! A connection under rounds scheduling (ADR-104) and the round that serves it.
//!
//! Events reach a connection as bits in `pending` (from its poller, from sends on any thread,
//! from timers). Whoever sets `scheduled` from false to true queues it on the workers; the
//! worker that runs the round takes the bits, serves them, clears `scheduled`, and queues it
//! again if bits arrived meanwhile. So at most one round of a connection runs at a time, and an
//! event is always seen by a round that starts after it.

use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::Instant,
};

use akio_core::{ConnInner, DynAcceptor, DynHandler, Error, LoopLink, LoopStats, Pool, Task};

use super::poller::PollerShared;
use super::workers::{Job, WorkerCtx, Workers};

/// `on_open` has not run yet (set once, when the connection is created).
pub(crate) const OPEN: u32 = 1;
/// The socket became readable (edge).
pub(crate) const READ: u32 = 1 << 1;
/// The socket became writable (edge).
pub(crate) const WRITE: u32 = 1 << 2;
/// Re-evaluate: flush, `close_after_send`, reads released by `hold_reads(false)`.
pub(crate) const WAKE: u32 = 1 << 3;
/// Close (the error, if any, is in `close_err`).
pub(crate) const CLOSE: u32 = 1 << 4;
/// `spawn_blocking` completions are waiting in `tasks`.
pub(crate) const TASK: u32 = 1 << 5;
/// The engine is shutting down: run the acceptor's `on_shutdown`.
pub(crate) const SHUTDOWN: u32 = 1 << 6;
/// The peer hung up (or the socket errored): read to the end, past short reads.
pub(crate) const HUP: u32 = 1 << 7;

/// Reads per round before the connection yields to the back of the queue.
const MAX_READS_PER_ROUND: usize = 16;
/// Rounds back to back on one worker while new events keep arriving, before it yields.
const MAX_PASSES: usize = 4;
/// `EIO`: what a read returns on a kernel TLS socket when a control record is next.
#[cfg(target_os = "linux")]
const EIO: i32 = 5;

/// State only the worker running the round touches (under `RConn::st`, never contended).
struct St {
    handler: Option<Box<dyn DynHandler>>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    /// The socket signalled readable and was not read dry since.
    read_ready: bool,
    /// Reads paused by backpressure.
    bp: bool,
    /// The peer sent EOF.
    eof: bool,
    /// The poller reported a hang-up: no further edge will come, so reads go on until end of
    /// stream (or `WouldBlock`) instead of stopping at a short read.
    hup: bool,
    closed: bool,
    /// Bytes queued as the last flush of a round reported them. Output queued by another thread
    /// since then either went out directly or woke the connection (`WAKE`), so a round without
    /// `WAKE` can trust it and skip the lock.
    q: usize,
}

pub(crate) struct RConn {
    pub(crate) id: u64,
    pub(crate) inner: Arc<ConnInner>,
    /// The listener of the group it was accepted on (ADR-130), or `NO_LISTENER` when dialed.
    pub(crate) lid: usize,
    pending: AtomicU32,
    scheduled: AtomicBool,
    /// When the connection was last queued (tracing, ADR-104 diagnostics).
    pub(crate) queued_ns: AtomicU64,
    st: Mutex<St>,
    tasks: Mutex<Vec<Task>>,
    close_err: Mutex<Option<io::Error>>,
    /// Milliseconds since the poller's epoch of the last inbound data (idle timeout).
    pub(crate) last_active: AtomicU64,
    pub(crate) opened: u64,
    pub(crate) bytes_in: AtomicU64,
    /// A write-timeout check is pending on the poller.
    pub(crate) write_armed: AtomicBool,
    /// `on_shutdown` was requested (it runs once, whoever asks first: the poller's shutdown or
    /// an accept that saw the drain begin).
    shutdown_sent: AtomicBool,
    /// Tests: rounds of this connection queued or running (more than one breaks the invariant).
    #[cfg(test)]
    pub(crate) in_queue: AtomicU32,
    pub(crate) bp_flag: AtomicBool,
    pub(crate) home: Arc<PollerShared>,
    workers: Arc<Workers>,
}

/// The connection's [`LoopLink`]: wake-ups and closes become pending bits.
struct Link {
    conn: Weak<RConn>,
    pool: Arc<Pool>,
    stats: Arc<LoopStats>,
}

impl LoopLink for Link {
    fn wake_conn(&self, _id: u64) {
        if let Some(c) = self.conn.upgrade() {
            c.notify(WAKE);
        }
    }
    fn close_conn(&self, _id: u64, err: Option<io::Error>) {
        if let Some(c) = self.conn.upgrade() {
            c.close_with(err);
        }
    }
    fn post_task(&self, _id: u64, task: Task) {
        if let Some(c) = self.conn.upgrade() {
            c.tasks.lock().unwrap_or_else(|p| p.into_inner()).push(task);
            c.notify(TASK);
        }
    }
    fn pool(&self) -> Option<&Pool> {
        Some(&self.pool)
    }
    fn stats(&self) -> Option<Arc<LoopStats>> {
        Some(self.stats.clone())
    }
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

impl RConn {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: u64,
        stream: std::net::TcpStream,
        local: std::net::SocketAddr,
        peer: std::net::SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        home: Arc<PollerShared>,
        workers: Arc<Workers>,
        now: u64,
        lid: usize,
    ) -> Arc<RConn> {
        Arc::new_cyclic(|me| {
            let link = Arc::new(Link {
                conn: me.clone(),
                pool: home.pool.clone(),
                stats: home.stats.clone(),
            });
            let inner = ConnInner::new(id, stream, local, peer, link, home.cfg.clone());
            // Reads happen only in rounds, between flushes: a transport may move its read
            // direction into the kernel (kernel TLS).
            inner.set_rx_offload_ok(true);
            RConn {
                id,
                inner,
                lid,
                pending: AtomicU32::new(OPEN),
                // Scheduled from birth: events that arrive between the registration and
                // `start` only add bits, and `start` queues the one first round.
                scheduled: AtomicBool::new(true),
                queued_ns: AtomicU64::new(0),
                st: Mutex::new(St {
                    handler: None,
                    acceptor: Some(acceptor),
                    read_ready: false,
                    bp: false,
                    eof: false,
                    hup: false,
                    closed: false,
                    q: 0,
                }),
                tasks: Mutex::new(Vec::new()),
                close_err: Mutex::new(None),
                last_active: AtomicU64::new(now),
                opened: now,
                bytes_in: AtomicU64::new(0),
                write_armed: AtomicBool::new(false),
                shutdown_sent: AtomicBool::new(false),
                #[cfg(test)]
                in_queue: AtomicU32::new(0),
                bp_flag: AtomicBool::new(false),
                home,
                workers,
            }
        })
    }

    /// Adds `bits` to the pending events and queues a round if none is queued or running.
    pub(crate) fn notify(self: &Arc<Self>, bits: u32) {
        self.pending.fetch_or(bits, Ordering::SeqCst);
        if self.scheduled.load(Ordering::SeqCst) {
            // The round running or queued clears `scheduled` before its last look at
            // `pending`, so it sees these bits.
            return;
        }
        if !self.scheduled.swap(true, Ordering::SeqCst) {
            self.workers.submit(Job::Round(self.clone()));
        }
    }

    /// Asks for `on_shutdown`, once per connection.
    pub(crate) fn shutdown_notice(self: &Arc<Self>) {
        if !self.shutdown_sent.swap(true, Ordering::SeqCst) {
            self.notify(SHUTDOWN);
        }
    }

    /// Queues the first round (`on_open`). The connection is born scheduled, so this is its
    /// only queueing until that round ends, whatever events came first.
    pub(crate) fn start(self: &Arc<Self>) {
        debug_assert!(self.scheduled.load(Ordering::SeqCst));
        self.workers.submit(Job::Round(self.clone()));
    }

    /// Closes the connection with `err` in its next round.
    pub(crate) fn close_with(self: &Arc<Self>, err: Option<io::Error>) {
        if let Some(e) = err {
            let mut g = self.close_err.lock().unwrap_or_else(|p| p.into_inner());
            if g.is_none() {
                *g = Some(e);
            }
        }
        self.notify(CLOSE);
    }

    fn tick(&self) -> u64 {
        self.home.tick()
    }

    /// Runs on a worker: serves pending events until none are left (or the connection should
    /// yield), then releases the connection.
    pub(crate) fn run_round(self: Arc<Self>, ctx: &mut WorkerCtx) {
        let q = self.queued_ns.load(Ordering::Relaxed);
        if q != 0 {
            super::trace::queued(super::trace::now_ns().saturating_sub(q));
        }
        let mut yielded = false;
        {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            for _ in 0..MAX_PASSES {
                let bits = self.pending.swap(0, Ordering::SeqCst);
                if bits == 0 {
                    break;
                }
                if self.serve(&mut st, bits, ctx) {
                    // Read budget spent with data left: let the others run first.
                    self.pending.fetch_or(READ, Ordering::SeqCst);
                    yielded = true;
                    break;
                }
            }
        }
        #[cfg(test)]
        self.in_queue.fetch_sub(1, Ordering::SeqCst);
        self.scheduled.store(false, Ordering::SeqCst);
        if (yielded || self.pending.load(Ordering::SeqCst) != 0)
            && !self.scheduled.swap(true, Ordering::SeqCst)
        {
            ctx.workers.submit(Job::Round(self));
        }
    }

    /// Serves `bits`. True when the read budget ran out with the socket still readable.
    fn serve(&self, st: &mut St, bits: u32, ctx: &mut WorkerCtx) -> bool {
        if st.closed {
            return false;
        }
        if bits & CLOSE != 0 {
            let e = self
                .close_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            self.finalize(st, e.map(Error::Io), ctx);
            return false;
        }
        if bits & OPEN != 0 {
            let acc = st.acceptor.clone().expect("acceptor until opened");
            let t0 = self.home.cfg.telemetry.timing();
            match catch_unwind(AssertUnwindSafe(|| acc.on_open(&self.inner))) {
                Ok(h) => st.handler = Some(h),
                Err(_) => {
                    self.finalize(st, None, ctx);
                    return false;
                }
            }
            self.home
                .cfg
                .telemetry
                .callback_done(&ctx.stats, "on_open", self.id, t0);
            if self.inner.handshake_timeout().is_some() {
                self.home.arm_handshake(self.id);
            }
        }
        if bits & SHUTDOWN != 0 {
            if let Some(acc) = &st.acceptor {
                if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&self.inner))).is_err() {
                    self.finalize(st, Some(panic_error()), ctx);
                    return false;
                }
            }
        }
        if bits & TASK != 0 {
            let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
            for task in tasks {
                let Some(h) = st.handler.as_mut() else { break };
                let t0 = self.home.cfg.telemetry.timing();
                self.inner.set_corked(true);
                let r = catch_unwind(AssertUnwindSafe(|| h.run_task(task)));
                self.home.cfg.telemetry.callback_done(
                    &ctx.stats,
                    "spawn_blocking completion",
                    self.id,
                    t0,
                );
                if r.is_err() {
                    self.finalize(st, Some(panic_error()), ctx);
                    return false;
                }
                match self.inner.uncork_flush() {
                    Ok(q) => st.q = q,
                    Err(e) => {
                        self.finalize(st, Some(Error::Io(e)), ctx);
                        return false;
                    }
                }
            }
        }
        // A writable edge alone only matters when this side left output queued.
        if bits & (OPEN | WAKE | TASK) != 0 || (bits & WRITE != 0 && st.q > 0) {
            match self.inner.flush_queue() {
                Err(e) => {
                    self.finalize(st, Some(Error::Io(e)), ctx);
                    return false;
                }
                Ok(true) => {
                    st.q = 0;
                    if self.inner.close_after_send_requested() {
                        self.finalize(st, None, ctx);
                        return false;
                    }
                }
                Ok(false) => st.q = self.inner.queued_bytes(),
            }
        }
        if bits & READ != 0 {
            st.read_ready = true;
        }
        if bits & HUP != 0 {
            st.hup = true;
            st.read_ready = true;
        }
        let mut more = false;
        let q = st.q;
        if st.read_ready && !st.eof && self.update_bp(st, q) {
            more = self.read(st, ctx);
            if st.closed {
                return false;
            }
        }
        self.after(st);
        more
    }

    /// Re-evaluates backpressure from `q` queued bytes. True when reads may go on.
    fn update_bp(&self, st: &mut St, q: usize) -> bool {
        let high = self.home.cfg.telemetry.live().write_high_watermark();
        if q >= high && self.inner.write_backpressure() {
            if !st.bp {
                self.home.stats.backpressure.add(1);
            }
            st.bp = true;
        } else if q <= high / 4 || !self.inner.write_backpressure() {
            st.bp = false;
        }
        self.bp_flag.store(st.bp, Ordering::Relaxed);
        !st.bp && !self.inner.read_held()
    }

    /// End of a round: re-evaluates backpressure and arms the write-timeout check if output is
    /// still queued.
    fn after(&self, st: &mut St) {
        if st.closed {
            return;
        }
        let q = st.q;
        let _ = self.update_bp(st, q);
        // The live value (ADR-108): a write timeout set by a reload applies to open connections.
        if self.home.cfg.telemetry.live().write_ms() == 0 {
            return;
        }
        if st.q > 0 && !self.write_armed.swap(true, Ordering::AcqRel) {
            self.home.arm_write(self.id);
        }
    }

    /// Reads until the socket is drained, the budget is spent (true), or reads must pause.
    fn read(&self, st: &mut St, ctx: &mut WorkerCtx) -> bool {
        enum Done {
            No,
            Eof,
            Err(io::Error),
            Panic,
        }
        let live = self.home.cfg.telemetry.live();
        let rb = live.read_buffer();
        if ctx.scratch.len() != rb {
            ctx.scratch = vec![0; rb];
        }
        let high = live.write_high_watermark();
        let timed = self.home.cfg.telemetry.timing_enabled();
        let mut clock = Instant::now();
        let mut done = Done::No;
        let mut budget = true;
        let Some(h) = st.handler.as_mut() else {
            return false;
        };
        for _ in 0..MAX_READS_PER_ROUND {
            let r = match self.inner.stream().read(&mut ctx.scratch) {
                #[cfg(target_os = "linux")]
                Err(e) if e.raw_os_error() == Some(EIO) && self.inner.kernel_rx() => {
                    match self.inner.kernel_read_record(&mut ctx.scratch) {
                        Ok(akio_core::KernelRead::Data(n)) => Ok(n),
                        Ok(akio_core::KernelRead::Control) => {
                            if let Err(e) = self.inner.uncork_flush() {
                                done = Done::Err(e);
                                budget = false;
                                break;
                            }
                            continue;
                        }
                        Err(e) => Err(e),
                    }
                }
                r => r,
            };
            match r {
                Ok(0) => {
                    done = Done::Eof;
                    budget = false;
                    break;
                }
                Ok(n) => {
                    self.last_active.store(self.tick(), Ordering::Relaxed);
                    self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    let stats = &ctx.stats;
                    stats.reads.add_local(1);
                    stats.bytes_in.add_local(n as u64);
                    self.inner.set_corked(true);
                    let data = &ctx.scratch[..n];
                    let r = catch_unwind(AssertUnwindSafe(|| h.on_data(data)));
                    if timed {
                        clock = self
                            .home
                            .cfg
                            .telemetry
                            .callback_done_at(stats, "on_data", self.id, clock);
                    } else {
                        stats.callbacks.add_local(1);
                    }
                    if r.is_err() {
                        done = Done::Panic;
                        budget = false;
                        break;
                    }
                    let q = match self.inner.uncork_flush() {
                        Ok(q) => {
                            st.q = q;
                            q
                        }
                        Err(e) => {
                            done = Done::Err(e);
                            budget = false;
                            break;
                        }
                    };
                    if n < ctx.scratch.len() && !st.hup {
                        // Short read: the socket is drained; the next edge brings us back.
                        st.read_ready = false;
                        budget = false;
                        break;
                    }
                    if !self.inner.is_open()
                        || self.inner.read_held()
                        || (q >= high && self.inner.write_backpressure())
                    {
                        // Still readable: `read_ready` stays set for when reads may go on.
                        let _ = self.update_bp(st, q);
                        budget = false;
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    st.read_ready = false;
                    budget = false;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    done = Done::Err(e);
                    budget = false;
                    break;
                }
            }
        }
        match done {
            Done::No => budget,
            Done::Eof => {
                st.eof = true;
                st.read_ready = false;
                // Peer is done sending: finish writing what we owe, then close.
                self.inner.close_after_responses();
                match self.inner.flush_queue() {
                    Err(e) => self.finalize(st, Some(Error::Io(e)), ctx),
                    Ok(true) => {
                        st.q = 0;
                        if self.inner.close_after_send_requested() {
                            self.finalize(st, None, ctx);
                        }
                    }
                    Ok(false) => st.q = self.inner.queued_bytes(),
                }
                false
            }
            Done::Err(e) => {
                self.finalize(st, Some(Error::Io(e)), ctx);
                false
            }
            Done::Panic => {
                self.finalize(st, Some(panic_error()), ctx);
                false
            }
        }
    }

    /// Closes the connection and runs `on_close` exactly once.
    fn finalize(&self, st: &mut St, err: Option<Error>, ctx: &WorkerCtx) {
        if st.closed {
            return;
        }
        st.closed = true;
        let fd = self.inner.stream().as_raw_fd();
        self.home.registry.delete(fd);
        self.inner.mark_closed();
        let _ = self.inner.stream().shutdown(std::net::Shutdown::Both);
        if let Some(mut h) = st.handler.take() {
            let t0 = self.home.cfg.telemetry.timing();
            if akio_log::log_enabled!(target: "akio", akio_log::Level::Trace) {
                akio_log::trace!(target: "akio", conn_id = self.id, peer:% = self.inner.peer_addr(), error:? = err; "connection closed");
            }
            let _ = catch_unwind(AssertUnwindSafe(|| h.on_close(err)));
            self.home
                .cfg
                .telemetry
                .callback_done(&ctx.stats, "on_close", self.id, t0);
        }
        st.acceptor = None;
        self.tasks.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.home.stats.closed.add(1);
        self.home.cfg.telemetry.conn_closed();
        // Out of the table, with its timers: no message to the poller. The socket closes with
        // the last reference (the round's own, at the latest).
        self.home.remove(self.id);
    }
}
