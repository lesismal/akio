//! One queue's I/O thread: a readiness poller (epoll / kqueue) with the queue's descriptor and a
//! waker, and the queue's one connection (`ConnInner::new_virtual`, datagram semantics).
//!
//! Reads: on readiness, up to [`READS_PER_EVENT`] packets are read into the thread's buffer and
//! handed to the handler one by one, then what the callbacks queued is written. Writes: `send`
//! from any thread only queues (and wakes this thread when the queue was empty); this thread
//! writes queued packets to the device after callbacks and on wake-ups, one `write` per packet
//! (TUN takes one packet per call), until the queue is empty or the device pushes back
//! (`EAGAIN`: write interest until it drains).

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, LoopLink, LoopMeta, LoopStats,
    Pool, Task, telemetry::LoopCmd,
};
use akio_sys::{Event, Poller, Waker};

/// Connection ids of TUN queues (process-unique, apart from the other backends' ranges).
static NEXT_ID: AtomicU64 = AtomicU64::new(1 << 42);

const DEV: u64 = 0;
const WAKER: u64 = 1;

/// Packets read per readiness event before commands get a turn (level-triggered: the rest is
/// read on the next iteration).
const READS_PER_EVENT: usize = 64;

/// How often a queue whose reads are off checks that its device still exists.
const GONE_PROBE: Duration = Duration::from_secs(1);

/// Backend name in metrics labels.
const BACKEND: &str = "tun";

pub(crate) enum Cmd {
    Wake,
    Close(Option<io::Error>),
    Task(Task),
    Core(LoopCmd),
    Shutdown,
}

/// What other threads reach: the command queue, the waker, and what connections ask of their
/// loop (`LoopLink`).
pub(crate) struct LoopShared {
    cmds: Mutex<Vec<Cmd>>,
    pending: AtomicBool,
    waker: Waker,
    pool: Arc<Pool>,
    stats: Arc<LoopStats>,
}

impl LoopShared {
    pub(crate) fn post(&self, cmd: Cmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        if !self.pending.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    fn take(&self, into: &mut Vec<Cmd>) {
        self.pending.store(false, Ordering::Release);
        std::mem::swap(
            &mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()),
            into,
        );
    }
}

impl LoopLink for LoopShared {
    // One connection per loop: the id names it, and is only checked by the loop.
    fn wake_conn(&self, _id: u64) {
        self.post(Cmd::Wake);
    }
    fn close_conn(&self, _id: u64, err: Option<io::Error>) {
        self.post(Cmd::Close(err));
    }
    fn post_task(&self, _id: u64, task: Task) {
        self.post(Cmd::Task(task));
    }
    fn pool(&self) -> Option<&Pool> {
        Some(&self.pool)
    }
    fn stats(&self) -> Option<Arc<LoopStats>> {
        Some(self.stats.clone())
    }
}

pub(crate) struct QueueLoop {
    poller: Poller,
    shared: Arc<LoopShared>,
    /// `None` once the queue has closed.
    fd: Option<OwnedFd>,
    inner: Arc<ConnInner>,
    acceptor: Arc<dyn DynAcceptor>,
    handler: Option<Box<dyn DynHandler>>,
    cfg: Arc<Config>,
    buf: Vec<u8>,
    /// Registered interest.
    reg: (bool, bool),
    /// The device refused a write (`EAGAIN`): packets wait for write readiness.
    blocked: bool,
    /// Reads paused by the queue's own backlog (`write_high_watermark`).
    backpressure: bool,
    draining: Option<Instant>,
    opened: Instant,
    last_read: Instant,
    bytes_in: u64,
    spare: Vec<Cmd>,
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

/// The local and peer address of a TUN connection: it has none.
fn no_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
}

impl QueueLoop {
    pub(crate) fn new(
        queue: usize,
        fd: OwnedFd,
        acceptor: Arc<dyn DynAcceptor>,
        cfg: Arc<Config>,
        pool: Arc<Pool>,
    ) -> io::Result<(QueueLoop, Arc<LoopShared>, Arc<ConnInner>)> {
        let poller = Poller::new()?;
        let waker = Waker::new(&poller, WAKER)?;
        poller.add(fd.as_raw_fd(), DEV, true, false)?;
        let stats = Arc::new(LoopStats::new(LoopMeta::new(BACKEND, None, queue)));
        let shared = Arc::new(LoopShared {
            cmds: Mutex::new(Vec::new()),
            pending: AtomicBool::new(false),
            waker,
            pool,
            stats: stats.clone(),
        });
        cfg.telemetry.register_loop(
            stats,
            Box::new({
                let sh = Arc::downgrade(&shared);
                move |c| {
                    if let Some(sh) = sh.upgrade() {
                        sh.post(Cmd::Core(c));
                    }
                }
            }),
        );
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let inner =
            ConnInner::new_virtual(id, true, no_addr(), no_addr(), shared.clone(), cfg.clone());
        // Room for the largest packet a TUN hands out (64 KiB, plus utun's 4-byte header).
        let size = 65536 + 4;
        let now = Instant::now();
        let l = QueueLoop {
            poller,
            shared: shared.clone(),
            fd: Some(fd),
            inner: inner.clone(),
            acceptor,
            handler: None,
            cfg,
            buf: vec![0; size],
            reg: (true, false),
            blocked: false,
            backpressure: false,
            draining: None,
            opened: now,
            last_read: now,
            bytes_in: 0,
            spare: Vec::new(),
        };
        Ok((l, shared, inner))
    }

    pub(crate) fn run(&mut self) {
        let stats = self.shared.stats.clone();
        stats.set_running(true);
        self.open();
        let mut events: Vec<Event> = Vec::with_capacity(4);
        while self.fd.is_some() {
            events.clear();
            // While reads are off the poller cannot tell that the device went away (the
            // device's wake-up carries `EPOLLIN`, which epoll filters out): probe it each second.
            let timeout = match (self.draining, self.reg.0) {
                (Some(_), _) => Some(Duration::from_millis(50)),
                (None, false) => Some(GONE_PROBE),
                (None, true) => None,
            };
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                self.finalize(Some(Error::Io(e)));
                break;
            }
            if !self.reg.0 && events.is_empty() {
                if let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) {
                    self.probe_gone(fd);
                }
            }
            stats.iterations.add_local(1);
            stats.events.add_local(events.len() as u64);
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker.drain(),
                    _ => {
                        if ev.writable {
                            self.blocked = false;
                            self.flush();
                        }
                        if ev.readable {
                            self.on_readable();
                        }
                    }
                }
            }
            self.drain_cmds();
            if let Some(deadline) = self.draining {
                if self.fd.is_some()
                    && (self.inner.queued_bytes() == 0 || Instant::now() >= deadline)
                {
                    self.finalize(None);
                }
            }
            self.update_interest();
        }
        stats.set_running(false);
        // Commands posted after the close (tasks, wake-ups) are dropped with the loop.
        self.shared.take(&mut self.spare);
        self.spare.clear();
    }

    /// The acceptor's `on_open`, on this thread.
    fn open(&mut self) {
        self.cfg.telemetry.conn_opened(false);
        self.shared.stats.dialed.add_local(1);
        let acc = self.acceptor.clone();
        let inner = self.inner.clone();
        match catch_unwind(AssertUnwindSafe(|| acc.on_open(&inner))) {
            Ok(h) => {
                self.handler = Some(h);
                // `on_open` (or another thread meanwhile) may have queued packets.
                self.flush();
            }
            Err(_) => self.finalize(Some(panic_error())),
        }
    }

    fn timed_start(&self) -> Option<Instant> {
        self.cfg.telemetry.timing_enabled().then(Instant::now)
    }

    fn timed_end(&self, kind: &'static str, t0: Option<Instant>) {
        self.cfg
            .telemetry
            .callback_done(&self.shared.stats, kind, self.inner.id(), t0);
    }

    /// Whether reads should be on: not held by the handler, not paused by the queue's own
    /// backlog, not shutting down.
    fn want_read(&mut self) -> bool {
        if self.inner.write_backpressure() {
            let high = self.cfg.telemetry.live().write_high_watermark();
            let q = self.inner.queued_bytes();
            if !self.backpressure && q >= high {
                self.backpressure = true;
            } else if self.backpressure && q <= high / 4 {
                self.backpressure = false;
            }
        } else {
            self.backpressure = false;
        }
        self.draining.is_none() && !self.inner.read_held() && !self.backpressure
    }

    fn on_readable(&mut self) {
        let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        if !self.want_read() {
            // Readiness without read interest is an error condition (`EPOLLERR` / `EPOLLHUP`,
            // reported whatever the interest): it must not spin the loop.
            self.probe_gone(fd);
            return;
        }
        let mut err = None;
        let mut got = false;
        for _ in 0..READS_PER_EVENT {
            // The handler may hold reads or close from a callback (an atomic each); the queue's
            // own backlog is checked once per event above.
            if self.inner.read_held() || !self.inner.is_open() {
                break;
            }
            let range = match akio_sys::read_packet(fd, &mut self.buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            };
            if range.is_empty() {
                continue;
            }
            got = true;
            let len = range.len();
            self.bytes_in += len as u64;
            self.shared.stats.datagram_in(len);
            let t0 = self.timed_start();
            let Some(h) = self.handler.as_mut() else {
                return;
            };
            let pkt = &self.buf[range];
            let r = catch_unwind(AssertUnwindSafe(|| h.on_data(pkt)));
            self.timed_end("on_data", t0);
            if r.is_err() {
                self.finalize(Some(panic_error()));
                return;
            }
        }
        if got {
            self.last_read = Instant::now();
            self.flush();
        }
        // An error on read: the device is gone (or the descriptor broke). A refused packet is
        // a write-side matter; reads have no other errors worth surviving.
        if let Some(e) = err {
            self.finalize(Some(Error::Io(e)));
        }
    }

    /// Reads are off (and the poller reported an error, or a probe interval passed): find
    /// out, without taking a packet, whether the device is gone. Linux: a zero-length write fails with `EBADFD` on a deleted
    /// device (`EINVAL` on a live one). Elsewhere a live device raises no such event.
    // `&mut self` is used on Linux alone, where a gone device is finalized here.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::needless_pass_by_ref_mut))]
    fn probe_gone(&mut self, fd: std::os::fd::RawFd) {
        #[cfg(target_os = "linux")]
        if let Err(e) = akio_sys::write_packet(fd, &[]) {
            if akio_sys::tun_gone(&e) {
                self.finalize(Some(Error::Io(e)));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = fd;
    }

    /// Writes queued packets until the queue is empty or the device pushes back; closes the
    /// queue after `close_after_send`, or when the device is gone.
    fn flush(&mut self) {
        if self.blocked {
            return;
        }
        let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let mut fatal = None;
        let mut blocked = false;
        let r = self.inner.drain_output(&mut |pkt| loop {
            match akio_sys::write_packet(fd, pkt) {
                Ok(_) => return pkt.len().max(1),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    return 0;
                }
                Err(e) => {
                    // A packet the device refuses (malformed, too large, interface down) is
                    // dropped, as a network drops it; a vanished device ends the queue.
                    if akio_sys::tun_gone(&e) && fatal.is_none() {
                        fatal = Some(e);
                    }
                    return pkt.len().max(1);
                }
            }
        });
        self.blocked = blocked;
        match (r, fatal) {
            (_, Some(e)) | (Err(e), None) => self.finalize(Some(Error::Io(e))),
            (Ok(true), None) if self.inner.close_after_send_requested() => self.finalize(None),
            (Ok(_), None) => {}
        }
    }

    fn update_interest(&mut self) {
        let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let want = (self.want_read(), self.blocked);
        if want != self.reg {
            self.reg = want;
            let _ = self.poller.modify(fd, DEV, want.0, want.1);
        }
    }

    fn drain_cmds(&mut self) {
        let mut cmds = std::mem::take(&mut self.spare);
        self.shared.take(&mut cmds);
        for cmd in cmds.drain(..) {
            match cmd {
                Cmd::Wake => self.flush(),
                Cmd::Close(err) => self.finalize(err.map(Error::Io)),
                Cmd::Task(task) => {
                    let t0 = self.timed_start();
                    let Some(h) = self.handler.as_mut() else {
                        continue; // closed meanwhile: the completion is skipped
                    };
                    let r = catch_unwind(AssertUnwindSafe(|| h.run_task(task)));
                    self.timed_end("spawn_blocking completion", t0);
                    match r {
                        Ok(()) => self.flush(),
                        Err(_) => self.finalize(Some(panic_error())),
                    }
                }
                Cmd::Core(LoopCmd::Inspect(f)) => f(self.inspect()),
                Cmd::Core(LoopCmd::Reload) => {}
                Cmd::Shutdown => self.begin_shutdown(),
            }
        }
        self.spare = cmds;
    }

    fn inspect(&self) -> Vec<ConnInfo> {
        if self.fd.is_none() {
            return Vec::new();
        }
        let mut info = ConnInfo::new(
            self.inner.id(),
            &self.inner,
            self.shared.stats.meta().clone(),
        );
        info.age = self.opened.elapsed();
        info.idle = self.last_read.elapsed();
        info.bytes_in = self.bytes_in;
        info.backpressure = self.backpressure;
        vec![info]
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() || self.fd.is_none() {
            return;
        }
        let timeout = self.cfg.telemetry.live().shutdown_timeout();
        self.draining = Some(Instant::now() + timeout);
        let acc = self.acceptor.clone();
        let inner = self.inner.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner)));
        self.flush();
    }

    /// The queue is over: `on_close`, then its descriptor is closed (the last queue's close
    /// destroys the interface).
    fn finalize(&mut self, err: Option<Error>) {
        let Some(fd) = self.fd.take() else {
            return;
        };
        self.poller.delete(fd.as_raw_fd());
        drop(fd);
        self.inner.mark_closed();
        if let Some(mut h) = self.handler.take() {
            let t0 = self.timed_start();
            let _ = catch_unwind(AssertUnwindSafe(|| h.on_close(err)));
            self.timed_end("on_close", t0);
        }
        self.shared.stats.closed.add_local(1);
        self.cfg.telemetry.conn_closed(false);
    }
}
