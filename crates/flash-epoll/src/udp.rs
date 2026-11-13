//! UDP: one loop per socket; every distinct peer address is a connection (`Conn`) with its own
//! handler, created on its first datagram and dropped after `Config::udp_idle_timeout` of silence.
//! `on_data` is called once per datagram, so message boundaries are preserved, and `send` sends
//! one datagram.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use flash_core::{Config, ConnInner, DynAcceptor, DynHandler, Error, Group, Pool, Task};
use flash_sys::{Event, Poller};
use flash_timer::{TimerId, Wheel};

use crate::reactor::{Cmd, LoopShared};

const WAKER: u64 = 0;
const SOCK: u64 = 1;
/// Datagrams taken from the socket per `recvmmsg`.
const BATCH: usize = 32;
const MAX_BATCHES_PER_EVENT: usize = 8;

static NEXT_ID: AtomicU64 = AtomicU64::new(1 << 40);

struct Peer {
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    addr: SocketAddr,
    last_active: u64,
    timer: Option<TimerId>,
}

struct UdpLoop {
    poller: Poller,
    shared: Arc<LoopShared>,
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    acceptor: Arc<dyn DynAcceptor>,
    peers: HashMap<SocketAddr, u64>,
    conns: HashMap<u64, Peer>,
    /// Connections with datagrams waiting for socket space.
    blocked: HashSet<u64>,
    want_write: bool,
    #[cfg(target_os = "linux")]
    batch: Option<flash_sys::RecvBatch>,
    #[cfg(not(target_os = "linux"))]
    scratch: Option<Vec<u8>>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    wheel: Wheel<u64>,
    epoch: Instant,
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

impl UdpLoop {
    fn new(
        poller: Poller,
        shared: Arc<LoopShared>,
        sock: UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
        cfg: Arc<Config>,
    ) -> io::Result<UdpLoop> {
        sock.set_nonblocking(true)?;
        poller.add(sock.as_raw_fd(), SOCK, true, false)?;
        let local = sock.local_addr()?;
        Ok(UdpLoop {
            poller,
            shared,
            sock: Arc::new(sock),
            local,
            acceptor,
            peers: HashMap::new(),
            conns: HashMap::new(),
            blocked: HashSet::new(),
            want_write: false,
            #[cfg(target_os = "linux")]
            batch: Some(flash_sys::RecvBatch::new(BATCH, cfg.read_buffer)),
            #[cfg(not(target_os = "linux"))]
            scratch: Some(vec![0; cfg.read_buffer]),
            cfg,
            draining: None,
            wheel: Wheel::new(0),
            epoch: Instant::now(),
        })
    }

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn idle_ms(&self) -> u64 {
        let d = self
            .cfg
            .idle_timeout
            .map_or(self.cfg.udp_idle_timeout, |i| {
                i.min(self.cfg.udp_idle_timeout)
            });
        d.as_millis().max(1) as u64
    }

    fn run(&mut self) {
        crate::reactor::set_current_loop(&self.shared);
        let mut events: Vec<Event> = Vec::with_capacity(64);
        loop {
            let mut timeout = self.draining.map(|_| Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            events.clear();
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                eprintln!("flash: poller error: {e}");
                break;
            }
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker().drain(),
                    SOCK => {
                        if ev.readable {
                            self.on_readable();
                        }
                        if ev.writable {
                            self.flush_blocked();
                        }
                    }
                    _ => {}
                }
            }
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                // Datagrams have no stream to drain: once handlers had their `on_shutdown` and
                // nothing is waiting for socket space, everything left is closed.
                if self.blocked.is_empty() || Instant::now() >= deadline {
                    let ids: Vec<u64> = self.conns.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    break;
                }
            }
        }
    }

    // ---- receive --------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn on_readable(&mut self) {
        let mut batch = self.batch.take().expect("batch present");
        let fd = self.sock.as_raw_fd();
        for _ in 0..MAX_BATCHES_PER_EVENT {
            let n = match batch.recv(fd) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("flash: recvmmsg: {e}");
                    break;
                }
            };
            for i in 0..n {
                if let Some((data, peer)) = batch.get(i) {
                    self.on_datagram(peer, data);
                }
            }
            if n < BATCH {
                break;
            }
        }
        self.batch = Some(batch);
    }

    #[cfg(not(target_os = "linux"))]
    fn on_readable(&mut self) {
        let mut buf = self.scratch.take().expect("scratch present");
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match self.sock.recv_from(&mut buf) {
                Ok((n, peer)) => self.on_datagram(peer, &buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("flash: recv_from: {e}");
                    break;
                }
            }
        }
        self.scratch = Some(buf);
    }

    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        if self.draining.is_some() {
            return;
        }
        let id = match self.peers.get(&peer) {
            Some(&id) => id,
            None => match self.open(peer) {
                Some(id) => id,
                None => return,
            },
        };
        let t0 = self.cfg.slow_callback_threshold.map(|_| Instant::now());
        let now = self.tick();
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        p.last_active = now;
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.on_data(data)));
        self.check_slow("on_data", id, t0);
        if r.is_err() {
            self.finalize(id, Some(panic_error()));
        }
    }

    fn open(&mut self, peer: SocketAddr) -> Option<u64> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let inner = ConnInner::new_udp(
            id,
            self.sock.clone(),
            self.local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let acceptor = self.acceptor.clone();
        let handler = match catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) {
            Ok(h) => h,
            Err(_) => {
                inner.mark_closed();
                return None;
            }
        };
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let timer = Some(self.wheel.schedule(now + self.idle_ms(), id));
        self.peers.insert(peer, id);
        self.conns.insert(
            id,
            Peer {
                inner,
                handler,
                addr: peer,
                last_active: now,
                timer,
            },
        );
        // `on_open` may already have queued datagrams or closed the connection.
        self.on_wake(id);
        self.conns.contains_key(&id).then_some(id)
    }

    // ---- writing --------------------------------------------------------------------------

    /// Flushes queued datagrams, applies `close_after_send`, tracks whether the socket is full.
    fn on_wake(&mut self, id: u64) {
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        match p.inner.flush_queue() {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(true) => {
                self.blocked.remove(&id);
                if p.inner.close_after_send_requested() {
                    self.finalize(id, None);
                }
                self.update_interest();
            }
            Ok(false) => {
                self.blocked.insert(id);
                self.update_interest();
            }
        }
    }

    fn flush_blocked(&mut self) {
        let ids: Vec<u64> = self.blocked.iter().copied().collect();
        for id in ids {
            self.on_wake(id);
        }
    }

    fn update_interest(&mut self) {
        let want = !self.blocked.is_empty();
        if want != self.want_write {
            self.want_write = want;
            let _ = self
                .poller
                .modify(self.sock.as_raw_fd(), SOCK, self.draining.is_none(), want);
        }
    }

    // ---- lifecycle ------------------------------------------------------------------------

    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(mut p) = self.conns.remove(&id) else {
            return;
        };
        self.peers.remove(&p.addr);
        self.blocked.remove(&id);
        if let Some(t) = p.timer.take() {
            self.wheel.cancel(t);
        }
        p.inner.mark_closed();
        let t0 = self.cfg.slow_callback_threshold.map(|_| Instant::now());
        let _ = catch_unwind(AssertUnwindSafe(|| p.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
        self.update_interest();
    }

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
                    Cmd::Dial { on_error, .. } => on_error(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "dial is not supported on a UDP listener",
                    )),
                }
            }
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.shutdown_timeout);
        self.poller.delete(self.sock.as_raw_fd());
        // Re-add for writing only if something is still waiting for socket space.
        self.want_write = false;
        if !self.blocked.is_empty() {
            let _ = self.poller.add(self.sock.as_raw_fd(), SOCK, false, true);
            self.want_write = true;
        }
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(p) = self.conns.get(&id) else {
                continue;
            };
            let (acc, inner) = (self.acceptor.clone(), p.inner.clone());
            if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                self.finalize(id, Some(panic_error()));
            } else {
                self.on_wake(id); // flush whatever on_shutdown sent
            }
        }
    }

    fn on_task(&mut self, id: u64, task: Task) {
        let t0 = self.cfg.slow_callback_threshold.map(|_| Instant::now());
        let Some(p) = self.conns.get_mut(&id) else {
            return; // peer dropped meanwhile: the completion is skipped
        };
        let r = catch_unwind(AssertUnwindSafe(|| p.handler.run_task(task)));
        self.check_slow("spawn_blocking completion", id, t0);
        match r {
            Ok(()) => self.on_wake(id),
            Err(_) => self.finalize(id, Some(panic_error())),
        }
    }

    fn fire_timers(&mut self) {
        let idle = self.idle_ms();
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        for id in due {
            let Some(p) = self.conns.get_mut(&id) else {
                continue;
            };
            p.timer = None;
            let expires = p.last_active + idle;
            if expires <= now {
                let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                self.finalize(id, Some(Error::Io(e)));
            } else {
                p.timer = Some(self.wheel.schedule(expires, id));
            }
        }
    }

    fn check_slow(&self, kind: &'static str, id: u64, started: Option<Instant>) {
        let (Some(t0), Some(limit)) = (started, self.cfg.slow_callback_threshold) else {
            return;
        };
        let elapsed = t0.elapsed();
        if elapsed < limit {
            return;
        }
        let rep = flash_core::SlowCallback {
            kind,
            conn_id: id,
            elapsed,
        };
        match &self.cfg.slow_hook {
            Some(h) => (h.0)(&rep),
            None => eprintln!(
                "flash: slow callback: {kind} on peer {id} blocked its I/O thread for \
                 {elapsed:?} (limit {limit:?}); move blocking work to Conn::spawn_blocking"
            ),
        }
    }
}

/// A group of UDP loops serving one address.
pub struct UdpGroup {
    addr: SocketAddr,
    shared: Vec<Arc<LoopShared>>,
    pending: Mutex<Vec<UdpLoop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    rr: AtomicUsize,
}

impl UdpGroup {
    /// Binds `addr` and prepares `threads` loops. On Linux every loop gets its own
    /// `SO_REUSEPORT` socket and the kernel keeps each peer on one loop; elsewhere UDP cannot be
    /// spread that way, so a single loop serves the socket.
    pub fn bind(
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<UdpGroup> {
        let threads = if cfg!(target_os = "linux") {
            threads.max(1)
        } else {
            1
        };
        let cfg = Arc::new(cfg);
        let first = flash_sys::listen_udp(addr, cfg!(target_os = "linux"))?;
        let bound = first.local_addr()?;
        let mut socks = vec![first];
        for _ in 1..threads {
            socks.push(flash_sys::listen_udp(bound, true)?);
        }
        let mut shared = Vec::new();
        let mut loops = Vec::new();
        for s in socks {
            let poller = Poller::new()?;
            let sh = LoopShared::new(&poller, pool.clone())?;
            loops.push(UdpLoop::new(
                poller,
                sh.clone(),
                s,
                acceptor.clone(),
                cfg.clone(),
            )?);
            shared.push(sh);
        }
        Ok(UdpGroup {
            addr: bound,
            shared,
            pending: Mutex::new(loops),
            threads: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            rr: AtomicUsize::new(0),
        })
    }
}

impl Group for UdpGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap());
        let mut handles = self.threads.lock().unwrap();
        for (i, mut l) in loops.into_iter().enumerate() {
            handles.push(
                std::thread::Builder::new()
                    .name(format!("flash-udp-{i}"))
                    .spawn(move || l.run())?,
            );
        }
        Ok(())
    }

    fn shutdown(&self) {
        for s in &self.shared {
            s.post(Cmd::Shutdown);
        }
    }

    fn join(&self) {
        let handles = std::mem::take(&mut *self.threads.lock().unwrap());
        for h in handles {
            let _ = h.join();
        }
    }

    fn dial(
        &self,
        _addr: SocketAddr,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        let _ = self.rr.fetch_add(1, Ordering::Relaxed);
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "dial is not supported on a UDP listener",
        ));
    }
}
