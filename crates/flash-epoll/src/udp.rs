//! UDP: one loop per socket; every distinct peer address is a connection (`Conn`) with its own
//! handler, created on its first datagram and dropped after `Config::udp_idle_timeout` of silence.
//! `on_data` is called once per datagram, so message boundaries are preserved, and `send` sends
//! one datagram.
//!
//! A loop can also own *client* connections (`Cmd::DialUdp`): each has its own `connect`ed socket
//! (so its own local port, and ICMP "port unreachable" surfaces as a connection error) registered
//! in the poller under the connection id.

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
    /// The connection's own connected socket (dialed clients); `None` for peers of the shared
    /// server socket.
    own: Option<Arc<UdpSocket>>,
    /// Write interest is registered for `own`.
    write_reg: bool,
    acceptor: Arc<dyn DynAcceptor>,
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    addr: SocketAddr,
    last_active: u64,
    timer: Option<TimerId>,
}

struct UdpLoop {
    poller: Poller,
    shared: Arc<LoopShared>,
    /// The shared server socket (absent in a client-only group).
    sock: Option<Arc<UdpSocket>>,
    local: Option<SocketAddr>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    peers: HashMap<SocketAddr, u64>,
    conns: HashMap<u64, Peer>,
    /// Server-socket peers with datagrams waiting for socket space.
    blocked: HashSet<u64>,
    /// Dialed connections with datagrams waiting for socket space.
    blocked_own: HashSet<u64>,
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
        server: Option<(UdpSocket, Arc<dyn DynAcceptor>)>,
        cfg: Arc<Config>,
    ) -> io::Result<UdpLoop> {
        let (sock, local, acceptor) = match server {
            Some((sock, acceptor)) => {
                sock.set_nonblocking(true)?;
                poller.add(sock.as_raw_fd(), SOCK, true, false)?;
                let local = sock.local_addr()?;
                (Some(Arc::new(sock)), Some(local), Some(acceptor))
            }
            None => (None, None, None),
        };
        let sock_present = sock.is_some();
        Ok(UdpLoop {
            poller,
            shared,
            sock,
            local,
            acceptor,
            peers: HashMap::new(),
            conns: HashMap::new(),
            blocked: HashSet::new(),
            blocked_own: HashSet::new(),
            want_write: false,
            #[cfg(target_os = "linux")]
            batch: sock_present.then(|| flash_sys::RecvBatch::new(BATCH, cfg.read_buffer)),
            #[cfg(not(target_os = "linux"))]
            scratch: sock_present.then(|| vec![0; cfg.read_buffer]),
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
                    id => {
                        if ev.readable {
                            self.on_client_readable(id);
                        }
                        if ev.writable {
                            self.on_wake(id);
                        }
                    }
                }
            }
            self.drain_cmds();
            self.fire_timers();
            if let Some(deadline) = self.draining {
                // Datagrams have no stream to drain: once handlers had their `on_shutdown` and
                // nothing is waiting for socket space, everything left is closed.
                if (self.blocked.is_empty() && self.blocked_own.is_empty())
                    || Instant::now() >= deadline
                {
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
        let Some(sock) = self.sock.clone() else {
            return;
        };
        let mut batch = self.batch.take().expect("batch present");
        let fd = sock.as_raw_fd();
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
        let Some(sock) = self.sock.clone() else {
            return;
        };
        let mut buf = self.scratch.take().expect("scratch present");
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match sock.recv_from(&mut buf) {
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
        let (sock, local, acceptor) = (self.sock.clone()?, self.local?, self.acceptor.clone()?);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let inner = ConnInner::new_udp(
            id,
            sock,
            false,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
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
                own: None,
                write_reg: false,
                acceptor,
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

    // ---- dialed clients -------------------------------------------------------------------

    fn open_client(&mut self, sock: UdpSocket, acceptor: Arc<dyn DynAcceptor>) {
        if self.draining.is_some() {
            return;
        }
        let (Ok(local), Ok(peer)) = (sock.local_addr(), sock.peer_addr()) else {
            return;
        };
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if self.poller.add(sock.as_raw_fd(), id, true, false).is_err() {
            return;
        }
        let sock = Arc::new(sock);
        let inner = ConnInner::new_udp(
            id,
            sock.clone(),
            true,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let acc = acceptor.clone();
        let handler = match catch_unwind(AssertUnwindSafe(|| acc.on_open(&inner))) {
            Ok(h) => h,
            Err(_) => {
                self.poller.delete(sock.as_raw_fd());
                inner.mark_closed();
                return;
            }
        };
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let timer = Some(self.wheel.schedule(now + self.idle_ms(), id));
        self.conns.insert(
            id,
            Peer {
                own: Some(sock),
                write_reg: false,
                acceptor,
                inner,
                handler,
                addr: peer,
                last_active: now,
                timer,
            },
        );
        self.on_wake(id);
    }

    /// Datagrams arrived on a dialed connection's own socket.
    fn on_client_readable(&mut self, id: u64) {
        let Some(sock) = self.conns.get(&id).and_then(|p| p.own.clone()) else {
            return;
        };
        let mut buf = vec![0u8; self.cfg.read_buffer];
        for _ in 0..MAX_BATCHES_PER_EVENT * BATCH {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    let t0 = self.cfg.slow_callback_threshold.map(|_| Instant::now());
                    let now = self.tick();
                    let Some(p) = self.conns.get_mut(&id) else {
                        return;
                    };
                    p.last_active = now;
                    let data = &buf[..n];
                    let r = catch_unwind(AssertUnwindSafe(|| p.handler.on_data(data)));
                    self.check_slow("on_data", id, t0);
                    if r.is_err() {
                        self.finalize(id, Some(panic_error()));
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // ICMP "port unreachable" from the peer (or another socket error): it is over.
                Err(e) => {
                    self.finalize(id, Some(Error::Io(e)));
                    return;
                }
            }
        }
    }

    // ---- writing --------------------------------------------------------------------------

    /// Flushes queued datagrams, applies `close_after_send`, tracks whether the socket is full.
    fn on_wake(&mut self, id: u64) {
        let Some(p) = self.conns.get_mut(&id) else {
            return;
        };
        let flushed = p.inner.flush_queue();
        let own = p.own.clone();
        match flushed {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && p.inner.close_after_send_requested() {
                    self.finalize(id, None);
                    return;
                }
                match own {
                    Some(sock) => {
                        if empty {
                            self.blocked_own.remove(&id);
                        } else {
                            self.blocked_own.insert(id);
                        }
                        if let Some(p) = self.conns.get_mut(&id) {
                            if p.write_reg == empty {
                                p.write_reg = !empty;
                                let _ = self.poller.modify(sock.as_raw_fd(), id, true, !empty);
                            }
                        }
                    }
                    None => {
                        if empty {
                            self.blocked.remove(&id);
                        } else {
                            self.blocked.insert(id);
                        }
                        self.update_interest();
                    }
                }
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
            if let Some(sock) = &self.sock {
                let _ = self
                    .poller
                    .modify(sock.as_raw_fd(), SOCK, self.draining.is_none(), want);
            }
        }
    }

    // ---- lifecycle ------------------------------------------------------------------------

    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(mut p) = self.conns.remove(&id) else {
            return;
        };
        match &p.own {
            Some(sock) => {
                self.poller.delete(sock.as_raw_fd());
                self.blocked_own.remove(&id);
            }
            None => {
                self.peers.remove(&p.addr);
                self.blocked.remove(&id);
            }
        }
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
                    Cmd::DialUdp { sock, acceptor } => self.open_client(sock, acceptor),
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
        if let Some(sock) = &self.sock {
            self.poller.delete(sock.as_raw_fd());
            // Re-add for writing only if something is still waiting for socket space.
            self.want_write = false;
            if !self.blocked.is_empty() {
                let _ = self.poller.add(sock.as_raw_fd(), SOCK, false, true);
                self.want_write = true;
            }
        }
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(p) = self.conns.get(&id) else {
                continue;
            };
            let (acc, inner) = (p.acceptor.clone(), p.inner.clone());
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
    /// Server socket fds in loop order when they form a `SO_REUSEPORT` group (Linux).
    fds: Vec<i32>,
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
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<UdpGroup> {
        let threads = match &listen {
            // Without SO_REUSEPORT spreading (non-Linux) one loop must own the server socket.
            Some(_) if !cfg!(target_os = "linux") => 1,
            _ => threads.max(1),
        };
        let cfg = Arc::new(cfg);
        let mut bound = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut socks: Vec<Option<(UdpSocket, Arc<dyn DynAcceptor>)>> =
            (0..threads).map(|_| None).collect();
        if let Some((addr, acceptor)) = listen {
            let first = flash_sys::listen_udp(addr, cfg!(target_os = "linux"))?;
            bound = first.local_addr()?;
            for slot in socks.iter_mut().skip(1) {
                *slot = Some((flash_sys::listen_udp(bound, true)?, acceptor.clone()));
            }
            socks[0] = Some((first, acceptor));
        }
        let fds = if cfg!(target_os = "linux") {
            socks
                .iter()
                .flatten()
                .map(|(s, _)| std::os::fd::AsRawFd::as_raw_fd(s))
                .collect()
        } else {
            Vec::new()
        };
        let mut shared = Vec::new();
        let mut loops = Vec::new();
        for server in socks {
            let poller = Poller::new()?;
            let sh = LoopShared::new(&poller, pool.clone())?;
            loops.push(UdpLoop::new(poller, sh.clone(), server, cfg.clone())?);
            shared.push(sh);
        }
        Ok(UdpGroup {
            addr: bound,
            fds,
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

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
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
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "use dial_udp for UDP groups",
        ));
    }

    fn dial_udp(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // `connect` on a UDP socket only fixes the peer: it does not block or send anything.
        let local: SocketAddr = if addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = UdpSocket::bind(local)
            .and_then(|s| s.connect(addr).map(|()| s))
            .and_then(|s| s.set_nonblocking(true).map(|()| s));
        match sock {
            Ok(sock) => {
                let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
                self.shared[i].post(Cmd::DialUdp { sock, acceptor });
            }
            Err(e) => on_error(e),
        }
    }
}
