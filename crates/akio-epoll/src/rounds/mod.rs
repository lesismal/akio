//! Rounds scheduling (ADR-104): a few pollers report readiness, and each round of a
//! connection (read, handler, write) runs on whichever worker is free. So does accepting: a
//! listening socket's readiness queues an accept job, and the worker running it opens and
//! registers what it accepted.

mod conn;
mod poller;
mod trace;
mod workers;

use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use akio_core::{
    AcceptFilter, Config, DynAcceptor, FilterCell, Group, ListenSocket, LoopMeta, LoopStats, Pool,
};
use akio_sys::Poller;

use poller::{ListenJob, PollerShared, RCmd, RLoop};
use workers::{Driver, Workers};

/// Backend name for metrics labels.
pub(crate) const BACKEND: &str = if cfg!(target_os = "linux") {
    "epoll-rounds"
} else {
    "kqueue-rounds"
};

/// Thread counts of rounds scheduling. 0 picks the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoundsConfig {
    /// epoll/kqueue instances the workers poll (default: 1; with dedicated poller threads,
    /// `AKIO_ROUNDS_POLLERS=dedicated`: one with 4 CPUs or fewer, else one per 4 CPUs, at
    /// least 2).
    pub pollers: usize,
    /// Workers that run rounds (default: one per CPU).
    pub workers: usize,
}

impl RoundsConfig {
    /// `pollers` pollers and `workers` workers (0: the default).
    pub fn new(pollers: usize, workers: usize) -> RoundsConfig {
        RoundsConfig { pollers, workers }
    }

    /// The poller and worker counts this configuration resolves to.
    pub fn resolved(&self) -> (usize, usize) {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let pollers = match self.pollers {
            // Driver mode: the workers poll; one epoll instance serves them all (as Tokio).
            0 if driver_mode() => 1,
            0 if cpus <= 4 => 1,
            0 => (cpus / 4).max(2),
            n => n,
        };
        let workers = match self.workers {
            0 => cpus,
            n => n,
        };
        (pollers, workers)
    }
}

/// Who waits in `epoll_wait`: the workers themselves (driver mode, the default) or poller
/// threads of their own (`AKIO_ROUNDS_POLLERS=dedicated`, kept for comparison).
fn driver_mode() -> bool {
    std::env::var("AKIO_ROUNDS_POLLERS").as_deref() != Ok("dedicated")
}

struct Slot {
    shared: Arc<PollerShared>,
    pending: Option<RLoop>,
    handle: Option<JoinHandle<()>>,
}

/// One listener of the group (ADR-130).
struct RListener {
    /// Its sockets, one accept job each, over the pollers.
    jobs: Vec<Arc<ListenJob>>,
    /// Its accept filter (ADR-099).
    filter: Arc<FilterCell>,
    /// Removed (`Group::remove_listener` or `stop_listening`).
    unlisted: bool,
}

/// A group served by rounds scheduling: one listener, several (a shared group, ADR-130), or
/// only dialed connections.
pub struct RoundsGroup {
    /// The listener's address when the group was built for one; the unspecified address for
    /// shared and client-only groups.
    addr: SocketAddr,
    fds: Vec<i32>,
    slots: Mutex<Vec<Slot>>,
    shareds: Vec<Arc<PollerShared>>,
    workers: Arc<Workers>,
    cfg: Arc<Config>,
    rr: AtomicUsize,
    started: AtomicBool,
    pins: Mutex<Vec<Vec<usize>>>,
    /// The listeners, by key; removed ones stay, marked.
    listeners: Mutex<Vec<RListener>>,
    /// Poll tokens of the accept jobs (unique in the group).
    next_token: AtomicU64,
    /// Serves listeners (not a client-only group).
    listens: bool,
    /// A shared group: listeners are added and removed, the threads stay until shutdown.
    shared: bool,
    /// Every listener was removed (`Group::stop_listening`, ADR-099).
    unlisted: AtomicBool,
    /// The engine is shutting down (`Group::shutdown`).
    stopping: AtomicBool,
}

impl std::fmt::Debug for RoundsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundsGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn not_listening() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not a listener group")
}

/// Binds a listener's sockets for `pollers` pollers and `workers` workers: on Linux one
/// `SO_REUSEPORT` socket per worker (at least one per poller), so that accepts run on several
/// workers at once; elsewhere one socket, cloned for each poller. Socket `i` goes to poller
/// `i % pollers`.
fn bind_socks(
    socket: ListenSocket,
    pollers: usize,
    workers: usize,
    backlog: i32,
) -> io::Result<Bound> {
    let clones = |first: TcpListener| -> io::Result<Vec<TcpListener>> {
        let mut v = Vec::with_capacity(pollers);
        for _ in 1..pollers {
            v.push(first.try_clone()?);
        }
        v.insert(0, first);
        Ok(v)
    };
    match socket {
        ListenSocket::Bind(a) if cfg!(target_os = "linux") => {
            let first = akio_sys::listen(a, true, backlog)?;
            let addr = first.local_addr()?;
            let mut socks = vec![first];
            for _ in 1..workers.max(pollers) {
                socks.push(akio_sys::listen(addr, true, backlog)?);
            }
            Ok(Bound {
                addr,
                unix: false,
                reuseport: true,
                socks,
            })
        }
        ListenSocket::Bind(a) => {
            let first = akio_sys::listen(a, false, backlog)?;
            Ok(Bound {
                addr: first.local_addr()?,
                unix: false,
                reuseport: false,
                socks: clones(first)?,
            })
        }
        ListenSocket::Inherited(l) => {
            l.set_nonblocking(true)?;
            Ok(Bound {
                addr: l.local_addr()?,
                unix: false,
                reuseport: false,
                socks: clones(l)?,
            })
        }
        // ADR-121: accepted without an address; every poller polls a clone.
        ListenSocket::Unix(l) => {
            l.set_nonblocking(true)?;
            Ok(Bound {
                addr: akio_core::UNIX_ADDR,
                unix: true,
                reuseport: false,
                socks: clones(l)?,
            })
        }
    }
}

/// A listener's sockets before it joins a group ([`bind_socks`]).
struct Bound {
    addr: SocketAddr,
    unix: bool,
    /// One `SO_REUSEPORT` socket per worker (Linux), whose fds steering could use.
    reuseport: bool,
    /// Socket `i` goes to poller `i % pollers`.
    socks: Vec<TcpListener>,
}

impl RoundsGroup {
    /// Binds `listen` (if any) with `rc`'s pollers and workers. Nothing runs until
    /// [`Group::start`].
    ///
    /// On Linux there is one `SO_REUSEPORT` socket per worker, spread over the pollers, so that
    /// accepts run on several workers at once; elsewhere one socket, cloned for each poller.
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        match listen {
            Some((a, acc)) => Self::one(ListenSocket::Bind(a), acc, rc, cfg, pool),
            None => Self::assemble(rc, None, false, false, cfg, pool),
        }
    }

    /// Serves an already bound and listening socket: every poller polls a clone of it.
    pub fn bind_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        Self::one(ListenSocket::Inherited(listener), acceptor, rc, cfg, pool)
    }

    /// Serves a listening Unix-domain stream socket (ADR-121, `akio_sys::listen_unix`) as
    /// [`bind_listener`](Self::bind_listener) serves an inherited one: every poller polls a
    /// clone. Its connections are accepted without reading an address; their `peer_addr` and
    /// `local_addr`, and the group's, are [`akio_core::UNIX_ADDR`].
    pub fn bind_unix_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        Self::one(ListenSocket::Unix(listener), acceptor, rc, cfg, pool)
    }

    /// A shared group with `rc`'s pollers and workers (ADR-130): it starts with no listener;
    /// listeners join with [`Group::add_listener`] and leave with [`Group::remove_listener`],
    /// and the workers serve them all until shutdown. Its `local_addr` is the unspecified
    /// address and its threads report no listener in their `LoopMeta`.
    pub fn shared(rc: RoundsConfig, cfg: Config, pool: Arc<Pool>) -> io::Result<RoundsGroup> {
        Self::assemble(rc, None, true, true, cfg, pool)
    }

    /// A group serving the one listener `socket`.
    fn one(
        socket: ListenSocket,
        acceptor: Arc<dyn DynAcceptor>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        let (pollers, workers) = rc.resolved();
        let b = bind_socks(socket, pollers, workers, cfg.backlog)?;
        let fds = if b.reuseport {
            b.socks.iter().map(|l| l.as_raw_fd()).collect()
        } else {
            Vec::new()
        };
        let mut g = Self::assemble(rc, Some(b.addr), true, false, cfg, pool)?;
        g.addr = b.addr;
        g.fds = fds;
        g.install(b, acceptor)?;
        Ok(g)
    }

    fn assemble(
        rc: RoundsConfig,
        listener_addr: Option<SocketAddr>,
        listens: bool,
        shared: bool,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let (npollers, nworkers) = rc.resolved();
        let workers = Workers::new(nworkers, &cfg, listener_addr);
        let mut slots = Vec::with_capacity(npollers);
        for i in 0..npollers {
            let poller = Poller::new()?;
            // Pollers are numbered after the workers in the metrics of the listener.
            let meta = LoopMeta::new(BACKEND, listener_addr, nworkers + i);
            let stats = Arc::new(LoopStats::new(meta));
            let sh = PollerShared::new(&poller, pool.clone(), cfg.clone(), stats, nworkers)?;
            let lp = RLoop::new(poller, sh.clone(), Vec::new(), workers.clone())?;
            slots.push(Slot {
                shared: sh,
                pending: Some(lp),
                handle: None,
            });
        }
        if driver_mode() {
            let drivers = slots
                .iter_mut()
                .filter_map(|s| {
                    s.pending.take().map(|lp| {
                        Arc::new(Driver {
                            lp: Mutex::new(Some(lp)),
                            shared: s.shared.clone(),
                            done: AtomicBool::new(false),
                            blocked: AtomicBool::new(false),
                        })
                    })
                })
                .collect();
            workers.set_drivers(drivers);
        }
        Ok(RoundsGroup {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            fds: Vec::new(),
            shareds: slots.iter().map(|s| s.shared.clone()).collect(),
            slots: Mutex::new(slots),
            workers,
            cfg,
            rr: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            pins: Mutex::new(Vec::new()),
            listeners: Mutex::new(Vec::new()),
            next_token: AtomicU64::new(0),
            listens,
            shared,
            unlisted: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
        })
    }

    /// Makes `socks` a listener of the group: socket `i` becomes an accept job of poller
    /// `i % pollers`, which registers it when it gets it. Its key.
    fn install(&self, b: Bound, acceptor: Arc<dyn DynAcceptor>) -> io::Result<usize> {
        let Bound {
            addr, unix, socks, ..
        } = b;
        let mut ls = lock(&self.listeners);
        let lid = ls.len();
        let filter = Arc::new(FilterCell::default());
        let mut jobs = Vec::with_capacity(socks.len());
        for (i, l) in socks.into_iter().enumerate() {
            let home = &self.shareds[i % self.shareds.len()];
            let token = self.next_token.fetch_add(1, Ordering::Relaxed);
            let j = ListenJob::new(
                l,
                lid,
                addr,
                unix,
                token,
                acceptor.clone(),
                &filter,
                home.clone(),
            )?;
            home.post(RCmd::AddJob(j.clone()));
            jobs.push(j);
        }
        ls.push(RListener {
            jobs,
            filter,
            unlisted: false,
        });
        Ok(lid)
    }

    fn next_poller(&self) -> &Arc<PollerShared> {
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shareds.len();
        &self.shareds[i]
    }
}

impl Group for RoundsGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        // Steering would pick pollers, not the threads that do the work.
        let _ = &self.fds;
        Vec::new()
    }

    fn pin_threads(&self, cpus: Vec<Vec<usize>>) {
        *lock(&self.pins) = cpus;
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut slots = lock(&self.slots);
        for s in slots.iter().filter(|s| s.pending.is_none()) {
            // Driver mode: polled by the workers.
            s.shared.stats.set_running(true);
        }
        self.workers.start(&self.cfg)?;
        let pins = lock(&self.pins).clone();
        for (i, slot) in slots.iter_mut().enumerate() {
            let Some(mut lp) = slot.pending.take() else {
                continue;
            };
            let pin = pins.get(i).cloned().unwrap_or_default();
            slot.shared.stats.set_running(true);
            slot.handle = Some(
                std::thread::Builder::new()
                    .name(format!("akio-io-p{i}"))
                    .spawn(move || {
                        if !pin.is_empty() {
                            akio_sys::process::pin_current_thread(&pin).ok();
                        }
                        lp.run();
                    })?,
            );
        }
        Ok(())
    }

    fn threads(&self) -> usize {
        self.workers.len()
    }

    fn set_threads(&self, _n: usize) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "set_threads on a listener with rounds scheduling",
        ))
    }

    fn stop_listening(&self, drain: Option<Duration>, exit_when_idle: bool) -> io::Result<()> {
        if !self.listens {
            return Err(not_listening());
        }
        if self.stopping.load(Ordering::SeqCst) || self.unlisted.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Here, not on the pollers: every socket (one per worker on Linux, all in one
        // `SO_REUSEPORT` group) is closed when this returns, so a connection made afterwards
        // cannot land on one, and an accept job queued or run later finds no socket. `close`
        // waits for an accept job in progress (a short one: it never runs handler code).
        for l in lock(&self.listeners).iter_mut() {
            l.unlisted = true;
            for j in &l.jobs {
                j.close();
            }
        }
        // The pollers keep the connections: they notify and drain them, and finish once none is
        // left when they may.
        for sh in &self.shareds {
            sh.post(RCmd::StopListening {
                lid: None,
                drain,
                exit: exit_when_idle,
            });
        }
        Ok(())
    }

    fn set_filter(&self, filter: Option<AcceptFilter>) -> io::Result<()> {
        // The group's listener (the first, in a group built for one).
        self.set_listener_filter(0, filter)
    }

    fn add_listener(
        &self,
        socket: ListenSocket,
        acceptor: Arc<dyn DynAcceptor>,
    ) -> io::Result<(usize, SocketAddr)> {
        if !self.shared {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this group serves one listener",
            ));
        }
        if self.stopping.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        let backlog = self.cfg.telemetry.live().backlog();
        let b = bind_socks(socket, self.shareds.len(), self.workers.len(), backlog)?;
        let addr = b.addr;
        Ok((self.install(b, acceptor)?, addr))
    }

    fn remove_listener(&self, key: usize, drain: Option<Duration>) -> io::Result<()> {
        if self.stopping.load(Ordering::SeqCst) {
            return Ok(());
        }
        {
            let mut ls = lock(&self.listeners);
            let Some(l) = ls.get_mut(key) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such listener"));
            };
            if l.unlisted {
                return Ok(());
            }
            l.unlisted = true;
            // Closed here, as `stop_listening` does: no wait is left for `await_listener_removed`.
            for j in &l.jobs {
                j.close();
            }
        }
        for sh in &self.shareds {
            sh.post(RCmd::StopListening {
                lid: Some(key),
                drain,
                exit: false,
            });
        }
        Ok(())
    }

    fn set_listener_filter(&self, key: usize, filter: Option<AcceptFilter>) -> io::Result<()> {
        let ls = lock(&self.listeners);
        let Some(l) = ls.get(key) else {
            return Err(not_listening());
        };
        l.filter.set(filter);
        Ok(())
    }

    fn finished(&self) -> bool {
        self.started.load(Ordering::Acquire)
            && lock(&self.slots).iter().all(|s| {
                s.pending.is_none() && s.handle.as_ref().is_none_or(JoinHandle::is_finished)
            })
            && self.workers.drivers_done()
    }

    fn loop_stats(&self) -> Vec<Arc<LoopStats>> {
        let mut v = self.workers.stats().to_vec();
        v.extend(self.shareds.iter().map(|s| s.stats.clone()));
        v
    }

    fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        for sh in &self.shareds {
            sh.post(RCmd::Shutdown);
        }
    }

    fn join(&self) {
        let handles: Vec<JoinHandle<()>> = lock(&self.slots)
            .iter_mut()
            .filter_map(|s| s.handle.take())
            .collect();
        let any = !handles.is_empty();
        for h in handles {
            let _ = h.join();
        }
        if self.started.load(Ordering::Acquire) {
            // Driver mode: the workers drain the pollers; wait until every one has finished.
            while !self.workers.drivers_done() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        if any || self.started.load(Ordering::Acquire) {
            self.workers.stop_and_join();
            // Break the cycle poller -> table -> connection -> poller.
            for sh in &self.shareds {
                sh.clear_table();
            }
        }
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        match akio_sys::connect_nonblocking(addr) {
            Ok(s) => poller::post_dial(self.next_poller(), s, acceptor, on_error, false, None),
            Err(e) => on_error(e),
        }
    }

    fn dial_with(
        &self,
        addr: SocketAddr,
        opts: akio_core::DialOptions,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        match akio_sys::connect_nonblocking(addr) {
            Ok(s) => poller::post_dial(
                self.next_poller(),
                s,
                acceptor,
                on_error,
                false,
                opts.connect_timeout,
            ),
            Err(e) => on_error(e),
        }
    }

    fn dial_stream(
        &self,
        stream: std::net::TcpStream,
        _addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        poller::post_dial(self.next_poller(), stream, acceptor, on_error, false, None);
    }

    fn dial_unix(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        poller::post_dial(self.next_poller(), stream, acceptor, on_error, true, None);
    }

    fn adopt(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        if let Err(e) = stream.set_nonblocking(true) {
            return on_error(e);
        }
        poller::post_dial(self.next_poller(), stream, acceptor, on_error, false, None);
    }
}
