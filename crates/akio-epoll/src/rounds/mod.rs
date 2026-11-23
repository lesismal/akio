//! Rounds scheduling (ADR-104): a few pollers report readiness, and each round of a
//! connection (read, handler, write) runs on whichever worker is free.

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
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

use akio_core::{Config, DynAcceptor, Group, LoopMeta, LoopStats, Pool};
use akio_sys::Poller;

use poller::{PollerShared, RCmd, RLoop};
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

/// A listener (or a client-only group) served by rounds scheduling.
pub struct RoundsGroup {
    addr: SocketAddr,
    fds: Vec<i32>,
    slots: Mutex<Vec<Slot>>,
    shareds: Vec<Arc<PollerShared>>,
    workers: Arc<Workers>,
    cfg: Arc<Config>,
    rr: AtomicUsize,
    started: AtomicBool,
    pins: Mutex<Vec<Vec<usize>>>,
}

impl std::fmt::Debug for RoundsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundsGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl RoundsGroup {
    /// Binds `listen` (if any) with `rc`'s pollers and workers. Nothing runs until
    /// [`Group::start`].
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        let (pollers, _) = rc.resolved();
        let mut listeners: Vec<Option<TcpListener>> = (0..pollers).map(|_| None).collect();
        let mut addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut acceptor = None;
        if let Some((a, acc)) = listen {
            let first = akio_sys::listen(a, cfg!(target_os = "linux"), cfg.backlog)?;
            addr = first.local_addr()?;
            for slot in listeners.iter_mut().skip(1) {
                *slot = Some(if cfg!(target_os = "linux") {
                    akio_sys::listen(addr, true, cfg.backlog)?
                } else {
                    first.try_clone()?
                });
            }
            listeners[0] = Some(first);
            acceptor = Some(acc);
        }
        let fds = if cfg!(target_os = "linux") {
            listeners.iter().flatten().map(|l| l.as_raw_fd()).collect()
        } else {
            Vec::new()
        };
        Self::assemble(listeners, addr, fds, acceptor, rc, cfg, pool)
    }

    /// Serves an already bound and listening socket: every poller polls a clone of it.
    pub fn bind_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let (pollers, _) = rc.resolved();
        let mut listeners = Vec::with_capacity(pollers);
        for _ in 1..pollers {
            listeners.push(Some(listener.try_clone()?));
        }
        listeners.insert(0, Some(listener));
        Self::assemble(listeners, addr, Vec::new(), Some(acceptor), rc, cfg, pool)
    }

    fn assemble(
        listeners: Vec<Option<TcpListener>>,
        addr: SocketAddr,
        fds: Vec<i32>,
        acceptor: Option<Arc<dyn DynAcceptor>>,
        rc: RoundsConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<RoundsGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let (_, nworkers) = rc.resolved();
        let listener_addr = acceptor.as_ref().map(|_| addr);
        let workers = Workers::new(nworkers, &cfg, listener_addr);
        let mut slots = Vec::with_capacity(listeners.len());
        for (i, l) in listeners.into_iter().enumerate() {
            let poller = Poller::new()?;
            // Pollers are numbered after the workers in the metrics of the listener.
            let meta = LoopMeta::new(BACKEND, listener_addr, nworkers + i);
            let stats = Arc::new(LoopStats::new(meta));
            let sh = PollerShared::new(&poller, pool.clone(), cfg.clone(), stats)?;
            let lp = RLoop::new(
                poller,
                sh.clone(),
                l.into_iter().collect(),
                acceptor.clone(),
                workers.clone(),
            )?;
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
                        })
                    })
                })
                .collect();
            workers.set_drivers(drivers);
        }
        Ok(RoundsGroup {
            addr,
            fds,
            shareds: slots.iter().map(|s| s.shared.clone()).collect(),
            slots: Mutex::new(slots),
            workers,
            cfg,
            rr: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            pins: Mutex::new(Vec::new()),
        })
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

    fn shutdown(&self) {
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
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        if any || self.started.load(Ordering::Acquire) {
            self.workers.stop_and_join();
        }
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        match akio_sys::connect_nonblocking(addr) {
            Ok(s) => poller::post_dial(self.next_poller(), s, acceptor, on_error),
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
        poller::post_dial(self.next_poller(), stream, acceptor, on_error);
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
        poller::post_dial(self.next_poller(), stream, acceptor, on_error);
    }
}
