use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use only_core::{Config, DynAcceptor, Group, LoopMeta, LoopStats, Pool};
use only_sys::Poller;

use crate::reactor::{Cmd, Loop, LoopShared, Roster};

/// A group of epoll/kqueue I/O threads serving one listener.
pub struct EpollGroup {
    addr: SocketAddr,
    /// Listener fds in loop order when they form a `SO_REUSEPORT` group (Linux), as bound.
    fds: Vec<i32>,
    /// The active loops (dials, listener handover).
    roster: Arc<Roster>,
    state: Mutex<State>,
    started: AtomicBool,
    /// CPU set per loop index ([`Group::pin_threads`]), applied to each loop thread when it starts
    /// (also loops added later by `set_threads`).
    pins: Mutex<Vec<Vec<usize>>>,
    cfg: Arc<Config>,
    pool: Arc<Pool>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
}

/// How the loops of a group get their listening sockets.
enum Listening {
    /// Client-only group.
    None,
    /// One `SO_REUSEPORT` socket per loop index ever used (Linux), bound when the group first
    /// grows to that index; each lives in exactly one active loop (or is on its way between
    /// two).
    ReusePort,
    /// Clones of one socket (elsewhere, or an inherited socket); the group keeps one to clone
    /// for loops it adds, until shutdown.
    Shared(Option<TcpListener>),
}

/// One loop index of the group.
struct LoopSlot {
    shared: Arc<LoopShared>,
    /// Built, not started yet.
    pending: Option<Loop>,
    handle: Option<JoinHandle<()>>,
}

/// The resizable part of a group, changed only under its lock (`set_threads`, `start`,
/// `shutdown`).
struct State {
    slots: Vec<LoopSlot>,
    /// Loops `0..active` are active; the rest are retiring or exited.
    active: usize,
    listening: Listening,
    stopping: bool,
}

impl std::fmt::Debug for EpollGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpollGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl EpollGroup {
    /// Binds `listen` (if any) and prepares `threads` loops. Nothing runs until [`Group::start`].
    ///
    /// With `listen == None` the group serves only dialed connections.
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        let threads = threads.max(1);
        // One listener per loop (Linux, SO_REUSEPORT) or clones of one (elsewhere).
        let mut listeners: Vec<Option<TcpListener>> = (0..threads).map(|_| None).collect();
        let mut addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut acceptor = None;
        let mut listening = Listening::None;
        if let Some((a, acc)) = listen {
            let first = only_sys::listen(a, cfg!(target_os = "linux"), cfg.backlog)?;
            addr = first.local_addr()?;
            for slot in listeners.iter_mut().skip(1) {
                *slot = Some(if cfg!(target_os = "linux") {
                    only_sys::listen(addr, true, cfg.backlog)?
                } else {
                    first.try_clone()?
                });
            }
            listening = if cfg!(target_os = "linux") {
                Listening::ReusePort
            } else {
                Listening::Shared(Some(first.try_clone()?))
            };
            listeners[0] = Some(first);
            acceptor = Some(acc);
        }
        let fds = if cfg!(target_os = "linux") {
            listeners.iter().flatten().map(|l| l.as_raw_fd()).collect()
        } else {
            Vec::new()
        };
        Self::assemble(listeners, addr, fds, acceptor, listening, cfg, pool)
    }

    /// Serves an already bound and listening socket (one inherited from a supervisor process,
    /// say) with `threads` loops that share it: each loop polls its own clone of the socket and
    /// they race to accept. The socket is made non-blocking. The listener forms no
    /// `SO_REUSEPORT` group of this process, so [`Group::listener_fds`] is empty.
    pub fn bind_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let mut listeners = Vec::with_capacity(threads.max(1));
        for _ in 1..threads.max(1) {
            listeners.push(Some(listener.try_clone()?));
        }
        let base = listener.try_clone()?;
        listeners.insert(0, Some(listener));
        Self::assemble(
            listeners,
            addr,
            Vec::new(),
            Some(acceptor),
            Listening::Shared(Some(base)),
            cfg,
            pool,
        )
    }

    fn assemble(
        listeners: Vec<Option<TcpListener>>,
        addr: SocketAddr,
        fds: Vec<i32>,
        acceptor: Option<Arc<dyn DynAcceptor>>,
        listening: Listening,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let roster = Arc::new(Roster::new(matches!(listening, Listening::ReusePort)));
        let n = listeners.len();
        let mut slots = Vec::with_capacity(n);
        for (thread, l) in listeners.into_iter().enumerate() {
            let ls = l.map(|l| vec![(thread, l)]).unwrap_or_default();
            slots.push(Self::make_loop(
                thread, None, ls, &acceptor, &roster, addr, &cfg, &pool,
            )?);
        }
        roster.set(slots.iter().map(|s| s.shared.clone()).collect());
        Ok(EpollGroup {
            addr,
            fds,
            roster,
            state: Mutex::new(State {
                slots,
                active: n,
                listening,
                stopping: false,
            }),
            started: AtomicBool::new(false),
            pins: Mutex::new(Vec::new()),
            cfg,
            pool,
            acceptor,
        })
    }

    /// Builds loop `thread` (reusing the counters `stats` of an exited loop of that index).
    #[allow(clippy::too_many_arguments)]
    fn make_loop(
        thread: usize,
        stats: Option<Arc<LoopStats>>,
        listeners: Vec<(usize, TcpListener)>,
        acceptor: &Option<Arc<dyn DynAcceptor>>,
        roster: &Arc<Roster>,
        addr: SocketAddr,
        cfg: &Arc<Config>,
        pool: &Arc<Pool>,
    ) -> io::Result<LoopSlot> {
        let poller = Poller::new()?;
        let sh = match stats {
            Some(st) => LoopShared::with_stats(&poller, pool.clone(), cfg, st)?,
            None => {
                let listener = acceptor.as_ref().map(|_| addr);
                let meta = LoopMeta::new(crate::reactor::BACKEND, listener, thread);
                LoopShared::new(&poller, pool.clone(), cfg, meta)?
            }
        };
        let lp = Loop::new(
            poller,
            sh.clone(),
            listeners,
            acceptor.clone(),
            roster.clone(),
            cfg.clone(),
        )?;
        Ok(LoopSlot {
            shared: sh,
            pending: Some(lp),
            handle: None,
        })
    }

    /// Starts built loop `i`, pinned to `pin` (best effort: a thread that cannot be pinned runs
    /// unpinned; empty means unpinned).
    fn spawn(i: usize, slot: &mut LoopSlot, pin: Vec<usize>) -> io::Result<()> {
        let Some(mut l) = slot.pending.take() else {
            return Ok(());
        };
        slot.shared.stats.set_running(true);
        match std::thread::Builder::new()
            .name(format!("only-io-{i}"))
            .spawn(move || {
                if !pin.is_empty() {
                    only_sys::process::pin_current_thread(&pin).ok();
                }
                l.run();
            }) {
            Ok(h) => {
                slot.handle = Some(h);
                Ok(())
            }
            Err(e) => {
                slot.shared.stats.set_running(false);
                Err(e)
            }
        }
    }

    /// The CPU set loop `i` is pinned to (empty: not pinned).
    fn pin_of(&self, i: usize) -> Vec<usize> {
        lock(&self.pins).get(i).cloned().unwrap_or_default()
    }

    /// Grows to `n > st.active` loops.
    fn grow(&self, st: &mut State, n: usize) -> io::Result<()> {
        while st.active < n {
            let i = st.active;
            // `ReusePort` keeps one listening socket per loop index ever used, so loop `i`
            // existed before exactly when listener `i` did.
            let existed = i < st.slots.len();
            let revived = existed && st.slots[i].shared.try_revive();
            if revived {
                // Still running (serving the connections it had): active again.
                st.slots[i].shared.post(Cmd::Revive);
            } else {
                // A new loop, with the counters of the exited one of this index if any.
                let stats = match st.slots.get_mut(i) {
                    Some(old) => {
                        // It committed to exiting with no connection left: this join is short.
                        if let Some(h) = old.handle.take() {
                            let _ = h.join();
                        }
                        Some(old.shared.stats.clone())
                    }
                    None => None,
                };
                let mut own = Vec::new();
                match &st.listening {
                    Listening::Shared(Some(base)) => own.push((0, base.try_clone()?)),
                    Listening::ReusePort if !existed => {
                        let backlog = self.cfg.telemetry.live().backlog();
                        own.push((i, only_sys::listen(self.addr, true, backlog)?));
                    }
                    _ => {}
                }
                let mut slot = Self::make_loop(
                    i,
                    stats,
                    own,
                    &self.acceptor,
                    &self.roster,
                    self.addr,
                    &self.cfg,
                    &self.pool,
                )?;
                Self::spawn(i, &mut slot, self.pin_of(i))?;
                if existed {
                    st.slots[i] = slot;
                } else {
                    st.slots.push(slot);
                }
            }
            // The roster first: from now on a listening socket on its way to some loop is
            // routed home (`Roster::route`).
            st.active += 1;
            self.roster.set(
                st.slots[..st.active]
                    .iter()
                    .map(|s| s.shared.clone())
                    .collect(),
            );
            match &st.listening {
                // Listener `i` went to another loop when loop `i` retired: whichever active
                // loop holds it now passes it back. The socket stays open on its way, so
                // connections arriving meanwhile queue instead of being refused.
                Listening::ReusePort if existed => {
                    let to = st.slots[i].shared.clone();
                    for s in &st.slots[..i] {
                        s.shared.post(Cmd::GiveListener {
                            idx: i,
                            to: to.clone(),
                        });
                    }
                }
                Listening::Shared(Some(base)) if revived => {
                    st.slots[i]
                        .shared
                        .post(Cmd::AddListener(0, base.try_clone()?));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Shrinks to `n < st.active` loops: the highest ones retire.
    fn shrink(&self, st: &mut State, n: usize) {
        let forward = matches!(st.listening, Listening::ReusePort);
        // Out of the roster first, so nothing is handed to a loop that is leaving.
        self.roster
            .set(st.slots[..n].iter().map(|s| s.shared.clone()).collect());
        for s in &st.slots[n..st.active] {
            s.shared.mark_retiring();
            s.shared.post(Cmd::Retire { forward });
        }
        st.active = n;
    }
}

impl Group for EpollGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }

    fn pin_threads(&self, cpus: Vec<Vec<usize>>) {
        *lock(&self.pins) = cpus;
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut st = lock(&self.state);
        // Running from now on: requests posted before a thread is first scheduled are queued.
        for (i, slot) in st.slots.iter_mut().enumerate() {
            Self::spawn(i, slot, self.pin_of(i))?;
        }
        Ok(())
    }

    fn threads(&self) -> usize {
        lock(&self.state).active
    }

    fn set_threads(&self, n: usize) -> io::Result<()> {
        let n = n.max(1);
        let mut st = lock(&self.state);
        if st.stopping {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        if !self.started.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "start the engine before changing its thread count",
            ));
        }
        match n.cmp(&st.active) {
            std::cmp::Ordering::Greater => self.grow(&mut st, n),
            std::cmp::Ordering::Less => {
                self.shrink(&mut st, n);
                Ok(())
            }
            std::cmp::Ordering::Equal => Ok(()),
        }
    }

    fn shutdown(&self) {
        let mut st = lock(&self.state);
        st.stopping = true;
        if let Listening::Shared(base) = &mut st.listening {
            // The loops' clones close as they drain; this one must not keep the socket open.
            *base = None;
        }
        for s in &st.slots {
            s.shared.post(Cmd::Shutdown);
        }
    }

    fn join(&self) {
        let handles: Vec<JoinHandle<()>> = lock(&self.state)
            .slots
            .iter_mut()
            .filter_map(|s| s.handle.take())
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        let stream = match only_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        self.post_dial(Cmd::Dial {
            stream,
            addr,
            acceptor,
            on_error,
        });
    }

    fn adopt(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // A connected stream goes through the dial path: it is writable at once and has no
        // pending error, so the loop opens it right away.
        let addr = match stream.peer_addr() {
            Ok(a) => a,
            Err(e) => return on_error(e),
        };
        if let Err(e) = stream.set_nonblocking(true) {
            return on_error(e);
        }
        self.post_dial(Cmd::Dial {
            stream,
            addr,
            acceptor,
            on_error,
        });
    }
}

impl EpollGroup {
    fn post_dial(&self, cmd: Cmd) {
        if let Err(Cmd::Dial { on_error, .. }) = self.roster.post_next(cmd) {
            on_error(io::Error::new(
                io::ErrorKind::NotConnected,
                "no I/O thread to serve the connection",
            ));
        }
    }
}
