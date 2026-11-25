use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use akio_core::{
    AcceptFilter, Config, Countdown, DynAcceptor, FilterCell, Group, ListenSocket, LoopMeta,
    LoopStats, Pool,
};
use akio_sys::Poller;

use crate::reactor::{Cmd, Ear, Loop, LoopShared, Roster, Sock};

/// A group of epoll/kqueue I/O threads serving one listener, several listeners (a shared group,
/// ADR-130), or only dialed connections.
pub struct EpollGroup {
    /// The listener's address when the group was built for one (`Group::local_addr`); the
    /// unspecified address for shared and client-only groups.
    addr: SocketAddr,
    /// That listener's fds in loop order when they form a `SO_REUSEPORT` group (Linux), as bound.
    fds: Vec<i32>,
    /// The listener the threads report in their `LoopMeta` (one-listener groups).
    meta_listener: Option<SocketAddr>,
    /// The active loops (dials, listener handover).
    roster: Arc<Roster>,
    state: Mutex<State>,
    started: AtomicBool,
    /// CPU set per loop index ([`Group::pin_threads`]), applied to each loop thread when it starts
    /// (also loops added later by `set_threads`).
    pins: Mutex<Vec<Vec<usize>>>,
    cfg: Arc<Config>,
    pool: Arc<Pool>,
    /// Serves listeners (not a client-only group).
    listens: bool,
    /// A shared group (ADR-130): listeners are added and removed, the threads stay until the
    /// engine shuts down.
    shared: bool,
}

/// How the loops of a group get one listener's sockets.
enum Listening {
    /// One `SO_REUSEPORT` socket per loop index (Linux), bound for indices `0..bound` so far;
    /// each lives in exactly one active loop (or is on its way between two).
    ReusePort { bound: usize },
    /// Clones of one socket (elsewhere, an inherited socket or a Unix-domain one); the group
    /// keeps one to clone for loops it adds, until the listener is removed or shutdown.
    Shared(Option<TcpListener>),
}

/// One listener of the group (ADR-130).
struct GListener {
    ear: Arc<Ear>,
    listening: Listening,
    /// Removed (`Group::remove_listener` or `stop_listening`).
    unlisted: bool,
    /// The loops still to close its sockets after `remove_listener`, for
    /// `Group::await_listener_removed`.
    unlisting: Option<Countdown>,
}

/// One loop index of the group.
struct LoopSlot {
    shared: Arc<LoopShared>,
    /// Built, not started yet.
    pending: Option<Loop>,
    handle: Option<JoinHandle<()>>,
}

/// The resizable part of a group, changed only under its lock (`set_threads`, `start`,
/// `shutdown`, listeners added and removed).
struct State {
    slots: Vec<LoopSlot>,
    /// Loops `0..active` are active; the rest are retiring or exited.
    active: usize,
    /// The listeners, by key (`lid`); removed ones stay, marked.
    listeners: Vec<GListener>,
    stopping: bool,
    /// Every listener was removed (`Group::stop_listening`, ADR-099).
    unlisted: bool,
    /// The loops still to stop their listening sockets after `stop_listening`, for
    /// `Group::await_unlisted`.
    unlisting: Option<Countdown>,
}

impl State {
    /// What a loop built now must know: the listeners still served, by key.
    fn ears(&self) -> Vec<Option<Arc<Ear>>> {
        self.listeners
            .iter()
            .map(|l| (!l.unlisted).then(|| l.ear.clone()))
            .collect()
    }
}

/// A listener's sockets, bound for `n` loops, before it joins a group.
struct Bound {
    addr: SocketAddr,
    unix: bool,
    listening: Listening,
    /// Loop `i` gets `socks[i]`.
    socks: Vec<TcpListener>,
}

impl Bound {
    fn new(socket: ListenSocket, n: usize, backlog: i32) -> io::Result<Bound> {
        let n = n.max(1);
        let clones = |l: TcpListener| -> io::Result<(Vec<TcpListener>, TcpListener)> {
            l.set_nonblocking(true)?;
            let mut v = Vec::with_capacity(n);
            for _ in 1..n {
                v.push(l.try_clone()?);
            }
            let base = l.try_clone()?;
            v.insert(0, l);
            Ok((v, base))
        };
        match socket {
            ListenSocket::Bind(a) if cfg!(target_os = "linux") => {
                // One listener per loop: a `SO_REUSEPORT` group.
                let first = akio_sys::listen(a, true, backlog)?;
                let addr = first.local_addr()?;
                let mut socks = vec![first];
                for _ in 1..n {
                    socks.push(akio_sys::listen(addr, true, backlog)?);
                }
                Ok(Bound {
                    addr,
                    unix: false,
                    listening: Listening::ReusePort { bound: n },
                    socks,
                })
            }
            ListenSocket::Bind(a) => {
                let first = akio_sys::listen(a, false, backlog)?;
                let addr = first.local_addr()?;
                let (socks, base) = clones(first)?;
                Ok(Bound {
                    addr,
                    unix: false,
                    listening: Listening::Shared(Some(base)),
                    socks,
                })
            }
            ListenSocket::Inherited(l) => {
                let addr = l.local_addr()?;
                let (socks, base) = clones(l)?;
                Ok(Bound {
                    addr,
                    unix: false,
                    listening: Listening::Shared(Some(base)),
                    socks,
                })
            }
            ListenSocket::Unix(l) => {
                let (socks, base) = clones(l)?;
                Ok(Bound {
                    addr: akio_core::UNIX_ADDR,
                    unix: true,
                    listening: Listening::Shared(Some(base)),
                    socks,
                })
            }
        }
    }

    /// Their fds when they form a `SO_REUSEPORT` group.
    fn fds(&self) -> Vec<i32> {
        match self.listening {
            Listening::ReusePort { .. } => self.socks.iter().map(|l| l.as_raw_fd()).collect(),
            Listening::Shared(_) => Vec::new(),
        }
    }
}

impl std::fmt::Debug for EpollGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpollGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn not_listening() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not a listener group")
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
        match listen {
            Some((a, acc)) => Self::one(ListenSocket::Bind(a), acc, threads, cfg, pool),
            None => Self::assemble(threads, None, false, false, cfg, pool),
        }
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
        Self::one(
            ListenSocket::Inherited(listener),
            acceptor,
            threads,
            cfg,
            pool,
        )
    }

    /// Serves a listening Unix-domain stream socket (ADR-121, `akio_sys::listen_unix`) as
    /// [`bind_listener`](Self::bind_listener) serves an inherited one: `threads` loops share it.
    /// Its connections are accepted without reading an address; their `peer_addr` and
    /// `local_addr`, and the group's, are [`akio_core::UNIX_ADDR`].
    pub fn bind_unix_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        Self::one(ListenSocket::Unix(listener), acceptor, threads, cfg, pool)
    }

    /// A shared group of `threads` loops (ADR-130): it starts with no listener; listeners join
    /// with [`Group::add_listener`] and leave with [`Group::remove_listener`], and the threads
    /// serve them all until shutdown. Its `local_addr` is the unspecified address and its
    /// threads report no listener in their `LoopMeta`.
    pub fn shared(threads: usize, cfg: Config, pool: Arc<Pool>) -> io::Result<EpollGroup> {
        Self::assemble(threads, None, true, true, cfg, pool)
    }

    /// A group of `threads` loops serving the one listener `socket`.
    fn one(
        socket: ListenSocket,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        let b = Bound::new(socket, threads, cfg.backlog)?;
        let mut g = Self::assemble(threads, Some(b.addr), true, false, cfg, pool)?;
        g.addr = b.addr;
        g.fds = b.fds();
        let mut st = lock(&g.state);
        Self::install(&mut st, b, acceptor);
        drop(st);
        Ok(g)
    }

    fn assemble(
        threads: usize,
        meta_listener: Option<SocketAddr>,
        listens: bool,
        shared: bool,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let roster = Arc::new(Roster::new());
        let n = threads.max(1);
        let mut slots = Vec::with_capacity(n);
        for thread in 0..n {
            slots.push(Self::make_loop(
                thread,
                None,
                Vec::new(),
                Vec::new(),
                &roster,
                meta_listener,
                &cfg,
                &pool,
            )?);
        }
        roster.set(slots.iter().map(|s| s.shared.clone()).collect());
        Ok(EpollGroup {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            fds: Vec::new(),
            meta_listener,
            roster,
            state: Mutex::new(State {
                slots,
                active: n,
                listeners: Vec::new(),
                stopping: false,
                unlisted: false,
                unlisting: None,
            }),
            started: AtomicBool::new(false),
            pins: Mutex::new(Vec::new()),
            cfg,
            pool,
            listens,
            shared,
        })
    }

    /// Makes `b` a listener of the group: every loop learns it, active loop `i` gets socket
    /// `b.socks[i]`. Its key.
    fn install(st: &mut State, b: Bound, acceptor: Arc<dyn DynAcceptor>) -> usize {
        let lid = st.listeners.len();
        let reuseport = matches!(b.listening, Listening::ReusePort { .. });
        let ear = Arc::new(Ear {
            acceptor,
            filter: Arc::new(FilterCell::default()),
            unix: b.unix,
            reuseport,
            addr: b.addr,
        });
        // Every loop, retiring ones too (they may be revived), before any socket: commands of
        // one loop run in order.
        for s in &st.slots {
            s.shared.post(Cmd::Listen {
                lid,
                ear: ear.clone(),
            });
        }
        for (i, l) in b.socks.into_iter().enumerate() {
            let sock = Sock {
                lid,
                idx: if reuseport { i } else { 0 },
            };
            st.slots[i].shared.post(Cmd::AddListener(sock, l));
        }
        st.listeners.push(GListener {
            ear,
            listening: b.listening,
            unlisted: false,
            unlisting: None,
        });
        lid
    }

    /// Builds loop `thread` (reusing the counters `stats` of an exited loop of that index).
    #[allow(clippy::too_many_arguments)]
    fn make_loop(
        thread: usize,
        stats: Option<Arc<LoopStats>>,
        listeners: Vec<(Sock, TcpListener)>,
        ears: Vec<Option<Arc<Ear>>>,
        roster: &Arc<Roster>,
        meta_listener: Option<SocketAddr>,
        cfg: &Arc<Config>,
        pool: &Arc<Pool>,
    ) -> io::Result<LoopSlot> {
        let poller = Poller::new()?;
        let sh = match stats {
            Some(st) => LoopShared::with_stats(&poller, pool.clone(), cfg, st)?,
            None => {
                let meta = LoopMeta::new(crate::reactor::BACKEND, meta_listener, thread);
                LoopShared::new(&poller, pool.clone(), cfg, meta)?
            }
        };
        let lp = Loop::new(
            poller,
            sh.clone(),
            listeners,
            ears,
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
            .name(format!("akio-io-{i}"))
            .spawn(move || {
                if !pin.is_empty() {
                    akio_sys::process::pin_current_thread(&pin).ok();
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
        let backlog = self.cfg.telemetry.live().backlog();
        while st.active < n {
            let i = st.active;
            let existed = i < st.slots.len();
            let revived = existed && st.slots[i].shared.try_revive();
            // Per listener: whether its `SO_REUSEPORT` socket `i` was bound before (it is then
            // held by some active loop, which passes it back below).
            let had: Vec<bool> = st
                .listeners
                .iter()
                .map(|l| matches!(l.listening, Listening::ReusePort { bound } if i < bound))
                .collect();
            // Sockets loop `i` gets now: new `SO_REUSEPORT` ones and clones.
            let mut own = Vec::new();
            for (lid, l) in st.listeners.iter_mut().enumerate() {
                if l.unlisted {
                    continue;
                }
                match &mut l.listening {
                    Listening::ReusePort { bound } if i >= *bound => {
                        own.push((
                            Sock { lid, idx: i },
                            akio_sys::listen(l.ear.addr, true, backlog)?,
                        ));
                        *bound = i + 1;
                    }
                    Listening::Shared(Some(base)) => {
                        own.push((Sock { lid, idx: 0 }, base.try_clone()?));
                    }
                    _ => {}
                }
            }
            if revived {
                // Still running (serving the connections it had): active again, and it knows
                // every listener (all loops are told of each).
                st.slots[i].shared.post(Cmd::Revive);
                for (sock, l) in own {
                    st.slots[i].shared.post(Cmd::AddListener(sock, l));
                }
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
                let mut slot = Self::make_loop(
                    i,
                    stats,
                    own,
                    st.ears(),
                    &self.roster,
                    self.meta_listener,
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
            // Socket `i` of a listener went to another loop when loop `i` retired: whichever
            // active loop holds it now passes it back. The socket stays open on its way, so
            // connections arriving meanwhile queue instead of being refused.
            let to = st.slots[i].shared.clone();
            for (lid, l) in st.listeners.iter().enumerate() {
                if had[lid] && !l.unlisted {
                    for s in &st.slots[..i] {
                        s.shared.post(Cmd::GiveListener {
                            sock: Sock { lid, idx: i },
                            to: to.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Shrinks to `n < st.active` loops: the highest ones retire.
    fn shrink(&self, st: &mut State, n: usize) {
        // Out of the roster first, so nothing is handed to a loop that is leaving.
        self.roster
            .set(st.slots[..n].iter().map(|s| s.shared.clone()).collect());
        for s in &st.slots[n..st.active] {
            s.shared.mark_retiring();
            s.shared.post(Cmd::Retire);
        }
        st.active = n;
    }

    /// Posts `StopListening` for listener `lid` (or all) to every loop; the countdown the
    /// running active ones drop once their sockets are closed.
    fn post_stop(st: &State, lid: Option<usize>, drain: Option<Duration>, exit: bool) -> Countdown {
        // The running active loops hold the listening sockets (and those on their way between
        // loops, posted to them ahead of this); a retiring loop handed its own on, and an exited
        // one acts on nothing, so the waits are for the former only.
        let done = Countdown::default();
        for (i, s) in st.slots.iter().enumerate() {
            let running = i < st.active && s.handle.is_some();
            s.shared.post(Cmd::StopListening {
                lid,
                drain,
                exit,
                done: running.then(|| done.token()),
            });
        }
        done
    }
}

impl Group for EpollGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }

    fn set_balance(&self, on: bool) {
        self.roster.set_balance(on);
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
        if st.unlisted {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the listener was removed",
            ));
        }
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

    fn stop_listening(&self, drain: Option<Duration>, exit_when_idle: bool) -> io::Result<()> {
        if !self.listens {
            return Err(not_listening());
        }
        let mut st = lock(&self.state);
        if st.stopping || st.unlisted {
            return Ok(());
        }
        st.unlisted = true;
        for l in &mut st.listeners {
            l.unlisted = true;
            if let Listening::Shared(base) = &mut l.listening {
                *base = None;
            }
        }
        if exit_when_idle {
            // Nothing is dialed here; an empty roster also closes a socket on its way between
            // loops (`Roster::forward_listener`).
            self.roster.set(Vec::new());
        }
        let done = Self::post_stop(&st, None, drain, exit_when_idle);
        st.unlisting = Some(done);
        Ok(())
    }

    fn await_unlisted(&self, limit: Duration) {
        let done = lock(&self.state).unlisting.take();
        // On an I/O thread (its own loop's among those waited for, perhaps): no waiting (rule 1).
        if let Some(done) = done {
            if !crate::reactor::on_loop_thread() {
                done.wait(limit);
            }
        }
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
        let mut st = lock(&self.state);
        if st.stopping {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        let b = Bound::new(socket, st.active, self.cfg.telemetry.live().backlog())?;
        let addr = b.addr;
        Ok((Self::install(&mut st, b, acceptor), addr))
    }

    fn remove_listener(&self, key: usize, drain: Option<Duration>) -> io::Result<()> {
        let mut st = lock(&self.state);
        if st.stopping {
            return Ok(());
        }
        let Some(l) = st.listeners.get_mut(key) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such listener"));
        };
        if l.unlisted {
            return Ok(());
        }
        l.unlisted = true;
        if let Listening::Shared(base) = &mut l.listening {
            *base = None;
        }
        let done = Self::post_stop(&st, Some(key), drain, false);
        st.listeners[key].unlisting = Some(done);
        Ok(())
    }

    fn await_listener_removed(&self, key: usize, limit: Duration) {
        let done = lock(&self.state)
            .listeners
            .get_mut(key)
            .and_then(|l| l.unlisting.take());
        if let Some(done) = done {
            if !crate::reactor::on_loop_thread() {
                done.wait(limit);
            }
        }
    }

    fn set_listener_filter(&self, key: usize, filter: Option<AcceptFilter>) -> io::Result<()> {
        let st = lock(&self.state);
        let Some(l) = st.listeners.get(key) else {
            return Err(not_listening());
        };
        l.ear.filter.set(filter);
        Ok(())
    }

    fn finished(&self) -> bool {
        self.started.load(Ordering::Acquire)
            && lock(&self.state).slots.iter().all(|s| {
                s.pending.is_none() && s.handle.as_ref().is_none_or(JoinHandle::is_finished)
            })
    }

    fn loop_stats(&self) -> Vec<Arc<LoopStats>> {
        lock(&self.state)
            .slots
            .iter()
            .map(|s| s.shared.stats.clone())
            .collect()
    }

    fn shutdown(&self) {
        let mut st = lock(&self.state);
        st.stopping = true;
        for l in &mut st.listeners {
            if let Listening::Shared(base) = &mut l.listening {
                // The loops' clones close as they drain; this one must not keep the socket open.
                *base = None;
            }
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
        let stream = match akio_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        self.post_dial(Cmd::Dial {
            stream,
            addr,
            acceptor,
            on_error,
            unix: false,
        });
    }

    fn dial_stream(
        &self,
        stream: std::net::TcpStream,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.post_dial(Cmd::Dial {
            stream,
            addr,
            acceptor,
            on_error,
            unix: false,
        });
    }

    fn dial_unix(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.post_dial(Cmd::Dial {
            stream,
            addr: akio_core::UNIX_ADDR,
            acceptor,
            on_error,
            unix: true,
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
            unix: false,
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
