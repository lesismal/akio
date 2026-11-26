use std::{
    io,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use std::panic::AssertUnwindSafe;

use akio_core::{
    AcceptFilter, Config, DatagramPort, DatagramSender, DatagramsFactory, DynAcceptor, FilterCell,
    Group, ListenSocket, LoopMeta, LoopStats, Pool,
};

use akio_core::Countdown;

use crate::reactor::{Cmd, Ear, Loop, LoopShared, RingPlace, Roster, Sock};
use crate::ring;
use akio_sys::ffi;

/// io_uring tuning.
#[derive(Clone, Debug, Default)]
pub struct UringOptions {
    /// Submission queue depth per I/O thread (0 = 1024).
    pub entries: u32,
    /// Use a kernel SQ polling thread (burns a core per ring; lowest latency).
    pub sqpoll: bool,
}

/// Checks that this kernel can run the backend: io_uring present, Linux 5.19+ (multishot accept
/// and recv with provided buffers) and the opcodes used. `Err` says what is missing. The probe
/// ring lives on a scratch thread, never the caller's (see `reactor::on_scratch_thread`).
pub fn probe() -> Result<(), String> {
    crate::reactor::on_scratch_thread(probe_here)
        .map_err(|e| format!("probe thread: {e}"))
        .and_then(|r| r)
}

fn probe_here() -> Result<(), String> {
    // SAFETY: `uname` fills the zeroed struct it is given.
    let mut u: ffi::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `u` is valid for writes.
    if unsafe { ffi::uname(&raw mut u) } != 0 {
        return Err("uname failed".into());
    }
    // SAFETY: the kernel NUL-terminates `release`.
    let rel = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy();
    let mut it = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let (maj, min): (u32, u32) = (
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    );
    if (maj, min) < (5, 19) {
        return Err(format!("kernel {rel} is older than 5.19"));
    }
    let ring = crate::reactor::make_ring_here(8, false, None)
        .map_err(|e| format!("io_uring_setup: {e}"))?
        .ring;
    if ring.features() & ring::FEAT_EXT_ARG == 0 {
        return Err("IORING_FEAT_EXT_ARG unsupported".into());
    }
    let probe = ring.probe().map_err(|e| format!("probe: {e}"))?;
    // The same setup the loops use, including a buffer ring (the registration must succeed on
    // the thread that owns a single-issuer ring, hence the enable call).
    ring.enable_rings().ok();
    crate::reactor::BufRing::new()
        .and_then(|b| b.register(&ring, crate::reactor::BGID))
        .map_err(|e| format!("buffer ring: {e}"))?;
    for (name, code) in [
        ("accept", ring::OP_ACCEPT),
        ("recv", ring::OP_RECV),
        ("poll_add", ring::OP_POLL_ADD),
        ("async_cancel", ring::OP_ASYNC_CANCEL),
        ("read", ring::OP_READ),
        ("send", ring::OP_SEND),
        ("sendmsg", ring::OP_SENDMSG),
    ] {
        if !probe.is_supported(code) {
            return Err(format!("opcode {name} unsupported"));
        }
    }
    Ok(())
}

/// Where loop `i` creates its ring, given the CPU sets `pins` of the group's loops: on its own
/// set, and with `sqpoll` its SQPOLL thread on one CPU of that set, the first for the first loop
/// with that set, the next for the next one (loops that share a whole-node set do not stack
/// their polling threads on one CPU).
fn ring_place(pins: &[Vec<usize>], i: usize, sqpoll: bool) -> RingPlace {
    let cpus = pins.get(i).cloned().unwrap_or_default();
    let sq_cpu = (sqpoll && !cpus.is_empty()).then(|| {
        let before = pins[..i].iter().filter(|s| **s == cpus).count();
        cpus[before % cpus.len()]
    });
    RingPlace { cpus, sq_cpu }
}

/// A group of io_uring I/O threads serving one listener, several listeners (a shared group,
/// ADR-130), a datagram listener, or only dialed connections.
pub struct UringGroup {
    /// The listener's address when the group was built for one (or a datagram listener's); the
    /// unspecified address for shared and client-only groups.
    addr: SocketAddr,
    /// That listener's fds in loop order when they form a `SO_REUSEPORT` group, as bound.
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
    // Wrapped as before this group could grow (no unwinding crosses it): the group stays
    // `UnwindSafe` although `Config` holds trait objects.
    cfg: AssertUnwindSafe<Arc<Config>>,
    pool: Arc<Pool>,
    opts: UringOptions,
    /// A datagram listener's sender (on loop 0's socket), ADR-065. Such a group keeps its
    /// thread count (a socket added to or removed from the `SO_REUSEPORT` group would move
    /// peers between threads, as for the UDP listeners).
    sender: Option<DatagramSender>,
    /// A datagram listener's accept filter (ADR-178), read by every loop's port.
    dgram_filter: Option<Arc<FilterCell>>,
    /// Serves TCP listeners (not a client-only or datagram group).
    listens: bool,
    /// A shared group (ADR-130): listeners are added and removed, the threads stay until the
    /// engine shuts down.
    shared: bool,
}

/// How the loops of a group get one listener's sockets.
enum Listening {
    /// One `SO_REUSEPORT` socket per loop index, bound for indices `0..bound` so far; each
    /// lives in exactly one active loop (or is on its way between two).
    ReusePort { bound: usize },
    /// Clones of one inherited or Unix-domain socket; the group keeps one to clone for loops it
    /// adds, until the listener is removed or shutdown.
    Shared(Option<TcpListener>),
}

/// One listener of the group (ADR-130).
struct GListener {
    ear: Arc<Ear>,
    listening: Listening,
    /// Removed (`Group::remove_listener` or `stop_listening`).
    unlisted: bool,
    /// The loops still to stop its sockets listening after `remove_listener`, for
    /// `Group::await_listener_removed`.
    unlisting: Option<Countdown>,
}

/// One loop index of the group.
struct LoopSlot {
    shared: Arc<LoopShared>,
    /// Built, not started yet.
    pending: Option<Loop>,
    /// The CPU its ring's SQPOLL thread is pinned to.
    sq_cpu: Option<usize>,
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
            ListenSocket::Bind(a) => {
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
            Listening::ReusePort { .. } => self
                .socks
                .iter()
                .map(std::os::fd::AsRawFd::as_raw_fd)
                .collect(),
            Listening::Shared(_) => Vec::new(),
        }
    }
}

impl std::fmt::Debug for UringGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn not_listening() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not a TCP listener group")
}

impl UringGroup {
    /// Binds `listen` (if any) and prepares `threads` rings. Nothing runs until [`Group::start`].
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        match listen {
            Some((a, acc)) => Self::one(ListenSocket::Bind(a), acc, threads, cfg, pool, opts),
            None => Self::assemble(threads, None, false, false, cfg, pool, opts),
        }
    }

    /// Serves an already bound and listening socket (one inherited from a supervisor process,
    /// say) with `threads` rings that share it, each accepting on its own clone of the socket.
    /// The socket is made non-blocking. The listener forms no `SO_REUSEPORT` group of this
    /// process, so [`Group::listener_fds`] is empty.
    pub fn bind_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        Self::one(
            ListenSocket::Inherited(listener),
            acceptor,
            threads,
            cfg,
            pool,
            opts,
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
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        Self::one(
            ListenSocket::Unix(listener),
            acceptor,
            threads,
            cfg,
            pool,
            opts,
        )
    }

    /// A shared group of `threads` rings (ADR-130): it starts with no listener; listeners join
    /// with [`Group::add_listener`] and leave with [`Group::remove_listener`], and the threads
    /// serve them all until shutdown. Its `local_addr` is the unspecified address and its
    /// threads report no listener in their `LoopMeta`.
    pub fn shared(
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        Self::assemble(threads, None, true, true, cfg, pool, opts)
    }

    /// A group of `threads` rings serving the one listener `socket`.
    fn one(
        socket: ListenSocket,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        let b = Bound::new(socket, threads, cfg.backlog)?;
        let mut g = Self::assemble(threads, Some(b.addr), true, false, cfg, pool, opts)?;
        g.addr = b.addr;
        g.fds = b.fds();
        let mut st = lock(&g.state);
        Self::install(&mut st, b, acceptor);
        drop(st);
        Ok(g)
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        threads: usize,
        meta_listener: Option<SocketAddr>,
        listens: bool,
        shared: bool,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
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
                &opts,
                &RingPlace::default(),
            )?);
        }
        roster.set(slots.iter().map(|s| s.shared.clone()).collect());
        Ok(UringGroup {
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
            cfg: AssertUnwindSafe(cfg),
            pool,
            opts,
            sender: None,
            dgram_filter: None,
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

    /// Binds `addr` for a connectionless datagram listener (ADR-065): `threads` rings, each
    /// polling its own `SO_REUSEPORT` UDP socket served by a
    /// [`DatagramsHandler`](akio_core::DatagramsHandler) from `factory`. Readiness comes from
    /// the ring (a one-shot `POLL_ADD`), the datagrams move with `recvmmsg` / `sendmmsg` as on
    /// epoll. The thread count is fixed (`Group::set_threads` is refused).
    pub fn bind_datagrams(
        addr: SocketAddr,
        factory: DatagramsFactory,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        let threads = threads.max(1);
        let first = akio_sys::listen_udp(addr, true)?;
        let bound = first.local_addr()?;
        let mut socks = vec![first];
        for _ in 1..threads {
            socks.push(akio_sys::listen_udp(bound, true)?);
        }
        let fds = socks.iter().map(std::os::fd::AsRawFd::as_raw_fd).collect();
        let mut g = Self::assemble(threads, Some(bound), false, false, cfg, pool, opts)?;
        g.addr = bound;
        g.fds = fds;
        let cfg = g.cfg.0.clone();
        let mut sender = None;
        let filter = Arc::new(FilterCell::default());
        {
            let mut st = lock(&g.state);
            for (slot, sock) in st.slots.iter_mut().zip(socks) {
                let port =
                    DatagramPort::new(sock, &factory, slot.shared.stats.clone(), cfg.clone())?
                        .with_filter(filter.clone());
                sender.get_or_insert_with(|| port.sender());
                if let Some(lp) = slot.pending.as_mut() {
                    lp.add_port(port);
                }
            }
        }
        g.sender = sender;
        g.dgram_filter = Some(filter);
        Ok(g)
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
        opts: &UringOptions,
        place: &RingPlace,
    ) -> io::Result<LoopSlot> {
        let sh = match stats {
            Some(st) => LoopShared::with_stats(pool.clone(), cfg, st)?,
            None => {
                let meta = LoopMeta::new("io_uring", meta_listener, thread);
                LoopShared::new(pool.clone(), cfg, meta)?
            }
        };
        let lp = Loop::new(
            sh.clone(),
            listeners,
            ears,
            roster.clone(),
            cfg.clone(),
            opts,
            place,
        )?;
        Ok(LoopSlot {
            shared: sh,
            sq_cpu: lp.sq_cpu(),
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

    /// Where loop `i` creates its ring ([`ring_place`]).
    fn place_of(&self, i: usize) -> RingPlace {
        ring_place(&lock(&self.pins), i, self.opts.sqpoll)
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
                    &self.opts,
                    &self.place_of(i),
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
    /// running active ones drop once their sockets stopped listening.
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

impl Group for UringGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }

    fn datagram_sender(&self) -> Option<DatagramSender> {
        self.sender.clone()
    }

    fn set_balance(&self, on: bool) {
        self.roster.set_balance(on);
    }

    fn pin_threads(&self, cpus: Vec<Vec<usize>>) {
        let mut st = lock(&self.state);
        *lock(&self.pins) = cpus;
        // Loops built but not started get a ring created on their CPU set (ADR-088, update):
        // the kernel allocates it on that node and pins an SQPOLL thread there. Best effort: a
        // loop whose ring cannot be recreated keeps the one it was built with.
        for (i, slot) in st.slots.iter_mut().enumerate() {
            let place = self.place_of(i);
            if place.cpus.is_empty() {
                continue;
            }
            if let Some(lp) = slot.pending.as_mut() {
                if lp.place_ring(&self.opts, &place).is_ok() {
                    slot.sq_cpu = lp.sq_cpu();
                }
            }
        }
    }

    fn sq_thread_cpus(&self) -> Vec<Option<usize>> {
        let st = lock(&self.state);
        st.slots[..st.active].iter().map(|s| s.sq_cpu).collect()
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
        if self.sender.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a datagram listener keeps its thread count",
            ));
        }
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
            // loops.
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
        if let Some(cell) = &self.dgram_filter {
            cell.set(filter);
            return Ok(());
        }
        if !self.listens {
            return Err(not_listening());
        }
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
            acceptor,
            on_error,
            unix: false,
            timeout: None,
        });
    }

    fn dial_with(
        &self,
        addr: SocketAddr,
        opts: akio_core::DialOptions,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        let stream = match akio_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        self.post_dial(Cmd::Dial {
            stream,
            acceptor,
            on_error,
            unix: false,
            timeout: opts.connect_timeout,
        });
    }

    fn dial_stream(
        &self,
        stream: std::net::TcpStream,
        _addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.post_dial(Cmd::Dial {
            stream,
            acceptor,
            on_error,
            unix: false,
            timeout: None,
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
            acceptor,
            on_error,
            unix: true,
            timeout: None,
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
        if let Err(e) = stream.set_nonblocking(true) {
            return on_error(e);
        }
        self.post_dial(Cmd::Dial {
            stream,
            acceptor,
            on_error,
            unix: false,
            timeout: None,
        });
    }
}

impl UringGroup {
    fn post_dial(&self, cmd: Cmd) {
        if let Err(Cmd::Dial { on_error, .. }) = self.roster.post_next(cmd) {
            on_error(io::Error::new(
                io::ErrorKind::NotConnected,
                "no I/O thread to serve the connection",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_place_spreads_sqpoll_threads_over_a_shared_set() {
        let node = vec![0, 1, 2, 3];
        let pins = vec![node.clone(), vec![4], node.clone(), node, vec![5, 6]];
        let at = |i, sqpoll| ring_place(&pins, i, sqpoll);
        // Each loop creates its ring on its own set.
        assert_eq!(at(1, false).cpus, vec![4]);
        assert_eq!(at(1, false).sq_cpu, None);
        // SQPOLL: the first loop with a set gets its first CPU, the next ones the next CPUs.
        assert_eq!(at(0, true).sq_cpu, Some(0));
        assert_eq!(at(1, true).sq_cpu, Some(4));
        assert_eq!(at(2, true).sq_cpu, Some(1));
        assert_eq!(at(3, true).sq_cpu, Some(2));
        assert_eq!(at(4, true).sq_cpu, Some(5));
        // Not pinned (no set, or past the end): no placement.
        assert_eq!(ring_place(&[], 0, true), RingPlace::default());
        assert_eq!(at(9, true), RingPlace::default());
        // A set shared by more loops than it has CPUs wraps.
        let one = vec![vec![7, 8]; 3];
        assert_eq!(ring_place(&one, 2, true).sq_cpu, Some(7));
    }
}
