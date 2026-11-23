use std::{
    io,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use std::panic::AssertUnwindSafe;

use akio_core::{
    Config, DatagramPort, DatagramSender, DatagramsFactory, DynAcceptor, Group, LoopMeta,
    LoopStats, Pool,
};

use crate::reactor::{Cmd, Loop, LoopShared, RingPlace, Roster};
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

/// A group of io_uring I/O threads serving one listener.
pub struct UringGroup {
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
    // Wrapped as before this group could grow (no unwinding crosses these): the group stays
    // `UnwindSafe` although `Config` and the acceptor hold trait objects.
    cfg: AssertUnwindSafe<Arc<Config>>,
    pool: Arc<Pool>,
    acceptor: AssertUnwindSafe<Option<Arc<dyn DynAcceptor>>>,
    opts: UringOptions,
    /// A datagram listener's sender (on loop 0's socket), ADR-065. Such a group keeps its
    /// thread count (a socket added to or removed from the `SO_REUSEPORT` group would move
    /// peers between threads, as for the UDP listeners).
    sender: Option<DatagramSender>,
}

/// How the loops of a group get their listening sockets.
enum Listening {
    /// Client-only group.
    None,
    /// One `SO_REUSEPORT` socket per loop index ever used, bound when the group first
    /// grows to that index; each lives in exactly one active loop (or is on its way between
    /// two).
    ReusePort,
    /// Clones of one inherited socket; the group keeps one to clone for loops it adds, until
    /// shutdown.
    Shared(Option<TcpListener>),
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
/// `shutdown`).
struct State {
    slots: Vec<LoopSlot>,
    /// Loops `0..active` are active; the rest are retiring or exited.
    active: usize,
    listening: Listening,
    stopping: bool,
}

impl std::fmt::Debug for UringGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringGroup").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
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
        let threads = threads.max(1);
        let mut listeners: Vec<Option<TcpListener>> = (0..threads).map(|_| None).collect();
        let mut addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut acceptor = None;
        let mut listening = Listening::None;
        if let Some((a, acc)) = listen {
            let first = akio_sys::listen(a, true, cfg.backlog)?;
            addr = first.local_addr()?;
            for slot in listeners.iter_mut().skip(1) {
                *slot = Some(akio_sys::listen(addr, true, cfg.backlog)?);
            }
            listeners[0] = Some(first);
            acceptor = Some(acc);
            listening = Listening::ReusePort;
        }
        let fds = listeners
            .iter()
            .flatten()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .collect();
        Self::assemble(listeners, addr, fds, acceptor, listening, cfg, pool, opts)
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
            opts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        listeners: Vec<Option<TcpListener>>,
        addr: SocketAddr,
        fds: Vec<i32>,
        acceptor: Option<Arc<dyn DynAcceptor>>,
        listening: Listening,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let roster = Arc::new(Roster::new(matches!(listening, Listening::ReusePort)));
        let n = listeners.len();
        let mut slots = Vec::with_capacity(n);
        for (thread, l) in listeners.into_iter().enumerate() {
            let ls = l.map(|l| vec![(thread, l)]).unwrap_or_default();
            slots.push(Self::make_loop(
                thread,
                None,
                ls,
                &acceptor,
                &roster,
                addr,
                &cfg,
                &pool,
                &opts,
                &RingPlace::default(),
            )?);
        }
        roster.set(slots.iter().map(|s| s.shared.clone()).collect());
        Ok(UringGroup {
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
            cfg: AssertUnwindSafe(cfg),
            pool,
            acceptor: AssertUnwindSafe(acceptor),
            opts,
            sender: None,
        })
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
        let none = (0..threads).map(|_| None).collect();
        let mut g = Self::assemble(none, bound, fds, None, Listening::None, cfg, pool, opts)?;
        let cfg = g.cfg.0.clone();
        let mut sender = None;
        {
            let mut st = lock(&g.state);
            for (slot, sock) in st.slots.iter_mut().zip(socks) {
                let port =
                    DatagramPort::new(sock, &factory, slot.shared.stats.clone(), cfg.clone())?;
                sender.get_or_insert_with(|| port.sender());
                if let Some(lp) = slot.pending.as_mut() {
                    lp.add_port(port);
                }
            }
        }
        g.sender = sender;
        Ok(g)
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
        opts: &UringOptions,
        place: &RingPlace,
    ) -> io::Result<LoopSlot> {
        let sh = match stats {
            Some(st) => LoopShared::with_stats(pool.clone(), cfg, st)?,
            None => {
                // A listener (TCP, or a datagram socket) has a port; a client-only group not.
                let listener = (addr.port() != 0).then_some(addr);
                let meta = LoopMeta::new("io_uring", listener, thread);
                LoopShared::new(pool.clone(), cfg, meta)?
            }
        };
        let lp = Loop::new(
            sh.clone(),
            listeners,
            acceptor.clone(),
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
                        own.push((i, akio_sys::listen(self.addr, true, backlog)?));
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
        let stream = match akio_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        self.post_dial(Cmd::Dial {
            stream,
            acceptor,
            on_error,
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
