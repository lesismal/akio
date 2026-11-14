//! One userspace stack per device, shared by every listener (group) on it: the I/O threads, the
//! command queues other threads post to, and the bookkeeping that ends the threads when the last
//! group has shut down.

use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Condvar, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{JoinHandle, Thread},
};

use only_core::{Config, DynAcceptor, LoopLink, LoopStats, Pool, Task, telemetry::LoopCmd};

use crate::{
    Device, DpdkConfig,
    device::{Inbox, Link, Port},
    lp::Loop,
};

pub(crate) enum Cmd {
    Wake(u64),
    Close(u64, Option<io::Error>),
    Task(u64, Task),
    /// A group starts using this loop (its listener, if any, is opened here).
    Attach(Arc<GroupSpec>),
    /// Graceful shutdown of one group.
    Shutdown(u64),
    Core(u64, LoopCmd),
    Dial {
        gid: u64,
        addr: SocketAddr,
        udp: bool,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
    /// The last group is gone: the thread ends.
    Exit,
}

/// The part of a loop other threads reach: its command queue and thread handle.
pub(crate) struct LoopShared {
    cmds: Mutex<Vec<Cmd>>,
    pending: AtomicBool,
    pub(crate) thread: OnceLock<Thread>,
}

impl LoopShared {
    fn new() -> Arc<LoopShared> {
        Arc::new(LoopShared {
            cmds: Mutex::new(Vec::new()),
            pending: AtomicBool::new(false),
            thread: OnceLock::new(),
        })
    }

    pub(crate) fn post(&self, cmd: Cmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        if !self.pending.swap(true, Ordering::AcqRel) {
            if let Some(t) = self.thread.get() {
                if t.id() != std::thread::current().id() {
                    t.unpark();
                }
            }
        }
    }

    /// Commands are waiting (one atomic load: checked on every poll iteration).
    pub(crate) fn has_cmds(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    pub(crate) fn take(&self) -> Vec<Cmd> {
        self.pending.store(false, Ordering::Release);
        std::mem::take(&mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

/// How the connections of one group on one loop reach that loop.
pub(crate) struct GroupLink {
    pub(crate) shared: Arc<LoopShared>,
    pub(crate) pool: Arc<Pool>,
    pub(crate) stats: Arc<LoopStats>,
}

impl LoopLink for GroupLink {
    fn wake_conn(&self, id: u64) {
        self.shared.post(Cmd::Wake(id));
    }
    fn close_conn(&self, id: u64, err: Option<io::Error>) {
        self.shared.post(Cmd::Close(id, err));
    }
    fn post_task(&self, id: u64, task: Task) {
        self.shared.post(Cmd::Task(id, task));
    }
    fn pool(&self) -> Option<&Pool> {
        Some(&self.pool)
    }
    fn stats(&self) -> Option<Arc<LoopStats>> {
        Some(self.stats.clone())
    }
}

/// What a group's listener serves.
pub(crate) struct Listen {
    pub(crate) udp: bool,
    pub(crate) port: u16,
    pub(crate) acceptor: Arc<dyn DynAcceptor>,
}

/// One group (listener) as the loops see it.
pub(crate) struct GroupSpec {
    pub(crate) gid: u64,
    pub(crate) listen: Option<Listen>,
    pub(crate) cfg: Arc<Config>,
    /// One per loop, in loop order.
    pub(crate) links: Vec<Arc<GroupLink>>,
    pub(crate) peers: AtomicUsize,
    pub(crate) rejected: AtomicU64,
    /// Loops still serving this group; 0 once it has shut down everywhere.
    left: Mutex<usize>,
    left_cv: Condvar,
}

impl GroupSpec {
    pub(crate) fn new(
        gid: u64,
        listen: Option<Listen>,
        cfg: Arc<Config>,
        links: Vec<Arc<GroupLink>>,
    ) -> GroupSpec {
        let n = links.len();
        GroupSpec {
            gid,
            listen,
            cfg,
            links,
            peers: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
            left: Mutex::new(n),
            left_cv: Condvar::new(),
        }
    }

    /// Blocks until every loop has finished this group.
    pub(crate) fn wait_done(&self) {
        let mut left = self.left.lock().unwrap_or_else(|p| p.into_inner());
        while *left > 0 {
            left = self.left_cv.wait(left).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// Shared between the stack handle and its loops (no reference to the loops themselves, so a
/// stack that never started is dropped normally).
pub(crate) struct StackCtl {
    pub(crate) shared: Vec<Arc<LoopShared>>,
    state: Mutex<CtlState>,
    next_ephemeral: AtomicU16,
    pub(crate) ip: Ipv4Addr,
}

struct CtlState {
    groups: usize,
    closed: bool,
    /// Ports bound by listeners: (udp, port).
    ports: HashSet<(bool, u16)>,
}

const EPHEMERAL_FIRST: u16 = 49152;

impl StackCtl {
    /// A free ephemeral port (dials, listeners on port 0).
    pub(crate) fn ephemeral(&self, udp: bool) -> u16 {
        loop {
            let p = self.next_ephemeral.fetch_add(1, Ordering::Relaxed);
            let p = if p < EPHEMERAL_FIRST {
                self.next_ephemeral
                    .store(EPHEMERAL_FIRST + 1, Ordering::Relaxed);
                EPHEMERAL_FIRST
            } else {
                p
            };
            let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !st.ports.contains(&(udp, p)) {
                return p;
            }
        }
    }

    /// A loop has finished `spec`. The last loop to finish the last group ends the stack.
    pub(crate) fn loop_done(&self, spec: &GroupSpec) {
        let mut left = spec.left.lock().unwrap_or_else(|p| p.into_inner());
        *left = left.saturating_sub(1);
        let last = *left == 0;
        drop(left);
        if !last {
            return;
        }
        let exit = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(l) = &spec.listen {
                st.ports.remove(&(l.udp, l.port));
            }
            st.groups = st.groups.saturating_sub(1);
            st.closed = st.groups == 0;
            st.closed
        };
        if exit {
            for s in &self.shared {
                s.post(Cmd::Exit);
            }
        }
        spec.left_cv.notify_all();
    }

    pub(crate) fn closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).closed
    }
}

/// A device's stack: created by the first group that names the device, shared by the others.
pub(crate) struct Stack {
    key: String,
    pub(crate) ctl: Arc<StackCtl>,
    pending: Mutex<Vec<Loop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
}

static REGISTRY: Mutex<Vec<(String, Weak<Stack>)>> = Mutex::new(Vec::new());

fn device_key(d: &Device) -> String {
    match d {
        Device::Dpdk(e) => format!("dpdk:{}", e.port),
        Device::Tap(n) => format!("tap:{n}"),
        Device::AfPacket(n) => format!("af_packet:{n}"),
        Device::Memory(m) => format!("memory:{}", m.id),
    }
}

impl Stack {
    /// The live stack for `cfg.device`, or a new one; registers a group on it and reserves
    /// `listen` (`(udp, port)`, port 0 = an ephemeral one). Returns the stack and the port.
    pub(crate) fn acquire(
        cfg: &DpdkConfig,
        listen: Option<(bool, u16)>,
    ) -> io::Result<(Arc<Stack>, u16)> {
        let key = device_key(&cfg.device);
        let mut reg = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
        reg.retain(|(_, w)| w.strong_count() > 0);
        let existing = reg
            .iter()
            .find(|(k, _)| *k == key)
            .and_then(|(_, w)| w.upgrade())
            .filter(|s| !s.ctl.closed());
        let stack = match existing {
            Some(s) => s,
            None => {
                let s = Arc::new(Stack::open(cfg, key.clone())?);
                reg.retain(|(k, _)| *k != key);
                reg.push((key, Arc::downgrade(&s)));
                s
            }
        };
        drop(reg);
        let port = match listen {
            Some((udp, 0)) => stack.ctl.ephemeral(udp),
            Some((_, p)) => p,
            None => 0,
        };
        let mut st = stack.ctl.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((udp, _)) = listen {
            if !st.ports.insert((udp, port)) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "{} port {port} is already served on this device",
                        if udp { "UDP" } else { "TCP" }
                    ),
                ));
            }
        }
        st.groups += 1;
        drop(st);
        Ok((stack, port))
    }

    fn open(cfg: &DpdkConfig, key: String) -> io::Result<Stack> {
        let (links, mac) = match &cfg.device {
            Device::Dpdk(eal) => {
                let info = crate::pmd::open(eal, cfg.mtu)?;
                let links = (0..info.queues)
                    .map(|q| Link::Dpdk(Box::new(crate::pmd::Queue::new(info.port, q))))
                    .collect();
                (links, cfg.mac.unwrap_or(info.mac))
            }
            #[cfg(target_os = "linux")]
            Device::Tap(name) => (vec![Link::tap(name)?], cfg.mac_or_derived()),
            #[cfg(target_os = "linux")]
            Device::AfPacket(name) => (vec![Link::af_packet(name)?], cfg.mac_or_derived()),
            #[cfg(not(target_os = "linux"))]
            Device::Tap(_) | Device::AfPacket(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TAP and AF_PACKET devices are Linux-only",
                ));
            }
            Device::Memory(m) => (vec![Link::Memory(m.clone())], cfg.mac_or_derived()),
        };
        let inboxes: Vec<Inbox> = links
            .iter()
            .map(|_| Arc::new(Mutex::new(VecDeque::new())))
            .collect();
        let shared: Vec<Arc<LoopShared>> = links.iter().map(|_| LoopShared::new()).collect();
        let ctl = Arc::new(StackCtl {
            shared: shared.clone(),
            state: Mutex::new(CtlState {
                groups: 0,
                closed: false,
                ports: HashSet::new(),
            }),
            next_ephemeral: AtomicU16::new(EPHEMERAL_FIRST),
            ip: cfg.address,
        });
        let mut loops = Vec::with_capacity(links.len());
        for (i, link) in links.into_iter().enumerate() {
            let siblings = inboxes
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, b)| b.clone())
                .collect();
            let port = Port::new(link, cfg.mtu, inboxes[i].clone(), siblings);
            loops.push(Loop::new(i, shared[i].clone(), ctl.clone(), port, mac, cfg));
        }
        Ok(Stack {
            key,
            ctl,
            pending: Mutex::new(loops),
            threads: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
        })
    }

    pub(crate) fn queues(&self) -> usize {
        self.ctl.shared.len()
    }

    /// Spawns the I/O threads (once, for the first group that starts).
    pub(crate) fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        let mut handles = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        for (i, mut l) in loops.into_iter().enumerate() {
            let h = std::thread::Builder::new()
                .name(format!("only-dpdk-{i}"))
                .spawn(move || l.run())?;
            // Set before the thread runs its first iteration's park, so posts can unpark it.
            let _ = self.ctl.shared[i].thread.set(h.thread().clone());
            handles.push(h);
        }
        Ok(())
    }

    pub(crate) fn started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// Joins the I/O threads once the stack has closed (the last group shut down).
    pub(crate) fn join_if_closed(&self) {
        if !self.ctl.closed() {
            return;
        }
        let handles = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
        for h in handles {
            let _ = h.join();
        }
    }
}

impl std::fmt::Debug for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stack")
            .field("device", &self.key)
            .finish_non_exhaustive()
    }
}
