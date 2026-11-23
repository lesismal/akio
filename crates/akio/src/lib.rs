#![forbid(unsafe_code)]
//! `akio`: an event-driven network library. This facade crate re-exports the core API and
//! provides [`Engine`], which composes one backend *group* per listener (ADR-004).
//!
//! ```no_run
//! use akio::{Conn, Engine, Handler, Listener, fn_acceptor};
//!
//! struct Echo;
//! impl Handler for Echo {
//!     fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
//!         let _ = c.send(data); // non-blocking, inline on the I/O thread
//!     }
//! }
//!
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("127.0.0.1:8080".parse().unwrap()).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Guide: [Concepts](https://lesismal.github.io/akio/en/concepts/index.html), [Getting started](https://lesismal.github.io/akio/en/getting-started.html)
//! (中文: [核心概念](https://lesismal.github.io/akio/zh-CN/concepts/index.html)、[快速上手](https://lesismal.github.io/akio/zh-CN/getting-started.html)).
#![warn(clippy::unwrap_used)]

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

pub mod dns;
pub mod numa;

/// TLS: wrap an acceptor in [`tls::Tls`] to serve or dial over TLS (configs: [`tls::ServerConfig`],
/// [`tls::ClientConfig`]).
pub use akio_tls as tls;

/// BPF acceleration (ADR-006): `SO_REUSEPORT` steering programs (used by [`Accel::Ebpf`]) and
/// the in-kernel sockmap [`ebpf::Relay`] for proxies.
pub use akio_ebpf as ebpf;

/// Logging (the `akio-log` facade): `akio` logs under the targets `akio`, `akio_http::access`
/// ... Install a logger with [`log::init`] (formatted lines on stderr) or [`log::set_logger`];
/// [`Config::log_level`] sets the maximum level. With the `log` cargo feature, records go to
/// the `log` crate's logger instead while none is installed here.
pub use akio_log as log;

/// Kernel bypass (experimental, cargo feature `dpdk`): configuration of [`Backend::Dpdk`], a
/// userspace TCP/IP stack over DPDK ports (feature `dpdk-pmd`), TAP, AF_PACKET or in-memory
/// devices.
#[cfg(feature = "dpdk")]
pub use akio_dpdk as dpdk;

pub use akio_core::{
    Acceptor, AnyAcceptor, Config, Conn, ConnInfo, DatagramSender, Datagrams, DatagramsHandler,
    DatagramsIter, Error, FnAcceptor, Handler, IcmpError, Live, LoopCounters, LoopMeta,
    LoopMetrics, Metrics, Part, PoolConfig, PoolStats, ReloadReport, Replies, ResponseSlot,
    ResponseStream, Result, SharedBuf, SlowCallback, SlowHook, SlowRecord, Telemetry, Transport,
    UdpBinding, UdpStats, fn_acceptor, metrics, telemetry,
};
use akio_core::{DatagramsFactory, Group, Pool, datagrams_factory, telemetry::log_or_stderr};
#[doc(hidden)]
pub use akio_core::{DynAcceptor, DynHandler};
pub use numa::{NumaConfig, NumaPlacement, NumaReport, NumaStatus, ThreadPlacement};

/// I/O backend of one listener (ADR-004).
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum Backend {
    /// epoll on Linux, kqueue on macOS. The default.
    #[default]
    Epoll,
    /// io_uring (Linux 5.19+). Where the kernel lacks it the listener falls back to epoll, unless
    /// [`UringConfig::strict`] is set, in which case `build` fails with `Unsupported`.
    IoUring(UringConfig),
    /// Kernel bypass (experimental, cargo feature `dpdk`): `akio`'s own userspace TCP/IP stack
    /// over a DPDK port, TAP, AF_PACKET or in-memory device; see [`dpdk`]. TCP and UDP
    /// listeners, `dial` and `dial_udp` (IPv4). Listeners naming the same device share its
    /// stack and I/O threads (one per queue), so `Listener::threads` does not apply.
    #[cfg(feature = "dpdk")]
    Dpdk(dpdk::DpdkConfig),
}

/// io_uring tuning. `#[non_exhaustive]`: start from `UringConfig::default()` and set fields.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct UringConfig {
    /// Submission queue depth (0 = default).
    pub entries: u32,
    /// Use a kernel SQ polling thread.
    pub sqpoll: bool,
    /// Fail `build` instead of falling back to epoll when io_uring is unavailable.
    pub strict: bool,
}

/// How a TCP listener's connections are scheduled onto threads (ADR-102).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scheduling {
    /// Thread-per-core (ADR-001, the default): each connection belongs to one I/O thread, which
    /// reads it, runs its handler inline and writes it, for the connection's whole life.
    #[default]
    Loops,
    /// A pool of workers, one per CPU, runs each round of a connection (read, handler, write) on
    /// whichever worker is free, one round of a connection at a time; a worker with nothing to
    /// run waits for readiness in `epoll_wait` itself (as Tokio's runtime does). Spreads load by work rather than by connection, at the cost of a hand-off per
    /// round. epoll/kqueue only (not io_uring or DPDK); TCP only (UDP listeners keep their
    /// loops); [`Engine::set_threads`] is refused.
    Rounds(RoundsConfig),
}

/// Thread counts of [`Scheduling::Rounds`]. `#[non_exhaustive]`: start from
/// `RoundsConfig::default()` (or [`RoundsConfig::new`]) and set fields; 0 picks the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoundsConfig {
    /// epoll/kqueue instances the workers poll (default: 1). Each listener socket and
    /// connection belongs to one of them; more than one rarely helps (ADR-102).
    pub pollers: usize,
    /// Workers that run rounds (default: one per CPU).
    pub workers: usize,
}

impl RoundsConfig {
    /// `pollers` pollers and `workers` workers (0: the default).
    pub fn new(pollers: usize, workers: usize) -> RoundsConfig {
        RoundsConfig { pollers, workers }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn epoll(self) -> akio_epoll::RoundsConfig {
        akio_epoll::RoundsConfig::new(self.pollers, self.workers)
    }
}

/// Acceleration/steering layer, orthogonal to [`Backend`] (ADR-006).
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum Accel {
    /// No acceleration: plain `SO_REUSEPORT` hashing.
    #[default]
    None,
    /// BPF steering of new connections / UDP peers to I/O threads (Linux). Attaches what the
    /// kernel and privileges allow and otherwise keeps the kernel's default distribution; see
    /// [`Engine::accel_status`] for what was attached.
    Ebpf(EbpfConfig),
}

/// Configuration of [`Accel::Ebpf`]. `#[non_exhaustive]`: start from
/// `EbpfConfig::default()` and set fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EbpfConfig {
    /// How the listener's threads share new flows (default: [`ebpf::Steering::Cpu`]).
    pub steering: ebpf::Steering,
    /// Prefer eBPF programs where they apply and the process is privileged (default: true);
    /// classic BPF, which needs no privileges, is the fallback.
    pub ebpf_programs: bool,
    /// Fail `build` with `Unsupported` instead of degrading when nothing could be attached.
    pub strict: bool,
    /// Pin I/O thread `i` of `n` to the CPUs `c` (of those the process may use) with
    /// `c % n == i` (default: false), so the thread [`ebpf::Steering::Cpu`] picks for a flow is
    /// the one running on the CPU that received it. Threads with no such CPU (more threads than
    /// CPUs) stay unpinned; pinning that fails leaves the thread unpinned. Linux only.
    pub pin_threads: bool,
    /// Join a steering program shared with other processes through bpffs instead of attaching
    /// one of this engine's own (default: `None`; ADR-063): the listener's sockets fill the
    /// handle's slots ([`ebpf::SharedSteering::at`]) and the group runs the pinned program,
    /// whose policy replaces [`steering`](Self::steering). `akio-prefork` sets it for its
    /// workers. Without privileges the listener degrades like any other steering failure.
    pub shared: Option<ebpf::SharedSteering>,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        EbpfConfig {
            steering: ebpf::Steering::Cpu,
            ebpf_programs: true,
            strict: false,
            pin_threads: false,
            shared: None,
        }
    }
}

/// What [`Accel`] a listener ended up with ([`Engine::accel_status`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccelStatus {
    /// No acceleration was requested.
    Off,
    /// A steering program is attached.
    Steering(ebpf::SteerInfo),
    /// Acceleration was requested but is unavailable (the reason); the listener runs with the
    /// kernel's default distribution.
    Degraded(String),
}

/// One bound address with its own acceptor, backend and I/O threads.
pub struct Listener {
    addr: SocketAddr,
    udp: bool,
    backend: Backend,
    /// Set by [`Listener::backend`]; `AKIO_DEFAULT_BACKEND` applies only when it is not.
    backend_explicit: bool,
    accel: Accel,
    threads: usize,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    /// The handler factory of a connectionless datagram listener (ADR-065).
    datagrams: Option<DatagramsFactory>,
    /// An already listening socket to serve instead of binding `addr`.
    inherited: Option<std::net::TcpListener>,
    /// Set by [`Listener::scheduling`]; `AKIO_DEFAULT_SCHEDULING` applies when it is not.
    scheduling: Option<Scheduling>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl Listener {
    /// A TCP listener on `addr` (port 0 picks a free port; see [`Engine::local_addrs`]).
    pub fn tcp(addr: SocketAddr) -> Self {
        Listener {
            addr,
            udp: false,
            backend: Backend::default(),
            backend_explicit: false,
            accel: Accel::default(),
            threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            acceptor: None,
            datagrams: None,
            inherited: None,
            scheduling: None,
        }
    }

    /// A TCP listener serving `listener`, a socket that is already bound and listening: one
    /// inherited from a supervisor process (`akio-prefork`), passed by systemd socket
    /// activation, or bound with options `akio` does not set. The listener's I/O threads share
    /// the socket (each polls its own clone and they race to accept) instead of binding one
    /// `SO_REUSEPORT` socket each, so [`Accel::Ebpf`] has no socket group to steer and reports
    /// [`AccelStatus::Degraded`]. The socket is made non-blocking when the engine is built.
    pub fn tcp_from_std(listener: std::net::TcpListener) -> Self {
        let addr = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Listener {
            inherited: Some(listener),
            ..Listener::tcp(addr)
        }
    }

    /// A UDP listener on `addr`. Every distinct peer address becomes a connection: the acceptor's
    /// `on_open` runs on its first datagram, `on_data` once per datagram (boundaries are kept),
    /// `Conn::send` sends one datagram to that peer, and a peer silent for
    /// `Config::udp_idle_timeout` is closed. Served by the epoll/kqueue backend; on Linux the
    /// threads share the port via `SO_REUSEPORT` (one peer always lands on the same thread), on
    /// other systems a single thread serves it.
    ///
    /// Served with [`serve_datagrams`](Self::serve_datagrams) instead of
    /// [`serve`](Self::serve), the listener has no connections at all: one
    /// [`DatagramsHandler`] per I/O thread gets the datagrams in batches.
    pub fn udp(addr: SocketAddr) -> Self {
        Listener {
            udp: true,
            ..Listener::tcp(addr)
        }
    }

    /// Chooses this listener's backend. A listener without this call uses [`Backend::Epoll`],
    /// or io_uring when `AKIO_DEFAULT_BACKEND=uring` is set on Linux (a test and diagnostic
    /// knob, ADR-029); a backend chosen here always wins over the environment.
    #[must_use]
    pub fn backend(mut self, b: Backend) -> Self {
        self.backend = b;
        self.backend_explicit = true;
        self
    }

    /// Chooses this listener's acceleration layer.
    #[must_use]
    pub fn accel(mut self, a: Accel) -> Self {
        self.accel = a;
        self
    }

    /// Number of I/O threads for this listener (default: one per core). Ignored with
    /// [`Scheduling::Rounds`], whose [`RoundsConfig`] sizes its threads.
    #[must_use]
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n.max(1);
        self
    }

    /// Chooses how this listener's connections are scheduled onto threads (default:
    /// [`Scheduling::Loops`], or what `AKIO_DEFAULT_SCHEDULING` says when this is not called:
    /// `rounds` or `loops`, a test and diagnostic knob like `AKIO_DEFAULT_BACKEND`). ADR-102.
    #[must_use]
    pub fn scheduling(mut self, s: Scheduling) -> Self {
        self.scheduling = Some(s);
        self
    }

    /// Attaches the acceptor that serves this listener.
    #[must_use]
    pub fn serve<A: Acceptor>(mut self, acceptor: A) -> Self {
        self.acceptor = Some(Arc::new(acceptor));
        self
    }

    /// Serves this UDP listener connectionlessly (ADR-065): `factory` creates one
    /// [`DatagramsHandler`] per I/O thread (given a [`DatagramSender`] on that thread's socket),
    /// which gets every receive batch as `(peer, bytes)` pairs and queues replies to any
    /// address on [`Replies`]; they leave together when the callback returns (`sendmmsg`, and
    /// UDP GSO for runs of equal-size datagrams to one address, on Linux). There is no peer
    /// table, no idle timeout and no `on_open` / `on_close`: memory does not grow with the number
    /// of peers, and `Config::udp_max_peers` / `udp_idle_timeout` do not apply. Suits DNS,
    /// syslog or StatsD servers; protocols with per-peer state (QUIC, DTLS) want
    /// [`serve`](Self::serve).
    ///
    /// Threads as for [`Listener::udp`]: on Linux one `SO_REUSEPORT` socket per thread (the
    /// kernel keeps a peer on one thread), elsewhere one thread. Backends: epoll, kqueue and
    /// io_uring (readiness from the ring, the datagrams through the same `recvmmsg` /
    /// `sendmmsg` path); not DPDK (`build` fails with `Unsupported`). The thread count is fixed
    /// ([`Engine::set_threads`] refuses it). Other threads send with a [`DatagramSender`]
    /// (also [`Engine::datagram_sender`]). `build` fails with `InvalidInput` on a TCP listener
    /// or one that also has [`serve`](Self::serve).
    #[must_use]
    pub fn serve_datagrams<H, F>(mut self, factory: F) -> Self
    where
        H: DatagramsHandler,
        F: Fn(&DatagramSender) -> H + Send + Sync + 'static,
    {
        self.datagrams = Some(datagrams_factory(factory));
        self
    }

    /// Attaches a type-erased acceptor, such as a protocol multiplexer (`akio_mux::Mux`).
    #[must_use]
    pub fn serve_any(mut self, acceptor: impl Into<AnyAcceptor>) -> Self {
        self.acceptor = Some(acceptor.into().into_dyn());
        self
    }
}

/// Builds an [`Engine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    listeners: Vec<Listener>,
    client_threads: usize,
    udp_client_threads: usize,
    cfg: Config,
    pool: PoolConfig,
    numa: Option<NumaConfig>,
}

impl EngineBuilder {
    /// Adds a listener.
    #[must_use]
    pub fn listen(mut self, l: Listener) -> Self {
        self.listeners.push(l);
        self
    }

    /// Adds `n` I/O threads that only serve connections made with [`Engine::dial`]. Without it,
    /// dialed connections run on the threads of the last listener added.
    #[must_use]
    pub fn client_threads(mut self, n: usize) -> Self {
        self.client_threads = n;
        self
    }

    /// Replaces the default [`Config`].
    #[must_use]
    pub fn config(mut self, cfg: Config) -> Self {
        self.cfg = cfg;
        self
    }

    /// Adds `n` I/O threads for connections made with [`Engine::dial_udp`]. Without it, UDP
    /// dials run on the threads of the last UDP listener added (and fail if there is none).
    #[must_use]
    pub fn udp_client_threads(mut self, n: usize) -> Self {
        self.udp_client_threads = n;
        self
    }

    /// Sizes the logical pool that runs [`Conn::spawn_blocking`] work (default: no threads until
    /// used, up to 8 per core, 65,536 queued jobs).
    #[must_use]
    pub fn pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool;
        self
    }

    /// Places the I/O threads (and the logical pool) on NUMA nodes ([`numa`] module, ADR-088;
    /// default: off, or what `AKIO_NUMA` says when this is not called). Linux only; see
    /// [`Engine::numa_status`] for what was done.
    #[must_use]
    pub fn numa(mut self, numa: NumaConfig) -> Self {
        self.numa = Some(numa);
        self
    }

    /// Validates the configuration, binds every listener and prepares the I/O threads.
    pub fn build(mut self) -> io::Result<Engine> {
        let numa_cfg = self
            .numa
            .take()
            .or_else(NumaConfig::from_env)
            .unwrap_or_default();
        let numa_nodes = numa_nodes(&numa_cfg)?;
        let mut pool_cpus = Vec::new();
        if let (Ok(nodes), true, None) = (&numa_nodes, numa_cfg.pool, &self.pool.on_start) {
            pool_cpus = nodes.iter().flat_map(|n| n.cpus.iter().copied()).collect();
            pool_cpus.sort_unstable();
            if !pool_cpus.is_empty() {
                self.pool.on_start = Some(akio_pool_hook(pool_cpus.clone()));
            }
        }
        if self.cfg.telemetry.is_bound() {
            // Another engine adopted this config's hub: metrics must not mix.
            self.cfg.telemetry = Telemetry::new();
        }
        let telemetry = self.cfg.telemetry.clone();
        telemetry.bind(&self.cfg);
        let mut groups: Vec<Box<dyn Group>> = Vec::new();
        let pool = Pool::new(self.pool.clone());
        telemetry.set_pool(&pool);
        let mut udp_last: Option<usize> = None;
        let mut udp_listeners: Vec<usize> = Vec::new();
        // Each listener adds exactly one group, at index `groups.len()` when it starts.
        let mut accels: Vec<Accel> = Vec::new();
        // Groups whose threads NUMA placement leaves alone (DPDK places its own lcores).
        #[cfg_attr(not(feature = "dpdk"), allow(unused_mut))]
        let mut unplaced: Vec<usize> = Vec::new();
        let env_backend = env_default_backend(); // read once per build (ADR-029)
        let env_scheduling = env_default_scheduling(); // likewise (ADR-102)
        for mut l in self.listeners {
            let explicit_scheduling = l.scheduling.is_some();
            // The environment's default never overrides what the listener asked for explicitly
            // elsewhere: io_uring (its own or `AKIO_DEFAULT_BACKEND`'s) and BPF steering need
            // per-thread loops.
            let env_applies = matches!(l.backend, Backend::Epoll)
                && (l.backend_explicit || env_backend.is_none())
                && matches!(l.accel, Accel::None);
            let scheduling = l
                .scheduling
                .take()
                .or_else(|| env_scheduling.clone().filter(|_| env_applies))
                .unwrap_or_default();
            if let Some(b) = &env_backend {
                // Per-peer UDP listeners always run on the epoll UDP loop; datagram listeners
                // follow the default like TCP.
                if !l.backend_explicit && (!l.udp || l.datagrams.is_some()) {
                    l.backend = b.clone();
                }
            }
            accels.push(l.accel.clone());
            if let Some(factory) = l.datagrams.take() {
                if !l.udp || l.acceptor.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "serve_datagrams needs a UDP listener without .serve(..)",
                    ));
                }
                // Never a target of `dial` (TCP) or of `dial_udp` / `bind_udp`.
                udp_listeners.push(groups.len());
                groups.push(bind_datagrams(
                    l.addr, factory, &l.backend, l.threads, &self.cfg, &pool,
                )?);
                continue;
            }
            let acceptor = l.acceptor.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
            })?;
            #[cfg(feature = "dpdk")]
            if let Backend::Dpdk(d) = &l.backend {
                if l.udp {
                    udp_last = Some(groups.len());
                }
                unplaced.push(groups.len());
                groups.push(Box::new(akio_dpdk::DpdkGroup::bind(
                    Some((l.addr, acceptor)),
                    l.udp,
                    d,
                    self.cfg.clone(),
                    pool.clone(),
                )?));
                continue;
            }
            if l.udp && explicit_scheduling && scheduling != Scheduling::Loops {
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!(
                        "rounds scheduling is TCP-only; UDP listener {} keeps its loops",
                        l.addr
                    ),
                );
            }
            if l.udp {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if let Backend::IoUring(u) = &l.backend {
                        if u.strict {
                            return Err(unsupported("UDP on the io_uring backend"));
                        }
                    }
                    udp_last = Some(groups.len());
                    udp_listeners.push(groups.len());
                    groups.push(Box::new(akio_epoll::UdpGroup::bind(
                        Some((l.addr, acceptor)),
                        l.threads,
                        self.cfg.clone(),
                        pool.clone(),
                    )?));
                    continue;
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                return Err(unsupported("UDP on this platform"));
            }
            if let Scheduling::Rounds(rc) = &scheduling {
                if let Backend::IoUring(_) = &l.backend {
                    if l.backend_explicit {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "rounds scheduling runs on epoll/kqueue, not io_uring",
                        ));
                    }
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let rc = rc.epoll();
                    groups.push(Box::new(match l.inherited {
                        Some(listener) => akio_epoll::RoundsGroup::bind_listener(
                            listener,
                            acceptor,
                            rc,
                            self.cfg.clone(),
                            pool.clone(),
                        )?,
                        None => akio_epoll::RoundsGroup::bind(
                            Some((l.addr, acceptor)),
                            rc,
                            self.cfg.clone(),
                            pool.clone(),
                        )?,
                    }));
                    continue;
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    let _ = rc;
                    return Err(unsupported("rounds scheduling on this platform"));
                }
            }
            if let Some(listener) = l.inherited {
                groups.push(bind_inherited(
                    listener, acceptor, &l.backend, l.threads, &self.cfg, &pool,
                )?);
                continue;
            }
            match l.backend {
                Backend::Epoll => {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    groups.push(Box::new(akio_epoll::EpollGroup::bind(
                        Some((l.addr, acceptor)),
                        l.threads,
                        self.cfg.clone(),
                        pool.clone(),
                    )?));
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    return Err(unsupported("the epoll/kqueue backend on this platform"));
                }
                #[cfg(feature = "dpdk")]
                Backend::Dpdk(_) => {} // served above
                Backend::IoUring(u) => {
                    #[cfg(target_os = "linux")]
                    match akio_uring::probe() {
                        Ok(()) => groups.push(Box::new(akio_uring::UringGroup::bind(
                            Some((l.addr, acceptor)),
                            l.threads,
                            self.cfg.clone(),
                            pool.clone(),
                            akio_uring::UringOptions {
                                entries: u.entries,
                                sqpoll: u.sqpoll,
                            },
                        )?)),
                        Err(why) if u.strict => {
                            return Err(unsupported(&format!("the io_uring backend ({why})")));
                        }
                        Err(why) => {
                            log_or_stderr(
                                akio_log::Level::Warn,
                                format_args!("io_uring unavailable ({why}); using epoll"),
                            );
                            groups.push(Box::new(akio_epoll::EpollGroup::bind(
                                Some((l.addr, acceptor)),
                                l.threads,
                                self.cfg.clone(),
                                pool.clone(),
                            )?));
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        if u.strict {
                            return Err(unsupported("the io_uring backend on this platform"));
                        }
                        log_or_stderr(
                            akio_log::Level::Warn,
                            format_args!("io_uring is Linux-only; using epoll/kqueue"),
                        );
                        groups.push(Box::new(akio_epoll::EpollGroup::bind(
                            Some((l.addr, acceptor)),
                            l.threads,
                            self.cfg.clone(),
                            pool.clone(),
                        )?));
                    }
                }
            }
        }
        let accel = accels
            .iter()
            .zip(&groups)
            .map(|(a, g)| apply_accel(a, g.as_ref()))
            .collect::<io::Result<Vec<_>>>()?;
        // `dial` goes to the client group, else to the last TCP listener's group (never to a UDP
        // group, which cannot dial TCP).
        let mut tcp_dial = (0..groups.len()).rev().find(|i| !udp_listeners.contains(i));
        if self.client_threads > 0 {
            tcp_dial = Some(groups.len());
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups.push(Box::new(akio_epoll::EpollGroup::bind(
                None,
                self.client_threads,
                self.cfg.clone(),
                pool.clone(),
            )?));
        }
        let mut udp_client = udp_last;
        if self.udp_client_threads > 0 {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                udp_client = Some(groups.len());
                groups.push(Box::new(akio_epoll::UdpGroup::bind(
                    None,
                    self.udp_client_threads,
                    self.cfg,
                    pool.clone(),
                )?));
            }
        }
        let numa = place_threads(&numa_cfg, numa_nodes, &groups, &accel, &unplaced, pool_cpus);
        Ok(Engine {
            groups,
            pool,
            udp_client,
            udp_listeners,
            tcp_dial,
            accel,
            telemetry,
            numa: Box::new(numa),
        })
    }
}

/// The group serving a datagram listener (ADR-065) on `backend`.
fn bind_datagrams(
    addr: SocketAddr,
    factory: DatagramsFactory,
    backend: &Backend,
    threads: usize,
    cfg: &Config,
    pool: &Arc<Pool>,
) -> io::Result<Box<dyn Group>> {
    let epoll = |factory: DatagramsFactory| -> io::Result<Box<dyn Group>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return Ok(Box::new(akio_epoll::UdpGroup::bind_datagrams(
            addr,
            factory,
            threads,
            cfg.clone(),
            pool.clone(),
        )?));
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = factory;
            Err(unsupported("UDP on this platform"))
        }
    };
    match backend {
        Backend::Epoll => epoll(factory),
        #[cfg(feature = "dpdk")]
        Backend::Dpdk(_) => Err(unsupported(
            "connectionless datagram handlers on the DPDK backend",
        )),
        Backend::IoUring(u) => {
            #[cfg(target_os = "linux")]
            match akio_uring::probe() {
                Ok(()) => Ok(Box::new(akio_uring::UringGroup::bind_datagrams(
                    addr,
                    factory,
                    threads,
                    cfg.clone(),
                    pool.clone(),
                    akio_uring::UringOptions {
                        entries: u.entries,
                        sqpoll: u.sqpoll,
                    },
                )?)),
                Err(why) if u.strict => Err(unsupported(&format!("the io_uring backend ({why})"))),
                Err(why) => {
                    log_or_stderr(
                        akio_log::Level::Warn,
                        format_args!("io_uring unavailable ({why}); using epoll"),
                    );
                    epoll(factory)
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                if u.strict {
                    return Err(unsupported("the io_uring backend on this platform"));
                }
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!("io_uring is Linux-only; using epoll/kqueue"),
                );
                epoll(factory)
            }
        }
    }
}

/// The group serving an inherited listener (see [`Listener::tcp_from_std`]).
fn bind_inherited(
    listener: std::net::TcpListener,
    acceptor: Arc<dyn DynAcceptor>,
    backend: &Backend,
    threads: usize,
    cfg: &Config,
    pool: &Arc<Pool>,
) -> io::Result<Box<dyn Group>> {
    #[cfg(target_os = "linux")]
    if let Backend::IoUring(u) = backend {
        match akio_uring::probe() {
            Ok(()) => {
                return Ok(Box::new(akio_uring::UringGroup::bind_listener(
                    listener,
                    acceptor,
                    threads,
                    cfg.clone(),
                    pool.clone(),
                    akio_uring::UringOptions {
                        entries: u.entries,
                        sqpoll: u.sqpoll,
                    },
                )?));
            }
            Err(why) if u.strict => {
                return Err(unsupported(&format!("the io_uring backend ({why})")));
            }
            Err(why) => log_or_stderr(
                akio_log::Level::Warn,
                format_args!("io_uring unavailable ({why}); using epoll"),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    if let Backend::IoUring(u) = backend {
        if u.strict {
            return Err(unsupported("the io_uring backend on this platform"));
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(Box::new(akio_epoll::EpollGroup::bind_listener(
            listener,
            acceptor,
            threads,
            cfg.clone(),
            pool.clone(),
        )?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (listener, acceptor, backend, threads, cfg, pool);
        Err(unsupported("the epoll/kqueue backend on this platform"))
    }
}

/// Attaches the steering program `a` asks for to the listener sockets of `g`.
fn apply_accel(a: &Accel, g: &dyn Group) -> io::Result<AccelStatus> {
    let Accel::Ebpf(cfg) = a else {
        return Ok(AccelStatus::Off);
    };
    let mut opts = ebpf::AttachOptions::default();
    opts.ebpf = cfg.ebpf_programs;
    let fds = g.listener_fds();
    let attached = match &cfg.shared {
        Some(s) if fds.is_empty() => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "shared steering ({}) needs a SO_REUSEPORT socket group",
                s.dir().display()
            ),
        )),
        Some(s) => s.join(&fds),
        None => ebpf::attach_reuseport(&fds, cfg.steering, opts),
    };
    match attached {
        Ok(mut info) => {
            if cfg.pin_threads {
                // Shared CPU steering picks slot `cpu % sockets`: thread `t` of a process at
                // slots `first..` runs on the CPUs of slot `first + t`.
                let sets = match &cfg.shared {
                    Some(s) => ebpf::cpu_pinning(s.sockets()).map(|v| {
                        let first = s.slots().0;
                        v.get(first..first + fds.len()).unwrap_or_default().to_vec()
                    }),
                    None => ebpf::cpu_pinning(fds.len()),
                };
                if let Ok(sets) = sets {
                    info.pinned_threads = sets.iter().filter(|s| !s.is_empty()).count();
                    g.pin_threads(sets);
                }
            }
            Ok(AccelStatus::Steering(info))
        }
        Err(e) if cfg.strict => Err(unsupported(&format!("BPF steering ({e})"))),
        Err(e) => {
            eprintln!("akio: BPF steering unavailable ({e}); using default SO_REUSEPORT hashing");
            Ok(AccelStatus::Degraded(e.to_string()))
        }
    }
}

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not supported"),
    )
}

/// A late-bound handle to an [`Engine`], for services that need to dial (proxies, clients
/// inside handlers) but are built before the engine. Holds the engine weakly.
#[derive(Debug, Clone, Default)]
pub struct EngineRef(Arc<std::sync::OnceLock<std::sync::Weak<Engine>>>);

impl EngineRef {
    /// An empty handle; call [`set`](Self::set) once the engine exists.
    pub fn new() -> EngineRef {
        EngineRef::default()
    }

    /// Points the handle at `engine`. Later calls are ignored.
    pub fn set(&self, engine: &Arc<Engine>) {
        let _ = self.0.set(Arc::downgrade(engine));
    }

    /// The engine, if set and still alive.
    pub fn get(&self) -> Option<Arc<Engine>> {
        self.0.get().and_then(std::sync::Weak::upgrade)
    }
}

/// `AKIO_DEFAULT_BACKEND` (ADR-029): the backend of TCP listeners that do not choose one with
/// [`Listener::backend`]. `uring` (or `io_uring`) selects a non-strict io_uring backend, which
/// falls back to epoll with a warning where the kernel lacks io_uring; unset, empty or `epoll`
/// keeps the default. Linux only: elsewhere the variable is ignored. A test and diagnostic knob
/// (run an unchanged program on io_uring), not a tuning setting.
/// The nodes NUMA placement uses: `Ok(empty)` when off, `Err(reason)` when it cannot be done
/// (an `io::Error` instead with [`NumaConfig::strict`]).
fn numa_nodes(cfg: &NumaConfig) -> io::Result<std::result::Result<Vec<numa::UsableNode>, String>> {
    if cfg.placement == NumaPlacement::Off {
        return Ok(Ok(Vec::new()));
    }
    #[cfg(target_os = "linux")]
    let r = match (akio_sys::numa::nodes(), akio_sys::process::allowed_cpus()) {
        (Ok(nodes), Ok(allowed)) => numa::choose(
            &cfg.placement,
            &nodes,
            &allowed,
            akio_sys::numa::interface_node,
        ),
        (Err(e), _) | (_, Err(e)) => Err(format!("NUMA topology unavailable: {e}")),
    };
    #[cfg(not(target_os = "linux"))]
    let r: std::result::Result<Vec<numa::UsableNode>, String> =
        Err("NUMA placement is Linux-only".into());
    match r {
        Err(why) if cfg.strict => Err(io::Error::new(
            if cfg!(target_os = "linux") {
                io::ErrorKind::InvalidInput
            } else {
                io::ErrorKind::Unsupported
            },
            why,
        )),
        Err(why) => {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!("NUMA placement off: {why}"),
            );
            Ok(Err(why))
        }
        ok => Ok(ok),
    }
}

/// A pool thread hook that pins the thread to `cpus` (best effort).
fn akio_pool_hook(cpus: Vec<usize>) -> akio_core::ThreadHook {
    akio_core::ThreadHook(Arc::new(move || {
        let _ = akio_sys::process::pin_current_thread(&cpus);
    }))
}

/// Gives each group's I/O threads their NUMA CPU sets (before `start`) and, with
/// `incoming_cpu`, their listening sockets `SO_INCOMING_CPU`; reports what was done.
fn place_threads(
    cfg: &NumaConfig,
    nodes: std::result::Result<Vec<numa::UsableNode>, String>,
    groups: &[Box<dyn Group>],
    accel: &[AccelStatus],
    unplaced: &[usize],
    pool_cpus: Vec<usize>,
) -> NumaStatus {
    let nodes = match nodes {
        Ok(n) if n.is_empty() => return NumaStatus::Off,
        Ok(n) => n,
        Err(why) => return NumaStatus::Degraded(why),
    };
    let usable: usize = nodes.iter().map(|n| n.cpus.len()).sum();
    let mut report = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        let steered =
            matches!(accel.get(i), Some(AccelStatus::Steering(s)) if s.pinned_threads > 0);
        if steered || unplaced.contains(&i) {
            report.push(Vec::new());
            continue;
        }
        let count = g.threads();
        // Sets for threads added later too (`set_threads`), up to one per usable CPU.
        let sets = numa::thread_sets(&nodes, cfg.per_cpu, count.max(usable));
        let fds = if cfg.incoming_cpu {
            g.listener_fds()
        } else {
            Vec::new()
        };
        let mut placed = Vec::new();
        for (t, (node, cpus)) in sets.iter().enumerate().take(count) {
            let incoming = fds.get(t).and_then(|&fd| {
                #[cfg(target_os = "linux")]
                {
                    akio_sys::numa::set_incoming_cpu(fd, cpus[0])
                        .ok()
                        .map(|()| cpus[0])
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = fd;
                    None
                }
            });
            placed.push(ThreadPlacement {
                node: *node,
                cpus: cpus.clone(),
                incoming_cpu: incoming,
                sq_thread_cpu: None,
            });
        }
        // io_uring groups recreate their rings on these sets here (ADR-088, update).
        g.pin_threads(sets.into_iter().map(|(_, c)| c).collect());
        for (p, sq) in placed.iter_mut().zip(g.sq_thread_cpus()) {
            p.sq_thread_cpu = sq;
        }
        report.push(placed);
    }
    NumaStatus::Placed(NumaReport {
        nodes: nodes.iter().map(|n| n.id).collect(),
        groups: report,
        pool_cpus,
    })
}

fn env_default_backend() -> Option<Backend> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    parse_default_backend(std::env::var("AKIO_DEFAULT_BACKEND").ok().as_deref())
}

fn env_default_scheduling() -> Option<Scheduling> {
    parse_default_scheduling(std::env::var("AKIO_DEFAULT_SCHEDULING").ok().as_deref())
}

fn parse_default_scheduling(v: Option<&str>) -> Option<Scheduling> {
    match v? {
        "rounds" => Some(Scheduling::Rounds(RoundsConfig::default())),
        "" | "loops" => None,
        other => {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!(
                    "AKIO_DEFAULT_SCHEDULING={other:?} is not `rounds` or `loops`; ignored"
                ),
            );
            None
        }
    }
}

fn parse_default_backend(v: Option<&str>) -> Option<Backend> {
    match v? {
        "uring" | "io_uring" => Some(Backend::IoUring(UringConfig::default())),
        "" | "epoll" => None,
        other => {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!("AKIO_DEFAULT_BACKEND={other:?} is not `uring` or `epoll`; ignored"),
            );
            None
        }
    }
}

/// A set of listeners, each served by its own backend group of I/O threads.
///
/// `Engine` is `Send + Sync`: share it in an `Arc` to call [`shutdown`](Engine::shutdown) or
/// [`dial`](Engine::dial) from other threads while [`run`](Engine::run) blocks.
pub struct Engine {
    groups: Vec<Box<dyn Group>>,
    pool: Arc<Pool>,
    udp_client: Option<usize>,
    /// Indices into `groups` of the UDP listeners.
    udp_listeners: Vec<usize>,
    /// Index into `groups` of the group `dial` uses.
    tcp_dial: Option<usize>,
    accel: Vec<AccelStatus>,
    telemetry: Arc<Telemetry>,
    /// Boxed: `Engine` is embedded by value in clients, keep it small.
    numa: Box<NumaStatus>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// Starts a builder.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// Bound addresses of the listeners, in the order they were added (resolves port 0).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.groups.iter().map(|g| g.local_addr()).collect()
    }

    /// The NUMA placement of the engine's threads ([`EngineBuilder::numa`]).
    pub fn numa_status(&self) -> &NumaStatus {
        &self.numa
    }

    /// What acceleration each listener got, in the order they were added.
    pub fn accel_status(&self) -> &[AccelStatus] {
        &self.accel
    }

    /// Spawns the I/O threads and returns immediately. Idempotent.
    pub fn start(&self) -> io::Result<()> {
        self.groups.iter().try_for_each(|g| g.start())?;
        akio_log::info!(target: "akio", listeners:? = self.local_addrs(); "engine started");
        Ok(())
    }

    /// Metrics, debug snapshots and live settings of this engine.
    pub fn telemetry(&self) -> &Arc<Telemetry> {
        &self.telemetry
    }

    /// A metrics snapshot: per-thread counters, totals, open connections, pool statistics.
    /// [`Metrics::to_prometheus`] renders it for a Prometheus scrape.
    pub fn metrics(&self) -> Metrics {
        self.telemetry.metrics()
    }

    /// The connection table (see [`Telemetry::connections`]). Do not call it from an I/O
    /// thread's callback.
    pub fn connections(&self, timeout: Duration) -> Vec<ConnInfo> {
        self.telemetry.connections(timeout)
    }

    /// The most recent slow callbacks, oldest first.
    pub fn slow_callbacks(&self) -> Vec<SlowRecord> {
        self.telemetry.slow_callbacks()
    }

    /// Applies the runtime-changeable settings of `cfg` without a restart: `idle_timeout`,
    /// `slow_callback_threshold`, `slow_hook`, `max_queued_bytes`, `write_high_watermark`,
    /// `max_connections`, `shutdown_timeout`, `retire_timeout`, `log_level`, `read_buffer`,
    /// `backlog` and `udp_idle_timeout`. Open connections pick up the new idle timeouts and
    /// watermark right away, and the new read buffer at their next read; listening sockets are
    /// `listen`ed again with the new backlog (see [`Live`]). Settings fixed at build time
    /// (`max_pending_responses`, `write_timeout`, `connect_timeout`, `udp_max_peers`,
    /// `udp_gro`) are reported in [`ReloadReport::ignored`] when they differ. Thread counts
    /// change with [`set_threads`](Self::set_threads); listeners, backends and pool sizes need
    /// a restart.
    pub fn reload(&self, cfg: &Config) -> ReloadReport {
        self.telemetry.reload(cfg)
    }

    /// Active I/O threads of each listener (and client group), in
    /// [`local_addrs`](Self::local_addrs) order. Retiring threads (see
    /// [`set_threads`](Self::set_threads)) are not counted.
    pub fn threads(&self) -> Vec<usize> {
        self.groups.iter().map(|g| g.threads()).collect()
    }

    /// Changes the number of I/O threads of group `index` (in [`local_addrs`](Self::local_addrs)
    /// order: the listeners, then the client groups) to `threads` (at least 1) while the engine
    /// runs (ADR-028). TCP listeners and client groups on epoll, kqueue and io_uring support it.
    ///
    /// * **Growing** starts new I/O threads (or reactivates retiring ones) and gives each a
    ///   listening socket: on Linux a new `SO_REUSEPORT` socket in the listener's group, from
    ///   which the kernel sends it its share of new connections; elsewhere, and for an inherited
    ///   listener, a clone of the shared socket. New dials are spread over all active threads.
    /// * **Shrinking** retires the highest threads: they stop taking new connections at once and
    ///   hand their listening sockets to the remaining threads (the sockets stay open, so no
    ///   connection waiting in an accept queue is reset), and keep serving the connections they
    ///   own until those close. **Connections never move between threads** (ADR-001); a retired
    ///   thread exits once its last connection is gone. With `Config::retire_timeout` the
    ///   connections still open after it are shut down gracefully, as by
    ///   [`shutdown`](Self::shutdown).
    ///
    /// Returns once the change is posted to the I/O threads, without waiting for it to take
    /// effect. The one wait: growing into the index of a retired thread that is just exiting
    /// (it has no connection left) joins that thread first, so it is safe but not ideal to call
    /// from an I/O thread's callback.
    /// [`Metrics::loops`] shows retiring threads (`retiring`). Errors: `Unsupported` for UDP
    /// listeners of both kinds (a socket added or removed from a UDP `SO_REUSEPORT` group would
    /// move peers between threads), DPDK groups and listeners with BPF steering (`Accel::Ebpf`); `NotFound`
    /// for an index out of range; `InvalidInput` before [`start`](Self::start); `NotConnected`
    /// after [`shutdown`](Self::shutdown).
    pub fn set_threads(&self, index: usize, threads: usize) -> io::Result<()> {
        let g = self.groups.get(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no listener or client group {index}"),
            )
        })?;
        if matches!(self.accel.get(index), Some(AccelStatus::Steering(_))) {
            return Err(unsupported(
                "changing the thread count of a listener with BPF steering",
            ));
        }
        let before = g.threads();
        g.set_threads(threads)?;
        akio_log::info!(target: "akio", group = index, local:% = g.local_addr(), from = before, to = threads.max(1); "I/O threads changed");
        Ok(())
    }

    /// Blocks until [`shutdown`](Self::shutdown) has completed.
    pub fn wait(&self) {
        self.groups.iter().for_each(|g| g.join());
        // I/O threads are gone, so no completion can be delivered any more: stop the pool.
        self.pool.shutdown();
        self.pool.join();
    }

    /// Counters of the logical pool.
    pub fn pool_stats(&self) -> PoolStats {
        self.pool.stats()
    }

    /// A sender on the socket of the datagram listener (see [`Listener::serve_datagrams`])
    /// bound at `local` (as [`local_addrs`](Self::local_addrs) reports it): sends to any
    /// address from any thread. On Linux, where each I/O thread has its own socket on the port,
    /// it sends from the first thread's. `InvalidInput` when there is no such listener.
    pub fn datagram_sender(&self, local: SocketAddr) -> io::Result<DatagramSender> {
        self.groups
            .iter()
            .filter(|g| g.local_addr() == local)
            .find_map(|g| g.datagram_sender())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no datagram listener at that address",
                )
            })
    }

    /// Peer counters of the UDP listeners, summed (see `Config::udp_max_peers`).
    pub fn udp_stats(&self) -> UdpStats {
        self.groups
            .iter()
            .map(|g| g.udp_stats())
            .fold(UdpStats::default(), |mut a, b| {
                a.peers += b.peers;
                a.rejected += b.rejected;
                a
            })
    }

    /// `start` + `wait`.
    pub fn run(&self) -> io::Result<()> {
        self.start()?;
        self.wait();
        Ok(())
    }

    /// Graceful shutdown: listeners stop accepting, every acceptor's `on_shutdown` runs for its
    /// open connections, and the engine waits (up to `Config::shutdown_timeout`) for them to
    /// close before forcing the rest. Returns immediately; use [`wait`](Self::wait) to block.
    pub fn shutdown(&self) {
        akio_log::info!(target: "akio", open_connections = self.telemetry.open_connections(); "engine shutting down");
        self.groups.iter().for_each(|g| g.shutdown());
    }

    /// Starts a UDP "connection" to `addr`: a socket of its own (so its own local port) that only
    /// exchanges datagrams with `addr`. `acceptor.on_open` runs on an I/O thread right away (UDP
    /// has no handshake), `on_data` once per datagram received, `Conn::send` sends one datagram,
    /// and an ICMP "port unreachable" or `Config::udp_idle_timeout` of silence closes it. On
    /// failure to create the socket `on_error` is called. Needs [`EngineBuilder::udp_client_threads`]
    /// or a UDP listener. The engine must have been [`start`](Self::start)ed.
    pub fn dial_udp<A: Acceptor>(
        &self,
        addr: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        match self.udp_client.and_then(|i| self.groups.get(i)) {
            Some(g) => g.dial_udp(addr, Arc::new(acceptor), Box::new(on_error)),
            None => on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no UDP I/O threads (use udp_client_threads or a UDP listener)",
            )),
        }
    }

    /// Binds an unconnected UDP socket on `addr` (port 0 picks a free port) and serves it on an
    /// I/O thread with `acceptor`, exactly like a [`Listener::udp`] (every distinct peer address
    /// is a connection), except that it can be created while the engine runs and that the
    /// returned [`UdpBinding`] sends to any address ([`UdpBinding::send_to`]): what an ICE agent
    /// (one local port talking to many candidates) or a TURN relay needs. Needs
    /// [`EngineBuilder::udp_client_threads`] or a UDP listener. The engine must have been
    /// [`start`](Self::start)ed.
    pub fn bind_udp<A: Acceptor>(&self, addr: SocketAddr, acceptor: A) -> io::Result<UdpBinding> {
        match self.udp_client.and_then(|i| self.groups.get(i)) {
            Some(g) => {
                let sock = std::net::UdpSocket::bind(addr)?;
                sock.set_nonblocking(true)?;
                g.bind_udp(sock, Arc::new(acceptor))
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no UDP I/O threads (use udp_client_threads or a UDP listener)",
            )),
        }
    }

    /// [`bind_udp`](Self::bind_udp), and the ICMP errors that answer datagrams the socket sends
    /// (destination or port unreachable, time exceeded, packet too big, parameter problem) go
    /// to `on_icmp`, on the socket's I/O thread: without it an unconnected socket never hears
    /// of them. For a relay that tells its client about unreachable peers (TURN, RFC 8656
    /// section 11.5).
    ///
    /// Linux: `IP_RECVERR` / `IPV6_RECVERR` (the kernel queues each error on the socket, the
    /// I/O thread reads them with `MSG_ERRQUEUE`). macOS, which has no such option: the I/O
    /// thread opens an unprivileged ICMP socket per address family (`SOCK_DGRAM`,
    /// `IPPROTO_ICMP` / `IPPROTO_ICMPV6`), which sees every ICMP error the host gets, and
    /// hands on the ones whose quoted datagram came from this socket's address and port (a
    /// socket bound to `[::]` hears of its IPv6 datagrams only). Both report the destination's
    /// port and need no privileges. Elsewhere it is `bind_udp` and `on_icmp` is never called.
    /// ICMP is best effort: errors are rate-limited by the hosts that send them and often
    /// filtered.
    pub fn bind_udp_icmp<A: Acceptor>(
        &self,
        addr: SocketAddr,
        acceptor: A,
        on_icmp: impl Fn(&IcmpError) + Send + Sync + 'static,
    ) -> io::Result<UdpBinding> {
        match self.udp_client.and_then(|i| self.groups.get(i)) {
            Some(g) => {
                let sock = std::net::UdpSocket::bind(addr)?;
                sock.set_nonblocking(true)?;
                g.bind_udp_icmp(sock, Arc::new(acceptor), Arc::new(on_icmp))
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no UDP I/O threads (use udp_client_threads or a UDP listener)",
            )),
        }
    }

    /// [`bind_udp`](Self::bind_udp) for a multicast group: binds the unspecified address of
    /// `group`'s family on `group.port()` with `SO_REUSEADDR` and `SO_REUSEPORT` (sharing the
    /// port with other responders on the host, e.g. the system's mDNS daemon on 5353), joins
    /// the group `group.ip()` on the default interface and serves the socket with `acceptor`:
    /// datagrams sent to the group (or to the port) arrive from their sources as on any bound
    /// socket, and [`UdpBinding::send_to`] with `group` multicasts (looped back to this host's
    /// members too) with a TTL / hop limit of 255. For multicast protocols such as mDNS (RFC
    /// 6762). Needs
    /// [`EngineBuilder::udp_client_threads`] or a UDP listener; the engine must have been
    /// [`start`](Self::start)ed.
    pub fn bind_udp_multicast<A: Acceptor>(
        &self,
        group: SocketAddr,
        acceptor: A,
    ) -> io::Result<UdpBinding> {
        self.bind_udp_multicast_on(group, &[0], acceptor)
    }

    /// [`bind_udp_multicast`](Self::bind_udp_multicast) joining the group on each of
    /// `interfaces` (interface indexes, the scope ids of IPv6 link-local addresses; 0 is the
    /// default interface): a link-scoped IPv6 group such as mDNS's `ff02::fb` reaches a socket
    /// only on the links it was joined on. Interfaces that refuse the join (down, no address of
    /// the group's family) are
    /// skipped; it fails with the last join error only when none accepts it. Datagrams arrive
    /// with the source's scope id; [`UdpBinding::send_to`] the group with a scope id to send on
    /// that link. `bind_udp_multicast(group, a)` is `bind_udp_multicast_on(group, &[0], a)`.
    ///
    /// An IPv4 group is joined the same way, on each interface's first IPv4 address
    /// (`IP_ADD_MEMBERSHIP` names an interface by address; the indexes are those of
    /// [`akio_sys::interfaces`]); interfaces without one are skipped. IPv4 has no scope id, so
    /// [`UdpBinding::send_to_on`] picks the interface a datagram to the group leaves on. Linux
    /// allows 20 IPv4 memberships per socket by default (`net.ipv4.igmp_max_memberships`): joins
    /// past it are refused and skipped. An empty list fails with
    /// [`io::ErrorKind::InvalidInput`].
    pub fn bind_udp_multicast_on<A: Acceptor>(
        &self,
        group: SocketAddr,
        interfaces: &[u32],
        acceptor: A,
    ) -> io::Result<UdpBinding> {
        if !group.ip().is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a multicast group address",
            ));
        }
        if interfaces.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no interface to join the multicast group on",
            ));
        }
        let Some(g) = self.udp_client.and_then(|i| self.groups.get(i)) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no UDP I/O threads (use udp_client_threads or a UDP listener)",
            ));
        };
        let any: std::net::IpAddr = match group {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        };
        let sock = akio_sys::listen_udp(SocketAddr::new(any, group.port()), true)?;
        match group.ip() {
            std::net::IpAddr::V4(ip) => {
                // Interface indexes to the addresses IPv4 joins name them by (0: the default).
                let list = if interfaces.iter().any(|&i| i != 0) {
                    akio_sys::interfaces()?
                } else {
                    Vec::new()
                };
                let mut last = None;
                let mut joined = false;
                for &i in interfaces {
                    let on = if i == 0 {
                        Some(std::net::Ipv4Addr::UNSPECIFIED)
                    } else {
                        list.iter().find(|f| f.index == i).and_then(|f| f.ipv4())
                    };
                    let Some(on) = on else {
                        last = Some(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!("interface {i} has no IPv4 address"),
                        ));
                        continue;
                    };
                    match sock.join_multicast_v4(&ip, &on) {
                        Ok(()) => joined = true,
                        Err(e) => last = Some(e),
                    }
                }
                if !joined {
                    return Err(last.unwrap_or_else(|| io::Error::other("no interface")));
                }
                sock.set_multicast_ttl_v4(255)?;
                sock.set_multicast_loop_v4(true)?;
            }
            std::net::IpAddr::V6(ip) => {
                let mut last = None;
                let mut joined = false;
                for &i in interfaces {
                    match sock.join_multicast_v6(&ip, i) {
                        Ok(()) => joined = true,
                        Err(e) => last = Some(e),
                    }
                }
                if !joined {
                    return Err(last.unwrap_or_else(|| io::Error::other("no interface")));
                }
                // As the IPv4 TTL above: 255, which link-local protocols (mDNS, RFC 6762 §11)
                // send with and some receivers check; the kernel's default is 1.
                akio_sys::set_multicast_hops_v6(&sock, 255)?;
                sock.set_multicast_loop_v6(true)?;
            }
        }
        sock.set_nonblocking(true)?;
        g.bind_udp(sock, Arc::new(acceptor))
    }

    /// Opens a UDP "connection" to `peer` on the socket of this engine's UDP listener bound at
    /// `local` (as [`local_addrs`](Self::local_addrs) reports it): datagrams leave from the
    /// listener's port, which is what protocols that share one port for a peer-to-peer node
    /// need (a DHT node, uTP, ICE). `acceptor.on_open` runs on an I/O thread, `on_data` gets the
    /// peer's datagrams, and the connection ends like the listener's own peers (idle timeout,
    /// close). Fails through `on_error` when there is no such UDP listener, or the peer already
    /// has a connection on it (`AlreadyExists`: its datagrams go to that one). On Linux, where
    /// a listener's threads share the port, the peer's answers may arrive on another thread,
    /// which opens a peer through the listener's own acceptor. The engine must have been
    /// [`start`](Self::start)ed.
    pub fn dial_udp_from<A: Acceptor>(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let g = self
            .udp_listeners
            .iter()
            .filter_map(|&i| self.groups.get(i))
            .find(|g| g.local_addr() == local);
        match g {
            Some(g) => g.open_udp_peer(peer, Arc::new(acceptor), Box::new(on_error)),
            None => on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no UDP listener at that address",
            )),
        }
    }

    /// Serves an already connected TCP stream (one accepted outside the engine, e.g. on a
    /// listening socket opened at run time) with `acceptor`, like a [`dial`](Self::dial)ed
    /// connection that has just connected: `acceptor.on_open` runs on an I/O thread, then
    /// `on_data` / `on_close` as for any connection. The stream is made non-blocking. On
    /// failure (no TCP I/O threads, engine shutting down) `on_error` is called and the stream
    /// is closed. Uses the same I/O threads as `dial`. The engine must have been
    /// [`start`](Self::start)ed.
    pub fn adopt_tcp<A: Acceptor>(
        &self,
        stream: std::net::TcpStream,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        match self.tcp_dial.and_then(|i| self.groups.get(i)) {
            Some(g) => g.adopt(stream, Arc::new(acceptor), Box::new(on_error)),
            None => on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no I/O threads",
            )),
        }
    }

    /// Connects to `addr` without blocking. When established, `acceptor.on_open` runs on an I/O
    /// thread exactly as for an accepted connection; on failure `on_error` is called instead.
    /// The engine must have been [`start`](Self::start)ed.
    pub fn dial<A: Acceptor>(
        &self,
        addr: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        match self.tcp_dial.and_then(|i| self.groups.get(i)) {
            // The client group when `client_threads` was set, else the last TCP listener's.
            Some(g) => g.dial(addr, Arc::new(acceptor), Box::new(on_error)),
            None => on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no I/O threads",
            )),
        }
    }

    /// [`dial`](Self::dial) from the local address `local` (port 0 picks one), bound with
    /// `SO_REUSEADDR` and `SO_REUSEPORT` before connecting: connections to different peers, and
    /// a listener, may share the local port, as TCP simultaneous open needs (ICE-TCP `so`
    /// candidates, RFC 6544, where both sides connect at once between their advertised ports).
    /// A connect that crosses the peer's own becomes one connection on both sides. The engine
    /// must have been [`start`](Self::start)ed.
    pub fn dial_from<A: Acceptor>(
        &self,
        local: SocketAddr,
        addr: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let Some(g) = self.tcp_dial.and_then(|i| self.groups.get(i)) else {
            return on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no I/O threads",
            ));
        };
        match akio_sys::connect_nonblocking_from(local, addr) {
            Ok(stream) => g.dial_stream(stream, addr, Arc::new(acceptor), Box::new(on_error)),
            Err(e) => on_error(e),
        }
    }
}
