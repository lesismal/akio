#![forbid(unsafe_code)]
//! `only`: an event-driven network library. This facade crate re-exports the core API and
//! provides [`Engine`], which composes one backend *group* per listener (ADR-004).
//!
//! ```no_run
//! use only::{Conn, Engine, Handler, Listener, fn_acceptor};
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
//! Guide: [Concepts](https://lesismal.github.io/only/en/concepts/index.html), [Getting started](https://lesismal.github.io/only/en/getting-started.html)
//! (中文: [核心概念](https://lesismal.github.io/only/zh-CN/concepts/index.html)、[快速上手](https://lesismal.github.io/only/zh-CN/getting-started.html)).
#![warn(clippy::unwrap_used)]

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

/// TLS: wrap an acceptor in [`tls::Tls`] to serve or dial over TLS (configs: [`tls::ServerConfig`],
/// [`tls::ClientConfig`]).
pub use only_tls as tls;

/// BPF acceleration (ADR-006): `SO_REUSEPORT` steering programs (used by [`Accel::Ebpf`]) and
/// the in-kernel sockmap [`ebpf::Relay`] for proxies.
pub use only_ebpf as ebpf;

/// Logging (the `only-log` facade): `only` logs under the targets `only`, `only_http::access`
/// ... Install a logger with [`log::init`] (formatted lines on stderr) or [`log::set_logger`];
/// [`Config::log_level`] sets the maximum level. With the `log` cargo feature, records go to
/// the `log` crate's logger instead while none is installed here.
pub use only_log as log;

/// Kernel bypass (experimental, cargo feature `dpdk`): configuration of [`Backend::Dpdk`], a
/// userspace TCP/IP stack over DPDK ports (feature `dpdk-pmd`), TAP, AF_PACKET or in-memory
/// devices.
#[cfg(feature = "dpdk")]
pub use only_dpdk as dpdk;

pub use only_core::{
    Acceptor, AnyAcceptor, Config, Conn, ConnInfo, Error, FnAcceptor, Handler, Live, LoopCounters,
    LoopMeta, LoopMetrics, Metrics, Part, PoolConfig, PoolStats, ReloadReport, ResponseSlot,
    ResponseStream, Result, SharedBuf, SlowCallback, SlowHook, SlowRecord, Telemetry, Transport,
    UdpBinding, UdpStats, fn_acceptor, telemetry,
};
#[doc(hidden)]
pub use only_core::{DynAcceptor, DynHandler};
use only_core::{Group, Pool, telemetry::log_or_stderr};

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
    /// Kernel bypass (experimental, cargo feature `dpdk`): `only`'s own userspace TCP/IP stack
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
}

impl Default for EbpfConfig {
    fn default() -> Self {
        EbpfConfig {
            steering: ebpf::Steering::Cpu,
            ebpf_programs: true,
            strict: false,
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
    accel: Accel,
    threads: usize,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    /// An already listening socket to serve instead of binding `addr`.
    inherited: Option<std::net::TcpListener>,
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
            accel: Accel::default(),
            threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            acceptor: None,
            inherited: None,
        }
    }

    /// A TCP listener serving `listener`, a socket that is already bound and listening: one
    /// inherited from a supervisor process (`only-prefork`), passed by systemd socket
    /// activation, or bound with options `only` does not set. The listener's I/O threads share
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
    pub fn udp(addr: SocketAddr) -> Self {
        Listener {
            udp: true,
            ..Listener::tcp(addr)
        }
    }

    /// Chooses this listener's backend.
    #[must_use]
    pub fn backend(mut self, b: Backend) -> Self {
        self.backend = b;
        self
    }

    /// Chooses this listener's acceleration layer.
    #[must_use]
    pub fn accel(mut self, a: Accel) -> Self {
        self.accel = a;
        self
    }

    /// Number of I/O threads for this listener (default: one per core).
    #[must_use]
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n.max(1);
        self
    }

    /// Attaches the acceptor that serves this listener.
    #[must_use]
    pub fn serve<A: Acceptor>(mut self, acceptor: A) -> Self {
        self.acceptor = Some(Arc::new(acceptor));
        self
    }

    /// Attaches a type-erased acceptor, such as a protocol multiplexer (`only_mux::Mux`).
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

    /// Validates the configuration, binds every listener and prepares the I/O threads.
    pub fn build(mut self) -> io::Result<Engine> {
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
        for l in self.listeners {
            accels.push(l.accel.clone());
            let acceptor = l.acceptor.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
            })?;
            #[cfg(feature = "dpdk")]
            if let Backend::Dpdk(d) = &l.backend {
                if l.udp {
                    udp_last = Some(groups.len());
                }
                groups.push(Box::new(only_dpdk::DpdkGroup::bind(
                    Some((l.addr, acceptor)),
                    l.udp,
                    d,
                    self.cfg.clone(),
                    pool.clone(),
                )?));
                continue;
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
                    groups.push(Box::new(only_epoll::UdpGroup::bind(
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
            if let Some(listener) = l.inherited {
                groups.push(bind_inherited(
                    listener, acceptor, &l.backend, l.threads, &self.cfg, &pool,
                )?);
                continue;
            }
            match l.backend {
                Backend::Epoll => {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    groups.push(Box::new(only_epoll::EpollGroup::bind(
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
                    match only_uring::probe() {
                        Ok(()) => groups.push(Box::new(only_uring::UringGroup::bind(
                            Some((l.addr, acceptor)),
                            l.threads,
                            self.cfg.clone(),
                            pool.clone(),
                            only_uring::UringOptions {
                                entries: u.entries,
                                sqpoll: u.sqpoll,
                            },
                        )?)),
                        Err(why) if u.strict => {
                            return Err(unsupported(&format!("the io_uring backend ({why})")));
                        }
                        Err(why) => {
                            log_or_stderr(
                                only_log::Level::Warn,
                                format_args!("io_uring unavailable ({why}); using epoll"),
                            );
                            groups.push(Box::new(only_epoll::EpollGroup::bind(
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
                            only_log::Level::Warn,
                            format_args!("io_uring is Linux-only; using epoll/kqueue"),
                        );
                        groups.push(Box::new(only_epoll::EpollGroup::bind(
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
            groups.push(Box::new(only_epoll::EpollGroup::bind(
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
                groups.push(Box::new(only_epoll::UdpGroup::bind(
                    None,
                    self.udp_client_threads,
                    self.cfg,
                    pool.clone(),
                )?));
            }
        }
        Ok(Engine {
            groups,
            pool,
            udp_client,
            udp_listeners,
            tcp_dial,
            accel,
            telemetry,
        })
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
        match only_uring::probe() {
            Ok(()) => {
                return Ok(Box::new(only_uring::UringGroup::bind_listener(
                    listener,
                    acceptor,
                    threads,
                    cfg.clone(),
                    pool.clone(),
                    only_uring::UringOptions {
                        entries: u.entries,
                        sqpoll: u.sqpoll,
                    },
                )?));
            }
            Err(why) if u.strict => {
                return Err(unsupported(&format!("the io_uring backend ({why})")));
            }
            Err(why) => log_or_stderr(
                only_log::Level::Warn,
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
        Ok(Box::new(only_epoll::EpollGroup::bind_listener(
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
    match ebpf::attach_reuseport(&g.listener_fds(), cfg.steering, opts) {
        Ok(info) => Ok(AccelStatus::Steering(info)),
        Err(e) if cfg.strict => Err(unsupported(&format!("BPF steering ({e})"))),
        Err(e) => {
            eprintln!("only: BPF steering unavailable ({e}); using default SO_REUSEPORT hashing");
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

    /// What acceleration each listener got, in the order they were added.
    pub fn accel_status(&self) -> &[AccelStatus] {
        &self.accel
    }

    /// Spawns the I/O threads and returns immediately. Idempotent.
    pub fn start(&self) -> io::Result<()> {
        self.groups.iter().try_for_each(|g| g.start())?;
        only_log::info!(target: "only", listeners:? = self.local_addrs(); "engine started");
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
    /// `max_connections`, `shutdown_timeout` and `log_level`. Open connections pick up the new
    /// idle timeout and watermark right away. Settings fixed at build time (`read_buffer`,
    /// `backlog`, `udp_idle_timeout`, listeners, backends, thread and pool sizes) are reported in
    /// [`ReloadReport::ignored`] when they differ.
    pub fn reload(&self, cfg: &Config) -> ReloadReport {
        self.telemetry.reload(cfg)
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
        only_log::info!(target: "only", open_connections = self.telemetry.open_connections(); "engine shutting down");
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
}
