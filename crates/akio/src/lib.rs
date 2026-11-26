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

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

pub mod dns;
pub mod numa;
mod shared;
#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "macos")))]
mod tun_engine;

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

use akio_core::{
    AcceptFilter, DatagramsFactory, Group, ListenSocket, Pool, datagrams_factory,
    telemetry::log_or_stderr,
};
/// TUN devices (cargo feature `tun`, Linux and macOS): layer-3 virtual interfaces served on I/O
/// threads, one IP packet per `on_data` and per `send`; see [`Engine::serve_tun`].
#[cfg(all(feature = "tun", any(target_os = "linux", target_os = "macos")))]
pub use akio_tun as tun;

/// WebAssembly for plugins (experimental, cargo feature `wasm`, ADR-125): a safe interpreter
/// built in milestones; this release loads modules ([`wasm::Module`]) and runs them
/// ([`wasm::Store`]).
#[cfg(feature = "wasm")]
pub use akio_wasm as wasm;

pub use akio_core::{
    Acceptor, AnyAcceptor, Config, Conn, ConnInfo, DatagramSender, Datagrams, DatagramsHandler,
    DatagramsIter, Error, FnAcceptor, Handler, IcmpError, Live, LoopCounters, LoopMeta,
    LoopMetrics, Metrics, Part, PoolConfig, PoolStats, ReloadReport, Replies, ResponseSlot,
    ResponseStream, Result, SharedBuf, SlowCallback, SlowHook, SlowRecord, Telemetry, Transport,
    UNIX_ADDR, UdpBinding, UdpStats, fn_acceptor, metrics, telemetry, timer,
};
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

/// How a TCP listener's connections are scheduled onto threads (ADR-104).
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
    /// loops); [`Engine::set_threads`] is refused. Listeners added, removed and drained at run
    /// time and accept filters work as with loops (ADR-099).
    Rounds(RoundsConfig),
}

/// Thread counts of [`Scheduling::Rounds`]. `#[non_exhaustive]`: start from
/// `RoundsConfig::default()` (or [`RoundsConfig::new`]) and set fields; 0 picks the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoundsConfig {
    /// epoll/kqueue instances the workers poll (default: 1). Each listener socket and
    /// connection belongs to one of them; more than one rarely helps (ADR-104).
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

/// How a TCP listener spreads new connections over its I/O threads ([`Listener::balance`],
/// ADR-105). Either way a connection stays on one thread for its whole life (ADR-001).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Balance {
    /// Each thread serves every connection its listening socket gets: the kernel's
    /// `SO_REUSEPORT` hash (or the [`Accel::Ebpf`] steering program) decides alone. The hash is
    /// even only on average (1024 connections over 8 threads: 119..141 measured), so when every
    /// connection carries the same load the busiest thread saturates first.
    Kernel,
    /// A thread that accepts a connection while it holds more than its share (more than
    /// `2 + min / 32` connections above the thread with the fewest) hands it, before reading
    /// a byte, to the thread with the fewest open connections, where `on_open` runs and the
    /// connection stays. The cost is one cross-thread wake-up per connection handed over, paid
    /// only while the threads are uneven. The default, except on listeners whose
    /// [`Accel::Ebpf`] steering program is attached or whose sockets have NUMA
    /// `SO_INCOMING_CPU` ([`NumaConfig::incoming_cpu`]): there the placement was asked for and
    /// is kept ([`Kernel`](Self::Kernel)).
    #[default]
    LeastConnections,
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
}

impl Default for EbpfConfig {
    fn default() -> Self {
        EbpfConfig {
            steering: ebpf::Steering::Cpu,
            ebpf_programs: true,
            strict: false,
            pin_threads: false,
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
    /// Set by [`Listener::threads`] / [`Listener::dedicated`]: a group of its own (ADR-130).
    threads: Option<usize>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    /// The handler factory of a connectionless datagram listener (ADR-065).
    datagrams: Option<DatagramsFactory>,
    /// An already listening socket to serve instead of binding `addr`.
    inherited: Option<std::net::TcpListener>,
    /// Set by [`Listener::scheduling`]; `AKIO_DEFAULT_SCHEDULING` applies when it is not.
    scheduling: Option<Scheduling>,
    balance: Balance,
    /// Run on every accepted connection before the acceptor (ADR-099).
    filter: Option<AcceptFilter>,
    /// A Unix-domain stream listener (ADR-121).
    unix: Option<UnixSpec>,
    /// The socket file's mode ([`Listener::unix_mode`]).
    unix_mode: Option<u32>,
}

/// Where a Unix-domain listener's socket comes from (ADR-121).
enum UnixSpec {
    /// Bound at this path when the listener is built.
    Path(std::path::PathBuf),
    /// Already bound and listening.
    Std(std::os::unix::net::UnixListener),
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
            threads: None,
            acceptor: None,
            datagrams: None,
            inherited: None,
            filter: None,
            scheduling: None,
            balance: Balance::default(),
            unix: None,
            unix_mode: None,
        }
    }

    /// A TCP listener serving `listener`, a socket that is already bound and listening: one
    /// passed by systemd socket activation, inherited from a parent process, or bound with
    /// options `akio` does not set. The listener's I/O threads share
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

    /// A Unix-domain stream listener at `path` (ADR-121), served like a TCP listener: the same
    /// acceptors (akio-http's `serve`, TLS, akio-mux), on epoll, kqueue and io_uring; its I/O
    /// threads share the one socket and race to accept, as for
    /// [`tcp_from_std`](Self::tcp_from_std). A connection has no IP address: its `peer_addr`
    /// and `local_addr` are [`UNIX_ADDR`] (`0.0.0.0:0`), and so is the listener's entry in
    /// [`Engine::local_addrs`]; an accept [`filter`](Self::filter) sees that address.
    ///
    /// The socket is bound when the engine is built (or by [`Engine::add_listener`]), with the
    /// permission bits of [`unix_mode`](Self::unix_mode) set before it listens. A socket file
    /// already at `path` that no one listens on (one a process left behind) is replaced; one
    /// that is in use, or a file that is not a socket, fails with `AddrInUse`. The file stays
    /// after the listener is removed or the engine shuts down (as with `tcp_from_std`, the
    /// socket is the caller's to clean up). A path that is empty, has a NUL byte or is longer
    /// than `sun_path` holds (107 bytes on Linux, 103 on macOS) fails with `InvalidInput`.
    /// Not on the DPDK backend (`Unsupported`); [`Accel::Ebpf`] has no socket group to steer.
    pub fn unix(path: impl Into<std::path::PathBuf>) -> Self {
        Listener {
            unix: Some(UnixSpec::Path(path.into())),
            ..Listener::tcp(UNIX_ADDR)
        }
    }

    /// A Unix-domain stream listener serving `listener`, a socket already bound and listening
    /// (passed by a supervisor, or bound by the caller), as [`unix`](Self::unix) serves one it
    /// binds. The socket is made non-blocking when the engine is built.
    pub fn unix_from_std(listener: std::os::unix::net::UnixListener) -> Self {
        Listener {
            unix: Some(UnixSpec::Std(listener)),
            ..Listener::tcp(UNIX_ADDR)
        }
    }

    /// The permission bits of a [`unix`](Self::unix) listener's socket file (`0o600`: its
    /// owner's processes only), set after the socket is bound and before it listens, so no
    /// connection is accepted while it has the process umask's. Without it the file keeps what
    /// the umask leaves. On any other listener (including
    /// [`unix_from_std`](Self::unix_from_std), already listening) `build` and
    /// [`Engine::add_listener`] fail with `InvalidInput`.
    #[must_use]
    pub fn unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
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

    /// How new connections are spread over the I/O threads (default:
    /// [`Balance::LeastConnections`]; TCP listeners only, UDP ignores it).
    #[must_use]
    pub fn balance(mut self, b: Balance) -> Self {
        self.balance = b;
        self
    }

    /// Gives this listener `n` I/O threads of its own (ADR-130). Without it (nor
    /// [`dedicated`](Self::dedicated)), a TCP listener on epoll/kqueue with per-thread loops
    /// shares the engine's I/O threads for its kind with the other such listeners
    /// ([`EngineBuilder::io_threads`], one per core by default), as one on io_uring does with
    /// the io_uring listeners of the same [`UringConfig`] ring options, and one with
    /// [`Scheduling::Rounds`] shares the workers of the other rounds listeners with the same
    /// [`RoundsConfig`]; UDP, datagram, DPDK and BPF-steered listeners always have their own
    /// (one per core by default). With rounds the count itself is ignored, [`RoundsConfig`]
    /// sizes the threads: it only keeps the listener's workers to itself.
    #[must_use]
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = Some(n.max(1));
        self
    }

    /// Gives this listener I/O threads of its own, one per core, instead of sharing the
    /// engine's (ADR-130): isolation for an admin port or a latency-critical protocol, whose
    /// connections then never wait behind another listener's callbacks. See
    /// [`threads`](Self::threads).
    #[must_use]
    pub fn dedicated(mut self) -> Self {
        self.threads = Some(default_threads());
        self
    }

    /// Chooses how this listener's connections are scheduled onto threads (default:
    /// [`Scheduling::Loops`], or what `AKIO_DEFAULT_SCHEDULING` says when this is not called:
    /// `rounds` or `loops`, a test and diagnostic knob like `AKIO_DEFAULT_BACKEND`). ADR-104.
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

    /// Filters this TCP listener's connections (ADR-099): `filter` is called on the I/O thread
    /// with the peer's address right after `accept`, before the `max_connections` check, the
    /// acceptor's `on_open` and any transport (TLS) work; `false` closes the connection at once.
    /// Allow / deny lists go here. It runs for every connection, on the hot path of accepting:
    /// keep it to a lookup, never block (rules 1, 12). A filter that panics refuses the
    /// connection. Refused connections are counted in [`LoopCounters::filtered`]
    /// (`akio_connections_filtered_total`). Swap or clear it while the engine runs with
    /// [`Engine::set_listener_filter`] / [`Engine::clear_listener_filter`].
    ///
    /// TCP listeners on epoll, kqueue and io_uring: on a UDP or datagram listener `build` /
    /// [`Engine::add_listener`] fail with `InvalidInput`, on the DPDK backend with
    /// `Unsupported`.
    #[must_use]
    pub fn filter(mut self, filter: impl Fn(&SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        self.filter = Some(Arc::new(filter));
        self
    }
}

/// Identifies one listener of an [`Engine`] (ADR-099). The listeners given to the builder have
/// ids `0..n` in the order they were added (their index in [`Engine::local_addrs`]); those added
/// with [`Engine::add_listener`] get the following ones. Never reused within an engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId(u64);

impl ListenerId {
    /// The id as a number.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ListenerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "listener#{}", self.0)
    }
}

/// One listener of a running engine ([`Engine::listeners`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ListenerInfo {
    /// Its id.
    pub id: ListenerId,
    /// The bound address (port 0 resolved).
    pub local_addr: SocketAddr,
    /// Active I/O threads.
    pub threads: usize,
    /// What [`Accel`] it got.
    pub accel: AccelStatus,
    /// A UDP or datagram listener (which cannot be removed or filtered at run time).
    pub udp: bool,
}

/// What kind of group a listener became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Tcp,
    /// Per-peer UDP on the epoll UDP loop.
    Udp,
    /// Connectionless datagrams (ADR-065).
    Datagrams,
    /// The DPDK backend (`udp`: a UDP listener).
    #[cfg_attr(not(feature = "dpdk"), allow(dead_code))]
    Dpdk {
        udp: bool,
    },
}

/// The default of [`EngineBuilder::max_listeners`].
const DEFAULT_MAX_LISTENERS: usize = 1024;

/// How long [`Engine::remove_listener`] waits for a busy I/O thread to stop its listening
/// socket listening.
const UNLISTEN_WAIT: Duration = Duration::from_secs(1);

/// Binds the group of listener `l` (as `build` and `Engine::add_listener` do) and installs its
/// filter; returns it with its kind, the acceleration it asks for and whether it asked for
/// accept-time balancing (ADR-105).
/// One per core: a listener's thread count when it has its own group, and
/// [`EngineBuilder::io_threads`]' default.
fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// What [`bind_one`] made of a listener: its group, kind and acceleration, whether accept-time
/// balancing applies, and whether it joined a shared group (ADR-130).
type Bound = (Box<dyn Group>, Kind, Accel, bool, bool);

/// `AKIO_PIN_IO_THREADS`: `1` (or `true`, `on`) turns [`EngineBuilder::pin_io_threads`] on.
fn pin_io_from_env() -> bool {
    matches!(
        std::env::var("AKIO_PIN_IO_THREADS").as_deref(),
        Ok("1" | "true" | "on")
    )
}

/// `AKIO_POOL_CPUS`: the CPUs [`EngineBuilder::reserve_pool_cpus`] keeps for the logical pool.
fn pool_cpus_from_env() -> Option<usize> {
    std::env::var("AKIO_POOL_CPUS").ok()?.trim().parse().ok()
}

/// Gives I/O threads one CPU each, in turn ([`EngineBuilder::pin_io_threads`]).
struct Pinner {
    /// The CPUs the process may use.
    cpus: Vec<usize>,
    /// The CPU the next thread gets (index into `cpus`).
    next: usize,
}

impl Pinner {
    /// Over `cpus`; `None` when there is none.
    fn new(cpus: Vec<usize>) -> Option<Pinner> {
        (!cpus.is_empty()).then_some(Pinner { cpus, next: 0 })
    }

    /// Pins `g`'s threads (before it starts) to the next CPUs; also those it may grow to, up
    /// to one per CPU.
    fn pin(&mut self, g: &dyn Group) {
        let n = self.cpus.len();
        let count = g.threads().max(1);
        let sets = (0..count.max(n))
            .map(|i| vec![self.cpus[(self.next + i) % n]])
            .collect();
        self.next = (self.next + count) % n;
        g.pin_threads(sets);
    }
}

/// Where listeners that share I/O threads get them (ADR-130).
struct Sharing<'a> {
    groups: &'a mut shared::SharedGroups,
    /// The size of a shared group made now.
    threads: usize,
}

fn bind_one(
    mut l: Listener,
    env_backend: Option<&Backend>,
    env_scheduling: Option<&Scheduling>,
    cfg: &Config,
    pool: &Arc<Pool>,
    sharing: Sharing<'_>,
) -> io::Result<Bound> {
    let explicit_scheduling = l.scheduling.is_some();
    // The environment's default never overrides what the listener asked for explicitly
    // elsewhere: io_uring (its own or `AKIO_DEFAULT_BACKEND`'s) and BPF steering need
    // per-thread loops. (Rounds runs accept filters too.)
    let env_applies = matches!(l.backend, Backend::Epoll)
        && (l.backend_explicit || env_backend.is_none())
        && matches!(l.accel, Accel::None);
    let scheduling = l
        .scheduling
        .take()
        .or_else(|| env_scheduling.cloned().filter(|_| env_applies))
        .unwrap_or_default();
    let balance = !l.udp && l.balance == Balance::LeastConnections;
    if let Some(b) = env_backend {
        // Per-peer UDP listeners always run on the epoll UDP loop; datagram listeners
        // follow the default like TCP.
        if !l.backend_explicit && (!l.udp || l.datagrams.is_some()) {
            l.backend = b.clone();
        }
    }
    let accel = l.accel.clone();
    let filter = l.filter.take();
    if filter.is_some() {
        #[cfg(feature = "dpdk")]
        if matches!(l.backend, Backend::Dpdk(_)) {
            return Err(unsupported("an accept filter on the DPDK backend"));
        }
        if l.udp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an accept filter applies to TCP listeners",
            ));
        }
    }
    // ADR-130: a TCP listener on epoll/kqueue loops that did not ask for threads of its own
    // joins the shared group of its kind.
    // Rounds listeners share a group per `RoundsConfig`.
    let rounds = match &scheduling {
        Scheduling::Rounds(rc) => Some(*rc),
        Scheduling::Loops => None,
    };
    // io_uring listeners (per-thread loops) share a group per ring options.
    let backend_shares = match &l.backend {
        Backend::Epoll => true,
        Backend::IoUring(_) => rounds.is_none(),
        #[cfg(feature = "dpdk")]
        Backend::Dpdk(_) => false,
    };
    let shares = l.threads.is_none()
        && !l.udp
        && l.datagrams.is_none()
        && backend_shares
        && matches!(l.accel, Accel::None)
        && cfg!(any(target_os = "linux", target_os = "macos"));
    if shares {
        let g = bind_shared(l, balance, rounds, cfg, pool, sharing)?;
        if filter.is_some() {
            g.set_filter(filter)?;
        }
        return Ok((g, Kind::Tcp, accel, balance, true));
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
    let (group, kind) = match &scheduling {
        Scheduling::Rounds(rc) if !l.udp && l.datagrams.is_none() => {
            (bind_rounds(l, *rc, cfg, pool)?, Kind::Tcp)
        }
        _ => bind_group(l, cfg, pool)?,
    };
    if filter.is_some() {
        group.set_filter(filter)?;
    }
    Ok((group, kind, accel, balance, false))
}

/// Adds a TCP listener to the engine's shared group of its kind (ADR-130), made now if it is
/// the first.
fn bind_shared(
    l: Listener,
    balance: bool,
    rounds: Option<RoundsConfig>,
    cfg: &Config,
    pool: &Arc<Pool>,
    sharing: Sharing<'_>,
) -> io::Result<Box<dyn Group>> {
    if l.unix_mode.is_some() && !matches!(l.unix, Some(UnixSpec::Path(_))) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix_mode applies to a Unix-domain listener akio binds (Listener::unix)",
        ));
    }
    let acceptor = l.acceptor.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
    })?;
    // io_uring when it is available here; else epoll, as `bind_group` falls back (or fails,
    // `strict`).
    let uring = match &l.backend {
        Backend::IoUring(u) => uring_or_epoll(u)?,
        _ => None,
    };
    let socket = match (l.unix, l.inherited) {
        (Some(UnixSpec::Path(path)), _) => {
            ListenSocket::Unix(listen_unix(&path, cfg.backlog, l.unix_mode)?)
        }
        (Some(UnixSpec::Std(u)), _) => {
            ListenSocket::Unix(std::net::TcpListener::from(std::os::fd::OwnedFd::from(u)))
        }
        (None, Some(inherited)) => ListenSocket::Inherited(inherited),
        (None, None) => ListenSocket::Bind(l.addr),
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let key = shared::ShareKey {
        // Accept-time balancing is a loops feature; rounds listeners share by thread counts.
        balance: balance && rounds.is_none(),
        rounds: rounds.map(|rc| rc.epoll().resolved()),
        uring: uring.as_ref().map(|u| (u.entries, u.sqpoll)),
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let key = shared::ShareKey {
        balance,
        rounds: None,
        uring: None,
    };
    let threads = sharing.threads;
    let group = sharing.groups.get_or_make(key, || {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let g: Arc<dyn Group> = match (rounds, &uring) {
                (Some(rc), _) => Arc::new(akio_epoll::RoundsGroup::shared(
                    rc.epoll(),
                    cfg.clone(),
                    pool.clone(),
                )?),
                #[cfg(target_os = "linux")]
                (None, Some(u)) => Arc::new(akio_uring::UringGroup::shared(
                    threads,
                    cfg.clone(),
                    pool.clone(),
                    akio_uring::UringOptions {
                        entries: u.entries,
                        sqpoll: u.sqpoll,
                    },
                )?),
                _ => Arc::new(akio_epoll::EpollGroup::shared(
                    threads,
                    cfg.clone(),
                    pool.clone(),
                )?),
            };
            g.set_balance(key.balance);
            Ok(g)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (threads, pool, rounds, uring);
            Err(unsupported("the epoll/kqueue backend on this platform"))
        }
    })?;
    let (k, addr) = group.add_listener(socket, acceptor)?;
    Ok(Box::new(shared::SharedListener::new(group, k, addr)))
}

/// The ring options a shared io_uring listener runs with (`Some`) when io_uring is available
/// here; `None` to fall back to epoll as `bind_group` does (a warning), or `Unsupported` with
/// `strict`.
fn uring_or_epoll(u: &UringConfig) -> io::Result<Option<UringConfig>> {
    #[cfg(target_os = "linux")]
    {
        match akio_uring::probe() {
            Ok(()) => Ok(Some(u.clone())),
            Err(why) if u.strict => Err(unsupported(&format!("the io_uring backend ({why})"))),
            Err(why) => {
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!("io_uring unavailable ({why}); using epoll"),
                );
                Ok(None)
            }
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
        Ok(None)
    }
}

/// Binds a TCP listener with [`Scheduling::Rounds`] (ADR-104).
fn bind_rounds(
    l: Listener,
    rc: RoundsConfig,
    cfg: &Config,
    pool: &Arc<Pool>,
) -> io::Result<Box<dyn Group>> {
    if let Backend::IoUring(_) = &l.backend {
        if l.backend_explicit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rounds scheduling runs on epoll/kqueue, not io_uring",
            ));
        }
    }
    #[cfg(feature = "dpdk")]
    if matches!(l.backend, Backend::Dpdk(_)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rounds scheduling runs on epoll/kqueue, not DPDK",
        ));
    }
    if l.unix_mode.is_some() && !matches!(l.unix, Some(UnixSpec::Path(_))) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix_mode applies to a Unix-domain listener akio binds (Listener::unix)",
        ));
    }
    let acceptor = l.acceptor.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
    })?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let rc = rc.epoll();
        let (cfg, pool) = (cfg.clone(), pool.clone());
        Ok(Box::new(match (l.unix, l.inherited) {
            (Some(spec), _) => {
                let listener = match spec {
                    UnixSpec::Path(path) => listen_unix(&path, cfg.backlog, l.unix_mode)?,
                    UnixSpec::Std(u) => std::net::TcpListener::from(std::os::fd::OwnedFd::from(u)),
                };
                akio_epoll::RoundsGroup::bind_unix_listener(listener, acceptor, rc, cfg, pool)?
            }
            (None, Some(listener)) => {
                akio_epoll::RoundsGroup::bind_listener(listener, acceptor, rc, cfg, pool)?
            }
            (None, None) => akio_epoll::RoundsGroup::bind(Some((l.addr, acceptor)), rc, cfg, pool)?,
        }))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (rc, acceptor, cfg, pool);
        Err(unsupported("rounds scheduling on this platform"))
    }
}

fn bind_group(l: Listener, cfg: &Config, pool: &Arc<Pool>) -> io::Result<(Box<dyn Group>, Kind)> {
    if let Some(factory) = l.datagrams {
        if !l.udp || l.acceptor.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serve_datagrams needs a UDP listener without .serve(..)",
            ));
        }
        let threads = l.threads.unwrap_or_else(default_threads);
        let g = bind_datagrams(l.addr, factory, &l.backend, threads, cfg, pool)?;
        return Ok((g, Kind::Datagrams));
    }
    if l.unix_mode.is_some() && !matches!(l.unix, Some(UnixSpec::Path(_))) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix_mode applies to a Unix-domain listener akio binds (Listener::unix)",
        ));
    }
    let acceptor = l.acceptor.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
    })?;
    let threads = l.threads.unwrap_or_else(default_threads);
    if let Some(spec) = l.unix {
        #[cfg(feature = "dpdk")]
        if matches!(l.backend, Backend::Dpdk(_)) {
            return Err(unsupported("a Unix-domain listener on the DPDK backend"));
        }
        let listener = match spec {
            UnixSpec::Path(path) => listen_unix(&path, cfg.backlog, l.unix_mode)?,
            UnixSpec::Std(u) => std::net::TcpListener::from(std::os::fd::OwnedFd::from(u)),
        };
        let g = bind_inherited(listener, true, acceptor, &l.backend, threads, cfg, pool)?;
        return Ok((g, Kind::Tcp));
    }
    #[cfg(feature = "dpdk")]
    if let Backend::Dpdk(d) = &l.backend {
        let g = akio_dpdk::DpdkGroup::bind(
            Some((l.addr, acceptor)),
            l.udp,
            d,
            cfg.clone(),
            pool.clone(),
        )?;
        return Ok((Box::new(g), Kind::Dpdk { udp: l.udp }));
    }
    if l.udp {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Backend::IoUring(u) = &l.backend {
                if u.strict {
                    return Err(unsupported("UDP on the io_uring backend"));
                }
            }
            let g = akio_epoll::UdpGroup::bind(
                Some((l.addr, acceptor)),
                threads,
                cfg.clone(),
                pool.clone(),
            )?;
            return Ok((Box::new(g), Kind::Udp));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(unsupported("UDP on this platform"));
    }
    if let Some(listener) = l.inherited {
        let g = bind_inherited(listener, false, acceptor, &l.backend, threads, cfg, pool)?;
        return Ok((g, Kind::Tcp));
    }
    let epoll = |acceptor| -> io::Result<Box<dyn Group>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return Ok(Box::new(akio_epoll::EpollGroup::bind(
            Some((l.addr, acceptor)),
            threads,
            cfg.clone(),
            pool.clone(),
        )?));
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = acceptor;
            Err(unsupported("the epoll/kqueue backend on this platform"))
        }
    };
    let g = match &l.backend {
        Backend::Epoll => epoll(acceptor)?,
        #[cfg(feature = "dpdk")]
        Backend::Dpdk(_) => unreachable!("served above"),
        Backend::IoUring(u) => {
            #[cfg(target_os = "linux")]
            match akio_uring::probe() {
                Ok(()) => Box::new(akio_uring::UringGroup::bind(
                    Some((l.addr, acceptor)),
                    threads,
                    cfg.clone(),
                    pool.clone(),
                    akio_uring::UringOptions {
                        entries: u.entries,
                        sqpoll: u.sqpoll,
                    },
                )?),
                Err(why) if u.strict => {
                    return Err(unsupported(&format!("the io_uring backend ({why})")));
                }
                Err(why) => {
                    log_or_stderr(
                        akio_log::Level::Warn,
                        format_args!("io_uring unavailable ({why}); using epoll"),
                    );
                    epoll(acceptor)?
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
                epoll(acceptor)?
            }
        }
    };
    Ok((g, Kind::Tcp))
}

/// Builds an [`Engine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    listeners: Vec<Listener>,
    /// The size of shared I/O groups (ADR-130); `None`: one thread per core.
    io_threads: Option<usize>,
    /// One CPU per I/O thread; `None`: what `AKIO_PIN_IO_THREADS` says.
    pin_io_threads: Option<bool>,
    /// CPUs kept for the logical pool when pinning; `None`: what `AKIO_POOL_CPUS` says.
    pool_cpus: Option<usize>,
    client_threads: usize,
    udp_client_threads: usize,
    cfg: Config,
    pool: PoolConfig,
    numa: Option<NumaConfig>,
    max_listeners: Option<usize>,
}

impl EngineBuilder {
    /// Adds a listener.
    #[must_use]
    pub fn listen(mut self, l: Listener) -> Self {
        self.listeners.push(l);
        self
    }

    /// Sizes the I/O threads the listeners share (ADR-130; default: one per core): every TCP
    /// listener with per-thread loops that has no [`threads`](Listener::threads) of its own
    /// (nor [`dedicated`](Listener::dedicated)) is served by one such group per backend (epoll
    /// or kqueue, and io_uring per ring options), whatever its port or protocol (listeners with
    /// and without accept-time [`Balance`] get one group each). Resize it while the engine runs with
    /// [`Engine::set_threads`] on any of its listeners.
    #[must_use]
    pub fn io_threads(mut self, n: usize) -> Self {
        self.io_threads = Some(n.max(1));
        self
    }

    /// Pins each I/O thread to one CPU (default: off, or `AKIO_PIN_IO_THREADS=1` when this is
    /// not called). The I/O threads of every group (shared and dedicated listeners, client
    /// threads) take the CPUs the process may use (`sched_getaffinity`) in turn, one each,
    /// continuing from group to group and starting over when there are more threads than CPUs;
    /// threads added later by [`Engine::set_threads`] and groups of listeners added at run time
    /// continue the round. Groups that NUMA placement ([`numa`](Self::numa)) or BPF steering
    /// with [`EbpfConfig::pin_threads`] already pin are left as they are, and rounds workers
    /// are not pinned. Linux only (elsewhere it does nothing).
    ///
    /// With as many busy I/O threads as CPUs (one shared group sized to the CPUs, say), the
    /// scheduler can otherwise leave two of them on one CPU for a while, idling another: on
    /// gpu51, HTTP/1.1 plaintext over 3 listeners sharing 4 threads on 4 CPUs ran at 754k
    /// requests/s (±1%) pinned and 612k to 752k unpinned (docs/BENCHMARKS.md). But a pinned
    /// thread can no longer move away from other busy threads on its CPU: h2c on the same
    /// setup, whose handlers run on the logical pool (`H2Config::run_on_pool`, on the same
    /// CPUs), fell from about 490k to 250k–400k. Turn it on for handlers served inline on CPUs
    /// the I/O threads have to themselves; leave it off when the logical pool or other busy
    /// processes share those CPUs.
    #[must_use]
    pub fn pin_io_threads(mut self, on: bool) -> Self {
        self.pin_io_threads = Some(on);
        self
    }

    /// With [`pin_io_threads`](Self::pin_io_threads): keeps the last `n` of the CPUs the process
    /// may use for the logical pool (its threads run on those, on any of them) and pins the I/O
    /// threads to the others (default: 0, or what `AKIO_POOL_CPUS` says when this is not called).
    /// For handlers that run on the pool (HTTP/2's by default, `run_on_pool`, `spawn_blocking`):
    /// a pinned I/O thread cannot move away from a busy pool thread on its CPU, so the two get
    /// CPUs of their own. Size [`io_threads`](Self::io_threads) to the CPUs left (one per CPU).
    /// Measure before relying on it: on gpu51 (4 CPUs, h2c on the pool over 3 listeners) 2 + 2
    /// raised io_uring from 496k to 840k requests/s but lowered epoll from 485k to 337k, and
    /// HTTP/1.1 served inline lost what the fewer I/O threads could not carry; serving such
    /// handlers inline (`run_on_pool` off) with pinning gave 4.0M (docs/BENCHMARKS.md).
    /// Ignored without pinning, when `n` leaves no CPU for the I/O threads, under NUMA placement
    /// (whose `NumaConfig::pool` confines the pool), and when the pool already has a start hook.
    /// Linux only.
    #[must_use]
    pub fn reserve_pool_cpus(mut self, n: usize) -> Self {
        self.pool_cpus = Some(n);
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

    /// The most listeners the engine may have at once (default 1024, at least 1; ADR-099):
    /// listeners accepting connections, of every kind, plus those removed with
    /// [`Engine::remove_listener`] / [`Engine::shutdown_listener`] whose threads still serve
    /// connections. [`Engine::add_listener`] past it fails with
    /// [`io::ErrorKind::QuotaExceeded`]. The listeners given to the builder count, but the
    /// builder itself is not limited.
    #[must_use]
    pub fn max_listeners(mut self, n: usize) -> Self {
        self.max_listeners = Some(n.max(1));
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
        // Pinning (ADR-130 follow-up): the CPUs the I/O threads take in turn, less those kept for
        // the logical pool. Not under NUMA placement, which places both itself.
        let pin_io = self.pin_io_threads.unwrap_or_else(pin_io_from_env);
        let numa_places = matches!(&numa_nodes, Ok(n) if !n.is_empty());
        let io_cpus = if pin_io && !numa_places {
            akio_sys::process::allowed_cpus().ok().map(|mut cpus| {
                let keep = self.pool_cpus.or_else(pool_cpus_from_env).unwrap_or(0);
                if keep > 0 && keep < cpus.len() && self.pool.on_start.is_none() {
                    let for_pool = cpus.split_off(cpus.len() - keep);
                    self.pool.on_start = Some(akio_pool_hook(for_pool));
                }
                cpus
            })
        } else {
            None
        };
        if self.cfg.telemetry.is_bound() {
            // Another engine adopted this config's hub: metrics must not mix.
            self.cfg.telemetry = Telemetry::new();
        }
        let telemetry = self.cfg.telemetry.clone();
        telemetry.bind(&self.cfg);
        let mut groups: Vec<Arc<dyn Group>> = Vec::new();
        let pool = Pool::new(self.pool.clone());
        telemetry.set_pool(&pool);
        let mut udp_last: Option<usize> = None;
        let mut udp_listeners: Vec<usize> = Vec::new();
        // Each listener adds exactly one group, at index `groups.len()` when it starts.
        let mut accels: Vec<Accel> = Vec::new();
        let mut kinds: Vec<Kind> = Vec::new();
        // Per listener: accept-time balancing asked for (ADR-105).
        let mut balances: Vec<bool> = Vec::new();
        // Groups whose threads NUMA placement leaves alone (DPDK places its own lcores).
        let mut unplaced: Vec<usize> = Vec::new();
        let env_backend = env_default_backend(); // read once per build (ADR-029)
        let env_scheduling = env_default_scheduling(); // likewise (ADR-104)
        let rt_cfg = self.cfg.clone();
        let io_threads = self.io_threads.unwrap_or_else(default_threads);
        let mut shared_groups = shared::SharedGroups::default();
        // Per listener: it joined a shared group (pinned with that group, not on its own).
        let mut shared_flags: Vec<bool> = Vec::new();
        for l in self.listeners {
            let (g, kind, accel, balance, shares) = bind_one(
                l,
                env_backend.as_ref(),
                env_scheduling.as_ref(),
                &self.cfg,
                &pool,
                Sharing {
                    groups: &mut shared_groups,
                    threads: io_threads,
                },
            )?;
            balances.push(balance);
            shared_flags.push(shares);
            match kind {
                // Never a target of `dial` (TCP) or of `dial_udp` / `bind_udp`.
                Kind::Datagrams => udp_listeners.push(groups.len()),
                Kind::Udp => {
                    udp_last = Some(groups.len());
                    udp_listeners.push(groups.len());
                }
                Kind::Dpdk { udp } => {
                    if udp {
                        udp_last = Some(groups.len());
                    }
                    unplaced.push(groups.len());
                }
                Kind::Tcp => {}
            }
            accels.push(accel);
            kinds.push(kind);
            groups.push(Arc::from(g));
        }
        let accel = accels
            .iter()
            .zip(&groups)
            .map(|(a, g)| apply_accel(a, g.as_ref()))
            .collect::<io::Result<Vec<_>>>()?;
        // Balancing would undo a placement the listener asked for: a steering program, or
        // NUMA's `SO_INCOMING_CPU`.
        for ((g, on), a) in groups.iter().zip(&balances).zip(&accel) {
            let placed = matches!(a, AccelStatus::Steering(_)) || numa_cfg.incoming_cpu;
            g.set_balance(*on && !placed);
        }
        // `dial` goes to the client group, else to the last TCP listener's group (never to a UDP
        // group, which cannot dial TCP).
        let mut tcp_dial = (0..groups.len()).rev().find(|i| !udp_listeners.contains(i));
        if self.client_threads > 0 {
            tcp_dial = Some(groups.len());
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups.push(Arc::new(akio_epoll::EpollGroup::bind(
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
                groups.push(Arc::new(akio_epoll::UdpGroup::bind(
                    None,
                    self.udp_client_threads,
                    self.cfg,
                    pool.clone(),
                )?));
            }
        }
        let rt_nodes = numa_nodes.as_ref().ok().cloned().unwrap_or_default();
        let numa = place_threads(&numa_cfg, numa_nodes, &groups, &accel, &unplaced, pool_cpus);
        // One CPU per I/O thread, where NUMA placement did not place them (ADR-130 follow-up).
        let mut pinner = io_cpus
            .filter(|_| !matches!(numa, NumaStatus::Placed(_)))
            .and_then(Pinner::new);
        if let Some(p) = pinner.as_mut() {
            for g in shared_groups.all() {
                p.pin(g.as_ref());
            }
            for (i, g) in groups.iter().enumerate() {
                let steered =
                    matches!(accel.get(i), Some(AccelStatus::Steering(s)) if s.pinned_threads > 0);
                if !steered
                    && !unplaced.contains(&i)
                    && !shared_flags.get(i).copied().unwrap_or(false)
                {
                    p.pin(g.as_ref());
                }
            }
        }
        let entries = kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| Entry {
                id: ListenerId(i as u64),
                group: groups[i].clone(),
                accel: accel[i].clone(),
                kind,
                index: Some(i),
            })
            .collect::<Vec<_>>();
        let next_id = entries.len() as u64;
        Ok(Engine {
            groups,
            pool,
            udp_client,
            udp_listeners,
            tcp_dial,
            accel,
            telemetry,
            numa: Box::new(numa),
            rt: Box::new(Runtime {
                state: Mutex::new(RtState {
                    entries,
                    leaving: Vec::new(),
                    next_id,
                    started: false,
                    stopped: false,
                }),
                stopped: Condvar::new(),
                shared: Mutex::new(shared_groups),
                pinner: Mutex::new(pinner),
                io_threads,
                cfg: rt_cfg,
                env_backend,
                env_scheduling,
                numa_cfg,
                numa_nodes: rt_nodes,
                max_listeners: self.max_listeners.unwrap_or(DEFAULT_MAX_LISTENERS),
            }),
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

/// Binds a Unix-domain listener at `path` (ADR-121): a socket file no one listens on is
/// replaced, one in use (or a file that is not a socket) is `AddrInUse`.
fn listen_unix(
    path: &std::path::Path,
    backlog: i32,
    mode: Option<u32>,
) -> io::Result<std::net::TcpListener> {
    match akio_sys::listen_unix(path, backlog, mode) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            use std::os::unix::fs::FileTypeExt;
            let stale = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
                && matches!(
                    akio_sys::connect_unix_nonblocking(path),
                    Err(c) if c.kind() == io::ErrorKind::ConnectionRefused
                );
            if !stale {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{}: in use, or not a socket", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
            akio_sys::listen_unix(path, backlog, mode)
        }
        r => r,
    }
}

/// The group serving an inherited listener (see [`Listener::tcp_from_std`]), or a Unix-domain
/// one (`unix`, ADR-121).
#[allow(clippy::too_many_arguments)]
fn bind_inherited(
    listener: std::net::TcpListener,
    unix: bool,
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
                let opts = akio_uring::UringOptions {
                    entries: u.entries,
                    sqpoll: u.sqpoll,
                };
                let (cfg, pool) = (cfg.clone(), pool.clone());
                return Ok(Box::new(if unix {
                    akio_uring::UringGroup::bind_unix_listener(
                        listener, acceptor, threads, cfg, pool, opts,
                    )?
                } else {
                    akio_uring::UringGroup::bind_listener(
                        listener, acceptor, threads, cfg, pool, opts,
                    )?
                }));
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
        let (cfg, pool) = (cfg.clone(), pool.clone());
        Ok(Box::new(if unix {
            akio_epoll::EpollGroup::bind_unix_listener(listener, acceptor, threads, cfg, pool)?
        } else {
            akio_epoll::EpollGroup::bind_listener(listener, acceptor, threads, cfg, pool)?
        }))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (listener, unix, acceptor, backend, threads, cfg, pool);
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
    match ebpf::attach_reuseport(&fds, cfg.steering, opts) {
        Ok(mut info) => {
            if cfg.pin_threads {
                if let Ok(sets) = ebpf::cpu_pinning(fds.len()) {
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
    groups: &[Arc<dyn Group>],
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
    groups: Vec<Arc<dyn Group>>,
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
    /// Listeners by id, added and removed at run time (ADR-099).
    rt: Box<Runtime>,
}

/// What the engine needs to add and remove listeners at run time (ADR-099).
struct Runtime {
    state: Mutex<RtState>,
    /// Signalled when `shutdown` is called (`wait`).
    stopped: Condvar,
    /// The shared I/O groups (ADR-130), which the engine shuts down and joins itself.
    shared: Mutex<shared::SharedGroups>,
    /// Pins the I/O threads of groups made later, when `pin_io_threads` is on.
    pinner: Mutex<Option<Pinner>>,
    /// The size of a shared group made by `add_listener`.
    io_threads: usize,
    /// The configuration listeners added later are bound with (live settings from telemetry).
    cfg: Config,
    env_backend: Option<Backend>,
    env_scheduling: Option<Scheduling>,
    numa_cfg: NumaConfig,
    /// The nodes the engine places threads on (empty: no placement).
    numa_nodes: Vec<numa::UsableNode>,
    max_listeners: usize,
}

struct RtState {
    /// The listeners still accepting, by id (build-time ones first).
    entries: Vec<Entry>,
    /// Groups of listeners added at run time and removed since, until their threads exit.
    leaving: Vec<Arc<dyn Group>>,
    next_id: u64,
    started: bool,
    stopped: bool,
}

struct Entry {
    id: ListenerId,
    group: Arc<dyn Group>,
    accel: AccelStatus,
    kind: Kind,
    /// Index in `Engine::groups` of a listener given to the builder.
    index: Option<usize>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn not_found(id: ListenerId) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no {id}"))
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
        // Held throughout: a listener added meanwhile is started here or by `add_listener`.
        let mut st = lock(&self.rt.state);
        self.groups.iter().try_for_each(|g| g.start())?;
        for e in st.entries.iter().filter(|e| e.index.is_none()) {
            e.group.start()?;
        }
        st.started = true;
        drop(st);
        akio_log::info!(target: "akio", listeners:? = self.local_addrs(); "engine started");
        Ok(())
    }

    /// Adds a TCP listener to the engine, running or not (ADR-099): it is bound as
    /// [`EngineBuilder::build`] binds the builder's listeners, with its own backend, thread
    /// count (one `SO_REUSEPORT` socket per thread on Linux), [`Accel`], inherited socket
    /// ([`Listener::tcp_from_std`]) and [`filter`](Listener::filter), the engine's [`Config`]
    /// (with the live settings in force), pool and telemetry, and NUMA placement when the
    /// engine places its threads. Its I/O threads start at once when the engine has started,
    /// else with [`start`](Self::start). Returns its id; [`listeners`](Self::listeners) reports
    /// its address (port 0 resolved).
    ///
    /// Errors: bind errors as from `build`; `InvalidInput` for a UDP or datagram listener
    /// ([`bind_udp`](Self::bind_udp) binds UDP at run time) or one without `serve`;
    /// `Unsupported` for the DPDK backend; `QuotaExceeded` at
    /// [`EngineBuilder::max_listeners`]; `NotConnected` after [`shutdown`](Self::shutdown).
    /// Do not call it from an I/O thread's callback (it binds sockets and may start threads).
    pub fn add_listener(&self, listener: Listener) -> io::Result<ListenerId> {
        self.reap();
        if listener.udp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "add_listener takes TCP listeners (bind_udp binds UDP sockets at run time)",
            ));
        }
        #[cfg(feature = "dpdk")]
        if matches!(listener.backend, Backend::Dpdk(_)) {
            return Err(unsupported("adding a DPDK listener at run time"));
        }
        let rt = &self.rt;
        let mut st = lock(&rt.state);
        if st.stopped {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the engine is shutting down",
            ));
        }
        if st.entries.len() + st.leaving.len() >= rt.max_listeners {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!(
                    "the engine has max_listeners ({}) listeners",
                    rt.max_listeners
                ),
            ));
        }
        let mut cfg = rt.cfg.clone();
        cfg.backlog = self.telemetry.live().backlog();
        let mut shared_groups = lock(&rt.shared);
        let shared_before = shared_groups.groups.len();
        let (g, kind, accel, balance, shares) = bind_one(
            listener,
            rt.env_backend.as_ref(),
            rt.env_scheduling.as_ref(),
            &cfg,
            &self.pool,
            Sharing {
                groups: &mut shared_groups,
                threads: rt.io_threads,
            },
        )?;
        // A shared group made for this listener (the first of its kind).
        let new_shared = (shared_groups.groups.len() > shared_before)
            .then(|| shared_groups.groups.last().map(|(_, g)| g.clone()))
            .flatten();
        drop(shared_groups);
        let g: Arc<dyn Group> = Arc::from(g);
        let accel = apply_accel(&accel, g.as_ref())?;
        let placed = matches!(accel, AccelStatus::Steering(_)) || rt.numa_cfg.incoming_cpu;
        g.set_balance(balance && !placed);
        if !rt.numa_nodes.is_empty() {
            // The report keeps describing the build.
            let _ = place_threads(
                &rt.numa_cfg,
                Ok(rt.numa_nodes.clone()),
                std::slice::from_ref(&g),
                std::slice::from_ref(&accel),
                &[],
                Vec::new(),
            );
        } else if let Some(p) = lock(&rt.pinner).as_mut() {
            let steered = matches!(&accel, AccelStatus::Steering(s) if s.pinned_threads > 0);
            if let Some(sg) = &new_shared {
                p.pin(sg.as_ref());
            } else if !shares && !steered {
                p.pin(g.as_ref());
            }
        }
        if st.started {
            if let Err(e) = g.start() {
                g.shutdown();
                st.leaving.push(g);
                return Err(e);
            }
        }
        let id = ListenerId(st.next_id);
        st.next_id += 1;
        akio_log::info!(target: "akio", listener = id.0, local:% = g.local_addr(), threads = g.threads(); "listener added");
        st.entries.push(Entry {
            id,
            group: g,
            accel,
            kind,
            index: None,
        });
        Ok(id)
    }

    /// Removes listener `id` (ADR-099): it stops accepting and its listening sockets are
    /// closed, while its open connections keep running on the threads that own them
    /// (connections never move). Each of its I/O threads exits once its last connection is
    /// closed, unless they are shared I/O threads (ADR-130), which keep serving the other
    /// listeners (only this listener's sockets close and, with a drain, only its connections);
    /// those of a builder listener that also serve [`dial`](Self::dial) and
    /// [`adopt_tcp`](Self::adopt_tcp) (the last TCP listener when there are no
    /// [`client_threads`](EngineBuilder::client_threads)) stay up for them until shutdown.
    ///
    /// Returns once every I/O thread of the listener has stopped its socket listening (waiting
    /// up to a second for a busy one; called on an I/O thread, it does not wait, and the
    /// threads do so at their next loop iteration): a connection made after that is not
    /// accepted by the old listener. Connections the kernel had queued and not yet accepted
    /// are reset, as when any listening socket closes. To replace a listener without a gap,
    /// add the new one first: on Linux both share the port (`SO_REUSEPORT`) until the old one
    /// goes, and once this returns new connections go to the new one only. A builder listener stays in
    /// [`local_addrs`](Self::local_addrs) (its index is stable), with no thread in
    /// [`threads`](Self::threads) once they exit.
    ///
    /// Errors: `NotFound` for an unknown or removed id; `Unsupported` for UDP, datagram and
    /// DPDK listeners.
    pub fn remove_listener(&self, id: ListenerId) -> io::Result<()> {
        self.unlisten(id, None)
    }

    /// [`remove_listener`](Self::remove_listener), and drains its connections (ADR-099): each
    /// gets [`Acceptor::on_shutdown`] at once, as in an engine [`shutdown`](Self::shutdown) (an
    /// HTTP server answers with `Connection: close` or GOAWAY), and those still open after
    /// `drain` are closed (`on_close` runs). `Duration::ZERO` closes them at the threads' next
    /// loop iteration. A builder listener whose threads also serve `dial` drains the dialed
    /// connections too. Errors as for `remove_listener`.
    pub fn shutdown_listener(&self, id: ListenerId, drain: Duration) -> io::Result<()> {
        self.unlisten(id, Some(drain))
    }

    fn unlisten(&self, id: ListenerId, drain: Option<Duration>) -> io::Result<()> {
        self.reap();
        let mut st = lock(&self.rt.state);
        let pos = st
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| not_found(id))?;
        let e = &st.entries[pos];
        if e.kind != Kind::Tcp {
            return Err(unsupported("removing a UDP, datagram or DPDK listener"));
        }
        // The threads of the group `dial` uses stay for dials.
        let dials_here = e.index.is_some() && e.index == self.tcp_dial;
        e.group.stop_listening(drain, !dials_here)?;
        let e = st.entries.remove(pos);
        akio_log::info!(target: "akio", listener = id.0, local:% = e.group.local_addr(), drain:? = drain; "listener removed");
        let group = Arc::clone(&e.group);
        if e.index.is_none() {
            st.leaving.push(e.group);
        }
        drop(st);
        group.await_unlisted(UNLISTEN_WAIT);
        Ok(())
    }

    /// Joins the groups of removed listeners whose threads have all exited, and takes their
    /// threads out of the metrics (their counts stay in the totals).
    fn reap(&self) {
        let done: Vec<Arc<dyn Group>> = {
            let mut st = lock(&self.rt.state);
            let (done, keep) = std::mem::take(&mut st.leaving)
                .into_iter()
                .partition(|g| g.finished());
            st.leaving = keep;
            done
        };
        for g in done {
            g.join();
            self.telemetry.unregister_loops(&g.loop_stats());
        }
    }

    /// The listeners still accepting connections (ADR-099): the builder's first, in the order
    /// they were added, then those added with [`add_listener`](Self::add_listener).
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.reap();
        lock(&self.rt.state)
            .entries
            .iter()
            .map(|e| ListenerInfo {
                id: e.id,
                local_addr: e.group.local_addr(),
                threads: e.group.threads(),
                accel: e.accel.clone(),
                udp: matches!(
                    e.kind,
                    Kind::Udp | Kind::Datagrams | Kind::Dpdk { udp: true }
                ),
            })
            .collect()
    }

    /// The group of listener `id` (still accepting) and its acceleration.
    fn entry_group(&self, id: ListenerId) -> io::Result<(Arc<dyn Group>, AccelStatus, Kind)> {
        let st = lock(&self.rt.state);
        let e = st
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| not_found(id))?;
        Ok((e.group.clone(), e.accel.clone(), e.kind))
    }

    /// [`set_threads`](Self::set_threads) for listener `id`, a builder listener or one added
    /// at run time (ADR-099). Same rules and errors, and `NotFound` for an unknown or removed
    /// id.
    pub fn set_listener_threads(&self, id: ListenerId, threads: usize) -> io::Result<()> {
        let (g, accel, _) = self.entry_group(id)?;
        if matches!(accel, AccelStatus::Steering(_)) {
            return Err(unsupported(
                "changing the thread count of a listener with BPF steering",
            ));
        }
        let before = g.threads();
        g.set_threads(threads)?;
        akio_log::info!(target: "akio", listener = id.0, local:% = g.local_addr(), from = before, to = threads.max(1); "I/O threads changed");
        Ok(())
    }

    /// Installs or replaces the accept filter of TCP listener `id` (see [`Listener::filter`]):
    /// every `accept` that starts after this returns runs it, on every I/O thread. `NotFound` for an unknown
    /// or removed id, `Unsupported` for UDP, datagram and DPDK listeners.
    pub fn set_listener_filter(
        &self,
        id: ListenerId,
        filter: impl Fn(&SocketAddr) -> bool + Send + Sync + 'static,
    ) -> io::Result<()> {
        self.swap_filter(id, Some(Arc::new(filter)))
    }

    /// Removes the accept filter of TCP listener `id`: every connection is accepted again.
    /// Errors as for [`set_listener_filter`](Self::set_listener_filter).
    pub fn clear_listener_filter(&self, id: ListenerId) -> io::Result<()> {
        self.swap_filter(id, None)
    }

    fn swap_filter(&self, id: ListenerId, filter: Option<AcceptFilter>) -> io::Result<()> {
        let (g, _, kind) = self.entry_group(id)?;
        if kind != Kind::Tcp {
            return Err(unsupported(
                "an accept filter on a UDP, datagram or DPDK listener",
            ));
        }
        g.set_filter(filter)
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
    /// (`max_pending_responses`, `connect_timeout`, `udp_max_peers`, `udp_gro`) are reported in [`ReloadReport::ignored`] when they differ. Thread counts
    /// change with [`set_threads`](Self::set_threads); listeners, backends and pool sizes need
    /// a restart.
    pub fn reload(&self, cfg: &Config) -> ReloadReport {
        self.telemetry.reload(cfg)
    }

    /// Active I/O threads of each listener (and client group), in
    /// [`local_addrs`](Self::local_addrs) order. Retiring threads (see
    /// [`set_threads`](Self::set_threads)) are not counted. Listeners that share I/O threads
    /// (ADR-130) each report the shared group's count; a removed one reports 0.
    pub fn threads(&self) -> Vec<usize> {
        self.groups.iter().map(|g| g.threads()).collect()
    }

    /// Changes the number of I/O threads of group `index` (in [`local_addrs`](Self::local_addrs)
    /// order: the listeners, then the client groups) to `threads` (at least 1) while the engine
    /// runs (ADR-028). TCP listeners and client groups on epoll, kqueue and io_uring support it.
    /// For a listener that shares I/O threads (ADR-130) it resizes the shared group, so every
    /// listener of that group gets the new count.
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

    /// Blocks until [`shutdown`](Self::shutdown) has completed: it was called and every I/O
    /// thread has exited, those of listeners added at run time included.
    pub fn wait(&self) {
        self.groups.iter().for_each(|g| g.join());
        let mut st = lock(&self.rt.state);
        while !st.stopped {
            st = self.rt.stopped.wait(st).unwrap_or_else(|p| p.into_inner());
        }
        // No listener is added any more.
        let mut rest: Vec<Arc<dyn Group>> = std::mem::take(&mut st.leaving);
        rest.extend(
            st.entries
                .iter()
                .filter(|e| e.index.is_none())
                .map(|e| e.group.clone()),
        );
        // The shared groups (ADR-130), which no listener handle joins.
        rest.extend(lock(&self.rt.shared).all());
        drop(st);
        for g in &rest {
            g.join();
        }
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
        let mut st = lock(&self.rt.state);
        st.stopped = true;
        self.rt.stopped.notify_all();
        self.groups.iter().for_each(|g| g.shutdown());
        st.entries
            .iter()
            .filter(|e| e.index.is_none())
            .for_each(|e| e.group.shutdown());
        st.leaving.iter().for_each(|g| g.shutdown());
        // The shared groups (ADR-130): their listeners' handles leave this to the engine.
        lock(&self.rt.shared)
            .all()
            .iter()
            .for_each(|g| g.shutdown());
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

    /// Connects to the Unix-domain stream socket at `path`, as the Docker daemon's
    /// `/var/run/docker.sock`, and serves the connection with `acceptor` on an I/O thread, as
    /// [`dial`](Self::dial) does a TCP one (ADR-120): `on_open` once connected, `on_error` if the
    /// connect fails (no such socket, refused, a full backlog as `WouldBlock`, a path too long
    /// for `sun_path`). The connection's `peer_addr` and `local_addr` are
    /// [`UNIX_ADDR`]; what is TCP's only (`TCP_NODELAY`, `TCP_INFO`) is not
    /// set or reported. The engine must have been [`start`](Self::start)ed.
    pub fn dial_unix<A: Acceptor>(
        &self,
        path: &std::path::Path,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let Some(g) = self.tcp_dial.and_then(|i| self.groups.get(i)) else {
            return on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no I/O threads",
            ));
        };
        match akio_sys::connect_unix_nonblocking(path) {
            // The backends hold every stream socket as a `TcpStream`; only what any stream
            // socket supports is done with this one.
            Ok(fd) => g.dial_unix(
                std::net::TcpStream::from(fd),
                Arc::new(acceptor),
                Box::new(on_error),
            ),
            Err(e) => on_error(e),
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
