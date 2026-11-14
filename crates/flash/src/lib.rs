#![forbid(unsafe_code)]
//! flash: an event-driven network library. This facade crate re-exports the core API and
//! provides [`Engine`], which composes one backend *group* per listener (ADR-004).
//!
//! ```no_run
//! use flash::{Conn, Engine, Handler, Listener, fn_acceptor};
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

use std::{io, net::SocketAddr, sync::Arc};

/// TLS (rustls): wrap an acceptor in [`tls::Tls`] to serve or dial over TLS.
pub use flash_tls as tls;

pub use flash_core::{
    Acceptor, Config, Conn, DynAcceptor, DynHandler, Error, FnAcceptor, Handler, PoolConfig,
    PoolStats, ResponseSlot, Result, SlowCallback, SlowHook, UdpStats, fn_acceptor,
};
use flash_core::{Group, Pool};

/// I/O backend of one listener (ADR-004).
#[derive(Clone, Debug, Default)]
pub enum Backend {
    /// epoll on Linux, kqueue on macOS. The default.
    #[default]
    Epoll,
    /// io_uring (Linux 5.19+). Where the kernel lacks it the listener falls back to epoll, unless
    /// [`UringConfig::strict`] is set, in which case `build` fails with `Unsupported`.
    IoUring(UringConfig),
}

/// io_uring tuning.
#[derive(Clone, Debug, Default)]
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
pub enum Accel {
    /// No acceleration: plain `SO_REUSEPORT` hashing.
    #[default]
    None,
    /// eBPF (M5). Selecting it today makes `build` fail with `Unsupported`.
    Ebpf,
}

/// One bound address with its own acceptor, backend and I/O threads.
pub struct Listener {
    addr: SocketAddr,
    udp: bool,
    backend: Backend,
    accel: Accel,
    threads: usize,
    acceptor: Option<Arc<dyn DynAcceptor>>,
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
    pub fn backend(mut self, b: Backend) -> Self {
        self.backend = b;
        self
    }

    /// Chooses this listener's acceleration layer.
    pub fn accel(mut self, a: Accel) -> Self {
        self.accel = a;
        self
    }

    /// Number of I/O threads for this listener (default: one per core).
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n.max(1);
        self
    }

    /// Attaches the acceptor that serves this listener.
    pub fn serve<A: Acceptor>(mut self, acceptor: A) -> Self {
        self.acceptor = Some(Arc::new(acceptor));
        self
    }

    /// Attaches a type-erased acceptor (for protocol multiplexers such as `flash-mux`).
    #[doc(hidden)]
    pub fn serve_dyn(mut self, acceptor: Arc<dyn DynAcceptor>) -> Self {
        self.acceptor = Some(acceptor);
        self
    }
}

/// Builds an [`Engine`].
#[derive(Default)]
pub struct EngineBuilder {
    listeners: Vec<Listener>,
    client_threads: usize,
    udp_client_threads: usize,
    cfg: Config,
    pool: PoolConfig,
}

impl EngineBuilder {
    /// Adds a listener.
    pub fn listen(mut self, l: Listener) -> Self {
        self.listeners.push(l);
        self
    }

    /// Adds `n` I/O threads that only serve connections made with [`Engine::dial`]. Without it,
    /// dialed connections run on the threads of the last listener added.
    pub fn client_threads(mut self, n: usize) -> Self {
        self.client_threads = n;
        self
    }

    /// Replaces the default [`Config`].
    pub fn config(mut self, cfg: Config) -> Self {
        self.cfg = cfg;
        self
    }

    /// Adds `n` I/O threads for connections made with [`Engine::dial_udp`]. Without it, UDP
    /// dials run on the threads of the last UDP listener added (and fail if there is none).
    pub fn udp_client_threads(mut self, n: usize) -> Self {
        self.udp_client_threads = n;
        self
    }

    /// Sizes the logical pool that runs [`Conn::spawn_blocking`] work (default: no threads until
    /// used, up to 8 per core, 65,536 queued jobs).
    pub fn pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool;
        self
    }

    /// Validates the configuration, binds every listener and prepares the I/O threads.
    pub fn build(self) -> io::Result<Engine> {
        let mut groups: Vec<Box<dyn Group>> = Vec::new();
        let pool = Pool::new(self.pool.clone());
        let mut udp_last: Option<usize> = None;
        for l in self.listeners {
            if matches!(l.accel, Accel::Ebpf) {
                return Err(unsupported("eBPF acceleration (planned for M5)"));
            }
            let acceptor = l.acceptor.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
            })?;
            if l.udp {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if let Backend::IoUring(u) = &l.backend {
                        if u.strict {
                            return Err(unsupported("UDP on the io_uring backend"));
                        }
                    }
                    udp_last = Some(groups.len());
                    groups.push(Box::new(flash_epoll::UdpGroup::bind(
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
            match l.backend {
                Backend::Epoll => {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    groups.push(Box::new(flash_epoll::EpollGroup::bind(
                        Some((l.addr, acceptor)),
                        l.threads,
                        self.cfg.clone(),
                        pool.clone(),
                    )?));
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    return Err(unsupported("the epoll/kqueue backend on this platform"));
                }
                Backend::IoUring(u) => {
                    #[cfg(target_os = "linux")]
                    match flash_uring::probe() {
                        Ok(()) => groups.push(Box::new(flash_uring::UringGroup::bind(
                            Some((l.addr, acceptor)),
                            l.threads,
                            self.cfg.clone(),
                            pool.clone(),
                            flash_uring::UringOptions {
                                entries: u.entries,
                                sqpoll: u.sqpoll,
                            },
                        )?)),
                        Err(why) if u.strict => {
                            return Err(unsupported(&format!("the io_uring backend ({why})")));
                        }
                        Err(why) => {
                            eprintln!("flash: io_uring unavailable ({why}); using epoll");
                            groups.push(Box::new(flash_epoll::EpollGroup::bind(
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
                        eprintln!("flash: io_uring is Linux-only; using epoll/kqueue");
                        groups.push(Box::new(flash_epoll::EpollGroup::bind(
                            Some((l.addr, acceptor)),
                            l.threads,
                            self.cfg.clone(),
                            pool.clone(),
                        )?));
                    }
                }
            }
        }
        if self.client_threads > 0 {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups.push(Box::new(flash_epoll::EpollGroup::bind(
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
                groups.push(Box::new(flash_epoll::UdpGroup::bind(
                    None,
                    self.udp_client_threads,
                    self.cfg.clone(),
                    pool.clone(),
                )?));
            }
        }
        Ok(Engine {
            groups,
            pool,
            udp_client,
        })
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
#[derive(Clone, Default)]
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

    /// Spawns the I/O threads and returns immediately. Idempotent.
    pub fn start(&self) -> io::Result<()> {
        self.groups.iter().try_for_each(|g| g.start())
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
            .fold(UdpStats::default(), |a, b| UdpStats {
                peers: a.peers + b.peers,
                rejected: a.rejected + b.rejected,
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

    /// Connects to `addr` without blocking. When established, `acceptor.on_open` runs on an I/O
    /// thread exactly as for an accepted connection; on failure `on_error` is called instead.
    /// The engine must have been [`start`](Self::start)ed.
    pub fn dial<A: Acceptor>(
        &self,
        addr: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        match self.groups.last() {
            // The last group is the client group when `client_threads` was set, else a listener's.
            Some(g) => g.dial(addr, Arc::new(acceptor), Box::new(on_error)),
            None => on_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "engine has no I/O threads",
            )),
        }
    }
}
