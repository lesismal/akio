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

pub use flash_core::{Acceptor, Config, Conn, Error, FnAcceptor, Handler, Result, fn_acceptor};
use flash_core::{DynAcceptor, Group};

/// I/O backend of one listener (ADR-004).
#[derive(Clone, Debug, Default)]
pub enum Backend {
    /// epoll on Linux, kqueue on macOS. The default.
    #[default]
    Epoll,
    /// io_uring (M2). Selecting it today makes `build` fail with `Unsupported`.
    IoUring(UringConfig),
}

/// io_uring tuning.
#[derive(Clone, Debug, Default)]
pub struct UringConfig {
    /// Submission queue depth (0 = default).
    pub entries: u32,
    /// Use a kernel SQ polling thread.
    pub sqpoll: bool,
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
            backend: Backend::default(),
            accel: Accel::default(),
            threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            acceptor: None,
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
}

/// Builds an [`Engine`].
#[derive(Default)]
pub struct EngineBuilder {
    listeners: Vec<Listener>,
    client_threads: usize,
    cfg: Config,
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

    /// Validates the configuration, binds every listener and prepares the I/O threads.
    pub fn build(self) -> io::Result<Engine> {
        let mut groups: Vec<Box<dyn Group>> = Vec::new();
        for l in self.listeners {
            if matches!(l.accel, Accel::Ebpf) {
                return Err(unsupported("eBPF acceleration (planned for M5)"));
            }
            let acceptor = l.acceptor.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "listener without .serve(..)")
            })?;
            match l.backend {
                Backend::Epoll => {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    groups.push(Box::new(flash_epoll::EpollGroup::bind(
                        Some((l.addr, acceptor)),
                        l.threads,
                        self.cfg.clone(),
                    )?));
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    return Err(unsupported("the epoll/kqueue backend on this platform"));
                }
                Backend::IoUring(_) => {
                    return Err(unsupported("the io_uring backend (planned for M2)"));
                }
            }
        }
        if self.client_threads > 0 {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups.push(Box::new(flash_epoll::EpollGroup::bind(
                None,
                self.client_threads,
                self.cfg.clone(),
            )?));
        }
        Ok(Engine { groups })
    }
}

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not supported"),
    )
}

/// A set of listeners, each served by its own backend group of I/O threads.
///
/// `Engine` is `Send + Sync`: share it in an `Arc` to call [`shutdown`](Engine::shutdown) or
/// [`dial`](Engine::dial) from other threads while [`run`](Engine::run) blocks.
pub struct Engine {
    groups: Vec<Box<dyn Group>>,
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
