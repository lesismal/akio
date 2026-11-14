#![forbid(unsafe_code)]
//! `only` prefork: serve one program from several worker processes, each running its own `only`
//! [`Engine`](only::Engine), under a supervisor that restarts crashed workers, drains them on
//! shutdown and swaps them for new ones on reload.
//!
//! The process [`Prefork::run`] is called in becomes the **supervisor**: it binds (or reserves)
//! the listening addresses, starts the workers by re-executing the current binary with the same
//! arguments and a few `ONLY_PREFORK_*` environment variables, and serves nothing itself. In a
//! **worker** the same call finds those variables and runs your `serve` closure with a
//! [`Worker`]: its index, the listeners to serve, and a [`Worker::serve`] that runs an engine
//! until the supervisor (or a signal) asks the worker to stop. Re-executing instead of forking
//! keeps clear of the fork-after-threads hazards of a multi-threaded Rust program: every worker
//! starts from `main` with a clean address space.
//!
//! ```no_run
//! use only::{Conn, Engine, Handler, fn_acceptor};
//! use only_prefork::Prefork;
//!
//! struct Echo;
//! impl Handler for Echo {
//!     fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
//!         let _ = c.send(data);
//!     }
//! }
//!
//! fn main() -> std::io::Result<()> {
//!     Prefork::new()
//!         .workers(4)
//!         .listen("0.0.0.0:8080".parse().unwrap())
//!         .run(|worker| {
//!             let engine = Engine::builder()
//!                 .listen(worker.listener(0)?.threads(2).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
//!                 .build()?;
//!             worker.serve(&engine)
//!         })
//! }
//! ```
//!
//! **Listening sockets** ([`ListenMode`]): with [`ListenMode::ReusePort`] every worker binds the
//! address itself with `SO_REUSEPORT` and the kernel spreads connections over all the workers'
//! sockets (Linux; the supervisor only reserves the port). With [`ListenMode::Inherit`] the
//! supervisor binds one listening socket and the workers inherit it: they share one accept
//! queue, nothing is lost when a worker exits, and it works where `SO_REUSEPORT` does not
//! balance (macOS). [`ListenMode::Auto`], the default, picks `ReusePort` on Linux and `Inherit`
//! elsewhere.
//!
//! **Lifecycle**: SIGTERM or SIGINT to the supervisor (or [`Supervisor::shutdown`]) asks every
//! worker to stop; each drains its engine (`Engine::shutdown`: stop accepting, let in-flight
//! requests finish) and exits, and workers still running after
//! [`Prefork::shutdown_timeout`] are killed. SIGHUP (or [`Supervisor::reload`]) starts a new
//! generation of workers and stops each old worker once its replacement reported ready. A worker
//! that exits on its own is restarted after an exponential backoff. Workers run in their own
//! process group (a terminal's Ctrl-C reaches only the supervisor, which drains them), stop when
//! the supervisor dies, and on Linux can be pinned to CPUs ([`CpuPinning`]).
//!
//! Supported on Linux and macOS.
//!
//! Guide: [Multi-process serving (prefork)](https://lesismal.github.io/flash/en/prefork.html)
//! (中文: [多进程服务（prefork）](https://lesismal.github.io/flash/zh-CN/prefork.html)).
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![warn(clippy::unwrap_used)]

mod env;
mod supervisor;
mod worker;

use std::{
    ffi::{OsStr, OsString},
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

pub use supervisor::{Controller, Status, Supervisor, WorkerInfo};
pub use worker::Worker;

/// How the workers get their listening sockets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenMode {
    /// [`ReusePort`](Self::ReusePort) on Linux, [`Inherit`](Self::Inherit) elsewhere.
    #[default]
    Auto,
    /// Every worker binds the address itself with `SO_REUSEPORT` (on Linux one socket per I/O
    /// thread) and the kernel spreads new connections over every worker's sockets by a hash of
    /// the connection's addresses. The supervisor binds the address without listening, which
    /// reserves the port (and resolves port 0) and receives nothing.
    ///
    /// When a worker's sockets close (it exits, or is drained by a reload) the connections the
    /// kernel had already queued on them but the worker had not accepted are reset; on Linux 5.14
    /// and later, `sysctl net.ipv4.tcp_migrate_req=1` makes the kernel move them to another
    /// worker instead. macOS accepts the binds but does not balance: the most recently bound
    /// socket gets the connections; prefer [`Inherit`](Self::Inherit) there.
    ReusePort,
    /// The supervisor binds and listens once; every worker inherits that socket (its I/O threads
    /// share it and race to accept). No connection is lost when a worker exits or is reloaded:
    /// the socket keeps listening in the supervisor and queued connections wait for the next
    /// `accept`. Balancing is by whichever worker accepts first.
    Inherit,
}

impl ListenMode {
    /// The mode `Auto` stands for on this platform.
    fn resolve(self) -> ListenMode {
        match self {
            ListenMode::Auto if cfg!(target_os = "linux") => ListenMode::ReusePort,
            ListenMode::Auto => ListenMode::Inherit,
            m => m,
        }
    }
}

/// Which CPUs each worker may run on (Linux; ignored with a warning elsewhere).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpuPinning {
    /// No pinning (the default): the scheduler places every thread.
    #[default]
    None,
    /// Worker `i` runs on CPU `i % available CPUs`: with one worker per core and a few I/O threads
    /// each, every worker's threads stay on one core and its caches.
    PerWorker,
    /// Worker `i` runs on the CPUs of `sets[i % sets.len()]` (CPU numbers as the kernel counts
    /// them). An empty list pins nothing.
    Sets(Vec<Vec<usize>>),
}

impl CpuPinning {
    fn cpus_for(&self, index: usize) -> Vec<usize> {
        match self {
            CpuPinning::None => Vec::new(),
            CpuPinning::PerWorker => {
                let n = std::thread::available_parallelism().map_or(1, |n| n.get());
                vec![index % n]
            }
            CpuPinning::Sets(sets) if sets.is_empty() => Vec::new(),
            CpuPinning::Sets(sets) => sets[index % sets.len()].clone(),
        }
    }
}

/// Default of [`Prefork::shutdown_timeout`].
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
/// Default of [`Prefork::ready_timeout`].
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Default first delay of [`Prefork::restart_backoff`].
pub const DEFAULT_RESTART_MIN: Duration = Duration::from_millis(100);
/// Default longest delay of [`Prefork::restart_backoff`].
pub const DEFAULT_RESTART_MAX: Duration = Duration::from_secs(10);

/// Configures and starts a prefork server; see the [crate docs](crate).
#[derive(Clone, Debug)]
pub struct Prefork {
    pub(crate) workers: usize,
    pub(crate) listen: Vec<SocketAddr>,
    pub(crate) mode: ListenMode,
    pub(crate) pinning: CpuPinning,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) ready_timeout: Duration,
    pub(crate) restart_min: Duration,
    pub(crate) restart_max: Duration,
    pub(crate) program: Option<PathBuf>,
    pub(crate) args: Option<Vec<OsString>>,
    pub(crate) envs: Vec<(OsString, OsString)>,
    pub(crate) backlog: i32,
    pub(crate) signals: bool,
}

impl Default for Prefork {
    fn default() -> Self {
        Prefork::new()
    }
}

impl Prefork {
    /// One worker per available CPU, no listeners yet, [`ListenMode::Auto`], signal handling on.
    pub fn new() -> Prefork {
        Prefork {
            workers: std::thread::available_parallelism().map_or(1, |n| n.get()),
            listen: Vec::new(),
            mode: ListenMode::Auto,
            pinning: CpuPinning::None,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            ready_timeout: DEFAULT_READY_TIMEOUT,
            restart_min: DEFAULT_RESTART_MIN,
            restart_max: DEFAULT_RESTART_MAX,
            program: None,
            args: None,
            envs: Vec::new(),
            backlog: 1024,
            signals: true,
        }
    }

    /// Number of worker processes. 0 runs `serve` in this process instead, with a single
    /// [`Worker`] that binds the listeners itself (handy under a debugger).
    #[must_use]
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n;
        self
    }

    /// Adds a TCP address to listen on; [`Worker::listener`] takes listeners in the order they
    /// were added. Port 0 picks a free port once, in the supervisor, for every worker.
    #[must_use]
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen.push(addr);
        self
    }

    /// How the workers get their listening sockets (default [`ListenMode::Auto`]).
    #[must_use]
    pub fn mode(mut self, mode: ListenMode) -> Self {
        self.mode = mode;
        self
    }

    /// Pins workers to CPUs (Linux).
    #[must_use]
    pub fn pin_cpus(mut self, pinning: CpuPinning) -> Self {
        self.pinning = pinning;
        self
    }

    /// How long a worker asked to stop may take to drain before it is killed (default 30 s).
    /// Keep it above the engines' `Config::shutdown_timeout`.
    #[must_use]
    pub fn shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }

    /// How long a worker started by a reload may take to report ready ([`Worker::ready`], which
    /// [`Worker::serve`] calls) before it is killed and the old worker kept (default 30 s).
    #[must_use]
    pub fn ready_timeout(mut self, d: Duration) -> Self {
        self.ready_timeout = d;
        self
    }

    /// A worker that exits on its own is restarted after `min`, doubling with every further
    /// failure of the same worker slot up to `max`; a worker that ran at least `max` resets its
    /// slot to `min` (defaults 100 ms and 10 s).
    #[must_use]
    pub fn restart_backoff(mut self, min: Duration, max: Duration) -> Self {
        self.restart_min = min;
        self.restart_max = max.max(min);
        self
    }

    /// The program the workers run (default: this process's executable).
    #[must_use]
    pub fn program(mut self, path: impl AsRef<Path>) -> Self {
        self.program = Some(path.as_ref().to_path_buf());
        self
    }

    /// The workers' arguments (default: this process's arguments).
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args = Some(args.into_iter().map(|a| a.as_ref().to_owned()).collect());
        self
    }

    /// Sets an environment variable for the workers (on top of this process's environment).
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.envs
            .push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    /// `listen(2)` backlog of the sockets the supervisor or the workers bind (default 1024).
    #[must_use]
    pub fn backlog(mut self, backlog: i32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Whether [`run`](Self::run) handles SIGTERM / SIGINT (graceful shutdown; a second one kills
    /// the workers) and SIGHUP (reload) in the supervisor (default: true).
    #[must_use]
    pub fn handle_signals(mut self, on: bool) -> Self {
        self.signals = on;
        self
    }

    /// In a worker started by a supervisor, runs `serve` with this worker's [`Worker`] and
    /// returns what it returns. Otherwise makes this process the supervisor: starts the workers,
    /// supervises them until SIGTERM / SIGINT (see [`handle_signals`](Self::handle_signals)), then
    /// drains them and returns. With [`workers(0)`](Self::workers) it runs `serve` in this
    /// process.
    pub fn run<F>(self, serve: F) -> io::Result<()>
    where
        F: FnOnce(Worker) -> io::Result<()>,
    {
        if let Some(w) = Worker::from_env()? {
            return serve(w);
        }
        if self.workers == 0 {
            return serve(Worker::standalone(&self)?);
        }
        let signals = self.signals;
        let sup = self.spawn()?;
        if signals {
            supervisor::forward_signals(sup.controller())?;
        }
        sup.wait()
    }

    /// Starts the supervisor on a thread of its own and returns its handle: the workers are
    /// being started. Unlike [`run`](Self::run) it installs no signal handlers. Call it in the
    /// supervisor only (see [`is_worker`]).
    pub fn spawn(self) -> io::Result<Supervisor> {
        if self.workers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prefork: spawn needs at least one worker",
            ));
        }
        Supervisor::start(self)
    }
}

/// Whether this process is a worker started by a prefork supervisor.
pub fn is_worker() -> bool {
    std::env::var_os(env::WORKER).is_some()
}
