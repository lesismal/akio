//! The worker side: what a worker learns from its supervisor and how it stops.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::net::UnixStream,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use only::{AccelStatus, Engine, Listener};
use only_sys::process as sys;

use crate::{ListenMode, Prefork, env};

/// A latch: set once, waited on by any number of threads.
#[derive(Debug, Default)]
pub(crate) struct Latch {
    set: Mutex<bool>,
    cv: Condvar,
}

impl Latch {
    pub(crate) fn set(&self) {
        *self.set.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.cv.notify_all();
    }

    pub(crate) fn is_set(&self) -> bool {
        *self.set.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn wait(&self) {
        let mut g = self.set.lock().unwrap_or_else(|p| p.into_inner());
        while !*g {
            g = self.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }

    pub(crate) fn wait_timeout(&self, d: Duration) -> bool {
        let g = self.set.lock().unwrap_or_else(|p| p.into_inner());
        let (g, _) = self
            .cv
            .wait_timeout_while(g, d, |s| !*s)
            .unwrap_or_else(|p| p.into_inner());
        *g
    }
}

/// One worker process, as [`Prefork::run`] hands it to `serve`: which worker it is, the
/// listeners it serves, and when to stop.
///
/// A worker stops when its supervisor asks it to (shutdown, or a reload that replaced it), when
/// the supervisor dies, or on SIGTERM / SIGINT sent to the worker itself.
#[derive(Debug)]
pub struct Worker {
    index: usize,
    workers: usize,
    generation: u64,
    mode: ListenMode,
    addrs: Vec<SocketAddr>,
    backlog: i32,
    /// `Inherit`: the inherited sockets, taken by `listener`.
    inherited: Mutex<Vec<Option<TcpListener>>>,
    ctl: Option<UnixStream>,
    ready_sent: AtomicBool,
    stop: Arc<Latch>,
    supervised: bool,
    reload: Arc<ReloadHook>,
}

/// The [`Worker::on_reload`] hook and how often it ran.
#[derive(Default)]
struct ReloadHook {
    hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    runs: AtomicU64,
}

impl std::fmt::Debug for ReloadHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadHook")
            .field("runs", &self.runs.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ReloadHook {
    /// Runs the hook (on the calling thread: the control or signal thread, never an I/O
    /// thread); a panic in it is caught and logged.
    fn run(&self) {
        let hook = self.hook.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(h) = hook {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h())).is_err() {
                only::telemetry::log_or_stderr(
                    only_log::Level::Error,
                    format_args!("prefork: the on_reload hook panicked"),
                );
            }
        }
        self.runs.fetch_add(1, Ordering::Relaxed);
    }
}

impl Worker {
    /// The worker this process is, read from the environment its supervisor set; `None` when
    /// this process is not a prefork worker. Takes the inherited descriptors, so it succeeds once
    /// per process ([`Prefork::run`] calls it).
    pub fn from_env() -> io::Result<Option<Worker>> {
        if !crate::is_worker() {
            return Ok(None);
        }
        let index: usize = env::number(env::WORKER)?;
        let workers: usize = env::number(env::WORKERS)?;
        let generation: u64 = env::number(env::GENERATION)?;
        let addrs: Vec<SocketAddr> = env::list(env::ADDRS)?;
        let backlog: i32 = env::number(env::BACKLOG)?;
        let mode = match env::get(env::MODE)?.as_str() {
            "inherit" => ListenMode::Inherit,
            "reuseport" => ListenMode::ReusePort,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("prefork: bad {}={other:?}", env::MODE),
                ));
            }
        };
        let mut inherited = Vec::new();
        if mode == ListenMode::Inherit {
            let fds: Vec<i32> = env::list(env::FDS)?;
            if fds.len() != addrs.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "prefork: inherited fds do not match the addresses",
                ));
            }
            for fd in fds {
                inherited.push(Some(TcpListener::from(sys::take_inherited_fd(fd)?)));
            }
        }
        let ctl = UnixStream::from(sys::take_inherited_fd(env::number(env::CTL)?)?);
        let stop = Arc::new(Latch::default());
        let reload = Arc::new(ReloadHook::default());
        // The supervisor writes MSG_STOP, or dies (EOF): either way, stop. MSG_RELOAD runs the
        // reload hook here.
        let mut reader = ctl.try_clone()?;
        let (s, r) = (stop.clone(), reload.clone());
        std::thread::Builder::new()
            .name("only-prefork-ctl".into())
            .spawn(move || {
                let mut b = [0u8; 1];
                loop {
                    match reader.read(&mut b) {
                        Ok(1) if b[0] == env::MSG_RELOAD => r.run(),
                        Ok(1) if b[0] != env::MSG_STOP => {}
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        _ => break,
                    }
                }
                s.set();
            })?;
        watch_signals(stop.clone(), reload.clone())?;
        Ok(Some(Worker {
            index,
            workers,
            generation,
            mode,
            addrs,
            backlog,
            inherited: Mutex::new(inherited),
            ctl: Some(ctl),
            ready_sent: AtomicBool::new(false),
            stop,
            supervised: true,
            reload,
        }))
    }

    /// The single worker of `Prefork::workers(0)`: binds the listeners in this process.
    pub(crate) fn standalone(cfg: &Prefork) -> io::Result<Worker> {
        let stop = Arc::new(Latch::default());
        let reload = Arc::new(ReloadHook::default());
        watch_signals(stop.clone(), reload.clone())?;
        Ok(Worker {
            index: 0,
            workers: 1,
            generation: 0,
            mode: ListenMode::Auto,
            addrs: cfg.listen.clone(),
            backlog: cfg.backlog,
            inherited: Mutex::new(Vec::new()),
            ctl: None,
            ready_sent: AtomicBool::new(false),
            stop,
            supervised: false,
            reload,
        })
    }

    /// This worker's index, `0..workers()`. A restarted or reloaded worker keeps the index of
    /// the one it replaces, so per-index resources (a log file, a shard) stay put.
    pub fn index(&self) -> usize {
        self.index
    }

    /// How many worker slots the supervisor runs: the number of processes that share whatever
    /// exists once per machine (a database's connection limit, say), so each worker can take its
    /// share. 1 without a supervisor.
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// The generation this worker belongs to: 0 for the first workers, one more per reload.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether a supervisor started this worker (false for [`Prefork::workers`]`(0)`).
    pub fn is_supervised(&self) -> bool {
        self.supervised
    }

    /// How this worker got its listening sockets (`Auto` when it binds them itself without a
    /// supervisor).
    pub fn mode(&self) -> ListenMode {
        self.mode
    }

    /// The listening addresses, in the order [`Prefork::listen`] added them, with port 0
    /// resolved by the supervisor.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// A [`Listener`] for address `i` (in [`Prefork::listen`] order), ready for `.threads(..)`,
    /// `.backend(..)` and `.serve(..)`: the inherited socket ([`ListenMode::Inherit`], once per
    /// address), or a listener that binds the address with `SO_REUSEPORT`.
    pub fn listener(&self, i: usize) -> io::Result<Listener> {
        let addr = *self.addrs.get(i).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("prefork: no listener {i} ({} configured)", self.addrs.len()),
            )
        })?;
        match self.mode {
            ListenMode::Inherit => {
                let mut inherited = self.inherited.lock().unwrap_or_else(|p| p.into_inner());
                let l = inherited.get_mut(i).and_then(Option::take).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("prefork: inherited listener {i} was already taken"),
                    )
                })?;
                Ok(Listener::tcp_from_std(l))
            }
            // Linux: the engine binds one SO_REUSEPORT socket per I/O thread, all in the same
            // group as every other worker's.
            ListenMode::ReusePort if cfg!(target_os = "linux") => Ok(Listener::tcp(addr)),
            // Elsewhere the engine's own first bind would not set SO_REUSEPORT: bind here.
            ListenMode::ReusePort => Ok(Listener::tcp_from_std(only_sys::listen(
                addr,
                true,
                self.backlog,
            )?)),
            _ => Ok(Listener::tcp(addr)),
        }
    }

    /// Tells the supervisor this worker is serving. A reload stops an old worker only once its
    /// replacement is ready. [`serve`](Self::serve) calls it after starting the engine; call it
    /// yourself when you run the engine some other way. Idempotent.
    pub fn ready(&self) {
        if self.ready_sent.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(ctl) = &self.ctl {
            let _ = (&*ctl).write_all(&[env::MSG_READY]);
        }
    }

    /// Sets what an in-place reload runs in this worker: [`Controller::reload_in_place`]
    /// (or SIGUSR1) to the supervisor, or SIGUSR1 to this process. Typically it re-reads the
    /// configuration and applies it to the running engine with `Engine::reload` and
    /// `Engine::set_threads`, which change live settings and I/O thread counts without
    /// touching a connection (ADR-028). It runs on the worker's control thread, never on an
    /// I/O thread, so it may read files; reloads run one at a time. Replaces an earlier hook.
    ///
    /// [`Controller::reload_in_place`]: crate::Controller::reload_in_place
    pub fn on_reload(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.reload.hook.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(hook));
    }

    /// How many in-place reloads this worker ran (with or without a hook).
    pub fn reloads(&self) -> u64 {
        self.reload.runs.load(Ordering::Relaxed)
    }

    /// Whether this worker has been asked to stop.
    pub fn stop_requested(&self) -> bool {
        self.stop.is_set()
    }

    /// Blocks until this worker is asked to stop.
    pub fn wait_for_stop(&self) {
        self.stop.wait();
    }

    /// As [`wait_for_stop`](Self::wait_for_stop), for at most `timeout`; true once asked to stop.
    pub fn wait_for_stop_timeout(&self, timeout: Duration) -> bool {
        self.stop.wait_timeout(timeout)
    }

    /// Runs `engine` until this worker is asked to stop, then drains it: starts it, reports
    /// [`ready`](Self::ready), waits, calls `Engine::shutdown` (stop accepting, let open
    /// connections finish, up to the engine's `Config::shutdown_timeout`) and waits for it.
    pub fn serve(&self, engine: &Engine) -> io::Result<()> {
        engine.start()?;
        self.warn_steering(engine);
        self.ready();
        self.wait_for_stop();
        engine.shutdown();
        engine.wait();
        Ok(())
    }

    /// Per-worker BPF steering in a cross-process `SO_REUSEPORT` group would route every
    /// connection to the sockets of whichever worker attached last (see the crate docs).
    fn warn_steering(&self, engine: &Engine) {
        if self.mode == ListenMode::ReusePort
            && self.workers > 1
            && engine
                .accel_status()
                .iter()
                .any(|s| matches!(s, AccelStatus::Steering(_)))
        {
            only::telemetry::log_or_stderr(
                only_log::Level::Warn,
                format_args!(
                    "prefork: worker {}: Accel::Ebpf steering in a SO_REUSEPORT group shared by \
                     {} worker processes replaces the group's program and sends new connections \
                     only to this worker's sockets; use ListenMode::Inherit or drop the Accel",
                    self.index, self.workers
                ),
            );
        }
    }
}

/// Sets `stop` on SIGTERM or SIGINT; runs the reload hook on SIGUSR1.
fn watch_signals(stop: Arc<Latch>, reload: Arc<ReloadHook>) -> io::Result<()> {
    let mut pipe = sys::signal_pipe(&[sys::SIGTERM, sys::SIGINT, sys::SIGUSR1])?;
    std::thread::Builder::new()
        .name("only-prefork-sig".into())
        .spawn(move || {
            let mut b = [0u8; 1];
            loop {
                match pipe.read(&mut b) {
                    Ok(1) => {
                        let sig = i32::from(b[0]);
                        if sig == sys::SIGTERM || sig == sys::SIGINT {
                            stop.set();
                        } else if sig == sys::SIGUSR1 {
                            reload.run();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    _ => return,
                }
            }
        })?;
    Ok(())
}
