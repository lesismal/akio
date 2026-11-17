//! The supervisor: starts, watches, restarts, drains and reloads the workers.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use only::telemetry::log_or_stderr;
use only_sys::process as sys;

use crate::{ListenMode, Prefork, env};

/// How often the supervisor looks at its workers when nothing else wakes it.
const TICK: Duration = Duration::from_millis(10);

/// What the supervisor knows about one running worker process.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerInfo {
    /// The worker's index (`Worker::index`).
    pub index: usize,
    /// Its process id.
    pub pid: u32,
    /// Its generation (`Worker::generation`).
    pub generation: u64,
    /// It reported ready (`Worker::ready`).
    pub ready: bool,
    /// It was asked to stop and is draining.
    pub draining: bool,
}

/// A snapshot of the supervisor ([`Supervisor::status`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status {
    /// The current generation: 0 at start, one more per reload.
    pub generation: u64,
    /// Every worker process alive: the serving ones, a reload's not yet ready ones, and the
    /// draining ones.
    pub workers: Vec<WorkerInfo>,
    /// Workers restarted after exiting on their own.
    pub restarts: u64,
    /// Reloads requested.
    pub reloads: u64,
    /// In-place reloads requested ([`Controller::reload_in_place`]).
    pub in_place_reloads: u64,
    /// Shutdown was requested.
    pub stopping: bool,
}

impl Status {
    /// The workers of the current generation that are serving and not draining, one per index
    /// at most: what `workers` serving workers look like once a start or a reload completed.
    pub fn serving(&self) -> Vec<&WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.generation == self.generation && w.ready && !w.draining)
            .collect()
    }
}

enum Cmd {
    Reload,
    ReloadInPlace,
    Shutdown,
}

/// A cloneable, `Send` remote control of a [`Supervisor`].
#[derive(Clone, Debug)]
pub struct Controller {
    tx: mpsc::Sender<Cmd>,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Cmd::Reload => "Reload",
            Cmd::ReloadInPlace => "ReloadInPlace",
            Cmd::Shutdown => "Shutdown",
        })
    }
}

impl Controller {
    /// Graceful reload: starts a new generation of workers and stops each old worker once its
    /// replacement reported ready (a replacement not ready within `Prefork::ready_timeout` is
    /// killed and the old worker kept). Workers re-read whatever they load at start-up, and pick
    /// up a new binary if the program file was replaced.
    pub fn reload(&self) {
        let _ = self.tx.send(Cmd::Reload);
    }

    /// Reload in place: asks every running worker (serving, or a reload's not yet ready one)
    /// to run its [`Worker::on_reload`](crate::Worker::on_reload) hook, which typically re-reads
    /// its configuration and applies it with `Engine::reload` and `Engine::set_threads`. No
    /// process is replaced and no connection is touched: only live settings change (ADR-028).
    /// A worker without a hook ignores it. A worker started later (a restart after a crash, a
    /// [`reload`](Self::reload)) starts from whatever its start-up code loads, so keep the
    /// configuration source up to date. SIGUSR1 to the supervisor does the same.
    pub fn reload_in_place(&self) {
        let _ = self.tx.send(Cmd::ReloadInPlace);
    }

    /// Graceful shutdown: asks every worker to drain and stop, kills those still running after
    /// `Prefork::shutdown_timeout`. A second call kills the remaining workers at once.
    pub fn shutdown(&self) {
        let _ = self.tx.send(Cmd::Shutdown);
    }
}

/// A running supervisor ([`Prefork::spawn`]).
#[derive(Debug)]
pub struct Supervisor {
    ctl: Controller,
    status: Arc<Mutex<Status>>,
    addrs: Vec<SocketAddr>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Supervisor {
    pub(crate) fn start(cfg: Prefork) -> io::Result<Supervisor> {
        let mode = cfg.mode.resolve();
        // Bind (Inherit) or reserve (ReusePort) every address here, so port 0 resolves once and
        // a bad address fails before any worker starts.
        let mut sockets = Vec::with_capacity(cfg.listen.len());
        for &a in &cfg.listen {
            sockets.push(match mode {
                ListenMode::Inherit => only_sys::listen(a, false, cfg.backlog)?,
                _ => sys::reserve_reuseport(a)?,
            });
        }
        let addrs = sockets
            .iter()
            .map(TcpListener::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        let program = match &cfg.program {
            Some(p) => p.clone(),
            None => std::env::current_exe()?,
        };
        let args = cfg
            .args
            .clone()
            .unwrap_or_else(|| std::env::args_os().skip(1).collect());
        let status = Arc::new(Mutex::new(Status::default()));
        let (tx, rx) = mpsc::channel();
        let mut state = State {
            spawner: Spawner {
                program,
                args,
                mode,
                addrs: addrs.clone(),
                sockets,
                cfg,
            },
            slots: Vec::new(),
            pending: Vec::new(),
            draining: Vec::new(),
            generation: 0,
            restarts: 0,
            reloads: 0,
            in_place_reloads: 0,
            stopping: false,
            status: status.clone(),
        };
        // Every worker is started from the supervisor thread: on Linux their parent-death signal
        // fires when the thread that spawned them exits, which must be when the last worker is
        // gone, not when the caller's thread ends. The first generation is started before
        // `spawn` returns, so a program that cannot be started fails it.
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("only-prefork".into())
            .spawn(move || {
                for i in 0..state.spawner.cfg.workers {
                    match state.spawner.spawn(i, 0) {
                        Ok(p) => state.slots.push(Slot {
                            proc: Some(p),
                            failures: 0,
                            restart_at: None,
                        }),
                        Err(e) => {
                            for p in state.all_procs() {
                                p.kill();
                                let _ = p.child.wait();
                            }
                            let _ = started_tx.send(Err(e));
                            return Ok(());
                        }
                    }
                }
                state.publish();
                let _ = started_tx.send(Ok(()));
                state.run(&rx)
            })?;
        match started_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(io::Error::other("prefork: the supervisor thread panicked"));
            }
        }
        Ok(Supervisor {
            ctl: Controller { tx },
            status,
            addrs,
            thread: Some(thread),
        })
    }

    /// The listening addresses, with port 0 resolved.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// A snapshot of the workers and counters.
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// A remote control for other threads (signal handlers, an admin endpoint).
    pub fn controller(&self) -> Controller {
        self.ctl.clone()
    }

    /// See [`Controller::reload`].
    pub fn reload(&self) {
        self.ctl.reload();
    }

    /// See [`Controller::reload_in_place`].
    pub fn reload_in_place(&self) {
        self.ctl.reload_in_place();
    }

    /// See [`Controller::shutdown`].
    pub fn shutdown(&self) {
        self.ctl.shutdown();
    }

    /// Blocks until the supervisor has stopped (after a shutdown, once every worker exited).
    pub fn wait(mut self) -> io::Result<()> {
        match self.thread.take().map(JoinHandle::join) {
            Some(Ok(r)) => r,
            Some(Err(_)) => Err(io::Error::other("prefork: the supervisor thread panicked")),
            None => Ok(()),
        }
    }
}

impl Drop for Supervisor {
    /// A supervisor dropped without [`wait`](Supervisor::wait) shuts down and waits.
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            self.ctl.shutdown();
            let _ = t.join();
        }
    }
}

/// Forwards the supervisor's SIGTERM / SIGINT (shutdown), SIGHUP (reload) and SIGUSR1 (reload
/// in place) to `ctl`.
pub(crate) fn forward_signals(ctl: Controller) -> io::Result<()> {
    let mut pipe = sys::signal_pipe(&[sys::SIGTERM, sys::SIGINT, sys::SIGHUP, sys::SIGUSR1])?;
    std::thread::Builder::new()
        .name("only-prefork-sig".into())
        .spawn(move || {
            let mut b = [0u8; 1];
            loop {
                match pipe.read(&mut b) {
                    Ok(1) => match i32::from(b[0]) {
                        s if s == sys::SIGHUP => ctl.reload(),
                        s if s == sys::SIGUSR1 => ctl.reload_in_place(),
                        s if s == sys::SIGTERM || s == sys::SIGINT => ctl.shutdown(),
                        _ => {}
                    },
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    _ => return,
                }
            }
        })?;
    Ok(())
}

/// Starts worker processes.
struct Spawner {
    program: std::path::PathBuf,
    args: Vec<std::ffi::OsString>,
    mode: ListenMode,
    addrs: Vec<SocketAddr>,
    /// Inherit: the listening sockets; ReusePort: the port reservations. Held for the
    /// supervisor's life.
    sockets: Vec<TcpListener>,
    cfg: Prefork,
}

impl Spawner {
    fn spawn(&self, index: usize, generation: u64) -> io::Result<Proc> {
        let (ours, theirs) = UnixStream::pair()?;
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        for v in env::ALL {
            cmd.env_remove(v);
        }
        cmd.envs(self.cfg.envs.iter().map(|(k, v)| (k, v)));
        let mut inherit = vec![theirs.as_raw_fd()];
        let mode = if self.mode == ListenMode::Inherit {
            inherit.extend(self.sockets.iter().map(AsRawFd::as_raw_fd));
            cmd.env(env::FDS, env::join(&inherit[1..]));
            "inherit"
        } else {
            "reuseport"
        };
        cmd.env(env::WORKER, index.to_string())
            .env(env::WORKERS, self.cfg.workers.to_string())
            .env(env::GENERATION, generation.to_string())
            .env(env::MODE, mode)
            .env(env::ADDRS, env::join(&self.addrs))
            .env(env::CTL, theirs.as_raw_fd().to_string())
            .env(env::BACKLOG, self.cfg.backlog.to_string())
            .stdin(Stdio::null())
            // A terminal's Ctrl-C reaches the supervisor only; it drains the workers.
            .process_group(0);
        let cpus = self.cfg.pinning.cpus_for(index);
        if !cpus.is_empty() && !cfg!(target_os = "linux") {
            log_or_stderr(
                only_log::Level::Warn,
                format_args!("prefork: CPU pinning is Linux-only; worker {index} is not pinned"),
            );
        }
        sys::configure_child(
            &mut cmd,
            &sys::ChildSetup {
                inherit,
                cpus,
                parent_death_signal: Some(sys::SIGTERM),
            },
        );
        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "prefork: starting worker {index} ({}): {e}",
                    self.program.display()
                ),
            )
        })?;
        drop(theirs);
        ours.set_nonblocking(true)?;
        Ok(Proc {
            index,
            generation,
            child,
            ctl: ours,
            ready: false,
            started: Instant::now(),
            stop_deadline: None,
        })
    }
}

/// One worker process.
struct Proc {
    index: usize,
    generation: u64,
    child: Child,
    ctl: UnixStream,
    ready: bool,
    started: Instant,
    /// Set once asked to stop: killed if still running then.
    stop_deadline: Option<Instant>,
}

impl Proc {
    /// Reads what the worker sent; false once its control socket closed.
    fn poll_ctl(&mut self) -> bool {
        let mut buf = [0u8; 16];
        loop {
            match self.ctl.read(&mut buf) {
                Ok(0) => return false,
                Ok(n) => {
                    if buf[..n].contains(&env::MSG_READY) {
                        self.ready = true;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
        }
    }

    /// Asks the worker to reload in place (a full control socket drops the request: the
    /// worker has a reload pending anyway).
    fn reload_in_place(&mut self) {
        let _ = self.ctl.write(&[env::MSG_RELOAD]);
    }

    /// Asks the worker to drain and stop, and arms its kill deadline.
    fn stop(&mut self, timeout: Duration) {
        if self.stop_deadline.is_none() {
            let _ = self.ctl.write_all(&[env::MSG_STOP]);
            self.stop_deadline = Some(Instant::now() + timeout);
        }
    }

    /// `Some(status)` once the process exited.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
    }

    fn info(&self) -> WorkerInfo {
        WorkerInfo {
            index: self.index,
            pid: self.child.id(),
            generation: self.generation,
            ready: self.ready,
            draining: self.stop_deadline.is_some(),
        }
    }
}

/// One worker index.
struct Slot {
    /// The serving worker (none while it waits for a restart).
    proc: Option<Proc>,
    /// Consecutive early exits, for the backoff.
    failures: u32,
    restart_at: Option<Instant>,
}

struct State {
    spawner: Spawner,
    slots: Vec<Slot>,
    /// A reload's new workers, not yet ready.
    pending: Vec<Proc>,
    /// Workers asked to stop.
    draining: Vec<Proc>,
    generation: u64,
    restarts: u64,
    reloads: u64,
    in_place_reloads: u64,
    stopping: bool,
    status: Arc<Mutex<Status>>,
}

impl State {
    fn run(mut self, rx: &mpsc::Receiver<Cmd>) -> io::Result<()> {
        loop {
            match rx.recv_timeout(TICK) {
                Ok(Cmd::Reload) => self.reload(),
                Ok(Cmd::ReloadInPlace) => self.reload_in_place(),
                Ok(Cmd::Shutdown) => self.shutdown(),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                // Every handle is gone: nobody can stop us any more, so stop now.
                Err(mpsc::RecvTimeoutError::Disconnected) => self.shutdown(),
            }
            self.tick();
            self.publish();
            if self.stopping
                && self.pending.is_empty()
                && self.draining.is_empty()
                && self.slots.iter().all(|s| s.proc.is_none())
            {
                return Ok(());
            }
        }
    }

    fn timeout(&self) -> Duration {
        self.spawner.cfg.shutdown_timeout
    }

    fn reload(&mut self) {
        if self.stopping {
            return;
        }
        self.reloads += 1;
        self.generation += 1;
        // A previous reload's stragglers are superseded.
        let timeout = self.timeout();
        for mut p in self.pending.drain(..) {
            p.stop(timeout);
            self.draining.push(p);
        }
        for i in 0..self.slots.len() {
            match self.spawner.spawn(i, self.generation) {
                Ok(p) => self.pending.push(p),
                Err(e) => log_or_stderr(
                    only_log::Level::Error,
                    format_args!("{e}; keeping the running worker"),
                ),
            }
        }
    }

    fn reload_in_place(&mut self) {
        if self.stopping {
            return;
        }
        self.in_place_reloads += 1;
        for p in self
            .slots
            .iter_mut()
            .filter_map(|s| s.proc.as_mut())
            .chain(self.pending.iter_mut())
        {
            p.reload_in_place();
        }
    }

    fn shutdown(&mut self) {
        if self.stopping {
            // The second request: no more waiting.
            for p in self.all_procs() {
                p.kill();
            }
            return;
        }
        self.stopping = true;
        let timeout = self.timeout();
        let mut stopped = std::mem::take(&mut self.pending);
        for s in &mut self.slots {
            s.restart_at = None;
            stopped.extend(s.proc.take());
        }
        for mut p in stopped {
            p.stop(timeout);
            self.draining.push(p);
        }
    }

    fn all_procs(&mut self) -> impl Iterator<Item = &mut Proc> {
        self.slots
            .iter_mut()
            .filter_map(|s| s.proc.as_mut())
            .chain(self.pending.iter_mut())
            .chain(self.draining.iter_mut())
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let timeout = self.timeout();
        let (min, max) = (self.spawner.cfg.restart_min, self.spawner.cfg.restart_max);

        // Serving workers: note readiness, notice exits, schedule restarts.
        for (i, s) in self.slots.iter_mut().enumerate() {
            let Some(p) = &mut s.proc else { continue };
            p.poll_ctl();
            let Some(status) = p.exited() else { continue };
            let uptime = now.saturating_duration_since(p.started);
            if uptime >= max {
                s.failures = 0;
            }
            let delay = min.saturating_mul(1u32 << s.failures.min(16)).min(max);
            s.failures = s.failures.saturating_add(1);
            log_or_stderr(
                only_log::Level::Error,
                format_args!(
                    "prefork: worker {i} (pid {}) exited on its own ({status}); restarting in {delay:?}",
                    p.child.id()
                ),
            );
            s.proc = None;
            s.restart_at = Some(now + delay);
        }

        // A reload's new workers: promote the ready ones, give up on the late or dead ones.
        let ready_timeout = self.spawner.cfg.ready_timeout;
        let mut i = 0;
        while i < self.pending.len() {
            let p = &mut self.pending[i];
            p.poll_ctl();
            if let Some(status) = p.exited() {
                log_or_stderr(
                    only_log::Level::Error,
                    format_args!(
                        "prefork: reloaded worker {} (pid {}) exited before it was ready ({status}); keeping the running worker",
                        p.index,
                        p.child.id()
                    ),
                );
                self.pending.swap_remove(i);
                continue;
            }
            if p.ready {
                let p = self.pending.swap_remove(i);
                let slot = &mut self.slots[p.index];
                slot.restart_at = None;
                slot.failures = 0;
                if let Some(mut old) = slot.proc.replace(p) {
                    old.stop(timeout);
                    self.draining.push(old);
                }
                continue;
            }
            if now.saturating_duration_since(p.started) >= ready_timeout {
                log_or_stderr(
                    only_log::Level::Error,
                    format_args!(
                        "prefork: reloaded worker {} (pid {}) not ready after {ready_timeout:?}; killing it and keeping the running worker",
                        p.index,
                        p.child.id()
                    ),
                );
                p.kill();
                let mut p = self.pending.swap_remove(i);
                let _ = p.child.wait();
                continue;
            }
            i += 1;
        }

        // Restarts that are due.
        if !self.stopping {
            for i in 0..self.slots.len() {
                let due = self.slots[i].restart_at.is_some_and(|t| t <= now);
                if !due || self.slots[i].proc.is_some() {
                    continue;
                }
                match self.spawner.spawn(i, self.generation) {
                    Ok(p) => {
                        self.restarts += 1;
                        self.slots[i].proc = Some(p);
                        self.slots[i].restart_at = None;
                    }
                    Err(e) => {
                        let s = &mut self.slots[i];
                        let delay = min.saturating_mul(1u32 << s.failures.min(16)).min(max);
                        s.failures = s.failures.saturating_add(1);
                        s.restart_at = Some(now + delay);
                        log_or_stderr(
                            only_log::Level::Error,
                            format_args!("{e}; retrying in {delay:?}"),
                        );
                    }
                }
            }
        }

        // Draining workers: reap the finished, kill the overdue.
        self.draining.retain_mut(|p| {
            p.poll_ctl();
            if p.exited().is_some() {
                return false;
            }
            if p.stop_deadline.is_some_and(|d| d <= now) {
                log_or_stderr(
                    only_log::Level::Warn,
                    format_args!(
                        "prefork: worker {} (pid {}) still running {timeout:?} after it was asked to stop; killing it",
                        p.index,
                        p.child.id()
                    ),
                );
                p.kill();
                let _ = p.child.wait();
                return false;
            }
            true
        });
    }

    fn publish(&self) {
        let mut workers: Vec<WorkerInfo> = self
            .slots
            .iter()
            .filter_map(|s| s.proc.as_ref())
            .chain(self.pending.iter())
            .chain(self.draining.iter())
            .map(Proc::info)
            .collect();
        workers.sort_by_key(|w| (w.index, w.generation));
        let mut st = self.status.lock().unwrap_or_else(|p| p.into_inner());
        *st = Status {
            generation: self.generation,
            workers,
            restarts: self.restarts,
            reloads: self.reloads,
            in_place_reloads: self.in_place_reloads,
            stopping: self.stopping,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(index: usize, generation: u64, ready: bool, draining: bool) -> WorkerInfo {
        WorkerInfo {
            index,
            pid: 1,
            generation,
            ready,
            draining,
        }
    }

    #[test]
    fn serving_filters_current_ready_workers() {
        let st = Status {
            generation: 1,
            workers: vec![
                info(0, 0, true, true),
                info(0, 1, true, false),
                info(1, 1, false, false),
            ],
            ..Status::default()
        };
        let s = st.serving();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].generation, 1);
    }
}
