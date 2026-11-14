use std::{
    io,
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

use flash_core::{Config, DynAcceptor, Group, LoopMeta, Pool};
use flash_sys::Poller;

use crate::reactor::{Cmd, Loop, LoopShared};

/// A group of epoll/kqueue I/O threads serving one listener.
pub struct EpollGroup {
    addr: SocketAddr,
    /// Listener fds in loop order when they form a `SO_REUSEPORT` group (Linux).
    fds: Vec<i32>,
    shared: Vec<Arc<LoopShared>>,
    pending: Mutex<Vec<Loop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    rr: AtomicUsize,
    cfg: Arc<Config>,
}

impl std::fmt::Debug for EpollGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpollGroup").finish_non_exhaustive()
    }
}

impl EpollGroup {
    /// Binds `listen` (if any) and prepares `threads` loops. Nothing runs until [`Group::start`].
    ///
    /// With `listen == None` the group serves only dialed connections.
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<EpollGroup> {
        let threads = threads.max(1);
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);

        // One listener per loop (Linux, SO_REUSEPORT) or clones of one (elsewhere).
        let mut listeners: Vec<Option<TcpListener>> = (0..threads).map(|_| None).collect();
        let mut addr = SocketAddr::from(([0, 0, 0, 0], 0));
        if let Some((a, _)) = &listen {
            let first = flash_sys::listen(*a, cfg!(target_os = "linux"), cfg.backlog)?;
            addr = first.local_addr()?;
            for slot in listeners.iter_mut().skip(1) {
                *slot = Some(if cfg!(target_os = "linux") {
                    flash_sys::listen(addr, true, cfg.backlog)?
                } else {
                    first.try_clone()?
                });
            }
            listeners[0] = Some(first);
        }
        let fds = if cfg!(target_os = "linux") {
            listeners.iter().flatten().map(|l| l.as_raw_fd()).collect()
        } else {
            Vec::new()
        };

        let mut shared = Vec::with_capacity(threads);
        let mut loops = Vec::with_capacity(threads);
        let listener = listen.as_ref().map(|_| addr);
        for (thread, l) in listeners.into_iter().enumerate() {
            let poller = Poller::new()?;
            let meta = LoopMeta {
                backend: crate::reactor::BACKEND,
                listener,
                thread,
            };
            let sh = LoopShared::new(&poller, pool.clone(), &cfg, meta)?;
            let acceptor = listen.as_ref().map(|(_, a)| a.clone());
            loops.push(Loop::new(poller, sh.clone(), l.zip(acceptor), cfg.clone())?);
            shared.push(sh);
        }
        Ok(EpollGroup {
            addr,
            fds,
            shared,
            pending: Mutex::new(loops),
            threads: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            rr: AtomicUsize::new(0),
            cfg,
        })
    }
}

impl Group for EpollGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn listener_fds(&self) -> Vec<i32> {
        self.fds.clone()
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        // Running from now on: requests posted before a thread is first scheduled are queued.
        for s in &self.shared {
            s.stats.set_running(true);
        }
        let mut handles = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        for (i, mut l) in loops.into_iter().enumerate() {
            let h = std::thread::Builder::new()
                .name(format!("flash-io-{i}"))
                .spawn(move || l.run())?;
            handles.push(h);
        }
        Ok(())
    }

    fn shutdown(&self) {
        for s in &self.shared {
            s.post(Cmd::Shutdown);
        }
    }

    fn join(&self) {
        let handles = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
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
        let stream = match flash_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
        let _ = &self.cfg;
        self.shared[i].post(Cmd::Dial {
            stream,
            addr,
            acceptor,
            on_error,
        });
    }
}
