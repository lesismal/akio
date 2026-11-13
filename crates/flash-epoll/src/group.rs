use std::{
    io,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

use flash_core::{Config, DynAcceptor, Group};
use flash_sys::Poller;

use crate::reactor::{Cmd, Loop, LoopShared};

/// A group of epoll/kqueue I/O threads serving one listener.
pub struct EpollGroup {
    addr: SocketAddr,
    shared: Vec<Arc<LoopShared>>,
    pending: Mutex<Vec<Loop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    rr: AtomicUsize,
    cfg: Arc<Config>,
}

impl EpollGroup {
    /// Binds `listen` (if any) and prepares `threads` loops. Nothing runs until [`Group::start`].
    ///
    /// With `listen == None` the group serves only dialed connections.
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
    ) -> io::Result<EpollGroup> {
        let threads = threads.max(1);
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

        let mut shared = Vec::with_capacity(threads);
        let mut loops = Vec::with_capacity(threads);
        for l in listeners {
            let poller = Poller::new()?;
            let sh = LoopShared::new(&poller)?;
            let acceptor = listen.as_ref().map(|(_, a)| a.clone());
            loops.push(Loop::new(poller, sh.clone(), l.zip(acceptor), cfg.clone())?);
            shared.push(sh);
        }
        Ok(EpollGroup {
            addr,
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

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let loops = std::mem::take(&mut *self.pending.lock().unwrap());
        let mut handles = self.threads.lock().unwrap();
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
        let handles = std::mem::take(&mut *self.threads.lock().unwrap());
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
