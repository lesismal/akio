use std::{
    io,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

use only_core::{Config, DynAcceptor, Group, LoopMeta, Pool};

use crate::reactor::{Cmd, Loop, LoopShared};
use crate::ring;
use only_sys::ffi;

/// io_uring tuning.
#[derive(Clone, Debug, Default)]
pub struct UringOptions {
    /// Submission queue depth per I/O thread (0 = 1024).
    pub entries: u32,
    /// Use a kernel SQ polling thread (burns a core per ring; lowest latency).
    pub sqpoll: bool,
}

/// Checks that this kernel can run the backend: io_uring present, Linux 5.19+ (multishot accept
/// and recv with provided buffers) and the opcodes used. `Err` says what is missing.
pub fn probe() -> Result<(), String> {
    // SAFETY: `uname` fills the zeroed struct it is given.
    let mut u: ffi::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `u` is valid for writes.
    if unsafe { ffi::uname(&raw mut u) } != 0 {
        return Err("uname failed".into());
    }
    // SAFETY: the kernel NUL-terminates `release`.
    let rel = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy();
    let mut it = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let (maj, min): (u32, u32) = (
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    );
    if (maj, min) < (5, 19) {
        return Err(format!("kernel {rel} is older than 5.19"));
    }
    let (ring, _) =
        crate::reactor::make_ring(8, false).map_err(|e| format!("io_uring_setup: {e}"))?;
    if ring.features() & ring::FEAT_EXT_ARG == 0 {
        return Err("IORING_FEAT_EXT_ARG unsupported".into());
    }
    let probe = ring.probe().map_err(|e| format!("probe: {e}"))?;
    // The same setup the loops use, including a buffer ring (the registration must succeed on
    // the thread that owns a single-issuer ring, hence the enable call).
    ring.enable_rings().ok();
    crate::reactor::BufRing::new()
        .and_then(|b| b.register(&ring))
        .map_err(|e| format!("buffer ring: {e}"))?;
    for (name, code) in [
        ("accept", ring::OP_ACCEPT),
        ("recv", ring::OP_RECV),
        ("poll_add", ring::OP_POLL_ADD),
        ("async_cancel", ring::OP_ASYNC_CANCEL),
        ("read", ring::OP_READ),
    ] {
        if !probe.is_supported(code) {
            return Err(format!("opcode {name} unsupported"));
        }
    }
    Ok(())
}

/// A group of io_uring I/O threads serving one listener.
pub struct UringGroup {
    addr: SocketAddr,
    /// Listener fds in ring order (one `SO_REUSEPORT` group).
    fds: Vec<i32>,
    shared: Vec<Arc<LoopShared>>,
    pending: Mutex<Vec<Loop>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    rr: AtomicUsize,
}

impl std::fmt::Debug for UringGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringGroup").finish_non_exhaustive()
    }
}

impl UringGroup {
    /// Binds `listen` (if any) and prepares `threads` rings. Nothing runs until [`Group::start`].
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        let threads = threads.max(1);
        let mut listeners: Vec<Option<TcpListener>> = (0..threads).map(|_| None).collect();
        let mut addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut acceptor = None;
        if let Some((a, acc)) = listen {
            let first = only_sys::listen(a, true, cfg.backlog)?;
            addr = first.local_addr()?;
            for slot in listeners.iter_mut().skip(1) {
                *slot = Some(only_sys::listen(addr, true, cfg.backlog)?);
            }
            listeners[0] = Some(first);
            acceptor = Some(acc);
        }
        let fds = listeners
            .iter()
            .flatten()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .collect();
        Self::assemble(listeners, addr, fds, acceptor, cfg, pool, &opts)
    }

    /// Serves an already bound and listening socket (one inherited from a supervisor process,
    /// say) with `threads` rings that share it, each accepting on its own clone of the socket.
    /// The socket is made non-blocking. The listener forms no `SO_REUSEPORT` group of this
    /// process, so [`Group::listener_fds`] is empty.
    pub fn bind_listener(
        listener: TcpListener,
        acceptor: Arc<dyn DynAcceptor>,
        threads: usize,
        cfg: Config,
        pool: Arc<Pool>,
        opts: UringOptions,
    ) -> io::Result<UringGroup> {
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let mut listeners = Vec::with_capacity(threads.max(1));
        for _ in 1..threads.max(1) {
            listeners.push(Some(listener.try_clone()?));
        }
        listeners.insert(0, Some(listener));
        Self::assemble(
            listeners,
            addr,
            Vec::new(),
            Some(acceptor),
            cfg,
            pool,
            &opts,
        )
    }

    fn assemble(
        listeners: Vec<Option<TcpListener>>,
        addr: SocketAddr,
        fds: Vec<i32>,
        acceptor: Option<Arc<dyn DynAcceptor>>,
        cfg: Config,
        pool: Arc<Pool>,
        opts: &UringOptions,
    ) -> io::Result<UringGroup> {
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let threads = listeners.len();
        let mut shared = Vec::with_capacity(threads);
        let mut loops = Vec::with_capacity(threads);
        let listener = acceptor.as_ref().map(|_| addr);
        for (thread, l) in listeners.into_iter().enumerate() {
            let meta = LoopMeta::new("io_uring", listener, thread);
            let sh = LoopShared::new(pool.clone(), &cfg, meta)?;
            loops.push(Loop::new(
                sh.clone(),
                l.zip(acceptor.clone()),
                cfg.clone(),
                opts,
            )?);
            shared.push(sh);
        }
        Ok(UringGroup {
            addr,
            fds,
            shared,
            pending: Mutex::new(loops),
            threads: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            rr: AtomicUsize::new(0),
        })
    }
}

impl Group for UringGroup {
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
                .name(format!("only-io-{i}"))
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
        let stream = match only_sys::connect_nonblocking(addr) {
            Ok(s) => s,
            Err(e) => return on_error(e),
        };
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
        self.shared[i].post(Cmd::Dial {
            stream,
            acceptor,
            on_error,
        });
    }

    fn adopt(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // A connected stream goes through the dial path: it is writable at once and has no
        // pending error, so the loop opens it right away.

        if let Err(e) = stream.set_nonblocking(true) {
            return on_error(e);
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.shared.len();
        self.shared[i].post(Cmd::Dial {
            stream,
            acceptor,
            on_error,
        });
    }
}
