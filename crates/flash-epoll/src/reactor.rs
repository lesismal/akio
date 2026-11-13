use std::{
    cell::Cell,
    collections::HashMap,
    io::{self, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use flash_core::{Config, ConnInner, DynAcceptor, DynHandler, Error, LoopLink};
use flash_sys::{Event, Poller, Waker};

const WAKER: u64 = 0;
const LISTENER: u64 = 1;
const FIRST_CONN: u64 = 16;
const MAX_ACCEPT_PER_EVENT: usize = 64;
const MAX_READS_PER_EVENT: usize = 16;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(FIRST_CONN);
static NEXT_LOOP_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    /// Uid of the loop running on this thread (0 = not a loop thread).
    static CURRENT_LOOP: Cell<usize> = const { Cell::new(0) };
}

pub(crate) enum Cmd {
    Wake(u64),
    Close(u64, Option<io::Error>),
    Shutdown,
    Dial {
        stream: TcpStream,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
}

/// The part of a loop other threads can reach: its command queue and waker.
pub(crate) struct LoopShared {
    uid: usize,
    waker: Waker,
    cmds: Mutex<Vec<Cmd>>,
    wake_pending: AtomicBool,
}

impl LoopShared {
    pub(crate) fn new(poller: &Poller) -> io::Result<Arc<LoopShared>> {
        Ok(Arc::new(LoopShared {
            uid: NEXT_LOOP_UID.fetch_add(1, Ordering::Relaxed),
            waker: Waker::new(poller, WAKER)?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
        }))
    }

    pub(crate) fn post(&self, cmd: Cmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        // The loop drains its queue after every batch of events, so a post from the loop's own
        // thread needs no wakeup.
        if CURRENT_LOOP.with(Cell::get) != self.uid
            && !self.wake_pending.swap(true, Ordering::AcqRel)
        {
            self.waker.wake();
        }
    }

    fn take(&self) -> Vec<Cmd> {
        self.wake_pending.store(false, Ordering::Release);
        std::mem::take(&mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl LoopLink for LoopShared {
    fn wake_conn(&self, id: u64) {
        self.post(Cmd::Wake(id));
    }
    fn close_conn(&self, id: u64, err: Option<io::Error>) {
        self.post(Cmd::Close(id, err));
    }
}

struct LoopConn {
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    acceptor: Arc<dyn DynAcceptor>,
    reg_read: bool,
    reg_write: bool,
    /// Reads paused by backpressure (queue above the high watermark).
    bp: bool,
    /// Peer sent EOF; we are only draining output.
    eof: bool,
}

enum Slot {
    Conn(LoopConn),
    Connecting {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
    },
}

pub(crate) struct Loop {
    poller: Poller,
    shared: Arc<LoopShared>,
    listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
    slots: HashMap<u64, Slot>,
    scratch: Vec<u8>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
}

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

impl Loop {
    pub(crate) fn new(
        poller: Poller,
        shared: Arc<LoopShared>,
        listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
        cfg: Arc<Config>,
    ) -> io::Result<Loop> {
        if let Some((l, _)) = &listener {
            l.set_nonblocking(true)?;
            poller.add(l.as_raw_fd(), LISTENER, true, false)?;
        }
        Ok(Loop {
            poller,
            shared,
            listener,
            slots: HashMap::new(),
            scratch: vec![0; cfg.read_buffer],
            cfg,
            draining: None,
        })
    }

    pub(crate) fn run(&mut self) {
        CURRENT_LOOP.with(|c| c.set(self.shared.uid));
        let mut events: Vec<Event> = Vec::with_capacity(1024);
        loop {
            let timeout = self.draining.map(|_| Duration::from_millis(50));
            events.clear();
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                eprintln!("flash: poller error: {e}");
                break;
            }
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker.drain(),
                    LISTENER => self.accept(),
                    id => self.on_event(id, *ev),
                }
            }
            self.drain_cmds();
            if let Some(deadline) = self.draining {
                if self.slots.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    let ids: Vec<u64> = self.slots.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    break;
                }
            }
        }
    }

    // ---- commands -------------------------------------------------------------------------

    fn drain_cmds(&mut self) {
        loop {
            let cmds = self.shared.take();
            if cmds.is_empty() {
                return;
            }
            for cmd in cmds {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Dial {
                        stream,
                        addr,
                        acceptor,
                        on_error,
                    } => self.begin_dial(stream, addr, acceptor, on_error),
                }
            }
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.shutdown_timeout);
        if let Some((l, _)) = self.listener.take() {
            self.poller.delete(l.as_raw_fd());
        }
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        for id in ids {
            match self.slots.get_mut(&id) {
                Some(Slot::Conn(lc)) => {
                    let (acc, inner) = (lc.acceptor.clone(), lc.inner.clone());
                    if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                        self.finalize(id, Some(panic_error()));
                    }
                }
                Some(Slot::Connecting { .. }) => {
                    if let Some(Slot::Connecting {
                        stream, on_error, ..
                    }) = self.slots.remove(&id)
                    {
                        self.poller.delete(stream.as_raw_fd());
                        if let Some(f) = on_error {
                            f(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "engine shutting down",
                            ));
                        }
                    }
                }
                None => {}
            }
        }
    }

    // ---- accept / dial --------------------------------------------------------------------

    fn accept(&mut self) {
        for _ in 0..MAX_ACCEPT_PER_EVENT {
            let Some((l, acceptor)) = &self.listener else {
                return;
            };
            match l.accept() {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    self.open(stream, peer, acceptor);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    // e.g. EMFILE: level-triggered, so we will be called again; avoid a hot loop.
                    eprintln!("flash: accept: {e}");
                    return;
                }
            }
        }
    }

    fn open(&mut self, stream: TcpStream, peer: SocketAddr, acceptor: Arc<dyn DynAcceptor>) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let fd = stream.as_raw_fd();
        let inner = ConnInner::new(
            id,
            stream,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let handler = match catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) {
            Ok(h) => h,
            Err(_) => {
                inner.mark_closed();
                return;
            }
        };
        if self.poller.add(fd, id, true, false).is_err() {
            inner.mark_closed();
            return;
        }
        self.slots.insert(
            id,
            Slot::Conn(LoopConn {
                inner,
                handler,
                acceptor,
                reg_read: true,
                reg_write: false,
                bp: false,
                eof: false,
            }),
        );
        // `on_open` may already have queued output or closed the connection.
        self.on_wake(id);
    }

    fn begin_dial(
        &mut self,
        stream: TcpStream,
        _addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        if self.draining.is_some() {
            return on_error(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "engine shutting down",
            ));
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.poller.add(stream.as_raw_fd(), id, false, true) {
            return on_error(e);
        }
        self.slots.insert(
            id,
            Slot::Connecting {
                stream,
                acceptor,
                on_error: Some(on_error),
            },
        );
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Slot::Connecting {
            stream,
            acceptor,
            on_error,
        }) = self.slots.remove(&id)
        else {
            return;
        };
        self.poller.delete(stream.as_raw_fd());
        let result = match stream.take_error() {
            Ok(None) => stream
                .peer_addr()
                .and_then(|p| stream.local_addr().map(|l| (l, p))),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok((_, peer)) => {
                // `open` re-registers the stream under a fresh id.
                self.open(stream, peer, acceptor);
            }
            Err(e) => {
                if let Some(f) = on_error {
                    f(e);
                }
            }
        }
    }

    // ---- events ---------------------------------------------------------------------------

    fn on_event(&mut self, id: u64, ev: Event) {
        if matches!(self.slots.get(&id), Some(Slot::Connecting { .. })) {
            if ev.writable || ev.readable {
                self.finish_connect(id);
            }
            return;
        }
        if ev.writable {
            self.on_wake(id);
        }
        if ev.readable {
            self.on_readable(id);
        }
    }

    /// Flushes output, applies `close_after_send`, and refreshes interest.
    fn on_wake(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        match lc.inner.flush_queue() {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && lc.inner.close_after_send_requested() {
                    self.finalize(id, None);
                } else {
                    self.refresh(id);
                }
            }
        }
    }

    fn on_readable(&mut self, id: u64) {
        enum Done {
            No,
            Eof,
            Err(io::Error),
            Panic,
        }
        let mut done = Done::No;
        {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                return;
            };
            if lc.eof || !lc.reg_read || !lc.inner.is_open() {
                return;
            }
            for _ in 0..MAX_READS_PER_EVENT {
                match lc.inner.stream().read(&mut self.scratch) {
                    Ok(0) => {
                        done = Done::Eof;
                        break;
                    }
                    Ok(n) => {
                        lc.inner.set_corked(true);
                        let r = catch_unwind(AssertUnwindSafe(|| {
                            lc.handler.on_data(&self.scratch[..n])
                        }));
                        if r.is_err() {
                            done = Done::Panic;
                            break;
                        }
                        if let Err(e) = lc.inner.uncork_flush() {
                            done = Done::Err(e);
                            break;
                        }
                        // Stop early on a short read (socket drained), or if the handler asked to
                        // stop reading / close / the queue got long.
                        if n < self.scratch.len()
                            || !lc.inner.is_open()
                            || lc.inner.read_held()
                            || lc.inner.queued_bytes() >= self.cfg.write_high_watermark
                        {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        done = Done::Err(e);
                        break;
                    }
                }
            }
            if matches!(done, Done::Eof) {
                lc.eof = true;
                // Peer is done sending: finish writing what we owe, then close.
                lc.inner.close_after_send();
            }
        }
        match done {
            Done::No => self.refresh(id),
            Done::Eof => self.on_wake(id),
            Done::Err(e) => self.finalize(id, Some(Error::Io(e))),
            Done::Panic => self.finalize(id, Some(panic_error())),
        }
    }

    /// Recomputes the poller interest of a connection from its queue and flags.
    fn refresh(&mut self, id: u64) {
        let high = self.cfg.write_high_watermark;
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let q = lc.inner.queued_bytes();
        if q >= high {
            lc.bp = true;
        } else if q <= high / 4 {
            lc.bp = false;
        }
        let read = !lc.inner.read_held() && !lc.bp && !lc.eof;
        let write = q > 0;
        if (read, write) != (lc.reg_read, lc.reg_write) {
            lc.reg_read = read;
            lc.reg_write = write;
            if let Err(e) = self
                .poller
                .modify(lc.inner.stream().as_raw_fd(), id, read, write)
            {
                self.finalize(id, Some(Error::Io(e)));
            }
        }
    }

    /// Removes a connection and runs `on_close` exactly once.
    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(Slot::Conn(mut lc)) = self.slots.remove(&id) else {
            // A dialing slot being closed by id is not possible: ids are not exposed before open.
            return;
        };
        self.poller.delete(lc.inner.stream().as_raw_fd());
        lc.inner.mark_closed();
        let _ = lc.inner.stream().shutdown(std::net::Shutdown::Both);
        let _ = catch_unwind(AssertUnwindSafe(|| lc.handler.on_close(err)));
    }
}
