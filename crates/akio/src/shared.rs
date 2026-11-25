//! Listeners that share an I/O thread group (ADR-130): the engine keeps one shared group per
//! backend and scheduling (epoll or io_uring loops with or without balancing, rounds per
//! thread counts), and gives each listener served by one a
//! [`SharedListener`], so its per-listener API (`local_addrs`, `threads`, `remove_listener`, ...)
//! keeps one entry per listener.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use akio_core::{AcceptFilter, DynAcceptor, Group, LoopStats};

/// What listeners of one shared group have in common: per-thread loops on epoll/kqueue or on
/// io_uring (with one set of ring options), with or without accept-time balancing, or rounds
/// scheduling with one poller and worker count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShareKey {
    pub(crate) balance: bool,
    /// Rounds scheduling (ADR-104): its resolved pollers and workers.
    pub(crate) rounds: Option<(usize, usize)>,
    /// io_uring loops: their ring options (entries, SQPOLL).
    pub(crate) uring: Option<(u32, bool)>,
}

/// The engine's shared groups, by key.
#[derive(Default)]
pub(crate) struct SharedGroups {
    pub(crate) groups: Vec<(ShareKey, Arc<dyn Group>)>,
}

impl SharedGroups {
    /// The group for `key`, made with `make` the first time.
    pub(crate) fn get_or_make(
        &mut self,
        key: ShareKey,
        make: impl FnOnce() -> io::Result<Arc<dyn Group>>,
    ) -> io::Result<Arc<dyn Group>> {
        if let Some((_, g)) = self.groups.iter().find(|(k, _)| *k == key) {
            return Ok(g.clone());
        }
        let g = make()?;
        self.groups.push((key, g.clone()));
        Ok(g)
    }

    pub(crate) fn all(&self) -> Vec<Arc<dyn Group>> {
        self.groups.iter().map(|(_, g)| g.clone()).collect()
    }
}

/// One listener of a shared group, as the engine sees a listener: its address, and its
/// operations on the group under its key. Starting, resizing and dialing act on the shared
/// group; shutting down and joining are the engine's business (it does both to every shared
/// group once), so they do nothing here.
pub(crate) struct SharedListener {
    group: Arc<dyn Group>,
    key: usize,
    addr: SocketAddr,
    removed: AtomicBool,
}

impl SharedListener {
    pub(crate) fn new(group: Arc<dyn Group>, key: usize, addr: SocketAddr) -> SharedListener {
        SharedListener {
            group,
            key,
            addr,
            removed: AtomicBool::new(false),
        }
    }
}

impl Group for SharedListener {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn pin_threads(&self, cpus: Vec<Vec<usize>>) {
        self.group.pin_threads(cpus);
    }

    fn set_balance(&self, on: bool) {
        // The same for every listener of the group: balancing is part of its key.
        self.group.set_balance(on);
    }

    fn sq_thread_cpus(&self) -> Vec<Option<usize>> {
        self.group.sq_thread_cpus()
    }

    fn start(&self) -> io::Result<()> {
        self.group.start()
    }

    fn threads(&self) -> usize {
        if self.removed.load(Ordering::Acquire) {
            0
        } else {
            self.group.threads()
        }
    }

    fn set_threads(&self, n: usize) -> io::Result<()> {
        if self.removed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the listener was removed",
            ));
        }
        self.group.set_threads(n)
    }

    fn stop_listening(&self, drain: Option<Duration>, _exit_when_idle: bool) -> io::Result<()> {
        // The threads serve the group's other listeners: they stay up.
        self.removed.store(true, Ordering::Release);
        self.group.remove_listener(self.key, drain)
    }

    fn await_unlisted(&self, limit: Duration) {
        self.group.await_listener_removed(self.key, limit);
    }

    fn set_filter(&self, filter: Option<AcceptFilter>) -> io::Result<()> {
        self.group.set_listener_filter(self.key, filter)
    }

    fn finished(&self) -> bool {
        // Its threads are the group's: once removed, there is nothing of its own to wait for.
        self.removed.load(Ordering::Acquire)
    }

    fn loop_stats(&self) -> Vec<Arc<LoopStats>> {
        // The group's threads stay registered for its other listeners.
        Vec::new()
    }

    fn shutdown(&self) {}

    fn join(&self) {}

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.group.dial(addr, acceptor, on_error);
    }

    fn dial_with(
        &self,
        addr: SocketAddr,
        opts: akio_core::DialOptions,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.group.dial_with(addr, opts, acceptor, on_error);
    }

    fn dial_stream(
        &self,
        stream: std::net::TcpStream,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.group.dial_stream(stream, addr, acceptor, on_error);
    }

    fn dial_unix(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.group.dial_unix(stream, acceptor, on_error);
    }

    fn adopt(
        &self,
        stream: std::net::TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.group.adopt(stream, acceptor, on_error);
    }
}
