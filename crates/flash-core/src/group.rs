use std::{io, net::SocketAddr, sync::Arc};

use crate::DynAcceptor;

/// One backend instance serving one listener (or, with no listener, only dialed connections):
/// a group of I/O threads. Implemented by backend crates; `Engine` composes groups, which is how
/// each listener gets its own backend (ADR-004). `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait Group: Send + Sync {
    /// Bound address of the listener (the unspecified address when there is none).
    fn local_addr(&self) -> SocketAddr;
    /// Spawns the I/O threads. Idempotent.
    fn start(&self) -> io::Result<()>;
    /// Begins graceful shutdown: stop accepting, notify, drain, then stop the threads.
    fn shutdown(&self);
    /// Blocks until the I/O threads have exited.
    fn join(&self);
    /// Starts a non-blocking connect to `addr` served by `acceptor`; `on_error` is called
    /// (on an I/O thread, or inline) if the connection cannot be established.
    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    );
}
