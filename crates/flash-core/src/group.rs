use std::{io, net::SocketAddr, sync::Arc};

use crate::DynAcceptor;

/// One backend instance serving one listener (or, with no listener, only dialed connections):
/// a group of I/O threads. Implemented by backend crates; `Engine` composes groups, which is how
/// each listener gets its own backend (ADR-004). `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait Group: Send + Sync {
    /// Bound address of the listener (the unspecified address when there is none).
    fn local_addr(&self) -> SocketAddr;
    /// Peer counters of a UDP listener (zero for other groups).
    fn udp_stats(&self) -> UdpStats {
        UdpStats::default()
    }
    /// Spawns the I/O threads. Idempotent.
    fn start(&self) -> io::Result<()>;
    /// Begins graceful shutdown: stop accepting, notify, drain, then stop the threads.
    fn shutdown(&self);
    /// Blocks until the I/O threads have exited.
    fn join(&self);
    /// Starts a non-blocking connect to `addr` served by `acceptor`; `on_error` is called
    /// (on an I/O thread, or inline) if the connection cannot be established.
    /// Starts a UDP "connection" to `addr` with its own socket, served by `acceptor`. Only UDP
    /// groups implement it.
    fn dial_udp(
        &self,
        _addr: SocketAddr,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "this listener does not support UDP dial",
        ));
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    );
}

/// Counters of a UDP listener (see `Config::udp_max_peers`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpStats {
    /// Peers ("connections") currently open.
    pub peers: usize,
    /// Datagrams dropped because they came from a new peer while `udp_max_peers` peers were
    /// open.
    pub rejected: u64,
}
