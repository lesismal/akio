use std::{io, net::SocketAddr, sync::Arc};

use crate::DynAcceptor;

/// One backend instance serving one listener (or, with no listener, only dialed connections):
/// a group of I/O threads. Implemented by backend crates; `Engine` composes groups, which is how
/// each listener gets its own backend (ADR-004). `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait Group: Send + Sync {
    /// Bound address of the listener (the unspecified address when there is none).
    fn local_addr(&self) -> SocketAddr;
    /// Raw fds of the listening sockets, one per I/O thread in thread order (thread `i` serves
    /// `listener_fds()[i]`), when they form one `SO_REUSEPORT` group; empty otherwise. Used to
    /// attach steering programs (`flash-ebpf`). Valid while the group is alive.
    fn listener_fds(&self) -> Vec<i32> {
        Vec::new()
    }
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

    /// Registers the unconnected, bound UDP socket `sock` on an I/O thread, served by
    /// `acceptor` exactly like a UDP listener (one connection per peer address). Only UDP
    /// groups implement it.
    fn bind_udp(
        &self,
        _sock: std::net::UdpSocket,
        _acceptor: Arc<dyn DynAcceptor>,
    ) -> io::Result<UdpBinding> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this listener does not support UDP bind",
        ))
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    );
}

/// A UDP socket bound at run time (`flash::Engine::bind_udp`): unconnected, so it exchanges
/// datagrams with any address from one local port. Datagrams it receives are served like a UDP
/// listener's (each distinct peer address is a [`Conn`](crate::Conn) of the acceptor);
/// [`send_to`](UdpBinding::send_to) sends to any address from any thread. Cheap to clone; the
/// socket stays open until [`close`](UdpBinding::close) or engine shutdown.
#[derive(Clone)]
pub struct UdpBinding {
    sock: Arc<std::net::UdpSocket>,
    local: SocketAddr,
    closer: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for UdpBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpBinding")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl UdpBinding {
    /// Backend-facing constructor: the socket, its bound address and how to unregister it.
    #[doc(hidden)]
    pub fn new(
        sock: Arc<std::net::UdpSocket>,
        local: SocketAddr,
        closer: Arc<dyn Fn() + Send + Sync>,
    ) -> UdpBinding {
        UdpBinding {
            sock,
            local,
            closer,
        }
    }

    /// The bound address (port 0 resolved).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Sends one datagram to `addr` right away, from the calling thread. The socket is
    /// non-blocking: when its send buffer is full the datagram is dropped with
    /// `ErrorKind::WouldBlock` (UDP semantics; protocols on top retransmit).
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        loop {
            match self.sock.send_to(data, addr) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Closes the socket: its connections are closed (their `on_close` runs on the I/O thread)
    /// and it stops receiving. Idempotent.
    pub fn close(&self) {
        (self.closer)();
    }
}

/// Counters of a UDP listener (see `Config::udp_max_peers`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpStats {
    /// Peers ("connections") currently open.
    pub peers: usize,
    /// Datagrams dropped because they came from a new peer while `udp_max_peers` peers were
    /// open.
    pub rejected: u64,
}
