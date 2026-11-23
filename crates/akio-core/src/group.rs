use std::{io, net::SocketAddr, sync::Arc};

use crate::{DatagramSender, DynAcceptor};

/// One backend instance serving one listener (or, with no listener, only dialed connections):
/// a group of I/O threads. Implemented by backend crates; `Engine` composes groups, which is how
/// each listener gets its own backend (ADR-004). `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait Group: Send + Sync {
    /// Bound address of the listener (the unspecified address when there is none).
    fn local_addr(&self) -> SocketAddr;
    /// Raw fds of the listening sockets, one per I/O thread in thread order (thread `i` serves
    /// `listener_fds()[i]`), when they form one `SO_REUSEPORT` group; empty otherwise. Used to
    /// attach steering programs (`akio-ebpf`). Valid while the group is alive.
    fn listener_fds(&self) -> Vec<i32> {
        Vec::new()
    }
    /// CPU sets the I/O threads pin themselves to when they start: thread `i` to `cpus[i]`
    /// (none for an empty set or past the end). Takes effect only before [`start`](Self::start);
    /// groups whose threads cannot be pinned ignore it.
    fn pin_threads(&self, _cpus: Vec<Vec<usize>>) {}
    /// Per active I/O thread, the CPU its kernel SQ polling thread is pinned to (io_uring with
    /// SQPOLL and pinned threads, ADR-088); empty for groups without one.
    fn sq_thread_cpus(&self) -> Vec<Option<usize>> {
        Vec::new()
    }
    /// A sender on the socket of a datagram listener (ADR-065; `None` for other groups).
    fn datagram_sender(&self) -> Option<DatagramSender> {
        None
    }
    /// Peer counters of a UDP listener (zero for other groups).
    fn udp_stats(&self) -> UdpStats {
        UdpStats::default()
    }
    /// Spawns the I/O threads. Idempotent.
    fn start(&self) -> io::Result<()>;
    /// Active I/O threads (those that take new connections; retiring ones are not counted).
    fn threads(&self) -> usize {
        0
    }
    /// Grows or shrinks the group to `n` active I/O threads (ADR-028): growing starts loops (or
    /// revives retiring ones) and gives them listening sockets; shrinking retires the highest
    /// loops, which hand their listening sockets to the others and exit once their connections
    /// are closed. Connections never move. Returns once the change is posted (growing into
    /// the index of a loop that is just exiting joins it first).
    fn set_threads(&self, _n: usize) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group cannot change its thread count",
        ))
    }
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

    /// Serves `stream`, whose non-blocking connect to `addr` is in progress (made by the
    /// caller, e.g. from a bound local port), exactly like a [`dial`](Self::dial)ed one:
    /// `on_open` once it connects, `on_error` if it fails. TCP groups implement it.
    fn dial_stream(
        &self,
        _stream: std::net::TcpStream,
        _addr: SocketAddr,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group cannot dial a TCP stream",
        ));
    }

    /// Serves the already connected, non-blocking TCP stream `stream` with `acceptor`, as a
    /// dialed connection that has just connected (`on_open` on an I/O thread); `on_error` if
    /// it cannot be registered. TCP groups implement it.
    fn adopt(
        &self,
        _stream: std::net::TcpStream,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group cannot adopt a TCP stream",
        ));
    }

    /// Opens a peer "connection" to `peer` on this UDP listener's own socket (datagrams leave
    /// from the listener's port), served by `acceptor` instead of the listener's. Only UDP
    /// listener groups implement it.
    fn open_udp_peer(
        &self,
        _peer: SocketAddr,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group is not a UDP listener",
        ));
    }
}

/// A UDP socket bound at run time (`akio::Engine::bind_udp`): unconnected, so it exchanges
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

    /// (internal, outside the stability promise) [`send_to`](Self::send_to) with ECN codepoint
    /// `ecn` (RFC 3168: 2 = ECT(0), 1 = ECT(1), 3 = CE, 0 = not ECN-capable), in an `IP_TOS` /
    /// `IPV6_TCLASS` control message on Linux and macOS (unless `AKIO_UDP_ECN=0`); elsewhere,
    /// and for `ecn` 0, the datagram goes out unmarked.
    #[doc(hidden)]
    pub fn send_to_ecn(&self, data: &[u8], addr: SocketAddr, ecn: u8) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if ecn & 3 != 0 && akio_sys::ecn_available() {
            use std::os::fd::AsRawFd;
            let fd = self.sock.as_raw_fd();
            let v6 = self.local.is_ipv6();
            loop {
                match akio_sys::send_to_ecn(fd, data, Some(&addr), ecn, v6) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    r => return r.map(|_| ()),
                }
            }
        }
        let _ = ecn;
        self.send_to(data, addr)
    }

    /// Sets the TTL (IPv4) or hop limit (IPv6) of the unicast datagrams this socket sends,
    /// 0 to 255 (`IP_TTL` / `IPV6_UNICAST_HOPS`; above 255 fails with
    /// [`io::ErrorKind::InvalidInput`]). Link-local protocols answer with 255 so receivers
    /// can check that an answer came from the link (mDNS, RFC 6762 §11); multicast datagrams
    /// keep their own limit (255 from `Engine::bind_udp_multicast`).
    pub fn set_unicast_hops(&self, hops: u32) -> io::Result<()> {
        if hops > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hop limit above 255",
            ));
        }
        if self.local.is_ipv6() {
            akio_sys::set_unicast_hops_v6(&self.sock, hops)
        } else {
            self.sock.set_ttl(hops)
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
