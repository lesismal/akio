use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

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

    /// [`bind_udp`](Self::bind_udp), and the ICMP errors about datagrams `sock` sends go to
    /// `on_icmp` on its I/O thread (Linux `IP_RECVERR`, set by the group). Default: plain
    /// `bind_udp`, no reports.
    fn bind_udp_icmp(
        &self,
        sock: std::net::UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
        on_icmp: IcmpHandler,
    ) -> io::Result<UdpBinding> {
        let _ = on_icmp;
        self.bind_udp(sock, acceptor)
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

/// An ICMP error about a datagram a [`UdpBinding`] sent (`akio::Engine::bind_udp_icmp`, Linux):
/// the network or the destination host refused it (destination or port unreachable, time
/// exceeded, packet too big, parameter problem). ICMP gives no guarantee: errors are rate
/// limited and may be filtered on the way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IcmpError {
    /// The bound address of the socket that sent the datagram.
    pub local: SocketAddr,
    /// Where the datagram was going (address and port).
    pub dest: SocketAddr,
    /// Who sent the ICMP message (a router on the way, or `dest`'s host), when known.
    pub from: Option<IpAddr>,
    /// An ICMPv6 message (RFC 4443); else ICMPv4 (RFC 792).
    pub v6: bool,
    /// The ICMP type (ICMPv4: 3 destination unreachable, 11 time exceeded, 12 parameter
    /// problem; ICMPv6: 1 destination unreachable, 2 packet too big, 3 time exceeded, 4
    /// parameter problem).
    pub icmp_type: u8,
    /// The ICMP code.
    pub code: u8,
    /// The next-hop MTU of an ICMPv4 "fragmentation needed" (type 3, code 4) or an ICMPv6
    /// "packet too big", else 0.
    pub mtu: u32,
}

impl IcmpError {
    /// An error with these fields (for tests and userspace stacks).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local: SocketAddr,
        dest: SocketAddr,
        from: Option<IpAddr>,
        v6: bool,
        icmp_type: u8,
        code: u8,
        mtu: u32,
    ) -> IcmpError {
        IcmpError {
            local,
            dest,
            from,
            v6,
            icmp_type,
            code,
            mtu,
        }
    }
}

/// Takes the [`IcmpError`]s of a bound socket (`akio::Engine::bind_udp_icmp`), on its I/O
/// thread.
pub type IcmpHandler = Arc<dyn Fn(&IcmpError) + Send + Sync>;

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
    /// The socket has `IP_RECVERR` (`bind_udp_icmp`): a send may fail once with the error an
    /// ICMP message left pending, having sent nothing.
    recverr: bool,
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
            recverr: false,
        }
    }

    /// Backend-facing: the socket has `IP_RECVERR` (see `Group::bind_udp_icmp`).
    #[doc(hidden)]
    #[must_use]
    pub fn with_recverr(mut self) -> UdpBinding {
        self.recverr = true;
        self
    }

    /// Whether `e`, from a send on a socket with `IP_RECVERR`, is an ICMP error left pending
    /// for the socket rather than about this send: the kernel returns it once (clearing it)
    /// without sending, so the send is tried again.
    fn pending_icmp(&self, e: &io::Error) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.recverr && akio_sys::is_icmp_error(e)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = e;
            false
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
        let mut retried = false;
        loop {
            match self.sock.send_to(data, addr) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if !retried && self.pending_icmp(&e) => retried = true,
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
        self.send_to_tos(data, addr, ecn & 3)
    }

    /// (internal, outside the stability promise) [`send_to_ecn`](Self::send_to_ecn) with the
    /// whole traffic class byte `tos` (IPv4 TOS / IPv6 traffic class: DSCP in the upper six
    /// bits, ECN in the low two); 0 sends the datagram unmarked.
    #[doc(hidden)]
    pub fn send_to_tos(&self, data: &[u8], addr: SocketAddr, tos: u8) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if tos != 0 && akio_sys::ecn_available() {
            use std::os::fd::AsRawFd;
            let fd = self.sock.as_raw_fd();
            let v6 = self.local.is_ipv6();
            let mut retried = false;
            loop {
                match akio_sys::send_to_tos(fd, data, Some(&addr), tos, v6) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if !retried && self.pending_icmp(&e) => retried = true,
                    r => return r.map(|_| ()),
                }
            }
        }
        let _ = tos;
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
