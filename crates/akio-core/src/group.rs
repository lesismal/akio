use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::{DatagramSender, DialOptions, DynAcceptor, LoopStats};

/// A listener's accept filter (ADR-099): called on the I/O thread with the peer's address
/// right after `accept`; `false` closes the connection before anything else runs.
/// Backend-facing.
#[doc(hidden)]
pub type AcceptFilter = Arc<dyn Fn(&SocketAddr) -> bool + Send + Sync>;

/// The accept filter of one listener group, shared by its loops (ADR-099): replaced under the
/// lock, then the generation is bumped; each loop reads the generation once per accept and
/// takes the new filter only when it changed, so no lock is taken per connection and a filter
/// is in force for every `accept` that starts after [`set`](Self::set) returned. Backend-facing.
#[doc(hidden)]
#[derive(Default)]
pub struct FilterCell {
    generation: std::sync::atomic::AtomicU64,
    filter: std::sync::Mutex<Option<AcceptFilter>>,
}

impl std::fmt::Debug for FilterCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterCell").finish_non_exhaustive()
    }
}

impl FilterCell {
    /// Installs `filter` (or with `None` removes it).
    pub fn set(&self, filter: Option<AcceptFilter>) {
        let mut g = self.filter.lock().unwrap_or_else(|p| p.into_inner());
        *g = filter;
        // Under the lock: a loop that sees the new generation reads the new filter.
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

/// A loop's view of its group's [`FilterCell`]: the filter it last read and its generation.
/// Backend-facing.
#[doc(hidden)]
pub struct FilterView {
    cell: Arc<FilterCell>,
    generation: u64,
    filter: Option<AcceptFilter>,
}

impl std::fmt::Debug for FilterView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterView")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl FilterView {
    /// A view of `cell` (it reads the filter at its first check).
    pub fn new(cell: Arc<FilterCell>) -> FilterView {
        FilterView {
            cell,
            generation: 0,
            filter: None,
        }
    }

    /// Whether the connection from `peer` may be opened: the current filter, if any, allows it.
    /// A filter that panics refuses the connection.
    #[inline]
    pub fn allows(&mut self, peer: &SocketAddr) -> bool {
        let g = self
            .cell
            .generation
            .load(std::sync::atomic::Ordering::Acquire);
        if g != self.generation {
            self.filter = self
                .cell
                .filter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            self.generation = g;
        }
        filter_allows(self.filter.as_ref(), peer)
    }
}

/// Runs `filter` for `peer` (none: accepted); a filter that panics refuses the connection.
fn filter_allows(filter: Option<&AcceptFilter>, peer: &SocketAddr) -> bool {
    let Some(f) = filter else {
        return true;
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(peer))) {
        Ok(allowed) => allowed,
        Err(_) => {
            crate::telemetry::log_or_stderr(
                akio_log::Level::Error,
                format_args!("accept filter panicked for {peer}; connection refused"),
            );
            false
        }
    }
}

/// Where a listener added to a shared group ([`Group::add_listener`], ADR-130) gets its
/// sockets. `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
#[derive(Debug)]
pub enum ListenSocket {
    /// Bound at this address: on Linux one `SO_REUSEPORT` socket per I/O thread, elsewhere
    /// clones of one socket.
    Bind(SocketAddr),
    /// An already bound and listening socket (one inherited from a supervisor, say), cloned
    /// for every I/O thread.
    Inherited(std::net::TcpListener),
    /// A listening Unix-domain stream socket (ADR-121), cloned for every I/O thread; its
    /// connections have [`UNIX_ADDR`](crate::UNIX_ADDR) for both addresses.
    Unix(std::net::TcpListener),
}

/// One backend instance serving one listener, several listeners of one backend (ADR-130), or,
/// with no listener, only dialed connections: a group of I/O threads. Implemented by backend
/// crates; `Engine` composes groups, which is how each backend gets its own threads (ADR-004).
/// `#[doc(hidden)]`: backend-facing.
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
    /// Accept-time balancing (ADR-105): when on, a thread that accepts a connection while it
    /// holds more than its share hands it to the least loaded thread before reading from it
    /// (`akio_core::balance`). TCP listener groups implement it; the others ignore it.
    fn set_balance(&self, _on: bool) {}
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
    /// Stops accepting for good (ADR-099): the listening sockets are closed, open connections
    /// stay on their threads. With `drain`, every open connection gets `on_shutdown` now and
    /// those still open after `drain` are closed. With `exit_when_idle` each thread exits once
    /// it has no connection left (otherwise it stays up for dials until shutdown). Returns once
    /// posted. Only TCP listener groups implement it.
    fn stop_listening(&self, _drain: Option<Duration>, _exit_when_idle: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group cannot stop listening",
        ))
    }
    /// After [`stop_listening`](Self::stop_listening), with no lock of the caller held: waits up
    /// to `limit` until every running I/O thread of the group has stopped its listening sockets
    /// listening, so a connection made after this returns cannot land on one of them (on Linux
    /// the `SO_REUSEPORT` group of the address then holds only other listeners' sockets). Does
    /// not wait on an I/O thread. Backend-facing.
    #[doc(hidden)]
    fn await_unlisted(&self, _limit: Duration) {}
    /// Installs (or with `None` removes) the accept filter of a TCP listener group: every
    /// `accept` its threads start after this returns runs it.
    fn set_filter(&self, _filter: Option<AcceptFilter>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group has no accept filter",
        ))
    }
    /// Adds a listener to a group that serves several (ADR-130): its sockets join every active
    /// I/O thread (and later ones), served by `acceptor`. Returns its key in the group and its
    /// bound address. Works before and after [`start`](Self::start). Groups of one listener
    /// return `Unsupported`.
    fn add_listener(
        &self,
        _socket: ListenSocket,
        _acceptor: Arc<dyn DynAcceptor>,
    ) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group serves one listener",
        ))
    }
    /// [`stop_listening`](Self::stop_listening) for listener `key` of a shared group alone: its
    /// sockets close, `drain` applies to its connections only, and the threads stay up for the
    /// other listeners.
    fn remove_listener(&self, _key: usize, _drain: Option<Duration>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group serves one listener",
        ))
    }
    /// [`await_unlisted`](Self::await_unlisted) for a [`remove_listener`](Self::remove_listener).
    #[doc(hidden)]
    fn await_listener_removed(&self, _key: usize, _limit: Duration) {}
    /// [`set_filter`](Self::set_filter) for listener `key` of a shared group.
    fn set_listener_filter(&self, _key: usize, _filter: Option<AcceptFilter>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group serves one listener",
        ))
    }
    /// Whether the group was started and every one of its threads has exited (a group that
    /// stopped listening and whose connections are all closed).
    fn finished(&self) -> bool {
        false
    }
    /// The counters of every thread the group has had (to unregister them from telemetry).
    fn loop_stats(&self) -> Vec<Arc<LoopStats>> {
        Vec::new()
    }
    /// Begins graceful shutdown: stop accepting, notify, drain, then stop the threads.
    fn shutdown(&self);
    /// Blocks until the I/O threads have exited.
    fn join(&self);
    /// Starts a UDP "connection" to `addr` with its own socket, served by `acceptor`. Only UDP
    /// groups implement it. It takes no connect timeout: UDP has no handshake, the socket is
    /// connected at once, and a silent peer is ended by `Config::udp_idle_timeout`.
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

    /// Starts a non-blocking connect to `addr` served by `acceptor`; `on_error` is called
    /// (on an I/O thread, or inline) if the connection cannot be established, with `TimedOut`
    /// once the engine's `Config::connect_timeout` passes.
    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    );

    /// [`dial`](Self::dial) with options of its own (ADR-154): `opts.connect_timeout`, when
    /// set, in place of the engine's. TCP groups implement it; the default ignores the options.
    fn dial_with(
        &self,
        addr: SocketAddr,
        opts: DialOptions,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        let _ = opts;
        self.dial(addr, acceptor, on_error);
    }

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

    /// Serves `stream`, a Unix-domain stream socket whose non-blocking connect is in progress
    /// (`akio_sys::connect_unix_nonblocking`, held as a `TcpStream` for the backends' sake: only
    /// what any stream socket supports is done with it), as a dialed connection (ADR-120):
    /// `on_open` once it connects, `on_error` if it fails. Its `Conn::peer_addr` and
    /// `Conn::local_addr` are [`UNIX_ADDR`](crate::UNIX_ADDR). TCP groups implement it.
    fn dial_unix(
        &self,
        _stream: std::net::TcpStream,
        _acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        on_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "this group cannot dial a Unix-domain socket",
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

/// An ICMP error about a datagram a [`UdpBinding`] sent (`akio::Engine::bind_udp_icmp`, Linux
/// and macOS):
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

    /// [`send_to`](Self::send_to) out of interface `interface` (an index, as
    /// `akio_sys::interfaces` lists them; 0: the system's choice, a plain `send_to`): the
    /// interface goes with the datagram (`IP_PKTINFO` / `IPV6_PKTINFO`), so a datagram to a
    /// multicast group leaves on that link, as `IP_MULTICAST_IF` would make every datagram of
    /// the socket do. What IPv4 multicast on several interfaces needs (IPv6 can name the link
    /// in the destination's scope id instead). Linux and macOS; elsewhere a non-zero
    /// `interface` fails with [`io::ErrorKind::Unsupported`].
    pub fn send_to_on(&self, data: &[u8], addr: SocketAddr, interface: u32) -> io::Result<()> {
        if interface == 0 {
            return self.send_to(data, addr);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        loop {
            match akio_sys::send_to_on(&self.sock, data, addr, interface) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => return r.map(|_| ()),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (data, addr);
            Err(io::Error::from(io::ErrorKind::Unsupported))
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
        self.send_to_ip(data, addr, tos, 0)
    }

    /// (internal, outside the stability promise) [`send_to_tos`](Self::send_to_tos) with the
    /// TTL (IPv4) or hop limit (IPv6) `ttl` (0: the socket's), in an `IP_TTL` /
    /// `IPV6_HOPLIMIT` control message: on Linux, and on macOS for IPv6 (XNU ignores `IP_TTL`
    /// on send); elsewhere the datagram has the socket's.
    #[doc(hidden)]
    pub fn send_to_ip(&self, data: &[u8], addr: SocketAddr, tos: u8, ttl: u8) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let tos = if akio_sys::ecn_available() { tos } else { 0 };
            if tos != 0 || ttl != 0 {
                use std::os::fd::AsRawFd;
                let fd = self.sock.as_raw_fd();
                let v6 = self.local.is_ipv6();
                let mut retried = false;
                loop {
                    match akio_sys::send_to_ip(fd, data, Some(&addr), tos, ttl, v6) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) if !retried && self.pending_icmp(&e) => retried = true,
                        r => return r.map(|_| ()),
                    }
                }
            }
        }
        let _ = (tos, ttl);
        self.send_to(data, addr)
    }

    /// (internal, outside the stability promise) asks the kernel for the TTL / hop limit of
    /// every datagram this socket receives, which its connections then report
    /// (`Conn::rx_ttl`). Linux and macOS; elsewhere `false`.
    #[doc(hidden)]
    pub fn enable_rx_ttl(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            akio_sys::enable_recv_ttl(std::os::fd::AsRawFd::as_raw_fd(&*self.sock))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        false
    }

    /// Asks the kernel to report (`on`), or to stop reporting, the interface every datagram
    /// this socket receives arrived on, which its connections then read in `on_data` with
    /// [`Conn::rx_interface`](crate::Conn::rx_interface): Linux `IP_PKTINFO`, macOS
    /// `IP_RECVPKTINFO`, and `IPV6_RECVPKTINFO` (an IPv6 socket sets both, the IPv4 option
    /// covering the IPv4 datagrams a dual-stack socket receives). For a protocol that must
    /// tell links apart when the source address does not (mDNS answering on the link of the
    /// query, RFC 6762 section 6.2). Off by default: each datagram then carries one more
    /// control message. Datagrams already queued arrive without it. Elsewhere than Linux and
    /// macOS it fails with [`io::ErrorKind::Unsupported`].
    pub fn set_recv_interface(&self, on: bool) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let fd = std::os::fd::AsRawFd::as_raw_fd(&*self.sock);
            if akio_sys::enable_recv_interface(fd, on) {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = on;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Sets or clears the "don't fragment" bit of the IPv4 datagrams this socket sends (on
    /// Linux `IP_MTU_DISCOVER` with `IP_PMTUDISC_DO` / `IP_PMTUDISC_DONT`, on macOS
    /// `IP_DONTFRAG`; an IPv6 socket also gets `IPV6_DONTFRAG`, which keeps the kernel from
    /// fragmenting its datagrams). Set, a datagram larger than the path MTU the kernel knows
    /// fails with `EMSGSIZE` instead of going out in fragments; cleared, the kernel and the
    /// routers on the way fragment it. Without a call the system's default applies (Linux:
    /// path MTU discovery, DF set while the datagram fits). Takes effect for the next send;
    /// elsewhere than Linux and macOS it fails with [`io::ErrorKind::Unsupported`].
    pub fn set_dont_fragment(&self, on: bool) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let fd = std::os::fd::AsRawFd::as_raw_fd(&*self.sock);
            akio_sys::set_dont_fragment(fd, self.local.is_ipv6(), on)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = on;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
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

    /// Joins multicast group `group` on interface `interface` (an index, as
    /// `akio_sys::interfaces` lists them; 0: the default one), on a socket already bound
    /// (`akio::Engine::bind_udp_multicast_on` joins the interfaces known when it binds; this
    /// adds those that appear later). An IPv4 join names the interface by its first IPv4
    /// address: an interface without one fails with [`io::ErrorKind::AddrNotAvailable`]. A
    /// group already joined there is not an error. The group's family must be the socket's.
    pub fn join_multicast(&self, group: IpAddr, interface: u32) -> io::Result<()> {
        let r = match group {
            IpAddr::V4(g) => {
                let on = ipv4_of(interface)?;
                self.sock.join_multicast_v4(&g, &on)
            }
            IpAddr::V6(g) => self.sock.join_multicast_v6(&g, interface),
        };
        match r {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => Ok(()),
            r => r,
        }
    }

    /// Leaves multicast group `group` on interface `interface` (as
    /// [`join_multicast`](Self::join_multicast) names it). An interface that has gone away
    /// takes its memberships with it; leaving one fails, which callers may ignore.
    pub fn leave_multicast(&self, group: IpAddr, interface: u32) -> io::Result<()> {
        match group {
            IpAddr::V4(g) => {
                let on = ipv4_of(interface)?;
                self.sock.leave_multicast_v4(&g, &on)
            }
            IpAddr::V6(g) => self.sock.leave_multicast_v6(&g, interface),
        }
    }

    /// Closes the socket: its connections are closed (their `on_close` runs on the I/O thread)
    /// and it stops receiving. Idempotent.
    pub fn close(&self) {
        (self.closer)();
    }
}

/// The address an IPv4 multicast join names interface `index` by: its first IPv4 address
/// (0: the default interface, `0.0.0.0`).
fn ipv4_of(index: u32) -> io::Result<std::net::Ipv4Addr> {
    if index == 0 {
        return Ok(std::net::Ipv4Addr::UNSPECIFIED);
    }
    akio_sys::interfaces()?
        .iter()
        .find(|i| i.index == index)
        .and_then(akio_sys::Interface::ipv4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("interface {index} has no IPv4 address"),
            )
        })
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

/// Counts the I/O threads still to act on a command posted to them, and lets the poster wait
/// for them (bounded): each thread gets a [`CountdownToken`] with the command and drops it once
/// it acted (or the command is dropped unprocessed). Backend-facing.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct Countdown(Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>);

/// One thread's share of a [`Countdown`]; dropping it counts the thread as done.
#[doc(hidden)]
#[derive(Debug)]
pub struct CountdownToken(Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>);

impl Countdown {
    /// A new token: the countdown waits for it too.
    pub fn token(&self) -> CountdownToken {
        *self
            .0
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        CountdownToken(Arc::clone(&self.0))
    }

    /// Waits until every token was dropped, or `limit` passed; true in the first case.
    pub fn wait(&self, limit: Duration) -> bool {
        let (m, cv) = &*self.0;
        let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (g, _) = cv
            .wait_timeout_while(g, limit, |n| *n > 0)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *g == 0
    }
}

impl Drop for CountdownToken {
    fn drop(&mut self) {
        let (m, cv) = &*self.0;
        let mut n = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *n = n.saturating_sub(1);
        if *n == 0 {
            cv.notify_all();
        }
    }
}
