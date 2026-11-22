#![deny(unsafe_code)] // `unsafe` is confined to the DPDK FFI (`pmd`) and TAP / AF_PACKET (`sys`)
//! `akio`'s kernel-bypass backend (experimental): its own userspace TCP/IP stack (Ethernet,
//! ARP, IPv4, ICMP, IPv6 with NDP, SLAAC and ICMPv6, UDP, TCP with SACK, CUBIC / NewReno,
//! window scaling and timestamps, optional ECN, Accurate ECN and pacing; safe Rust, `#![forbid(unsafe_code)]`, no
//! dependencies) driven by `akio` I/O threads, over
//!
//! * a **DPDK** port ([`Device::Dpdk`], cargo feature `pmd`, Linux, links `libdpdk`): the EAL is
//!   initialised from [`EalConfig`], each I/O thread polls one rx/tx queue pair with
//!   `rte_eth_rx_burst` / `rte_eth_tx_burst`, frames are read from and written to mbufs in place;
//! * an existing Linux interface through **AF_XDP** sockets ([`Device::AfXdp`], ADR-063): the
//!   kernel's lighter bypass, without DPDK or a dedicated driver: an XDP program redirects each
//!   RX queue to a socket whose rings and UMEM the I/O thread polls (zero-copy where the driver
//!   supports it, copy mode otherwise);
//! * a Linux **TAP** interface ([`Device::Tap`]) or an existing interface through an
//!   **AF_PACKET** socket ([`Device::AfPacket`]): the same stack without DPDK, for development,
//!   tests and machines without a DPDK-capable NIC;
//! * an in-process **memory wire** ([`Device::Memory`], [`MemoryWire`]): two stacks in one
//!   process, on any platform, for tests.
//!
//! Applications do not use this crate directly: enable the `dpdk` feature of `akio` (and
//! `dpdk-pmd` for real DPDK ports) and pick `Backend::Dpdk(DpdkConfig)` for a listener. UDP
//! listeners deliver one datagram per `on_data` and TCP listeners a byte stream, exactly as on
//! the kernel backends, so protocol crates (akio-kcp, akio-http, ...) run unchanged.
//!
//! Design (see the book chapter "Kernel bypass (DPDK)"):
//!
//! * One *stack* per device: a stack instance per queue (its own ARP cache, connection table,
//!   timer heap), each owned by one I/O thread that polls the device (busy or adaptive,
//!   [`DpdkConfig::busy_poll`]). Every listener on the same device shares those threads; each
//!   listener is still its own `Group` (own acceptor, config, telemetry, shutdown).
//! * Connections are `ConnInner::new_virtual`: `Conn::send` only queues, and the owning thread
//!   moves the bytes into the stack's send buffers after each callback (no locks on the wire
//!   path besides the per-connection queue lock). The thread works from the stack's events and
//!   timer heap: no per-iteration scan of all connections.
//! * With several queues, the NIC's RSS keeps a flow on one queue; ARP and NDP frames are copied
//!   to every queue so each stack resolves its neighbours, and dialed connections use local ports
//!   that name their queue (`port % queues`), so replies RSS puts elsewhere are handed over.
//! * IPv6 is on when [`DpdkConfig::address6`] is set or [`DpdkConfig::ipv6_slaac`] is on: the
//!   stack then also has a link-local address derived from the MAC, answers neighbor
//!   solicitations and pings, and listeners accept both families on their port (dual-stack).
//!   With `ipv6_slaac` it configures addresses, default routers, the MTU and the hop limit from
//!   router advertisements (RFC 4862); with [`DpdkConfig::ipv6_dad`] it runs duplicate address
//!   detection before using an address. Our addresses are defended against other nodes'
//!   detection either way.
//!
//! Guide: [Kernel bypass (DPDK)](https://lesismal.github.io/akio/en/dpdk.html)
//! (中文: [内核旁路（DPDK）](https://lesismal.github.io/akio/zh-CN/dpdk.html)).
#![warn(clippy::unwrap_used)]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

mod device;
mod group;
mod lp;
mod net;
mod pmd;
mod stack;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use group::DpdkGroup;

/// Configuration of [`Device::Dpdk`]: how the DPDK environment abstraction layer (EAL) is
/// initialised and which port is used. `#[non_exhaustive]`: start from
/// [`EalConfig::default()`] and set fields.
///
/// The EAL is initialised once per process, by the first DPDK stack created; the `args` of later
/// configurations are ignored.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EalConfig {
    /// EAL arguments (without the program name), for example
    /// `["-l", "0-1", "--vdev=net_tap0,iface=dtap0"]` or `["-a", "0000:03:00.0"]`.
    pub args: Vec<String>,
    /// Port to use: its index (`"0"`) or its device name (`"net_tap0"`, `"0000:03:00.0"`).
    pub port: String,
    /// rx/tx queue pairs, one I/O thread each (default 1). With more than one, the port is
    /// configured for RSS on the IP/UDP/TCP 4-tuple.
    pub queues: u16,
    /// Descriptors per queue (default 1024; the PMD may adjust it).
    pub descriptors: u16,
    /// mbufs in the port's pool (default 8191).
    pub mbufs: u32,
}

impl Default for EalConfig {
    fn default() -> Self {
        EalConfig {
            args: Vec::new(),
            port: "0".to_owned(),
            queues: 1,
            descriptors: 1024,
            mbufs: 8191,
        }
    }
}

pub use akio_ebpf::xdp::XdpMode;

/// Whether [`Device::AfXdp`] binds its sockets in zero-copy mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZeroCopy {
    /// Zero-copy where the driver supports it on the queue (the NIC writes frames straight into
    /// the socket's memory), copy mode otherwise (the kernel copies each frame once, still
    /// without an skb or a syscall per frame).
    #[default]
    Auto,
    /// Zero-copy, or fail.
    Required,
    /// Copy mode.
    Off,
}

/// Configuration of [`Device::AfXdp`]. `#[non_exhaustive]`: start from
/// [`AfXdpConfig::new`] and set fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AfXdpConfig {
    /// The interface (a NIC, or one end of a veth pair).
    pub interface: String,
    /// RX/TX queues `0..queues`, one AF_XDP socket and one I/O thread each (default 1). The
    /// interface must have that many queues; with several, its RSS spreads flows over them.
    /// Frames of the interface's other queues go to the kernel.
    pub queues: u16,
    /// How the redirect program is attached (default [`XdpMode::Auto`]: native, else generic).
    pub mode: XdpMode,
    /// Zero-copy or copy mode (default [`ZeroCopy::Auto`]).
    pub zero_copy: ZeroCopy,
    /// UMEM chunks of 4 KiB per queue, half for receiving and half for sending (default 4096,
    /// 16 MiB per queue; at least 128). Rings have `min(2048, frames / 2)` entries. With
    /// [`shared_umem`](Self::shared_umem), the chunks of all queues together.
    pub frames: u32,
    /// One UMEM for all the queues (`XDP_SHARED_UMEM`, Linux 5.10+) instead of one per queue
    /// (default `false`): one registration and one pinned area, `frames` split evenly between
    /// the queues (each queue still owns its chunks: no locking between I/O threads). The
    /// sockets after the first take its mode (zero-copy or copy).
    pub shared_umem: bool,
    /// Multi-buffer frames (`XDP_USE_SG`, Linux 6.6+; default `false`): a frame larger than a
    /// chunk spans several descriptors both ways, so [`DpdkConfig::mtu`] may go up to 9000
    /// (jumbo frames; without it the MTU is at most 3826). The redirect program is loaded
    /// frags-aware, which also lets a veth carry an MTU above about 3.5 KB with native XDP.
    pub multi_buffer: bool,
}

impl AfXdpConfig {
    /// One queue of `interface`, defaults for the rest.
    pub fn new(interface: impl Into<String>) -> AfXdpConfig {
        AfXdpConfig {
            interface: interface.into(),
            queues: 1,
            mode: XdpMode::Auto,
            zero_copy: ZeroCopy::Auto,
            frames: 4096,
            shared_umem: false,
            multi_buffer: false,
        }
    }
}

/// What a [`Device::AfXdp`] stack set up ([`af_xdp_info`]). `#[doc(hidden)]`: for tests and
/// benchmarks.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AfXdpInfo {
    /// The redirect program runs in the driver (native XDP), not in the generic skb path.
    pub native: bool,
    /// Every socket is bound in zero-copy mode.
    pub zero_copy: bool,
    /// Queues (sockets).
    pub queues: u16,
    /// The queues share one UMEM.
    pub shared_umem: bool,
    /// Frames may span several chunks.
    pub multi_buffer: bool,
}

static AF_XDP_INFO: Mutex<Vec<(String, AfXdpInfo)>> = Mutex::new(Vec::new());

/// How the last [`Device::AfXdp`] stack opened on `interface` was set up (`None` if none
/// was). `#[doc(hidden)]`: for tests and benchmarks.
#[doc(hidden)]
pub fn af_xdp_info(interface: &str) -> Option<AfXdpInfo> {
    AF_XDP_INFO
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .rev()
        .find(|(i, _)| i == interface)
        .map(|(_, v)| *v)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn record_af_xdp(interface: &str, info: AfXdpInfo) {
    let mut v = AF_XDP_INFO.lock().unwrap_or_else(|p| p.into_inner());
    v.retain(|(i, _)| i != interface);
    v.push((interface.to_owned(), info));
}

/// The link layer a stack runs on.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Device {
    /// A DPDK port (Linux, cargo feature `pmd` of this crate / `dpdk-pmd` of `akio`, and a
    /// `libdpdk` found at build time; otherwise creating the stack fails with `Unsupported`).
    Dpdk(EalConfig),
    /// A Linux TAP interface of this name, created if it does not exist (needs `CAP_NET_ADMIN`
    /// and `/dev/net/tun`). The kernel side of the TAP is a separate host on the link: give it an
    /// address in the same subnet (`ip addr add 10.0.0.1/24 dev NAME; ip link set NAME up`).
    Tap(String),
    /// An existing Linux interface through an `AF_PACKET` socket (needs `CAP_NET_RAW`). The
    /// kernel keeps its own stack on that interface too: use an interface the kernel does not
    /// use (one end of a veth pair, a dedicated NIC), with an address the kernel does not own.
    AfPacket(String),
    /// An existing Linux interface through AF_XDP sockets (Linux 5.4+; needs `CAP_NET_ADMIN`,
    /// `CAP_NET_RAW` and `CAP_BPF`, or root). An XDP program redirects every frame of the
    /// configured queues to the stack, so the kernel no longer sees that traffic: give the
    /// stack an interface (or queues) of its own. The default MAC is the interface's, so a NIC
    /// needs no promiscuous mode. Fails with `AlreadyExists`/`Busy` if another XDP program is
    /// attached, and with `Unsupported` off Linux.
    AfXdp(AfXdpConfig),
    /// One end of an in-process [`MemoryWire`].
    Memory(MemoryPort),
}

/// Configuration of the kernel-bypass backend (`Backend::Dpdk`). `#[non_exhaustive]`: start
/// from [`DpdkConfig::new`] and set fields.
///
/// Every listener whose configuration names the same device shares one stack (one set of I/O
/// threads, one IP address): the address, MAC, MTU and buffer settings of the first one win.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DpdkConfig {
    /// The link layer.
    pub device: Device,
    /// The stack's IPv4 address.
    pub address: Ipv4Addr,
    /// Prefix length of the local subnet (default 24).
    pub prefix_len: u8,
    /// Default gateway, for peers outside the local subnet.
    pub gateway: Option<Ipv4Addr>,
    /// The stack's IPv6 address (global or unique local). `None` (the default): IPv4 only.
    /// When set, IPv6 is on: the stack also takes the link-local address derived from its MAC
    /// (`fe80::` + modified EUI-64), and listeners accept IPv6 on their port. Needs an MTU of
    /// at least 1280.
    pub address6: Option<Ipv6Addr>,
    /// Prefix length of the IPv6 subnet (default 64): destinations inside it, and link-local
    /// ones, are on the link.
    pub prefix_len6: u8,
    /// IPv6 default router (usually its link-local address), for peers off the link.
    pub gateway6: Option<Ipv6Addr>,
    /// IPv6 stateless address autoconfiguration (RFC 4862), default `false`: the stack sends
    /// router solicitations at start and takes from router advertisements a global address per
    /// advertised /64 prefix (the prefix plus the modified EUI-64 interface identifier of its
    /// MAC, kept for the advertised lifetimes), the default routers, the on-link prefixes, the
    /// link MTU and the hop limit. Turns IPv6 on even without [`address6`](Self::address6);
    /// [`ipv6_addresses`] reports what was configured.
    pub ipv6_slaac: bool,
    /// Duplicate address detection (RFC 4862 5.4, with RFC 7527's nonce), default `false`:
    /// each of the stack's IPv6 addresses (link-local, static, SLAAC) is probed for about a
    /// second before it is used, and given up if another node answers (a duplicate link-local
    /// address turns IPv6 off). Without it the addresses are used at once (other nodes' probes
    /// for them are answered either way).
    pub ipv6_dad: bool,
    /// MAC address. `None`: the DPDK port's or AF_XDP interface's own address, or a locally
    /// administered address derived from `address` for the other devices.
    pub mac: Option<[u8; 6]>,
    /// IP MTU (default 1500, at most 9000: jumbo frames).
    pub mtu: usize,
    /// Receive and send buffer of each TCP connection, bytes each (default 64 KiB). Also bounds
    /// the TCP window.
    pub tcp_buffer: usize,
    /// Receive and send buffer of each UDP socket, bytes each (default 1 MiB).
    pub udp_buffer: usize,
    /// Handshakes in progress per TCP listener and queue (default 64). Beyond it, new SYNs are
    /// answered with SYN cookies ([`syn_cookies`](Self::syn_cookies)) or dropped.
    pub tcp_backlog: usize,
    /// Answer SYNs with stateless SYN cookies once the backlog is full (default `true`).
    pub syn_cookies: bool,
    /// TCP congestion control (default [`Congestion::Cubic`]).
    pub congestion: Congestion,
    /// Negotiate ECN on TCP connections (RFC 3168: data sent ECN-capable, congestion marks
    /// answered like a loss without the retransmission). Default `false`.
    pub tcp_ecn: bool,
    /// Negotiate Accurate ECN on TCP connections (RFC 9768), default `false`: SYNs ask for it,
    /// and with a peer that agrees each ACK reports how many packets arrived CE-marked (the
    /// 3-bit ACE field) and how many bytes arrived with each ECN codepoint (the AccECN option),
    /// instead of RFC 3168's one ECE bit per round trip. Data is sent ECN-capable and CE
    /// feedback answered like a loss without the retransmission, once per window. Peers that
    /// only know RFC 3168 ECN get it (this implies [`tcp_ecn`](Self::tcp_ecn) towards them),
    /// others none. Linux 6.18+ answers with `net.ipv4.tcp_ecn = 3` (or 4 / 5).
    pub tcp_accecn: bool,
    /// Pace TCP transmissions at about `cwnd / srtt` (twice that in slow start) instead of
    /// sending each window as a burst: fewer drops at shallow bottleneck queues, at some CPU
    /// cost. Default `false`.
    pub tcp_pacing: bool,
    /// Idle time before TCP keepalive probes start (`None`, the default: no keepalive; the
    /// engine's idle timeout usually covers dead peers). Probes repeat every
    /// `min(keepalive, 75 s)`; 9 unanswered ones reset the connection.
    pub tcp_keepalive: Option<Duration>,
    /// Poll the device without ever sleeping (DPDK style: lowest latency, one core per queue at
    /// 100%). `false` (the default): after a short spin without traffic the thread sleeps up to a
    /// millisecond at a time.
    pub busy_poll: bool,
}

impl DpdkConfig {
    /// A configuration for `device` with IPv4 address `address` and defaults for the rest.
    pub fn new(device: Device, address: Ipv4Addr) -> DpdkConfig {
        DpdkConfig {
            device,
            address,
            prefix_len: 24,
            gateway: None,
            address6: None,
            prefix_len6: 64,
            gateway6: None,
            ipv6_slaac: false,
            ipv6_dad: false,
            mac: None,
            mtu: 1500,
            tcp_buffer: 64 << 10,
            udp_buffer: 1 << 20,
            tcp_backlog: 64,
            syn_cookies: true,
            congestion: Congestion::Cubic,
            tcp_ecn: false,
            tcp_accecn: false,
            tcp_pacing: false,
            tcp_keepalive: None,
            busy_poll: false,
        }
    }

    pub(crate) fn mac_or_derived(&self) -> [u8; 6] {
        self.mac.unwrap_or_else(|| {
            let o = self.address.octets();
            // Locally administered, unicast.
            [0x02, 0xf1, o[0], o[1], o[2], o[3]]
        })
    }
}

/// The IPv6 addresses the stack open on `device` uses now: its link-local address, the static
/// [`DpdkConfig::address6`] and the addresses SLAAC formed ([`DpdkConfig::ipv6_slaac`]), each
/// once duplicate address detection passed ([`DpdkConfig::ipv6_dad`]); deprecated SLAAC
/// addresses (past their preferred lifetime) are included. Empty when IPv6 is off, `None`
/// when no stack is open on `device` (it starts with the first listener's group).
pub fn ipv6_addresses(device: &Device) -> Option<Vec<Ipv6Addr>> {
    stack::ipv6_addresses(device)
}

/// Process-wide ECN counters of the userspace TCP (`#[doc(hidden)]`: for tests and
/// benchmarks).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpEcnStats {
    /// Connections established in Accurate ECN mode.
    pub accecn: u64,
    /// Connections established with RFC 3168 ECN.
    pub classic: u64,
    /// CE-marked packets received on AccECN connections.
    pub ce_received: u64,
    /// Congestion responses to AccECN feedback.
    pub ce_responses: u64,
}

/// The process-wide [`TcpEcnStats`] (`#[doc(hidden)]`).
#[doc(hidden)]
pub fn tcp_ecn_stats() -> TcpEcnStats {
    use std::sync::atomic::Ordering::Relaxed;
    let s = &net::ECN_STATS;
    TcpEcnStats {
        accecn: s[0].load(Relaxed),
        classic: s[1].load(Relaxed),
        ce_received: s[2].load(Relaxed),
        ce_responses: s[3].load(Relaxed),
    }
}

/// TCP congestion control of a userspace stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Congestion {
    /// CUBIC (RFC 9438), the Linux default.
    #[default]
    Cubic,
    /// NewReno (RFC 5681 / RFC 6582).
    NewReno,
}

/// One direction of a [`MemoryWire`]: the frames in flight and the thread reading them (woken
/// when frames arrive, so an idle reader does not add its sleep to the latency).
#[derive(Default)]
struct Direction {
    frames: Mutex<std::collections::VecDeque<Vec<u8>>>,
    reader: Mutex<Option<std::thread::Thread>>,
}

type Frames = Arc<Direction>;

/// An in-process Ethernet link between two stacks: what one end transmits, the other receives.
/// For tests and examples; works on every platform and needs no privileges.
#[derive(Debug)]
#[non_exhaustive]
pub struct MemoryWire;

impl MemoryWire {
    /// Creates a link and returns its two ends.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> (MemoryPort, MemoryPort) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let a: Frames = Arc::default();
        let b: Frames = Arc::default();
        let id = NEXT.fetch_add(2, Ordering::Relaxed);
        (
            MemoryPort {
                id,
                rx: a.clone(),
                tx: b.clone(),
            },
            MemoryPort {
                id: id + 1,
                rx: b,
                tx: a,
            },
        )
    }
}

/// One end of a [`MemoryWire`]. Clones refer to the same end.
#[derive(Clone)]
pub struct MemoryPort {
    id: u64,
    rx: Frames,
    tx: Frames,
}

impl std::fmt::Debug for MemoryPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryPort").field("id", &self.id).finish()
    }
}

impl MemoryPort {
    /// Most frames queued per direction; beyond it frames are dropped, like a full NIC ring.
    const CAPACITY: usize = 4096;

    pub(crate) fn recv(&self) -> Option<Vec<u8>> {
        self.rx
            .frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
    }

    pub(crate) fn send(&self, frame: Vec<u8>) {
        let mut q = self.tx.frames.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() < Self::CAPACITY {
            q.push_back(frame);
        }
    }

    /// The calling thread reads this end (woken by `wake_peer` of the other end).
    pub(crate) fn register_reader(&self) {
        *self.rx.reader.lock().unwrap_or_else(|p| p.into_inner()) = Some(std::thread::current());
    }

    /// Wakes the thread reading the other end (after a burst was sent).
    pub(crate) fn wake_peer(&self) {
        let reader = self
            .tx
            .reader
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(t) = reader {
            t.unpark();
        }
    }
}

/// How long a dialed TCP connection may take to be established.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
