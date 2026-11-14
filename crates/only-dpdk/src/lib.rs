#![deny(unsafe_code)] // `unsafe` is confined to the DPDK FFI module (`pmd`)
//! `only`'s kernel-bypass backend (experimental): a userspace TCP/IP stack
//! ([smoltcp](https://docs.rs/smoltcp)) driven by `only` I/O threads, over
//!
//! * a **DPDK** port ([`Device::Dpdk`], cargo feature `pmd`, Linux, links `libdpdk`): the EAL is
//!   initialised from [`EalConfig`], each I/O thread polls one rx/tx queue pair with
//!   `rte_eth_rx_burst` / `rte_eth_tx_burst`, frames are read from and written to mbufs in place;
//! * a Linux **TAP** interface ([`Device::Tap`]) or an existing interface through an
//!   **AF_PACKET** socket ([`Device::AfPacket`]): the same stack without DPDK, for development,
//!   tests and machines without a DPDK-capable NIC;
//! * an in-process **memory wire** ([`Device::Memory`], [`MemoryWire`]): two stacks in one
//!   process, on any platform, for tests.
//!
//! Applications do not use this crate directly: enable the `dpdk` feature of `only` (and
//! `dpdk-pmd` for real DPDK ports) and pick `Backend::Dpdk(DpdkConfig)` for a listener. UDP
//! listeners deliver one datagram per `on_data` and TCP listeners a byte stream, exactly as on
//! the kernel backends, so protocol crates (only-kcp, only-http, ...) run unchanged.
//!
//! Design (see the book chapter "Kernel bypass (DPDK)"):
//!
//! * One *stack* per device: a smoltcp `Interface` and socket set per queue, each owned by one
//!   I/O thread that polls the device (busy or adaptive, [`DpdkConfig::busy_poll`]). Every
//!   listener on the same device shares those threads; each listener is still its own `Group`
//!   (own acceptor, config, telemetry, shutdown).
//! * Connections are `ConnInner::new_virtual`: `Conn::send` only queues, and the owning thread
//!   moves the bytes into smoltcp's socket buffers after each callback (no locks on the wire
//!   path besides the per-connection queue lock).
//! * With several queues, the NIC's RSS keeps a flow on one queue; ARP frames are copied to every
//!   queue so each stack resolves its neighbours.
//!
//! Guide: [Kernel bypass (DPDK)](https://lesismal.github.io/only/en/dpdk.html)
//! (中文: [内核旁路（DPDK）](https://lesismal.github.io/only/zh-CN/dpdk.html)).
#![warn(clippy::unwrap_used)]

use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

mod device;
mod group;
mod lp;
mod pmd;
mod stack;

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

/// The link layer a stack runs on.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Device {
    /// A DPDK port (Linux, cargo feature `pmd` of this crate / `dpdk-pmd` of `only`, and a
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
    /// MAC address. `None`: the DPDK port's own address, or a locally administered address
    /// derived from `address` for the other devices.
    pub mac: Option<[u8; 6]>,
    /// IP MTU (default 1500).
    pub mtu: usize,
    /// Receive and send buffer of each TCP connection, bytes each (default 64 KiB). Also bounds
    /// the TCP window.
    pub tcp_buffer: usize,
    /// Receive and send buffer of each UDP socket, bytes each (default 1 MiB).
    pub udp_buffer: usize,
    /// Listening TCP sockets kept ready per TCP listener and queue: how many handshakes can be in
    /// progress at once (default 64).
    pub tcp_backlog: usize,
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
            mac: None,
            mtu: 1500,
            tcp_buffer: 64 << 10,
            udp_buffer: 1 << 20,
            tcp_backlog: 64,
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

/// Frames in flight on one direction of a [`MemoryWire`].
type Frames = Arc<Mutex<std::collections::VecDeque<Vec<u8>>>>;

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
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
    }

    pub(crate) fn send(&self, frame: Vec<u8>) {
        let mut q = self.tx.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() < Self::CAPACITY {
            q.push_back(frame);
        }
    }
}

/// How long a dialed TCP connection may take to be established.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
