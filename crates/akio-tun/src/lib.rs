//! TUN devices on `akio` I/O threads (ADR-096): layer-3 virtual interfaces whose every read is
//! one IP packet and every write takes one, for VPNs and overlay networks.
//!
//! * **Linux**: `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`; with [`TunConfig::queues`] above 1,
//!   `IFF_MULTI_QUEUE`, one descriptor per queue and one I/O thread per queue (the kernel keeps a
//!   flow on one queue). Needs `CAP_NET_ADMIN`.
//! * **macOS**: a `utun` interface from the `com.apple.net.utun_control` kernel control (one
//!   queue; the 4-byte address family header in front of each packet is stripped on reads and
//!   added on writes without copying the packet). Needs root.
//!
//! [`TunDevice::create`] opens and configures the interface (name, MTU, addresses, up);
//! [`TunServer::start`] (or `akio::Engine::serve_tun`, which shares the engine's logical pool and
//! telemetry) serves it. Each queue is one connection like a dialed UDP socket's: the
//! [`Acceptor`]'s handler gets every packet read from the device as a borrowed `&[u8]` in
//! [`Handler::on_data`](akio_core::Handler::on_data), on that queue's I/O thread, and
//! [`Conn::send`](akio_core::Conn::send) writes one packet to the device from any thread without
//! blocking. Sends go through the connection's queue, bounded by `Config::max_queued_bytes`
//! (past it `send` fails with `Overloaded`, and the packet is the caller's to drop, as IP
//! allows), with `on_drain` when it empties and `hold_reads` to pause the device's reads (rules 7
//! and 8): a relay holds the device's reads while the other side is backed up and resumes them
//! from its `on_drain`. [`TunWriter`] is a cloneable handle on every queue that picks the queue
//! by flow, for threads that have no `Conn` of their own.
//!
//! The device's reads pause by themselves while its own queue of packets to write is at
//! `Config::write_high_watermark` (resuming at a quarter of it), unless the connection is marked
//! relayed. A device deleted underneath (`ip link del`) closes the connection with the error;
//! [`TunServer::shutdown`] (or dropping the server) writes what is queued, up to
//! `Config::shutdown_timeout`, then closes every queue, which destroys the interface.
//!
//! ```no_run
//! use akio_core::{Conn, Config, Handler, fn_acceptor};
//! use akio_tun::{TunConfig, TunDevice, TunServer};
//!
//! struct Node;
//! impl Handler for Node {
//!     fn on_data(&mut self, _c: &Conn<Self>, packet: &[u8]) {
//!         // route `packet` to a peer...
//!         let _ = packet;
//!     }
//! }
//!
//! # fn main() -> std::io::Result<()> {
//! let dev = TunDevice::create(
//!     &TunConfig::new()
//!         .mtu(1280)
//!         .address("10.7.0.1".parse().unwrap(), 24)
//!         .address("fd07::1".parse().unwrap(), 64),
//! )?;
//! let server = TunServer::start(dev, fn_acceptor(|_c: &Conn<Node>| Node), Config::default())?;
//! let writer = server.writer();
//! # let packet_from_peer = vec![0x45u8; 20];
//! writer.send(&packet_from_peer).ok(); // from any thread
//! # Ok(())
//! # }
//! ```
//!
//! Design: [ADR-096](https://github.com/lesismal/akio/blob/main/docs/adr/096-tun-devices.md)
//! (中文: [ADR-096](https://github.com/lesismal/akio/blob/main/docs/adr/096-tun-devices.zh-CN.md)).
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]

use std::{
    io,
    net::IpAddr,
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use akio_core::{Acceptor, Config, ConnInner, DynAcceptor, Pool, PoolConfig, Result, Telemetry};

mod lp;

use lp::{Cmd, LoopShared};

/// How to create a TUN interface ([`TunDevice::create`]).
#[derive(Clone, Debug)]
pub struct TunConfig {
    name: Option<String>,
    mtu: Option<u32>,
    addresses: Vec<(IpAddr, u8)>,
    queues: usize,
    up: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig::new()
    }
}

impl TunConfig {
    /// A kernel-named interface (`tunN` on Linux, `utunN` on macOS), the kernel's MTU, no
    /// addresses, one queue, brought up.
    pub fn new() -> TunConfig {
        TunConfig {
            name: None,
            mtu: None,
            addresses: Vec::new(),
            queues: 1,
            up: true,
        }
    }

    /// The interface name. Linux: any valid name (created if missing, opened if it exists and
    /// is a TUN the caller may use); macOS: `utunN`.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The MTU (left at the kernel's default when unset: 1500 on Linux and macOS). A VPN whose
    /// packets travel inside another protocol sets it to fit, 1280 being IPv6's minimum.
    #[must_use]
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Adds an address with its prefix length. Linux: one IPv4 address (a second replaces the
    /// first) and any number of IPv6 ones; the kernel routes the prefix to the interface. macOS:
    /// the interface is point-to-point, its destination the address itself; routes for the prefix
    /// are the application's (`route add -net <prefix> -interface utunN`).
    #[must_use]
    pub fn address(mut self, ip: IpAddr, prefix_len: u8) -> Self {
        self.addresses.push((ip, prefix_len));
        self
    }

    /// Queues (Linux only, at least 1): above 1 the interface is multi-queue
    /// (`IFF_MULTI_QUEUE`) and is served by one I/O thread per queue. macOS has one.
    #[must_use]
    pub fn queues(mut self, n: usize) -> Self {
        self.queues = n.max(1);
        self
    }

    /// Bring the interface up once configured (the default) or leave it down.
    #[must_use]
    pub fn up(mut self, up: bool) -> Self {
        self.up = up;
        self
    }
}

/// An open, configured TUN interface: its queues' descriptors, not served yet. Dropping it
/// closes them, which destroys the interface.
#[derive(Debug)]
pub struct TunDevice {
    control: TunControl,
    queues: Vec<OwnedFd>,
}

impl TunDevice {
    /// Creates (Linux: or opens) the interface `cfg` describes, with all its queues, and applies
    /// the MTU, the addresses and the up flag. These are system calls the kernel serialises
    /// with other interface changes: call it on a control thread or the pool, not on an I/O
    /// thread (rule 1).
    ///
    /// Fails with `PermissionDenied` without `CAP_NET_ADMIN` (Linux) or root (macOS).
    pub fn create(cfg: &TunConfig) -> io::Result<TunDevice> {
        let (queues, name) = open_queues(cfg)?;
        let control = TunControl { name };
        if let Some(mtu) = cfg.mtu {
            control.set_mtu(mtu)?;
        }
        for &(ip, prefix) in &cfg.addresses {
            control.add_address(ip, prefix)?;
        }
        if cfg.up {
            control.set_up(true)?;
        }
        Ok(TunDevice { control, queues })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.control.name
    }

    /// The number of queues.
    pub fn queues(&self) -> usize {
        self.queues.len()
    }

    /// The interface's settings.
    pub fn control(&self) -> TunControl {
        self.control.clone()
    }
}

#[cfg(target_os = "linux")]
fn open_queues(cfg: &TunConfig) -> io::Result<(Vec<OwnedFd>, String)> {
    let multi = cfg.queues > 1;
    let (first, name) = akio_sys::tun_open(cfg.name.as_deref(), multi)?;
    let mut queues = vec![first];
    for _ in 1..cfg.queues {
        queues.push(akio_sys::tun_open(Some(&name), true)?.0);
    }
    Ok((queues, name))
}

#[cfg(target_os = "macos")]
fn open_queues(cfg: &TunConfig) -> io::Result<(Vec<OwnedFd>, String)> {
    if cfg.queues > 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "utun has a single queue",
        ));
    }
    let unit = match cfg.name.as_deref() {
        None => None,
        Some(n) => Some(
            n.strip_prefix("utun")
                .and_then(|u| u.parse::<u32>().ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("macOS TUN interfaces are named utunN, not {n:?}"),
                    )
                })?,
        ),
    };
    let fd = akio_sys::utun_open(unit)?;
    let name = akio_sys::utun_name(&fd)?;
    Ok((vec![fd], name))
}

/// The settings of a TUN interface, by name: MTU, addresses, up / down. Cloneable; every call
/// is a system call (an ioctl), for a control thread or the pool, not an I/O thread (rule 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunControl {
    name: String,
}

impl TunControl {
    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface index.
    pub fn index(&self) -> io::Result<u32> {
        akio_sys::if_index(&self.name)
    }

    /// The MTU.
    pub fn mtu(&self) -> io::Result<u32> {
        akio_sys::if_mtu(&self.name)
    }

    /// Sets the MTU.
    pub fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        akio_sys::if_set_mtu(&self.name, mtu)
    }

    /// Adds an address (see [`TunConfig::address`]).
    pub fn add_address(&self, ip: IpAddr, prefix_len: u8) -> io::Result<()> {
        akio_sys::if_add_addr(&self.name, ip, prefix_len)
    }

    /// Removes an address.
    pub fn remove_address(&self, ip: IpAddr, prefix_len: u8) -> io::Result<()> {
        akio_sys::if_del_addr(&self.name, ip, prefix_len)
    }

    /// Whether the interface is up.
    pub fn is_up(&self) -> io::Result<bool> {
        akio_sys::if_is_up(&self.name)
    }

    /// Brings the interface up or down. While it is down the kernel sends nothing through it,
    /// and packets written to it are dropped.
    pub fn set_up(&self, up: bool) -> io::Result<()> {
        akio_sys::if_set_up(&self.name, up)
    }
}

/// A served TUN device: one I/O thread and one connection per queue. Dropping it shuts it down
/// and waits for its threads.
pub struct TunServer {
    control: TunControl,
    writer: TunWriter,
    shared: Vec<Arc<LoopShared>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for TunServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunServer")
            .field("name", &self.control.name)
            .field("queues", &self.shared.len())
            .finish_non_exhaustive()
    }
}

impl TunServer {
    /// Serves `device` with `acceptor` on its own I/O threads (one per queue) and a logical
    /// pool of its own (`Conn::spawn_blocking`). `cfg` gives the queue bounds
    /// (`max_queued_bytes`, `write_high_watermark`), `shutdown_timeout`, the slow-callback
    /// threshold and telemetry (the read buffer always holds the largest packet, 64 KiB).
    /// `akio::Engine::serve_tun` serves it with the engine's pool and telemetry instead.
    ///
    /// As with an engine, a `cfg` whose telemetry hub another engine or server already adopted
    /// gets a fresh hub, so metrics do not mix; the reloadable settings can then be changed with
    /// `cfg.telemetry.reload`.
    pub fn start<A: Acceptor>(
        device: TunDevice,
        acceptor: A,
        mut cfg: Config,
    ) -> io::Result<TunServer> {
        if cfg.telemetry.is_bound() {
            cfg.telemetry = Telemetry::new();
        }
        let telemetry = cfg.telemetry.clone();
        telemetry.bind(&cfg);
        let pool = Pool::new(PoolConfig::default());
        telemetry.set_pool(&pool);
        TunServer::start_dyn(device, Arc::new(acceptor), cfg, pool)
    }

    /// [`start`](Self::start) with a type-erased acceptor and a given pool; `cfg.telemetry` must
    /// be bound already (its live settings are the limits). Backend-facing
    /// (`akio::Engine::serve_tun`).
    #[doc(hidden)]
    pub fn start_dyn(
        device: TunDevice,
        acceptor: Arc<dyn DynAcceptor>,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<TunServer> {
        let cfg = Arc::new(cfg);
        let TunDevice { control, queues } = device;
        let mut shared = Vec::with_capacity(queues.len());
        let mut inners = Vec::with_capacity(queues.len());
        let mut loops = Vec::with_capacity(queues.len());
        for (i, fd) in queues.into_iter().enumerate() {
            let (l, sh, inner) =
                lp::QueueLoop::new(i, fd, acceptor.clone(), cfg.clone(), pool.clone())?;
            loops.push(l);
            shared.push(sh);
            inners.push(inner);
        }
        let mut threads = Vec::with_capacity(loops.len());
        for (i, mut l) in loops.into_iter().enumerate() {
            let name = format!("akio-tun-{i}");
            match std::thread::Builder::new()
                .name(name)
                .spawn(move || l.run())
            {
                Ok(t) => threads.push(t),
                Err(e) => {
                    for sh in &shared[..i] {
                        sh.post(Cmd::Shutdown);
                    }
                    for t in threads {
                        let _ = t.join();
                    }
                    return Err(e);
                }
            }
        }
        Ok(TunServer {
            control,
            writer: TunWriter {
                queues: inners.into(),
            },
            shared,
            threads: Mutex::new(threads),
        })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.control.name
    }

    /// The interface's settings.
    pub fn control(&self) -> TunControl {
        self.control.clone()
    }

    /// The number of queues (I/O threads).
    pub fn queues(&self) -> usize {
        self.shared.len()
    }

    /// A cloneable `Send + Sync` handle that writes packets to the device from any thread.
    pub fn writer(&self) -> TunWriter {
        self.writer.clone()
    }

    /// Whether every queue has closed (shut down, closed by its handler, or the device was
    /// deleted).
    pub fn is_closed(&self) -> bool {
        self.writer.queues.iter().all(|q| !q.is_open())
    }

    /// Begins shutdown: each queue's acceptor gets `on_shutdown`, reads stop, what is queued is
    /// written (up to `Config::shutdown_timeout`), then the queue closes (`on_close(None)`)
    /// and its thread ends. Returns at once; [`join`](Self::join) waits.
    pub fn shutdown(&self) {
        for sh in &self.shared {
            sh.post(Cmd::Shutdown);
        }
    }

    /// Blocks until every queue's thread has ended.
    pub fn join(&self) {
        let threads = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
        for t in threads {
            let _ = t.join();
        }
    }
}

impl Drop for TunServer {
    fn drop(&mut self) {
        self.shutdown();
        self.join();
    }
}

/// Writes packets to a served TUN device from any thread, without blocking (see the crate
/// docs). Cloneable, `Send + Sync`.
///
/// [`send`](Self::send) picks the queue from the packet's addresses, so the packets of one
/// flow keep their order; [`send_on`](Self::send_on) names it.
#[derive(Clone)]
pub struct TunWriter {
    queues: Arc<[Arc<ConnInner>]>,
}

impl std::fmt::Debug for TunWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunWriter")
            .field("queues", &self.queues.len())
            .finish()
    }
}

impl TunWriter {
    /// Queues one IP packet for the device. `Overloaded` when that queue holds
    /// `Config::max_queued_bytes`; `Closed` once it has closed. Empty packets are ignored.
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        self.queues[self.queue_of(packet)].send(packet)
    }

    /// [`send`](Self::send) with a buffer the queue takes over (no copy when it is queued).
    pub fn send_owned(&self, packet: Vec<u8>) -> Result<()> {
        self.queues[self.queue_of(&packet)].send_owned(packet)
    }

    /// Queues one packet on queue `queue` (taken modulo the number of queues).
    pub fn send_on(&self, queue: usize, packet: &[u8]) -> Result<()> {
        self.queues[queue % self.queues.len()].send(packet)
    }

    /// The queue [`send`](Self::send) uses for `packet`: a hash of its source and destination
    /// addresses (0 when there is one queue or the packet is not IP).
    pub fn queue_of(&self, packet: &[u8]) -> usize {
        let n = self.queues.len();
        if n == 1 {
            return 0;
        }
        let addrs = match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => &packet[12..20],
            Some(6) if packet.len() >= 40 => &packet[8..40],
            _ => return 0,
        };
        // FNV-1a over the address bytes: order-sensitive, which is fine since each direction of
        // a flow is written by one side only.
        let mut h: u32 = 0x811c_9dc5;
        for &b in addrs {
            h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        h as usize % n
    }

    /// The number of queues.
    pub fn queues(&self) -> usize {
        self.queues.len()
    }

    /// Bytes queued on `queue`, not yet written to the device.
    pub fn queued_bytes(&self, queue: usize) -> usize {
        self.queues[queue % self.queues.len()].queued_bytes()
    }

    /// Calls `f` once queue `queue` has written everything queued (at once if it is empty), or
    /// when it closes; replaces an earlier waiter of that queue. With `Overloaded` from
    /// [`send`](Self::send), this is how a relay resumes reading the other side.
    pub fn on_drain(&self, queue: usize, f: impl FnOnce() + Send + 'static) {
        self.queues[queue % self.queues.len()].on_drain(Box::new(f));
    }

    /// Whether queue `queue` is open.
    pub fn is_open(&self, queue: usize) -> bool {
        self.queues[queue % self.queues.len()].is_open()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builder() {
        let c = TunConfig::new()
            .name("t0")
            .mtu(1280)
            .address("10.0.0.1".parse().unwrap(), 24)
            .queues(0)
            .up(false);
        assert_eq!(c.name.as_deref(), Some("t0"));
        assert_eq!(c.mtu, Some(1280));
        assert_eq!(c.addresses.len(), 1);
        assert_eq!(c.queues, 1);
        assert!(!c.up);
    }
}
