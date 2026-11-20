//! The link layer under one stack queue: a DPDK queue, an AF_XDP socket, a TAP interface, an
//! AF_PACKET socket or a memory wire, plus the hand-over of frames between the queues of one device (ARP fan-out,
//! frames for dialed connections that RSS put on another queue).

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{MemoryPort, net, pmd, stack::LoopShared};

/// Frames handed from one queue's thread to another.
pub(crate) type Inbox = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// Most frames waiting in one queue's inbox.
const INBOX_CAP: usize = 4096;

pub(crate) enum Link {
    Dpdk(Box<pmd::Queue>),
    #[cfg(target_os = "linux")]
    Xdp(Box<only_ebpf::xsk::XskSocket>),
    #[cfg(target_os = "linux")]
    Fd(crate::sys::LinkFd),
    Memory(MemoryPort),
}

impl Link {
    #[cfg(target_os = "linux")]
    pub(crate) fn tap(name: &str) -> std::io::Result<Link> {
        crate::sys::LinkFd::tap(name).map(Link::Fd)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn af_packet(name: &str) -> std::io::Result<Link> {
        crate::sys::LinkFd::af_packet(name).map(Link::Fd)
    }
}

/// Opens the AF_XDP sockets of `x` (one link per queue) and returns them with the stack's MAC
/// (`cfg.mac`, else the interface's own).
#[cfg(target_os = "linux")]
pub(crate) fn af_xdp(
    x: &crate::AfXdpConfig,
    cfg: &crate::DpdkConfig,
) -> std::io::Result<(Vec<Link>, [u8; 6])> {
    use only_ebpf::xsk;
    let bad = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, m);
    if x.frames < 128 {
        return Err(bad(format!(
            "AF_XDP: frames must be at least 128, not {}",
            x.frames
        )));
    }
    let mut c = xsk::XskConfig::default();
    c.queues = u32::from(x.queues.max(1));
    c.frames = x.frames;
    c.frame_size = 4096;
    c.ring_size = (x.frames / 2).min(2048);
    c.ring_size = 1 << (31 - c.ring_size.leading_zeros()); // a power of two
    c.mode = x.mode;
    c.zero_copy = match x.zero_copy {
        crate::ZeroCopy::Required => xsk::ZeroCopy::Required,
        crate::ZeroCopy::Off => xsk::ZeroCopy::Off,
        _ => xsk::ZeroCopy::Auto,
    };
    // The kernel keeps 256 bytes of XDP headroom in every chunk.
    if cfg.mtu + 14 > c.frame_size as usize - 256 {
        return Err(bad(format!(
            "AF_XDP: MTU {} above {}",
            cfg.mtu,
            c.frame_size - 256 - 14
        )));
    }
    let ifindex = xsk::if_index(&x.interface)?;
    let mac = match cfg.mac {
        Some(m) => m,
        None => interface_mac(&x.interface)?,
    };
    let (socks, info) = xsk::open(ifindex, &c)
        .map_err(|e| std::io::Error::new(e.kind(), format!("AF_XDP on {}: {e}", x.interface)))?;
    crate::record_af_xdp(
        &x.interface,
        crate::AfXdpInfo {
            native: info.mode == crate::XdpMode::Native,
            zero_copy: info.zero_copy,
            queues: info.queues as u16,
        },
    );
    Ok((
        socks.into_iter().map(|s| Link::Xdp(Box::new(s))).collect(),
        mac,
    ))
}

/// The MAC address of `name` (`/sys/class/net/NAME/address`).
#[cfg(target_os = "linux")]
fn interface_mac(name: &str) -> std::io::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
    let mut mac = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in &mut mac {
        *b = parts
            .next()
            .and_then(|p| u8::from_str_radix(p, 16).ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("MAC {s:?}"))
            })?;
    }
    Ok(mac)
}

/// Where a received frame is.
pub(crate) enum Rx {
    /// Copied (or moved) into the caller's buffer.
    Buf,
    /// In place in a DPDK mbuf.
    Mbuf(pmd::Mbuf),
}

/// What a frame being built is written into (see `net::Tx`).
enum Staged {
    None,
    /// A DPDK mbuf (`Queue::alloc`).
    Mbuf,
    /// An AF_XDP TX chunk (`XskSocket::alloc`).
    #[cfg(target_os = "linux")]
    Xsk,
    /// `scratch`: written to the fd / memory wire on commit.
    Scratch,
    /// `scratch`, but the device could not take a frame: dropped on commit.
    Drop,
}

/// One queue's device.
pub(crate) struct Port {
    link: Link,
    index: usize,
    /// Every queue's inbox, in queue order (this one's included).
    inboxes: Vec<Inbox>,
    /// Every queue's loop, to wake a sibling a frame was handed to.
    loops: Vec<Arc<LoopShared>>,
    scratch: Vec<u8>,
    staged: Staged,
    /// Frames were sent since the last `flush`.
    sent_since_flush: bool,
    /// Frames received / transmitted (idle detection and stats).
    pub(crate) rx_frames: u64,
    pub(crate) tx_frames: u64,
}

impl Port {
    pub(crate) fn new(
        link: Link,
        index: usize,
        inboxes: Vec<Inbox>,
        loops: Vec<Arc<LoopShared>>,
    ) -> Port {
        Port {
            link,
            index,
            inboxes,
            loops,
            scratch: Vec::new(),
            staged: Staged::None,
            sent_since_flush: false,
            rx_frames: 0,
            tx_frames: 0,
        }
    }

    /// Received frames carry the sender's partial checksums (AF_PACKET next to the local
    /// kernel): do not verify them.
    pub(crate) fn partial_checksums(&self) -> bool {
        // AF_XDP too: a veth peer (or the local kernel) sends with checksum offload.
        #[cfg(target_os = "linux")]
        if let Link::Fd(_) | Link::Xdp(_) = self.link {
            return true;
        }
        false
    }

    /// Called first thing on the I/O thread that owns this port.
    pub(crate) fn on_thread_start(&self) {
        match &self.link {
            Link::Dpdk(_) => pmd::register_thread(),
            Link::Memory(m) => m.register_reader(),
            #[cfg(target_os = "linux")]
            Link::Fd(_) | Link::Xdp(_) => {}
        }
    }

    /// The next received frame: from the inbox (frames other queues handed over) first, then
    /// from the device.
    pub(crate) fn recv(&mut self, buf: &mut Vec<u8>) -> Option<Rx> {
        let injected = self.inboxes[self.index]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        let rx = if let Some(frame) = injected {
            *buf = frame;
            Rx::Buf
        } else {
            match &mut self.link {
                Link::Dpdk(q) => {
                    let m = q.recv()?;
                    Self::fan_out(&self.inboxes, self.index, &self.loops, m.data());
                    Rx::Mbuf(m)
                }
                #[cfg(target_os = "linux")]
                Link::Xdp(x) => {
                    x.recv(buf)?;
                    Self::fan_out(&self.inboxes, self.index, &self.loops, buf);
                    Rx::Buf
                }
                #[cfg(target_os = "linux")]
                Link::Fd(fd) => {
                    fd.recv(buf)?;
                    Rx::Buf
                }
                Link::Memory(m) => {
                    *buf = m.recv()?;
                    Rx::Buf
                }
            }
        };
        self.rx_frames += 1;
        Some(rx)
    }

    /// Copies an ARP or NDP frame to the sibling queues: replies and requests land on one queue
    /// (RSS does not hash ARP, and puts a neighbor advertisement wherever its addresses hash),
    /// but every queue's stack needs the neighbour.
    fn fan_out(inboxes: &[Inbox], me: usize, loops: &[Arc<LoopShared>], frame: &[u8]) {
        if inboxes.len() > 1 && net::is_neighbor_frame(frame) {
            for (i, b) in inboxes.iter().enumerate() {
                if i != me {
                    Self::hand_to(b, &loops[i], frame.to_vec());
                }
            }
        }
    }

    fn hand_to(inbox: &Inbox, lp: &LoopShared, frame: Vec<u8>) {
        let mut q = inbox.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() < INBOX_CAP {
            q.push_back(frame);
        }
        drop(q);
        lp.unpark();
    }

    /// Hands a frame to queue `q` (a dialed connection's frame that arrived here).
    pub(crate) fn forward(&self, q: usize, frame: Vec<u8>) {
        if let (Some(b), Some(lp)) = (self.inboxes.get(q), self.loops.get(q)) {
            Self::hand_to(b, lp, frame);
        }
    }

    /// Transmits frames batched by the device (DPDK tx burst).
    pub(crate) fn flush(&mut self) {
        match &mut self.link {
            Link::Dpdk(q) => q.flush(),
            #[cfg(target_os = "linux")]
            Link::Xdp(x) => x.flush(),
            Link::Memory(m) if self.sent_since_flush => m.wake_peer(),
            _ => {}
        }
        self.sent_since_flush = false;
    }

    /// Sleeps until a frame may have arrived, at most `timeout`.
    pub(crate) fn wait(&self, timeout: Duration) {
        match &self.link {
            #[cfg(target_os = "linux")]
            Link::Fd(fd) => fd.wait(timeout),
            #[cfg(target_os = "linux")]
            Link::Xdp(x) => x.wait(timeout),
            // Woken early by `Thread::unpark` when a command or frame is posted.
            Link::Dpdk(_) | Link::Memory(_) => std::thread::park_timeout(timeout),
        }
    }
}

impl net::Tx for Port {
    fn buffer(&mut self, len: usize) -> &mut [u8] {
        self.tx_frames += 1;
        self.sent_since_flush = true;
        self.staged = match &mut self.link {
            Link::Dpdk(q) => {
                if q.alloc(len) {
                    Staged::Mbuf
                } else {
                    Staged::Drop
                }
            }
            #[cfg(target_os = "linux")]
            Link::Xdp(x) => {
                if x.alloc(len) {
                    Staged::Xsk
                } else {
                    Staged::Drop
                }
            }
            _ => Staged::Scratch,
        };
        match (&self.staged, &mut self.link) {
            (Staged::Mbuf, Link::Dpdk(q)) => return q.staged_mut(),
            #[cfg(target_os = "linux")]
            (Staged::Xsk, Link::Xdp(x)) => return x.staged_mut(),
            _ => {}
        }
        self.scratch.clear();
        self.scratch.resize(len, 0);
        &mut self.scratch
    }

    fn commit(&mut self) {
        match std::mem::replace(&mut self.staged, Staged::None) {
            Staged::Mbuf => {
                if let Link::Dpdk(q) = &mut self.link {
                    q.commit();
                }
            }
            #[cfg(target_os = "linux")]
            Staged::Xsk => {
                if let Link::Xdp(x) = &mut self.link {
                    x.commit();
                }
            }
            Staged::Scratch => match &mut self.link {
                #[cfg(target_os = "linux")]
                Link::Fd(fd) => fd.send(&self.scratch),
                Link::Memory(m) => m.send(std::mem::take(&mut self.scratch)),
                #[cfg(target_os = "linux")]
                Link::Xdp(_) => {}
                Link::Dpdk(_) => {}
            },
            Staged::Drop | Staged::None => {}
        }
    }
}
