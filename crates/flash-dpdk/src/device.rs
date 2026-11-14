//! The link layer under one stack queue: a smoltcp `phy::Device` over a DPDK queue, a TAP
//! interface, an AF_PACKET socket or a memory wire.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use smoltcp::{
    phy::{self, DeviceCapabilities, Medium},
    time::Instant,
};

use crate::{MemoryPort, pmd};

/// Frames handed from one queue's thread to another (ARP fan-out).
pub(crate) type Inbox = Arc<Mutex<VecDeque<Vec<u8>>>>;

pub(crate) enum Link {
    Dpdk(Box<pmd::Queue>),
    #[cfg(target_os = "linux")]
    Tap(pmd::Sendable<phy::TunTapInterface>),
    #[cfg(target_os = "linux")]
    Raw(pmd::Sendable<phy::RawSocket>),
    Memory(MemoryPort),
}

impl Link {
    /// Opens the device for TAP / AF_PACKET (DPDK queues and memory ports are built by the
    /// caller).
    #[cfg(target_os = "linux")]
    pub(crate) fn tap(name: &str) -> std::io::Result<Link> {
        phy::TunTapInterface::new(name, Medium::Ethernet).map(|t| Link::Tap(pmd::Sendable::new(t)))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn af_packet(name: &str) -> std::io::Result<Link> {
        phy::RawSocket::new(name, Medium::Ethernet).map(|r| Link::Raw(pmd::Sendable::new(r)))
    }
}

/// One queue's device: the link plus the ARP fan-out between sibling queues.
pub(crate) struct Port {
    link: Link,
    /// Ethernet frame MTU (IP MTU + 14).
    frame_mtu: usize,
    inbox: Inbox,
    siblings: Vec<Inbox>,
    rx_buf: Vec<u8>,
    tx_scratch: Vec<u8>,
    now: Instant,
    /// Frames received / transmitted (for the loop's idle detection and stats).
    pub(crate) rx_frames: u64,
    pub(crate) tx_frames: u64,
}

impl Port {
    pub(crate) fn new(link: Link, ip_mtu: usize, inbox: Inbox, siblings: Vec<Inbox>) -> Port {
        Port {
            link,
            frame_mtu: ip_mtu + 14,
            inbox,
            siblings,
            rx_buf: Vec::new(),
            tx_scratch: Vec::new(),
            now: Instant::from_millis(0),
            rx_frames: 0,
            tx_frames: 0,
        }
    }

    /// Called first thing on the I/O thread that owns this port.
    pub(crate) fn on_thread_start(&self) {
        if let Link::Dpdk(_) = self.link {
            pmd::register_thread();
        }
    }

    /// Transmits frames batched by the device (DPDK tx burst).
    pub(crate) fn flush(&mut self) {
        if let Link::Dpdk(q) = &mut self.link {
            q.flush();
        }
    }

    /// Sleeps until a frame may have arrived, at most `timeout`.
    pub(crate) fn wait(&self, timeout: Duration) {
        match &self.link {
            #[cfg(target_os = "linux")]
            Link::Tap(t) => {
                let fd = std::os::fd::AsRawFd::as_raw_fd(t.get());
                let _ = phy::wait(fd, Some(timeout.into()));
            }
            #[cfg(target_os = "linux")]
            Link::Raw(r) => {
                let fd = std::os::fd::AsRawFd::as_raw_fd(r.get());
                let _ = phy::wait(fd, Some(timeout.into()));
            }
            // Woken early by `Thread::unpark` when a command is posted.
            Link::Dpdk(_) | Link::Memory(_) => std::thread::park_timeout(timeout),
        }
    }

    /// Copies an ARP frame to the sibling queues: replies and requests land on one queue (RSS
    /// does not hash ARP), but every queue's stack needs the neighbour.
    fn fan_out(siblings: &[Inbox], frame: &[u8]) {
        if !siblings.is_empty() && frame.len() >= 14 && frame[12..14] == [0x08, 0x06] {
            for s in siblings {
                let mut q = s.lock().unwrap_or_else(|p| p.into_inner());
                if q.len() < 1024 {
                    q.push_back(frame.to_vec());
                }
            }
        }
    }
}

pub(crate) enum Rx<'a> {
    Buf(&'a [u8]),
    Mbuf(pmd::Mbuf),
}

impl phy::RxToken for Rx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        match self {
            Rx::Buf(b) => f(b),
            Rx::Mbuf(m) => f(m.data()),
        }
    }
}

pub(crate) struct Tx<'a> {
    link: &'a mut Link,
    scratch: &'a mut Vec<u8>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    now: Instant,
    sent: &'a mut u64,
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        *self.sent += 1;
        // A frame the device cannot take right now is built in `scratch` and dropped.
        let mut f = Some(f);
        let r = match self.link {
            Link::Dpdk(q) => q.send(len, |b| (f.take().expect("unused"))(b)),
            #[cfg(target_os = "linux")]
            Link::Tap(t) => phy::Device::transmit(t.get_mut(), self.now)
                .map(|tx| phy::TxToken::consume(tx, len, |b| (f.take().expect("unused"))(b))),
            #[cfg(target_os = "linux")]
            Link::Raw(r) => phy::Device::transmit(r.get_mut(), self.now)
                .map(|tx| phy::TxToken::consume(tx, len, |b| (f.take().expect("unused"))(b))),
            Link::Memory(m) => {
                let mut frame = vec![0u8; len];
                let r = (f.take().expect("unused"))(&mut frame);
                m.send(frame);
                Some(r)
            }
        };
        match r {
            Some(r) => r,
            None => {
                self.scratch.clear();
                self.scratch.resize(len, 0);
                (f.take().expect("not called"))(self.scratch)
            }
        }
    }
}

impl phy::Device for Port {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, now: Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        self.now = now;
        let Port {
            link,
            inbox,
            siblings,
            rx_buf,
            tx_scratch,
            rx_frames,
            tx_frames,
            ..
        } = self;
        let injected = inbox.lock().unwrap_or_else(|p| p.into_inner()).pop_front();
        let rx = if let Some(frame) = injected {
            *rx_buf = frame;
            Rx::Buf(rx_buf)
        } else {
            match link {
                Link::Dpdk(q) => {
                    let m = q.recv()?;
                    Port::fan_out(siblings, m.data());
                    Rx::Mbuf(m)
                }
                #[cfg(target_os = "linux")]
                Link::Tap(t) => {
                    let (rx, _) = phy::Device::receive(t.get_mut(), now)?;
                    phy::RxToken::consume(rx, |b| {
                        rx_buf.clear();
                        rx_buf.extend_from_slice(b);
                    });
                    Rx::Buf(rx_buf)
                }
                #[cfg(target_os = "linux")]
                Link::Raw(r) => {
                    let (rx, _) = phy::Device::receive(r.get_mut(), now)?;
                    phy::RxToken::consume(rx, |b| {
                        rx_buf.clear();
                        rx_buf.extend_from_slice(b);
                    });
                    Rx::Buf(rx_buf)
                }
                Link::Memory(m) => {
                    *rx_buf = m.recv()?;
                    Rx::Buf(rx_buf)
                }
            }
        };
        *rx_frames += 1;
        Some((
            rx,
            Tx {
                link,
                scratch: tx_scratch,
                now,
                sent: tx_frames,
            },
        ))
    }

    fn transmit(&mut self, now: Instant) -> Option<Tx<'_>> {
        self.now = now;
        Some(Tx {
            link: &mut self.link,
            scratch: &mut self.tx_scratch,
            now,
            sent: &mut self.tx_frames,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.frame_mtu;
        #[cfg(target_os = "linux")]
        if matches!(self.link, Link::Raw(_)) {
            // Frames an AF_PACKET socket sees from the local kernel (a veth peer, checksum
            // offload) carry partial checksums: compute ours, do not verify theirs.
            caps.checksum.ipv4 = phy::Checksum::Tx;
            caps.checksum.udp = phy::Checksum::Tx;
            caps.checksum.tcp = phy::Checksum::Tx;
        }
        caps
    }
}
