//! XDP per-source rate limiting: a token bucket per source address, run on every received
//! packet of an interface before the kernel allocates anything for it, so floods from a few
//! sources (a SYN flood, a UDP flood) are dropped at the cheapest point.
//!
//! [`RateLimiter::attach`] loads the program (hand-assembled, like the steering ones) with a
//! bounded LRU map of sources and attaches it to the interface: with a BPF link (Linux 5.9+;
//! the kernel detaches it when the process exits, even on a crash) or, on older kernels, with
//! netlink (`RTM_SETLINK`/`IFLA_XDP`). It never replaces a program someone else attached.
//! Dropping the [`RateLimiter`] detaches it. Needs `CAP_NET_ADMIN` and `CAP_BPF` (or
//! `CAP_SYS_ADMIN`).
//!
//! What it does not do: the buckets are per receiving CPU (no atomics on the packet path), so a
//! source whose flows the NIC spreads over several RX queues gets up to `rate` per queue; a
//! flood with spoofed, ever-changing source addresses gives every packet a fresh bucket (that
//! is what SYN cookies, the kernel default, are for); VLAN-tagged frames and IPv6 packets with
//! extension headers before TCP (in [`Count::TcpSyn`] mode) are not counted.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{io, net::IpAddr};

/// Which packets count against a source's bucket. Packets that do not count always pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Count {
    /// TCP SYNs without ACK (new connections): connection-flood protection that leaves
    /// established traffic alone.
    #[default]
    TcpSyn,
    /// Every IPv4 and IPv6 packet.
    AllPackets,
}

/// How the program is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum XdpMode {
    /// Native (driver) mode where the driver supports it, else generic.
    #[default]
    Auto,
    /// Native (driver) XDP only: fails where the driver has no XDP support.
    Native,
    /// Generic (`skb`) XDP: works on every interface, after the kernel allocated the `skb`.
    Generic,
}

/// Default [`XdpLimit::rate`].
pub const DEFAULT_RATE: u32 = 100;
/// Default [`XdpLimit::burst`].
pub const DEFAULT_BURST: u32 = 200;
/// Default [`XdpLimit::max_sources`].
pub const DEFAULT_MAX_SOURCES: u32 = 16 << 10;
/// Largest [`XdpLimit::max_sources`].
pub const MAX_SOURCES: u32 = 1 << 24;

/// Configuration of a [`RateLimiter`]. `#[non_exhaustive]`: start from
/// `XdpLimit::default()` and set fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct XdpLimit {
    /// Sustained packets per second each source may send (per receiving CPU), 1 to 10^9.
    /// Default [`DEFAULT_RATE`].
    pub rate: u32,
    /// Packets a source may send at once after being quiet (bucket size), at least 1. Default
    /// [`DEFAULT_BURST`].
    pub burst: u32,
    /// Sources tracked at once (an LRU map: the least recently seen is forgotten, which only
    /// gives it a full bucket again). Memory is about `max_sources * (80 + 16 * possible CPUs)`
    /// bytes, 1.6 MiB per 1024 sources on 96 CPUs. Default [`DEFAULT_MAX_SOURCES`], at most
    /// [`MAX_SOURCES`].
    pub max_sources: u32,
    /// Which packets are counted. Default [`Count::TcpSyn`].
    pub count: Count,
    /// Attachment mode. Default [`XdpMode::Auto`].
    pub mode: XdpMode,
    /// Attach with netlink even where BPF links exist (testing the fallback).
    #[doc(hidden)]
    pub force_netlink: bool,
}

impl Default for XdpLimit {
    fn default() -> Self {
        XdpLimit {
            rate: DEFAULT_RATE,
            burst: DEFAULT_BURST,
            max_sources: DEFAULT_MAX_SOURCES,
            count: Count::TcpSyn,
            mode: XdpMode::Auto,
            force_netlink: false,
        }
    }
}

impl XdpLimit {
    /// `(cost, cap)` of the program: nanoseconds of credit per packet and per full bucket.
    pub(crate) fn bucket(&self) -> io::Result<(u64, u64)> {
        let bad = |what: &str| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                what.to_string(),
            ))
        };
        if self.rate == 0 || self.rate > 1_000_000_000 {
            return bad("XDP rate must be 1 to 10^9 packets per second");
        }
        if self.burst == 0 {
            return bad("XDP burst must be at least 1");
        }
        if self.max_sources == 0 || self.max_sources > MAX_SOURCES {
            return bad("XDP max_sources must be 1 to MAX_SOURCES");
        }
        let cost = 1_000_000_000 / u64::from(self.rate);
        Ok((cost, cost * u64::from(self.burst)))
    }
}

/// Counters of a [`RateLimiter`], summed over CPUs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct XdpStats {
    /// Counted packets that passed (including each source's first).
    pub passed: u64,
    /// Counted packets dropped for lack of credit.
    pub dropped: u64,
    /// Times a source was not in the map (new, or forgotten by the LRU) on the receiving CPU.
    pub new_sources: u64,
}

/// How a [`RateLimiter`] is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attachment {
    /// A BPF link (Linux 5.9+): detached when the last fd closes, even if the process dies.
    Link,
    /// `IFLA_XDP` over netlink: detached by [`RateLimiter::detach`] or drop; it would outlive a
    /// process that dies without either.
    Netlink,
}

/// An attached XDP rate limiter; detached when dropped.
pub struct RateLimiter {
    #[cfg(target_os = "linux")]
    inner: imp::Attached,
    ifindex: u32,
    mode: XdpMode,
    attachment: Attachment,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("ifindex", &self.ifindex)
            .field("mode", &self.mode)
            .field("attachment", &self.attachment)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Loads the limiter and attaches it to the interface named `interface` (e.g. `"eth0"`).
    /// Fails with `InvalidInput` for a bad configuration, `NotFound` for an unknown interface,
    /// `PermissionDenied` without the capabilities, `Unsupported` off Linux, the kernel's error
    /// (`EBUSY` or `EEXIST`: another XDP program is attached; `EOPNOTSUPP`: [`XdpMode::Native`] on a driver
    /// without XDP) otherwise.
    pub fn attach(interface: &str, cfg: &XdpLimit) -> io::Result<RateLimiter> {
        #[cfg(target_os = "linux")]
        return Self::attach_index(crate::sys::if_index(interface)?, cfg);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (interface, cfg);
            Err(unsupported())
        }
    }

    /// [`attach`](Self::attach) by interface index.
    pub fn attach_index(ifindex: u32, cfg: &XdpLimit) -> io::Result<RateLimiter> {
        let (cost, cap) = cfg.bucket()?;
        #[cfg(target_os = "linux")]
        {
            let (inner, mode, attachment) = imp::Attached::new(ifindex, cfg, cost, cap)?;
            Ok(RateLimiter {
                inner,
                ifindex,
                mode,
                attachment,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ifindex, cost, cap);
            Err(unsupported())
        }
    }

    /// The interface index.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The mode the program runs in: [`XdpMode::Native`] or [`XdpMode::Generic`].
    pub fn mode(&self) -> XdpMode {
        self.mode
    }

    /// How the program is attached.
    pub fn attachment(&self) -> Attachment {
        self.attachment
    }

    /// The counters, summed over CPUs.
    pub fn stats(&self) -> io::Result<XdpStats> {
        #[cfg(target_os = "linux")]
        return self.inner.stats();
        #[cfg(not(target_os = "linux"))]
        Err(unsupported())
    }

    /// Removes a source's bucket on every CPU (it starts again with a full one); `false` when it
    /// was not tracked.
    pub fn forget(&self, source: IpAddr) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        return self.inner.forget(source_key(source));
        #[cfg(not(target_os = "linux"))]
        {
            let _ = source;
            Err(unsupported())
        }
    }

    /// Detaches the program, reporting an error the drop would ignore.
    pub fn detach(mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let inner = std::mem::replace(&mut self.inner, imp::Attached::empty());
            inner.detach(self.ifindex)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RateLimiter {
    fn drop(&mut self) {
        let inner = std::mem::replace(&mut self.inner, imp::Attached::empty());
        let _ = inner.detach(self.ifindex);
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "XDP is Linux-only")
}

/// The map key of a source: its IPv6 address, IPv4 mapped to `::ffff:a.b.c.d`.
pub(crate) fn source_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    }
}

// Netlink message building (pure, testable everywhere).
const RTM_SETLINK: u16 = 19;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const IFLA_XDP: u16 = 43;
const NLA_F_NESTED: u16 = 0x8000;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;
const IFLA_XDP_EXPECTED_FD: u16 = 8;

pub(crate) const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
pub(crate) const XDP_FLAGS_SKB_MODE: u32 = 2;
pub(crate) const XDP_FLAGS_DRV_MODE: u32 = 4;
pub(crate) const XDP_FLAGS_REPLACE: u32 = 16;

/// An `RTM_SETLINK` request setting `IFLA_XDP` of `ifindex`: program `fd` (-1 detaches) with
/// `flags`, replacing only program `expected` when given.
pub(crate) fn setlink_xdp(ifindex: u32, fd: i32, flags: u32, expected: Option<i32>) -> Vec<u8> {
    let mut xdp = Vec::new();
    let mut attr = |t: u16, v: [u8; 4]| {
        xdp.extend(8u16.to_ne_bytes());
        xdp.extend(t.to_ne_bytes());
        xdp.extend(v);
    };
    attr(IFLA_XDP_FD, fd.to_ne_bytes());
    attr(IFLA_XDP_FLAGS, flags.to_ne_bytes());
    if let Some(e) = expected {
        attr(IFLA_XDP_EXPECTED_FD, e.to_ne_bytes());
    }
    let len = 16 + 16 + 4 + xdp.len();
    let mut m = Vec::with_capacity(len);
    m.extend((len as u32).to_ne_bytes());
    m.extend(RTM_SETLINK.to_ne_bytes());
    m.extend((NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    m.extend(1u32.to_ne_bytes()); // seq
    m.extend(0u32.to_ne_bytes()); // pid: the kernel
    // struct ifinfomsg: family, pad, type, index, flags, change.
    m.extend([0u8, 0, 0, 0]);
    m.extend(ifindex.to_ne_bytes());
    m.extend([0u8; 8]);
    m.extend(((4 + xdp.len()) as u16).to_ne_bytes());
    m.extend((IFLA_XDP | NLA_F_NESTED).to_ne_bytes());
    m.extend(xdp);
    m
}

/// The result an `NLMSG_ERROR` acknowledgement carries: `Ok` for 0, the errno otherwise.
pub(crate) fn parse_ack(b: &[u8]) -> io::Result<()> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed netlink reply");
    let ty = u16::from_ne_bytes(b.get(4..6).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    if ty != NLMSG_ERROR {
        return Err(bad());
    }
    let err = i32::from_ne_bytes(
        b.get(16..20)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    );
    if err == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-err))
    }
}

/// Loads (and drops) the program with the default configuration.
#[cfg(target_os = "linux")]
pub(crate) fn probe_load() -> io::Result<()> {
    let (cost, cap) = XdpLimit::default().bucket()?;
    imp::load(&XdpLimit::default(), cost, cap).map(drop)
}

#[cfg(target_os = "linux")]
pub(crate) use imp::ProgLink;

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        io,
        os::fd::{AsRawFd, OwnedFd},
    };

    use super::*;
    use crate::{ebpf, sys};

    type Sources = sys::Map<[u8; 16], ebpf::Bucket>;

    /// Creates the maps and loads the program.
    pub(super) fn load(
        cfg: &XdpLimit,
        cost: u64,
        cap: u64,
    ) -> io::Result<(Sources, sys::Map<u32, u64>, OwnedFd)> {
        let sources = Sources::create(sys::MAP_LRU_PERCPU_HASH, cfg.max_sources)?;
        let counters = sys::Map::<u32, u64>::create(sys::MAP_PERCPU_ARRAY, ebpf::COUNTERS)?;
        let prog = sys::prog_load(
            sys::PROG_XDP,
            0,
            &ebpf::xdp_rate_limit(ebpf::LimitProg {
                sources: sources.fd(),
                counters: counters.fd(),
                cost,
                cap,
                syn_only: cfg.count == Count::TcpSyn,
            }),
            "only_xdp_limit",
        )?;
        Ok((sources, counters, prog))
    }

    enum How {
        Link(OwnedFd),
        Netlink { mode_flags: u32 },
        Detached,
    }

    /// An XDP program attached to an interface (by a BPF link or netlink); detached by
    /// [`ProgLink::detach`] or when the link fd closes.
    pub(crate) struct ProgLink {
        how: How,
        prog: Option<OwnedFd>,
    }

    fn netlink(msg: &[u8]) -> io::Result<()> {
        let s = sys::netlink_route()?;
        sys::write_all(s.as_raw_fd(), msg)?;
        let mut buf = [0u8; 4096];
        let n = sys::read(s.as_raw_fd(), &mut buf)?;
        parse_ack(&buf[..n])
    }

    impl ProgLink {
        pub(crate) fn empty() -> ProgLink {
            ProgLink {
                how: How::Detached,
                prog: None,
            }
        }

        /// Attaches the loaded XDP program `prog` to `ifindex` in `mode` (native first, then
        /// generic, for `Auto`): with a BPF link, or with netlink on kernels without XDP links
        /// (or when `force_netlink`). Never replaces a program someone else attached.
        pub(crate) fn attach(
            ifindex: u32,
            prog: OwnedFd,
            mode: XdpMode,
            force_netlink: bool,
        ) -> io::Result<(ProgLink, XdpMode, Attachment)> {
            let modes: &[(u32, XdpMode)] = match mode {
                XdpMode::Native => &[(XDP_FLAGS_DRV_MODE, XdpMode::Native)],
                XdpMode::Generic => &[(XDP_FLAGS_SKB_MODE, XdpMode::Generic)],
                _ => &[
                    (XDP_FLAGS_DRV_MODE, XdpMode::Native),
                    (XDP_FLAGS_SKB_MODE, XdpMode::Generic),
                ],
            };
            // Errors that mean "this mode is not available here", worth trying the next one.
            let mode_unavailable = |e: &io::Error| {
                matches!(
                    e.raw_os_error(),
                    Some(only_sys::ffi::EOPNOTSUPP | only_sys::ffi::EINVAL)
                )
            };
            let mut first_err = None;
            let mut link_unsupported = force_netlink;
            if !link_unsupported {
                for &(flags, mode) in modes {
                    match sys::xdp_link_create(prog.as_raw_fd(), ifindex, flags) {
                        Ok(link) => {
                            return Ok((
                                ProgLink {
                                    how: How::Link(link),
                                    prog: Some(prog),
                                },
                                mode,
                                Attachment::Link,
                            ));
                        }
                        Err(e) if mode_unavailable(&e) => {
                            first_err.get_or_insert(e);
                        }
                        Err(e) => return Err(e),
                    }
                }
                // EINVAL for every mode: most likely a kernel without XDP links (< 5.9).
                link_unsupported = true;
            }
            if link_unsupported {
                for &(flags, mode) in modes {
                    let msg = setlink_xdp(
                        ifindex,
                        prog.as_raw_fd(),
                        flags | XDP_FLAGS_UPDATE_IF_NOEXIST,
                        None,
                    );
                    match netlink(&msg) {
                        Ok(()) => {
                            return Ok((
                                ProgLink {
                                    how: How::Netlink { mode_flags: flags },
                                    prog: Some(prog),
                                },
                                mode,
                                Attachment::Netlink,
                            ));
                        }
                        Err(e) if mode_unavailable(&e) => {
                            first_err.get_or_insert(e);
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(first_err.unwrap_or_else(|| io::Error::other("XDP attach failed")))
        }

        pub(crate) fn detach(mut self, ifindex: u32) -> io::Result<()> {
            match std::mem::replace(&mut self.how, How::Detached) {
                How::Detached => Ok(()),
                // Closing the last link fd detaches.
                How::Link(link) => {
                    drop(link);
                    Ok(())
                }
                How::Netlink { mode_flags } => {
                    let Some(prog) = &self.prog else {
                        return Ok(());
                    };
                    // Remove only our program (5.7+); older kernels reject the flag, and then
                    // whatever is attached in our mode goes.
                    let ours = setlink_xdp(
                        ifindex,
                        -1,
                        mode_flags | XDP_FLAGS_REPLACE,
                        Some(prog.as_raw_fd()),
                    );
                    match netlink(&ours) {
                        Err(e) if e.raw_os_error() == Some(only_sys::ffi::EINVAL) => {
                            netlink(&setlink_xdp(ifindex, -1, mode_flags, None))
                        }
                        r => r,
                    }
                }
            }
        }
    }

    pub(super) struct Attached {
        link: ProgLink,
        sources: Option<Sources>,
        counters: Option<sys::Map<u32, u64>>,
    }

    impl Attached {
        pub(super) fn empty() -> Attached {
            Attached {
                link: ProgLink::empty(),
                sources: None,
                counters: None,
            }
        }

        pub(super) fn new(
            ifindex: u32,
            cfg: &XdpLimit,
            cost: u64,
            cap: u64,
        ) -> io::Result<(Attached, XdpMode, Attachment)> {
            let (sources, counters, prog) = load(cfg, cost, cap)?;
            let (link, mode, attachment) =
                ProgLink::attach(ifindex, prog, cfg.mode, cfg.force_netlink)?;
            Ok((
                Attached {
                    link,
                    sources: Some(sources),
                    counters: Some(counters),
                },
                mode,
                attachment,
            ))
        }

        pub(super) fn stats(&self) -> io::Result<XdpStats> {
            let c = self
                .counters
                .as_ref()
                .ok_or_else(|| io::Error::other("detached"))?;
            let sum =
                |k: i32| -> io::Result<u64> { Ok(c.lookup_percpu(&(k as u32))?.iter().sum()) };
            let new_sources = sum(ebpf::CTR_NEW)?;
            Ok(XdpStats {
                passed: sum(ebpf::CTR_PASSED)? + new_sources,
                dropped: sum(ebpf::CTR_DROPPED)?,
                new_sources,
            })
        }

        pub(super) fn forget(&self, key: [u8; 16]) -> io::Result<bool> {
            let m = self
                .sources
                .as_ref()
                .ok_or_else(|| io::Error::other("detached"))?;
            match m.delete(&key) {
                Ok(()) => Ok(true),
                Err(e) if e.raw_os_error() == Some(only_sys::ffi::ENOENT) => Ok(false),
                Err(e) => Err(e),
            }
        }

        pub(super) fn detach(self, ifindex: u32) -> io::Result<()> {
            self.link.detach(ifindex)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_parameters() {
        let mut c = XdpLimit::default();
        assert_eq!(c.bucket().unwrap(), (10_000_000, 2_000_000_000));
        c.rate = 1_000_000_000;
        c.burst = 1;
        assert_eq!(c.bucket().unwrap(), (1, 1));
        for bad in [
            XdpLimit {
                rate: 0,
                ..XdpLimit::default()
            },
            XdpLimit {
                burst: 0,
                ..XdpLimit::default()
            },
            XdpLimit {
                max_sources: MAX_SOURCES + 1,
                ..XdpLimit::default()
            },
        ] {
            assert_eq!(
                bad.bucket().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn setlink_message_layout() {
        let m = setlink_xdp(
            7,
            42,
            XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
            Some(9),
        );
        assert_eq!(m.len(), 16 + 16 + 4 + 24);
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), RTM_SETLINK);
        assert_eq!(u32::from_ne_bytes(m[20..24].try_into().unwrap()), 7);
        assert_eq!(u16::from_ne_bytes(m[32..34].try_into().unwrap()), 28);
        assert_eq!(
            u16::from_ne_bytes(m[34..36].try_into().unwrap()),
            43 | 0x8000
        );
        assert_eq!(i32::from_ne_bytes(m[40..44].try_into().unwrap()), 42);
        assert_eq!(u32::from_ne_bytes(m[48..52].try_into().unwrap()), 3);
        assert_eq!(i32::from_ne_bytes(m[56..60].try_into().unwrap()), 9);
    }

    #[test]
    fn acks() {
        let mut ack = vec![0u8; 36];
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert!(parse_ack(&ack).is_ok());
        ack[16..20].copy_from_slice(&(-16i32).to_ne_bytes());
        assert_eq!(parse_ack(&ack).unwrap_err().raw_os_error(), Some(16));
        assert!(parse_ack(&ack[..10]).is_err());
        ack[4] = 3;
        assert!(parse_ack(&ack).is_err());
    }

    #[test]
    fn source_keys_map_ipv4() {
        let k = source_key("10.1.2.3".parse().unwrap());
        assert_eq!(k, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3]);
        let k = source_key("2001:db8::1".parse().unwrap());
        assert_eq!(k[0..2], [0x20, 0x01]);
    }
}
