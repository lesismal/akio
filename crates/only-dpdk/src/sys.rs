//! Linux TAP and AF_PACKET devices: opening them (`/dev/net/tun` + `TUNSETIFF`, an
//! `AF_PACKET` raw socket bound to an interface) and non-blocking frame I/O on their file
//! descriptor. Thin calls through the workspace's own C library bindings (`only_sys::ffi`); together with `pmd` the only `unsafe` of the crate
//! (docs/unsafe-review.md).
#![allow(unsafe_code)]

use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};

use only_sys::ffi;

const TUNSETIFF: ffi::c_ulong = 0x4004_54ca;
const IFF_TAP: ffi::c_short = 0x0002;
const IFF_NO_PI: ffi::c_short = 0x1000;
const ETH_P_ALL: u16 = 0x0003;
const PACKET_OUTGOING: u8 = 4;

/// `struct ifreq` with the `ifr_flags` member of its union (40 bytes on Linux).
#[repr(C)]
struct IfReqFlags {
    name: [ffi::c_char; ffi::IFNAMSIZ],
    flags: ffi::c_short,
    _pad: [u8; 22],
}

fn name_bytes(name: &str) -> io::Result<[ffi::c_char; ffi::IFNAMSIZ]> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= ffi::IFNAMSIZ || b.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {name:?}"),
        ));
    }
    let mut out = [0 as ffi::c_char; ffi::IFNAMSIZ];
    for (o, &c) in out.iter_mut().zip(b) {
        *o = c as ffi::c_char;
    }
    Ok(out)
}

fn cvt(rc: ffi::c_int) -> io::Result<ffi::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// A TAP or AF_PACKET file descriptor (non-blocking).
#[derive(Debug)]
pub(crate) struct LinkFd {
    fd: OwnedFd,
    /// AF_PACKET: skip frames the local host sent (`PACKET_OUTGOING`).
    packet: bool,
}

impl LinkFd {
    /// Opens (creating if needed) TAP interface `name` (needs `CAP_NET_ADMIN`).
    pub(crate) fn tap(name: &str) -> io::Result<LinkFd> {
        let mut req = IfReqFlags {
            name: name_bytes(name)?,
            flags: IFF_TAP | IFF_NO_PI,
            _pad: [0; 22],
        };
        let path = c"/dev/net/tun";
        // SAFETY: `path` is a valid NUL-terminated string; the flags are plain integers.
        let raw = cvt(unsafe {
            ffi::open(
                path.as_ptr(),
                ffi::O_RDWR | ffi::O_NONBLOCK | ffi::O_CLOEXEC,
            )
        })?;
        // SAFETY: `raw` is a freshly opened descriptor owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: TUNSETIFF reads and writes a `struct ifreq`; `req` has its layout and size
        // and lives across the call.
        cvt(unsafe { ffi::ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut req) })?;
        Ok(LinkFd { fd, packet: false })
    }

    /// An `AF_PACKET` socket on existing interface `name` (needs `CAP_NET_RAW`).
    pub(crate) fn af_packet(name: &str) -> io::Result<LinkFd> {
        let cname =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `cname` is a valid NUL-terminated string.
        let index = unsafe { ffi::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let proto = ETH_P_ALL.to_be();
        // SAFETY: plain integer arguments.
        let raw = cvt(unsafe {
            ffi::socket(
                ffi::AF_PACKET,
                ffi::SOCK_RAW | ffi::SOCK_NONBLOCK | ffi::SOCK_CLOEXEC,
                ffi::c_int::from(proto),
            )
        })?;
        // SAFETY: `raw` is a freshly created socket owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `sockaddr_ll` is plain old data; all-zero is a valid value.
        let mut sll: ffi::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = ffi::AF_PACKET as u16;
        sll.sll_protocol = proto;
        sll.sll_ifindex = index as ffi::c_int;
        // SAFETY: `sll` is a valid `sockaddr_ll` and the length passed is its size.
        cvt(unsafe {
            ffi::bind(
                fd.as_raw_fd(),
                (&raw const sll).cast::<ffi::sockaddr>(),
                size_of::<ffi::sockaddr_ll>() as ffi::socklen_t,
            )
        })?;
        // A deep receive buffer: a burst from many kernel flows must not overflow it while the
        // loop is busy (SO_RCVBUFFORCE needs CAP_NET_ADMIN; SO_RCVBUF is capped by rmem_max).
        let size: ffi::c_int = 8 << 20;
        for opt in [ffi::SO_RCVBUFFORCE, ffi::SO_RCVBUF] {
            // SAFETY: `size` is a valid `c_int` option value of the length passed.
            let rc = unsafe {
                ffi::setsockopt(
                    fd.as_raw_fd(),
                    ffi::SOL_SOCKET,
                    opt,
                    (&raw const size).cast(),
                    size_of::<ffi::c_int>() as ffi::socklen_t,
                )
            };
            if rc == 0 {
                break;
            }
        }
        Ok(LinkFd { fd, packet: true })
    }

    /// Reads one frame into `buf` (resized to fit). `None` when nothing is pending.
    pub(crate) fn recv(&self, buf: &mut Vec<u8>) -> Option<()> {
        // Large enough for GSO/GRO aggregates the kernel hands to packet sockets on a veth.
        const MAX: usize = 65536 + 64;
        buf.resize(MAX, 0);
        loop {
            let n = if self.packet {
                // SAFETY: `sockaddr_ll` is plain old data; all-zero is a valid value.
                let mut from: ffi::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut len = size_of::<ffi::sockaddr_ll>() as ffi::socklen_t;
                // SAFETY: `buf` has `MAX` writable bytes; `from` / `len` are a valid address
                // buffer and its length.
                let n = unsafe {
                    ffi::recvfrom(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        MAX,
                        ffi::MSG_TRUNC,
                        (&raw mut from).cast::<ffi::sockaddr>(),
                        &raw mut len,
                    )
                };
                if n >= 0 && from.sll_pkttype == PACKET_OUTGOING {
                    continue;
                }
                n
            } else {
                // SAFETY: `buf` has `MAX` writable bytes.
                unsafe { ffi::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), MAX) }
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                buf.clear();
                return None;
            }
            let n = n as usize;
            if n > MAX {
                continue; // truncated: larger than any frame we accept
            }
            buf.truncate(n);
            return Some(());
        }
    }

    /// Writes one frame; a frame the device cannot take now is dropped (like a full ring).
    pub(crate) fn send(&self, frame: &[u8]) {
        loop {
            // SAFETY: `frame` is a valid readable buffer of its length.
            let n = unsafe { ffi::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
    }

    /// Waits until a frame may be readable, at most `timeout`.
    pub(crate) fn wait(&self, timeout: Duration) {
        let mut p = ffi::pollfd {
            fd: self.fd.as_raw_fd(),
            events: ffi::POLLIN,
            revents: 0,
        };
        let t = timeout.min(Duration::from_secs(1));
        let ts = ffi::timespec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: ffi::c_long::from(t.subsec_nanos() as i32),
        };
        // SAFETY: `p` is one valid `pollfd`, `ts` a valid timespec; no signal mask is passed.
        let _ = unsafe { ffi::ppoll(&raw mut p, 1, &raw const ts, std::ptr::null()) };
    }
}
