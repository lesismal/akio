//! In-kernel relay of two TCP sockets with a sockmap (`SOCKHASH` + `sk_skb` stream verdict).
//!
//! Once two sockets are spliced, every byte received on one is redirected by the kernel to the
//! send path of the other, without waking userspace. This is what a proxy (SOCKS, `CONNECT`,
//! a TCP load balancer) does after its handshake. Needs `CAP_BPF`/`CAP_NET_ADMIN` (or
//! `CAP_SYS_ADMIN`) and, by default, Linux 6.15+ (see [`MIN_KERNEL`]); everywhere else
//! [`Relay::new`] fails and the caller keeps relaying in userspace.
//!
//! # Ordering contract
//!
//! The kernel takes over the byte streams from the moment of [`Relay::splice`], including bytes
//! already waiting in the sockets' receive queues. Bytes userspace already read but has not yet
//! written to the other side would be overtaken by the kernel's newer bytes, so splice only when
//! nothing is in flight in userspace: typically right after the proxy handshake, with no data
//! queued on either connection ([`Relay::splice_conns`] checks the queues). A last message of
//! the handshake (the SOCKS success reply) can be written from
//! [`Relay::splice_inner_with`]'s callback: it runs when both sockets are in the map but before
//! anything is relayed, so it reaches the client ahead of the first relayed byte. After
//! splicing, userspace must not read payload from the sockets (`akio`'s loop sees no more data
//! on them, only EOF and errors) and should only watch for close: closing either socket removes
//! it from the map.
//!
//! While the two sockets are inserted (one at a time) their `SO_RCVLOWAT` is raised so that
//! arriving data waits in the receive queue instead of reaching the verdict program before both
//! are in the map (where it would be passed to a psock queue that only userspace reads); it is
//! then set back to 1, which runs the verdict over whatever arrived meanwhile, in order.
//!
//! The kernel's redirect backlog is not bounded by `akio`'s write watermarks.

use std::{io, sync::Arc};

use akio_core::{Conn, ConnInner};

/// Oldest kernel [`Relay::new`] accepts. Earlier kernels can drop or misorder relayed bytes
/// when the destination socket's send buffer is full and the psock backlog retries after
/// `EAGAIN` (reproduced on 6.12 with 4 MiB transfers; fixed upstream by "bpf, sockmap: Fix
/// data lost during EAGAIN retries").
pub const MIN_KERNEL: (u32, u32) = (6, 15);

/// Capacity of a [`Relay`] in spliced pairs, when not given.
pub const DEFAULT_PAIRS: u32 = 16 << 10;

/// A loaded relay: one `SOCKHASH` map with the verdict program attached. Cheap to share
/// (`Clone`); typically one per engine.
#[derive(Clone)]
pub struct Relay {
    #[cfg(target_os = "linux")]
    inner: Arc<imp::RelayInner>,
    #[cfg(not(target_os = "linux"))]
    _inner: Arc<()>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Relay(..)")
    }
}

/// A spliced pair. Dropping it leaves the splice in place (it ends when either socket closes);
/// call [`Splice::unsplice`] to hand the streams back to userspace.
#[derive(Debug)]
pub struct Splice {
    relay: Relay,
    cookies: [u64; 2],
}

impl Relay {
    /// Loads the relay with room for `pairs` spliced pairs (0 = [`DEFAULT_PAIRS`]). Fails with
    /// `PermissionDenied` without the needed capabilities, `Unsupported` off Linux or on
    /// kernels older than [`MIN_KERNEL`], or the kernel's error (with the verifier's message)
    /// on kernels lacking the features.
    pub fn new(pairs: u32) -> io::Result<Relay> {
        #[cfg(target_os = "linux")]
        if let Some(v) = imp::kernel_version() {
            if v < MIN_KERNEL {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "kernel {}.{} may lose relayed data when the destination's send buffer \
                         fills (sockmap EAGAIN bug, fixed in {}.{}); see Relay::new_any_kernel",
                        v.0, v.1, MIN_KERNEL.0, MIN_KERNEL.1
                    ),
                ));
            }
        }
        Self::new_any_kernel(pairs)
    }

    /// [`Relay::new`] without the kernel version check, for kernels that carry the fix as a
    /// backport, or for workloads that never fill a send buffer.
    pub fn new_any_kernel(pairs: u32) -> io::Result<Relay> {
        let pairs = if pairs == 0 { DEFAULT_PAIRS } else { pairs };
        #[cfg(target_os = "linux")]
        return Ok(Relay {
            inner: Arc::new(imp::RelayInner::new(pairs.saturating_mul(2))?),
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pairs;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "sockmap relay is Linux-only",
            ))
        }
    }

    /// Splices the connected TCP sockets `a` and `b` (raw fds): data received on `a` is sent on
    /// `b` and vice versa, in the kernel. See the module's ordering contract.
    pub fn splice(&self, a: i32, b: i32) -> io::Result<Splice> {
        self.splice_fds(a, b, &mut || Ok(()))
    }

    fn splice_fds(
        &self,
        a: i32,
        b: i32,
        before_relaying: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Splice> {
        #[cfg(target_os = "linux")]
        {
            let cookies = self.inner.splice(a, b, before_relaying)?;
            Ok(Splice {
                relay: self.clone(),
                cookies,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (a, b, before_relaying);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "sockmap relay is Linux-only",
            ))
        }
    }

    /// Splices two `akio` connections. Refuses (`WouldBlock`) while either has bytes queued for
    /// sending, and (`Unsupported`) for UDP connections or ones with a transport layer such as
    /// TLS, whose bytes on the wire are not the payload. Call it on an I/O thread of one of the
    /// connections, after forwarding whatever data that callback received; on error just keep
    /// relaying in userspace.
    pub fn splice_conns<A, B>(&self, a: &Conn<A>, b: &Conn<B>) -> io::Result<Splice> {
        self.splice_inner(a.inner(), b.inner())
    }

    /// [`splice_conns`](Self::splice_conns) for the connections' shared state (what a handler
    /// of one side keeps of the other).
    pub fn splice_inner(&self, a: &ConnInner, b: &ConnInner) -> io::Result<Splice> {
        self.splice_inner_with(a, b, || Ok(()))
    }

    /// [`splice_inner`](Self::splice_inner) that runs `before_relaying` once both sockets are
    /// spliced but before the kernel relays any byte: what it writes directly to a socket (not
    /// through the engine's queue) goes out ahead of every relayed byte. If it fails, the splice
    /// is undone without losing data and its error returned.
    pub fn splice_inner_with(
        &self,
        a: &ConnInner,
        b: &ConnInner,
        before_relaying: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Splice> {
        use std::os::fd::AsRawFd;
        let (Some(sa), Some(sb)) = (a.tcp_stream(), b.tcp_stream()) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only TCP connections can be spliced",
            ));
        };
        if a.has_transport() || b.has_transport() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "connections with a transport layer (TLS) cannot be spliced",
            ));
        }
        if !a.is_open() || !b.is_open() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }
        if a.queued_bytes() > 0 || b.queued_bytes() > 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "data still queued in userspace",
            ));
        }
        let mut f = Some(before_relaying);
        self.splice_fds(sa.as_raw_fd(), sb.as_raw_fd(), &mut || {
            f.take().map_or(Ok(()), |f| f())
        })
    }
}

/// Byte counters of a TCP socket ([`byte_counts`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ByteCounts {
    /// Payload bytes received in order (`tcpi_bytes_received`).
    pub received: u64,
    /// Payload bytes written to the socket: acknowledged by the peer (`tcpi_bytes_acked`) plus
    /// still in its send queue (`SIOCOUTQ`).
    pub written: u64,
}

/// The counters of `s` (Linux 4.1+; `Unsupported` elsewhere). Spliced sockets never hand their
/// data to userspace, so this is how a proxy sees a spliced tunnel's progress: whether it is
/// idle, and when everything one side received has reached the other side's send queue (the
/// kernel's relay backlog is invisible otherwise, and closing a socket drops what is still in
/// it).
pub fn byte_counts(s: &std::net::TcpStream) -> io::Result<ByteCounts> {
    #[cfg(target_os = "linux")]
    {
        let fd = std::os::fd::AsRawFd::as_raw_fd(s);
        let (received, acked) = crate::sys::tcp_bytes(fd)?;
        Ok(ByteCounts {
            received,
            written: acked + crate::sys::unsent_bytes(fd)? as u64,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = s;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_INFO is read on Linux only",
        ))
    }
}

impl Splice {
    /// The socket cookies (`SO_COOKIE`) of the two sockets.
    pub fn cookies(&self) -> [u64; 2] {
        self.cookies
    }

    /// Ends the splice: later data goes to userspace again. The sockets stay in the map (with
    /// no peer) until they close, which is harmless.
    pub fn unsplice(self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        return self.relay.inner.unsplice(self.cookies);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &self.relay;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        io,
        os::fd::{AsRawFd, OwnedFd},
    };

    use crate::{ebpf, sys};

    /// `(major, minor)` of the running kernel.
    pub(crate) fn kernel_version() -> Option<(u32, u32)> {
        let r = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
        let mut it = r.trim().split(|c: char| !c.is_ascii_digit());
        Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
    }

    pub(super) struct RelayInner {
        /// Socket cookie -> socket fd.
        map: sys::Map<u64, u32>,
        _prog: OwnedFd,
    }

    impl RelayInner {
        pub(super) fn new(entries: u32) -> io::Result<RelayInner> {
            // Key: a socket cookie; value: the socket to redirect that socket's data to.
            let map = sys::Map::<u64, u32>::create(sys::MAP_SOCKHASH, entries)?;
            let prog = sys::prog_load(
                sys::PROG_SK_SKB,
                0,
                &ebpf::relay_verdict(map.fd()),
                "akio_relay",
            )?;
            sys::prog_attach(
                map.fd(),
                prog.as_raw_fd(),
                sys::ATTACH_SK_SKB_STREAM_VERDICT,
            )?;
            Ok(RelayInner { map, _prog: prog })
        }

        pub(super) fn splice(
            &self,
            a: i32,
            b: i32,
            before_relaying: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<[u64; 2]> {
            let ca = sys::socket_cookie(a)?;
            let cb = sys::socket_cookie(b)?;
            // Gate both sockets: data arriving from now on waits in the receive queue (no
            // data_ready wake-up below the low-water mark, so no verdict run).
            let gate = |v: i32| -> io::Result<()> {
                sys::set_rcvlowat(a, v)?;
                sys::set_rcvlowat(b, v)
            };
            let ungate = || gate(1);
            if let Err(e) = gate(i32::MAX) {
                let _ = ungate();
                return Err(e);
            }
            let m = &self.map;
            // Inserting a socket as a value gives it the verdict program; the gate keeps it
            // from running until both entries exist.
            let inserted = m.update(&ca, &(b as u32)).and_then(|()| {
                m.update(&cb, &(a as u32)).inspect_err(|_| {
                    let _ = m.delete(&ca);
                })
            });
            if let Err(e) = inserted {
                let _ = ungate();
                return Err(e);
            }
            // Nothing was relayed yet: undoing loses nothing.
            if let Err(e) = before_relaying().and_then(|()| ungate()) {
                let _ = self.unsplice([ca, cb]);
                let _ = ungate();
                return Err(e);
            }
            Ok([ca, cb])
        }

        pub(super) fn unsplice(&self, cookies: [u64; 2]) -> io::Result<()> {
            let r1 = self.map.delete(&cookies[0]);
            let r2 = self.map.delete(&cookies[1]);
            // ENOENT: already removed because a socket closed.
            for r in [r1, r2] {
                match r {
                    Err(e) if e.raw_os_error() != Some(akio_sys::ffi::ENOENT) => return Err(e),
                    _ => {}
                }
            }
            Ok(())
        }
    }
}
