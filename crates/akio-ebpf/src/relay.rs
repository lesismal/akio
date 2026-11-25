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
//! the handshake (the SOCKS success reply, a PROXY header for the upstream, a ClientHello read
//! to pick the upstream) is passed as `first` to [`Relay::splice_conns_with`] (or
//! [`Relay::tunnel`]): it is written to the second socket once both sockets are in the map but
//! before anything is relayed, so it goes out ahead of the first relayed byte. After
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
//!
//! # Counters
//!
//! A spliced socket's bytes never reach userspace, so a proxy follows a splice by the sockets'
//! TCP counters ([`ByteCounts`], [`byte_counts`], [`conn_byte_counts`]). [`Splice::base`] holds
//! both sockets' counters as the kernel began relaying: what the kernel relays from a socket is
//! everything it receives past `received - unread` of its base. [`Tunnel`](crate::Tunnel) does
//! that arithmetic for the usual needs (an idle timeout, closing a side once the other's data
//! reached it).

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
    base: Option<[ByteCounts; 2]>,
}

/// Why [`Relay::splice_conns_with`] (or [`Relay::tunnel`]) did not splice: the error, and how
/// much of `first` had been written to the second socket already. The splice is undone and
/// nothing was relayed: the caller sends `first[written..]` through the engine and relays in
/// userspace.
#[derive(Debug)]
#[non_exhaustive]
pub struct SpliceError {
    /// What failed: `Unsupported` (UDP, a transport layer such as TLS, not Linux, ...),
    /// `NotConnected` (a side closed), `WouldBlock` (bytes queued in userspace, or the second
    /// socket's send buffer could not take all of `first`), or the kernel's error.
    pub error: io::Error,
    /// Bytes of `first` written to the second socket before the failure.
    pub written: usize,
}

impl SpliceError {
    fn new(error: io::Error) -> SpliceError {
        SpliceError { error, written: 0 }
    }

    /// The error's kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }
}

impl std::fmt::Display for SpliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({} bytes of first written)",
            self.error, self.written
        )
    }
}

impl std::error::Error for SpliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<SpliceError> for io::Error {
    fn from(e: SpliceError) -> io::Error {
        e.error
    }
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
    ///
    /// [`Splice::base`] holds the sockets' counters when they can be read (TCP sockets).
    pub fn splice(&self, a: i32, b: i32) -> io::Result<Splice> {
        self.splice_fds(a, b, false, &mut || Ok(()))
    }

    /// `counts`: the base counters must be read (TCP sockets), else the splice fails.
    fn splice_fds(
        &self,
        a: i32,
        b: i32,
        counts: bool,
        before_relaying: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Splice> {
        #[cfg(target_os = "linux")]
        {
            let (cookies, base) = self.inner.splice(a, b, counts, before_relaying)?;
            Ok(Splice {
                relay: self.clone(),
                cookies,
                base,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (a, b, counts, before_relaying);
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
    /// relaying in userspace. [`Splice::base`] holds both sockets' counters.
    pub fn splice_conns<A, B>(&self, a: &Conn<A>, b: &Conn<B>) -> io::Result<Splice> {
        self.splice_inner(a.inner(), b.inner())
    }

    /// [`splice_conns`](Self::splice_conns) that first writes `first` to `b`'s socket: once
    /// both sockets are in the map and before the kernel relays any byte, so `first` reaches
    /// `b`'s peer ahead of every relayed byte (a proxy's reply to its client, a PROXY header or
    /// a ClientHello read to pick the upstream for the upstream). `first` is written directly
    /// to the non-blocking socket, not through the engine's queue: a send buffer that cannot
    /// take all of it fails the splice (`WouldBlock`), which is then undone without relaying
    /// anything, and [`SpliceError::written`] says how much of `first` went out.
    ///
    /// [`Splice::base`] holds both sockets' counters as the kernel began relaying, `first`
    /// counted in `b`'s `written`. Call it as [`splice_conns`](Self::splice_conns): with both
    /// connections' reads held or nothing in flight in userspace, and nothing queued for
    /// sending.
    pub fn splice_conns_with<A, B>(
        &self,
        a: &Conn<A>,
        b: &Conn<B>,
        first: &[u8],
    ) -> Result<Splice, SpliceError> {
        self.splice_inner_first(a.inner(), b.inner(), first)
    }

    /// [`splice_conns_with`](Self::splice_conns_with) for the connections' shared state.
    pub fn splice_inner_first(
        &self,
        a: &ConnInner,
        b: &ConnInner,
        first: &[u8],
    ) -> Result<Splice, SpliceError> {
        let Some(sb) = b.tcp_stream() else {
            return Err(SpliceError::new(not_tcp()));
        };
        let mut written = 0;
        let r = self.splice_checked(a, b, &mut || {
            use std::io::Write;
            while written < first.len() {
                match (&*sb).write(first.get(written..).unwrap_or_default()) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => written += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        });
        r.map_err(|error| SpliceError { error, written })
    }

    /// Splices two `akio` connections as a [`Tunnel`](crate::Tunnel), `first` written to `b`
    /// ahead of the relayed bytes: [`splice_conns_with`](Self::splice_conns_with), plus what a
    /// proxy needs to run the spliced pair (its idle probe, closing one side once the other's
    /// data reached it).
    pub fn tunnel<A, B>(
        &self,
        a: &Conn<A>,
        b: &Conn<B>,
        first: &[u8],
    ) -> Result<crate::Tunnel, SpliceError> {
        self.tunnel_inner(a.inner(), b.inner(), first)
    }

    /// [`tunnel`](Self::tunnel) for the connections' shared state.
    pub fn tunnel_inner(
        &self,
        a: &Arc<ConnInner>,
        b: &Arc<ConnInner>,
        first: &[u8],
    ) -> Result<crate::Tunnel, SpliceError> {
        let s = self.splice_inner_first(a, b, first)?;
        Ok(crate::Tunnel::new(s, a, b))
    }

    /// [`splice_conns`](Self::splice_conns) for the connections' shared state (what a handler
    /// of one side keeps of the other).
    pub fn splice_inner(&self, a: &ConnInner, b: &ConnInner) -> io::Result<Splice> {
        self.splice_inner_with(a, b, || Ok(()))
    }

    /// [`splice_inner`](Self::splice_inner) that runs `before_relaying` once both sockets are
    /// spliced but before the kernel relays any byte: what it writes directly to a socket (not
    /// through the engine's queue) goes out ahead of every relayed byte. If it fails, the splice
    /// is undone without losing data and its error returned. [`splice_conns_with`]
    /// (Self::splice_conns_with) does this for bytes to write first.
    pub fn splice_inner_with(
        &self,
        a: &ConnInner,
        b: &ConnInner,
        before_relaying: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Splice> {
        let mut f = Some(before_relaying);
        self.splice_checked(a, b, &mut || f.take().map_or(Ok(()), |f| f()))
    }

    fn splice_checked(
        &self,
        a: &ConnInner,
        b: &ConnInner,
        before_relaying: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Splice> {
        use std::os::fd::AsRawFd;
        let (Some(sa), Some(sb)) = (a.tcp_stream(), b.tcp_stream()) else {
            return Err(not_tcp());
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
        self.splice_fds(sa.as_raw_fd(), sb.as_raw_fd(), true, before_relaying)
    }
}

fn not_tcp() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "only TCP connections can be spliced",
    )
}

/// Byte counters of a TCP socket ([`byte_counts`], [`conn_byte_counts`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ByteCounts {
    /// Payload bytes received in order (`tcpi_bytes_received`).
    pub received: u64,
    /// Payload bytes written to the socket: acknowledged by the peer (`tcpi_bytes_acked`) plus
    /// still in its send queue (`SIOCOUTQ`).
    pub written: u64,
    /// Bytes received but not read from the socket yet: its receive queue (`SIOCINQ`, the same
    /// as `FIONREAD`). On a socket not spliced, `received - unread` ([`consumed`]
    /// (Self::consumed)) is what userspace read from it, by `akio` and the layers above (a PROXY
    /// header, a ClientHello). Not meaningful on a spliced socket: the relay drains its receive
    /// queue, and some kernels report the psock's queue there instead; [`Splice::base`] has it
    /// as the splice began.
    pub unread: u64,
}

impl ByteCounts {
    /// `received - unread`: bytes taken from the socket. In a [`Splice::base`], what was read
    /// before the kernel began relaying: the kernel relays everything the socket receives
    /// past it.
    pub fn consumed(&self) -> u64 {
        self.received.saturating_sub(self.unread)
    }
}

/// The counters of `s` (Linux 4.1+; `Unsupported` elsewhere). Spliced sockets never hand their
/// data to userspace, so this is how a proxy sees a spliced tunnel's progress: whether it is
/// idle, and when everything one side received has reached the other side's send queue (the
/// kernel's relay backlog is invisible otherwise, and closing a socket drops what is still in
/// it).
///
/// The counters come from three calls (`TCP_INFO`, `SIOCINQ`, `SIOCOUTQ`), read again until
/// `TCP_INFO` is the same before and after the two `ioctl`s (a few tries at most), so that they
/// describe one moment unless the socket keeps moving bytes meanwhile. Never blocks.
pub fn byte_counts(s: &std::net::TcpStream) -> io::Result<ByteCounts> {
    #[cfg(target_os = "linux")]
    {
        imp::counts(std::os::fd::AsRawFd::as_raw_fd(s))
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

/// [`byte_counts`] of an `akio` connection's socket: the bytes on the wire, so for a connection
/// with a transport layer (TLS) the records, not the payload. `Unsupported` for UDP
/// connections and off Linux. Never blocks: it may be called on any thread, an I/O thread
/// included.
pub fn conn_byte_counts<H>(c: &Conn<H>) -> io::Result<ByteCounts> {
    inner_byte_counts(c.inner())
}

/// [`conn_byte_counts`] for a connection's shared state.
pub fn inner_byte_counts(c: &ConnInner) -> io::Result<ByteCounts> {
    match c.tcp_stream() {
        Some(s) => byte_counts(s),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a TCP connection",
        )),
    }
}

impl Splice {
    /// The socket cookies (`SO_COOKIE`) of the two sockets.
    pub fn cookies(&self) -> [u64; 2] {
        self.cookies
    }

    /// The counters of the two sockets (`[a, b]`) as the kernel began relaying: read once both
    /// were in the map, after `first` was written ([`Relay::splice_conns_with`]) and before any
    /// byte was relayed. The kernel relays to `b` everything `a` receives past
    /// `base[0].consumed()`, and the other way round, so `b`'s `written` counter reaches
    /// `base[1].written + received(a) - base[0].consumed()` once all of it is in `b`'s send
    /// queue. Always `Some` for a splice of two connections; for [`Relay::splice`] of raw fds,
    /// `None` when they are not TCP sockets.
    pub fn base(&self) -> Option<[ByteCounts; 2]> {
        self.base
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

    use super::ByteCounts;
    use crate::{ebpf, sys};

    /// [`counts`] of `fd`: its error when `required`, else `None` on error (not a TCP socket).
    fn counts_or(fd: i32, required: bool) -> io::Result<Option<ByteCounts>> {
        match counts(fd) {
            Ok(c) => Ok(Some(c)),
            Err(e) if required => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// The counters of `fd`, read again while `TCP_INFO` moves under the two `ioctl`s.
    pub(super) fn counts(fd: i32) -> io::Result<ByteCounts> {
        let mut tries = 0;
        loop {
            let (received, acked) = sys::tcp_bytes(fd)?;
            let unread = sys::unread_bytes(fd)? as u64;
            let unsent = sys::unsent_bytes(fd)? as u64;
            tries += 1;
            // Stable: one moment. Else, after a few tries, these: `unread` read after
            // `received` (what was read is under-counted) and `unsent` after `acked` (what was
            // written is under-counted), never over.
            if tries >= 8 || sys::tcp_bytes(fd)? == (received, acked) {
                return Ok(ByteCounts {
                    received,
                    written: acked.saturating_add(unsent),
                    unread,
                });
            }
        }
    }

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
            counts: bool,
            before_relaying: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<([u64; 2], Option<[ByteCounts; 2]>)> {
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
            // What userspace took from each socket: fixed from here on (the gate keeps the
            // sockets from being readable, and nothing reads them but the verdict once ungated).
            // Read before the sockets enter the map, where `SIOCINQ` may report the psock's
            // queue instead of the socket's (`tcp_bpf_ioctl`).
            let consumed = match (counts_or(a, counts), counts_or(b, counts)) {
                (Ok(x), Ok(y)) => x.zip(y).map(|(x, y)| [x.consumed(), y.consumed()]),
                (Err(e), _) | (_, Err(e)) => {
                    let _ = ungate();
                    return Err(e);
                }
            };
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
            // Nothing was relayed yet: undoing loses nothing. The base counters are read while
            // the gate holds the verdict back, after what `before_relaying` wrote; `unread` is
            // what arrived past what userspace took.
            let mut base = None;
            let r = before_relaying().and_then(|()| {
                let Some(consumed) = consumed else {
                    return ungate();
                };
                let mut now = [counts_or(a, counts)?, counts_or(b, counts)?];
                if let [Some(x), Some(y)] = &mut now {
                    x.unread = x.received.saturating_sub(consumed[0]);
                    y.unread = y.received.saturating_sub(consumed[1]);
                    base = Some([*x, *y]);
                }
                ungate()
            });
            if let Err(e) = r {
                let _ = self.unsplice([ca, cb]);
                let _ = ungate();
                return Err(e);
            }
            Ok(([ca, cb], base))
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

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn counters_and_relay_are_unsupported_off_linux() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let s = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert_eq!(
            byte_counts(&s).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            Relay::new(1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(ByteCounts::default().consumed(), 0);
    }
}
