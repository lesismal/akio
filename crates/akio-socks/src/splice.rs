//! The kernel fast path of `CONNECT` tunnels ([`ProxyConfig::sockmap`](crate::ProxyConfig)):
//! once the upstream is connected, and before the client is told so, the two sockets are
//! spliced with the sockmap relay and the bytes stop passing through userspace.
//!
//! Splicing is refused (and the tunnel relays in userspace as before) when the client sent data
//! behind its request that userspace already holds, for TLS connections, and wherever the relay
//! is unavailable. Bytes waiting in the sockets' receive queues (a server that greets first) are
//! relayed by the kernel after the reply, in order. Should userspace still read payload from a
//! spliced tunnel while both ends are open (an io_uring read that completed before the splice
//! took over), the tunnel is closed rather than risk reordering. A spliced tunnel's progress is read from the sockets'
//! TCP counters: for the idle timeout, and on close, where the other side is only closed once
//! everything the closing side sent has reached its send queue (closing a socket drops what the
//! kernel's relay still holds for it).

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use akio::ebpf::{Relay, Tunnel, TunnelSide, inner_byte_counts};
use akio_core::ConnInner;

/// Tunnels spliced since the process started.
static SPLICED: AtomicU64 = AtomicU64::new(0);

/// Number of tunnels the sockmap fast path has spliced in this process (tests, metrics).
#[doc(hidden)]
pub fn spliced_tunnels() -> u64 {
    SPLICED.load(Ordering::Relaxed)
}

/// The fast path of one tunnel: akio-ebpf's [`Tunnel`] with the upstream as `a` and the
/// client as `b` (the success reply is written to the client first).
pub(crate) struct SpliceCtl {
    relay: Relay,
    /// The client sent bytes the userspace relay holds: never splice.
    early: AtomicBool,
    tunnel: OnceLock<Tunnel>,
}

impl SpliceCtl {
    pub(crate) fn new(relay: Option<&Relay>) -> Option<Arc<SpliceCtl>> {
        relay.map(|r| {
            Arc::new(SpliceCtl {
                relay: r.clone(),
                early: AtomicBool::new(false),
                tunnel: OnceLock::new(),
            })
        })
    }

    /// Userspace holds client bytes for the upstream (call with the upstream slot locked, so
    /// that the upstream's thread sees it before deciding).
    pub(crate) fn mark_early(&self) {
        self.early.store(true, Ordering::Release);
    }

    pub(crate) fn is_spliced(&self) -> bool {
        self.tunnel.get().is_some()
    }

    /// Splices `client` and `up` on the upstream's I/O thread, writing the success `reply`
    /// to the client directly once both are spliced and before any byte is relayed (the client
    /// is waiting for it with its reads held). Returns how much of `reply` was written: all of
    /// it when the tunnel is spliced; otherwise the caller sends the rest and relays in
    /// userspace.
    pub(crate) fn try_splice(
        &self,
        client: &Arc<ConnInner>,
        up: &Arc<ConnInner>,
        reply: &[u8],
    ) -> usize {
        if self.early.load(Ordering::Acquire) {
            return 0;
        }
        match self.relay.tunnel_inner(up, client, reply) {
            Ok(t) => {
                let _ = self.tunnel.set(t);
                SPLICED.fetch_add(1, Ordering::Relaxed);
                reply.len()
            }
            Err(e) => e.written,
        }
    }

    /// Bytes received on both sockets: changes while the tunnel moves data.
    pub(crate) fn activity(client: &ConnInner, up: &ConnInner) -> u64 {
        let rx = |c: &ConnInner| inner_byte_counts(c).map_or(0, |b| b.received);
        rx(client).wrapping_add(rx(up))
    }

    /// A side closed (`from_client`: it is the client): closes the other once everything the
    /// closed side received since splicing has been written to it, or when that stops
    /// progressing for `stall` ([`Tunnel::close_after_forward`]).
    pub(crate) fn close_after_forward(&self, from_client: bool, to: &ConnInner, stall: Duration) {
        match self.tunnel.get() {
            Some(t) => t.close_after_forward(
                if from_client {
                    TunnelSide::B
                } else {
                    TunnelSide::A
                },
                stall,
            ),
            None => to.close_after_send(),
        }
    }
}
