//! Taking a connection over as a plain byte stream after an HTTP request (`CONNECT` tunnels,
//! custom upgrades).

use std::{net::SocketAddr, sync::Arc};

use flash_core::{ConnInner, Result};

/// A connection handed over by [`Context::upgrade_raw`](crate::Context::upgrade_raw). Cheap to
/// clone and usable from any thread.
#[derive(Clone)]
pub struct RawConn(pub(crate) Arc<ConnInner>);

impl RawConn {
    /// Sends bytes.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.0.send(data)
    }

    /// Sends bytes without copying.
    pub fn send_owned(&self, data: Vec<u8>) -> Result<()> {
        self.0.send_owned(data)
    }

    /// Closes now, dropping unsent data.
    pub fn close(&self) {
        self.0.close()
    }

    /// Closes once everything queued is written.
    pub fn close_after_send(&self) {
        self.0.close_after_send()
    }

    /// Pauses or resumes reading.
    pub fn hold_reads(&self, hold: bool) {
        self.0.hold_reads(hold)
    }

    /// Calls `f` once the send queue is empty (or the connection closed).
    pub fn on_drain(&self, f: impl FnOnce() + Send + 'static) {
        self.0.on_drain(Box::new(f))
    }

    /// Bytes queued but not yet written.
    pub fn queued_bytes(&self) -> usize {
        self.0.queued_bytes()
    }

    /// Whether the connection is open.
    pub fn is_open(&self) -> bool {
        self.0.is_open()
    }

    /// The peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.0.peer_addr()
    }

    /// The underlying connection state, for crates that relay between connections.
    #[doc(hidden)]
    pub fn inner(&self) -> &Arc<ConnInner> {
        &self.0
    }
}

/// Callbacks of an upgraded raw connection. They run on its I/O thread and must not block.
pub trait RawHandler: Send + 'static {
    /// The connection is now raw; nothing has been sent for the request yet.
    fn on_open(&mut self, _conn: &RawConn) {}
    /// Bytes arrived.
    fn on_data(&mut self, conn: &RawConn, data: &[u8]);
    /// The connection closed.
    fn on_close(&mut self) {}
}
