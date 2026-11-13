use std::{marker::PhantomData, net::SocketAddr, sync::Arc};

use crate::{Handler, Result};

/// Type-erased shared connection state (send queue + lock, state bits, owner loop). Built in M1.
pub(crate) struct ConnInner {}

/// A cloneable, thread-safe handle to a connection (ADR-002).
///
/// `Conn<H>` is `Send + Sync + Clone` for **any** `H` (the type parameter only types the
/// completion callbacks of [`Conn::spawn_blocking`]). Using a handle after the connection closed
/// returns [`Error::Closed`](crate::Error::Closed); it never panics or touches a recycled fd.
pub struct Conn<H> {
    #[allow(dead_code)]
    inner: Arc<ConnInner>,
    // `fn() -> H` keeps the handle Send + Sync regardless of H.
    _h: PhantomData<fn() -> H>,
}

impl<H> Clone for Conn<H> {
    fn clone(&self) -> Self {
        Conn {
            inner: self.inner.clone(),
            _h: PhantomData,
        }
    }
}

impl<H: Handler> Conn<H> {
    /// Copies `data` into the send queue (or writes it directly when the queue is empty).
    pub fn send(&self, _data: &[u8]) -> Result<()> {
        unimplemented!("M1")
    }

    /// Like [`send`](Self::send) but takes ownership, avoiding a copy.
    pub fn send_owned(&self, _data: Vec<u8>) -> Result<()> {
        unimplemented!("M1")
    }

    /// Starts coalescing writes until [`flush`](Self::flush) (or the end of the callback).
    pub fn cork(&self) {
        unimplemented!("M1")
    }

    /// Flushes corked output.
    pub fn flush(&self) -> Result<()> {
        unimplemented!("M1")
    }

    /// Closes the connection now.
    pub fn close(&self) {
        unimplemented!("M1")
    }

    /// Closes after everything queued has been sent.
    pub fn close_after_send(&self) {
        unimplemented!("M1")
    }

    /// Pauses (`true`) or resumes (`false`) reading from the peer.
    pub fn hold_reads(&self, _hold: bool) {
        unimplemented!("M1")
    }

    /// Local address.
    pub fn local_addr(&self) -> SocketAddr {
        unimplemented!("M1")
    }

    /// Peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        unimplemented!("M1")
    }

    /// Runs `work` on the logical pool, then runs `done` **on this connection's owning I/O
    /// thread** with exclusive access to the handler. If the connection closed meanwhile, `done`
    /// is skipped. Returns [`Error::Overloaded`](crate::Error::Overloaded) when the pool is full.
    pub fn spawn_blocking<R, W, D>(&self, _work: W, _done: D) -> Result<()>
    where
        R: Send + 'static,
        W: FnOnce() -> R + Send + 'static,
        D: FnOnce(&mut H, &Conn<H>, R) + Send + 'static,
    {
        unimplemented!("M2")
    }
}
