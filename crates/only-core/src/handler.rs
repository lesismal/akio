use std::sync::Arc;

use crate::{Conn, ConnInner, Error, Task, Transport, conn::Completion};

/// Per-connection state *and* event callbacks (ADR-003).
///
/// One `Handler` value is created per connection by an [`Acceptor`] and is only ever touched on the
/// connection's owning I/O thread, so it must be `Send` (it moves there once) but need **not** be
/// `Sync`. Callbacks run inline on the I/O thread and **must not block**; offload blocking work
/// with [`Conn::spawn_blocking`].
///
/// Everything sent from inside a callback is coalesced and written when the callback returns.
/// A panic in a callback closes that connection (and is reported to `on_close`).
pub trait Handler: Send + Sized + 'static {
    /// Bytes arrived. `data` is only valid for the duration of the call.
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]);

    /// The connection closed; called exactly once, after every earlier `on_data`. `err` is `None`
    /// for an orderly close (peer EOF after pending output drained, or a local close).
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<Error>) {}
}

/// Creates a [`Handler`] for each accepted or dialed connection. Shared by all I/O threads.
pub trait Acceptor: Send + Sync + 'static {
    /// The per-connection handler type.
    type Handler: Handler;

    /// A connection was established; return its handler. Runs on the owning I/O thread.
    fn on_open(&self, c: &Conn<Self::Handler>) -> Self::Handler;

    /// The engine is shutting down: end the connection when convenient (optional).
    fn on_shutdown(&self, _c: &Conn<Self::Handler>) {}

    /// A [`Transport`] to layer under each connection of this acceptor (TLS, for example), created
    /// before `on_open`. The default is none: plain TCP.
    fn transport(&self) -> Option<Box<dyn Transport>> {
        None
    }
}

/// An [`Acceptor`] built from a closure; see [`fn_acceptor`].
///
/// A blanket `impl Acceptor for F: Fn(&Conn<H>) -> H` is rejected by coherence (`H` would be
/// unconstrained), so closures go through this wrapper.
pub struct FnAcceptor<H, F> {
    f: F,
    _h: std::marker::PhantomData<fn() -> H>,
}

impl<H, F> std::fmt::Debug for FnAcceptor<H, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnAcceptor").finish_non_exhaustive()
    }
}

/// Wraps `f` as an [`Acceptor`].
pub fn fn_acceptor<H, F>(f: F) -> FnAcceptor<H, F>
where
    H: Handler,
    F: Fn(&Conn<H>) -> H + Send + Sync + 'static,
{
    FnAcceptor {
        f,
        _h: std::marker::PhantomData,
    }
}

impl<H, F> Acceptor for FnAcceptor<H, F>
where
    H: Handler,
    F: Fn(&Conn<H>) -> H + Send + Sync + 'static,
{
    type Handler = H;
    fn on_open(&self, c: &Conn<H>) -> H {
        (self.f)(c)
    }
}

/// A type-erased [`Acceptor`]: lets one listener hand connections to acceptors of different
/// handler types (protocol multiplexers such as `only-mux` are built on it). Serve it with
/// `only::Listener::serve_any`.
#[derive(Clone)]
pub struct AnyAcceptor(Arc<dyn DynAcceptor>);

impl AnyAcceptor {
    /// Erases the handler type of `acceptor`.
    pub fn new<A: Acceptor>(acceptor: A) -> AnyAcceptor {
        AnyAcceptor(Arc::new(acceptor))
    }

    /// Wraps a backend-level acceptor. Backend-facing.
    #[doc(hidden)]
    pub fn from_dyn(acceptor: Arc<dyn DynAcceptor>) -> AnyAcceptor {
        AnyAcceptor(acceptor)
    }

    /// The backend-level acceptor. Backend-facing.
    #[doc(hidden)]
    pub fn into_dyn(self) -> Arc<dyn DynAcceptor> {
        self.0
    }
}

impl std::fmt::Debug for AnyAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyAcceptor").finish_non_exhaustive()
    }
}

/// Type-erased handler stored by a backend's loop. `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait DynHandler: Send {
    fn on_data(&mut self, data: &[u8]);
    fn on_close(&mut self, err: Option<Error>);
    /// Runs a `spawn_blocking` completion posted by [`Conn::spawn_blocking`].
    fn run_task(&mut self, task: Task);
}

/// Type-erased acceptor. `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub trait DynAcceptor: Send + Sync {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler>;
    fn on_shutdown(&self, inner: &Arc<ConnInner>);
}

struct HandlerBox<H: Handler> {
    h: H,
    // Created once at open: callbacks borrow it, so no Arc clone per callback.
    conn: Conn<H>,
    /// A transport layer is installed: bytes read must be decoded before `on_data`.
    secured: bool,
    plain: Vec<u8>,
}

impl<H: Handler> DynHandler for HandlerBox<H> {
    fn on_data(&mut self, data: &[u8]) {
        if !self.secured {
            return self.h.on_data(&self.conn, data);
        }
        let mut plain = std::mem::take(&mut self.plain);
        plain.clear();
        match self.conn.inner.transport_recv(data, &mut plain) {
            Ok(()) => {
                if !plain.is_empty() {
                    self.h.on_data(&self.conn, &plain);
                }
            }
            // Whatever the transport produced (an alert) is flushed, then the connection ends.
            Err(_) => {
                self.conn.inner.note_transport_error();
                self.conn.close_after_send();
            }
        }
        self.plain = plain;
    }
    fn on_close(&mut self, err: Option<Error>) {
        self.h.on_close(&self.conn, err);
    }
    fn run_task(&mut self, task: Task) {
        if let Ok(f) = task.downcast::<Completion<H>>() {
            (*f)(&mut self.h, &self.conn);
        }
    }
}

impl<A: Acceptor> DynAcceptor for A {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        let conn = Conn::<A::Handler>::new(inner.clone());
        let secured = match Acceptor::transport(self) {
            Some(t) => {
                inner.set_transport(t);
                // Lets a client transport send its opening records right away.
                let _ = inner.transport_recv(&[], &mut Vec::new());
                true
            }
            None => false,
        };
        let h = Acceptor::on_open(self, &conn);
        Box::new(HandlerBox {
            h,
            conn,
            secured,
            plain: Vec::new(),
        })
    }
    fn on_shutdown(&self, inner: &Arc<ConnInner>) {
        Acceptor::on_shutdown(self, &Conn::<A::Handler>::new(inner.clone()));
    }
}
