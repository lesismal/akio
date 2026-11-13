use crate::{Conn, Error};

/// Per-connection state *and* event callbacks (ADR-003).
///
/// One `Handler` value is created per connection by an [`Acceptor`] and is only ever touched on the
/// connection's owning I/O thread, so it must be `Send` (it moves there once) but need **not** be
/// `Sync`. Callbacks run inline on the I/O thread and **must not block**; offload blocking work
/// with [`Conn::spawn_blocking`].
pub trait Handler: Send + Sized + 'static {
    /// Bytes arrived. `data` is only valid for the duration of the call.
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]);

    /// The peer hung up while a callback of this connection was still running (optional).
    fn on_hangup(&mut self, _c: &Conn<Self>) {}

    /// The connection closed; called exactly once, after every earlier `on_data`.
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<Error>) {}
}

/// Creates a [`Handler`] for each accepted connection. Shared by all I/O threads, hence `Sync`.
pub trait Acceptor: Send + Sync + 'static {
    /// The per-connection handler type.
    type Handler: Handler;

    /// A connection was accepted; return its handler.
    fn on_open(&self, c: &Conn<Self::Handler>) -> Self::Handler;

    /// The engine is shutting down: end the connection when convenient (optional).
    fn on_shutdown(&self, _c: &Conn<Self::Handler>) {}
}

/// An [`Acceptor`] built from a closure; see [`fn_acceptor`].
///
/// A blanket `impl Acceptor for F: Fn(&Conn<H>) -> H` is rejected by coherence (`H` would be
/// unconstrained), so closures go through this wrapper.
pub struct FnAcceptor<H, F> {
    f: F,
    _h: std::marker::PhantomData<fn() -> H>,
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
