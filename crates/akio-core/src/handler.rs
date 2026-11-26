use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;

use crate::{
    Conn, ConnHandle, ConnInner, Error, Task, Transport,
    conn::{Completion, LoopFn, TransportPoll, TransportWaker},
};

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

    /// UDP (internal, outside the stability promise): the receive batch that delivered one or
    /// more `on_data` calls to this connection is over; what is sent from here leaves with the
    /// batch's other replies. Called once per batch, after its last `on_data`, by the UDP loops
    /// of the epoll backend (which also serves io_uring and kqueue UDP); other backends never
    /// call it, so a handler must not wait for it before it has seen one.
    #[doc(hidden)]
    fn on_batch_end(&mut self, _c: &Conn<Self>) {}

    /// UDP (internal, outside the stability promise): the handler wants datagrams as owned,
    /// writable receive-slab ranges ([`on_data_owned`](Self::on_data_owned)) rather than
    /// borrowed slices, so it can keep or decrypt them in place without a copy (ADR-024).
    #[doc(hidden)]
    const OWNED_DATA: bool = false;

    /// UDP (internal, outside the stability promise): one datagram, owned. Called instead of
    /// `on_data` by the UDP loops of the epoll backend (which also serves io_uring and kqueue
    /// UDP) when [`OWNED_DATA`](Self::OWNED_DATA) is set and no transport layer is installed;
    /// everywhere else datagrams keep arriving through `on_data`. The default passes the bytes
    /// to `on_data`.
    #[doc(hidden)]
    fn on_data_owned(&mut self, c: &Conn<Self>, data: akio_buf::slab::ChunkMut) {
        self.on_data(c, &data);
    }
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
/// handler types (protocol multiplexers such as `akio-mux` are built on it). Serve it with
/// `akio::Listener::serve_any`.
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
    /// The receive batch that called `on_data` is over ([`Handler::on_batch_end`]).
    fn on_batch_end(&mut self) {}
    /// Datagrams should go to [`on_data_owned`](Self::on_data_owned) ([`Handler::OWNED_DATA`]).
    /// Asked once, when the connection opens.
    fn wants_owned(&self) -> bool {
        false
    }
    /// One datagram, owned ([`Handler::on_data_owned`]).
    fn on_data_owned(&mut self, data: akio_buf::slab::ChunkMut) {
        self.on_data(&data);
    }
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
        // With the read direction in the kernel (kernel TLS) the bytes are already decoded.
        if !self.secured || self.conn.inner.kernel_rx() {
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
    fn on_batch_end(&mut self) {
        self.h.on_batch_end(&self.conn);
    }
    fn wants_owned(&self) -> bool {
        H::OWNED_DATA && !self.secured
    }
    fn on_data_owned(&mut self, data: akio_buf::slab::ChunkMut) {
        if self.secured {
            return self.on_data(&data);
        }
        self.h.on_data_owned(&self.conn, data);
    }
    fn run_task(&mut self, task: Task) {
        if task.is::<TransportPoll>() {
            // The transport finished waiting (TransportWaker): poll it as if bytes arrived.
            if self.secured && !self.conn.inner.kernel_rx() {
                self.on_data(&[]);
            }
            return;
        }
        let task = match task.downcast::<LoopFn>() {
            Ok(f) => return (f.0)(),
            Err(task) => task,
        };
        if let Ok(f) = task.downcast::<Completion<H>>() {
            (*f)(&mut self.h, &self.conn);
        }
    }
}

impl<A: Acceptor> DynAcceptor for A {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        let conn = Conn::<A::Handler>::new(inner.clone());
        let secured = match Acceptor::transport(self) {
            Some(mut t) => {
                t.set_waker(TransportWaker::new(inner));
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

/// A hook on every connection of a listener ([`hooked`]): told with a [`ConnHandle`].
#[doc(hidden)]
pub type ConnHook = Arc<dyn Fn(&ConnHandle) + Send + Sync>;

/// Wraps `acceptor` so that `on_accept` is told of each connection it opens, before its
/// `on_open`, and `on_close` of each one that closes, after its handler's `on_close` (akit
/// A232, ADR-180). Backend-facing: `akio`'s `Listener::on_accept` and `on_close`.
#[doc(hidden)]
pub fn hooked(
    acceptor: Arc<dyn DynAcceptor>,
    on_accept: Option<ConnHook>,
    on_close: Option<ConnHook>,
) -> Arc<dyn DynAcceptor> {
    if on_accept.is_none() && on_close.is_none() {
        return acceptor;
    }
    Arc::new(Hooked {
        acceptor,
        on_accept,
        on_close,
    })
}

struct Hooked {
    acceptor: Arc<dyn DynAcceptor>,
    on_accept: Option<ConnHook>,
    on_close: Option<ConnHook>,
}

impl Hooked {
    /// Tells `on_close` of a connection that will not get a handler (a hook or `on_open`
    /// panicked), closing it first.
    fn refused(&self, conn: &ConnHandle) {
        conn.close();
        if let Some(f) = &self.on_close {
            let _ = catch_unwind(AssertUnwindSafe(|| f(conn)));
        }
    }
}

impl DynAcceptor for Hooked {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        let conn = ConnHandle::from_inner(inner.clone());
        if let Some(f) = &self.on_accept {
            if let Err(p) = catch_unwind(AssertUnwindSafe(|| f(&conn))) {
                self.refused(&conn);
                resume_unwind(p);
            }
        }
        let h = match catch_unwind(AssertUnwindSafe(|| self.acceptor.on_open(inner))) {
            Ok(h) => h,
            Err(p) => {
                self.refused(&conn);
                resume_unwind(p);
            }
        };
        match &self.on_close {
            None => h,
            Some(f) => Box::new(HookedHandler {
                h,
                conn,
                on_close: f.clone(),
                told: false,
            }),
        }
    }
    fn on_shutdown(&self, inner: &Arc<ConnInner>) {
        self.acceptor.on_shutdown(inner);
    }
}

/// A connection's handler with the listener's `on_close` hook after its own. A handler
/// dropped without `on_close` (a backend that could not register the connection) tells the
/// hook when it is dropped.
struct HookedHandler {
    h: Box<dyn DynHandler>,
    conn: ConnHandle,
    on_close: ConnHook,
    told: bool,
}

impl Drop for HookedHandler {
    fn drop(&mut self) {
        if !self.told {
            self.told = true;
            self.conn.close();
            let _ = catch_unwind(AssertUnwindSafe(|| (self.on_close)(&self.conn)));
        }
    }
}

impl DynHandler for HookedHandler {
    fn on_data(&mut self, data: &[u8]) {
        self.h.on_data(data);
    }
    fn on_close(&mut self, err: Option<Error>) {
        // The hook runs even if the handler's `on_close` panics, so an application's table
        // of connections never keeps one that closed.
        let r = catch_unwind(AssertUnwindSafe(|| self.h.on_close(err)));
        self.told = true;
        (self.on_close)(&self.conn);
        if let Err(p) = r {
            resume_unwind(p);
        }
    }
    fn run_task(&mut self, task: Task) {
        self.h.run_task(task);
    }
    fn on_batch_end(&mut self) {
        self.h.on_batch_end();
    }
    fn wants_owned(&self) -> bool {
        self.h.wants_owned()
    }
    fn on_data_owned(&mut self, data: akio_buf::slab::ChunkMut) {
        self.h.on_data_owned(data);
    }
}
