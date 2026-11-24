//! Requests run on the engine's logical pool instead of the connection's I/O thread: the
//! `run_on_pool` options of HTTP/1.1 ([`HttpConfig`](crate::HttpConfig)) and HTTP/2
//! ([`H2Config`](crate::H2Config)) (and HTTP/3's, through
//! [`dispatch_conn_on_pool`](crate::transport::dispatch_conn_on_pool)), and
//! [`Context::executor`] / [`Context::detach_to_pool`] for single requests.

use std::{cell::Cell, sync::Arc};

use akio_core::{ConnInner, Job};

use crate::{
    context::{Context, Detached, Service},
    message::Response,
    transport::SharedSink,
};

/// Runs work on the engine's logical pool on behalf of one connection; see
/// [`Context::executor`]. Cheap to clone, usable from any thread.
#[derive(Clone)]
pub struct Executor(Kind);

#[derive(Clone)]
enum Kind {
    /// HTTP/1.1 and HTTP/2: the TCP connection.
    Conn(Arc<ConnInner>),
    /// A transport outside this crate (HTTP/3): its connection sink.
    Ext(SharedSink),
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor").finish_non_exhaustive()
    }
}

impl Executor {
    pub(crate) fn conn(c: Arc<ConnInner>) -> Executor {
        Executor(Kind::Conn(c))
    }

    pub(crate) fn ext(s: SharedSink) -> Executor {
        Executor(Kind::Ext(s))
    }

    /// Runs `work` on the logical pool. `Err(Overloaded)` when the pool cannot take it (its
    /// queue is full, or the connection is gone); `work` is dropped unrun then.
    pub fn execute(&self, work: impl FnOnce() + Send + 'static) -> akio_core::Result<()> {
        self.try_execute(Box::new(work))
            .map_err(|_| akio_core::Error::Overloaded)
    }

    /// Runs `job` on the pool, or hands it back unrun.
    pub(crate) fn try_execute(&self, job: Job) -> Result<(), Job> {
        match &self.0 {
            Kind::Conn(c) => c.execute(job),
            Kind::Ext(s) => s.get().execute(job),
        }
    }
}

thread_local! {
    /// Set just before a job the pool refused is run here instead: the job answers `503`
    /// rather than doing its work. (A refused job comes back as an opaque `FnOnce`, so this
    /// is how it learns; it runs right away, on this thread, and clears the flag.)
    static REFUSED: Cell<bool> = const { Cell::new(false) };
}

/// Queues `job` on `exec`; when the pool refuses it, runs it here with [`REFUSED`] set.
fn queue(exec: &Executor, job: Job) -> bool {
    match exec.try_execute(job) {
        Ok(()) => true,
        Err(job) => {
            REFUSED.set(true);
            job();
            REFUSED.set(false);
            false
        }
    }
}

/// The answer to a request the pool had no room for.
fn busy() -> Response {
    let mut r = Response::text(503, "server busy");
    r.headers.set("retry-after", "1");
    r
}

/// Runs `service` for `ctx` on the pool: middleware and handler on a pool thread, then the
/// `500` for a handler that neither responded nor detached. Responses keep their order on
/// HTTP/1.1 (the context holds its reserved position). When the pool refuses, `503`.
pub(crate) fn call_on_pool<S: Service + ?Sized>(svc: Arc<S>, mut ctx: Context, exec: &Executor) {
    ctx.set_pooled();
    queue(
        exec,
        Box::new(move || {
            if REFUSED.get() {
                return ctx.respond(busy());
            }
            let g = crate::trace::begin(&mut ctx);
            svc.call(&mut ctx);
            drop(g);
            if !ctx.responded() && !ctx.is_detached() {
                ctx.respond(Response::text(500, "handler did not respond"));
            }
        }),
    );
}

/// Queues `work` with the suspended request `s` on `exec`; when the pool refuses it, answers
/// the request `503` ([`Context::suspend_to_pool`]).
pub(crate) fn queue_suspended(
    exec: &Executor,
    s: crate::context::Suspended,
    work: impl FnOnce(crate::context::Suspended) + Send + 'static,
) -> bool {
    queue(
        exec,
        Box::new(move || {
            if REFUSED.get() {
                return s.resume(|ctx| ctx.respond(busy()));
            }
            work(s);
        }),
    )
}

impl Context {
    /// Runs work on the engine's logical pool for this request's connection: detach, then
    /// answer from the pool (or see [`detach_to_pool`](Self::detach_to_pool), which does
    /// both). `None` once the response is sent or the context detached, so take it first.
    pub fn executor(&self) -> Option<Executor> {
        self.out_executor()
    }

    /// Detaches the request and runs `f` with it on the logical pool, for a handler that has
    /// slow work to do (a database, a file) while the rest of the connection's requests go on.
    /// On HTTP/1.1 the responses of pipelined requests still go out in request order, however
    /// the inline and pooled ones interleave. When the pool has no room the request is
    /// answered `503` and `false` returned (as it is, with nothing sent, when the response was
    /// already sent or the context detached).
    pub fn detach_to_pool(&mut self, f: impl FnOnce(Detached) + Send + 'static) -> bool {
        let Some(exec) = self.executor() else {
            return false;
        };
        let Some(d) = self.detach() else {
            return false;
        };
        queue(
            &exec,
            Box::new(move || {
                if REFUSED.get() {
                    return d.respond(busy());
                }
                f(d);
            }),
        )
    }
}
