//! Requests run on the engine's logical pool instead of the connection's I/O thread: the
//! `handlers_on_logical_pool` options of HTTP/1.1 ([`HttpConfig`](crate::HttpConfig)) and HTTP/2
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

    /// Runs `job` on the pool as the next step of work admitted before (the next message of an
    /// open call, the next piece of a response under way): ahead of new work, and not refused
    /// for a full queue (`Pool::resume`). Hands `job` back, unrun, only when the pool is shut
    /// down or the connection is gone. Keep one such step queued or running at a time.
    pub fn resume(&self, job: Job) -> Result<(), Job> {
        match &self.0 {
            Kind::Conn(c) => c.resume(job),
            Kind::Ext(s) => s.get().resume(job),
        }
    }

    /// Runs `job` on the pool, or hands it back unrun.
    pub(crate) fn try_execute(&self, job: Job) -> Result<(), Job> {
        match &self.0 {
            Kind::Conn(c) => c.execute(job),
            Kind::Ext(s) => s.get().execute(job),
        }
    }

    /// Runs the jobs of `jobs` on the pool, all queued at once where the transport allows;
    /// what the pool refuses is left in `jobs`, in order.
    fn try_execute_batch(&self, jobs: &mut Vec<Job>) {
        match &self.0 {
            Kind::Conn(c) => c.execute_batch(jobs),
            Kind::Ext(_) => {
                let mut refused = Vec::new();
                for job in jobs.drain(..) {
                    if let Err(job) = self.try_execute(job) {
                        refused.push(job);
                    }
                }
                *jobs = refused;
            }
        }
    }

    fn same(&self, other: &Executor) -> bool {
        match (&self.0, &other.0) {
            (Kind::Conn(a), Kind::Conn(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

thread_local! {
    /// Set just before a job the pool refused is run here instead: the job answers `503`
    /// rather than doing its work. (A refused job comes back as an opaque `FnOnce`, so this
    /// is how it learns; it runs right away, on this thread, and clears the flag.)
    static REFUSED: Cell<bool> = const { Cell::new(false) };
    /// Set while a pool job runs the service of a request dispatched to the pool
    /// (`handlers_on_logical_pool`): an HTTP/2 response sent meanwhile goes back to the I/O
    /// thread to be written with the others of its connection (`h2::Deferred`); work the
    /// handler posts to the pool itself (`detach_to_pool`, `executor`) answers on its own.
    static DEFERRING: Cell<bool> = const { Cell::new(false) };
}

thread_local! {
    /// The pooled requests of the read an I/O thread is handling ([`Gather`]): handed to the
    /// pool together when it is done.
    static GATHERED: std::cell::RefCell<Option<(Executor, Vec<Job>)>> =
        const { std::cell::RefCell::new(None) };
    /// A [`Gather`] is open on this thread.
    static GATHERING: Cell<bool> = const { Cell::new(false) };
    /// The emptied vector of the last [`Gather`], for the next one.
    static SPARE_JOBS: Cell<Vec<Job>> = const { Cell::new(Vec::new()) };
}

/// While it lives, the requests an HTTP/2 read dispatches to the pool are collected, then queued
/// at once when it drops: one lock on the pool's queue and the wake-ups they need, instead of
/// one each (`Pool::try_execute_batch`). A request the pool refuses is answered `503` then.
pub(crate) struct Gather(bool);

impl Gather {
    /// Starts collecting if `on` (the connection runs its requests on the pool) and nothing
    /// collects already.
    pub(crate) fn begin(on: bool) -> Gather {
        let on = on && !GATHERING.get();
        if on {
            GATHERING.set(true);
        }
        Gather(on)
    }
}

impl Drop for Gather {
    fn drop(&mut self) {
        if !self.0 {
            return;
        }
        GATHERING.set(false);
        let Some((exec, mut jobs)) = GATHERED.take() else {
            return;
        };
        exec.try_execute_batch(&mut jobs);
        for job in jobs.drain(..) {
            REFUSED.set(true);
            job();
            REFUSED.set(false);
        }
        SPARE_JOBS.set(jobs);
    }
}

/// Queues `job` on `exec`, into the open [`Gather`] if there is one for this connection.
fn queue_gathered(exec: &Executor, job: Job) {
    if GATHERING.get() {
        let job = GATHERED.with_borrow_mut(|g| match g {
            Some((e, jobs)) if e.same(exec) => {
                jobs.push(job);
                None
            }
            Some(_) => Some(job),
            None => {
                let mut jobs = SPARE_JOBS.take();
                jobs.push(job);
                *g = Some((exec.clone(), jobs));
                None
            }
        });
        let Some(job) = job else { return };
        queue(exec, job);
        return;
    }
    queue(exec, job);
}

/// Whether this thread is running a pooled request's service (see [`DEFERRING`]).
pub(crate) fn deferring() -> bool {
    DEFERRING.get()
}

/// Clears [`DEFERRING`] when the service returns or panics.
struct Deferring;

impl Deferring {
    fn on() -> Deferring {
        DEFERRING.set(true);
        Deferring
    }
}

impl Drop for Deferring {
    fn drop(&mut self) {
        DEFERRING.set(false);
    }
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
    queue_gathered(
        exec,
        Box::new(move || {
            if REFUSED.get() {
                return ctx.respond(busy());
            }
            let on = Deferring::on();
            let g = crate::trace::begin(&mut ctx);
            svc.call(&mut ctx);
            drop(g);
            if !ctx.responded() && !ctx.is_detached() {
                ctx.respond(Response::text(500, "handler did not respond"));
            }
            drop(on);
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
