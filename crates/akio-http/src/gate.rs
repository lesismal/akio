//! Asynchronous body filters (ADR-128): a response body passed through work done elsewhere (a
//! WebAssembly plugin's `proxy_on_response_body` on its pool), one call at a time, with what is
//! written meanwhile held, and the writer paced by what is held and by the client.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use crate::context::BodyStream;
use crate::message::Headers;

/// A response body filter whose work is done elsewhere ([`Context::add_body_filter`], ADR-128).
///
/// [`filter`](BodyFilter::filter) is given each part of the body, as written by the handler (and
/// by the body filters registered before this one), and answers through its [`FilterDone`], from
/// any thread, at once or later, with what goes out in its place. One call is made at a time:
/// what is written meanwhile is held and goes to the next call whole. The last call has
/// [`BodyChunk::end`] set and carries the body's trailer fields, which it may change (or add, to
/// a body that had none). Its output goes on to the next body filter, then to the stream coding a
/// response filter set ([`Response::set_stream_coding`](crate::Response::set_stream_coding)),
/// then to the client.
///
/// `filter` runs on the thread writing the body (an I/O thread for a response sent whole), so it
/// must not block: it hands the work on and returns.
///
/// [`Context::add_body_filter`]: crate::Context::add_body_filter
pub trait BodyFilter: Send + 'static {
    /// Filters `chunk`; `done` takes the output. Dropping `done` unanswered fails the response.
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone);

    /// The response ended before its last call was made: the client went, the response failed
    /// (a call failed, a write failed, or the held bytes went past their bound), or the handler
    /// dropped its stream unfinished. Called at most once, after any call under way has come
    /// back; never once the last call was made, even if it fails. The default does nothing.
    fn abort(&mut self) {}
}

/// A part of a response body, for a [`BodyFilter`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BodyChunk {
    /// The bytes written since the last call (possibly none, in the last call).
    pub data: Vec<u8>,
    /// The body ends with this call.
    pub end: bool,
    /// In the last call, the body's trailer fields (empty when it has none); empty otherwise.
    pub trailers: Headers,
}

/// Answers a [`BodyFilter::filter`] call, from any thread; see [`done`](FilterDone::done).
/// Dropped unanswered, it fails the response.
pub struct FilterDone {
    gate: Option<Arc<Gate>>,
}

impl std::fmt::Debug for FilterDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterDone").finish_non_exhaustive()
    }
}

impl FilterDone {
    /// Sends `data` in the call's place; at the last call, `trailers` follow the body (none when
    /// empty; ignored in the other calls). The output is paced by the client: the next call waits
    /// until what the connection holds of it is down to its watermark.
    pub fn done(mut self, data: Vec<u8>, trailers: Headers) {
        if let Some(g) = self.gate.take() {
            g.came_back(Ok((data, trailers)));
        }
    }

    /// Fails the response: its HTTP/1 connection is closed, its HTTP/2 or HTTP/3 stream reset
    /// (the head may have gone already).
    pub fn fail(mut self) {
        if let Some(g) = self.gate.take() {
            g.came_back(Err(()));
        }
    }
}

impl Drop for FilterDone {
    fn drop(&mut self) {
        if let Some(g) = self.gate.take() {
            g.came_back(Err(()));
        }
    }
}

/// Bytes written to a gate and not yet through it (held while its head is held or a call is
/// under way) past which its writes fail, as a client too far behind fails them.
pub(crate) const HELD_MAX: usize = 4 << 20;
/// Bytes the output stream may hold before the next call waits for it to drain.
const OUT_HIGH: usize = 256 << 10;

type Waiter = Box<dyn FnOnce() + Send>;

/// Where a streamed body goes through a [`BodyFilter`], or is held until its head goes: written
/// by the handler (or the gate before it), it hands its output to `out` once
/// [`open`](Gate::open)ed. One thread at a time works on `out`, taken out of the state, so the
/// state's lock is never held while calling out of the gate.
pub(crate) struct Gate(Mutex<GateState>);

#[derive(Default)]
struct GateState {
    /// Where the output goes: `None` until opened, and while a thread works on it.
    out: Option<BodyStream>,
    /// A thread took `out` to work on it (it puts it back, or drops it, then pumps).
    working: bool,
    /// A filter was given (`filter` is `None` while a call is made).
    has_filter: bool,
    filter: Option<Box<dyn BodyFilter>>,
    /// A call is out, not yet answered.
    busy: bool,
    /// Bytes handed to the call under way, for `queued_bytes`.
    in_call: usize,
    /// Written, not yet handed on.
    pending: Vec<u8>,
    /// The writer finished, with these trailers (empty: none).
    finish: Option<Headers>,
    /// The last call was made (or, without a filter, the output finished).
    last: bool,
    /// Done: the output finished, or failed.
    ended: bool,
    failed: bool,
    /// Waiting for the output to drain before going on.
    waiting: bool,
    /// Output the output refused (`Overloaded`, not taken: HTTP/3), sent again first once it
    /// drained, and the trailers to finish with after it.
    retry: Option<(Vec<u8>, Option<Headers>)>,
    /// The writer's [`BodyStream::on_drain`] waiter.
    drain: Option<Waiter>,
}

fn lock(g: &Gate) -> MutexGuard<'_, GateState> {
    g.0.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a pass of [`Gate::pump`] does once it let go of the lock.
enum Step {
    /// Call the filter with this.
    Call(Box<dyn BodyFilter>, BodyChunk),
    /// No filter: write this to the output (and finish it, with these trailers).
    Pass(BodyStream, Vec<u8>, Option<Headers>),
    /// Drop the output unfinished (the response is cut), abort the filter, wake the writer.
    Cut(
        Option<BodyStream>,
        Option<Box<dyn BodyFilter>>,
        Option<Waiter>,
    ),
    /// Wait for the output to drain, then wake the writer.
    Wait(BodyStream),
    /// Wake the writer.
    Wake(Waiter),
}

impl Gate {
    pub(crate) fn new(filter: Option<Box<dyn BodyFilter>>) -> Arc<Gate> {
        Arc::new(Gate(Mutex::new(GateState {
            has_filter: filter.is_some(),
            filter,
            ..GateState::default()
        })))
    }

    /// A gate open from the start, writing to `out`.
    pub(crate) fn opened(filter: Box<dyn BodyFilter>, out: BodyStream) -> Arc<Gate> {
        let g = Gate::new(Some(filter));
        lock(&g).out = Some(out);
        g
    }

    /// The head went: output goes to `out` from now on.
    pub(crate) fn open(self: &Arc<Self>, out: BodyStream) {
        {
            let mut st = lock(self);
            if st.failed {
                drop(st);
                out.cut();
                return self.pump();
            }
            st.out = Some(out);
        }
        self.pump();
    }

    /// Gives back the output a thread took (`None`: it cut it); the caller goes on with a pass.
    fn release(&self, out: Option<BodyStream>) {
        let mut st = lock(self);
        st.working = false;
        if out.is_none() {
            st.failed = true;
        }
        st.out = out;
    }

    /// Writes `data` (copied); `Err` once the gate failed, or when what it holds would go past
    /// [`HELD_MAX`] (which fails it).
    pub(crate) fn write(self: &Arc<Self>, data: &[u8]) -> akio_core::Result<()> {
        {
            let mut st = lock(self);
            if st.failed || st.finish.is_some() {
                return Err(gone());
            }
            if data.is_empty() {
                return Ok(());
            }
            if st.pending.len() + st.in_call + data.len() > HELD_MAX {
                st.failed = true;
                drop(st);
                self.pump();
                return Err(akio_core::Error::Overloaded);
            }
            st.pending.extend_from_slice(data);
        }
        self.pump();
        Ok(())
    }

    /// A whole body, written and finished at once, with no bound: it is in memory already.
    pub(crate) fn preload(self: &Arc<Self>, body: Vec<u8>, trailers: Headers) {
        {
            let mut st = lock(self);
            st.pending = body;
            st.finish = Some(trailers);
        }
        self.pump();
    }

    /// The writer finished, with `trailers` (empty: none).
    pub(crate) fn finish(self: &Arc<Self>, trailers: Headers) {
        {
            let mut st = lock(self);
            if st.failed || st.finish.is_some() {
                return;
            }
            st.finish = Some(trailers);
        }
        self.pump();
    }

    /// Fails the gate: the response is cut.
    pub(crate) fn fail(self: &Arc<Self>) {
        {
            let mut st = lock(self);
            if st.ended {
                return;
            }
            st.failed = true;
        }
        self.pump();
    }

    /// The gate failed: the response is cut.
    pub(crate) fn failed(&self) -> bool {
        lock(self).failed
    }

    /// Bytes written and not yet sent: held here, in the call under way, and in the output.
    pub(crate) fn queued_bytes(&self) -> usize {
        let st = lock(self);
        st.pending.len()
            + st.in_call
            + st.retry.as_ref().map_or(0, |r| r.0.len())
            + st.out.as_ref().map_or(0, BodyStream::queued_bytes)
    }

    /// Calls `f` once nothing written is held here or in the output, or the gate failed.
    pub(crate) fn on_drain(self: &Arc<Self>, f: Waiter) {
        {
            let mut st = lock(self);
            if !st.ended {
                st.drain = Some(f);
                drop(st);
                return self.pump();
            }
        }
        f();
    }

    /// A call came back.
    fn came_back(self: &Arc<Self>, r: Result<(Vec<u8>, Headers), ()>) {
        let (out, last) = {
            let mut st = lock(self);
            st.busy = false;
            st.in_call = 0;
            match r {
                Err(()) => {
                    st.failed = true;
                    (None, false)
                }
                // A gate cut meanwhile drops what comes back.
                Ok(_) if st.failed => (None, false),
                Ok(_) => {
                    let out = st.out.take();
                    st.working = out.is_some();
                    (out, st.last)
                }
            }
        };
        let Some(out) = out else {
            return self.pump();
        };
        let Ok((data, trailers)) = r else {
            return self.pump();
        };
        if self.emit(out, data, last.then_some(trailers)) {
            self.pump();
        }
    }

    /// Writes `data` to the output this thread took, then finishes it with `fin`'s trailers
    /// (none when empty), or puts it back. A write the output refuses for now (HTTP/3's
    /// `Overloaded`: not taken) is made again once it drained; any other failure cuts.
    ///
    /// `true` when a pass should follow (the output given back, or cut).
    fn emit(self: &Arc<Self>, out: BodyStream, data: Vec<u8>, fin: Option<Headers>) -> bool {
        if !data.is_empty() {
            match out.write(&data) {
                Ok(()) => {}
                Err(akio_core::Error::Overloaded) => {
                    {
                        let mut st = lock(self);
                        st.retry = Some((data, fin));
                        st.waiting = true;
                    }
                    self.wait(out, false);
                    return true;
                }
                Err(_) => {
                    out.cut();
                    self.release(None);
                    return true;
                }
            }
        }
        if let Some(t) = fin {
            if t.is_empty() {
                out.finish();
            } else {
                out.finish_with_trailers(t);
            }
            self.ended();
            return false;
        }
        self.put_back(out);
        true
    }

    /// The output finished: wakes the writer.
    fn ended(&self) {
        let w = {
            let mut st = lock(self);
            st.ended = true;
            st.working = false;
            st.drain.take()
        };
        if let Some(w) = w {
            w();
        }
    }

    /// Puts the output back, waiting first for it to drain when it holds too much.
    fn put_back(self: &Arc<Self>, out: BodyStream) {
        if out.queued_bytes() > OUT_HIGH {
            lock(self).waiting = true;
            return self.wait(out, false);
        }
        self.release(Some(out));
    }

    /// Waits for `out` to drain (`waiting` set), then goes on.
    ///
    /// `wake`: the writer's waiter runs when the output drained, as the output's transport
    /// means it (HTTP/3: room for more, which may be at once with bytes still queued; checking
    /// `queued_bytes` again would wait forever).
    fn wait(self: &Arc<Self>, out: BodyStream, wake: bool) {
        let w: Weak<Gate> = Arc::downgrade(self);
        // May run at once, on this thread: it takes the lock, which is not held here, and the
        // pass it starts stops at once (the output is this thread's until released).
        out.on_drain(move || {
            if let Some(g) = w.upgrade() {
                let waiter = {
                    let mut st = lock(&g);
                    st.waiting = false;
                    if wake { st.drain.take() } else { None }
                };
                if let Some(f) = waiter {
                    f();
                }
                g.pump();
            }
        });
        self.release(Some(out));
    }

    /// Hands on what is held, as far as it can now.
    fn pump(self: &Arc<Self>) {
        loop {
            let step = {
                let mut st = lock(self);
                if st.ended {
                    return;
                }
                if st.failed {
                    if st.busy || st.working {
                        // A call is out, or a thread works on the output: cut when it is back.
                        return;
                    }
                    st.ended = true;
                    st.pending = Vec::new();
                    st.retry = None;
                    // A filter whose last call was made is not aborted.
                    let f = if st.last { None } else { st.filter.take() };
                    Step::Cut(st.out.take(), f, st.drain.take())
                } else if st.out.is_none() || st.working || st.waiting {
                    // Not opened yet, the output is another thread's, or it is draining.
                    return;
                } else if let Some((data, fin)) = st.retry.take() {
                    let Some(out) = st.out.take() else { return };
                    st.working = true;
                    Step::Pass(out, data, fin)
                } else if st.busy {
                    // A call is out.
                    return;
                } else if !st.pending.is_empty() || st.finish.is_some() {
                    let data = std::mem::take(&mut st.pending);
                    let fin = st.finish.take();
                    if st.has_filter {
                        let Some(f) = st.filter.take() else { return };
                        st.busy = true;
                        st.in_call = data.len();
                        st.last = fin.is_some();
                        Step::Call(
                            f,
                            BodyChunk {
                                data,
                                end: fin.is_some(),
                                trailers: fin.unwrap_or_default(),
                            },
                        )
                    } else {
                        let Some(out) = st.out.take() else { return };
                        st.working = true;
                        Step::Pass(out, data, fin)
                    }
                } else if st.drain.is_some() {
                    // Idle: the writer's waiter runs once the output drained too.
                    if st.out.as_ref().map_or(0, BodyStream::queued_bytes) == 0 {
                        match st.drain.take() {
                            Some(w) => Step::Wake(w),
                            None => return,
                        }
                    } else {
                        let Some(out) = st.out.take() else { return };
                        st.waiting = true;
                        st.working = true;
                        Step::Wait(out)
                    }
                } else {
                    return;
                }
            };
            match step {
                Step::Call(mut f, chunk) => {
                    f.filter(
                        chunk,
                        FilterDone {
                            gate: Some(self.clone()),
                        },
                    );
                    let mut st = lock(self);
                    if st.failed && st.ended {
                        // Cut while the filter was out of the state: told now, unless this was
                        // its last call.
                        let last = st.last;
                        drop(st);
                        if !last {
                            f.abort();
                        }
                        return;
                    }
                    if st.ended {
                        // The last call came back already: the filter is done with.
                        return;
                    }
                    st.filter = Some(f);
                }
                Step::Pass(out, data, fin) => {
                    if !self.emit(out, data, fin) {
                        return;
                    }
                }
                Step::Cut(out, f, w) => {
                    if let Some(out) = out {
                        out.cut();
                    }
                    if let Some(mut f) = f {
                        f.abort();
                    }
                    if let Some(w) = w {
                        w();
                    }
                    return;
                }
                Step::Wait(out) => self.wait(out, true),
                Step::Wake(w) => {
                    w();
                    return;
                }
            }
        }
    }
}

fn gone() -> akio_core::Error {
    akio_core::Error::Closed
}

/// The writer's side of a gate, in a [`BodyStream`]: dropped unfinished, it cuts the response.
pub(crate) struct GateHandle(pub(crate) Option<Arc<Gate>>);

impl GateHandle {
    pub(crate) fn gate(&self) -> Option<&Arc<Gate>> {
        self.0.as_ref()
    }

    pub(crate) fn finish(mut self, trailers: Headers) {
        if let Some(g) = self.0.take() {
            g.finish(trailers);
        }
    }
}

impl Drop for GateHandle {
    fn drop(&mut self) {
        if let Some(g) = self.0.take() {
            g.fail();
        }
    }
}
