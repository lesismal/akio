#![forbid(unsafe_code)]
//! arpc on `only`: two-way calls, notifies, asynchronous calls, streams and broadcast on the wire
//! format of [lesismal/arpc](https://github.com/lesismal/arpc) and fib's `arpc` package, so a
//! peer of either talks to one of these.
//!
//! Every connection is a [`Peer`] on both ends: it calls the other side and serves the other
//! side's calls with the [`Routes`] it was given. Payloads are bytes (Go peers send `string` and
//! `[]byte` as they are, and other values JSON-encoded by default).
//!
//! Handlers run inline on the connection's I/O thread and must not block; [`Context::detach`]
//! answers later from any thread.
//!
//! ```no_run
//! # use std::sync::Arc; use only::{Engine, EngineRef, Listener}; use only_arpc::{Routes, Server};
//! let routes = Routes::new().handle("/echo", |ctx| {
//!     let body = ctx.body().to_vec();
//!     ctx.write(&body);
//! });
//! let server = Server::new(Arc::new(routes));
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("127.0.0.1:8888".parse().unwrap()).serve(server.clone()))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Guide: [arpc](https://lesismal.github.io/only/en/protocols/arpc.html)
//! (中文: [arpc](https://lesismal.github.io/only/zh-CN/protocols/arpc.html)).
#![warn(clippy::unwrap_used)]

mod deadline;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod proto;

use std::{
    collections::HashMap,
    future::Future,
    hash::{BuildHasherDefault, Hasher},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, Engine, EngineRef, Handler};
use only_buf::SharedBuf;
use only_core::ConnInner;

use crate::{
    deadline::Timer,
    proto::{Cmd, Decoder, Message, encode},
};

/// Error text of a call to a method the peer does not serve (the same as Go's).
pub const METHOD_NOT_FOUND: &str = "method not found";

/// Default most streams the peer may have open on one connection
/// ([`Routes::max_streams_per_conn`]).
pub const DEFAULT_MAX_STREAMS_PER_CONN: usize = 1024;

/// Default timeout of calls made without one ([`Routes::call_timeout`]).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The hash of the route tables: they are built once and peers only look names up in them
/// (they cannot insert), so a fast unkeyed hash is safe here and cheaper than SipHash.
#[derive(Default, Clone, Copy)]
struct RouteHasher(u64);

impl RouteHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

impl Hasher for RouteHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut it = bytes.chunks_exact(8);
        for c in &mut it {
            self.add(u64::from_le_bytes(c.try_into().expect("8 bytes")));
        }
        let rest = it.remainder();
        if !rest.is_empty() {
            let mut b = [0u8; 8];
            b[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(b));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

type RouteMap<V> = HashMap<String, V, BuildHasherDefault<RouteHasher>>;

type HandlerFn = Arc<dyn Fn(&mut Context) + Send + Sync>;
type StreamFn =
    Arc<dyn Fn(&Stream) -> Box<dyn FnMut(&Stream, StreamEvent<'_>) + Send> + Send + Sync>;
type PeerFn = Arc<dyn Fn(&Peer) + Send + Sync>;
type ReadyFn = Box<dyn FnOnce(Peer) + Send>;
type StreamCb = Box<dyn FnMut(&Stream, StreamEvent<'_>) + Send>;

/// A connection's streams by (id, opened by this side).
#[derive(Default)]
struct Streams {
    map: HashMap<(u64, bool), Arc<Mutex<StreamState>>>,
    /// Entries opened by the peer (bounded by [`Routes::max_streams_per_conn`]).
    remote: usize,
}

impl Streams {
    fn remove(&mut self, key: &(u64, bool)) {
        if self.map.remove(key).is_some() && !key.1 {
            self.remote -= 1;
        }
    }
}

/// Methods served to the peer, connection hooks and limits.
pub struct Routes {
    handlers: RouteMap<HandlerFn>,
    streams: RouteMap<StreamFn>,
    on_connected: Option<PeerFn>,
    on_disconnected: Option<PeerFn>,
    max_body: Option<usize>,
    max_streams: usize,
    call_timeout: Option<Duration>,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            handlers: RouteMap::default(),
            streams: RouteMap::default(),
            on_connected: None,
            on_disconnected: None,
            max_body: None,
            max_streams: DEFAULT_MAX_STREAMS_PER_CONN,
            call_timeout: Some(DEFAULT_CALL_TIMEOUT),
        }
    }
}

impl std::fmt::Debug for Routes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Routes").finish_non_exhaustive()
    }
}

impl Routes {
    /// No methods.
    pub fn new() -> Routes {
        Routes::default()
    }

    /// Serves `method` (requests and notifies). `""` is the fallback for unknown methods;
    /// without it they get the error [`METHOD_NOT_FOUND`].
    #[must_use]
    pub fn handle(
        mut self,
        method: &str,
        f: impl Fn(&mut Context) + Send + Sync + 'static,
    ) -> Routes {
        self.handlers.insert(method.to_owned(), Arc::new(f));
        self
    }

    /// Serves streams the peer opens for `method`: `open` runs on the first message and returns
    /// the callback that receives this and every later message of the stream.
    #[must_use]
    pub fn handle_stream<F>(
        mut self,
        method: &str,
        open: impl Fn(&Stream) -> F + Send + Sync + 'static,
    ) -> Routes
    where
        F: FnMut(&Stream, StreamEvent<'_>) + Send + 'static,
    {
        self.streams
            .insert(method.to_owned(), Arc::new(move |s| Box::new(open(s))));
        self
    }

    /// Runs when a connection is established.
    #[must_use]
    pub fn on_connected(mut self, f: impl Fn(&Peer) + Send + Sync + 'static) -> Routes {
        self.on_connected = Some(Arc::new(f));
        self
    }

    /// Runs when a connection is lost.
    #[must_use]
    pub fn on_disconnected(mut self, f: impl Fn(&Peer) + Send + Sync + 'static) -> Routes {
        self.on_disconnected = Some(Arc::new(f));
        self
    }

    /// Longest body (method + payload) accepted; longer closes the connection. Default 64 MiB.
    #[must_use]
    pub fn max_body_bytes(mut self, n: usize) -> Routes {
        self.max_body = Some(n);
        self
    }

    /// Most streams the peer may have open at once on one connection (default
    /// [`DEFAULT_MAX_STREAMS_PER_CONN`], 1024). A stream opened past it is ended at once (the
    /// opener gets its end, as for a method that is not served) and its message dropped.
    /// Streams this side opens are not counted.
    #[must_use]
    pub fn max_streams_per_conn(mut self, n: usize) -> Routes {
        self.max_streams = n;
        self
    }

    /// Timeout of calls on connections using these routes that are made without one
    /// ([`Peer::call`] / [`Peer::call_async`] with `None`). Default
    /// [`DEFAULT_CALL_TIMEOUT`] (30 s), so a peer that never answers cannot grow the table of
    /// pending calls for ever; `None` lets such calls wait until the connection closes.
    #[must_use]
    pub fn call_timeout(mut self, t: Option<Duration>) -> Routes {
        self.call_timeout = t;
        self
    }
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallError {
    /// The peer answered with an error (its text).
    Remote(String),
    /// The connection is gone (or was lost before the answer).
    Closed,
    /// No answer in time.
    Timeout,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Remote(s) => write!(f, "{s}"),
            CallError::Closed => f.write_str("connection closed"),
            CallError::Timeout => f.write_str("timeout"),
        }
    }
}

impl std::error::Error for CallError {}

/// The outcome of a call: the response payload or an error.
pub type CallResult = Result<Vec<u8>, CallError>;
type CallCb = Box<dyn FnOnce(CallResult) + Send>;

/// One message of a stream, or its end.
pub enum StreamEvent<'a> {
    /// A message's payload.
    Message(&'a [u8]),
    /// The peer closed its sending half (or the connection is gone).
    Eof,
}

impl<'a> std::fmt::Debug for StreamEvent<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEvent").finish_non_exhaustive()
    }
}

struct StreamState {
    cb: StreamCb,
}

struct PeerInner {
    conn: Mutex<Option<Arc<ConnInner>>>,
    routes: Arc<Routes>,
    seq: AtomicU64,
    /// Calls waiting for their answer, with their timeout.
    pending: Mutex<HashMap<u64, (CallCb, Option<Timer>)>>,
    streams: Mutex<Streams>,
    /// For clients: how to reconnect.
    redial: Option<(EngineRef, SocketAddr)>,
    stopped: std::sync::atomic::AtomicBool,
}

/// One end of an arpc connection: call, notify and stream to the peer. Cheap to clone.
#[derive(Clone)]
pub struct Peer(Arc<PeerInner>);

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer").finish_non_exhaustive()
    }
}

impl Peer {
    fn conn(&self) -> Option<Arc<ConnInner>> {
        self.0
            .conn
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn send(&self, frame: Vec<u8>) -> bool {
        match self.conn() {
            Some(c) => c.send_owned(frame).is_ok(),
            None => false,
        }
    }

    /// Whether the connection is up.
    pub fn is_connected(&self) -> bool {
        self.conn().is_some_and(|c| c.is_open())
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.conn().map(|c| c.peer_addr())
    }

    /// Calls `method`; `done` receives the answer, an error, or `Timeout` after `timeout`
    /// (`None`: the routes' [`call_timeout`](Routes::call_timeout), 30 s by default).
    pub fn call_async(
        &self,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
        done: impl FnOnce(CallResult) + Send + 'static,
    ) {
        let seq = self.0.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let frame = encode(Cmd::Request, 0, false, false, method, seq, payload);
        let deadline = timeout
            .or(self.0.routes.call_timeout)
            .and_then(|t| Instant::now().checked_add(t));
        {
            let mut pending = self.0.pending.lock().unwrap_or_else(|p| p.into_inner());
            // Armed under the lock: a timer that fires at once waits for the entry.
            let timer = deadline.map(|at| {
                let me = Arc::downgrade(&self.0);
                Timer::at(at, move || {
                    if let Some(p) = me.upgrade() {
                        Peer(p).complete(seq, Err(CallError::Timeout));
                    }
                })
            });
            pending.insert(seq, (Box::new(done), timer));
        }
        if !self.send(frame) {
            self.complete(seq, Err(CallError::Closed));
        }
    }

    /// Calls `method` and returns a handle to wait on or await (`timeout` as in
    /// [`call_async`](Self::call_async)).
    pub fn call(&self, method: &str, payload: &[u8], timeout: Option<Duration>) -> CallFuture {
        let shared = Arc::new(Shared::default());
        let s = shared.clone();
        self.call_async(method, payload, timeout, move |r| s.done(r));
        CallFuture(shared)
    }

    /// Sends a one-way notify. `false` if the connection is down.
    pub fn notify(&self, method: &str, payload: &[u8]) -> bool {
        let seq = self.0.seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.send(encode(Cmd::Notify, 0, false, false, method, seq, payload))
    }

    /// Opens a stream for `method`; `on_event` receives the peer's messages and end.
    pub fn new_stream(
        &self,
        method: &str,
        on_event: impl FnMut(&Stream, StreamEvent<'_>) + Send + 'static,
    ) -> Stream {
        let id = self.0.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let s = Stream {
            peer: self.clone(),
            id,
            local: true,
            method: method.to_owned(),
        };
        self.0
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map
            .insert(
                (id, true),
                Arc::new(Mutex::new(StreamState {
                    cb: Box::new(on_event),
                })),
            );
        s
    }

    /// Closes the connection (and stops reconnecting).
    pub fn close(&self) {
        self.0.stopped.store(true, Ordering::Release);
        if let Some(c) = self.conn() {
            c.close();
        }
    }

    fn complete(&self, seq: u64, r: CallResult) {
        let entry = self
            .0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&seq);
        if let Some((cb, timer)) = entry {
            if let Some(t) = timer {
                t.cancel();
            }
            cb(r);
        }
    }

    /// Calls waiting for an answer.
    #[cfg(test)]
    fn pending_calls(&self) -> usize {
        self.0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    fn fail_all(&self) {
        let pending: Vec<_> = self
            .0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .map(|(_, c)| c)
            .collect();
        for (cb, timer) in pending {
            if let Some(t) = timer {
                t.cancel();
            }
            cb(Err(CallError::Closed));
        }
        let streams: Vec<_> = {
            let mut g = self.0.streams.lock().unwrap_or_else(|p| p.into_inner());
            g.remote = 0;
            g.map.drain().collect()
        };
        for ((id, local), st) in streams {
            let s = Stream {
                peer: self.clone(),
                id,
                local,
                method: String::new(),
            };
            (st.lock().unwrap_or_else(|p| p.into_inner()).cb)(&s, StreamEvent::Eof);
        }
    }

    /// Dispatches one message received on `conn`.
    fn on_message(&self, conn: &Arc<ConnInner>, m: Message) {
        match m.cmd {
            Cmd::Ping => {
                let _ = conn.send_owned(proto::pong());
            }
            Cmd::Pong => {}
            Cmd::Request | Cmd::Notify => {
                let routes = &self.0.routes;
                let h = routes
                    .handlers
                    .get(m.method.as_str())
                    .or_else(|| routes.handlers.get(""));
                let mut ctx = Context {
                    peer: self.clone(),
                    conn: conn.clone(),
                    msg: m,
                    responded: false,
                };
                match h {
                    Some(h) => h(&mut ctx),
                    None => ctx.error(METHOD_NOT_FOUND),
                }
            }
            Cmd::Response => {
                let r = if m.error {
                    Err(CallError::Remote(
                        String::from_utf8_lossy(&m.payload).into_owned(),
                    ))
                } else {
                    Ok(m.payload)
                };
                self.complete(m.seq, r);
            }
            Cmd::Stream => self.on_stream(m),
        }
    }

    fn on_stream(&self, m: Message) {
        // The opener sets the local bit; from here, a local-bit message is the peer's stream.
        let ours = !m.stream_local;
        let key = (m.seq, ours);
        let (existing, full) = {
            let g = self.0.streams.lock().unwrap_or_else(|p| p.into_inner());
            (
                g.map.get(&key).cloned(),
                g.remote >= self.0.routes.max_streams,
            )
        };
        let Message {
            seq,
            method,
            payload,
            stream_eof,
            ..
        } = m;
        let stream = Stream {
            peer: self.clone(),
            id: seq,
            local: ours,
            method,
        };
        let st = match existing {
            Some(st) => st,
            None => {
                let open = if ours || full {
                    None
                } else {
                    self.0.routes.streams.get(stream.method.as_str())
                };
                let Some(open) = open else {
                    if !ours {
                        // Not served, or too many open: end the opener's receiving half so it
                        // does not wait for good.
                        self.send(encode(
                            Cmd::Stream,
                            0,
                            false,
                            true,
                            &stream.method,
                            seq,
                            &[],
                        ));
                    }
                    return;
                };
                let st = Arc::new(Mutex::new(StreamState { cb: open(&stream) }));
                if !stream_eof {
                    let mut g = self.0.streams.lock().unwrap_or_else(|p| p.into_inner());
                    if g.map.insert(key, st.clone()).is_none() {
                        g.remote += 1;
                    }
                }
                st
            }
        };
        let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
        if !payload.is_empty() || !stream_eof {
            (g.cb)(&stream, StreamEvent::Message(&payload));
        }
        if stream_eof {
            (g.cb)(&stream, StreamEvent::Eof);
            drop(g);
            self.0
                .streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
        }
    }

    /// Streams the peer has open.
    #[cfg(test)]
    fn remote_streams(&self) -> usize {
        self.0
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remote
    }
}

/// One side of a stream.
#[derive(Debug, Clone)]
pub struct Stream {
    peer: Peer,
    id: u64,
    local: bool,
    method: String,
}

impl Stream {
    /// The stream's id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The method it is bound to.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Sends a message.
    pub fn send(&self, payload: &[u8]) -> bool {
        self.peer.send(encode(
            Cmd::Stream,
            0,
            self.local,
            false,
            &self.method,
            self.id,
            payload,
        ))
    }

    /// Closes the sending half (the peer gets its end).
    pub fn close_send(&self) -> bool {
        self.peer.send(encode(
            Cmd::Stream,
            0,
            self.local,
            true,
            &self.method,
            self.id,
            &[],
        ))
    }

    /// The connection it belongs to.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }
}

/// A request or notify being served.
#[derive(Debug)]
pub struct Context {
    peer: Peer,
    /// The connection the request came on: the answer goes there without taking the peer's
    /// connection lock.
    conn: Arc<ConnInner>,
    msg: Message,
    responded: bool,
}

impl Context {
    /// The method called.
    pub fn method(&self) -> &str {
        &self.msg.method
    }

    /// The request payload.
    pub fn body(&self) -> &[u8] {
        &self.msg.payload
    }

    /// Whether this is a notify (no answer expected).
    pub fn is_notify(&self) -> bool {
        self.msg.cmd == Cmd::Notify
    }

    /// The connection, to call the peer back.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Answers with `payload` (ignored for notifies and after the first answer).
    pub fn write(&mut self, payload: &[u8]) {
        self.answer(payload, false);
    }

    /// Answers with an error.
    pub fn error(&mut self, text: &str) {
        self.answer(text.as_bytes(), true);
    }

    fn answer(&mut self, payload: &[u8], err: bool) {
        if self.responded || self.msg.cmd != Cmd::Request {
            return;
        }
        self.responded = true;
        let flags = if self.msg.async_flag {
            proto::FLAG_ASYNC
        } else {
            0
        };
        let mut frame = encode(
            Cmd::Response,
            flags,
            false,
            false,
            &self.msg.method,
            self.msg.seq,
            payload,
        );
        if err {
            frame[proto::IDX_FLAG] |= proto::FLAG_ERROR;
        }
        let _ = self.conn.send_owned(frame);
    }

    /// Takes over the answer, to send it later from any thread.
    pub fn detach(&mut self) -> Responder {
        let r = Responder {
            peer: self.peer.clone(),
            method: self.msg.method.clone(),
            seq: self.msg.seq,
            async_flag: self.msg.async_flag,
            request: self.msg.cmd == Cmd::Request && !self.responded,
        };
        self.responded = true;
        r
    }
}

/// An answer to send later; see [`Context::detach`].
#[derive(Debug)]
pub struct Responder {
    peer: Peer,
    method: String,
    seq: u64,
    async_flag: bool,
    request: bool,
}

impl Responder {
    /// Answers with `payload`.
    pub fn write(self, payload: &[u8]) {
        self.send(payload, false);
    }

    /// Answers with an error.
    pub fn error(self, text: &str) {
        self.send(text.as_bytes(), true);
    }

    fn send(self, payload: &[u8], err: bool) {
        if !self.request {
            return;
        }
        let flags = if self.async_flag {
            proto::FLAG_ASYNC
        } else {
            0
        };
        let mut frame = encode(
            Cmd::Response,
            flags,
            false,
            false,
            &self.method,
            self.seq,
            payload,
        );
        if err {
            frame[proto::IDX_FLAG] |= proto::FLAG_ERROR;
        }
        self.peer.send(frame);
    }
}

// ---- futures ---------------------------------------------------------------------------------

#[derive(Default)]
struct Shared {
    slot: Mutex<(Option<CallResult>, Option<Waker>)>,
    cv: Condvar,
}

impl Shared {
    fn done(&self, r: CallResult) {
        let mut g = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        g.0 = Some(r);
        if let Some(w) = g.1.take() {
            w.wake();
        }
        self.cv.notify_all();
    }
}

/// The result of [`Peer::call`]: wait for it or `.await` it.
pub struct CallFuture(Arc<Shared>);

impl std::fmt::Debug for CallFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallFuture").finish_non_exhaustive()
    }
}

impl CallFuture {
    /// Blocks until the answer.
    pub fn wait(self) -> CallResult {
        let mut g = self.0.slot.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(r) = g.0.take() {
                return r;
            }
            g = self.0.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

impl Future for CallFuture {
    type Output = CallResult;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<CallResult> {
        let mut g = self.0.slot.lock().unwrap_or_else(|p| p.into_inner());
        match g.0.take() {
            Some(r) => Poll::Ready(r),
            None => {
                g.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

// ---- the connection handler ------------------------------------------------------------------

/// The `only` handler of an arpc connection.
#[derive(Debug)]
pub struct ArpcConn {
    peer: Peer,
    dec: Decoder,
}

impl Handler for ArpcConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (peer, conn) = (&self.peer, c.inner());
        if self
            .dec
            .feed_with(data, |m| peer.on_message(conn, m))
            .is_err()
        {
            c.close();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        *self.peer.0.conn.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.peer.fail_all();
        if let Some(f) = &self.peer.0.routes.on_disconnected {
            f(&self.peer);
        }
        // Clients reconnect on their own.
        if let Some((engine, addr)) = self.peer.0.redial.clone() {
            if !self.peer.0.stopped.load(Ordering::Acquire) {
                let weak = Arc::downgrade(&self.peer.0);
                Timer::at(Instant::now() + Duration::from_secs(1), move || {
                    redial(weak, engine, addr);
                });
            }
        }
    }
}

fn redial(weak: Weak<PeerInner>, engine: EngineRef, addr: SocketAddr) {
    let (Some(inner), Some(e)) = (weak.upgrade(), engine.get()) else {
        return;
    };
    if inner.stopped.load(Ordering::Acquire) {
        return;
    }
    let peer = Peer(inner);
    let w2 = Arc::downgrade(&peer.0);
    let e2 = engine;
    e.dial(
        addr,
        Attach {
            peer,
            ready: Mutex::new(None),
        },
        move |_err| {
            Timer::at(Instant::now() + Duration::from_secs(1), move || {
                redial(w2, e2, addr);
            });
        },
    );
}

/// Attaches a dialed connection to an existing (client) peer.
struct Attach {
    peer: Peer,
    ready: Mutex<Option<ReadyFn>>,
}

impl Acceptor for Attach {
    type Handler = ArpcConn;
    fn on_open(&self, c: &Conn<ArpcConn>) -> ArpcConn {
        *self.peer.0.conn.lock().unwrap_or_else(|p| p.into_inner()) = Some(c.inner().clone());
        if let Some(f) = &self.peer.0.routes.on_connected {
            f(&self.peer);
        }
        let taken = self.ready.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(r) = taken {
            r(self.peer.clone());
        }
        ArpcConn {
            peer: self.peer.clone(),
            dec: Decoder::new(
                self.peer
                    .0
                    .routes
                    .max_body
                    .unwrap_or(proto::DEFAULT_MAX_BODY),
            ),
        }
    }
}

/// Connects to an arpc server and keeps reconnecting (every second) until [`Peer::close`].
/// Blocks until the first connection is up (10 s at most).
pub fn dial_blocking(
    engine: &Arc<Engine>,
    addr: SocketAddr,
    routes: Arc<Routes>,
) -> io::Result<Peer> {
    let er = EngineRef::new();
    er.set(engine);
    let peer = Peer(Arc::new(PeerInner {
        conn: Mutex::new(None),
        routes,
        seq: AtomicU64::new(0),
        pending: Mutex::new(HashMap::new()),
        streams: Mutex::new(Streams::default()),
        redial: Some((er, addr)),
        stopped: std::sync::atomic::AtomicBool::new(false),
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    engine.dial(
        addr,
        Attach {
            peer,
            ready: Mutex::new(Some(Box::new(move |p| {
                let _ = tx.send(Ok(p));
            }))),
        },
        move |e| {
            let _ = tx2.send(Err(e));
        },
    );
    rx.recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "arpc dial timed out"))?
}

/// An arpc server: serve it on a listener. Every accepted connection is a [`Peer`].
#[derive(Debug, Clone)]
pub struct Server {
    routes: Arc<Routes>,
    peers: Arc<Mutex<HashMap<u64, Peer>>>,
}

impl Server {
    /// A server for `routes`.
    pub fn new(routes: Arc<Routes>) -> Server {
        Server {
            routes,
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Sends a notify to every connected client. The frame is encoded once and shared.
    pub fn broadcast(&self, method: &str, payload: &[u8]) {
        let frame = SharedBuf::from(encode(Cmd::Notify, 0, false, false, method, 0, payload));
        for p in self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
        {
            if let Some(c) = p.conn() {
                let _ = c.send_shared(frame.clone());
            }
        }
    }

    /// The connected clients.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect()
    }
}

/// The handler of a server-side connection: an [`ArpcConn`] that also leaves the registry.
#[derive(Debug)]
pub struct ServerConn {
    conn: ArpcConn,
    id: u64,
    peers: Arc<Mutex<HashMap<u64, Peer>>>,
}

impl Handler for ServerConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (peer, conn) = (&self.conn.peer, c.inner());
        if self
            .conn
            .dec
            .feed_with(data, |m| peer.on_message(conn, m))
            .is_err()
        {
            c.close();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
        *self
            .conn
            .peer
            .0
            .conn
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        self.conn.peer.fail_all();
        if let Some(f) = &self.conn.peer.0.routes.on_disconnected {
            f(&self.conn.peer);
        }
    }
}

impl Acceptor for Server {
    type Handler = ServerConn;
    fn on_open(&self, c: &Conn<ServerConn>) -> ServerConn {
        let peer = Peer(Arc::new(PeerInner {
            conn: Mutex::new(Some(c.inner().clone())),
            routes: self.routes.clone(),
            seq: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            streams: Mutex::new(Streams::default()),
            redial: None,
            stopped: std::sync::atomic::AtomicBool::new(false),
        }));
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(c.id(), peer.clone());
        if let Some(f) = &self.routes.on_connected {
            f(&peer);
        }
        ServerConn {
            conn: ArpcConn {
                dec: Decoder::new(self.routes.max_body.unwrap_or(proto::DEFAULT_MAX_BODY)),
                peer,
            },
            id: c.id(),
            peers: self.peers.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    use only::{Config, Listener};

    use super::*;

    fn engine(server: Server) -> Arc<Engine> {
        let e = Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .client_threads(1)
            .listen(
                Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                    .threads(1)
                    .serve(server),
            )
            .build()
            .expect("engine");
        let e = Arc::new(e);
        e.start().expect("start");
        e
    }

    fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(5), "timed out: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn calls_time_out_by_default_and_finished_calls_leave_no_timer() {
        assert_eq!(Routes::new().call_timeout, Some(DEFAULT_CALL_TIMEOUT));
        let server = Server::new(Arc::new(
            Routes::new()
                .handle("/echo", |ctx| {
                    let b = ctx.body().to_vec();
                    ctx.write(&b);
                })
                .handle("/never", |ctx| drop(ctx.detach())),
        ));
        let e = engine(server);
        let routes = Routes::new().call_timeout(Some(Duration::from_millis(100)));
        let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(routes)).expect("dial");

        // No timeout given: the routes' default ends a call the peer never answers.
        let t = Instant::now();
        assert_eq!(
            peer.call("/never", b"", None).wait(),
            Err(CallError::Timeout)
        );
        assert!(t.elapsed() >= Duration::from_millis(100));
        assert_eq!(peer.pending_calls(), 0);

        // A flood of calls with long deadlines that are answered at once: each timer is
        // removed when its call completes, so neither table grows.
        let before = deadline::pending();
        let futs: Vec<_> = (0..2000)
            .map(|_| peer.call("/echo", b"x", Some(Duration::from_secs(3600))))
            .collect();
        for f in futs {
            assert_eq!(f.wait().expect("answer"), b"x");
        }
        assert_eq!(peer.pending_calls(), 0);
        assert!(
            deadline::pending() < before + 50,
            "timers left behind: {} -> {}",
            before,
            deadline::pending()
        );

        // Calls pending when the connection closes fail at once and drop their timers.
        let hung: Vec<_> = (0..100)
            .map(|_| peer.call("/never", b"", Some(Duration::from_secs(3600))))
            .collect();
        wait_until("calls sent", || peer.pending_calls() == 100);
        peer.close();
        for f in hung {
            assert_eq!(f.wait(), Err(CallError::Closed));
        }
        assert!(deadline::pending() < before + 50);
        e.shutdown();
        e.wait();
    }

    #[test]
    fn peer_opened_streams_are_capped() {
        let server = Server::new(Arc::new(
            Routes::new()
                .max_streams_per_conn(3)
                .handle_stream("/s", |_s| {
                    |s: &Stream, ev: StreamEvent<'_>| {
                        if let StreamEvent::Eof = ev {
                            s.close_send();
                        }
                    }
                }),
        ));
        let e = engine(server.clone());
        let peer = dial_blocking(&e, e.local_addrs()[0], Arc::new(Routes::new())).expect("dial");
        wait_until("registered", || server.peers().len() == 1);
        let sp = server.peers().remove(0);
        let (tx, rx) = mpsc::channel();
        let open = |i: usize| {
            let tx = tx.clone();
            let s = peer.new_stream("/s", move |_s, ev| {
                if let StreamEvent::Eof = ev {
                    let _ = tx.send(i);
                }
            });
            assert!(s.send(b"hi"));
            s
        };
        // Under and at the limit: every stream stays open.
        let s0 = open(0);
        let _s1 = open(1);
        let _s2 = open(2);
        wait_until("three open", || sp.remote_streams() == 3);
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        // Over: the fourth is ended at once and not stored.
        let _s3 = open(3);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("end"), 3);
        assert_eq!(sp.remote_streams(), 3);
        // Closing one frees its place.
        s0.close_send();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("end"), 0);
        wait_until("one closed", || sp.remote_streams() == 2);
        let _s4 = open(4);
        wait_until("reopened", || sp.remote_streams() == 3);
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        // The connection going away clears the count.
        peer.close();
        wait_until("cleared", || sp.remote_streams() == 0);
        e.shutdown();
        e.wait();
    }

    #[test]
    fn route_hash_spreads_and_finds_names() {
        let r = Routes::new()
            .handle("/a", |_| {})
            .handle("/abcdefgh", |_| {})
            .handle("/abcdefgh1", |_| {});
        for k in ["/a", "/abcdefgh", "/abcdefgh1"] {
            assert!(r.handlers.contains_key(k), "{k}");
        }
        assert!(!r.handlers.contains_key("/abcdefgh2"));
        assert!(!r.handlers.contains_key(""));
    }
}
