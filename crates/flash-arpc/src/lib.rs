#![forbid(unsafe_code)]
//! arpc on flash: two-way calls, notifies, asynchronous calls, streams and broadcast on the wire
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
//! # use std::sync::Arc; use flash::{Engine, EngineRef, Listener}; use flash_arpc::{Routes, Server};
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
//! Guide: [arpc](https://lesismal.github.io/flash/en/protocols/arpc.html)
//! (中文: [arpc](https://lesismal.github.io/flash/zh-CN/protocols/arpc.html)).

pub mod proto;

use std::{
    collections::HashMap,
    future::Future,
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

use flash::{Acceptor, Conn, Engine, EngineRef, Handler};
use flash_buf::SharedBuf;
use flash_core::ConnInner;

use crate::proto::{Cmd, Decoder, Message, encode};

/// Error text of a call to a method the peer does not serve (the same as Go's).
pub const METHOD_NOT_FOUND: &str = "method not found";

type HandlerFn = Arc<dyn Fn(&mut Context) + Send + Sync>;
type StreamFn = Arc<dyn Fn(&Stream) -> Box<dyn FnMut(&Stream, StreamEvent) + Send> + Send + Sync>;
type PeerFn = Arc<dyn Fn(&Peer) + Send + Sync>;
type ReadyFn = Box<dyn FnOnce(Peer) + Send>;
type StreamCb = Box<dyn FnMut(&Stream, StreamEvent) + Send>;
type StreamMap = HashMap<(u64, bool), Arc<Mutex<StreamState>>>;

/// Methods served to the peer, and connection hooks.
#[derive(Default)]
pub struct Routes {
    handlers: HashMap<String, HandlerFn>,
    streams: HashMap<String, StreamFn>,
    on_connected: Option<PeerFn>,
    on_disconnected: Option<PeerFn>,
    max_body: Option<usize>,
}

impl Routes {
    /// No methods.
    pub fn new() -> Routes {
        Routes::default()
    }

    /// Serves `method` (requests and notifies). `""` is the fallback for unknown methods;
    /// without it they get the error [`METHOD_NOT_FOUND`].
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
    pub fn handle_stream<F>(
        mut self,
        method: &str,
        open: impl Fn(&Stream) -> F + Send + Sync + 'static,
    ) -> Routes
    where
        F: FnMut(&Stream, StreamEvent) + Send + 'static,
    {
        self.streams
            .insert(method.to_owned(), Arc::new(move |s| Box::new(open(s))));
        self
    }

    /// Runs when a connection is established.
    pub fn on_connected(mut self, f: impl Fn(&Peer) + Send + Sync + 'static) -> Routes {
        self.on_connected = Some(Arc::new(f));
        self
    }

    /// Runs when a connection is lost.
    pub fn on_disconnected(mut self, f: impl Fn(&Peer) + Send + Sync + 'static) -> Routes {
        self.on_disconnected = Some(Arc::new(f));
        self
    }

    /// Longest body (method + payload) accepted; longer closes the connection. Default 64 MiB.
    pub fn max_body(mut self, n: usize) -> Routes {
        self.max_body = Some(n);
        self
    }
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
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

struct StreamState {
    cb: StreamCb,
}

struct PeerInner {
    conn: Mutex<Option<Arc<ConnInner>>>,
    routes: Arc<Routes>,
    seq: AtomicU64,
    pending: Mutex<HashMap<u64, CallCb>>,
    /// Streams by (id, opened by this side).
    streams: Mutex<StreamMap>,
    /// For clients: how to reconnect.
    redial: Option<(EngineRef, SocketAddr)>,
    stopped: std::sync::atomic::AtomicBool,
}

/// One end of an arpc connection: call, notify and stream to the peer. Cheap to clone.
#[derive(Clone)]
pub struct Peer(Arc<PeerInner>);

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

    /// Calls `method`; `done` receives the answer, an error, or `Timeout` after `timeout`.
    pub fn call_async(
        &self,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
        done: impl FnOnce(CallResult) + Send + 'static,
    ) {
        let seq = self.0.seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(seq, Box::new(done));
        let frame = encode(Cmd::Request, 0, false, false, method, seq, payload);
        if !self.send(frame) {
            self.complete(seq, Err(CallError::Closed));
            return;
        }
        if let Some(t) = timeout {
            let me = Arc::downgrade(&self.0);
            timers().add(Instant::now() + t, move || {
                if let Some(p) = me.upgrade() {
                    Peer(p).complete(seq, Err(CallError::Timeout));
                }
            });
        }
    }

    /// Calls `method` and returns a handle to wait on or await.
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
        on_event: impl FnMut(&Stream, StreamEvent) + Send + 'static,
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
        let cb = self
            .0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&seq);
        if let Some(cb) = cb {
            cb(r);
        }
    }

    fn fail_all(&self) {
        let pending: Vec<CallCb> = self
            .0
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .map(|(_, c)| c)
            .collect();
        for cb in pending {
            cb(Err(CallError::Closed));
        }
        let streams: Vec<_> = self
            .0
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .collect();
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

    /// Dispatches one received message.
    fn on_message(&self, m: Message) {
        match m.cmd {
            Cmd::Ping => {
                self.send(proto::pong());
            }
            Cmd::Pong => {}
            Cmd::Request | Cmd::Notify => {
                let routes = self.0.routes.clone();
                let mut ctx = Context {
                    peer: self.clone(),
                    msg: m,
                    responded: false,
                };
                match routes
                    .handlers
                    .get(&ctx.msg.method)
                    .or_else(|| routes.handlers.get(""))
                {
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
        let existing = self
            .0
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .cloned();
        let stream = Stream {
            peer: self.clone(),
            id: m.seq,
            local: ours,
            method: m.method.clone(),
        };
        let st = match existing {
            Some(st) => st,
            None => {
                let open = if ours {
                    None
                } else {
                    self.0.routes.streams.get(&m.method).cloned()
                };
                let Some(open) = open else {
                    if !ours {
                        // End the opener's receiving half so it does not wait for good.
                        self.send(encode(Cmd::Stream, 0, false, true, &m.method, m.seq, &[]));
                    }
                    return;
                };
                let st = Arc::new(Mutex::new(StreamState { cb: open(&stream) }));
                self.0
                    .streams
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(key, st.clone());
                st
            }
        };
        let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
        if !m.payload.is_empty() || !m.stream_eof {
            (g.cb)(&stream, StreamEvent::Message(&m.payload));
        }
        if m.stream_eof {
            (g.cb)(&stream, StreamEvent::Eof);
            drop(g);
            self.0
                .streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
        }
    }
}

/// One side of a stream.
#[derive(Clone)]
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
pub struct Context {
    peer: Peer,
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
        self.peer.send(frame);
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

// ---- call timeouts: one shared timer thread ----------------------------------------------------

type TimerFn = Box<dyn FnOnce() + Send>;

struct Timers {
    q: Mutex<Vec<(Instant, TimerFn)>>,
    cv: Condvar,
}

impl Timers {
    fn add(&self, at: Instant, f: impl FnOnce() + Send + 'static) {
        self.q
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((at, Box::new(f)));
        self.cv.notify_one();
    }
}

fn timers() -> &'static Timers {
    static T: std::sync::OnceLock<&'static Timers> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let t: &'static Timers = Box::leak(Box::new(Timers {
            q: Mutex::new(Vec::new()),
            cv: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("flash-arpc-timers".into())
            .spawn(move || {
                let mut g = t.q.lock().unwrap_or_else(|p| p.into_inner());
                loop {
                    let now = Instant::now();
                    let mut due = Vec::new();
                    let mut i = 0;
                    while i < g.len() {
                        if g[i].0 <= now {
                            due.push(g.swap_remove(i).1);
                        } else {
                            i += 1;
                        }
                    }
                    if !due.is_empty() {
                        drop(g);
                        for f in due {
                            f();
                        }
                        g = t.q.lock().unwrap_or_else(|p| p.into_inner());
                        continue;
                    }
                    let next = g.iter().map(|(at, _)| *at).min();
                    g = match next {
                        Some(at) => {
                            t.cv.wait_timeout(g, at.saturating_duration_since(now))
                                .unwrap_or_else(|p| p.into_inner())
                                .0
                        }
                        None => t.cv.wait(g).unwrap_or_else(|p| p.into_inner()),
                    };
                }
            })
            .expect("timer thread");
        t
    })
}

// ---- the connection handler ------------------------------------------------------------------

/// The flash handler of an arpc connection.
pub struct ArpcConn {
    peer: Peer,
    dec: Decoder,
}

impl Handler for ArpcConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut msgs = Vec::new();
        if self.dec.feed(data, &mut msgs).is_err() {
            c.close();
            return;
        }
        for m in msgs {
            self.peer.on_message(m);
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        *self.peer.0.conn.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.peer.fail_all();
        if let Some(f) = &self.peer.0.routes.on_disconnected {
            f(&self.peer);
        }
        // Clients reconnect on their own.
        if let Some((engine, addr)) = self.peer.0.redial.clone() {
            if !self.peer.0.stopped.load(Ordering::Acquire) {
                let weak = Arc::downgrade(&self.peer.0);
                timers().add(Instant::now() + Duration::from_secs(1), move || {
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
    let e2 = engine.clone();
    e.dial(
        addr,
        Attach {
            peer: peer.clone(),
            ready: Mutex::new(None),
        },
        move |_err| {
            timers().add(Instant::now() + Duration::from_secs(1), move || {
                redial(w2, e2, addr)
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
        if let Some(r) = self.ready.lock().unwrap_or_else(|p| p.into_inner()).take() {
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
pub fn dial(engine: &Arc<Engine>, addr: SocketAddr, routes: Arc<Routes>) -> io::Result<Peer> {
    let er = EngineRef::new();
    er.set(engine);
    let peer = Peer(Arc::new(PeerInner {
        conn: Mutex::new(None),
        routes,
        seq: AtomicU64::new(0),
        pending: Mutex::new(HashMap::new()),
        streams: Mutex::new(HashMap::new()),
        redial: Some((er, addr)),
        stopped: std::sync::atomic::AtomicBool::new(false),
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    engine.dial(
        addr,
        Attach {
            peer: peer.clone(),
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
#[derive(Clone)]
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
pub struct ServerConn {
    conn: ArpcConn,
    id: u64,
    peers: Arc<Mutex<HashMap<u64, Peer>>>,
}

impl Handler for ServerConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut msgs = Vec::new();
        if self.conn.dec.feed(data, &mut msgs).is_err() {
            c.close();
            return;
        }
        for m in msgs {
            self.conn.peer.on_message(m);
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
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
            streams: Mutex::new(HashMap::new()),
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
