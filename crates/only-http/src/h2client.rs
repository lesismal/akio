//! An HTTP/2 client: one connection multiplexing many concurrent requests, with flow control
//! both ways, trailers and (optionally) server push.
//!
//! ```no_run
//! # use only::Engine; use only_http::{client::ClientRequest, h2client::{H2Client, H2Options}};
//! # let engine = Engine::builder().client_threads(1).build().unwrap(); engine.start().unwrap();
//! let c = H2Client::dial_blocking(&engine, "127.0.0.1:8082".parse().unwrap(), None, H2Options::default())
//!     .unwrap();
//! let r = c.send(ClientRequest::get("http://127.0.0.1:8082/")).wait().unwrap();
//! ```
//!
//! Callbacks run on an I/O thread and must not block.
//!
//! Responses are bounded by [`H2Options`]: frames by the default `SETTINGS_MAX_FRAME_SIZE`
//! (16 KiB), header lists by `max_header_list` (64 KiB, advertised), buffered bodies by
//! `max_body_bytes` (64 MiB). Request timeouts are [`ClientRequest::timeout`].
//!
//! [`H2Client::websocket`] opens a WebSocket on a stream of the connection (RFC 8441 extended
//! CONNECT), next to the connection's other requests.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use only_ws::{WsConfig, WsHandler, WsLink, WsSender, WsSession, deflate::PmdOffer};

use crate::hpack::{Decoder, Encoder};
use only::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, Tls},
};

use crate::{
    client::{
        ClientError, ClientRequest, ClientResponse, FutureShared, Outcome, ResponseFuture,
        parse_url,
    },
    h2::{DEFAULT_FRAME, DEFAULT_WINDOW, MAX_WINDOW, PREFACE, err, flag, frame, ty},
    message::{Headers, Method},
};

/// Connection options.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H2Options {
    /// Receive window per stream.
    pub initial_window: u32,
    /// Receive window of the connection.
    pub conn_window: u32,
    /// Accept server push (`ClientResponse::pushed` then carries the pushed responses).
    pub enable_push: bool,
    /// Largest response header list (uncompressed: name + value + 32 per field), advertised as
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`. A larger response fails its request with
    /// [`ClientError::TooLarge`]; a header block (HEADERS + CONTINUATION) whose compressed
    /// size passes twice this (at least 64 KiB) ends the connection. Default 64 KiB.
    pub max_header_list: u32,
    /// Largest buffered response body ([`request`](H2Client::request),
    /// [`send`](H2Client::send), pushed responses); past it the stream is reset and the request
    /// fails with [`ClientError::TooLarge`]. Streamed responses ([`open`](H2Client::open)) are
    /// handed over as they arrive and not limited. Default 64 MiB.
    pub max_body_bytes: usize,
}

impl Default for H2Options {
    fn default() -> Self {
        H2Options {
            initial_window: 1 << 20,
            conn_window: 1 << 24,
            enable_push: false,
            max_header_list: 64 << 10,
            max_body_bytes: 64 << 20,
        }
    }
}

/// How [`H2Client::websocket`] opens a WebSocket over HTTP/2 (RFC 8441).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H2WsOptions {
    /// Message limits and compression; `permessage_deflate` decides whether it is offered.
    pub config: WsConfig,
    /// What the `permessage-deflate` offer asks for.
    pub pmd: PmdOffer,
    /// Subprotocols to offer, in order of preference; the server's choice is
    /// [`WsSender::subprotocol`].
    pub protocols: Vec<String>,
    /// `Origin` header, for servers that check it.
    pub origin: Option<String>,
    /// Extra request header fields (e.g. `authorization`).
    pub headers: Vec<(String, String)>,
    /// After the close handshake, how long to wait for the server to end the stream before
    /// resetting it from this side. Default 3 s.
    pub close_timeout: Duration,
    /// How long to wait for the server's SETTINGS and its answer; past it the stream is reset
    /// (`CANCEL`) and the WebSocket fails with [`ClientError::Timeout`]. Default 10 s.
    pub timeout: Duration,
    /// Bytes the WebSocket may hold for the server (not yet written to the connection, because
    /// the stream's or the connection's window is closed) before sends fail with
    /// `Overloaded`: [`WsSender::queued_bytes`] paces a producer. Default 8 MiB.
    pub max_queued_bytes: usize,
}

impl Default for H2WsOptions {
    fn default() -> H2WsOptions {
        H2WsOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            close_timeout: Duration::from_secs(3),
            timeout: Duration::from_secs(10),
            max_queued_bytes: 8 << 20,
        }
    }
}

type WsDone = Box<dyn FnOnce(Result<WsSender, ClientError>) + Send>;

/// The callback of a WebSocket being opened, taken once: by the answer or by the timeout.
#[derive(Clone)]
struct WsOnce(Arc<Mutex<Option<WsDone>>>);

impl WsOnce {
    fn take(&self) -> Option<WsDone> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    fn fail(&self, e: ClientError) {
        if let Some(cb) = self.take() {
            cb(Err(e));
        }
    }
}

/// A WebSocket being opened.
struct WsOpen {
    url: String,
    /// Regular request fields (lowercase names).
    fields: Vec<(String, String)>,
    handler: Box<dyn WsHandler>,
    cfg: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    max_queued: usize,
    done: WsOnce,
    /// The stream it got (0 until started), for the timeout to cancel.
    sid: Arc<AtomicU32>,
}

/// The WebSocket on a stream. Dropped with its stream, whatever ended it: the opener then
/// hears [`ClientError::Closed`], an open session `on_close` (1006 unless the close handshake
/// ended it).
struct CWs(WsState);

enum WsState {
    Opening(Box<WsOpen>),
    Open(Box<WsSession>, Arc<LinkShared>),
    Gone,
}

impl CWs {
    fn fail(&mut self, e: ClientError) {
        match std::mem::replace(&mut self.0, WsState::Gone) {
            WsState::Opening(w) => w.done.fail(e),
            WsState::Open(mut s, sh) => {
                sh.closed.store(true, Ordering::Release);
                s.on_transport_closed();
            }
            WsState::Gone => {}
        }
    }
}

impl Drop for CWs {
    fn drop(&mut self) {
        self.fail(ClientError::Closed);
    }
}

/// What a WebSocket's sender queued for its stream, moved there on the I/O thread.
struct LinkShared {
    q: Mutex<LinkQ>,
    /// Bytes accepted by `send` and not yet handed to the connection.
    queued: AtomicUsize,
    max: usize,
    closed: AtomicBool,
}

#[derive(Default)]
struct LinkQ {
    chunks: VecDeque<Vec<u8>>,
    end: LinkEnd,
    /// A pump is on its way to the I/O thread.
    scheduled: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum LinkEnd {
    #[default]
    No,
    /// END_STREAM after what is queued.
    Graceful,
    /// END_STREAM if the server ended its half, else `RST_STREAM CANCEL`.
    Now,
}

/// The stream of a WebSocket over HTTP/2, client side.
struct ClientLink {
    conn: Conn<H2Conn>,
    sid: u32,
    sh: Arc<LinkShared>,
}

impl ClientLink {
    fn lock(&self) -> std::sync::MutexGuard<'_, LinkQ> {
        self.sh.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Has the I/O thread move what is queued to the stream (once per batch).
    fn kick(&self) -> only::Result<()> {
        let (sid, sh) = (self.sid, self.sh.clone());
        self.conn
            .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.ws_pump(c, sid, &sh))
    }

    fn end(&self, end: LinkEnd) {
        self.sh.closed.store(true, Ordering::Release);
        let mut q = self.lock();
        q.end = q.end.max(end);
        if !std::mem::replace(&mut q.scheduled, true) {
            drop(q);
            if self.kick().is_err() {
                self.lock().scheduled = false;
            }
        }
    }
}

impl WsLink for ClientLink {
    fn send(&self, data: Vec<u8>) -> only::Result<()> {
        if self.sh.closed.load(Ordering::Acquire) || !self.conn.is_open() {
            return Err(only::Error::Closed);
        }
        let n = data.len();
        if self.sh.queued.load(Ordering::Acquire) + n > self.sh.max {
            return Err(only::Error::Overloaded);
        }
        let mut q = self.lock();
        q.chunks.push_back(data);
        self.sh.queued.fetch_add(n, Ordering::AcqRel);
        if std::mem::replace(&mut q.scheduled, true) {
            return Ok(());
        }
        drop(q);
        if let Err(e) = self.kick() {
            // Not handed over: take the bytes back (sends of one sender are serialized).
            let mut q = self.lock();
            q.scheduled = false;
            q.chunks.pop_back();
            self.sh.queued.fetch_sub(n, Ordering::AcqRel);
            return Err(match e {
                only::Error::Overloaded => only::Error::Overloaded,
                _ => only::Error::Closed,
            });
        }
        Ok(())
    }

    fn close_after_send(&self) {
        self.end(LinkEnd::Graceful);
    }

    fn close(&self) {
        self.end(LinkEnd::Now);
    }

    fn is_open(&self) -> bool {
        !self.sh.closed.load(Ordering::Acquire) && self.conn.is_open()
    }

    fn queued_bytes(&self) -> usize {
        self.sh.queued.load(Ordering::Acquire)
    }
}

/// Pushed responses outstanding per request; further promises are refused.
const MAX_PUSHES_PER_STREAM: u32 = 32;

type Callback = Box<dyn FnOnce(Outcome) + Send>;
type EventCb = Box<dyn FnMut(H2Event<'_>) + Send>;

/// What a streamed request ([`H2Client::open`]) reports as the response arrives.
pub enum H2Event<'a> {
    /// The response head.
    Head {
        /// Status code.
        status: u16,
        /// Header fields.
        headers: &'a Headers,
    },
    /// Body bytes, as they arrive.
    Data(&'a [u8]),
    /// Trailer fields.
    Trailers(&'a Headers),
    /// The response is complete.
    End,
    /// The stream failed (reset, connection lost).
    Error(ClientError),
}

impl<'a> std::fmt::Debug for H2Event<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Event").finish_non_exhaustive()
    }
}

/// Request body still to be produced for a streamed request.
struct UpShared {
    q: Mutex<(VecDeque<Vec<u8>>, bool)>,
    sid: Mutex<Option<u32>>,
}

/// The request body of a streamed request: write pieces, then finish. Usable from any thread.
pub struct H2Upload {
    conn: Conn<H2Conn>,
    up: Arc<UpShared>,
}

impl std::fmt::Debug for H2Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Upload").finish_non_exhaustive()
    }
}

impl H2Upload {
    fn kick(&self) -> bool {
        let up = self.up.clone();
        self.conn
            .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.pump(c, &up))
            .is_ok()
    }

    /// Queues body bytes. `false` if the connection is gone.
    pub fn write(&self, data: &[u8]) -> bool {
        self.up
            .q
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .push_back(data.to_vec());
        self.kick()
    }

    /// Ends the request body.
    pub fn finish(&self) -> bool {
        self.up.q.lock().unwrap_or_else(|p| p.into_inner()).1 = true;
        self.kick()
    }
}

/// A connection to an HTTP/2 server. Cheap to clone.
#[derive(Debug, Clone)]
pub struct H2Client {
    conn: Conn<H2Conn>,
}

impl H2Client {
    /// Connects (prior knowledge, or TLS with ALPN `h2` when `tls` is given: the client config's
    /// `alpn_protocols` must contain `h2`), then calls `ready`.
    pub fn dial(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(TlsClientConfig, &str)>,
        opts: H2Options,
        ready: impl FnOnce(Result<H2Client, io::Error>) + Send + 'static,
    ) {
        let ready: Arc<Mutex<Option<ReadyCb>>> = Arc::new(Mutex::new(Some(Box::new(ready))));
        let fail = {
            let ready = ready.clone();
            move |e: io::Error| {
                let taken = ready.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(cb) = taken {
                    cb(Err(e));
                }
            }
        };
        let acceptor = H2Acceptor { opts, ready };
        match tls {
            Some((cfg, host)) => match Tls::client(cfg, host, acceptor) {
                Ok(a) => engine.dial(addr, a, fail),
                Err(e) => fail(e),
            },
            None => engine.dial(addr, acceptor, fail),
        }
    }

    /// Like [`dial`](Self::dial), waiting for the result (10 s).
    pub fn dial_blocking(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(TlsClientConfig, &str)>,
        opts: H2Options,
    ) -> io::Result<H2Client> {
        let (tx, rx) = mpsc::channel();
        H2Client::dial(engine, addr, tls, opts, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "h2 connect timed out"))?
    }

    /// Sends a request on a new stream; `done` is called once with the outcome. With
    /// [`ClientRequest::timeout`], the stream is reset (`CANCEL`) and the request fails with
    /// [`ClientError::Timeout`] when it passes (`done` then runs on the timer thread).
    pub fn request(&self, req: ClientRequest, done: impl FnOnce(Outcome) + Send + 'static) {
        let timeout = req.timeout;
        let mut done: Callback = Box::new(done);
        // The stream the request got (0 until started), for the timeout to cancel.
        let sid = Arc::new(AtomicU32::new(0));
        if let Some(d) = timeout {
            let once = Arc::new(Mutex::new(Some(done)));
            let (o2, sid2, conn) = (once.clone(), sid.clone(), self.conn.clone());
            crate::timer::after(d, move || {
                let cb = o2.lock().unwrap_or_else(|p| p.into_inner()).take();
                let Some(cb) = cb else { return };
                let id = sid2.load(Ordering::Acquire);
                if id != 0 {
                    let _ =
                        conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.cancel(c, id));
                }
                cb(Err(ClientError::Timeout));
            });
            done = Box::new(move |r| {
                let cb = once.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(cb) = cb {
                    cb(r);
                }
            });
        }
        let slot = Arc::new(Mutex::new(Some((req, done))));
        let s2 = slot.clone();
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some((req, cb)) = taken {
                    let id = h.next_id;
                    h.start(c, req, cb);
                    if h.streams.contains_key(&id) {
                        sid.store(id, Ordering::Release);
                    }
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some((_, cb)) = taken {
                cb(Err(ClientError::Closed));
            }
        }
    }

    /// Starts a request whose body is written afterwards through the returned [`H2Upload`] and
    /// whose response is reported piece by piece to `on_event` (gRPC streaming, uploads of
    /// unknown size). `req.body`, if any, is sent first.
    pub fn open(
        &self,
        mut req: ClientRequest,
        on_event: impl FnMut(H2Event<'_>) + Send + 'static,
    ) -> H2Upload {
        let up = Arc::new(UpShared {
            q: Mutex::new((VecDeque::new(), false)),
            sid: Mutex::new(None),
        });
        let first = std::mem::take(&mut req.body);
        if !first.is_empty() {
            up.q.lock()
                .unwrap_or_else(|p| p.into_inner())
                .0
                .push_back(first);
        }
        let slot = Arc::new(Mutex::new(Some((req, Box::new(on_event) as EventCb))));
        let (s2, up2) = (slot.clone(), up.clone());
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some((req, ev)) = taken {
                    h.start_full(c, req, None, Some((up2, ev)));
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some((_, mut ev)) = taken {
                ev(H2Event::Error(ClientError::Closed));
            }
        }
        H2Upload {
            conn: self.conn.clone(),
            up,
        }
    }

    /// Sends a request and returns a handle to wait on or await.
    pub fn send(&self, req: ClientRequest) -> ResponseFuture {
        let shared = FutureShared::new();
        let s = shared.clone();
        self.request(req, move |r| s.complete(r));
        ResponseFuture { shared }
    }

    /// Opens a WebSocket at `url` (`http`, `https`, `ws` or `wss`; the scheme only names the
    /// `:scheme` sent, the connection is this one) on a new stream of this connection (RFC 8441:
    /// an extended CONNECT, whose stream then carries the WebSocket), served by `handler` as an
    /// `only_ws::client` connection is: callbacks on the connection's I/O thread, [`WsSender`]
    /// to send from any thread. It waits for the server's SETTINGS first. `done` gets the
    /// sender once the server accepted (`on_open` has run), or why not:
    /// [`ClientError::Status`] for a refusal, [`ClientError::Protocol`] when the server does not
    /// allow extended CONNECT, [`ClientError::Timeout`] past [`H2WsOptions::timeout`].
    ///
    /// The stream's window paces what is sent; sends fail with `Overloaded` past
    /// [`H2WsOptions::max_queued_bytes`] queued. A reset stream or a lost connection is a close
    /// without handshake (1006).
    pub fn websocket(
        &self,
        url: &str,
        opts: &H2WsOptions,
        handler: impl WsHandler,
        done: impl FnOnce(Result<WsSender, ClientError>) + Send + 'static,
    ) {
        let url = match url.split_once("://") {
            Some(("ws", rest)) => format!("http://{rest}"),
            Some(("wss", rest)) => format!("https://{rest}"),
            _ => url.to_owned(),
        };
        let mut fields = vec![("sec-websocket-version".to_owned(), "13".to_owned())];
        if !opts.protocols.is_empty() {
            fields.push(("sec-websocket-protocol".into(), opts.protocols.join(", ")));
        }
        let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
        if let Some(p) = &pmd {
            fields.push(("sec-websocket-extensions".into(), p.header()));
        }
        if let Some(o) = &opts.origin {
            fields.push(("origin".into(), o.clone()));
        }
        for (n, v) in &opts.headers {
            let lower = n.to_ascii_lowercase();
            let hop = matches!(
                lower.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "te"
                    | "content-length"
            );
            if !hop && !lower.starts_with("sec-websocket-") && lower != "origin" {
                fields.push((lower, v.replace(['\r', '\n'], "")));
            }
        }
        let once = WsOnce(Arc::new(Mutex::new(Some(Box::new(done) as WsDone))));
        let sid = Arc::new(AtomicU32::new(0));
        {
            let (once, sid, conn) = (once.clone(), sid.clone(), self.conn.clone());
            crate::timer::after(opts.timeout, move || {
                let Some(cb) = once.take() else { return };
                let id = sid.load(Ordering::Acquire);
                if id != 0 {
                    let _ =
                        conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.cancel(c, id));
                }
                cb(Err(ClientError::Timeout));
            });
        }
        let open = Box::new(WsOpen {
            url,
            fields,
            handler: Box::new(handler),
            cfg: opts.config.clone(),
            pmd,
            protocols: opts.protocols.clone(),
            close_timeout: opts.close_timeout,
            max_queued: opts.max_queued_bytes,
            done: once,
            sid,
        });
        let slot = Arc::new(Mutex::new(Some(open)));
        let s2 = slot.clone();
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(w) = taken {
                    h.ws_start(c, w);
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some(w) = taken {
                w.done.fail(ClientError::Closed);
            }
        }
    }

    /// [`websocket`](Self::websocket), waiting for the outcome (at most
    /// [`H2WsOptions::timeout`]).
    pub fn websocket_blocking(
        &self,
        url: &str,
        opts: &H2WsOptions,
        handler: impl WsHandler,
    ) -> Result<WsSender, ClientError> {
        let (tx, rx) = mpsc::channel();
        self.websocket(url, opts, handler, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(opts.timeout + Duration::from_secs(1))
            .map_err(|_| ClientError::Timeout)?
    }

    /// Whether the connection can still take requests.
    pub fn is_open(&self) -> bool {
        self.conn.is_open()
    }

    /// Closes the connection after sending GOAWAY.
    pub fn close(&self) {
        let _ = self.conn.spawn_blocking(
            || (),
            |h: &mut H2Conn, c, ()| {
                let mut out = Vec::new();
                let mut p = 0u32.to_be_bytes().to_vec();
                p.extend_from_slice(&err::NO_ERROR.to_be_bytes());
                frame(&mut out, ty::GOAWAY, 0, 0, &p);
                let _ = c.send_owned(out);
                h.fail_all(ClientError::Closed);
                c.close_after_send();
            },
        );
    }
}

type ReadyCb = Box<dyn FnOnce(Result<H2Client, io::Error>) + Send>;

struct H2Acceptor {
    opts: H2Options,
    ready: Arc<Mutex<Option<ReadyCb>>>,
}

impl Acceptor for H2Acceptor {
    type Handler = H2Conn;

    fn on_open(&self, c: &Conn<H2Conn>) -> H2Conn {
        let h = H2Conn::new(self.opts.clone());
        // Preface, our SETTINGS and a bigger connection window go out first.
        let mut out = PREFACE.to_vec();
        let mut p = Vec::new();
        for (id, v) in [
            (2u16, u32::from(self.opts.enable_push)),
            (4, self.opts.initial_window),
            (6, self.opts.max_header_list),
        ] {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        frame(&mut out, ty::SETTINGS, 0, 0, &p);
        let extra = self.opts.conn_window.saturating_sub(DEFAULT_WINDOW as u32);
        if extra > 0 {
            frame(&mut out, ty::WINDOW_UPDATE, 0, 0, &extra.to_be_bytes());
        }
        let _ = c.send_owned(out);
        let taken = self.ready.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(cb) = taken {
            cb(Ok(H2Client { conn: c.clone() }));
        }
        h
    }
}

struct CStream {
    /// The request URL (the pushed path for a pushed stream).
    url: String,
    cb: Option<Callback>,
    status: u16,
    headers: Headers,
    body: Vec<u8>,
    trailers: Headers,
    got_head: bool,
    ended: bool,
    send_window: i64,
    recv_window: i64,
    /// Request body still to send.
    upload: VecDeque<u8>,
    upload_done: bool,
    /// More request body may still be written (streamed requests).
    upload_open: bool,
    /// Streamed requests report the response here instead of buffering it.
    events: Option<EventCb>,
    head_only: bool,
    /// For pushed streams: the path promised, and the stream that carried the promise.
    pushed_path: Option<String>,
    parent: Option<u32>,
    /// Pushed responses still outstanding for this (parent) stream.
    pending_pushes: u32,
    pushed: Vec<(String, ClientResponse)>,
    /// A WebSocket (extended CONNECT) carried by this stream.
    ws: Option<Box<CWs>>,
}

/// The connection's handler.
pub struct H2Conn {
    opts: H2Options,
    rbuf: Vec<u8>,
    dec: Decoder,
    enc: Encoder,
    streams: HashMap<u32, CStream>,
    next_id: u32,
    conn_send: i64,
    conn_recv: i64,
    remote_initial: i64,
    remote_max_frame: usize,
    /// A header block being assembled: (stream, promised stream, block, end_stream).
    cont: Option<(u32, Option<u32>, Vec<u8>, bool)>,
    goaway: bool,
    dead: bool,
    /// The server's first SETTINGS arrived, and whether it allows extended CONNECT.
    got_settings: bool,
    connect_protocol: bool,
    /// WebSockets waiting for the server's SETTINGS (RFC 8441 §3).
    #[allow(clippy::vec_box)] // each moves on into its stream as it is
    ws_wait: Vec<Box<WsOpen>>,
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

fn window_update(out: &mut Vec<u8>, sid: u32, inc: u32) {
    if inc > 0 {
        frame(out, ty::WINDOW_UPDATE, 0, sid, &inc.to_be_bytes());
    }
}

impl H2Conn {
    fn new(opts: H2Options) -> H2Conn {
        H2Conn {
            conn_recv: DEFAULT_WINDOW
                + i64::from(opts.conn_window.saturating_sub(DEFAULT_WINDOW as u32)),
            opts,
            rbuf: Vec::new(),
            dec: Decoder::new(),
            enc: Encoder::new(),
            streams: HashMap::new(),
            next_id: 1,
            conn_send: DEFAULT_WINDOW,
            remote_initial: DEFAULT_WINDOW,
            remote_max_frame: DEFAULT_FRAME as usize,
            cont: None,
            goaway: false,
            dead: false,
            got_settings: false,
            connect_protocol: false,
            ws_wait: Vec::new(),
        }
    }

    fn start(&mut self, c: &Conn<Self>, req: ClientRequest, cb: Callback) {
        self.start_full(c, req, Some(cb), None);
    }

    /// Abandons stream `sid` (its request timed out): reset it and forget it.
    fn cancel(&mut self, c: &Conn<Self>, sid: u32) {
        if self.streams.remove(&sid).is_some() && !self.dead {
            let mut out = Vec::new();
            frame(&mut out, ty::RST_STREAM, 0, sid, &err::CANCEL.to_be_bytes());
            let _ = c.send_owned(out);
        }
    }

    fn start_full(
        &mut self,
        c: &Conn<Self>,
        req: ClientRequest,
        cb: Option<Callback>,
        streaming: Option<(Arc<UpShared>, EventCb)>,
    ) {
        let fail =
            |cb: Option<Callback>, streaming: Option<(Arc<UpShared>, EventCb)>, e: ClientError| {
                if let Some(cb) = cb {
                    cb(Err(e));
                } else if let Some((_, mut ev)) = streaming {
                    ev(H2Event::Error(e));
                }
            };
        if self.dead || self.goaway {
            return fail(cb, streaming, ClientError::Closed);
        }
        let pu = match parse_url(&req.url) {
            Ok(p) => p,
            Err(e) => return fail(cb, streaming, e),
        };
        let is_stream = streaming.is_some();
        let sid = self.next_id;
        self.next_id += 2;
        let mut list: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), req.method.as_str().as_bytes().to_vec()),
            (
                b":scheme".to_vec(),
                (if pu.key.tls { "https" } else { "http" })
                    .as_bytes()
                    .to_vec(),
            ),
            (b":authority".to_vec(), pu.host_header.clone().into_bytes()),
            (b":path".to_vec(), pu.target.into_bytes()),
        ];
        let mut has_cl = false;
        for (n, v) in req.headers.iter() {
            let n = n.to_ascii_lowercase();
            if matches!(
                n.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
            ) {
                continue;
            }
            has_cl |= n == "content-length";
            list.push((n.into_bytes(), v.replace(['\r', '\n'], "").into_bytes()));
        }
        if !has_cl
            && !is_stream
            && (!req.body.is_empty()
                || matches!(req.method, Method::Post | Method::Put | Method::Patch))
        {
            list.push((
                b"content-length".to_vec(),
                req.body.len().to_string().into_bytes(),
            ));
        }
        if !list.iter().any(|(n, _)| n == b"user-agent") {
            list.push((b"user-agent".to_vec(), b"only-http".to_vec()));
        }
        let block = self
            .enc
            .encode(list.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut out = Vec::new();
        let end_now = req.body.is_empty() && !is_stream;
        self.header_block(&mut out, ty::HEADERS, sid, &[], &block, end_now);
        let head_only = req.method == Method::Head;
        let (up, events) = match streaming {
            Some((u, e)) => (Some(u), Some(e)),
            None => (None, None),
        };
        let mut st = CStream {
            url: req.url.clone(),
            cb,
            status: 0,
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
            got_head: false,
            ended: false,
            send_window: self.remote_initial,
            recv_window: i64::from(self.opts.initial_window),
            upload: req.body.into(),
            upload_done: false,
            upload_open: is_stream,
            events,
            head_only,
            pushed_path: None,
            parent: None,
            pending_pushes: 0,
            pushed: Vec::new(),
            ws: None,
        };
        st.upload_done = st.upload.is_empty() && !is_stream;
        self.streams.insert(sid, st);
        self.send_upload(sid, &mut out);
        let _ = c.send_owned(out);
        if let Some(up) = up {
            *up.sid.lock().unwrap_or_else(|p| p.into_inner()) = Some(sid);
            self.pump(c, &up);
        }
    }

    /// Starts a WebSocket's extended CONNECT, once the server's SETTINGS allow it.
    fn ws_start(&mut self, c: &Conn<Self>, w: Box<WsOpen>) {
        if self.dead || self.goaway {
            return w.done.fail(ClientError::Closed);
        }
        if !self.got_settings {
            self.ws_wait.push(w);
            return;
        }
        if !self.connect_protocol {
            return w.done.fail(ClientError::Protocol(
                "server does not allow extended CONNECT",
            ));
        }
        if w.done.0.lock().unwrap_or_else(|p| p.into_inner()).is_none() {
            return; // timed out while waiting for the SETTINGS
        }
        let pu = match parse_url(&w.url) {
            Ok(p) => p,
            Err(e) => return w.done.fail(e),
        };
        let sid = self.next_id;
        self.next_id += 2;
        let scheme: &[u8] = if pu.key.tls { b"https" } else { b"http" };
        let mut list: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", scheme),
            (b":authority", pu.host_header.as_bytes()),
            (b":path", pu.target.as_bytes()),
        ];
        for (n, v) in &w.fields {
            list.push((n.as_bytes(), v.as_bytes()));
        }
        if !w.fields.iter().any(|(n, _)| n == "user-agent") {
            list.push((b"user-agent", b"only-http"));
        }
        let block = self.enc.encode(list);
        let mut out = Vec::new();
        self.header_block(&mut out, ty::HEADERS, sid, &[], &block, false);
        w.sid.store(sid, Ordering::Release);
        self.streams.insert(
            sid,
            CStream {
                url: String::new(),
                cb: None,
                status: 0,
                headers: Headers::new(),
                body: Vec::new(),
                trailers: Headers::new(),
                got_head: false,
                ended: false,
                send_window: self.remote_initial,
                recv_window: i64::from(self.opts.initial_window),
                upload: VecDeque::new(),
                upload_done: false,
                upload_open: true,
                events: None,
                head_only: false,
                pushed_path: None,
                parent: None,
                pending_pushes: 0,
                pushed: Vec::new(),
                ws: Some(Box::new(CWs(WsState::Opening(w)))),
            },
        );
        let _ = c.send_owned(out);
    }

    /// The server answered a WebSocket's extended CONNECT: check the answer, start the session.
    fn ws_answer(&mut self, c: &Conn<Self>, sid: u32, status: u16, hs: &Headers) {
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        let Some(WsState::Opening(w)) = st
            .ws
            .as_deref_mut()
            .map(|w| std::mem::replace(&mut w.0, WsState::Gone))
        else {
            return;
        };
        let checked = (|| {
            if !(200..300).contains(&status) {
                return Err(ClientError::Status(status));
            }
            let mut protos = hs.get_all("sec-websocket-protocol");
            let protocol = match (protos.next(), protos.next()) {
                (None, _) => None,
                (Some(p), None) if w.protocols.iter().any(|o| o == p) => Some(p.to_owned()),
                _ => {
                    return Err(ClientError::Protocol(
                        "server selected a subprotocol that was not offered",
                    ));
                }
            };
            let pmd = match &w.pmd {
                Some(offer) => offer
                    .accept_response(hs.get_all("sec-websocket-extensions"))
                    .map_err(ClientError::Protocol)?,
                None => {
                    if hs
                        .get_all("sec-websocket-extensions")
                        .any(|v| !v.is_empty())
                    {
                        return Err(ClientError::Protocol(
                            "server accepted an extension that was not offered",
                        ));
                    }
                    None
                }
            };
            Ok((protocol, pmd))
        })();
        let done = w.done.take();
        let (protocol, pmd, cb) = match (checked, done) {
            (Ok((protocol, pmd)), Some(cb)) => (protocol, pmd, cb),
            (Err(e), Some(cb)) => {
                self.cancel(c, sid);
                return cb(Err(e));
            }
            // Timed out meanwhile: nobody waits for it.
            (_, None) => return self.cancel(c, sid),
        };
        let WsOpen {
            handler,
            cfg,
            close_timeout,
            max_queued,
            ..
        } = *w;
        let sh = Arc::new(LinkShared {
            q: Mutex::new(LinkQ::default()),
            queued: AtomicUsize::new(0),
            max: max_queued,
            closed: AtomicBool::new(false),
        });
        let link: Arc<dyn WsLink> = Arc::new(ClientLink {
            conn: c.clone(),
            sid,
            sh: sh.clone(),
        });
        let mut ws = WsSession::client_with_link(link, &cfg, pmd, handler, protocol, close_timeout);
        let sender = ws.sender().clone();
        ws.open();
        if let Some(st) = self.streams.get_mut(&sid) {
            st.ws = Some(Box::new(CWs(WsState::Open(Box::new(ws), sh))));
        }
        cb(Ok(sender));
    }

    /// The server ended its half of a WebSocket's stream: the session's transport is closed,
    /// and our half ends after what is queued.
    fn ws_peer_ended(&mut self, c: &Conn<Self>, sid: u32) {
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        st.ended = true;
        let sh = match st.ws.as_deref_mut() {
            Some(CWs(WsState::Open(s, sh))) => {
                s.on_transport_closed();
                sh.clone()
            }
            _ => {
                // Ended before it opened.
                return self.cancel(c, sid);
            }
        };
        self.ws_pump(c, sid, &sh);
    }

    /// Moves what a WebSocket's sender queued into its stream, sends what the windows allow,
    /// and ends or resets the stream as asked.
    fn ws_pump(&mut self, c: &Conn<Self>, sid: u32, sh: &Arc<LinkShared>) {
        let (chunks, end) = {
            let mut q = sh.q.lock().unwrap_or_else(|p| p.into_inner());
            q.scheduled = false;
            (std::mem::take(&mut q.chunks), q.end)
        };
        let Some(st) = self.streams.get_mut(&sid) else {
            sh.queued.store(0, Ordering::Release);
            return;
        };
        for ch in chunks {
            st.upload.extend(ch);
        }
        match end {
            LinkEnd::No => {}
            LinkEnd::Graceful => st.upload_open = false,
            LinkEnd::Now if st.ended => st.upload_open = false,
            LinkEnd::Now => {
                sh.queued.store(0, Ordering::Release);
                return self.cancel(c, sid);
            }
        }
        let mut out = Vec::new();
        self.send_upload(sid, &mut out);
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
        self.ws_finish(sid);
    }

    /// A WebSocket's stream whose halves have both ended is done.
    fn ws_finish(&mut self, sid: u32) {
        if self
            .streams
            .get(&sid)
            .is_some_and(|s| s.ws.is_some() && s.ended && s.upload_done)
        {
            self.streams.remove(&sid);
        }
    }

    /// Moves what an [`H2Upload`] queued into its stream and sends what the windows allow.
    fn pump(&mut self, c: &Conn<Self>, up: &Arc<UpShared>) {
        let Some(sid) = *up.sid.lock().unwrap_or_else(|p| p.into_inner()) else {
            return; // not started yet: the start drains the queue
        };
        let (chunks, finished) = {
            let mut q = up.q.lock().unwrap_or_else(|p| p.into_inner());
            (std::mem::take(&mut q.0), q.1)
        };
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        for ch in chunks {
            st.upload.extend(ch);
        }
        if finished {
            st.upload_open = false;
        }
        let mut out = Vec::new();
        self.send_upload(sid, &mut out);
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
    }

    fn header_block(
        &self,
        out: &mut Vec<u8>,
        ty_: u8,
        sid: u32,
        extra: &[u8],
        block: &[u8],
        end_stream: bool,
    ) {
        let max = self.remote_max_frame;
        let cap = max.saturating_sub(extra.len());
        let (first, mut rest) = block.split_at(block.len().min(cap));
        let mut flags = if end_stream { flag::END_STREAM } else { 0 };
        if rest.is_empty() {
            flags |= flag::END_HEADERS;
        }
        let mut p = extra.to_vec();
        p.extend_from_slice(first);
        frame(out, ty_, flags, sid, &p);
        while !rest.is_empty() {
            let (chunk, r) = rest.split_at(rest.len().min(max));
            rest = r;
            frame(
                out,
                ty::CONTINUATION,
                if rest.is_empty() {
                    flag::END_HEADERS
                } else {
                    0
                },
                sid,
                chunk,
            );
        }
    }

    /// Sends as much of the stream's request body as the windows allow.
    fn send_upload(&mut self, sid: u32, out: &mut Vec<u8>) {
        loop {
            let Some(st) = self.streams.get_mut(&sid) else {
                return;
            };
            if st.upload_done {
                return;
            }
            if st.upload.is_empty() {
                if st.upload_open {
                    return; // wait for more body
                }
                st.upload_done = true;
                frame(out, ty::DATA, flag::END_STREAM, sid, &[]);
                return;
            }
            let allow = st
                .send_window
                .min(self.conn_send)
                .min(self.remote_max_frame as i64);
            if allow <= 0 {
                return;
            }
            let n = st.upload.len().min(allow as usize);
            let data: Vec<u8> = st.upload.drain(..n).collect();
            if let Some(CWs(WsState::Open(_, sh))) = st.ws.as_deref() {
                sh.queued.fetch_sub(n, Ordering::AcqRel);
            }
            let last = st.upload.is_empty() && !st.upload_open;
            st.send_window -= n as i64;
            self.conn_send -= n as i64;
            if last {
                st.upload_done = true;
            }
            frame(
                out,
                ty::DATA,
                if last { flag::END_STREAM } else { 0 },
                sid,
                &data,
            );
            if last {
                return;
            }
        }
    }

    fn flush_uploads(&mut self, c: &Conn<Self>) {
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.upload_done)
            .map(|(i, _)| *i)
            .collect();
        let mut out = Vec::new();
        for &id in &ids {
            self.send_upload(id, &mut out);
        }
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
        for id in ids {
            self.ws_finish(id);
        }
    }

    fn fail_all(&mut self, e: ClientError) {
        self.dead = true;
        let msg = |e: &ClientError| match e {
            ClientError::Protocol(m) => ClientError::Protocol(m),
            ClientError::TooLarge(m) => ClientError::TooLarge(m),
            ClientError::Timeout => ClientError::Timeout,
            ClientError::Io(x) => ClientError::Io(io::Error::new(x.kind(), x.to_string())),
            _ => ClientError::Closed,
        };
        for (_, mut s) in self.streams.drain() {
            if let Some(cb) = s.cb.take() {
                cb(Err(msg(&e)));
            } else if let Some(ev) = s.events.as_mut() {
                ev(H2Event::Error(msg(&e)));
            } else if let Some(w) = s.ws.as_deref_mut() {
                w.fail(msg(&e));
            }
        }
        for w in std::mem::take(&mut self.ws_wait) {
            w.done.fail(msg(&e));
        }
    }

    fn conn_error(&mut self, c: &Conn<Self>, code: u32, why: &'static str) {
        let mut out = Vec::new();
        let mut p = 0u32.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        frame(&mut out, ty::GOAWAY, 0, 0, &p);
        let _ = c.send_owned(out);
        self.fail_all(ClientError::Protocol(why));
        c.close_after_send();
    }

    /// Resets stream `sid` (`CANCEL`) and fails its request with `e`.
    fn abort_stream(&mut self, out: &mut Vec<u8>, sid: u32, e: ClientError) {
        let Some(mut s) = self.streams.remove(&sid) else {
            return;
        };
        frame(out, ty::RST_STREAM, 0, sid, &err::CANCEL.to_be_bytes());
        if let Some(cb) = s.cb.take() {
            cb(Err(e));
        } else if let Some(ev) = s.events.as_mut() {
            ev(H2Event::Error(e));
        } else if let Some(w) = s.ws.as_deref_mut() {
            w.fail(e);
        }
        if let Some(parent) = s.parent {
            if let Some(pp) = self.streams.get_mut(&parent) {
                pp.pending_pushes = pp.pending_pushes.saturating_sub(1);
            }
            self.try_finish(parent);
        }
    }

    /// Delivers the response of `sid` if it is complete (and its pushes are).
    fn try_finish(&mut self, sid: u32) {
        let Some(st) = self.streams.get(&sid) else {
            return;
        };
        if !st.ended || st.pending_pushes > 0 {
            return;
        }
        let mut st = self.streams.remove(&sid).expect("present");
        if let Some(ev) = st.events.as_mut() {
            ev(H2Event::End);
            return;
        }
        let resp = ClientResponse {
            status: st.status,
            reason: String::new(),
            headers: std::mem::take(&mut st.headers),
            body: std::mem::take(&mut st.body),
            trailers: std::mem::take(&mut st.trailers),
            pushed: std::mem::take(&mut st.pushed),
            url: std::mem::take(&mut st.url),
        };
        match (st.parent, st.pushed_path.take()) {
            (Some(parent), Some(path)) => {
                if let Some(p) = self.streams.get_mut(&parent) {
                    p.pushed.push((path, resp));
                    p.pending_pushes -= 1;
                }
                self.try_finish(parent);
            }
            _ => {
                if let Some(cb) = st.cb.take() {
                    cb(Ok(resp));
                }
            }
        }
    }

    fn headers_done(
        &mut self,
        c: &Conn<Self>,
        sid: u32,
        promised: Option<u32>,
        block: Vec<u8>,
        end_stream: bool,
    ) {
        // The whole block is decoded even past the limit: HPACK state must stay in step.
        let limit = self.opts.max_header_list as usize;
        let Ok((list, size)) = self.dec.decode_limited(&block, limit) else {
            return self.conn_error(c, err::COMPRESSION, "bad header block");
        };
        if let Some(pid) = promised {
            if pid % 2 == 1 || pid == 0 || self.streams.contains_key(&pid) {
                return self.conn_error(c, err::PROTOCOL, "bad promised stream");
            }
            let refuse = !self.opts.enable_push
                || size > limit
                || self
                    .streams
                    .get(&sid)
                    .is_none_or(|p| p.pending_pushes >= MAX_PUSHES_PER_STREAM);
            // A pushed request: remember which path it is for.
            let path = list
                .iter()
                .find(|(n, _)| n == b":path")
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            if refuse {
                let mut out = Vec::new();
                frame(
                    &mut out,
                    ty::RST_STREAM,
                    0,
                    pid,
                    &err::REFUSED_STREAM.to_be_bytes(),
                );
                let _ = c.send_owned(out);
                return;
            }
            let Some(parent) = self.streams.get_mut(&sid) else {
                return;
            };
            parent.pending_pushes += 1;
            self.streams.insert(
                pid,
                CStream {
                    url: path.clone(),
                    cb: None,
                    status: 0,
                    headers: Headers::new(),
                    body: Vec::new(),
                    trailers: Headers::new(),
                    got_head: false,
                    ended: false,
                    send_window: 0,
                    recv_window: i64::from(self.opts.initial_window),
                    upload: VecDeque::new(),
                    upload_done: true,
                    upload_open: false,
                    events: None,
                    head_only: false,
                    pushed_path: Some(path),
                    parent: Some(sid),
                    pending_pushes: 0,
                    pushed: Vec::new(),
                    ws: None,
                },
            );
            return;
        }
        if size > limit {
            let mut out = Vec::new();
            self.abort_stream(
                &mut out,
                sid,
                ClientError::TooLarge("response header list too large"),
            );
            if !out.is_empty() {
                let _ = c.send_owned(out);
            }
            return;
        }
        let Some(st) = self.streams.get_mut(&sid) else {
            return; // a reset or unknown stream: the block was decoded to keep HPACK in step
        };
        let mut hs = Headers::new();
        let mut status = 0u16;
        for (n, v) in &list {
            let v = String::from_utf8_lossy(v).into_owned();
            if n == b":status" {
                status = v.parse().unwrap_or(0);
            } else if n.first() != Some(&b':') {
                hs.append(String::from_utf8_lossy(n), v);
            }
        }
        if st.ws.is_some() {
            if !st.got_head && !(100..200).contains(&status) {
                st.got_head = true;
                self.ws_answer(c, sid, status, &hs);
            }
            // Trailers end the server's half like END_STREAM on DATA.
            if end_stream {
                self.ws_peer_ended(c, sid);
            }
            return;
        }
        if !st.got_head {
            if (100..200).contains(&status) {
                return; // interim
            }
            st.got_head = true;
            st.status = status;
            if let Some(ev) = st.events.as_mut() {
                ev(H2Event::Head {
                    status,
                    headers: &hs,
                });
            }
            st.headers = hs;
        } else {
            if let Some(ev) = st.events.as_mut() {
                ev(H2Event::Trailers(&hs));
            }
            st.trailers = hs;
        }
        if end_stream {
            st.ended = true;
            self.try_finish(sid);
        }
    }

    fn handle(&mut self, c: &Conn<Self>, ty_: u8, flags: u8, sid: u32, mut p: Vec<u8>) {
        let mut out = Vec::new();
        if self.cont.is_some() && ty_ != ty::CONTINUATION {
            // RFC 9113 §6.10: a header block is contiguous.
            return self.conn_error(c, err::PROTOCOL, "frame inside a header block");
        }
        match ty_ {
            ty::SETTINGS => {
                if flags & flag::ACK != 0 {
                    return;
                }
                if p.len() % 6 != 0 {
                    return self.conn_error(c, err::FRAME_SIZE, "bad SETTINGS");
                }
                for s in p.chunks_exact(6) {
                    let id = u16::from_be_bytes([s[0], s[1]]);
                    let v = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
                    match id {
                        1 => self.enc.set_max_table_size(v as usize),
                        4 => {
                            if i64::from(v) > MAX_WINDOW {
                                return self.conn_error(c, err::FLOW_CONTROL, "window too large");
                            }
                            let delta = i64::from(v) - self.remote_initial;
                            self.remote_initial = i64::from(v);
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                            }
                        }
                        5 if (DEFAULT_FRAME..(1 << 24)).contains(&v) => {
                            self.remote_max_frame = v as usize;
                        }
                        // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3).
                        8 => self.connect_protocol = v == 1,
                        _ => {}
                    }
                }
                frame(&mut out, ty::SETTINGS, flag::ACK, 0, &[]);
                let _ = c.send_owned(out);
                self.flush_uploads(c);
                if !std::mem::replace(&mut self.got_settings, true) {
                    for w in std::mem::take(&mut self.ws_wait) {
                        self.ws_start(c, w);
                    }
                }
            }
            ty::PING => {
                if flags & flag::ACK == 0 && p.len() == 8 {
                    frame(&mut out, ty::PING, flag::ACK, 0, &p);
                    let _ = c.send_owned(out);
                }
            }
            ty::WINDOW_UPDATE => {
                if p.len() != 4 {
                    return self.conn_error(c, err::FRAME_SIZE, "bad WINDOW_UPDATE");
                }
                let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                if sid == 0 {
                    self.conn_send += inc;
                } else if let Some(st) = self.streams.get_mut(&sid) {
                    st.send_window += inc;
                }
                self.flush_uploads(c);
            }
            ty::GOAWAY => {
                self.goaway = true;
                if p.len() >= 8 {
                    let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                    // Requests above the last processed stream were not and will not be.
                    let doomed: Vec<u32> = self
                        .streams
                        .keys()
                        .copied()
                        .filter(|id| id % 2 == 1 && *id > last)
                        .collect();
                    for id in doomed {
                        if let Some(mut s) = self.streams.remove(&id) {
                            if let Some(cb) = s.cb.take() {
                                cb(Err(ClientError::Closed));
                            }
                        }
                    }
                }
            }
            ty::RST_STREAM => {
                if let Some(mut s) = self.streams.remove(&sid) {
                    let code = if p.len() == 4 {
                        u32::from_be_bytes([p[0], p[1], p[2], p[3]])
                    } else {
                        0
                    };
                    if let Some(ev) = s.events.as_mut() {
                        ev(H2Event::Error(ClientError::Protocol(
                            "stream reset by the server",
                        )));
                    }
                    let why = if code == err::REFUSED_STREAM {
                        "stream refused"
                    } else {
                        "stream reset by the server"
                    };
                    if let Some(cb) = s.cb.take() {
                        cb(Err(ClientError::Protocol(why)));
                    } else if let Some(w) = s.ws.as_deref_mut() {
                        w.fail(ClientError::Protocol(why));
                    }
                    if let Some(parent) = s.parent {
                        if let Some(pp) = self.streams.get_mut(&parent) {
                            pp.pending_pushes = pp.pending_pushes.saturating_sub(1);
                        }
                        self.try_finish(parent);
                    }
                }
            }
            ty::DATA => {
                let total = p.len() as u32;
                let mut start = 0;
                let mut end = p.len();
                if flags & flag::PADDED != 0 && !p.is_empty() {
                    start = 1;
                    end = p.len().saturating_sub(p[0] as usize);
                }
                self.conn_recv -= i64::from(total);
                window_update(&mut out, 0, total);
                self.conn_recv += i64::from(total);
                let end_stream = flags & flag::END_STREAM != 0;
                if let Some(st) = self.streams.get_mut(&sid).filter(|s| s.ws.is_some()) {
                    // A WebSocket's bytes: consumed now, so the window is given back now.
                    if !end_stream {
                        window_update(&mut out, sid, total);
                    }
                    if let (Some(CWs(WsState::Open(ws, _))), true) =
                        (st.ws.as_deref_mut(), start <= end)
                    {
                        ws.on_data(&p[start..end]);
                    }
                    if !out.is_empty() {
                        let _ = c.send_owned(out);
                    }
                    if end_stream {
                        self.ws_peer_ended(c, sid);
                    }
                    return;
                }
                let max_body = self.opts.max_body_bytes;
                let mut too_large = false;
                if let Some(st) = self.streams.get_mut(&sid) {
                    if !st.head_only && start <= end {
                        match st.events.as_mut() {
                            Some(ev) => ev(H2Event::Data(&p[start..end])),
                            None if st.body.len() + (end - start) > max_body => too_large = true,
                            None => st.body.extend_from_slice(&p[start..end]),
                        }
                    }
                    st.recv_window -= i64::from(total);
                    if flags & flag::END_STREAM == 0 {
                        st.recv_window += i64::from(total);
                        window_update(&mut out, sid, total);
                    }
                    if flags & flag::END_STREAM != 0 {
                        st.ended = true;
                    }
                }
                if too_large {
                    self.abort_stream(
                        &mut out,
                        sid,
                        ClientError::TooLarge("response body too large"),
                    );
                    let _ = c.send_owned(out);
                    return;
                }
                if !out.is_empty() {
                    let _ = c.send_owned(out);
                }
                if flags & flag::END_STREAM != 0 {
                    self.try_finish(sid);
                }
            }
            ty::HEADERS | ty::PUSH_PROMISE => {
                let mut block = &p[..];
                if flags & flag::PADDED != 0 && !block.is_empty() {
                    let pad = block[0] as usize;
                    block = &block[1..];
                    block = &block[..block.len().saturating_sub(pad)];
                }
                if ty_ == ty::HEADERS && flags & flag::PRIORITY != 0 && block.len() >= 5 {
                    block = &block[5..];
                }
                let mut promised = None;
                if ty_ == ty::PUSH_PROMISE {
                    if block.len() < 4 {
                        return self.conn_error(c, err::FRAME_SIZE, "short PUSH_PROMISE");
                    }
                    promised = Some(
                        u32::from_be_bytes([block[0], block[1], block[2], block[3]]) & 0x7fff_ffff,
                    );
                    block = &block[4..];
                }
                let end_stream = flags & flag::END_STREAM != 0;
                if flags & flag::END_HEADERS == 0 {
                    self.cont = Some((sid, promised, block.to_vec(), end_stream));
                } else {
                    let b = block.to_vec();
                    self.headers_done(c, sid, promised, b, end_stream);
                }
            }
            ty::CONTINUATION => {
                let Some((s, promised, mut block, end_stream)) = self.cont.take() else {
                    return self.conn_error(c, err::PROTOCOL, "stray CONTINUATION");
                };
                if s != sid {
                    return self.conn_error(c, err::PROTOCOL, "CONTINUATION on another stream");
                }
                block.append(&mut p);
                // Bounded like the server: what a CONTINUATION flood may make us buffer.
                let cap = (self.opts.max_header_list as usize)
                    .saturating_mul(2)
                    .max(1 << 16);
                if block.len() > cap {
                    return self.conn_error(c, err::ENHANCE, "header block too large");
                }
                if flags & flag::END_HEADERS == 0 {
                    self.cont = Some((s, promised, block, end_stream));
                } else {
                    self.headers_done(c, s, promised, block, end_stream);
                }
            }
            _ => {}
        }
    }
}

impl Handler for H2Conn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.dead {
            return;
        }
        self.rbuf.extend_from_slice(data);
        loop {
            if self.rbuf.len() < 9 {
                return;
            }
            let len = u32::from_be_bytes([0, self.rbuf[0], self.rbuf[1], self.rbuf[2]]) as usize;
            // We never raise SETTINGS_MAX_FRAME_SIZE, so the default is the limit (§4.2); this
            // also bounds `rbuf` before a frame is buffered whole.
            if len > DEFAULT_FRAME as usize {
                self.rbuf.clear();
                return self.conn_error(c, err::FRAME_SIZE, "frame too large");
            }
            if self.rbuf.len() < 9 + len {
                return;
            }
            let ty_ = self.rbuf[3];
            let flags = self.rbuf[4];
            let sid = u32::from_be_bytes([self.rbuf[5], self.rbuf[6], self.rbuf[7], self.rbuf[8]])
                & 0x7fff_ffff;
            let payload = self.rbuf[9..9 + len].to_vec();
            self.rbuf.drain(..9 + len);
            self.handle(c, ty_, flags, sid, payload);
            if self.dead {
                return;
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        self.fail_all(ClientError::Closed);
    }
}
