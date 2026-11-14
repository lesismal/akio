//! An HTTP/2 client: one connection multiplexing many concurrent requests, with flow control
//! both ways, trailers and (optionally) server push.
//!
//! ```no_run
//! # use flash::Engine; use flash_http::{client::ClientRequest, h2client::{H2Client, H2Options}};
//! # let engine = Engine::builder().client_threads(1).build().unwrap(); engine.start().unwrap();
//! let c = H2Client::connect_blocking(&engine, "127.0.0.1:8082".parse().unwrap(), None, H2Options::default())
//!     .unwrap();
//! let r = c.send(ClientRequest::get("http://127.0.0.1:8082/")).wait().unwrap();
//! ```
//!
//! Callbacks run on an I/O thread and must not block.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use flash::{
    Acceptor, Conn, Engine, Handler,
    tls::{Tls, rustls},
};
use loona_hpack::{Decoder, Encoder};

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
pub struct H2Options {
    /// Receive window per stream.
    pub initial_window: u32,
    /// Receive window of the connection.
    pub conn_window: u32,
    /// Accept server push (`ClientResponse::pushed` then carries the pushed responses).
    pub enable_push: bool,
}

impl Default for H2Options {
    fn default() -> Self {
        H2Options {
            initial_window: 1 << 20,
            conn_window: 1 << 24,
            enable_push: false,
        }
    }
}

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
    pub fn connect(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(Arc<rustls::ClientConfig>, &str)>,
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

    /// Like [`connect`](Self::connect), waiting for the result (10 s).
    pub fn connect_blocking(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(Arc<rustls::ClientConfig>, &str)>,
        opts: H2Options,
    ) -> io::Result<H2Client> {
        let (tx, rx) = mpsc::channel();
        H2Client::connect(engine, addr, tls, opts, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "h2 connect timed out"))?
    }

    /// Sends a request on a new stream; `done` is called once with the outcome.
    pub fn request(&self, req: ClientRequest, done: impl FnOnce(Outcome) + Send + 'static) {
        let slot = Arc::new(Mutex::new(Some((req, Box::new(done) as Callback))));
        let s2 = slot.clone();
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some((req, cb)) = taken {
                    h.start(c, req, cb);
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
}

/// The connection's handler.
pub struct H2Conn {
    opts: H2Options,
    rbuf: Vec<u8>,
    dec: Decoder<'static>,
    enc: Encoder<'static>,
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
        }
    }

    fn start(&mut self, c: &Conn<Self>, req: ClientRequest, cb: Callback) {
        self.start_full(c, req, Some(cb), None);
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
            list.push((b"user-agent".to_vec(), b"flash-http".to_vec()));
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
        for id in ids {
            self.send_upload(id, &mut out);
        }
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
    }

    fn fail_all(&mut self, e: ClientError) {
        self.dead = true;
        let msg = |e: &ClientError| match e {
            ClientError::Protocol(m) => ClientError::Protocol(m),
            ClientError::Io(x) => ClientError::Io(io::Error::new(x.kind(), x.to_string())),
            _ => ClientError::Closed,
        };
        for (_, mut s) in self.streams.drain() {
            if let Some(cb) = s.cb.take() {
                cb(Err(msg(&e)));
            } else if let Some(ev) = s.events.as_mut() {
                ev(H2Event::Error(msg(&e)));
            }
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
        let Some(list) = crate::hpack::strip_huffman(&block)
            .ok()
            .and_then(|b| self.dec.decode(&b).ok())
        else {
            return self.conn_error(c, err::COMPRESSION, "bad header block");
        };
        if let Some(pid) = promised {
            // A pushed request: remember which path it is for.
            let path = list
                .iter()
                .find(|(n, _)| n == b":path")
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            if !self.opts.enable_push {
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
                },
            );
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
                        _ => {}
                    }
                }
                frame(&mut out, ty::SETTINGS, flag::ACK, 0, &[]);
                let _ = c.send_owned(out);
                self.flush_uploads(c);
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
                    if let Some(cb) = s.cb.take() {
                        cb(Err(ClientError::Protocol(if code == err::REFUSED_STREAM {
                            "stream refused"
                        } else {
                            "stream reset by the server"
                        })));
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
                if let Some(st) = self.streams.get_mut(&sid) {
                    if !st.head_only && start <= end {
                        match st.events.as_mut() {
                            Some(ev) => ev(H2Event::Data(&p[start..end])),
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
                block.append(&mut p);
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

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        self.fail_all(ClientError::Closed);
    }
}
