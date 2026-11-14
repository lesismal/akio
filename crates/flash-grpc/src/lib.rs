#![forbid(unsafe_code)]
//! gRPC on flash: a server ([`GrpcServer`], a `flash-http` service, so it shares the port and
//! HTTP/2 stack with ordinary HTTP) and a client ([`GrpcClient`], on `flash-http`'s HTTP/2
//! client).
//!
//! * Unary, server-streaming, client-streaming and bidirectional calls.
//! * Metadata (headers and trailers), deadlines (`grpc-timeout`), interceptors, gzip message
//!   compression, status codes and messages.
//! * Messages are bytes; with the `prost` feature, [`codec`] converts prost messages.
//!
//! Handlers run on the connection's I/O thread and must not block; the [`Sink`] they get answers
//! from any thread, so slow work goes to the logical pool or another thread.
//!
//! Guide: [gRPC](https://lesismal.github.io/flash/en/protocols/grpc.html)
//! (中文: [gRPC](https://lesismal.github.io/flash/zh-CN/protocols/grpc.html)).

pub mod codec;

use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use flash_http::{
    BodyEvent, BodyMode, BodyStream, Context, Headers, Method, Request, Response, Service,
    client::ClientRequest,
    h2client::{H2Client, H2Event},
};

// ---- status ----------------------------------------------------------------------------------

/// gRPC status codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Code {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl Code {
    fn from_i32(v: i32) -> Code {
        use Code::*;
        [
            Ok,
            Cancelled,
            Unknown,
            InvalidArgument,
            DeadlineExceeded,
            NotFound,
            AlreadyExists,
            PermissionDenied,
            ResourceExhausted,
            FailedPrecondition,
            Aborted,
            OutOfRange,
            Unimplemented,
            Internal,
            Unavailable,
            DataLoss,
            Unauthenticated,
        ]
        .get(v as usize)
        .copied()
        .unwrap_or(Unknown)
    }
}

/// A call's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// Code.
    pub code: Code,
    /// Human-readable message.
    pub message: String,
}

impl Status {
    /// Success.
    pub fn ok() -> Status {
        Status::new(Code::Ok, "")
    }

    /// A status with a message.
    pub fn new(code: Code, message: impl Into<String>) -> Status {
        Status {
            code,
            message: message.into(),
        }
    }

    fn put(&self, h: &mut Headers) {
        h.set("grpc-status", (self.code as i32).to_string());
        if !self.message.is_empty() {
            h.set("grpc-message", pct_encode(&self.message));
        }
    }

    fn from_headers(h: &Headers) -> Option<Status> {
        let code = h.get("grpc-status")?.trim().parse::<i32>().ok()?;
        let msg = h.get("grpc-message").map(pct_decode).unwrap_or_default();
        Some(Status::new(Code::from_i32(code), msg))
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Status {}

/// `grpc-message` percent-encoding (RFC 3986 unreserved stays, as in the gRPC spec: printable
/// ASCII except `%` stays).
fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if (0x20..0x7f).contains(&b) && b != b'%' {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn pct_decode(s: &str) -> String {
    flash_http::message::percent_decode(s).unwrap_or_else(|| s.to_owned())
}

// ---- framing ---------------------------------------------------------------------------------

/// Default largest message (4 MiB, as in grpc-go).
pub const DEFAULT_MAX_MESSAGE: usize = 4 << 20;

fn frame(msg: &[u8], gzip: bool) -> Vec<u8> {
    let (flag, body) = if gzip {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = e.write_all(msg);
        (1u8, e.finish().unwrap_or_default())
    } else {
        (0, msg.to_vec())
    };
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(flag);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Splits a byte stream into messages.
struct Deframer {
    buf: Vec<u8>,
    max: usize,
    gzip: bool,
}

impl Deframer {
    fn new(max: usize, gzip: bool) -> Deframer {
        Deframer {
            buf: Vec::new(),
            max,
            gzip,
        }
    }

    fn feed(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), Status> {
        self.buf.extend_from_slice(data);
        let mut pos = 0;
        while self.buf.len() - pos >= 5 {
            let flag = self.buf[pos];
            let len = u32::from_be_bytes([
                self.buf[pos + 1],
                self.buf[pos + 2],
                self.buf[pos + 3],
                self.buf[pos + 4],
            ]) as usize;
            if len > self.max {
                return Err(Status::new(
                    Code::ResourceExhausted,
                    "message larger than the limit",
                ));
            }
            if self.buf.len() - pos < 5 + len {
                break;
            }
            let body = &self.buf[pos + 5..pos + 5 + len];
            let msg = if flag == 1 {
                if !self.gzip {
                    return Err(Status::new(
                        Code::Internal,
                        "compressed message without grpc-encoding",
                    ));
                }
                let mut d = flate2::read::GzDecoder::new(body).take(self.max as u64 + 1);
                let mut v = Vec::new();
                d.read_to_end(&mut v)
                    .map_err(|_| Status::new(Code::Internal, "bad gzip message"))?;
                if v.len() > self.max {
                    return Err(Status::new(
                        Code::ResourceExhausted,
                        "message larger than the limit",
                    ));
                }
                v
            } else {
                body.to_vec()
            };
            out.push(msg);
            pos += 5 + len;
        }
        self.buf.drain(..pos);
        Ok(())
    }

    fn leftover(&self) -> bool {
        !self.buf.is_empty()
    }
}

fn parse_timeout(v: &str) -> Option<Duration> {
    let (n, unit) = v.split_at(v.len().checked_sub(1)?);
    let n: u64 = n.parse().ok()?;
    Some(match unit {
        "H" => Duration::from_secs(n * 3600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    })
}

fn format_timeout(d: Duration) -> String {
    format!("{}m", d.as_millis().max(1))
}

// ---- timers ----------------------------------------------------------------------------------

type TimerFn = Box<dyn FnOnce() + Send>;

fn after(at: Instant, f: impl FnOnce() + Send + 'static) {
    struct T {
        q: Mutex<Vec<(Instant, TimerFn)>>,
        cv: Condvar,
    }
    static TIMERS: std::sync::OnceLock<&'static T> = std::sync::OnceLock::new();
    let t = TIMERS.get_or_init(|| {
        let t: &'static T = Box::leak(Box::new(T {
            q: Mutex::new(Vec::new()),
            cv: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("flash-grpc-deadlines".into())
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
                    let next = g.iter().map(|(a, _)| *a).min();
                    g = match next {
                        Some(a) => {
                            t.cv.wait_timeout(g, a.saturating_duration_since(now))
                                .unwrap_or_else(|p| p.into_inner())
                                .0
                        }
                        None => t.cv.wait(g).unwrap_or_else(|p| p.into_inner()),
                    };
                }
            })
            .expect("deadline thread");
        t
    });
    t.q.lock()
        .unwrap_or_else(|p| p.into_inner())
        .push((at, Box::new(f)));
    t.cv.notify_one();
}

// ---- server ----------------------------------------------------------------------------------

/// The request side of a call: its metadata.
#[derive(Clone, Debug)]
pub struct Metadata {
    /// The full method path, `/package.Service/Method`.
    pub method: String,
    /// Request headers (custom metadata included, binary `-bin` values as sent).
    pub headers: Headers,
    /// The deadline the client set, if any.
    pub deadline: Option<Instant>,
}

impl Metadata {
    /// A metadata value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key)
    }
}

enum Out {
    /// Response not started: headers still settable.
    Pending(flash_http::Detached),
    Streaming(BodyStream),
    Done,
}

struct SinkInner {
    out: Mutex<Out>,
    headers: Mutex<Headers>,
    trailers: Mutex<Headers>,
    gzip: bool,
    finished: AtomicBool,
}

/// Sends a call's response messages and ends it with a status. Cheap to clone, usable from any
/// thread. Dropping every clone without [`finish`](Self::finish) ends the call with `INTERNAL`.
#[derive(Clone)]
pub struct Sink(Arc<SinkInner>);

impl Sink {
    /// Adds response header metadata (before the first message only).
    pub fn set_header(&self, key: &str, value: &str) {
        self.0
            .headers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set(key, value);
    }

    /// Adds trailer metadata.
    pub fn set_trailer(&self, key: &str, value: &str) {
        self.0
            .trailers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set(key, value);
    }

    /// Sends the response head (with the headers set so far) if it has not gone out yet.
    fn start(&self, out: &mut Out) {
        if let Out::Pending(_) = out {
            let Out::Pending(d) = std::mem::replace(out, Out::Done) else {
                unreachable!()
            };
            let mut h =
                std::mem::take(&mut *self.0.headers.lock().unwrap_or_else(|p| p.into_inner()));
            h.set("content-type", "application/grpc");
            if self.0.gzip {
                h.set("grpc-encoding", "gzip");
            }
            if let Some(s) = d.stream_response(200, h) {
                *out = Out::Streaming(s);
            }
        }
    }

    /// Sends one response message. `false` once the call is over.
    pub fn send(&self, msg: &[u8]) -> bool {
        let mut out = self.0.out.lock().unwrap_or_else(|p| p.into_inner());
        self.start(&mut out);
        match &*out {
            Out::Streaming(s) => s.write(&frame(msg, self.0.gzip)).is_ok(),
            _ => false,
        }
    }

    /// Ends the call with `status` (trailers carry it).
    pub fn finish(&self, status: Status) {
        if self.0.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut trailers =
            std::mem::take(&mut *self.0.trailers.lock().unwrap_or_else(|p| p.into_inner()));
        status.put(&mut trailers);
        let mut out = self.0.out.lock().unwrap_or_else(|p| p.into_inner());
        match std::mem::replace(&mut *out, Out::Done) {
            Out::Streaming(s) => s.finish_with_trailers(trailers),
            Out::Pending(d) => {
                // No message was sent: a trailers-only response (one HEADERS frame).
                let mut r = Response::new(200);
                r.headers =
                    std::mem::take(&mut *self.0.headers.lock().unwrap_or_else(|p| p.into_inner()));
                r.headers.set("content-type", "application/grpc");
                for (k, v) in trailers.iter() {
                    r.headers.set(k, v);
                }
                d.respond(r);
            }
            Out::Done => {}
        }
    }

    /// Whether the call has ended.
    pub fn is_finished(&self) -> bool {
        self.0.finished.load(Ordering::Acquire)
    }
}

impl Drop for SinkInner {
    fn drop(&mut self) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        let mut t = Headers::new();
        Status::new(Code::Internal, "handler dropped the call").put(&mut t);
        match std::mem::replace(
            self.out.get_mut().unwrap_or_else(|p| p.into_inner()),
            Out::Done,
        ) {
            Out::Streaming(s) => s.finish_with_trailers(t),
            Out::Pending(d) => {
                let mut r = Response::new(200);
                r.headers.set("content-type", "application/grpc");
                for (k, v) in t.iter() {
                    r.headers.set(k, v);
                }
                d.respond(r);
            }
            Out::Done => {}
        }
    }
}

/// Request messages of a call, as they arrive: a message, or `None` when the client has
/// finished sending.
pub type OnMessage = Box<dyn FnMut(Option<Vec<u8>>) + Send>;
type OpenFn = Arc<dyn Fn(&Metadata, Sink) -> OnMessage + Send + Sync>;
type Interceptor = Arc<dyn Fn(&Metadata) -> Result<(), Status> + Send + Sync>;

/// A gRPC server: register methods, then serve it with `flash_http::serve` (alone, or mounted in
/// a router's fallback next to ordinary routes). The listener should speak HTTP/2 (prior
/// knowledge, or TLS with ALPN `h2`).
#[derive(Clone, Default)]
pub struct GrpcServer {
    methods: HashMap<String, OpenFn>,
    interceptors: Vec<Interceptor>,
    max_message: Option<usize>,
    compress: bool,
}

impl GrpcServer {
    /// No methods.
    pub fn new() -> GrpcServer {
        GrpcServer::default()
    }

    /// The general form: `open` runs when a call starts and returns the function that receives
    /// its request messages (then `None` at the client's half-close). Answer with the [`Sink`].
    pub fn bidi(
        mut self,
        path: &str,
        open: impl Fn(&Metadata, Sink) -> OnMessage + Send + Sync + 'static,
    ) -> GrpcServer {
        self.methods.insert(path.to_owned(), Arc::new(open));
        self
    }

    /// A unary method: one request message, `f` answers through the sink (`send` then `finish`).
    pub fn unary(
        self,
        path: &str,
        f: impl Fn(&Metadata, Vec<u8>, Sink) + Send + Sync + 'static,
    ) -> GrpcServer {
        let f = Arc::new(f);
        self.bidi(path, move |md, sink| {
            let (f, md) = (f.clone(), md.clone());
            let mut req: Option<Vec<u8>> = None;
            let mut count = 0;
            Box::new(move |m| match m {
                Some(m) => {
                    count += 1;
                    req = Some(m);
                }
                None => match (count, req.take()) {
                    (1, Some(r)) => f(&md, r, sink.clone()),
                    _ => sink.finish(Status::new(
                        Code::Unimplemented,
                        "unary call needs exactly one message",
                    )),
                },
            })
        })
    }

    /// A server-streaming method: one request, any number of responses through the sink.
    pub fn server_stream(
        self,
        path: &str,
        f: impl Fn(&Metadata, Vec<u8>, Sink) + Send + Sync + 'static,
    ) -> GrpcServer {
        self.unary(path, f)
    }

    /// A client-streaming method: `f` gets every request message once the client finishes.
    pub fn client_stream(
        self,
        path: &str,
        f: impl Fn(&Metadata, Vec<Vec<u8>>, Sink) + Send + Sync + 'static,
    ) -> GrpcServer {
        let f = Arc::new(f);
        self.bidi(path, move |md, sink| {
            let (f, md) = (f.clone(), md.clone());
            let mut all = Vec::new();
            Box::new(move |m| match m {
                Some(m) => all.push(m),
                None => f(&md, std::mem::take(&mut all), sink.clone()),
            })
        })
    }

    /// Runs before every call; an `Err` ends the call with that status.
    pub fn interceptor(
        mut self,
        f: impl Fn(&Metadata) -> Result<(), Status> + Send + Sync + 'static,
    ) -> GrpcServer {
        self.interceptors.push(Arc::new(f));
        self
    }

    /// Largest request message accepted (default 4 MiB).
    pub fn max_message(mut self, n: usize) -> GrpcServer {
        self.max_message = Some(n);
        self
    }

    /// Compress responses with gzip for clients that accept it.
    pub fn compress(mut self, on: bool) -> GrpcServer {
        self.compress = on;
        self
    }

    fn trailers_only(ctx: &mut Context, status: Status) {
        let mut r = Response::new(200);
        r.headers.set("content-type", "application/grpc");
        status.put(&mut r.headers);
        ctx.respond(r);
    }
}

impl Service for GrpcServer {
    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Stream
    }

    fn call(&self, ctx: &mut Context) {
        let ct = ctx.header("content-type").unwrap_or("");
        if *ctx.method() != Method::Post || !ct.starts_with("application/grpc") {
            return ctx.text(415, "gRPC requests are POSTs of application/grpc");
        }
        let path = ctx.path().to_owned();
        let md = Metadata {
            method: path.clone(),
            headers: ctx.req().headers.clone(),
            deadline: ctx
                .header("grpc-timeout")
                .and_then(parse_timeout)
                .map(|d| Instant::now() + d),
        };
        for i in &self.interceptors {
            if let Err(s) = i(&md) {
                return GrpcServer::trailers_only(ctx, s);
            }
        }
        let Some(open) = self.methods.get(&path).cloned() else {
            return GrpcServer::trailers_only(
                ctx,
                Status::new(Code::Unimplemented, format!("unknown method {path}")),
            );
        };
        let req_gzip = match ctx.header("grpc-encoding") {
            None | Some("identity") => false,
            Some("gzip") => true,
            Some(_) => {
                return GrpcServer::trailers_only(
                    ctx,
                    Status::new(Code::Unimplemented, "unsupported grpc-encoding"),
                );
            }
        };
        let resp_gzip = self.compress
            && ctx
                .header("grpc-accept-encoding")
                .is_some_and(|v| v.split(',').any(|e| e.trim() == "gzip"));
        let Some(detached) = ctx.detach() else {
            return;
        };
        let sink = Sink(Arc::new(SinkInner {
            out: Mutex::new(Out::Pending(detached)),
            headers: Mutex::new(Headers::new()),
            trailers: Mutex::new(Headers::new()),
            gzip: resp_gzip,
            finished: AtomicBool::new(false),
        }));
        if let Some(at) = md.deadline {
            let weak = Arc::downgrade(&sink.0);
            after(at, move || {
                if let Some(s) = weak.upgrade() {
                    Sink(s).finish(Status::new(Code::DeadlineExceeded, "deadline exceeded"));
                }
            });
        }
        let mut on_msg = open(&md, sink.clone());
        let mut deframer = Deframer::new(self.max_message.unwrap_or(DEFAULT_MAX_MESSAGE), req_gzip);
        let sink2 = sink.clone();
        ctx.on_body(move |_ctx, ev| match ev {
            BodyEvent::Chunk(b) => {
                if sink2.is_finished() {
                    return;
                }
                let mut msgs = Vec::new();
                match deframer.feed(b, &mut msgs) {
                    Ok(()) => {
                        for m in msgs {
                            on_msg(Some(m));
                        }
                    }
                    Err(s) => sink2.finish(s),
                }
            }
            BodyEvent::End(_) => {
                if sink2.is_finished() {
                    return;
                }
                if deframer.leftover() {
                    return sink2.finish(Status::new(Code::Internal, "truncated message"));
                }
                on_msg(None);
            }
        });
    }
}

// ---- client ----------------------------------------------------------------------------------

/// A gRPC client on one HTTP/2 connection.
#[derive(Clone)]
pub struct GrpcClient {
    h2: H2Client,
    base: String,
    gzip: bool,
    max_message: usize,
}

/// Call options.
#[derive(Clone, Debug, Default)]
pub struct CallOptions {
    /// Deadline, sent as `grpc-timeout`.
    pub timeout: Option<Duration>,
    /// Custom metadata.
    pub metadata: Vec<(String, String)>,
}

type DoneFn = Box<dyn FnOnce(Status, Headers) + Send>;

/// The sending half of a streaming call.
pub struct ClientSink {
    up: flash_http::h2client::H2Upload,
    gzip: bool,
}

impl ClientSink {
    /// Sends a request message.
    pub fn send(&self, msg: &[u8]) -> bool {
        self.up.write(&frame(msg, self.gzip))
    }

    /// Ends the request side (half-close).
    pub fn close_send(&self) -> bool {
        self.up.finish()
    }
}

impl GrpcClient {
    /// A client for the server `base` (`http://host:port` or `https://...`) on `h2`.
    pub fn new(h2: H2Client, base: &str) -> GrpcClient {
        GrpcClient {
            h2,
            base: base.trim_end_matches('/').to_owned(),
            gzip: false,
            max_message: DEFAULT_MAX_MESSAGE,
        }
    }

    /// Compress request messages with gzip.
    pub fn gzip(mut self, on: bool) -> GrpcClient {
        self.gzip = on;
        self
    }

    /// The general form: `on_message` receives response messages, `done` the final status and
    /// trailers; the returned sink sends requests.
    pub fn bidi(
        &self,
        path: &str,
        opts: CallOptions,
        mut on_message: impl FnMut(Vec<u8>) + Send + 'static,
        done: impl FnOnce(Status, Headers) + Send + 'static,
    ) -> ClientSink {
        let mut req = ClientRequest::post(&format!("{}{path}", self.base), Vec::new());
        req.headers.set("content-type", "application/grpc");
        req.headers.set("te", "trailers");
        req.headers.set("grpc-accept-encoding", "gzip");
        if self.gzip {
            req.headers.set("grpc-encoding", "gzip");
        }
        if let Some(t) = opts.timeout {
            req.headers.set("grpc-timeout", format_timeout(t));
        }
        for (k, v) in &opts.metadata {
            req.headers.append(k.as_str(), v.as_str());
        }
        let mut done: Option<DoneFn> = Some(Box::new(done));
        let mut deframer: Option<Deframer> = None;
        let max = self.max_message;
        let mut status: Option<Status> = None;
        let mut trailers = Headers::new();
        let up = self.h2.open(req, move |ev| match ev {
            H2Event::Head {
                status: http,
                headers,
            } => {
                if http != 200 {
                    status = Some(Status::new(
                        Code::Unavailable,
                        format!("HTTP status {http}"),
                    ));
                }
                // Trailers-only responses carry the status in the headers.
                if let Some(s) = Status::from_headers(headers) {
                    status = Some(s);
                    trailers = headers.clone();
                }
                let gz = headers.get("grpc-encoding") == Some("gzip");
                deframer = Some(Deframer::new(max, gz));
            }
            H2Event::Data(b) => {
                let mut msgs = Vec::new();
                if let Some(d) = deframer.as_mut() {
                    if let Err(s) = d.feed(b, &mut msgs) {
                        status = Some(s);
                    }
                }
                for m in msgs {
                    on_message(m);
                }
            }
            H2Event::Trailers(t) => {
                if let Some(s) = Status::from_headers(t) {
                    status = Some(s);
                }
                trailers = t.clone();
            }
            H2Event::End => {
                if let Some(d) = done.take() {
                    d(
                        status
                            .take()
                            .unwrap_or_else(|| Status::new(Code::Internal, "no grpc-status")),
                        std::mem::take(&mut trailers),
                    );
                }
            }
            H2Event::Error(e) => {
                if let Some(d) = done.take() {
                    d(
                        Status::new(Code::Unavailable, e.to_string()),
                        Headers::new(),
                    );
                }
            }
        });
        ClientSink {
            up,
            gzip: self.gzip,
        }
    }

    /// A unary call; blocks until the answer (use [`bidi`](Self::bidi) for callbacks).
    pub fn unary(&self, path: &str, msg: &[u8], opts: CallOptions) -> Result<Vec<u8>, Status> {
        let (msgs, st) = self.collect(path, vec![msg.to_vec()], opts);
        match st.code {
            Code::Ok => msgs
                .into_iter()
                .next()
                .ok_or_else(|| Status::new(Code::Internal, "no response message")),
            _ => Err(st),
        }
    }

    /// Sends `requests`, half-closes, and returns every response message with the status.
    /// Covers server-streaming and client-streaming calls.
    pub fn collect(
        &self,
        path: &str,
        requests: Vec<Vec<u8>>,
        opts: CallOptions,
    ) -> (Vec<Vec<u8>>, Status) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let fin = Arc::new((Mutex::new(None::<Status>), Condvar::new()));
        let (o2, f2) = (out.clone(), fin.clone());
        let sink = self.bidi(
            path,
            opts,
            move |m| o2.lock().unwrap_or_else(|p| p.into_inner()).push(m),
            move |s, _| {
                *f2.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(s);
                f2.1.notify_all();
            },
        );
        for r in &requests {
            sink.send(r);
        }
        sink.close_send();
        let mut g = fin.0.lock().unwrap_or_else(|p| p.into_inner());
        while g.is_none() {
            g = fin.1.wait(g).unwrap_or_else(|p| p.into_inner());
        }
        let st = g.take().expect("set");
        let msgs = std::mem::take(&mut *out.lock().unwrap_or_else(|p| p.into_inner()));
        (msgs, st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_and_gzip() {
        let mut d = Deframer::new(1 << 20, true);
        let mut wire = frame(b"one", false);
        wire.extend(frame(&vec![b'x'; 10_000], true));
        wire.extend(frame(b"", false));
        let mut out = Vec::new();
        for c in wire.chunks(3) {
            d.feed(c, &mut out).unwrap();
        }
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], b"one");
        assert_eq!(out[1].len(), 10_000);
        assert!(out[2].is_empty());
        let mut small = Deframer::new(10, false);
        assert_eq!(
            small
                .feed(&frame(&[0; 11], false), &mut Vec::new())
                .unwrap_err()
                .code,
            Code::ResourceExhausted
        );
    }

    #[test]
    fn timeouts_and_messages() {
        assert_eq!(parse_timeout("100m"), Some(Duration::from_millis(100)));
        assert_eq!(parse_timeout("2S"), Some(Duration::from_secs(2)));
        assert_eq!(parse_timeout("1H"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_timeout("x"), None);
        assert_eq!(pct_encode("a%b\nc é"), "a%25b%0Ac %C3%A9");
        assert_eq!(pct_decode("a%25b%0Ac %C3%A9"), "a%b\nc é");
    }
}
