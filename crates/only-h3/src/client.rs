//! An HTTP/3 client: requests multiplexed on one QUIC connection, request bodies streamed
//! ([`H3Client::upload`]) and WebSocket over HTTP/3 ([`H3Client::websocket`]).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, mpsc};
use std::time::Duration;

use only_http::message::{Headers, Method, Response};
use only_http::ws::deflate::PmdOffer;
use only_http::ws::{WsConfig, WsHandler, WsSender, WsSession};
use only_quic::Bytes;
use only_quic::{Connection, ConnectionError, Dir, QuicHandler, StreamId};

use crate::frame::{self, Piece, Reader, StreamReader};
use crate::qpack::{self, FieldBuf, SectionError};
use crate::{Blocked, EncShared, H3Config, Peer, Settings, StreamLink, StreamMap, Uni, code, sid};

type Callback = Box<dyn FnOnce(Result<Response, H3Error>) + Send>;
type WsDone = Box<dyn FnOnce(Result<WsSender, H3Error>) + Send>;
type Encode = Box<dyn FnOnce(StreamId, Option<&EncShared>) -> Vec<u8> + Send>;

/// Why an HTTP/3 request got no response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3Error {
    /// The connection is closed (why).
    Closed(String),
    /// The server reset the request stream with this HTTP/3 error code ([`code`](crate::code)).
    Reset(u64),
    /// The response broke the protocol (what was wrong).
    Protocol(&'static str),
    /// No response within the timeout of a blocking call.
    Timeout,
    /// The server refused a WebSocket ([`H3Client::websocket`]) with this status.
    Status(u16),
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Closed(why) => write!(f, "connection closed: {why}"),
            H3Error::Reset(code) => write!(f, "stream reset (code {code:#x})"),
            H3Error::Protocol(what) => write!(f, "HTTP/3 protocol error: {what}"),
            H3Error::Timeout => f.write_str("timed out"),
            H3Error::Status(s) => write!(f, "WebSocket refused with status {s}"),
        }
    }
}

impl std::error::Error for H3Error {}

/// How [`H3Client::websocket`] opens a WebSocket over HTTP/3 (RFC 9220).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H3WsOptions {
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
    /// ending it from this side.
    pub close_timeout: Duration,
}

impl Default for H3WsOptions {
    fn default() -> H3WsOptions {
        H3WsOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            close_timeout: Duration::from_secs(3),
        }
    }
}

/// A WebSocket being opened.
struct WsOpen {
    handler: Box<dyn WsHandler>,
    cfg: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    done: WsDone,
}

/// What a request stream is for.
enum Kind {
    /// A request whose response goes to the callback.
    Plain(Callback),
    /// A WebSocket being opened: done once the response head arrives.
    Ws(Box<WsOpen>),
}

impl Kind {
    fn fail(self, e: H3Error) {
        match self {
            Kind::Plain(cb) => cb(Err(e)),
            Kind::Ws(w) => (w.done)(Err(e)),
        }
    }
}

/// A request waiting for a stream.
struct Job {
    /// Its bytes, or how to encode them once the stream id is known (QPACK with a dynamic
    /// table needs it).
    wire: Result<Bytes, Encode>,
    /// End the stream after `wire` (not for uploads and WebSockets).
    fin: bool,
    up: Option<Arc<UpState>>,
    kind: Kind,
}

struct InFlight {
    r: Reader,
    resp: Option<Response>,
    cb: Option<Callback>,
    /// What only uploads, WebSockets and blocked responses need (boxed, so a plain request's
    /// state stays small).
    x: Option<Box<Extra>>,
}

#[derive(Default)]
struct Extra {
    ws: Option<Box<WsOpen>>,
    up: Option<Arc<UpState>>,
    blocked: Option<Box<Blocked>>,
}

impl InFlight {
    fn new(kind: Kind, up: Option<Arc<UpState>>) -> InFlight {
        let (cb, ws) = match kind {
            Kind::Plain(cb) => (Some(cb), None),
            Kind::Ws(w) => (None, Some(w)),
        };
        let x = (ws.is_some() || up.is_some()).then(|| {
            Box::new(Extra {
                ws,
                up,
                blocked: None,
            })
        });
        InFlight {
            r: Reader::default(),
            resp: None,
            cb,
            x,
        }
    }

    fn take_kind(&mut self) -> Option<Kind> {
        match self.cb.take() {
            Some(cb) => Some(Kind::Plain(cb)),
            None => self.x.as_mut()?.ws.take().map(Kind::Ws),
        }
    }

    fn up(&self) -> Option<&Arc<UpState>> {
        self.x.as_ref()?.up.as_ref()
    }

    fn blocked(&self) -> Option<&Blocked> {
        self.x.as_ref()?.blocked.as_deref()
    }

    fn take_blocked(&mut self) -> Option<Box<Blocked>> {
        self.x.as_mut()?.blocked.take()
    }
}

#[derive(Default)]
struct State {
    ready: bool,
    closed: Option<String>,
    queue: VecDeque<Job>,
    inflight: StreamMap<InFlight>,
    /// The server's SETTINGS, once they arrived.
    settings: Option<Settings>,
    /// WebSockets waiting for the server's SETTINGS (extended CONNECT allowed?).
    ws_wait: Vec<Job>,
}

struct Shared {
    st: Mutex<State>,
    /// The QPACK encoder with a dynamic table, once the server allows one.
    enc: OnceLock<Arc<EncShared>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// An HTTP/3 connection to one server. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct H3Client {
    conn: Connection,
    sh: Arc<Shared>,
    authority: String,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client").finish_non_exhaustive()
    }
}

/// The body of a request started with [`H3Client::upload`]: write it in pieces from any
/// thread, then finish it.
pub struct H3Upload {
    up: Arc<UpState>,
}

impl std::fmt::Debug for H3Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Upload").finish_non_exhaustive()
    }
}

struct UpState {
    c: Connection,
    s: Mutex<Up>,
}

#[derive(Default)]
struct Up {
    /// The stream, once open (the head is sent first).
    id: Option<StreamId>,
    /// DATA frames written before the stream opened.
    queued: Vec<u8>,
    finished: bool,
    failed: bool,
}

impl UpState {
    fn lock(&self) -> MutexGuard<'_, Up> {
        self.s.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The stream is open and its head sent: what was written goes out.
    fn attach(&self, id: StreamId) {
        let mut u = self.lock();
        u.id = Some(id);
        if !u.queued.is_empty() {
            let q = std::mem::take(&mut u.queued);
            let _ = self.c.send(id, q);
        }
        if u.finished {
            let _ = self.c.finish(id);
        }
    }

    fn fail(&self) {
        self.lock().failed = true;
    }
}

impl H3Upload {
    /// Sends body bytes (in a DATA frame). `false` once the request failed or was finished.
    pub fn write(&self, data: &[u8]) -> bool {
        let mut u = self.up.lock();
        if u.failed || u.finished {
            return false;
        }
        if data.is_empty() {
            return true;
        }
        match u.id {
            Some(id) => self.up.c.send(id, crate::data_frame(data)).is_ok(),
            None => {
                frame::put_frame(&mut u.queued, frame::DATA, data);
                true
            }
        }
    }

    /// Ends the body. `false` if the request already failed.
    pub fn finish(&self) -> bool {
        let mut u = self.up.lock();
        if u.failed {
            return false;
        }
        if !std::mem::replace(&mut u.finished, true) {
            if let Some(id) = u.id {
                return self.up.c.finish(id).is_ok();
            }
        }
        true
    }

    /// Bytes written but not yet sent, for pacing the writer.
    pub fn queued_bytes(&self) -> usize {
        let u = self.up.lock();
        match u.id {
            Some(id) => self.up.c.queued_bytes(id),
            None => u.queued.len(),
        }
    }
}

impl H3Client {
    /// Connects to `addr`, verifying it as `server_name`, with a QUIC client config offering
    /// ALPN `h3` (for example `only_quic::client_config(roots, &[b"h3"])`). The engine needs
    /// UDP client threads. Requests sent before the handshake completes wait for it, unless
    /// the connection resumes with 0-RTT (`only_quic::ClientConfig::zero_rtt`): then they go
    /// out at once, in 0-RTT packets that may be **replayed**, so make only requests that are
    /// safe to repeat on such a client (a server may answer `425 Too Early`, RFC 8470).
    pub fn dial(
        engine: &only::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: only_quic::ClientConfig,
    ) -> Result<H3Client, only_quic::Error> {
        let h3 = H3Config {
            max_field_section_bytes: 1 << 20,
            ..H3Config::default()
        };
        H3Client::dial_with(engine, addr, server_name, config, &h3)
    }

    /// [`dial`](Self::dial) with HTTP/3 settings: the field section limit and the QPACK ones
    /// (`max_body_bytes` does not apply to responses).
    pub fn dial_with(
        engine: &only::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: only_quic::ClientConfig,
        h3: &H3Config,
    ) -> Result<H3Client, only_quic::Error> {
        let sh = Arc::new(Shared {
            st: Mutex::new(State::default()),
            enc: OnceLock::new(),
        });
        let handler = ClientConn {
            sh: sh.clone(),
            cfg: h3.clone(),
            peer: Peer::new(h3),
            uni: StreamMap::default(),
            ws: StreamMap::default(),
            ws_answer: None,
            fields: FieldBuf::default(),
        };
        let conn = only_quic::dial(engine, addr, server_name, config, handler)?;
        // Resuming with 0-RTT: requests go out before the handshake completes.
        if conn.early_data() == only::tls::EarlyData::Pending {
            sh.lock().ready = true;
        }
        let authority = if addr.port() == 443 {
            server_name.to_owned()
        } else {
            format!("{server_name}:{}", addr.port())
        };
        Ok(H3Client {
            conn,
            sh,
            authority,
        })
    }

    /// The QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Sends a request; `cb` gets the response (interim 1xx responses are skipped) or why
    /// there is none. `path` is the request target (`/a?b=c`).
    pub fn request(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        cb: impl FnOnce(Result<Response, H3Error>) + Send + 'static,
    ) {
        let kind = Kind::Plain(Box::new(cb));
        let Some(enc) = self.sh.enc.get() else {
            let wire = Ok(self.encode_now(&method, path, headers, body));
            return self.push(Job {
                wire,
                fin: true,
                up: None,
                kind,
            });
        };
        match self.open_now(kind) {
            // A stream right away (the usual case): encoded with its id, nothing copied.
            Ok(id) => {
                let wire = encode_with(&method, &self.authority, path, headers, &body, id, enc);
                let _ = self.conn.send(id, wire);
                let _ = self.conn.finish(id);
            }
            Err(kind) => self.push(Job {
                wire: Err(self.encode_later(method, path, headers, body)),
                fin: true,
                up: None,
                kind,
            }),
        }
    }

    /// Opens a stream for a request now if nothing is queued before it; `Err` gives `kind`
    /// back when it has to wait.
    fn open_now(&self, kind: Kind) -> Result<StreamId, Kind> {
        let mut st = self.sh.lock();
        if st.closed.is_some() || !st.ready || !st.queue.is_empty() {
            return Err(kind);
        }
        let Some(id) = self.conn.open_bi() else {
            return Err(kind);
        };
        st.inflight.insert(id, InFlight::new(kind, None));
        Ok(id)
    }

    /// The request's HEADERS and DATA frames, with static QPACK references and literals.
    #[inline]
    fn encode_now(&self, method: &Method, path: &str, headers: &Headers, body: Vec<u8>) -> Bytes {
        let pseudo = pseudo(method, &self.authority, path);
        let pseudo = pseudo_for(method, &pseudo);
        let hint = crate::head_hint(headers) + self.authority.len() + path.len() + body.len() + 64;
        let len = (!body.is_empty()).then_some(body.len() as u64);
        let encode = |wire: &mut Vec<u8>| {
            crate::put_head(wire, None, pseudo, headers, false, len, None);
            if !body.is_empty() {
                frame::put_frame(wire, frame::DATA, &body);
            }
        };
        if body.len() <= crate::POOLED_BODY_MAX {
            Bytes::pooled(hint, encode)
        } else {
            let mut wire = Vec::with_capacity(hint);
            encode(&mut wire);
            Bytes::from(wire)
        }
    }

    /// Encoding deferred until the stream is open (the dynamic table tracks sections by
    /// stream).
    fn encode_later(&self, method: Method, path: &str, headers: &Headers, body: Vec<u8>) -> Encode {
        let (authority, path, headers) = (self.authority.clone(), path.to_owned(), headers.clone());
        Box::new(move |id, enc| match enc {
            Some(enc) => encode_with(&method, &authority, &path, &headers, &body, id, enc),
            None => {
                let pseudo = pseudo(&method, &authority, &path);
                let pseudo = pseudo_for(&method, &pseudo);
                let len = (!body.is_empty()).then_some(body.len() as u64);
                let mut wire = Vec::with_capacity(crate::head_hint(&headers) + body.len() + 64);
                crate::put_head(&mut wire, None, pseudo, &headers, false, len, None);
                if !body.is_empty() {
                    frame::put_frame(&mut wire, frame::DATA, &body);
                }
                wire
            }
        })
    }

    fn push(&self, job: Job) {
        let mut st = self.sh.lock();
        if let Some(e) = st.closed.clone() {
            drop(st);
            if let Some(up) = &job.up {
                up.fail();
            }
            return job.kind.fail(H3Error::Closed(e));
        }
        st.queue.push_back(job);
        let ready = st.ready;
        drop(st);
        if ready {
            start_queued(&self.conn, &self.sh);
        }
    }

    /// Starts a request whose body is written afterwards through the returned [`H3Upload`]
    /// (uploads of unknown size, or too large to hold); `cb` gets the response. Add a
    /// `content-length` header when the size is known.
    pub fn upload(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        cb: impl FnOnce(Result<Response, H3Error>) + Send + 'static,
    ) -> H3Upload {
        let up = Arc::new(UpState {
            c: self.conn.clone(),
            s: Mutex::new(Up::default()),
        });
        let wire = match self.sh.enc.get() {
            None => Ok(self.encode_now(&method, path, headers, Vec::new())),
            Some(_) => Err(self.encode_later(method, path, headers, Vec::new())),
        };
        self.push(Job {
            wire,
            fin: false,
            up: Some(up.clone()),
            kind: Kind::Plain(Box::new(cb)),
        });
        H3Upload { up }
    }

    /// Sends a request and waits for its response, up to `timeout`.
    pub fn request_blocking(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Response, H3Error> {
        let (tx, rx) = mpsc::channel();
        self.request(method, path, headers, body, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout).map_err(|_| H3Error::Timeout)?
    }

    /// `GET path`, blocking.
    pub fn get(&self, path: &str, timeout: Duration) -> Result<Response, H3Error> {
        self.request_blocking(Method::Get, path, &Headers::new(), Vec::new(), timeout)
    }

    /// Opens a WebSocket on `path` over this connection (RFC 9220: an extended CONNECT on a
    /// new stream, which then carries the WebSocket), served by `handler` as a
    /// `only_ws::client` connection is: callbacks on the connection's I/O thread,
    /// [`WsSender`] to send from any thread. `done` gets the sender once the server accepted
    /// (`on_open` has run), or why not: [`H3Error::Status`] for a refusal,
    /// [`H3Error::Protocol`] when the server does not allow extended CONNECT.
    pub fn websocket(
        &self,
        path: &str,
        opts: &H3WsOptions,
        handler: impl WsHandler,
        done: impl FnOnce(Result<WsSender, H3Error>) + Send + 'static,
    ) {
        let mut headers = Headers::new();
        headers.append("sec-websocket-version", "13");
        if !opts.protocols.is_empty() {
            headers.append("sec-websocket-protocol", opts.protocols.join(", "));
        }
        let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
        if let Some(p) = &pmd {
            headers.append("sec-websocket-extensions", p.header());
        }
        if let Some(o) = &opts.origin {
            headers.append("origin", o.as_str());
        }
        for (n, v) in &opts.headers {
            let lower = n.to_ascii_lowercase();
            if !lower.starts_with("sec-websocket-") && lower != "origin" {
                headers.append(lower, v.as_str());
            }
        }
        let (authority, path) = (self.authority.clone(), path.to_owned());
        let wire: Encode = Box::new(move |id, enc| {
            let pseudo: [(&[u8], &[u8]); 5] = [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", authority.as_bytes()),
                (b":path", path.as_bytes()),
            ];
            let mut wire = Vec::with_capacity(crate::head_hint(&headers) + 128);
            crate::put_head(
                &mut wire,
                None,
                &pseudo,
                &headers,
                false,
                None,
                enc.map(|e| (e, id)),
            );
            wire
        });
        let job = Job {
            wire: Err(wire),
            fin: false,
            up: None,
            kind: Kind::Ws(Box::new(WsOpen {
                handler: Box::new(handler),
                cfg: opts.config.clone(),
                pmd,
                protocols: opts.protocols.clone(),
                close_timeout: opts.close_timeout,
                done: Box::new(done),
            })),
        };
        let mut st = self.sh.lock();
        match st.settings {
            // Extended CONNECT needs the server's SETTINGS first (RFC 8441 §3).
            None if st.closed.is_none() => st.ws_wait.push(job),
            Some(s) if !s.connect_protocol => {
                drop(st);
                job.kind
                    .fail(H3Error::Protocol("server does not allow extended CONNECT"));
            }
            _ => {
                drop(st);
                self.push(job);
            }
        }
    }

    /// [`websocket`](Self::websocket), waiting up to `timeout` for the server's answer.
    pub fn websocket_blocking(
        &self,
        path: &str,
        opts: &H3WsOptions,
        handler: impl WsHandler,
        timeout: Duration,
    ) -> Result<WsSender, H3Error> {
        let (tx, rx) = mpsc::channel();
        self.websocket(path, opts, handler, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout).map_err(|_| H3Error::Timeout)?
    }

    /// Closes the connection (`H3_NO_ERROR`).
    pub fn close(&self) {
        self.conn.close(code::NO_ERROR, b"");
    }
}

/// A request's HEADERS (with the dynamic table, for stream `id`) and DATA frames.
fn encode_with(
    method: &Method,
    authority: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    id: StreamId,
    enc: &EncShared,
) -> Vec<u8> {
    let pseudo = pseudo(method, authority, path);
    let pseudo = pseudo_for(method, &pseudo);
    let len = (!body.is_empty()).then_some(body.len() as u64);
    let mut wire = Vec::with_capacity(crate::head_hint(headers) + body.len() + 64);
    crate::put_head(
        &mut wire,
        None,
        pseudo,
        headers,
        false,
        len,
        Some((enc, id)),
    );
    if !body.is_empty() {
        frame::put_frame(&mut wire, frame::DATA, body);
    }
    wire
}

/// The request pseudo-header fields (`:path` and `:scheme` are left out of a CONNECT by
/// [`pseudo_for`]).
fn pseudo<'a>(method: &'a Method, authority: &'a str, path: &'a str) -> [(&'a [u8], &'a [u8]); 4] {
    [
        (b":method", method.as_str().as_bytes()),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", path.as_bytes()),
    ]
}

fn pseudo_for<'a, 'b>(
    method: &Method,
    p: &'b [(&'a [u8], &'a [u8]); 4],
) -> &'b [(&'a [u8], &'a [u8])] {
    if *method == Method::Connect {
        &p[..3]
    } else {
        &p[..]
    }
}

/// Opens streams for queued requests while the peer allows.
fn start_queued(conn: &Connection, sh: &Shared) {
    loop {
        let mut s = sh.lock();
        if s.queue.is_empty() || !s.ready {
            return;
        }
        let Some(id) = conn.open_bi() else { return };
        let job = s.queue.pop_front().expect("non-empty");
        s.inflight
            .insert(id, InFlight::new(job.kind, job.up.clone()));
        drop(s);
        let wire = match job.wire {
            Ok(b) => b,
            Err(f) => Bytes::from(f(id, sh.enc.get().map(|e| &**e))),
        };
        let _ = conn.send(id, wire);
        match &job.up {
            Some(up) => up.attach(id),
            None if job.fin => {
                let _ = conn.finish(id);
            }
            None => {}
        }
    }
}

struct ClientConn {
    sh: Arc<Shared>,
    cfg: H3Config,
    peer: Peer,
    uni: StreamMap<Uni>,
    /// A WebSocket's answer `on_resp` just took off its stream, for `report`.
    ws_answer: Option<Box<WsAnswer>>,
    /// Open WebSockets, by stream.
    ws: StreamMap<(StreamReader, WsSession)>,
    /// Field sections are decoded here, then copied once into the response's `Headers`.
    fields: FieldBuf,
}

fn fields_to_response(fields: &FieldBuf) -> Option<Response> {
    let mut status = None;
    let mut headers = Headers::with_capacity(fields.len(), fields.bytes());
    for (n, v) in fields.strs()? {
        if n == ":status" {
            status = v.parse::<u16>().ok();
        } else if n.starts_with(':') {
            return None;
        } else {
            headers.append(n, v);
        }
    }
    let mut r = Response::new(status?);
    r.headers = headers;
    Some(r)
}

/// A WebSocket's answer (its body: the WebSocket bytes that came with it), whether the stream
/// already ended, and the stream's reader (holding the start of a frame, maybe).
struct WsAnswer {
    w: Box<WsOpen>,
    r: Result<Response, H3Error>,
    fin: bool,
    reader: Reader,
}

/// A finished request: its callback and the response, or why there is none.
type Done = (Callback, Result<Response, H3Error>);

impl ClientConn {
    fn fail_all(&mut self, why: String) {
        let mut st = self.sh.lock();
        st.closed = Some(why.clone());
        let mut kinds: Vec<Kind> = st.queue.drain(..).map(|j| j.kind).collect();
        kinds.extend(st.ws_wait.drain(..).map(|j| j.kind));
        for (_, mut f) in st.inflight.drain() {
            if let Some(up) = f.up() {
                up.fail();
            }
            kinds.extend(f.take_kind());
        }
        drop(st);
        for k in kinds {
            k.fail(H3Error::Closed(why.clone()));
        }
        for (_, (_, mut ws)) in self.ws.drain() {
            ws.on_transport_closed();
        }
    }

    /// Feeds a response stream; what to report, once the response is complete (a WebSocket's
    /// once its head arrived).
    fn on_resp(&mut self, id: StreamId, data: &[u8], fin: bool) -> Option<Done> {
        let mut st = self.sh.lock();
        let InFlight { r, resp, x, .. } = st.inflight.get_mut(&id)?;
        let fields = &mut self.fields;
        let peer = &mut self.peer;
        let max_field = self.cfg.max_field_section_bytes;
        let fed = r.feed(
            data,
            1 << 30,
            || H3Error::Protocol("frame too large"),
            |ty, p| {
                if let Some(b) = x.as_mut().and_then(|x| x.blocked.as_mut()) {
                    // Held back, in order, until the section before them can be decoded.
                    frame::put_frame(&mut b.rest, ty, p);
                    return Ok(());
                }
                match ty {
                    frame::HEADERS => {
                        match qpack::decode_section(p, max_field, &peer.dec, fields) {
                            Ok(0) => {}
                            Ok(ric) => peer.dec.section_ack(sid(id), ric),
                            Err(SectionError::Blocked(ric)) => {
                                if peer.blocked >= peer.max_blocked {
                                    return Err(H3Error::Protocol("too many blocked streams"));
                                }
                                peer.blocked += 1;
                                x.get_or_insert_with(Box::default).blocked =
                                    Some(Box::new(Blocked {
                                        ric,
                                        section: p.to_vec(),
                                        rest: Vec::new(),
                                        fin: false,
                                    }));
                                return Ok(());
                            }
                            Err(SectionError::Bad(_)) => {
                                return Err(H3Error::Protocol("bad field section"));
                            }
                        }
                        match resp.as_mut() {
                            None => match fields_to_response(fields) {
                                Some(r) if r.status < 200 => {}
                                Some(r) => *resp = Some(r),
                                None => return Err(H3Error::Protocol("malformed response")),
                            },
                            Some(r) => {
                                let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                                for (n, v) in fields.iter() {
                                    t.append(
                                        String::from_utf8_lossy(n),
                                        String::from_utf8_lossy(v),
                                    );
                                }
                                r.trailers = Some(t);
                            }
                        }
                    }
                    frame::DATA => match resp.as_mut() {
                        Some(r) => r.body.extend_from_slice(p),
                        None => return Err(H3Error::Protocol("DATA before HEADERS")),
                    },
                    _ => {}
                }
                Ok(())
            },
        );
        let err = fed.err();
        if err.is_none() {
            if let Some(b) = x.as_mut().and_then(|x| x.blocked.as_mut()) {
                b.fin |= fin;
                return None;
            }
        }
        let ws_head = resp.is_some() && x.as_ref().is_some_and(|x| x.ws.is_some());
        if err.is_none() && !fin && !ws_head {
            return None;
        }
        let mut f = st.inflight.remove(&id)?;
        if f.x.is_some() {
            if f.take_blocked().is_some() {
                self.peer.blocked -= 1;
            }
            if let Some(up) = f.up() {
                up.fail();
            }
        }
        let r = match (err, f.resp.take()) {
            (Some(e), _) => Err(e),
            (None, Some(r)) => Ok(r),
            (None, None) => Err(H3Error::Protocol("stream ended without a response")),
        };
        match f.take_kind()? {
            Kind::Plain(cb) => Some((cb, r)),
            Kind::Ws(w) => {
                // Started by the caller (`report`), outside the lock.
                self.ws_answer = Some(Box::new(WsAnswer {
                    w,
                    r,
                    fin,
                    reader: std::mem::take(&mut f.r),
                }));
                None
            }
        }
    }

    /// Reports what a response stream produced (without the state lock: callbacks may send
    /// requests).
    #[inline]
    fn report(&mut self, c: &Connection, id: StreamId, done: Option<Done>) {
        if let Some((cb, r)) = done {
            return cb(r);
        }
        if let Some(a) = self.ws_answer.take() {
            let WsAnswer { w, r, fin, reader } = *a;
            self.ws_open(c, id, *w, r, fin, reader);
        }
    }

    /// Checks a WebSocket's answer and starts it.
    fn ws_open(
        &mut self,
        c: &Connection,
        id: StreamId,
        w: WsOpen,
        r: Result<Response, H3Error>,
        fin: bool,
        reader: Reader,
    ) {
        let checked = r.and_then(|resp| {
            if !(200..300).contains(&resp.status) {
                return Err(H3Error::Status(resp.status));
            }
            let mut protos = resp.headers.get_all("sec-websocket-protocol");
            let protocol = match (protos.next(), protos.next()) {
                (None, _) => None,
                (Some(p), None) if w.protocols.iter().any(|o| o == p) => Some(p.to_owned()),
                _ => {
                    return Err(H3Error::Protocol(
                        "server selected a subprotocol that was not offered",
                    ));
                }
            };
            let pmd = match &w.pmd {
                Some(offer) => offer
                    .accept_response(resp.headers.get_all("sec-websocket-extensions"))
                    .map_err(H3Error::Protocol)?,
                None => {
                    if resp
                        .headers
                        .get_all("sec-websocket-extensions")
                        .any(|v| !v.is_empty())
                    {
                        return Err(H3Error::Protocol(
                            "server accepted an extension that was not offered",
                        ));
                    }
                    None
                }
            };
            Ok((resp.body, protocol, pmd))
        });
        let (early, protocol, pmd) = match checked {
            Ok(v) => v,
            Err(e) => {
                let _ = c.stop(id, code::REQUEST_CANCELLED);
                let _ = c.reset(id, code::REQUEST_CANCELLED);
                return (w.done)(Err(e));
            }
        };
        let link = Arc::new(StreamLink::new(c.clone(), id));
        let mut ws =
            WsSession::client_with_link(link, &w.cfg, pmd, w.handler, protocol, w.close_timeout);
        let sender = ws.sender().clone();
        ws.open();
        if !early.is_empty() {
            ws.on_data(&early);
        }
        if fin {
            ws.on_transport_closed();
        } else {
            self.ws.insert(id, (StreamReader::from(reader), ws));
        }
        (w.done)(Ok(sender));
    }

    /// Bytes of an open WebSocket's stream.
    fn on_ws(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool) {
        let Some((r, ws)) = self.ws.get_mut(&id) else {
            return;
        };
        let fed = r.feed_stream(
            data,
            self.cfg.max_field_section_bytes as u64,
            || (),
            |p| {
                match p {
                    Piece::Data(d) => ws.on_data(d),
                    // Trailers end nothing; unknown frames are skipped.
                    Piece::Headers(_) => {}
                    Piece::Skip(t) if crate::h2_only(t) || t == frame::SETTINGS => return Err(()),
                    Piece::Skip(_) => {}
                }
                Ok(())
            },
        );
        if fed.is_err() {
            c.close(code::FRAME_UNEXPECTED, b"");
        }
        if fin || fed.is_err() {
            if let Some((_, mut ws)) = self.ws.remove(&id) {
                ws.on_transport_closed();
            }
        }
    }

    /// Responses whose field sections the last inserts made decodable go on.
    fn unblock(&mut self, c: &Connection) {
        if !std::mem::take(&mut self.peer.inserted) || self.peer.blocked == 0 {
            return;
        }
        let have = self.peer.dec.inserted();
        let ready: Vec<StreamId> = self
            .sh
            .lock()
            .inflight
            .iter()
            .filter(|(_, f)| f.blocked().is_some_and(|b| b.ric <= have))
            .map(|(&id, _)| id)
            .collect();
        for id in ready {
            let (b, held) = {
                let mut st = self.sh.lock();
                let Some(f) = st.inflight.get_mut(&id) else {
                    continue;
                };
                let Some(b) = f.take_blocked() else { continue };
                (b, std::mem::take(&mut f.r))
            };
            self.peer.blocked -= 1;
            let mut data = Vec::with_capacity(b.section.len() + b.rest.len() + 9);
            frame::put_frame(&mut data, frame::HEADERS, &b.section);
            data.extend_from_slice(&b.rest);
            // The held-back frames come before whatever the stream's reader still holds.
            let mut done = self.on_resp(id, &data, false);
            if let Some(f) = self.sh.lock().inflight.get_mut(&id) {
                f.r = held;
            }
            if done.is_none() && self.ws_answer.is_none() && b.fin {
                done = self.on_resp(id, &[], true);
            }
            self.report(c, id, done);
        }
    }
}

impl QuicHandler for ClientConn {
    fn on_connected(&mut self, c: &Connection) {
        self.peer
            .open(c, crate::control_stream_preamble(&self.cfg, false));
        self.sh.lock().ready = true;
        start_queued(c, &self.sh);
    }

    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
        if id.dir() == Dir::Uni {
            self.uni.insert(id, Uni::Unknown(Reader::default()));
        }
    }

    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        if id.dir() == Dir::Uni {
            if let Some(u) = self.uni.get_mut(&id) {
                let mut stop = |id, e| {
                    let _ = c.stop(id, e);
                };
                if let Err(e) = crate::on_uni(u, &mut self.peer, &mut stop, id, &data, fin, false) {
                    c.close(e, b"");
                    return;
                }
                if self.peer.new_settings {
                    self.on_settings(c);
                }
                self.unblock(c);
                self.peer.dec.increment();
                self.peer.after(c);
                if let Some(e) = &self.peer.enc {
                    let _ = self.sh.enc.set(e.clone());
                }
            }
            return;
        }
        if !self.ws.is_empty() && self.ws.contains_key(&id) {
            return self.on_ws(c, id, &data, fin);
        }
        match self.on_resp(id, &data, fin) {
            Some((cb, r)) => cb(r),
            None if self.ws_answer.is_some() => self.report(c, id, None),
            None => {}
        }
        self.peer.flush(c);
    }

    fn on_stream_reset(&mut self, c: &Connection, id: StreamId, code: u64) {
        if let Some((_, mut ws)) = self.ws.remove(&id) {
            return ws.on_transport_closed();
        }
        let f = self.sh.lock().inflight.remove(&id);
        if let Some(mut f) = f {
            if f.take_blocked().is_some() {
                self.peer.blocked -= 1;
                self.peer.dec.cancel(sid(id));
                self.peer.flush(c);
            }
            if let Some(up) = f.up() {
                up.fail();
            }
            if let Some(k) = f.take_kind() {
                k.fail(H3Error::Reset(code));
            }
        }
    }

    fn on_streams_available(&mut self, c: &Connection, _dir: Dir) {
        start_queued(c, &self.sh);
    }

    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        self.fail_all(reason.to_string());
    }
}

impl ClientConn {
    /// The server's SETTINGS arrived: WebSockets waiting for them go (or fail).
    fn on_settings(&self, c: &Connection) {
        let s = self.peer.settings.unwrap_or_default();
        let mut st = self.sh.lock();
        st.settings = Some(s);
        let waiting = std::mem::take(&mut st.ws_wait);
        if s.connect_protocol {
            st.queue.extend(waiting);
            let ready = st.ready;
            drop(st);
            if ready {
                start_queued(c, &self.sh);
            }
        } else {
            drop(st);
            for j in waiting {
                j.kind
                    .fail(H3Error::Protocol("server does not allow extended CONNECT"));
            }
        }
    }
}
