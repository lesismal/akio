//! The HTTP/1.1 connection state machine and its `only` `Acceptor`.

use std::{sync::Arc, time::Duration};

use only_core::{Acceptor, Conn, Error, Handler};
use only_ws::{WsSession, http1::Resume};

use crate::{
    deadline::{OnDeadline, Watch},
    h2::{H2Config, H2Session, PREFACE},
};

use crate::{
    context::{BodyEvent, BodyMode, Context, Service},
    message::{Headers, Request, Response, Version},
    parse::{ChunkDecoder, ChunkError, Head, ParseError, parse_head},
};

/// Limits and options of the HTTP server.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HttpConfig {
    /// Largest request head (request line + headers) accepted; else 431.
    pub max_header_bytes: usize,
    /// Largest request body accepted; else 413. Bodies are buffered in memory.
    pub max_body_bytes: usize,
    /// HTTP/2 settings, or `None` to serve HTTP/1 only. HTTP/2 is detected from the client
    /// preface (prior knowledge, and TLS with ALPN `h2`) or an `Upgrade: h2c` request.
    pub h2: Option<H2Config>,
    /// Longest time a request head may take to arrive, measured from its first byte to its
    /// end, so a peer trickling a byte at a time cannot keep a half-received head alive
    /// (slowloris). When it passes the request is answered `408` and the connection closed.
    /// On HTTP/2 it bounds the time from the connection start to the client's `SETTINGS`.
    /// Default 10 s; `None` disables it.
    pub head_timeout: Option<Duration>,
    /// Longest time a keep-alive connection may wait for its next request. It starts once a
    /// request has been read; when it passes, the connection is closed after the responses
    /// still being prepared have been sent. On HTTP/2 it is the time without any frame from
    /// the peer, after which a connection with no open stream is closed with `GOAWAY`.
    /// Default 75 s; `None` disables it.
    pub keep_alive_timeout: Option<Duration>,
    /// Longest time without progress while a request body is being received: no body byte
    /// for this long answers a buffered request `408` (a streamed one is cut) and closes the
    /// connection. On HTTP/2, no frame for this long while request bodies are incomplete
    /// answers those streams `408` (streamed ones are reset). Default 60 s; `None` disables it.
    pub body_timeout: Option<Duration>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            max_header_bytes: 64 << 10,
            max_body_bytes: 1 << 20,
            h2: Some(H2Config::default()),
            head_timeout: Some(Duration::from_secs(10)),
            keep_alive_timeout: Some(Duration::from_secs(75)),
            body_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl HttpConfig {
    /// The shortest timeout configured, if any.
    fn shortest_timeout(&self) -> Option<Duration> {
        [
            self.head_timeout,
            self.keep_alive_timeout,
            self.body_timeout,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// Serves HTTP/1.x with `service`. Pass the result to `Listener::serve` (or wrap it in `Tls`).
pub fn serve<S: Service>(service: S) -> HttpAcceptor<S> {
    serve_with(HttpConfig::default(), service)
}

/// [`serve`] with explicit limits.
pub fn serve_with<S: Service>(cfg: HttpConfig, service: S) -> HttpAcceptor<S> {
    HttpAcceptor {
        service: Arc::new(service),
        cfg: Arc::new(cfg),
    }
}

/// The `only` acceptor created by [`serve`].
pub struct HttpAcceptor<S> {
    service: Arc<S>,
    cfg: Arc<HttpConfig>,
}

impl<S> std::fmt::Debug for HttpAcceptor<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAcceptor").finish_non_exhaustive()
    }
}

impl<S: Service> Acceptor for HttpAcceptor<S> {
    type Handler = Session<S>;

    fn on_open(&self, c: &Conn<Session<S>>) -> Session<S> {
        // The first head is timed from the connection's start (a peer that connects and sends
        // nothing, or stalls in the TLS handshake, is covered too).
        let watch = self.cfg.shortest_timeout().map(|t| {
            let w = Watch::register(c, t);
            w.arm(self.cfg.head_timeout);
            w
        });
        Session {
            service: self.service.clone(),
            cfg: self.cfg.clone(),
            watch,
            armed: Phase::Head,
            buf: Vec::new(),
            state: State::Head,
            ws: None,
            raw: None,
            h2: None,
            started: false,
            head: Resume::default(),
            early_probe: true,
            early_len: 0,
            consumed: 0,
            span: crate::trace::connection(c.peer_addr(), "1.1"),
        }
    }

    fn on_shutdown(&self, c: &Conn<Session<S>>) {
        // Run on the handler (it knows whether this is HTTP/1 or HTTP/2).
        let ok = c.spawn_blocking(|| (), |h: &mut Session<S>, c, ()| h.shutdown(c));
        if ok.is_err() {
            h1_shutdown(c);
        }
    }
}

enum Kind {
    Length(usize),
    Chunked(Box<ChunkDecoder>),
}

enum State {
    Head,
    /// A buffered body being collected before dispatch.
    Body {
        req: Box<Request>,
        kind: Kind,
        body: Vec<u8>,
        keep_alive: bool,
    },
    /// A streamed body: the service already runs and receives chunks through its sink.
    Stream {
        ctx: Box<Context>,
        kind: Kind,
        keep_alive: bool,
        scratch: Vec<u8>,
    },
    /// No more requests are read (`Connection: close`, or a protocol error).
    Closed,
}

/// Which deadline is armed on a connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Phase {
    /// None (or one that must be re-armed at the next read).
    Off,
    /// A request head is arriving (measured from its first byte).
    Head,
    /// Waiting for the next request.
    Idle,
    /// A request body is arriving (re-armed on progress).
    Body,
}

/// The per-connection handler: parses requests and dispatches them to the [`Service`].
pub struct Session<S> {
    service: Arc<S>,
    /// Shared by every connection of the acceptor.
    cfg: Arc<HttpConfig>,
    /// The connection's deadline, when any timeout is configured.
    watch: Option<Arc<Watch<Session<S>>>>,
    /// What `watch` is armed for.
    armed: Phase,
    /// Bytes of an incomplete head, carried over to the next `on_data`.
    buf: Vec<u8>,
    state: State,
    /// Set once a request was upgraded to WebSocket; the connection then speaks only that.
    ws: Option<Box<WsSession>>,
    /// Set once a request handed the connection over as raw bytes.
    raw: Option<(crate::raw::RawConn, Box<dyn crate::raw::RawHandler>)>,
    /// Set once the connection speaks HTTP/2.
    h2: Option<H2Session<S>>,
    /// Some bytes have been seen (the HTTP/2 preface is only looked for at the very start).
    started: bool,
    /// Progress on the head being received (so a head arriving in pieces is scanned once).
    head: Resume,
    /// TLS early data may still be arriving: ask the transport how much there is.
    early_probe: bool,
    /// The first this many bytes of the connection came as TLS early data (0-RTT).
    early_len: u64,
    /// Bytes consumed so far, while within the early data.
    consumed: u64,
    /// The connection span (`crate::trace`), ended on close.
    span: only_log::span::Span,
}

impl<S> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

/// HTTP/1 shutdown: the close goes into the response order, so it happens after every response
/// still being prepared (possibly on the pool) has been written, and right away when idle.
fn h1_shutdown<S: Service>(c: &Conn<Session<S>>) {
    match c.reserve_response() {
        Ok(slot) => slot.fill_close(Vec::new()),
        Err(_) => c.close_after_send(),
    }
}

impl<S: Service> Handler for Session<S> {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.read(c, data);
        if self.watch.is_some() {
            self.rearm();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        if let Some(w) = &self.watch {
            w.release();
        }
        if self.span.is_recording() {
            if let Some(e) = &err {
                self.span.record("error.type", e.to_string());
            }
            drop(std::mem::take(&mut self.span));
        }
        if let Some(h2) = &self.h2 {
            h2.on_close();
        }
        if let Some(ws) = &mut self.ws {
            ws.on_transport_closed();
        }
        if let Some((_, h)) = &mut self.raw {
            h.on_close();
        }
    }
}

impl<S> Drop for Session<S> {
    fn drop(&mut self) {
        if let Some(w) = &self.watch {
            w.release();
        }
    }
}

impl<S: Service> OnDeadline for Session<S> {
    fn on_deadline(&mut self, c: &Conn<Self>) {
        let Some(w) = &self.watch else { return };
        if !w.fired() {
            return; // re-armed since it fired
        }
        self.armed = Phase::Off;
        if let Some(h2) = &self.h2 {
            if let Some(p) = h2.on_deadline() {
                self.arm_h2(p, true);
            }
            return;
        }
        if self.ws.is_some() || self.raw.is_some() {
            return;
        }
        match &self.state {
            State::Closed => {}
            // Waiting for the next request: close once the pending responses are out.
            State::Head if self.buf.is_empty() => {
                self.state = State::Closed;
                h1_shutdown(c);
            }
            State::Head | State::Body { .. } => {
                self.buf = Vec::new();
                self.fail(c, 408);
            }
            // The service already runs and owns the response: the request cannot be answered.
            State::Stream { .. } => {
                self.state = State::Closed;
                c.close();
            }
        }
    }
}

impl<S: Service> Session<S> {
    /// Arms the deadline that fits the connection's state after a read.
    fn rearm(&mut self) {
        if let Some(h2) = &self.h2 {
            let p = h2.phase();
            return self.arm_h2(p, false);
        }
        let (phase, t) = if self.ws.is_some() || self.raw.is_some() {
            (Phase::Off, None)
        } else {
            match self.state {
                State::Closed => (Phase::Off, None),
                State::Head if self.buf.is_empty() => (Phase::Idle, self.cfg.keep_alive_timeout),
                State::Head => (Phase::Head, self.cfg.head_timeout),
                State::Body { .. } | State::Stream { .. } => (Phase::Body, self.cfg.body_timeout),
            }
        };
        // A head is timed from its first byte and idleness from the end of the last request:
        // only progress on a body re-arms an armed deadline.
        if phase == self.armed && phase != Phase::Body {
            return;
        }
        self.armed = phase;
        if let Some(w) = &self.watch {
            w.arm(t);
        }
    }

    /// HTTP/2: the preface deadline runs from the connection start; the others restart with
    /// every read.
    fn arm_h2(&mut self, phase: Phase, force: bool) {
        if phase == Phase::Head && self.armed == Phase::Head && !force {
            return;
        }
        let t = match phase {
            Phase::Off => None,
            Phase::Head => self.cfg.head_timeout,
            Phase::Idle => self.cfg.keep_alive_timeout,
            Phase::Body => self.cfg.body_timeout,
        };
        self.armed = phase;
        if let Some(w) = &self.watch {
            w.arm(t);
        }
    }

    fn read(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.early_probe {
            // TLS early data comes first and ends with the handshake; plain TCP has none.
            match only::tls::tls_info(c) {
                Some(i) => {
                    self.early_len = i.early_data_len;
                    self.early_probe = i.handshaking;
                }
                None => self.early_probe = false,
            }
        }
        if let Some(h2) = &self.h2 {
            return h2.on_data(data);
        }
        if let Some(ws) = &mut self.ws {
            return ws.on_data(data);
        }
        if let Some((rc, h)) = &mut self.raw {
            return h.on_data(rc, data);
        }
        if !self.started {
            // HTTP/2 with prior knowledge starts with a fixed 24-byte preface.
            if let Some(cfg) = self.cfg.h2.clone() {
                let mut seen = std::mem::take(&mut self.buf);
                seen.extend_from_slice(data);
                let n = seen.len().min(PREFACE.len());
                if PREFACE[..n] == seen[..n] {
                    if seen.len() >= PREFACE.len() {
                        self.started = true;
                        self.span.record("network.protocol.version", "2");
                        self.h2 = Some(H2Session::new(
                            c.inner().clone(),
                            cfg,
                            self.service.clone(),
                            c.peer_addr(),
                            &seen,
                            None,
                            self.early_len > 0,
                        ));
                    } else {
                        self.buf = seen; // wait for the rest of the preface
                    }
                    return;
                }
                // Neither the HTTP/2 preface nor the start of a known HTTP/1 method after a whole
                // preface's worth of bytes: a client that meant HTTP/2 and got it wrong. Say so in
                // HTTP/2 terms (GOAWAY PROTOCOL_ERROR) and hang up.
                if seen.len() >= PREFACE.len() && !starts_with_http1_method(&seen) {
                    let goaway = [
                        0, 0, 8, 7, 0, 0, 0, 0, 0, // GOAWAY on stream 0, 8 bytes
                        0, 0, 0, 0, 0, 0, 0, 1, // last stream 0, PROTOCOL_ERROR
                    ];
                    let _ = c.send(&goaway);
                    c.close_after_send();
                    self.state = State::Closed;
                    self.started = true;
                    return;
                }
                self.buf = seen[..seen.len() - data.len()].to_vec();
            }
            self.started = true;
        }
        if matches!(self.state, State::Closed) {
            return;
        }
        // Common case: nothing carried over, so parse straight from the borrowed read buffer.
        let mut owned = std::mem::take(&mut self.buf);
        if owned.is_empty() {
            let used = self.process(c, data);
            self.count_early(used);
            if !matches!(self.state, State::Closed) && used < data.len() {
                self.buf = data[used..].to_vec();
            }
        } else {
            owned.extend_from_slice(data);
            let used = self.process(c, &owned);
            self.count_early(used);
            if !matches!(self.state, State::Closed) && used < owned.len() {
                // Keep the allocation: an incomplete head grows in place.
                owned.drain(..used);
                self.buf = owned;
            }
        }
    }

    /// Counts consumed bytes while they may be early data.
    fn count_early(&mut self, used: usize) {
        if self.early_probe || self.consumed < self.early_len {
            self.consumed += used as u64;
        }
    }

    /// Whether a request head starting `pos` bytes into what `process` got arrived as TLS
    /// early data.
    fn early_at(&self, pos: usize) -> bool {
        self.consumed + (pos as u64) < self.early_len
    }

    fn shutdown(&self, c: &Conn<Self>) {
        match &self.h2 {
            Some(h2) => h2.shutdown(),
            None => h1_shutdown(c),
        }
    }

    /// Consumes as many whole requests as `src` holds. Returns the bytes used.
    fn process(&mut self, c: &Conn<Self>, src: &[u8]) -> usize {
        let mut pos = 0;
        loop {
            // After an upgrade whatever follows the handshake request is WebSocket data.
            if let Some(ws) = &mut self.ws {
                ws.on_data(&src[pos..]);
                return src.len();
            }
            if let Some((rc, h)) = &mut self.raw {
                if pos < src.len() {
                    h.on_data(rc, &src[pos..]);
                }
                return src.len();
            }
            match &mut self.state {
                State::Closed => return src.len(),
                State::Head => {
                    if pos == src.len() {
                        return pos;
                    }
                    match parse_head(&src[pos..], &mut self.head) {
                        Ok(None) => {
                            if src.len() - pos > self.cfg.max_header_bytes {
                                self.fail(c, 431);
                                return src.len();
                            }
                            return pos;
                        }
                        Ok(Some((head, n))) => {
                            if n > self.cfg.max_header_bytes {
                                self.fail(c, 431);
                                return src.len();
                            }
                            let early = self.early_at(pos);
                            pos += n;
                            // The next head and the next idle period are timed afresh.
                            self.armed = Phase::Off;
                            self.on_head(c, head, early);
                        }
                        Err(e) => {
                            self.fail(
                                c,
                                match e {
                                    ParseError::Bad => 400,
                                    ParseError::TooManyHeaders => 431,
                                    ParseError::Version => 505,
                                },
                            );
                            return src.len();
                        }
                    }
                }
                State::Body { kind, body, .. } => {
                    let rest = &src[pos..];
                    let done = match kind {
                        Kind::Length(left) => {
                            let n = rest.len().min(*left);
                            body.extend_from_slice(&rest[..n]);
                            *left -= n;
                            pos += n;
                            *left == 0
                        }
                        Kind::Chunked(dec) => match dec.feed(rest, body, self.cfg.max_body_bytes) {
                            Ok(n) => {
                                pos += n;
                                dec.is_done()
                            }
                            Err(e) => {
                                let status = if e == ChunkError::TooLarge { 413 } else { 400 };
                                self.fail(c, status);
                                return src.len();
                            }
                        },
                    };
                    if !done {
                        return pos; // need more bytes
                    }
                    let State::Body {
                        mut req,
                        kind,
                        body,
                        keep_alive,
                    } = std::mem::replace(&mut self.state, State::Head)
                    else {
                        unreachable!()
                    };
                    if let Kind::Chunked(dec) = kind {
                        req.trailers = dec.trailers();
                    }
                    req.body = body;
                    self.dispatch(c, *req, keep_alive);
                }
                State::Stream {
                    ctx, kind, scratch, ..
                } => {
                    let rest = &src[pos..];
                    let done = match kind {
                        Kind::Length(left) => {
                            let n = rest.len().min(*left);
                            if n > 0 {
                                ctx.deliver(BodyEvent::Chunk(&rest[..n]));
                            }
                            *left -= n;
                            pos += n;
                            *left == 0
                        }
                        Kind::Chunked(dec) => {
                            scratch.clear();
                            match dec.feed(rest, scratch, usize::MAX) {
                                Ok(n) => {
                                    pos += n;
                                    if !scratch.is_empty() {
                                        ctx.deliver(BodyEvent::Chunk(scratch));
                                    }
                                    dec.is_done()
                                }
                                Err(_) => {
                                    // Framing error mid-stream: the request cannot be answered
                                    // normally any more.
                                    self.state = State::Closed;
                                    c.close();
                                    return src.len();
                                }
                            }
                        }
                    };
                    if !done {
                        return pos;
                    }
                    let State::Stream {
                        mut ctx,
                        kind,
                        keep_alive,
                        ..
                    } = std::mem::replace(&mut self.state, State::Head)
                    else {
                        unreachable!()
                    };
                    let trailers = match kind {
                        Kind::Chunked(dec) => dec.trailers(),
                        Kind::Length(_) => Headers::new(),
                    };
                    ctx.deliver(BodyEvent::End(&trailers));
                    if !ctx.responded() && !ctx.is_detached() {
                        ctx.respond(Response::text(500, "handler did not respond"));
                    }
                    if !keep_alive {
                        self.state = State::Closed;
                    }
                }
            }
        }
    }

    /// Validates a head, decides how the body is framed, and either dispatches or waits for it.
    fn on_head(&mut self, c: &Conn<Self>, mut head: Head, early: bool) {
        if early {
            // Arrived as TLS early data (maybe a replay): marked as an RFC 8470 intermediary
            // would, so the application can answer 425 Too Early.
            head.headers.append("early-data", "1");
        }
        let h = &head.headers;
        // One pass over the fields for everything framing needs (a lookup per header name
        // cost ~4% of pipelined throughput).
        let (mut host, mut close, mut keep, mut te, mut te_n, mut expect) =
            (false, false, false, None, 0, None);
        // Content-Length: every value must parse and agree.
        let (mut cl, mut cl_bad) = (None::<usize>, false);
        for (n, v) in h.iter() {
            let token = |t: &str| v.split(',').any(|x| x.trim().eq_ignore_ascii_case(t));
            match n.len() {
                4 if n.eq_ignore_ascii_case("host") => host = true,
                6 if n.eq_ignore_ascii_case("expect") => {
                    expect = expect.or(Some(v));
                }
                10 if n.eq_ignore_ascii_case("connection") => {
                    close |= token("close");
                    keep |= token("keep-alive");
                }
                14 if n.eq_ignore_ascii_case("content-length") => match v.parse::<usize>() {
                    Ok(len) if cl.is_none_or(|l| l == len) => cl = Some(len),
                    _ => cl_bad = true,
                },
                17 if n.eq_ignore_ascii_case("transfer-encoding") => {
                    te = te.or(Some(v));
                    te_n += 1;
                }
                _ => {}
            }
        }
        if head.version == Version::Http11 && !host {
            return self.fail(c, 400);
        }
        let keep_alive = match head.version {
            Version::Http11 => !close,
            Version::Http10 => keep,
            Version::Http2 | Version::Http3 => true,
        };
        let mut declared = 0usize;
        let kind = match (te, cl.is_none() && !cl_bad) {
            (Some(_), false) => return self.fail(c, 400), // request smuggling vector
            (Some(te), true) => {
                let last = te.rsplit(',').next().unwrap_or("").trim();
                if !last.eq_ignore_ascii_case("chunked") || te_n > 1 {
                    return self.fail(c, 501);
                }
                Some(Kind::Chunked(Box::new(ChunkDecoder::new())))
            }
            (None, false) => {
                if cl_bad {
                    return self.fail(c, 400);
                }
                declared = cl.unwrap_or(0);
                (declared > 0).then_some(Kind::Length(declared))
            }
            (None, true) => None,
        };
        let expect_continue = head.version == Version::Http11
            && expect.is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        let req = Request {
            method: head.method,
            target: head.target,
            version: head.version,
            headers: head.headers,
            trailers: Headers::new(),
            body: Vec::new(),
            peer: c.peer_addr(),
            protocol: None,
        };
        let Some(kind) = kind else {
            return self.dispatch(c, req, keep_alive);
        };
        let stream =
            self.service.streams_bodies() && self.service.body_mode(&req) == BodyMode::Stream;
        if !stream && declared > self.cfg.max_body_bytes {
            return self.fail(c, 413);
        }
        if expect_continue {
            let _ = c.send(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        if !stream {
            self.state = State::Body {
                req: Box::new(req),
                kind,
                body: Vec::new(),
                keep_alive,
            };
            return;
        }
        // Streamed: run the service now, feed it the body as it arrives.
        let Ok(slot) = c.reserve_response() else {
            self.state = State::Closed;
            return;
        };
        let mut ctx = Box::new(Context::new(req, slot, keep_alive));
        let g = crate::trace::begin(&mut ctx);
        self.service.call(&mut ctx);
        drop(g);
        self.state = State::Stream {
            ctx,
            kind,
            keep_alive,
            scratch: Vec::new(),
        };
    }

    fn dispatch(&mut self, c: &Conn<Self>, req: Request, keep_alive: bool) {
        if self.cfg.h2.is_some() && req.body.is_empty() {
            if let Some(settings) = h2c_settings(&req) {
                // HTTP/2 takes the connection over: no HTTP/1 response slot is needed.
                let _ = c.send(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
                );
                let cfg = self.cfg.h2.clone().unwrap_or_default();
                self.span.record("network.protocol.version", "2");
                self.h2 = Some(H2Session::new(
                    c.inner().clone(),
                    cfg,
                    self.service.clone(),
                    c.peer_addr(),
                    &[],
                    Some((req, settings)),
                    self.early_len > 0,
                ));
                return;
            }
        }
        let Ok(slot) = c.reserve_response() else {
            self.state = State::Closed;
            return;
        };
        let mut ctx = Context::new(req, slot, keep_alive);
        let g = crate::trace::begin(&mut ctx);
        self.service.call(&mut ctx);
        drop(g);
        if !ctx.responded() && !ctx.is_detached() {
            ctx.respond(Response::text(500, "handler did not respond"));
        }
        if let Some(mut h) = ctx.take_raw() {
            let rc = crate::raw::RawConn(c.inner().clone());
            h.on_open(&rc);
            self.raw = Some((rc, h));
            return;
        }
        if let Some(up) = ctx.take_upgrade() {
            let mut ws = WsSession::new(c.inner().clone(), &up.cfg, up.pmd, up.handler);
            ws.open();
            self.ws = Some(Box::new(ws));
            return;
        }
        if !keep_alive {
            self.state = State::Closed;
        }
    }

    /// Answers a protocol error and stops reading from the connection.
    fn fail(&mut self, c: &Conn<Self>, status: u16) {
        self.state = State::Closed;
        if let Ok(slot) = c.reserve_response() {
            let mut out = Vec::new();
            Response::text(status, crate::message::reason(status)).encode(
                Version::Http11,
                false,
                false,
                &mut out,
            );
            slot.fill_close(out);
        }
    }
}

/// The decoded `HTTP2-Settings` of an `Upgrade: h2c` request, if it is one.
fn h2c_settings(req: &Request) -> Option<Vec<u8>> {
    let h = &req.headers;
    if !h.has_token("upgrade", "h2c") || !h.has_token("connection", "upgrade") {
        return None;
    }
    let mut all = h.get_all("http2-settings");
    let v = all.next()?;
    if all.next().is_some() {
        return None;
    }
    let bytes = only_crypto::base64::URL_SAFE_NO_PAD
        .decode(v.trim().trim_end_matches('='))
        .ok()?;
    (bytes.len() % 6 == 0).then_some(bytes)
}

fn starts_with_http1_method(b: &[u8]) -> bool {
    [
        &b"GET "[..],
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ]
    .iter()
    .any(|m| b.starts_with(m))
}

#[cfg(test)]
mod size_tests {
    /// Every keep-alive connection holds one `Session`; the WebSocket / HTTP/2 / body states are
    /// boxed so an idle HTTP/1 connection does not pay for them (it was 736 bytes).
    #[test]
    fn idle_session_stays_small() {
        let n = size_of::<super::Session<crate::Router>>();
        assert!(n <= 256, "Session is {n} bytes");
    }
}
