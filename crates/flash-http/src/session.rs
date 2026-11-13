//! The HTTP/1.1 connection state machine and its flash `Acceptor`.

use std::sync::Arc;

use flash_core::{Acceptor, Conn, Error, Handler};
use flash_ws::WsSession;

use crate::{
    context::{BodyEvent, BodyMode, Context, Service},
    message::{Headers, Request, Response, Version},
    parse::{ChunkDecoder, ChunkError, Head, ParseError, parse_head},
};

/// Limits and options of the HTTP server.
#[derive(Clone, Debug)]
pub struct HttpConfig {
    /// Largest request head (request line + headers) accepted; else 431.
    pub max_header_bytes: usize,
    /// Largest request body accepted; else 413. Bodies are buffered in memory.
    pub max_body_bytes: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            max_header_bytes: 64 << 10,
            max_body_bytes: 1 << 20,
        }
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
        cfg,
    }
}

/// The flash acceptor created by [`serve`].
pub struct HttpAcceptor<S> {
    service: Arc<S>,
    cfg: HttpConfig,
}

impl<S: Service> Acceptor for HttpAcceptor<S> {
    type Handler = Session<S>;

    fn on_open(&self, _c: &Conn<Session<S>>) -> Session<S> {
        Session {
            service: self.service.clone(),
            cfg: self.cfg.clone(),
            buf: Vec::new(),
            state: State::Head,
            ws: None,
        }
    }

    fn on_shutdown(&self, c: &Conn<Session<S>>) {
        // The close goes into the response order: it happens after every response still being
        // prepared (possibly on the pool) has been written, and right away on an idle connection.
        match c.reserve_response() {
            Ok(slot) => slot.fill_close(Vec::new()),
            Err(_) => c.close_after_send(),
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
        req: Request,
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

/// The per-connection handler: parses requests and dispatches them to the [`Service`].
pub struct Session<S> {
    service: Arc<S>,
    cfg: HttpConfig,
    /// Bytes of an incomplete head, carried over to the next `on_data`.
    buf: Vec<u8>,
    state: State,
    /// Set once a request was upgraded to WebSocket; the connection then speaks only that.
    ws: Option<WsSession>,
}

impl<S: Service> Handler for Session<S> {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(ws) = &mut self.ws {
            return ws.on_data(data);
        }
        if matches!(self.state, State::Closed) {
            return;
        }
        // Common case: nothing carried over, so parse straight from the borrowed read buffer.
        let mut owned = std::mem::take(&mut self.buf);
        let src: &[u8] = if owned.is_empty() {
            data
        } else {
            owned.extend_from_slice(data);
            &owned
        };
        let used = self.process(c, src);
        if !matches!(self.state, State::Closed) && used < src.len() {
            self.buf = src[used..].to_vec();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<Error>) {
        if let Some(ws) = &mut self.ws {
            ws.on_transport_closed();
        }
    }
}

impl<S: Service> Session<S> {
    /// Consumes as many whole requests as `src` holds. Returns the bytes used.
    fn process(&mut self, c: &Conn<Self>, src: &[u8]) -> usize {
        let mut pos = 0;
        loop {
            // After an upgrade whatever follows the handshake request is WebSocket data.
            if let Some(ws) = &mut self.ws {
                ws.on_data(&src[pos..]);
                return src.len();
            }
            match &mut self.state {
                State::Closed => return src.len(),
                State::Head => {
                    if pos == src.len() {
                        return pos;
                    }
                    match parse_head(&src[pos..]) {
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
                            pos += n;
                            self.on_head(c, head);
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
                    self.dispatch(c, req, keep_alive);
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
    fn on_head(&mut self, c: &Conn<Self>, head: Head) {
        let h = &head.headers;
        if head.version == Version::Http11 && h.get("host").is_none() {
            return self.fail(c, 400);
        }
        let keep_alive = match head.version {
            Version::Http11 => !h.has_token("connection", "close"),
            Version::Http10 => h.has_token("connection", "keep-alive"),
        };
        let te = h.get("transfer-encoding");
        let cl = h.get_all("content-length").collect::<Vec<_>>();
        let mut declared = 0usize;
        let kind = match (te, cl.is_empty()) {
            (Some(_), false) => return self.fail(c, 400), // request smuggling vector
            (Some(te), true) => {
                let last = te.rsplit(',').next().unwrap_or("").trim();
                if !last.eq_ignore_ascii_case("chunked")
                    || h.get_all("transfer-encoding").count() > 1
                {
                    return self.fail(c, 501);
                }
                Some(Kind::Chunked(Box::new(ChunkDecoder::new())))
            }
            (None, false) => {
                let mut len = None;
                for v in &cl {
                    match v.parse::<usize>() {
                        Ok(n) if len.is_none_or(|l| l == n) => len = Some(n),
                        _ => return self.fail(c, 400),
                    }
                }
                declared = len.unwrap_or(0);
                (declared > 0).then_some(Kind::Length(declared))
            }
            (None, true) => None,
        };
        let expect_continue = head.version == Version::Http11
            && head
                .headers
                .get("expect")
                .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        let req = Request {
            method: head.method,
            target: head.target,
            version: head.version,
            headers: head.headers,
            trailers: Headers::new(),
            body: Vec::new(),
            peer: c.peer_addr(),
        };
        let Some(kind) = kind else {
            return self.dispatch(c, req, keep_alive);
        };
        let stream = self.service.body_mode(&req) == BodyMode::Stream;
        if !stream && declared > self.cfg.max_body_bytes {
            return self.fail(c, 413);
        }
        if expect_continue {
            let _ = c.send(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        if !stream {
            self.state = State::Body {
                req,
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
        self.service.call(&mut ctx);
        self.state = State::Stream {
            ctx,
            kind,
            keep_alive,
            scratch: Vec::new(),
        };
    }

    fn dispatch(&mut self, c: &Conn<Self>, req: Request, keep_alive: bool) {
        let Ok(slot) = c.reserve_response() else {
            self.state = State::Closed;
            return;
        };
        let mut ctx = Context::new(req, slot, keep_alive);
        self.service.call(&mut ctx);
        if !ctx.responded() && !ctx.is_detached() {
            ctx.respond(Response::text(500, "handler did not respond"));
        }
        if let Some(up) = ctx.take_upgrade() {
            let mut ws = WsSession::new(c.inner().clone(), &up.cfg, up.pmd, up.handler);
            ws.open();
            self.ws = Some(ws);
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
