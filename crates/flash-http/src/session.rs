//! The HTTP/1.1 connection state machine and its flash `Acceptor`.

use std::sync::Arc;

use flash_core::{Acceptor, Conn, Error, Handler};

use crate::{
    context::{Context, Service},
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
    Body {
        head: Head,
        kind: Kind,
        body: Vec<u8>,
        keep_alive: bool,
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
}

impl<S: Service> Handler for Session<S> {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
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

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<Error>) {}
}

impl<S: Service> Session<S> {
    /// Consumes as many whole requests as `src` holds. Returns the bytes used.
    fn process(&mut self, c: &Conn<Self>, src: &[u8]) -> usize {
        let mut pos = 0;
        loop {
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
                        head,
                        kind,
                        body,
                        keep_alive,
                    } = std::mem::replace(&mut self.state, State::Head)
                    else {
                        unreachable!()
                    };
                    let trailers = match kind {
                        Kind::Chunked(dec) => dec.trailers(),
                        Kind::Length(_) => Headers::new(),
                    };
                    self.dispatch(c, head, body, trailers, keep_alive);
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
                let n = len.unwrap_or(0);
                if n > self.cfg.max_body_bytes {
                    return self.fail(c, 413);
                }
                (n > 0).then_some(Kind::Length(n))
            }
            (None, true) => None,
        };
        match kind {
            None => self.dispatch(c, head, Vec::new(), Headers::new(), keep_alive),
            Some(kind) => {
                if head.version == Version::Http11
                    && head
                        .headers
                        .get("expect")
                        .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"))
                {
                    let _ = c.send(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                self.state = State::Body {
                    head,
                    kind,
                    body: Vec::new(),
                    keep_alive,
                };
            }
        }
    }

    fn dispatch(
        &mut self,
        c: &Conn<Self>,
        head: Head,
        body: Vec<u8>,
        trailers: Headers,
        keep_alive: bool,
    ) {
        let Ok(slot) = c.reserve_response() else {
            self.state = State::Closed;
            return;
        };
        let req = Request {
            method: head.method,
            target: head.target,
            version: head.version,
            headers: head.headers,
            trailers,
            body,
            peer: c.peer_addr(),
        };
        let mut ctx = Context::new(req, slot, keep_alive);
        self.service.call(&mut ctx);
        if !ctx.responded() && !ctx.is_detached() {
            ctx.respond(Response::text(500, "handler did not respond"));
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
