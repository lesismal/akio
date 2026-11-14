//! The WebSocket client: dial `ws://` and `wss://` URLs on a `only` [`Engine`].
//!
//! [`dial`] resolves the host (on the calling thread), connects without blocking (trying every
//! resolved address in turn), runs TLS through `only::tls` for `wss://`, performs the opening
//! handshake and then serves the connection with the same [`WsHandler`] model the server uses:
//! callbacks on the connection's I/O thread, [`WsSender`] to send from any thread. Frames are
//! masked, `permessage-deflate` is offered when [`WsConfig::permessage_deflate`] is set.
//! [`dial_blocking`] is the blocking convenience that waits for the handshake.
//!
//! ```no_run
//! use std::sync::Arc;
//! use only::Engine;
//! use only_ws::{Message, WsHandler, WsSender, client::{self, DialOptions}};
//!
//! struct Print;
//! impl WsHandler for Print {
//!     fn on_message(&mut self, _ws: &WsSender, msg: Message) {
//!         println!("{msg:?}");
//!     }
//! }
//!
//! let engine = Arc::new(Engine::builder().client_threads(1).build().unwrap());
//! engine.start().unwrap();
//! let ws = client::dial_blocking(&engine, "ws://127.0.0.1:8080/ws", &DialOptions::default(), Print).unwrap();
//! ws.send_text("hello").unwrap();
//! ```

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, Weak, mpsc},
    time::Duration,
};

use only::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, Tls},
};
use only_core::ConnInner;

use crate::{
    Message, WsConfig, WsHandler, WsSender, WsSession, accept_key, deflate::PmdOffer, http1,
};

/// How to dial.
#[derive(Clone)]
#[non_exhaustive]
pub struct DialOptions {
    /// Message limits and compression; `permessage_deflate` decides whether it is offered.
    pub config: WsConfig,
    /// What the `permessage-deflate` offer asks for.
    pub pmd: PmdOffer,
    /// Subprotocols to offer, in order of preference (`Sec-WebSocket-Protocol`). The server's
    /// choice is available from [`WsSender::subprotocol`].
    pub protocols: Vec<String>,
    /// `Origin` header, for servers that check it.
    pub origin: Option<String>,
    /// Extra request header fields (e.g. `Authorization`, cookies). Fields the handshake itself
    /// sets (`Host`, `Upgrade`, `Connection`, `Sec-WebSocket-*`) are ignored here.
    pub headers: Vec<(String, String)>,
    /// TLS client configuration for `wss://` (roots, client certificate, ALPN...). Required for
    /// `wss://`; do not offer `h2` in its ALPN list.
    pub tls: Option<TlsClientConfig>,
    /// Name for certificate verification and SNI; the URL's host by default.
    pub server_name: Option<String>,
    /// Limit for connecting plus the TLS and WebSocket handshakes.
    pub handshake_timeout: Duration,
    /// After the close handshake, how long to wait for the server to close the TCP connection
    /// before closing it from this side.
    pub close_timeout: Duration,
}

impl Default for DialOptions {
    fn default() -> Self {
        DialOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            tls: None,
            server_name: None,
            handshake_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(3),
        }
    }
}

impl std::fmt::Debug for DialOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialOptions")
            .field("config", &self.config)
            .field("pmd", &self.pmd)
            .field("protocols", &self.protocols)
            .field("origin", &self.origin)
            .field("headers", &self.headers)
            .field("tls", &self.tls.is_some())
            .field("server_name", &self.server_name)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("close_timeout", &self.close_timeout)
            .finish()
    }
}

/// Why a dial failed (before `on_open`).
#[derive(Debug)]
#[non_exhaustive]
pub enum WsClientError {
    /// The URL is not a usable `ws://` or `wss://` URL.
    InvalidUrl(String),
    /// Resolving, connecting, TLS or the connection itself failed.
    Io(io::Error),
    /// The server answered with something other than `101 Switching Protocols`.
    Status(u16, String),
    /// The server's `101` answer is not a valid WebSocket handshake.
    Handshake(&'static str),
    /// [`DialOptions::handshake_timeout`] passed.
    Timeout,
    /// The connection closed before the handshake completed.
    Closed,
}

impl std::fmt::Display for WsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsClientError::InvalidUrl(u) => write!(f, "invalid WebSocket url: {u}"),
            WsClientError::Io(e) => write!(f, "io: {e}"),
            WsClientError::Status(s, r) => write!(f, "handshake refused: {s} {r}"),
            WsClientError::Handshake(m) => write!(f, "bad handshake: {m}"),
            WsClientError::Timeout => f.write_str("handshake timed out"),
            WsClientError::Closed => f.write_str("connection closed during the handshake"),
        }
    }
}

impl std::error::Error for WsClientError {}

/// A parsed `ws://` / `wss://` URL.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WsUrl {
    tls: bool,
    host: String,
    port: u16,
    target: String,
    host_header: String,
}

pub(crate) fn parse_url(url: &str) -> Result<WsUrl, WsClientError> {
    let bad = || WsClientError::InvalidUrl(url.to_owned());
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "ws" => false,
        "wss" => true,
        _ => return Err(bad()),
    };
    if rest.contains('#') {
        return Err(bad()); // RFC 6455 3: fragments are not allowed
    }
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let default_port = if tls { 443 } else { 80 };
    let (host_part, port) = if let Some(after) = authority.strip_prefix('[') {
        let (h, tail) = after.split_once(']').ok_or_else(bad)?;
        let port = match tail {
            "" => default_port,
            t => t
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .ok_or_else(bad)?,
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| bad())?),
            None => (authority, default_port),
        }
    };
    if host_part.is_empty() {
        return Err(bad());
    }
    let shown = if authority.starts_with('[') {
        format!("[{host_part}]")
    } else {
        host_part.to_owned()
    };
    let host_header = if port == default_port {
        shown
    } else {
        format!("{shown}:{port}")
    };
    Ok(WsUrl {
        tls,
        host: host_part.to_owned(),
        port,
        target,
        host_header,
    })
}

type ErrCb = Box<dyn FnOnce(WsClientError) + Send>;

/// What one dial still owns until it resolves (opens or fails).
struct Pending {
    handler: Option<Box<dyn WsHandler>>,
    on_error: Option<ErrCb>,
    /// The connection being handshaken, for the timeout to close.
    conn: Option<Weak<ConnInner>>,
    timed_out: bool,
}

impl Pending {
    fn resolved(&self) -> bool {
        self.on_error.is_none()
    }
}

/// Everything a dial needs, shared by its address attempts.
struct Plan {
    engine: Arc<Engine>,
    addrs: Vec<SocketAddr>,
    tls: Option<(TlsClientConfig, String)>,
    request: Vec<u8>,
    expected_accept: String,
    config: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    pending: Mutex<Pending>,
}

impl Plan {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reports `e` unless the dial already resolved.
    fn fail(&self, e: WsClientError) {
        let cb = {
            let mut p = self.lock();
            p.handler = None;
            p.on_error.take()
        };
        if let Some(cb) = cb {
            cb(e);
        }
    }
}

/// Dials `url` and serves the connection with `handler` once the handshake succeeds
/// (`on_open` runs then, on an I/O thread). On failure before that, `on_error` is called once
/// instead (on an I/O thread, the calling thread for an invalid URL or a failed resolution, or
/// the timer thread when the handshake times out while connecting); the handler is dropped
/// unused.
///
/// The engine must be started; connections run on its client threads
/// ([`EngineBuilder::client_threads`](only::EngineBuilder::client_threads)) when it has them.
/// Name resolution happens on the calling thread and may block.
pub fn dial(
    engine: &Arc<Engine>,
    url: &str,
    opts: &DialOptions,
    handler: impl WsHandler,
    on_error: impl FnOnce(WsClientError) + Send + 'static,
) {
    let u = match parse_url(url) {
        Ok(u) => u,
        Err(e) => return on_error(e),
    };
    let tls = if u.tls {
        let Some(cfg) = opts.tls.clone() else {
            return on_error(WsClientError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wss:// needs DialOptions::tls",
            )));
        };
        Some((
            cfg,
            opts.server_name.clone().unwrap_or_else(|| u.host.clone()),
        ))
    } else {
        None
    };
    let addrs: Vec<SocketAddr> = match (u.host.as_str(), u.port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => return on_error(WsClientError::Io(e)),
    };
    if addrs.is_empty() {
        return on_error(WsClientError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "host did not resolve",
        )));
    }
    let key = new_key();
    let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
    let request = build_request(&u, &key, opts, pmd.as_ref());
    let plan = Arc::new(Plan {
        engine: engine.clone(),
        addrs,
        tls,
        request,
        expected_accept: accept_key(&key),
        config: opts.config.clone(),
        pmd,
        protocols: opts.protocols.clone(),
        close_timeout: opts.close_timeout,
        pending: Mutex::new(Pending {
            handler: Some(Box::new(handler)),
            on_error: Some(Box::new(on_error)),
            conn: None,
            timed_out: false,
        }),
    });
    let weak = Arc::downgrade(&plan);
    crate::timer::after(opts.handshake_timeout, move || {
        let Some(plan) = weak.upgrade() else { return };
        let conn = {
            let mut p = plan.lock();
            if p.resolved() {
                return;
            }
            p.timed_out = true;
            p.conn.as_ref().map(Weak::upgrade)
        };
        match conn {
            // Handshaking: closing it reports the timeout from the I/O thread.
            Some(Some(c)) => c.close(),
            // Still connecting (or the connection is already gone): report it now.
            _ => plan.fail(WsClientError::Timeout),
        }
    });
    dial_addr(plan, 0);
}

fn dial_addr(plan: Arc<Plan>, i: usize) {
    let addr = plan.addrs[i];
    let acceptor = ClientAcceptor { plan: plan.clone() };
    let on_err = {
        let plan = plan.clone();
        move |e: io::Error| {
            if plan.lock().resolved() {
                return;
            }
            if i + 1 < plan.addrs.len() {
                // Next address (`localhost` is often ::1 first, then 127.0.0.1).
                dial_addr(plan, i + 1);
            } else {
                plan.fail(WsClientError::Io(e));
            }
        }
    };
    match &plan.tls {
        Some((cfg, name)) => match Tls::client(cfg.clone(), name, acceptor) {
            Ok(a) => plan.engine.dial(addr, a, on_err),
            Err(e) => plan.fail(WsClientError::Io(e)),
        },
        None => plan.engine.dial(addr, acceptor, on_err),
    }
}

/// Like [`dial`], blocking until the handshake completes; returns the connection's sender.
/// `handler.on_open` has been called (or is about to be) when this returns. Do not call it on
/// an I/O thread of the same engine.
pub fn dial_blocking(
    engine: &Arc<Engine>,
    url: &str,
    opts: &DialOptions,
    handler: impl WsHandler,
) -> Result<WsSender, WsClientError> {
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    dial(
        engine,
        url,
        opts,
        Notify {
            inner: Box::new(handler),
            tx: Some(tx),
        },
        move |e| {
            let _ = tx2.send(Err(e));
        },
    );
    // The handshake timeout always resolves the dial; the margin only guards against a bug.
    rx.recv_timeout(opts.handshake_timeout + Duration::from_secs(5))
        .unwrap_or(Err(WsClientError::Timeout))
}

/// Forwards to the application's handler, reporting the open to [`dial_blocking`].
struct Notify {
    inner: Box<dyn WsHandler>,
    tx: Option<mpsc::Sender<Result<WsSender, WsClientError>>>,
}

impl WsHandler for Notify {
    fn on_open(&mut self, ws: &WsSender) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Ok(ws.clone()));
        }
        self.inner.on_open(ws);
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        self.inner.on_message(ws, msg);
    }
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {
        self.inner.on_pong(ws, payload);
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        self.inner.on_close(code, reason);
    }
}

fn new_key() -> String {
    use base64::Engine;
    let mut k = [0u8; 16];
    if getrandom::getrandom(&mut k).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        k = t.to_le_bytes();
    }
    base64::engine::general_purpose::STANDARD.encode(k)
}

fn build_request(u: &WsUrl, key: &str, opts: &DialOptions, pmd: Option<&PmdOffer>) -> Vec<u8> {
    let clean = |v: &str| v.replace(['\r', '\n'], "");
    let mut r = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        u.target, u.host_header
    );
    if !opts.protocols.is_empty() {
        r.push_str(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            clean(&opts.protocols.join(", "))
        ));
    }
    if let Some(o) = pmd {
        r.push_str(&format!("Sec-WebSocket-Extensions: {}\r\n", o.header()));
    }
    if let Some(origin) = &opts.origin {
        r.push_str(&format!("Origin: {}\r\n", clean(origin)));
    }
    let mut ua = false;
    for (n, v) in &opts.headers {
        let lower = n.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "upgrade" | "connection" | "origin")
            || lower.starts_with("sec-websocket-")
            || n.contains([':', '\r', '\n'])
        {
            continue;
        }
        ua |= lower == "user-agent";
        r.push_str(&format!("{n}: {}\r\n", clean(v)));
    }
    if !ua {
        r.push_str("User-Agent: only-ws\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

struct ClientAcceptor {
    plan: Arc<Plan>,
}

impl Acceptor for ClientAcceptor {
    type Handler = ClientConn;

    fn on_open(&self, c: &Conn<ClientConn>) -> ClientConn {
        let resolved = {
            let mut p = self.plan.lock();
            p.conn = Some(Arc::downgrade(c.inner()));
            p.resolved()
        };
        if resolved {
            c.close(); // timed out while connecting
        } else if c.send(&self.plan.request).is_err() {
            c.close();
        }
        ClientConn {
            plan: Some(self.plan.clone()),
            buf: Vec::new(),
            ws: None,
        }
    }
}

/// The connection handler of a dialed WebSocket: handshake, then the session.
struct ClientConn {
    plan: Option<Arc<Plan>>,
    buf: Vec<u8>,
    ws: Option<WsSession>,
}

/// Largest response head accepted.
const MAX_HEAD: usize = 16 << 10;

impl ClientConn {
    fn handshake(&mut self, c: &Conn<Self>) {
        let Some(plan) = self.plan.clone() else {
            return;
        };
        match check_response(
            &plan.expected_accept,
            &plan.protocols,
            plan.pmd.as_ref(),
            &self.buf,
        ) {
            Ok(None) => {
                if self.buf.len() > MAX_HEAD {
                    self.plan = None;
                    plan.fail(WsClientError::Handshake("response head too large"));
                    c.close();
                }
            }
            Err(e) => {
                self.plan = None;
                plan.fail(e);
                c.close();
            }
            Ok(Some(ok)) => {
                self.plan = None;
                let handler = {
                    let mut p = plan.lock();
                    p.on_error = None;
                    p.conn = None;
                    p.handler.take()
                };
                let Some(handler) = handler else {
                    c.close();
                    return;
                };
                let rest = self.buf.split_off(ok.head_len);
                self.buf = Vec::new();
                let mut ws = WsSession::client(
                    c.inner().clone(),
                    &plan.config,
                    ok.pmd,
                    handler,
                    ok.protocol,
                    plan.close_timeout,
                );
                ws.open();
                if !rest.is_empty() {
                    ws.on_data(&rest);
                }
                self.ws = Some(ws);
            }
        }
    }
}

pub(crate) struct Accepted {
    pub(crate) head_len: usize,
    pmd: Option<crate::deflate::PmdParams>,
    protocol: Option<String>,
}

/// Validates the server's handshake response; `Ok(None)` while it is incomplete.
pub(crate) fn check_response(
    expected_accept: &str,
    protocols: &[String],
    pmd: Option<&PmdOffer>,
    buf: &[u8],
) -> Result<Option<Accepted>, WsClientError> {
    let mut storage = [http1::Header::EMPTY; 64];
    let r = match http1::parse_response(buf, &mut storage, &mut http1::Resume::default()) {
        Ok(http1::Status::Complete(r)) => r,
        Ok(http1::Status::Partial) => return Ok(None),
        Err(_) => return Err(WsClientError::Handshake("malformed response head")),
    };
    let head_len = r.len;
    let status = r.code;
    if status != 101 {
        return Err(WsClientError::Status(status, r.reason.to_owned()));
    }
    let values = |name: &'static str| {
        r.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .filter_map(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let has_token = |name: &'static str, token: &str| {
        values(name).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    if !has_token("upgrade", "websocket") {
        return Err(WsClientError::Handshake("missing Upgrade: websocket"));
    }
    if !has_token("connection", "upgrade") {
        return Err(WsClientError::Handshake("missing Connection: Upgrade"));
    }
    let mut accept = values("sec-websocket-accept");
    if accept.next() != Some(expected_accept) || accept.next().is_some() {
        return Err(WsClientError::Handshake("wrong Sec-WebSocket-Accept"));
    }
    let mut protos = values("sec-websocket-protocol");
    let protocol = match (protos.next(), protos.next()) {
        (None, _) => None,
        (Some(p), None) if protocols.iter().any(|o| o == p) => Some(p.to_owned()),
        _ => {
            return Err(WsClientError::Handshake(
                "server selected a subprotocol that was not offered",
            ));
        }
    };
    let pmd = match pmd {
        Some(offer) => offer
            .accept_response(values("sec-websocket-extensions"))
            .map_err(WsClientError::Handshake)?,
        None => {
            if values("sec-websocket-extensions").any(|v| !v.is_empty()) {
                return Err(WsClientError::Handshake(
                    "server accepted an extension that was not offered",
                ));
            }
            None
        }
    };
    Ok(Some(Accepted {
        head_len,
        pmd,
        protocol,
    }))
}

impl Handler for ClientConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(ws) = self.ws.as_mut() {
            ws.on_data(data);
            return;
        }
        if self.plan.is_none() {
            return; // failed handshake, closing
        }
        self.buf.extend_from_slice(data);
        self.handshake(c);
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        if let Some(ws) = self.ws.as_mut() {
            ws.on_transport_closed();
            return;
        }
        if let Some(plan) = self.plan.take() {
            let timed_out = plan.lock().timed_out;
            plan.fail(match err {
                _ if timed_out => WsClientError::Timeout,
                Some(only::Error::Io(e)) => WsClientError::Io(e),
                Some(e) => WsClientError::Io(io::Error::other(e.to_string())),
                None => WsClientError::Closed,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("ws://example.com/chat?x=1").unwrap();
        assert_eq!(
            u,
            WsUrl {
                tls: false,
                host: "example.com".into(),
                port: 80,
                target: "/chat?x=1".into(),
                host_header: "example.com".into(),
            }
        );
        let u = parse_url("WSS://example.com:8443").unwrap();
        assert!(u.tls);
        assert_eq!((u.port, u.target.as_str()), (8443, "/"));
        assert_eq!(u.host_header, "example.com:8443");
        let u = parse_url("wss://example.com:443/").unwrap();
        assert_eq!(u.host_header, "example.com");
        let u = parse_url("ws://h?q").unwrap();
        assert_eq!(u.target, "/?q");
        let u = parse_url("ws://[::1]:9000/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9000));
        assert_eq!(u.host_header, "[::1]:9000");
        let u = parse_url("ws://[::1]/").unwrap();
        assert_eq!((u.port, u.host_header.as_str()), (80, "[::1]"));
        for bad in [
            "http://x/",
            "example.com",
            "ws:///x",
            "ws://u@h/",
            "ws://h:port/",
            "ws://h/#frag",
            "ws://[::1/",
            "ws://[::1]x/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_has_the_handshake_fields() {
        let u = parse_url("ws://example.com:9000/ws").unwrap();
        let opts = DialOptions {
            protocols: vec!["chat".into(), "v2".into()],
            origin: Some("http://example.com".into()),
            headers: vec![
                ("Authorization".into(), "Bearer x\r\nEvil: 1".into()),
                ("Host".into(), "ignored".into()),
                ("Sec-WebSocket-Key".into(), "ignored".into()),
            ],
            ..DialOptions::default()
        };
        let r = String::from_utf8(build_request(
            &u,
            "dGhlIHNhbXBsZSBub25jZQ==",
            &opts,
            Some(&PmdOffer::default()),
        ))
        .unwrap();
        assert!(
            r.starts_with("GET /ws HTTP/1.1\r\nHost: example.com:9000\r\n"),
            "{r}"
        );
        assert!(r.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(r.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(r.contains("Sec-WebSocket-Protocol: chat, v2\r\n"));
        assert!(
            r.contains("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n")
        );
        assert!(r.contains("Origin: http://example.com\r\n"));
        assert!(r.contains("Authorization: Bearer xEvil: 1\r\n"));
        assert!(r.contains("User-Agent: only-ws\r\n"));
        assert_eq!(r.matches("Host:").count(), 1);
        assert_eq!(r.matches("Sec-WebSocket-Key:").count(), 1);
        assert!(r.ends_with("\r\n\r\n"));
        // Keys are fresh, valid base64 of 16 bytes.
        let (a, b) = (new_key(), new_key());
        assert_ne!(a, b);
        assert!(crate::valid_key(&a));
    }
}
