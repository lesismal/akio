#![forbid(unsafe_code)]
//! Several protocols on one listening port, told apart by the first bytes each client sends.
//!
//! ```no_run
//! # use akio::{Engine, Listener}; use akio_mux::{Mux, Rule};
//! # fn tls_acceptor() -> akio_core::FnAcceptor<Echo, fn(&akio_core::Conn<Echo>) -> Echo> { unimplemented!() }
//! # struct Echo; impl akio_core::Handler for Echo { fn on_data(&mut self, _: &akio_core::Conn<Self>, _: &[u8]) {} }
//! let mux = Mux::new()
//!     .route(Rule::Tls, tls_acceptor())
//!     .route(Rule::Http1, akio_core::fn_acceptor(|_c: &akio_core::Conn<Echo>| Echo))
//!     .fallback(akio_core::fn_acceptor(|_c: &akio_core::Conn<Echo>| Echo));
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("0.0.0.0:443".parse().unwrap()).serve_any(mux))
//!     .build()
//!     .unwrap();
//! ```
//!
//! The connection belongs to the chosen acceptor's handler from then on, as if it had been
//! accepted by it directly: the sniffed bytes are replayed to it, `spawn_blocking` completions and
//! graceful shutdown reach it. Protocols where the server speaks first cannot be told apart this
//! way; give them their own port.
//!
//! A client that has not sent enough bytes to decide within the sniff timeout (default 5 s,
//! [`Mux::sniff_timeout`]) is closed, so silent or trickling connections cannot pile up.
//!
//! [`Rule::TlsSni`] and [`Rule::TlsHello`] route TLS by its ClientHello (server name, ALPN)
//! without terminating it, for passthrough to an upstream ([`tls`]). [`proxy::ProxyProtocol`]
//! reads a PROXY protocol v1/v2 header before the next acceptor (a `Mux` or any other) runs and
//! exposes the original addresses; [`proxy::send_header`] writes one on an outgoing connection.
//!
//! Guide: [Protocol multiplexing](https://lesismal.github.io/akio/en/protocols/mux.html)
//! (中文: [协议复用](https://lesismal.github.io/akio/zh-CN/protocols/mux.html)).
#![warn(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

mod deadline;
use deadline::Pending;

pub mod proxy;
pub mod tls;
pub use tls::{ClientHello, SniMatcher, TLS_SNIFF_BYTES};

/// Default [`Mux::sniff_timeout`].
pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_secs(5);

use akio_core::{Acceptor, AnyAcceptor, ConnInner, DynAcceptor, DynHandler, Error, Task};

/// The outcome of looking at the first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// This rule's protocol.
    Yes,
    /// Not this protocol.
    No,
    /// Too few bytes to tell yet.
    NeedMore,
}

type Matcher = Arc<dyn Fn(&[u8]) -> Decision + Send + Sync>;
type HelloMatcher = Arc<dyn Fn(&ClientHello<'_>) -> bool + Send + Sync>;

/// How a protocol is recognised.
#[derive(Clone)]
#[non_exhaustive]
pub enum Rule {
    /// A TLS ClientHello (`0x16 0x03 ..`).
    Tls,
    /// A complete TLS ClientHello whose server name matches; the TLS is not terminated, so the
    /// route can relay it (passthrough). The hello may span several reads and records; a mux
    /// with this rule sniffs up to [`TLS_SNIFF_BYTES`] unless told otherwise. A hello without
    /// a server name, or a malformed one, does not match.
    TlsSni(SniMatcher),
    /// A complete TLS ClientHello for which the function returns true (server name, ALPN...).
    TlsHello(HelloMatcher),
    /// An HTTP/1.x request line starting with a known method.
    Http1,
    /// The HTTP/2 connection preface (cleartext HTTP/2 with prior knowledge).
    Http2,
    /// HTTP/1.x or the HTTP/2 preface: what `akio-http` serves.
    Http,
    /// SOCKS version 5.
    Socks5,
    /// SOCKS version 4 / 4a.
    Socks4,
    /// The data starts with these bytes.
    Prefix(Vec<u8>),
    /// Any test.
    Custom(Matcher),
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule").finish_non_exhaustive()
    }
}

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"HEAD ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
];
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn prefix(b: &[u8], p: &[u8]) -> Decision {
    let n = b.len().min(p.len());
    if b[..n] != p[..n] {
        Decision::No
    } else if n < p.len() {
        Decision::NeedMore
    } else {
        Decision::Yes
    }
}

fn hello_decision(b: &[u8], f: impl FnOnce(&ClientHello<'_>) -> bool) -> Decision {
    match tls::parse_client_hello(b) {
        Ok(h) if f(&h) => Decision::Yes,
        Ok(_) => Decision::No,
        Err(tls::HelloError::Incomplete) => Decision::NeedMore,
        Err(_) => Decision::No,
    }
}

impl Rule {
    /// Applies the rule to the bytes seen so far (never empty).
    pub fn decide(&self, b: &[u8]) -> Decision {
        match self {
            Rule::Tls => match b {
                [0x16] => Decision::NeedMore,
                [0x16, 0x03, ..] => Decision::Yes,
                _ => Decision::No,
            },
            Rule::TlsSni(m) => hello_decision(b, |h| h.server_name().is_some_and(|n| m.matches(n))),
            Rule::TlsHello(f) => hello_decision(b, |h| f(h)),
            Rule::Http1 => {
                let mut need = false;
                for m in METHODS {
                    match prefix(b, m) {
                        Decision::Yes => return Decision::Yes,
                        Decision::NeedMore => need = true,
                        Decision::No => {}
                    }
                }
                if need {
                    Decision::NeedMore
                } else {
                    Decision::No
                }
            }
            Rule::Http2 => prefix(b, H2_PREFACE),
            Rule::Http => match (Rule::Http1.decide(b), Rule::Http2.decide(b)) {
                (Decision::Yes, _) | (_, Decision::Yes) => Decision::Yes,
                (Decision::NeedMore, _) | (_, Decision::NeedMore) => Decision::NeedMore,
                _ => Decision::No,
            },
            Rule::Socks5 => {
                if b[0] == 0x05 {
                    Decision::Yes
                } else {
                    Decision::No
                }
            }
            Rule::Socks4 => {
                if b[0] == 0x04 {
                    Decision::Yes
                } else {
                    Decision::No
                }
            }
            Rule::Prefix(p) => prefix(b, p),
            Rule::Custom(f) => f(b),
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

struct Inner {
    routes: Vec<(Rule, Arc<dyn DynAcceptor>)>,
    fallback: Option<Arc<dyn DynAcceptor>>,
    max_sniff_bytes: usize,
    /// `max_sniff_bytes` was set: routes do not raise it.
    sniff_bytes_set: bool,
    sniff_timeout: Option<Duration>,
    /// Which acceptor each connection went to (for graceful shutdown).
    chosen: Mutex<HashMap<u64, Arc<dyn DynAcceptor>>>,
}

/// The multiplexer: an acceptor that hands each connection to the first matching route.
#[derive(Clone)]
pub struct Mux(Arc<Inner>);

impl std::fmt::Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux").finish_non_exhaustive()
    }
}

impl Default for Mux {
    fn default() -> Self {
        Mux::new()
    }
}

impl Mux {
    /// No routes yet; 64 bytes are looked at at most, for at most 5 s.
    pub fn new() -> Mux {
        Mux(Arc::new(Inner {
            routes: Vec::new(),
            fallback: None,
            max_sniff_bytes: 64,
            sniff_bytes_set: false,
            sniff_timeout: Some(DEFAULT_SNIFF_TIMEOUT),
            chosen: Mutex::new(HashMap::new()),
        }))
    }

    fn inner_mut(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.0).expect("configure the Mux before serving with it")
    }

    /// Adds a route; routes are tried in order.
    #[must_use]
    pub fn route<A: Acceptor>(self, rule: Rule, acceptor: A) -> Mux {
        self.push(rule, Arc::new(acceptor))
    }

    /// Adds a route to a type-erased acceptor (another `Mux`, for instance).
    #[must_use]
    pub fn route_any(self, rule: Rule, acceptor: impl Into<AnyAcceptor>) -> Mux {
        self.push(rule, acceptor.into().into_dyn())
    }

    fn push(mut self, rule: Rule, acc: Arc<dyn DynAcceptor>) -> Mux {
        let inner = self.inner_mut();
        if matches!(rule, Rule::TlsSni(_) | Rule::TlsHello(_)) && !inner.sniff_bytes_set {
            inner.max_sniff_bytes = inner.max_sniff_bytes.max(TLS_SNIFF_BYTES);
        }
        inner.routes.push((rule, acc));
        self
    }

    /// Where connections go that match nothing (or that decide nothing within
    /// `max_sniff_bytes`). Without a fallback they are closed.
    #[must_use]
    pub fn fallback<A: Acceptor>(mut self, acceptor: A) -> Mux {
        self.inner_mut().fallback = Some(Arc::new(acceptor));
        self
    }

    /// How many bytes to look at before giving up and using the fallback (default 64, or
    /// [`TLS_SNIFF_BYTES`] once a [`Rule::TlsSni`] or [`Rule::TlsHello`] route is added).
    #[must_use]
    pub fn max_sniff_bytes(mut self, n: usize) -> Mux {
        let inner = self.inner_mut();
        inner.max_sniff_bytes = n.max(1);
        inner.sniff_bytes_set = true;
        self
    }

    /// How long a connection may take to send enough bytes for a decision (default 5 s). A
    /// client still undecided then (silent, or trickling a prefix that several rules share) is
    /// closed. `None` waits forever.
    #[must_use]
    pub fn sniff_timeout(mut self, d: Option<Duration>) -> Mux {
        self.inner_mut().sniff_timeout = d;
        self
    }

    /// The form `akio::Listener::serve_any` takes (`From<Mux>` does the same).
    pub fn into_any(self) -> AnyAcceptor {
        AnyAcceptor::from_dyn(Arc::new(self))
    }

    /// Routes are tried in order: a match waits while an earlier route is still undecided (an
    /// SNI rule before `Rule::Tls`), unless the sniff limit is reached.
    fn pick(&self, b: &[u8]) -> Option<Option<Arc<dyn DynAcceptor>>> {
        let mut undecided = false;
        let mut matched = None;
        for (rule, acc) in &self.0.routes {
            match rule.decide(b) {
                Decision::Yes if !undecided => return Some(Some(acc.clone())),
                Decision::Yes => {
                    matched = Some(acc.clone());
                    break;
                }
                Decision::NeedMore => undecided = true,
                Decision::No => {}
            }
        }
        if undecided && b.len() < self.0.max_sniff_bytes {
            return None; // wait for more bytes
        }
        Some(matched.or_else(|| self.0.fallback.clone()))
    }
}

impl From<Mux> for AnyAcceptor {
    fn from(mux: Mux) -> AnyAcceptor {
        mux.into_any()
    }
}

impl DynAcceptor for Mux {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        Box::new(MuxConn {
            mux: self.clone(),
            conn: inner.clone(),
            buf: Vec::new(),
            target: None,
            pending: self.0.sniff_timeout.map(|d| Pending::start(inner, d)),
        })
    }

    fn on_shutdown(&self, inner: &Arc<ConnInner>) {
        let acc = self
            .0
            .chosen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&inner.id())
            .cloned();
        match acc {
            Some(a) => a.on_shutdown(inner),
            None => inner.close(), // still undecided: nothing to finish
        }
    }
}

struct MuxConn {
    mux: Mux,
    conn: Arc<ConnInner>,
    buf: Vec<u8>,
    target: Option<Box<dyn DynHandler>>,
    /// The sniff deadline, until a route is chosen.
    pending: Option<Arc<Pending>>,
}

impl DynHandler for MuxConn {
    fn on_data(&mut self, data: &[u8]) {
        if let Some(t) = &mut self.target {
            return t.on_data(data);
        }
        self.buf.extend_from_slice(data);
        match self.mux.pick(&self.buf) {
            None => {}
            Some(None) => self.conn.close(),
            Some(Some(acc)) => {
                if let Some(p) = self.pending.take() {
                    p.decided();
                }
                self.mux
                    .0
                    .chosen
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(self.conn.id(), acc.clone());
                let mut h = acc.on_open(&self.conn);
                let seen = std::mem::take(&mut self.buf);
                h.on_data(&seen);
                self.target = Some(h);
            }
        }
    }

    fn on_close(&mut self, err: Option<Error>) {
        self.mux
            .0
            .chosen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.conn.id());
        if let Some(t) = &mut self.target {
            t.on_close(err);
        }
    }

    fn run_task(&mut self, task: Task) {
        if let Some(t) = &mut self.target {
            t.run_task(task);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(Rule::Tls.decide(&[0x16]), Decision::NeedMore);
        assert_eq!(Rule::Tls.decide(&[0x16, 0x03, 0x01]), Decision::Yes);
        assert_eq!(Rule::Tls.decide(b"GET"), Decision::No);
        assert_eq!(Rule::Http1.decide(b"GE"), Decision::NeedMore);
        assert_eq!(Rule::Http1.decide(b"GET /"), Decision::Yes);
        assert_eq!(
            Rule::Http1.decide(b"PO"),
            Decision::NeedMore,
            "POST or PUT or PATCH"
        );
        assert_eq!(Rule::Http1.decide(b"XYZ"), Decision::No);
        assert_eq!(Rule::Http2.decide(b"PRI * HTTP"), Decision::NeedMore);
        assert_eq!(Rule::Http.decide(H2_PREFACE), Decision::Yes);
        assert_eq!(Rule::Http.decide(b"PATCH /x"), Decision::Yes);
        assert_eq!(Rule::Socks5.decide(&[5, 1, 0]), Decision::Yes);
        assert_eq!(Rule::Socks4.decide(&[5]), Decision::No);
        assert_eq!(
            Rule::Prefix(b"PING".to_vec()).decide(b"PI"),
            Decision::NeedMore
        );
        assert_eq!(Rule::Prefix(b"PING".to_vec()).decide(b"PONG"), Decision::No);
    }
}
