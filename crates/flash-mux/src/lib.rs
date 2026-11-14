#![forbid(unsafe_code)]
//! Several protocols on one listening port, told apart by the first bytes each client sends.
//!
//! ```no_run
//! # use flash::{Engine, Listener}; use flash_mux::{Mux, Rule};
//! # fn tls_acceptor() -> flash_core::FnAcceptor<Echo, fn(&flash_core::Conn<Echo>) -> Echo> { unimplemented!() }
//! # struct Echo; impl flash_core::Handler for Echo { fn on_data(&mut self, _: &flash_core::Conn<Self>, _: &[u8]) {} }
//! let mux = Mux::new()
//!     .route(Rule::Tls, tls_acceptor())
//!     .route(Rule::Http1, flash_core::fn_acceptor(|_c: &flash_core::Conn<Echo>| Echo))
//!     .fallback(flash_core::fn_acceptor(|_c: &flash_core::Conn<Echo>| Echo));
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("0.0.0.0:443".parse().unwrap()).serve_dyn(mux.into_dyn()))
//!     .build()
//!     .unwrap();
//! ```
//!
//! The connection belongs to the chosen acceptor's handler from then on, as if it had been
//! accepted by it directly: the sniffed bytes are replayed to it, `spawn_blocking` completions and
//! graceful shutdown reach it. Protocols where the server speaks first cannot be told apart this
//! way; give them their own port.
#![warn(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use flash_core::{Acceptor, ConnInner, DynAcceptor, DynHandler, Error, Task};

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

/// How a protocol is recognised.
#[derive(Clone)]
pub enum Rule {
    /// A TLS ClientHello (`0x16 0x03 ..`).
    Tls,
    /// An HTTP/1.x request line starting with a known method.
    Http1,
    /// The HTTP/2 connection preface (cleartext HTTP/2 with prior knowledge).
    Http2,
    /// HTTP/1.x or the HTTP/2 preface: what `flash-http` serves.
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

impl Rule {
    /// Applies the rule to the bytes seen so far (never empty).
    pub fn decide(&self, b: &[u8]) -> Decision {
        match self {
            Rule::Tls => match b {
                [0x16] => Decision::NeedMore,
                [0x16, 0x03, ..] => Decision::Yes,
                _ => Decision::No,
            },
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

struct Inner {
    routes: Vec<(Rule, Arc<dyn DynAcceptor>)>,
    fallback: Option<Arc<dyn DynAcceptor>>,
    max_sniff: usize,
    /// Which acceptor each connection went to (for graceful shutdown).
    chosen: Mutex<HashMap<u64, Arc<dyn DynAcceptor>>>,
}

/// The multiplexer: an acceptor that hands each connection to the first matching route.
#[derive(Clone)]
pub struct Mux(Arc<Inner>);

impl Default for Mux {
    fn default() -> Self {
        Mux::new()
    }
}

impl Mux {
    /// No routes yet; 64 bytes are looked at at most.
    pub fn new() -> Mux {
        Mux(Arc::new(Inner {
            routes: Vec::new(),
            fallback: None,
            max_sniff: 64,
            chosen: Mutex::new(HashMap::new()),
        }))
    }

    fn inner_mut(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.0).expect("configure the Mux before serving with it")
    }

    /// Adds a route; routes are tried in order.
    pub fn route<A: Acceptor>(mut self, rule: Rule, acceptor: A) -> Mux {
        self.inner_mut().routes.push((rule, Arc::new(acceptor)));
        self
    }

    /// Adds a route to a type-erased acceptor (another `Mux`, for instance).
    pub fn route_dyn(mut self, rule: Rule, acceptor: Arc<dyn DynAcceptor>) -> Mux {
        self.inner_mut().routes.push((rule, acceptor));
        self
    }

    /// Where connections go that match nothing (or that decide nothing within `max_sniff`
    /// bytes). Without a fallback they are closed.
    pub fn fallback<A: Acceptor>(mut self, acceptor: A) -> Mux {
        self.inner_mut().fallback = Some(Arc::new(acceptor));
        self
    }

    /// How many bytes to look at before giving up and using the fallback (default 64).
    pub fn max_sniff(mut self, n: usize) -> Mux {
        self.inner_mut().max_sniff = n.max(1);
        self
    }

    /// The form `Listener::serve_dyn` takes.
    pub fn into_dyn(self) -> Arc<dyn DynAcceptor> {
        Arc::new(self)
    }

    fn pick(&self, b: &[u8]) -> Option<Option<Arc<dyn DynAcceptor>>> {
        let mut undecided = false;
        for (rule, acc) in &self.0.routes {
            match rule.decide(b) {
                Decision::Yes => return Some(Some(acc.clone())),
                Decision::NeedMore => undecided = true,
                Decision::No => {}
            }
        }
        if undecided && b.len() < self.0.max_sniff {
            return None; // wait for more bytes
        }
        Some(self.0.fallback.clone())
    }
}

impl DynAcceptor for Mux {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        Box::new(MuxConn {
            mux: self.clone(),
            conn: inner.clone(),
            buf: Vec::new(),
            target: None,
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
