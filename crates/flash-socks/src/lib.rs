#![forbid(unsafe_code)]
//! Proxies on flash: a SOCKS5 / SOCKS4 / SOCKS4a server ([`Socks`]) and an HTTP `CONNECT`
//! proxy ([`connect_proxy`]), both relaying callback to callback with backpressure in both
//! directions: when one side cannot keep up, reading from the other pauses until it drains.
//!
//! Supported: SOCKS5 `CONNECT` with no authentication or username/password (RFC 1929), IPv4,
//! IPv6 and domain names (resolved on the logical pool); SOCKS4 and 4a `CONNECT`; HTTP
//! `CONNECT host:port`. Not supported: SOCKS `BIND` and `UDP ASSOCIATE`, a Linux `splice` path.
//!
//! Guide: [SOCKS and HTTP CONNECT proxies](https://lesismal.github.io/flash/en/protocols/socks.html)
//! (中文: [SOCKS 与 HTTP CONNECT 代理](https://lesismal.github.io/flash/zh-CN/protocols/socks.html)).
#![warn(clippy::unwrap_used)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};

use flash::{Acceptor, Conn, EngineRef, Handler};
use flash_core::ConnInner;
use flash_http::{
    Context, Method, Response, Service,
    raw::{RawConn, RawHandler},
};

/// Largest handshake (greeting, authentication or request) buffered before the client is cut
/// off. The largest valid SOCKS5 message is 513 bytes; SOCKS4's user id and 4a's host name are
/// NUL-terminated, so without a bound a client could make the buffer grow forever.
const MAX_HANDSHAKE: usize = 4096;

/// Queue size on the outgoing side above which reading from the incoming side pauses.
const HIGH_WATER: usize = 256 << 10;

/// Forwards `data` read from `from` to `to`, pausing `from` while `to` is backed up.
fn forward(from: &Arc<ConnInner>, to: &Arc<ConnInner>, data: &[u8]) {
    if to.send(data).is_err() {
        from.close_after_send();
        return;
    }
    if to.queued_bytes() > HIGH_WATER {
        from.hold_reads(true);
        let from = from.clone();
        to.on_drain(Box::new(move || from.hold_reads(false)));
    }
}

/// The far side of a tunnel: its data goes back to the client.
type UpstreamSlot = Arc<Mutex<Option<Arc<ConnInner>>>>;

struct Upstream {
    client: Arc<ConnInner>,
}

impl Handler for Upstream {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        forward(c.inner(), &self.client, data);
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        self.client.close_after_send();
    }
}

/// Runs when the upstream connection is established (on its I/O thread).
type OnUp = Box<dyn FnOnce(&Arc<ConnInner>) + Send>;

struct UpstreamAcceptor {
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    on_up: Arc<Mutex<Option<OnUp>>>,
}

impl Acceptor for UpstreamAcceptor {
    type Handler = Upstream;
    fn on_open(&self, c: &Conn<Upstream>) -> Upstream {
        *self.slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(c.inner().clone());
        let taken = self.on_up.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(f) = taken {
            f(c.inner());
        }
        Upstream {
            client: self.client.clone(),
        }
    }
}

type OnFail = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// Dials the addresses in order for `client`; `on_up` runs on the first that connects,
/// `on_fail` when none does.
fn dial(
    engine: &EngineRef,
    addrs: Vec<SocketAddr>,
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    on_up: OnUp,
    on_fail: Box<dyn FnOnce() + Send>,
) {
    let up = Arc::new(Mutex::new(Some(on_up)));
    let fail: OnFail = Arc::new(Mutex::new(Some(on_fail)));
    try_dial(engine.get(), Arc::new(addrs), 0, client, slot, up, fail);
}

fn try_dial(
    engine: Option<Arc<flash::Engine>>,
    addrs: Arc<Vec<SocketAddr>>,
    i: usize,
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    up: Arc<Mutex<Option<OnUp>>>,
    fail: OnFail,
) {
    let (Some(e), Some(&addr)) = (engine, addrs.get(i)) else {
        let taken = fail.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(f) = taken {
            f();
        }
        return;
    };
    let acceptor = UpstreamAcceptor {
        client: client.clone(),
        slot: slot.clone(),
        on_up: up.clone(),
    };
    let e2 = e.clone();
    e.dial(addr, acceptor, move |_err| {
        try_dial(Some(e2), addrs, i + 1, client, slot, up, fail);
    });
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

// ---- SOCKS ---------------------------------------------------------------------------------

/// Username/password check for SOCKS5.
pub type Auth = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// A SOCKS5/4/4a server. Serve it on a listener (`Listener::tcp(..).serve(socks)`); set the
/// [`EngineRef`] once the engine is built so it can dial upstream.
pub struct Socks {
    engine: EngineRef,
    auth: Option<Auth>,
    allow_socks4: bool,
}

impl std::fmt::Debug for Socks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks").finish_non_exhaustive()
    }
}

impl Socks {
    /// A server that dials through `engine`.
    pub fn new(engine: EngineRef) -> Socks {
        Socks {
            engine,
            auth: None,
            allow_socks4: true,
        }
    }

    /// Requires SOCKS5 username/password authentication (and turns SOCKS4, which has none, off).
    #[must_use]
    pub fn auth(mut self, check: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Socks {
        self.auth = Some(Arc::new(check));
        self.allow_socks4 = false;
        self
    }
}

enum St {
    Greeting,
    Auth,
    Request,
    Socks4,
    /// Waiting for the upstream connection.
    Connecting,
    Relaying,
}

/// One client of the SOCKS server.
pub struct SocksSession {
    engine: EngineRef,
    auth: Option<Auth>,
    allow_socks4: bool,
    st: St,
    buf: Vec<u8>,
    upstream: UpstreamSlot,
}

impl std::fmt::Debug for SocksSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksSession").finish_non_exhaustive()
    }
}

impl Acceptor for Socks {
    type Handler = SocksSession;
    fn on_open(&self, _c: &Conn<SocksSession>) -> SocksSession {
        SocksSession {
            engine: self.engine.clone(),
            auth: self.auth.clone(),
            allow_socks4: self.allow_socks4,
            st: St::Greeting,
            buf: Vec::new(),
            upstream: Arc::new(Mutex::new(None)),
        }
    }
}

/// SOCKS5 reply codes.
const REP_OK: u8 = 0;
const REP_UNREACHABLE: u8 = 4;
const REP_REFUSED: u8 = 5;
const REP_CMD: u8 = 7;
const REP_ATYP: u8 = 8;

fn socks5_reply(code: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut r = vec![5, code, 0];
    match bound {
        Some(SocketAddr::V6(a)) => {
            r.push(4);
            r.extend_from_slice(&a.ip().octets());
            r.extend_from_slice(&a.port().to_be_bytes());
        }
        Some(SocketAddr::V4(a)) => {
            r.push(1);
            r.extend_from_slice(&a.ip().octets());
            r.extend_from_slice(&a.port().to_be_bytes());
        }
        None => r.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
    }
    r
}

/// Where a client asked to go.
enum Target {
    Addr(SocketAddr),
    Name(String, u16),
}

impl SocksSession {
    fn fail(&mut self, c: &Conn<Self>, reply: Vec<u8>) {
        let _ = c.send_owned(reply);
        c.close_after_send();
        self.st = St::Relaying; // ignore anything else
    }

    fn connect(&mut self, c: &Conn<Self>, target: Target, v5: bool) {
        self.st = St::Connecting;
        c.hold_reads(true);
        let engine = self.engine.clone();
        let slot = self.upstream.clone();
        let client = c.inner().clone();
        let ok_reply = move |up: &Arc<ConnInner>| {
            let reply = if v5 {
                socks5_reply(REP_OK, Some(up.local_addr()))
            } else {
                vec![0, 0x5a, 0, 0, 0, 0, 0, 0]
            };
            let _ = client.send_owned(reply);
            client.hold_reads(false);
        };
        let client2 = c.inner().clone();
        let fail = move || {
            let reply = if v5 {
                socks5_reply(REP_REFUSED, None)
            } else {
                vec![0, 0x5b, 0, 0, 0, 0, 0, 0]
            };
            let _ = client2.send_owned(reply);
            client2.close_after_send();
        };
        let client3 = c.inner().clone();
        match target {
            Target::Addr(a) => dial(
                &engine,
                vec![a],
                client3,
                slot,
                Box::new(ok_reply),
                Box::new(fail),
            ),
            Target::Name(host, port) => {
                // Name resolution blocks: do it on the logical pool.
                let r = c.spawn_blocking(
                    move || {
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|a| a.collect::<Vec<_>>())
                    },
                    move |_me: &mut SocksSession, c, res| match res {
                        Ok(addrs) if !addrs.is_empty() => dial(
                            &engine,
                            addrs,
                            c.inner().clone(),
                            slot,
                            Box::new(ok_reply),
                            Box::new(fail),
                        ),
                        _ => {
                            let reply = if v5 {
                                socks5_reply(REP_UNREACHABLE, None)
                            } else {
                                vec![0, 0x5b, 0, 0, 0, 0, 0, 0]
                            };
                            let _ = c.send_owned(reply);
                            c.close_after_send();
                        }
                    },
                );
                if r.is_err() {
                    c.close();
                }
            }
        }
    }

    /// Handles as much of the handshake as is buffered.
    fn step(&mut self, c: &Conn<Self>) {
        loop {
            let b = &self.buf;
            match self.st {
                St::Greeting => {
                    let Some(&ver) = b.first() else { return };
                    if ver == 4 {
                        if !self.allow_socks4 {
                            return self.fail(c, vec![0, 0x5b, 0, 0, 0, 0, 0, 0]);
                        }
                        self.st = St::Socks4;
                        continue;
                    }
                    if ver != 5 {
                        c.close();
                        self.st = St::Relaying;
                        return;
                    }
                    if b.len() < 2 || b.len() < 2 + b[1] as usize {
                        return;
                    }
                    let methods = &b[2..2 + b[1] as usize];
                    let want = if self.auth.is_some() { 2 } else { 0 };
                    let n = 2 + b[1] as usize;
                    if !methods.contains(&want) {
                        return self.fail(c, vec![5, 0xff]);
                    }
                    let _ = c.send(&[5, want]);
                    self.buf.drain(..n);
                    self.st = if want == 2 { St::Auth } else { St::Request };
                }
                St::Auth => {
                    // RFC 1929: VER=1 ULEN UNAME PLEN PASSWD
                    if b.len() < 2 {
                        return;
                    }
                    let ul = b[1] as usize;
                    if b.len() < 3 + ul || b.len() < 3 + ul + b[2 + ul] as usize {
                        return;
                    }
                    let pl = b[2 + ul] as usize;
                    let user = String::from_utf8_lossy(&b[2..2 + ul]).into_owned();
                    let pass = String::from_utf8_lossy(&b[3 + ul..3 + ul + pl]).into_owned();
                    let n = 3 + ul + pl;
                    let ok = self.auth.as_ref().is_some_and(|f| f(&user, &pass));
                    if !ok {
                        return self.fail(c, vec![1, 1]);
                    }
                    let _ = c.send(&[1, 0]);
                    self.buf.drain(..n);
                    self.st = St::Request;
                }
                St::Request => {
                    if b.len() < 4 {
                        return;
                    }
                    let (cmd, atyp) = (b[1], b[3]);
                    let (target, n) = match atyp {
                        1 => {
                            if b.len() < 10 {
                                return;
                            }
                            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
                            let port = u16::from_be_bytes([b[8], b[9]]);
                            (Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)), 10)
                        }
                        4 => {
                            if b.len() < 22 {
                                return;
                            }
                            let mut o = [0u8; 16];
                            o.copy_from_slice(&b[4..20]);
                            let port = u16::from_be_bytes([b[20], b[21]]);
                            (
                                Target::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)),
                                22,
                            )
                        }
                        3 => {
                            if b.len() < 5 || b.len() < 7 + b[4] as usize {
                                return;
                            }
                            let l = b[4] as usize;
                            let host = String::from_utf8_lossy(&b[5..5 + l]).into_owned();
                            let port = u16::from_be_bytes([b[5 + l], b[6 + l]]);
                            (Target::Name(host, port), 7 + l)
                        }
                        _ => return self.fail(c, socks5_reply(REP_ATYP, None)),
                    };
                    if cmd != 1 {
                        return self.fail(c, socks5_reply(REP_CMD, None));
                    }
                    self.buf.drain(..n);
                    return self.connect(c, target, true);
                }
                St::Socks4 => {
                    // VN CD DSTPORT DSTIP USERID NUL [DOMAIN NUL]
                    if b.len() < 9 {
                        return;
                    }
                    let Some(uend) = b[8..].iter().position(|x| *x == 0).map(|p| p + 8) else {
                        return;
                    };
                    if b[1] != 1 {
                        return self.fail(c, vec![0, 0x5b, 0, 0, 0, 0, 0, 0]);
                    }
                    let port = u16::from_be_bytes([b[2], b[3]]);
                    let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
                    let (target, n) = if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] != 0 {
                        // 4a: a domain name follows the user id.
                        let Some(dend) = b[uend + 1..]
                            .iter()
                            .position(|x| *x == 0)
                            .map(|p| p + uend + 1)
                        else {
                            return;
                        };
                        let host = String::from_utf8_lossy(&b[uend + 1..dend]).into_owned();
                        (Target::Name(host, port), dend + 1)
                    } else {
                        (
                            Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)),
                            uend + 1,
                        )
                    };
                    self.buf.drain(..n);
                    return self.connect(c, target, false);
                }
                St::Connecting | St::Relaying => return,
            }
        }
    }
}

impl Handler for SocksSession {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let St::Relaying | St::Connecting = self.st {
            let up = self
                .upstream
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            match up {
                Some(up) => {
                    // Bytes buffered behind the request go first.
                    if !self.buf.is_empty() {
                        let pending = std::mem::take(&mut self.buf);
                        forward(c.inner(), &up, &pending);
                    }
                    forward(c.inner(), &up, data);
                    self.st = St::Relaying;
                }
                // Early data while the upstream connects is kept for it; after a failure (the
                // session is closing) there is nobody to give it to.
                None if matches!(self.st, St::Connecting) => self.buf.extend_from_slice(data),
                None => {}
            }
            return;
        }
        self.buf.extend_from_slice(data);
        self.step(c);
        if matches!(self.st, St::Greeting | St::Auth | St::Request | St::Socks4)
            && self.buf.len() > MAX_HANDSHAKE
        {
            self.buf = Vec::new();
            self.st = St::Relaying; // ignore anything else
            c.close();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        let taken = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(up) = taken {
            up.close_after_send();
        }
    }
}

// ---- HTTP CONNECT --------------------------------------------------------------------------

/// An HTTP proxy service for `CONNECT host:port` tunnels (use it as a `flash-http` service, or
/// mount it in a router's fallback). Other methods get 405.
pub fn connect_proxy(engine: EngineRef) -> impl Service {
    move |ctx: &mut Context| {
        if *ctx.method() != Method::Connect {
            return ctx.respond(
                Response::text(405, "only CONNECT is proxied").header("Allow", "CONNECT"),
            );
        }
        let target = ctx.req().target.clone();
        let Some((host, port)) = target.rsplit_once(':').and_then(|(h, p)| {
            Some((
                h.trim_matches(['[', ']']).to_owned(),
                p.parse::<u16>().ok()?,
            ))
        }) else {
            return ctx.text(400, "CONNECT needs host:port");
        };
        ctx.upgrade_raw(Tunnel {
            engine: engine.clone(),
            host: Some((host, port)),
            upstream: Arc::new(Mutex::new(None)),
            pending: Vec::new(),
        });
    }
}

struct Tunnel {
    engine: EngineRef,
    host: Option<(String, u16)>,
    upstream: UpstreamSlot,
    pending: Vec<u8>,
}

impl RawHandler for Tunnel {
    fn on_open(&mut self, conn: &RawConn) {
        conn.hold_reads(true);
        let (host, port) = self.host.take().expect("opened once");
        let engine = self.engine.clone();
        let slot = self.upstream.clone();
        let client = conn.inner().clone();
        // Resolution may block: a short-lived thread keeps it off the I/O thread (a raw
        // connection has no typed handle for the logical pool).
        std::thread::spawn(move || {
            let addrs: Vec<SocketAddr> = (host.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.collect())
                .unwrap_or_default();
            let c_ok = client.clone();
            let c_fail = client.clone();
            if addrs.is_empty() {
                let _ = client.send(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                return client.close_after_send();
            }
            dial(
                &engine,
                addrs,
                client,
                slot,
                Box::new(move |_up| {
                    let _ = c_ok.send(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    c_ok.hold_reads(false);
                }),
                Box::new(move || {
                    let _ = c_fail.send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    c_fail.close_after_send();
                }),
            );
        });
    }

    fn on_data(&mut self, conn: &RawConn, data: &[u8]) {
        let up = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match up {
            Some(up) => {
                if !self.pending.is_empty() {
                    let p = std::mem::take(&mut self.pending);
                    forward(conn.inner(), &up, &p);
                }
                forward(conn.inner(), &up, data);
            }
            None => self.pending.extend_from_slice(data),
        }
    }

    fn on_close(&mut self) {
        let taken = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(up) = taken {
            up.close_after_send();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a SOCKS4 request whose user id never ends used to be buffered without limit.
    #[test]
    fn endless_socks4_user_id_is_cut_off() {
        let c = flash_core::fuzzing::conn();
        let mut s = Socks::new(EngineRef::new()).on_open(&c);
        s.on_data(&c, &[4, 1, 0, 80, 127, 0, 0, 1]);
        for _ in 0..100 {
            s.on_data(&c, &[b'u'; 1000]);
        }
        assert!(s.buf.len() <= MAX_HANDSHAKE);
        assert!(!c.is_open());
    }

    #[test]
    fn socks5_replies() {
        assert_eq!(
            socks5_reply(REP_OK, Some("1.2.3.4:80".parse().unwrap())),
            vec![5, 0, 0, 1, 1, 2, 3, 4, 0, 80]
        );
        assert_eq!(socks5_reply(REP_REFUSED, None)[..4], [5, 5, 0, 1]);
        let r = socks5_reply(REP_OK, Some("[::1]:443".parse().unwrap()));
        assert_eq!((r[3], r.len()), (4, 22));
    }
}
