//! The client side of a SOCKS handshake, sans-io (ADR-019): SOCKS5 (RFC 1928) with no
//! authentication, username/password (RFC 1929) or GSS-API (RFC 1961, ADR-071, the mechanism
//! supplied by the application: [`Handshake::gssapi`]), SOCKS4 and SOCKS4a, for `CONNECT`,
//! `BIND` and (SOCKS5) `UDP ASSOCIATE`.
//!
//! Not public API: [`proxy::Connect`](crate::proxy::Connect) runs it as a transport under the
//! HTTP and WebSocket clients (`socks5://` / `socks4a://` proxies), and `only-socks`' client
//! builds its engine and blocking helpers on it.
//!
//! ```
//! use only_ws::socks::{Cmd, Handshake, Target, Version};
//! let mut h = Handshake::new(
//!     Version::Socks5,
//!     Cmd::Connect,
//!     Target::Name("example.com".into(), 443),
//!     None,
//! )
//! .unwrap();
//! let mut out = Vec::new();
//! h.start(&mut out);
//! assert_eq!(out, [5, 1, 0]); // greeting: no authentication
//! out.clear();
//! let (n, r) = h.feed(&[5, 0], &mut out).unwrap(); // method chosen
//! assert_eq!((n, r.is_none()), (2, true));
//! assert_eq!(&out[..5], &[5, 1, 0, 3, 11]); // CONNECT example.com
//! let reply = [5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90, b'x'];
//! let (n, r) = h.feed(&reply, &mut Vec::new()).unwrap();
//! assert_eq!(n, 10); // the trailing `x` belongs to the tunnel
//! assert!(r.is_some() && h.is_done());
//! ```

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Mutex, PoisonError},
};

use crate::gss;
use crate::proxy::ProxyRefused;

pub use crate::gss::{GssContext, GssFactory, GssLayer, GssStep, Protection};

/// The protocol spoken to the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// SOCKS5 (RFC 1928): addresses and host names, authentication, all three commands.
    Socks5,
    /// SOCKS4: IPv4 addresses only, `CONNECT` and `BIND`.
    Socks4,
    /// SOCKS4a: SOCKS4 plus host names resolved by the proxy.
    Socks4a,
}

impl Version {
    fn label(self) -> &'static str {
        match self {
            Version::Socks5 => "SOCKS5",
            Version::Socks4 => "SOCKS4",
            Version::Socks4a => "SOCKS4a",
        }
    }
}

/// What is asked of the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cmd {
    /// A TCP connection to the target.
    Connect,
    /// Listen for one TCP connection from the target (two replies: where, then who).
    Bind,
    /// A UDP relay (SOCKS5 only); the target is the address datagrams will come from.
    UdpAssociate,
}

/// A destination: an address, or a host name the proxy resolves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// An address and port.
    Addr(SocketAddr),
    /// A host name and port.
    Name(String, u16),
}

impl Target {
    /// `host` as an address when it is an IP literal (brackets allowed), a name otherwise.
    pub fn parse(host: &str, port: u16) -> Target {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        match h.parse::<IpAddr>() {
            Ok(ip) => Target::Addr(SocketAddr::new(ip, port)),
            Err(_) => Target::Name(host.to_owned(), port),
        }
    }
}

/// A reply of the proxy: its code was success, and this is the address it carried
/// (`BND.ADDR` / `BND.PORT`: the proxy's side of `CONNECT`, where `BIND` listens and then who
/// connected, where the UDP relay is).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The address in the reply. SOCKS4 replies carry an IPv4 address (`0.0.0.0` when the
    /// proxy means "my own address").
    pub addr: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Start,
    /// SOCKS5: waiting for the chosen method.
    Method,
    /// SOCKS5: waiting for the RFC 1929 status.
    Auth,
    /// GSS-API: an establishment step is to run, or running ([`Handshake::take_gss_job`]).
    GssWait,
    /// GSS-API: waiting for the proxy's next establishment token.
    GssAuth,
    /// GSS-API: waiting for the proxy's protection level.
    GssProt,
    /// Waiting for the (first) reply.
    Reply,
    /// `BIND`: waiting for the second reply.
    Second,
    Done,
}

/// Longest SOCKS5 user name or password (one length byte).
const MAX_CRED: usize = 255;

/// Most unwrapped bytes held while a wrapped reply is incomplete (a reply is at most 262).
const MAX_WRAPPED_REPLY: usize = 64 << 10;

/// GSS-API settings of a handshake. The factory is the application's and is only called, so
/// the handshake keeps the unwind safety it had before GSS-API.
#[derive(Clone)]
struct GssConf {
    factory: GssFactory,
    host: String,
    want: Protection,
}

impl std::panic::UnwindSafe for GssConf {}
impl std::panic::RefUnwindSafe for GssConf {}

/// GSS-API state of one handshake (not cloned). The context and the job sit in mutexes only
/// to make the handshake `Sync`; they are reached through `&mut self` (`get_mut`, no locking).
#[derive(Default)]
struct GssState {
    ctx: Mutex<Option<Box<dyn GssContext>>>,
    job: Mutex<Option<GssJob>>,
    /// The agreed protection.
    level: Option<Protection>,
    /// Unwrapped bytes of the proxy's replies.
    plain: Vec<u8>,
}

/// One client handshake. Cloning gives a handshake that has not started (GSS-API state is not
/// copied).
pub struct Handshake {
    version: Version,
    cmd: Cmd,
    target: Target,
    auth: Option<(String, String)>,
    gss: Option<GssConf>,
    g: Box<GssState>,
    st: St,
    buf: Vec<u8>,
}

impl Clone for Handshake {
    fn clone(&self) -> Handshake {
        Handshake {
            version: self.version,
            cmd: self.cmd,
            target: self.target.clone(),
            auth: self.auth.clone(),
            gss: self.gss.clone(),
            g: Box::default(),
            st: St::Start,
            buf: Vec::new(),
        }
    }
}

/// A GSS-API establishment step for the caller to run off the I/O thread
/// ([`Handshake::take_gss_job`]): [`run`](Self::run) it (it may block) and give the result to
/// [`Handshake::gss_done`].
pub struct GssJob {
    /// Set for the first step: the context is created first.
    factory: Option<(GssFactory, String)>,
    ctx: Option<Box<dyn GssContext>>,
    token: Vec<u8>,
}

impl std::fmt::Debug for GssJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssJob").finish_non_exhaustive()
    }
}

/// The outcome of a [`GssJob`].
pub struct GssDone {
    ctx: Option<Box<dyn GssContext>>,
    result: io::Result<GssStep>,
}

impl std::fmt::Debug for GssDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssDone").finish_non_exhaustive()
    }
}

impl GssJob {
    /// Creates the context (first step) and runs `GSS_Init_sec_context` with the proxy's token.
    pub fn run(self) -> GssDone {
        let mut ctx = match (self.ctx, self.factory) {
            (Some(c), _) => c,
            (None, Some((f, host))) => match f(&host) {
                Ok(c) => c,
                Err(e) => {
                    return GssDone {
                        ctx: None,
                        result: Err(e),
                    };
                }
            },
            (None, None) => {
                return GssDone {
                    ctx: None,
                    result: Err(io::Error::other("GSS-API job without a context")),
                };
            }
        };
        let result = ctx.step(&self.token);
        GssDone {
            ctx: Some(ctx),
            result,
        }
    }
}

impl std::fmt::Debug for Handshake {
    // Without the credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("version", &self.version)
            .field("cmd", &self.cmd)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn malformed(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Handshake {
    /// A handshake for `cmd` to `target`. `auth`: the SOCKS5 user name and password (offered
    /// alongside "no authentication"; the proxy picks), or the SOCKS4 user id (the password is
    /// ignored). Fails when the request cannot be expressed: a host name or IPv6 address over
    /// SOCKS4, IPv6 over SOCKS4a, `UDP ASSOCIATE` over SOCKS4, a name or credential longer than
    /// 255 bytes, empty credentials over SOCKS5, NUL bytes where SOCKS4 terminates fields.
    pub fn new(
        version: Version,
        cmd: Cmd,
        target: Target,
        auth: Option<(&str, &str)>,
    ) -> io::Result<Handshake> {
        match (version, &target) {
            (Version::Socks5, Target::Name(h, _)) if h.is_empty() || h.len() > 255 => {
                return Err(invalid("SOCKS5 host names are 1 to 255 bytes"));
            }
            (Version::Socks4, Target::Name(..)) => {
                return Err(invalid(
                    "SOCKS4 cannot carry a host name (resolve it first, or use SOCKS4a/SOCKS5)",
                ));
            }
            (Version::Socks4 | Version::Socks4a, Target::Addr(SocketAddr::V6(_))) => {
                return Err(invalid("SOCKS4 carries IPv4 addresses only"));
            }
            (Version::Socks4a, Target::Name(h, _)) if h.is_empty() || h.contains('\0') => {
                return Err(invalid("bad SOCKS4a host name"));
            }
            _ => {}
        }
        if cmd == Cmd::UdpAssociate && version != Version::Socks5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP ASSOCIATE needs SOCKS5",
            ));
        }
        if let Some((u, p)) = auth {
            match version {
                Version::Socks5 => {
                    if u.is_empty() || u.len() > MAX_CRED || p.is_empty() || p.len() > MAX_CRED {
                        return Err(invalid(
                            "SOCKS5 user names and passwords are 1 to 255 bytes",
                        ));
                    }
                }
                Version::Socks4 | Version::Socks4a => {
                    if u.contains('\0') || u.len() > MAX_CRED {
                        return Err(invalid("bad SOCKS4 user id"));
                    }
                }
            }
        }
        Ok(Handshake {
            version,
            cmd,
            target,
            auth: auth.map(|(u, p)| (u.to_owned(), p.to_owned())),
            gss: None,
            g: Box::default(),
            st: St::Start,
            buf: Vec::new(),
        })
    }

    /// Offers GSS-API authentication (RFC 1961, method 1; SOCKS5 only), with the
    /// username/password method too when credentials were given, but not "no authentication".
    /// `factory` makes the security context (it is given `host`, the proxy's host name);
    /// `protection` is the level asked for after authentication, and the least accepted.
    ///
    /// Establishment steps are not run by [`feed`](Self::feed): after each call, take the step
    /// with [`take_gss_job`](Self::take_gss_job), run it where blocking is allowed and hand the
    /// result to [`gss_done`](Self::gss_done). With protection, the request, the replies and the
    /// tunnel are wrapped: [`take_protection`](Self::take_protection) hands over the context
    /// once done.
    pub fn gssapi(
        mut self,
        factory: GssFactory,
        host: &str,
        protection: Protection,
    ) -> io::Result<Handshake> {
        if self.version != Version::Socks5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "GSS-API authentication needs SOCKS5",
            ));
        }
        self.gss = Some(GssConf {
            factory,
            host: host.to_owned(),
            want: protection,
        });
        Ok(self)
    }

    /// The GSS-API establishment step waiting to be run, if any.
    pub fn take_gss_job(&mut self) -> Option<GssJob> {
        self.g
            .job
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Continues with the outcome of a [`GssJob`], appending what must be sent to the proxy to
    /// `out`; then call [`feed`](Self::feed) (with no new bytes, if none came) to go on with
    /// what the proxy already sent. A failed step is a refusal ([`ProxyRefused`]); the abort
    /// message is appended to `out` for the proxy.
    pub fn gss_done(&mut self, d: GssDone, out: &mut Vec<u8>) -> io::Result<()> {
        if self.st != St::GssWait {
            return Err(io::Error::other("no GSS-API step was pending"));
        }
        let ctx_slot = self.g.ctx.get_mut().unwrap_or_else(PoisonError::into_inner);
        *ctx_slot = d.ctx;
        let Ok(step) = d.result else {
            out.extend_from_slice(&gss::ABORT);
            return Err(refused(self.version, Refusal::Auth));
        };
        match step {
            GssStep::Continue(t) => {
                gss::push_msg(out, gss::MTYP_AUTH, &t)?;
                self.st = St::GssAuth;
            }
            GssStep::Complete(t) => {
                if !t.is_empty() {
                    gss::push_msg(out, gss::MTYP_AUTH, &t)?;
                }
                let (Some(ctx), Some(conf)) = (ctx_slot.as_mut(), &self.gss) else {
                    return Err(io::Error::other("GSS-API step without a context"));
                };
                gss::protection_msg(ctx.as_mut(), conf.want, out)?;
                self.st = St::GssProt;
            }
        }
        Ok(())
    }

    /// The protection agreed with the proxy (GSS-API only, once negotiated).
    pub fn protection(&self) -> Option<Protection> {
        self.g.level
    }

    /// Once [`is_done`](Self::is_done) with per-message protection: the security context, the
    /// level, and tunnel bytes the proxy sent inside the last reply's message (already
    /// unwrapped). What follows on the wire is wrapped: put a [`GssLayer`] on the connection.
    pub fn take_protection(&mut self) -> Option<(Box<dyn GssContext>, Protection, Vec<u8>)> {
        let level = self.g.level.filter(|l| *l != Protection::None)?;
        if self.st != St::Done {
            return None;
        }
        let ctx = self
            .g
            .ctx
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        Some((ctx, level, std::mem::take(&mut self.g.plain)))
    }

    /// Whether the request and replies are wrapped.
    fn wrapped(&self) -> bool {
        self.g.level.is_some_and(|l| l != Protection::None)
    }

    /// Appends the SOCKS5 request, wrapped when protection is on.
    fn send_request(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.wrapped() {
            self.socks5_request(out);
            return Ok(());
        }
        let mut req = Vec::new();
        self.socks5_request(&mut req);
        let conf = self.g.level == Some(Protection::Confidentiality);
        let ctx = self
            .g
            .ctx
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .ok_or_else(|| io::Error::other("GSS-API protection without a context"))?;
        gss::seal_data(ctx.as_mut(), conf, &req, out)
    }

    /// The protocol.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The command.
    pub fn cmd(&self) -> Cmd {
        self.cmd
    }

    /// Whether the last reply has been received: for `CONNECT` and `UDP ASSOCIATE` the first,
    /// for `BIND` the second. Bytes after it belong to the tunnel.
    pub fn is_done(&self) -> bool {
        self.st == St::Done
    }

    /// Appends the first message to `out`: the SOCKS5 greeting or the SOCKS4 request. Does
    /// nothing when called again.
    pub fn start(&mut self, out: &mut Vec<u8>) {
        if self.st != St::Start {
            return;
        }
        match self.version {
            Version::Socks5 => {
                match (self.gss.is_some(), self.auth.is_some()) {
                    (true, true) => out.extend_from_slice(&[5, 2, 1, 2]),
                    (true, false) => out.extend_from_slice(&[5, 1, 1]),
                    (false, true) => out.extend_from_slice(&[5, 2, 0, 2]),
                    (false, false) => out.extend_from_slice(&[5, 1, 0]),
                }
                self.st = St::Method;
            }
            Version::Socks4 | Version::Socks4a => {
                self.socks4_request(out);
                self.st = St::Reply;
            }
        }
    }

    fn cmd_byte(&self) -> u8 {
        match self.cmd {
            Cmd::Connect => 1,
            Cmd::Bind => 2,
            Cmd::UdpAssociate => 3,
        }
    }

    fn socks4_request(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[4, self.cmd_byte()]);
        let user = self.auth.as_ref().map_or("", |(u, _)| u.as_str());
        match &self.target {
            Target::Addr(SocketAddr::V4(a)) => {
                out.extend_from_slice(&a.port().to_be_bytes());
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(user.as_bytes());
                out.push(0);
            }
            // Checked in `new`: only SOCKS4a gets here with a name.
            Target::Name(h, port) => {
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(user.as_bytes());
                out.push(0);
                out.extend_from_slice(h.as_bytes());
                out.push(0);
            }
            Target::Addr(SocketAddr::V6(_)) => unreachable!("refused in Handshake::new"),
        }
    }

    fn socks5_request(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[5, self.cmd_byte(), 0]);
        match &self.target {
            Target::Addr(SocketAddr::V4(a)) => {
                out.push(1);
                out.extend_from_slice(&a.ip().octets());
            }
            Target::Addr(SocketAddr::V6(a)) => {
                out.push(4);
                out.extend_from_slice(&a.ip().octets());
            }
            Target::Name(h, _) => {
                out.push(3);
                out.push(h.len() as u8); // at most 255, checked in `new`
                out.extend_from_slice(h.as_bytes());
            }
        }
        let port = match &self.target {
            Target::Addr(a) => a.port(),
            Target::Name(_, p) => *p,
        };
        out.extend_from_slice(&port.to_be_bytes());
    }

    /// Consumes bytes from the proxy, appending what must be sent to it to `out`. Returns how
    /// many bytes of `data` were used and, when a successful reply completed, the reply; call
    /// again with the rest (a `BIND`'s second reply may follow in the same read). Once
    /// [`is_done`](Self::is_done), `data[used..]` is tunnel data. A refusal is an error
    /// carrying [`ProxyRefused`]; anything that is not SOCKS is `InvalidData`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<(usize, Option<Reply>)> {
        if self.st == St::Start {
            self.start(out);
        }
        if self.st == St::Done {
            return Ok((0, None));
        }
        let before = self.buf.len();
        self.buf.extend_from_slice(data);
        loop {
            // Incomplete: everything is held.
            let Some((used, reply)) = self.step(out)? else {
                return Ok((data.len(), None));
            };
            self.buf.drain(..used);
            if let Some(r) = reply {
                // Hand back what followed the reply.
                let rest = self.buf.len();
                self.buf = Vec::new();
                let used_of_data = (before + data.len() - rest).saturating_sub(before);
                return Ok((used_of_data, Some(r)));
            }
        }
    }

    /// A complete reply (`n`: its bytes in `buf`): success moves on, anything else is a refusal.
    fn replied(&mut self, code: u8, addr: Target, n: usize) -> io::Result<(usize, Option<Reply>)> {
        let ok = match self.version {
            Version::Socks5 => code == 0,
            _ => code == 0x5a,
        };
        if !ok {
            return Err(refused(self.version, Refusal::Reply(code)));
        }
        self.st = if self.cmd == Cmd::Bind && self.st == St::Reply {
            St::Second
        } else {
            St::Done
        };
        Ok((n, Some(Reply { addr })))
    }

    /// Parses one message from `buf`: `None` when incomplete, else the bytes it took and the
    /// reply it completed, if any.
    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<Option<(usize, Option<Reply>)>> {
        let b = &self.buf;
        match self.st {
            St::Start | St::Done => Ok(None),
            St::Method => {
                if b.len() < 2 {
                    return Ok(None);
                }
                if b[0] != 5 {
                    return Err(malformed("not a SOCKS5 proxy"));
                }
                match (b[1], &self.auth) {
                    (0, _) if self.gss.is_none() => {
                        self.socks5_request(out);
                        self.st = St::Reply;
                    }
                    (1, _) if self.gss.is_some() => {
                        let conf = self
                            .gss
                            .as_ref()
                            .map(|g| (g.factory.clone(), g.host.clone()));
                        *self.g.job.get_mut().unwrap_or_else(PoisonError::into_inner) =
                            Some(GssJob {
                                factory: conf,
                                ctx: None,
                                token: Vec::new(),
                            });
                        self.st = St::GssWait;
                    }
                    (2, Some((u, p))) => {
                        out.push(1);
                        out.push(u.len() as u8);
                        out.extend_from_slice(u.as_bytes());
                        out.push(p.len() as u8);
                        out.extend_from_slice(p.as_bytes());
                        self.st = St::Auth;
                    }
                    (0xff, _) => {
                        return Err(refused(self.version, Refusal::NoMethod));
                    }
                    _ => return Err(malformed("SOCKS5 proxy chose a method we did not offer")),
                }
                Ok(Some((2, None)))
            }
            St::Auth => {
                if b.len() < 2 {
                    return Ok(None);
                }
                // RFC 1929 says VER 1; some servers answer with 5.
                if !matches!(b[0], 1 | 5) {
                    return Err(malformed("bad SOCKS5 authentication reply"));
                }
                if b[1] != 0 {
                    return Err(refused(self.version, Refusal::Auth));
                }
                self.socks5_request(out);
                self.st = St::Reply;
                Ok(Some((2, None)))
            }
            // Held until `gss_done`.
            St::GssWait => Ok(None),
            St::GssAuth => {
                let Some((mtyp, token, n)) = gss::parse_msg(b)? else {
                    return Ok(None);
                };
                match mtyp {
                    gss::MTYP_AUTH => {
                        let ctx = self
                            .g
                            .ctx
                            .get_mut()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take();
                        *self.g.job.get_mut().unwrap_or_else(PoisonError::into_inner) =
                            Some(GssJob {
                                factory: None,
                                ctx,
                                token: token.to_vec(),
                            });
                        self.st = St::GssWait;
                        Ok(Some((n, None)))
                    }
                    gss::MTYP_ABORT => Err(refused(self.version, Refusal::Auth)),
                    _ => Err(malformed("unexpected SOCKS GSS-API message")),
                }
            }
            St::GssProt => {
                let Some((mtyp, token, n)) = gss::parse_msg(b)? else {
                    return Ok(None);
                };
                match mtyp {
                    gss::MTYP_PROTECTION => {}
                    gss::MTYP_ABORT => return Err(refused(self.version, Refusal::Auth)),
                    _ => return Err(malformed("unexpected SOCKS GSS-API message")),
                }
                let ctx = self.g.ctx.get_mut().unwrap_or_else(PoisonError::into_inner);
                let (Some(ctx), Some(conf)) = (ctx.as_mut(), &self.gss) else {
                    return Err(io::Error::other("GSS-API negotiation without a context"));
                };
                let level = gss::protection_of(ctx.as_mut(), token)?;
                if level < conf.want {
                    out.extend_from_slice(&gss::ABORT);
                    return Err(refused(self.version, Refusal::Protection));
                }
                self.g.level = Some(level);
                self.send_request(out)?;
                self.st = St::Reply;
                Ok(Some((n, None)))
            }
            St::Reply | St::Second if self.wrapped() => {
                // A complete reply among the unwrapped bytes?
                if let Some((code, addr, n)) = parse_socks5_reply(&self.g.plain)? {
                    self.g.plain.drain(..n);
                    return self.replied(code, addr, 0).map(Some);
                }
                let Some((mtyp, token, n)) = gss::parse_msg(b)? else {
                    return Ok(None);
                };
                match mtyp {
                    gss::MTYP_DATA => {}
                    gss::MTYP_ABORT => return Err(refused(self.version, Refusal::Auth)),
                    _ => return Err(malformed("unexpected SOCKS GSS-API message")),
                }
                let ctx = self
                    .g
                    .ctx
                    .get_mut()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_mut()
                    .ok_or_else(|| io::Error::other("GSS-API protection without a context"))?;
                let opened = ctx.unwrap(token)?;
                self.g.plain.extend_from_slice(&opened);
                if self.g.plain.len() > MAX_WRAPPED_REPLY {
                    return Err(malformed("oversized SOCKS5 reply"));
                }
                Ok(Some((n, None)))
            }
            St::Reply | St::Second => {
                let parsed = match self.version {
                    Version::Socks5 => parse_socks5_reply(b)?,
                    Version::Socks4 | Version::Socks4a => parse_socks4_reply(b)?,
                };
                let Some((code, addr, n)) = parsed else {
                    return Ok(None);
                };
                self.replied(code, addr, n).map(Some)
            }
        }
    }
}

/// `VER REP RSV ATYP BND.ADDR BND.PORT`: the code, the address and the length, or `None` when
/// incomplete.
pub fn parse_socks5_reply(b: &[u8]) -> io::Result<Option<(u8, Target, usize)>> {
    if b.len() < 4 {
        return Ok(None);
    }
    if b[0] != 5 {
        return Err(malformed("bad SOCKS5 reply"));
    }
    match parse_addr(b[3], &b[4..]) {
        Ok(Some((addr, n))) => Ok(Some((b[1], addr, 4 + n))),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `VN CD DSTPORT DSTIP`: the code, the address and the length, or `None` when incomplete.
/// `VN` is 0 by the protocol; 4 is accepted (some servers echo the version).
pub fn parse_socks4_reply(b: &[u8]) -> io::Result<Option<(u8, Target, usize)>> {
    if b.len() < 8 {
        return Ok(None);
    }
    if !matches!(b[0], 0 | 4) {
        return Err(malformed("bad SOCKS4 reply"));
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
    Ok(Some((
        b[1],
        Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)),
        8,
    )))
}

/// `ATYP`-typed `ADDR PORT` from `b`: the target and its length, `None` when incomplete,
/// `InvalidData` for an unknown type or an empty or non-UTF-8 name.
pub fn parse_addr(atyp: u8, b: &[u8]) -> io::Result<Option<(Target, usize)>> {
    Ok(match atyp {
        1 => b.get(..6).map(|b| {
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            (Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)), 6)
        }),
        4 => b.get(..18).map(|b| {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[16], b[17]]);
            (
                Target::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)),
                18,
            )
        }),
        3 => {
            let Some(&l) = b.first() else { return Ok(None) };
            let l = usize::from(l);
            let Some(rest) = b.get(1..3 + l) else {
                return Ok(None);
            };
            let host = std::str::from_utf8(&rest[..l])
                .ok()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| malformed("bad host name in SOCKS5 address"))?;
            let port = u16::from_be_bytes([rest[l], rest[l + 1]]);
            Some((Target::Name(host.to_owned(), port), 3 + l))
        }
        _ => return Err(malformed("unknown SOCKS5 address type")),
    })
}

/// Appends `ATYP ADDR PORT` for `t` (SOCKS5; names longer than 255 bytes are cut off, which
/// [`Handshake::new`] and the datagram builders refuse beforehand).
pub fn push_addr(out: &mut Vec<u8>, t: &Target) {
    match t {
        Target::Addr(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Addr(SocketAddr::V6(a)) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Name(h, p) => {
            let h = &h.as_bytes()[..h.len().min(255)];
            out.push(3);
            out.push(h.len() as u8);
            out.extend_from_slice(h);
            out.extend_from_slice(&p.to_be_bytes());
        }
    }
}

enum Refusal {
    NoMethod,
    Auth,
    Protection,
    Reply(u8),
}

fn refused(version: Version, r: Refusal) -> io::Error {
    let (code, status, text) = match r {
        Refusal::NoMethod => (0xff, 407, "no acceptable authentication method"),
        Refusal::Auth => (0xff, 407, "authentication failed"),
        Refusal::Protection => (0xff, 407, "GSS-API protection weaker than required"),
        Refusal::Reply(c) => {
            let (status, text) = reply_text(version, c);
            (c, status, text)
        }
    };
    ProxyRefused::socks(version.label(), code, status, text).to_io()
}

/// The closest HTTP status and the text of a SOCKS reply code.
fn reply_text(version: Version, code: u8) -> (u16, &'static str) {
    match version {
        Version::Socks5 => match code {
            1 => (502, "general SOCKS server failure"),
            2 => (403, "connection not allowed by ruleset"),
            3 => (502, "network unreachable"),
            4 => (502, "host unreachable"),
            5 => (502, "connection refused"),
            6 => (504, "TTL expired"),
            7 => (501, "command not supported"),
            8 => (501, "address type not supported"),
            _ => (502, "unknown SOCKS5 failure"),
        },
        Version::Socks4 | Version::Socks4a => match code {
            0x5b => (502, "request rejected or failed"),
            0x5c => (403, "request rejected: no identd on the client"),
            0x5d => (403, "request rejected: identd user id mismatch"),
            _ => (502, "unknown SOCKS4 failure"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(e: &io::Error) -> &ProxyRefused {
        e.get_ref().unwrap().downcast_ref::<ProxyRefused>().unwrap()
    }

    #[test]
    fn socks5_with_authentication() {
        let mut h = Handshake::new(
            Version::Socks5,
            Cmd::Connect,
            Target::parse("[::1]", 443),
            Some(("alice", "pw")),
        )
        .unwrap();
        let mut out = Vec::new();
        h.start(&mut out);
        assert_eq!(out, [5, 2, 0, 2]);
        out.clear();
        // Byte by byte.
        assert_eq!(h.feed(&[5], &mut out).unwrap(), (1, None));
        assert_eq!(h.feed(&[2], &mut out).unwrap(), (1, None));
        assert_eq!(out, b"\x01\x05alice\x02pw");
        out.clear();
        h.feed(&[1, 0], &mut out).unwrap();
        assert_eq!(out[..4], [5, 1, 0, 4]);
        assert_eq!(out.len(), 4 + 16 + 2);
        let mut reply = vec![5, 0, 0, 4];
        reply.extend_from_slice(&[0; 15]);
        reply.extend_from_slice(&[1, 0, 80]);
        let mut got = None;
        for (i, b) in reply.iter().enumerate() {
            let (n, r) = h.feed(&[*b], &mut Vec::new()).unwrap();
            assert_eq!(n, 1);
            if i + 1 < reply.len() {
                assert!(r.is_none());
            } else {
                got = r;
            }
        }
        assert_eq!(got.unwrap().addr, Target::Addr("[::1]:80".parse().unwrap()));
        assert!(h.is_done());
        assert_eq!(h.feed(b"later", &mut out).unwrap(), (0, None));
    }

    #[test]
    fn bind_has_two_replies_and_tunnel_bytes_follow() {
        let mut h = Handshake::new(
            Version::Socks5,
            Cmd::Bind,
            Target::Addr("0.0.0.0:0".parse().unwrap()),
            None,
        )
        .unwrap();
        let mut out = Vec::new();
        h.feed(&[5, 0], &mut out).unwrap();
        assert_eq!(out, [5, 1, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut wire = vec![5, 0, 0, 1, 10, 0, 0, 1, 4, 0];
        wire.extend_from_slice(&[5, 0, 0, 3, 1, b'p', 0, 9]);
        wire.extend_from_slice(b"data");
        let (n, r) = h.feed(&wire, &mut out).unwrap();
        assert_eq!(n, 10);
        assert_eq!(
            r.unwrap().addr,
            Target::Addr("10.0.0.1:1024".parse().unwrap())
        );
        assert!(!h.is_done());
        let (n2, r) = h.feed(&wire[n..], &mut out).unwrap();
        assert_eq!(n2, 8);
        assert_eq!(r.unwrap().addr, Target::Name("p".into(), 9));
        assert!(h.is_done());
        assert_eq!(&wire[n + n2..], b"data");
    }

    #[test]
    fn socks4_and_4a_requests() {
        let mut h = Handshake::new(
            Version::Socks4,
            Cmd::Connect,
            Target::parse("10.1.2.3", 80),
            Some(("me", "")),
        )
        .unwrap();
        let mut out = Vec::new();
        h.start(&mut out);
        assert_eq!(out, b"\x04\x01\x00\x50\x0a\x01\x02\x03me\x00");
        let (n, r) = h
            .feed(&[0, 0x5a, 0, 0, 0, 0, 0, 0, b'!'], &mut out)
            .unwrap();
        assert_eq!((n, r.is_some(), h.is_done()), (8, true, true));

        let mut h = Handshake::new(
            Version::Socks4a,
            Cmd::Bind,
            Target::parse("example.com", 21),
            None,
        )
        .unwrap();
        let mut out = Vec::new();
        h.start(&mut out);
        assert_eq!(out, b"\x04\x02\x00\x15\x00\x00\x00\x01\x00example.com\x00");
        h.feed(&[0, 0x5a, 4, 0, 1, 2, 3, 4], &mut out).unwrap();
        assert!(!h.is_done());
        let e = h.feed(&[0, 0x5b, 0, 0, 0, 0, 0, 0], &mut out).unwrap_err();
        assert_eq!(refusal(&e).socks_reply(), Some(0x5b));
        assert_eq!(refusal(&e).status(), 502);
    }

    #[test]
    fn requests_that_cannot_be_expressed() {
        let v6 = Target::parse("::1", 1);
        let name = Target::parse("h", 1);
        assert!(Handshake::new(Version::Socks4, Cmd::Connect, name.clone(), None).is_err());
        assert!(Handshake::new(Version::Socks4a, Cmd::Connect, v6.clone(), None).is_err());
        assert!(Handshake::new(Version::Socks4a, Cmd::Connect, name.clone(), None).is_ok());
        let v4 = Target::parse("1.2.3.4", 1);
        let e = Handshake::new(Version::Socks4a, Cmd::UdpAssociate, v4, None);
        assert_eq!(e.unwrap_err().kind(), io::ErrorKind::Unsupported);
        let long = Target::Name("a".repeat(256), 1);
        assert!(Handshake::new(Version::Socks5, Cmd::Connect, long, None).is_err());
        assert!(Handshake::new(Version::Socks5, Cmd::Connect, name, Some(("", "p"))).is_err());
        let big = "u".repeat(256);
        assert!(Handshake::new(Version::Socks5, Cmd::Connect, v6, Some((&big, "p"))).is_err());
    }

    #[test]
    fn refusals_and_garbage() {
        let new = |auth| {
            Handshake::new(
                Version::Socks5,
                Cmd::Connect,
                Target::parse("1.2.3.4", 5),
                auth,
            )
            .unwrap()
        };
        let mut out = Vec::new();
        let e = new(None).feed(&[5, 0xff], &mut out).unwrap_err();
        assert_eq!(refusal(&e).status(), 407);
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let mut h = new(Some(("u", "p")));
        h.feed(&[5, 2], &mut out).unwrap();
        let e = h.feed(&[1, 1], &mut out).unwrap_err();
        assert_eq!(refusal(&e).status(), 407);
        // Method 2 without credentials, a SOCKS4 answer to SOCKS5, an HTTP proxy.
        assert!(new(None).feed(&[5, 2], &mut out).is_err());
        assert!(new(None).feed(&[0, 0x5a], &mut out).is_err());
        let e = new(None).feed(b"HTTP/1.1 400 Bad", &mut out).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let mut h = new(None);
        h.feed(&[5, 0], &mut out).unwrap();
        let e = h
            .feed(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0], &mut out)
            .unwrap_err();
        let r = refusal(&e);
        assert_eq!((r.status(), r.socks_reply()), (403, Some(2)));
        assert!(r.to_string().contains("not allowed by ruleset"), "{r}");
        let mut h = new(None);
        h.feed(&[5, 0], &mut out).unwrap();
        assert!(h.feed(&[5, 0, 0, 9, 0], &mut out).is_err());
        let mut h = new(None);
        h.feed(&[5, 0], &mut out).unwrap();
        assert!(h.feed(&[5, 0, 0, 3, 0, 0, 1], &mut out).is_err());
    }

    /// The proxy side of a GSS-API exchange, by hand, with the toy mechanism.
    fn gss_client(secret: u8, want: Protection) -> Handshake {
        let f: GssFactory = std::sync::Arc::new(move |_host: &str| {
            Ok(Box::new(gss::toy::Toy::initiator("alice", secret)) as Box<dyn GssContext>)
        });
        Handshake::new(
            Version::Socks5,
            Cmd::Connect,
            Target::parse("1.2.3.4", 80),
            None,
        )
        .unwrap()
        .gssapi(f, "proxy", want)
        .unwrap()
    }

    /// Runs the pending job inline.
    fn run_job(h: &mut Handshake, out: &mut Vec<u8>) -> io::Result<()> {
        let job = h.take_gss_job().expect("a GSS-API step is pending");
        h.gss_done(job.run(), out)
    }

    #[test]
    fn gssapi_with_each_protection() {
        for (want, granted) in [
            (Protection::None, Protection::None),
            (Protection::Integrity, Protection::Integrity),
            (Protection::Integrity, Protection::Confidentiality),
            (Protection::Confidentiality, Protection::Confidentiality),
        ] {
            let mut h = gss_client(7, want);
            let mut srv = gss::toy::Toy::acceptor(7);
            let mut out = Vec::new();
            h.start(&mut out);
            assert_eq!(out, [5, 1, 1]); // GSS-API only
            out.clear();
            assert_eq!(h.feed(&[5, 1], &mut out).unwrap(), (2, None));
            assert!(out.is_empty());
            run_job(&mut h, &mut out).unwrap();
            let (t, tok, n) = gss::parse_msg(&out).unwrap().unwrap();
            assert_eq!((t, n), (gss::MTYP_AUTH, out.len()));
            let GssStep::Complete(reply) = srv.step(tok).unwrap() else {
                panic!("toy acceptor completes at once");
            };
            assert_eq!(srv.peer_name().as_deref(), Some("alice"));
            let mut wire = Vec::new();
            gss::push_msg(&mut wire, gss::MTYP_AUTH, &reply).unwrap();
            out.clear();
            // Byte by byte: the step is queued once the token is complete.
            for b in &wire {
                h.feed(std::slice::from_ref(b), &mut out).unwrap();
            }
            run_job(&mut h, &mut out).unwrap();
            let (t, tok, n) = gss::parse_msg(&out).unwrap().unwrap();
            assert_eq!((t, n), (gss::MTYP_PROTECTION, out.len()));
            assert_eq!(gss::protection_of(&mut srv, tok).unwrap(), want);
            let mut wire = Vec::new();
            gss::protection_msg(&mut srv, granted, &mut wire).unwrap();
            out.clear();
            assert_eq!(h.feed(&wire, &mut out).unwrap(), (wire.len(), None));
            assert_eq!(h.protection(), Some(granted));
            // The request, wrapped unless the level is none.
            let request = [5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
            let mut reply = vec![5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90];
            if granted == Protection::None {
                assert_eq!(out, request);
                reply.extend_from_slice(b"tunnel");
                let (n, r) = h.feed(&reply, &mut out).unwrap();
                assert_eq!((n, r.is_some()), (10, true));
                assert!(h.take_protection().is_none());
                continue;
            }
            let mut rx = out.clone();
            let mut plain = Vec::new();
            gss::open_data(&mut srv, &mut rx, &mut plain).unwrap();
            assert!(rx.is_empty());
            assert_eq!(plain, request);
            // The reply and some tunnel bytes in one message, then a wrapped tunnel message.
            let conf = granted == Protection::Confidentiality;
            reply.extend_from_slice(b"early");
            let mut wire = Vec::new();
            gss::seal_data(&mut srv, conf, &reply, &mut wire).unwrap();
            let first = wire.len();
            gss::seal_data(&mut srv, conf, b"later", &mut wire).unwrap();
            let (n, r) = h.feed(&wire[..first + 3], &mut out).unwrap();
            assert_eq!(n, first);
            assert_eq!(r.unwrap().addr, Target::parse("10.0.0.1", 8080));
            let (ctx, level, leftover) = h.take_protection().unwrap();
            assert_eq!((level, leftover.as_slice()), (granted, &b"early"[..]));
            let mut layer = GssLayer::new(ctx, level, None);
            let (mut p, mut o) = (Vec::new(), Vec::new());
            only::Transport::recv(&mut layer, &wire[first..], &mut p, &mut o).unwrap();
            assert_eq!(p, b"later");
        }
    }

    #[test]
    fn gssapi_failures() {
        // The proxy offers no acceptable method / aborts the establishment.
        let mut out = Vec::new();
        let e = gss_client(7, Protection::None)
            .feed(&[5, 0xff], &mut out)
            .unwrap_err();
        assert_eq!(refusal(&e).status(), 407);
        // Method 0 was not offered with GSS-API.
        assert!(
            gss_client(7, Protection::None)
                .feed(&[5, 0], &mut out)
                .is_err()
        );
        let mut h = gss_client(7, Protection::None);
        h.feed(&[5, 1], &mut out).unwrap();
        run_job(&mut h, &mut out).unwrap();
        let e = h.feed(&gss::ABORT, &mut out).unwrap_err();
        assert_eq!(refusal(&e).status(), 407);
        // A proof made with another secret: the step fails, the abort goes to the proxy.
        let mut h = gss_client(7, Protection::None);
        h.feed(&[5, 1], &mut out).unwrap();
        run_job(&mut h, &mut out).unwrap();
        let mut wire = Vec::new();
        gss::push_msg(&mut wire, gss::MTYP_AUTH, &[b'P', 1]).unwrap();
        h.feed(&wire, &mut out).unwrap();
        out.clear();
        let e = run_job(&mut h, &mut out).unwrap_err();
        assert_eq!(refusal(&e).status(), 407);
        assert_eq!(out, gss::ABORT);
        // Weaker protection than asked for.
        let mut h = gss_client(7, Protection::Confidentiality);
        let mut srv = gss::toy::Toy::acceptor(7);
        h.feed(&[5, 1], &mut out).unwrap();
        out.clear();
        run_job(&mut h, &mut out).unwrap();
        let (_, tok, _) = gss::parse_msg(&out).unwrap().unwrap();
        let GssStep::Complete(proof) = srv.step(tok).unwrap() else {
            unreachable!()
        };
        let mut wire = Vec::new();
        gss::push_msg(&mut wire, gss::MTYP_AUTH, &proof).unwrap();
        h.feed(&wire, &mut out).unwrap();
        out.clear();
        run_job(&mut h, &mut out).unwrap();
        let (_, tok, _) = gss::parse_msg(&out).unwrap().unwrap();
        gss::protection_of(&mut srv, tok).unwrap();
        let mut wire = Vec::new();
        gss::protection_msg(&mut srv, Protection::Integrity, &mut wire).unwrap();
        let e = h.feed(&wire, &mut out).unwrap_err();
        assert!(refusal(&e).to_string().contains("protection"), "{e}");
        // SOCKS4 has no GSS-API.
        let f: GssFactory = std::sync::Arc::new(|_: &str| Err(io::Error::other("unused")));
        let h4 = Handshake::new(
            Version::Socks4,
            Cmd::Connect,
            Target::parse("1.2.3.4", 1),
            None,
        );
        assert!(h4.unwrap().gssapi(f, "p", Protection::None).is_err());
    }

    #[test]
    fn addresses_round_trip() {
        for t in [
            Target::parse("1.2.3.4", 5),
            Target::parse("[2001:db8::1]", 443),
            Target::parse("example.com", 53),
        ] {
            let mut b = Vec::new();
            push_addr(&mut b, &t);
            let (back, n) = parse_addr(b[0], &b[1..]).unwrap().unwrap();
            assert_eq!((back, n + 1), (t, b.len()));
            assert!(parse_addr(b[0], &b[1..b.len() - 1]).unwrap().is_none());
        }
    }
}
