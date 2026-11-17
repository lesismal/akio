//! The client side of a SOCKS handshake, sans-io (ADR-019): SOCKS5 (RFC 1928) with no
//! authentication or username/password (RFC 1929), SOCKS4 and SOCKS4a, for `CONNECT`, `BIND`
//! and (SOCKS5) `UDP ASSOCIATE`.
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
};

use crate::proxy::ProxyRefused;

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
    /// Waiting for the (first) reply.
    Reply,
    /// `BIND`: waiting for the second reply.
    Second,
    Done,
}

/// Longest SOCKS5 user name or password (one length byte).
const MAX_CRED: usize = 255;

/// One client handshake.
#[derive(Clone)]
pub struct Handshake {
    version: Version,
    cmd: Cmd,
    target: Target,
    auth: Option<(String, String)>,
    st: St,
    buf: Vec<u8>,
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
            st: St::Start,
            buf: Vec::new(),
        })
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
                if self.auth.is_some() {
                    out.extend_from_slice(&[5, 2, 0, 2]);
                } else {
                    out.extend_from_slice(&[5, 1, 0]);
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
                    (0, _) => {
                        self.socks5_request(out);
                        self.st = St::Reply;
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
            St::Reply | St::Second => {
                let parsed = match self.version {
                    Version::Socks5 => parse_socks5_reply(b)?,
                    Version::Socks4 | Version::Socks4a => parse_socks4_reply(b)?,
                };
                let Some((code, addr, n)) = parsed else {
                    return Ok(None);
                };
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
                Ok(Some((n, Some(Reply { addr }))))
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
    Reply(u8),
}

fn refused(version: Version, r: Refusal) -> io::Error {
    let (code, status, text) = match r {
        Refusal::NoMethod => (0xff, 407, "no acceptable authentication method"),
        Refusal::Auth => (0xff, 407, "authentication failed"),
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
