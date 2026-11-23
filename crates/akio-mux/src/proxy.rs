//! The PROXY protocol, versions 1 (text) and 2 (binary): the header a load balancer sends before
//! a connection's first byte to pass on the client's address (ADR-095).
//!
//! **Listener side**: [`ProxyProtocol`] reads and checks the header, attaches it to the
//! connection and hands the connection to the next acceptor with the bytes after the header.
//! The next handler reads it with [`header`] or [`client_addr`]:
//!
//! ```no_run
//! # use akio::{Engine, Listener}; use akio_core::{Conn, Handler, fn_acceptor};
//! use akio_mux::proxy::{self, ProxyProtocol};
//! struct App;
//! impl Handler for App {
//!     fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
//!         println!("client {}", proxy::client_addr(c));
//!     }
//! }
//! let pp = ProxyProtocol::new(fn_acceptor(|_c: &Conn<App>| App));
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("0.0.0.0:8080".parse().unwrap()).serve_any(pp))
//!     .build()
//!     .unwrap();
//! ```
//!
//! **Dial side**: build a [`ProxyHeader`] and send it first with [`send_header`] from the dialing
//! handler's `on_open`.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use akio_core::{Acceptor, AnyAcceptor, Conn, ConnInner, DynAcceptor, DynHandler, Error, Task};

use crate::deadline::Pending;

/// Connection ids, hashed with akio-core's cheap id hasher (ids are not attacker-chosen).
type IdSet = HashSet<u64, std::hash::BuildHasherDefault<akio_core::IdHasher>>;

/// The v2 signature.
pub const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_PREFIX: &[u8] = b"PROXY ";
/// The longest v1 header, CRLF included.
pub const V1_MAX: usize = 107;
/// The longest v2 header.
pub const V2_MAX: usize = 16 + 65535;
/// Default [`ProxyProtocol::max_header_bytes`].
pub const DEFAULT_MAX_HEADER: usize = 4096;
/// Default [`ProxyProtocol::header_timeout`].
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const UNIX_LEN: usize = 108;

/// TLV types of the specification (section 2.2.7 onwards).
pub mod tlv {
    /// Application-Layer Protocol Negotiation.
    pub const ALPN: u8 = 0x01;
    /// The host name the client asked for (SNI, `Host`).
    pub const AUTHORITY: u8 = 0x02;
    /// A CRC32C of the whole header, verified when present.
    pub const CRC32C: u8 = 0x03;
    /// Padding.
    pub const NOOP: u8 = 0x04;
    /// An opaque connection id.
    pub const UNIQUE_ID: u8 = 0x05;
    /// TLS information, with sub-TLVs.
    pub const SSL: u8 = 0x20;
    /// The network namespace.
    pub const NETNS: u8 = 0x30;
}

/// The header's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// Text.
    V1,
    /// Binary.
    V2,
}

/// What the header says about the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// Made by the proxy itself (a health check): the real addresses apply.
    Local,
    /// Relayed for a client: the addresses are the client's.
    Proxy,
}

/// The client's transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Unknown or not given.
    Unspec,
    /// TCP (or another stream).
    Stream,
    /// UDP (or another datagram transport).
    Datagram,
}

/// The original endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Addresses {
    /// None given (`LOCAL`, `UNKNOWN`, `UNSPEC`): the real ones apply.
    None,
    /// IPv4 or IPv6, both of the same family.
    Inet {
        /// The client.
        source: SocketAddr,
        /// The address the client connected to.
        destination: SocketAddr,
    },
    /// Unix socket paths (trailing NUL bytes removed).
    Unix {
        /// The client's path.
        source: Vec<u8>,
        /// The path the client connected to.
        destination: Vec<u8>,
    },
}

/// One type-length-value extension of a v2 header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tlv {
    /// The type ([`tlv`] has the known ones).
    pub kind: u8,
    /// The value.
    pub value: Vec<u8>,
}

/// A PROXY protocol header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyHeader {
    /// The format it came in (or [`Version::V2`] for one built here).
    pub version: Version,
    /// `LOCAL` or `PROXY`.
    pub command: Command,
    /// The client's transport.
    pub transport: Transport,
    /// The original endpoints.
    pub addresses: Addresses,
    /// v2 extensions, in order.
    pub tlvs: Vec<Tlv>,
}

/// Why a header could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyError {
    /// A well-formed prefix: more bytes are needed.
    Incomplete,
    /// Not a PROXY header, or a malformed one. More bytes do not change this.
    Invalid(&'static str),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Incomplete => f.write_str("incomplete PROXY header"),
            ProxyError::Invalid(why) => write!(f, "invalid PROXY header: {why}"),
        }
    }
}

impl std::error::Error for ProxyError {}

fn prefix_state(b: &[u8], p: &[u8]) -> Option<bool> {
    // Some(true): b starts with p; Some(false): b is a proper prefix of p; None: neither.
    let n = b.len().min(p.len());
    if b[..n] != p[..n] {
        None
    } else {
        Some(n == p.len())
    }
}

impl ProxyHeader {
    /// A `PROXY` header for a stream from `source` to `destination` (an IPv4 address of a mixed
    /// pair is written as IPv4-mapped IPv6).
    pub fn proxy(source: SocketAddr, destination: SocketAddr) -> ProxyHeader {
        let (source, destination) = same_family(source, destination);
        ProxyHeader {
            version: Version::V2,
            command: Command::Proxy,
            transport: Transport::Stream,
            addresses: Addresses::Inet {
                source,
                destination,
            },
            tlvs: Vec::new(),
        }
    }

    /// A `LOCAL` header (a health check of the proxy itself).
    pub fn local() -> ProxyHeader {
        ProxyHeader {
            version: Version::V2,
            command: Command::Local,
            transport: Transport::Unspec,
            addresses: Addresses::None,
            tlvs: Vec::new(),
        }
    }

    /// Adds a TLV (v2 only).
    #[must_use]
    pub fn with_tlv(mut self, kind: u8, value: impl Into<Vec<u8>>) -> ProxyHeader {
        self.tlvs.push(Tlv {
            kind,
            value: value.into(),
        });
        self
    }

    /// The client's address, for a `PROXY` header with IP addresses.
    pub fn source(&self) -> Option<SocketAddr> {
        match (&self.command, &self.addresses) {
            (Command::Proxy, Addresses::Inet { source, .. }) => Some(*source),
            _ => None,
        }
    }

    /// The address the client connected to, for a `PROXY` header with IP addresses.
    pub fn destination(&self) -> Option<SocketAddr> {
        match (&self.command, &self.addresses) {
            (Command::Proxy, Addresses::Inet { destination, .. }) => Some(*destination),
            _ => None,
        }
    }

    /// The value of the first TLV of this type.
    pub fn tlv(&self, kind: u8) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|t| t.kind == kind)
            .map(|t| &t.value[..])
    }

    /// The [`tlv::AUTHORITY`] TLV (the host name the client asked for), if valid UTF-8.
    pub fn authority(&self) -> Option<&str> {
        std::str::from_utf8(self.tlv(tlv::AUTHORITY)?).ok()
    }

    /// Reads a v1 or v2 header from the start of `b`; returns it and its length.
    ///
    /// Prefix-consistent: a prefix of a header is [`ProxyError::Incomplete`], and input found
    /// invalid stays invalid however many bytes follow.
    pub fn parse(b: &[u8]) -> Result<(ProxyHeader, usize), ProxyError> {
        if b.is_empty() {
            return Err(ProxyError::Incomplete);
        }
        match (prefix_state(b, V1_PREFIX), prefix_state(b, &V2_SIGNATURE)) {
            (Some(true), _) => parse_v1(b),
            (_, Some(true)) => parse_v2(b),
            (Some(false), _) | (_, Some(false)) => Err(ProxyError::Incomplete),
            (None, None) => Err(ProxyError::Invalid("no PROXY signature")),
        }
    }

    /// The v1 form: `None` when v1 cannot carry the header (Unix addresses, TLVs, datagrams).
    /// A `LOCAL` header or one without addresses is written as `PROXY UNKNOWN`.
    pub fn encode_v1(&self) -> Option<Vec<u8>> {
        if !self.tlvs.is_empty() || self.transport == Transport::Datagram {
            return None;
        }
        let line = match (&self.command, &self.addresses) {
            (Command::Local, _) | (_, Addresses::None) => "PROXY UNKNOWN\r\n".to_owned(),
            (_, Addresses::Unix { .. }) => return None,
            (
                Command::Proxy,
                Addresses::Inet {
                    source,
                    destination,
                },
            ) => {
                let (s, d) = same_family(*source, *destination);
                let fam = if s.is_ipv4() { "TCP4" } else { "TCP6" };
                format!(
                    "PROXY {fam} {} {} {} {}\r\n",
                    s.ip(),
                    d.ip(),
                    s.port(),
                    d.port()
                )
            }
        };
        Some(line.into_bytes())
    }

    /// The v2 form: `None` when the addresses and TLVs pass 65535 bytes. A [`tlv::CRC32C`] TLV
    /// of 4 bytes gets the header's checksum.
    pub fn encode_v2(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(16 + 36);
        out.extend_from_slice(&V2_SIGNATURE);
        out.push(0x20 | u8::from(self.command == Command::Proxy));
        let proto = match self.transport {
            Transport::Unspec => 0,
            Transport::Stream => 1,
            Transport::Datagram => 2,
        };
        let (fam, addr): (u8, Vec<u8>) = match &self.addresses {
            Addresses::None => (0, Vec::new()),
            Addresses::Inet {
                source,
                destination,
            } => {
                let (s, d) = same_family(*source, *destination);
                let mut a = Vec::with_capacity(36);
                match (s.ip(), d.ip()) {
                    (IpAddr::V4(si), IpAddr::V4(di)) => {
                        a.extend_from_slice(&si.octets());
                        a.extend_from_slice(&di.octets());
                    }
                    (si, di) => {
                        a.extend_from_slice(&v6(si).octets());
                        a.extend_from_slice(&v6(di).octets());
                    }
                }
                a.extend_from_slice(&s.port().to_be_bytes());
                a.extend_from_slice(&d.port().to_be_bytes());
                (if s.is_ipv4() { 1 } else { 2 }, a)
            }
            Addresses::Unix {
                source,
                destination,
            } => {
                if source.len() > UNIX_LEN || destination.len() > UNIX_LEN {
                    return None;
                }
                let mut a = vec![0u8; 2 * UNIX_LEN];
                a[..source.len()].copy_from_slice(source);
                a[UNIX_LEN..UNIX_LEN + destination.len()].copy_from_slice(destination);
                (3, a)
            }
        };
        out.push((fam << 4) | proto);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&addr);
        let mut crc_at = None;
        for t in &self.tlvs {
            let n = u16::try_from(t.value.len()).ok()?;
            out.push(t.kind);
            out.extend_from_slice(&n.to_be_bytes());
            if t.kind == tlv::CRC32C && t.value.len() == 4 && crc_at.is_none() {
                crc_at = Some(out.len());
                out.extend_from_slice(&[0; 4]);
            } else {
                out.extend_from_slice(&t.value);
            }
        }
        let len = u16::try_from(out.len() - 16).ok()?;
        out[14..16].copy_from_slice(&len.to_be_bytes());
        if let Some(at) = crc_at {
            let c = crc32c(&out);
            out[at..at + 4].copy_from_slice(&c.to_be_bytes());
        }
        Some(out)
    }

    /// The header in `version`'s form (`None` as [`encode_v1`](Self::encode_v1) /
    /// [`encode_v2`](Self::encode_v2)).
    pub fn encode(&self, version: Version) -> Option<Vec<u8>> {
        match version {
            Version::V1 => self.encode_v1(),
            Version::V2 => self.encode_v2(),
        }
    }
}

fn v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}

fn same_family(s: SocketAddr, d: SocketAddr) -> (SocketAddr, SocketAddr) {
    if s.is_ipv4() == d.is_ipv4() {
        (s, d)
    } else {
        (
            SocketAddr::new(IpAddr::V6(v6(s.ip())), s.port()),
            SocketAddr::new(IpAddr::V6(v6(d.ip())), d.port()),
        )
    }
}

fn parse_v1(b: &[u8]) -> Result<(ProxyHeader, usize), ProxyError> {
    let window = &b[..b.len().min(V1_MAX)];
    let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
        return if b.len() >= V1_MAX {
            Err(ProxyError::Invalid("v1 header longer than 107 bytes"))
        } else {
            Err(ProxyError::Incomplete)
        };
    };
    let line = std::str::from_utf8(&b[V1_PREFIX.len()..end])
        .map_err(|_| ProxyError::Invalid("v1 header not ASCII"))?;
    let used = end + 2;
    let unknown = ProxyHeader {
        version: Version::V1,
        command: Command::Proxy,
        transport: Transport::Unspec,
        addresses: Addresses::None,
        tlvs: Vec::new(),
    };
    if line == "UNKNOWN" || line.starts_with("UNKNOWN ") {
        return Ok((unknown, used));
    }
    let f: Vec<&str> = line.split(' ').collect();
    let [fam, src, dst, sport, dport] = f[..] else {
        return Err(ProxyError::Invalid("v1 header needs 5 fields"));
    };
    let (s, d): (IpAddr, IpAddr) = match fam {
        "TCP4" => (
            src.parse::<Ipv4Addr>()
                .map_err(|_| ProxyError::Invalid("v1 source address"))?
                .into(),
            dst.parse::<Ipv4Addr>()
                .map_err(|_| ProxyError::Invalid("v1 destination address"))?
                .into(),
        ),
        "TCP6" => (
            src.parse::<Ipv6Addr>()
                .map_err(|_| ProxyError::Invalid("v1 source address"))?
                .into(),
            dst.parse::<Ipv6Addr>()
                .map_err(|_| ProxyError::Invalid("v1 destination address"))?
                .into(),
        ),
        _ => return Err(ProxyError::Invalid("v1 protocol not TCP4, TCP6 or UNKNOWN")),
    };
    let (sp, dp) = (port(sport)?, port(dport)?);
    Ok((
        ProxyHeader {
            version: Version::V1,
            command: Command::Proxy,
            transport: Transport::Stream,
            addresses: Addresses::Inet {
                source: SocketAddr::new(s, sp),
                destination: SocketAddr::new(d, dp),
            },
            tlvs: Vec::new(),
        },
        used,
    ))
}

/// A decimal port, 0..=65535, no sign and no leading zero.
fn port(s: &str) -> Result<u16, ProxyError> {
    let bad = ProxyError::Invalid("v1 port");
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad);
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(bad);
    }
    s.parse().map_err(|_| bad)
}

fn parse_v2(b: &[u8]) -> Result<(ProxyHeader, usize), ProxyError> {
    if let Some(&vc) = b.get(12) {
        if vc >> 4 != 2 {
            return Err(ProxyError::Invalid("v2 version not 2"));
        }
        if vc & 0xf > 1 {
            return Err(ProxyError::Invalid("v2 command not LOCAL or PROXY"));
        }
    }
    if let Some(&fp) = b.get(13) {
        if fp >> 4 > 3 || fp & 0xf > 2 {
            return Err(ProxyError::Invalid("v2 family or protocol unknown"));
        }
    }
    if b.len() < 16 {
        return Err(ProxyError::Incomplete);
    }
    let len = usize::from(u16::from_be_bytes([b[14], b[15]]));
    let total = 16 + len;
    if b.len() < total {
        return Err(ProxyError::Incomplete);
    }
    let local = b[12] & 0xf == 0;
    let transport = match b[13] & 0xf {
        0 => Transport::Unspec,
        1 => Transport::Stream,
        _ => Transport::Datagram,
    };
    if local {
        // The block, family included, is discarded (section 2.2).
        return Ok((
            ProxyHeader {
                version: Version::V2,
                command: Command::Local,
                transport,
                addresses: Addresses::None,
                tlvs: Vec::new(),
            },
            total,
        ));
    }
    let block = &b[16..total];
    let fam = b[13] >> 4;
    let alen = [0, 12, 36, 2 * UNIX_LEN][usize::from(fam)];
    if len < alen {
        return Err(ProxyError::Invalid("v2 length shorter than its addresses"));
    }
    let a = &block[..alen];
    let addresses = match fam {
        1 => {
            let ip = |o: usize| Ipv4Addr::new(a[o], a[o + 1], a[o + 2], a[o + 3]);
            Addresses::Inet {
                source: SocketAddr::new(ip(0).into(), u16::from_be_bytes([a[8], a[9]])),
                destination: SocketAddr::new(ip(4).into(), u16::from_be_bytes([a[10], a[11]])),
            }
        }
        2 => {
            let ip = |o: usize| {
                let mut x = [0u8; 16];
                x.copy_from_slice(&a[o..o + 16]);
                Ipv6Addr::from(x)
            };
            Addresses::Inet {
                source: SocketAddr::new(ip(0).into(), u16::from_be_bytes([a[32], a[33]])),
                destination: SocketAddr::new(ip(16).into(), u16::from_be_bytes([a[34], a[35]])),
            }
        }
        3 => {
            let trim = |p: &[u8]| {
                let n = p.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
                p[..n].to_vec()
            };
            Addresses::Unix {
                source: trim(&a[..UNIX_LEN]),
                destination: trim(&a[UNIX_LEN..]),
            }
        }
        _ => Addresses::None,
    };
    let mut tlvs = Vec::new();
    let mut rest = &block[alen..];
    let mut crc: Option<(usize, u32)> = None;
    while !rest.is_empty() {
        if rest.len() < 3 {
            return Err(ProxyError::Invalid("v2 TLV truncated"));
        }
        let n = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        if rest.len() < 3 + n {
            return Err(ProxyError::Invalid("v2 TLV length past the header"));
        }
        let value = &rest[3..3 + n];
        if rest[0] == tlv::CRC32C {
            if n != 4 || crc.is_some() {
                return Err(ProxyError::Invalid("v2 CRC32C TLV"));
            }
            let at = total - rest.len() + 3;
            crc = Some((
                at,
                u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            ));
        }
        tlvs.push(Tlv {
            kind: rest[0],
            value: value.to_vec(),
        });
        rest = &rest[3 + n..];
    }
    if let Some((at, want)) = crc {
        let mut h = b[..total].to_vec();
        h[at..at + 4].fill(0);
        if crc32c(&h) != want {
            return Err(ProxyError::Invalid("v2 CRC32C mismatch"));
        }
    }
    Ok((
        ProxyHeader {
            version: Version::V2,
            command: Command::Proxy,
            transport,
            addresses,
            tlvs,
        },
        total,
    ))
}

const CRC32C_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32C (Castagnoli), as the [`tlv::CRC32C`] TLV carries it.
pub fn crc32c(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c = CRC32C_TABLE[((c ^ u32::from(x)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The PROXY header the listener layer attached to the connection.
pub fn header<H>(c: &Conn<H>) -> Option<&ProxyHeader> {
    c.attachment::<ProxyHeader>()
}

/// The client's address: the PROXY header's source when there is one, else the socket's peer.
pub fn client_addr<H>(c: &Conn<H>) -> SocketAddr {
    header(c)
        .and_then(ProxyHeader::source)
        .unwrap_or_else(|| c.peer_addr())
}

/// Dial side: sends `header` in `version`'s form as the connection's first bytes (call it from
/// the dialing handler's `on_open`, before anything else). `Error::Io(InvalidInput)` when the
/// header cannot be written in that form.
pub fn send_header<H>(
    c: &Conn<H>,
    header: &ProxyHeader,
    version: Version,
) -> akio_core::Result<()> {
    let bytes = header.encode(version).ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "header not representable in this PROXY version",
        ))
    })?;
    c.send_owned(bytes)
}

type Trust = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

struct Inner {
    next: Arc<dyn DynAcceptor>,
    timeout: Option<Duration>,
    max: usize,
    v1: bool,
    v2: bool,
    allow_missing: bool,
    trusted: Option<Trust>,
    /// Connections still reading their header (for graceful shutdown).
    reading: Mutex<IdSet>,
}

/// Listener side: reads a PROXY header before the next acceptor runs (ADR-095).
///
/// A connection whose header is malformed, longer than [`max_header_bytes`](Self::max_header_bytes)
/// or not complete within [`header_timeout`](Self::header_timeout) is closed. The header is
/// attached to the connection ([`header`], [`client_addr`]); the bytes after it are replayed to
/// the next acceptor's handler, which owns the connection from then on.
#[derive(Clone)]
pub struct ProxyProtocol(Arc<Inner>);

impl std::fmt::Debug for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyProtocol").finish_non_exhaustive()
    }
}

impl ProxyProtocol {
    /// Reads the header, then hands the connection to `next`.
    pub fn new<A: Acceptor>(next: A) -> ProxyProtocol {
        Self::from_dyn(Arc::new(next))
    }

    /// The same, for a type-erased acceptor (a `Mux`, for instance).
    pub fn new_any(next: impl Into<AnyAcceptor>) -> ProxyProtocol {
        Self::from_dyn(next.into().into_dyn())
    }

    fn from_dyn(next: Arc<dyn DynAcceptor>) -> ProxyProtocol {
        ProxyProtocol(Arc::new(Inner {
            next,
            timeout: Some(DEFAULT_HEADER_TIMEOUT),
            max: DEFAULT_MAX_HEADER,
            v1: true,
            v2: true,
            allow_missing: false,
            trusted: None,
            reading: Mutex::new(IdSet::default()),
        }))
    }

    fn inner_mut(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.0).expect("configure ProxyProtocol before serving with it")
    }

    /// How long a client may take to send the whole header (default 5 s); `None` waits forever.
    #[must_use]
    pub fn header_timeout(mut self, d: Option<Duration>) -> ProxyProtocol {
        self.inner_mut().timeout = d;
        self
    }

    /// The longest header accepted (default 4096 bytes; a v1 header is never longer than 107).
    #[must_use]
    pub fn max_header_bytes(mut self, n: usize) -> ProxyProtocol {
        self.inner_mut().max = n.clamp(16, V2_MAX);
        self
    }

    /// Which versions are accepted (both by default); a header of the other one is refused.
    #[must_use]
    pub fn versions(mut self, v1: bool, v2: bool) -> ProxyProtocol {
        let i = self.inner_mut();
        i.v1 = v1;
        i.v2 = v2;
        self
    }

    /// Lets connections without a header through to the next acceptor, unchanged and with no
    /// header attached (default false: they are closed).
    #[must_use]
    pub fn allow_missing(mut self, allow: bool) -> ProxyProtocol {
        self.inner_mut().allow_missing = allow;
        self
    }

    /// Only peers for which `f` returns true may send a header (the load balancers); others go
    /// straight to the next acceptor as if this layer were absent, so a header they send is not
    /// believed. All peers by default.
    #[must_use]
    pub fn trusted(
        mut self,
        f: impl Fn(SocketAddr) -> bool + Send + Sync + 'static,
    ) -> ProxyProtocol {
        self.inner_mut().trusted = Some(Arc::new(f));
        self
    }

    /// The form `akio::Listener::serve_any` takes (`From<ProxyProtocol>` does the same).
    pub fn into_any(self) -> AnyAcceptor {
        AnyAcceptor::from_dyn(Arc::new(self))
    }

    fn reading(&self) -> std::sync::MutexGuard<'_, IdSet> {
        self.0.reading.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl From<ProxyProtocol> for AnyAcceptor {
    fn from(p: ProxyProtocol) -> AnyAcceptor {
        p.into_any()
    }
}

impl DynAcceptor for ProxyProtocol {
    fn on_open(&self, inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
        if let Some(t) = &self.0.trusted {
            if !t(inner.peer_addr()) {
                return self.0.next.on_open(inner);
            }
        }
        self.reading().insert(inner.id());
        Box::new(ProxyConn {
            pp: self.clone(),
            conn: inner.clone(),
            buf: Vec::new(),
            target: None,
            pending: self.0.timeout.map(|d| Pending::start(inner, d)),
        })
    }

    fn on_shutdown(&self, inner: &Arc<ConnInner>) {
        if self.reading().contains(&inner.id()) {
            inner.close(); // still reading the header: nothing to finish
        } else {
            self.0.next.on_shutdown(inner);
        }
    }
}

struct ProxyConn {
    pp: ProxyProtocol,
    conn: Arc<ConnInner>,
    buf: Vec<u8>,
    target: Option<Box<dyn DynHandler>>,
    pending: Option<Arc<Pending>>,
}

impl ProxyConn {
    fn hand_off(&mut self, header: Option<ProxyHeader>, skip: usize) {
        if let Some(p) = self.pending.take() {
            p.decided();
        }
        self.pp.reading().remove(&self.conn.id());
        if let Some(h) = header {
            if self.conn.attach(Arc::new(h)).is_err() {
                return self.conn.close(); // another layer attached first
            }
        }
        let mut t = self.pp.0.next.on_open(&self.conn);
        let buf = std::mem::take(&mut self.buf);
        if buf.len() > skip {
            t.on_data(&buf[skip..]);
        }
        self.target = Some(t);
    }

    fn step(&mut self) {
        let cfg = &self.pp.0;
        let b = &self.buf;
        let (v1, v2) = (prefix_state(b, V1_PREFIX), prefix_state(b, &V2_SIGNATURE));
        if v1.is_none() && v2.is_none() {
            if cfg.allow_missing {
                self.hand_off(None, 0);
            } else {
                self.conn.close();
            }
            return;
        }
        if (v1 == Some(true) && !cfg.v1) || (v2 == Some(true) && !cfg.v2) {
            return self.conn.close();
        }
        let cap = if v1.is_some() {
            V1_MAX.min(cfg.max)
        } else {
            cfg.max
        };
        if v2 == Some(true)
            && b.len() >= 16
            && 16 + usize::from(u16::from_be_bytes([b[14], b[15]])) > cap
        {
            return self.conn.close(); // announces more than the limit: no need to wait for it
        }
        match ProxyHeader::parse(b) {
            Ok((h, n)) if n <= cap => self.hand_off(Some(h), n),
            Err(ProxyError::Incomplete) if b.len() < cap => {}
            _ => self.conn.close(),
        }
    }
}

impl DynHandler for ProxyConn {
    fn on_data(&mut self, data: &[u8]) {
        if let Some(t) = &mut self.target {
            return t.on_data(data);
        }
        if !self.conn.is_open() {
            return;
        }
        self.buf.extend_from_slice(data);
        self.step();
    }

    fn on_close(&mut self, err: Option<Error>) {
        if self.target.is_none() {
            self.pp.reading().remove(&self.conn.id());
        }
        if let Some(t) = &mut self.target {
            t.on_close(err);
        }
    }

    fn run_task(&mut self, task: Task) {
        if let Some(t) = &mut self.target {
            t.run_task(task);
        }
    }

    fn on_batch_end(&mut self) {
        if let Some(t) = &mut self.target {
            t.on_batch_end();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v1_valid() {
        let w = b"PROXY TCP4 192.0.2.1 198.51.100.2 51000 443\r\nGET /";
        let (h, n) = ProxyHeader::parse(w).unwrap();
        assert_eq!(n, w.len() - 5);
        assert_eq!(h.version, Version::V1);
        assert_eq!(h.source(), Some(v4("192.0.2.1:51000")));
        assert_eq!(h.destination(), Some(v4("198.51.100.2:443")));
        assert_eq!(h.encode_v1().unwrap(), w[..n]);
        let (h6, _) = ProxyHeader::parse(b"PROXY TCP6 2001:db8::1 ::1 1 65535\r\n").unwrap();
        assert_eq!(h6.source(), Some("[2001:db8::1]:1".parse().unwrap()));
        let (u, n) = ProxyHeader::parse(b"PROXY UNKNOWN ffff::1 x y z\r\n").unwrap();
        assert_eq!((u.addresses, n), (Addresses::None, 29));
        for p in 1..w.len() - 5 {
            assert_eq!(
                ProxyHeader::parse(&w[..p]).unwrap_err(),
                ProxyError::Incomplete,
                "{p}"
            );
        }
    }

    #[test]
    fn v1_invalid() {
        for w in [
            &b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n"[..],
            b"PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n",
            b"PROXY TCP4 ::1 5.6.7.8 1 2\r\n",
            b"PROXY TCP6 1.2.3.4 ::1 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n",
            b"PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
            b"PROXY \xff\r\n",
            b"GET / HTTP/1.1\r\n",
        ] {
            assert!(
                matches!(ProxyHeader::parse(w), Err(ProxyError::Invalid(_))),
                "{w:?}"
            );
        }
        // No CRLF within 107 bytes.
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(V1_MAX, b'a');
        assert!(matches!(
            ProxyHeader::parse(&long),
            Err(ProxyError::Invalid(_))
        ));
        assert_eq!(
            ProxyHeader::parse(&long[..106]).unwrap_err(),
            ProxyError::Incomplete
        );
    }

    #[test]
    fn v2_roundtrip_and_prefixes() {
        let hs = [
            ProxyHeader::proxy(v4("10.0.0.1:1234"), v4("10.0.0.2:80")),
            ProxyHeader::proxy(
                "[2001:db8::5]:9".parse().unwrap(),
                "[::1]:443".parse().unwrap(),
            )
            .with_tlv(tlv::AUTHORITY, "example.com")
            .with_tlv(tlv::CRC32C, [0; 4])
            .with_tlv(tlv::NOOP, []),
            ProxyHeader {
                transport: Transport::Datagram,
                addresses: Addresses::Unix {
                    source: b"/run/a.sock".to_vec(),
                    destination: b"/run/b.sock".to_vec(),
                },
                ..ProxyHeader::proxy(v4("1.1.1.1:1"), v4("2.2.2.2:2"))
            },
            ProxyHeader::local(),
        ];
        for h in hs {
            let w = h.encode_v2().unwrap();
            let (got, n) = ProxyHeader::parse(&w).unwrap();
            assert_eq!(n, w.len());
            let mut want = h;
            if let Some(t) = want.tlvs.iter_mut().find(|t| t.kind == tlv::CRC32C) {
                t.value = got.tlv(tlv::CRC32C).unwrap().to_vec();
            }
            assert_eq!(got, want);
            for p in 1..w.len() {
                assert_eq!(
                    ProxyHeader::parse(&w[..p]).unwrap_err(),
                    ProxyError::Incomplete
                );
            }
        }
        let h = ProxyHeader::proxy(v4("1.2.3.4:5"), "[::1]:6".parse().unwrap());
        let (got, _) = ProxyHeader::parse(&h.encode_v2().unwrap()).unwrap();
        assert_eq!(got.source(), Some("[::ffff:1.2.3.4]:5".parse().unwrap()));
        assert_eq!(
            ProxyHeader::parse(&ProxyHeader::local().encode_v1().unwrap())
                .unwrap()
                .0
                .addresses,
            Addresses::None
        );
    }

    #[test]
    fn v2_forged() {
        let good = ProxyHeader::proxy(v4("1.2.3.4:5"), v4("5.6.7.8:9"))
            .with_tlv(tlv::CRC32C, [0; 4])
            .encode_v2()
            .unwrap();
        let bad = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut w = good.clone();
            f(&mut w);
            ProxyHeader::parse(&w)
        };
        assert!(matches!(
            bad(&|w| w[12] = 0x31),
            Err(ProxyError::Invalid(_))
        )); // version 3
        assert!(matches!(
            bad(&|w| w[12] = 0x22),
            Err(ProxyError::Invalid(_))
        )); // command 2
        assert!(matches!(
            bad(&|w| w[13] = 0x41),
            Err(ProxyError::Invalid(_))
        )); // family 4
        assert!(matches!(
            bad(&|w| w[13] = 0x13),
            Err(ProxyError::Invalid(_))
        )); // protocol 3
        // Length shorter than the address block.
        assert!(matches!(
            bad(&|w| w[14..16].copy_from_slice(&[0, 4])),
            Err(ProxyError::Invalid(_))
        ));
        // A TLV whose length runs past the header.
        assert!(matches!(
            bad(&|w| w[30] = 0x50),
            Err(ProxyError::Invalid(_))
        ));
        // A length longer than what was sent: waits (bounded by the layer's cap).
        assert_eq!(bad(&|w| w[15] += 10).unwrap_err(), ProxyError::Incomplete);
        // A flipped address bit fails the checksum.
        assert!(matches!(
            bad(&|w| w[16] ^= 1),
            Err(ProxyError::Invalid("v2 CRC32C mismatch"))
        ));
        // LOCAL ignores whatever follows.
        let (l, n) = bad(&|w| w[12] = 0x20).unwrap();
        assert_eq!(
            (l.command, l.addresses, n),
            (Command::Local, Addresses::None, good.len())
        );
    }

    #[test]
    fn crc32c_vector() {
        // RFC 3720 B.4: 32 bytes of zeros.
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
}
