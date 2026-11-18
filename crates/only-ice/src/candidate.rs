//! Credentials and candidates: priorities and foundations (RFC 8445 §5.1), the SDP
//! `candidate` attribute (RFC 8839 §5.1).

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// The `ice-char` alphabet of RFC 8839 §5.4 (`ALPHA / DIGIT / "+" / "/"`).
const ICE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Fills `buf` with random bytes: the OS generator, or (should it be unavailable) the
/// randomly keyed std hasher, so that this never fails.
pub(crate) fn random_bytes(buf: &mut [u8]) {
    if only_crypto::rand::fill_random(buf).is_ok() {
        return;
    }
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        let v = h.finish().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

/// A random `u64` (tie-breakers).
pub(crate) fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    random_bytes(&mut b);
    u64::from_le_bytes(b)
}

/// ICE credentials: the `a=ice-ufrag` and `a=ice-pwd` of one side.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Credentials {
    /// Username fragment (`a=ice-ufrag`, 4 to 256 ice-chars).
    pub ufrag: String,
    /// Password (`a=ice-pwd`, 22 to 256 ice-chars); the short-term STUN key.
    pub pwd: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("ufrag", &self.ufrag)
            .field("pwd", &"..")
            .finish()
    }
}

impl Credentials {
    /// Fresh random credentials: an 8-character ufrag and a 24-character password from the
    /// ice-char set `[A-Za-z0-9+/]`.
    pub fn random() -> Credentials {
        fn chars(n: usize) -> String {
            let mut b = vec![0u8; n];
            random_bytes(&mut b);
            b.iter()
                .map(|&x| char::from(ICE_CHARS[usize::from(x & 63)]))
                .collect()
        }
        Credentials {
            ufrag: chars(8),
            pwd: chars(24),
        }
    }

    /// Credentials from SDP values (not validated).
    pub fn new(ufrag: impl Into<String>, pwd: impl Into<String>) -> Credentials {
        Credentials {
            ufrag: ufrag.into(),
            pwd: pwd.into(),
        }
    }
}

/// The type of a candidate (RFC 8445 §5.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// An address of a local interface (`typ host`).
    Host,
    /// The address a STUN server saw (`typ srflx`).
    ServerReflexive,
    /// An address learned from a connectivity check (`typ prflx`).
    PeerReflexive,
    /// An address allocated on a TURN server (`typ relay`).
    Relayed,
}

impl CandidateKind {
    /// The type preference of RFC 8445 §5.1.2.2: host 126, prflx 110, srflx 100, relay 0.
    pub fn type_preference(self) -> u32 {
        match self {
            CandidateKind::Host => 126,
            CandidateKind::PeerReflexive => 110,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relayed => 0,
        }
    }

    /// The SDP `typ` token.
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateKind::Host => "host",
            CandidateKind::PeerReflexive => "prflx",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::Relayed => "relay",
        }
    }
}

/// The `tcptype` of a TCP candidate (RFC 6544 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpType {
    /// Opens connections, never accepts them (its port is 9 in the SDP).
    Active,
    /// Accepts connections, never opens them.
    Passive,
    /// Simultaneous open.
    So,
}

impl TcpType {
    /// The SDP token.
    pub fn as_str(self) -> &'static str {
        match self {
            TcpType::Active => "active",
            TcpType::Passive => "passive",
            TcpType::So => "so",
        }
    }

    /// The direction preference of RFC 6544 §4.2 (host and server-reflexive candidates,
    /// UDP-preferring order: active 6, passive 4, so 2).
    fn direction_pref(self) -> u32 {
        match self {
            TcpType::Active => 6,
            TcpType::Passive => 4,
            TcpType::So => 2,
        }
    }

    /// Whether a local candidate of this type pairs with a remote one of type `remote`
    /// (RFC 6544 §6.2: active with passive, so with so).
    pub fn pairs_with(self, remote: TcpType) -> bool {
        matches!(
            (self, remote),
            (TcpType::Active, TcpType::Passive)
                | (TcpType::Passive, TcpType::Active)
                | (TcpType::So, TcpType::So)
        )
    }
}

/// Why a candidate line was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Not a valid `candidate` attribute.
    Syntax(&'static str),
    /// The address is an mDNS name (`*.local`, as browsers hide host addresses).
    Mdns,
    /// The address is another fully qualified domain name.
    Fqdn,
}

impl ParseError {
    /// Whether the line is well formed but describes a candidate this agent does not use
    /// (mDNS, FQDN): callers usually skip those silently.
    pub fn is_unsupported(&self) -> bool {
        !matches!(self, ParseError::Syntax(_))
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Syntax(why) => write!(f, "ice candidate: {why}"),
            ParseError::Mdns => f.write_str("ice candidate: mDNS address not resolved"),
            ParseError::Fqdn => f.write_str("ice candidate: FQDN address not resolved"),
        }
    }
}

impl std::error::Error for ParseError {}

/// An ICE candidate: UDP, or TCP with a [`TcpType`] (RFC 6544); component 1 when created
/// locally.
///
/// For candidates created with the constructors, [`Candidate::base`] is the local address
/// the candidate sends from; for parsed (remote) candidates it equals [`Candidate::addr`] and
/// the SDP `raddr`/`rport` is kept as [`Candidate::related`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Candidate {
    foundation: String,
    component: u16,
    priority: u32,
    addr: SocketAddr,
    kind: CandidateKind,
    base: SocketAddr,
    related: Option<SocketAddr>,
    ufrag: Option<String>,
    generation: Option<u32>,
    tcp: Option<TcpType>,
}

/// Type preferences of TCP candidates: below every UDP type so that UDP pairs win when both
/// work (RFC 6544 §4.2 leaves the values to the implementation; these are Chrome's).
fn tcp_type_preference(kind: CandidateKind) -> u32 {
    match kind {
        CandidateKind::Host => 90,
        CandidateKind::PeerReflexive => 80,
        CandidateKind::ServerReflexive => 65,
        CandidateKind::Relayed => 0,
    }
}

/// Local preference of a TCP candidate, RFC 6544 §4.2: `2^13 * direction-pref + other-pref`,
/// the other preference ranking IPv6 above IPv4.
fn tcp_local_preference(addr: &SocketAddr, t: TcpType) -> u32 {
    let other = match addr.ip() {
        IpAddr::V6(ip) if (ip.segments()[0] & 0xffc0) == 0xfe80 => 2047,
        IpAddr::V6(_) => 8191,
        IpAddr::V4(_) => 4095,
    };
    (t.direction_pref() << 13) + other
}

/// Local preference: IPv6 above IPv4 (RFC 8421 style), leaving room below.
fn local_preference(addr: &SocketAddr) -> u32 {
    match addr.ip() {
        IpAddr::V6(ip) if (ip.segments()[0] & 0xffc0) == 0xfe80 => 30_000,
        IpAddr::V6(_) => 65_535,
        IpAddr::V4(_) => 32_767,
    }
}

/// Candidate priority, RFC 8445 §5.1.2.1.
pub(crate) fn priority(type_pref: u32, local_pref: u32, component: u16) -> u32 {
    (type_pref << 24) | ((local_pref & 0xffff) << 8) | (256 - u32::from(component.clamp(1, 256)))
}

/// A stable foundation (RFC 8445 §5.1.1.3): same type, base IP and transport give the same
/// value. FNV-1a, printed in decimal (ice-chars).
fn foundation(kind: CandidateKind, base: &SocketAddr, tcp: bool) -> String {
    let mut h: u32 = 0x811c_9dc5;
    let mut eat = |b: u8| h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    eat(kind.type_preference() as u8);
    match base.ip() {
        IpAddr::V4(ip) => ip.octets().into_iter().for_each(&mut eat),
        IpAddr::V6(ip) => ip.octets().into_iter().for_each(&mut eat),
    }
    eat(if tcp { b't' } else { b'u' });
    h.to_string()
}

impl Candidate {
    fn local(kind: CandidateKind, addr: SocketAddr, base: SocketAddr, prio: Option<u32>) -> Self {
        let lp = local_preference(&base);
        Candidate {
            foundation: foundation(kind, &base, false),
            component: 1,
            priority: prio.unwrap_or_else(|| priority(kind.type_preference(), lp, 1)),
            addr,
            kind,
            base,
            related: (kind != CandidateKind::Host).then_some(base),
            ufrag: None,
            generation: None,
            tcp: None,
        }
    }

    /// A host candidate: a local socket address (its own base).
    pub fn host(addr: SocketAddr) -> Candidate {
        Candidate::local(CandidateKind::Host, addr, addr, None)
    }

    /// A server-reflexive candidate `addr` (from a STUN server) of the local socket `base`.
    pub fn server_reflexive(addr: SocketAddr, base: SocketAddr) -> Candidate {
        Candidate::local(CandidateKind::ServerReflexive, addr, base, None)
    }

    /// A relayed candidate `addr` (a TURN allocation) reached from the local socket `base`.
    /// Checks and data on a relayed pair use the relayed address as their
    /// [`Transmit::source`](crate::Transmit::source): the caller wraps them for its TURN
    /// client, and passes the relayed address as the destination of what it unwraps.
    pub fn relayed(addr: SocketAddr, base: SocketAddr) -> Candidate {
        Candidate::local(CandidateKind::Relayed, addr, base, None)
    }

    /// A relayed candidate whose allocation is reached over a TCP (`tls == false`) or TLS
    /// connection to the TURN server: the relayed address is still UDP, but the candidate
    /// ranks below one allocated over UDP (local preference halved over TCP, quartered over
    /// TLS, as browsers rank them) and has a foundation of its own.
    pub fn relayed_over_stream(addr: SocketAddr, base: SocketAddr, tls: bool) -> Candidate {
        let kind = CandidateKind::Relayed;
        let mut c = Candidate::local(kind, addr, base, None);
        let lp = local_preference(&base) >> if tls { 2 } else { 1 };
        c.priority = priority(kind.type_preference(), lp, 1);
        let mut f = foundation(kind, &base, false);
        f.push(if tls { '3' } else { '2' });
        c.foundation = f;
        c
    }

    /// A TCP host candidate (RFC 6544) on the local address `addr`: for
    /// [`TcpType::Passive`], the address of a listening socket.
    pub fn host_tcp(addr: SocketAddr, tcp: TcpType) -> Candidate {
        let kind = CandidateKind::Host;
        let mut c = Candidate::local(kind, addr, addr, None);
        c.tcp = Some(tcp);
        c.foundation = foundation(kind, &addr, true);
        c.priority = priority(
            tcp_type_preference(kind),
            tcp_local_preference(&addr, tcp),
            1,
        );
        c
    }

    /// A peer-reflexive candidate with an explicit priority.
    pub fn peer_reflexive(addr: SocketAddr, base: SocketAddr, priority: u32) -> Candidate {
        Candidate::local(CandidateKind::PeerReflexive, addr, base, Some(priority))
    }

    /// The transport address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base (the local address it sends from; [`Candidate::addr`] for remote candidates).
    pub fn base(&self) -> SocketAddr {
        self.base
    }

    /// The SDP related address (`raddr`/`rport`), if any.
    pub fn related(&self) -> Option<SocketAddr> {
        self.related
    }

    /// The type.
    pub fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// The priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// The foundation.
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// The component id (1 for RTP; candidates of other components are ignored by the agent).
    pub fn component(&self) -> u16 {
        self.component
    }

    /// The `ufrag` extension (RFC 8840 trickle: the generation's username fragment).
    pub fn ufrag(&self) -> Option<&str> {
        self.ufrag.as_deref()
    }

    /// The `generation` extension.
    pub fn generation(&self) -> Option<u32> {
        self.generation
    }

    /// The `tcptype` of a TCP candidate; `None` for UDP.
    pub fn tcp_type(&self) -> Option<TcpType> {
        self.tcp
    }

    /// Whether candidates `self` (local) and `remote` can form a pair: same IP family and
    /// transport, and for TCP compatible types.
    pub(crate) fn pairs_with(&self, remote: &Candidate) -> bool {
        self.send_addr().is_ipv4() == remote.addr().is_ipv4()
            && match (self.tcp, remote.tcp) {
                (None, None) => true,
                (Some(l), Some(r)) => l.pairs_with(r),
                _ => false,
            }
    }

    /// The address the agent sends from for this local candidate: the base, except for a
    /// relayed candidate (the relayed address).
    pub(crate) fn send_addr(&self) -> SocketAddr {
        if self.kind == CandidateKind::Relayed {
            self.addr
        } else {
            self.base
        }
    }

    /// The local preference part of the priority.
    pub(crate) fn local_pref(&self) -> u32 {
        (self.priority >> 8) & 0xffff
    }

    /// A remote peer-reflexive candidate learned from a check that arrived over `tcp` (the
    /// type of the remote end of that connection), or over UDP.
    pub(crate) fn remote_prflx(addr: SocketAddr, priority: u32, tcp: Option<TcpType>) -> Candidate {
        let mut c = Candidate::local(CandidateKind::PeerReflexive, addr, addr, Some(priority));
        c.related = None;
        c.tcp = tcp;
        if tcp.is_some() {
            c.foundation = foundation(c.kind, &addr, true);
        }
        c
    }

    /// The SDP attribute value (without `a=`):
    /// `candidate:<foundation> <component> udp|tcp <priority> <ip> <port> typ <type>[ raddr
    /// <ip> rport <port>][ tcptype <type>]`. An active TCP candidate's port is 9 (RFC 6544
    /// §4.5).
    pub fn to_sdp(&self) -> String {
        let port = match self.tcp {
            Some(TcpType::Active) => 9,
            _ => self.addr.port(),
        };
        let mut s = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            if self.tcp.is_some() { "tcp" } else { "udp" },
            self.priority,
            self.addr.ip(),
            port,
            self.kind.as_str()
        );
        if let Some(r) = self.related {
            s.push_str(&format!(" raddr {} rport {}", r.ip(), r.port()));
        }
        if let Some(t) = self.tcp {
            s.push_str(" tcptype ");
            s.push_str(t.as_str());
        }
        s
    }

    /// Parses an SDP `candidate` attribute (`candidate:...`, with or without a leading `a=`),
    /// RFC 8839 §5.1 plus the `generation`, `ufrag`, `network-id` and `network-cost`
    /// extensions (other extension pairs are ignored).
    pub fn parse(s: &str) -> Result<Candidate, ParseError> {
        let s = s.trim();
        let s = s.strip_prefix("a=").unwrap_or(s);
        let rest = s
            .strip_prefix("candidate:")
            .ok_or(ParseError::Syntax("missing \"candidate:\""))?;
        let mut it = rest.split_ascii_whitespace();
        let mut next = |what: &'static str| it.next().ok_or(ParseError::Syntax(what));
        let foundation = next("missing foundation")?;
        if foundation.is_empty()
            || foundation.len() > 32
            || !foundation.bytes().all(|b| ICE_CHARS.contains(&b))
        {
            return Err(ParseError::Syntax("bad foundation"));
        }
        let component = next("missing component")?;
        if component.len() > 5 {
            return Err(ParseError::Syntax("bad component"));
        }
        let component: u16 = component
            .parse()
            .map_err(|_| ParseError::Syntax("bad component"))?;
        if component == 0 {
            return Err(ParseError::Syntax("bad component"));
        }
        let transport = next("missing transport")?;
        let tcp = if transport.eq_ignore_ascii_case("udp") {
            false
        } else if transport.eq_ignore_ascii_case("tcp") {
            true
        } else {
            return Err(ParseError::Syntax("unknown transport"));
        };
        let priority: u32 = next("missing priority")?
            .parse()
            .map_err(|_| ParseError::Syntax("bad priority"))?;
        let host = next("missing address")?;
        let port: u16 = next("missing port")?
            .parse()
            .map_err(|_| ParseError::Syntax("bad port"))?;
        if next("missing typ")? != "typ" {
            return Err(ParseError::Syntax("missing typ"));
        }
        let kind = match next("missing type")? {
            "host" => CandidateKind::Host,
            "srflx" => CandidateKind::ServerReflexive,
            "prflx" => CandidateKind::PeerReflexive,
            "relay" => CandidateKind::Relayed,
            _ => return Err(ParseError::Syntax("unknown candidate type")),
        };
        let mut raddr: Option<IpAddr> = None;
        let mut rport: Option<u16> = None;
        let mut ufrag = None;
        let mut generation = None;
        let mut tcptype = None;
        while let Some(name) = it.next() {
            let value = it
                .next()
                .ok_or(ParseError::Syntax("extension without value"))?;
            match name {
                "raddr" => {
                    // Browsers may hide it ("0.0.0.0", or an mDNS name): ignore what is not an IP.
                    raddr = value.parse().ok();
                }
                "rport" => {
                    rport = Some(value.parse().map_err(|_| ParseError::Syntax("bad rport"))?);
                }
                "generation" => {
                    generation = Some(
                        value
                            .parse()
                            .map_err(|_| ParseError::Syntax("bad generation"))?,
                    );
                }
                "ufrag" => ufrag = Some(value.to_owned()),
                "tcptype" => {
                    tcptype = Some(match value {
                        "active" => TcpType::Active,
                        "passive" => TcpType::Passive,
                        "so" => TcpType::So,
                        _ => return Err(ParseError::Syntax("bad tcptype")),
                    });
                }
                "network-id" | "network-cost" => {
                    let _: u32 = value
                        .parse()
                        .map_err(|_| ParseError::Syntax("bad network extension"))?;
                }
                _ => {}
            }
        }
        if tcp && tcptype.is_none() {
            return Err(ParseError::Syntax("tcp candidate without tcptype"));
        }
        let ip: IpAddr = match host.parse() {
            Ok(ip) => ip,
            Err(_) => return Err(host_error(host)),
        };
        let addr = SocketAddr::new(ip, port);
        Ok(Candidate {
            foundation: foundation.to_owned(),
            component,
            priority,
            addr,
            kind,
            base: addr,
            related: raddr.map(|ip| SocketAddr::new(ip, rport.unwrap_or(0))),
            ufrag,
            generation,
            tcp: if tcp { tcptype } else { None },
        })
    }
}

fn host_error(host: &str) -> ParseError {
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        ParseError::Syntax("bad address")
    } else if host.to_ascii_lowercase().ends_with(".local") {
        ParseError::Mdns
    } else {
        ParseError::Fqdn
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_sdp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn credentials_random() {
        let c = Credentials::random();
        assert!(c.ufrag.len() >= 4 && c.pwd.len() >= 22);
        assert!(
            c.ufrag
                .bytes()
                .chain(c.pwd.bytes())
                .all(|b| ICE_CHARS.contains(&b))
        );
        assert_ne!(Credentials::random(), c);
        assert!(!format!("{c:?}").contains(&c.pwd));
    }

    #[test]
    fn priorities() {
        let h = Candidate::host(a("192.168.1.2:5000"));
        assert_eq!(h.priority(), (126 << 24) | (32767 << 8) | 255);
        let s = Candidate::server_reflexive(a("1.2.3.4:6000"), a("192.168.1.2:5000"));
        assert_eq!(s.priority() >> 24, 100);
        let r = Candidate::relayed(a("5.6.7.8:7000"), a("192.168.1.2:5000"));
        assert_eq!(r.priority() >> 24, 0);
        let p = Candidate::peer_reflexive(a("1.2.3.4:6001"), a("192.168.1.2:5000"), 77);
        assert_eq!(p.priority(), 77);
        let v6 = Candidate::host(a("[2001:db8::1]:5000"));
        assert!(v6.priority() > h.priority());
        assert_ne!(h.foundation(), s.foundation());
        assert_eq!(
            h.foundation(),
            Candidate::host(a("192.168.1.2:5001")).foundation()
        );
        assert_eq!(r.send_addr(), a("5.6.7.8:7000"));
        assert_eq!(s.send_addr(), a("192.168.1.2:5000"));
    }

    #[test]
    fn tcp_candidates() {
        let p = Candidate::host_tcp(a("192.168.1.2:5001"), TcpType::Passive);
        let u = Candidate::host(a("192.168.1.2:5000"));
        // Below every UDP host candidate, above UDP server-reflexive ones.
        assert!(p.priority() < u.priority());
        assert_eq!(p.priority() >> 24, 90);
        assert_eq!((p.priority() >> 8) & 0xffff, (4 << 13) + 4095);
        assert_ne!(p.foundation(), u.foundation());
        let s = p.to_sdp();
        assert!(
            s.contains(" tcp ") && s.ends_with(" typ host tcptype passive"),
            "{s}"
        );
        let back = Candidate::parse(&s).unwrap();
        assert_eq!(back.tcp_type(), Some(TcpType::Passive));
        assert_eq!((back.addr(), back.priority()), (p.addr(), p.priority()));
        let act = Candidate::host_tcp(a("192.168.1.2:40000"), TcpType::Active);
        assert!(
            act.to_sdp()
                .contains(" 192.168.1.2 9 typ host tcptype active")
        );
        // Pairing: passive with active only, never across transports.
        let ra =
            Candidate::parse("candidate:1 1 tcp 1 10.0.0.9 9 typ host tcptype active").unwrap();
        let rp =
            Candidate::parse("candidate:1 1 tcp 1 10.0.0.9 7 typ host tcptype passive").unwrap();
        let ru = Candidate::parse("candidate:1 1 udp 1 10.0.0.9 7 typ host").unwrap();
        assert!(p.pairs_with(&ra));
        assert!(!p.pairs_with(&rp) && !p.pairs_with(&ru) && !u.pairs_with(&ra));
        assert!(u.pairs_with(&ru));
        assert!(TcpType::So.pairs_with(TcpType::So));
    }

    #[test]
    fn sdp_round_trip() {
        for c in [
            Candidate::host(a("192.168.1.2:5000")),
            Candidate::host(a("[2001:db8::1]:5000")),
            Candidate::server_reflexive(a("1.2.3.4:6000"), a("192.168.1.2:5000")),
            Candidate::relayed(a("5.6.7.8:7000"), a("192.168.1.2:5000")),
        ] {
            let s = c.to_sdp();
            assert!(s.starts_with("candidate:"));
            let p = Candidate::parse(&s).unwrap();
            assert_eq!(p.addr(), c.addr());
            assert_eq!(p.kind(), c.kind());
            assert_eq!(p.priority(), c.priority());
            assert_eq!(p.foundation(), c.foundation());
            assert_eq!(p.related(), c.related());
            assert_eq!(p.to_sdp(), s);
            assert_eq!(Candidate::parse(&format!("a={s}")).unwrap(), p);
        }
        assert_eq!(
            Candidate::host(a("10.0.0.1:9")).to_sdp(),
            format!(
                "candidate:{} 1 udp 2122317823 10.0.0.1 9 typ host",
                Candidate::host(a("10.0.0.1:9")).foundation()
            )
        );
    }

    #[test]
    fn parse_browser_lines() {
        let c = Candidate::parse(
            "candidate:842163049 1 udp 1677729535 203.0.113.7 61665 typ srflx raddr 0.0.0.0 \
             rport 0 generation 0 ufrag EsAw network-id 1 network-cost 10",
        )
        .unwrap();
        assert_eq!(c.kind(), CandidateKind::ServerReflexive);
        assert_eq!(c.addr(), a("203.0.113.7:61665"));
        assert_eq!(c.ufrag(), Some("EsAw"));
        assert_eq!(c.generation(), Some(0));
        assert_eq!(c.related(), Some(a("0.0.0.0:0")));
        let c = Candidate::parse("a=candidate:1 1 UDP 2122260223 [::1] 5000 typ host");
        assert!(c.is_err()); // brackets are not SDP syntax
        let c = Candidate::parse("a=candidate:1 1 UDP 2122260223 ::1 5000 typ host").unwrap();
        assert_eq!(c.addr(), a("[::1]:5000"));
        let c = Candidate::parse(
            "candidate:3 1 udp 2122260223 1.2.3.4 5 typ relay raddr x.local rport 9",
        )
        .unwrap();
        assert_eq!(c.related(), None);
    }

    #[test]
    fn parse_unsupported_and_errors() {
        assert_eq!(
            Candidate::parse("candidate:1 1 udp 2122260223 4c1f-ab.local 5000 typ host"),
            Err(ParseError::Mdns)
        );
        assert_eq!(
            Candidate::parse("candidate:1 1 udp 2122260223 example.com 5000 typ host"),
            Err(ParseError::Fqdn)
        );
        let t = Candidate::parse(
            "candidate:1 1 tcp 1518280447 192.168.1.2 9 typ host tcptype active generation 0",
        )
        .unwrap();
        assert_eq!(t.tcp_type(), Some(TcpType::Active));
        assert_eq!(t.addr(), a("192.168.1.2:9"));
        assert!(matches!(
            Candidate::parse("candidate:1 1 tcp 1518280447 192.168.1.2 9 typ host"),
            Err(ParseError::Syntax(_))
        ));
        assert!(matches!(
            Candidate::parse("candidate:1 1 tcp 1 1.2.3.4 9 typ host tcptype both"),
            Err(ParseError::Syntax(_))
        ));
        assert!(ParseError::Mdns.is_unsupported());
        assert!(!ParseError::Syntax("x").is_unsupported());
        for bad in [
            "nonsense",
            "",
            "candidate:",
            "candidate:1 1 udp 1 1.2.3.4 5 typ",
            "candidate:1 1 udp 1 1.2.3.4 5 typ weird",
            "candidate:1 1 udp 1 1.2.3.4 99999 typ host",
            "candidate:1 1 udp x 1.2.3.4 5 typ host",
            "candidate:1 0 udp 1 1.2.3.4 5 typ host",
            "candidate:1 1 sctp 1 1.2.3.4 5 typ host",
            "candidate:1 1 udp 1 1.2.3.4 5 type host",
            "candidate:1 1 udp 1 1.2.3.4 5 typ host generation",
            "candidate:1 1 udp 1 1.2.3.4 5 typ host rport x",
            "candidate:! 1 udp 1 1.2.3.4 5 typ host",
            "candidate:1 1 udp 1 bad..name 5 typ host",
        ] {
            assert!(
                matches!(Candidate::parse(bad), Err(ParseError::Syntax(_))),
                "{bad}"
            );
        }
    }
}
