//! A minimal TLS ClientHello reader: the server name and ALPN list, for routing a TLS connection
//! without terminating it ([`Rule::TlsSni`](crate::Rule::TlsSni),
//! [`Rule::TlsHello`](crate::Rule::TlsHello); ADR-095).
//!
//! The hello may arrive in several reads and span several TLS records; the parser takes the
//! bytes seen so far and says whether they hold a whole, well-formed ClientHello.
//!
//! ```
//! use akio_mux::tls::{parse_client_hello, HelloError};
//! assert_eq!(parse_client_hello(&[0x16, 0x03]).unwrap_err(), HelloError::Incomplete);
//! assert_eq!(parse_client_hello(b"GET / HTTP/1.1").unwrap_err(), HelloError::Invalid);
//! ```

use std::{borrow::Cow, collections::HashSet, sync::Arc};

/// The default `Mux::max_sniff_bytes` of a mux with a [`Rule::TlsSni`](crate::Rule::TlsSni) or
/// [`Rule::TlsHello`](crate::Rule::TlsHello) route: one full-size record and its header.
pub const TLS_SNIFF_BYTES: usize = MAX_RECORD + 5;

/// The largest plaintext record (RFC 8446 section 5.1).
const MAX_RECORD: usize = 1 << 14;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
/// version (2) + random (32) + session id length (1) + suites length (2) + one suite (2) +
/// compression length (1) + one method (1).
const MIN_HELLO_BODY: usize = 41;

/// Why the bytes are not a ClientHello (yet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HelloError {
    /// A well-formed prefix: more bytes are needed.
    Incomplete,
    /// Not a TLS ClientHello, or a malformed one. More bytes do not change this.
    Invalid,
}

/// A parsed ClientHello: what routing needs, borrowed from the bytes read when the hello came
/// in one record.
#[derive(Clone, Debug)]
pub struct ClientHello<'a> {
    /// The handshake message (type, length, body).
    msg: Cow<'a, [u8]>,
    version: u16,
    sni: Option<(usize, usize)>,
    alpn: Option<(usize, usize)>,
    /// Bytes of the input the hello took, records included.
    consumed: usize,
}

impl<'a> ClientHello<'a> {
    /// The `server_name` extension's host name, as sent (ASCII; compare without case).
    pub fn server_name(&self) -> Option<&str> {
        let (a, b) = self.sni?;
        std::str::from_utf8(&self.msg[a..b]).ok()
    }

    /// The protocols of the ALPN extension, in the client's order (none without it).
    pub fn alpn(&self) -> Alpn<'_> {
        Alpn {
            rest: self.alpn.map_or(&[][..], |(a, b)| &self.msg[a..b]),
        }
    }

    /// Whether the ALPN extension offers `proto`.
    pub fn offers_alpn(&self, proto: &[u8]) -> bool {
        self.alpn().any(|p| p == proto)
    }

    /// `legacy_version` (0x0303 for TLS 1.2 and 1.3 clients).
    pub fn legacy_version(&self) -> u16 {
        self.version
    }

    /// How many bytes of the input the hello took: its records' headers and the message.
    pub fn consumed(&self) -> usize {
        self.consumed
    }
}

/// The protocols of an ALPN extension ([`ClientHello::alpn`]).
#[derive(Clone, Debug)]
pub struct Alpn<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Alpn<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let (&n, rest) = self.rest.split_first()?;
        let (p, rest) = rest.split_at(usize::from(n).min(rest.len()));
        self.rest = rest;
        Some(p)
    }
}

/// Reads a ClientHello from the first bytes of a connection: TLS records of the handshake type
/// carrying one ClientHello message, split across records in any way.
///
/// Prefix-consistent: a prefix of a valid hello is [`HelloError::Incomplete`], never `Ok`, and
/// input found [`HelloError::Invalid`] stays invalid however many bytes follow.
pub fn parse_client_hello(b: &[u8]) -> Result<ClientHello<'_>, HelloError> {
    // Pass 1: walk the record headers until the handshake message is complete. Allocates
    // nothing, so a hello still arriving costs one walk per read.
    let mut pos = 0;
    let mut hdr = [0u8; 4];
    let mut nhdr = 0;
    let mut have = 0; // handshake bytes seen
    let mut need = usize::MAX; // handshake bytes of the whole message, once known
    let mut records = 0;
    loop {
        let avail = &b[pos..];
        if avail.is_empty() {
            return Err(HelloError::Incomplete);
        }
        if avail[0] != CONTENT_HANDSHAKE || avail.get(1).is_some_and(|&v| v != 3) {
            return Err(HelloError::Invalid);
        }
        if avail.len() < 5 {
            return Err(HelloError::Incomplete);
        }
        let rlen = usize::from(u16::from_be_bytes([avail[3], avail[4]]));
        if rlen == 0 || rlen > MAX_RECORD {
            return Err(HelloError::Invalid);
        }
        let payload = &avail[5..avail.len().min(5 + rlen)];
        for &x in payload.iter().take(4 - nhdr) {
            hdr[nhdr] = x;
            nhdr += 1;
            if nhdr == 1 && x != HANDSHAKE_CLIENT_HELLO {
                return Err(HelloError::Invalid);
            }
        }
        if nhdr == 4 && need == usize::MAX {
            let mlen =
                (usize::from(hdr[1]) << 16) | (usize::from(hdr[2]) << 8) | usize::from(hdr[3]);
            if mlen < MIN_HELLO_BODY {
                return Err(HelloError::Invalid);
            }
            need = 4 + mlen;
        }
        have += payload.len();
        records += 1;
        if have >= need {
            // Bytes after the hello in its last record (none from a real client) are ignored.
            let end = pos + 5 + payload.len() - (have - need);
            return parse_message(b, records, need, end);
        }
        if payload.len() < rlen {
            return Err(HelloError::Incomplete);
        }
        pos += 5 + rlen;
    }
}

/// Pass 2: gathers the message from its `records` and parses it.
fn parse_message(
    b: &[u8],
    records: usize,
    need: usize,
    consumed: usize,
) -> Result<ClientHello<'_>, HelloError> {
    let msg: Cow<'_, [u8]> = if records == 1 {
        Cow::Borrowed(&b[5..5 + need])
    } else {
        let mut v = Vec::with_capacity(need);
        let mut pos = 0;
        while v.len() < need {
            let rlen = usize::from(u16::from_be_bytes([b[pos + 3], b[pos + 4]]));
            let take = rlen.min(need - v.len());
            v.extend_from_slice(&b[pos + 5..pos + 5 + take]);
            pos += 5 + rlen;
        }
        Cow::Owned(v)
    };
    let (version, sni, alpn) = parse_body(&msg).ok_or(HelloError::Invalid)?;
    Ok(ClientHello {
        msg,
        version,
        sni,
        alpn,
        consumed,
    })
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<(usize, &'a [u8])> {
        let start = self.pos;
        let s = self.b.get(start..start.checked_add(n)?)?;
        self.pos += n;
        Some((start, s))
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?.1[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let (_, s) = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn vec8(&mut self) -> Option<(usize, &'a [u8])> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }
    fn vec16(&mut self) -> Option<(usize, &'a [u8])> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
    fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

type Range = Option<(usize, usize)>;

/// The ClientHello body (offsets are into `msg`, which starts with the 4-byte header).
fn parse_body(msg: &[u8]) -> Option<(u16, Range, Range)> {
    let mut r = Reader { b: msg, pos: 4 };
    let version = r.u16()?;
    r.take(32)?; // random
    let (_, sid) = r.vec8()?;
    if sid.len() > 32 {
        return None;
    }
    let (_, suites) = r.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    let (_, comp) = r.vec8()?;
    if comp.is_empty() {
        return None;
    }
    let (mut sni, mut alpn) = (None, None);
    if r.done() {
        return Some((version, sni, alpn)); // no extensions (SSL 3.0-era clients)
    }
    let (base, exts) = r.vec16()?;
    if !r.done() {
        return None;
    }
    let mut e = Reader { b: exts, pos: 0 };
    let mut seen = [0u64; 1024]; // one bit per extension type
    while !e.done() {
        let ty = e.u16()?;
        let (off, data) = e.vec16()?;
        let (w, bit) = (usize::from(ty / 64), 1u64 << (ty % 64));
        if seen[w] & bit != 0 {
            return None; // RFC 8446 section 4.2: at most one of each
        }
        seen[w] |= bit;
        let at = base + off;
        match ty {
            EXT_SERVER_NAME => sni = server_name(data, at)?,
            EXT_ALPN => alpn = Some(alpn_list(data, at)?),
            _ => {}
        }
    }
    Some((version, sni, alpn))
}

/// The `server_name` extension (RFC 6066 section 3); `at`: its offset in the message. An
/// extension without a host name entry yields `Some(None)`.
fn server_name(data: &[u8], at: usize) -> Option<Range> {
    let mut r = Reader { b: data, pos: 0 };
    let (_, list) = r.vec16()?;
    if !r.done() || list.is_empty() {
        return None;
    }
    let mut l = Reader { b: list, pos: 0 };
    let mut found = None;
    while !l.done() {
        let ty = l.u8()?;
        let (off, name) = l.vec16()?;
        if ty != 0 {
            continue; // unknown name types are skipped
        }
        if found.is_some() || !valid_host_name(name) {
            return None;
        }
        let start = at + 2 + off;
        found = Some((start, start + name.len()));
    }
    Some(found)
}

/// Letters, digits, `-`, `_` and `.`, 1..=255 bytes, no empty label but an optional final dot.
fn valid_host_name(n: &[u8]) -> bool {
    if n.is_empty() || n.len() > 255 {
        return false;
    }
    let n = n.strip_suffix(b".").unwrap_or(n);
    !n.is_empty()
        && n.split(|&c| c == b'.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.iter()
                    .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}

/// The ALPN extension (RFC 7301 section 3.1): a non-empty list of non-empty names.
fn alpn_list(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut r = Reader { b: data, pos: 0 };
    let (off, list) = r.vec16()?;
    if !r.done() || list.is_empty() {
        return None;
    }
    let mut l = Reader { b: list, pos: 0 };
    while !l.done() {
        if l.vec8()?.1.is_empty() {
            return None;
        }
    }
    Some((at + off, at + off + list.len()))
}

/// Server names to match a ClientHello against: exact names and `*.` wildcards of one label,
/// as in certificates. Case and a trailing dot do not matter.
///
/// ```
/// use akio_mux::tls::SniMatcher;
/// let m = SniMatcher::new(["example.com", "*.example.org"]);
/// assert!(m.matches("Example.COM."));
/// assert!(m.matches("a.example.org"));
/// assert!(!m.matches("example.org"));
/// assert!(!m.matches("a.b.example.org"));
/// ```
#[derive(Clone, Debug, Default)]
pub struct SniMatcher(Arc<Names>);

/// Behind an `Arc` so that [`Rule`](crate::Rule) stays small: routes are scanned for every
/// connection.
#[derive(Clone, Debug, Default)]
struct Names {
    exact: HashSet<String>,
    /// What follows `*.`.
    wildcard: HashSet<String>,
}

fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

impl SniMatcher {
    /// Matches these names (`*.example.org` for any one label under `example.org`).
    pub fn new<I, S>(names: I) -> SniMatcher
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        names
            .into_iter()
            .fold(SniMatcher::default(), |m, n| m.with_name(n))
    }

    /// Also matches `name`.
    #[must_use]
    pub fn with_name(mut self, name: impl AsRef<str>) -> SniMatcher {
        let n = normalize(name.as_ref());
        let names = Arc::make_mut(&mut self.0);
        match n.strip_prefix("*.") {
            Some(suffix) if !suffix.is_empty() => {
                names.wildcard.insert(suffix.to_owned());
            }
            _ => {
                names.exact.insert(n);
            }
        }
        self
    }

    /// Whether `name` (a server name as sent) matches.
    pub fn matches(&self, name: &str) -> bool {
        let n = normalize(name);
        if self.0.exact.contains(&n) {
            return true;
        }
        match n.split_once('.') {
            Some((label, suffix)) if !label.is_empty() => self.0.wildcard.contains(suffix),
            _ => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello message (handshake header included) with these extensions.
    pub(crate) fn hello_msg(sni: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(n) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(n.len() as u16).to_be_bytes());
            entry.extend_from_slice(n.as_bytes());
            exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            exts.extend_from_slice(&entry);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for p in alpn {
                list.push(p.len() as u8);
                list.extend_from_slice(p);
            }
            exts.extend_from_slice(&EXT_ALPN.to_be_bytes());
            exts.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        // A padding-like unknown extension.
        exts.extend_from_slice(&[0x00, 0x15, 0x00, 0x03, 0, 0, 0]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![1];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// `msg` in records of at most `rec` bytes.
    pub(crate) fn records(msg: &[u8], rec: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for c in msg.chunks(rec) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(c.len() as u16).to_be_bytes());
            out.extend_from_slice(c);
        }
        out
    }

    #[test]
    fn one_record() {
        let w = records(
            &hello_msg(Some("api.example.com"), &[b"h2", b"http/1.1"]),
            1 << 14,
        );
        let h = parse_client_hello(&w).unwrap();
        assert_eq!(h.server_name(), Some("api.example.com"));
        assert_eq!(h.alpn().collect::<Vec<_>>(), [&b"h2"[..], b"http/1.1"]);
        assert!(h.offers_alpn(b"h2"));
        assert_eq!(h.legacy_version(), 0x0303);
        assert_eq!(h.consumed(), w.len());
        assert!(matches!(h.msg, Cow::Borrowed(_)));
        for n in 1..w.len() {
            assert_eq!(
                parse_client_hello(&w[..n]).unwrap_err(),
                HelloError::Incomplete,
                "{n}"
            );
        }
    }

    #[test]
    fn split_across_records() {
        let msg = hello_msg(Some("b.example"), &[b"h2"]);
        for rec in [1, 2, 3, 4, 5, 17, 100] {
            let w = records(&msg, rec);
            let h = parse_client_hello(&w).unwrap();
            assert_eq!(h.server_name(), Some("b.example"), "{rec}");
            assert!(h.offers_alpn(b"h2"));
            assert_eq!(h.consumed(), w.len());
            for n in 1..w.len() {
                assert_eq!(
                    parse_client_hello(&w[..n]).unwrap_err(),
                    HelloError::Incomplete
                );
            }
        }
    }

    #[test]
    fn no_sni_no_alpn() {
        let w = records(&hello_msg(None, &[]), 1 << 14);
        let h = parse_client_hello(&w).unwrap();
        assert_eq!(h.server_name(), None);
        assert_eq!(h.alpn().count(), 0);
    }

    #[test]
    fn malformed() {
        let good = records(&hello_msg(Some("x.example"), &[b"h2"]), 1 << 14);
        let bad = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut w = good.clone();
            f(&mut w);
            parse_client_hello(&w).unwrap_err()
        };
        // Not a handshake record, wrong major version, empty and oversized records.
        assert_eq!(bad(&|w| w[0] = 0x17), HelloError::Invalid);
        assert_eq!(bad(&|w| w[1] = 2), HelloError::Invalid);
        assert_eq!(
            bad(&|w| w[3..5].copy_from_slice(&[0, 0])),
            HelloError::Invalid
        );
        assert_eq!(
            bad(&|w| w[3..5].copy_from_slice(&[0x40, 1])),
            HelloError::Invalid
        );
        // A ServerHello, a message too short to be a hello.
        assert_eq!(bad(&|w| w[5] = 2), HelloError::Invalid);
        assert_eq!(
            bad(&|w| w[6..9].copy_from_slice(&[0, 0, 5])),
            HelloError::Invalid
        );
        // A forged extensions length past the message.
        let ext_len_at = 5 + 4 + 2 + 32 + 33 + 6 + 2;
        assert_eq!(bad(&|w| w[ext_len_at] = 0xff), HelloError::Invalid);
        // A bad character in the server name.
        assert_eq!(
            parse_client_hello(&records(&hello_msg(Some("a b.example"), &[]), 1 << 14))
                .unwrap_err(),
            HelloError::Invalid
        );
        assert_eq!(
            parse_client_hello(&records(&hello_msg(Some("a..example"), &[]), 1 << 14)).unwrap_err(),
            HelloError::Invalid
        );
        // A record of another type between two parts of the hello.
        let msg = hello_msg(Some("x.example"), &[]);
        let mut w = records(&msg[..10], 10);
        w.extend_from_slice(&[0x15, 3, 3, 0, 2, 2, 40]);
        w.extend_from_slice(&records(&msg[10..], 1 << 14));
        assert_eq!(parse_client_hello(&w).unwrap_err(), HelloError::Invalid);
        // A duplicated extension.
        let mut m = hello_msg(Some("x.example"), &[]);
        let dup = [0x00, 0x15, 0x00, 0x03, 0, 0, 0];
        m.extend_from_slice(&dup);
        let el = 4 + 2 + 32 + 33 + 6 + 2;
        let n = u16::from_be_bytes([m[el], m[el + 1]]) + 7;
        m[el..el + 2].copy_from_slice(&n.to_be_bytes());
        let ml = (m.len() - 4) as u32;
        m[1..4].copy_from_slice(&ml.to_be_bytes()[1..]);
        assert_eq!(
            parse_client_hello(&records(&m, 1 << 14)).unwrap_err(),
            HelloError::Invalid
        );
    }

    #[test]
    fn wildcards() {
        let m = SniMatcher::new(["a.example", "*.wild.example", "*."]);
        assert!(m.matches("a.example"));
        assert!(m.matches("A.EXAMPLE."));
        assert!(!m.matches("b.a.example"));
        assert!(m.matches("x.wild.example"));
        assert!(!m.matches("wild.example"));
        assert!(!m.matches("y.x.wild.example"));
        assert!(!m.matches(".wild.example"));
        assert!(!m.matches(""));
    }
}
