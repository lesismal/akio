//! STUN messages (RFC 8489): parsing, building, `MESSAGE-INTEGRITY` (HMAC-SHA1) and
//! `FINGERPRINT` (CRC-32), plus the TURN attributes (RFC 8656) and the ICE ones (RFC 8445).
//!
//! [`Message::parse`] borrows the datagram and indexes its attributes without copying;
//! [`MessageBuilder`] writes a message attribute by attribute, keeping the header length right
//! so that integrity and fingerprint can be appended last.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use only_crypto::crc::Crc32;
use only_crypto::hash::{Md5, Sha1};
use only_crypto::mac::Hmac;

/// The magic cookie of every RFC 5389+ message.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Length of the fixed STUN header.
pub const HEADER_LEN: usize = 20;
/// XOR mask applied to the CRC-32 of a `FINGERPRINT`.
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// A STUN method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Method(pub u16);

impl Method {
    /// Binding (RFC 8489).
    pub const BINDING: Method = Method(0x001);
    /// Allocate (TURN).
    pub const ALLOCATE: Method = Method(0x003);
    /// Refresh (TURN).
    pub const REFRESH: Method = Method(0x004);
    /// Send (TURN, indication).
    pub const SEND: Method = Method(0x006);
    /// Data (TURN, indication).
    pub const DATA: Method = Method(0x007);
    /// CreatePermission (TURN).
    pub const CREATE_PERMISSION: Method = Method(0x008);
    /// ChannelBind (TURN).
    pub const CHANNEL_BIND: Method = Method(0x009);
    /// Connect (TURN TCP relays, RFC 6062).
    pub const CONNECT: Method = Method(0x00a);
    /// ConnectionBind (TURN TCP relays, RFC 6062).
    pub const CONNECTION_BIND: Method = Method(0x00b);
    /// ConnectionAttempt (TURN TCP relays, RFC 6062, indication).
    pub const CONNECTION_ATTEMPT: Method = Method(0x00c);
}

/// The class of a STUN message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// A request, answered by a success or error response.
    Request,
    /// An indication: no response.
    Indication,
    /// A success response.
    Success,
    /// An error response.
    Error,
}

impl Class {
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0b00,
            Class::Indication => 0b01,
            Class::Success => 0b10,
            Class::Error => 0b11,
        }
    }
}

fn type_value(m: Method, c: Class) -> u16 {
    let m = m.0 & 0x0fff;
    let c = c.bits();
    (m & 0x000f) | ((c & 1) << 4) | ((m & 0x0070) << 1) | ((c & 2) << 7) | ((m & 0x0f80) << 2)
}

fn split_type(v: u16) -> (Method, Class) {
    let m = (v & 0x000f) | ((v >> 1) & 0x0070) | ((v >> 2) & 0x0f80);
    let class = match ((v >> 4) & 1) | ((v >> 7) & 2) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    };
    (Method(m), class)
}

/// Attribute types.
pub mod attr {
    /// MAPPED-ADDRESS.
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    /// USERNAME.
    pub const USERNAME: u16 = 0x0006;
    /// MESSAGE-INTEGRITY (HMAC-SHA1).
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    /// ERROR-CODE.
    pub const ERROR_CODE: u16 = 0x0009;
    /// UNKNOWN-ATTRIBUTES.
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    /// CHANNEL-NUMBER (TURN).
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    /// LIFETIME (TURN).
    pub const LIFETIME: u16 = 0x000D;
    /// XOR-PEER-ADDRESS (TURN).
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    /// DATA (TURN).
    pub const DATA: u16 = 0x0013;
    /// REALM.
    pub const REALM: u16 = 0x0014;
    /// NONCE.
    pub const NONCE: u16 = 0x0015;
    /// XOR-RELAYED-ADDRESS (TURN).
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    /// REQUESTED-ADDRESS-FAMILY (TURN).
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    /// EVEN-PORT (TURN).
    pub const EVEN_PORT: u16 = 0x0018;
    /// REQUESTED-TRANSPORT (TURN).
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    /// DONT-FRAGMENT (TURN).
    pub const DONT_FRAGMENT: u16 = 0x001A;
    /// MESSAGE-INTEGRITY-SHA256.
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    /// USERHASH.
    pub const USERHASH: u16 = 0x001E;
    /// XOR-MAPPED-ADDRESS.
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    /// RESERVATION-TOKEN (TURN).
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    /// PRIORITY (ICE).
    pub const PRIORITY: u16 = 0x0024;
    /// USE-CANDIDATE (ICE).
    pub const USE_CANDIDATE: u16 = 0x0025;
    /// CONNECTION-ID (TURN TCP relays, RFC 6062): a 32-bit connection identifier.
    pub const CONNECTION_ID: u16 = 0x002A;
    /// ADDITIONAL-ADDRESS-FAMILY (TURN).
    pub const ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
    /// ADDRESS-ERROR-CODE (TURN): why one family of a dual allocation was not allocated.
    pub const ADDRESS_ERROR_CODE: u16 = 0x8001;
    /// `ADDITIONAL-ADDRESS-FAMILY` as draft-ietf-tram-turnbis numbered it, which coturn 4.6
    /// still sends and understands (unassigned by IANA): accepted as an alias (ADR-083).
    pub(crate) const ADDITIONAL_ADDRESS_FAMILY_DRAFT: u16 = 0x8032;
    /// `ADDRESS-ERROR-CODE` as the same draft numbered it.
    pub(crate) const ADDRESS_ERROR_CODE_DRAFT: u16 = 0x8033;
    /// PASSWORD-ALGORITHMS.
    pub const PASSWORD_ALGORITHMS: u16 = 0x8002;
    /// SOFTWARE.
    pub const SOFTWARE: u16 = 0x8022;
    /// ALTERNATE-SERVER.
    pub const ALTERNATE_SERVER: u16 = 0x8023;
    /// FINGERPRINT.
    pub const FINGERPRINT: u16 = 0x8028;
    /// ICE-CONTROLLED (ICE).
    pub const ICE_CONTROLLED: u16 = 0x8029;
    /// ICE-CONTROLLING (ICE).
    pub const ICE_CONTROLLING: u16 = 0x802A;
    /// RESPONSE-ORIGIN.
    pub const RESPONSE_ORIGIN: u16 = 0x802B;
}

/// Why a datagram is not a well-formed STUN message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StunError {
    /// Shorter than its header or declared length, or the length is not a multiple of 4.
    Truncated,
    /// The two top bits are not zero or the magic cookie is wrong.
    NotStun,
    /// An attribute runs past the end of the message.
    BadAttribute,
    /// Attributes follow `FINGERPRINT`, or something other than `FINGERPRINT` follows
    /// `MESSAGE-INTEGRITY`.
    Misplaced,
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StunError::Truncated => "stun: truncated message",
            StunError::NotStun => "stun: not a STUN message",
            StunError::BadAttribute => "stun: malformed attribute",
            StunError::Misplaced => "stun: attribute after integrity or fingerprint",
        })
    }
}

impl std::error::Error for StunError {}

/// Whether `data` looks like a STUN message (top bits clear, magic cookie present): the RFC 7983
/// demultiplexing test. It does not validate the attributes.
pub fn is_stun(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN
        && data[0] < 4
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == MAGIC_COOKIE
}

/// Whether `data` is a TURN ChannelData message (first byte 0x40..=0x4F, RFC 8656; this
/// accepts the RFC 5766 range up to 0x7F).
pub fn is_channel_data(data: &[u8]) -> bool {
    data.len() >= 4 && (0x40..=0x7f).contains(&data[0])
}

/// A fresh random transaction id.
pub fn transaction_id() -> [u8; 12] {
    let mut t = [0u8; 12];
    crate::fill_random(&mut t);
    t
}

/// A parsed STUN message borrowing its datagram.
#[derive(Clone)]
pub struct Message<'a> {
    raw: &'a [u8],
    method: Method,
    class: Class,
    tid: [u8; 12],
    /// (type, value offset, value length, attribute offset)
    attrs: Vec<(u16, usize, usize, usize)>,
}

impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("method", &self.method)
            .field("class", &self.class)
            .field("attrs", &self.attrs.iter().map(|a| a.0).collect::<Vec<_>>())
            .finish()
    }
}

impl<'a> Message<'a> {
    /// Parses one message; trailing bytes after the declared length are an error.
    pub fn parse(raw: &'a [u8]) -> Result<Message<'a>, StunError> {
        if raw.len() < HEADER_LEN {
            return Err(StunError::Truncated);
        }
        if !is_stun(raw) {
            return Err(StunError::NotStun);
        }
        let len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
        if len % 4 != 0 || raw.len() != HEADER_LEN + len {
            return Err(StunError::Truncated);
        }
        let (method, class) = split_type(u16::from_be_bytes([raw[0], raw[1]]));
        let mut tid = [0u8; 12];
        tid.copy_from_slice(&raw[8..20]);
        let mut attrs = Vec::new();
        let mut off = HEADER_LEN;
        let mut seen_mi = false;
        let mut seen_fp = false;
        while off < raw.len() {
            if raw.len() - off < 4 {
                return Err(StunError::BadAttribute);
            }
            let t = u16::from_be_bytes([raw[off], raw[off + 1]]);
            let l = usize::from(u16::from_be_bytes([raw[off + 2], raw[off + 3]]));
            let v = off + 4;
            let padded = (l + 3) & !3;
            if raw.len() - v < padded {
                return Err(StunError::BadAttribute);
            }
            if seen_fp || (seen_mi && t != attr::FINGERPRINT) {
                return Err(StunError::Misplaced);
            }
            match t {
                attr::MESSAGE_INTEGRITY => seen_mi = true,
                attr::FINGERPRINT => seen_fp = true,
                _ => {}
            }
            attrs.push((t, v, l, off));
            off = v + padded;
        }
        Ok(Message {
            raw,
            method,
            class,
            tid,
            attrs,
        })
    }

    /// The whole datagram.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// The transaction id.
    pub fn transaction_id(&self) -> [u8; 12] {
        self.tid
    }

    /// The attribute types, in order.
    pub fn attr_types(&self) -> impl Iterator<Item = u16> + '_ {
        self.attrs.iter().map(|a| a.0)
    }

    /// The value of the first attribute of type `t`.
    pub fn get(&self, t: u16) -> Option<&'a [u8]> {
        self.attrs
            .iter()
            .find(|a| a.0 == t)
            .map(|&(_, v, l, _)| &self.raw[v..v + l])
    }

    /// Every value of attributes of type `t`, in order (several `XOR-PEER-ADDRESS`es).
    pub fn get_all(&self, t: u16) -> impl Iterator<Item = &'a [u8]> + '_ {
        let raw = self.raw;
        self.attrs
            .iter()
            .filter(move |a| a.0 == t)
            .map(move |&(_, v, l, _)| &raw[v..v + l])
    }

    /// Whether an attribute of type `t` is present.
    pub fn has(&self, t: u16) -> bool {
        self.attrs.iter().any(|a| a.0 == t)
    }

    /// A UTF-8 attribute (`USERNAME`, `REALM`, `NONCE`, `SOFTWARE`).
    pub fn get_str(&self, t: u16) -> Option<&'a str> {
        std::str::from_utf8(self.get(t)?).ok()
    }

    /// A 32-bit attribute (`LIFETIME`, `PRIORITY`).
    pub fn get_u32(&self, t: u16) -> Option<u32> {
        let v = self.get(t)?;
        (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    /// An XOR-encoded address attribute (`XOR-MAPPED-ADDRESS`, `XOR-PEER-ADDRESS`,
    /// `XOR-RELAYED-ADDRESS`).
    pub fn get_xor_addr(&self, t: u16) -> Option<SocketAddr> {
        decode_addr(self.get(t)?, Some(&self.tid))
    }

    /// Every XOR-encoded address of type `t`; `None` entries are malformed.
    pub fn get_xor_addrs(&self, t: u16) -> Vec<Option<SocketAddr>> {
        self.get_all(t)
            .map(|v| decode_addr(v, Some(&self.tid)))
            .collect()
    }

    /// A plain address attribute (`MAPPED-ADDRESS`, `ALTERNATE-SERVER`).
    pub fn get_addr(&self, t: u16) -> Option<SocketAddr> {
        decode_addr(self.get(t)?, None)
    }

    /// The `ERROR-CODE`: code and reason phrase.
    pub fn error_code(&self) -> Option<(u16, &'a str)> {
        let v = self.get(attr::ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        let code = u16::from(v[2] & 7) * 100 + u16::from(v[3]);
        Some((code, std::str::from_utf8(&v[4..]).unwrap_or("")))
    }

    /// `ADDRESS-ERROR-CODE` (RFC 8656 section 18.12): the address family a dual allocation
    /// did not get (1 IPv4, 2 IPv6), the error code (440 or 508) and the reason phrase.
    pub fn address_error_code(&self) -> Option<(u8, u16, &'a str)> {
        // Or the draft-ietf-tram-turnbis codepoint coturn 4.6 answers with.
        let v = self
            .get(attr::ADDRESS_ERROR_CODE)
            .or_else(|| self.get(attr::ADDRESS_ERROR_CODE_DRAFT))?;
        if v.len() < 4 {
            return None;
        }
        let code = u16::from(v[2] & 7) * 100 + u16::from(v[3]);
        Some((v[0], code, std::str::from_utf8(&v[4..]).unwrap_or("")))
    }

    /// Verifies `MESSAGE-INTEGRITY` with `key` (the short-term password, or the long-term key
    /// from [`long_term_key`]). `false` when it is absent or wrong.
    pub fn check_integrity(&self, key: &[u8]) -> bool {
        let Some(&(_, v, l, off)) = self.attrs.iter().find(|a| a.0 == attr::MESSAGE_INTEGRITY)
        else {
            return false;
        };
        if l != 20 {
            return false;
        }
        let mac = integrity(&self.raw[..off], off + 24 - HEADER_LEN, key);
        only_crypto::ct_eq(&mac, &self.raw[v..v + 20])
    }

    /// Verifies `FINGERPRINT`. `false` when it is absent or wrong.
    pub fn check_fingerprint(&self) -> bool {
        let Some(&(_, v, l, off)) = self.attrs.last() else {
            return false;
        };
        if self.attrs.last().map(|a| a.0) != Some(attr::FINGERPRINT) || l != 4 {
            return false;
        }
        let want = fingerprint(&self.raw[..off], off + 8 - HEADER_LEN);
        self.raw[v..v + 4] == want.to_be_bytes()
    }
}

/// HMAC-SHA1 over `prefix` with its length field replaced by `len`.
fn integrity(prefix: &[u8], len: usize, key: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new(key);
    mac.update(&prefix[..2]);
    mac.update(&(len as u16).to_be_bytes());
    mac.update(&prefix[4..]);
    mac.finalize()
}

fn fingerprint(prefix: &[u8], len: usize) -> u32 {
    let mut h = Crc32::new();
    h.update(&prefix[..2]);
    h.update(&(len as u16).to_be_bytes());
    h.update(&prefix[4..]);
    h.finalize() ^ FINGERPRINT_XOR
}

fn decode_addr(v: &[u8], xor: Option<&[u8; 12]>) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    let ip = match (v[1], v.len()) {
        (1, 8) => {
            let mut b = [v[4], v[5], v[6], v[7]];
            if xor.is_some() {
                for (x, c) in b.iter_mut().zip(cookie) {
                    *x ^= c;
                }
            }
            IpAddr::V4(Ipv4Addr::from(b))
        }
        (2, 20) => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&v[4..20]);
            if let Some(tid) = xor {
                let mask: Vec<u8> = cookie.iter().chain(tid.iter()).copied().collect();
                for (x, m) in b.iter_mut().zip(mask) {
                    *x ^= m;
                }
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn encode_addr(a: SocketAddr, xor: Option<&[u8; 12]>) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut port = a.port();
    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    let mut v = vec![0u8];
    match a.ip() {
        IpAddr::V4(ip) => {
            v.push(1);
            v.extend_from_slice(&port.to_be_bytes());
            let mut b = ip.octets();
            if xor.is_some() {
                for (x, c) in b.iter_mut().zip(cookie) {
                    *x ^= c;
                }
            }
            v.extend_from_slice(&b);
        }
        IpAddr::V6(ip) => {
            v.push(2);
            v.extend_from_slice(&port.to_be_bytes());
            let mut b = ip.octets();
            if let Some(tid) = xor {
                let mask: Vec<u8> = cookie.iter().chain(tid.iter()).copied().collect();
                for (x, m) in b.iter_mut().zip(mask) {
                    *x ^= m;
                }
            }
            v.extend_from_slice(&b);
        }
    }
    v
}

/// The long-term credential key of RFC 8489 section 9.2.2: `MD5(username ":" realm ":"
/// password)`.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize()
}

/// Writes a STUN message.
#[derive(Clone, Debug)]
pub struct MessageBuilder {
    buf: Vec<u8>,
    tid: [u8; 12],
}

impl MessageBuilder {
    /// A message of `method` and `class` with transaction id `tid`.
    pub fn new(method: Method, class: Class, tid: [u8; 12]) -> MessageBuilder {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&type_value(method, class).to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&tid);
        MessageBuilder { buf, tid }
    }

    /// The response of `class` to request `req` (same method and transaction id).
    pub fn response(req: &Message<'_>, class: Class) -> MessageBuilder {
        MessageBuilder::new(req.method(), class, req.transaction_id())
    }

    fn set_len(&mut self) {
        let len = (self.buf.len() - HEADER_LEN) as u16;
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
    }

    /// Appends an attribute (padded to 4 bytes). Values longer than 65535 bytes are truncated.
    #[must_use]
    pub fn attr(mut self, t: u16, v: &[u8]) -> Self {
        let v = &v[..v.len().min(usize::from(u16::MAX))];
        self.buf.extend_from_slice(&t.to_be_bytes());
        self.buf.extend_from_slice(&(v.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(v);
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
        self.set_len();
        self
    }

    /// Appends a 32-bit attribute.
    #[must_use]
    pub fn u32(self, t: u16, v: u32) -> Self {
        self.attr(t, &v.to_be_bytes())
    }

    /// Appends an XOR-encoded address attribute.
    #[must_use]
    pub fn xor_addr(self, t: u16, a: SocketAddr) -> Self {
        let tid = self.tid;
        self.attr(t, &encode_addr(a, Some(&tid)))
    }

    /// Appends a plain address attribute.
    #[must_use]
    pub fn addr(self, t: u16, a: SocketAddr) -> Self {
        self.attr(t, &encode_addr(a, None))
    }

    /// Appends an `ERROR-CODE`.
    #[must_use]
    pub fn error(self, code: u16, reason: &str) -> Self {
        let mut v = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        v.extend_from_slice(reason.as_bytes());
        self.attr(attr::ERROR_CODE, &v)
    }

    /// Appends `ADDRESS-ERROR-CODE` (RFC 8656 section 18.12) for address family `family` (1
    /// IPv4, 2 IPv6).
    #[must_use]
    pub fn address_error(self, family: u8, code: u16, reason: &str) -> Self {
        let mut v = vec![family, 0, (code / 100) as u8, (code % 100) as u8];
        v.extend_from_slice(reason.as_bytes());
        self.attr(attr::ADDRESS_ERROR_CODE, &v)
    }

    /// Appends `MESSAGE-INTEGRITY` keyed with `key`. Only `FINGERPRINT` may follow.
    #[must_use]
    pub fn integrity(mut self, key: &[u8]) -> Self {
        let len = self.buf.len() + 24 - HEADER_LEN;
        let mac = integrity(&self.buf, len, key);
        self.buf
            .extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
        self.buf.extend_from_slice(&20u16.to_be_bytes());
        self.buf.extend_from_slice(&mac);
        self.set_len();
        self
    }

    /// Appends `FINGERPRINT`. Must be last.
    #[must_use]
    pub fn fingerprint(mut self) -> Self {
        let len = self.buf.len() + 8 - HEADER_LEN;
        let fp = fingerprint(&self.buf, len);
        self.buf.extend_from_slice(&attr::FINGERPRINT.to_be_bytes());
        self.buf.extend_from_slice(&4u16.to_be_bytes());
        self.buf.extend_from_slice(&fp.to_be_bytes());
        self.set_len();
        self
    }

    /// The encoded message.
    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

/// A Binding request with `FINGERPRINT` (what a client sends a STUN server to learn its
/// server-reflexive address).
pub fn binding_request(tid: [u8; 12]) -> Vec<u8> {
    MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .fingerprint()
        .build()
}

/// The `XOR-MAPPED-ADDRESS` (or `MAPPED-ADDRESS`) of a Binding success response to `tid`.
pub fn parse_binding_response(data: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let m = Message::parse(data).ok()?;
    if m.method() != Method::BINDING || m.class() != Class::Success || &m.transaction_id() != tid {
        return None;
    }
    m.get_xor_addr(attr::XOR_MAPPED_ADDRESS)
        .or_else(|| m.get_addr(attr::MAPPED_ADDRESS))
}

/// The success response to a Binding request from `from` (`XOR-MAPPED-ADDRESS`, plus
/// `FINGERPRINT` if the request had one); `None` if `data` is not a Binding request.
pub fn binding_response(data: &[u8], from: SocketAddr, software: Option<&str>) -> Option<Vec<u8>> {
    let m = Message::parse(data).ok()?;
    if m.method() != Method::BINDING || m.class() != Class::Request {
        return None;
    }
    let mut b =
        MessageBuilder::response(&m, Class::Success).xor_addr(attr::XOR_MAPPED_ADDRESS, from);
    if let Some(s) = software {
        b = b.attr(attr::SOFTWARE, s.as_bytes());
    }
    if m.has(attr::FINGERPRINT) {
        b = b.fingerprint();
    }
    Some(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5769 section 2.1: sample request (short-term credentials).
    const REQ: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];

    #[test]
    fn rfc5769_request_verifies() {
        let m = Message::parse(REQ).unwrap();
        assert_eq!(m.method(), Method::BINDING);
        assert_eq!(m.class(), Class::Request);
        assert_eq!(m.get_str(attr::USERNAME), Some("evtj:h6vY"));
        assert_eq!(m.get_u32(attr::PRIORITY), Some(0x6e0001ff));
        assert!(m.check_integrity(b"VOkJxbRl1RmTxUk/WvJxBt"));
        assert!(!m.check_integrity(b"wrong"));
        assert!(m.check_fingerprint());
    }

    // RFC 5769 section 2.5: long-term credentials.
    #[test]
    fn rfc5769_long_term_key() {
        let key = long_term_key(
            "\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}",
            "example.org",
            "TheMatrIX",
        );
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn build_and_parse_round_trip() {
        let tid = transaction_id();
        for a in [
            "1.2.3.4:5678".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let raw = MessageBuilder::new(Method::ALLOCATE, Class::Success, tid)
                .xor_addr(attr::XOR_RELAYED_ADDRESS, a)
                .addr(attr::MAPPED_ADDRESS, a)
                .u32(attr::LIFETIME, 600)
                .attr(attr::REALM, b"r")
                .error(438, "Stale Nonce")
                .integrity(b"key")
                .fingerprint()
                .build();
            let m = Message::parse(&raw).unwrap();
            assert_eq!(m.method(), Method::ALLOCATE);
            assert_eq!(m.class(), Class::Success);
            assert_eq!(m.get_xor_addr(attr::XOR_RELAYED_ADDRESS), Some(a));
            assert_eq!(m.get_addr(attr::MAPPED_ADDRESS), Some(a));
            assert_eq!(m.get_u32(attr::LIFETIME), Some(600));
            assert_eq!(m.error_code(), Some((438, "Stale Nonce")));
            assert!(m.check_integrity(b"key"));
            assert!(m.check_fingerprint());
        }
    }

    #[test]
    fn binding_round_trip() {
        let tid = transaction_id();
        let req = binding_request(tid);
        let from: SocketAddr = "9.8.7.6:5432".parse().unwrap();
        let resp = binding_response(&req, from, Some("only")).unwrap();
        assert_eq!(parse_binding_response(&resp, &tid), Some(from));
        assert_eq!(parse_binding_response(&resp, &[0; 12]), None);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(
            Message::parse(&REQ[..19]).unwrap_err(),
            StunError::Truncated
        );
        let mut bad = REQ.to_vec();
        bad[4] = 0;
        assert_eq!(Message::parse(&bad).unwrap_err(), StunError::NotStun);
        let mut bad = REQ.to_vec();
        bad[23] = 0xff; // SOFTWARE length past the end
        assert_eq!(Message::parse(&bad).unwrap_err(), StunError::BadAttribute);
        // attribute after FINGERPRINT
        let tid = transaction_id();
        let mut raw = MessageBuilder::new(Method::BINDING, Class::Request, tid)
            .fingerprint()
            .build();
        raw.extend_from_slice(&[0x80, 0x22, 0, 0]);
        let len = (raw.len() - HEADER_LEN) as u16;
        raw[2..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(Message::parse(&raw).unwrap_err(), StunError::Misplaced);
    }
}
