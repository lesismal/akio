//! Multicast DNS messages (RFC 6762) for the `.local` names of ICE candidates.
//!
//! Browsers write their host candidates as `<uuid>.local` names (draft-ietf-mmusic-mdns-ice-
//! candidates) and answer mDNS queries for them on the local network. This module is the codec
//! only (no sockets): [`Message::query`] builds a one-shot query (RFC 6762 §5.1) for the `A`
//! or `AAAA` record of a name (one question per message: Chromium's responder ignores
//! messages with several), [`Message::parse`] reads the answers (and the queries a
//! responder for our own concealed names must answer, with the authority section of probes),
//! [`Message::response`] builds an answer (or an announcement or goodbye), [`Message::probe`]
//! a probe for a name about to be claimed (RFC 6762 §8.1).
//!
//! Names are compared case-insensitively (RFC 6762 §16): parsed names are lowercased.
//! Compression pointers are followed on parsing (backwards only, at most
//! [`MAX_POINTERS`] per name); built messages are not compressed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The mDNS port.
pub const PORT: u16 = 5353;
/// The IPv4 mDNS group `224.0.0.251`.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The IPv6 mDNS group `ff02::fb`.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// The IPv4 mDNS group and port, where queries and multicast answers go.
pub const MULTICAST_V4: SocketAddr = SocketAddr::new(IpAddr::V4(GROUP_V4), PORT);
/// The IPv6 mDNS group and port, `[ff02::fb]:5353`. The group is link-scoped: to send to it,
/// set the interface with [`multicast_v6_on`] (macOS refuses a datagram to it without one).
pub const MULTICAST_V6: SocketAddr =
    SocketAddr::V6(std::net::SocketAddrV6::new(GROUP_V6, PORT, 0, 0));

/// [`MULTICAST_V6`] on interface `scope` (its index, the scope id of the link-local addresses
/// on that link).
pub const fn multicast_v6_on(scope: u32) -> SocketAddr {
    SocketAddr::V6(std::net::SocketAddrV6::new(GROUP_V6, PORT, 0, scope))
}

/// Record type `A` (an IPv4 address).
pub const TYPE_A: u16 = 1;
/// Record type `AAAA` (an IPv6 address).
pub const TYPE_AAAA: u16 = 28;
/// Question type `ANY`.
pub const TYPE_ANY: u16 = 255;
/// Class `IN`.
const CLASS_IN: u16 = 1;
/// The top bit of a question's class: unicast response requested (QU, RFC 6762 §5.4); of a
/// record's class: cache flush (§10.2).
const CLASS_TOP: u16 = 0x8000;

/// Most questions read from one message.
pub const MAX_QUESTIONS: usize = 32;
/// Most address records read from one message (answer and additional sections).
pub const MAX_RECORDS: usize = 64;
/// Most compression pointers followed in one name.
pub const MAX_POINTERS: usize = 16;
/// Most bytes of a name in wire form (RFC 1035 §2.3.4).
const MAX_NAME: usize = 255;

/// Why a message was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mdns: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// A question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// The name, lowercased, without the trailing dot (`1f3c...-9a.local`).
    pub name: String,
    /// The type ([`TYPE_A`], [`TYPE_AAAA`], [`TYPE_ANY`], or another).
    pub qtype: u16,
    /// The QU bit: the querier asks for a unicast response.
    pub unicast_response: bool,
}

/// An address record (`A` or `AAAA`, class `IN`); records of other types are skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The name, lowercased, without the trailing dot.
    pub name: String,
    /// The address.
    pub addr: IpAddr,
    /// Time to live in seconds (0: a goodbye, the record is withdrawn).
    pub ttl: u32,
    /// The cache-flush bit (the responder owns the name: RFC 6762 §10.2).
    pub cache_flush: bool,
}

/// An mDNS message: what a querier or a responder for our concealed names needs of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The query id (0 in multicast mDNS; a legacy unicast querier's own id).
    pub id: u16,
    /// A response (the QR bit).
    pub response: bool,
    /// The questions (at most [`MAX_QUESTIONS`] are kept).
    pub questions: Vec<Question>,
    /// The `A`/`AAAA` records of the answer and additional sections (at most
    /// [`MAX_RECORDS`]).
    pub records: Vec<Record>,
    /// The `A`/`AAAA` records of the authority section (at most [`MAX_RECORDS`]): in a probe
    /// (RFC 6762 §8.2), the records the prober proposes for the names it asks about.
    pub authority: Vec<Record>,
}

/// Whether `name` is a valid name to put on the wire: dot-separated non-empty labels of at
/// most 63 bytes, at most 253 bytes in all, no trailing dot.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME - 2
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

fn put_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn put_record(out: &mut Vec<u8>, r: &Record) {
    put_name(out, &r.name);
    let (t, data): (u16, &[u8]) = match &r.addr {
        IpAddr::V4(a) => (TYPE_A, &a.octets()[..]),
        IpAddr::V6(a) => (TYPE_AAAA, &a.octets()[..]),
    };
    out.extend_from_slice(&t.to_be_bytes());
    let class = CLASS_IN | if r.cache_flush { CLASS_TOP } else { 0 };
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&r.ttl.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

impl Record {
    /// How two records of one name compare in a simultaneous probe tiebreak (RFC 6762 §8.2):
    /// class (always `IN` here), then type, then the record data as unsigned bytes. The
    /// greater record wins.
    pub fn tiebreak(&self, other: &Record) -> std::cmp::Ordering {
        fn key(r: &Record) -> (u16, Vec<u8>) {
            match r.addr {
                IpAddr::V4(a) => (TYPE_A, a.octets().to_vec()),
                IpAddr::V6(a) => (TYPE_AAAA, a.octets().to_vec()),
            }
        }
        key(self).cmp(&key(other))
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(Error("truncated"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A name at the current position (following compression pointers), lowercased.
    fn name(&mut self) -> Result<String, Error> {
        let mut out = String::new();
        let mut wire = 0usize;
        let mut pos = self.pos;
        let mut jumps = 0usize;
        // Where reading continues after the name: past the first pointer, or the final 0.
        let mut resume: Option<usize> = None;
        loop {
            let len = *self.buf.get(pos).ok_or(Error("truncated name"))?;
            match len & 0xc0 {
                0x00 => {
                    if len == 0 {
                        self.pos = resume.unwrap_or(pos + 1);
                        if out.is_empty() {
                            return Err(Error("empty name"));
                        }
                        return Ok(out);
                    }
                    let l = usize::from(len);
                    let label = self
                        .buf
                        .get(pos + 1..pos + 1 + l)
                        .ok_or(Error("truncated label"))?;
                    wire += l + 1;
                    if wire + 1 > MAX_NAME {
                        return Err(Error("name too long"));
                    }
                    let label = std::str::from_utf8(label).map_err(|_| Error("label not UTF-8"))?;
                    if label.contains('.') {
                        return Err(Error("dot in a label"));
                    }
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(&label.to_lowercase());
                    pos += 1 + l;
                }
                0xc0 => {
                    let lo = *self.buf.get(pos + 1).ok_or(Error("truncated pointer"))?;
                    let target = (usize::from(len & 0x3f) << 8) | usize::from(lo);
                    // Only backwards: a pointer to itself or later could loop.
                    if target >= pos {
                        return Err(Error("forward compression pointer"));
                    }
                    jumps += 1;
                    if jumps > MAX_POINTERS {
                        return Err(Error("too many compression pointers"));
                    }
                    resume.get_or_insert(pos + 2);
                    pos = target;
                }
                _ => return Err(Error("bad label type")),
            }
        }
    }
}

impl Message {
    /// A one-shot query (id 0, RFC 6762 §5.1) with one question: the `qtype` record
    /// ([`TYPE_A`], [`TYPE_AAAA`]) of `name` (`<uuid>.local`); `unicast_response` sets the QU
    /// bit. `None` if the name is not valid ([`valid_name`]). Ask for `A` and `AAAA` in two
    /// messages: Chromium's responder ignores a message with several questions.
    pub fn query(name: &str, qtype: u16, unicast_response: bool) -> Option<Vec<u8>> {
        if !valid_name(name) {
            return None;
        }
        let mut out = Vec::with_capacity(12 + name.len() + 6);
        out.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let class = CLASS_IN | if unicast_response { CLASS_TOP } else { 0 };
        put_name(&mut out, name);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        Some(out)
    }

    /// A response (QR and AA set) with `records` as answers (their names must be valid) and
    /// `questions` repeated in the question section: a legacy unicast response (RFC 6762
    /// §6.7) repeats the query's id and questions, a multicast one has id 0 and none. Records
    /// with an invalid name are left out.
    pub fn response(id: u16, questions: &[Question], records: &[Record]) -> Vec<u8> {
        let questions: Vec<&Question> = questions
            .iter()
            .filter(|q| valid_name(&q.name))
            .take(MAX_QUESTIONS)
            .collect();
        let records: Vec<&Record> = records
            .iter()
            .filter(|r| valid_name(&r.name))
            .take(MAX_RECORDS)
            .collect();
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&[0x84, 0x00]);
        out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for q in questions {
            put_name(&mut out, &q.name);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
        }
        for r in records {
            put_record(&mut out, r);
        }
        out
    }

    /// A probe (RFC 6762 §8.1) for `name`, about to be claimed with `records`: one question
    /// for `name`, type [`TYPE_ANY`] with the QU bit, and `records` (the proposed ones, all
    /// named `name`) in the authority section, without the cache-flush bit. `None` if the
    /// name is not valid or a record has another name.
    pub fn probe(name: &str, records: &[Record]) -> Option<Vec<u8>> {
        if !valid_name(name)
            || records.is_empty()
            || records.len() > MAX_RECORDS
            || records.iter().any(|r| r.name != name)
        {
            return None;
        }
        let mut out = Vec::with_capacity(12 + (name.len() + 30) * (1 + records.len()));
        out.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0]);
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        put_name(&mut out, name);
        out.extend_from_slice(&TYPE_ANY.to_be_bytes());
        out.extend_from_slice(&(CLASS_IN | CLASS_TOP).to_be_bytes());
        for r in records {
            put_record(
                &mut out,
                &Record {
                    cache_flush: false,
                    ..r.clone()
                },
            );
        }
        Some(out)
    }

    /// Parses a message. Questions past [`MAX_QUESTIONS`] and address records past
    /// [`MAX_RECORDS`] (per list: answers and additional records, authority records) are
    /// ignored; records of other types and classes are skipped. Messages with a nonzero
    /// opcode or rcode are refused.
    pub fn parse(packet: &[u8]) -> Result<Message, Error> {
        let mut r = Reader {
            buf: packet,
            pos: 0,
        };
        let id = r.u16()?;
        let flags = r.u16()?;
        let qd = r.u16()?;
        let an = r.u16()?;
        let ns = r.u16()?;
        let ar = r.u16()?;
        if flags & 0x7800 != 0 {
            return Err(Error("opcode is not QUERY"));
        }
        if flags & 0x000f != 0 {
            return Err(Error("error rcode"));
        }
        let response = flags & 0x8000 != 0;
        let mut questions = Vec::new();
        for _ in 0..qd {
            let name = r.name()?;
            let qtype = r.u16()?;
            let class = r.u16()?;
            if class & !CLASS_TOP == CLASS_IN && questions.len() < MAX_QUESTIONS {
                questions.push(Question {
                    name,
                    qtype,
                    unicast_response: class & CLASS_TOP != 0,
                });
            }
        }
        let mut records = Vec::new();
        let mut authority = Vec::new();
        let total = u32::from(an) + u32::from(ns) + u32::from(ar);
        for i in 0..total {
            let name = r.name()?;
            let rtype = r.u16()?;
            let class = r.u16()?;
            let ttl = r.u32()?;
            let len = r.u16()?;
            let data = r.take(usize::from(len))?;
            let in_authority = i >= u32::from(an) && i < u32::from(an) + u32::from(ns);
            let list = if in_authority {
                &mut authority
            } else {
                &mut records
            };
            if class & !CLASS_TOP != CLASS_IN || list.len() >= MAX_RECORDS {
                continue;
            }
            let addr = match (rtype, data.len()) {
                (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                (TYPE_AAAA, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(data);
                    IpAddr::V6(Ipv6Addr::from(b))
                }
                (TYPE_A | TYPE_AAAA, _) => return Err(Error("bad address length")),
                _ => continue,
            };
            list.push(Record {
                name,
                addr,
                ttl,
                cache_flush: class & CLASS_TOP != 0,
            });
        }
        Ok(Message {
            id,
            response,
            questions,
            records,
            authority,
        })
    }
}

/// Whether `name` (lowercased or not) is an mDNS name: it ends in `.local`.
pub fn is_mdns_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() > 6 && b[b.len() - 6..].eq_ignore_ascii_case(b".local") && valid_name(name)
}

/// A fresh random name `<uuid>.local` (a version 4 UUID, as browsers make them).
pub fn random_name() -> String {
    let mut b = [0u8; 16];
    crate::candidate::random_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}.local",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_groups() {
        assert_eq!(MULTICAST_V6.to_string(), "[ff02::fb]:5353");
        assert_eq!(MULTICAST_V4.to_string(), "224.0.0.251:5353");
        match multicast_v6_on(3) {
            SocketAddr::V6(a) => {
                assert_eq!((*a.ip(), a.port(), a.scope_id()), (GROUP_V6, PORT, 3));
            }
            SocketAddr::V4(_) => panic!("IPv4"),
        }
    }

    #[test]
    fn query_round_trip() {
        let name = "1f3c8b2e-0d4a-4c11-9e2f-5a6b7c8d9e0f.local";
        let q = Message::query(name, TYPE_A, false).unwrap();
        assert_eq!(&q[..12], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let m = Message::parse(&q).unwrap();
        assert!(!m.response);
        assert_eq!(m.questions.len(), 1);
        assert_eq!(m.questions[0].name, name);
        assert_eq!(m.questions[0].qtype, TYPE_A);
        assert!(!m.questions[0].unicast_response);
        let q = Message::query(name, TYPE_AAAA, true).unwrap();
        let m = Message::parse(&q).unwrap();
        assert!(m.questions[0].unicast_response && m.questions[0].qtype == TYPE_AAAA);
        assert!(Message::query("", TYPE_A, false).is_none());
        assert!(Message::query("a..local", TYPE_A, false).is_none());
        assert!(Message::query(&format!("{}.local", "x".repeat(64)), TYPE_A, false).is_none());
    }

    #[test]
    fn response_round_trip() {
        let rec = |n: &str, a: &str| Record {
            name: n.to_owned(),
            addr: a.parse().unwrap(),
            ttl: 120,
            cache_flush: true,
        };
        let records = [
            rec("abc.local", "192.168.1.20"),
            rec("abc.local", "fe80::1"),
        ];
        let questions = [Question {
            name: "abc.local".into(),
            qtype: TYPE_A,
            unicast_response: false,
        }];
        let b = Message::response(0x1234, &questions, &records);
        let m = Message::parse(&b).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(m.response);
        assert_eq!(m.questions, questions);
        assert_eq!(m.records, records);
    }

    #[test]
    fn probe_round_trip() {
        let name = "1f3c8b2e-0d4a-4c11-9e2f-5a6b7c8d9e0f.local";
        let rec = |a: &str| Record {
            name: name.to_owned(),
            addr: a.parse().unwrap(),
            ttl: 120,
            cache_flush: true,
        };
        let b = Message::probe(name, &[rec("192.168.1.20"), rec("fd00::5")]).unwrap();
        let m = Message::parse(&b).unwrap();
        assert!(!m.response && m.id == 0);
        assert_eq!(
            m.questions,
            [Question {
                name: name.to_owned(),
                qtype: TYPE_ANY,
                unicast_response: true,
            }]
        );
        assert!(m.records.is_empty());
        assert_eq!(m.authority.len(), 2);
        assert!(m.authority.iter().all(|r| !r.cache_flush && r.ttl == 120));
        assert_eq!(m.authority[1].addr, "fd00::5".parse::<IpAddr>().unwrap());
        // Records of another name, no records, a bad name.
        let mut other = rec("10.0.0.1");
        other.name = "x.local".into();
        assert!(Message::probe(name, &[other]).is_none());
        assert!(Message::probe(name, &[]).is_none());
        assert!(Message::probe("a..local", &[rec("10.0.0.1")]).is_none());
        // Answers do not land in the authority list.
        let r = Message::response(0, &[], &[rec("10.0.0.1")]);
        let m = Message::parse(&r).unwrap();
        assert!(m.authority.is_empty() && m.records.len() == 1);
    }

    #[test]
    fn tiebreak_order() {
        let rec = |a: &str| Record {
            name: "n.local".into(),
            addr: a.parse().unwrap(),
            ttl: 120,
            cache_flush: false,
        };
        use std::cmp::Ordering::*;
        assert_eq!(rec("10.0.0.2").tiebreak(&rec("10.0.0.1")), Greater);
        assert_eq!(rec("10.0.0.1").tiebreak(&rec("10.0.0.1")), Equal);
        // Type first: AAAA (28) beats A (1) whatever the data.
        assert_eq!(rec("::1").tiebreak(&rec("255.255.255.255")), Greater);
        assert_eq!(rec("169.254.0.1").tiebreak(&rec("192.168.0.1")), Less);
    }

    #[test]
    fn compression_and_case() {
        // A response as a browser's responder sends it: the name once, then a pointer.
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        put_name(&mut b, "AbC.Local");
        b.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 7]);
        b.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 120, 0, 16]);
        b.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let m = Message::parse(&b).unwrap();
        assert_eq!(m.records.len(), 2);
        assert_eq!(m.records[0].name, "abc.local");
        assert_eq!(m.records[1].name, "abc.local");
        assert_eq!(m.records[0].addr, IpAddr::from([10, 0, 0, 7]));
        assert!(m.records[0].cache_flush && !m.records[1].cache_flush);
        // Pointer loops and forward pointers are refused.
        let mut l = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        l.extend_from_slice(&[0xc0, 12]);
        assert!(Message::parse(&l).is_err());
        let mut f = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        f.extend_from_slice(&[0xc0, 20]);
        assert!(Message::parse(&f).is_err());
    }

    #[test]
    fn skips_and_errors() {
        // Another record type is skipped, a bad A length refused.
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        put_name(&mut b, "x.local");
        b.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 1, 0, 2, 1, b'a']);
        put_name(&mut b, "x.local");
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        let m = Message::parse(&b).unwrap();
        assert_eq!(m.records.len(), 1);
        let n = b.len();
        b[n - 5] = 3; // A with 3 bytes of data, and one left over
        assert!(Message::parse(&b).is_err());
        assert!(Message::parse(&[0; 11]).is_err());
        // Opcode and rcode.
        assert!(Message::parse(&[0, 0, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(Message::parse(&[0, 0, 0x80, 3, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Counts larger than the message.
        assert!(Message::parse(&[0, 0, 0x84, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn names() {
        assert!(is_mdns_name("abc.local") && is_mdns_name("ABC.LOCAL"));
        assert!(!is_mdns_name(".local") && !is_mdns_name("example.com"));
        let n = random_name();
        assert!(is_mdns_name(&n), "{n}");
        assert_eq!(n.len(), 36 + 6);
        assert_eq!(&n[14..15], "4");
        assert_ne!(n, random_name());
    }
}
