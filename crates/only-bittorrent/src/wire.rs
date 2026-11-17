//! The peer wire protocol as a codec without I/O: the [`Handshake`] with its reserved bits,
//! [`Message`]s of BEP 3 (plus `port`, BEP 5), the Fast extension (BEP 6), the extension
//! protocol (BEP 10) and BEP 52's hash request, hashes and hash reject, an incremental [`Parser`], [`Bitfield`], the extension handshake, the
//! ut_metadata (BEP 9) and ut_pex (BEP 11) payloads, and BEP 6's allowed-fast set.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bencode::{self, Value};
use crate::metainfo::{InfoHash, sha1};

/// A peer ID: 20 bytes.
pub type PeerId = [u8; 20];

/// The protocol string, length-prefixed.
pub const PROTOCOL: &[u8; 20] = b"\x13BitTorrent protocol";
/// Length of a handshake.
pub const HANDSHAKE_LEN: usize = 68;
/// The block size everyone requests.
pub const BLOCK_SIZE: u32 = 16 * 1024;
/// The largest message [`Parser`] accepts by default (a bitfield of 8M pieces, a metadata piece).
pub const DEFAULT_MAX_MESSAGE: usize = 1 << 20;
/// ut_metadata piece size.
pub const METADATA_PIECE: usize = 16 * 1024;

/// A new Azureus-style peer ID: `-ON0100-` and 12 random bytes.
pub fn new_peer_id() -> PeerId {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(b"-ON0100-");
    crate::rand_fill(&mut id[8..]);
    id
}

/// The 68-byte handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handshake {
    /// Extension bits.
    pub reserved: [u8; 8],
    /// The torrent asked for.
    pub info_hash: InfoHash,
    /// The sender's peer ID.
    pub peer_id: PeerId,
}

impl Handshake {
    /// A handshake announcing the extension protocol, the DHT, the Fast extension and v2
    /// (BEP 52).
    pub fn new(info_hash: InfoHash, peer_id: PeerId) -> Handshake {
        let mut reserved = [0u8; 8];
        reserved[5] |= 0x10; // BEP 10
        reserved[7] |= 0x01 | 0x04 | 0x10; // BEP 5 DHT, BEP 6 Fast, BEP 52 v2
        Handshake {
            reserved,
            info_hash,
            peer_id,
        }
    }

    /// Encodes it.
    pub fn encode(&self) -> [u8; HANDSHAKE_LEN] {
        let mut b = [0u8; HANDSHAKE_LEN];
        b[..20].copy_from_slice(PROTOCOL);
        b[20..28].copy_from_slice(&self.reserved);
        b[28..48].copy_from_slice(&self.info_hash.0);
        b[48..68].copy_from_slice(&self.peer_id);
        b
    }

    /// Parses the first 68 bytes of `b`; `None` if it is not a BitTorrent handshake.
    pub fn parse(b: &[u8]) -> Option<Handshake> {
        if b.len() < HANDSHAKE_LEN || &b[..20] != PROTOCOL {
            return None;
        }
        let mut h = Handshake {
            reserved: [0; 8],
            info_hash: InfoHash::default(),
            peer_id: [0; 20],
        };
        h.reserved.copy_from_slice(&b[20..28]);
        h.info_hash.0.copy_from_slice(&b[28..48]);
        h.peer_id.copy_from_slice(&b[48..68]);
        Some(h)
    }

    /// The peer speaks the extension protocol (BEP 10).
    pub fn extended(&self) -> bool {
        self.reserved[5] & 0x10 != 0
    }

    /// The peer runs a DHT node (BEP 5).
    pub fn dht(&self) -> bool {
        self.reserved[7] & 0x01 != 0
    }

    /// The peer speaks the Fast extension (BEP 6).
    pub fn fast(&self) -> bool {
        self.reserved[7] & 0x04 != 0
    }

    /// The peer supports v2 torrents (BEP 52: hash requests, upgrading hybrid connections).
    pub fn v2(&self) -> bool {
        self.reserved[7] & 0x10 != 0
    }
}

/// The payload of a hash request or hash reject (BEP 52), and the head of a hashes message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HashRequest {
    /// The file's merkle root.
    pub pieces_root: [u8; 32],
    /// The lowest layer asked for (0 = 16 KiB blocks).
    pub base_layer: u32,
    /// First node asked for in that layer (a multiple of `length`).
    pub index: u32,
    /// Nodes asked for (a power of two, at least 2).
    pub length: u32,
    /// Ancestor layers to prove them with.
    pub proof_layers: u32,
}

impl HashRequest {
    /// A request.
    pub fn new(
        pieces_root: [u8; 32],
        base_layer: u32,
        index: u32,
        length: u32,
        proof_layers: u32,
    ) -> HashRequest {
        HashRequest {
            pieces_root,
            base_layer,
            index,
            length,
            proof_layers,
        }
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pieces_root);
        put_u32(out, self.base_layer);
        put_u32(out, self.index);
        put_u32(out, self.length);
        put_u32(out, self.proof_layers);
    }

    fn take(p: &[u8]) -> HashRequest {
        let u = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let mut pieces_root = [0u8; 32];
        pieces_root.copy_from_slice(&p[..32]);
        HashRequest {
            pieces_root,
            base_layer: u(32),
            index: u(36),
            length: u(40),
            proof_layers: u(44),
        }
    }
}

/// A peer wire message.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// Zero length.
    KeepAlive,
    /// 0
    Choke,
    /// 1
    Unchoke,
    /// 2
    Interested,
    /// 3
    NotInterested,
    /// 4
    Have(u32),
    /// 5: the raw bitfield bytes.
    Bitfield(Vec<u8>),
    /// 6
    Request {
        /// Piece.
        index: u32,
        /// Offset in the piece.
        begin: u32,
        /// Bytes.
        length: u32,
    },
    /// 7
    Piece {
        /// Piece.
        index: u32,
        /// Offset in the piece.
        begin: u32,
        /// The block.
        data: Vec<u8>,
    },
    /// 8
    Cancel {
        /// Piece.
        index: u32,
        /// Offset in the piece.
        begin: u32,
        /// Bytes.
        length: u32,
    },
    /// 9 (BEP 5): the sender's DHT port.
    Port(u16),
    /// 0x0D (BEP 6)
    Suggest(u32),
    /// 0x0E (BEP 6)
    HaveAll,
    /// 0x0F (BEP 6)
    HaveNone,
    /// 0x10 (BEP 6)
    Reject {
        /// Piece.
        index: u32,
        /// Offset in the piece.
        begin: u32,
        /// Bytes.
        length: u32,
    },
    /// 0x11 (BEP 6)
    AllowedFast(u32),
    /// 21 (BEP 52): asks for merkle hashes.
    HashRequest(HashRequest),
    /// 22 (BEP 52): the hashes asked for, then the uncle hashes proving them, leaf to root.
    Hashes {
        /// The request answered.
        req: HashRequest,
        /// The hashes.
        hashes: Vec<[u8; 32]>,
    },
    /// 23 (BEP 52): refuses a hash request.
    HashReject(HashRequest),
    /// 20 (BEP 10): extended message `id` (0 = the extension handshake).
    Extended {
        /// Extended message ID as the receiver assigned it.
        id: u8,
        /// The payload.
        payload: Vec<u8>,
    },
    /// Any other message ID, kept to be ignored.
    Unknown {
        /// The ID.
        id: u8,
        /// The payload.
        payload: Vec<u8>,
    },
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Piece { index, begin, data } => {
                write!(
                    f,
                    "Piece {{ index: {index}, begin: {begin}, len: {} }}",
                    data.len()
                )
            }
            Message::Bitfield(b) => write!(f, "Bitfield(<{} bytes>)", b.len()),
            Message::Extended { id, payload } => {
                write!(f, "Extended {{ id: {id}, len: {} }}", payload.len())
            }
            Message::Unknown { id, payload } => {
                write!(f, "Unknown {{ id: {id}, len: {} }}", payload.len())
            }
            Message::KeepAlive => f.write_str("KeepAlive"),
            Message::Choke => f.write_str("Choke"),
            Message::Unchoke => f.write_str("Unchoke"),
            Message::Interested => f.write_str("Interested"),
            Message::NotInterested => f.write_str("NotInterested"),
            Message::Have(i) => write!(f, "Have({i})"),
            Message::Request {
                index,
                begin,
                length,
            } => {
                write!(f, "Request {{ {index}, {begin}, {length} }}")
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => write!(f, "Cancel {{ {index}, {begin}, {length} }}"),
            Message::Reject {
                index,
                begin,
                length,
            } => write!(f, "Reject {{ {index}, {begin}, {length} }}"),
            Message::Port(p) => write!(f, "Port({p})"),
            Message::Suggest(i) => write!(f, "Suggest({i})"),
            Message::HaveAll => f.write_str("HaveAll"),
            Message::HaveNone => f.write_str("HaveNone"),
            Message::AllowedFast(i) => write!(f, "AllowedFast({i})"),
            Message::HashRequest(r) => write!(f, "HashRequest({r:?})"),
            Message::Hashes { req, hashes } => {
                write!(f, "Hashes {{ {req:?}, {} hashes }}", hashes.len())
            }
            Message::HashReject(r) => write!(f, "HashReject({r:?})"),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

impl Message {
    /// Appends the encoded message (length prefix included) to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        let three = |out: &mut Vec<u8>, id: u8, a: u32, b: u32, c: u32| {
            put_u32(out, 13);
            out.push(id);
            put_u32(out, a);
            put_u32(out, b);
            put_u32(out, c);
        };
        let one = |out: &mut Vec<u8>, id: u8, a: u32| {
            put_u32(out, 5);
            out.push(id);
            put_u32(out, a);
        };
        let bare = |out: &mut Vec<u8>, id: u8| {
            put_u32(out, 1);
            out.push(id);
        };
        match self {
            Message::KeepAlive => put_u32(out, 0),
            Message::Choke => bare(out, 0),
            Message::Unchoke => bare(out, 1),
            Message::Interested => bare(out, 2),
            Message::NotInterested => bare(out, 3),
            Message::Have(i) => one(out, 4, *i),
            Message::Bitfield(b) => {
                put_u32(out, 1 + b.len() as u32);
                out.push(5);
                out.extend_from_slice(b);
            }
            Message::Request {
                index,
                begin,
                length,
            } => three(out, 6, *index, *begin, *length),
            Message::Piece { index, begin, data } => {
                put_u32(out, 9 + data.len() as u32);
                out.push(7);
                put_u32(out, *index);
                put_u32(out, *begin);
                out.extend_from_slice(data);
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => three(out, 8, *index, *begin, *length),
            Message::Port(p) => {
                put_u32(out, 3);
                out.push(9);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Message::Suggest(i) => one(out, 0x0D, *i),
            Message::HaveAll => bare(out, 0x0E),
            Message::HaveNone => bare(out, 0x0F),
            Message::Reject {
                index,
                begin,
                length,
            } => three(out, 0x10, *index, *begin, *length),
            Message::AllowedFast(i) => one(out, 0x11, *i),
            Message::HashRequest(r) | Message::HashReject(r) => {
                put_u32(out, 49);
                out.push(if matches!(self, Message::HashRequest(_)) {
                    21
                } else {
                    23
                });
                r.put(out);
            }
            Message::Hashes { req, hashes } => {
                put_u32(out, 49 + 32 * hashes.len() as u32);
                out.push(22);
                req.put(out);
                for h in hashes {
                    out.extend_from_slice(h);
                }
            }
            Message::Extended { id, payload } => {
                put_u32(out, 2 + payload.len() as u32);
                out.push(20);
                out.push(*id);
                out.extend_from_slice(payload);
            }
            Message::Unknown { id, payload } => {
                put_u32(out, 1 + payload.len() as u32);
                out.push(*id);
                out.extend_from_slice(payload);
            }
        }
    }

    /// The encoded message.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_to(&mut v);
        v
    }

    /// Decodes one message body (without the length prefix; empty = keep-alive).
    pub fn decode(body: &[u8]) -> Result<Message, WireError> {
        let Some((&id, p)) = body.split_first() else {
            return Ok(Message::KeepAlive);
        };
        let u = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let want = |n: usize| {
            if p.len() == n {
                Ok(())
            } else {
                Err(WireError::BadLength(id))
            }
        };
        Ok(match id {
            0 => want(0).map(|()| Message::Choke)?,
            1 => want(0).map(|()| Message::Unchoke)?,
            2 => want(0).map(|()| Message::Interested)?,
            3 => want(0).map(|()| Message::NotInterested)?,
            4 => want(4).map(|()| Message::Have(u(0)))?,
            5 => Message::Bitfield(p.to_vec()),
            6 | 8 | 0x10 => {
                want(12)?;
                let (index, begin, length) = (u(0), u(4), u(8));
                match id {
                    6 => Message::Request {
                        index,
                        begin,
                        length,
                    },
                    8 => Message::Cancel {
                        index,
                        begin,
                        length,
                    },
                    _ => Message::Reject {
                        index,
                        begin,
                        length,
                    },
                }
            }
            7 => {
                if p.len() < 8 {
                    return Err(WireError::BadLength(id));
                }
                Message::Piece {
                    index: u(0),
                    begin: u(4),
                    data: p[8..].to_vec(),
                }
            }
            9 => want(2).map(|()| Message::Port(u16::from_be_bytes([p[0], p[1]])))?,
            0x0D => want(4).map(|()| Message::Suggest(u(0)))?,
            0x0E => want(0).map(|()| Message::HaveAll)?,
            0x0F => want(0).map(|()| Message::HaveNone)?,
            0x11 => want(4).map(|()| Message::AllowedFast(u(0)))?,
            21 => want(48).map(|()| Message::HashRequest(HashRequest::take(p)))?,
            23 => want(48).map(|()| Message::HashReject(HashRequest::take(p)))?,
            22 => {
                if p.len() < 48 || (p.len() - 48) % 32 != 0 {
                    return Err(WireError::BadLength(id));
                }
                Message::Hashes {
                    req: HashRequest::take(p),
                    hashes: p[48..]
                        .chunks_exact(32)
                        .map(|c| c.try_into().unwrap_or([0; 32]))
                        .collect(),
                }
            }
            20 => {
                let Some((&eid, rest)) = p.split_first() else {
                    return Err(WireError::BadLength(id));
                };
                Message::Extended {
                    id: eid,
                    payload: rest.to_vec(),
                }
            }
            _ => Message::Unknown {
                id,
                payload: p.to_vec(),
            },
        })
    }
}

/// A protocol violation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// A message longer than the limit.
    TooLong(usize),
    /// A message whose length does not fit its ID.
    BadLength(u8),
    /// A malformed extension payload.
    BadPayload(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::TooLong(n) => write!(f, "message of {n} bytes is too long"),
            WireError::BadLength(id) => write!(f, "message {id} has a bad length"),
            WireError::BadPayload(m) => write!(f, "bad payload: {m}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Splits a byte stream into messages; feed it pieces of any size.
#[derive(Debug)]
pub struct Parser {
    buf: Vec<u8>,
    start: usize,
    max: usize,
}

impl Default for Parser {
    fn default() -> Self {
        Parser::new(DEFAULT_MAX_MESSAGE)
    }
}

impl Parser {
    /// A parser refusing messages longer than `max` bytes.
    pub fn new(max: usize) -> Parser {
        Parser {
            buf: Vec::new(),
            start: 0,
            max,
        }
    }

    /// Appends stream bytes.
    pub fn feed(&mut self, data: &[u8]) {
        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 64 * 1024 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next complete message, if one has arrived.
    pub fn next_message(&mut self) -> Result<Option<Message>, WireError> {
        let avail = &self.buf[self.start..];
        if avail.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([avail[0], avail[1], avail[2], avail[3]]) as usize;
        if n > self.max {
            return Err(WireError::TooLong(n));
        }
        if avail.len() < 4 + n {
            return Ok(None);
        }
        let m = Message::decode(&avail[4..4 + n]);
        self.start += 4 + n;
        m.map(Some)
    }

    /// Bytes buffered but not yet returned as messages.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Takes the buffered bytes out (a handshake reader handing over to the message parser).
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let v = self.buf[self.start..].to_vec();
        self.buf.clear();
        self.start = 0;
        v
    }
}

/// A set of pieces, as the bitfield message carries it (high bit first).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bitfield {
    bits: Vec<u8>,
    len: usize,
    count: usize,
}

impl fmt::Debug for Bitfield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bitfield({}/{})", self.count, self.len)
    }
}

impl Bitfield {
    /// An empty set of `len` pieces.
    pub fn new(len: usize) -> Bitfield {
        Bitfield {
            bits: vec![0; len.div_ceil(8)],
            len,
            count: 0,
        }
    }

    /// The full set of `len` pieces.
    pub fn full(len: usize) -> Bitfield {
        let mut b = Bitfield::new(len);
        for i in 0..len {
            b.set(i, true);
        }
        b
    }

    /// From the bytes of a bitfield message; `None` if the length is wrong or spare bits are set.
    pub fn from_bytes(bytes: &[u8], len: usize) -> Option<Bitfield> {
        if bytes.len() != len.div_ceil(8) {
            return None;
        }
        if len % 8 != 0 && bytes.last().is_some_and(|&l| l & (0xFF >> (len % 8)) != 0) {
            return None;
        }
        let count = bytes.iter().map(|b| b.count_ones() as usize).sum();
        Some(Bitfield {
            bits: bytes.to_vec(),
            len,
            count,
        })
    }

    /// The bytes of a bitfield message.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Number of pieces.
    pub fn len(&self) -> usize {
        self.len
    }

    /// No pieces at all (length zero).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether piece `i` is in the set.
    pub fn get(&self, i: usize) -> bool {
        i < self.len && self.bits[i / 8] & (0x80 >> (i % 8)) != 0
    }

    /// Adds or removes piece `i` (ignored out of range).
    pub fn set(&mut self, i: usize, v: bool) {
        if i >= self.len {
            return;
        }
        let m = 0x80 >> (i % 8);
        let had = self.bits[i / 8] & m != 0;
        if v && !had {
            self.bits[i / 8] |= m;
            self.count += 1;
        } else if !v && had {
            self.bits[i / 8] &= !m;
            self.count -= 1;
        }
    }

    /// Pieces in the set.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Every piece is in the set.
    pub fn is_full(&self) -> bool {
        self.count == self.len
    }

    /// The pieces in the set.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(|&i| self.get(i))
    }
}

/// The extension handshake (BEP 10): extended message 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtendedHandshake {
    /// `m`: extension name to the ID the sender wants to receive it with (0 = disabled).
    pub m: BTreeMap<String, u8>,
    /// `v`: client name and version.
    pub v: Option<String>,
    /// `p`: the sender's listen port.
    pub p: Option<u16>,
    /// `metadata_size` (BEP 9).
    pub metadata_size: Option<u32>,
    /// `reqq`: requests the sender keeps without dropping.
    pub reqq: Option<u32>,
    /// `yourip`: the receiver's address as the sender sees it (4 or 16 bytes).
    pub yourip: Option<IpAddr>,
}

impl ExtendedHandshake {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Value::dict();
        for (k, id) in &self.m {
            m.insert(k, i64::from(*id));
        }
        let mut d = Value::dict().with("m", m);
        if let Some(v) = &self.v {
            d.insert("v", v.as_str());
        }
        if let Some(p) = self.p {
            d.insert("p", i64::from(p));
        }
        if let Some(n) = self.metadata_size {
            d.insert("metadata_size", i64::from(n));
        }
        if let Some(n) = self.reqq {
            d.insert("reqq", i64::from(n));
        }
        match self.yourip {
            Some(IpAddr::V4(a)) => d.insert("yourip", a.octets().to_vec()),
            Some(IpAddr::V6(a)) => d.insert("yourip", a.octets().to_vec()),
            None => {}
        }
        bencode::encode(&d)
    }

    /// Decodes a payload; unknown keys are ignored.
    pub fn decode(b: &[u8]) -> Result<ExtendedHandshake, WireError> {
        let (v, _) =
            bencode::decode_prefix(b).map_err(|_| WireError::BadPayload("extension handshake"))?;
        let mut h = ExtendedHandshake::default();
        if let Some(m) = v.get("m").and_then(Value::as_dict) {
            for (k, id) in m {
                if let (Ok(k), Some(id)) = (std::str::from_utf8(k), id.as_int()) {
                    if let Ok(id) = u8::try_from(id) {
                        h.m.insert(k.to_owned(), id);
                    }
                }
            }
        }
        h.v = v.str_at("v").map(str::to_owned);
        h.p = v.int("p").and_then(|p| u16::try_from(p).ok());
        h.metadata_size = v.int("metadata_size").and_then(|n| u32::try_from(n).ok());
        h.reqq = v.int("reqq").and_then(|n| u32::try_from(n).ok());
        h.yourip = v.bytes_at("yourip").and_then(|b| match b.len() {
            4 => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            16 => <[u8; 16]>::try_from(b)
                .ok()
                .map(|a| IpAddr::V6(Ipv6Addr::from(a))),
            _ => None,
        });
        Ok(h)
    }
}

/// A ut_metadata message (BEP 9).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataMsg {
    /// `msg_type` 0: asks for a piece.
    Request(u32),
    /// `msg_type` 1: a piece, followed by its bytes.
    Data {
        /// Piece index.
        piece: u32,
        /// `total_size` of the info dictionary.
        total_size: u32,
        /// The piece's bytes.
        data: Vec<u8>,
    },
    /// `msg_type` 2: refuses a piece.
    Reject(u32),
}

impl MetadataMsg {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            MetadataMsg::Request(p) => bencode::encode(
                &Value::dict()
                    .with("msg_type", 0)
                    .with("piece", i64::from(*p)),
            ),
            MetadataMsg::Reject(p) => bencode::encode(
                &Value::dict()
                    .with("msg_type", 2)
                    .with("piece", i64::from(*p)),
            ),
            MetadataMsg::Data {
                piece,
                total_size,
                data,
            } => {
                let mut v = bencode::encode(
                    &Value::dict()
                        .with("msg_type", 1)
                        .with("piece", i64::from(*piece))
                        .with("total_size", i64::from(*total_size)),
                );
                v.extend_from_slice(data);
                v
            }
        }
    }

    /// Decodes a payload.
    pub fn decode(b: &[u8]) -> Result<MetadataMsg, WireError> {
        let bad = WireError::BadPayload("ut_metadata");
        let (v, n) = bencode::decode_prefix(b).map_err(|_| bad.clone())?;
        let piece = v
            .int("piece")
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| bad.clone())?;
        match v.int("msg_type") {
            Some(0) => Ok(MetadataMsg::Request(piece)),
            Some(1) => {
                let total_size = v
                    .int("total_size")
                    .and_then(|p| u32::try_from(p).ok())
                    .ok_or_else(|| bad.clone())?;
                if b.len() - n > METADATA_PIECE {
                    return Err(bad);
                }
                Ok(MetadataMsg::Data {
                    piece,
                    total_size,
                    data: b[n..].to_vec(),
                })
            }
            Some(2) => Ok(MetadataMsg::Reject(piece)),
            _ => Err(bad),
        }
    }
}

/// A ut_pex message (BEP 11): peers added and dropped since the last one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pex {
    /// Peers connected since the last message.
    pub added: Vec<SocketAddr>,
    /// Peers disconnected since the last message.
    pub dropped: Vec<SocketAddr>,
}

/// Compact peer encoding: 6 bytes per IPv4 peer, 18 per IPv6 peer.
pub fn compact_peers(peers: &[SocketAddr], v6: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for p in peers {
        match (p.ip(), v6) {
            (IpAddr::V4(a), false) => out.extend_from_slice(&a.octets()),
            (IpAddr::V6(a), true) => out.extend_from_slice(&a.octets()),
            _ => continue,
        }
        out.extend_from_slice(&p.port().to_be_bytes());
    }
    out
}

/// Decodes compact peers (6 bytes each for IPv4, 18 for IPv6); a trailing partial entry is ignored.
pub fn parse_compact_peers(b: &[u8], v6: bool) -> Vec<SocketAddr> {
    let n = if v6 { 18 } else { 6 };
    b.chunks_exact(n)
        .map(|c| {
            let port = u16::from_be_bytes([c[n - 2], c[n - 1]]);
            let ip = if v6 {
                let mut a = [0u8; 16];
                a.copy_from_slice(&c[..16]);
                IpAddr::V6(Ipv6Addr::from(a))
            } else {
                IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3]))
            };
            SocketAddr::new(ip, port)
        })
        .collect()
}

impl Pex {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        let a4 = compact_peers(&self.added, false);
        let a6 = compact_peers(&self.added, true);
        let mut d = Value::dict()
            .with("added", a4.clone())
            .with("added.f", vec![0u8; a4.len() / 6])
            .with("dropped", compact_peers(&self.dropped, false));
        if !a6.is_empty() {
            d.insert("added6", a6.clone());
            d.insert("added6.f", vec![0u8; a6.len() / 18]);
        }
        let d6 = compact_peers(&self.dropped, true);
        if !d6.is_empty() {
            d.insert("dropped6", d6);
        }
        bencode::encode(&d)
    }

    /// Decodes a payload.
    pub fn decode(b: &[u8]) -> Result<Pex, WireError> {
        let (v, _) = bencode::decode_prefix(b).map_err(|_| WireError::BadPayload("ut_pex"))?;
        let get = |k: &str| v.bytes_at(k).unwrap_or_default();
        let mut p = Pex {
            added: parse_compact_peers(get("added"), false),
            dropped: parse_compact_peers(get("dropped"), false),
        };
        p.added.extend(parse_compact_peers(get("added6"), true));
        p.dropped.extend(parse_compact_peers(get("dropped6"), true));
        Ok(p)
    }
}

/// BEP 6's allowed-fast set: `k` pieces of `num_pieces` for the peer at `ip` (IPv4).
pub fn allowed_fast_set(info_hash: &InfoHash, ip: Ipv4Addr, num_pieces: u32, k: usize) -> Vec<u32> {
    let mut out = Vec::new();
    if num_pieces == 0 {
        return out;
    }
    let k = k.min(num_pieces as usize);
    let o = ip.octets();
    let mut x = Vec::with_capacity(24);
    x.extend_from_slice(&[o[0], o[1], o[2], 0]);
    x.extend_from_slice(&info_hash.0);
    while out.len() < k {
        let h = sha1(&x);
        for c in h.chunks_exact(4) {
            if out.len() >= k {
                break;
            }
            let y = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
            let i = y % num_pieces;
            if !out.contains(&i) {
                out.push(i);
            }
        }
        x = h.to_vec();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let h = Handshake::new(InfoHash::of(b"x"), new_peer_id());
        let b = h.encode();
        let p = Handshake::parse(&b).unwrap();
        assert_eq!(p, h);
        assert!(p.extended() && p.dht() && p.fast() && p.v2());
        assert!(Handshake::parse(&b[..60]).is_none());
    }

    #[test]
    fn messages_round_trip_split() {
        let msgs = vec![
            Message::KeepAlive,
            Message::Choke,
            Message::Unchoke,
            Message::Interested,
            Message::NotInterested,
            Message::Have(7),
            Message::Bitfield(vec![0xF0]),
            Message::Request {
                index: 1,
                begin: 16384,
                length: 16384,
            },
            Message::Piece {
                index: 1,
                begin: 0,
                data: vec![9; 100],
            },
            Message::Cancel {
                index: 1,
                begin: 0,
                length: 3,
            },
            Message::Port(6881),
            Message::Suggest(3),
            Message::HaveAll,
            Message::HaveNone,
            Message::Reject {
                index: 2,
                begin: 0,
                length: 5,
            },
            Message::AllowedFast(4),
            Message::HashRequest(HashRequest::new([7; 32], 2, 512, 512, 9)),
            Message::Hashes {
                req: HashRequest::new([7; 32], 0, 4, 2, 0),
                hashes: vec![[1; 32], [2; 32]],
            },
            Message::HashReject(HashRequest::new([8; 32], 1, 0, 2, 3)),
            Message::Extended {
                id: 0,
                payload: b"de".to_vec(),
            },
            Message::Unknown {
                id: 99,
                payload: vec![1, 2],
            },
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            m.encode_to(&mut stream);
        }
        let mut p = Parser::default();
        let mut got = Vec::new();
        for c in stream.chunks(3) {
            p.feed(c);
            while let Some(m) = p.next_message().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, msgs);
        let mut p = Parser::new(10);
        p.feed(&[0, 0, 0, 11]);
        assert!(p.next_message().is_err());
        assert!(Message::decode(&[4, 0]).is_err());
    }

    #[test]
    fn bitfield() {
        let mut b = Bitfield::new(10);
        b.set(0, true);
        b.set(9, true);
        b.set(9, true);
        assert_eq!(b.count(), 2);
        assert_eq!(b.as_bytes(), &[0x80, 0x40]);
        assert!(Bitfield::from_bytes(&[0x80, 0x20], 10).is_none()); // spare bit set
        assert_eq!(Bitfield::from_bytes(&[0x80, 0x40], 10).unwrap(), b);
        assert!(Bitfield::full(10).is_full());
        assert_eq!(b.ones().collect::<Vec<_>>(), vec![0, 9]);
    }

    #[test]
    fn extensions() {
        let mut h = ExtendedHandshake::default();
        h.m.insert("ut_metadata".into(), 3);
        h.metadata_size = Some(1234);
        h.p = Some(6881);
        h.yourip = Some("10.0.0.1".parse().unwrap());
        assert_eq!(ExtendedHandshake::decode(&h.encode()).unwrap(), h);
        for m in [
            MetadataMsg::Request(2),
            MetadataMsg::Reject(1),
            MetadataMsg::Data {
                piece: 0,
                total_size: 5,
                data: b"hello".to_vec(),
            },
        ] {
            assert_eq!(MetadataMsg::decode(&m.encode()).unwrap(), m);
        }
        let p = Pex {
            added: vec!["1.2.3.4:5".parse().unwrap(), "[::1]:7".parse().unwrap()],
            dropped: vec!["5.6.7.8:9".parse().unwrap()],
        };
        assert_eq!(Pex::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn allowed_fast_bep6_vector() {
        // BEP 6's example: 0xAA x 20 info hash, 80.4.4.200, 1313 pieces.
        let ih = InfoHash([0xAA; 20]);
        let s = allowed_fast_set(&ih, Ipv4Addr::new(80, 4, 4, 200), 1313, 7);
        assert_eq!(s, vec![1059, 431, 808, 1217, 287, 376, 1188]);
        let s9 = allowed_fast_set(&ih, Ipv4Addr::new(80, 4, 4, 200), 1313, 9);
        assert_eq!(s9, vec![1059, 431, 808, 1217, 287, 376, 1188, 353, 508]);
    }
}
