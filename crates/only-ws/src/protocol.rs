//! Sans-io RFC 6455 framing: an incremental decoder that reassembles messages and enforces the
//! protocol's rules, and frame encoders.

use crate::deflate::Inflater;

/// Frame opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    /// Continuation of a fragmented message.
    Continue = 0x0,
    /// UTF-8 text.
    Text = 0x1,
    /// Binary.
    Binary = 0x2,
    /// Close.
    Close = 0x8,
    /// Ping.
    Ping = 0x9,
    /// Pong.
    Pong = 0xA,
}

impl Opcode {
    fn from_u8(b: u8) -> Option<Opcode> {
        Some(match b {
            0x0 => Opcode::Continue,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => return None,
        })
    }

    fn is_control(self) -> bool {
        (self as u8) & 0x8 != 0
    }
}

/// Close status codes used by the protocol itself.
pub mod close {
    /// Normal closure.
    pub const NORMAL: u16 = 1000;
    /// Endpoint going away.
    pub const GOING_AWAY: u16 = 1001;
    /// Protocol error.
    pub const PROTOCOL: u16 = 1002;
    /// Data of a type the endpoint cannot accept.
    pub const UNSUPPORTED: u16 = 1003;
    /// Text data was not valid UTF-8.
    pub const INVALID_DATA: u16 = 1007;
    /// Policy violation.
    pub const POLICY: u16 = 1008;
    /// Message too big.
    pub const TOO_BIG: u16 = 1009;
    /// Unexpected condition on the server.
    pub const INTERNAL: u16 = 1011;
}

/// What the decoder hands out.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A complete text message.
    Text(String),
    /// A complete binary message.
    Binary(Vec<u8>),
    /// A ping (a pong is due).
    Ping(Vec<u8>),
    /// A pong.
    Pong(Vec<u8>),
    /// The peer is closing.
    Close {
        /// Status code, if the frame had one.
        code: Option<u16>,
        /// Reason text.
        reason: String,
    },
}

/// A protocol violation; the connection should be closed with `code`.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProtocolError {
    /// The close status to send.
    pub code: u16,
    /// What went wrong.
    pub reason: &'static str,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "websocket protocol error {}: {}", self.code, self.reason)
    }
}

impl std::error::Error for ProtocolError {}

fn err(code: u16, reason: &'static str) -> ProtocolError {
    ProtocolError { code, reason }
}

/// Which side of the connection the decoder serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Receives masked frames.
    Server,
    /// Receives unmasked frames.
    Client,
}

enum State {
    /// Collecting the frame header.
    Header,
    /// Reading `remaining` payload bytes of the current frame.
    Payload {
        fin: bool,
        opcode: Opcode,
        compressed: bool,
        mask: Option<[u8; 4]>,
        mask_pos: usize,
        remaining: u64,
    },
}

/// A data message being reassembled.
struct Partial {
    text: bool,
    compressed: bool,
    buf: Vec<u8>,
    /// For text: bytes of `buf` already checked to be valid UTF-8.
    valid: usize,
}

/// Incremental frame decoder and message assembler.
pub struct Decoder {
    role: Role,
    max_message: usize,
    state: State,
    hdr: [u8; 14],
    hdr_len: usize,
    partial: Option<Partial>,
    /// Payload of the control frame being read.
    control: Vec<u8>,
    inflater: Option<Inflater>,
    /// Buffer of the compressed bytes of the last message, reused by the next compressed one.
    zbuf: Vec<u8>,
}

/// Largest buffer kept between messages for reuse; larger ones are freed.
const KEEP_BUF: usize = 64 << 10;

/// The most raw (compressed) bytes a message decompressing to at most `max` bytes may take.
/// Deflate never needs more than about 9/8 of the input for any data (fixed Huffman codes of
/// 9 bits per literal; stored blocks add 5 bytes per 64 KiB), so this never rejects a message
/// that would inflate within the limit, while bounding what a peer can make the decoder buffer
/// before any inflating is paid for (RFC 7692 messages fragmented forever without FIN).
pub(crate) fn max_compressed(max: usize) -> usize {
    max.saturating_add(max / 8).saturating_add(1024)
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl Decoder {
    /// A decoder that accepts messages up to `max_message` bytes (after decompression).
    pub fn new(role: Role, max_message: usize, inflater: Option<Inflater>) -> Decoder {
        Decoder {
            role,
            max_message,
            state: State::Header,
            hdr: [0; 14],
            hdr_len: 0,
            partial: None,
            control: Vec::new(),
            inflater,
            zbuf: Vec::new(),
        }
    }

    /// Hands back the payload of a ping or pong event so the next control frame reuses it.
    pub(crate) fn recycle_control(&mut self, mut v: Vec<u8>) {
        if self.control.capacity() == 0 && v.capacity() <= KEEP_BUF {
            v.clear();
            self.control = v;
        }
    }

    /// The per-message buffer limit for raw bytes: compressed messages get some headroom.
    fn raw_limit(&self, compressed: bool) -> usize {
        if compressed {
            max_compressed(self.max_message)
        } else {
            self.max_message
        }
    }

    /// Feeds bytes from the peer; completed messages are appended to `out`. After an `Err` the
    /// decoder must not be used again.
    pub fn decode(&mut self, mut input: &[u8], out: &mut Vec<Event>) -> Result<(), ProtocolError> {
        while !input.is_empty() {
            match &mut self.state {
                State::Header => {
                    // Take header bytes one at a time until the header is complete.
                    let need = self.header_len_needed();
                    let take = (need - self.hdr_len).min(input.len());
                    self.hdr[self.hdr_len..self.hdr_len + take].copy_from_slice(&input[..take]);
                    self.hdr_len += take;
                    input = &input[take..];
                    if self.hdr_len < self.header_len_needed() {
                        continue; // still short (length bytes follow the first two)
                    }
                    self.start_frame(out)?;
                }
                State::Payload {
                    fin,
                    opcode,
                    compressed,
                    mask,
                    mask_pos,
                    remaining,
                } => {
                    let (fin, opcode, compressed, mask, mask_pos, remaining) =
                        (*fin, *opcode, *compressed, *mask, *mask_pos, *remaining);
                    let n = input.len().min(remaining as usize);
                    self.append(opcode, &input[..n], mask, mask_pos)?;
                    input = &input[n..];
                    if n as u64 == remaining {
                        self.state = State::Header;
                        self.hdr_len = 0;
                        self.finish_frame(fin, opcode, compressed, out)?;
                    } else if let State::Payload {
                        mask_pos,
                        remaining,
                        ..
                    } = &mut self.state
                    {
                        *mask_pos += n;
                        *remaining -= n as u64;
                    }
                }
            }
        }
        Ok(())
    }

    /// Total header size for the bytes seen so far (2, then 4 or 10 with an extended length,
    /// plus 4 for the mask).
    fn header_len_needed(&self) -> usize {
        if self.hdr_len < 2 {
            return 2;
        }
        let masked = self.hdr[1] & 0x80 != 0;
        let ext = match self.hdr[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        2 + ext + if masked { 4 } else { 0 }
    }

    fn start_frame(&mut self, out: &mut Vec<Event>) -> Result<(), ProtocolError> {
        let h = self.hdr;
        let fin = h[0] & 0x80 != 0;
        let rsv1 = h[0] & 0x40 != 0;
        if h[0] & 0x30 != 0 {
            return Err(err(close::PROTOCOL, "reserved bits set"));
        }
        let opcode =
            Opcode::from_u8(h[0] & 0x0f).ok_or_else(|| err(close::PROTOCOL, "unknown opcode"))?;
        let masked = h[1] & 0x80 != 0;
        match (self.role, masked) {
            (Role::Server, false) => return Err(err(close::PROTOCOL, "client frame not masked")),
            (Role::Client, true) => return Err(err(close::PROTOCOL, "server frame masked")),
            _ => {}
        }
        let (len, at) = match h[1] & 0x7f {
            126 => (u64::from(u16::from_be_bytes([h[2], h[3]])), 4),
            127 => {
                let l = u64::from_be_bytes(h[2..10].try_into().expect("8 bytes"));
                if l >> 63 != 0 {
                    return Err(err(close::PROTOCOL, "length high bit set"));
                }
                (l, 10)
            }
            n => (u64::from(n), 2),
        };
        // Lengths must be minimally encoded.
        if (h[1] & 0x7f == 126 && len < 126) || (h[1] & 0x7f == 127 && len < 65_536) {
            return Err(err(close::PROTOCOL, "non-minimal length encoding"));
        }
        let mask = if masked {
            Some([h[at], h[at + 1], h[at + 2], h[at + 3]])
        } else {
            None
        };
        if opcode.is_control() {
            if !fin {
                return Err(err(close::PROTOCOL, "fragmented control frame"));
            }
            if len > 125 {
                return Err(err(close::PROTOCOL, "control frame too long"));
            }
            if rsv1 {
                return Err(err(close::PROTOCOL, "compressed control frame"));
            }
            self.control.clear();
        }
        let mut compressed = false;
        match opcode {
            Opcode::Text | Opcode::Binary => {
                if self.partial.is_some() {
                    return Err(err(close::PROTOCOL, "new message inside a fragmented one"));
                }
                if rsv1 {
                    if self.inflater.is_none() {
                        return Err(err(close::PROTOCOL, "RSV1 without permessage-deflate"));
                    }
                    compressed = true;
                }
                let buf = if compressed {
                    // Reuse the compressed buffer of the previous message.
                    std::mem::take(&mut self.zbuf)
                } else if fin && len <= self.max_message as u64 {
                    // The whole message is in this frame: size it once.
                    Vec::with_capacity(len as usize)
                } else {
                    Vec::new()
                };
                self.partial = Some(Partial {
                    text: opcode == Opcode::Text,
                    compressed,
                    buf,
                    valid: 0,
                });
            }
            Opcode::Continue => {
                if rsv1 {
                    return Err(err(close::PROTOCOL, "RSV1 on a continuation frame"));
                }
                match &self.partial {
                    None => return Err(err(close::PROTOCOL, "continuation without a message")),
                    Some(p) => compressed = p.compressed,
                }
            }
            _ => {}
        }
        if len == 0 {
            self.hdr_len = 0;
            self.finish_frame(fin, opcode, compressed, out)?;
            return Ok(());
        }
        // Reject early what can never fit, before buffering it. Compressed messages are bounded
        // too (rule 6): their raw bytes by `max_compressed`, their output by the inflater.
        if !opcode.is_control() {
            let have = self.partial.as_ref().map_or(0, |p| p.buf.len()) as u64;
            if have + len > self.raw_limit(compressed) as u64 {
                return Err(err(close::TOO_BIG, "message too big"));
            }
        }
        self.state = State::Payload {
            fin,
            opcode,
            compressed,
            mask,
            mask_pos: 0,
            remaining: len,
        };
        Ok(())
    }

    /// Unmasks `chunk` into the message (or control payload) buffer and validates text so far.
    fn append(
        &mut self,
        opcode: Opcode,
        chunk: &[u8],
        mask: Option<[u8; 4]>,
        mask_pos: usize,
    ) -> Result<(), ProtocolError> {
        let dst: &mut Vec<u8> = if opcode.is_control() {
            &mut self.control
        } else {
            &mut self.partial.as_mut().expect("partial message").buf
        };
        let start = dst.len();
        dst.extend_from_slice(chunk);
        if let Some(m) = mask {
            unmask(&mut dst[start..], m, mask_pos);
        }
        if !opcode.is_control() {
            let limit = self.raw_limit(self.partial.as_ref().is_some_and(|p| p.compressed));
            let p = self.partial.as_mut().expect("partial message");
            if p.buf.len() > limit {
                return Err(err(close::TOO_BIG, "message too big"));
            }
            // Fail fast on invalid UTF-8, without waiting for the end of the message. Compressed
            // text can only be checked after inflating.
            if p.text && !p.compressed {
                match std::str::from_utf8(&p.buf[p.valid..]) {
                    Ok(_) => p.valid = p.buf.len(),
                    Err(e) if e.error_len().is_none() => p.valid += e.valid_up_to(),
                    Err(_) => return Err(err(close::INVALID_DATA, "invalid UTF-8")),
                }
            }
        }
        Ok(())
    }

    fn finish_frame(
        &mut self,
        fin: bool,
        opcode: Opcode,
        compressed: bool,
        out: &mut Vec<Event>,
    ) -> Result<(), ProtocolError> {
        if opcode.is_control() {
            let payload = std::mem::take(&mut self.control);
            out.push(match opcode {
                Opcode::Ping => Event::Ping(payload),
                Opcode::Pong => Event::Pong(payload),
                _ => parse_close(&payload)?,
            });
            return Ok(());
        }
        if !fin {
            return Ok(());
        }
        let mut p = self.partial.take().expect("partial message");
        if compressed {
            let inf = self.inflater.as_mut().expect("inflater");
            let inflated = inf.inflate(&p.buf, self.max_message).map_err(|e| match e {
                crate::deflate::InflateError::TooBig => err(close::TOO_BIG, "message too big"),
                crate::deflate::InflateError::Corrupt => {
                    err(close::INVALID_DATA, "corrupt compressed data")
                }
            })?;
            let mut raw = std::mem::replace(&mut p.buf, inflated);
            if raw.capacity() <= KEEP_BUF {
                raw.clear();
                self.zbuf = raw;
            }
        }
        if p.text {
            match String::from_utf8(p.buf) {
                Ok(s) => out.push(Event::Text(s)),
                Err(_) => return Err(err(close::INVALID_DATA, "invalid UTF-8")),
            }
        } else {
            out.push(Event::Binary(p.buf));
        }
        Ok(())
    }
}

/// XORs `data` with the mask, where `data[0]` is byte `pos` of the payload.
pub(crate) fn unmask(data: &mut [u8], mask: [u8; 4], pos: usize) {
    let mut m = mask;
    m.rotate_left(pos % 4);
    // Eight bytes at a time, then the tail.
    let m8 = u64::from_ne_bytes([m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3]]);
    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes(c.try_into().expect("8-byte chunk")) ^ m8;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= m[i % 4];
    }
}

fn parse_close(payload: &[u8]) -> Result<Event, ProtocolError> {
    match payload.len() {
        0 => Ok(Event::Close {
            code: None,
            reason: String::new(),
        }),
        1 => Err(err(close::PROTOCOL, "close payload of one byte")),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let valid = matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999);
            if !valid {
                return Err(err(close::PROTOCOL, "invalid close code"));
            }
            let reason = std::str::from_utf8(&payload[2..])
                .map_err(|_| err(close::INVALID_DATA, "close reason is not UTF-8"))?;
            Ok(Event::Close {
                code: Some(code),
                reason: reason.to_owned(),
            })
        }
    }
}

/// Encodes a frame header (with the masking key when `mask` is set) into a stack buffer;
/// returns it and its length.
pub(crate) fn frame_header(
    opcode: Opcode,
    fin: bool,
    rsv1: bool,
    len: usize,
    mask: Option<[u8; 4]>,
) -> ([u8; 14], usize) {
    let mut h = [0u8; 14];
    h[0] = (u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode as u8;
    let m = if mask.is_some() { 0x80 } else { 0 };
    let mut at = match len {
        n if n < 126 => {
            h[1] = m | n as u8;
            2
        }
        n if n < 65_536 => {
            h[1] = m | 126;
            h[2..4].copy_from_slice(&(n as u16).to_be_bytes());
            4
        }
        n => {
            h[1] = m | 127;
            h[2..10].copy_from_slice(&(n as u64).to_be_bytes());
            10
        }
    };
    if let Some(k) = mask {
        h[at..at + 4].copy_from_slice(&k);
        at += 4;
    }
    (h, at)
}

/// Appends one unmasked (server → client) frame to `out`. `rsv1` marks a compressed message.
pub fn encode_frame(opcode: Opcode, fin: bool, rsv1: bool, payload: &[u8], out: &mut Vec<u8>) {
    let (h, n) = frame_header(opcode, fin, rsv1, payload.len(), None);
    out.extend_from_slice(&h[..n]);
    out.extend_from_slice(payload);
}

/// Appends one masked (client → server) frame to `out`, masking the payload with `key`.
pub fn encode_frame_masked(
    opcode: Opcode,
    fin: bool,
    rsv1: bool,
    payload: &[u8],
    key: [u8; 4],
    out: &mut Vec<u8>,
) {
    let (h, n) = frame_header(opcode, fin, rsv1, payload.len(), Some(key));
    out.extend_from_slice(&h[..n]);
    let start = out.len();
    out.extend_from_slice(payload);
    unmask(&mut out[start..], key, 0);
}

/// Encodes a close frame body: status code and reason (truncated to fit a control frame).
pub fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    let mut end = reason.len().min(123);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    p.extend_from_slice(&reason.as_bytes()[..end]);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a masked client frame.
    fn client_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut f = vec![(u8::from(fin) << 7) | opcode];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n if n < 65_536 => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(0x80 | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        f
    }

    fn decode_split(wire: &[u8], split: usize) -> Result<Vec<Event>, ProtocolError> {
        let mut d = Decoder::new(Role::Server, 1 << 20, None);
        let mut out = Vec::new();
        for piece in wire.chunks(split.max(1)) {
            d.decode(piece, &mut out)?;
        }
        Ok(out)
    }

    #[test]
    fn rfc_example_masked_hello() {
        // RFC 6455 5.7: a single-frame masked text message "Hello".
        let wire = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        assert_eq!(
            decode_split(&wire, 64).unwrap(),
            vec![Event::Text("Hello".into())]
        );
    }

    #[test]
    fn messages_survive_any_split_and_size_class() {
        for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let wire = client_frame(2, true, &payload);
            for split in [1usize, 2, 3, 7, 13, 1000, wire.len()] {
                let ev = decode_split(&wire, split).unwrap();
                assert_eq!(
                    ev,
                    vec![Event::Binary(payload.clone())],
                    "len {len} split {split}"
                );
            }
        }
    }

    #[test]
    fn fragmentation_with_interleaved_control_frames() {
        let mut wire = client_frame(1, false, b"Hel");
        wire.extend(client_frame(9, true, b"ping")); // control frames may interleave
        wire.extend(client_frame(0, false, b"lo "));
        wire.extend(client_frame(0, true, b"world"));
        let ev = decode_split(&wire, 5).unwrap();
        assert_eq!(
            ev,
            vec![
                Event::Ping(b"ping".to_vec()),
                Event::Text("Hello world".into())
            ]
        );
    }

    #[test]
    fn utf8_split_across_fragments_is_fine_and_invalid_fails_fast() {
        let euro = "€".as_bytes(); // 3 bytes
        let mut wire = client_frame(1, false, &euro[..1]);
        wire.extend(client_frame(0, false, &euro[1..2]));
        wire.extend(client_frame(0, true, &euro[2..]));
        assert_eq!(
            decode_split(&wire, 64).unwrap(),
            vec![Event::Text("€".into())]
        );
        // An invalid byte in the first fragment fails before the message ends.
        let mut d = Decoder::new(Role::Server, 1 << 20, None);
        let e = d
            .decode(
                &client_frame(1, false, &[0x66, 0xff, 0x6f]),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(e.code, close::INVALID_DATA);
        // Truncated sequence at the end of a message is invalid too.
        let e = decode_split(&client_frame(1, true, &euro[..2]), 64).unwrap_err();
        assert_eq!(e.code, close::INVALID_DATA);
    }

    #[test]
    fn protocol_violations() {
        let bad = |wire: Vec<u8>| decode_split(&wire, 64).unwrap_err().code;
        // Unmasked client frame.
        assert_eq!(bad(vec![0x81, 0x01, b'x']), close::PROTOCOL);
        // RSV bits, unknown opcode.
        assert_eq!(
            bad({
                let mut f = client_frame(1, true, b"x");
                f[0] |= 0x40;
                f
            }),
            close::PROTOCOL
        );
        assert_eq!(bad(client_frame(3, true, b"x")), close::PROTOCOL);
        // Fragmented / oversized control frames.
        assert_eq!(bad(client_frame(9, false, b"x")), close::PROTOCOL);
        assert_eq!(bad(client_frame(9, true, &[0; 126])), close::PROTOCOL);
        // Continuation without a start; a new message inside a fragmented one.
        assert_eq!(bad(client_frame(0, true, b"x")), close::PROTOCOL);
        let mut w = client_frame(1, false, b"a");
        w.extend(client_frame(1, true, b"b"));
        assert_eq!(bad(w), close::PROTOCOL);
        // Non-minimal length.
        let mut f = vec![0x82, 0x80 | 126, 0, 5, 1, 2, 3, 4];
        f.extend([0; 5]);
        assert_eq!(bad(f), close::PROTOCOL);
    }

    #[test]
    fn close_frames() {
        let ok = |payload: &[u8]| decode_split(&client_frame(8, true, payload), 64);
        assert_eq!(
            ok(&[]).unwrap(),
            vec![Event::Close {
                code: None,
                reason: String::new()
            }]
        );
        assert_eq!(
            ok(&close_payload(1000, "bye")).unwrap(),
            vec![Event::Close {
                code: Some(1000),
                reason: "bye".into()
            }]
        );
        assert!(ok(&[0x03]).is_err(), "one-byte payload");
        for code in [999u16, 1004, 1005, 1006, 1012, 1015, 2999, 5000] {
            assert_eq!(
                ok(&close_payload(code, "")).unwrap_err().code,
                close::PROTOCOL,
                "{code}"
            );
        }
        assert!(ok(&close_payload(3000, "")).is_ok());
        assert_eq!(
            ok(&[0x03, 0xe8, 0xff]).unwrap_err().code,
            close::INVALID_DATA
        );
    }

    #[test]
    fn size_limit() {
        let mut d = Decoder::new(Role::Server, 10, None);
        let e = d
            .decode(&client_frame(2, true, &[0; 11]), &mut Vec::new())
            .unwrap_err();
        assert_eq!(e.code, close::TOO_BIG);
        let mut d = Decoder::new(Role::Server, 10, None);
        let mut w = client_frame(2, false, &[0; 6]);
        w.extend(client_frame(0, true, &[0; 6]));
        assert_eq!(
            d.decode(&w, &mut Vec::new()).unwrap_err().code,
            close::TOO_BIG
        );
    }

    /// A compressed message fragmented without FIN forever is cut at the raw-bytes cap (1009)
    /// instead of buffering without limit; before the fix `!compressed` skipped both checks.
    #[test]
    fn compressed_fragments_without_fin_are_bounded() {
        let max = 1000;
        let cap = max_compressed(max);
        let mut d = Decoder::new(Role::Server, max, Some(Inflater::new(false)));
        let mut first = client_frame(2, false, &[0u8; 100]);
        first[0] |= 0x40; // RSV1: compressed
        let mut out = Vec::new();
        d.decode(&first, &mut out).unwrap();
        let mut sent = 100;
        let e = loop {
            match d.decode(&client_frame(0, false, &[0u8; 100]), &mut out) {
                Ok(()) => sent += 100,
                Err(e) => break e,
            }
            assert!(sent <= cap, "buffered {sent} raw bytes past the cap {cap}");
        };
        assert_eq!(e.code, close::TOO_BIG);
        assert!(sent + 100 > cap);
        // One frame that alone passes the cap is refused from its header, before buffering.
        let mut d = Decoder::new(Role::Server, max, Some(Inflater::new(false)));
        let mut f = client_frame(2, false, &vec![0u8; cap + 1]);
        f[0] |= 0x40;
        assert_eq!(
            d.decode(&f[..16], &mut Vec::new()).unwrap_err().code,
            close::TOO_BIG
        );
    }

    /// Incompressible data at exactly the message limit still decodes: the raw cap leaves room
    /// for deflate's expansion. Messages after it reuse the compressed buffer.
    #[test]
    fn compressed_message_at_the_limit_decodes() {
        let max = 70_000;
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..max)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let mut def = crate::deflate::Deflater::new(false, 15);
        let mut d = Decoder::new(Role::Server, max, Some(Inflater::new(false)));
        for msg in [&data[..], &data[..max - 1], b"small"] {
            let z = def.deflate(msg);
            assert!(z.len() <= max_compressed(max));
            let mut f = client_frame(2, true, &z);
            f[0] |= 0x40;
            let mut out = Vec::new();
            d.decode(&f, &mut out).unwrap();
            assert_eq!(out, vec![Event::Binary(msg.to_vec())]);
        }
        // Over the limit by one byte: refused after inflating.
        let mut big = data.clone();
        big.push(1);
        let mut f = client_frame(2, true, &def.deflate(&big));
        f[0] |= 0x40;
        assert_eq!(
            d.decode(&f, &mut Vec::new()).unwrap_err().code,
            close::TOO_BIG
        );
    }

    #[test]
    fn encode_frame_sizes_and_close_payload_truncation() {
        let mut out = Vec::new();
        encode_frame(Opcode::Text, true, false, b"hi", &mut out);
        assert_eq!(out, [0x81, 2, b'h', b'i']);
        let mut out = Vec::new();
        encode_frame(Opcode::Binary, true, false, &[7; 300], &mut out);
        assert_eq!(&out[..4], &[0x82, 126, 1, 44]);
        let mut out = Vec::new();
        encode_frame(Opcode::Binary, true, false, &vec![0; 70_000], &mut out);
        assert_eq!(&out[..2], &[0x82, 127]);
        assert_eq!(u64::from_be_bytes(out[2..10].try_into().unwrap()), 70_000);
        // A long reason is cut at a char boundary so the control frame stays <= 125 bytes.
        let p = close_payload(1000, &"é".repeat(100));
        assert!(p.len() <= 125);
        assert!(std::str::from_utf8(&p[2..]).is_ok());
    }

    #[test]
    fn masked_frames_decode_on_the_server_side() {
        for len in [0usize, 5, 125, 126, 65_535, 65_536, 70_001] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let mut wire = Vec::new();
            encode_frame_masked(
                Opcode::Binary,
                true,
                false,
                &payload,
                [9, 8, 7, 6],
                &mut wire,
            );
            assert_eq!(
                decode_split(&wire, 1000).unwrap(),
                vec![Event::Binary(payload)]
            );
        }
        // And unmasked server frames decode on the client side.
        let mut wire = Vec::new();
        encode_frame(Opcode::Text, true, false, b"hi", &mut wire);
        let mut d = Decoder::new(Role::Client, 1 << 20, None);
        let mut out = Vec::new();
        d.decode(&wire, &mut out).unwrap();
        assert_eq!(out, vec![Event::Text("hi".into())]);
        let mut wire = Vec::new();
        encode_frame_masked(Opcode::Text, true, false, b"hi", [1, 2, 3, 4], &mut wire);
        let mut d = Decoder::new(Role::Client, 1 << 20, None);
        assert_eq!(d.decode(&wire, &mut out).unwrap_err().code, close::PROTOCOL);
    }

    #[test]
    fn unmask_matches_the_naive_loop_at_every_offset() {
        let data: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        let mask = [1, 2, 3, 4];
        for pos in 0..8 {
            let mut a = data.clone();
            unmask(&mut a, mask, pos);
            let b: Vec<u8> = data
                .iter()
                .enumerate()
                .map(|(i, x)| x ^ mask[(i + pos) % 4])
                .collect();
            assert_eq!(a, b, "pos {pos}");
        }
    }
}
