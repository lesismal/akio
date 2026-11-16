//! The arpc wire format: a 16-byte little-endian header, the method name, then the payload.
//!
//! ```text
//! [0, 4)  body length: len(method) + len(payload)
//! [4]     reserved (user flag bits)
//! [5]     cmd in the low six bits; stream EOF (bit 6) and stream local (bit 7)
//! [6]     flags: error (0x01), async (0x02)
//! [7]     method length
//! [8, 16) sequence number
//! ```

/// Header length.
pub const HEAD_LEN: usize = 16;
/// Longest method name.
pub const MAX_METHOD_LEN: usize = 127;
/// Longest body accepted unless configured otherwise (as in Go: 64 MiB - 16).
pub const DEFAULT_MAX_BODY: usize = 64 * 1024 * 1024 - 16;

pub(crate) const IDX_CMD: usize = 5;
pub(crate) const IDX_FLAG: usize = 6;
pub(crate) const FLAG_ERROR: u8 = 0x01;
pub(crate) const FLAG_ASYNC: u8 = 0x02;
const STREAM_LOCAL: u8 = 0x80;
const STREAM_EOF: u8 = 0x40;
const CMD_MASK: u8 = !(STREAM_LOCAL | STREAM_EOF);

/// Message commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cmd {
    /// A request expecting a response.
    Request = 1,
    /// The response to a request.
    Response = 2,
    /// A one-way message.
    Notify = 3,
    /// Heartbeat.
    Ping = 4,
    /// Heartbeat answer.
    Pong = 5,
    /// A stream message.
    Stream = 6,
}

impl Cmd {
    fn from_u8(b: u8) -> Option<Cmd> {
        Some(match b {
            1 => Cmd::Request,
            2 => Cmd::Response,
            3 => Cmd::Notify,
            4 => Cmd::Ping,
            5 => Cmd::Pong,
            6 => Cmd::Stream,
            _ => return None,
        })
    }
}

/// A decoded message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Message {
    /// Command.
    pub cmd: Cmd,
    /// Error response.
    pub error: bool,
    /// Part of an asynchronous call.
    pub async_flag: bool,
    /// Stream message sent by the side that opened the stream.
    pub stream_local: bool,
    /// Last stream message of its sender.
    pub stream_eof: bool,
    /// The reserved (user) byte.
    pub reserved: u8,
    /// Method name.
    pub method: String,
    /// Sequence number (stream id for streams).
    pub seq: u64,
    /// Payload.
    pub payload: Vec<u8>,
}

/// Encodes one message.
pub fn encode(
    cmd: Cmd,
    flags: u8,
    stream_local: bool,
    stream_eof: bool,
    method: &str,
    seq: u64,
    payload: &[u8],
) -> Vec<u8> {
    let m = &method.as_bytes()[..method.len().min(MAX_METHOD_LEN)];
    let body = m.len() + payload.len();
    let mut out = Vec::with_capacity(HEAD_LEN + body);
    out.extend_from_slice(&(body as u32).to_le_bytes());
    out.push(0);
    let mut c = cmd as u8;
    if stream_local {
        c |= STREAM_LOCAL;
    }
    if stream_eof {
        c |= STREAM_EOF;
    }
    out.push(c);
    out.push(flags);
    out.push(m.len() as u8);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(m);
    out.extend_from_slice(payload);
    out
}

/// A pong frame.
pub fn pong() -> Vec<u8> {
    let mut f = vec![0u8; HEAD_LEN];
    f[IDX_CMD] = Cmd::Pong as u8;
    f
}

/// A ping frame.
pub fn ping() -> Vec<u8> {
    let mut f = vec![0u8; HEAD_LEN];
    f[IDX_CMD] = Cmd::Ping as u8;
    f
}

/// The connection must be closed: bad framing.
#[derive(Debug, PartialEq, Eq)]
pub struct FrameError(pub &'static str);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "arpc framing error: {}", self.0)
    }
}

impl std::error::Error for FrameError {}

/// Incremental decoder.
///
/// Complete messages are parsed straight from the bytes fed to it; only a message split across
/// reads is gathered in an internal buffer, and only its own bytes are copied there.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    max_body: usize,
}

/// A buffer that held a message larger than this is released once the message is decoded.
const KEEP_BUF: usize = 64 * 1024;

impl Decoder {
    /// A decoder that refuses bodies over `max_body`.
    pub fn new(max_body: usize) -> Decoder {
        Decoder {
            buf: Vec::new(),
            max_body,
        }
    }

    /// Appends `data` and decodes every complete message into `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Message>) -> Result<(), FrameError> {
        self.feed_with(data, |m| out.push(m))
    }

    /// Decodes every complete message in what was buffered plus `data`, calling `f` with each,
    /// and keeps the incomplete tail.
    pub(crate) fn feed_with(
        &mut self,
        mut data: &[u8],
        mut f: impl FnMut(Message),
    ) -> Result<(), FrameError> {
        if !self.buf.is_empty() {
            // Finish the message split across reads, copying only its bytes.
            if self.buf.len() < HEAD_LEN {
                let take = (HEAD_LEN - self.buf.len()).min(data.len());
                self.buf.extend_from_slice(&data[..take]);
                data = &data[take..];
                if self.buf.len() < HEAD_LEN {
                    return Ok(());
                }
            }
            let total = HEAD_LEN + self.body_len(&self.buf)?;
            let take = (total - self.buf.len()).min(data.len());
            self.buf.reserve_exact(total - self.buf.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < total {
                return Ok(());
            }
            decode_one(&self.buf, &mut f)?;
            self.buf.clear();
            if self.buf.capacity() > KEEP_BUF {
                self.buf = Vec::new();
            }
        }
        let mut pos = 0;
        while data.len() - pos >= HEAD_LEN {
            let total = HEAD_LEN + self.body_len(&data[pos..])?;
            if data.len() - pos < total {
                break;
            }
            decode_one(&data[pos..pos + total], &mut f)?;
            pos += total;
        }
        self.buf.extend_from_slice(&data[pos..]);
        Ok(())
    }

    /// The body length in the header at the start of `b`, checked against the limit.
    fn body_len(&self, b: &[u8]) -> Result<usize, FrameError> {
        let body = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if body > self.max_body {
            return Err(FrameError("body too long"));
        }
        Ok(body)
    }
}

/// Decodes one complete message (`frame` is its header and body).
fn decode_one(frame: &[u8], f: &mut impl FnMut(Message)) -> Result<(), FrameError> {
    let h = &frame[..HEAD_LEN];
    let b = &frame[HEAD_LEN..];
    let raw_cmd = h[IDX_CMD];
    let cmd = Cmd::from_u8(raw_cmd & CMD_MASK).ok_or(FrameError("invalid cmd"))?;
    let flags = h[IDX_FLAG];
    let ml = h[7] as usize;
    let seq = u64::from_le_bytes(h[8..16].try_into().expect("8 bytes"));
    let reserved = h[4];
    if matches!(cmd, Cmd::Ping | Cmd::Pong) {
        f(Message {
            cmd,
            error: false,
            async_flag: false,
            stream_local: false,
            stream_eof: false,
            reserved,
            method: String::new(),
            seq,
            payload: Vec::new(),
        });
        return Ok(());
    }
    if ml == 0 || ml > MAX_METHOD_LEN || ml > b.len() {
        // As in Go: a message with an invalid method length is dropped, not fatal.
        return Ok(());
    }
    f(Message {
        cmd,
        error: flags & FLAG_ERROR != 0,
        async_flag: flags & FLAG_ASYNC != 0,
        stream_local: raw_cmd & STREAM_LOCAL != 0,
        stream_eof: raw_cmd & STREAM_EOF != 0,
        reserved,
        method: match std::str::from_utf8(&b[..ml]) {
            Ok(s) => s.to_owned(),
            Err(_) => String::from_utf8_lossy(&b[..ml]).into_owned(),
        },
        seq,
        payload: b[ml..].to_vec(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_go_implementation() {
        let f = encode(Cmd::Request, FLAG_ASYNC, false, false, "/echo", 7, b"hi");
        assert_eq!(&f[0..4], &7u32.to_le_bytes(), "body = method + payload");
        assert_eq!(f[5], 1);
        assert_eq!(f[6], FLAG_ASYNC);
        assert_eq!(f[7], 5);
        assert_eq!(&f[8..16], &7u64.to_le_bytes());
        assert_eq!(&f[16..], b"/echohi");
        let s = encode(Cmd::Stream, 0, true, true, "/s", 3, b"");
        assert_eq!(s[5], 6 | 0x80 | 0x40);
    }

    #[test]
    fn decoder_splits_and_reassembles() {
        let mut wire = encode(Cmd::Request, 0, false, false, "/a", 1, b"one");
        wire.extend(ping());
        wire.extend(encode(Cmd::Stream, 0, true, false, "/s", 9, b"two"));
        for split in 1..wire.len() {
            let mut d = Decoder::new(1 << 20);
            let mut out = Vec::new();
            for piece in wire.chunks(split) {
                d.feed(piece, &mut out).unwrap();
            }
            assert_eq!(out.len(), 3, "split {split}");
            assert_eq!(
                (out[0].method.as_str(), out[0].payload.as_slice()),
                ("/a", &b"one"[..])
            );
            assert_eq!(out[1].cmd, Cmd::Ping);
            assert!(out[2].stream_local && !out[2].stream_eof);
            assert_eq!(out[2].seq, 9);
        }
    }

    #[test]
    fn split_messages_are_gathered_and_big_buffers_released() {
        let big = encode(
            Cmd::Request,
            0,
            false,
            false,
            "/big",
            2,
            &vec![5u8; 200_000],
        );
        let mut wire = encode(Cmd::Notify, 0, false, false, "/n", 1, b"a");
        wire.extend(&big);
        wire.extend(encode(Cmd::Notify, 0, false, false, "/n", 3, b"b"));
        let mut d = Decoder::new(1 << 20);
        let mut out = Vec::new();
        // The first read ends inside the big message's header, the second inside its body.
        let (a, rest) = wire.split_at(17 + 2 + 8);
        let (b, c) = rest.split_at(100_000);
        d.feed(a, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(d.buf.len(), 8, "only the partial header is kept");
        d.feed(b, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        d.feed(c, &mut out).unwrap();
        assert_eq!(out.iter().map(|m| m.seq).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(out[1].payload.len(), 200_000);
        assert!(d.buf.is_empty() && d.buf.capacity() <= KEEP_BUF);
        // A body over the limit is refused as soon as its header is complete.
        let mut d = Decoder::new(1000);
        d.feed(&big[..10], &mut out).unwrap();
        assert_eq!(
            d.feed(&big[10..16], &mut out),
            Err(FrameError("body too long"))
        );
    }

    #[test]
    fn limits() {
        let mut d = Decoder::new(10);
        let f = encode(Cmd::Request, 0, false, false, "/a", 1, &[0; 20]);
        assert!(d.feed(&f, &mut Vec::new()).is_err());
        let mut bad = encode(Cmd::Request, 0, false, false, "/a", 1, b"");
        bad[5] = 9;
        assert!(Decoder::new(100).feed(&bad, &mut Vec::new()).is_err());
        // A method length past the body is dropped quietly.
        let mut odd = encode(Cmd::Request, 0, false, false, "/a", 1, b"");
        odd[7] = 50;
        let mut out = Vec::new();
        Decoder::new(100).feed(&odd, &mut out).unwrap();
        assert!(out.is_empty());
    }
}
