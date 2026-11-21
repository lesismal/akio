//! STUN and TURN over a byte stream (TCP or TLS, RFC 8656 section 3.1 and 12.5): the stream
//! carries STUN messages and ChannelData messages back to back, each delimited by its own
//! length field, ChannelData padded to a multiple of four bytes.
//!
//! [`frame_len`] measures the message at the head of a buffer; [`FrameReader`] cuts a stream
//! into messages, handing complete ones out without copying when they arrive whole and keeping
//! at most one partial message (bounded by [`MAX_FRAME`]) between reads.

use std::fmt;

use crate::stun::{HEADER_LEN, MAGIC_COOKIE};

/// The longest message on a stream: a STUN header and 65532 bytes of attributes (ChannelData
/// is at most 4 + 65535 bytes and 1 byte of padding).
pub const MAX_FRAME: usize = HEADER_LEN + 0xfffc;

/// The stream does not carry STUN or ChannelData: the connection should be closed (there is no
/// way to find the next message boundary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The first byte of a message is neither STUN (`0b00`) nor ChannelData (`0b01`), or a
    /// STUN header lacks the magic cookie or has a length that is not a multiple of four.
    NotTurn,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("turn stream: neither STUN nor ChannelData")
    }
}

impl std::error::Error for FrameError {}

/// The length of the message at the head of `buf`, padding included: `Ok(None)` until enough
/// bytes are there to tell (4 for ChannelData, 8 for STUN, so that the magic cookie is checked).
pub fn frame_len(buf: &[u8]) -> Result<Option<usize>, FrameError> {
    let Some(&b0) = buf.first() else {
        return Ok(None);
    };
    match b0 >> 6 {
        0 => {
            if buf.len() < 8 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
            if len % 4 != 0 || u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE
            {
                return Err(FrameError::NotTurn);
            }
            Ok(Some(HEADER_LEN + len))
        }
        1 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
            Ok(Some((4 + len + 3) & !3))
        }
        _ => Err(FrameError::NotTurn),
    }
}

/// Zero bytes to pad a ChannelData message of `len` bytes (header included) to a multiple of
/// four, as streams require.
pub fn channel_data_padding(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// Cuts a TURN stream into messages. Holds at most one incomplete message.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl fmt::Debug for FrameReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameReader")
            .field("buffered", &self.buf.len())
            .finish()
    }
}

impl FrameReader {
    /// An empty reader.
    pub fn new() -> FrameReader {
        FrameReader::default()
    }

    /// Bytes held from an incomplete message.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Feeds bytes read from the stream; `f` gets every complete message (with its padding), in
    /// order. On an error the stream is unusable (messages before the bad one were delivered).
    pub fn push(&mut self, data: &[u8], mut f: impl FnMut(&[u8])) -> Result<(), FrameError> {
        self.push_until(data, |m| {
            f(m);
            true
        })
        .map(drop)
    }

    /// [`push`](Self::push) that stops after the message for which `f` returns false and
    /// returns the bytes of `data` that follow it, untouched (nothing is held then): a
    /// ConnectionBind turns the stream into raw data (RFC 6062). Empty when every byte was
    /// taken.
    pub(crate) fn push_until<'d>(
        &mut self,
        mut data: &'d [u8],
        mut f: impl FnMut(&[u8]) -> bool,
    ) -> Result<&'d [u8], FrameError> {
        // Finish the message carried over from the last read.
        while !self.buf.is_empty() {
            // Enough of the header to know the length (4 bytes for ChannelData, 8 for STUN:
            // never past the end of the shortest message, 4 bytes of empty ChannelData).
            let Some(need) = frame_len(&self.buf)? else {
                let hdr = if self.buf[0] >> 6 == 1 { 4 } else { 8 };
                let take = data.len().min(hdr - self.buf.len());
                if take == 0 {
                    return Ok(&[]);
                }
                self.buf.extend_from_slice(&data[..take]);
                data = &data[take..];
                continue;
            };
            let take = (need - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < need {
                return Ok(&[]);
            }
            let go = f(&self.buf);
            self.buf.clear();
            if !go {
                return Ok(data);
            }
        }
        // Whole messages straight from the read buffer.
        loop {
            match frame_len(data)? {
                Some(n) if n <= data.len() => {
                    let go = f(&data[..n]);
                    data = &data[n..];
                    if !go {
                        return Ok(data);
                    }
                }
                _ => break,
            }
        }
        if !data.is_empty() {
            if self.buf.capacity() == 0 {
                self.buf.reserve(2048.min(MAX_FRAME));
            }
            self.buf.extend_from_slice(data);
        }
        Ok(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{Class, MessageBuilder, Method, transaction_id};

    fn channel(len: usize) -> Vec<u8> {
        let mut v = vec![0x40, 0x01];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.extend(std::iter::repeat_n(7u8, len));
        v.extend(std::iter::repeat_n(0u8, channel_data_padding(4 + len)));
        v
    }

    #[test]
    fn lengths() {
        let stun = MessageBuilder::new(Method::BINDING, Class::Request, transaction_id()).build();
        assert_eq!(frame_len(&stun), Ok(Some(stun.len())));
        assert_eq!(frame_len(&stun[..7]), Ok(None));
        assert_eq!(frame_len(&[]), Ok(None));
        assert_eq!(frame_len(&channel(5)), Ok(Some(12)));
        assert_eq!(frame_len(&channel(8)), Ok(Some(12)));
        assert_eq!(frame_len(&channel(0)), Ok(Some(4)));
        assert_eq!(frame_len(&[0x40, 1, 0]), Ok(None));
        assert_eq!(frame_len(&[0x80, 0, 0, 0]), Err(FrameError::NotTurn));
        // (Text starting with 0x40..=0x7f reads as ChannelData: only the first byte is checked.)
        assert_eq!(
            frame_len(b"\x16\x03\x01\x02\x00\x01\x00\x01"),
            Err(FrameError::NotTurn)
        );
        let mut bad = stun.clone();
        bad[4] ^= 1;
        assert_eq!(frame_len(&bad), Err(FrameError::NotTurn));
        bad = stun;
        bad[3] = 2;
        assert_eq!(frame_len(&bad), Err(FrameError::NotTurn));
        assert_eq!(frame_len(&channel(0xffff)), Ok(Some(0x10004)));
        assert_eq!(channel(0xffff).len(), 0x10004);
        let mut big = vec![0u8, 1, 0xff, 0xfc];
        big.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert_eq!(frame_len(&big), Ok(Some(MAX_FRAME)));
        assert_eq!(channel_data_padding(4), 0);
        assert_eq!(channel_data_padding(5), 3);
    }

    /// Every way of cutting a stream of messages gives the same messages back.
    #[test]
    fn reader_split_anywhere() {
        let stun = MessageBuilder::new(Method::BINDING, Class::Request, transaction_id())
            .attr(0x8022, b"x")
            .build();
        let msgs = vec![channel(3), stun.clone(), channel(0), channel(9), stun];
        let stream: Vec<u8> = msgs.concat();
        for step in [1, 2, 3, 5, 7, 8, 13, stream.len()] {
            let mut r = FrameReader::new();
            let mut got = Vec::new();
            for chunk in stream.chunks(step) {
                r.push(chunk, |m| got.push(m.to_vec())).unwrap();
            }
            assert_eq!(got, msgs, "step {step}");
            assert_eq!(r.buffered(), 0);
        }
        // Two cuts at once: a header split and a message split.
        let mut r = FrameReader::new();
        let mut got = Vec::new();
        r.push(&stream[..2], |m| got.push(m.to_vec())).unwrap();
        r.push(&stream[2..30], |m| got.push(m.to_vec())).unwrap();
        r.push(&stream[30..], |m| got.push(m.to_vec())).unwrap();
        assert_eq!(got, msgs);
    }

    /// `push_until` hands back what follows the message it stopped at, whether that message
    /// was held from an earlier read or whole in this one.
    #[test]
    fn reader_stops_and_returns_the_rest() {
        let stun = MessageBuilder::new(Method::BINDING, Class::Request, transaction_id()).build();
        let mut stream = [channel(3), stun.clone()].concat();
        stream.extend_from_slice(b"\xffraw bytes");
        for cut in 1..stream.len() {
            let mut r = FrameReader::new();
            let mut got = Vec::new();
            let mut rest = Vec::new();
            for part in [&stream[..cut], &stream[cut..]] {
                if !rest.is_empty() || got.len() == 2 {
                    rest.extend_from_slice(part);
                    continue;
                }
                let tail = r
                    .push_until(part, |m| {
                        got.push(m.to_vec());
                        m != stun.as_slice()
                    })
                    .unwrap();
                rest.extend_from_slice(tail);
            }
            assert_eq!(got, vec![channel(3), stun.clone()], "cut {cut}");
            assert_eq!(rest, b"\xffraw bytes", "cut {cut}");
            assert_eq!(r.buffered(), 0);
        }
    }

    #[test]
    fn reader_errors_and_bounds() {
        let mut r = FrameReader::new();
        let mut n = 0;
        let mut s = channel(2);
        s.extend_from_slice(b"\xffjunk");
        assert_eq!(r.push(&s, |_| n += 1), Err(FrameError::NotTurn));
        assert_eq!(n, 1);
        // The largest message is held, never more.
        let big = channel(0xffff);
        let n = big.len();
        let mut r = FrameReader::new();
        let mut got = 0;
        r.push(&big[..n - 1], |_| got += 1).unwrap();
        assert_eq!(r.buffered(), n - 1);
        r.push(&big[n - 1..], |m| got += m.len()).unwrap();
        assert_eq!((got, r.buffered()), (n, 0));
    }
}
