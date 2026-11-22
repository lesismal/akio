//! RFC 4571 framing for ICE-TCP (RFC 6544 §3): every STUN message and every datagram of the
//! application (DTLS, SRTP) is sent on the connection as a 16-bit big-endian length and the
//! bytes.

use std::fmt;

/// The longest frame (the 16-bit length).
pub const MAX_FRAME: usize = 0xffff;

/// Frames `data` for the connection: length then bytes. `None` when it is longer than
/// [`MAX_FRAME`].
pub fn frame(data: &[u8]) -> Option<Vec<u8>> {
    let n = u16::try_from(data.len()).ok()?;
    let mut v = Vec::with_capacity(2 + data.len());
    v.extend_from_slice(&n.to_be_bytes());
    v.extend_from_slice(data);
    Some(v)
}

/// Cuts a connection's byte stream into frames. Holds at most one incomplete frame (2 +
/// [`MAX_FRAME`] bytes).
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

    /// Bytes held from an incomplete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Feeds bytes read from the connection; `f` gets each complete frame's payload in order,
    /// and returns `false` to stop (the rest is dropped: the caller closes the connection).
    pub fn push(&mut self, mut data: &[u8], mut f: impl FnMut(&[u8]) -> bool) {
        while !self.buf.is_empty() {
            if self.buf.len() < 2 {
                let take = (2 - self.buf.len()).min(data.len());
                self.buf.extend_from_slice(&data[..take]);
                data = &data[take..];
                if self.buf.len() < 2 {
                    return;
                }
            }
            let need = 2 + usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
            let take = (need - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < need {
                return;
            }
            let go = f(&self.buf[2..]);
            self.buf.clear();
            if !go {
                return;
            }
        }
        while data.len() >= 2 {
            let n = 2 + usize::from(u16::from_be_bytes([data[0], data[1]]));
            if data.len() < n {
                break;
            }
            if !f(&data[2..n]) {
                return;
            }
            data = &data[n..];
        }
        self.buf.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_anywhere() {
        let frames: Vec<Vec<u8>> = vec![vec![], vec![1], vec![2; 300], vec![3; 2], vec![4; 0xffff]];
        let stream: Vec<u8> = frames.iter().flat_map(|f| frame(f).unwrap()).collect();
        for step in [1, 2, 3, 7, 1000, stream.len()] {
            let mut r = FrameReader::new();
            let mut got = Vec::new();
            for c in stream.chunks(step) {
                r.push(c, |f| {
                    got.push(f.to_vec());
                    true
                });
                assert!(r.buffered() <= 2 + MAX_FRAME);
            }
            assert_eq!(got, frames, "step {step}");
            assert_eq!(r.buffered(), 0);
        }
        assert!(frame(&vec![0; 0x10000]).is_none());
    }

    #[test]
    fn stop_early() {
        let stream: Vec<u8> = [frame(b"a").unwrap(), frame(b"b").unwrap()].concat();
        let mut r = FrameReader::new();
        let mut n = 0;
        r.push(&stream, |_| {
            n += 1;
            false
        });
        assert_eq!(n, 1);
    }
}
