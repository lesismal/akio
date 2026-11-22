//! HTTP/3 framing (RFC 9114 §7) and QUIC variable-length integers.

pub(crate) const DATA: u64 = 0x0;
pub(crate) const HEADERS: u64 = 0x1;
pub(crate) const CANCEL_PUSH: u64 = 0x3;
pub(crate) const SETTINGS: u64 = 0x4;
pub(crate) const PUSH_PROMISE: u64 = 0x5;
pub(crate) const GOAWAY: u64 = 0x7;
pub(crate) const MAX_PUSH_ID: u64 = 0xd;

/// Stream types of unidirectional streams.
pub(crate) const STREAM_CONTROL: u64 = 0x0;
pub(crate) const STREAM_PUSH: u64 = 0x1;
pub(crate) const STREAM_QPACK_ENCODER: u64 = 0x2;
pub(crate) const STREAM_QPACK_DECODER: u64 = 0x3;

pub(crate) const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
pub(crate) const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
pub(crate) const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
/// RFC 8441 / RFC 9220: extended CONNECT allowed.
pub(crate) const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;

/// HTTP/3 error codes.
pub mod code {
    /// No error.
    pub const NO_ERROR: u32 = 0x100;
    /// Generic protocol error.
    pub const GENERAL_PROTOCOL_ERROR: u32 = 0x101;
    /// Internal error.
    pub const INTERNAL_ERROR: u32 = 0x102;
    /// A stream of a type not allowed, or a second critical stream.
    pub const STREAM_CREATION_ERROR: u32 = 0x103;
    /// A critical stream closed.
    pub const CLOSED_CRITICAL_STREAM: u32 = 0x104;
    /// A frame not allowed where it came.
    pub const FRAME_UNEXPECTED: u32 = 0x105;
    /// A malformed frame.
    pub const FRAME_ERROR: u32 = 0x106;
    /// The peer is generating too much load.
    pub const EXCESSIVE_LOAD: u32 = 0x107;
    /// Bad identifier.
    pub const ID_ERROR: u32 = 0x108;
    /// Bad SETTINGS.
    pub const SETTINGS_ERROR: u32 = 0x109;
    /// No SETTINGS first on the control stream.
    pub const MISSING_SETTINGS: u32 = 0x10a;
    /// The request was not processed.
    pub const REQUEST_REJECTED: u32 = 0x10b;
    /// The request was cancelled.
    pub const REQUEST_CANCELLED: u32 = 0x10c;
    /// The request stream ended early.
    pub const REQUEST_INCOMPLETE: u32 = 0x10d;
    /// A malformed message.
    pub const MESSAGE_ERROR: u32 = 0x10e;
    /// QPACK could not decode a field section.
    pub const QPACK_DECOMPRESSION_FAILED: u32 = 0x200;
    /// Bad QPACK encoder stream instructions.
    pub const QPACK_ENCODER_STREAM_ERROR: u32 = 0x201;
    /// Bad QPACK decoder stream instructions.
    pub const QPACK_DECODER_STREAM_ERROR: u32 = 0x202;
}

pub(crate) fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// A varint at the start of `b` and its length; `None` if incomplete.
#[inline]
pub(crate) fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let n = 1usize << (first >> 6);
    let raw = b.get(..n)?;
    let mut v = u64::from(first & 0x3f);
    for &x in &raw[1..] {
        v = (v << 8) | u64::from(x);
    }
    Some((v, n))
}

/// A whole frame of type `ty` at the start of `b`: its payload and the bytes after it.
#[inline]
pub(crate) fn frame_at(b: &[u8], ty: u64) -> Option<(&[u8], &[u8])> {
    let (t, n) = get_varint(b)?;
    if t != ty {
        return None;
    }
    let (len, m) = get_varint(&b[n..])?;
    let rest = &b[n + m..];
    let len = usize::try_from(len).ok().filter(|&l| l <= rest.len())?;
    Some(rest.split_at(len))
}

/// Appends a frame.
pub(crate) fn put_frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    put_varint(out, ty);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Starts a frame of type `ty` whose payload the caller appends next; returns where its length
/// goes, for [`end_frame`]. Encoding straight into the output saves a buffer and a copy.
pub(crate) fn begin_frame(out: &mut Vec<u8>, ty: u64) -> usize {
    put_varint(out, ty);
    out.push(0);
    out.len() - 1
}

/// Fills in the length of a frame started with [`begin_frame`] at `at`: in place when the
/// payload is under 64 bytes, else by widening the placeholder (a short move of the payload).
pub(crate) fn end_frame(out: &mut Vec<u8>, at: usize) {
    let len = out.len() - at - 1;
    if len < 1 << 6 {
        out[at] = len as u8;
    } else {
        // Widen the one-byte placeholder in place (a `splice` allocated twice per frame).
        let len = len as u64;
        let (v, n) = if len < 1 << 14 {
            ((len | 0x4000) << 48, 2)
        } else if len < 1 << 30 {
            ((len | 0x8000_0000) << 32, 4)
        } else {
            (len | 0xc000_0000_0000_0000, 8)
        };
        let v = v.to_be_bytes();
        let old = out.len();
        out.resize(old + n - 1, 0);
        out.copy_within(at + 1..old, at + n);
        out[at..at + n].copy_from_slice(&v[..n]);
    }
}

/// The type, header length and frame length of the frame at the start of `r`; `Ok(None)` if
/// incomplete, `Err(len)` if it announces more than `max` payload bytes.
fn next_frame(r: &[u8], max: u64) -> Result<Option<(u64, usize, usize)>, u64> {
    let Some((ty, a)) = get_varint(r) else {
        return Ok(None);
    };
    let Some((len, b)) = get_varint(&r[a..]) else {
        return Ok(None);
    };
    if len > max {
        return Err(len);
    }
    let end = a + b + len as usize;
    if r.len() < end {
        return Ok(None);
    }
    Ok(Some((ty, a + b, end)))
}

/// A piece of a request stream read by [`StreamReader::feed_stream`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Piece<'a> {
    /// A whole HEADERS frame's payload.
    Headers(&'a [u8]),
    /// DATA payload bytes as they arrive: a frame may come in several pieces, an empty one in
    /// none.
    Data(&'a [u8]),
    /// The header of a frame of another type; its payload is skipped.
    Skip(u64),
}

/// Bytes of a stream, split into frames as they complete.
#[derive(Default)]
pub(crate) struct Reader {
    buf: Vec<u8>,
    pos: usize,
}

/// A [`Reader`] that streams DATA payloads ([`StreamReader::feed_stream`]); a separate type so
/// streams read whole frames only (responses, control streams) stay small.
#[derive(Default)]
pub(crate) struct StreamReader {
    r: Reader,
    /// Payload bytes left of the current DATA (or skipped) frame.
    left: u64,
    skip: bool,
}

impl From<Reader> for StreamReader {
    /// Continues where `r` stopped (at a frame boundary).
    fn from(r: Reader) -> StreamReader {
        StreamReader {
            r,
            left: 0,
            skip: false,
        }
    }
}

/// Splits `b` into pieces for [`StreamReader::feed_stream`]; the bytes taken (an incomplete frame
/// header or HEADERS frame is left).
#[inline]
fn pieces<E, T: FnMut() -> E, F: FnMut(Piece<'_>) -> Result<(), E>>(
    left: &mut u64,
    skip: &mut bool,
    b: &[u8],
    max: u64,
    too_large: &mut T,
    f: &mut F,
) -> Result<usize, E> {
    let mut pos = 0;
    loop {
        if *left > 0 {
            let n = (*left).min((b.len() - pos) as u64) as usize;
            if n == 0 {
                return Ok(pos);
            }
            if !*skip {
                f(Piece::Data(&b[pos..pos + n]))?;
            }
            pos += n;
            *left -= n as u64;
            continue;
        }
        let r = &b[pos..];
        let Some((ty, a)) = get_varint(r) else {
            return Ok(pos);
        };
        let Some((len, c)) = get_varint(&r[a..]) else {
            return Ok(pos);
        };
        match ty {
            DATA => {
                pos += a + c;
                (*left, *skip) = (len, false);
            }
            HEADERS => {
                if len > max {
                    return Err(too_large());
                }
                let end = a + c + len as usize;
                let Some(p) = r.get(a + c..end) else {
                    return Ok(pos);
                };
                f(Piece::Headers(p))?;
                pos += end;
            }
            _ => {
                f(Piece::Skip(ty))?;
                pos += a + c;
                (*left, *skip) = (len, true);
            }
        }
    }
}

impl Reader {
    /// Nothing buffered.
    pub(crate) fn idle(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn push(&mut self, data: &[u8]) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Bytes not yet taken.
    pub(crate) fn rest(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Takes a varint off the front.
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let (v, n) = get_varint(self.rest())?;
        self.pos += n;
        Some(v)
    }

    /// The next complete frame; `Err(len)` with the length of a frame header announcing more
    /// than `max` payload bytes.
    pub(crate) fn frame(&mut self, max: u64) -> Result<Option<(u64, Vec<u8>)>, u64> {
        let r = self.rest();
        let Some((ty, h, end)) = next_frame(r, max)? else {
            return Ok(None);
        };
        let payload = r[h..end].to_vec();
        self.pos += end;
        Ok(Some((ty, payload)))
    }

    /// Takes `data` and calls `f` with every frame that completes (type, payload), stopping at
    /// the first `Err`; a frame announcing more than `max` bytes is `Err(too_large)`. When
    /// nothing is buffered the frames are read straight from `data` and only a trailing partial
    /// frame is copied, so a request or response that arrives whole is never copied.
    pub(crate) fn feed<E>(
        &mut self,
        data: &[u8],
        max: u64,
        too_large: impl FnOnce() -> E,
        mut f: impl FnMut(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            let mut pos = 0;
            loop {
                match next_frame(&data[pos..], max) {
                    Ok(Some((ty, h, end))) => {
                        f(ty, &data[pos + h..pos + end])?;
                        pos += end;
                    }
                    Ok(None) => break,
                    Err(_) => return Err(too_large()),
                }
            }
            self.buf.extend_from_slice(&data[pos..]);
            return Ok(());
        }
        self.push(data);
        loop {
            match next_frame(&self.buf[self.pos..], max) {
                Ok(Some((ty, h, end))) => {
                    let at = self.pos;
                    self.pos += end;
                    f(ty, &self.buf[at + h..at + end])?;
                }
                Ok(None) => return Ok(()),
                Err(_) => return Err(too_large()),
            }
        }
    }
}

impl StreamReader {
    /// Nothing buffered and no frame in progress.
    pub(crate) fn idle(&self) -> bool {
        self.r.pos == self.r.buf.len() && self.left == 0
    }

    /// Takes `data` and calls `f` with its pieces: whole HEADERS frames (`Err(too_large)` for one
    /// over `max` bytes), DATA payloads as they arrive (never buffered), and the types of other
    /// frames (skipped). Only an incomplete frame header or HEADERS frame is kept for the next
    /// call, so a large body streams through without being held.
    pub(crate) fn feed_stream<E>(
        &mut self,
        data: &[u8],
        max: u64,
        mut too_large: impl FnMut() -> E,
        mut f: impl FnMut(Piece<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let StreamReader { r, left, skip } = self;
        if r.pos == r.buf.len() {
            r.buf.clear();
            r.pos = 0;
            let n = pieces(left, skip, data, max, &mut too_large, &mut f)?;
            r.buf.extend_from_slice(&data[n..]);
            return Ok(());
        }
        r.push(data);
        let n = pieces(left, skip, &r.buf[r.pos..], max, &mut too_large, &mut f)?;
        r.pos += n;
        Ok(())
    }

    /// [`Reader::feed`] (whole frames), when nothing is streaming.
    pub(crate) fn feed<E>(
        &mut self,
        data: &[u8],
        max: u64,
        too_large: impl FnOnce() -> E,
        f: impl FnMut(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.r.feed(data, max, too_large, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_and_frames() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(get_varint(&b), Some((v, b.len())));
        }
        let mut wire = Vec::new();
        put_frame(&mut wire, HEADERS, b"abc");
        put_frame(&mut wire, 0x21, b"");
        put_frame(&mut wire, DATA, &[7; 300]);
        let mut r = Reader::default();
        let mut got = Vec::new();
        for ch in wire.chunks(7) {
            r.push(ch);
            while let Some(f) = r.frame(1000).unwrap() {
                got.push(f);
            }
        }
        assert_eq!(got.len(), 3);
        assert_eq!(got[2].1.len(), 300);
        let mut r = Reader::default();
        r.push(&wire[5..]);
        let _ = r.frame(10);
        let mut r = Reader::default();
        let mut big = Vec::new();
        put_varint(&mut big, DATA);
        put_varint(&mut big, 5000);
        r.push(&big);
        assert_eq!(r.frame(1000), Err(5000));
        // `feed` sees the same frames whole or in pieces.
        for size in [1, 3, 7, 64, wire.len()] {
            let mut r = Reader::default();
            let mut fed = Vec::new();
            for ch in wire.chunks(size) {
                r.feed(
                    ch,
                    1000,
                    || (),
                    |t, p| {
                        fed.push((t, p.to_vec()));
                        Ok(())
                    },
                )
                .unwrap();
            }
            assert_eq!(fed, got);
        }
        let mut r = Reader::default();
        assert_eq!(r.feed(&big, 1000, || 1, |_, _| Ok(())), Err(1));
        // `feed_stream`: the same HEADERS, DATA bytes and skipped types whatever the splits,
        // and a large DATA frame is never buffered.
        let mut wire = Vec::new();
        put_frame(&mut wire, HEADERS, b"head");
        put_frame(&mut wire, 0x21, &[1; 100]);
        put_frame(&mut wire, DATA, &[]);
        put_frame(&mut wire, DATA, &[7; 5000]);
        put_frame(&mut wire, HEADERS, b"trailers");
        let run = |size: usize| {
            let mut r = StreamReader::default();
            let (mut heads, mut data, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
            for ch in wire.chunks(size) {
                r.feed_stream(
                    ch,
                    100,
                    || (),
                    |p| {
                        match p {
                            Piece::Headers(h) => heads.push(h.to_vec()),
                            Piece::Data(d) => data.extend_from_slice(d),
                            Piece::Skip(t) => skipped.push(t),
                        }
                        Ok(())
                    },
                )
                .unwrap();
                assert!(
                    r.r.buf.len() - r.r.pos < 64,
                    "buffered {}",
                    r.r.buf.len() - r.r.pos
                );
            }
            (heads, data, skipped)
        };
        let whole = run(wire.len());
        assert_eq!(whole.0, [b"head".to_vec(), b"trailers".to_vec()]);
        assert_eq!((whole.1.len(), &whole.2[..]), (5000, &[0x21][..]));
        for size in [1, 2, 3, 7, 100, 1000] {
            assert_eq!(run(size), whole, "{size}");
        }
        let mut big = Vec::new();
        put_varint(&mut big, HEADERS);
        put_varint(&mut big, 101);
        assert_eq!(
            StreamReader::default().feed_stream(&big, 100, || 1, |_| Ok(())),
            Err(1)
        );
        // Lengths of every varint size are filled in by `end_frame`.
        for n in [0usize, 63, 64, 16383, 16384] {
            let mut out = vec![9];
            let at = begin_frame(&mut out, HEADERS);
            out.extend(std::iter::repeat_n(5u8, n));
            end_frame(&mut out, at);
            let mut want = vec![9];
            put_frame(&mut want, HEADERS, &vec![5u8; n]);
            assert_eq!(out, want);
        }
    }
}
