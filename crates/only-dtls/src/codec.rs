//! Byte reading and writing for the TLS presentation language.

use crate::Error;

/// A cursor over a byte slice; every read fails with `decode_error` when the input is short.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.buf.len() < n {
            return Err(Error::decode("truncated message"));
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, Error> {
        let b = self.bytes(3)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// The unread rest.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    pub(crate) fn u48(&mut self) -> Result<u64, Error> {
        let b = self.bytes(6)?;
        Ok(b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }

    pub(crate) fn vec8(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u8()?;
        self.bytes(usize::from(n))
    }

    pub(crate) fn vec16(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }

    pub(crate) fn vec24(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u24()?;
        self.bytes(n)
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::decode("trailing bytes in message"))
        }
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
}

pub(crate) fn put_u48(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes()[2..]);
}

/// `data` with a one-byte length prefix (`data.len() <= 255`, checked by the callers).
pub(crate) fn put_vec8(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= 0xff);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// `data` with a two-byte length prefix (`data.len() <= 65535`, checked by the callers).
pub(crate) fn put_vec16(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= 0xffff);
    put_u16(out, data.len() as u16);
    out.extend_from_slice(data);
}

pub(crate) fn put_vec24(out: &mut Vec<u8>, data: &[u8]) {
    put_u24(out, data.len());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut v = Vec::new();
        put_u16(&mut v, 0x1234);
        put_u24(&mut v, 0x56789a);
        put_u48(&mut v, 0x0102_0304_0506);
        put_vec8(&mut v, b"ab");
        put_vec16(&mut v, b"cde");
        put_vec24(&mut v, b"f");
        let mut r = Reader::new(&v);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u24().unwrap(), 0x56789a);
        assert_eq!(r.u48().unwrap(), 0x0102_0304_0506);
        assert_eq!(r.vec8().unwrap(), b"ab");
        assert_eq!(r.vec16().unwrap(), b"cde");
        assert_eq!(r.vec24().unwrap(), b"f");
        r.finish().unwrap();
        assert!(r.u8().is_err());
    }
}
