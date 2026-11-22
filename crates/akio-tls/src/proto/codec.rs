//! Big-endian TLS presentation-language encoding: integers and length-prefixed vectors.

use super::alert::{Alert, Fatal};

/// A bounds-checked cursor over received bytes; every failure is a `decode_error`.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

pub(crate) type DResult<T> = Result<T, Fatal>;

fn short() -> Fatal {
    Fatal::new(Alert::DecodeError, "truncated message")
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    pub(crate) fn bytes(&mut self, n: usize) -> DResult<&'a [u8]> {
        if self.buf.len() < n {
            return Err(short());
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> DResult<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> DResult<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> DResult<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> DResult<usize> {
        let b = self.bytes(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    pub(crate) fn u32(&mut self) -> DResult<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A vector with a one-byte length.
    pub(crate) fn vec8(&mut self) -> DResult<&'a [u8]> {
        let n = self.u8()?;
        self.bytes(usize::from(n))
    }

    /// A vector with a two-byte length.
    pub(crate) fn vec16(&mut self) -> DResult<&'a [u8]> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }

    /// A vector with a three-byte length.
    pub(crate) fn vec24(&mut self) -> DResult<&'a [u8]> {
        let n = self.u24()?;
        self.bytes(n)
    }

    pub(crate) fn sub8(&mut self) -> DResult<Reader<'a>> {
        Ok(Reader::new(self.vec8()?))
    }

    pub(crate) fn sub16(&mut self) -> DResult<Reader<'a>> {
        Ok(Reader::new(self.vec16()?))
    }

    pub(crate) fn sub24(&mut self) -> DResult<Reader<'a>> {
        Ok(Reader::new(self.vec24()?))
    }

    /// Fails unless everything was consumed.
    pub(crate) fn finish(&self) -> DResult<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Fatal::new(Alert::DecodeError, "trailing bytes"))
        }
    }

    /// A list of `u16`s in a two-byte-length vector (non-empty, even length).
    pub(crate) fn u16_list(&mut self) -> DResult<Vec<u16>> {
        let mut r = self.sub16()?;
        if r.buf.is_empty() || r.buf.len() % 2 != 0 {
            return Err(Fatal::new(Alert::DecodeError, "bad u16 list"));
        }
        let mut out = Vec::with_capacity(r.buf.len() / 2);
        while !r.is_empty() {
            out.push(r.u16()?);
        }
        Ok(out)
    }
}

pub(crate) fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, v: usize) {
    debug_assert!(v < 1 << 24);
    out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
}

pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes a vector whose length prefix has `width` bytes (1, 2 or 3), the body produced by `f`.
pub(crate) fn put_vec(out: &mut Vec<u8>, width: usize, f: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0, 0, 0][..width]);
    f(out);
    let n = out.len() - at - width;
    let len = n.to_be_bytes();
    let l = len.len();
    out[at..at + width].copy_from_slice(&len[l - width..]);
}

pub(crate) fn put_vec8(out: &mut Vec<u8>, b: &[u8]) {
    put_u8(out, b.len() as u8);
    out.extend_from_slice(b);
}

pub(crate) fn put_vec16(out: &mut Vec<u8>, b: &[u8]) {
    put_u16(out, b.len() as u16);
    out.extend_from_slice(b);
}

pub(crate) fn put_vec24(out: &mut Vec<u8>, b: &[u8]) {
    put_u24(out, b.len());
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut o = Vec::new();
        put_u8(&mut o, 1);
        put_u16(&mut o, 0x0203);
        put_u24(&mut o, 0x040506);
        put_u32(&mut o, 0x0708090a);
        put_vec(&mut o, 2, |o| o.extend_from_slice(b"abc"));
        put_vec8(&mut o, b"d");
        put_vec24(&mut o, b"ef");
        let mut r = Reader::new(&o);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u24().unwrap(), 0x040506);
        assert_eq!(r.u32().unwrap(), 0x0708090a);
        assert_eq!(r.vec16().unwrap(), b"abc");
        assert_eq!(r.vec8().unwrap(), b"d");
        assert_eq!(r.vec24().unwrap(), b"ef");
        r.finish().unwrap();
        assert!(r.u8().is_err());
        assert!(Reader::new(&[0, 3, 1]).vec16().is_err());
        assert!(Reader::new(&[0, 1, 1]).u16_list().is_err());
        assert!(Reader::new(&[0, 0]).u16_list().is_err());
    }
}
