//! Strict ASN.1 DER (X.690) reading and writing: the subset X.509, PKCS#1, PKCS#8, SEC1 and
//! signature encodings use.
//!
//! The [`Reader`] rejects everything that is valid BER but not DER: indefinite and non-minimal
//! lengths, high tag numbers (`0x1f` form), non-minimal or empty INTEGERs, BOOLEANs other than
//! `00`/`FF`, BIT STRINGs with nonzero padding bits, trailing data. It works on borrowed slices
//! and never allocates. The [`Writer`] produces DER.
//!
//! ```
//! use only_crypto::der::{Reader, Writer, tag};
//!
//! let mut w = Writer::new();
//! w.sequence(|w| {
//!     w.uint(&[0x00, 0x80]); // leading zeros are stripped, a sign byte added
//!     w.bool(true);
//! });
//! let der = w.into_vec();
//! assert_eq!(der, [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x01, 0x01, 0xff]);
//!
//! let mut r = Reader::new(&der);
//! let mut seq = r.sequence().unwrap();
//! assert_eq!(seq.read_uint().unwrap(), &[0x80]);
//! assert!(seq.read_bool().unwrap());
//! seq.finish().unwrap();
//! r.finish().unwrap();
//! # let _ = tag::SEQUENCE;
//! ```

use crate::Error;

/// Universal tags and helpers for context-specific ones.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// UTF8String.
    pub const UTF8_STRING: u8 = 0x0c;
    /// PrintableString.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// TeletexString (T61String).
    pub const TELETEX_STRING: u8 = 0x14;
    /// IA5String.
    pub const IA5_STRING: u8 = 0x16;
    /// UTCTime.
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// UniversalString.
    pub const UNIVERSAL_STRING: u8 = 0x1c;
    /// BMPString.
    pub const BMP_STRING: u8 = 0x1e;
    /// SEQUENCE (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// SET (constructed).
    pub const SET: u8 = 0x31;

    /// `[n]` constructed, context-specific (`0xa0 | n`), for EXPLICIT tagging and constructed
    /// IMPLICIT types.
    #[must_use]
    pub const fn explicit(n: u8) -> u8 {
        0xa0 | n
    }

    /// `[n]` primitive, context-specific (`0x80 | n`), for IMPLICIT primitive types.
    #[must_use]
    pub const fn implicit(n: u8) -> u8 {
        0x80 | n
    }
}

/// Object identifiers used by the key and certificate formats, as DER content bytes (the
/// value of an OBJECT IDENTIFIER without tag and length).
pub mod oid {
    /// id-ecPublicKey, 1.2.840.10045.2.1.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// secp256r1 (prime256v1), 1.2.840.10045.3.1.7.
    pub const SECP256R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1, 1.3.132.0.34.
    pub const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// id-Ed25519, 1.3.101.112.
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    /// id-X25519, 1.3.101.110.
    pub const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
    /// id-X448, 1.3.101.111.
    pub const X448: &[u8] = &[0x2b, 0x65, 0x6f];
    /// id-Ed448, 1.3.101.113.
    pub const ED448: &[u8] = &[0x2b, 0x65, 0x71];
    /// id-dsa, 1.2.840.10040.4.1.
    pub const DSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
    /// id-dsa-with-sha1, 1.2.840.10040.4.3.
    pub const DSA_WITH_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03];
    /// id-dsa-with-sha224, 2.16.840.1.101.3.4.3.1.
    pub const DSA_WITH_SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01];
    /// id-dsa-with-sha256, 2.16.840.1.101.3.4.3.2.
    pub const DSA_WITH_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02];
    /// rsaEncryption, 1.2.840.113549.1.1.1.
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// sha1WithRSAEncryption, 1.2.840.113549.1.1.5.
    pub const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    /// id-mgf1, 1.2.840.113549.1.1.8.
    pub const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
    /// id-RSASSA-PSS, 1.2.840.113549.1.1.10.
    pub const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    /// sha256WithRSAEncryption, 1.2.840.113549.1.1.11.
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// sha384WithRSAEncryption, 1.2.840.113549.1.1.12.
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// sha512WithRSAEncryption, 1.2.840.113549.1.1.13.
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// ecdsa-with-SHA256, 1.2.840.10045.4.3.2.
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384, 1.2.840.10045.4.3.3.
    pub const ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// ecdsa-with-SHA512, 1.2.840.10045.4.3.4.
    pub const ECDSA_WITH_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    /// id-sha1, 1.3.14.3.2.26.
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    /// id-sha256, 2.16.840.1.101.3.4.2.1.
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// id-sha384, 2.16.840.1.101.3.4.2.2.
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// id-sha512, 2.16.840.1.101.3.4.2.3.
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    /// The dotted-decimal form of OID content bytes (`"1.2.840.10045.2.1"`), or `None` if
    /// they are not a valid encoding.
    #[must_use]
    pub fn to_string(oid: &[u8]) -> Option<String> {
        if !super::valid_oid(oid) {
            return None;
        }
        let mut out = String::new();
        let mut v: u64 = 0;
        let mut first = true;
        for &b in oid {
            v = (v << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                if first {
                    let (a, b) = match v {
                        0..=39 => (0, v),
                        40..=79 => (1, v - 40),
                        _ => (2, v - 80),
                    };
                    out.push_str(&format!("{a}.{b}"));
                    first = false;
                } else {
                    out.push_str(&format!(".{v}"));
                }
                v = 0;
            }
        }
        Some(out)
    }
}

/// Whether OID content bytes are minimally encoded base-128 arcs that fit in 63 bits.
fn valid_oid(b: &[u8]) -> bool {
    if b.is_empty() || b[b.len() - 1] & 0x80 != 0 {
        return false;
    }
    let mut start = true;
    let mut len = 0;
    for &x in b {
        if start && x == 0x80 {
            return false; // leading 0x80: non-minimal
        }
        len += 1;
        if len > 9 {
            return false;
        }
        start = x & 0x80 == 0;
        if start {
            len = 0;
        }
    }
    true
}

/// A strict DER reader over a borrowed buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data }
    }

    /// Whether everything has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The unread bytes.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// The tag of the next element, if any.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Fails unless everything has been read.
    pub fn finish(self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }

    /// The next element: `(tag, contents, whole encoding)`.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), Error> {
        let d = self.data;
        let (&tag, rest) = d.split_first().ok_or(Error::Encoding)?;
        if tag & 0x1f == 0x1f {
            return Err(Error::Encoding); // high tag numbers: not used here
        }
        let (&l0, rest) = rest.split_first().ok_or(Error::Encoding)?;
        let (len, rest) = if l0 < 0x80 {
            (usize::from(l0), rest)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(Error::Encoding); // indefinite, too long, truncated
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | usize::from(b);
            }
            // Minimal: no leading zero byte, and the long form only for lengths >= 128.
            if rest[0] == 0 || len < 0x80 {
                return Err(Error::Encoding);
            }
            (len, &rest[n..])
        };
        if rest.len() < len {
            return Err(Error::Encoding);
        }
        let header = d.len() - rest.len();
        let whole = &d[..header + len];
        self.data = &rest[len..];
        Ok((tag, &rest[..len], whole))
    }

    /// The contents of the next element, which must have tag `t`.
    pub fn read(&mut self, t: u8) -> Result<&'a [u8], Error> {
        let (tag, c, _) = self.read_tlv()?;
        if tag != t {
            return Err(Error::Encoding);
        }
        Ok(c)
    }

    /// The whole encoding (tag, length, contents) of the next element, which must have tag
    /// `t`.
    pub fn read_element(&mut self, t: u8) -> Result<&'a [u8], Error> {
        let (tag, _, whole) = self.read_tlv()?;
        if tag != t {
            return Err(Error::Encoding);
        }
        Ok(whole)
    }

    /// The contents of the next element if its tag is `t`, else `None` (nothing consumed).
    pub fn read_optional(&mut self, t: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek_tag() == Some(t) {
            self.read(t).map(Some)
        } else {
            Ok(None)
        }
    }

    /// A reader over the contents of the next element, a SEQUENCE.
    pub fn sequence(&mut self) -> Result<Reader<'a>, Error> {
        self.read(tag::SEQUENCE).map(Reader::new)
    }

    /// A reader over the contents of the next element with constructed tag `t`.
    pub fn constructed(&mut self, t: u8) -> Result<Reader<'a>, Error> {
        self.read(t).map(Reader::new)
    }

    /// An INTEGER's contents, checked for minimal two's-complement encoding.
    pub fn read_integer(&mut self) -> Result<&'a [u8], Error> {
        let c = self.read(tag::INTEGER)?;
        match c {
            [] => Err(Error::Encoding),
            [0, b, ..] if *b < 0x80 => Err(Error::Encoding),
            [0xff, b, ..] if *b >= 0x80 => Err(Error::Encoding),
            _ => Ok(c),
        }
    }

    /// A non-negative INTEGER's magnitude, big-endian without leading zeros (`[]` for 0).
    pub fn read_uint(&mut self) -> Result<&'a [u8], Error> {
        let c = self.read_integer()?;
        if c[0] & 0x80 != 0 {
            return Err(Error::Encoding);
        }
        Ok(if c[0] == 0 { &c[1..] } else { c })
    }

    /// A non-negative INTEGER that fits in a `u64`.
    pub fn read_small_uint(&mut self) -> Result<u64, Error> {
        let m = self.read_uint()?;
        if m.len() > 8 {
            return Err(Error::Encoding);
        }
        Ok(m.iter().fold(0, |a, &b| (a << 8) | u64::from(b)))
    }

    /// A BOOLEAN (`00` or `FF`).
    pub fn read_bool(&mut self) -> Result<bool, Error> {
        match self.read(tag::BOOLEAN)? {
            [0] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error::Encoding),
        }
    }

    /// An OBJECT IDENTIFIER's content bytes (validated).
    pub fn read_oid(&mut self) -> Result<&'a [u8], Error> {
        let c = self.read(tag::OID)?;
        if !valid_oid(c) {
            return Err(Error::Encoding);
        }
        Ok(c)
    }

    /// A BIT STRING with a whole number of bytes (no unused bits).
    pub fn read_bit_string(&mut self) -> Result<&'a [u8], Error> {
        match self.read_bit_string_bits()? {
            (0, b) => Ok(b),
            _ => Err(Error::Encoding),
        }
    }

    /// A BIT STRING: `(unused bits in the last byte, bytes)`; the unused bits must be zero.
    pub fn read_bit_string_bits(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let c = self.read(tag::BIT_STRING)?;
        let (&unused, bits) = c.split_first().ok_or(Error::Encoding)?;
        if unused > 7 || (bits.is_empty() && unused != 0) {
            return Err(Error::Encoding);
        }
        if bits
            .last()
            .is_some_and(|&last| last & ((1u8 << unused) - 1) != 0)
        {
            return Err(Error::Encoding);
        }
        Ok((unused, bits))
    }

    /// An OCTET STRING's contents.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], Error> {
        self.read(tag::OCTET_STRING)
    }

    /// A NULL.
    pub fn read_null(&mut self) -> Result<(), Error> {
        if self.read(tag::NULL)?.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

/// A DER writer appending to a `Vec<u8>`.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Writer {
        Writer::default()
    }

    /// The encoding written so far.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// The encoding written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Appends already-encoded DER.
    pub fn raw(&mut self, der: &[u8]) {
        self.buf.extend_from_slice(der);
    }

    /// Appends an element with tag `t` and these contents.
    pub fn tlv(&mut self, t: u8, contents: &[u8]) {
        self.buf.push(t);
        let n = contents.len();
        if n < 0x80 {
            self.buf.push(n as u8);
        } else {
            let bytes = (n as u64).to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            self.buf.push(0x80 | (8 - skip) as u8);
            self.buf.extend_from_slice(&bytes[skip..]);
        }
        self.buf.extend_from_slice(contents);
    }

    /// Appends an element with tag `t` whose contents `f` writes.
    pub fn nested(&mut self, t: u8, f: impl FnOnce(&mut Writer)) {
        let mut w = Writer::new();
        f(&mut w);
        self.tlv(t, &w.buf);
    }

    /// Appends a SEQUENCE whose contents `f` writes.
    pub fn sequence(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nested(tag::SEQUENCE, f);
    }

    /// Appends a non-negative INTEGER from big-endian magnitude bytes (leading zeros are
    /// stripped; a zero byte is added when the top bit is set).
    pub fn uint(&mut self, magnitude: &[u8]) {
        let skip = magnitude.iter().take_while(|&&b| b == 0).count();
        let m = &magnitude[skip..];
        if m.is_empty() {
            self.tlv(tag::INTEGER, &[0]);
        } else if m[0] & 0x80 != 0 {
            let mut v = Vec::with_capacity(m.len() + 1);
            v.push(0);
            v.extend_from_slice(m);
            self.tlv(tag::INTEGER, &v);
        } else {
            self.tlv(tag::INTEGER, m);
        }
    }

    /// Appends a non-negative INTEGER.
    pub fn small_uint(&mut self, v: u64) {
        self.uint(&v.to_be_bytes());
    }

    /// Appends a BOOLEAN.
    pub fn bool(&mut self, v: bool) {
        self.tlv(tag::BOOLEAN, &[if v { 0xff } else { 0 }]);
    }

    /// Appends an OBJECT IDENTIFIER from its content bytes.
    pub fn oid(&mut self, oid: &[u8]) {
        self.tlv(tag::OID, oid);
    }

    /// Appends a NULL.
    pub fn null(&mut self) {
        self.tlv(tag::NULL, &[]);
    }

    /// Appends an OCTET STRING.
    pub fn octet_string(&mut self, b: &[u8]) {
        self.tlv(tag::OCTET_STRING, b);
    }

    /// Appends a BIT STRING of whole bytes.
    pub fn bit_string(&mut self, b: &[u8]) {
        let mut v = Vec::with_capacity(b.len() + 1);
        v.push(0);
        v.extend_from_slice(b);
        self.tlv(tag::BIT_STRING, &v);
    }

    /// Appends a BIT STRING of `nbits` bits (named-bit-list encoding: the caller trims trailing
    /// zero bits).
    pub fn bit_string_bits(&mut self, b: &[u8], nbits: usize) {
        let unused = (b.len() * 8).saturating_sub(nbits) as u8;
        let mut v = Vec::with_capacity(b.len() + 1);
        v.push(unused);
        v.extend_from_slice(b);
        self.tlv(tag::BIT_STRING, &v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        let mut w = Writer::new();
        w.octet_string(&[7; 200]);
        let v = w.into_vec();
        assert_eq!(&v[..3], &[0x04, 0x81, 200]);
        let mut r = Reader::new(&v);
        assert_eq!(r.read_octet_string().unwrap().len(), 200);
        // Non-minimal lengths and indefinite form.
        for bad in [
            &[0x04, 0x81, 0x05, 1, 2, 3, 4, 5][..],
            &[0x04, 0x82, 0x00, 0x81][..],
            &[0x04, 0x80, 0, 0][..],
            &[0x04, 0x02, 1][..],
            &[0x1f, 0x01, 0x00][..],
        ] {
            assert!(Reader::new(bad).read_tlv().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn integers() {
        for (enc, ok) in [
            (&[0x02, 0x01, 0x00][..], true),
            (&[0x02, 0x02, 0x00, 0x7f][..], false),
            (&[0x02, 0x02, 0x00, 0x80][..], true),
            (&[0x02, 0x02, 0xff, 0x80][..], false),
            (&[0x02, 0x00][..], false),
        ] {
            assert_eq!(Reader::new(enc).read_integer().is_ok(), ok, "{enc:?}");
        }
        assert!(Reader::new(&[0x02, 0x01, 0x80]).read_uint().is_err());
        assert_eq!(
            Reader::new(&[0x02, 0x01, 0x00]).read_uint().unwrap(),
            &[] as &[u8]
        );
        let mut w = Writer::new();
        w.small_uint(0);
        w.small_uint(65537);
        assert_eq!(w.as_bytes(), &[2, 1, 0, 2, 3, 1, 0, 1]);
        assert!(Reader::new(&[1, 1, 1]).read_bool().is_err());
        assert!(Reader::new(&[3, 2, 1, 1]).read_bit_string_bits().is_err());
        assert_eq!(
            Reader::new(&[3, 2, 1, 2]).read_bit_string_bits().unwrap(),
            (1, &[2u8][..])
        );
    }

    #[test]
    fn oids() {
        assert_eq!(
            oid::to_string(oid::EC_PUBLIC_KEY).unwrap(),
            "1.2.840.10045.2.1"
        );
        assert_eq!(
            oid::to_string(oid::SHA256).unwrap(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert!(oid::to_string(&[0x2a, 0x80, 0x01]).is_none());
        assert!(oid::to_string(&[0x2a, 0x86]).is_none());
    }
}
