//! Base64 (RFC 4648): the standard and URL-safe alphabets, with or without `=` padding.
//!
//! Decoding is strict, like the `base64` crate's `general_purpose` engines: padded engines
//! require canonical padding, unpadded engines reject `=`, and the unused bits of the last
//! symbol must be zero. No whitespace is skipped.
//!
//! ```
//! use only_crypto::base64::{STANDARD, URL_SAFE_NO_PAD};
//!
//! assert_eq!(STANDARD.encode(b"foob"), "Zm9vYg==");
//! assert_eq!(STANDARD.decode("Zm9vYg==").unwrap(), b"foob");
//! assert_eq!(URL_SAFE_NO_PAD.encode([0xfb, 0xff]), "-_8");
//! assert!(STANDARD.decode("Zm9vYg").is_err());
//! ```

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const INVALID: u8 = 0xff;

const fn decode_table(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut t = [INVALID; 256];
    let mut i = 0;
    while i < 64 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t
}

/// An alphabet plus a padding rule.
#[derive(Clone, Copy)]
pub struct Engine {
    encode: &'static [u8; 64],
    decode: &'static [u8; 256],
    pad: bool,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("url_safe", &(self.encode[62] == b'-'))
            .field("pad", &self.pad)
            .finish()
    }
}

static STD_DECODE: [u8; 256] = decode_table(STD_ALPHABET);
static URL_DECODE: [u8; 256] = decode_table(URL_ALPHABET);

/// The standard alphabet (`+`, `/`) with padding.
pub const STANDARD: Engine = Engine {
    encode: STD_ALPHABET,
    decode: &STD_DECODE,
    pad: true,
};
/// The standard alphabet without padding.
pub const STANDARD_NO_PAD: Engine = Engine {
    encode: STD_ALPHABET,
    decode: &STD_DECODE,
    pad: false,
};
/// The URL- and filename-safe alphabet (`-`, `_`) with padding.
pub const URL_SAFE: Engine = Engine {
    encode: URL_ALPHABET,
    decode: &URL_DECODE,
    pad: true,
};
/// The URL- and filename-safe alphabet without padding.
pub const URL_SAFE_NO_PAD: Engine = Engine {
    encode: URL_ALPHABET,
    decode: &URL_DECODE,
    pad: false,
};

/// Why base64 input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// A byte outside the alphabet (or a `=` where none may be) at this offset.
    InvalidByte(usize, u8),
    /// The input length cannot be valid (one symbol left over, or a padded engine got input
    /// that is not a multiple of four).
    InvalidLength(usize),
    /// The last symbol, at this offset, has non-zero bits that the data does not use.
    InvalidLastSymbol(usize, u8),
    /// Missing, excess or misplaced `=` padding.
    InvalidPadding,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidByte(i, b) => write!(f, "invalid byte {b:#04x} at offset {i}"),
            DecodeError::InvalidLength(n) => write!(f, "invalid input length {n}"),
            DecodeError::InvalidLastSymbol(i, b) => {
                write!(f, "invalid last symbol {b:#04x} at offset {i}")
            }
            DecodeError::InvalidPadding => f.write_str("invalid padding"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Engine {
    /// The encoded length of `n` bytes.
    #[must_use]
    pub const fn encoded_len(&self, n: usize) -> usize {
        if self.pad {
            n.div_ceil(3) * 4
        } else {
            n / 3 * 4 + [0, 2, 3][n % 3]
        }
    }

    /// Encodes `input`.
    #[must_use]
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(self.encoded_len(input.as_ref().len()));
        self.encode_to(input, &mut s);
        s
    }

    /// Encodes `input`, appending to `out`.
    pub fn encode_to(&self, input: impl AsRef<[u8]>, out: &mut String) {
        let input = input.as_ref();
        let a = self.encode;
        let mut buf = Vec::with_capacity(self.encoded_len(input.len()));
        let mut chunks = input.chunks_exact(3);
        for c in &mut chunks {
            let n = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
            buf.extend_from_slice(&[
                a[(n >> 18) as usize & 63],
                a[(n >> 12) as usize & 63],
                a[(n >> 6) as usize & 63],
                a[n as usize & 63],
            ]);
        }
        match *chunks.remainder() {
            [x] => {
                buf.extend_from_slice(&[a[usize::from(x >> 2)], a[usize::from(x & 3) << 4]]);
                if self.pad {
                    buf.extend_from_slice(b"==");
                }
            }
            [x, y] => {
                buf.extend_from_slice(&[
                    a[usize::from(x >> 2)],
                    a[usize::from(x & 3) << 4 | usize::from(y >> 4)],
                    a[usize::from(y & 15) << 2],
                ]);
                if self.pad {
                    buf.push(b'=');
                }
            }
            _ => {}
        }
        // The alphabet is ASCII.
        out.push_str(std::str::from_utf8(&buf).unwrap_or_else(|_| unreachable!()));
    }

    /// Decodes `input` strictly (see the module documentation).
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
        let mut out = Vec::new();
        self.decode_to(input, &mut out)?;
        Ok(out)
    }

    /// Decodes `input` strictly, appending to `out`. On error `out` may hold a partial result.
    pub fn decode_to(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) -> Result<(), DecodeError> {
        let input = input.as_ref();
        let data = if self.pad {
            if input.len() % 4 != 0 {
                return Err(DecodeError::InvalidLength(input.len()));
            }
            let pads = input
                .iter()
                .rev()
                .take(2)
                .take_while(|&&b| b == b'=')
                .count();
            &input[..input.len() - pads]
        } else {
            input
        };
        if data.len() % 4 == 1 {
            return Err(DecodeError::InvalidLength(input.len()));
        }
        let t = self.decode;
        let sym = |i: usize| -> Result<u32, DecodeError> {
            let b = data[i];
            match t[usize::from(b)] {
                INVALID if b == b'=' && self.pad => Err(DecodeError::InvalidPadding),
                INVALID => Err(DecodeError::InvalidByte(i, b)),
                v => Ok(u32::from(v)),
            }
        };
        out.reserve(data.len() / 4 * 3 + 2);
        let full = data.len() / 4 * 4;
        for i in (0..full).step_by(4) {
            let n = sym(i)? << 18 | sym(i + 1)? << 12 | sym(i + 2)? << 6 | sym(i + 3)?;
            out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        }
        match data.len() - full {
            2 => {
                let (a, b) = (sym(full)?, sym(full + 1)?);
                if b & 15 != 0 {
                    return Err(DecodeError::InvalidLastSymbol(full + 1, data[full + 1]));
                }
                out.push((a << 2 | b >> 4) as u8);
            }
            3 => {
                let (a, b, c) = (sym(full)?, sym(full + 1)?, sym(full + 2)?);
                if c & 3 != 0 {
                    return Err(DecodeError::InvalidLastSymbol(full + 2, data[full + 2]));
                }
                let n = a << 18 | b << 12 | c << 6;
                out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10.
    #[test]
    fn rfc4648() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(STANDARD.encode(raw), enc);
            assert_eq!(STANDARD.decode(enc).unwrap(), raw.as_bytes());
            let nopad = enc.trim_end_matches('=');
            assert_eq!(STANDARD_NO_PAD.encode(raw), nopad);
            assert_eq!(STANDARD_NO_PAD.decode(nopad).unwrap(), raw.as_bytes());
            assert_eq!(STANDARD.encoded_len(raw.len()), enc.len());
            assert_eq!(STANDARD_NO_PAD.encoded_len(raw.len()), nopad.len());
        }
    }

    #[test]
    fn alphabets() {
        let b = [0xfbu8, 0xff, 0xfe];
        assert_eq!(STANDARD.encode(b), "+//+");
        assert_eq!(URL_SAFE.encode(b), "-__-");
        assert_eq!(URL_SAFE.decode("-__-").unwrap(), b);
        assert!(URL_SAFE.decode("+//+").is_err());
        assert!(STANDARD.decode("-__-").is_err());
    }

    #[test]
    fn strict() {
        // Missing / excess / misplaced padding.
        assert_eq!(STANDARD.decode("Zg"), Err(DecodeError::InvalidLength(2)));
        assert_eq!(STANDARD.decode("Zg="), Err(DecodeError::InvalidLength(3)));
        assert_eq!(STANDARD.decode("Z==="), Err(DecodeError::InvalidPadding));
        assert_eq!(
            STANDARD.decode("Zg==Zg=="),
            Err(DecodeError::InvalidPadding)
        );
        assert_eq!(STANDARD.decode("Z=g="), Err(DecodeError::InvalidPadding));
        assert_eq!(
            STANDARD_NO_PAD.decode("Zg=="),
            Err(DecodeError::InvalidByte(2, b'='))
        );
        // Non-zero trailing bits.
        assert_eq!(
            STANDARD.decode("Zh=="),
            Err(DecodeError::InvalidLastSymbol(1, b'h'))
        );
        assert_eq!(
            STANDARD.decode("Zm9="),
            Err(DecodeError::InvalidLastSymbol(2, b'9'))
        );
        // One symbol left over.
        assert_eq!(
            STANDARD_NO_PAD.decode("Zm9vY"),
            Err(DecodeError::InvalidLength(5))
        );
        // Bytes outside the alphabet, whitespace included.
        assert_eq!(
            STANDARD.decode("Zm9v\n"),
            Err(DecodeError::InvalidLength(5))
        );
        assert_eq!(
            STANDARD.decode("Zm 9"),
            Err(DecodeError::InvalidByte(2, b' '))
        );
    }

    #[test]
    fn roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255).collect();
        for e in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
            for n in 0..data.len() {
                assert_eq!(e.decode(e.encode(&data[..n])).unwrap(), &data[..n]);
            }
        }
    }
}
