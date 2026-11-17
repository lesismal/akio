//! Coders: transformations of whole messages on the wire (compression, appended values, user
//! encodings), the counterpart of Go arpc's `MessageCoder`.
//!
//! A coder sees a complete frame (the 16-byte header, the method and the payload) and may
//! rewrite it. [`Routes::coder`](crate::Routes::coder) adds one; frames are encoded by the
//! coders in the order they were added and decoded in the opposite order, as in Go, so the same
//! chain on both sides undoes itself. A coder marks what it did in a bit of the reserved header
//! byte ([`flag_bit`] / [`set_flag_bit`]) and only undoes frames that carry its bit.
//!
//! Two coders interoperate with the Go ones of `arpcex/extension/middleware/coder`:
//! [`Gzip`] (bit 7) and [`Appender`] (bit 0 for tracing, any bit for values of your own).
//!
//! The body length in the header is set from the frame's length after every coder, so a coder
//! need not maintain it. Pings and pongs are never coded.

use only_deflate::{Format, Level};

use crate::proto::{HEAD_LEN, IDX_RESERVED};

/// The reserved-byte bit of the [`Gzip`] coder (Go: `coder.FlagBitGZip`).
pub const FLAG_BIT_GZIP: u8 = 7;
/// The reserved-byte bit of the Go tracing appender (Go: `coder.FlagBitOpenTracing`).
pub const FLAG_BIT_TRACING: u8 = 0;

/// Why a received frame could not be decoded; the connection is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoderError(pub &'static str);

impl std::fmt::Display for CoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "arpc coder: {}", self.0)
    }
}

impl std::error::Error for CoderError {}

/// A transformation of whole frames; see the [module documentation](self).
pub trait Coder: Send + Sync + 'static {
    /// Rewrites `frame`, a whole message about to be sent. `values` are the message's (those
    /// of the call, or of the request a response answers).
    fn encode(&self, frame: &mut Vec<u8>, values: &Values);

    /// Undoes [`encode`](Self::encode) on a received `frame`, storing what it carries in
    /// `values` (handlers and middleware see them through
    /// [`Context::values`](crate::Context::values)). The body of the result may be at most
    /// `max_body` bytes ([`Routes::max_body_bytes`](crate::Routes::max_body_bytes)): stop
    /// expanding past it. An error closes the connection.
    fn decode(
        &self,
        frame: &mut Vec<u8>,
        values: &mut Values,
        max_body: usize,
    ) -> Result<(), CoderError>;
}

/// Whether bit `index` (0 to 7) of the reserved header byte of `frame` is set.
pub fn flag_bit(frame: &[u8], index: u8) -> bool {
    index < 8
        && frame
            .get(IDX_RESERVED)
            .is_some_and(|b| b & (1 << index) != 0)
}

/// Sets or clears bit `index` (0 to 7) of the reserved header byte of `frame`.
pub fn set_flag_bit(frame: &mut [u8], index: u8, on: bool) {
    if let (true, Some(b)) = (index < 8, frame.get_mut(IDX_RESERVED)) {
        if on {
            *b |= 1 << index;
        } else {
            *b &= !(1 << index);
        }
    }
}

/// Values attached to a message: they travel only through coders that carry them (such as
/// [`Appender`]) and are otherwise local, as Go's `Message.Values`. Keys are strings and values
/// bytes; a message usually has none, and then this costs nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(Vec<(String, Vec<u8>)>);

impl Values {
    /// No values.
    pub const fn new() -> Values {
        Values(Vec::new())
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Sets the value of `key`, replacing an earlier one.
    pub fn set(&mut self, key: &str, value: impl Into<Vec<u8>>) {
        let value = value.into();
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(e) => e.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    /// Sets `key` and returns the values, for building them inline.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<Vec<u8>>) -> Values {
        self.set(key, value);
        self
    }

    /// Removes `key` and returns its value.
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        let i = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.swap_remove(i).1)
    }

    /// Number of values.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The keys and values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }
}

/// Compresses frames with gzip, as Go's `arpcex/extension/middleware/coder/gzip`: a frame
/// longer than the threshold has everything after its reserved byte (cmd, flags, method
/// length, sequence number, method and payload) replaced by its gzip stream, and bit
/// [`FLAG_BIT_GZIP`] set, when that makes it shorter. Received frames with the bit are
/// inflated, at most to the body limit.
#[derive(Debug, Clone, Copy)]
pub struct Gzip {
    threshold: usize,
    level: Level,
}

impl Gzip {
    /// Compresses frames longer than `threshold` bytes (Go: `gzip.New(threshold)`), at the
    /// default level.
    pub fn new(threshold: usize) -> Gzip {
        Gzip {
            threshold,
            level: Level::DEFAULT,
        }
    }

    /// The compression level, 0 (stored) to 9 (smallest), clamped; default 6, as Go's
    /// `gzip.NewWriter`.
    #[must_use]
    pub fn level(mut self, level: u32) -> Gzip {
        self.level = Level::new(level);
        self
    }
}

impl Coder for Gzip {
    fn encode(&self, frame: &mut Vec<u8>, _values: &Values) {
        if frame.len() <= self.threshold || flag_bit(frame, FLAG_BIT_GZIP) {
            return;
        }
        let z = only_deflate::compress(Format::Gzip, self.level, &frame[IDX_RESERVED + 1..]);
        if IDX_RESERVED + 1 + z.len() < frame.len() {
            frame.truncate(IDX_RESERVED + 1);
            frame.extend_from_slice(&z);
            set_flag_bit(frame, FLAG_BIT_GZIP, true);
        }
    }

    fn decode(
        &self,
        frame: &mut Vec<u8>,
        _values: &mut Values,
        max_body: usize,
    ) -> Result<(), CoderError> {
        if !flag_bit(frame, FLAG_BIT_GZIP) {
            return Ok(());
        }
        // What was compressed: the header after the reserved byte, then the body.
        let limit = (HEAD_LEN - IDX_RESERVED - 1).saturating_add(max_body);
        let plain = only_deflate::decompress(Format::Gzip, &frame[IDX_RESERVED + 1..], limit)
            .map_err(|e| match e {
                only_deflate::Error::TooLarge => CoderError("gzip: body too long"),
                _ => CoderError("gzip: bad data"),
            })?;
        if plain.len() < HEAD_LEN - IDX_RESERVED - 1 {
            return Err(CoderError("gzip: short header"));
        }
        frame.truncate(IDX_RESERVED + 1);
        frame.extend_from_slice(&plain);
        set_flag_bit(frame, FLAG_BIT_GZIP, false);
        Ok(())
    }
}

/// Carries one value of [`Values`] at the end of the frame, as Go's
/// `arpcex/extension/middleware/coder.Appender`: when the message has a value for the coder's
/// name, the name, the value and a two-byte big-endian length of both plus two are appended and
/// the coder's bit is set. The receiving coder of the same name and bit strips them and stores
/// the value. Go's tracing coder is `Appender::new(<its name>, FLAG_BIT_TRACING)`.
#[derive(Debug, Clone)]
pub struct Appender {
    name: String,
    bit: u8,
}

impl Appender {
    /// Carries the value named `name`, marked with reserved bit `bit` (0 to 7; panics
    /// otherwise). Names and values longer than 65533 bytes together are not sent.
    pub fn new(name: &str, bit: u8) -> Appender {
        assert!(bit < 8, "arpc: flag bit {bit} is not 0 to 7");
        Appender {
            name: name.to_owned(),
            bit,
        }
    }
}

impl Coder for Appender {
    fn encode(&self, frame: &mut Vec<u8>, values: &Values) {
        let Some(v) = values.get(&self.name) else {
            return;
        };
        let n = self.name.len() + v.len() + 2;
        if n > usize::from(u16::MAX) || flag_bit(frame, self.bit) {
            return;
        }
        frame.reserve(n);
        frame.extend_from_slice(self.name.as_bytes());
        frame.extend_from_slice(v);
        frame.extend_from_slice(&(n as u16).to_be_bytes());
        set_flag_bit(frame, self.bit, true);
    }

    fn decode(
        &self,
        frame: &mut Vec<u8>,
        values: &mut Values,
        _max_body: usize,
    ) -> Result<(), CoderError> {
        if !flag_bit(frame, self.bit) {
            return Ok(());
        }
        let len = frame.len();
        if len < HEAD_LEN + 2 {
            return Err(CoderError("appender: short frame"));
        }
        let n = usize::from(u16::from_be_bytes([frame[len - 2], frame[len - 1]]));
        if n < self.name.len() + 2 || n > len - HEAD_LEN {
            return Err(CoderError("appender: bad length"));
        }
        let start = len - n;
        if &frame[start..start + self.name.len()] != self.name.as_bytes() {
            // Another appender's value on the same bit: left as it is, as in Go.
            return Ok(());
        }
        values.set(&self.name, &frame[start + self.name.len()..len - 2]);
        frame.truncate(start);
        set_flag_bit(frame, self.bit, false);
        Ok(())
    }
}

/// Runs `coders` over a frame to send, in order, and fixes the body length.
pub(crate) fn encode_frame(coders: &[std::sync::Arc<dyn Coder>], frame: &mut Vec<u8>, v: &Values) {
    for c in coders {
        c.encode(frame, v);
    }
    set_body_len(frame);
}

/// Runs `coders` over a received frame, in reverse order, checking the result.
pub(crate) fn decode_frame(
    coders: &[std::sync::Arc<dyn Coder>],
    frame: &mut Vec<u8>,
    values: &mut Values,
    max_body: usize,
) -> Result<(), CoderError> {
    for c in coders.iter().rev() {
        c.decode(frame, values, max_body)?;
        if frame.len() < HEAD_LEN {
            return Err(CoderError("frame shorter than a header"));
        }
        if frame.len() - HEAD_LEN > max_body {
            return Err(CoderError("body too long"));
        }
        set_body_len(frame);
    }
    Ok(())
}

fn set_body_len(frame: &mut [u8]) {
    if frame.len() >= HEAD_LEN {
        let body = (frame.len() - HEAD_LEN) as u32;
        frame[..4].copy_from_slice(&body.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::proto::{Cmd, Decoder, encode};

    fn chain() -> Vec<Arc<dyn Coder>> {
        vec![
            Arc::new(Appender::new("trace", FLAG_BIT_TRACING)),
            Arc::new(Gzip::new(64)),
        ]
    }

    fn roundtrip(payload: &[u8], values: &Values) -> (Vec<u8>, Vec<u8>, Values) {
        let coders = chain();
        let plain = encode(Cmd::Request, 0, false, false, "/m", 9, payload);
        let mut wire = plain.clone();
        encode_frame(&coders, &mut wire, values);
        let mut back = wire.clone();
        let mut got = Values::new();
        decode_frame(&coders, &mut back, &mut got, 1 << 20).expect("decode");
        assert_eq!(back, plain);
        (wire, back, got)
    }

    #[test]
    fn gzip_and_appender_undo_each_other() {
        let v = Values::new().with("trace", "abc-123");
        // Small: only the appender applies.
        let (wire, _, got) = roundtrip(b"hi", &v);
        assert!(flag_bit(&wire, FLAG_BIT_TRACING) && !flag_bit(&wire, FLAG_BIT_GZIP));
        assert_eq!(got.get("trace"), Some(&b"abc-123"[..]));
        // Big and compressible: both, and the frame shrinks.
        let big = vec![b'a'; 10_000];
        let (wire, _, got) = roundtrip(&big, &v);
        assert!(flag_bit(&wire, FLAG_BIT_TRACING) && flag_bit(&wire, FLAG_BIT_GZIP));
        assert!(wire.len() < 200, "{}", wire.len());
        assert_eq!(got.get("trace"), Some(&b"abc-123"[..]));
        // The decoder frames it by the rewritten length.
        let mut out = Vec::new();
        Decoder::new(1 << 20)
            .feed_frames(&wire, |f| {
                out.push(f.to_vec());
                Ok(())
            })
            .expect("frames");
        assert_eq!(out, std::slice::from_ref(&wire));
        // No values, incompressible small payload: untouched.
        let (wire, _, got) = roundtrip(b"xy", &Values::new());
        assert_eq!(wire[IDX_RESERVED], 0);
        assert!(got.is_empty());
    }

    #[test]
    fn gzip_bombs_and_garbage_are_refused() {
        let coders: Vec<Arc<dyn Coder>> = vec![Arc::new(Gzip::new(0))];
        let mut f = encode(Cmd::Request, 0, false, false, "/m", 1, &vec![0u8; 100_000]);
        encode_frame(&coders, &mut f, &Values::new());
        assert!(f.len() < 1000);
        let mut v = Values::new();
        // Inflates past the limit: refused before the whole output exists.
        assert_eq!(
            decode_frame(&coders, &mut f.clone(), &mut v, 50_000),
            Err(CoderError("gzip: body too long"))
        );
        // At the limit (method + payload): accepted.
        assert!(decode_frame(&coders, &mut f.clone(), &mut v, 100_002).is_ok());
        assert!(decode_frame(&coders, &mut f.clone(), &mut v, 100_001).is_err());
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - 10] ^= 0xff;
        assert!(decode_frame(&coders, &mut bad, &mut v, 1 << 20).is_err());
    }

    #[test]
    fn appender_checks_lengths_and_names() {
        let a: Vec<Arc<dyn Coder>> = vec![Arc::new(Appender::new("k", 3))];
        let mut f = encode(Cmd::Notify, 0, false, false, "/m", 1, b"p");
        encode_frame(&a, &mut f, &Values::new().with("k", "v"));
        assert_eq!(&f[f.len() - 4..], b"kv\x00\x04");
        // Length past the body.
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - 1] = 200;
        assert!(decode_frame(&a, &mut bad, &mut Values::new(), 1000).is_err());
        // Shorter than the name.
        bad[n - 1] = 2;
        assert!(decode_frame(&a, &mut bad, &mut Values::new(), 1000).is_err());
        // Another name: left alone.
        let other: Vec<Arc<dyn Coder>> = vec![Arc::new(Appender::new("j", 3))];
        let mut g = f.clone();
        let mut v = Values::new();
        decode_frame(&other, &mut g, &mut v, 1000).expect("ok");
        assert_eq!(g, f);
        assert!(v.is_empty());
        // Too long to append: not sent.
        let mut h = encode(Cmd::Notify, 0, false, false, "/m", 1, b"p");
        encode_frame(&a, &mut h, &Values::new().with("k", vec![0u8; 70_000]));
        assert!(!flag_bit(&h, 3));
    }

    #[test]
    fn values_and_bits() {
        let mut v = Values::new().with("a", "1").with("b", "2").with("a", "3");
        assert_eq!(v.len(), 2);
        assert_eq!(v.get("a"), Some(&b"3"[..]));
        assert_eq!(v.remove("a"), Some(b"3".to_vec()));
        assert_eq!(v.iter().count(), 1);
        let mut f = vec![0u8; 16];
        set_flag_bit(&mut f, 5, true);
        assert!(flag_bit(&f, 5) && f[4] == 32);
        set_flag_bit(&mut f, 9, true);
        assert!(!flag_bit(&f, 9));
        set_flag_bit(&mut f, 5, false);
        assert_eq!(f[4], 0);
    }
}
