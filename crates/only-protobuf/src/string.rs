//! [`ProtoString`]: the value of a `string` field whose UTF-8 is not checked.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

/// The value of a `string` field declared with `features.utf8_validation = NONE` (editions), or
/// of a proto2 `string` field when `only-protobuf-build`'s `Config::proto2_unchecked_strings`
/// is on.
///
/// The protobuf specification lets such a field hold any bytes: the parser must not reject
/// them, and the serializer writes them back unchanged. Rust's `String` cannot hold them, so
/// these fields are bytes that are *usually* UTF-8: [`to_str`](Self::to_str) checks when the
/// text is needed, [`to_string_lossy`](Self::to_string_lossy) replaces what is not UTF-8, and
/// [`as_bytes`](Self::as_bytes) is always there. Decoding into it does no UTF-8 check.
///
/// ```
/// use only_protobuf::ProtoString;
///
/// let s = ProtoString::from("héllo");
/// assert_eq!(s.to_str(), Ok("héllo"));
/// assert_eq!(s, "héllo");
///
/// let raw = ProtoString::from(vec![b'a', 0xff]);
/// assert!(raw.to_str().is_err());
/// assert_eq!(raw.to_string_lossy(), "a\u{fffd}");
/// assert_eq!(raw.as_bytes(), b"a\xff");
/// ```
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtoString(Vec<u8>);

impl ProtoString {
    /// The empty string.
    pub const fn new() -> ProtoString {
        ProtoString(Vec::new())
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, to change in place.
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    /// The bytes, owned.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The text, when the bytes are UTF-8.
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// The text, with every sequence that is not UTF-8 replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    /// The text, owned, when the bytes are UTF-8.
    pub fn into_string(self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.0)
    }

    /// Whether the bytes are UTF-8.
    pub fn is_utf8(&self) -> bool {
        self.to_str().is_ok()
    }

    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes every byte (the allocation is kept).
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl fmt::Debug for ProtoString {
    /// As a string literal when the bytes are UTF-8, else as a byte string literal (`b"a\xff"`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str() {
            Ok(s) => fmt::Debug::fmt(s, f),
            Err(_) => write!(f, "b\"{}\"", self.0.escape_ascii()),
        }
    }
}

impl fmt::Display for ProtoString {
    /// The text, lossily (see [`to_string_lossy`](ProtoString::to_string_lossy)).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_string_lossy(), f)
    }
}

impl From<String> for ProtoString {
    fn from(s: String) -> ProtoString {
        ProtoString(s.into_bytes())
    }
}

impl From<&str> for ProtoString {
    fn from(s: &str) -> ProtoString {
        ProtoString(s.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for ProtoString {
    fn from(b: Vec<u8>) -> ProtoString {
        ProtoString(b)
    }
}

impl From<&[u8]> for ProtoString {
    fn from(b: &[u8]) -> ProtoString {
        ProtoString(b.to_vec())
    }
}

impl From<ProtoString> for Vec<u8> {
    fn from(s: ProtoString) -> Vec<u8> {
        s.0
    }
}

impl TryFrom<ProtoString> for String {
    type Error = FromUtf8Error;
    fn try_from(s: ProtoString) -> Result<String, FromUtf8Error> {
        s.into_string()
    }
}

impl AsRef<[u8]> for ProtoString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for ProtoString {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<str> for ProtoString {
    fn eq(&self, other: &str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<&str> for ProtoString {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<String> for ProtoString {
    fn eq(&self, other: &String) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<[u8]> for ProtoString {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl PartialEq<&[u8]> for ProtoString {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::ProtoString;
    use std::collections::HashMap;

    #[test]
    fn conversions_and_formatting() {
        let s = ProtoString::from(String::from("ab"));
        assert_eq!(s, "ab");
        assert_eq!(s, String::from("ab"));
        assert_eq!(s, &b"ab"[..]);
        assert!(s.is_utf8());
        assert_eq!(format!("{s:?}"), "\"ab\"");
        assert_eq!(format!("{s}"), "ab");
        assert_eq!(String::try_from(s).as_deref(), Ok("ab"));

        let mut bad = ProtoString::from(&b"a\xff\n"[..]);
        assert!(!bad.is_utf8());
        assert_eq!(format!("{bad:?}"), "b\"a\\xff\\n\"");
        assert_eq!(format!("{bad}"), "a\u{fffd}\n");
        assert!(bad.clone().into_string().is_err());
        assert_eq!(bad.len(), 3);
        bad.as_mut_vec().truncate(1);
        assert_eq!(bad.into_bytes(), b"a");

        let mut e = ProtoString::new();
        assert!(e.is_empty());
        e.as_mut_vec().push(b'x');
        e.clear();
        assert_eq!(e, ProtoString::default());
    }

    #[test]
    fn map_lookup_by_bytes() {
        let mut m = HashMap::new();
        m.insert(ProtoString::from(&b"k\xfe"[..]), 1);
        assert_eq!(m.get(&b"k\xfe"[..]), Some(&1));
    }
}
