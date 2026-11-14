//! Message codecs. gRPC carries bytes; [`encode`] and [`decode`] convert any type implementing
//! this crate's [`Message`] trait.
//!
//! With the `prost` cargo feature, every prost message (`prost::Message + Default`) implements
//! [`Message`]. That adapter names prost's types, so the `prost` feature is **outside the semver
//! promise** (docs/api-stability.md): a prost upgrade may come in a minor release. Without the
//! feature, implement [`Message`] for your types with any serializer.
//!
//! ```
//! use flash_grpc::{Code, Status, codec::{self, Message}};
//!
//! #[derive(Debug, PartialEq)]
//! struct Hello(String);
//!
//! impl Message for Hello {
//!     fn encode_to(&self, buf: &mut Vec<u8>) {
//!         buf.extend_from_slice(self.0.as_bytes());
//!     }
//!     fn decode_from(bytes: &[u8]) -> Result<Self, Status> {
//!         String::from_utf8(bytes.to_vec())
//!             .map(Hello)
//!             .map_err(|e| Status::new(Code::InvalidArgument, e.to_string()))
//!     }
//! }
//!
//! let bytes = codec::encode(&Hello("hi".into()));
//! assert_eq!(codec::decode::<Hello>(&bytes).unwrap(), Hello("hi".into()));
//! ```

use crate::Status;

/// A type carried in gRPC messages.
pub trait Message: Sized {
    /// Appends the encoding of `self` to `buf`.
    fn encode_to(&self, buf: &mut Vec<u8>);
    /// Decodes a message; a malformed one should be an `INVALID_ARGUMENT` status.
    fn decode_from(bytes: &[u8]) -> Result<Self, Status>;
}

/// Encodes a message.
pub fn encode<M: Message>(m: &M) -> Vec<u8> {
    let mut v = Vec::new();
    m.encode_to(&mut v);
    v
}

/// Decodes a message.
pub fn decode<M: Message>(b: &[u8]) -> Result<M, Status> {
    M::decode_from(b)
}

/// The prost adapter (cargo feature `prost`, outside the semver promise).
#[cfg(feature = "prost")]
impl<T: prost::Message + Default> Message for T {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.encoded_len());
        // A `Vec` grows as needed: encoding cannot run out of space.
        let _ = prost::Message::encode(self, buf);
    }

    fn decode_from(bytes: &[u8]) -> Result<Self, Status> {
        T::decode(bytes).map_err(|e| Status::new(crate::Code::InvalidArgument, e.to_string()))
    }
}

#[cfg(all(test, feature = "prost"))]
mod tests {
    use super::*;

    #[test]
    fn prost_messages_round_trip_and_bad_input_is_invalid_argument() {
        let b = encode(&"hello".to_string());
        assert_eq!(decode::<String>(&b).unwrap(), "hello");
        let e = decode::<String>(&[0xff, 0xff]).unwrap_err();
        assert_eq!(e.code, crate::Code::InvalidArgument);
    }
}
