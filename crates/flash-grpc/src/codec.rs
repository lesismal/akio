//! Message codecs. gRPC carries bytes; with the `prost` feature these helpers convert prost
//! messages (any codec that turns a type into bytes works the same way).

#[cfg(feature = "prost")]
use crate::{Code, Status};

/// Encodes a prost message.
#[cfg(feature = "prost")]
pub fn encode<M: prost::Message>(m: &M) -> Vec<u8> {
    m.encode_to_vec()
}

/// Decodes a prost message; a malformed one is an `INVALID_ARGUMENT` status.
#[cfg(feature = "prost")]
pub fn decode<M: prost::Message + Default>(b: &[u8]) -> Result<M, Status> {
    M::decode(b).map_err(|e| Status::new(Code::InvalidArgument, e.to_string()))
}
