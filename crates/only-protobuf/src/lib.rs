#![forbid(unsafe_code)]
//! Protocol Buffers for `only`, without third-party dependencies.
//!
//! * [`encoding`]: the wire format (varints, ZigZag, fixed-width values, length-delimited
//!   fields, groups skipped) and the per-field encoders and decoders.
//! * [`Message`]: encode, decode, merge, length-delimited framing; [`Enumeration`] for open
//!   enums; [`UnknownFields`] keeps fields a message does not know and writes them back.
//! * [`well_known`]: `google.protobuf` `Empty`, `Timestamp`, `Duration`, `Any`, the wrappers,
//!   `FieldMask`, `Struct` / `Value` / `ListValue`, with conversions to `std` types.
//! * Decoding is bounded: messages and groups nest at most [`encoding::RECURSION_LIMIT`] deep,
//!   lengths are checked against the input, strings must be UTF-8.
//!
//! Messages are generated from `.proto` files by `only-protobuf-build` in `build.rs`
//! (no `protoc`), and included with [`include_proto!`]:
//!
//! ```ignore
//! // build.rs
//! fn main() {
//!     only_protobuf_build::compile(&["proto/helloworld.proto"], std::env::var("OUT_DIR").unwrap())
//!         .unwrap();
//! }
//!
//! // src/lib.rs
//! pub mod helloworld {
//!     only_protobuf::include_proto!("helloworld");
//! }
//! ```
//!
//! A message can also be written by hand:
//!
//! ```
//! use only_protobuf::{DecodeError, Message, encoding::{self, Int32, Reader, StringCodec, WireType}};
//!
//! #[derive(Debug, Default, PartialEq)]
//! struct Point {
//!     x: i32,
//!     label: String,
//! }
//!
//! impl Message for Point {
//!     fn encode_raw(&self, buf: &mut Vec<u8>) {
//!         encoding::encode_implicit::<Int32>(1, &self.x, buf);
//!         encoding::encode_implicit::<StringCodec>(2, &self.label, buf);
//!     }
//!     fn encoded_len(&self) -> usize {
//!         encoding::implicit_len::<Int32>(1, &self.x)
//!             + encoding::implicit_len::<StringCodec>(2, &self.label)
//!     }
//!     fn merge_field(&mut self, field: u32, wt: WireType, r: &mut Reader<'_>) -> Result<(), DecodeError> {
//!         match field {
//!             1 => encoding::merge_value::<Int32>(field, wt, r, &mut self.x),
//!             2 => encoding::merge_value::<StringCodec>(field, wt, r, &mut self.label),
//!             _ => r.skip_field(field, wt).map(drop),
//!         }
//!     }
//! }
//!
//! let p = Point { x: -3, label: "a".into() };
//! let bytes = p.encode_to_vec();
//! assert_eq!(Point::decode(&bytes).unwrap(), p);
//! ```
//!
//! Guide: [gRPC](https://lesismal.github.io/only/en/protocols/grpc.html)
//! (中文: [gRPC](https://lesismal.github.io/only/zh-CN/protocols/grpc.html)).
#![warn(clippy::unwrap_used)]

// Generated code names this crate `::only_protobuf`, also inside it (the well-known types).
extern crate self as only_protobuf;

pub mod encoding;
mod error;
mod message;
pub mod well_known;

pub use error::{DecodeError, DecodeErrorKind};
pub use message::{Enumeration, Message, Name, UnknownFields};

/// Includes the code `only-protobuf-build` generated for a protobuf package:
/// `include_proto!("helloworld")` includes `$OUT_DIR/helloworld.rs` (`_` for files without a
/// package).
#[macro_export]
macro_rules! include_proto {
    ($package:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $package, ".rs"));
    };
}
