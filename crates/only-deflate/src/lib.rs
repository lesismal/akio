#![forbid(unsafe_code)]
//! DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) in pure, safe Rust, without
//! dependencies: the compression behind permessage-deflate in `only-ws`, the HTTP compression
//! middleware of `only-http` and gzip messages in `only-grpc`.
//!
//! - [`Inflater`]: streaming decompression with input split anywhere, output taken in pieces of
//!   any size, a size limit for decompression bombs ([`Inflater::decompress_vec`]) and window
//!   sizes from 2⁸ to 2¹⁵ bytes.
//! - [`Deflater`]: streaming compression (LZ77 with hash chains and lazy matching, dynamic
//!   Huffman codes limited to 15 bits, fixed codes or stored blocks, whichever is smallest)
//!   with zlib's levels 0..=9, [`Flush::Sync`] / [`Flush::Full`] / [`Flush::Finish`], window
//!   sizes from 2⁸ to 2¹⁵ bytes and [`Deflater::reset`] for permessage-deflate without context
//!   takeover.
//! - [`compress`] / [`decompress`]: one-shot helpers.
//! - [`Adler32`] / [`Crc32`]: the checksums of the zlib and gzip formats.
//!
//! ```
//! use only_deflate::{Format, Level, compress, decompress};
//!
//! let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
//! for format in [Format::Raw, Format::Zlib, Format::Gzip] {
//!     let packed = compress(format, Level::DEFAULT, &data);
//!     assert!(packed.len() < data.len() / 20);
//!     assert_eq!(decompress(format, &packed, data.len()).unwrap(), data);
//! }
//! ```
//!
//! The streams interoperate with zlib, zlib-rs, miniz and `gzip(1)` in both directions; the
//! decoder accepts and rejects exactly what zlib does on its checks of the Huffman code
//! descriptions.
#![warn(clippy::unwrap_used)]

mod checksum;
mod deflate;
mod inflate;
mod tables;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use checksum::{Adler32, Crc32, adler32, crc32};
pub use deflate::{Deflater, compress};
pub use inflate::{Inflater, Progress, decompress};

/// The container around the DEFLATE data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// Raw DEFLATE (RFC 1951), as in permessage-deflate, ZIP and HTTP `deflate` done wrong.
    Raw,
    /// zlib (RFC 1950): a two-byte header and an Adler-32 trailer (HTTP `deflate`).
    Zlib,
    /// gzip (RFC 1952): a header (with optional name, comment and extra fields) and a CRC-32 and
    /// length trailer (HTTP `gzip`, gRPC `gzip`). One member per stream.
    Gzip,
}

/// Compression level, 0 (stored, no compression) to 9 (smallest output); zlib's scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Level(u8);

impl Level {
    /// No compression (stored blocks).
    pub const NONE: Level = Level(0);
    /// The fastest compression.
    pub const FASTEST: Level = Level(1);
    /// zlib's default trade-off (6).
    pub const DEFAULT: Level = Level(6);
    /// The smallest output.
    pub const BEST: Level = Level(9);

    /// Level `n`, clamped to 0..=9.
    pub const fn new(n: u32) -> Level {
        Level(if n > 9 { 9 } else { n as u8 })
    }

    /// The level as a number, 0..=9.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// What [`Deflater::compress`] does after taking its input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Flush {
    /// Nothing: output may lag behind input (best compression).
    #[default]
    None,
    /// Write everything so far and end on a byte boundary with an empty stored block
    /// (`00 00 ff ff`); later data may still refer back to earlier data.
    Sync,
    /// Like [`Flush::Sync`], and later data does not refer back to earlier data (a decoder can
    /// start at this point).
    Full,
    /// Write everything and end the stream (final block, then the zlib or gzip trailer).
    Finish,
}

/// Why decompression failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The zlib or gzip header is malformed, names another method, or announces a window
    /// larger than the decoder's.
    BadHeader,
    /// The zlib stream needs a preset dictionary (not supported).
    DictionaryRequired,
    /// Block type 3 (reserved).
    BadBlockType,
    /// A stored block whose length and its complement disagree.
    BadStoredLength,
    /// A dynamic block's Huffman code description is invalid (over-subscribed or incomplete
    /// code, bad repeat, too many symbols, no end-of-block code).
    BadHuffmanCode,
    /// A literal/length or distance code that the block's code does not define.
    BadSymbol,
    /// A back-reference before the start of the data or beyond the window.
    BadDistance,
    /// The Adler-32, CRC-32 or length in the trailer does not match the data.
    ChecksumMismatch,
    /// The input ended before the stream did ([`decompress`] only).
    Truncated,
    /// The output would exceed the limit ([`decompress`] only).
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadHeader => "invalid zlib or gzip header",
            Error::DictionaryRequired => "zlib stream needs a preset dictionary",
            Error::BadBlockType => "invalid deflate block type",
            Error::BadStoredLength => "invalid stored block length",
            Error::BadHuffmanCode => "invalid Huffman code description",
            Error::BadSymbol => "invalid literal/length or distance code",
            Error::BadDistance => "invalid distance too far back",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::Truncated => "truncated stream",
            Error::TooLarge => "decompressed data too large",
        })
    }
}

impl std::error::Error for Error {}
