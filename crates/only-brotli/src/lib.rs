#![forbid(unsafe_code)]
//! Brotli (RFC 7932) in pure, safe Rust, without dependencies: the `br` content coding of the
//! HTTP compression middleware in `only-http` and certificate compression (RFC 8879) in
//! `only-tls`.
//!
//! - [`decompress`]: one-shot decompression of a complete brotli stream under a size limit (the
//!   decompression-bomb defence). The whole format is implemented: window sizes 2¹⁰..2²⁴,
//!   uncompressed, metadata and empty meta-blocks, simple and complex prefix codes, block
//!   switching for literals, commands and distances, the four literal context modes, context
//!   maps (run lengths and inverse move-to-front), `NPOSTFIX` / `NDIRECT` distance codes, the
//!   distance ring and its 16 short codes, and the static dictionary with its 121 transforms.
//!   The decoder accepts and rejects the same streams as Google's decoder (the differential
//!   fuzz target checks that against `brotli-decompressor`), refuses the non-standard
//!   large-window extension and refuses data after the end of the stream.
//! - [`compress`]: LZ77 over hash chains (greedy at the low levels, lazy matching from level 4,
//!   cost-based optimal parsing at levels 10 and 11, where static dictionary words are
//!   candidates too), literals coded with a context map over clustered context histograms
//!   from level 5, block splitting (block types for literals, commands and distances) from
//!   level 4, prefix codes limited to 15 bits, uncompressed meta-blocks where those are
//!   smaller. Levels follow the brotli quality scale 0..=11.
//! - [`Compressor`] / [`Decompressor`]: streaming, with bounded memory: input in pieces of any
//!   size, output a meta-block at a time ([`Flush`] makes everything so far decodable); the
//!   decoder resumes where its input ran out at the last command or header unit.
//! - [`compress_with_dictionary`] / [`decompress_with_dictionary`]: raw (LZ77 prefix)
//!   dictionaries, as `brotli -D` and Google's `BROTLI_SHARED_DICTIONARY_RAW` use them.
//!
//! ```
//! use only_brotli::{Level, compress, decompress};
//!
//! let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
//! let packed = compress(Level::DEFAULT, &data);
//! assert!(packed.len() < data.len() / 20);
//! assert_eq!(decompress(&packed, data.len()).unwrap(), data);
//! ```
#![warn(clippy::unwrap_used)]

mod bits;
mod cstream;
mod decode;
mod dictionary;
mod dstream;
mod encode;
mod huffman;
mod tables;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use cstream::Compressor;
pub use decode::{decompress, decompress_with_dictionary};
pub use dstream::Decompressor;
pub use encode::{compress, compress_with_dictionary};

/// What a streaming [`Compressor::compress`] call does after taking its input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Flush {
    /// Nothing: input may stay buffered until a meta-block is full (best compression).
    #[default]
    None,
    /// End the current meta-block and pad to a byte boundary with an empty metadata block, so
    /// that a decoder can produce everything taken so far; later data may still refer back
    /// to earlier data.
    Flush,
    /// Write everything and end the stream.
    Finish,
}

/// What one [`Decompressor`] call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// Input bytes consumed (taken into the decompressor: they are not passed again).
    pub consumed: usize,
    /// Output bytes written.
    pub produced: usize,
    /// The stream ended and all of its output was delivered.
    pub done: bool,
}

/// Compression level, 0 (fastest) to 11 (smallest output); brotli's quality scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Level(u8);

impl Level {
    /// The fastest compression that still finds matches (1).
    pub const FASTEST: Level = Level(1);
    /// A balanced trade-off (6).
    pub const DEFAULT: Level = Level(6);
    /// The smallest output (11).
    pub const BEST: Level = Level(11);

    /// Level `n`, clamped to 0..=11.
    pub const fn new(n: u32) -> Level {
        Level(if n > 11 { 11 } else { n as u8 })
    }

    /// The level as a number, 0..=11.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// Why decompression failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The window size in the stream header is invalid, or names the non-standard large-window
    /// extension.
    BadWindow,
    /// A meta-block header is malformed: a length with a superfluous zero nibble or byte, or a
    /// reserved bit set.
    BadHeader,
    /// A prefix code description is invalid (over-subscribed or incomplete code, a symbol
    /// outside the alphabet, a repeated symbol, a repeat past the end of the alphabet).
    BadPrefixCode,
    /// A context map run goes past the end of the map.
    BadContextMap,
    /// The commands of a meta-block produce more bytes than its header declares.
    BadBlockLength,
    /// A distance outside both the window and the static dictionary.
    BadDistance,
    /// A static dictionary reference with an invalid word length or transform.
    BadDictionaryReference,
    /// Padding bits that must be zero are not.
    BadPadding,
    /// Bytes follow the end of the stream.
    TrailingData,
    /// The input ended before the stream did.
    Truncated,
    /// The output would exceed the limit.
    TooLarge,
    /// The stream's window is larger than the streaming decoder accepts
    /// ([`Decompressor::max_window_bits`]).
    WindowTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadWindow => "invalid brotli window size",
            Error::BadHeader => "invalid brotli meta-block header",
            Error::BadPrefixCode => "invalid prefix code description",
            Error::BadContextMap => "invalid context map",
            Error::BadBlockLength => "meta-block longer than declared",
            Error::BadDistance => "invalid backward distance",
            Error::BadDictionaryReference => "invalid static dictionary reference",
            Error::BadPadding => "non-zero padding bits",
            Error::TrailingData => "data after the end of the brotli stream",
            Error::Truncated => "truncated stream",
            Error::TooLarge => "decompressed data too large",
            Error::WindowTooLarge => "brotli window larger than allowed",
        })
    }
}

impl std::error::Error for Error {}
