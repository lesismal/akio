#![forbid(unsafe_code)]
//! Zstandard (RFC 8878) in pure, safe Rust, without dependencies: the `zstd` algorithm of TLS
//! certificate compression (RFC 8879) in `only-tls` and the `zstd` content coding of `only-http`.
//!
//! - [`decompress`]: one-shot decompression of one or more concatenated frames (skippable frames
//!   included) under an output limit, the decompression-bomb defence. Raw, RLE and compressed
//!   blocks; raw, RLE, Huffman (one or four streams) and treeless literals; predefined, RLE,
//!   FSE-compressed and repeated sequence tables; repeat offsets; Frame_Content_Size and the
//!   XXH64 content checksum are verified.
//! - [`compress`]: one frame with Frame_Content_Size and a content checksum. LZ77 with libzstd's
//!   `fast` / `double_fast` match finders (levels 1..=4), hash chains with lazy matching
//!   (5..=15) and, from level 16, a shortest-path parse priced with the symbol statistics of a
//!   previous pass (libzstd's `btopt` / `btultra`); Huffman-coded literals and FSE-coded
//!   sequences with tables chosen per block by size, the previous block's tables repeated when
//!   cheaper, raw or RLE blocks when those are smaller. Levels follow zstd's 1..=22 scale.
//! - [`Compressor`] / [`Decompressor`]: streaming, with bounded memory: input in pieces of any
//!   size, output a block at a time ([`Flush`] makes everything so far decodable); the decoder
//!   holds the frame's window (at most 8 MiB by default) and one block of input.
//! - [`Dictionary`]: raw content or the trained format of `zstd --train` (Dictionary_ID,
//!   entropy tables, repeat offsets), for [`compress_with_dictionary`],
//!   [`decompress_with_dictionary`] and the streaming types.
//! - [`xxh64`]: the XXH64 hash behind the content checksum.
//!
//! ```
//! use only_zstd::{Level, compress, decompress};
//!
//! let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
//! let packed = compress(Level::DEFAULT, &data);
//! assert!(packed.len() < data.len() / 20);
//! assert_eq!(decompress(&packed, data.len()).unwrap(), data);
//! // One byte less than the content is refused.
//! assert_eq!(decompress(&packed, data.len() - 1), Err(only_zstd::Error::TooLarge));
//! ```
//!
//! The decoder accepts and rejects what libzstd does, with one intentional difference: it
//! requires every Huffman-coded literal stream to end exactly where its symbols do
//! ([`Error::BadHuffmanStream`]), which libzstd's fast four-stream decoder does not check.
//! Frames that need a dictionary are refused without one ([`Error::DictionaryRequired`]), as by
//! libzstd. The streaming decoder holds the frame's window, not the whole frame, so a match
//! reaching further back than the window (and what it still holds beyond it) is refused
//! ([`Error::BadOffset`]), as by libzstd's streaming decoder.
#![warn(clippy::unwrap_used)]

mod bits;
mod cstream;
mod decode;
mod dict;
mod dstream;
mod encode;
mod fse;
mod huffman;
mod tables;
mod xxhash;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use cstream::Compressor;
pub use decode::decompress;
pub use dict::Dictionary;
pub use dstream::{DEFAULT_MAX_WINDOW, Decompressor, decompress_with_dictionary};
pub use encode::{compress, compress_with_dictionary};
pub use xxhash::xxh64;

/// What a streaming [`Compressor::compress`] call does after taking its input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Flush {
    /// Nothing: input may stay buffered until a block (128 KiB) is full (best compression).
    #[default]
    None,
    /// Write everything taken so far as complete blocks, so that a decoder can produce all of
    /// it; later data may still refer back to earlier data.
    Flush,
    /// Write everything and end the frame (last block, content checksum).
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
    /// The input so far ends with a complete frame and all of its output was delivered.
    pub done: bool,
}

/// Compression level on zstd's scale, 1 (fastest) to 22 (smallest output).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Level(u8);

impl Level {
    /// The fastest compression (1).
    pub const FASTEST: Level = Level(1);
    /// zstd's default trade-off (3).
    pub const DEFAULT: Level = Level(3);
    /// The smallest output (22).
    pub const BEST: Level = Level(22);

    /// Level `n`, clamped to 1..=22 (0 gives 1).
    pub const fn new(n: u32) -> Level {
        Level(if n == 0 {
            1
        } else if n > 22 {
            22
        } else {
            n as u8
        })
    }

    /// The level as a number, 1..=22.
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
    /// A frame starts with neither the Zstandard nor a skippable-frame magic number.
    BadMagic,
    /// The frame header sets its reserved bit, or a skippable frame's size overflows.
    BadFrameHeader,
    /// The frame announces a window larger than 2³¹ + 2³⁰ · 7/8 bytes (libzstd's limit).
    WindowTooLarge,
    /// The frame names a dictionary and none was given.
    DictionaryRequired,
    /// The frame names a dictionary other than the one given.
    WrongDictionary,
    /// A trained dictionary is malformed: invalid entropy tables, or repeat offsets that are
    /// zero or larger than its content.
    BadDictionary,
    /// A block of the reserved type, or larger than the frame's maximum block size.
    BadBlock,
    /// The literals section header is invalid, or repeats a Huffman table that does not exist.
    BadLiterals,
    /// The Huffman tree description of the literals is invalid.
    BadHuffmanTable,
    /// A Huffman-coded literal stream lacks its end mark, or does not end exactly where its
    /// symbols do.
    BadHuffmanStream,
    /// An FSE table description of the sequences is invalid, or repeats a table that does not
    /// exist.
    BadFseTable,
    /// The sequences section is invalid: its header, its bit stream (which must end exactly
    /// after the last sequence), or literal lengths beyond the block's literals.
    BadSequences,
    /// A match offset of zero or reaching before the start of the frame.
    BadOffset,
    /// The frame's content differs in size from its Frame_Content_Size.
    ContentSizeMismatch,
    /// The content checksum does not match the data.
    ChecksumMismatch,
    /// The input ended before the frame did, or 1 to 4 bytes follow the last frame.
    Truncated,
    /// The output would exceed the limit.
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadMagic => "unknown frame magic number",
            Error::BadFrameHeader => "invalid frame header",
            Error::WindowTooLarge => "window size too large",
            Error::DictionaryRequired => "frame needs a dictionary",
            Error::WrongDictionary => "frame needs another dictionary",
            Error::BadDictionary => "malformed dictionary",
            Error::BadBlock => "invalid block",
            Error::BadLiterals => "invalid literals section",
            Error::BadHuffmanTable => "invalid Huffman tree description",
            Error::BadHuffmanStream => "corrupt Huffman-coded literals",
            Error::BadFseTable => "invalid FSE table description",
            Error::BadSequences => "invalid sequences section",
            Error::BadOffset => "invalid match offset",
            Error::ContentSizeMismatch => "frame content size mismatch",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::Truncated => "truncated input",
            Error::TooLarge => "decompressed data too large",
        })
    }
}

impl std::error::Error for Error {}
