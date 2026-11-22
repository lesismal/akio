#![no_main]
//! akio-zstd's decoder on arbitrary bytes: never panics, the limit is exact, and it accepts what
//! libzstd (the `zstd` crate) accepts, with the same output. Tolerated differences, all where
//! akio-zstd is stricter (see the crate README):
//! - `BadHuffmanStream`: libzstd's fast four-stream Huffman decoder does not check that each
//!   stream ends exactly where its symbols do;
//! - `BadBlock`: libzstd 1.5.7's one-shot decoder does not check a block's decompressed size
//!   against Block_Maximum_Size (its streaming decoder and later versions do).
//!
//! The `zstd` crate is built without its `legacy` feature, so neither side decodes pre-1.0
//! frames.

use akio_zstd::{Error, fuzzing};

fn libzstd(data: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::decompress(data, fuzzing::LIMIT).ok()
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let ours = fuzzing::decompress_checked(data);
    let theirs = libzstd(data);
    match (&ours, &theirs) {
        (Ok(a), Some(b)) => assert!(a == b, "outputs differ"),
        (Ok(_), None) => panic!("akio-zstd accepts what libzstd rejects"),
        (Err(Error::TooLarge), _) | (Err(_), None) => {}
        (Err(Error::BadHuffmanStream | Error::BadBlock), Some(_)) => {}
        (Err(e), Some(_)) => panic!("libzstd accepts what akio-zstd rejects ({e})"),
    }
});
