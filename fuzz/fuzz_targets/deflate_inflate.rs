#![no_main]
//! akio-deflate's decoder on arbitrary bytes: never panics, split input/output agrees with
//! one-shot decoding, and on raw DEFLATE and zlib streams it accepts exactly what zlib-rs
//! accepts, with the same output.

use akio_deflate::{Error, Format, decompress, fuzzing};

fn zlib_rs(data: &[u8], zlib_header: bool) -> Option<Vec<u8>> {
    let mut z = flate2::Decompress::new(zlib_header);
    let mut out = Vec::with_capacity(fuzzing::LIMIT + 1);
    match z.decompress_vec(data, &mut out, flate2::FlushDecompress::Finish) {
        Ok(flate2::Status::StreamEnd) => Some(out),
        _ => None,
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzzing::inflate(data);
    for (format, zlib_header) in [(Format::Raw, false), (Format::Zlib, true)] {
        let ours = decompress(format, data, fuzzing::LIMIT);
        let theirs = zlib_rs(data, zlib_header);
        match (&ours, &theirs) {
            (Ok(a), Some(b)) => assert!(a == b, "{format:?}: outputs differ"),
            (Ok(_), None) => panic!("{format:?}: akio-deflate accepts what zlib-rs rejects"),
            (Err(Error::TooLarge), _) => {}
            (Err(e), Some(_)) => panic!("{format:?}: zlib-rs accepts what akio-deflate rejects ({e})"),
            (Err(_), None) => {}
        }
    }
});
