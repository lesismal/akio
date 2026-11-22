#![no_main]
//! akio-brotli's decoder on arbitrary bytes: never panics, is deterministic with an exact
//! limit, and accepts exactly what `brotli-decompressor` (a port of Google's decoder) accepts
//! as one complete stream with nothing after it, with the same output.
//!
//! brotli-decompressor's state allows the non-standard large-window extension by default; it is
//! turned off, as in Google's decoder, since RFC 7932 has no such thing.
//!
//! One known difference has no verdict: a meta-block whose commands produce more bytes than its header
//! declares is an error in Google's C decoder (`BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2`) and
//! in akio-brotli (`BadBlockLength`), but brotli-decompressor 5 only notices it in the last
//! meta-block and accepts the overlong output otherwise; that case has no verdict.

use akio_brotli::{Error, decompress, fuzzing};
use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

/// `Some(output)` for a complete stream that uses all of `data`, `None` for a rejected one;
/// `Err(())` when the output passes the limit (no verdict).
fn reference(data: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    let mut out = vec![0u8; fuzzing::LIMIT + 1];
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    state.large_window = false;
    let (mut avail_in, mut in_off) = (data.len(), 0);
    let (mut avail_out, mut out_off, mut total) = (out.len(), 0, 0);
    match BrotliDecompressStream(
        &mut avail_in,
        &mut in_off,
        data,
        &mut avail_out,
        &mut out_off,
        &mut out,
        &mut total,
        &mut state,
    ) {
        BrotliResult::ResultSuccess if avail_in == 0 && out_off <= fuzzing::LIMIT => {
            out.truncate(out_off);
            Ok(Some(out))
        }
        BrotliResult::NeedsMoreOutput => Err(()),
        _ if out_off > fuzzing::LIMIT => Err(()),
        _ => Ok(None),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzzing::decompress(data);
    let ours = decompress(data, fuzzing::LIMIT);
    let Ok(theirs) = reference(data) else {
        return;
    };
    match (&ours, &theirs) {
        (Ok(a), Some(b)) => assert!(a == b, "outputs differ"),
        (Ok(_), None) => panic!("akio-brotli accepts what brotli-decompressor rejects"),
        (Err(Error::TooLarge), _) => {}
        (Err(Error::BadBlockLength), Some(_)) => {}
        (Err(e), Some(_)) => panic!("brotli-decompressor accepts what akio-brotli rejects ({e})"),
        (Err(_), None) => {}
    }
});
