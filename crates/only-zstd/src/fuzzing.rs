//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them (adding a differential check against libzstd there); the unit tests below replay
//! `fuzz/corpus/<target>` on stable.

use crate::{Error, Level, compress};

/// Output limit of the decoding target.
pub const LIMIT: usize = 1 << 20;

/// `zstd_decompress`: arbitrary bytes as concatenated frames. Never panics; a successful
/// decoding also succeeds with its exact size as the limit and fails with
/// [`Error::TooLarge`] one byte below.
pub fn decompress_checked(data: &[u8]) -> Result<Vec<u8>, Error> {
    let r = crate::decompress(data, LIMIT);
    if let Ok(out) = &r {
        assert!(
            crate::decompress(data, out.len()).as_ref() == Ok(out),
            "exact limit fails"
        );
        if !out.is_empty() {
            assert_eq!(
                crate::decompress(data, out.len() - 1),
                Err(Error::TooLarge),
                "limit one below the size"
            );
        }
    }
    r
}

/// `zstd_decompress` without the result (see [`decompress_checked`]).
pub fn decompress(data: &[u8]) {
    let _ = decompress_checked(data);
}

/// The level and body of a `zstd_roundtrip` input: the level from `data[0]`, the rest is the
/// data.
pub fn split(data: &[u8]) -> Option<(Level, &[u8])> {
    let (&b, body) = data.split_first()?;
    Some((Level::new(u32::from(b % 22) + 1), body))
}

/// `zstd_roundtrip`: compresses `data[1..]` at the level of `data[0]` and checks that
/// decompression gives it back, within exactly its size as the limit. Returns the frame.
pub fn roundtrip_frame(data: &[u8]) -> Option<Vec<u8>> {
    let (level, body) = split(data)?;
    let packed = compress(level, body);
    let back = crate::decompress(&packed, body.len()).expect("own output decodes");
    assert!(back == body, "round trip differs");
    if !body.is_empty() {
        assert_eq!(
            crate::decompress(&packed, body.len() - 1),
            Err(Error::TooLarge)
        );
    }
    Some(packed)
}

/// `zstd_roundtrip` without the frame (see [`roundtrip_frame`]).
pub fn roundtrip(data: &[u8]) {
    let _ = roundtrip_frame(data);
}

#[cfg(test)]
mod tests {
    fn replay(target: &str, f: fn(&[u8])) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus")
            .join(target);
        let mut n = 0;
        for e in std::fs::read_dir(&dir).expect("corpus directory") {
            let p = e.expect("entry").path();
            f(&std::fs::read(&p).expect("corpus file"));
            n += 1;
        }
        assert!(n > 0, "empty corpus {}", dir.display());
    }

    #[test]
    fn zstd_decompress_corpus() {
        replay("zstd_decompress", super::decompress);
    }

    #[test]
    fn zstd_roundtrip_corpus() {
        replay("zstd_roundtrip", super::roundtrip);
    }
}
