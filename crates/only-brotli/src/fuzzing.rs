//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them (adding a differential check against `brotli-decompressor` there); the unit tests
//! below replay `fuzz/corpus/<target>` on stable.

use crate::{Error, Level, compress};

/// Output limit of the decoding targets.
pub const LIMIT: usize = 1 << 20;

/// `brotli_decompress`: arbitrary bytes as a brotli stream. Never panics; decoding is
/// deterministic, and the limit is exact: a stream that decodes to `n` bytes decodes with limit
/// `n` and fails with `TooLarge` under limit `n - 1`.
pub fn decompress(data: &[u8]) {
    let r = crate::decompress(data, LIMIT);
    match &r {
        Ok(out) => {
            assert!(out.len() <= LIMIT);
            let again = crate::decompress(data, out.len()).expect("decodes with an exact limit");
            assert!(again == *out, "output differs between runs");
            if !out.is_empty() {
                assert_eq!(crate::decompress(data, out.len() - 1), Err(Error::TooLarge));
            }
        }
        Err(Error::TooLarge) => {}
        Err(e) => {
            // A stream that fails does so whatever the limit, once the limit is big enough.
            assert_eq!(crate::decompress(data, LIMIT * 2).err(), Some(*e));
        }
    }
}

/// `brotli_roundtrip`: compresses `data[1..]` at the level chosen by `data[0]` and checks that
/// decompression gives it back, with an exact limit.
pub fn roundtrip(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let level = Level::new(u32::from(cfg) % 12);
    let packed = compress(level, body);
    let back = crate::decompress(&packed, body.len()).expect("own output decodes");
    assert!(back == body, "round trip differs");
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
    fn brotli_decompress_corpus() {
        replay("brotli_decompress", super::decompress);
    }

    #[test]
    fn brotli_roundtrip_corpus() {
        replay("brotli_roundtrip", super::roundtrip);
    }
}
