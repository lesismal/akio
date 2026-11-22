//! RFC 9841 shared dictionaries against Google's libbrotli: streams its encoder (built with
//! `BROTLI_EXPERIMENTAL`) made from the first 20,000 bytes of alice29.txt with serialized
//! dictionaries of each kind (`tests/data/shared`, written by
//! `tools/interop/brotli-shared/run.sh` with `UPDATE=1`, which also checks the other
//! direction and thousands of random dictionaries), and our encoder with them.

use std::path::Path;

use only_brotli::{
    Decompressor, Error, Level, SharedDictionary, compress_with_shared_dictionary, decompress,
    decompress_with_dictionary, decompress_with_shared_dictionary,
};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name),
    )
    .unwrap()
}

fn alice() -> Vec<u8> {
    let mut a = decompress(&data("alice29.txt.compressed"), 1 << 20).unwrap();
    a.truncate(20_000);
    a
}

#[test]
fn libbrotli_streams() {
    let text = alice();
    for name in ["prefix", "words", "transforms", "context"] {
        let dict = SharedDictionary::new(&data(&format!("shared/{name}.dict"))).unwrap();
        assert_eq!(dict.is_raw(), name == "prefix", "{name}");
        let br = data(&format!("shared/{name}.br"));
        assert_eq!(
            decompress_with_shared_dictionary(&br, text.len(), &dict).unwrap(),
            text,
            "{name}"
        );
        // Streamed, in small pieces.
        let mut d = Decompressor::with_shared_dictionary(&dict);
        let mut out = Vec::new();
        for p in br.chunks(7) {
            let mut at = 0;
            while at < p.len() {
                at += d
                    .decompress_vec(&p[at..], &mut out, text.len())
                    .unwrap()
                    .consumed;
            }
        }
        assert!(d.is_done() && out == text, "{name} streamed");
        // The custom words are used: the prefix alone does not decode it.
        let raw = decompress_with_dictionary(&br, text.len(), dict.prefix());
        assert_eq!(raw.as_deref() == Ok(&text[..]), name == "prefix", "{name}");
        // Our encoder with the dictionary: its prefix and, at levels 10 and 11, its custom
        // words (for a dictionary with custom words, smaller than with its prefix alone).
        for q in [5, 10, 11] {
            let ours = compress_with_shared_dictionary(Level::new(q), &text, &dict);
            assert_eq!(
                decompress_with_shared_dictionary(&ours, text.len(), &dict).unwrap(),
                text,
                "{name} level {q}"
            );
            // At level 11 within 1% of libbrotli's quality 11 (custom words: 6,867..7,054
            // bytes against 6,866..7,059; 7,609..7,692 without searching them).
            if q == 11 {
                assert!(
                    ours.len() * 100 <= br.len() * 101,
                    "{name}: {} against libbrotli's {}",
                    ours.len(),
                    br.len()
                );
            }
        }
    }
}

#[test]
fn errors() {
    assert_eq!(
        SharedDictionary::new(b"not a dictionary").err(),
        Some(Error::BadDictionary)
    );
    assert_eq!(
        Error::BadDictionary.to_string(),
        "invalid serialized shared dictionary"
    );
    // A raw dictionary behaves as decompress_with_dictionary.
    let dict = SharedDictionary::raw(b"0123456789abcdef");
    assert!(dict.is_raw());
    let packed = only_brotli::compress_with_dictionary(
        Level::BEST,
        b"0123456789abcdef!",
        b"0123456789abcdef",
    );
    assert_eq!(
        decompress_with_shared_dictionary(&packed, 99, &dict).unwrap(),
        b"0123456789abcdef!"
    );
}
