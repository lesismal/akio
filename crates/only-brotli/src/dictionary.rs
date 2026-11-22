//! The static dictionary (RFC 7932 section 8 and appendices A and B).
//!
//! `dictionary.bin` is `c/common/dictionary.bin` of Google's brotli at tag v1.1.0 (MIT licence,
//! Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors): 122,784 bytes, byte for byte the
//! hex dump of RFC 7932 Appendix A (SHA-256
//! 20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70). The transforms are those
//! of Appendix B, generated from the same source (`c/common/transform.c`).

/// The dictionary words, grouped by length 4..=24.
pub(crate) static DICTIONARY: &[u8; 122_784] = include_bytes!("dictionary.bin");

/// Offset of the words of each length in [`DICTIONARY`].
pub(crate) const OFFSETS_BY_LENGTH: [u32; 25] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864,
    104704, 106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016,
];

/// log2 of the number of words of each length (`NDBITS`); 0 for lengths without words.
pub(crate) const SIZE_BITS_BY_LENGTH: [u8; 25] = [
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5,
];

/// What a transform does to the word between its prefix and suffix.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum T {
    Identity,
    UppercaseFirst,
    UppercaseAll,
    OmitFirst(u8),
    OmitLast(u8),
}

/// A word transform: prefix, kind, suffix.
pub(crate) struct Transform(
    pub(crate) &'static [u8],
    pub(crate) T,
    pub(crate) &'static [u8],
);

/// Uppercases the character at the start of `w` (the RFC's simplified UTF-8 model) and returns
/// its length in bytes; bytes past the end of `w` are left alone.
pub(crate) fn to_upper(w: &mut [u8]) -> usize {
    let Some(&b) = w.first() else {
        return 1;
    };
    if b < 0xc0 {
        if b.is_ascii_lowercase() {
            w[0] ^= 32;
        }
        1
    } else if b < 0xe0 {
        if let Some(x) = w.get_mut(1) {
            *x ^= 32;
        }
        2
    } else {
        if let Some(x) = w.get_mut(2) {
            *x ^= 5;
        }
        3
    }
}

/// Writes `word` under transform `t` to the start of `buf` and returns the number of bytes
/// written (at most 8 + 24 + 8: no prefix or suffix is longer than 8 bytes).
pub(crate) fn transform_word(buf: &mut [u8; 64], word: &[u8], t: usize) -> usize {
    let Some(Transform(prefix, kind, suffix)) = TRANSFORMS.get(t) else {
        return 0;
    };
    let mut n = 0;
    for &b in *prefix {
        buf[n] = b;
        n += 1;
    }
    let w: &[u8] = match *kind {
        T::OmitFirst(k) => word.get(usize::from(k)..).unwrap_or(&[]),
        T::OmitLast(k) => &word[..word.len().saturating_sub(usize::from(k))],
        _ => word,
    };
    let start = n;
    for &b in w {
        buf[n] = b;
        n += 1;
    }
    match *kind {
        T::UppercaseFirst => {
            to_upper(&mut buf[start..n]);
        }
        T::UppercaseAll => {
            let mut i = start;
            while i < n {
                i += to_upper(&mut buf[i..n]);
            }
        }
        _ => {}
    }
    for &b in *suffix {
        buf[n] = b;
        n += 1;
    }
    n
}

/// The 121 transforms of Appendix B, in order.
pub(crate) const TRANSFORMS: [Transform; 121] = [
    Transform(b"", T::Identity, b""),
    Transform(b"", T::Identity, b" "),
    Transform(b" ", T::Identity, b" "),
    Transform(b"", T::OmitFirst(1), b""),
    Transform(b"", T::UppercaseFirst, b" "),
    Transform(b"", T::Identity, b" the "),
    Transform(b" ", T::Identity, b""),
    Transform(b"s ", T::Identity, b" "),
    Transform(b"", T::Identity, b" of "),
    Transform(b"", T::UppercaseFirst, b""),
    Transform(b"", T::Identity, b" and "),
    Transform(b"", T::OmitFirst(2), b""),
    Transform(b"", T::OmitLast(1), b""),
    Transform(b", ", T::Identity, b" "),
    Transform(b"", T::Identity, b", "),
    Transform(b" ", T::UppercaseFirst, b" "),
    Transform(b"", T::Identity, b" in "),
    Transform(b"", T::Identity, b" to "),
    Transform(b"e ", T::Identity, b" "),
    Transform(b"", T::Identity, b"\x22"),
    Transform(b"", T::Identity, b"."),
    Transform(b"", T::Identity, b"\x22>"),
    Transform(b"", T::Identity, b"\x0a"),
    Transform(b"", T::OmitLast(3), b""),
    Transform(b"", T::Identity, b"]"),
    Transform(b"", T::Identity, b" for "),
    Transform(b"", T::OmitFirst(3), b""),
    Transform(b"", T::OmitLast(2), b""),
    Transform(b"", T::Identity, b" a "),
    Transform(b"", T::Identity, b" that "),
    Transform(b" ", T::UppercaseFirst, b""),
    Transform(b"", T::Identity, b". "),
    Transform(b".", T::Identity, b""),
    Transform(b" ", T::Identity, b", "),
    Transform(b"", T::OmitFirst(4), b""),
    Transform(b"", T::Identity, b" with "),
    Transform(b"", T::Identity, b"'"),
    Transform(b"", T::Identity, b" from "),
    Transform(b"", T::Identity, b" by "),
    Transform(b"", T::OmitFirst(5), b""),
    Transform(b"", T::OmitFirst(6), b""),
    Transform(b" the ", T::Identity, b""),
    Transform(b"", T::OmitLast(4), b""),
    Transform(b"", T::Identity, b". The "),
    Transform(b"", T::UppercaseAll, b""),
    Transform(b"", T::Identity, b" on "),
    Transform(b"", T::Identity, b" as "),
    Transform(b"", T::Identity, b" is "),
    Transform(b"", T::OmitLast(7), b""),
    Transform(b"", T::OmitLast(1), b"ing "),
    Transform(b"", T::Identity, b"\x0a\x09"),
    Transform(b"", T::Identity, b":"),
    Transform(b" ", T::Identity, b". "),
    Transform(b"", T::Identity, b"ed "),
    Transform(b"", T::OmitFirst(9), b""),
    Transform(b"", T::OmitFirst(7), b""),
    Transform(b"", T::OmitLast(6), b""),
    Transform(b"", T::Identity, b"("),
    Transform(b"", T::UppercaseFirst, b", "),
    Transform(b"", T::OmitLast(8), b""),
    Transform(b"", T::Identity, b" at "),
    Transform(b"", T::Identity, b"ly "),
    Transform(b" the ", T::Identity, b" of "),
    Transform(b"", T::OmitLast(5), b""),
    Transform(b"", T::OmitLast(9), b""),
    Transform(b" ", T::UppercaseFirst, b", "),
    Transform(b"", T::UppercaseFirst, b"\x22"),
    Transform(b".", T::Identity, b"("),
    Transform(b"", T::UppercaseAll, b" "),
    Transform(b"", T::UppercaseFirst, b"\x22>"),
    Transform(b"", T::Identity, b"=\x22"),
    Transform(b" ", T::Identity, b"."),
    Transform(b".com/", T::Identity, b""),
    Transform(b" the ", T::Identity, b" of the "),
    Transform(b"", T::UppercaseFirst, b"'"),
    Transform(b"", T::Identity, b". This "),
    Transform(b"", T::Identity, b","),
    Transform(b".", T::Identity, b" "),
    Transform(b"", T::UppercaseFirst, b"("),
    Transform(b"", T::UppercaseFirst, b"."),
    Transform(b"", T::Identity, b" not "),
    Transform(b" ", T::Identity, b"=\x22"),
    Transform(b"", T::Identity, b"er "),
    Transform(b" ", T::UppercaseAll, b" "),
    Transform(b"", T::Identity, b"al "),
    Transform(b" ", T::UppercaseAll, b""),
    Transform(b"", T::Identity, b"='"),
    Transform(b"", T::UppercaseAll, b"\x22"),
    Transform(b"", T::UppercaseFirst, b". "),
    Transform(b" ", T::Identity, b"("),
    Transform(b"", T::Identity, b"ful "),
    Transform(b" ", T::UppercaseFirst, b". "),
    Transform(b"", T::Identity, b"ive "),
    Transform(b"", T::Identity, b"less "),
    Transform(b"", T::UppercaseAll, b"'"),
    Transform(b"", T::Identity, b"est "),
    Transform(b" ", T::UppercaseFirst, b"."),
    Transform(b"", T::UppercaseAll, b"\x22>"),
    Transform(b" ", T::Identity, b"='"),
    Transform(b"", T::UppercaseFirst, b","),
    Transform(b"", T::Identity, b"ize "),
    Transform(b"", T::UppercaseAll, b"."),
    Transform(b"\xc2\xa0", T::Identity, b""),
    Transform(b" ", T::Identity, b","),
    Transform(b"", T::UppercaseFirst, b"=\x22"),
    Transform(b"", T::UppercaseAll, b"=\x22"),
    Transform(b"", T::Identity, b"ous "),
    Transform(b"", T::UppercaseAll, b", "),
    Transform(b"", T::UppercaseFirst, b"='"),
    Transform(b" ", T::UppercaseFirst, b","),
    Transform(b" ", T::UppercaseAll, b"=\x22"),
    Transform(b" ", T::UppercaseAll, b", "),
    Transform(b"", T::UppercaseAll, b","),
    Transform(b"", T::UppercaseAll, b"("),
    Transform(b"", T::UppercaseAll, b". "),
    Transform(b" ", T::UppercaseAll, b"."),
    Transform(b"", T::UppercaseAll, b"='"),
    Transform(b" ", T::UppercaseAll, b". "),
    Transform(b" ", T::UppercaseFirst, b"=\x22"),
    Transform(b" ", T::UppercaseAll, b"='"),
    Transform(b" ", T::UppercaseFirst, b"='"),
];
