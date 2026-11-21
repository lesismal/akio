//! Static dictionary references for the encoder (RFC 7932 section 8): the words of the
//! dictionary that, under one of the 121 transforms, produce the input at a position.
//!
//! The words are indexed by their first four bytes in lower case; at a position the input is
//! looked up after each transform prefix it starts with, and a candidate word is checked against
//! the transforms with that prefix: identity, uppercase first or all (ASCII), and omitting the
//! last bytes, each with its suffix. Transforms that omit the first bytes are not searched.

use std::sync::OnceLock;

use crate::dictionary::{
    DICTIONARY, OFFSETS_BY_LENGTH, SIZE_BITS_BY_LENGTH, T, TRANSFORMS, transform_word,
};

const BUCKET_BITS: u32 = 15;

struct Index {
    /// Per bucket: the start of its entries in `entries` (and the next bucket's start).
    starts: Vec<u32>,
    /// `length << 16 | word index`.
    entries: Vec<u32>,
    /// The prefixes of the searched transforms, each with its transforms: id, kind, suffix.
    prefixes: Vec<(&'static [u8], Vec<(u8, T, &'static [u8])>)>,
}

fn bucket(b: &[u8]) -> usize {
    let k = u32::from_le_bytes([
        b[0].to_ascii_lowercase(),
        b[1].to_ascii_lowercase(),
        b[2].to_ascii_lowercase(),
        b[3].to_ascii_lowercase(),
    ]);
    (k.wrapping_mul(0x1E35_A7BD) >> (32 - BUCKET_BITS)) as usize
}

fn word(len: usize, idx: usize) -> &'static [u8] {
    let at = OFFSETS_BY_LENGTH[len] as usize + idx * len;
    &DICTIONARY[at..at + len]
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut keyed: Vec<(u32, u32)> = Vec::new();
        for len in 4..=24usize {
            let bits = SIZE_BITS_BY_LENGTH[len];
            for idx in 0..1usize << bits {
                let w = word(len, idx);
                keyed.push((bucket(w) as u32, (len as u32) << 16 | idx as u32));
            }
        }
        keyed.sort_unstable();
        let mut starts = vec![0u32; (1 << BUCKET_BITS) + 1];
        for &(b, _) in &keyed {
            starts[b as usize + 1] += 1;
        }
        for i in 0..1 << BUCKET_BITS {
            starts[i + 1] += starts[i];
        }
        let entries = keyed.into_iter().map(|(_, e)| e).collect();
        let mut prefixes: Vec<(&'static [u8], Vec<(u8, T, &'static [u8])>)> = Vec::new();
        for (t, tr) in TRANSFORMS.iter().enumerate() {
            if matches!(tr.1, T::OmitFirst(_)) {
                continue;
            }
            let e = (t as u8, tr.1, tr.2);
            match prefixes.iter_mut().find(|(p, _)| *p == tr.0) {
                Some((_, ts)) => ts.push(e),
                None => prefixes.push((tr.0, vec![e])),
            }
        }
        Index {
            starts,
            entries,
            prefixes,
        }
    })
}

/// A static dictionary reference: the bytes it produces, the word length (the command's copy
/// length) and its address (`transform << NDBITS | word index`, to which the distance adds
/// the window's reach, one and a raw dictionary's length).
#[derive(Clone, Copy, Debug)]
pub(super) struct DictMatch {
    pub(super) out: u8,
    pub(super) len: u8,
    pub(super) addr: u32,
}

/// The references that produce a prefix of `s`, the one with the lowest address for each
/// output length, into `found` (cleared first).
pub(super) fn matches(s: &[u8], found: &mut Vec<DictMatch>) {
    found.clear();
    let ix = index();
    let mut best: [Option<DictMatch>; 64] = [None; 64];
    for (prefix, transforms) in &ix.prefixes {
        let j = prefix.len();
        if s.len() < j + 4 || !s.starts_with(prefix) {
            continue;
        }
        let rest = &s[j..];
        let b = bucket(rest);
        let (from, to) = (ix.starts[b] as usize, ix.starts[b + 1] as usize);
        for &e in &ix.entries[from..to] {
            let len = (e >> 16) as usize;
            let idx = (e & 0xffff) as usize;
            let w = word(len, idx);
            // Exact, first letter upper case and all upper case match lengths (ASCII).
            let exact = w.iter().zip(rest).take_while(|(a, b)| a == b).count();
            let upper_first = match (w.first(), rest.first()) {
                (Some(&a), Some(&b)) if a.is_ascii_lowercase() && b == a ^ 32 => {
                    1 + w[1..]
                        .iter()
                        .zip(&rest[1..])
                        .take_while(|(a, b)| a == b)
                        .count()
                }
                _ => 0,
            };
            let upper_all = w
                .iter()
                .zip(rest)
                .take_while(|(a, b)| a.to_ascii_uppercase() == **b)
                .count();
            if exact < 4.min(len) && upper_first < len && upper_all < len {
                continue;
            }
            // Upper-casing is checked as ASCII; words with other bytes are checked by
            // transforming them.
            let ascii = w.is_ascii();
            for &(t, kind, suffix) in transforms {
                let wl = match kind {
                    T::Identity if exact == len => len,
                    T::UppercaseFirst if upper_first == len => len,
                    T::UppercaseAll if upper_all == len => len,
                    T::OmitLast(c) if usize::from(c) < len && len - usize::from(c) <= exact => {
                        len - usize::from(c)
                    }
                    _ => continue,
                };
                if !rest[wl..].starts_with(suffix) {
                    continue;
                }
                let n = j + wl + suffix.len();
                if n < 4 || n >= 64 {
                    continue;
                }
                if !ascii && matches!(kind, T::UppercaseFirst | T::UppercaseAll) {
                    let mut buf = [0u8; 64];
                    let m = transform_word(&mut buf, w, usize::from(t));
                    if m != n || s[..n] != buf[..n] {
                        continue;
                    }
                }
                let addr = (u32::from(t) << SIZE_BITS_BY_LENGTH[len]) + idx as u32;
                if best[n].is_none_or(|m| addr < m.addr) {
                    best[n] = Some(DictMatch {
                        out: n as u8,
                        len: len as u8,
                        addr,
                    });
                }
            }
        }
    }
    found.extend(best.iter().flatten());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_words_under_transforms() {
        let mut found = Vec::new();
        // Each match decodes back to the input it claims.
        for text in [
            &b"the quick brown fox jumps over the lazy dog"[..],
            b" information about the ",
            b"Information",
            b"<div class=\"container\">",
            b"function returning",
        ] {
            for i in 0..text.len() {
                matches(&text[i..], &mut found);
                for m in &found {
                    let t = (m.addr >> SIZE_BITS_BY_LENGTH[usize::from(m.len)]) as usize;
                    let idx =
                        (m.addr & ((1 << SIZE_BITS_BY_LENGTH[usize::from(m.len)]) - 1)) as usize;
                    let mut buf = [0u8; 64];
                    let n = transform_word(&mut buf, word(usize::from(m.len), idx), t);
                    assert_eq!(n, usize::from(m.out));
                    assert_eq!(&buf[..n], &text[i..i + n]);
                }
            }
        }
        matches(b" information about", &mut found);
        assert!(found.iter().any(|m| m.out >= 12), "{found:?}");
    }
}
