//! The only-brotli side of the RFC 9841 shared dictionary cross-check against Google's
//! libbrotli (`tools/interop/brotli-shared/run.sh`).
//!
//! - `gen-cases FILE N`: `N` random dictionaries with streams of dictionary references (the
//!   `brotli_shared` fuzz target's generator), as records `u32 len, dictionary, u32 len,
//!   stream`, for libbrotli's decoder.
//! - `check-cases FILE RESULTS`: our decoder on the same records against libbrotli's results
//!   (records `u8 ok, u32 len, output`): the same output, or both refuse.
//! - `dicts DIR`: writes the dictionaries libbrotli's encoder compresses with
//!   (`DIR/<name>.dict`) and the input (`DIR/input`).
//! - `check-dir DIR`: decodes every `DIR/<name>.q<level>.br` (libbrotli's output) with
//!   `<name>.dict` and compares it with `DIR/input`; compresses `input` with each dictionary
//!   (prefix only) into `DIR/<name>.ours.br` for libbrotli to decode.
//!
//! Needs the `fuzzing` feature (the generator is not public API).

use std::path::Path;

use only_brotli::fuzzing::shared::{DictSpec, Source, random_references, random_spec};
use only_brotli::{
    Level, SharedDictionary, compress_with_shared_dictionary, decompress,
    decompress_with_shared_dictionary,
};

fn put(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

fn get<'a>(b: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    let r = &b[4..4 + n];
    *b = &b[4 + n..];
    r
}

/// Text to build word lists from and to compress: Alice's Adventures in Wonderland (Google's
/// test vector).
fn alice() -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/alice29.txt.compressed");
    decompress(&std::fs::read(p).unwrap(), 1 << 20).unwrap()
}

/// A word list of the most frequent words of `text` of each length 4..=`max` (a power of two
/// of them per length, at most 2^`bits`), lower-cased or not.
fn word_list(text: &[u8], max: usize, bits: u8, skip: usize) -> ([u8; 28], Vec<u8>) {
    let mut counts = std::collections::HashMap::<&[u8], usize>::new();
    for w in text.split(|b| !b.is_ascii_alphabetic()) {
        if (4..=max).contains(&w.len()) {
            *counts.entry(w).or_default() += 1;
        }
    }
    let mut sizes = [0u8; 28];
    let mut data = Vec::new();
    for len in 4..=max {
        let mut ws: Vec<(&[u8], usize)> = counts
            .iter()
            .filter(|(w, _)| w.len() == len)
            .map(|(w, c)| (*w, *c))
            .collect();
        ws.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let ws: Vec<&[u8]> = ws.into_iter().skip(skip).map(|x| x.0).collect();
        let mut b = bits;
        while b > 0 && ws.len() < 1 << b {
            b -= 1;
        }
        if b == 0 {
            continue;
        }
        sizes[len - 4] = b;
        for w in &ws[..1 << b] {
            data.extend_from_slice(w);
        }
    }
    (sizes, data)
}

/// The dictionaries libbrotli's encoder uses: a prefix only; custom words with brotli's
/// transforms; custom words and transforms with a prefix; two word lists and brotli's own
/// chosen by context.
fn dictionaries(text: &[u8]) -> Vec<(&'static str, DictSpec)> {
    let prefix = text[text.len() - 4096..].to_vec();
    let words = word_list(text, 16, 7, 0);
    let more = word_list(text, 12, 6, 128);
    let custom_transforms = (
        vec![
            b" ".to_vec(),
            b", ".to_vec(),
            b". ".to_vec(),
            b"ing ".to_vec(),
        ],
        vec![
            (4, 0, 4, 0),  // identity
            (4, 0, 0, 0),  // word + " "
            (0, 0, 0, 0),  // " " + word + " "
            (4, 1, 4, 0),  // omit last 1
            (4, 2, 4, 0),  // omit last 2
            (4, 10, 4, 0), // upper-case first
            (0, 10, 0, 0),
            (4, 0, 1, 0),
            (4, 0, 2, 0),
            (4, 3, 4, 0),
            (4, 11, 4, 0), // upper-case all
            (4, 1, 3, 0),  // omit last 1 + "ing "
            (4, 21, 4, 1), // shift first +1 (unused by encoders)
        ],
    );
    let mut map = [0u8; 64];
    for (i, m) in map.iter_mut().enumerate() {
        // LSB6 of the previous byte: after a space, the first list; after letters, the
        // second; otherwise brotli's own.
        *m = if i == usize::from(b' ' & 63) {
            0
        } else if (usize::from(b'a' & 63)..=usize::from(b'z' & 63)).contains(&i) {
            1
        } else {
            2
        };
    }
    vec![
        (
            "prefix",
            DictSpec {
                prefix: prefix.clone(),
                ..DictSpec::default()
            },
        ),
        (
            "words",
            DictSpec {
                words: vec![words.clone()],
                dicts: vec![(0, 0)],
                ..DictSpec::default()
            },
        ),
        (
            "transforms",
            DictSpec {
                prefix: prefix[..1024].to_vec(),
                words: vec![words.clone()],
                transforms: vec![custom_transforms],
                dicts: vec![(0, 0)],
                ..DictSpec::default()
            },
        ),
        (
            "context",
            DictSpec {
                words: vec![words, more],
                dicts: vec![(0, 0), (1, 0), (2, 0)],
                context_map: Some(map),
                ..DictSpec::default()
            },
        ),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen-cases") => {
            let n: u64 = args[3].parse().unwrap();
            let mut o = Vec::new();
            for seed in 1..=n {
                let mut s = Source::seeded(seed.wrapping_mul(0x2545_f491_4f6c_dd1d));
                let spec = random_spec(&mut s);
                let ser = spec.serialize();
                let dict = SharedDictionary::new(&ser).unwrap();
                let (stream, _) = random_references(&mut s, &spec, &dict);
                put(&mut o, &ser);
                put(&mut o, &stream);
            }
            std::fs::write(&args[2], o).unwrap();
        }
        Some("check-cases") => {
            let cases = std::fs::read(&args[2]).unwrap();
            let results = std::fs::read(&args[3]).unwrap();
            let (mut c, mut r) = (&cases[..], &results[..]);
            let (mut n, mut ok, mut bad) = (0, 0, 0);
            while !c.is_empty() {
                let dict = SharedDictionary::new(get(&mut c)).unwrap();
                let stream = get(&mut c);
                let theirs_ok = r[0] == 1;
                r = &r[1..];
                let theirs = get(&mut r);
                let ours = decompress_with_shared_dictionary(stream, 1 << 20, &dict);
                n += 1;
                match (&ours, theirs_ok) {
                    (Ok(o), true) if o == theirs => ok += 1,
                    (Err(_), false) => {}
                    _ => {
                        bad += 1;
                        if bad <= 10 {
                            eprintln!(
                                "case {n}: ours {:?}, libbrotli {}",
                                ours.as_ref().map(|o| o.len()),
                                if theirs_ok { "ok" } else { "error" }
                            );
                        }
                    }
                }
            }
            println!(
                "{n} cases: {ok} decoded identically, {} refused by both, {bad} differ",
                n - ok - bad
            );
            if bad > 0 {
                std::process::exit(1);
            }
        }
        Some("dicts") => {
            let dir = Path::new(&args[2]);
            let text = alice();
            std::fs::write(dir.join("input"), &text).unwrap();
            for (name, spec) in dictionaries(&text) {
                std::fs::write(dir.join(format!("{name}.dict")), spec.serialize()).unwrap();
            }
        }
        Some("check-dir") => {
            let dir = Path::new(&args[2]);
            let input = std::fs::read(dir.join("input")).unwrap();
            let mut failed = false;
            for (name, _) in dictionaries(&input) {
                let dict = SharedDictionary::new(
                    &std::fs::read(dir.join(format!("{name}.dict"))).unwrap(),
                )
                .unwrap();
                for q in [1, 5, 9, 11] {
                    let p = dir.join(format!("{name}.q{q}.br"));
                    let Ok(br) = std::fs::read(&p) else { continue };
                    let plain = dir.join(format!("plain.q{q}.br"));
                    let base = std::fs::read(plain).map_or(0, |b| b.len());
                    let r = decompress_with_shared_dictionary(&br, input.len(), &dict);
                    let good = r.as_deref() == Ok(&input[..]);
                    failed |= !good;
                    // With the prefix alone (the built-in static dictionary), a stream that
                    // uses custom words decodes differently or not at all.
                    let raw =
                        only_brotli::decompress_with_dictionary(&br, input.len(), dict.prefix());
                    let custom = raw.as_deref() != Ok(&input[..]);
                    println!(
                        "{name} q{q}: libbrotli {} bytes (without dictionary {base}), {}: ours {}",
                        br.len(),
                        if custom {
                            "custom words used"
                        } else {
                            "no custom words"
                        },
                        if good { "decodes" } else { "FAILS" }
                    );
                }
                let ours = compress_with_shared_dictionary(Level::new(9), &input, &dict);
                std::fs::write(dir.join(format!("{name}.ours.br")), ours).unwrap();
            }
            if failed {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: shared-dict-interop gen-cases|check-cases|dicts|check-dir ...");
            std::process::exit(2);
        }
    }
}
