#![no_main]

// only-regex (the engine behind only-log's `/regex` message filters) against the `regex` crate
// (a fuzz-only dependency): an unanchored search, Unicode classes, case folding, assertions and
// flags. Whatever only-regex compiles, `regex` compiles and matches the same way; only-regex may
// refuse syntax it does not support. Each subject is also matched by the NFA alone and fed in
// pieces through `is_match_fmt`; all the outcomes must agree.
//
// Input: the pattern, then up to 16 subjects, NUL-separated (lossy UTF-8).

use std::fmt;

/// Writes a subject in pieces whose sizes come from `cuts` (moved to character boundaries).
struct Pieces<'a>(&'a str, &'a [u8]);

impl fmt::Display for Pieces<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        let mut at = 0;
        for &c in self.1 {
            let mut end = (at + usize::from(c % 8)).min(s.len());
            while !s.is_char_boundary(end) {
                end += 1;
            }
            f.write_str(&s[at..end])?;
            at = end;
        }
        f.write_str(&s[at..])
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let mut parts = data.split(|&b| b == 0);
    let pattern = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let subjects: Vec<String> = parts
        .take(16)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let Ok(ours) = only_regex::Regex::new(&pattern) else {
        return;
    };
    let theirs = match regex::Regex::new(&pattern) {
        Ok(re) => re,
        // Programs past `regex`'s size or nesting limits (only-regex counts differently).
        Err(regex::Error::CompiledTooBig(_)) => return,
        Err(regex::Error::Syntax(e)) if e.contains("nest limit") => return,
        Err(e) => panic!("only-regex compiled {pattern:?}, regex refused it: {e}"),
    };
    for s in std::iter::once("").chain(subjects.iter().map(String::as_str)) {
        let want = theirs.is_match(s);
        assert_eq!(ours.is_match(s), want, "pattern {pattern:?}, subject {s:?}");
        assert_eq!(
            ours.nfa_is_match(s),
            want,
            "NFA: pattern {pattern:?}, subject {s:?}"
        );
        assert_eq!(
            ours.is_match_fmt(format_args!("{}", Pieces(s, pattern.as_bytes()))),
            want,
            "pieces: pattern {pattern:?}, subject {s:?}"
        );
    }
});
