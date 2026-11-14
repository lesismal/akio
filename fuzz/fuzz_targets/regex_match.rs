#![no_main]

// The route constraint regexp engine (`only_http::re`): its own checks, then a differential
// check against the `regex` crate (a fuzz-only dependency) with the pattern anchored as the
// router used it (`^(?:pattern)$`). Whatever only compiles, `regex` compiles and matches the
// same way; only may refuse syntax it does not support. `\d \w \s` are ASCII in only and Unicode
// in `regex`, so subjects are compared only when they are ASCII or the pattern has none.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::regex_match(data);
    if data.len() > 4096 {
        return;
    }
    let (pattern, subjects) = only_http::fuzzing::regex_input(data);
    let Ok(ours) = only_http::re::Regex::new(&pattern) else {
        return;
    };
    let theirs = match regex::Regex::new(&format!("^(?:{pattern})$")) {
        Ok(re) => re,
        // Compiled programs past `regex`'s size limit (only's limit is in instructions).
        Err(regex::Error::CompiledTooBig(_)) => return,
        Err(e) => panic!("only compiled {pattern:?}, regex refused it: {e}"),
    };
    let perl = ["\\d", "\\D", "\\w", "\\W", "\\s", "\\S"]
        .iter()
        .any(|c| pattern.contains(c));
    for s in std::iter::once("").chain(subjects.iter().map(String::as_str)) {
        if perl && !s.is_ascii() {
            continue;
        }
        assert_eq!(
            ours.is_match(s),
            theirs.is_match(s),
            "pattern {pattern:?}, subject {s:?}"
        );
    }
});
