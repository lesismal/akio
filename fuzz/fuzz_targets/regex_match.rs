#![no_main]

// Route constraints (`{id:[0-9]+}`): the router's matcher (only-regex with `whole_text` and
// `ascii_classes`, ADR-051) against the engine it replaced, kept as a test reference
// (`only_http::fuzzing::regex_match`: same accepted patterns up to the documented superset, same
// matches), then against the `regex` crate (a fuzz-only dependency) with the pattern anchored
// (`^(?:pattern)$`): whatever the router compiles, `regex` compiles and matches the same way.
// `\d \w \s` and `\b` are ASCII in the router and Unicode in `regex`, so subjects are compared
// only when they are ASCII or the pattern has none.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::regex_match(data);
    if data.len() > 4096 {
        return;
    }
    let (pattern, subjects) = only_http::fuzzing::regex_input(data);
    let Some(ours) = only_http::fuzzing::RouteRegex::new(&pattern) else {
        return;
    };
    let theirs = match regex::Regex::new(&format!("^(?:{pattern})$")) {
        Ok(re) => re,
        // Programs past `regex`'s size or nesting limits (only-regex counts differently).
        Err(regex::Error::CompiledTooBig(_)) => return,
        Err(regex::Error::Syntax(e)) if e.contains("nest limit") => return,
        Err(e) => panic!("the router compiled {pattern:?}, regex refused it: {e}"),
    };
    let perl = ["\\d", "\\D", "\\w", "\\W", "\\s", "\\S", "\\b", "\\B"]
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
