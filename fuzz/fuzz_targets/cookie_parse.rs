#![no_main]

// The HTTP client's cookie jar (ADR-059): `Set-Cookie` and cookie-date parsing and the storage
// rules, from an optional `url\n` line and `Set-Cookie` values one per line.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::cookie_parse(data);
});
