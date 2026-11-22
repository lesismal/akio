#![no_main]
//! W3C `traceparent` parsing: never panics; what parses has non-zero ids and prints back to an
//! equal version-00 header.

use akio_log::span::SpanContext;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Some(c) = SpanContext::from_traceparent(s) {
        assert!(c.trace_id() != 0 && c.span_id() != 0 && c.is_remote());
        let again = SpanContext::from_traceparent(&c.to_traceparent()).expect("round trip");
        assert_eq!(again, c);
    }
});
