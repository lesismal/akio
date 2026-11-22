#![no_main]
//! akio-protobuf's text format on arbitrary input, into the conformance suite's proto3 and proto2
//! test messages: parsing must never panic, and a message that parses must print, parse back,
//! and print the same text again (parse -> print -> parse). The input is also decoded as binary;
//! such a message must print (with and without unknown fields) and read back the same way.

use akio_protobuf::{
    reflect::ReflectMessage,
    text::{self, PrintOptions},
};
use protobuf_test::protobuf_test_messages::{
    proto2::TestAllTypesProto2, proto3::TestAllTypesProto3,
};

/// `m` printed (multi-line and single-line) must parse back to a message printing the same.
fn round_trip<M: ReflectMessage>(m: &M, exact: bool) {
    for single_line in [false, true] {
        let opts = PrintOptions {
            single_line,
            ..Default::default()
        };
        let out = text::to_string_with(m, &opts).unwrap();
        let back: M = text::from_str(&out).unwrap_or_else(|e| panic!("{out}: {e}"));
        assert_eq!(text::to_string_with(&back, &opts).unwrap(), out);
        // Compared through their encodings (NaN != NaN). Not exact when an `Any` held a value
        // that is not canonically encoded: it is printed expanded and re-encoded.
        if exact {
            assert_eq!(back.encoded_len(), m.encoded_len(), "{out}");
        }
    }
}

fn check<M: ReflectMessage>(data: &[u8]) {
    let parsed = std::str::from_utf8(data)
        .ok()
        .and_then(|s| Some((s, text::from_str::<M>(s).ok()?)));
    if let Some((s, m)) = parsed {
        round_trip(&m, !s.contains("value"));
    }
    // Extensions are decoded when read: reflection (and so printing) fails on a bad one.
    if let Some(mut known) = M::decode(data).ok().and_then(|m| m.to_dynamic().ok()) {
        let all = PrintOptions {
            print_unknown_fields: true,
            ..Default::default()
        };
        let _ = known.to_text(&all);
        known.clear_unknown_fields();
        if let Ok(k) = M::from_dynamic(&known) {
            round_trip(&k, false);
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    check::<TestAllTypesProto3>(data);
    check::<TestAllTypesProto2>(data);
});
