#![no_main]
//! akio-protobuf's JSON mapping on arbitrary input, into the conformance suite's proto3 and proto2
//! test messages: parsing must never panic, and a message that parses must print, parse back to
//! the same message, and print the same text again.

use akio_protobuf::{json, reflect::ReflectMessage};
use protobuf_test::protobuf_test_messages::{
    proto2::TestAllTypesProto2, proto3::TestAllTypesProto3,
};

fn check<M: ReflectMessage>(s: &str) {
    let Ok(m) = json::from_str::<M>(s) else {
        return;
    };
    // Printing fails only for values JSON cannot hold (a Value without a kind, a Timestamp out
    // of range, ...).
    let Ok(text) = json::to_string(&m) else {
        return;
    };
    // Compared through their encodings and texts (NaN != NaN; maps print sorted).
    let back: M = json::from_str(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
    assert_eq!(back.encoded_len(), m.encoded_len(), "{text}");
    assert_eq!(json::to_string(&back).unwrap(), text);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    check::<TestAllTypesProto3>(s);
    check::<TestAllTypesProto2>(s);
});
