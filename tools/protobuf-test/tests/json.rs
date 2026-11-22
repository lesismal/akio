//! JSON mapping of generated messages (the conformance suite covers the rest:
//! `conformance/run.sh`), and a mutation smoke test with the `protobuf_json` fuzz target's
//! property.

use akio_protobuf::{
    Extendable,
    json::{self, ParseOptions, PrintOptions},
    reflect::ReflectMessage,
};
use protobuf_test::protobuf_test_messages::{
    proto2::{self as p2, TestAllTypesProto2},
    proto3::{TestAllTypesProto3, test_all_types_proto3 as t3},
};

#[test]
fn generated_messages() {
    let m = TestAllTypesProto3 {
        optional_int64: -5,
        optional_uint64: u64::MAX,
        optional_float: f32::NAN,
        optional_double: 0.1,
        optional_bytes: vec![0xfb, 0xff],
        optional_nested_enum: t3::NestedEnum::BAZ,
        repeated_int32: vec![1, -1],
        map_int32_int32: std::iter::once((7, 8)).collect(),
        oneof_field: Some(t3::OneofField::OneofString("é".into())),
        ..Default::default()
    };
    let s = json::to_string(&m).unwrap();
    assert_eq!(
        s,
        r#"{"optionalInt64":"-5","optionalUint64":"18446744073709551615","optionalFloat":"NaN","optionalDouble":0.1,"optionalBytes":"+/8=","optionalNestedEnum":"BAZ","repeatedInt32":[1,-1],"mapInt32Int32":{"7":8},"oneofString":"é"}"#
    );
    let back: TestAllTypesProto3 = json::from_str(&s).unwrap();
    assert!(back.optional_float.is_nan());
    assert_eq!(back.optional_bytes, m.optional_bytes);
    assert_eq!(back.map_int32_int32, m.map_int32_int32);

    let s = json::to_string_with(
        &TestAllTypesProto3::default(),
        &PrintOptions {
            always_print_fields_with_no_presence: true,
            preserve_proto_field_names: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(s.contains("\"optional_int32\":0") && s.contains("\"repeated_int32\":[]"));
    assert!(!s.contains("optional_nested_message"));

    // proto2: extensions by full name, groups by field name.
    let m: TestAllTypesProto2 = json::from_str(
        r#"{"[protobuf_test_messages.proto2.extension_int32]":5,"data":{"groupInt32":1},"optional_int32":0}"#,
    )
    .unwrap();
    assert_eq!(m.extension(&p2::EXTENSION_INT32).unwrap(), Some(5));
    assert_eq!(m.optional_int32, Some(0), "explicit presence keeps a 0");
    let s = json::to_string(&m).unwrap();
    assert_eq!(
        s,
        r#"{"optionalInt32":0,"data":{"groupInt32":1},"[protobuf_test_messages.proto2.extension_int32]":5}"#
    );

    // Errors and lenience.
    for bad in [
        r#"{"optionalInt32":1,"optional_int32":2}"#,
        r#"{"oneofUint32":1,"oneofString":"x"}"#,
        r#"{"optionalInt32":2147483648}"#,
        r#"{"optionalInt32":1.5}"#,
        r#"{"optionalFloat":1e39}"#,
        r#"{"optionalNestedEnum":"NOPE"}"#,
        r#"{"unknown":1}"#,
        r#"{"repeatedInt32":[null]}"#,
    ] {
        assert!(json::from_str::<TestAllTypesProto3>(bad).is_err(), "{bad}");
    }
    let lax = ParseOptions {
        ignore_unknown_fields: true,
        ..Default::default()
    };
    let m: TestAllTypesProto3 = json::from_str_with(
        r#"{"unknown":1,"optionalNestedEnum":"NOPE","optionalInt32":"1e2"}"#,
        &lax,
    )
    .unwrap();
    assert_eq!(m.optional_int32, 100);
    assert_eq!(m.optional_nested_enum, t3::NestedEnum::FOO);
}

fn property<M: ReflectMessage>(s: &str) {
    let Ok(m) = json::from_str::<M>(s) else {
        return;
    };
    let Ok(text) = json::to_string(&m) else {
        return;
    };
    // Compared through their encodings and texts (NaN != NaN; maps print sorted).
    let back: M = json::from_str(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
    assert_eq!(back.encoded_len(), m.encoded_len(), "{text}");
    assert_eq!(json::to_string(&back).unwrap(), text);
}

#[test]
fn mutation_smoke() {
    let seeds = [
        r#"{"optionalInt32":1,"optionalString":"aé","repeatedDouble":[1.5,"NaN"],"mapStringNestedMessage":{"k":{"a":1}},"optionalTimestamp":"2000-01-01T00:00:00.5Z","optionalDuration":"-1.5s","optionalAny":{"@type":"type.googleapis.com/protobuf_test_messages.proto3.TestAllTypesProto3","optionalInt32":3},"optionalValue":{"a":[1,null,true]},"optionalFieldMask":"a.bC,d","optionalBoolWrapper":false,"oneofUint32":7}"#,
        r#"{"data":{"groupInt32":1},"[protobuf_test_messages.proto2.extension_int32]":5,"optionalNestedEnum":"BAZ","repeatedBytes":["AAE=","_-8"]}"#,
    ];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for seed in seeds {
        property::<TestAllTypesProto3>(seed);
        property::<TestAllTypesProto2>(seed);
        for _ in 0..3000 {
            let mut b = seed.as_bytes().to_vec();
            for _ in 0..=(next() % 4) {
                let i = (next() % b.len() as u64) as usize;
                match next() % 3 {
                    0 => b[i] = b"{}[],:\"0129eE.-+ntfa\\u"[(next() % 22) as usize],
                    1 => {
                        b.remove(i);
                    }
                    _ => b.insert(i, (next() % 128) as u8),
                }
            }
            if let Ok(s) = std::str::from_utf8(&b) {
                property::<TestAllTypesProto3>(s);
                property::<TestAllTypesProto2>(s);
            }
        }
    }
}
