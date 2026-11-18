//! Text format of generated messages (the conformance suite covers the rest:
//! `conformance/run.sh`), and a mutation smoke test with the `protobuf_text` fuzz target's
//! property.

use only_protobuf::{
    Extendable, Message,
    reflect::ReflectMessage,
    text::{self, ParseOptions, PrintOptions},
};
use protobuf_test::protobuf_test_messages::{
    proto2::{self as p2, TestAllTypesProto2, test_all_types_proto2 as t2},
    proto3::{TestAllTypesProto3, test_all_types_proto3 as t3},
};

#[test]
fn print_format() {
    let m = TestAllTypesProto3 {
        optional_int64: -5,
        optional_uint64: u64::MAX,
        optional_float: f32::NAN,
        optional_double: 0.1,
        optional_string: "a\"\n\u{e9}".into(),
        optional_bytes: vec![0xfb, b'\'', 0],
        optional_nested_enum: t3::NestedEnum::BAZ,
        optional_nested_message: Some(Box::new(t3::NestedMessage {
            a: 1,
            ..Default::default()
        })),
        repeated_int32: vec![1, -1],
        map_int32_int32: [(7, 8), (-1, 0)].into_iter().collect(),
        oneof_field: Some(t3::OneofField::OneofUint32(3)),
        ..Default::default()
    };
    let s = text::to_string(&m).unwrap();
    assert_eq!(
        s,
        "optional_int64: -5
optional_uint64: 18446744073709551615
optional_float: nan
optional_double: 0.1
optional_string: \"a\\\"\\n\u{e9}\"
optional_bytes: \"\\373\\'\\000\"
optional_nested_message {
  a: 1
}
optional_nested_enum: BAZ
repeated_int32: 1
repeated_int32: -1
map_int32_int32 {
  key: -1
  value: 0
}
map_int32_int32 {
  key: 7
  value: 8
}
oneof_uint32: 3
"
    );
    let back: TestAllTypesProto3 = text::from_str(&s).unwrap();
    assert!(back.optional_float.is_nan());
    assert_eq!(back.encode_to_vec().len(), m.encode_to_vec().len());
    assert_eq!(text::to_string(&back).unwrap(), s);

    let one = PrintOptions {
        single_line: true,
        ..Default::default()
    };
    let m = TestAllTypesProto3 {
        optional_int32: 1,
        optional_nested_message: Some(Box::new(t3::NestedMessage {
            a: 2,
            ..Default::default()
        })),
        ..Default::default()
    };
    assert_eq!(
        text::to_string_with(&m, &one).unwrap(),
        "optional_int32: 1 optional_nested_message { a: 2 }"
    );
    assert_eq!(text::to_string(&TestAllTypesProto3::default()).unwrap(), "");
}

#[test]
fn parse_forms() {
    let m: TestAllTypesProto3 = text::from_str(
        r#"
        # comment
        optional_int32: -0x10, optional_uint32: 017;
        optional_float: -inf optional_double: 1.5e3f
        optional_bool: t
        optional_string: 'a' "b" '\x41\101\u00e9\U0001F600'
        optional_nested_message < a: 1 corecursive { optional_int32: 2 } >
        repeated_int32: [1, 2] repeated_int32: 3
        repeated_nested_message: [{ a: 1 }, < a: 2 >]
        repeated_nested_enum: [FOO, 1, -1]
        map_string_string [{ key: "k" value: "v" }, { key: "k" value: "w" }]
        map_int32_int32 { key: 1 }
        oneof_nested_message {}
        "#,
    )
    .unwrap();
    assert_eq!((m.optional_int32, m.optional_uint32), (-16, 15));
    assert_eq!(m.optional_float, f32::NEG_INFINITY);
    assert_eq!(m.optional_double, 1500.0);
    assert!(m.optional_bool);
    assert_eq!(m.optional_string, "abAA\u{e9}\u{1F600}");
    let n = m.optional_nested_message.as_ref().unwrap();
    assert_eq!(n.a, 1);
    assert_eq!(n.corecursive.as_ref().unwrap().optional_int32, 2);
    assert_eq!(m.repeated_int32, [1, 2, 3]);
    assert_eq!(m.repeated_nested_message.len(), 2);
    assert_eq!(
        m.repeated_nested_enum,
        [
            t3::NestedEnum::FOO,
            t3::NestedEnum::BAR,
            t3::NestedEnum::NEG
        ]
    );
    assert_eq!(
        m.map_string_string["k"], "w",
        "the last entry of a key wins"
    );
    assert_eq!(m.map_int32_int32[&1], 0);
    assert!(matches!(
        m.oneof_field,
        Some(t3::OneofField::OneofNestedMessage(_))
    ));

    // Field names are case-sensitive; reserved names are skipped.
    let m: TestAllTypesProto3 =
        text::from_str("reserved_field { a: [1, 2] b < c: -inf > [x.y]: 1 } optional_int32: 4")
            .unwrap();
    assert_eq!(m.optional_int32, 4);
}

#[test]
fn parse_errors() {
    for bad in [
        "optional_int32: 1 optional_int32: 2",
        "oneof_uint32: 1 oneof_string: 'x'",
        "optional_int32: 2147483648",
        "optional_int32: 1.5",
        "optional_int32 1",
        "optional_uint32: -1",
        "optional_uint32: -0",
        "optional_float: 0x1",
        "optional_float: 012",
        "optional_bool: 2",
        "optional_nested_enum: NOPE",
        "optional_string: '\\xc0'",
        "optional_string: 'a\nb'",
        "optional_string: '\\ud800'",
        "optional_string: '\\U00110000'",
        "optional_string: '\\400'",
        "optional_int32: 1a",
        "optional_int32: 09",
        "optional_int32: [1]",
        "repeated_int32: [1,]",
        "repeated_int32: [1 2]",
        "optional_int32: 1;;",
        "Optional_int32: 1",
        "unknown: 1",
        "optional_nested_message { a: 1",
        "optional_nested_message { a: 1 >",
        "optional_any { [type.googleapis.com/x.Nope] {} }",
        "optional_any { [a/%ZZ/protobuf_test_messages.proto3.TestAllTypesProto3] {} }",
        "optional_any { type_url: 'x' [type.googleapis.com/protobuf_test_messages.proto3.TestAllTypesProto3] {} }",
        "[protobuf_test_messages.proto2.extension_int32]: 1",
    ] {
        let e = text::from_str::<TestAllTypesProto3>(bad).unwrap_err();
        assert!(e.line() >= 1, "{bad}: {e}");
    }
    let e = text::from_str::<TestAllTypesProto3>("\n  optional_int32: x").unwrap_err();
    assert_eq!((e.line(), e.column()), (2, 19), "{e}");
    let deep = "recursive_message { ".repeat(101) + &"}".repeat(101);
    assert!(text::from_str::<TestAllTypesProto3>(&deep).is_err());
    let ok = "recursive_message { ".repeat(99) + &"}".repeat(99);
    assert!(text::from_str::<TestAllTypesProto3>(&ok).is_ok());

    let lax = ParseOptions {
        allow_unknown_fields: true,
        ..Default::default()
    };
    let m: TestAllTypesProto3 = text::from_str_with(
        "unknown: [1, 2] [x.y] { z: 'a' } nope < > optional_int32: 7",
        &lax,
    )
    .unwrap();
    assert_eq!(m.optional_int32, 7);
}

#[test]
fn proto2_groups_extensions_any() {
    let s = "Data { group_int32: 1 }
[protobuf_test_messages.proto2.extension_int32]: 5
[protobuf_test_messages.proto2.groupfield] { group_int32: 2 }
optional_nested_enum: BAR
message_set_correct {
  [protobuf_test_messages.proto2.TestAllTypesProto2.MessageSetCorrectExtension1] { str: \"x\" }
}";
    let m: TestAllTypesProto2 = text::from_str(s).unwrap();
    assert_eq!(m.data.as_ref().unwrap().group_int32, Some(1));
    assert_eq!(m.extension(&p2::EXTENSION_INT32).unwrap(), Some(5));
    assert_eq!(
        m.extension(&p2::GROUPFIELD).unwrap().unwrap().group_int32,
        Some(2)
    );
    let set = m.message_set_correct.as_ref().unwrap();
    let e1 = set
        .extension(&t2::message_set_correct_extension1::MESSAGE_SET_EXTENSION)
        .unwrap()
        .unwrap();
    assert_eq!(e1.str.as_deref(), Some("x"));
    let printed = text::to_string(&m).unwrap();
    assert_eq!(
        printed,
        "optional_nested_enum: BAR
[protobuf_test_messages.proto2.extension_int32]: 5
[protobuf_test_messages.proto2.groupfield] {
  group_int32: 2
}
Data {
  group_int32: 1
}
message_set_correct {
  [protobuf_test_messages.proto2.TestAllTypesProto2.MessageSetCorrectExtension1] {
    str: \"x\"
  }
}
"
    );
    assert_eq!(text::from_str::<TestAllTypesProto2>(&printed).unwrap(), m);
    // The group's field name works too; closed enums take only known numbers.
    let m: TestAllTypesProto2 = text::from_str("data { group_int32: 3 }").unwrap();
    assert_eq!(m.data.unwrap().group_int32, Some(3));
    assert!(text::from_str::<TestAllTypesProto2>("optional_nested_enum: 42").is_err());
    assert!(text::from_str::<TestAllTypesProto3>("optional_nested_enum: 42").is_ok());
    assert!(
        text::from_str::<TestAllTypesProto2>(
            "[protobuf_test_messages.proto2.GroupField] { group_int32: 1 }"
        )
        .is_err()
    );

    // Any, expanded both ways, and raw when the type is unknown.
    let s = "optional_any {
  [type.googleapis.com/protobuf_test_messages.proto3.TestAllTypesProto3] {
    optional_int32: 12345
  }
}
";
    let m: TestAllTypesProto3 = text::from_str(s).unwrap();
    let any = m.optional_any.as_ref().unwrap();
    assert_eq!(
        any.type_url,
        "type.googleapis.com/protobuf_test_messages.proto3.TestAllTypesProto3"
    );
    assert_eq!(any.value, [0x08, 0xb9, 0x60]);
    assert_eq!(text::to_string(&m).unwrap(), s);
    let raw: TestAllTypesProto3 =
        text::from_str("optional_any { type_url: 'x/y.Z' value: '\\001' }").unwrap();
    assert_eq!(
        text::to_string(&raw).unwrap(),
        "optional_any {\n  type_url: \"x/y.Z\"\n  value: \"\\001\"\n}\n"
    );
}

#[test]
fn unknown_fields() {
    let mut raw = Vec::new();
    // 1001: 5, 1002: "hello" (not a field set, unlike "hi"), 1003 { 1: 7 }, 1004 (group) { 1: 2 }, 1005: fixed32, 1006: fixed64
    raw.extend_from_slice(&[0xc8, 0x3e, 0x05]);
    raw.extend_from_slice(&[0xd2, 0x3e, 0x05]);
    raw.extend_from_slice(b"hello");
    raw.extend_from_slice(&[0xda, 0x3e, 0x02, 0x08, 0x07]);
    raw.extend_from_slice(&[0xe3, 0x3e, 0x08, 0x02, 0xe4, 0x3e]);
    raw.extend_from_slice(&[0xed, 0x3e, 1, 0, 0, 0]);
    raw.extend_from_slice(&[0xf1, 0x3e, 2, 0, 0, 0, 0, 0, 0, 0]);
    let m = TestAllTypesProto3::decode(&raw).unwrap();
    assert_eq!(text::to_string(&m).unwrap(), "");
    let opts = PrintOptions {
        print_unknown_fields: true,
        single_line: true,
        ..Default::default()
    };
    assert_eq!(
        text::to_string_with(&m, &opts).unwrap(),
        "1001: 5 1002: \"hello\" 1003 { 1: 7 } 1004 { 1: 2 } 1005: 0x00000001 1006: 0x0000000000000002"
    );
}

#[test]
fn floats() {
    for (input, want) in [
        ("1e50", "inf"),
        ("-1e50", "-inf"),
        ("1e-50", ""),
        ("-1e-50", "-0"),
        ("-0", "-0"),
        (".5", "0.5"),
        ("3.4028235e+38", "3.4028235e38"),
        ("1.e2", "100"),
        ("18446744073709551616", "1.8446744e19"),
        ("1e18446744073709551616", "inf"),
        ("1e-18446744073709551616", ""),
        ("NaN", "nan"),
        ("-Infinity", "-inf"),
    ] {
        let m: TestAllTypesProto3 = text::from_str(&format!("optional_float: {input}")).unwrap();
        let got = text::to_string(&m).unwrap();
        let got = got
            .trim_end()
            .strip_prefix("optional_float: ")
            .unwrap_or(&got);
        assert_eq!(got, want, "{input}");
    }
    let m: TestAllTypesProto3 = text::from_str("optional_double: 1e308").unwrap();
    assert_eq!(text::to_string(&m).unwrap(), "optional_double: 1e308\n");
}

fn property<M: ReflectMessage>(s: &str) {
    let Ok(m) = text::from_str::<M>(s) else {
        return;
    };
    let out = text::to_string(&m).unwrap();
    // Compared through their encodings and texts (NaN != NaN).
    let back: M = text::from_str(&out).unwrap_or_else(|e| panic!("{out}: {e}"));
    assert_eq!(back.encoded_len(), m.encoded_len(), "{out}");
    assert_eq!(text::to_string(&back).unwrap(), out);
}

#[test]
fn mutation_smoke() {
    let seeds = [
        r#"optional_int32: 1 optional_string: "a\303\251" repeated_double: [1.5, nan] map_string_nested_message { key: "k" value { a: 1 } } optional_any { [type.googleapis.com/protobuf_test_messages.proto3.TestAllTypesProto3] { optional_int32: 3 } } oneof_uint32: 7 optional_nested_enum: BAZ"#,
        r#"Data { group_int32: 1 } [protobuf_test_messages.proto2.extension_int32]: 5 repeated_bytes: ['\x00\001', "\u00e9"] optional_float: -0x0 # c"#,
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
                    0 => {
                        let alphabet = b"{}<>[],:;\"'0179eExf.-#\\un";
                        b[i] = alphabet[(next() % alphabet.len() as u64) as usize];
                    }
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
