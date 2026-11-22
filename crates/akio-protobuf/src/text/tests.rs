use super::*;
use crate::{
    Message,
    reflect::{DynamicMessage, Value},
    well_known::{self, Any, Duration, Timestamp},
};

#[test]
fn well_known_types() {
    let d: Duration = from_str("seconds: -0x10 nanos: -017").unwrap();
    assert_eq!((d.seconds, d.nanos), (-16, -15));
    assert_eq!(to_string(&d).unwrap(), "seconds: -16\nnanos: -15\n");

    let pool = well_known::descriptor_pool();
    let st = pool.get_message_by_name("google.protobuf.Struct").unwrap();
    let m = parse_dynamic(
        st,
        r#"fields { key: "b" value { list_value { values [{ bool_value: true }, < null_value: NULL_VALUE >] } } }
           fields [{ key: "a" value { number_value: -inf } }]"#,
        &ParseOptions::default(),
    )
    .unwrap();
    let one = PrintOptions {
        single_line: true,
        ..Default::default()
    };
    assert_eq!(
        m.to_text(&one),
        "fields { key: \"a\" value { number_value: -inf } } fields { key: \"b\" value { list_value { values { bool_value: true } values { null_value: NULL_VALUE } } } }"
    );
}

#[test]
fn any() {
    let t = Timestamp {
        seconds: 1,
        nanos: 2,
    };
    let a = Any {
        type_url: "type.googleapis.com/google.protobuf.Timestamp".into(),
        value: t.encode_to_vec(),
    };
    let s = to_string(&a).unwrap();
    assert_eq!(
        s,
        "[type.googleapis.com/google.protobuf.Timestamp] {\n  seconds: 1\n  nanos: 2\n}\n"
    );
    assert_eq!(from_str::<Any>(&s).unwrap(), a);
    // Expanded with `<>`, a `:`, another URL prefix.
    let b: Any = from_str("[x.y/z/google.protobuf.Timestamp]: < seconds: 1 nanos: 2 >").unwrap();
    assert_eq!(b.value, a.value);
    assert_eq!(b.type_url, "x.y/z/google.protobuf.Timestamp");
    // Unknown fields inside keep it raw.
    let c = Any {
        value: [t.encode_to_vec(), vec![0x18, 0x01]].concat(),
        ..a
    };
    assert!(to_string(&c).unwrap().starts_with("type_url: "));
    let u = PrintOptions {
        print_unknown_fields: true,
        single_line: true,
        ..Default::default()
    };
    assert_eq!(
        to_string_with(&c, &u).unwrap(),
        "[type.googleapis.com/google.protobuf.Timestamp] { seconds: 1 nanos: 2 3: 1 }"
    );
    // Unknown type, bad URL.
    let d = Any {
        type_url: "x/nope.T".into(),
        value: vec![1],
    };
    assert_eq!(
        to_string(&d).unwrap(),
        "type_url: \"x/nope.T\"\nvalue: \"\\001\"\n"
    );
    for bad in [
        "[x/nope.T] {}",
        "[google.protobuf.Timestamp] {}",
        "[a^b/google.protobuf.Timestamp] {}",
        "[a/google.protobuf.] {}",
        "[x/google.protobuf.Timestamp] {} [x/google.protobuf.Timestamp] {}",
        "[x/google.protobuf.Timestamp] 1",
        "[x/google.protobuf.Timestamp",
    ] {
        assert!(from_str::<Any>(bad).is_err(), "{bad}");
    }
    // Whitespace and comments inside the brackets are dropped.
    let e: Any = from_str("[x / google . # c\n protobuf.Timestamp] {}").unwrap();
    assert_eq!(e.type_url, "x/google.protobuf.Timestamp");
}

#[test]
fn strings_and_escapes() {
    let pool = well_known::descriptor_pool();
    let sv = pool
        .get_message_by_name("google.protobuf.StringValue")
        .unwrap();
    let bv = pool
        .get_message_by_name("google.protobuf.BytesValue")
        .unwrap();
    let o = ParseOptions::default();
    let get = |m: &DynamicMessage| m.get_by_name("value").unwrap().into_owned();
    let m = parse_dynamic(
        bv,
        r#"value: '\a\b\f\n\r\t\v\?\\\'\"' "\0\00\000\1234\x4\x41g\X7e" '\u00e9\U0001f600'"#,
        &o,
    )
    .unwrap();
    let want: Vec<u8> = [
        &b"\x07\x08\x0c\n\r\t\x0b?\\'\""[..],
        b"\0\0\0\x534\x04\x41g\x7e",
        "\u{e9}\u{1f600}".as_bytes(),
    ]
    .concat();
    assert_eq!(get(&m), Value::Bytes(want));
    // Bytes print with octal escapes; strings keep UTF-8.
    assert_eq!(
        m.to_text(&PrintOptions::default()),
        "value: \"\\007\\010\\014\\n\\r\\t\\013?\\\\\\'\\\"\\000\\000\\000S4\\004Ag~\\303\\251\\360\\237\\230\\200\"\n"
    );
    let s = parse_dynamic(sv.clone(), r#"value: "\303\251\u00e9""#, &o).unwrap();
    assert_eq!(get(&s), Value::String("éé".into()));
    assert_eq!(s.to_text(&PrintOptions::default()), "value: \"éé\"\n");
    for bad in [
        r#"value: "\xc3""#,
        r#"value: "\q""#,
        r#"value: "\x""#,
        r#"value: "\u12""#,
        r#"value: "\udfff""#,
        r#"value: "\U0000d800""#,
        r#"value: "\777""#,
        "value: \"a",
        "value: 'a\"",
        "value: 1",
    ] {
        assert!(parse_dynamic(sv.clone(), bad, &o).is_err(), "{bad}");
    }
}

#[test]
fn numbers() {
    let pool = well_known::descriptor_pool();
    let msg = |n: &str| pool.get_message_by_name(n).unwrap();
    let o = ParseOptions::default();
    let get = |t: &str, s: &str| {
        parse_dynamic(msg(t), &format!("value: {s}"), &o)
            .map(|m| m.get_by_name("value").unwrap().into_owned())
    };
    assert_eq!(
        get("google.protobuf.Int64Value", "-0x8000000000000000"),
        Ok(Value::I64(i64::MIN))
    );
    assert_eq!(get("google.protobuf.Int64Value", "- 1"), Ok(Value::I64(-1)));
    assert!(get("google.protobuf.Int64Value", "0x8000000000000000").is_err());
    assert_eq!(
        get("google.protobuf.UInt64Value", "01777777777777777777777"),
        Ok(Value::U64(u64::MAX))
    );
    assert!(get("google.protobuf.UInt64Value", "18446744073709551616").is_err());
    assert_eq!(
        get("google.protobuf.UInt32Value", "0xFFFFFFFF"),
        Ok(Value::U32(u32::MAX))
    );
    assert_eq!(
        get("google.protobuf.BoolValue", "0x1"),
        Ok(Value::Bool(true))
    );
    assert_eq!(
        get("google.protobuf.BoolValue", "False"),
        Ok(Value::Bool(false))
    );
    assert!(get("google.protobuf.BoolValue", "TRUE").is_err());
    assert_eq!(
        get("google.protobuf.DoubleValue", "1f"),
        Ok(Value::F64(1.0))
    );
    assert_eq!(
        get("google.protobuf.DoubleValue", "1.5E-3F"),
        Ok(Value::F64(0.0015))
    );
    assert_eq!(
        get("google.protobuf.DoubleValue", "-iNfInItY"),
        Ok(Value::F64(f64::NEG_INFINITY))
    );
    assert!(get("google.protobuf.DoubleValue", "infinit").is_err());
    assert!(get("google.protobuf.DoubleValue", "1e").is_err());
    assert!(get("google.protobuf.DoubleValue", "1.5.5").is_err());
    assert!(get("google.protobuf.DoubleValue", "0x").is_err());
    assert!(get("google.protobuf.DoubleValue", "--1").is_err());
    let f = get("google.protobuf.FloatValue", "3.123456789123456789").unwrap();
    assert_eq!(f, Value::F32(3.123_456_7));
    let m = parse_dynamic(
        msg("google.protobuf.FloatValue"),
        "value: 3.123456789123456789",
        &o,
    )
    .unwrap();
    assert_eq!(m.to_text(&PrintOptions::default()), "value: 3.1234567\n");
}

#[test]
fn errors_have_positions() {
    let d = well_known::descriptor_pool()
        .get_message_by_name("google.protobuf.Duration")
        .unwrap();
    let e =
        parse_dynamic(d, "seconds: 1\n# x\n  nanos: 'a'", &ParseOptions::default()).unwrap_err();
    assert_eq!((e.line(), e.column()), (3, 10));
    assert!(
        e.to_string().starts_with("protobuf text format: 3:10: "),
        "{e}"
    );
}
