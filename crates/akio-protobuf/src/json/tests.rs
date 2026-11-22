use super::*;
use crate::{
    reflect::Value,
    well_known::{
        self, Any, BoolValue, Duration, FieldMask, Int64Value, ListValue, Struct, Timestamp,
    },
};

fn roundtrip<M: ReflectMessage + PartialEq + fmt::Debug>(m: &M, want: &str) {
    let s = to_string(m).unwrap();
    assert_eq!(s, want);
    assert_eq!(&from_str::<M>(&s).unwrap(), m);
}

#[test]
fn well_known_types() {
    roundtrip(
        &Timestamp {
            seconds: 0,
            nanos: 1000,
        },
        "\"1970-01-01T00:00:00.000001Z\"",
    );
    roundtrip(
        &Duration {
            seconds: 3,
            nanos: 0,
        },
        "\"3s\"",
    );
    roundtrip(
        &FieldMask {
            paths: vec!["foo_bar".into(), "a.b_c".into()],
        },
        "\"fooBar,a.bC\"",
    );
    roundtrip(&Int64Value { value: -5 }, "\"-5\"");
    roundtrip(&BoolValue { value: false }, "false");
    let st: Struct = from_str(r#"{"a":[1,"x",null,true,{"b":{}}]}"#).unwrap();
    assert_eq!(
        to_string(&st).unwrap(),
        r#"{"a":[1,"x",null,true,{"b":{}}]}"#
    );
    let l: ListValue = from_str("[]").unwrap();
    assert!(l.values.is_empty());
    let any = Any::pack(&Duration {
        seconds: 1,
        nanos: 0,
    });
    roundtrip(
        &any,
        r#"{"@type":"type.googleapis.com/google.protobuf.Duration","value":"1s"}"#,
    );
    let any = Any::pack(&well_known::Empty {});
    roundtrip(
        &any,
        r#"{"@type":"type.googleapis.com/google.protobuf.Empty"}"#,
    );
    roundtrip(&Any::default(), "{}");
    assert!(to_string(&well_known::Value::default()).is_err());
}

#[test]
fn rejects_bad_json() {
    for s in [
        "{\"a\":1,}",
        "[1,]",
        "01",
        "\"\\x\"",
        "\"\\ud800\"",
        "\"a\u{1}\"",
        "1.",
        "-",
        "{\"a\" 1}",
        "nul",
    ] {
        assert!(tree::parse(s).is_err(), "{s}");
    }
    let deep = "[".repeat(101) + &"]".repeat(101);
    assert!(tree::parse(&deep).is_err());
    let ok = "[".repeat(100) + &"]".repeat(100);
    assert!(tree::parse(&ok).is_ok());
    let v = tree::parse(r#"{"a":"\u00e9\ud83d\ude00","b":-1.5e+3}"#).unwrap();
    let mut out = String::new();
    tree::write(&mut out, &v);
    assert_eq!(out, "{\"a\":\"é😀\",\"b\":-1.5e+3}");
}

#[test]
fn dynamic_messages() {
    let desc = well_known::descriptor_pool()
        .get_message_by_name("google.protobuf.Type")
        .unwrap();
    let m = parse_dynamic(
        desc.clone(),
        r#"{"name":"t","fields":[{"kind":"TYPE_INT32","number":3,"jsonName":"x"}],"syntax":1}"#,
        &ParseOptions::default(),
    )
    .unwrap();
    assert_eq!(
        m.get_by_name("name").as_deref(),
        Some(&Value::String("t".into()))
    );
    let s = m.to_json(&PrintOptions::default()).unwrap();
    assert_eq!(
        s,
        r#"{"name":"t","fields":[{"kind":"TYPE_INT32","number":3,"jsonName":"x"}],"syntax":"SYNTAX_PROTO3"}"#
    );
    let s = m
        .to_json(&PrintOptions {
            preserve_proto_field_names: true,
            ..Default::default()
        })
        .unwrap();
    assert!(s.contains("\"json_name\":\"x\""));
    assert!(parse_dynamic(desc.clone(), r#"{"nope":1}"#, &ParseOptions::default()).is_err());
    let lax = ParseOptions {
        ignore_unknown_fields: true,
        ..Default::default()
    };
    assert!(parse_dynamic(desc.clone(), r#"{"nope":1}"#, &lax).is_ok());
    assert!(parse_dynamic(desc, r#"{"name":"a","name":"b"}"#, &ParseOptions::default()).is_err());
}
