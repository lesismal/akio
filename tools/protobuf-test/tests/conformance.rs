//! Conformance against golden encodings made by protoc (the C++ implementation) from the
//! text-format cases in `golden/` (`golden/regen.sh`): the generated messages must decode them
//! to the expected values and re-encode them byte for byte.

use only_protobuf::{Extendable, Message, well_known};
use protobuf_test::test::{
    all::{AllTypes, Color, Extended, Small, all_types},
    common::Shared,
    p2::{self, Level, P2},
};

fn golden(name: &str) -> Vec<u8> {
    let p = format!("{}/golden/{name}.bin", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// Decodes the golden encoding, checks it against `want` and that both re-encode to it.
fn check<M: Message + PartialEq + std::fmt::Debug>(name: &str, want: &M) {
    let bin = golden(name);
    let got = M::decode(&bin).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(&got, want, "{name}: decoded value");
    assert_eq!(
        got.encode_to_vec(),
        bin,
        "{name}: re-encoding the decoded value"
    );
    assert_eq!(
        want.encode_to_vec(),
        bin,
        "{name}: encoding the expected value"
    );
    assert_eq!(want.encoded_len(), bin.len(), "{name}: encoded_len");
}

fn nested(a: i32) -> all_types::Nested {
    all_types::Nested {
        a,
        ..Default::default()
    }
}

#[test]
fn scalars() {
    let want = AllTypes {
        f_int32: -42,
        f_int64: -9_000_000_000,
        f_uint32: u32::MAX,
        f_uint64: u64::MAX,
        f_sint32: i32::MIN,
        f_sint64: i64::MIN,
        f_fixed32: 123_456,
        f_fixed64: 9_876_543_210,
        f_sfixed32: -5,
        f_sfixed64: -6,
        f_float: -0.0,
        f_double: 3.5,
        f_bool: true,
        f_string: "héllo ✓".into(),
        f_bytes: vec![0, 1, 255],
        f_enum: Color::NEGATIVE,
        f_nested: Some(all_types::Nested {
            a: 7,
            r#type: "kw".into(),
            deep: all_types::nested::inner::Deep::ONE,
            child: Some(Box::new(nested(8))),
            ..Default::default()
        }),
        f_shared: Some(Shared {
            id: "s".into(),
            values: vec![1, -1],
            ..Default::default()
        }),
        o_int32: Some(0),
        o_string: Some(String::new()),
        o_enum: Some(Color::UNSPECIFIED),
        o_nested: Some(all_types::Nested::default()),
        max_field_number: 1,
        ..Default::default()
    };
    check("scalars", &want);
    assert_eq!(want.o_int32(), 0);
    assert_eq!(AllTypes::default().o_string(), "");
}

#[test]
fn repeated() {
    let want = AllTypes {
        r_int32: vec![1, -1, 300],
        r_sint64: vec![-1, 1, -300],
        r_fixed32: vec![1, u32::MAX],
        r_double: vec![0.5, -0.0, f64::INFINITY],
        r_bool: vec![true, false],
        r_enum: vec![Color::RED, Color::NEGATIVE],
        r_int32_unpacked: vec![5, -5],
        r_string: vec!["a".into(), String::new(), "c".into()],
        r_bytes: vec![vec![], b"x".to_vec()],
        r_nested: vec![nested(1), nested(0)],
        r_uint64: vec![0, u64::MAX],
        ..Default::default()
    };
    check("repeated", &want);
}

#[test]
fn maps_write_default_keys_and_values() {
    let want = AllTypes {
        m_string_int32: [("k".to_string(), -1)].into(),
        m_int64_string: [(-5, "v".to_string())].into(),
        m_bool_nested: [(true, nested(3))].into(),
        m_uint32_enum: [(0, Color::GREEN)].into(),
        m_sint32_bytes: [(-1, vec![])].into(),
        m_fixed64_double: [(7, 0.0)].into(),
        ..Default::default()
    };
    check("maps", &want);
}

#[test]
fn oneofs_recursion_and_well_known_types() {
    let shared = Shared {
        id: "inside".into(),
        ..Default::default()
    };
    let want = AllTypes {
        choice: Some(all_types::Choice::CNested(nested(1))),
        recursive: Some(Box::new(AllTypes {
            f_int32: 1,
            recursive: Some(Box::new(AllTypes {
                f_string: "deep".into(),
                ..Default::default()
            })),
            ..Default::default()
        })),
        ts: Some(well_known::Timestamp {
            seconds: 1_700_000_000,
            nanos: 5,
        }),
        any: Some(well_known::Any::pack(&shared)),
        st: Some(well_known::Struct {
            fields: [(
                "n".to_string(),
                well_known::Value {
                    kind: Some(well_known::value::Kind::NumberValue(1.5)),
                },
            )]
            .into(),
        }),
        wrapped: Some(well_known::Int32Value { value: 0 }),
        ..Default::default()
    };
    check("oneof_wkt", &want);
    let got = AllTypes::decode(&golden("oneof_wkt")).unwrap();
    assert_eq!(got.any.unwrap().unpack::<Shared>().unwrap(), Some(shared));

    // A oneof member is written even when it holds the default.
    let want = AllTypes {
        choice: Some(all_types::Choice::CUint32(0)),
        ..Default::default()
    };
    check("oneof_default", &want);

    let want = AllTypes {
        choice: Some(all_types::Choice::CSelf(Box::new(AllTypes {
            choice: Some(all_types::Choice::CString(String::new())),
            o_nested: Some(all_types::Nested {
                child: Some(Box::new(all_types::Nested {
                    child: Some(Box::default()),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }))),
        ..Default::default()
    };
    check("oneof_self", &want);
}

#[test]
fn proto2_presence_defaults_and_extensions() {
    let bin = golden("p2");
    let got = P2::decode(&bin).unwrap();
    assert_eq!(
        got.a,
        Some(0),
        "present, even though 0 is not the declared default"
    );
    assert_eq!(got.a(), 0);
    assert_eq!(got.s.as_deref(), Some(""));
    assert_eq!(got.level, Some(Level::LOW));
    assert_eq!((got.req, got.req_s.as_str()), (-1, ""));
    assert_eq!(
        (got.unpacked.as_slice(), got.packed.as_slice()),
        (&[1, 2][..], &[3, 4][..])
    );
    assert_eq!(
        got.child.as_ref().map(|c| (c.req, c.req_s.as_str())),
        Some((5, "c"))
    );
    assert_eq!(got.flag, Some(false));
    assert_eq!(got.m.get(&1).map(String::as_str), Some("one"));
    // The extension (field 100) is kept in the extension set, as read (tag 100 << 3 = 0x320 ->
    // a0 06, value 9), and readable through the generated constant.
    assert!(got.unknown_fields.is_empty());
    assert_eq!(got.extensions.raw(100), Some(&[0xa0, 0x06, 0x09][..]));
    assert_eq!(got.extension(&p2::EXT).unwrap(), Some(9));
    assert_eq!(got.encode_to_vec(), bin);

    // Unset optional fields read as their declared defaults; required ones use theirs.
    let d = P2::default();
    assert_eq!(
        (d.a(), d.s(), d.b(), d.level(), d.d(), d.f()),
        (
            42,
            "hello \"x\"",
            &[1u8, 2][..],
            Level::HIGH,
            f64::NEG_INFINITY,
            1.5
        )
    );
    assert_eq!(
        (d.big(), d.neg(), d.plain_level(), d.flag()),
        (u64::MAX, -16, Level::LOW, false)
    );
    assert_eq!(d.req_s, "rs");
    assert_eq!(
        Level::default(),
        Level::LOW,
        "a proto2 enum defaults to its first value"
    );
    // Required fields are always written, unset optional ones never.
    let mut e = Vec::new();
    d.encode(&mut e);
    assert_eq!(e, [0x38, 0x00, 0x42, 0x02, b'r', b's']);
    // proto2 repeated scalars are unpacked unless `[packed = true]`.
    let m = P2 {
        unpacked: vec![1, 2],
        packed: vec![1, 2],
        req_s: String::new(),
        ..Default::default()
    };
    assert_eq!(
        m.encode_to_vec(),
        [
            0x38, 0x00, 0x42, 0x00, 0x48, 0x01, 0x48, 0x02, 0x52, 0x02, 0x01, 0x02
        ]
    );
}

#[test]
fn unknown_fields_survive_a_round_trip_through_an_older_message() {
    let ext = Extended {
        f_int32: 3,
        f_string: "known".into(),
        extra_varint: -1,
        extra_string: "unknown".into(),
        extra_fixed32: 7,
        extra_fixed64: 8,
        extra_message: Some(nested(9)),
        ..Default::default()
    };
    let bin = ext.encode_to_vec();
    let small = Small::decode(&bin).unwrap();
    assert_eq!((small.f_int32, small.f_string.as_str()), (3, "known"));
    assert!(!small.unknown_fields.is_empty());
    // Known fields first, then the unknown ones in their original order: the same bytes here.
    assert_eq!(small.encode_to_vec(), bin);
    assert_eq!(Extended::decode(&small.encode_to_vec()).unwrap(), ext);
    // A modified known field keeps the unknown ones.
    let mut s2 = small;
    s2.f_int32 = 4;
    let back = Extended::decode(&s2.encode_to_vec()).unwrap();
    assert_eq!((back.f_int32, back.extra_string.as_str()), (4, "unknown"));
}

/// Decodes a golden encoding and checks that the decoded value re-encodes to it byte for byte.
fn roundtrip<M: Message + PartialEq + std::fmt::Debug>(name: &str) -> M {
    let bin = golden(name);
    let got = M::decode(&bin).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(got.encode_to_vec(), bin, "{name}: re-encoding");
    assert_eq!(got.encoded_len(), bin.len(), "{name}: encoded_len");
    got
}

#[test]
fn proto2_groups_extensions_and_message_sets() {
    use protobuf_test::protobuf_test_messages::proto2::{
        self as p2m, GroupField, TestAllTypesProto2, test_all_types_proto2 as t,
    };
    let got: TestAllTypesProto2 = roundtrip("p2_groups_ext");
    assert_eq!(
        got.data,
        Some(t::Data {
            group_int32: Some(-2),
            group_uint32: Some(3),
            ..Default::default()
        })
    );
    assert_eq!(got.multiwordgroupfield.as_ref().unwrap().group_int32, Some(4));
    assert_eq!(got.optional_nested_enum, Some(t::NestedEnum::BAZ));
    assert_eq!(got.packed_nested_enum, [t::NestedEnum::BAZ, t::NestedEnum::FOO]);
    assert_eq!(got.extension(&p2m::EXTENSION_INT32).unwrap(), Some(77));
    assert_eq!(
        got.extension(&p2m::EXTENSION_STRING).unwrap().as_deref(),
        Some("ext")
    );
    assert_eq!(
        got.extension(&p2m::GROUPFIELD).unwrap(),
        Some(GroupField {
            group_int32: Some(5),
            group_uint32: Some(6),
            ..Default::default()
        })
    );
    let set = got.message_set_correct.as_ref().unwrap();
    let e1 = set
        .extension(&t::message_set_correct_extension1::MESSAGE_SET_EXTENSION)
        .unwrap()
        .unwrap();
    assert_eq!(e1.str.as_deref(), Some("in a set"));
    let e2 = set
        .extension(&t::message_set_correct_extension2::MESSAGE_SET_EXTENSION)
        .unwrap()
        .unwrap();
    assert_eq!(e2.i, Some(9));

    // Built from scratch through the typed API, the encoding is protoc's.
    let mut want = TestAllTypesProto2 {
        optional_int32: Some(1),
        optional_nested_enum: Some(t::NestedEnum::BAZ),
        repeated_nested_enum: vec![t::NestedEnum::FOO, t::NestedEnum::BAR],
        packed_nested_enum: vec![t::NestedEnum::BAZ, t::NestedEnum::FOO],
        data: got.data.clone(),
        multiwordgroupfield: got.multiwordgroupfield.clone(),
        default_int32: Some(0),
        map_string_nested_enum: std::iter::once(("k".to_string(), t::NestedEnum::BAR)).collect(),
        oneof_field: Some(t::OneofField::OneofUint32(8)),
        ..Default::default()
    };
    want.set_extension(&p2m::EXTENSION_INT32, &77);
    want.set_extension(&p2m::EXTENSION_STRING, &"ext".to_string());
    want.set_extension(
        &p2m::GROUPFIELD,
        &GroupField {
            group_int32: Some(5),
            group_uint32: Some(6),
            ..Default::default()
        },
    );
    let mut set = t::MessageSetCorrect::default();
    set.set_extension(
        &t::message_set_correct_extension1::MESSAGE_SET_EXTENSION,
        &t::MessageSetCorrectExtension1 {
            str: Some("in a set".into()),
            ..Default::default()
        },
    );
    set.set_extension(
        &t::message_set_correct_extension2::MESSAGE_SET_EXTENSION,
        &t::MessageSetCorrectExtension2 {
            i: Some(9),
            ..Default::default()
        },
    );
    want.message_set_correct = Some(set);
    assert_eq!(want, got);
    assert_eq!(want.encode_to_vec(), golden("p2_groups_ext"));
}

#[test]
fn closed_enums_keep_unknown_numbers_as_unknown_fields() {
    use protobuf_test::protobuf_test_messages::proto2::{TestAllTypesProto2, test_all_types_proto2 as t};
    // optional_nested_enum (21) = 7, repeated_nested_enum (51) = [1, 9] unpacked, packed (88)
    // = [2, 10], map_string_nested_enum (73) {"a": 11}, oneof_enum (119) = 12.
    let bin = [
        0xa8, 0x01, 0x07, // 21: 7 (unknown)
        0x98, 0x03, 0x01, // 51: BAR
        0x98, 0x03, 0x09, // 51: 9 (unknown)
        0xc2, 0x05, 0x02, 0x02, 0x0a, // 88 packed: BAZ, 10 (unknown)
        0xca, 0x04, 0x05, 0x0a, 0x01, b'a', 0x10, 0x0b, // 73 {"a": 11} (unknown)
        0xb8, 0x07, 0x0c, // 119: 12 (unknown)
    ];
    let m = TestAllTypesProto2::decode(&bin).unwrap();
    assert_eq!(m.optional_nested_enum, None);
    assert_eq!(m.repeated_nested_enum, [t::NestedEnum::BAR]);
    assert_eq!(m.packed_nested_enum, [t::NestedEnum::BAZ]);
    assert!(m.map_string_nested_enum.is_empty());
    assert_eq!(m.oneof_field, None);
    // The unknown numbers come back after the known fields (unpacked), in the order read.
    let mut want = vec![0x98, 0x03, 0x01, 0xc2, 0x05, 0x01, 0x02];
    want.extend_from_slice(&[0xa8, 0x01, 0x07, 0x98, 0x03, 0x09, 0xc0, 0x05, 0x0a]);
    want.extend_from_slice(&[0xca, 0x04, 0x05, 0x0a, 0x01, b'a', 0x10, 0x0b, 0xb8, 0x07, 0x0c]);
    assert_eq!(m.encode_to_vec(), want);
}

#[test]
fn editions_features() {
    use protobuf_test::protobuf_test_messages::editions::{
        self as e23, GroupLikeType, TestAllTypesEdition2023, proto2 as ep2,
    };
    // proto2 semantics in edition 2023: closed enums, expanded repeated fields, delimited groups.
    let got: ep2::TestAllTypesProto2 = roundtrip("editions_p2");
    assert_eq!(got.optional_int32, Some(1), "explicit presence");
    assert_eq!(got.data.as_ref().unwrap().group_int32, Some(-2));
    assert_eq!(
        got.extension(&ep2::GROUPFIELD).unwrap().unwrap().group_int32,
        Some(5)
    );
    // Edition 2023 with DELIMITED as the file default.
    let got: TestAllTypesEdition2023 = roundtrip("edition2023");
    assert_eq!(got.optional_int32, Some(7));
    assert_eq!(got.groupliketype.as_ref().unwrap().group_int32, Some(6));
    assert_eq!(got.delimited_field.as_ref().unwrap().group_int32, Some(8));
    assert_eq!(
        got.extension(&e23::GROUPLIKETYPE).unwrap(),
        Some(GroupLikeType {
            c: Some(9),
            ..Default::default()
        })
    );
    assert_eq!(got.extension(&e23::DELIMITED_EXT).unwrap().unwrap().c, Some(10));
    assert_eq!(got.map_recursive[&1].optional_int32, Some(11));
    assert_eq!(got.repeated_int32, [1, 2, 3], "packed by default in 2023");
}
