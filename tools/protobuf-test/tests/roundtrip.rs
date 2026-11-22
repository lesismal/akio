//! Round trips, merge semantics, limits and hostile input for the generated messages.

use akio_protobuf::{DecodeErrorKind, Enumeration, Message, Name};
use protobuf_test::test::{
    all::{AllTypes, Color, Small, all_types},
    btree::{Sorted, sorted},
};

fn nested(a: i32) -> all_types::Nested {
    all_types::Nested {
        a,
        ..Default::default()
    }
}

#[test]
fn full_message_round_trip() {
    let m = AllTypes {
        f_int32: 1,
        f_string: "x".into(),
        r_nested: vec![nested(1), nested(2)],
        m_string_int32: [
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
        ]
        .into(),
        m_bool_nested: [(false, nested(0)), (true, nested(9))].into(),
        choice: Some(all_types::Choice::CSelf(Box::new(AllTypes {
            f_bool: true,
            ..Default::default()
        }))),
        recursive: Some(Box::new(AllTypes {
            o_enum: Some(Color(1234)),
            ..Default::default()
        })),
        ..Default::default()
    };
    let b = m.encode_to_vec();
    assert_eq!(b.len(), m.encoded_len());
    assert_eq!(AllTypes::decode(&b).unwrap(), m);
    let mut framed = Vec::new();
    m.encode_length_delimited(&mut framed);
    framed.extend_from_slice(b"trailing");
    assert_eq!(AllTypes::decode_length_delimited(&framed).unwrap(), m);
    assert_eq!(AllTypes::default().encode_to_vec(), b"");
    assert_eq!(AllTypes::FULL_NAME, "test.all.AllTypes");
    assert_eq!(all_types::Nested::FULL_NAME, "test.all.AllTypes.Nested");
    assert_eq!(
        AllTypes::type_url(),
        "type.googleapis.com/test.all.AllTypes"
    );
}

#[test]
fn merging_follows_the_specification() {
    let a = AllTypes {
        f_int32: 1,
        f_string: "first".into(),
        r_int32: vec![1, 2],
        f_nested: Some(all_types::Nested {
            a: 1,
            r#type: "kept".into(),
            ..Default::default()
        }),
        m_string_int32: [("k".to_string(), 1), ("akio-a".to_string(), 0)].into(),
        choice: Some(all_types::Choice::CNested(nested(5))),
        ..Default::default()
    };
    let b = AllTypes {
        f_int32: 2,
        r_int32: vec![3],
        f_nested: Some(nested(2)),
        m_string_int32: [("k".to_string(), 2)].into(),
        choice: Some(all_types::Choice::CNested(all_types::Nested {
            r#type: "merged".into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut cat = a.encode_to_vec();
    cat.extend(b.encode_to_vec());
    let m = AllTypes::decode(&cat).unwrap();
    assert_eq!(m.f_int32, 2, "scalars: last wins");
    assert_eq!(m.f_string, "first", "absent in b: kept");
    assert_eq!(m.r_int32, [1, 2, 3], "repeated: appended");
    assert_eq!(
        m.f_nested.as_ref().map(|n| (n.a, n.r#type.as_str())),
        Some((2, "kept")),
        "messages: merged"
    );
    assert_eq!(m.m_string_int32.len(), 2);
    assert_eq!(m.m_string_int32["k"], 2, "maps: last key wins");
    match &m.choice {
        Some(all_types::Choice::CNested(n)) => assert_eq!((n.a, n.r#type.as_str()), (5, "merged")),
        other => panic!("{other:?}"),
    }
    // Another oneof member replaces it.
    let mut m2 = m;
    m2.merge(
        &AllTypes {
            choice: Some(all_types::Choice::CString("s".into())),
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .unwrap();
    assert_eq!(m2.choice, Some(all_types::Choice::CString("s".into())));
    m2.clear();
    assert_eq!(m2, AllTypes::default());
}

#[test]
fn open_enums_keep_unknown_numbers() {
    let m = AllTypes::decode(&[0x80, 0x01, 0x05]).unwrap(); // f_enum = 5
    assert_eq!(m.f_enum, Color(5));
    assert_eq!(m.f_enum.name(), None);
    assert_eq!(format!("{:?}", m.f_enum), "5");
    assert_eq!(m.encode_to_vec(), [0x80, 0x01, 0x05]);
    assert_eq!(format!("{:?}", Color::NEGATIVE), "COLOR_NEGATIVE");
    assert_eq!(Color::from_name("COLOR_GREEN"), Some(Color::GREEN));
    assert_eq!(Color::from_name("GREEN"), None);
    assert_eq!(i32::from(Color::NEGATIVE), -1);
    assert_eq!(Color::from(2), Color::GREEN);
    assert_eq!(Color::default(), Color::UNSPECIFIED);
    // -1 is a 10-byte varint (sign-extended), as for int32.
    let e = AllTypes {
        f_enum: Color::NEGATIVE,
        ..Default::default()
    };
    assert_eq!(e.encode_to_vec().len(), 2 + 10);
}

#[test]
fn wrong_wire_types_become_unknown_fields() {
    // f_int32 (field 1) sent as fixed32, f_string (14) as a varint: both kept as unknown,
    // written back unchanged; the fields keep their defaults.
    let b = [0x0d, 1, 2, 3, 4, 0x70, 0x07];
    let m = AllTypes::decode(&b).unwrap();
    assert_eq!((m.f_int32, m.f_string.as_str()), (0, ""));
    assert_eq!(m.unknown_fields.as_bytes(), b);
    assert_eq!(m.encode_to_vec(), b);
    // A map sent as a varint, a message as fixed64.
    let b = [0x90, 0x03, 0x01, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    let m = AllTypes::decode(&b).unwrap();
    assert!(m.m_string_int32.is_empty() && m.f_nested.is_none());
    assert_eq!(m.encode_to_vec(), b);
}

#[test]
fn limits_and_hostile_input() {
    // 100 nested messages decode, 101 do not.
    let chain = |depth: usize| {
        let mut m = AllTypes::default();
        for _ in 0..depth {
            m = AllTypes {
                recursive: Some(Box::new(m)),
                ..Default::default()
            };
        }
        m.encode_to_vec()
    };
    assert!(AllTypes::decode(&chain(100)).is_ok());
    let e = AllTypes::decode(&chain(101)).unwrap_err();
    assert_eq!(e.kind(), DecodeErrorKind::RecursionLimit);
    assert_eq!(e.field(), Some(70));
    // A length beyond the input, at any depth.
    assert_eq!(
        AllTypes::decode(&[0x8a, 0x01, 0x7f, 0x08])
            .unwrap_err()
            .kind(),
        DecodeErrorKind::Truncated
    );
    let huge = [0x72, 0xff, 0xff, 0xff, 0xff, 0x0f];
    assert_eq!(
        AllTypes::decode(&huge).unwrap_err().kind(),
        DecodeErrorKind::Truncated
    );
    assert_eq!(
        AllTypes::decode(&[0x72, 0x02, 0xc3, 0x28])
            .unwrap_err()
            .kind(),
        DecodeErrorKind::InvalidUtf8
    );
    // Deep groups in unknown fields.
    let mut g = [0xfb, 0x07].repeat(200);
    g.extend([0xfc, 0x07].repeat(200));
    assert_eq!(
        AllTypes::decode(&g).unwrap_err().kind(),
        DecodeErrorKind::RecursionLimit
    );
    // A stray end-group tag.
    assert_eq!(
        AllTypes::decode(&[0x0c]).unwrap_err().kind(),
        DecodeErrorKind::UnbalancedGroup
    );
    // Garbage never panics, and whatever decodes re-encodes to something that decodes the same.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..100_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 24) as usize;
        let b: Vec<u8> = (0..n).map(|i| (x >> (i % 8 * 8)) as u8 ^ i as u8).collect();
        if let Ok(m) = AllTypes::decode(&b) {
            let re = m.encode_to_vec();
            assert_eq!(re.len(), m.encoded_len());
            let back = AllTypes::decode(&re).unwrap();
            assert_eq!(format!("{back:?}"), format!("{m:?}"));
        }
    }
}

#[test]
fn unknown_fields_are_optional_and_maps_can_be_sorted() {
    // `test.btree` is generated without unknown fields and with BTreeMap maps: struct literals
    // need no `..Default::default()`, and map entries are written in key order.
    let s = Sorted {
        m: [("b".to_string(), 2), ("a".to_string(), 1)].into(),
        e: Some(sorted::Empty {}),
        list: vec![sorted::Empty {}, sorted::Empty {}],
    };
    let b = s.encode_to_vec();
    assert_eq!(&b[..7], &[0x0a, 0x05, 0x0a, 0x01, b'a', 0x10, 0x01]);
    assert_eq!(Sorted::decode(&b).unwrap(), s);
    // Unknown fields are skipped.
    let mut with_unknown = b.clone();
    with_unknown.extend([0xa0, 0x06, 0x01]);
    assert_eq!(Sorted::decode(&with_unknown).unwrap().encode_to_vec(), b);
    // For `Small` (with unknown fields) all of it is unknown: field 1 is an int32 there, so the
    // length-delimited field 1 is kept as unknown too.
    let small = Small::decode(&with_unknown).unwrap();
    assert_eq!(small.f_int32, 0);
    assert_eq!(small.unknown_fields.as_bytes(), with_unknown);
    assert_eq!(small.encode_to_vec(), with_unknown);
}
