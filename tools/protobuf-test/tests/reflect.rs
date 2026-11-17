//! Runtime reflection: dynamic messages decode and re-encode the golden encodings exactly as
//! the generated code does, and agree with it field by field.

use only_protobuf::{
    Message,
    reflect::{DynamicMessage, ReflectMessage, Value},
};
use protobuf_test::protobuf_test_messages::{editions, proto2, proto3};

fn golden(name: &str) -> Vec<u8> {
    let p = format!("{}/golden/{name}.bin", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn same<M: ReflectMessage + PartialEq + std::fmt::Debug>(name: &str) {
    let bin = golden(name);
    let d = DynamicMessage::decode(M::descriptor(), &bin).unwrap();
    assert_eq!(d.encode_to_vec(), bin, "{name}: dynamic re-encoding");
    let typed = M::decode(&bin).unwrap();
    assert_eq!(M::from_dynamic(&d).unwrap(), typed, "{name}");
    assert_eq!(typed.to_dynamic().unwrap(), d, "{name}");
}

#[test]
fn dynamic_messages_match_generated_code() {
    same::<proto2::TestAllTypesProto2>("p2_groups_ext");
    same::<editions::proto2::TestAllTypesProto2>("editions_p2");
    same::<editions::TestAllTypesEdition2023>("edition2023");
    same::<protobuf_test::test::all::AllTypes>("scalars");
    same::<protobuf_test::test::all::AllTypes>("repeated");
    same::<protobuf_test::test::all::AllTypes>("maps");
    same::<protobuf_test::test::p2::P2>("p2");
}

#[test]
fn descriptors_resolve() {
    let d = proto3::TestAllTypesProto3::descriptor();
    assert_eq!(
        d.full_name(),
        "protobuf_test_messages.proto3.TestAllTypesProto3"
    );
    let f = d.get_field_by_name("optional_int32").unwrap();
    assert!(!f.has_presence());
    let f = d.get_field_by_name("repeated_int32").unwrap();
    assert!(f.is_packed() && f.is_list());
    let f = d.get_field_by_json_name("mapStringNestedMessage").unwrap();
    assert!(f.is_map());
    let (k, v) = f.map_entry_fields().unwrap();
    assert_eq!(
        (k.name(), v.message_type().unwrap().name()),
        ("key", "NestedMessage")
    );
    let f = d.get_field_by_name("optional_nested_enum").unwrap();
    assert!(!f.enum_type().unwrap().is_closed());

    let d = proto2::TestAllTypesProto2::descriptor();
    let f = d.get_field_by_name("optional_nested_enum").unwrap();
    assert!(f.has_presence() && f.enum_type().unwrap().is_closed());
    assert!(d.get_field_by_name("data").unwrap().is_group());
    assert_eq!(
        d.get_field_by_name("default_int32")
            .unwrap()
            .default_value(),
        Value::I32(-123456789)
    );
    assert_eq!(
        d.get_field_by_name("default_bytes")
            .unwrap()
            .default_value(),
        Value::Bytes(b"joshua".to_vec())
    );
    let exts = d.extensions();
    assert!(
        exts.iter()
            .any(|x| x.full_name() == "protobuf_test_messages.proto2.extension_int32")
    );
    let pool = d.pool();
    let x = pool
        .get_extension_by_name("protobuf_test_messages.proto2.groupfield")
        .unwrap();
    assert!(x.is_extension() && x.is_group());
    assert_eq!(
        pool.file_containing_symbol(
            "protobuf_test_messages.proto2.TestAllTypesProto2.NestedMessage.a"
        )
        .unwrap()
        .name(),
        "google/protobuf/test_messages_proto2.proto"
    );

    // Editions: features resolved per field.
    let d = editions::TestAllTypesEdition2023::descriptor();
    assert!(d.get_field_by_name("groupliketype").unwrap().is_group());
    assert!(
        !d.get_field_by_name("optional_nested_message")
            .unwrap()
            .is_group()
    );
    assert!(
        d.get_field_by_name("optional_int32")
            .unwrap()
            .has_presence()
    );
    let d = editions::proto3::TestAllTypesProto3::descriptor();
    assert!(
        !d.get_field_by_name("optional_int32")
            .unwrap()
            .has_presence()
    );
}

#[test]
fn dynamic_set_get_and_oneofs() {
    let d = proto3::TestAllTypesProto3::descriptor();
    let mut m = DynamicMessage::new(d.clone());
    let a = d.get_field_by_name("oneof_uint32").unwrap();
    let b = d.get_field_by_name("oneof_string").unwrap();
    m.set(&a, Value::U32(7)).unwrap();
    m.set(&b, Value::String("x".into())).unwrap();
    assert!(
        !m.has(&a) && m.has(&b),
        "setting a oneof member clears the others"
    );
    assert!(m.set(&a, Value::I32(1)).is_err());
    let r = d.get_field_by_name("repeated_int32").unwrap();
    m.set(&r, Value::List(vec![Value::I32(1), Value::I32(2)]))
        .unwrap();
    let typed = proto3::TestAllTypesProto3::from_dynamic(&m).unwrap();
    assert_eq!(typed.repeated_int32, [1, 2]);
    assert_eq!(
        typed.oneof_field,
        Some(proto3::test_all_types_proto3::OneofField::OneofString(
            "x".into()
        ))
    );
    assert_eq!(m.encoded_len(), typed.encoded_len());
}
