//! `features.utf8_validation`: a `string` field with `NONE` (and a proto2 one compiled with
//! `Config::proto2_unchecked_strings`) accepts any bytes and writes them back unchanged; one with
//! `VERIFY` rejects what is not UTF-8. Generated code, dynamic messages, JSON and the text format.

use only_protobuf::{
    DecodeErrorKind, Extendable, Message, ProtoString, encoding,
    reflect::{DynamicMessage, ReflectMessage, Value},
};
use protobuf_test::test::{
    utf8::{self, Strings},
    utf8f::Relaxed,
    utf8p2::Legacy,
};

const BAD: &[u8] = b"a\xff\xfeb";

/// One length-delimited field.
fn len_field(n: u32, b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encoding::put_varint(&mut out, u64::from((n << 3) | 2));
    encoding::put_bytes(&mut out, b);
    out
}

/// A map entry field (`key` = 1, `value` = 2, both length-delimited).
fn map_field(n: u32, k: &[u8], v: &[u8]) -> Vec<u8> {
    let mut e = len_field(1, k);
    e.extend(len_field(2, v));
    len_field(n, &e)
}

fn rejects<M: Message + std::fmt::Debug>(b: &[u8]) {
    let e = M::decode(b).expect_err("not UTF-8 must be rejected");
    assert_eq!(e.kind(), DecodeErrorKind::InvalidUtf8, "{e:?}");
}

#[test]
fn none_fields_keep_any_bytes() {
    let mut wire = Vec::new();
    wire.extend(len_field(2, BAD));
    wire.extend(len_field(3, BAD));
    wire.extend(len_field(3, b"ok"));
    wire.extend(map_field(4, BAD, BAD));
    wire.extend(len_field(6, BAD));
    wire.extend(len_field(9, BAD));
    let mut e = Vec::new();
    encoding::put_varint(&mut e, 1 << 3);
    encoding::put_varint(&mut e, 7);
    e.extend(len_field(2, BAD));
    wire.extend(len_field(10, &e));

    let m = Strings::decode(&wire).expect("NONE fields accept any bytes");
    assert_eq!(m.raw(), BAD);
    assert_eq!(
        m.raw_list,
        [ProtoString::from(BAD), ProtoString::from("ok")]
    );
    assert_eq!(m.raw_map.get(BAD), Some(&ProtoString::from(BAD)));
    assert_eq!(m.choice, Some(utf8::strings::Choice::RawChoice(BAD.into())));
    assert_eq!(m.implicit_raw, BAD);
    assert_eq!(m.raw_values[&7], BAD);
    // Written back byte for byte (fields in number order, as decoded).
    assert_eq!(Strings::decode(&m.encode_to_vec()).unwrap(), m);
    assert_eq!(m.encode_to_vec().len(), m.encoded_len());
    assert_eq!(
        m.raw.as_ref().unwrap().to_string_lossy(),
        "a\u{fffd}\u{fffd}b"
    );
}

#[test]
fn verify_fields_still_reject() {
    rejects::<Strings>(&len_field(1, BAD));
    rejects::<Strings>(&map_field(5, BAD, b"v"));
    rejects::<Strings>(&map_field(5, b"k", BAD));
    rejects::<Strings>(&len_field(7, BAD));
    // Valid UTF-8 goes through both kinds.
    let m = Strings::decode(&[len_field(1, "é".as_bytes()), len_field(2, "é".as_bytes())].concat())
        .unwrap();
    assert_eq!(m.checked(), "é");
    assert_eq!(m.raw.as_ref().unwrap().to_str(), Ok("é"));
}

#[test]
fn defaults_and_getters() {
    let m = Strings::default();
    assert_eq!(m.raw(), b"");
    assert_eq!(m.raw_default(), "dé".as_bytes());
    assert_eq!(m.checked(), "");
    let l = Legacy::default();
    assert_eq!(l.id, ProtoString::from(&b"x\xff"[..]));
    assert_eq!(l.name(), b"");
}

#[test]
fn file_wide_none_with_a_field_back_to_verify() {
    let m = Relaxed::decode(&[len_field(1, BAD), map_field(3, BAD, BAD)].concat()).unwrap();
    assert_eq!(m.raw.as_ref().unwrap(), BAD);
    assert_eq!(m.raw_map.get(BAD).unwrap(), BAD);
    rejects::<Relaxed>(&len_field(2, BAD));
}

#[test]
fn proto2_unchecked_strings() {
    let wire = [
        len_field(1, BAD),
        len_field(2, BAD),
        map_field(3, BAD, BAD),
        len_field(4, b"id"),
    ]
    .concat();
    let l = Legacy::decode(&wire).unwrap();
    assert_eq!(l.name(), BAD);
    assert_eq!(l.tags, [ProtoString::from(BAD)]);
    assert_eq!(l.attrs.get(BAD).unwrap(), BAD);
    assert_eq!(l.encode_to_vec(), wire);
    // Without the option, proto2 strings are checked (`test.p2`, `String`).
    rejects::<protobuf_test::test::p2::P2>(&len_field(2, BAD));
}

#[test]
fn extensions() {
    let m = Strings::decode(&[len_field(100, BAD), len_field(1, b"c")].concat()).unwrap();
    assert_eq!(m.extension(&utf8::RAW_EXT).unwrap(), Some(BAD.into()));
    rejects::<Strings>(&len_field(101, BAD));
    let mut n = Strings::default();
    n.set_extension(&utf8::RAW_EXT, &ProtoString::from(BAD));
    assert_eq!(Strings::decode(&n.encode_to_vec()).unwrap(), n);
}

#[test]
fn dynamic_messages_follow_the_descriptor() {
    let d = Strings::descriptor();
    let f = |name: &str| d.get_field_by_name(name).unwrap();
    assert!(f("checked").requires_utf8());
    assert!(!f("raw").requires_utf8());
    // The map field's feature reaches its entry's key and value (as protoc writes it).
    let (k, v) = f("raw_map").map_entry_fields().unwrap();
    assert!(!k.requires_utf8() && !v.requires_utf8());
    let (k, v) = f("checked_map").map_entry_fields().unwrap();
    assert!(k.requires_utf8() && v.requires_utf8());

    let wire = [len_field(2, BAD), len_field(3, BAD), len_field(3, b"ok")].concat();
    let dm = DynamicMessage::decode(d.clone(), &wire).unwrap();
    assert_eq!(dm.get(&f("raw")).into_owned(), Value::Bytes(BAD.to_vec()));
    assert_eq!(
        dm.get(&f("raw_list")).into_owned(),
        Value::List(vec![Value::Bytes(BAD.to_vec()), Value::String("ok".into())])
    );
    assert_eq!(dm.encode_to_vec(), wire);
    assert_eq!(
        Strings::from_dynamic(&dm).unwrap(),
        Strings::decode(&wire).unwrap()
    );
    assert_eq!(Strings::decode(&wire).unwrap().to_dynamic().unwrap(), dm);

    let e = DynamicMessage::decode(d.clone(), &len_field(1, BAD)).unwrap_err();
    assert_eq!(e.kind(), DecodeErrorKind::InvalidUtf8);
    // Map values are fine; a key that is not UTF-8 cannot be a `MapKey` (a `String`).
    let dm = DynamicMessage::decode(d.clone(), &map_field(4, b"k", BAD)).unwrap();
    assert_eq!(dm.encode_to_vec(), map_field(4, b"k", BAD));
    let e = DynamicMessage::decode(d.clone(), &map_field(4, BAD, b"v")).unwrap_err();
    assert_eq!(e.kind(), DecodeErrorKind::InvalidUtf8);

    let mut dm = DynamicMessage::new(d.clone());
    dm.set(&f("raw"), Value::Bytes(BAD.to_vec())).unwrap();
    assert!(dm.set(&f("checked"), Value::Bytes(BAD.to_vec())).is_err());
    assert_eq!(dm.encode_to_vec(), len_field(2, BAD));

    // proto2 strings do not ask for UTF-8 either.
    let p2 = protobuf_test::test::p2::P2::descriptor();
    let dm = DynamicMessage::decode(p2, &len_field(2, BAD)).unwrap();
    assert_eq!(dm.encode_to_vec(), len_field(2, BAD));
}

#[test]
fn json_and_text() {
    let m = Strings {
        raw: Some(BAD.into()),
        checked: Some("c".into()),
        ..Default::default()
    };
    // JSON text is Unicode: written lossily.
    let j = only_protobuf::json::to_string(&m).unwrap();
    assert_eq!(j, "{\"checked\":\"c\",\"raw\":\"a\u{fffd}\u{fffd}b\"}");
    // The text format escapes the bytes and reads them back.
    let t = only_protobuf::text::to_string(&m).unwrap();
    assert!(t.contains(r#"raw: "a\377\376b""#), "{t}");
    let back: Strings = only_protobuf::text::from_str(&t).unwrap();
    assert_eq!(back, m);
    assert!(only_protobuf::text::from_str::<Strings>(r#"checked: "\377""#).is_err());
}
