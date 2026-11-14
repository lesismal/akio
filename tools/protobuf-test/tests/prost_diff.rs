//! Differential tests against prost: random messages must encode to what prost decodes to the
//! same value (and back), and mutated encodings must be accepted or rejected alike, with the
//! same result. The fuzz target `protobuf_diff` runs the same check on fuzzer input.

#[path = "../prost_mirror.rs"]
mod mirror;

use only_protobuf::{Message, well_known};
use protobuf_test::test::{
    all::{AllTypes, Color, all_types},
    common::Shared,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    fn int<T: TryFrom<i128> + Default>(&mut self) -> T {
        // Mostly edge values.
        let v: i128 = match self.below(6) {
            0 => 0,
            1 => -1,
            2 => i128::from(self.next() as i64),
            3 => i128::from(self.next()),
            4 => i128::from(self.below(300) as i64 - 150),
            _ => i128::from(self.next() as u32),
        };
        T::try_from(v).unwrap_or_default()
    }
    fn string(&mut self) -> String {
        let n = self.below(6);
        (0..n)
            .map(|_| ['a', 'é', '✓', '\0', 'Z', '𝄞'][self.below(6) as usize])
            .collect()
    }
    fn bytes(&mut self) -> Vec<u8> {
        let n = self.below(6);
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn float(&mut self) -> f64 {
        match self.below(5) {
            0 => 0.0,
            1 => -0.0,
            2 => f64::INFINITY,
            3 => (self.next() as i64) as f64 / 7.0,
            _ => 1.5,
        }
    }
    fn color(&mut self) -> Color {
        Color([0, 1, 2, -1, 77][self.below(5) as usize])
    }
}

fn nested(r: &mut Rng, depth: u32) -> all_types::Nested {
    all_types::Nested {
        a: r.int(),
        child: (depth > 0 && r.chance(30)).then(|| Box::new(nested(r, depth - 1))),
        r#type: r.string(),
        deep: all_types::nested::inner::Deep(r.int::<i32>() % 3),
        ..Default::default()
    }
}

fn value(r: &mut Rng, depth: u32) -> well_known::Value {
    use well_known::value::Kind;
    let kind = match r.below(if depth > 0 { 7 } else { 5 }) {
        0 => None,
        1 => Some(Kind::NullValue(well_known::NullValue::NULL_VALUE)),
        2 => Some(Kind::NumberValue(r.float())),
        3 => Some(Kind::StringValue(r.string())),
        4 => Some(Kind::BoolValue(r.chance(50))),
        5 => Some(Kind::StructValue(well_known::Struct {
            fields: (0..r.below(3))
                .map(|_| (r.string(), value(r, depth - 1)))
                .collect(),
        })),
        _ => Some(Kind::ListValue(well_known::ListValue {
            values: (0..r.below(3)).map(|_| value(r, depth - 1)).collect(),
        })),
    };
    well_known::Value { kind }
}

fn random(r: &mut Rng, depth: u32, maps: bool) -> AllTypes {
    let mut m = AllTypes {
        f_int32: r.int(),
        f_int64: r.int(),
        f_uint32: r.int(),
        f_uint64: r.int(),
        f_sint32: r.int(),
        f_sint64: r.int(),
        f_fixed32: r.int(),
        f_fixed64: r.int(),
        f_sfixed32: r.int(),
        f_sfixed64: r.int(),
        // No -0.0 in singular floats: we write it (as C++ does, see the golden tests), prost skips it.
        f_float: r.float() as f32 + 0.0,
        f_double: r.float() + 0.0,
        f_bool: r.chance(50),
        f_string: r.string(),
        f_bytes: r.bytes(),
        f_enum: r.color(),
        ..Default::default()
    };
    if r.chance(50) {
        m.f_nested = Some(nested(r, 2));
    }
    if r.chance(30) {
        m.f_shared = Some(Shared {
            id: r.string(),
            values: (0..r.below(4)).map(|_| r.int()).collect(),
            ..Default::default()
        });
    }
    if r.chance(50) {
        m.o_int32 = Some(r.int());
    }
    if r.chance(50) {
        m.o_string = Some(r.string());
    }
    if r.chance(50) {
        m.o_enum = Some(r.color());
    }
    if r.chance(30) {
        m.o_nested = Some(nested(r, 1));
    }
    let n = |r: &mut Rng| r.below(5);
    m.r_int32 = (0..n(r)).map(|_| r.int()).collect();
    m.r_sint64 = (0..n(r)).map(|_| r.int()).collect();
    m.r_fixed32 = (0..n(r)).map(|_| r.int()).collect();
    m.r_double = (0..n(r)).map(|_| r.float()).collect();
    m.r_bool = (0..n(r)).map(|_| r.chance(50)).collect();
    m.r_enum = (0..n(r)).map(|_| r.color()).collect();
    m.r_int32_unpacked = (0..n(r)).map(|_| r.int()).collect();
    m.r_string = (0..n(r)).map(|_| r.string()).collect();
    m.r_bytes = (0..n(r)).map(|_| r.bytes()).collect();
    m.r_nested = (0..n(r)).map(|_| nested(r, 1)).collect();
    m.r_uint64 = (0..n(r)).map(|_| r.int()).collect();
    if maps {
        m.m_string_int32 = (0..n(r)).map(|_| (r.string(), r.int())).collect();
        m.m_int64_string = (0..n(r)).map(|_| (r.int(), r.string())).collect();
        m.m_bool_nested = (0..n(r)).map(|_| (r.chance(50), nested(r, 1))).collect();
        m.m_uint32_enum = (0..n(r)).map(|_| (r.int(), r.color())).collect();
        m.m_sint32_bytes = (0..n(r)).map(|_| (r.int(), r.bytes())).collect();
        m.m_fixed64_double = (0..n(r)).map(|_| (r.int(), r.float())).collect();
    }
    m.choice = match r.below(7) {
        0 => Some(all_types::Choice::CUint32(r.int())),
        1 => Some(all_types::Choice::CString(r.string())),
        2 => Some(all_types::Choice::CNested(nested(r, 1))),
        3 => Some(all_types::Choice::CBytes(r.bytes())),
        4 => Some(all_types::Choice::CEnum(r.color())),
        5 if depth > 0 => Some(all_types::Choice::CSelf(Box::new(random(
            r,
            depth - 1,
            maps,
        )))),
        _ => None,
    };
    if depth > 0 && r.chance(30) {
        m.recursive = Some(Box::new(random(r, depth - 1, maps)));
    }
    if r.chance(30) {
        m.ts = Some(well_known::Timestamp {
            seconds: r.int(),
            nanos: r.int(),
        });
    }
    if r.chance(20) {
        m.any = Some(well_known::Any::pack(&nested(r, 0)));
    }
    // `Struct` is a map: prost skips default keys and values in map entries, C++ and we do not.
    if maps && r.chance(30) {
        m.st = Some(well_known::Struct {
            fields: (0..r.below(3)).map(|_| (r.string(), value(r, 2))).collect(),
        });
    }
    if r.chance(30) {
        m.wrapped = Some(well_known::Int32Value { value: r.int() });
    }
    m.max_field_number = r.int();
    m
}

#[test]
fn random_messages_agree_with_prost() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for i in 0..3000 {
        let maps = i % 2 == 0;
        let m = random(&mut r, 2, maps);
        let ours = m.encode_to_vec();
        assert_eq!(ours.len(), m.encoded_len());
        let p = mirror::to_prost(&m);
        let theirs = prost::Message::encode_to_vec(&p);
        if !maps {
            // Same field order (by number) and the same choices: the same bytes.
            assert_eq!(ours, theirs, "encodings differ for {m:?}");
        }
        mirror::differential(&ours);
        mirror::differential(&theirs);
        let back = AllTypes::decode(&theirs).unwrap();
        assert!(mirror::to_prost(&back) == p, "{back:?}");
    }
}

#[test]
fn mutated_encodings_are_accepted_or_rejected_alike() {
    let mut r = Rng(0x1234_5678_9abc_def1);
    // PROTOBUF_DIFF_ITERS=1000000 for a longer run.
    let n = std::env::var("PROTOBUF_DIFF_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    for _ in 0..n {
        let maps = r.chance(50);
        let m = random(&mut r, 1, maps);
        let mut b = m.encode_to_vec();
        for _ in 0..=r.below(3) {
            if b.is_empty() {
                break;
            }
            let at = r.below(b.len() as u64) as usize;
            match r.below(5) {
                0 => b[at] ^= 1 << r.below(8),
                1 => b.truncate(at),
                2 => b[at] = r.next() as u8,
                3 => b.insert(at, r.next() as u8),
                _ => {
                    let end = (at + 1 + r.below(8) as usize).min(b.len());
                    let seg = b[at..end].to_vec();
                    b.splice(at..at, seg);
                }
            }
        }
        mirror::differential(&b);
    }
}

#[test]
fn edge_inputs_agree_with_prost() {
    let cases: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0x08],
        &[0x08, 0x80],
        &[
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ],
        &[
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ],
        &[
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ],
        &[0x72, 0x01, 0xff],                         // invalid UTF-8 in f_string
        &[0x7a, 0x01, 0xff],                         // bytes are not checked
        &[0x0b, 0x0c], // an empty group as an unknown field 1? (field 1 is known)
        &[0xfb, 0x07, 0xfc, 0x07], // group at unknown field 127
        &[0xfb, 0x07, 0xfc, 0x0f], // mismatched end group
        &[0x0c],       // stray end group
        &[0x0d, 1, 2, 3, 4], // wrong wire type for field 1
        &[0xfa, 0x01, 0x02, 0x08, 0x01], // r_int32 packed
        &[0xfa, 0x01, 0x01, 0x80], // truncated packed varint
        &[0x80, 0x01, 0x05], // f_enum unknown value 5 (field 16)
        &[0x92, 0x03, 0x00], // empty map entry
        &[0x92, 0x03, 0x02, 0x10, 0x05], // map entry without key
        &[0x92, 0x03, 0x03, 0x08, 0x01, 0x00], // map entry with an invalid tag
        &[0xf8, 0xff, 0xff, 0xff, 0x0f, 0x01], // max field number
        &[0x88, 0x01, 0x00, 0x88, 0x01, 0x01], // f_nested? no: field 17 as varint (mismatch)
        &[0xe0, 0x03, 0x01, 0xea, 0x03, 0x01, b'x'], // two oneof members: last wins
    ];
    for c in cases {
        mirror::differential(c);
    }
    // Recursion: both stop at 100 levels.
    for depth in [99usize, 100, 101, 150] {
        let mut b = Vec::new();
        for _ in 0..depth {
            // field 70 (recursive), length-delimited, wrapping what follows
            let mut outer = vec![0xb2, 0x04];
            only_protobuf::encoding::put_varint(&mut outer, b.len() as u64);
            outer.extend_from_slice(&b);
            b = outer;
        }
        mirror::differential(&b);
    }
}
