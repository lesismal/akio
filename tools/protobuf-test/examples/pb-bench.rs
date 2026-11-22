//! Encode / decode time of akio-protobuf against prost 0.13 for a few message shapes.
//!
//! `cargo run --release -p protobuf-test --example pb-bench`

#[path = "../prost_mirror.rs"]
mod mirror;

use std::{hint::black_box, time::Instant};

use akio_protobuf::Message;
use protobuf_test::{
    routeguide::{Feature, Point},
    test::all::{AllTypes, Color, all_types},
};

#[derive(Clone, PartialEq, prost::Message)]
struct PPoint {
    #[prost(int32, tag = "1")]
    latitude: i32,
    #[prost(int32, tag = "2")]
    longitude: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PFeature {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    location: Option<PPoint>,
}

/// ns per call of `f`, best of 5 runs of ~100 ms.
fn time(mut f: impl FnMut()) -> f64 {
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        if t.elapsed().as_millis() >= 100 {
            break;
        }
        n *= 2;
    }
    (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_nanos() as f64 / n as f64
        })
        .fold(f64::MAX, f64::min)
}

fn row<O: Message, P: prost::Message + Default>(name: &str, ours: &O, theirs: &P) {
    let ob = ours.encode_to_vec();
    let pb = theirs.encode_to_vec();
    let mut buf = Vec::with_capacity(ob.len().max(pb.len()) * 2);
    let enc_o = time(|| {
        buf.clear();
        black_box(ours).encode(&mut buf);
        black_box(&buf);
    });
    let enc_p = time(|| {
        buf.clear();
        black_box(theirs).encode(&mut buf).unwrap();
        black_box(&buf);
    });
    let dec_o = time(|| {
        black_box(O::decode(black_box(&ob)).unwrap());
    });
    let dec_p = time(|| {
        black_box(P::decode(black_box(pb.as_slice())).unwrap());
    });
    println!(
        "| {name} | {} B | {enc_o:.0} | {enc_p:.0} | {dec_o:.0} | {dec_p:.0} |",
        ob.len()
    );
}

fn main() {
    println!(
        "| message | size | encode ns (akio) | encode ns (prost) | decode ns (akio) | decode ns (prost) |"
    );
    println!("|---|---|---|---|---|---|");
    let p = Point {
        latitude: 409_146_138,
        longitude: -746_188_906,
        ..Default::default()
    };
    row(
        "Point (2 varints)",
        &p,
        &PPoint {
            latitude: p.latitude,
            longitude: p.longitude,
        },
    );
    let f = Feature {
        name: "Berkshire Valley Management Area Trail, Jefferson, NJ, USA".into(),
        location: Some(p.clone()),
        ..Default::default()
    };
    row(
        "Feature (string + message)",
        &f,
        &PFeature {
            name: f.name.clone(),
            location: Some(PPoint {
                latitude: p.latitude,
                longitude: p.longitude,
            }),
        },
    );
    let nested = |a| all_types::Nested {
        a,
        r#type: "nested".into(),
        ..Default::default()
    };
    let all = AllTypes {
        f_int32: -42,
        f_int64: 1 << 40,
        f_uint32: 7,
        f_uint64: u64::MAX,
        f_sint32: -3,
        f_sint64: -(1 << 50),
        f_fixed32: 1,
        f_fixed64: 2,
        f_sfixed32: -1,
        f_sfixed64: -2,
        f_float: 1.5,
        f_double: 2.5,
        f_bool: true,
        f_string: "hello world".into(),
        f_bytes: vec![1; 64],
        f_enum: Color::GREEN,
        f_nested: Some(nested(1)),
        r_int32: (0..32).collect(),
        r_double: (0..16).map(f64::from).collect(),
        r_string: (0..8).map(|i| format!("item {i}")).collect(),
        r_nested: (0..8).map(nested).collect(),
        m_string_int32: (0..8).map(|i| (format!("k{i}"), i)).collect(),
        choice: Some(all_types::Choice::CString("oneof".into())),
        ..Default::default()
    };
    row(
        "AllTypes (scalars, repeated, maps, nested)",
        &all,
        &mirror::to_prost(&all),
    );
}
