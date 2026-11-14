//! Generates the test messages with only-protobuf-build.

fn main() {
    // ANCHOR: build
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    only_protobuf_build::compile(
        &[
            "proto/all_types.proto",
            "proto/proto2.proto",
            "proto/route_guide.proto",
            "proto/helloworld.proto",
        ],
        &out,
    )
    .expect("generate");
    // ANCHOR_END: build
    only_protobuf_build::Config::new()
        .btree_maps(true)
        .unknown_fields(false)
        .compile(&["proto/btree.proto"], &out)
        .expect("generate btree");
}
