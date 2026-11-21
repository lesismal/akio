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
            "proto/ext.proto",
            "proto/ed2024.proto",
        ],
        &out,
    )
    .expect("generate");
    // ANCHOR_END: build
    // `utf8_validation = NONE`; proto2 strings as `ProtoString` too (their legacy NONE).
    only_protobuf_build::Config::new()
        .proto2_unchecked_strings(true)
        .compile(
            &[
                "proto/utf8.proto",
                "proto/utf8_file.proto",
                "proto/utf8_proto2.proto",
            ],
            &out,
        )
        .expect("generate utf8");
    // The conformance suite's messages (`conformance/proto`, from the protobuf repository).
    only_protobuf_build::Config::new()
        .include("conformance/proto")
        .compile(
            &[
                "conformance/proto/conformance/conformance.proto",
                "conformance/proto/google/protobuf/test_messages_proto2.proto",
                "conformance/proto/google/protobuf/test_messages_proto3.proto",
                "conformance/proto/conformance/test_protos/test_messages_edition2023.proto",
                "conformance/proto/editions/golden/test_messages_proto2_editions.proto",
                "conformance/proto/editions/golden/test_messages_proto3_editions.proto",
            ],
            &out,
        )
        .expect("generate conformance");
    only_protobuf_build::Config::new()
        .btree_maps(true)
        .unknown_fields(false)
        .compile(&["proto/btree.proto"], &out)
        .expect("generate btree");
}
