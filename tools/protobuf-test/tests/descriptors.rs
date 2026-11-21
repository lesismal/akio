//! Descriptors: the `FileDescriptorSet` only-protobuf-build writes must equal protoc's
//! (`protoc --include_imports --descriptor_set_out`, `golden/descriptors/*.pb`, made by
//! `golden/regen.sh`) for the test and conformance files, file by file.

use std::path::{Path, PathBuf};

use only_protobuf::{Message, well_known::FileDescriptorSet};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Compiles `protos` with only-protobuf-build and returns its descriptor set.
fn ours(protos: &[&str]) -> FileDescriptorSet {
    let tmp = std::env::temp_dir().join(format!(
        "only-pb-desc-{}-{}",
        std::process::id(),
        protos[0].replace('/', "_")
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let set = tmp.join("set.pb");
    let paths: Vec<PathBuf> = protos.iter().map(|p| dir().join(p)).collect();
    only_protobuf_build::Config::new()
        .include(dir().join("proto"))
        .include(dir().join("conformance/proto"))
        .file_descriptor_set_path(&set)
        .compile(&paths, &tmp)
        .unwrap();
    let b = std::fs::read(&set).unwrap();
    if let Some(d) = std::env::var_os("ONLY_PB_DESC_DUMP") {
        std::fs::write(Path::new(&d).join(protos[0].replace('/', "_") + ".pb"), &b).unwrap();
    }
    std::fs::remove_dir_all(&tmp).ok();
    FileDescriptorSet::decode(&b).unwrap()
}

fn golden(name: &str) -> FileDescriptorSet {
    let p = dir().join("golden/descriptors").join(name);
    FileDescriptorSet::decode(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

fn compare(golden_name: &str, protos: &[&str]) {
    let got = ours(protos);
    let want = golden(golden_name);
    let mut names: Vec<_> = want.file.iter().map(|f| f.name.clone()).collect();
    names.sort();
    let mut have: Vec<_> = got.file.iter().map(|f| f.name.clone()).collect();
    have.sort();
    assert_eq!(have, names, "{golden_name}: files");
    for w in &want.file {
        let g = got.file.iter().find(|f| f.name == w.name).unwrap();
        // Messages first, one by one, for a readable failure.
        for (wm, gm) in w.message_type.iter().zip(&g.message_type) {
            assert_eq!(gm, wm, "{golden_name}: {:?}", w.name);
        }
        assert_eq!(g, w, "{golden_name}: {:?}", w.name);
    }
}

#[test]
fn test_files() {
    compare("all_types.pb", &["proto/all_types.proto"]);
    compare("proto2.pb", &["proto/proto2.proto"]);
    compare("route_guide.pb", &["proto/route_guide.proto"]);
    // Custom options, aggregates, option paths; descriptor.proto itself (edition defaults,
    // retention, targets) comes along as an import.
    compare("options.pb", &["proto/options.proto"]);
    compare("ext.pb", &["proto/ext.proto"]);
    compare("ed2024.pb", &["proto/ed2024.proto"]);
    // Features of a map field are copied to its entry's key and value, as protoc does.
    compare("utf8.pb", &["proto/utf8.proto"]);
    compare("utf8_file.pb", &["proto/utf8_file.proto"]);
    // Not `utf8_proto2.proto`: its string default is not UTF-8, which protoc writes as is and
    // only-protobuf's `FieldDescriptorProto` (a `String`) cannot hold; it is written lossily.
}

#[test]
fn conformance_files() {
    if std::env::var_os("ONLY_PB_DESC_DUMP").is_some() {
        for p in [
            "conformance/proto/conformance/conformance.proto",
            "conformance/proto/google/protobuf/test_messages_proto2.proto",
            "conformance/proto/google/protobuf/test_messages_proto3.proto",
            "conformance/proto/conformance/test_protos/test_messages_edition2023.proto",
            "conformance/proto/editions/golden/test_messages_proto2_editions.proto",
            "conformance/proto/editions/golden/test_messages_proto3_editions.proto",
        ] {
            ours(&[p]);
        }
    }
    compare(
        "conformance.pb",
        &["conformance/proto/conformance/conformance.proto"],
    );
    compare(
        "test_messages_proto2.pb",
        &["conformance/proto/google/protobuf/test_messages_proto2.proto"],
    );
    compare(
        "test_messages_proto3.pb",
        &["conformance/proto/google/protobuf/test_messages_proto3.proto"],
    );
    compare(
        "test_messages_edition2023.pb",
        &["conformance/proto/conformance/test_protos/test_messages_edition2023.proto"],
    );
    compare(
        "test_messages_proto2_editions.pb",
        &["conformance/proto/editions/golden/test_messages_proto2_editions.proto"],
    );
    compare(
        "test_messages_proto3_editions.pb",
        &["conformance/proto/editions/golden/test_messages_proto3_editions.proto"],
    );
}
