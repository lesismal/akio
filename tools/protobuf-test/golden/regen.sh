#!/usr/bin/env bash
# Regenerates the golden encodings with protoc (the C++ reference implementation): each
# `<case>.txtpb` (text format; its first line names the message type) becomes `<case>.bin`.
#   tools/protobuf-test/golden/regen.sh
# Without a local protoc, in Docker:
#   docker run --rm -v "$PWD":/w -w /w debian:stable bash -c \
#     'apt-get update -qq && apt-get install -y -qq protobuf-compiler >/dev/null && tools/protobuf-test/golden/regen.sh'
set -eu
cd "$(dirname "$0")"
for t in *.txtpb; do
    type=$(head -1 "$t" | sed 's/^# //')
    file=all_types.proto
    case "$type" in
    test.p2.*) file=proto2.proto ;;
    protobuf_test_messages.proto2.*) file=google/protobuf/test_messages_proto2.proto ;;
    protobuf_test_messages.editions.proto2.*) file=editions/golden/test_messages_proto2_editions.proto ;;
    protobuf_test_messages.editions.*) file=conformance/test_protos/test_messages_edition2023.proto ;;
    esac
    protoc -I ../proto -I ../conformance/proto --encode="$type" "$file" <"$t" >"${t%.txtpb}.bin"
done
protoc --version
# Descriptor sets (with imports, without source info) for tests/descriptors.rs.
for p in proto/all_types.proto proto/proto2.proto proto/route_guide.proto proto/options.proto \
    conformance/proto/conformance/conformance.proto \
    conformance/proto/google/protobuf/test_messages_proto2.proto \
    conformance/proto/google/protobuf/test_messages_proto3.proto \
    conformance/proto/conformance/test_protos/test_messages_edition2023.proto \
    conformance/proto/editions/golden/test_messages_proto2_editions.proto \
    conformance/proto/editions/golden/test_messages_proto3_editions.proto; do
    rel=${p#proto/}
    rel=${rel#conformance/proto/}
    base=$(basename "$p" .proto)
    protoc -I ../proto -I ../conformance/proto --include_imports \
        --descriptor_set_out="descriptors/$base.pb" "$rel"
done
