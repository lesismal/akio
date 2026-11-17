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
