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
    case "$type" in test.p2.*) file=proto2.proto ;; esac
    protoc -I ../proto --encode="$type" "$file" <"$t" >"${t%.txtpb}.bin"
done
protoc --version
