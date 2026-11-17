#!/usr/bin/env bash
# Runs the protobuf conformance suite (binary and JSON) against only-protobuf's testee
# (`tools/protobuf-test/examples/conformance-testee.rs`), in Docker.
#   docker build -t only-protobuf-conformance tools/protobuf-test/conformance   # once
#   tools/protobuf-test/conformance/run.sh [runner options, e.g. --test <name>]
# Exits non-zero when a test outside `failure_list.txt` fails (or a listed one passes).
set -eu
repo=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm \
    -v "$repo":/w -w /w \
    -v only-pb-conformance-cargo:/usr/local/cargo/registry \
    -v only-pb-conformance-target:/target \
    -e CARGO_TARGET_DIR=/target -e ONLY_CONFORMANCE_STATS=/target/conformance-stats.txt \
    only-protobuf-conformance bash -c '
        rm -f /target/conformance-stats.txt.* &&
        cargo build -q --release -p protobuf-test --example conformance-testee &&
        conformance_test_runner --enforce_recommended --maximum_edition 2024 \
            --failure_list tools/protobuf-test/conformance/failure_list.txt \
            --text_format_failure_list tools/protobuf-test/conformance/failure_list.txt \
            '"$*"' /target/release/examples/conformance-testee &&
        echo "testee requests by category:" && cat /target/conformance-stats.txt.*'
