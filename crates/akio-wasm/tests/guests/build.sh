#!/bin/sh
# Rebuilds the guests tests/guests.rs runs, fit's test plugins, from a fit checkout:
#
#   crates/akio-wasm/tests/guests/build.sh <fit checkout>
#
# Needs Go (1.27 built the committed ones), TinyGo (0.44) and Rust with the wasm32-wasip1 target
# (rustup target add wasm32-wasip1); a guest whose toolchain is missing is left as it is. The
# output is gzipped (tests/guests.rs inflates it with akio-deflate) and replaces the files here.
# Run it by hand when fit's guests or the toolchains move, then run the tests, and commit.
set -eu

fit=$(cd "$1" && pwd)
out=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$fit/plugin/wasm"
echo "fit $(git -C "$fit" rev-parse --short HEAD)"

if command -v go >/dev/null; then
    echo "$(go version)"
    # fit's own ABI (module fit), Go's reactor build.
    GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 \
        go build -trimpath -buildmode=c-shared -o "$tmp/headers-go.wasm" ./testdata/headers
    # A Proxy-Wasm filter, the Proxy-Wasm Go SDK's example (its own Go module).
    (cd testdata/proxywasm && GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 \
        go build -trimpath -buildmode=c-shared -o "$tmp/http_routing-go.wasm" ./http_routing)
else
    echo "no go: the Go guests are left as they are"
fi

if command -v tinygo >/dev/null; then
    echo "$(tinygo version)"
    # fit's sync plugin, the same source as Go's, by TinyGo.
    tinygo build -target=wasip1 -buildmode=c-shared -scheduler=none \
        -o "$tmp/sync-tinygo.wasm" ./testdata/sync
else
    echo "no tinygo: the TinyGo guest is left as it is"
fi

if command -v cargo >/dev/null &&
    [ -d "$(rustc --print sysroot)/lib/rustlib/wasm32-wasip1" ]; then
    echo "$(rustc --version)"
    # fit's sync plugin in Rust, on the fit-guest crate.
    CARGO_TARGET_DIR="$tmp/rust" cargo build --release --quiet --target wasm32-wasip1 \
        --manifest-path testdata/rust/Cargo.toml
    cp "$tmp/rust/wasm32-wasip1/release/fit_sync_test.wasm" "$tmp/sync-rust.wasm"
else
    echo "no rust wasm32-wasip1 target: the Rust guest is left as it is"
fi

for f in "$tmp"/*.wasm; do
    [ -e "$f" ] || continue
    name=$(basename "$f")
    gzip -9 -n -c "$f" >"$out/$name.gz"
    echo "$name: $(wc -c <"$f" | tr -d ' ') bytes, $(wc -c <"$out/$name.gz" | tr -d ' ') gzipped"
done
