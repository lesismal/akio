#!/usr/bin/env bash
# Public API snapshots (docs/api-stability.md).
#
#   tools/api/public-api.sh          # check: diff every crate's API against api/<crate>.txt
#   tools/api/public-api.sh --bless  # regenerate api/<crate>.txt after a deliberate change
#   tools/api/public-api.sh only-core only   # only these crates
#
# Needs a nightly toolchain (rustdoc JSON) and cargo-public-api. CI pins both (ci.yml, job
# `public-api`). Run it on Linux x86_64/aarch64 (the snapshots are taken there): only-uring and
# parts of only-ebpf / only-sys only exist on Linux.
#
# Items under `#[doc(hidden)]`, the `fuzzing` and `unstable` features and the `prost` feature of
# only-grpc are not in the snapshots: they are outside the stability promise.
# Blanket impls are omitted to keep the files readable; auto-trait impls (Send / Sync / Unpin / UnwindSafe ...) stay, because losing one is a breaking change.
set -euo pipefail
cd "$(dirname "$0")/../.."

bless=0
if [ "${1:-}" = "--bless" ]; then
    bless=1
    shift
fi

# Publishable library crates (tools/ and fuzz/ are not published).
all=(only-sys only-log only-crypto only-x509 only-dtls only-srtp only-rtp only-sctp only-ice only-buf only-deflate only-brotli only-zstd only-timer only-pool only-core only-epoll only-uring only-tls
    only-http only-ws only-mux only-socks only-arpc only-grpc only-protobuf only-protobuf-build
    only-kcp only-quic only-h3
    only-ebpf only-prefork only-dpdk only-turn only-webrtc only-media only-bittorrent only-export only)
if [ "$#" -gt 0 ]; then
    crates=("$@")
else
    crates=("${all[@]}")
fi

# Every covered (non-`fuzzing`, non-`unstable`) feature of a crate beyond the defaults (`prost`
# is outside the promise, docs/api-stability.md).
features_for() {
    case "$1" in
    only-media) echo "--features webrtc" ;;
    *) echo "" ;;
    esac
}

mkdir -p api
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0
for c in "${crates[@]}"; do
    out="$tmp/$c.txt"
    # shellcheck disable=SC2046
    if ! cargo public-api --package "$c" $(features_for "$c") --omit blanket-impls \
        >"$out.raw" 2>"$tmp/$c.err"; then
        echo "public-api: could not build the API of $c" >&2
        cat "$tmp/$c.err" >&2
        exit 1
    fi
    # Nightly-only marker traits (Freeze, and the experimental Forget / Move / UnsafeUnpin) are
    # not part of the stable API and churn between nightlies.
    grep -vE '^impl.* !?core::marker::(Freeze|Forget|Move|UnsafeUnpin) for ' "$out.raw" >"$out" || true
    if [ "$bless" = 1 ]; then
        cp "$out" "api/$c.txt"
    elif ! diff -u "api/$c.txt" "$out" >"$tmp/$c.diff"; then
        echo "::error::public API of $c differs from api/$c.txt"
        cat "$tmp/$c.diff"
        fail=1
    fi
done
if [ "$fail" = 1 ]; then
    cat <<'MSG'

The public API changed. If that is intended: run `tools/api/public-api.sh --bless`, commit
api/*.txt and add a CHANGELOG.md entry. After 1.0.0, removing or changing an item needs a new
major version; deprecate first (docs/api-stability.md, docs/deprecation.md).
MSG
    exit 1
fi
if [ "$bless" = 1 ]; then
    echo "api/*.txt regenerated"
else
    echo "public API matches api/*.txt"
fi
