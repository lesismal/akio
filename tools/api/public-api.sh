#!/usr/bin/env bash
# Public API snapshots (docs/api-stability.md).
#
#   tools/api/public-api.sh          # check: diff every crate's API against api/<crate>.txt
#   tools/api/public-api.sh --bless  # regenerate api/<crate>.txt after a deliberate change
#   tools/api/public-api.sh flash-core flash   # only these crates
#
# Needs a nightly toolchain (rustdoc JSON) and cargo-public-api. CI pins both (ci.yml, job
# `public-api`). Run it on Linux x86_64/aarch64 (the snapshots are taken there): flash-uring and
# parts of flash-ebpf / flash-sys only exist on Linux.
#
# Items under `#[doc(hidden)]`, the `fuzzing` and `unstable` features and the `prost` feature of
# flash-grpc are not in the snapshots: they are outside the stability promise.
# Blanket impls are omitted to keep the files readable; auto-trait impls (Send / Sync / Unpin / UnwindSafe ...) stay, because losing one is a breaking change.
set -euo pipefail
cd "$(dirname "$0")/../.."

bless=0
if [ "${1:-}" = "--bless" ]; then
    bless=1
    shift
fi

# Publishable library crates (tools/ and fuzz/ are not published).
all=(flash-sys flash-buf flash-timer flash-pool flash-core flash-epoll flash-uring flash-tls
    flash-http flash-ws flash-mux flash-socks flash-arpc flash-grpc flash-kcp flash-quic flash-h3
    flash-ebpf flash-prefork flash-dpdk flash-turn flash-webrtc flash-media flash-bittorrent flash)
if [ "$#" -gt 0 ]; then
    crates=("$@")
else
    crates=("${all[@]}")
fi

# Every covered (non-`fuzzing`, non-`unstable`) feature of a crate beyond the defaults (none today;
# `prost` is outside the promise, docs/api-stability.md).
features_for() {
    case "$1" in
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
