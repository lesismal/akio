#!/usr/bin/env bash
# Converts the WebAssembly specification tests (`.wast`) into JSON commands and binary modules
# for akio-wasm's `tests/spec.rs` (ADR-125, section 6). Run by hand when the pinned test-suite
# commit moves; the output is committed, so running the tests needs no tool.
#
#   tools/wasm-spec/convert.sh <testsuite checkout> [commit]
#
# Needs `wasm-tools` (`cargo install wasm-tools`) on PATH. The checkout is
# https://github.com/WebAssembly/testsuite; COMMIT below is the pinned commit, the last one whose
# top level is WebAssembly 2.0 (the specification's 3.0 draft became the top level after it).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
COMMIT=${2:-a8101597d3c3c660086c3cd1eedee608ff18d3c3}
src=$(cd "$1" && pwd)
out=$(cd "$(dirname "$0")/../.." && pwd)/crates/akio-wasm/tests/spec
git -C "$src" checkout -q "$COMMIT"
rm -rf "$out"
mkdir -p "$out"
convert() { # <group> <wast file> [refused]
    local name
    name=$(basename "$2" .wast)
    mkdir -p "$out/$1/$name"
    (cd "$out/$1/$name" && wasm-tools json-from-wast "$2" -o "../$name.json" --wasm-dir . >/dev/null)
    # Text modules of `assert_malformed` are not run (binary modules only, ADR-125 section 7).
    rm -f "$out/$1/$name"/*.wat
    python3 -I "$here/trim.py" "$out/$1/$name.json" "${3:-}"
}
# WebAssembly 2.0: the core suite (its SIMD files are refused features).
for f in "$src"/*.wast; do
    case $(basename "$f") in
    simd_*) convert core "$f" refused ;;
    *) convert core "$f" ;;
    esac
done
# Proposals whose features akio-wasm refuses: every module must be refused, none may crash.
for p in threads relaxed-simd custom-page-sizes wide-arithmetic; do
    for f in "$src/proposals/$p"/*.wast; do convert "$p" "$f" refused; done
done
# The 3.0 draft's files for refused features (its other files re-test 2.0 under 3.0's rules).
for f in "$src"/proposals/wasm-3.0/{memory64,address64,align64,load64,store64,table64,memory-multi,return_call,return_call_indirect,return_call_ref,try_table,throw,throw_ref,tag,struct,array,i31,call_ref,ref_as_non_null,br_on_null,br_on_non_null,type-rec,type-subtyping,binary-gc,ref_eq}.wast; do
    [ -f "$f" ] && convert wasm-3.0 "$f" refused
done
cp "$src/LICENSE" "$out/LICENSE"
git -C "$src" rev-parse HEAD >"$out/COMMIT"
du -sh "$out"
