#!/usr/bin/env bash
# only-brotli's RFC 9841 shared dictionaries against Google's libbrotli (built with
# BROTLI_EXPERIMENTAL at $BROTLI_REV), both ways:
#  1. random dictionaries (custom word lists, transforms with every operation, context maps,
#     fallback across dictionaries, prefixes) with hand-made streams of dictionary references,
#     decoded by both: the same output, or both refuse ($CASES of them);
#  2. libbrotli's encoder with four dictionaries (a prefix; custom words; custom words and
#     transforms; two word lists and brotli's own by context) on alice29.txt at q1/5/9/11,
#     decoded by only-brotli; only-brotli's output with each at levels 9 (prefix use) and 11
#     (custom words too) decoded by libbrotli;
#  3. large-window streams: Google's brotli CLI (built from the same revision) decodes
#     only-brotli's (levels 0..=11, one-shot and streamed, distances past 64 MiB) and only-brotli
#     decodes the CLI's (`cargo test --test large_window -- --include-ignored`).
# UPDATE=1 also rewrites crates/only-brotli/tests/data/shared (libbrotli's q11 output for the
# first 20,000 bytes of alice29.txt with each dictionary; `cargo test -p only-brotli --test
# shared` decodes them).
# Needs git, a C compiler (CC, default cc) and cargo. In Docker:
#   docker run --rm -v "$PWD":/src -w /src rust:1 tools/interop/brotli-shared/run.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BROTLI_REV=${BROTLI_REV:-fed075f48eaffa447243a8e0452a88b103506118}
CASES=${CASES:-20000}
W=${WORK:-$(mktemp -d)}
if [ ! -d "$W/brotli" ]; then
  git clone -q https://github.com/google/brotli.git "$W/brotli"
fi
(cd "$W/brotli" && git checkout -q "$BROTLI_REV")
B="$W/brotli/c"
${CC:-cc} -O2 -DBROTLI_EXPERIMENTAL -I"$B/include" -I"$B" -o "$W/sdtool" \
  "$ROOT/tools/interop/brotli-shared/sdtool.c" "$B"/common/*.c "$B"/dec/*.c "$B"/enc/*.c -lm
EX="cargo run -q --release --manifest-path $ROOT/Cargo.toml -p only-brotli --features fuzzing --example shared-dict-interop --"

echo "== 1. reference streams, only-brotli and libbrotli decoders"
$EX gen-cases "$W/cases.bin" "$CASES"
"$W/sdtool" cases "$W/cases.bin" "$W/results.bin"
$EX check-cases "$W/cases.bin" "$W/results.bin"

echo "== 2. libbrotli's encoder -> only-brotli; only-brotli's encoder -> libbrotli"
D="$W/dir"
mkdir -p "$D"
$EX dicts "$D"
for q in 1 5 9 11; do
  "$W/sdtool" c - "$q" "$D/input" "$D/plain.q$q.br"
  for d in "$D"/*.dict; do
    n=$(basename "$d" .dict)
    "$W/sdtool" c "$d" "$q" "$D/input" "$D/$n.q$q.br"
  done
done
$EX check-dir "$D"
for d in "$D"/*.dict; do
  n=$(basename "$d" .dict)
  for q in 9 11; do
    "$W/sdtool" d "$d" "$D/$n.ours$q.br" "$D/$n.ours$q.out"
    cmp "$D/input" "$D/$n.ours$q.out"
    echo "$n: libbrotli decodes ours at level $q ($(wc -c < "$D/$n.ours$q.br") bytes)"
  done
done

echo "== 3. large-window brotli (RFC 9841 section 6) against Google's brotli CLI, both ways"
mkdir -p "$W/bin"
${CC:-cc} -O2 -I"$B/include" -I"$B" -o "$W/bin/brotli" "$B/tools/brotli.c" \
  "$B"/common/*.c "$B"/dec/*.c "$B"/enc/*.c -lm
PATH="$W/bin:$PATH" cargo test -q --release --manifest-path "$ROOT/Cargo.toml" -p only-brotli \
  --test large_window -- --include-ignored
if [ "${UPDATE:-0}" = 1 ]; then
  V="$ROOT/crates/only-brotli/tests/data/shared"
  mkdir -p "$V"
  head -c 20000 "$D/input" > "$D/small"
  for d in "$D"/*.dict; do
    n=$(basename "$d" .dict)
    cp "$d" "$V/$n.dict"
    "$W/sdtool" c "$d" 11 "$D/small" "$V/$n.br"
  done
  echo "updated $V"
fi
