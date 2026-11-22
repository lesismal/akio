#!/usr/bin/env bash
# Builds the corpus of `codec-bench brotli|zstd` in DIR (default target/codec-corpus):
# typical HTTP payloads made from this repository (the workspace's `cargo metadata` JSON, the
# largest rustdoc HTML page and the search JavaScript of akio-http's documentation, two DER
# certificate chains) and, with SILESIA=1, the Silesia corpus as one tar (downloaded once from
# its home page).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
dir=${1:-$root/target/codec-corpus}
mkdir -p "$dir"
cd "$root"
cargo metadata --format-version 1 > "$dir/metadata.json"
doc=$dir/doc-target
CARGO_TARGET_DIR=$doc cargo doc -p akio-http --no-deps -q
cp "$(ls -S "$doc"/doc/akio_http/*.html | head -1)" "$dir/page.html"
cp "$(ls -S "$doc"/doc/static.files/search-*.js | head -1)" "$dir/search.js"
rm -rf "$doc"
cp crates/akio-brotli/tests/data/github.com.chain.der crates/akio-brotli/tests/data/www.wikipedia.org.chain.der "$dir/"
if [ "${SILESIA:-0}" = 1 ] && [ ! -f "$dir/silesia.tar" ]; then
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/silesia.zip" https://sun.aei.polsl.pl/~sdeor/corpus/silesia.zip
  mkdir "$tmp/s" && (cd "$tmp/s" && unzip -q ../silesia.zip)
  tar -C "$tmp/s" -cf "$dir/silesia.tar" .
  rm -rf "$tmp"
fi
ls -l "$dir"
