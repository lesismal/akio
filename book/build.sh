#!/usr/bin/env bash
# Builds the English and Chinese books into target/book/{en,zh-CN} with a language picker at
# target/book/index.html, after checking that every snippet the books include exists and
# compiles.
#
#   book/build.sh            # check includes + compile examples + build both books
#   book/build.sh --no-check # build only
#
# Needs mdBook 0.4.x (`cargo install mdbook --locked --version 0.4.52`) and python3.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ "${1:-}" != "--no-check" ]]; then
  # Every Rust snippet in the books is {{#include}}d from an example program.
  python3 book/check-includes.py
  cargo build --workspace --examples --quiet
fi

for lang in en zh-CN; do
  mdbook build "book/$lang"
done
cp book/index.html target/book/index.html
echo "books in target/book/ (open target/book/index.html?stay)"
