#!/usr/bin/env bash
# Builds the whole documentation site, as published on GitHub Pages, into one directory:
#
#   <out>/index.html      language picker (redirects by browser language)
#   <out>/404.html        site-wide "not found" page (the English book's 404; Chinese paths
#                         are sent on to zh-CN/404.html)
#   <out>/en/  <out>/zh-CN/   the two books, each with a language switch and an API link
#   <out>/api/            rustdoc of every published crate (api/only/index.html, ...)
#
#   book/site.sh                     # base /only/ (lesismal.github.io/only), out target/site
#   book/site.sh --base / --out DIR  # served at the root of a host instead
#   book/site.sh --no-check          # skip check-includes and building the examples
#   book/site.sh --no-api            # skip rustdoc (faster when working on the books)
#
# Then check every link, served over HTTP under the same base, in both languages:
#
#   python3 book/check-site.py target/site --base /only/
#   python3 book/check-site.py target/site --base /only/ --serve 8000   # browse it
#
# Needs mdBook 0.4.x (`cargo install mdbook --locked --version 0.4.52`) and python3. Used by
# .github/workflows/pages.yml, so what you check locally is what gets deployed.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

base=/only/
out="$root/target/site"
check=1
api=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) base="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --no-check) check=0; shift ;;
    --no-api) api=0; shift ;;
    *) echo "usage: book/site.sh [--base /only/] [--out DIR] [--no-check] [--no-api]" >&2; exit 2 ;;
  esac
done
[[ "$base" == /* && "$base" == */ ]] || { echo "--base must start and end with /" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"

if [[ $check == 1 ]]; then
  python3 book/check-includes.py
  cargo build --workspace --examples --quiet
fi

rm -rf "$out"/{en,zh-CN,api,index.html,404.html,.nojekyll}
for lang in en zh-CN; do
  # site-url is where the book lives; mdBook uses it for <base> in 404.html.
  MDBOOK_OUTPUT__HTML__SITE_URL="${base}${lang}/" mdbook build "book/$lang" -d "$out/$lang"
done
cp book/index.html "$out/index.html"
cp "$out/en/404.html" "$out/404.html"

if [[ $api == 1 ]]; then
  # Published crates only: tools with `publish = false` are left out.
  excludes=$(cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p["publish"] == []:
        print("--exclude", p["name"])')
  doc="${CARGO_TARGET_DIR:-$root/target}/doc"
  rm -rf "$doc" # no pages left over from crates that are excluded or gone
  # shellcheck disable=SC2086
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features $excludes
  rm -rf "$out/api"
  cp -R "$doc" "$out/api"
  cat >"$out/api/index.html" <<'EOF'
<!doctype html>
<meta charset="utf-8">
<title>only API documentation</title>
<meta http-equiv="refresh" content="0; url=only/index.html">
<p><a href="only/index.html">only API documentation</a></p>
EOF
fi
touch "$out/.nojekyll"
echo "site in $out (base $base)"
