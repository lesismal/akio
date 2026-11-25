# The `akio` book: sources

English | [简体中文](README.zh-CN.md)

Two [mdBook](https://rust-lang.github.io/mdBook/) books with the same chapters:

```text
book/
├─ en/        book.toml + src/   English
├─ zh-CN/     book.toml + src/   Simplified Chinese (same file names, same includes)
├─ index.html                    language picker (site root)
├─ build.sh                      check + build both books into target/book
├─ check-includes.py             every {{#include}} target and anchor; en and zh-CN have the same sections
├─ site.sh                       the published site: both books + rustdoc into target/site
├─ check-site.py                 serves target/site and checks every link, both languages
└─ check-guides.sh               runs every example the books include
```

`en/lang-switch.js` and `zh-CN/lang-switch.js` (identical) add the language switch and the API
link to every page; `src/404.md` is each book's "page not found" page.

The architecture chapter includes `docs/architecture.md` / `docs/architecture.zh-CN.md`, so the
architecture document is maintained in one place and renders both on GitHub and in the book.

## Code snippets

Every Rust snippet is `{{#include}}`d from a runnable example program, never typed into the
Markdown: the `guide-*` examples in `crates/*/examples/` (plus `echo`, `hello`, `udp-echo`), using
`// ANCHOR: name` / `// ANCHOR_END: name` markers for fragments. `cargo build --workspace
--examples` therefore compiles every snippet, and running an example exercises it end to end. The
code blocks are marked `rust,ignore` because `mdbook test` cannot link the workspace crates; do
not use `mdbook test`. Snippets from other ecosystems (Go, tokio, axum) are comparisons and are
not compiled.

## Building

```console
$ cargo install mdbook --locked --version 0.4.52
$ book/build.sh            # check includes, compile examples, build target/book/{en,zh-CN}
$ book/build.sh --no-check # only build
$ python3 -m http.server -d target/book 8000   # then open http://127.0.0.1:8000/
```

## The published site

```console
$ book/site.sh                                  # books + rustdoc into target/site, base /akio/
$ python3 book/check-site.py target/site        # link check over HTTP, exit 1 on any problem
$ python3 book/check-site.py target/site --serve 8000   # http://127.0.0.1:8000/akio/
```

`.github/workflows/pages.yml` runs exactly these two commands and deploys `target/site` to
GitHub Pages: on a published release or by hand (Actions -> Pages -> Run workflow), never on a
push. Layout: `/akio/` language picker, `/akio/en/`, `/akio/zh-CN/`, `/akio/api/` (rustdoc of the
published crates), `/akio/404.html`. Enabling Pages (Settings -> Pages -> Source: GitHub Actions)
is a one-time step for a maintainer.

## Running the examples

```console
$ book/check-guides.sh             # every guide-* example plus echo, udp-echo, hello
$ book/check-guides.sh guide-h3    # one of them
$ AKIO_DEFAULT_BACKEND=uring book/check-guides.sh   # on io_uring (Linux, ADR-029)
```

Self-checking examples must exit 0; the serving ones are probed from outside and stopped. On
Linux the script runs in a private network namespace when `unshare -rn` works, because some
examples use fixed ports (8080, 1935, 8554, 8000-8001, 7002); elsewhere a busy port fails the
example and names the reason. Run it on macOS, Linux arm64 (Docker) and x86_64 Linux.

Mermaid diagrams are rendered in the browser by `mermaid-init.js` (loaded from jsDelivr); GitHub
renders the same blocks natively.

## Editing rules

- Change a chapter in **both** languages in the same commit; the file trees must stay identical.
- Put new code in an example, mark it with anchors, and include it in both books.
- Keep statements in line with `docs/DEV-PLAN.md` (what is done) and the code; say what is not
  done.
- Published at `https://lesismal.github.io/akio/` (`/en/`, `/zh-CN/`, `/api/`) by
  `.github/workflows/pages.yml`; crate-level rustdoc links point there, and `check-site.py`
  checks those links against the built site.
