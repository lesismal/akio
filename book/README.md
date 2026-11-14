# The `only` book: sources

English | [简体中文](README.zh-CN.md)

Two [mdBook](https://rust-lang.github.io/mdBook/) books with the same chapters:

```text
book/
├─ en/        book.toml + src/   English
├─ zh-CN/     book.toml + src/   Simplified Chinese (same file names, same includes)
├─ index.html                    language picker copied to target/book/index.html
├─ build.sh                      check + build both books
└─ check-includes.py             verifies every {{#include}} target and anchor
```

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

Mermaid diagrams are rendered in the browser by `mermaid-init.js` (loaded from jsDelivr); GitHub
renders the same blocks natively.

## Editing rules

- Change a chapter in **both** languages in the same commit; the file trees must stay identical.
- Put new code in an example, mark it with anchors, and include it in both books.
- Keep statements in line with `docs/DEV-PLAN.md` (what is done) and the code; say what is not
  done.
- Published at `https://lesismal.github.io/flash/` (`/en/`, `/zh-CN/`) once the docs CI job
  deploys it; crate-level rustdoc links point there.
