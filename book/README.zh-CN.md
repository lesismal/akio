# flash 指南：源文件

[English](README.md) | 简体中文

这里是两本章节相同的 [mdBook](https://rust-lang.github.io/mdBook/)：

```text
book/
├─ en/        book.toml + src/   英文
├─ zh-CN/     book.toml + src/   简体中文（文件名相同，引用相同）
├─ index.html                    语言选择页，复制到 target/book/index.html
├─ build.sh                      检查并构建两本书
└─ check-includes.py             校验每个 {{#include}} 的目标文件与锚点
```

架构一章引用 `docs/architecture.md` / `docs/architecture.zh-CN.md`，因此架构文档只在一处维护，
在 GitHub 和书中都能正常显示。

## 代码片段

每一段 Rust 代码都通过 `{{#include}}` 从可运行的示例程序引入，从不直接写在 Markdown 里：
即 `crates/*/examples/` 中的 `guide-*` 示例（以及 `echo`、`hello`、`udp-echo`），片段用
`// ANCHOR: name` / `// ANCHOR_END: name` 标记。因此 `cargo build --workspace --examples` 会编译
每一段代码，运行示例则会端到端地执行它。代码块标记为 `rust,ignore`，因为 `mdbook test` 无法
链接工作区的 crate；不要使用 `mdbook test`。来自其他生态（Go、tokio、axum）的代码只用于对比，
不参与编译。

## 构建

```console
$ cargo install mdbook --locked --version 0.4.52
$ book/build.sh            # 检查引用、编译示例、构建 target/book/{en,zh-CN}
$ book/build.sh --no-check # 只构建
$ python3 -m http.server -d target/book 8000   # 然后打开 http://127.0.0.1:8000/
```

Mermaid 图由 `mermaid-init.js` 在浏览器中渲染（从 jsDelivr 加载）；GitHub 会原生渲染同样的
代码块。

## 编辑规则

- 在同一个提交中同时修改**两种语言**的章节；两边的文件树必须保持一致。
- 新代码放进示例程序，用锚点标记，并在两本书中引用。
- 内容要与 `docs/DEV-PLAN.zh-CN.md`（已完成的内容）和代码保持一致；未完成的要说明。
- 文档 CI 任务部署后发布在 `https://lesismal.github.io/flash/`（`/en/`、`/zh-CN/`）；crate 级
  rustdoc 的链接指向这里。
