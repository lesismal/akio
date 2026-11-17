# only 指南：源文件

[English](README.md) | 简体中文

这里是两本章节相同的 [mdBook](https://rust-lang.github.io/mdBook/)：

```text
book/
├─ en/        book.toml + src/   英文
├─ zh-CN/     book.toml + src/   简体中文（文件名相同，引用相同）
├─ index.html                    语言选择页（站点根）
├─ build.sh                      检查并构建两本书到 target/book
├─ check-includes.py             校验每个 {{#include}} 的目标与锚点；中英文章节结构一致
├─ site.sh                       发布的站点：两本书 + rustdoc 构建到 target/site
├─ check-site.py                 以 HTTP 服务 target/site 并检查两种语言的每个链接
└─ check-guides.sh               运行书中引用的每个示例
```

`en/lang-switch.js` 与 `zh-CN/lang-switch.js`（内容相同）为每页加上语言切换和 API 链接；
`src/404.md` 是每本书的“页面不存在”页。

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

## 发布的站点

```console
$ book/site.sh                                  # 两本书 + rustdoc 构建到 target/site，基础路径 /only/
$ python3 book/check-site.py target/site        # 通过 HTTP 检查链接，有问题时退出码为 1
$ python3 book/check-site.py target/site --serve 8000   # http://127.0.0.1:8000/only/
```

`.github/workflows/pages.yml` 运行的正是这两条命令，并把 `target/site` 部署到 GitHub Pages：
在发布 release 时或手动触发（Actions -> Pages -> Run workflow），从不在 push 时运行。布局：
`/only/` 语言选择页，`/only/en/`、`/only/zh-CN/`、`/only/api/`（已发布 crate 的 rustdoc）、
`/only/404.html`。启用 Pages（Settings -> Pages -> Source: GitHub Actions）是维护者的一次性操作。

## 运行示例

```console
$ book/check-guides.sh             # 每个 guide-* 示例，以及 echo、udp-echo、hello、prefork-http
$ book/check-guides.sh guide-h3    # 只运行其中一个
$ ONLY_DEFAULT_BACKEND=uring book/check-guides.sh   # 在 io_uring 上运行（Linux，ADR-029）
```

自检型示例必须以 0 退出；服务型示例从外部探测后停止。部分示例使用固定端口（8080、1935、8554、
8000-8001、7002），因此在 Linux 上只要 `unshare -rn` 可用，脚本就在私有网络命名空间中运行；
其他环境下端口被占用会使该示例失败并给出原因。请在 macOS、Linux arm64（Docker）和 x86_64 Linux
上运行。

Mermaid 图由 `mermaid-init.js` 在浏览器中渲染（从 jsDelivr 加载）；GitHub 会原生渲染同样的
代码块。

## 编辑规则

- 在同一个提交中同时修改**两种语言**的章节；两边的文件树必须保持一致。
- 新代码放进示例程序，用锚点标记，并在两本书中引用。
- 内容要与 `docs/DEV-PLAN.zh-CN.md`（已完成的内容）和代码保持一致；未完成的要说明。
- 由 `.github/workflows/pages.yml` 发布在 `https://lesismal.github.io/only/`（`/en/`、
  `/zh-CN/`、`/api/`）；crate 级 rustdoc 的链接指向这里，`check-site.py` 会对照构建出的站点检查
  这些链接。
