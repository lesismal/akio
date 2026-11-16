# only-log

[English](README.md)

[`only`](https://github.com/lesismal/only) 的日志门面，无任何依赖（`#![forbid(unsafe_code)]`）。
`only` 以 `only::log` 重新导出它。它在 `only` 的所有库中取代了 `log` crate；可选的桥接让基于
`log` 的配置（env_logger、`tracing-log` ……）继续可用。

- 级别 `Error` .. `Trace` 与 `LevelFilter`（`Off` .. `Trace`），排序、解析和打印方式与 `log`
  crate 相同。
- 宏 `error!`、`warn!`、`info!`、`debug!`、`trace!`、`log!`、`log_enabled!`，语法与 `log` 相同：
  `target: "..."`，键值对 `key = value`、`key:% = value`（Display）、`key:? = value`（Debug），
  然后是 `;` 和格式串。
- 全局最大级别存放在一个原子变量中：被禁用的语句只需一次 relaxed 读和一次比较，参数不会被求值。
  `set_max_level` 可在运行时修改它（`only` 的 `Config::log_level` 与 `Engine::reload` 会调用它）。
- `Logger` trait（`enabled`、`log`、`flush`），用 `set_logger(&'static ...)` 或
  `set_boxed_logger` 安装一次。记录提供级别、target、消息（`fmt::Arguments`，延迟格式化）、
  键值对和源码位置。
- 内置 logger：`init(LevelFilter)` 一次调用安装 `FmtLogger`
  （`2026-11-14T08:00:00.000123Z INFO  only: engine started listeners=[127.0.0.1:8080]`，UTC，
  可按 target 设上限，输出到 stderr 或 stdout）；`StderrLogger` 打印 `target: message`。
- `Filter`：从 env_logger 风格的指令得到按 target 的级别；`init_from_env(default)` 只读取一次
  `ONLY_LOG=info,only_http=debug,only_quic::conn=trace` 并据此安装 `FmtLogger`（需显式调用：否则没有
  代码读取环境变量）。target 按 `::` 边界匹配，最具体者胜出，不支持 `/regex` 过滤。
- 编译期上限，与 `log` crate 相同：feature `max_level_off` .. `max_level_trace` 与
  `release_max_level_*` 把超出上限的语句编译掉（`STATIC_MAX_LEVEL`）。只应由应用开启（cargo 会在整个
  依赖图中合并 feature）。
- 未安装 logger：记录被丢弃；`log_or_stderr` 会把交给它的记录打印到 stderr（`only` 用它输出错误与
  降级信息，慢回调警告也以同样方式打印，因此不会悄无声息地丢失）。

```rust
use only_log::{LevelFilter, info, warn};

only_log::init(LevelFilter::Info).unwrap();
let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 9000));
info!(target: "app", conn_id = 7u64, peer:% = peer; "connection opened");
warn!("{} retries left", 3);
```

## `log` 桥接（cargo feature `log`）

启用 `only`（或 only-core / only-log）的 `log` feature：

- **only-log 到 `log`**，自动：在未安装 only-log logger 时，记录以相同的级别、target、消息、位置和
  键值对交给 `log::logger()`，有效最大级别为 `log::max_level()`；`set_max_level` 也会设置 `log`
  的级别。调用了 `env_logger::init()` 的应用会像以前一样看到 `only` 的记录。
- **`log` 到 only-log**，按需开启：`only_log::bridge::route_log_to_only()` 安装一个 `log::Log`
  适配器，使通过 `log` 记日志的 crate（str0m、rustls ……）进入 only-log 的 logger。
- 两个 crate 的级别类型之间可 `From` / `Into` 转换。

两个方向不会形成循环。该 feature 跟随 `log` 0.4，不在 semver 承诺之内（次版本可能升级 `log`）。

## 开销

`cargo bench -p only-log --bench overhead`（Apple M 系列，release；每条语句的纳秒数）：

| 语句 | only-log | `log` 0.4 |
|---|---|---|
| 带 2 个键值对的 `trace!`，级别被禁用 | 0.25-0.29 | 0.36-0.37 |
| `log_enabled!`，被禁用 | 0.25 | 0.25 |
| 带 2 个键值对的 `info!`，启用，logger 丢弃 | 2.3 | 3.0 |

启用 `log` feature 且未安装 only-log logger 时，禁用检查还会读取 `log::max_level()`（约 0.5 ns）。
未开启上限 feature 时编译期上限没有任何开销（macOS 上基准二进制逐字节相同；x86_64 上同一轮测得禁用的
`trace!` 前后为 0.400 ns 与 0.401 ns）；开启上限后，超出的语句不复存在。
