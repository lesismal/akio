# akio-regex

[English](README.md)

[`akio`](https://github.com/lesismal/akio) 的小型正则表达式引擎，纯安全 Rust
（`#![forbid(unsafe_code)]`），无依赖。无论模式如何，匹配时间都与输入长度成线性关系。它是
`akio-log` 中 env_logger 风格消息过滤（`AKIO_LOG=info/connection (reset|refused)`）以及 `akio-http`
路由约束（`/users/{id:[0-9]+}`，ADR-051）背后的引擎。属于内部 crate（docs/api-stability.zh-CN.md）：
请通过 `akio-log` 与 `akio-http` 使用。

- 只回答一个问题：模式是否出现在这段文本的某处？`Regex::is_match(&str)`，以及
  `Regex::is_match_fmt(format_args!(..))`：在格式化的同时逐段匹配，不拼接字符串，也不分配内存。
- `RegexBuilder` 选项：`whole_text(true)` 只匹配整段文本（相当于 `\A(?:...)\z`），`ascii_classes(true)`
  让 `\d \w \s` 与 `\b` 只看 ASCII。路由器同时使用两者。
- 语法是 `regex` crate 的子集，含义相同：字面字符、`.`、带范围与取反的字符类、支持 Unicode 的
  `\d \w \s`（及 `\D \W \S`）、重复 `* + ? {m,n}`（贪婪或惰性）、分支、分组（不捕获，接受命名分组）、
  `^ $ \A \z`、`\b \B`（Unicode 单词边界）、标志 `(?i)`（Unicode 简单大小写折叠）、`(?m)`、`(?s)` 与
  `(?U)`，可取反（`(?-i)`）也可限定作用域（`(?i:...)`）。Unicode 类（`\p{..}`）、反向引用、环视以及
  `u` / `x` / `R` 标志会产生说明原因的编译错误。
- 引擎：Thompson NFA。纯字面模式直接用 `str::contains` 查找。其余模式在编译正则时构建 DFA
  （最多 2048 个状态，字母表是任何指令都区分不开的字符类：ASCII 用查表，其余字符用区间），因此每个
  字符的代价是一次字符类查找加一次表读取。DFA 之外的转移由 Pike VM 从该状态的线程集合出发完成，
  使用按线程保留、跨搜索复用的工作内存；一旦到达已知状态，搜索就回到 DFA。没有回溯：在
  100 000 个 `a` 上匹配 `(a*)*b` 也是线性时间。
- Unicode 表（`\w`、`\d`、`\s`、简单大小写折叠）由 `tools/regex-tables` 从 regex-syntax 生成，因此差分
  模糊测试目标 `regex_search` 比较两个引擎时使用的是同一份 Unicode 数据。

```rust
use akio_regex::Regex;

let re = Regex::new(r"(?i)\bconn(ection)? (reset|refused)\b").unwrap();
assert!(re.is_match("peer 10.0.0.7: Connection reset by peer"));
assert!(!re.is_match("connections reset: 0"));
let peer = "10.0.0.7";
assert!(re.is_match_fmt(format_args!("{peer}: conn refused")));
```

## 开销

`cargo run --release --manifest-path tools/codec-bench/Cargo.toml logregex` 在一条 86 字节的日志消息上
与 `regex` crate 对比（基准测试主机上的数据见 docs/BENCHMARKS.zh-CN.md）。DFA 在 ASCII 与非 ASCII 文本上
都约为每字符 1 纳秒；纯字面模式就是一次 `str::contains`（6.8 ns，`regex` 为 12.3 ns）。`regex` crate 在
多个字面量的分支和 `\b` 上快数倍（它有 SIMD 字面量查找和按字节的惰性 DFA），在大小写不敏感的分支上
更慢（69 对 86 ns）。编译需要 15-100 µs（预先构建 DFA），含 `\b` 的模式最久，因为 Unicode 单词边界会
加入字符类的划分。
