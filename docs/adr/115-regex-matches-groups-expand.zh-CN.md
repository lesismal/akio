# ADR-115：`akio-regex` 的匹配位置、分组与 Go 的模板

[English](115-regex-matches-groups-expand.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

基于 akio 的网关 akit 以 fit 为准，而 fit 用的是 Go 的 `regexp`。fit 的 `rewrite` 中间件把请求路径中正则表达式
的每处匹配替换掉（`regexp`，以及含 `$1`、`${name}` 的 `replacement`）；它的 `redirect` 中间件用那一处匹配的
分组拼出 URL（`"to": "/new/$1"`）。akio-regex（ADR-047、ADR-051）只回答模式是否出现在文本中：它解析分组却不捕获，
惰性量词和 `(?U)` 被接受但不起作用。akit 因此把这些字段作为"尚不支持"拒绝（akit 的请求 A32）。

## 决定

1. **`Regex` 上的匹配与分组**：`find` 与 `find_at(text, start)`（字节范围）、`find_iter`、`captures` 与
   `captures_at`（`Captures`：用 `get` 按编号、用 `name` 按名字取各组范围，用 `range` 取整个匹配）、
   `captures_len` 与 `group_names`。`find_at` 和 `captures_at` 的起点不在字符边界或超出末尾时视为无匹配；
   断言能看到起点之前的文本（`^` 仍是文本开头）。
2. **Go `regexp` 的最左优先语义**（`regex` crate 也是如此）：取最先开始的匹配，其中再取模式更偏好的那个。
   解析器现在保留捕获组（`Node::Group`，按其 `(` 编号，最多 1000 个）以及每个重复的贪婪性（`*?`，`(?U)`
   交换两者）。编译器按 Go 的 `regexp/syntax` 化简并编译重复的形状来生成指令，因为子表达式能匹配空文本时，
   形状决定哪个线程胜出：`x{n,}` 是 `n - 1` 份 `x` 再接 `x+`；`x+` 在 `x` 之后回跳；`x` 能匹配空文本时
   `x*` 是 `(x+)?`（golang/go#46123），否则是 `x` 之前的循环；`x{n,m}` 是 `n` 份再接嵌套的可选；
   同种类、同贪婪性的重复套重复合为一个（`x**` 即 `x*`）。
3. **捕获用的第二个程序。** `Prog` 保留原来的匹配程序（DFA 与 `is_match` 不变：惰性不改变它们的任何答案），
   另编译一个捕获程序：同一模式，在每个分组和整个匹配两侧加 `Save` 指令，每个 split 按优先级排序。两者受同一个
   20 000 条指令上限约束，因此分组重复到超过该上限的模式在编译时被拒绝（"pattern too large"）。
4. **带捕获的 Pike VM**（`pike.rs`）：线程按优先级排列，各带捕获槽（每条指令一行，加入线程时复制；`Save`
   在其所在分支走完后撤销）。优先级最高的线程到达 `Match` 时，记下该匹配并丢弃其后的线程；在找到匹配之前，
   每个位置都启动一个线程。时间与文本长度乘以程序大小成线性，与模式无关；工作内存按线程在多次搜索间保留，
   与匹配 VM 相同。从文本开头运行之前，先用 `is_match`（DFA）排除不匹配的文本；纯字面量模式用 `str::find`。
5. **Go 的模板**：`expand(caps, template, text, out)` 遵循 `Regexp.Expand`：`$1`、`${1}`、`$name`、
   `${name}`（名字取字母、数字和 `_` 的最长连续串，所以 `$1x` 指名为 `1x` 的组）、`$$`；不存在或未参与匹配的组
   为空，格式不对的 `$` 原样保留。`replace_all(text, template)` 即 `ReplaceAllString`，包括空匹配（紧跟在一次
   匹配之后的空匹配不替换），无匹配时借用原文本。`find_iter` 即 `FindAllString` 的迭代方式。一处差异：模板中
   组名里的非 ASCII 字符，按 Rust 的 `char::is_alphabetic` 判定是否字母（Go 要求 Unicode 字母类别；两者在字母
   数字和部分组合标记上不同），按 `\d` 是否匹配判定是否数字。

## 影响

- akit 的 `rewrite`（`regexp`、`replacement`）和 `redirect`（`to` 中的分组）与 fit 行为一致，在编译配置时编译。
- 捕获程序中分组重复到超过 20 000 条指令的模式，`Regex::new` 现在会失败，而以前能编译；超过 1000 个分组的
  模式也会失败。两者都远超路由和日志过滤器的用量。
- 编译时多构建一个程序（大小约等于第一个加上每组两条指令）；DFA 仍由第一个构建。
- 只含一个纯字面量分组的模式 `(abc)`，`is_match` 和 `find` 仍走字面量快速路径。

## 验证

- `tests/captures.rs`：一张由 Go 1.27 的 `regexp` 打印期望值（`FindStringSubmatchIndex`、`FindAllStringIndex`、
  `ReplaceAllString`）的模式、文本和模板表，覆盖空匹配、可空重复（`(a*)*`、`(a*)+`）、惰性与 `(?U)`、选择分支
  优先级、未参与的分组、Unicode、`\b`、`(?m)^` 及模板的边界情况；`expand` 的规则；分组与名字；`find_at` 的起点
  与断言；各项上限；从较后起点（DFA 不先行排除）在病态模式上的线性时间；多线程搜索。
- 与 Go `regexp` 的离线差分：由随机文法（分组、命名组、选择、字符类、`^ $ \b \B`、`(?i:...)`、贪婪与惰性的
  计数重复、`(?U)`）生成的 132 000 个（模式、文本、模板）用例，在两个引擎都能编译的情况下，子匹配下标、全部匹配
  和 `ReplaceAllString` 全部一致（akio-regex 拒绝 `\b{...}`，Go 将其读作重复的 `\b`：这是 `regex` crate 的语法，
  未改）。
- `regex_search` 模糊测试目标还将 `find`、`find_iter` 和 `captures` 的整个匹配与 `regex` crate 比较。
- akio-regex、akio-log 与 akio-http（路由）的 `cargo test`，以及 Linux 上 epoll 与 io_uring 的全工作区测试。
