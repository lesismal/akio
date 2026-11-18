# ADR-047：only-log 的 `/regex` 消息过滤，基于新的内部 crate `only-regex`

[English](047-log-regex-filters.md) | 简体中文

状态：已接受（2026-11-19）

## 背景

`only_log::Filter`（ADR-012）解析 env_logger 风格的指令，但拒绝 `/regex` 后缀
（`RUST_LOG=info/connection reset`）；env_logger 用它只保留消息匹配的记录。从 env_logger 迁移过来的用户
会期望有这个功能，而且它是把嘈杂的 debug 日志缩小到某一个连接或某一种错误的最快办法。

在日志路径上使用正则有两个风险。回溯引擎在 `(a*)*b` 这类模式上可能耗费指数时间，一次日志调用就会让
I/O 线程停顿（rules.zh-CN.md 第 1 条）。另外，没有设置模式时匹配不能有任何开销，设置了模式时也不能每条
记录都分配内存（第 12 条）。

ADR-005 不允许库依赖第三方 crate，因此 only-log 不能用 `regex` crate。工作区里已经有一个引擎
`only_http::re`（DEV-PLAN 第 A 波，ADR-007）：用于路由约束的 Thompson NFA。它只做整段匹配（相当于加了
锚点），`\d \w \s` 只认 ASCII，拒绝 `(?i)` 与 `\b`。它是 only-http 的私有实现，而在依赖图中 only-log 位于
only-http 之下。在工作区中检索，没有其他模式匹配器：路由的段内部分匹配只是按字面文本切分，其他地方也
不解析正则。

## 决定

1. **新增内部 crate `only-regex`**（无依赖，`#![forbid(unsafe_code)]`，版本同步发布，在
   docs/api-stability.zh-CN.md 中属于内部层级）：线性时间引擎，API 刻意保持很小：`Regex::new`、`as_str`、
   `is_match(&str)`、`is_match_fmt(fmt::Arguments)`、`FromStr` / `Display` / `Debug` / `Clone` / `Eq`
   （按模式文本比较），以及带 `position()` / `message()` 的 `Error`。
   - 语法：`regex` crate 语法的子集，含义相同：字面字符、`.`、带范围与取反的字符类、Unicode 的
     `\d \w \s` 及其取反、贪婪与惰性的 `* + ? {m,n}`、分支、分组（不捕获；接受命名分组）、
     `^ $ \A \z \b \B`，以及标志 `i`（Unicode 简单大小写折叠）、`m`、`s`、`U`，可取反、可限定作用域。
     其余语法（Unicode 类、反向引用、环视、`u` / `x` / `R` 标志、`\<`、`\b{..}`）都是指明原因的编译错误。
   - 引擎：模式编译为 Thompson NFA（最多 20 000 条指令）。编译时构建 DFA（指令数不超过 4096 的程序；
     最多 2048 个状态、2 MiB 转移表，并有工作量预算），字母表是任何指令和断言都区分不开的字符类
     （ASCII 用 128 项的表，其余字符用有序区间）。一个状态是待展开的 NFA 线程集合加上前一个字符的类别
     （开头、`\n`、单词字符、其他），这正是断言所需的全部信息。DFA 没有构建的转移由 Pike VM 从该状态的
     线程出发完成，到达已知状态后搜索回到 DFA。纯字面文本的模式用 `str::contains` 查找。任何情况下
     时间都与输入长度成线性关系；每次搜索都不分配内存（NFA 的工作内存按线程保留）。
   - Unicode 数据：`\w`、`\d`、`\s` 与大小写折叠轨道由 `tools/regex-tables` 从 regex-syntax（固定为
     fuzz/Cargo.lock 中的版本）生成；该工具与 `tools/codec-bench` 一样是独立工作区，因此差分模糊测试比较
     的是引擎，而不是两个 Unicode 版本。
2. **only-log 用它实现 `/regex`。** `Filter` 新增 `message_regex(pattern)`、`message_pattern()` 与
   `matches(&Record)`（级别加消息；消息通过 `is_match_fmt` 逐段送入匹配器，不拼接字符串）。指令解析器把
   第一个 `/` 之后的全部内容作为模式（env_logger 拒绝第二个 `/`；这里模式中可以有 `/`）；空模式表示不
   过滤；无效模式产生 `ParseFilterError`，其 directive 为 `/pattern`，reason 带有正则错误及字节偏移。
   `ParseFilterError` 的私有字段 `reason` 改为 `Cow<'static, str>`。`Display` 会写回模式，过滤器仍可往返
   转换。`enabled(metadata)` 不变（只看级别：logger 的 `enabled` 在还没有消息时就被调用）。`FmtLogger`
   直接匹配它已经格式化好的那一行中的消息部分，因此消息过滤不会重复格式化。
3. **only-http 暂时保留 `only_http::re`。** 路由约束是锚定的，并且文档写明只认 ASCII（`\d` = `[0-9]`）；
   改用 `only-regex` 会改变哪些路由能匹配。之后的变更可以让路由改用带 ASCII 模式和位并行匹配器的
   `only-regex`；本 ADR 不做这件事。

## 备选方案

- **把引擎放在 only-log 内部**（私有模块）。否决：正则引擎不是日志的职责，以后也难以与路由共享；独立的
  crate 有自己的模糊测试目标、README、API 快照与 Miri 测试，而且不会扩大 only-log 的 API。
- **把 `only_http::re` 下移到共享 crate 并扩展它。** 本次否决：整段匹配语义与 ASCII 字符类是路由文档中
  承诺的行为，位并行快速路径也是围绕锚定匹配设计的。把它通用化会在改日志的同时改变路由。
- **回溯引擎**（更小，支持更多语法）。否决：`ONLY_LOG` 里一个病态模式就会让所有写日志的线程停顿。
- **惰性 DFA**（搜索时构建状态）。暂时否决：`is_match` 接收 `&self`，日志调用来自所有线程，缓存需要
  加锁或按线程复制。预先构建的 DFA 加上 NFA 回退已经能覆盖日志过滤（模式都很短），且没有共享的可变状态。
- **把消息格式化到线程局部的 `String` 再匹配。** 否决：`is_match_fmt` 在写入时逐段匹配，不需要缓冲区，
  也没有拷贝。

## 影响

- 公开 API：only-log 新增 `Filter::message_regex`、`Filter::message_pattern`、`Filter::matches`（增量）。
  `"info/foo".parse::<Filter>()` 以前报错，现在成功。only-regex 是新的内部 crate（因 only-log 依赖它而发布）。
- 开销（gpu51，CPU 2，docs/BENCHMARKS.zh-CN.md）：没有模式的过滤器不变（`FmtLogger::log` 中多一次
  `Option` 判断；禁用语句前后都是 0.397 ns）。有模式时，`FmtLogger` 对消息做一次搜索；`Filter::matches`
  以 `/connection (reset|refused)` 匹配 72 字节的消息为 107 ns，含格式化（无模式 7.1 ns）。在 86 字节消息上
  与 `regex` crate 对比（`tools/codec-bench logregex`）：字面量 6.8 对 12.3 ns，
  `(?i)CONNECTION (reset|refused)` 69 对 86 ns，`\b\d+ms\b` 93 对 33 ns，多个字面量的分支 93 对 16 ns
  （`regex` 有 SIMD 字面量查找）；非 ASCII 文本与 ASCII 同速。编译需要 15-100 µs（含 `\b` 时最久）；只在
  解析过滤器时发生一次。
- 验证：单元测试（语法错误、标志、Unicode 类与大小写折叠、断言、在 100 000 字符输入上的病态模式、
  DFA 与 NFA 一致、分段输入、`Display` 实现中嵌套的搜索），带消息正则的 `ONLY_LOG` 端到端测试，以及
  cargo-fuzz 目标 `regex_search`：only-regex 能编译的模式，`regex` crate 必须也能编译且匹配结果相同，
  分别在 DFA、单独的 NFA 和分段输入下比较。
- 在路由迁移之前（第 3 点），工作区中有两个正则引擎。
