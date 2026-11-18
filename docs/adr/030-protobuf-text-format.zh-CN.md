# ADR-030：protobuf 文本格式

[English](030-protobuf-text-format.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

ADR-022 为 `only-protobuf` 加入了运行时反射（`DescriptorPool`、`DynamicMessage`）与标准 JSON 映射，
但没有做文本格式：protobuf 一致性运行器跳过了其中 909 项文本格式测试。protoc 的 `--decode`、
`DebugString`、测试数据、配置文件（`.textproto`、`.pbtxt`）以及许多工具读写的都是文本格式。

## 决定

新增模块 `only_protobuf::text`，建立在反射之上，与 `only_protobuf::json` 对应。全部为新增；
生成代码不变。

- 生成消息（`ReflectMessage`）用 `to_string`、`to_string_with(&PrintOptions)`、`from_str`、
  `from_str_with(&ParseOptions)`；动态消息用 `parse_dynamic`、`DynamicMessage::to_text` /
  `from_text`。`TextError` 带行号和列号（从 1 起）。
- `PrintOptions { single_line, print_unknown_fields, type_pool }`；
  `ParseOptions { allow_unknown_fields, type_pool }`；`RECURSION_LIMIT`（100）。
- 解析遵循[文本格式规范](https://protobuf.dev/reference/protobuf/textformat-spec/)：
  - 标量；枚举可用名字或数值（封闭枚举只接受声明过的数值）；
  - string 与 bytes 支持全部转义（简单转义、八进制、`\x`、`\u`、`\U`；拒绝代理项和大于 U+10FFFF
    的码点），相邻字面量拼接，string 必须是 UTF-8；
  - 消息写在 `{ }` 或 `< >` 中，`:` 可省略；repeated 字段可逐个给出，也可写成 `[a, b]`；map 写成
    条目消息（同一个键给出多次时取最后一个值）；
  - oneof；group 可用类型名或字段名；扩展写成 `[pkg.ext]`（MessageSet 条目也可用其类型名）；
    `Any` 展开写成 `[前缀/pkg.Type] { ... }`，方括号内可有空白和注释（与 protoc 一致）；
  - `#` 注释，字段后可跟 `,` 或 `;`；
  - 整数可为十进制、八进制、十六进制，检查范围；浮点数可带 `f` 后缀，`inf` / `infinity` / `nan`
    不区分大小写，超出范围的值变为无穷大或（带符号的）零，浮点字段不接受十六进制和八进制。
- 与 protoc 的 `TextFormat::Parse` 一致：单值字段给出两次、或 oneof 给出第二个成员是错误，
  `reserved` 中列出的字段名被跳过，未知字段和未知扩展是错误（除非 `allow_unknown_fields`）。
- 输出与 protoc 的 printer 一致：字段按字段号排列（扩展穿插其中），两个空格缩进（或单行），
  repeated 字段每行一个值，map 条目按键排序并同时输出 `key` 和 `value`，group 用类型名，枚举用名字，
  浮点数输出为能读回相同值的最短文本（`inf`、`-inf`、`nan`），字符串用 C 转义（bytes 用八进制，
  string 保留 UTF-8），`Any` 的类型在池（或 `type_pool`）中时展开输出。
- 与 protoc 的差异：当 `Any` 的类型 URL 无法原样读回，或其值含有未知字段而又不输出未知字段时，
  `Any` 按原始字段输出（不展开），因此输出不丢信息；大于 `\377` 的八进制转义是错误；proto3 单值
  字段给出两次也是错误，即使第一次给的是默认值（protoc 检查的是 `HasField`）。不支持：按字段号
  解析字段（`AllowFieldNumber`），以及 protoc 需要显式选用的合并模式（`TextFormat::Merge`，允许
  单值字段给出多次）。

## 验证

- protobuf 一致性运行器 v35.1（`tools/protobuf-test/conformance/run.sh`，
  `--enforce_recommended --maximum_edition 2024`）：文本格式通过 909 项、失败 0 项、跳过 0 项
  （proto2、proto3、edition）；二进制 + JSON 仍为通过 5627 项。
- `tools/protobuf-test/tests/text.rs`（精确输出、所有输入形式、错误、group、扩展、MessageSet、
  `Any`、未知字段、浮点数、变异冒烟测试）以及模块内的单元测试。
- fuzz 目标 `protobuf_text`：文本解析 → 输出 → 再解析（多行与单行）必须输出相同文本、编码长度
  相同；二进制输入必须能连同未知字段输出并读回。

## 影响

文本格式为本 crate 增加了代码，但编码、解码路径和生成代码都没有变化。它适用于任何带描述符的消息
（默认如此）；用 `Config::descriptors(false)` 生成的消息只能通过以其他方式构建的
`DescriptorPool` 使用它。
