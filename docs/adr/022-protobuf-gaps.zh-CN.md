# ADR-022：protobuf 的 group、extension、edition、JSON 与反射

[English](022-protobuf-gaps.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

`akio-protobuf` / `akio-protobuf-build`（ADR-005：无第三方依赖、不需要 `protoc`）已支持 proto2 与
proto3 的消息、枚举、map、oneof 和常用 well-known 类型。尚未完成（DEV-PLAN）：proto2 的 group 与
extension、edition、标准 JSON 映射，以及运行时反射；没有反射，gRPC 服务端反射（grpcurl、grpcui）
无法工作。

## 决定

全部为新增；生成代码仍只引用 `::akio_protobuf`（服务桩另引用 `::akio_grpc`）。

**group 与 extension。**
- `encoding::GroupCodec<M, const N: u32>` 把消息编码为字段 `N` 的 group；生成代码用于 proto2 的
  `group` 字段和 `features.message_encoding = DELIMITED`。
- `ExtensionSet` 以编码形式保存消息的扩展字段（按字段号，与声明字段按号交错写回，与 protoc 一致）。
  有扩展范围的消息带 `pub extensions: ExtensionSet`（`Config::unknown_fields(false)` 时也有），并实现
  `Extendable`。每个 `extend` 字段生成一个带类型的常量（`Extension<被扩展类型, Codec>` /
  `RepeatedExtension`），通过 `msg.extension(&EXT)`、`set_extension`、`has_extension`、
  `clear_extension`、`repeated_extension`、`set_repeated_extension` 读写。扩展内容在读取时才解码
  （其中的错误在读取时报告，而不是在解码消息时）。
- MessageSet（`message_set_wire_format`）的条目映射为扩展。
- **封闭枚举**（proto2 枚举、`features.enum_type = CLOSED`）：未知数值放入未知字段而不是字段本身
  （与 C++、Go 一致；值未知的 map 条目整条放入）。新增 `Enumeration::is_known`（带默认实现）。
  这改变了 proto2 枚举字段遇到未知数值时的解码结果。

**edition 2023 与 2024。** 解析 `edition = "2023" | "2024"` 文件，按文件 / 消息 / 字段 / 枚举解析
`features.*`（字段存在性含 `LEGACY_REQUIRED`、枚举开闭、packed 或 expanded、delimited、UTF-8、JSON
格式；2024 的命名风格检查、`export` / `local` 符号可见性、`import option`）。proto2 / proto3 文件映射到
等价的旧版特性，由同一个解析器处理。差异：`utf8_validation = NONE` 的 string 字段仍是 `String` 并仍校验
UTF-8（Rust 字符串必须是 UTF-8，与 prost 相同）；该特性会记录在描述符中。

**描述符。** 生成器按 protoc 的写法构建 `FileDescriptorProto`（map 条目类型、合成 oneof、JSON 名称、
规范化默认值、选项，自定义选项与文本格式聚合值按 `descriptor.proto` 编码，去掉 source 保留期的选项）；
`descriptor.proto` 与 `type.proto`、`api.proto`、`source_context.proto` 现已内置。每个生成的包都有
`FILE_DESCRIPTOR_SET`（本包文件及其导入）和 `descriptor_pool()`。新增 `Config::descriptors(bool)`
（默认开启）与 `Config::file_descriptor_set_path`。

**反射**（`akio_protobuf::reflect`）：`DescriptorPool`（由编码后的描述符集构建，经过校验、名称解析与
特性解析）、`FileDescriptor`、`MessageDescriptor`、`FieldDescriptor`、`EnumDescriptor`、
`ServiceDescriptor`、`MethodDescriptor`；`DynamicMessage` / `Value` / `MapKey`（解码、编码、读写字段、
oneof、扩展、未知字段）；`ReflectMessage`（生成代码实现：`descriptor()`、`to_dynamic`、`from_dynamic`）。

**JSON**（`akio_protobuf::json`）：基于反射的 proto3 JSON 映射：`to_string`、
`to_string_with(&PrintOptions)`、`from_str`、`from_str_with(&ParseOptions)`（含
`ignore_unknown_fields`）、`parse_dynamic`、`DynamicMessage::to_json` / `from_json`；支持 well-known
类型、`json_name`、以 `[full.name]` 表示的扩展；自研严格 JSON 解析器。

**gRPC 服务端反射**（`akio_grpc::reflection`）：`register(server, &pool)` 注册
`grpc.reflection.v1.ServerReflection` 与 `v1alpha`（列出服务；按文件名、符号、扩展取文件；扩展号）；
反射消息公开（`reflection::v1`、`v1alpha`）。akio-grpc 现在依赖 akio-protobuf。

## 验证

- protoc 35.1 黄金数据：编码（group、extension、MessageSet、edition 2023 与 2024）逐字节解码并重新编码；
  11 个文件的描述符集与 protoc `--descriptor_set_out` 一致（含自定义选项、`descriptor.proto` 本身、
  edition 2024）。
- protobuf 一致性测试运行器 v35.1（Docker，`tools/protobuf-test/conformance/run.sh`，
  `--enforce_recommended --maximum_edition 2024`）：二进制 + JSON 通过 5627 项，失败 0 项，跳过 4 项
  （UNSTABLE edition 的消息）；文本格式未实现（跳过）。
- grpcurl（`tools/interop/grpc/grpcurl.sh`）：通过反射 list、describe（proto2 group 与 extension、
  edition 2024）以及 JSON 调用。
- 差分：group 与封闭枚举对照 prost，动态消息对照生成代码；fuzz 目标 `protobuf_diff`、
  `protobuf_descriptor`、`protobuf_json`。

## 影响

生成的包内嵌描述符（每个包几 KB；`Config::descriptors(false)` 可去掉）。编解码路径不变，除了 proto2
字段的封闭枚举分支和一次 tag 长度检查；同一次运行的 A/B 结果见 CHANGELOG。文本格式仍不支持。
