# only-protobuf

[English](README.md)

[only](https://github.com/lesismal/only) 的 Protocol Buffers 运行时，没有任何依赖。消息由
[`only-protobuf-build`](../only-protobuf-build) 从 `.proto` 文件生成（不需要 `protoc`）。

- `encoding`：线格式（varint、ZigZag、定长值、length-delimited 字段，group 会被跳过），以及生成代码
  调用的逐字段编码 / 解码函数。
- `Message`：编码、解码、合并、长度前缀分帧。`Enumeration` 用于开放枚举（未知数值得以保留），
  `UnknownFields` 保存消息不认识的字段并在编码时写回，`Name` 提供完整名称与 `Any` 的类型 URL。
- `well_known`：`Empty`、`Timestamp`、`Duration`、`Any`、各包装类型、`FieldMask`、`Struct` /
  `Value` / `ListValue`，并提供与 `SystemTime` / `std::time::Duration` 的转换和
  `Any::pack` / `unpack`。
- 有界解码：最多 100 层嵌套，长度对照输入检查，检查 UTF-8；线类型不符的字段作为未知字段保留
  （与 C++、Go 一致）。
- 编码结果与 protoc 的 C++ 运行时一致（按字段号顺序，写出 `-0.0` 以及 map 条目中的默认 key 和
  value），并用 protoc 生成的黄金编码做了校验。
- `reflect`：描述符池与 `DynamicMessage`（运行时才知道类型的消息）；`json`：标准 proto3 JSON 映射；
  `Extendable` / `Extension` 用于 proto2 extension，另支持封闭枚举、group 与 edition（ADR-022）。
- `text`：文本格式，解析与输出方式与 protoc 一致（ADR-030）。

```rust,ignore
// build.rs:  only_protobuf_build::compile(&["proto/route_guide.proto"], std::env::var("OUT_DIR")?)?;
pub mod routeguide {
    only_protobuf::include_proto!("routeguide");
}

use only_protobuf::Message;
let p = routeguide::Point { latitude: 1, longitude: 2, ..Default::default() };
let bytes = p.encode_to_vec();
assert_eq!(routeguide::Point::decode(&bytes)?, p);
```

测试（`tools/protobuf-test`）：protoc 生成的黄金编码、往返、合并语义、限制、与 prost 的差分测试和
fuzz 目标，以及使用 grpc-go 自带生成代码（route_guide / helloworld）的 gRPC 互通测试
（`tools/interop/grpc/run.sh`）。

指南：[gRPC](https://lesismal.github.io/only/zh-CN/protocols/grpc.html)。
