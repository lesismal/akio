# akio-protobuf-build

[English](README.md)

在 `build.rs` 中为 `.proto` 文件生成 Rust 代码，供 [`akio-protobuf`](../akio-protobuf) 与
[`akio-grpc`](../akio-grpc) 使用。`.proto` 解析器是内置的：不需要 `protoc`，不用 `syn` / `quote`，
没有任何第三方 crate。

- proto3 与 proto2：消息、嵌套类型、枚举（开放枚举：包裹 `i32` 的 newtype，每个枚举值一个常量）、
  全部标量类型、`optional`（`Option<T>`）、`required`、`repeated`（按语法或 `[packed = ...]`
  决定是否 packed）、`map<K, V>`（`HashMap`，或开启 `btree_maps(true)` 后为 `BTreeMap`）、
  `oneof`（生成枚举）、proto2 的 `[default = ...]`（getter）、递归消息（Box）、package 与
  import，`.proto` 中的注释成为文档注释。
- 未知字段保存在 `unknown_fields` 成员中（可用 `unknown_fields(false)` 关闭，此时结构体字面量不再
  需要 `..Default::default()`）。
- 内置 `google/protobuf/{empty,timestamp,duration,any,wrappers,field_mask,struct}.proto`，映射到
  `akio_protobuf::well_known`；`extern_path` 可把其他 package 映射到已有的 crate。
- service 生成 `akio-grpc` 代码：`<service>_server::{<Service> trait, register}` 与
  `<service>_client::<Service>Client`，支持一元、服务端流、客户端流与双向流方法；此时每个消息也都
  实现 `akio_grpc::codec::Message`。
- proto2 的 group、extension（带类型的 `Extension` 常量、`ExtensionSet` 成员）、MessageSet、封闭枚举；
  edition 2023 与 2024 及其特性；自定义 option 与聚合值编码进描述符。每个包内嵌与 protoc 一致的
  `FILE_DESCRIPTOR_SET` 和 `descriptor_pool()`（用于反射、JSON、gRPC 服务端反射）；内置 `descriptor.proto`。
- 文本格式由运行时提供：`akio_protobuf::text` 解析并打印生成的消息（ADR-030）。

```rust,ignore
// build.rs
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    akio_protobuf_build::compile(&["proto/route_guide.proto"], &out).unwrap();
}

// src/lib.rs：每个 package 一个文件，作为模块引入
pub mod routeguide {
    akio_protobuf::include_proto!("routeguide");
}
```

服务端实现生成的 trait 并注册：

```rust,ignore
use akio_grpc::{GrpcServer, Metadata, Sink, Status};
use routeguide::{route_guide_server::{self, RouteGuide}, Feature, Point};

struct Guide;
impl RouteGuide for Guide {
    fn get_feature(&self, _md: &Metadata, p: Point) -> Result<Feature, Status> {
        Ok(Feature { name: "here".into(), location: Some(p), ..Default::default() })
    }
    // list_features(.., sink: Sink)、record_route(.., Vec<Point>)、route_chat(..) -> Box<dyn FnMut>
}
let grpc = route_guide_server::register(GrpcServer::new(), Guide);
```

客户端包装一个 `GrpcClient`：
`RouteGuideClient::new(grpc).get_feature(&point, CallOptions::default())?`。

指南：[gRPC](https://lesismal.github.io/akio/zh-CN/protocols/grpc.html)。
