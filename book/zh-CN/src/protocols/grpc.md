# gRPC

`only-grpc` 提供一个 gRPC 服务端，它本身是一个 only-http `Service`（因此与普通 HTTP 路由
共享端口和 HTTP/2 协议栈），以及一个建立在 only-http HTTP/2 客户端之上的客户端。与 grpc-go
做过双向互通测试（`tools/interop/grpc/run.sh`）。

## 服务端

```rust,ignore
{{#include ../../../../crates/only-grpc/examples/guide-grpc.rs:server}}
```

注册方法（`path` 为 `/package.Service/Method`）：

| 构建方法 | handler 签名 | 用途 |
|---|---|---|
| `unary(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | 一个请求，一个响应 |
| `server_stream(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | 一个请求，多个响应 |
| `client_stream(path, f)` | `Fn(&Metadata, Vec<Vec<u8>>, Sink)` | 多个请求（在半关闭时交付），一个响应 |
| `bidi(path, open)` | `Fn(&Metadata, Sink) -> OnMessage` | 通用形式：每个请求消息调用一次 `OnMessage(Some(msg))`，半关闭时调用 `None` |

其他设置：`interceptor(Fn(&Metadata) -> Result<(), Status>)` 在每次调用前执行（返回 `Err`
时以该状态结束调用），`max_message_bytes(n)`（默认 4 MiB），`compress(bool)`（对接受 gzip 的客户端
压缩响应；gzip 压缩的请求总是被接受），`max_collect_bytes(n)`（默认 64 MiB：`client_stream`
方法为一次调用收集的请求字节上限，超出时返回 `RESOURCE_EXHAUSTED`；需在注册这些方法之前设置），
以及 `max_deadline(d)`（默认 24 小时：更长的 `grpc-timeout` 会被缩短到该值）。

`Sink` 可在任何线程上答复：`send(msg) -> bool`、`set_header`、`set_trailer`、
`finish(Status)`、`is_finished`。`Status::ok()`、`Status::new(Code::.., message)`；`Code`
包含标准的 gRPC 状态码。未知方法返回 `Unimplemented`；在发送任何消息之前出错时以
trailers-only 响应发送；`grpc-timeout` 截止时间会被执行（调用结束时计时器立即移除）。

handler 在 I/O 线程上执行：处理很快时直接答复，否则把 `Sink` 移到其他线程（上例的
server-streaming 方法就是这样做的）。

提供服务：单独使用 `only_http::serve(grpc)`，或者像上面那样作为 `Router` 的 `fallback`
（或某个路由）。gRPC 需要 HTTP/2：明文用 prior knowledge，或 ALPN 为 `h2` 的 TLS。

## 客户端

```rust,ignore
{{#include ../../../../crates/only-grpc/examples/guide-grpc.rs:client}}
```

- `GrpcClient::new(h2_client, base_url)`；`.compress(true)` 压缩请求。
- `unary(path, msg, CallOptions) -> Result<Vec<u8>, Status>` 会阻塞调用线程（不要在 I/O 线程上
  调用）。
- `collect(path, requests, opts) -> (Vec<Vec<u8>>, Status)` 用于流式调用，同样是阻塞的。
- `bidi(path, opts, on_message, on_done) -> ClientSink` 是非阻塞的通用形式：
  `ClientSink::send`、`close_send`。
- `CallOptions`：`timeout`（作为 `grpc-timeout` 发送，客户端也会执行：到期时无论服务端如何，
  调用都以 `DEADLINE_EXCEEDED` 结束）、`metadata`。未设置时，`unary` 和 `collect` 使用客户端的
  `default_timeout(Option<Duration>)`（30 秒），因为它们会阻塞线程；`bidi` 调用没有截止时间。
- `max_message_bytes(n)`（4 MiB）限制每条响应消息，`max_collect_bytes(n)`（64 MiB）限制
  `unary` 和 `collect` 为一次调用收集的响应总量（超出：`RESOURCE_EXHAUSTED`）。

## 消息

消息是字节。`only_grpc::codec::{encode, decode}` 可转换任何实现了 `codec::Message`
（`encode_to` / `decode_from`）的类型，因此任意序列化方式都能接入。对 protobuf，`only` 有自己的
运行时和代码生成器，不需要 `protoc`，也没有第三方 crate：

- `only-protobuf`：线格式、`Message` trait、开放枚举、未知字段、well-known 类型（`Timestamp`、
  `Duration`、`Any`、`Struct`、包装类型 ...）。
- `only-protobuf-build`：供 `build.rs` 使用的 `.proto` 解析器与 Rust 代码生成器。支持 proto3 与
  proto2 的消息、枚举、`optional`、`repeated`、`map`、`oneof`、嵌套与递归类型、package、import；
  service 生成基于 `only-grpc` 的类型化服务端 trait 与客户端。

### 不用 prost 定义消息

依赖：`only-protobuf` 与 `only-grpc`，并在 `[build-dependencies]` 中加入 `only-protobuf-build`。
然后在 `build.rs` 中（取自 `tools/protobuf-test`，其 `proto/` 目录包含 grpc-go 的 route_guide 与
helloworld 定义）：

```rust,ignore
{{#include ../../../../tools/protobuf-test/build.rs:build}}
```

每个 protobuf package 在 `OUT_DIR` 中生成一个文件，作为模块引入。引用其他 package 的类型时写作
`super::other::Type`，因此模块要按 package 嵌套（`test.all` -> `pub mod test { pub mod all { .. } }`）：

```rust,ignore
pub mod routeguide {
    only_protobuf::include_proto!("routeguide");
}
```

`.proto` 构造对应的 Rust 代码：

| `.proto` | Rust |
|---|---|
| `message Point { int32 latitude = 1; }` | `pub struct Point { pub latitude: i32, pub unknown_fields: UnknownFields }`（`Clone`、`PartialEq`、`Debug`、`Default`；不含浮点数时还有 `Eq`） |
| `string`、`bytes` | `String`、`Vec<u8>` |
| 消息类型字段、proto3 `optional`、proto2 `optional` | `Option<T>`（递归时为 `Option<Box<T>>`）；proto2 默认值通过 getter 获取（`p.a()`） |
| `repeated T` / `map<K, V>` | `Vec<T>` / `HashMap<K, V>`（`Config::btree_maps(true)` 时为 `BTreeMap`） |
| `oneof kind { .. }` | `pub kind: Option<point::Kind>`，枚举位于消息对应的模块中 |
| `enum Corpus { CORPUS_WEB = 1; }` | `pub struct Corpus(pub i32)`，常量 `Corpus::WEB`：开放枚举，未知数值得以保留 |
| `Outer` 中嵌套的 `message Inner` | `outer::Inner` |
| `google.protobuf.Timestamp` ... | `only_protobuf::well_known::Timestamp` ... |

消息会保留未知字段并在编码时写回（`Config::unknown_fields(false)` 去掉该成员，结构体字面量就不再
需要 `..Default::default()`）。编码结果与 protoc 的 C++ 运行时逐字节一致；解码有界（最多 100 层
嵌套、检查长度、检查 UTF-8）。

### Service

对 `service RouteGuide`，生成器写出 `route_guide_server`，其中有一个待实现的 trait：

```rust,ignore
{{#include ../../../../tools/protobuf-test/src/service.rs:server}}
```

一元方法返回响应；服务端流方法拿到 `Sink`（可在任意线程使用；先 `sink.send_message(&m)`，再
`finish`）；客户端流方法在客户端半关闭后拿到全部请求；双向流方法返回一个接收每条请求的函数。
`register` 把所有方法注册到 `GrpcServer`，可以与原始字节方法并存：

```rust,ignore
{{#include ../../../../tools/protobuf-test/src/service.rs:register}}
```

`route_guide_client::RouteGuideClient` 包装一个 `GrpcClient`：

```rust,ignore
let rg = RouteGuideClient::new(grpc_client);
let feature = rg.get_feature(&point, CallOptions::default())?;           // 一元
let features = rg.list_features(&rect, CallOptions::default())?;         // Vec<Feature>
let summary = rg.record_route(&points, CallOptions::default())?;         // 客户端流
let sink = rg.route_chat(CallOptions::default(), |note| { /* 每条响应 */ }, |status, _| {});
sink.send_message(&note);
sink.close_send();
```

一元调用和收集型调用会阻塞；双向流调用不会。无法解码的请求以 `INVALID_ARGUMENT` 应答。互通：
`tools/interop/grpc/run.sh` 让这些桩代码与 grpc-go 自带的 route_guide、helloworld 生成代码以及
`google.golang.org/protobuf` 的 well-known 类型双向互通。

### proto2 extension、group 与 edition

proto2 的 `group` 字段和 `extend` 块会生成代码；edition 2023 与 2024 文件也一样，并遵循其
`features.*`（字段存在性、封闭枚举、packed 或 expanded、`DELIMITED`）。有扩展范围的消息带
`pub extensions: ExtensionSet` 并实现 `only_protobuf::Extendable`；每个扩展是一个带类型的常量：

```rust,ignore
use only_protobuf::Extendable;
let mut b = ext::Base::default();
b.set_extension(&ext::LEVEL, &ext::Level::LOW);          // extend Base { optional Level level = 100; }
b.set_repeated_extension(&ext::TAGS, &[1, 2]);
assert_eq!(b.extension(&ext::LEVEL)?, Some(ext::Level::LOW));
```

封闭枚举（proto2，或 `enum_type = CLOSED`）把未知数值保存为未知字段。

### 反射与 JSON

每个生成的包内嵌自己的描述符（`FILE_DESCRIPTOR_SET`、`descriptor_pool()`；
`Config::descriptors(false)` 可关闭），其消息实现 `only_protobuf::reflect::ReflectMessage`。
`only_protobuf::reflect` 提供描述符池与 `DynamicMessage`（运行时才知道类型的消息）；
`only_protobuf::json` 提供标准 proto3 JSON 映射，含 well-known 类型：

```rust,ignore
let text = only_protobuf::json::to_string(&feature)?;    // {"name":"...","location":{...}}
let back: Feature = only_protobuf::json::from_str(&text)?;
```

gRPC 服务端反射让 grpcurl、grpcui 不需要 `.proto` 文件就能列出并调用服务：

```rust,ignore
{{#include ../../../../tools/protobuf-test/src/service.rs:reflection}}
{{#include ../../../../tools/protobuf-test/src/service.rs:reflection_register}}
```

`tools/interop/grpc/grpcurl.sh` 用 grpcurl 验证它，`tools/protobuf-test/conformance/run.sh` 对生成代码
运行 protobuf 一致性测试套件（二进制与 JSON）。

### prost（已弃用）

启用 `prost` feature 后，所有 prost 生成的消息都实现 `codec::Message`。它仍然可用，但已弃用，
推荐改用 `only-protobuf`；它用到 prost 的类型，所以这个 feature 不在 semver 承诺之内（prost 升级
或移除该 feature 可能出现在 minor 版本中）。

未提供：服务端反射（reflection）、标准健康检查服务、客户端负载均衡。互通测试只针对 grpc-go
（未测 tonic）。
