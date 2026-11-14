# gRPC

`flash-grpc` 提供一个 gRPC 服务端，它本身是一个 flash-http `Service`（因此与普通 HTTP 路由
共享端口和 HTTP/2 协议栈），以及一个建立在 flash-http HTTP/2 客户端之上的客户端。与 grpc-go
做过双向互通测试（`tools/interop/grpc/run.sh`）。

## 服务端

```rust,ignore
{{#include ../../../../crates/flash-grpc/examples/guide-grpc.rs:server}}
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
压缩响应；gzip 压缩的请求总是被接受）。

`Sink` 可在任何线程上答复：`send(msg) -> bool`、`set_header`、`set_trailer`、
`finish(Status)`、`is_finished`。`Status::ok()`、`Status::new(Code::.., message)`；`Code`
包含标准的 gRPC 状态码。未知方法返回 `Unimplemented`；在发送任何消息之前出错时以
trailers-only 响应发送；`grpc-timeout` 截止时间会被执行。

handler 在 I/O 线程上执行：处理很快时直接答复，否则把 `Sink` 移到其他线程（上例的
server-streaming 方法就是这样做的）。

提供服务：单独使用 `flash_http::serve(grpc)`，或者像上面那样作为 `Router` 的 `fallback`
（或某个路由）。gRPC 需要 HTTP/2：明文用 prior knowledge，或 ALPN 为 `h2` 的 TLS。

## 客户端

```rust,ignore
{{#include ../../../../crates/flash-grpc/examples/guide-grpc.rs:client}}
```

- `GrpcClient::new(h2_client, base_url)`；`.compress(true)` 压缩请求。
- `unary(path, msg, CallOptions) -> Result<Vec<u8>, Status>` 会阻塞调用线程（不要在 I/O 线程上
  调用）。
- `collect(path, requests, opts) -> (Vec<Vec<u8>>, Status)` 用于流式调用，同样是阻塞的。
- `bidi(path, opts, on_message, on_done) -> ClientSink` 是非阻塞的通用形式：
  `ClientSink::send`、`close_send`。
- `CallOptions`：`timeout`（作为 `grpc-timeout` 发送）、`metadata`。

## 消息

消息是字节。启用 `prost` feature 后，`flash_grpc::codec` 负责与 prost 生成的消息互相转换；
其他序列化方式只需自己编码成 `Vec<u8>` 即可。

未提供：服务端反射（reflection）、标准健康检查服务、客户端负载均衡。互通测试只针对 grpc-go
（未测 tonic）。
