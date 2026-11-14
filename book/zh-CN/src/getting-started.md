# 快速上手

## 环境要求

- Rust stable，1.85 或更新（edition 2024）。
- 生产环境用 Linux（io_uring 需要 5.19+ 内核，否则任何支持 epoll 的内核都可以）。macOS 上
  用 kqueue 后端做开发。不支持 Windows。

## 在项目中引入 flash

这些 crate 还没有发布到 crates.io，请直接依赖仓库。按需选择：`flash` 是引擎，其他是协议。

```toml
[dependencies]
flash      = { git = "https://github.com/lesismal/flash" }
flash-http = { git = "https://github.com/lesismal/flash" }   # HTTP/1.1、HTTP/2、Router
# flash-ws、flash-grpc、flash-arpc、flash-socks、flash-mux、
# flash-quic、flash-h3、flash-kcp：写法相同
```

TLS（`flash::tls`，基于 rustls）和 eBPF 分流（`flash::ebpf`）都包含在 `flash` crate 里。

## 一个 TCP echo 服务

服务端就是一个带一个或多个 **listener** 的 **engine**。每个 listener 有一个 **acceptor**，
它为每个连接创建一个 **handler**；handler 的回调在连接所属的 I/O 线程上执行。

```rust,ignore
{{#include ../../../crates/flash/examples/echo.rs}}
```

运行并测试：

```console
$ cargo run --release -p flash --example echo -- 127.0.0.1:7000
$ nc 127.0.0.1 7000
hello
hello
```

要注意三点：

1. `on_data` 拿到的是借用的 `&[u8]`，只在本次调用期间有效。需要保留的数据请复制。
2. `c.send(..)` 永远不阻塞：socket 能写多少就写多少，剩下的排队；在回调里发送的所有数据
   会在回调返回时合并成一次 `writev`。
3. `engine.run()` 等于 `start()`（启动 I/O 线程）加 `wait()`。

## 一个 HTTP 服务

```rust,ignore
{{#include ../../../crates/flash-http/examples/hello.rs}}
```

```console
$ cargo run --release -p flash-http --example hello
$ curl -i localhost:8080/users/7
$ curl --http2-prior-knowledge localhost:8080/   # 同一端口上的 HTTP/2
```

`/slow` 路由展示了在 flash 里随处可见的规则：**handler 在 I/O 线程上执行，不能阻塞**。
需要慢操作才能给出答复时，把请求 detach，在别的线程完成它；见
[阻塞任务](concepts/blocking.md)。

## 指南示例

本书每一章都有可运行的示例。它们在空闲端口上启动服务端，用客户端访问后退出：

| 示例 | 主题 |
|---|---|
| `cargo run -p flash --example guide-basics` | handler、`Conn`、线程池、顺序、dial、停机 |
| `cargo run -p flash --example guide-config` | 所有配置项、后端、指标、热更新、UDP |
| `cargo run -p flash --example guide-tls` | TLS 服务端与客户端 |
| `cargo run -p flash-http --example guide-http` | 路由、中间件、静态文件、流式、客户端 |
| `cargo run -p flash-http --example guide-observe` | Prometheus、调试端点、访问日志、热更新 |
| `cargo run -p flash-http --example guide-bridge` | 与其他运行时和线程衔接 |
| `cargo run -p flash-ws --example guide-ws` | WebSocket 服务端与客户端 |
| `cargo run -p flash-grpc --example guide-grpc` | gRPC 服务端与客户端 |
| `cargo run -p flash-arpc --example guide-arpc` | arpc 调用、通知、广播 |
| `cargo run -p flash-socks --example guide-socks` | SOCKS5 与 HTTP CONNECT |
| `cargo run -p flash-mux --example guide-mux` | 一个端口上的多种协议 |
| `cargo run -p flash-quic --example guide-quic` | QUIC 服务端与客户端 |
| `cargo run -p flash-h3 --example guide-h3` | HTTP/3 服务端与客户端 |
| `cargo run -p flash-kcp --example guide-kcp` | 带 FEC 与加密的 KCP |

下一步：[核心概念](concepts/index.md)。
