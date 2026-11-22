# 从 fib（Go）迁移

akio 是 fib 的 Rust 对应物，大部分概念可以直接沿用。最大的区别在于**你的代码在哪里执行**：
fib 默认把每一轮读交给 worker 池，所以 fib 的 handler 可以阻塞；akio 的回调**直接在连接所属的
I/O 线程上执行**，所以 akio 的 handler 不能阻塞，阻塞任务需要显式移到逻辑线程池。其余差异
都源于这一点以及 Rust 的所有权规则。

## 概念对照

| fib（Go） | akio（Rust） | 说明 |
|---|---|---|
| `fib.New(config, fib.Binding{...})` | `Engine::builder().config(cfg).listen(Listener::tcp(addr).serve(acceptor)).build()?` | 每个绑定地址一个 `Listener` |
| `Binding{Network: "udp", ...}` | `Listener::udp(addr)` | 不支持 Unix socket |
| `Binding.Addrs`（多个地址） | 每个地址一个 `Listener` | 每个 listener 有自己的线程 |
| `server.Run()` | `engine.run()`（= `start()` + `wait()`） | |
| `Shutdown(ctx)` | `shutdown()` + `wait()`，上限为 `Config::shutdown_timeout` | `Acceptor::on_shutdown` ≈ `ShutdownHandler.OnShutdown` |
| `Stop()` / `Close()` | 设置较短 `shutdown_timeout` 的 `shutdown()` | akio 停止时总会关闭连接 |
| `fib.Handler`（`OnOpen`、`OnData`、`OnClose`） | `Acceptor::on_open` 返回一个 `Handler`（`on_data`、`on_close`） | handler 值**就是**每连接状态 |
| `fib.HandlerFuncs{Data: ..., Close: ...}` | `fn_acceptor(|c| MyHandler { .. })` + `impl Handler` | |
| `c.SetAttachment(v)` / `c.Attachment()` | handler 的字段 | 有类型、没有 `any`、不加锁 |
| `*fib.Connection` | `Conn<H>`（`Clone + Send + Sync`） | |
| `c.Send`、`SendOwned`、`SendShared` | `send`、`send_owned`、`send_shared(SharedBuf)` | |
| `c.Cork()` / `c.Flush()` | `cork()` / `flush()` | 两者在回调内都是自动的 |
| `c.Close()` / `c.CloseAfterSend()` | `close()` / `close_after_send()` | |
| `c.HoldReads(bool)` | `hold_reads(bool)` | |
| `c.NotifyOutput(limit, fn)` | `queued_bytes()` + `on_drain(f)` | `on_drain` 在队列清空时触发 |
| `c.SendFile(f, off, n)` | `ResponseSlot::fill_parts` 配合 `Part::File`；HTTP 中用 `Response::from_file` | 没有直接的 `Conn::send_file` |
| `e.Dial(network, addr, timeout, done)` | `engine.dial(addr, acceptor, on_error)` | 没有超时参数：用 `idle_timeout` 或自己的定时器 |
| UDP 对端连接 | 相同：每个对端一个 `Conn`，每个数据报一次 `on_data` | |
| `DatagramsHandler` | 没有 | |
| `Config.ReadBufferSize`（16 KiB） | `Config::read_buffer`（64 KiB） | akio 中是每个 I/O 线程一个 |
| `Config.WriteBufferHighWatermark` | `Config::write_high_watermark`（256 KiB） | 两者都在四分之一处恢复 |
| `Config.MaxWriteQueueBytes`（以 `ErrSendQueueFull` 关闭） | `Config::max_queued_bytes`（64 MiB） | akio 返回 `Error::Overloaded` 并保留连接 |
| `Config.MaxPendingBytes` | 没有 | 只有每连接上限 |
| `Config.MaxConns` | `Config::max_connections` | akio 也计入 dial 的连接和 UDP 对端 |
| `Config.UDPIdleTimeout` | `Config::udp_idle_timeout`（60 s） | |
| `Config.Backlog` | `Config::backlog`（1024） | |
| `Config.IOPollers` / `IOPollerCount` | `Listener::threads(n)` | akio 没有执行回调的独立 worker 池 |
| `Config.BalanceReusePort` | `Listener::accel(Accel::Ebpf(..))` | 按 CPU 或一致性哈希分流，经典 BPF 无需特权 |
| `Config.WorkerCount`、`MaxEvents` | `PoolConfig::max_threads`、`queue_capacity` | 只用于显式的 `spawn_blocking` 任务 |
| `TaskPoolMode` | 无 | 线程池是自适应的 |
| `Engine.Stats()` | `engine.metrics()`，通过 `observe::metrics_handler` 输出 Prometheus | |
| `pprof` 中间件 | `observe::debug_handler`（连接、事件循环、慢回调、实时设置） | 不是 CPU profiler：用 `perf` |
| `LogSettings`、`fib/log` | `akio::log`（`akio-log` 门面），target 为 `akio` | |
| `prefork` | 没有 | |

## handler：从 worker 池到 I/O 线程

在 fib 中这样写没问题，因为 handler 运行在池中的 worker 上：

```go
Data: func(c *fib.Connection, data []byte) {
    row := db.Query(string(data)) // 阻塞的是一个 worker，不是事件循环
    c.Send(row)
},
```

在 akio 中同样的代码会让该线程上的所有连接停顿。把阻塞部分移走：

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:offload}}
```

`reserve_response` 保持回复按请求顺序发出；在 fib 中，这是由"同一连接一次只运行一轮"来保证的。
如果 handler 只做解析和回复，什么都不用改：它继续直接执行。

## HTTP

| fib `http` | akio-http |
|---|---|
| `fibhttp.NewHandler(h)` | `akio_http::serve(service)` |
| `func(c *fibhttp.Context)` | `Fn(&mut Context)` |
| `c.Respond(status, type, body)` | `ctx.bytes(status, type, body)`、`ctx.text(..)`、`ctx.respond(Response)` |
| `c.Retain()` ... `c.Release()` | `let d = ctx.detach()` ... `d.respond(resp)` |
| `c.OnBody(func(data, fin, err))` | `Streaming(svc)` + `ctx.on_body(|ctx, BodyEvent| ..)` |
| `http.ResponseWriter` 流式写、`Flush` | `ctx.stream_response(status, headers)` → `BodyStream` |
| `fibhttp.NewRouter()`、`r.Get`、`r.Route`、`r.Mount` | `Router::new().get(..)`、`nest(prefix, router)` |
| `{id:[0-9]+}`、`{name}`、`*` | 相同的模式（通配用 `*rest` 命名） |
| `r.Use(mw)`、`r.With(mw)`、`r.Group` | `router.layer(mw)`（包装此前注册的路由）；分组用嵌套 router |
| `middleware.Chain(app, recover.New(), ...)` | `.layer(middleware::recover())` ...（最后添加的在最外层） |
| `recover`、`requestid`、`logger`、`responsetime`、`limiter`、`cors`、`csrf`、`compress`、`etag` | `akio_http::middleware` 中同名；`logger` + `observe::access_log` |
| `FileCache` / `http.FileServer` | `files::Files::new(root)` |
| 兼容 net/http handler | 没有：akio-http 有自己的 `Context` |
| HTTP/2 服务端推送 | `ctx.push(path)` |
| 异步 HTTP 客户端 | `client::Client`（HTTP/1.1）、`h2client::H2Client` |
| `ConnectProxy` | `akio_socks::connect_proxy(engine_ref)` |

## 其他协议

| fib package | akio crate | 差异 |
|---|---|---|
| `tls`（crypto/tls 握手，自有记录层） | `akio::tls`（自研 TLS 1.3 / 1.2 与记录层） | `ServerConfig` / `ClientConfig` 构建器；不用 kTLS（已评估：比自研记录层慢，见[基准](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.zh-CN.md#内核-tlsktls评估)） |
| `websocket` | `akio-ws`（+ `Context::upgrade_websocket`） | 只交付完整消息（不按帧交付）；不支持基于 HTTP/2 或 HTTP/3 的 WebSocket；客户端停机时尚不发送 1001 |
| `http3`（自有 QUIC） | `akio-quic`（自研 QUIC）+ `akio-h3` | 无 QPACK 动态表、无推送、客户端无 Alt-Svc 自动切换 |
| `grpc` | `akio-grpc` | 字节或实现 `codec::Message` 的类型（prost 需启用 feature）；没有对应 protoc-gen-go-grpc 的代码生成器 |
| `arpc` | `akio-arpc` | 线路格式相同；无中间件 / coder 链 |
| `socks` | `akio-socks` | 只支持 CONNECT（无 BIND / UDP ASSOCIATE）；客户端不能经 SOCKS 拨号 |
| `mux` / `multiproto` | `akio-mux` | 基于规则的首字节嗅探 |
| `kcp` | `akio-kcp` | 线路兼容性相同（kcp-go 的 FEC 与加密）；只有消息回调（没有 `net.Conn` 式会话） |
| `webrtc`、`media`、`bittorrent` | 暂无（里程碑 M7） | |
| `prefork`、`filewatch` | 没有 | 用你自己的监视器触发 `Engine::reload` |

## 平台

fib 运行在 Linux、macOS、各 BSD 和 Windows 上。akio 首先面向 Linux（epoll、io_uring、eBPF），
macOS 上的 kqueue 用于开发；没有针对 BSD 的测试，也不支持 Windows。
