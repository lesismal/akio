# 协议复用

`flash-mux` 在一个监听端口上提供多种协议，按每个客户端发来的前几个字节区分它们。

```rust,ignore
{{#include ../../../../crates/flash-mux/examples/guide-mux.rs:mux}}
```

规则按路由添加的顺序尝试：

| `Rule` | 匹配 |
|---|---|
| `Tls` | TLS ClientHello（`0x16 0x03 ..`） |
| `Http1` | 以已知方法开头的 HTTP/1.x 请求行 |
| `Http2` | HTTP/2 连接前言（明文 prior knowledge） |
| `Http` | 上面两者之一：即 flash-http 提供的内容 |
| `Socks5`、`Socks4` | SOCKS 版本 5 / 4 及 4a |
| `Prefix(bytes)` | 以这些字节开头的数据 |
| `Custom(Arc<dyn Fn(&[u8]) -> Decision>)` | 自定义判断：`Yes`、`No` 或 `NeedMore` |

`fallback(acceptor)` 接收不匹配任何规则、或在 `max_sniff(n)` 字节（默认 64）内仍无法判断的
连接；没有 fallback 时这些连接被关闭。用 `Listener::serve_any(mux.into_any())` 提供 mux。在
开始提供服务之前完成全部配置。

一旦某条规则匹配，连接就归该路由的 acceptor 所有，如同由它 accept 的一样：嗅探到的字节会重放
给它的 handler，`spawn_blocking` 的完成回调会送达它，优雅停机调用的也是*它的* `on_shutdown`。
路由可以是 `Tls::server(..)` acceptor（嗅探之后再终止 TLS），也可以是另一个 `Mux`
（`route_dyn`）。

**服务端先发言**的协议（SMTP、MySQL、SSH 横幅等）无法用这种方式识别，请给它们单独的端口。
