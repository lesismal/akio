# 协议复用

`akio-mux` 在一个监听端口上提供多种协议，按每个客户端发来的前几个字节区分它们。

```rust,ignore
{{#include ../../../../crates/akio-mux/examples/guide-mux.rs:mux}}
```

规则按路由添加的顺序尝试（更早的路由尚未决定时，后面的匹配会等待，因此放在 `Tls` 之前的 SNI 路由能看到
完整的 hello）：

| `Rule` | 匹配 |
|---|---|
| `Tls` | TLS ClientHello（`0x16 0x03 ..`） |
| `TlsSni(SniMatcher)` | 服务器名匹配的完整 ClientHello（精确名或单标签 `*.` 通配） |
| `TlsHello(Arc<dyn Fn(&ClientHello) -> bool>)` | 你的函数接受的完整 ClientHello（服务器名、ALPN） |
| `Http1` | 以已知方法开头的 HTTP/1.x 请求行 |
| `Http2` | HTTP/2 连接前言（明文 prior knowledge） |
| `Http` | 上面两者之一：即 akio-http 提供的内容 |
| `Socks5`、`Socks4` | SOCKS 版本 5 / 4 及 4a |
| `Prefix(bytes)` | 以这些字节开头的数据 |
| `Custom(Arc<dyn Fn(&[u8]) -> Decision>)` | 自定义判断：`Yes`、`No` 或 `NeedMore` |

`fallback(acceptor)` 接收不匹配任何规则、或在 `max_sniff_bytes(n)` 字节（默认 64）内仍无法判断的
连接；没有 fallback 时这些连接被关闭。用 `Listener::serve_any(mux)`（`Mux` 可转换为类型擦除的 `akio::AnyAcceptor`） 提供 mux。在
开始提供服务之前完成全部配置。

`sniff_timeout(Some(d))`（默认 5 s）限制客户端发送足以判断的字节所用的时间：沉默的客户端、或慢慢
发送多条规则共有前缀的客户端，在截止时被关闭（不会交给 fallback）。`sniff_timeout(None)` 表示
一直等待。

一旦某条规则匹配，连接就归该路由的 acceptor 所有，如同由它 accept 的一样：嗅探到的字节会重放
给它的 handler，`spawn_blocking` 的完成回调会送达它，优雅停机调用的也是*它的* `on_shutdown`。
路由可以是 `Tls::server(..)` acceptor（嗅探之后再终止 TLS），也可以是另一个 `Mux`
（`route_any`）。

## 按服务器名透传 TLS

`TlsSni` 和 `TlsHello` 读取 ClientHello 但不终止 TLS：路由原样收到 hello 的字节，可以把它转发给上游。
hello 可以分多次读取、跨多个 TLS 记录到达；带有这类路由的 mux 默认嗅探到 `TLS_SNIFF_BYTES`
（16 KiB + 5），除非 `max_sniff_bytes` 另有设置，并且仍受 `sniff_timeout` 约束。畸形的 hello 或没有
服务器名的 hello 不匹配 `TlsSni`；在 SNI 路由之后放 `Rule::Tls` 接住其余的。解析器
`akio_mux::tls::parse_client_hello` 也可单独使用。

```rust,ignore
let mux = Mux::new()
    .route(Rule::TlsSni(SniMatcher::new(["api.example.com", "*.apps.example.com"])), relay_a)
    .route(Rule::TlsHello(Arc::new(|h: &ClientHello| h.offers_alpn(b"h2"))), relay_h2)
    .route(Rule::Tls, Tls::server(cfg, app))
    .fallback(other);
```

## PROXY 协议

在负载均衡器之后，用 `akio_mux::proxy::ProxyProtocol` 包住监听器的 acceptor：它在下一个 acceptor
运行之前读取 v1 或 v2 头部（TLV、LOCAL、IPv4 / IPv6 / Unix），然后把连接连同头部之后的字节交出去。
畸形的头部、超过 `max_header_bytes`（4096）的头部或在 `header_timeout`（5 秒）内未完整的头部会关闭
连接。`allow_missing(true)` 放行没有头部的连接；`trusted(f)` 只读取来自负载均衡器地址的头部。

```rust,ignore
let pp = ProxyProtocol::new_any(mux).trusted(|peer| peer.ip().is_loopback());
// 在 handler 中：
let client = akio_mux::proxy::client_addr(&conn); // 头部中的来源地址，否则为 peer_addr
let tlvs = akio_mux::proxy::header(&conn).map(|h| h.tlvs.clone());
```

`Conn::peer_addr` 仍是套接字的对端。要在出站连接上发送头部，构造 `ProxyHeader::proxy(source,
destination)`，并在拨号处理器的 `on_open` 中首先调用 `proxy::send_header(&conn, &h, Version::V2)`。

**服务端先发言**的协议（SMTP、MySQL、SSH 横幅等）无法用这种方式识别，请给它们单独的端口。
