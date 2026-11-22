# Migrating from fib (Go)

`akio` is fib's Rust counterpart, so most concepts carry over. The biggest difference is **where
your code runs**: fib hands each read round to a worker pool by default, so a fib handler may
block; `akio` runs callbacks **inline on the connection's I/O thread**, so a `akio` handler must
not block, and blocking work is moved to the logical pool explicitly. Everything else follows
from that and from Rust's ownership rules.

## Concept map

| fib (Go) | `akio` (Rust) | Notes |
|---|---|---|
| `fib.New(config, fib.Binding{...})` | `Engine::builder().config(cfg).listen(Listener::tcp(addr).serve(acceptor)).build()?` | one `Listener` per binding address |
| `Binding{Network: "udp", ...}` | `Listener::udp(addr)` | Unix sockets are not supported |
| `Binding.Addrs` (several addresses) | one `Listener` per address | each listener has its own threads |
| `server.Run()` | `engine.run()` (= `start()` + `wait()`) | |
| `Shutdown(ctx)` | `shutdown()` + `wait()`, bounded by `Config::shutdown_timeout` | `Acceptor::on_shutdown` ≈ `ShutdownHandler.OnShutdown` |
| `Stop()` / `Close()` | `shutdown()` with a short `shutdown_timeout` | `akio` always closes connections when stopping |
| `fib.Handler` (`OnOpen`, `OnData`, `OnClose`) | `Acceptor::on_open` returns a `Handler` (`on_data`, `on_close`) | the handler value **is** the per-connection state |
| `fib.HandlerFuncs{Data: ..., Close: ...}` | `fn_acceptor(|c| MyHandler { .. })` + `impl Handler` | |
| `c.SetAttachment(v)` / `c.Attachment()` | fields of your handler | typed, no `any`, no lock |
| `*fib.Connection` | `Conn<H>` (`Clone + Send + Sync`) | |
| `c.Send`, `SendOwned`, `SendShared` | `send`, `send_owned`, `send_shared(SharedBuf)` | |
| `c.Cork()` / `c.Flush()` | `cork()` / `flush()` | automatic inside callbacks in both |
| `c.Close()` / `c.CloseAfterSend()` | `close()` / `close_after_send()` | |
| `c.HoldReads(bool)` | `hold_reads(bool)` | |
| `c.NotifyOutput(limit, fn)` | `queued_bytes()` + `on_drain(f)` | `on_drain` fires when the queue is empty |
| `c.SendFile(f, off, n)` | `ResponseSlot::fill_parts` with `Part::File`; `Response::from_file` in HTTP | no direct `Conn::send_file` |
| `e.Dial(network, addr, timeout, done)` | `engine.dial(addr, acceptor, on_error)` | no timeout argument: use `idle_timeout` or your own timer |
| UDP peer connections | same: one `Conn` per peer, one `on_data` per datagram | |
| `DatagramsHandler` | not available | |
| `Config.ReadBufferSize` (16 KiB) | `Config::read_buffer` (64 KiB) | per I/O thread in `akio` |
| `Config.WriteBufferHighWatermark` | `Config::write_high_watermark` (256 KiB) | resume at a quarter in both |
| `Config.MaxWriteQueueBytes` (closes with `ErrSendQueueFull`) | `Config::max_queued_bytes` (64 MiB) | `akio` returns `Error::Overloaded` and keeps the connection |
| `Config.MaxPendingBytes` | not available | per-connection limits only |
| `Config.MaxConns` | `Config::max_connections` | `akio` counts dialed connections and UDP peers too |
| `Config.UDPIdleTimeout` | `Config::udp_idle_timeout` (60 s) | |
| `Config.Backlog` | `Config::backlog` (1024) | |
| `Config.IOPollers` / `IOPollerCount` | `Listener::threads(n)` | `akio` has no separate worker pool for callbacks |
| `Config.BalanceReusePort` | `Listener::accel(Accel::Ebpf(..))` | CPU or consistent-hash steering, classic BPF unprivileged |
| `Config.WorkerCount`, `MaxEvents` | `PoolConfig::max_threads`, `queue_capacity` | only for explicit `spawn_blocking` work |
| `TaskPoolMode` | n/a | the pool is adaptive |
| `Engine.Stats()` | `engine.metrics()`, Prometheus via `observe::metrics_handler` | |
| `pprof` middleware | `observe::debug_handler` (connections, loops, slow callbacks, live settings) | not a CPU profiler: use `perf` |
| `LogSettings`, `fib/log` | `akio::log` (the `akio-log` facade), target `akio` | |
| `prefork` | not available | |

## Handlers: from worker pool to I/O thread

In fib this is fine, because the handler runs on a pool worker:

```go
Data: func(c *fib.Connection, data []byte) {
    row := db.Query(string(data)) // blocks a worker, not the event loop
    c.Send(row)
},
```

In `akio` the same code would stall every connection on the thread. Move the blocking part:

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:offload}}
```

`reserve_response` keeps replies in request order, which fib gives you by running one round of
a connection at a time. If a handler only parses and replies, nothing changes: it stays inline.

## HTTP

| fib `http` | akio-http |
|---|---|
| `fibhttp.NewHandler(h)` | `akio_http::serve(service)` |
| `func(c *fibhttp.Context)` | `Fn(&mut Context)` |
| `c.Respond(status, type, body)` | `ctx.bytes(status, type, body)`, `ctx.text(..)`, `ctx.respond(Response)` |
| `c.Retain()` ... `c.Release()` | `let d = ctx.detach()` ... `d.respond(resp)` |
| `c.OnBody(func(data, fin, err))` | `Streaming(svc)` + `ctx.on_body(|ctx, BodyEvent| ..)` |
| `http.ResponseWriter` streaming, `Flush` | `ctx.stream_response(status, headers)` → `BodyStream` |
| `fibhttp.NewRouter()`, `r.Get`, `r.Route`, `r.Mount` | `Router::new().get(..)`, `nest(prefix, router)` |
| `{id:[0-9]+}`, `{name}`, `*` | the same patterns (`*rest` names the wildcard) |
| `r.Use(mw)`, `r.With(mw)`, `r.Group` | `router.layer(mw)` (wraps routes registered so far); nest a router for groups |
| `middleware.Chain(app, recover.New(), ...)` | `.layer(middleware::recover())` ... (last added = outermost) |
| `recover`, `requestid`, `logger`, `responsetime`, `limiter`, `cors`, `csrf`, `compress`, `etag` | same names in `akio_http::middleware`; `logger` + `observe::access_log` |
| `FileCache` / `http.FileServer` | `files::Files::new(root)` |
| net/http handler compatibility | not available: akio-http has its own `Context` |
| HTTP/2 server push | `ctx.push(path)` |
| async HTTP client | `client::Client` (HTTP/1.1), `h2client::H2Client` |
| `ConnectProxy` | `akio_socks::connect_proxy(engine_ref)` |

## Other protocols

| fib package | `akio` crate | Differences |
|---|---|---|
| `tls` (crypto/tls handshakes, own record layer) | `akio::tls` (own TLS 1.3 / 1.2 and record layer) | `ServerConfig` / `ClientConfig` builders; no kTLS (evaluated: slower than the own record layer, [benchmarks](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md#kernel-tls-ktls-evaluation)) |
| `websocket` | `akio-ws` (+ `Context::upgrade_websocket`) | complete messages only (no per-frame delivery); no WebSocket over HTTP/2 or HTTP/3; client sends no 1001 on shutdown yet |
| `http3` (own QUIC) | `akio-quic` (own QUIC) + `akio-h3` | no QPACK dynamic table, no push, no Alt-Svc auto-switch in the client |
| `grpc` | `akio-grpc` | bytes or `codec::Message` types (prost with a feature); no protoc-gen-go-grpc equivalent code generator |
| `arpc` | `akio-arpc` | same wire format; no middleware/coder chain |
| `socks` | `akio-socks` | CONNECT only (no BIND / UDP ASSOCIATE); no SOCKS dialing for clients |
| `mux` / `multiproto` | `akio-mux` | first-bytes sniffing with rules |
| `kcp` | `akio-kcp` | same wire compatibility (kcp-go FEC and crypts); message callbacks only (no `net.Conn` sessions) |
| `webrtc`, `media`, `bittorrent` | not yet (milestone M7) | |
| `prefork`, `filewatch` | not available | trigger `Engine::reload` from your own watcher |

## Platform

fib runs on Linux, macOS, the BSDs and Windows. `akio` targets Linux first (epoll, io_uring,
eBPF) with kqueue on macOS for development; there is no BSD-specific testing and no Windows
support.
