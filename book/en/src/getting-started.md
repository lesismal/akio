# Getting started

## Requirements

- Rust stable, 1.85 or newer (edition 2024).
- Linux for production (kernel 5.19+ for io_uring; any kernel with epoll otherwise). macOS works
  with the kqueue backend for development. Windows is not supported.

## Adding `only` to a project

The crates are not published on crates.io yet; depend on the repository. Pick the crates you
need: `only` is the engine, the others are protocols.

```toml
[dependencies]
only      = { git = "https://github.com/lesismal/only" }
only-http = { git = "https://github.com/lesismal/only" }   # HTTP/1.1, HTTP/2, Router
# only-ws, only-grpc, only-arpc, only-socks, only-mux,
# only-quic, only-h3, only-kcp: same form
```

TLS (`only::tls`) and eBPF steering (`only::ebpf`) are part of the `only` crate.

## A TCP echo server

A server is an **engine** with one or more **listeners**. Each listener has an **acceptor** that
creates one **handler** per connection; the handler's callbacks run on the connection's I/O
thread.

```rust,ignore
{{#include ../../../crates/only/examples/echo.rs}}
```

Run it and talk to it:

```console
$ cargo run --release -p only --example echo -- 127.0.0.1:7000
$ nc 127.0.0.1 7000
hello
hello
```

Three things to notice:

1. `on_data` gets a borrowed `&[u8]`: it is valid only during the call. Copy what you keep.
2. `c.send(..)` never blocks. It writes what the socket takes and queues the rest; inside a
   callback, everything you send is coalesced into one `writev` when the callback returns.
3. `engine.run()` is `start()` (spawn the I/O threads) followed by `wait()`.

## An HTTP server

```rust,ignore
{{#include ../../../crates/only-http/examples/hello.rs}}
```

```console
$ cargo run --release -p only-http --example hello
$ curl -i localhost:8080/users/7
$ curl --http2-prior-knowledge localhost:8080/   # HTTP/2 on the same port
```

The `/slow` route shows the rule you will meet everywhere in `only`: **handlers run on the I/O
thread and must not block**. When an answer needs slow work, detach the request and finish it
from another thread; see [Blocking work](concepts/blocking.md).

## The guide examples

Every chapter of this book is backed by a runnable example. They start a server on a free port,
exercise it with a client and exit:

| Example | Topic |
|---|---|
| `cargo run -p only --example guide-basics` | handlers, `Conn`, pool, ordering, dial, shutdown |
| `cargo run -p only --example guide-config` | every config knob, backends, metrics, reload, UDP |
| `cargo run -p only --example guide-tls` | TLS server and client |
| `cargo run -p only-http --example guide-http` | router, middleware, files, streaming, clients |
| `cargo run -p only-http --example guide-observe` | Prometheus, debug endpoint, access log, reload |
| `cargo run -p only-http --example guide-metrics` | your own counters, gauges, histograms, collectors |
| `cargo run -p only-http --example guide-bridge` | bridging to other runtimes and threads |
| `cargo run -p only-ws --example guide-ws` | WebSocket server and client |
| `cargo run -p only-grpc --example guide-grpc` | gRPC server and client |
| `cargo run -p only-arpc --example guide-arpc` | arpc calls, notifies, broadcast |
| `cargo run -p only-socks --example guide-socks` | SOCKS5 and HTTP CONNECT |
| `cargo run -p only-mux --example guide-mux` | several protocols on one port |
| `cargo run -p only-quic --example guide-quic` | QUIC server and client |
| `cargo run -p only-h3 --example guide-h3` | HTTP/3 server and client, WebSocket over HTTP/3, uploads |
| `cargo run -p only-kcp --example guide-kcp` | KCP with FEC and encryption |
| `cargo run -p only-webrtc --example guide-webrtc` | WebRTC data channel, STUN, TURN |
| `cargo run -p only-media --example guide-media-srt` | SRT publish, play and relay |
| `cargo run -p only-bittorrent --example guide-bittorrent` | tracker, seeder and magnet leecher |
| `cargo run -p only-dpdk --example guide-dpdk` | the userspace TCP/IP stack (in-memory wire) |

Two media examples serve until stopped instead, for ffmpeg to talk to:
`cargo run -p only-media --example guide-media` (RTMP, HTTP-FLV, HLS; `ONLY_MEDIA_SECS=n` stops
after n seconds) and `--example guide-media-rtsp` (RTSP, WHIP/WHEP; `ONLY_RTSP_SECS=n`).
`book/check-guides.sh` runs all of them, probes the serving ones and reports pass or fail.

Next: [Concepts](concepts/index.md).
