# Getting started

## Requirements

- Rust stable, 1.85 or newer (edition 2024).
- Linux for production (kernel 5.19+ for io_uring; any kernel with epoll otherwise). macOS works
  with the kqueue backend for development. Windows is not supported.

## Adding flash to a project

The crates are not published on crates.io yet; depend on the repository. Pick the crates you
need: `flash` is the engine, the others are protocols.

```toml
[dependencies]
flash      = { git = "https://github.com/lesismal/flash" }
flash-http = { git = "https://github.com/lesismal/flash" }   # HTTP/1.1, HTTP/2, Router
# flash-ws, flash-grpc, flash-arpc, flash-socks, flash-mux,
# flash-quic, flash-h3, flash-kcp: same form
```

TLS (`flash::tls`, on rustls) and eBPF steering (`flash::ebpf`) are part of the `flash` crate.

## A TCP echo server

A server is an **engine** with one or more **listeners**. Each listener has an **acceptor** that
creates one **handler** per connection; the handler's callbacks run on the connection's I/O
thread.

```rust,ignore
{{#include ../../../crates/flash/examples/echo.rs}}
```

Run it and talk to it:

```console
$ cargo run --release -p flash --example echo -- 127.0.0.1:7000
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
{{#include ../../../crates/flash-http/examples/hello.rs}}
```

```console
$ cargo run --release -p flash-http --example hello
$ curl -i localhost:8080/users/7
$ curl --http2-prior-knowledge localhost:8080/   # HTTP/2 on the same port
```

The `/slow` route shows the rule you will meet everywhere in flash: **handlers run on the I/O
thread and must not block**. When an answer needs slow work, detach the request and finish it
from another thread; see [Blocking work](concepts/blocking.md).

## The guide examples

Every chapter of this book is backed by a runnable example. They start a server on a free port,
exercise it with a client and exit:

| Example | Topic |
|---|---|
| `cargo run -p flash --example guide-basics` | handlers, `Conn`, pool, ordering, dial, shutdown |
| `cargo run -p flash --example guide-config` | every config knob, backends, metrics, reload, UDP |
| `cargo run -p flash --example guide-tls` | TLS server and client |
| `cargo run -p flash-http --example guide-http` | router, middleware, files, streaming, clients |
| `cargo run -p flash-http --example guide-observe` | Prometheus, debug endpoint, access log, reload |
| `cargo run -p flash-http --example guide-bridge` | bridging to other runtimes and threads |
| `cargo run -p flash-ws --example guide-ws` | WebSocket server and client |
| `cargo run -p flash-grpc --example guide-grpc` | gRPC server and client |
| `cargo run -p flash-arpc --example guide-arpc` | arpc calls, notifies, broadcast |
| `cargo run -p flash-socks --example guide-socks` | SOCKS5 and HTTP CONNECT |
| `cargo run -p flash-mux --example guide-mux` | several protocols on one port |
| `cargo run -p flash-quic --example guide-quic` | QUIC server and client |
| `cargo run -p flash-h3 --example guide-h3` | HTTP/3 server and client |
| `cargo run -p flash-kcp --example guide-kcp` | KCP with FEC and encryption |

Next: [Concepts](concepts/index.md).
