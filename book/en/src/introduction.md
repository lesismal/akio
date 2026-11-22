# Introduction

[English](../en/) | [简体中文](../zh-CN/)

**`akio`** is an event-driven network library for Rust. It is the Rust counterpart of the Go
library [fib](https://github.com/lesismal/fib): the same feature surface, built the Rust way:
ownership instead of a garbage collector, `Send`/`Sync` boundaries instead of conventions,
sans-io protocol state machines, and no async runtime.

```text
           your Handler / Service / WsHandler / QuicHandler ...
                 │ callbacks, inline on the connection's I/O thread
 ┌───────────────┴─────────────────────────────────────────────────┐
 │ akio-http  akio-ws  akio-grpc  akio-arpc  akio-socks  ...  │  protocols (sans-io)
 │ akio-tls (Transport layer)        akio-quic / akio-kcp (UDP) │
 ├─────────────────────────────────────────────────────────────────┤
 │ akio (Engine, Listener, Backend, Accel)   akio-core (Conn)    │
 ├─────────────────────────────────────────────────────────────────┤
 │ akio-epoll (epoll / kqueue)   akio-uring (io_uring)           │  one backend per listener
 │ akio-ebpf (SO_REUSEPORT steering, sockmap relay)               │  optional acceleration
 └─────────────────────────────────────────────────────────────────┘
```

## What makes `akio` different

- **Thread-per-core.** Every connection belongs to exactly one I/O thread for its whole life.
  Your callbacks run inline on that thread, so per-connection state needs no lock and no
  `Sync`.
- **Callbacks, not futures.** A `Handler` gets `on_data(&mut self, conn, bytes)`. There is no
  executor, no task per connection and no `.await` on the hot path.
- **A thread-safe connection handle.** `Conn` is `Clone + Send + Sync`: any thread may `send`,
  `close` or pause reads, and nothing ever blocks.
- **An explicit pool for blocking work.** `Conn::spawn_blocking` runs work on a bounded,
  adaptive *logical pool* and brings the result back to the connection's own I/O thread, with
  ordered response slots for pipelined protocols.
- **Per-listener backends.** One engine can serve an HTTP listener on io_uring next to an RPC
  listener on epoll, each with its own threads; eBPF steering is an orthogonal layer.
- **Many protocols on one core.** TCP, UDP, TLS, HTTP/1.1, HTTP/2, WebSocket, HTTP/3 and QUIC,
  gRPC, arpc, SOCKS4/5 and HTTP CONNECT, KCP, and port sharing by sniffing.

## How to read this book

- New to `akio`: [Getting started](getting-started.md), then the [Concepts](concepts/index.md)
  chapters. They are short and explain the rules every protocol crate follows.
- Looking for a protocol: the [Protocols](protocols/index.md) part has one chapter per crate.
- Running `akio` in production: [Configuration](configuration.md),
  [Observability](observability.md), [Performance tuning](performance.md) and
  [Troubleshooting](troubleshooting.md).
- Coming from Go, tokio or axum: the [migration guides](migration/from-fib.md).
- Curious about the internals: [Architecture](architecture.md).

Every Rust snippet in this book is included from an example program in the repository and is
compiled by `cargo build --workspace --examples`; the file name is given with each snippet so you
can run it (`cargo run -p <crate> --example <name>`).

## Status

`akio` is approaching 1.0. Linux is the first-class platform (epoll, io_uring, eBPF); macOS uses
kqueue and is meant for development. Windows is not supported. What is done and what is not is
tracked milestone by milestone in
[docs/DEV-PLAN.md](https://github.com/lesismal/akio/blob/main/docs/DEV-PLAN.md); measured
performance is in
[docs/BENCHMARKS.md](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md).
