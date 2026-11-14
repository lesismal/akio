# only

English | [简体中文](README.zh-CN.md)

`only` is an event-driven, thread-per-core network library for Rust, the Rust counterpart of the
Go library [fib](https://github.com/lesismal/fib). Callbacks run inline on the connection's I/O
thread, a cloneable `Conn` handle can be used from any thread, blocking work goes to an explicit
logical pool, and each listener picks its own backend (epoll/kqueue or io_uring) with optional
eBPF steering. There is no async runtime. (Formerly named *flash*; renamed before 1.0.0, see
[CHANGELOG.md](CHANGELOG.md).)

**Documentation:** [the `only` book](https://lesismal.github.io/only/en/) ·
[architecture](docs/architecture.md) · [migration from fib, tokio, hyper/axum](https://lesismal.github.io/only/en/migration/from-fib.html) ·
API reference: `cargo doc --workspace --no-deps --open`

## Features

| Area | What is there |
|---|---|
| Engine | per-listener backends: epoll (Linux), kqueue (macOS), io_uring (Linux 5.19+, falls back to epoll); thread-per-core I/O threads; `SO_REUSEPORT` accept distribution; eBPF/classic-BPF steering (`Accel::Ebpf`) and an in-kernel sockmap relay |
| Connections | `Conn` is `Clone + Send + Sync`; non-blocking `send` from any thread with direct writes, corking, `writev`, `sendfile`; backpressure (watermarks, `hold_reads`, `on_drain`, `max_queued_bytes`); idle timeouts; async dial; graceful shutdown |
| Blocking work | adaptive bounded logical pool, `Conn::spawn_blocking` with completions back on the I/O thread, ordered response slots, slow-callback detection |
| UDP | one `Conn` per peer, `recvmmsg`/`sendmmsg`, UDP GSO/GRO, peer caps, UDP dial |
| TLS | rustls as a connection transport (server and client, ALPN, SNI) |
| HTTP | HTTP/1.1 and HTTP/2 (h2spec 147/147) on one port, pipelining, streaming both ways, Router (static/regexp/param/wildcard), 9 middlewares, static files with `sendfile`, HTTP/1 and HTTP/2 clients |
| WebSocket | server and client, permessage-deflate, Autobahn 100% (server and client) |
| HTTP/3 and QUIC | own QUIC v1 (RFC 9000/9001/9002, datagrams, migration, Retry, key updates, GSO), HTTP/3 serving the same `Router`, H3 client; interop with quic-go and fib |
| RPC | gRPC (unary and streaming, interop with grpc-go), arpc (wire-compatible with lesismal/arpc and fib) |
| Proxies | SOCKS5/4/4a, HTTP CONNECT, port sharing by first-byte sniffing (only-mux) |
| KCP | wire-compatible with skywind3000/kcp and kcp-go (FEC, crypts) |
| BitTorrent | trackers (HTTP/UDP, client and server), peer wire with MSE, Fast extension, metadata exchange and PEX, uTP (LEDBAT), mainline DHT, a client; interop with libtorrent and aria2 |
| Streaming media | only-media: one stream hub (GOP cache, slow-player dropping, auth hooks, stats) behind RTMP (digest handshake, Enhanced RTMP H.265/Opus), RTSP server (TCP and UDP, record and play), SRT live (ARQ, TSBPD, AES encryption, caller push/pull), HTTP-FLV, WS-FLV, HLS (MPEG-TS, LL-HLS parts, blocking reload) and WHIP/WHEP signalling; interop-tested with ffmpeg |
| WebRTC, STUN, TURN | str0m-based WebRTC (ICE-lite server and full ICE agent, DTLS-SRTP, data channels, RTP/RTCP media) on a pure-Rust crypto stack; STUN and TURN servers; interop with pion and coturn |
| Operations | Prometheus metrics, connection table, slow-callback records, JSON debug endpoint, structured logs via `log`, hot reload of runtime settings; multi-process prefork serving with worker restarts and zero-downtime reload ([only-prefork](crates/only-prefork/README.md)) |

Measured performance (one machine, see the caveats): [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Quick start

```toml
[dependencies]
only = { git = "https://github.com/lesismal/only" }
```

```rust
use only::{Conn, Engine, Handler, Listener, fn_acceptor};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data); // non-blocking, inline on the I/O thread
    }
}

fn main() -> std::io::Result<()> {
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:7000".parse().unwrap())
            .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
        .build()?;
    engine.run()
}
```

More: `cargo run -p only --example guide-basics`, `cargo run -p only-http --example hello`,
and the other `guide-*` examples listed in the book's
[Getting started](https://lesismal.github.io/only/en/getting-started.html).

## Status

Milestones M0–M5 are done and production observability (M6) is in place; DPDK, chaos tests and
the M7 protocols (media, WebRTC, BitTorrent) are not. Linux is the first-class platform; macOS is
for development; Windows is not supported. Plan and progress: [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/DEV-PLAN.md](docs/DEV-PLAN.md), design decisions in [docs/adr](docs/adr/README.md).

The current version is `1.0.0-rc.1`: the API is frozen for review. From 1.0.0 on `only` follows
semver as described in [docs/api-stability.md](docs/api-stability.md) (covered crates, MSRV 1.85,
platform tiers) and [docs/deprecation.md](docs/deprecation.md); changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## Building the docs

```console
$ cargo install mdbook --locked --version 0.4.52
$ book/build.sh          # checks and compiles every snippet, builds target/book/{en,zh-CN}
```

See [book/README.md](book/README.md).

## License

MIT
