# Performance tuning

Measure before tuning. The numbers quoted here come from
[docs/BENCHMARKS.md](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.md): one
Docker VM on a laptop-class Mac, loopback, 4 server threads. Treat them as direction, not as a
ranking. In that report `only`'s TCP echo was in the same class as tokio and ahead of fib (ahead
of tokio at 512 connections, about 15% behind at 64 connections and at 16 KiB messages), UDP
echo was level with fib, and moving 5 ms of blocking work to the logical pool gave about 58× the
throughput of blocking inline. `tools/bench/run.sh` reproduces the runs; `tools/echo-bench` is the
load generator.

## 1. Keep the I/O threads free

Nothing else matters if callbacks block. Watch `only_slow_callbacks_total` and
`only_loop_callback_seconds_total`; lower `slow_callback_threshold` (to 1–10 ms) in staging to
find offenders; move blocking work to `spawn_blocking`, `Context::detach`, or your own threads.
See [Blocking work](concepts/blocking.md).

## 2. Threads

- `Listener::threads(n)` defaults to one per core **per listener**. With several busy listeners
  the total can exceed the core count; give secondary listeners fewer threads.
- Client-heavy services (proxies, gateways) should have `client_threads(n)` so upstream
  connections do not compete with accepted ones.
- The logical pool should match what the blocking work waits on (database connections, disk
  queue depth), not the core count.
- Load is balanced per connection. Few, very busy connections (a handful of HTTP/2 clients
  multiplexing everything) cannot use more threads than they have connections.

## 3. Backend choice

- **epoll** is the default and the baseline. Reads are level-triggered from one scratch buffer
  per thread; writes go straight to the socket from whichever thread calls `send`.
- **io_uring** (Linux 5.19+) uses multishot accept/recv and a provided-buffer ring, so idle
  connections hold no read buffer, and returning a buffer is a memory write. It was 10–25% ahead
  of epoll when the server was the bottleneck (one server thread, 512 connections) and within a
  few percent, either way, when the client was. Try it for many-connection, server-bound
  workloads, measure, and keep the one that wins; per-listener choice lets you mix.
  `sqpoll` trades a busy kernel thread for fewer syscalls; it only pays off at sustained high
  load.
- UDP always uses the readiness backend with `recvmmsg`/`sendmmsg`.

## 4. Buffers and writes

- `Config::read_buffer` (64 KiB) is per I/O thread, not per connection. Larger helps bulk
  transfers; it is also the most one `on_data` call sees. io_uring instead keeps a ring of 1024
  provided buffers of `min(read_buffer, 16 KiB)` per thread (16 MiB by default).
- Everything sent inside a callback leaves in one `writev`. From other threads, batch with
  `cork()` ... `flush()`, or build one buffer and `send_owned` it.
- Use `send_owned(Vec<u8>)` for buffers you already own (no copy when queueing) and
  `send_shared(SharedBuf)` / `PreparedMessage` / `Server::broadcast` to encode a broadcast once.
- `write_high_watermark` bounds memory per slow reader; raising it helps throughput to fast
  readers with large responses at the cost of memory.
- Static files above `max_cached_bytes` go out with `sendfile(2)` on plain TCP; keep the
  in-memory cache for small, hot files.

## 5. UDP: GSO, GRO, batching

- On Linux, receives use `recvmmsg`; the replies produced for a receive batch leave with
  `sendmmsg`, and equal-size runs to one peer as a single GSO send. In the UDP batching work this
  cut server CPU per datagram by 30–46% for bursts and raised 64-byte echo by about 19%.
- `Conn::send_segments` sends many datagrams in one call (only-quic uses it).
- `Config::udp_gro = true` helps bulk receivers of GSO traffic (QUIC downloads) and costs for
  small request/response traffic. It needs `read_buffer` >= 64 KiB.
- `udp_max_peers` caps per-peer state under floods.

## 6. eBPF steering

`Accel::Ebpf` decides which I/O thread gets each new connection or UDP peer:

- `Steering::Cpu` keeps a flow on the thread matching the CPU that received its packets. Combine
  it with NIC RSS/RPS and pinned I/O threads for cache locality (thread pinning itself is not
  provided by `only` yet).
- `Steering::Hash` (consistent hashing by source IP, or IP and port) keeps a client on the same
  thread across reconnects, useful for per-client caches.

Classic BPF works unprivileged; check `Engine::accel_status()` to see what was attached. No
eBPF benchmark has been published yet.

## 7. TLS

TLS throughput was within noise of tokio-rustls in the report (TLS 1.3, 1 KiB records). Enable
session resumption (`ticketer`) to make reconnects cheap; offer `h2` in ALPN so HTTP clients
multiplex instead of opening more connections. kTLS is not implemented.

## 8. Operating system

Usual Linux settings for many connections apply: raise the file descriptor limit (`ulimit -n`),
`net.core.somaxconn` to at least `Config::backlog`, and the local port range for clients making
many outbound connections. `max_connections` and `idle_timeout` keep the process within those
limits.
