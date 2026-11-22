# Performance tuning

Measure before tuning. The numbers quoted here come from
[docs/BENCHMARKS.md](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md): one
Docker VM on a laptop-class Mac, loopback, 4 server threads. Treat them as direction, not as a
ranking. In that report `akio`'s TCP echo was in the same class as tokio and ahead of fib (ahead
of tokio at 512 connections, about 15% behind at 64 connections and at 16 KiB messages), UDP
echo was level with fib, and moving 5 ms of blocking work to the logical pool gave about 58× the
throughput of blocking inline. `tools/bench/run.sh` reproduces the runs; `tools/echo-bench` is the
load generator.

## 1. Keep the I/O threads free

Nothing else matters if callbacks block. Watch `akio_slow_callbacks_total` and
`akio_loop_callback_seconds_total`; lower `slow_callback_threshold` (to 1–10 ms) in staging to
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
- Other io_uring features were measured on Linux 7.0 and left out, since none gained a clear 3%
  without losing elsewhere (see the benchmark report, "io_uring features evaluation"):
  registered files and a registered ring fd (in steady state the backend submits no entry per
  request: the multishot recv stays armed and responses are written directly), `MSG_RING`
  wake-ups instead of the eventfd (−1.3% to +4.8% on `spawn_blocking` round trips, noise elsewhere),
  ring-based sends (`IORING_OP_SEND`: +1–4% and 2–6% less CPU per request in a bare-ring prototype,
  but the engine writes from any thread, so adopting them means redesigning the write path), and
  `SEND_ZC`, which on loopback or veth always falls back to copying and was 12–27% slower from
  16 KiB up. Zero-copy sends are worth re-measuring only with a real NIC
  (`tools/bench/uring-eval.sh`).
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
- `Conn::send_segments` sends many datagrams in one call (akio-quic uses it).
- `Config::udp_gro` (on by default where the kernel supports it) lets bulk receivers of GSO
  traffic (QUIC downloads) take a whole GSO batch in one receive: QUIC bulk on loopback went from
  6.4 to 9.8 Gbit/s with it, and 64-byte UDP echo did not change measurably. It needs
  `read_buffer` >= 64 KiB; `AKIO_UDP_GRO=0` turns it off.
- `udp_max_peers` caps per-peer state under floods.

## 6. eBPF steering

`Accel::Ebpf` decides which I/O thread gets each new connection or UDP peer:

- `Steering::Cpu` keeps a flow on the thread matching the CPU that received its packets. Combine
  it with NIC RSS/RPS and `EbpfConfig::pin_threads` (thread `i` runs on the CPUs `c % n == i`)
  for cache locality.
- `Steering::Hash` (consistent hashing by source IP, or IP and port) keeps a client on the same
  thread across reconnects, useful for per-client caches.

Classic BPF works unprivileged; check `Engine::accel_status()` to see what was attached.

For proxies, `ProxyConfig::sockmap` splices tunnels in the kernel. In the
[benchmark](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md#ebpf-acceleration-toolsbenchebpfsh)
it doubled a SOCKS upload's throughput, at more CPU per byte over loopback.
`ebpf::xdp::RateLimiter` drops floods from a few sources before the network stack sees them.

## 7. TLS

TLS throughput was within noise of tokio-rustls in the report (TLS 1.3, 1 KiB records). Enable
session resumption (`ticketer`) to make reconnects cheap; offer `h2` in ALPN so HTTP clients
multiplex instead of opening more connections. Kernel TLS in software is off by default: on
x86_64 with VAES it was slower than akio-tls's own record layer, `sendfile` of large files
included ([measurements](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md#kernel-tls-ktls-evaluation)).
On a NIC with TLS offload (ConnectX-6 Dx and later), build with the `ktls` feature and set
`.ktls(Ktls::Hardware)`: the NIC then does the record crypto and `sendfile` stays zero-copy, and
hosts without such a NIC are unaffected ([TLS](protocols/tls.md#kernel-tls)).

## 8. Operating system

Usual Linux settings for many connections apply: raise the file descriptor limit (`ulimit -n`),
`net.core.somaxconn` to at least `Config::backlog`, and the local port range for clients making
many outbound connections. `max_connections` and `idle_timeout` keep the process within those
limits.
