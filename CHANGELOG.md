# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to `akio` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and `akio` adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Added: the process's effective user (akio-sys)

akit's A247, for its LLM node, which runs root commands through `sudo -n` only when it is not root
(as fit's `os.Geteuid() != 0`). `akio_sys::process::euid()` is the process's effective user id
(`geteuid(2)`, which cannot fail): `0` when it runs as root. Linux and macOS, through the own
`ffi` bindings.

### Added: the QUIC server's handshake bounds (akio-quic)

akit's A245, for its tunnel hub's QUIC listener (fit's `handshake_timeout` and `max_handshakes`);
ADR-185. `ServerConfig::handshake_timeout(Option<Duration>)` (default 10 s,
`DEFAULT_HANDSHAKE_TIMEOUT`): a connection whose handshake is not done by then is dropped without a
`CONNECTION_CLOSE`, its handler's `on_close` getting `TimedOut`. `ServerConfig::max_handshakes(n)`
(default 8192, `DEFAULT_MAX_HANDSHAKES`): from half of them in progress, a client without a valid
token proves its address with a Retry first (before, from a fixed 4096); at the limit a new
client's Initial is dropped unanswered, keeping no state, and counted by
`QuicServer::refused_connections()`. Behaviour change: handshakes used to be bounded only by the
idle timeout (30 s, renewed by every client packet), and handshakes in progress not at all.

### Added: a WebSocket ended at once, what is queued dropped (akio-ws, akio-http, akio-h3, akio-quic)

akit's A238, for its tunnel's WebSocket links (a failed link, a kicked peer, a revoked token, a role
stopped); ADR-184. `WsSender::abort()` ends a WebSocket now, without a close frame: what is queued
and not yet written is dropped, later sends fail with `Closed`, nothing more reaches the handler,
and both ends' `on_close` hear 1006. Over TCP or TLS the connection is closed; over HTTP/2 the
stream is reset (`CANCEL`) and over HTTP/3 reset both ways (`H3_REQUEST_CANCELLED`), the connection
going on. Server and client sides, from any thread or the handler's callbacks; it also cuts short a
close handshake under way. For it, akio-quic's `Connection::notify()` has the handler's new
`QuicHandler::on_notify` run on the thread that delivers the connection's events (several calls
before it runs make one; never after `on_close`).

### Fixed: waiting for the engine from a thread-local's destructor (akio-pool, akio)

akit's A237. `Engine::wait` asks `Pool::is_current` whether it runs on a logical-pool thread, which
read akio-pool's thread-local `CURRENT` with `with`: an engine waited for (or dropped) by another
thread-local's destructor as its thread exits found `CURRENT` destroyed already, panicked, and the
panic, in a thread-local destructor, aborted the process. `Pool::is_current`, `on_pool_thread` and
`blocking` read it with `try_with` now, a destroyed `CURRENT` taken as not a pool thread.

### Added: a WebSocket's reads held, its drain heard, and its peer's address (akio-ws, akio-http, akio-h3)

akit's A236, for its tunnel's WebSocket links and its LLM mesh; ADR-183. `WsSender` gets
`hold_reads(bool)` (the connection's reads over TCP or TLS; the stream's over HTTP/2 and HTTP/3,
whose window is then not given back), `on_drain(f)` (once `queued_bytes()` is back to 0, or the
connection closes; over HTTP/3 once the QUIC stream's send buffer has room), `peer_addr()`,
`set_relayed(bool)` and `set_max_queued_bytes(Option<usize>)` (the connection's, over TCP or TLS;
over HTTP/2 and HTTP/3 the first does nothing and the second fails with `Unsupported`). On the
server (`Context::upgrade_websocket`, HTTP/1.1, HTTP/2 and HTTP/3) and the client sides
(`akio_ws::client`, `H2Client::websocket`, `H3Client::websocket`), from any thread.

### Fixed: `akio_ws::client::dial_blocking` forwards `on_message_ref` (akio-ws)

The wrapper that hands the sender back forwarded `on_message` only, so a handler implementing
`on_message_ref` alone got no messages through `dial_blocking`.

### Added: a pinned server certificate in the TLS client (akio-tls, akio-quic)

akit's A235, for its tunnel's and LLM mesh's links to self-signed hubs; ADR-182.
`ClientConfigBuilder::pin_sha256(pins)`: the SHA-256 of the server's leaf certificate must be one of
`pins` (compared in constant time), in place of the chain, the name and the dates, as Go's
`VerifyPeerCertificate` under `InsecureSkipVerify`; otherwise the handshake fails with
`bad_certificate`. The leaf's key still verifies the server's handshake signature. QUIC clients
built from such a configuration (`akio_quic::client_config_from`) are pinned too; an empty list
fails `build`.

### Added: a connection's own bound of its send queue (akio-core, akio)

akit's A234, for its tunnel's and LLM mesh's links, whose queues hold their streams' windows;
ADR-181. `Conn::set_max_queued_bytes(Some(n))` (also on `ConnHandle`) gives a connection a bound
of its own in place of the engine's `Config::max_queued_bytes`, `None` restores the engine's, and
`Conn::max_queued_bytes()` reads the bound in force. Callable from any thread; the next send is
checked against it (as are `send_room`, HTTP/1.1's held-back ordered responses and files sent
through a transport). Lowering it below what is queued drops nothing; `write_high_watermark` is
unchanged. `WriteState` is 16 bytes larger.

### Added: connection handles, close deadlines, and a listener's accept and close hooks (akio-core, akio, akio-http)

akit's A232, for its console's connection rules (fit's: no login, closed 5 s after accept; a
session, 2 minutes idle; past `max_conns`, the oldest unauthenticated connection evicted);
ADR-180. `ConnHandle` (akio-core, re-exported by `akio`; `Conn::handle()`) is a cloneable,
thread-safe handle without the handler type: `id`, `is_open`, addresses, `close`,
`set_idle_timeout`, and a close deadline, `close_at` / `close_after` (closed then whatever the
connection sends; the last one set is in force) and `cancel_close`, run by a timer on the
connection's own I/O thread. `Listener::on_accept` tells an application of every connection
accepted (after the filter and `max_connections`, before TLS and `on_open`) and
`Listener::on_close` of every one closed (exactly once for each, panics and refused connections
included), so it can keep a table of them and close the one it chooses. In akio-http,
`Context::connection()` gives a request's connection (HTTP/1.1 and HTTP/2; `None` on HTTP/3).
`ConnInner` is 8 bytes larger; a listener without hooks is unchanged.

### Added: a terminal's echo turned off, and raw mode (akio-sys)

akit's A233, for `akit hash-password` at a terminal. `akio_sys::terminal::no_echo(fd)` turns
`ECHO` off (line editing and Ctrl-C kept, as Go's `term.ReadPassword`), `terminal::raw(fd)` puts
the terminal in raw mode (as `cfmakeraw` and Go's `term.MakeRaw`: a key at a time, no echo, no
signals from keys); both return a `TerminalGuard` that puts back the modes it found when dropped
or `restore`d, and both fail (`ENOTTY`) for a descriptor that is not a terminal.
`terminal::echo_enabled(fd)` reads the echo bit. Linux and macOS, through the own `ffi`
bindings (`termios`, `tcgetattr`, `tcsetattr`, checked against `libc`); tested on a
pseudo-terminal.

### Added: Argon2id, BLAKE2b and XChaCha20-Poly1305 (akio-crypto)

akit's A230 and A231, for fit's encrypted store; ADR-179. `kdf::argon2id(password, salt, time,
memory_kib, lanes, out)` is Argon2id (RFC 9106, version 0x13) as Go's `argon2.IDKey`: RFC 9106's
bounds are errors (`Error::InvalidLength`, the new `Error::InvalidParameter`), the memory is one
fallible allocation (the new `Error::OutOfMemory`), and the lanes run on scoped threads (up to one
per lane and per CPU) with the same result as on one. It blocks for a time in proportion to
`time × memory_kib`: call it off the I/O threads. `hash::Blake2b` (RFC 7693: digests of 1 to 64
bytes, keyed or not) and `hash::Blake2b512` (the `Hash` trait) come with it. `chacha::hchacha20`
and `chacha::XChaCha20Poly1305` (`XNONCE_LEN = 24`; draft-irtf-cfrg-xchacha, as Go's
`chacha20poly1305.NewX`) have `ChaCha20Poly1305`'s `encrypt`, `decrypt` and in-place methods.
Tested against RFC 9106, RFC 7693, the XChaCha draft, Wycheproof's XChaCha20-Poly1305 vectors and
Go's golang.org/x/crypto output (fit's Argon2id setting among them); `ct-dudect` has two new
targets, `xchacha20poly1305-open-tag` and `blake2b-key`. Argon2id reads memory at
password-dependent indices after its first half pass, by design (docs/constant-time.md).

### Added: every pool submission is registered with its lane (tests)

A workspace test, `crates/akio/tests/pool_submissions.rs`, scans the libraries' sources for
calls that hand work to a pool (`try_execute`, `try_execute_batch`, `execute_batch`, `execute`,
`spawn_blocking`, `resume`, `detach_to_pool`) and checks each against a table giving its
function, its lane (new work, the next step of admitted work, a wrapper forwarding its caller's
choice, or no pool at all) and what happens when it is refused. It fails on an unlisted call, on
a listed one that is gone, on a resumed step that does not call `resume`, and on a timer call
following a submission in the same function (a refusal tried again later). 46 calls are listed:
14 new work, 4 resumed steps, 18 wrappers, 10 named alike but no pool.

The pressure watcher's "pressure over" summary, and the "command batches back under 1024" line
of an I/O thread's queue, are rate limited per pool or queue as the level lines are (one per
10 s, the next counting those held back): a pool flapping around the line logged one about every
second. The doc of `akio_http::transport::after` no longer offers it for asking a full pool
again.

### Added: a pool under pressure says so, and only then runs a watcher (akio-pool, akio-core, akio, akio-http, akio-bittorrent)

A submission that finds a pool's backlog (new and resumed jobs waiting) past half of
`queue_capacity`, is refused for a full queue, or finds work held up by `max_blocked_threads`
hands the pool to a process-wide watcher thread, `akio-pool-watch`, started then. It samples the
watched pools every 100 ms and logs through `akio-log` (target `akio-pool`): a warning when the
backlog rises to 50, 75 or 90% of the capacity, an error at 100% (a refusal or a stand-in limit
hit between samples counts as 100%), a warning when threads are blocked at the
`max_blocked_threads` ceiling; at most one line per 10 s per pool and level, the next one
counting those held back; a level is left 10 points below it. A pool calm for a second (under
40%, no refusal, no limit hit) leaves with an info line summing up the episode; with no pool
left the thread exits, so no timer runs while every pool is calm. The submit path gains a
comparison and a flag read under the lock it already holds.

- `PoolConfig::name` (default `"akio-pool"`) names the pool in those lines; the engine's pool
  is `"akio"`, the HTTP and BitTorrent disk pools `akio-http-disk` and `akio-bittorrent-disk`.
  Threads keep the name `akio-pool`.
- `PoolStats` gains `warnings` (rises per level) and `watched`.
- The metrics endpoint exports the pool's `akio_pool_resumes`, `akio_pool_max_queued`,
  `akio_pool_blocked`, `akio_pool_watched` (gauges), `akio_pool_compensated_total`,
  `akio_pool_blocked_at_ceiling_total` and `akio_pool_pressure_warnings_total{level}`
  (counters); `Metrics::to_json` adds the same fields to `pool`.
- akio-pool depends on akio-log (in the workspace).
- I/O threads record the deepest batch they took from their command list
  (`LoopCounters::max_cmd_batch`, metric `akio_loop_max_command_batch`; epoll, kqueue, UDP,
  work-stealing and io_uring loops). A batch of more than 1024 commands hands the loop to the
  same watcher, which logs batches past 1024, 16384 and 131072 commands and lets the loop go
  once none has passed 1024 for a second.

### Fixed: joining the pool or waiting for the engine from one of its own threads (akio-pool, akio)

- `Pool::join` called from one of the pool's threads (a job that shuts its pool down and joins
  it) joined that thread too, and std panicked ("failed to join thread"). It now waits for the
  other threads only; the calling one exits once its job returns, and a later `join` from
  outside the pool waits for it.
- `Engine::wait` (and `run`) called on one of the engine's logical-pool threads or on an I/O
  thread waited for its own thread to exit: it held that pool thread forever, or hung or
  panicked joining its own I/O group. It now returns at once without waiting and logs an error
  (target `akio`): call it from a thread of the application's own. I/O threads are told by the
  timer wheel every backend installs on them, so an I/O thread of any engine counts.

### Added: a pool thread that waits is stood in for (akio-pool, akio-core, akio, akio-http, akio-arpc, akio-h3, akio-ws, akio-socks, akio-grpc, akio-bittorrent, akio-media, akio-webrtc)

`akio::blocking(f)` (also `akio_core::blocking`, `akio_pool::blocking`) runs a wait telling the
calling thread's pool that the thread is blocked: queued work no idle thread will take then gets
a new thread, up to `max_threads` plus one per blocked thread, at most
`PoolConfig::max_blocked_threads` (new, default the default `max_threads`) more. Once the waits
end, a thread above that allowance leaves after its current job, not after `keep_alive`.
`akio::on_pool_thread()` and `Pool::is_current` tell whether the caller is a pool thread.
`PoolStats` gains `blocked`, `compensated` and `blocked_at_ceiling`.

- A handler on the logical pool that called, through a blocking client, a route of the same
  engine whose handlers ran on the pool too, then waited, hung for good once every pool thread
  waited so (`wait()` without a timeout): the inner request sat in the queue. The blocking
  waits of the libraries now go through `blocking`: `ResponseFuture::wait` / `wait_timeout`,
  `H2Client::dial_blocking` / `websocket_blocking`, arpc `CallFuture::wait`, `dial_blocking`
  and `ClientPool::dial`, gRPC `unary` / `collect`, HTTP/3 `request_blocking` / `get` /
  `websocket_blocking`, `akio_ws::client::dial_blocking`, the SOCKS client's
  `dial_blocking` / `bind_blocking` / `udp_associate_blocking` and the blocking `accept` /
  `recv_from`, BitTorrent `wait_complete` / `wait_metadata`, the RTSP client's `pull` / `push`
  handshake, and WebRTC `gather_srflx` / `gather_relay`.

### Changed: admitted work goes on through a full pool instead of being cut or retried (akio-pool, akio-core, akio-http, akio-h3, akio-grpc, akio-quic, akio-bittorrent)

`Pool::resume` queues the next step of work the pool admitted before in a lane of its own:
taken before new work, never refused while the pool runs, and counted against the room
`try_execute` leaves for new work. `ConnInner::resume`, `akio_http::Executor::resume`,
`ConnSink::resume` and `akio_quic::Connection::resume` reach it. `PoolStats` gains `resumes`
and `max_queued`; the pool drops the handles of threads that have exited instead of keeping one
per thread ever started.

- A coded file body (`FilePump`) and an HTTP/3 file body asked a full pool again every 5 ms
  from a timer, and cut the response after a second; they now resume and wait for a thread.
- A gRPC call on the pool (`handlers_on_logical_pool`) whose handler was idle ended with
  `RESOURCE_EXHAUSTED` when its next message met a full queue; it is resumed now. Opening a
  call is still new work, turned away when busy.
- A BitTorrent piece downloaded whole was thrown away, and fetched again, when the disk pool's
  queue was full; it is resumed now.

### Fixed: IPv4 multicast out of a chosen interface on macOS (akio-sys, akio-core)

`UdpBinding::send_to_on` (and `akio_sys::send_to_on`) named the interface in an `IP_PKTINFO`
control message, which macOS turns into a route lookup scoped to that interface: an interface
without a route for 224.0.0.0/4 (`lo0`, or any but the one the multicast route names) failed
with `ENETUNREACH`, so mDNS (akio-webrtc) could not answer on it, and
`ipv4_group_reports_the_interface_each_datagram_arrived_on` failed on every Mac with one network
interface. There an IPv4 multicast send now sets the socket's `IP_MULTICAST_IFINDEX` (which picks
the interface without a route) for the send and puts it back, under a lock that the binding's
other IPv4 multicast sends (`send_to`, `send_to_tos`) take too, so none leaves on the interface
another named. Linux, IPv6 and unicast are unchanged.

### Fixed: connections reset when the thread count shrinks again soon after growing (akio-epoll, akio-uring)

Growing the I/O threads asks the loop holding an `SO_REUSEPORT` socket handed on by an earlier
shrink to give it back, and it was posted straight to the loop of that index named at the time.
When the group shrank again before that command was handled, that loop could already have retired
and exited: the socket sat in a queue nobody read, stayed in the kernel's `SO_REUSEPORT` group
taking its share of new connections, and was dropped, resetting them all, when the next growth
replaced the loop. The socket now goes back through the roster, posted under its read lock like
every other hand-over, so it reaches its home loop, or an active one, before any `Retire`. The
same race could drop a connection handed over by accept-time balancing (ADR-105): the target loop
was picked under the lock and posted to after it; both now happen under it. Seen as
`balancing_survives_resizing` failing about one run in eight (all four clients reset at once);
0 in 60 runs each on epoll and io_uring since.

### Changed: fewer wake-ups in the logical pool (akio-pool, akio-core, akio-http)

A job queued on the logical pool wakes a sleeping thread only when no thread is free to take it
(it used to wake one for every job, a futex call even with every thread busy); new
`Pool::try_execute_batch` and `ConnInner::execute_batch` queue several jobs under one lock, and
HTTP/2 hands the requests of one read to the pool that way; before sleeping, one thread at a time
looks for work for 10 µs, yielding the CPU between looks, but only while looking has lately found
work. h2c through the pool on gpu51 (4 CPUs): +12% on epoll, +16% on io_uring and +20% with work stealing (0.68M to 0.76M–0.81M requests/s), and the same CPU as before at light load (docs/BENCHMARKS.md, which also records
the variants tried: a busy-spinning thread cost 4–12% by taking a CPU from the I/O threads).

### Fixed: a request head of many fields read in pieces is answered as in one piece (akio-http, akio-ws)

A head of more than 32 fields is parsed again with room for the limit (100); arriving in pieces,
the 32-field attempt resumed with the count of the larger one, which `fields` compared with `==`
and so never stopped at a limit: a head past 100 fields with a malformed line after them was
answered 400, where the same head read in one piece is answered 431 (fuzzing, `http1_request`).
`parse_head` now goes straight to the larger parse once a head has shown more than 32 fields
(through the new `Resume::fields`), which also keeps such heads from being parsed from scratch
on every piece, and akio-ws's field loop checks the limit with `>=`. The input is a corpus seed
of `http1_request`, and a test feeds heads split at every offset.

### Added: an accept filter on UDP listeners, bound UDP sockets and QUIC servers (akio, akio-core, akio-epoll, akio-uring, akio-quic; akit A220)

ADR-178. `Listener::filter` now works on UDP listeners: it is asked for each datagram from a
peer that has no connection yet, before `udp_max_peers` and `on_open`, and a refused datagram is
dropped with nothing kept of the peer and counted in `LoopCounters::filtered`. On a datagram
listener (`serve_datagrams`) every datagram is asked, and those refused never reach the handler
(epoll, kqueue and io_uring). `Engine::set_listener_filter` / `clear_listener_filter` swap it on a
running UDP or datagram listener without binding anew (they answered `Unsupported`, and a filter
on a UDP listener failed `build`). Sockets bound at run time take one with the new
`Engine::bind_udp_filtered`, in force from the first datagram, and swap it with
`UdpBinding::set_filter` / `clear_filter`. akio-quic's server asks the filter again, through the
new `Conn::filter_allows`, before an Initial packet makes a new connection (before any TLS work;
nothing is sent back), so a filter swapped after a UDP peer was opened applies to its new QUIC
connections; akio-h3's listeners get it through `QuicServer`. DPDK listeners still take no filter.

### Changed: scheduling modes renamed: `Scheduling::Rounds` is `WorkStealing`, `Scheduling::Loops` is `EventLoops` (akio, akio-epoll)

ADR-104, update of 2026-11-26. `Scheduling::Rounds(RoundsConfig)` is now
`Scheduling::WorkStealing(WorkStealingConfig)` and `Scheduling::Loops` is `Scheduling::EventLoops`
(still the default); in akio-epoll `RoundsConfig` is `WorkStealingConfig`, `RoundsGroup` is
`WorkStealingGroup` and the module `rounds` is `work_stealing`. The environment variables
`AKIO_ROUNDS_POLLERS`, `AKIO_ROUNDS_TRACE`, `AKIO_ROUNDS_SPIN` and `AKIO_ROUNDS_POLL_INTERVAL` are
`AKIO_WORK_STEALING_*`, `AKIO_DEFAULT_SCHEDULING` takes `work-stealing` or `event-loops` (was
`rounds` or `loops`), the metrics backend label is `epoll-work-stealing` / `kqueue-work-stealing`,
trace lines start with `work-stealing-trace`, `http-bench` and `tools/bench/shared.sh` take
`work-stealing` in place of `rounds`, and `skew-bench server` takes `event-loops` or
`work-stealing` (was `loops` or `rounds`). No release had the old names, so there are no
aliases. Why: "rounds" named the internal unit of work, one round of a connection, not what a
user chooses: connections bound to one thread each, or a pool of workers that steal work from
each other. A round still means one round of a connection.

### Changed: pooled HTTP/2 responses are written by the connection's own thread (akio-http, akio-core)

With `H2Config::handlers_on_logical_pool`, a handler that answers on its pool job no longer
locks the connection and writes its response itself: it queues the response, and one task per
batch (`ConnInner::run_on_loop`, new) encodes and writes the batch on the connection's I/O
thread, or with work stealing the worker of its next round, in one write. Work a handler posts to
the pool itself (`detach_to_pool`, `executor`), other threads and timers still write their own.
Measured on gpu51 (docs/BENCHMARKS.md): h2c through the pool +30% to +39% (0.49M to 0.65M–0.67M
requests/s); inline unchanged. What remains is the logical pool's own hand-off (a futex wake and a
context switch per job).

### Fixed: a request target in absolute form is taken by its path and host (akio-http, akio-h3; akit A200)

ADR-177. An HTTP/1 request whose target is in absolute form (`GET http://a.example/admin/x?q
HTTP/1.1`) is taken as RFC 9112 §3.2.2 asks of an origin server: `Request::target` is its origin
form (`/admin/x?q`, `/` for an empty path) and the target's authority, without user information,
replaces `Host`. The target was kept whole, so a router took the request for no path it knew
while a proxy asked its upstream for the path: akit's fuzzing found such a request passing a
route that protected `/admin/*`. `Request::raw_target()` gives the target as sent, and the access
log writes it. `Host` is still required once on HTTP/1.1. Targets in no form RFC 9112 gives an
origin server (authority form but for `CONNECT`, a relative path, `*` but for `OPTIONS`, an absolute
form without a host) are answered 400. On HTTP/2 and HTTP/3 a `:path` that is not in origin form
(or `*` for `OPTIONS`), an absolute URI included, makes the request malformed (RFC 9113 §8.3.1,
RFC 9114 §4.3.1).

### Changed: a WebAssembly guest call 44% cheaper (akio-wasm; akit A180)

ADR-125's W5. A call of fit's Go `headers` guest on a warm instance takes 5.1 µs instead of
9.1 on the benchmark host (wazero's compiler 3.5 µs, its interpreter 42 µs), a typed host call
17.5 ns instead of 28. The translator folds and fuses what Go's `wasm` code does needlessly
(`i64.extend_i32_u`, address wraps, constants stored, returned and passed, double `eqz`
tests, the stack pointer's update), branches take their target block's fuel, and typed host
functions (`Linker::func_wrap`) run over slots instead of `Value`s. Fuel is metered exactly as
before. No public API change; `examples/wasm-bench.rs` measures a call and its parts.

### Added: a connect timeout per dial, `Engine::dial_with` (akio, akio-core, backends, akio-http; akit A12, A79)

ADR-154. `Engine::dial_with(addr, DialOptions::new().connect_timeout(d), acceptor, on_error)`
bounds one dial's TCP handshake by its own timeout, shorter or longer than the engine's
`Config::connect_timeout` (`TimedOut` to `on_error` past it), so each upstream of a proxy is
dialed within its own on one engine. Every TCP backend honours it: epoll/kqueue event loops,
work-stealing scheduling, io_uring, and DPDK (in place of its stack's 10 s).
`HappyEyeballs::dial` and `connect` now dial every attempt with their `connect_timeout`, a lone
address and the addresses dialed in turn when the racer is full included (they used the
engine's), and so do the clients that dial through them (akio-http `Client`,
`H2Client::connect`, akio-ws); `H2Client::dial` uses `H2Options::happy_eyeballs.connect_timeout`
too. `dial_udp` takes none: UDP has no handshake.

### Added: `akio::timer::after_send`, a timer any thread may set (akio-core; akit A45)

ADR-154. `timer::after_send(delay, f: FnOnce() + Send)` runs `f` on akio's one process-wide
timer thread (`akio-timer`, started on first use, leaving after 30 s idle), from whatever thread
sets it; `SendTimer::cancel()` works from any thread and says whether the timer was still
pending. Bounded (`MAX_SEND_TIMERS`, 2^20 pending, then `Error::Overloaded`), never early, a
panicking job caught and logged. For control-plane code with no loop of its own (probes and
their deadlines, sweeps, refreshes); jobs must be quick and non-blocking, posting real work
elsewhere. On an I/O thread the loop-local `timer::after` remains the cheaper choice.

### Added: `akio::Pool` for an application's own blocking work (akio, akio-core; akit A117)

The `akio` facade re-exports `Pool`, `Rejected` and `Job` beside `PoolConfig` and `PoolStats`:
an application builds a bounded pool of its own (`Pool::new(PoolConfig)`), apart from the
engine's logical pool, for blocking work that must hold up nothing else (a cache's disk tier,
say), and submits jobs with `Pool::try_execute`, which never blocks and gives the job back as
`Rejected` when the queue is full or the pool is shut down. `akio_core::Pool` is no longer
`#[doc(hidden)]`.

### Added: `Telemetry::open_accepted` (akio-core, backends; akit A30)

`Telemetry::open_accepted()` (and `Metrics::open_accepted`, `"open_accepted"` in
`Metrics::to_json`) counts the accepted TCP connections open now, on every TCP listener,
without the dialed connections, adopted streams, UDP peers and TUN devices that
`open_connections` also counts: what a gateway reports as its client connections when it dials
its upstreams on the same engine. Every backend (epoll/kqueue event loops, work stealing,
io_uring, DPDK) tells the kind on close (the backend-facing `Telemetry::conn_closed` takes it); an
accept still costs one atomic update.
### Added: idle HTTP/1 connections drained after a grace (akio-http; akit A54)

`HttpConfig::idle_drain_grace` (250 ms by default): when a listener is drained
(`Engine::shutdown_listener`, `Engine::shutdown`), an idle HTTP/1 keep-alive connection is no
longer closed at once, racing a request its client may have sent already. It stays open up to the
grace; a request that arrives in it, or was in the receive buffer, is answered with
`Connection: close` and the connection closed after its response; a request partly received, or
whose body is arriving, is busy and answered so too; with none, the connection closes at the end
of the grace. The drain's deadline caps the grace. `Duration::ZERO` keeps the old behaviour. A
connection that turns HTTP/2 in the grace is sent `GOAWAY` at once.

### Added: a listener's response observer, without an allocation per request (akio-http, akio-h3; akit A29)

ADR-158. `ResponseObserver::on_response(&self, resp, req, words: [u64; 2], started: Instant)`,
set once with `HttpAcceptor::observer` (HTTP/1.1 and HTTP/2) or `akio_h3::serve_with_observer`
(HTTP/3); a request opts in with `Context::set_observed(words) -> bool`, which stores the two
words and the time inline. The observer runs once per observed request when its response goes,
on the thread that sends it, after the filters, whether the response is sent inline, detached,
after a suspension, through a held head or streamed (at its head); a response never sent is not
observed. Each connection clones its own handle on the observer, so a request bumps no count
other threads share; an observed HTTP/1.1 request allocates nothing (a test counts). New
`transport::ConnSink::observer` and `transport::conn_observer` for transports on the seam. The
HTTP/2 session is boxed inside the HTTP/1 session (one allocation per HTTP/2 connection), which
keeps an idle HTTP/1 connection within its size budget.

### Added: a request whose body streams can be suspended (akio-http, akio-h3; akit A75)

ADR-159. `Context::suspend` no longer returns `None` for a request whose body streams
(`BodyMode::Stream`): the body's reads are held from the suspension (HTTP/1.1 stops reading the
connection, HTTP/2 stops giving the window back, HTTP/3 holds the stream), what was read already
(one read's worth, or a stream window) is kept, and once `Suspended::resume`'s closure returns
the resumed context's `on_body` sink gets the whole body in order and the reads go on. A handler
that holds the reads (`body_reads`) in the closure keeps them held; a client that goes meanwhile
runs `on_gone`; a request dropped unresumed is answered `500` and its body read past. HTTP/1.1,
HTTP/2 and HTTP/3.
### Added: an idle timeout per connection (akio-core, akio-epoll, akio-uring; akit A78)

ADR-155. `Conn::set_idle_timeout(Option<Duration>)` gives one TCP connection or UDP peer
(accepted or dialed) an idle timeout in place of the engine's (`Config::idle_timeout`,
`Config::udp_idle_timeout`): `None` keeps it open however long it is idle. Callable from any
thread; the connection is closed on its I/O thread with `ErrorKind::TimedOut` "idle timeout",
as the engine's idle close does. `Conn::set_idle_counts_writes(bool)` counts data sent as
activity too (checked every eighth of the timeout), for a relay that is idle only when neither
side sends. epoll/kqueue event loops, work-stealing scheduling, io_uring and the UDP loop; DPDK and
TUN answer `Unsupported`. Connections that set none run exactly as before: the loops read the
setting only when it changes (`LoopLink::retime_conn`).

### Added: UDP listeners added, removed and drained at run time (akio, akio-epoll, akio-core, akio-quic, akio-h3; akit A22)

ADR-155. `Engine::add_listener` takes per-peer UDP listeners (threads of their own), and
`Engine::remove_listener` / `shutdown_listener(id, drain)` remove them: datagrams from new
addresses are dropped while the listener's peers keep being served; with a drain each peer gets
`on_shutdown` and those left at the deadline are closed; the sockets close once the listener has
no peer left on any thread, and its threads exit unless they serve `dial_udp` / `bind_udp`.
`UdpBinding::shutdown(drain)` drains a socket bound at run time the same way. A QUIC server's
connections hear of it (`QuicHandler::on_shutdown`), and akio-h3 sends `GOAWAY`, answers the
requests in flight and refuses later ones with `H3_REQUEST_REJECTED` (engine shutdown now sends
`GOAWAY` too). Datagram listeners and DPDK remain `Unsupported`.
### Added: a connection's TCP counters, splices with a first write, and spliced tunnels (akio-ebpf, akio-mux, akio-socks; akit A170)

ADR-156. A proxy that splices two `akio` connections with the sockmap relay no longer reaches
into `Conn::inner`:

- `akio::ebpf::conn_byte_counts(&Conn<H>)` (and `inner_byte_counts(&ConnInner)`) read a
  connection's TCP counters. `ByteCounts` gains `unread` (`SIOCINQ`, the receive queue) and
  `consumed()` (`received - unread`: what userspace read, a PROXY header or ClientHello
  included). The three calls behind it are read again until `TCP_INFO` is stable around them.
  A received FIN no longer counts as a byte in `received`, nor an acknowledged FIN of this side
  in `written` (a dialed socket's `written` still counts its SYN, as the kernel does).
- `Relay::splice_conns_with(&Conn<A>, &Conn<B>, first: &[u8]) -> Result<Splice, SpliceError>`
  (and `splice_inner_first` for `ConnInner`s) writes `first` to `b`'s socket once both are in
  the map and before any byte is relayed. `SpliceError` carries the error and how much of
  `first` was written. `Splice::base()` holds both sockets' counters as the relay began, read
  under the gate (`consumed` before the sockets enter the map, where `SIOCINQ` may report the
  psock's queue); every splice of connections fills it.
- `akio::ebpf::Tunnel` (`Relay::tunnel`, `Relay::tunnel_inner`) runs a spliced pair: `base`,
  `counts`, `relayed_from`, the idle probe (`activity`, `moved`), `close_after_forward` (the
  other side closed once everything the ended side received reached its send queue, or after a
  stall, polled on one `akio-ebpf-drain` thread) and `late_payload`. It keeps the connections
  weakly.
- akio-socks's `CONNECT` splice runs on `Tunnel`: its private drain thread is gone, and a side's
  drain target now counts the bytes that waited in the other socket's receive queue at the
  splice (a server that greets first), which the old target missed.
- akio-mux: `ProxyHeader::wire_len()` is the header's length on the wire when it was read
  (`parse`, and so the header `ProxyProtocol` attaches), `None` for one built here. The struct
  gains a private field (build headers with `proxy` / `local`), and equality and hashing ignore
  it.
### Added: an HTTP/1 response's `Connection: close` closes the connection and stops reading the body (akio-http; akit A24)

ADR-157. A response whose `Connection` field says `close` (sent with `respond`, from a `Detached`,
after a held head, or as a streamed head) now closes the HTTP/1 connection once it is written,
whatever the request asked, and the connection reads nothing more: the rest of a request body the
service refused (a `413`, a `401`) is not read, and the requests pipelined behind it are not
served. A whole response stops the reads as it is sent, a streamed one once it finishes. Before,
the field was sent but keep-alive came from the request alone, and the body was read on until the
body timeout. HTTP/2 and HTTP/3 drop the field, as before.

### Added: `Context::limit_body`, a request body bounded by a middleware (akio-http, akio-h3; akit A49)

ADR-157. `Context::limit_body(max) -> bool` lowers the bound of a request's body, before or after
the handler sets its sink. A body already here (buffered) longer than `max` is answered `413`. A
streamed body (`BodyMode::Stream`) declared longer is refused at once, and one that grows past
`max` is refused as it does: its sink gets the new `BodyEvent::TooLarge` and nothing more, the
request is answered `413` unless its response was taken (the handler answers then), and the rest of
the body is not read: HTTP/1 closes the connection after the answer, HTTP/2 stops the stream's
window and resets it (`NO_ERROR`) once answered, HTTP/3 sends `STOP_SENDING` (`H3_NO_ERROR`).
`transport::Started::body_refused` tells a transport outside akio-http. `false` when refused: the
middleware does not call the handler.

**Breaking (before 1.0.0):** `BodyEvent` has a new variant, `TooLarge`; an exhaustive `match` on it
needs an arm (it comes only after `limit_body`).

### Added: a streamed HTTP/1 response framed by its `Content-Length` (akio-http; akit A35)

ADR-157. `stream_response` (and `Detached::stream_response`) on HTTP/1 now frames the body by the
`Content-Length` its head gives: no chunked framing, the pieces written as they are, a write past
the length refused (`Error::Io` of kind `InvalidInput`, nothing written), and `finish` on a body
short of its length closing the connection (the request ends `End::Gone`, its tap `TapEnd::Cut`).
A stream coding a response filter sets (the `compress` middleware's) or a body filter drops the
field and goes chunked, as the body is no longer that length. Without a length, the framing is as
before (chunked on keep-alive HTTP/1.1, close-delimited otherwise); a chunked head no longer
carries a `Content-Length` beside `Transfer-Encoding`. HTTP/2 and HTTP/3 are unchanged.

### Added: `Request::local` and `Context::local_addr`, the address a request came to (akio-http, akio-h3, akio-quic; akit A148)

ADR-157. Filled as `Request::peer` is: the connection's local address on HTTP/1.1 and HTTP/2, the
UDP socket's on HTTP/3, unspecified where there is none (`Request::new`, a Unix-domain socket).
`akio_quic::Connection::local_addr` gives a QUIC connection's.
### Added: CPUs kept for the logical pool when pinning (akio, tools/bench)

`EngineBuilder::reserve_pool_cpus(n)` (or `AKIO_POOL_CPUS=n`), with `pin_io_threads`: the last
`n` of the CPUs the process may use run the logical pool's threads, the I/O threads are pinned to
the others. Ignored without pinning, under NUMA placement and when the pool has a start hook.
Linux only. `http-bench` gains `AKIO_BENCH_H2_POOL=1` (HTTP/2 handlers on the logical pool),
`AKIO_BENCH_POOL_MAX=n` (pool thread cap) and the `work-stealing` backend argument, and
`tools/bench/shared.sh` the `-h2pool`, `-cap<N>` and `-pool<N>` modes.

Measured (docs/BENCHMARKS.md): the drop of pinned h2c is the logical pool's (served inline, h2c
pinned is fastest, 4.0M requests/s ±1%); keeping 2 of 4 CPUs for the pool helped io_uring (496k
to 840k) but not epoll (485k to 337k) and cost HTTP/1.1. The same runs show that the pool
hand-off dominates trivial HTTP/2 handlers: 3.2M–4.0M requests/s inline against about 0.49M with
`H2Config::handlers_on_logical_pool` on, the default for a day (see below).

### Added: a budget of the bytes queued across an engine, an accepted-connection limit, and an HTTP server of HTTP/2 alone (akio-core, the backends, akio-http)

akit's A214, A215 and A168, for fit's `limits.max_pending_bytes`, `limits.max_conns` and a listener
of `h2c` alone:

- `Config::max_pending_bytes: Option<usize>` (ADR-172; default `None`, reloadable,
  `Live::set_max_pending_bytes`): while the bytes queued for sending across every connection of
  the engine reach it, every connection's reads pause after its current read, as the write
  watermark pauses one connection's, and resume once they are back at three quarters of it. A
  watcher thread (`akio-budget`, only while a budget is set) sums the I/O threads' existing
  `queued_bytes` gauges every millisecond (10 ms while under half the budget); the write path is
  unchanged, and a read checks one relaxed load. Connections are paused through
  `ConnInner::read_held`, which every backend asks, parked once per episode and woken as
  `hold_reads(false)` wakes them. New: `LoopCounters::budget_pauses`
  (`akio_budget_pauses_total`), `Telemetry::pending_bytes`, `Telemetry::over_budget`.
- `Config::max_accepted_connections: usize` (ADR-173; 0, no limit, by default; reloadable,
  `Live::set_max_accepted_connections`): accepted TCP connections past it are closed right after
  `accept` and counted as `rejected`, whatever the engine dials; `max_connections` still counts
  every connection. It reads the counters of akit's A30 (`Telemetry::open_accepted`, taken here
  as they are on `claude/akit-open-requests`).
- `HttpConfig::http1: bool` (ADR-174; default `true`): with `false` the server speaks HTTP/2 alone,
  as a listener of `h2c` with prior knowledge and nothing else: a connection whose first bytes
  leave the client preface gets a `GOAWAY` (`PROTOCOL_ERROR`) and is closed; no `Upgrade: h2c`.
- `tools/bench/echo.sh connect` (new TCP connections per second, the accept path) and
  `AKIO_BENCH_MAX_PENDING_BYTES` / `AKIO_BENCH_MAX_ACCEPTED` in the bench servers, for the A/B
  in docs/BENCHMARKS.md ("Engine budget and accepted-connection limit").

### Added: pinning I/O threads to CPUs, and a shared-group benchmark (akio, tools/bench)

`EngineBuilder::pin_io_threads(bool)` (or `AKIO_PIN_IO_THREADS=1`), off by default, pins each I/O
thread to one CPU of those the process may use, in turn over the groups (shared and dedicated
listeners, client threads; threads added by `set_threads` and groups added at run time continue
the round). Groups pinned by NUMA placement or BPF steering are left alone; work-stealing workers
are not pinned. Linux only.

Why (docs/BENCHMARKS.md, "Shared I/O groups and I/O thread pinning"): with as many busy I/O
threads as CPUs, as in a shared group sized to the CPUs, the scheduler sometimes stacks two of
them on one CPU; unpinned, HTTP/1.1 over 3 listeners sharing 4 threads swung between 612k and
752k requests/s, pinned it held 754k (±1%), at or above 12 dedicated threads. But h2c, whose
handlers run on the logical pool on the same CPUs, fell by up to half pinned, so it stays off by
default. `tools/bench/shared.sh` measures shared against dedicated groups, pinned or not
(`http-bench` gains `AKIO_BENCH_LISTENERS` and `AKIO_BENCH_SHARED`).

### Fixed: requests RFC 9112, RFC 9113 and RFC 9114 call malformed are refused (akio-http, akio-h3)

akit's A169, found by akit's I25 conformance suite, where an akio server let these through to
an application, and a proxy on akio passed them to its upstream:

- HTTP/1: a request with more than one `Host` field is answered 400 and the connection closed,
  as RFC 9112 §3.2 asks (one was accepted, and an intermediary could route by either).
- HTTP/2: a request or trailer field whose name holds a byte in 0x00-0x20, 0x41-0x5A or
  0x7F-0xFF, or whose value (a pseudo-header's too) holds a NUL, CR or LF, resets the stream with
  `PROTOCOL_ERROR` (RFC 9113 §8.2.1). Only uppercase names were refused; a NUL in a value reached
  the application, and an HTTP/1.1 client then wrote it to its upstream.
- HTTP/3: the same, as RFC 9114 §4.2 asks.

The HTTP/2 checks cost nothing measurable: the HPACK decoder works out each field's byte classes
with a 256-entry table as it reads a string and keeps them with the dynamic table entry (an
indexed field is not scanned at all), and the server takes a block's text from one UTF-8 check
instead of one per name and value. h2c with handlers inline is 10–14% faster than with the
first, per-byte version of the checks (docs/BENCHMARKS.md).

### Fixed: an HTTP client request's timeout no longer holds the request until it would pass (akio-http)

akit's A171, found by akit's I25 benchmarks, where akit's proxy grew by about 240 bytes a request
(1.8 GiB in a 35-second run at 230k requests a second): the timer thread's job for a request's
`timeout` (`Client`) and for an h2 stream's timeout and header and idle checks (`H2Client`)
stayed queued after the request ended, keeping its exchange's allocation (or its callback and
stream control) until the delay passed. With a 60s timeout that is a minute of requests; with an
hour, an hour. The job is now cancelled when the request ends, and the heap entries of cancelled
jobs are compacted once they outnumber the live ones.

Scheduling and cancelling no longer wake the timer thread or touch a counter shared by every
thread: each thread queues its jobs and cancels on a queue of its own, the timer thread is woken
only for a job due before its next wake-up (or by a cancel while it sleeps idle) and collects the
queues every 10 ms while they fill, so a cancelled job goes within 10 ms. A 10 s timeout now
costs the HTTP/1.1 client 1.6% on epoll and 3.3% on io_uring, instead of 15–17%; the h2 client
with a timeout is 1.11× (epoll) and 1.69× (io_uring) faster (docs/BENCHMARKS.md).

### Added: `Client::close_idle` (akio-http, akit's A10)

`akio_http::client::Client::close_idle` closes every idle keep-alive connection of a client now,
and from then on closes each connection once its response is in instead of keeping it idle, as the
engine's graceful shutdown already did; requests sent afterwards are still served, each on a
connection of its own. Until now a client's idle connections closed only after
`ClientOptions::idle_timeout` (90 s by default), when the server closed them, or when the engine
shut down: dropping the `Client` did not close them, since each idle connection holds a clone. An
application that lets a client go (akit's upstream pool replaced by a reload) calls it so that the
connections go too. Test: `client`'s `close_idle_closes_idle_connections_now`.

### Fixed: a TLS server takes a ClientHello whose server name is an IP address (akio-tls)

akit's A172, found by akit's I25 benchmarks, where wrk's HTTPS requests to `https://127.0.0.1/`
all failed: wrk (OpenSSL) sends the URL's host as the SNI even when it is an IP address, which
RFC 6066 does not allow, and akio-tls's server answered `decode_error`. Such a name is now taken
as no name, as Go's, OpenSSL's and nginx's servers take it, and a trailing dot is dropped from a
host name rather than failing the handshake. An empty or non-ASCII name still fails it.

### Fixed: Unix-domain listeners with work-stealing scheduling are served (akio, akio-epoll)

A `Listener::unix` (or `unix_from_std`) listener with `Scheduling::WorkStealing`, or any Unix-domain
listener under `AKIO_DEFAULT_SCHEDULING=work-stealing`, was bound as a TCP listener at its
unspecified address: the socket file never appeared and connections to it failed, and `unix_mode` on
a TCP listener was not refused. Work-stealing groups now serve Unix-domain sockets
(`WorkStealingGroup::bind_unix_listener`; accept jobs accept without reading an address, and the
connections' addresses are `UNIX_ADDR`), and `unix_mode` is checked as with event loops. The
`unix_listener` tests of akio-http pass under work-stealing scheduling.

### Changed: TCP listeners share one group of I/O threads by default (akio, akio-epoll, akio-uring, akio-core)

ADR-130, phases 1 to 3. TCP listeners on epoll/kqueue with event loops (bound, inherited or
Unix-domain) no longer get one I/O thread per core each: they share one group, sized by the new
`EngineBuilder::io_threads(n)` (one thread per core by default). An HTTP, a gRPC and an admin
port on 8 cores now run 8 I/O threads instead of 24. Each thread polls every listener's sockets
and runs that listener's acceptor and accept filter; connections stay on the thread that
accepted them.

- `Listener::threads(n)` and the new `Listener::dedicated()` (one per core) give a listener a
  group of its own, as before: isolation for an admin port or a latency-critical protocol.
  UDP, datagram, DPDK and BPF-steered listeners keep groups of their own.
- io_uring: listeners with the same ring options (`UringConfig::entries`, `sqpoll`) share one
  group, sized by `io_threads`; each listening socket has its multishot accept, whose
  `user_data` names listener and socket. Removing one cancels its accepts and drains its
  connections only. Where io_uring is unavailable they fall back to the shared epoll group (or
  fail with `strict`).
- Work-stealing scheduling (ADR-104): listeners with the same `WorkStealingConfig` (resolved
  pollers and workers) share its workers and pollers instead of one pool each; each listener keeps
  its own accept jobs and filter, a listener added later gets its accept jobs posted to the pollers,
  and removing one closes its jobs and drains its connections only. Unix-domain listeners share too.
- The per-listener API keeps one entry per listener: `local_addrs`, `listeners`, `threads` and
  the `ListenerId`s. `threads()` reports the shared group's size for each of its listeners (0 once
  removed), and `set_threads` / `set_listener_threads` on a shared listener resize the shared
  group, for all of its listeners.
- `remove_listener` / `shutdown_listener` on a shared listener close its sockets and drain its
  connections only; the threads keep serving the other listeners until `shutdown`.
- Telemetry: a shared thread's `LoopMeta::listener` is `None`; `ConnInfo::owner.listener` names
  the listener each accepted connection came from.
- Backend-facing: `Group::add_listener`, `remove_listener`, `await_listener_removed`,
  `set_listener_filter` and `akio_core::ListenSocket`; `EpollGroup::shared`,
  `WorkStealingGroup::shared` and `UringGroup::shared`. One epoll/kqueue loop now keeps a table of
  its group's listeners.

### Fixed: HTTP clients called from the logical pool no longer deadlock it (akio-core, akio-http, akio-ws)

The HTTP/1.1 client (reusing a keep-alive connection) and the HTTP/2 client (every request,
streamed request, WebSocket, cancel, timeout and `close`) reached their connection's loop by
queuing an empty job on the logical pool and letting its completion run there. A pooled handler
that sent a request and waited for it (`send(..).wait()`) therefore needed a second pool thread
for the request to even start: with every pool thread waiting so, none ever started, and with no
request timeout (the default) they waited for good. The server's head, idle and body deadlines
and the graceful `on_shutdown` of HTTP server and WebSocket client connections went the same
way, so a jammed pool also stopped them.

- New `Conn::run_on_loop(f)` (akio-core): runs `f` on the owning I/O thread with `&mut` access
  to the handler, posted straight to the loop, with no pool job. All of the above use it now.
- A request handed to a connection that closes before its loop starts it is no longer lost (its
  completion was dropped silently, so `wait()` never returned): the HTTP/2 client fails it with
  `ClientError::Closed`, the HTTP/1.1 client dials a new connection for it.
- docs/rules.md rule 2: a pool task never waits for another task of the same pool, blocking
  calls from pool tasks carry a timeout, and reaching a loop uses `run_on_loop`.

### Changed: `run_on_pool` is now `handlers_on_logical_pool`, off by default everywhere (akio-http, akio-h3, akio-grpc, akio-arpc)

The switch that runs every request's middleware and handler on the engine's logical pool is
renamed after what it moves: `HttpConfig::handlers_on_logical_pool`,
`H2Config::handlers_on_logical_pool`, `H3Config::handlers_on_logical_pool`,
`GrpcServer::handlers_on_logical_pool(bool)` and `Routes::handlers_on_logical_pool(bool)` (arpc),
all formerly `run_on_pool` (no release had it, so no deprecated alias). `H2Config`'s was on by
default from 2026-11-25 and is off again (ADR-094, update of 2026-11-26; ADR-176 has the same-run A/B and the profile): the pool hand-off cut
trivial HTTP/2 handlers from 3.2M–4.0M to about 0.49M requests/s on the same 4 CPUs
(docs/BENCHMARKS.md; the same ceiling with work stealing and with the pool capped at 16 threads,
less with fewer). HTTP/2 streams run inline on the I/O thread again unless a service turns the
switch on; a single request can still go to the pool with `Context::detach_to_pool`.

### Fixed: four engine hangs (akio-epoll, akio-uring, akio-http, akio-ws, akio-h3, akio-quic, akio-webrtc, akio-turn, akio-kcp)

- **A panic on a shared timer thread no longer stops every later timer of the process.** The
  timer threads of akio-http, akio-ws, akio-h3 (client request deadlines), akio-quic,
  akio-webrtc, akio-turn and akio-kcp ran their jobs without catching panics, and they reach
  user callbacks (a handler's `on_close`, a request's callback). One panic killed the thread;
  from then on the `after` functions dropped their jobs silently, so request, handshake and
  close timeouts stopped working. A panicking job is now caught, as akio-media's timer already
  did.
- **A command a loop posts to itself after its drain is no longer left waiting.** A post from a
  loop's own thread skips the wakeup, since the loop drains its queue after every batch; but
  callbacks run after that drain (an `on_close` from the idle, write or handshake timers, from
  retiring or draining) could post commands for other connections of the same loop, which then
  waited until something else woke the loop: on an idle loop with no timer left, never. The
  loop now drains again before it blocks when it posted to itself (epoll/kqueue TCP and UDP
  loops, and io_uring).
- **An accept filter may stop its own listener with work-stealing scheduling.** The filter ran under
  the listening socket's lock, which `stop_listening` takes to close the socket: a filter that
  removed its own listener deadlocked the worker. It now runs without that lock; a connection
  whose check was running when the listener closed is dropped.
- **Work-stealing scheduling in driver mode polls every poller.** Workers always tried the first
  driver first, and work queued from other threads woke the first driver whether or not a worker
  waited in it, so with fewer idle workers than pollers (`WorkStealingConfig::new(2, 1)`, say) a
  second poller's listeners, dials and connections could go unpolled for good. Workers now take the
  drivers in turn, a blocked worker wakes every 10 ms to poll the next while another driver has
  nobody waiting in it, a poster interrupts the driver a worker is actually blocked in, and a worker
  about to block runs work queued since it last looked.

### Fixed: client deadlines, connection losses and full pools no longer hang or duplicate (akio-grpc, akio-arpc, akio-h3, akio-http)

- **A call's `done` no longer runs on the deadline thread** (akio-grpc, akio-arpc). One thread
  per crate fires every client deadline, and it ran the caller's callback of a call that timed
  out: a gRPC `bidi` call's `done`, an arpc `call_async`'s `done`. A blocking call made there
  (`unary`, `collect`, `call(..).wait()`) waited for a deadline only that thread could fire, and
  every deadline in the process stalled for good. Those callbacks now run on a callbacks thread
  (`akio-grpc-callbacks`, `akio-arpc-callbacks`); the crates' own waiters are still signalled on
  the deadline thread. The API docs and the book say where `done` runs.
- **gRPC `collect` and `unary` with `default_timeout(None)` no longer wait for ever** when the
  HTTP/2 connection goes between the call being started and the request reaching the
  connection's I/O thread (the hop through the logical pool is skipped then, and the request
  dropped with no event). The call now ends with `UNAVAILABLE`.
- **HTTP/3 file responses no longer read the file on the I/O thread** when the logical pool
  refuses the read (akio-h3). The read is asked again every 5 ms from the HTTP layer's timer
  thread, as HTTP/1.1 and HTTP/2's file pump does; after a second of a pool that stays full the
  stream is reset.
- **`H2Upload::try_write` no longer sends bytes twice** (akio-http). When the logical pool
  refused the hop to the connection's I/O thread it returned `Err(Closed)` but left the bytes
  queued, and a caller that wrote them again sent them twice. They are now taken back.

### Fixed: HTTP/3 QPACK encoding and WebSocket sends from an application thread no longer deadlock (akio-h3, akio-quic)

The same kind of deadlock as the client's request lock: a call on a QUIC connection from outside
its handler drives the connection on the calling thread and runs the handler for what is pending,
and two more callers held a lock the handler takes:

- QPACK encoding with the dynamic table (on by default for servers' responses; on for a client
  with `qpack_encoder_capacity`) sent its inserts on the encoder stream under the encoder's lock,
  and the handler locks the encoder to read the peer's decoder stream. A response head or trailers
  written from an application thread (a detached request, a streamed response's trailers), or a
  client request, hung that thread for good when an acknowledgment from the peer was waiting. The
  inserts now go out after the lock is let go, in order, under a send lock the handler never
  waits for (a thread finding it taken leaves them to its holder).
- A WebSocket over HTTP/3 (RFC 9220), on either side, sent under its sender's lock, which the
  handler takes to answer a ping or close, and in the application's callbacks that send. A send
  from an application thread while a ping (or any message whose callback sends) was waiting hung
  it. Its stream's sends no longer drive the connection on the calling thread.

Added for it: `akio_quic::Connection::without_driving(f)`, in which the connection's calls leave
driving it (and running its handler) to its timer thread, for callers holding a lock the handler
also takes. akio-quic's `testing` feature (not a public API) has a hook that forces the
interleaving; akio-h3's `off_handler` tests use it.

### Removed: akio-prefork (akio-prefork, akio, akio-sys)

ADR-129. akio and akit do not use prefork; the crate had been on hold and untested since
cb49a04b. Breaking for any outside user of these items:

- The crate `akio-prefork` (`Prefork`, `BpfSteering`, `ListenMode`, `CpuPinning`, `Controller`,
  `Supervisor`, `Status`, `WorkerInfo`, `Worker`), its example `prefork-http` and the book chapter
  "Multi-process serving (prefork)".
- `akio::EbpfConfig::shared` (only akio-prefork's workers set it). `akio_ebpf::SharedSteering`
  stays.
- `akio_sys::process::{ChildSetup, configure_child, take_inherited_fd, reserve_reuseport,
  SIGQUIT, SIGUSR1}`, and in the hidden `akio_sys::ffi`: `prctl`, `PR_SET_PDEATHSIG`, `getpid`,
  `getppid`, `ESRCH`, `SIGQUIT`, `SIGUSR1`.
- Kept: `Listener::tcp_from_std` (systemd socket activation), `akio_sys::process::{allowed_cpus,
  pin_current_thread, signal_pipe, kill, SIGHUP, SIGINT, SIGTERM, SIGUSR2}`.
### Added: response heads held, and response bodies filtered, by work done elsewhere (akio-http, akio-h3)

ADR-128, ADR-125's milestone W6 (akit's A166 and A167, for I72's Proxy-Wasm response callbacks),
over HTTP/1.1, HTTP/2 and HTTP/3 alike:

- `Context::hold_response_head(timeout, f)`: `f` gets the response's head in a `HeldHead` once
  the ordinary response filters ran, and hands it on (to a plugin's pool, say); the response goes
  on when it is `resume`d from any thread (through the outer filters), or is replaced by
  `respond(Response)`, or cut by `fail`, a drop or the deadline (HTTP/1 connection closed, HTTP/2
  and HTTP/3 stream reset, the request ended `End::Gone`). A streamed body written meanwhile is
  held (up to 4 MiB, in `BodyStream::queued_bytes`).
- `Context::add_body_filter(impl BodyFilter)`, with `BodyChunk` and `FilterDone`: the body goes
  through calls answered elsewhere, one at a time, what is written meanwhile held and given to the
  next call; the last call carries the trailers, which it may change or add; the output is paced
  by the client and then coded (`compress`) and tapped. Whole and file bodies go through as
  streams, without `Content-Length`. `BodyFilter::abort` hears a response that ended before its
  last call. Not called for `HEAD`, `1xx`, `204`, `304`, `CONNECT` or upgrades.
- The doc-hidden transport seam gains `ConnSink::reset` and `BodySink::reset` (defaulted), which
  akio-h3 implements, so a cut response resets its HTTP/3 stream.

### Added: akio-wasm's instance pool, milestone W4 (akio-wasm, akio)

ADR-125, fourth milestone: WebAssembly runs on threads that own instances, never on the I/O
threads. With it the API that akit's I71 needs is complete; the crate stays in the experimental
tier until the maintainer moves it (docs/api-stability.md).

- `InstancePool<S>`, made by `InstancePool::builder(module, linker, |index| state)` with
  `PoolConfig` (instances: the CPUs, at most 16; `queue` 1024; `instance_queue` 1024;
  `wait_timeout` 1 s; `call_timeout` 100 ms; `init_timeout` 1 s; `start_attempts` 3; the
  `InstanceLimits`) and an optional `on_start` hook (Proxy-Wasm's `proxy_on_vm_start`);
  `build()` waits until every instance is made (a WASI reactor's `_initialize` included) or
  fails with a `StartError`.
- `submit(job, done)` to any free instance through one bounded queue, `submit_to(InstanceId, job,
  done)` to a given one through its own bounded queue, served first; a full queue, a closed or
  failed pool, or an instance remade since its id was taken refuses the job at once with
  `Refused { reason: Refusal, job, done }`, nothing waits. The job, `FnOnce(&mut Pooled<S>) ->
  R`, runs under a deadline `call_timeout` from its start (`Pooled::call`, `call_typed`,
  `typed_func`, `budget`, `discard`); `done` gets `Result<R, JobError>` on the pool's thread, to
  hand back to the caller's I/O thread without blocking (akio-http's `Suspended::resume`). A job
  not started within `wait_timeout` gets `JobError::Expired` when the wait passes, even while every
  instance is busy (a reaper thread watches the queues).
- An instance a trap ended (a guest past its deadline included), whose job panicked, or that was
  discarded is dropped and made again before its thread's next job; jobs queued for it get
  `JobError::Remade`. An instance that fails to be made `start_attempts` times in a row fails the
  pool: queued and later jobs get `JobError::Failed`. `close()` (or dropping the pool) hands queued
  jobs back as `JobError::Closed` and interrupts the running ones.
- `stats()`: `PoolStats` with the shared and per-instance queue depths, running jobs, calls,
  refusals, expiries, `TrapStats` (traps by kind), panics, remakes, failed makings.
- `Store::trap()`: the trap that ended a store.
- Tests (`tests/pool.rs`): a hung guest stopped at its deadline and its instance remade, a full
  queue refused, a wait expiring while the instance is busy, `submit_to` ahead of the shared
  queue, jobs for a remade instance, a panicking job, a module that cannot be instantiated and an
  initialization past its deadline failing the build, a pool failed by an instance that will not
  be remade, closing with jobs queued and a guest running, the last handle dropped in a
  completion, four submitting threads.

### Added: akio-wasm's host API and WASI, milestone W3 (akio-wasm, akio)

ADR-125, third milestone: plugins get the host's functions and WASI, and fit's guests run.
Experimental until W4.

- `Linker<S>`: host functions by module and name, typed (`func_wrap(module, name, |caller,
  (a, b): (u32, i64)| -> Result<R, Trap>)`, over `i32`, `u32`, `i64`, `u64`, `f32`, `f64`) or over
  `Value`s (`func_new`); `instantiate(&mut Store<S>, &Arc<Module>, &Budget)` resolves each import
  and checks its type; `trap_unresolved(true)` makes function imports nothing defines trap when
  called instead of refusing the module. `Clone + Send + Sync`, shared across stores and threads.
  `LinkError`, `InstantiateError::UnknownImport`.
- `Caller`: bounds-checked views of the calling instance's memory (`read`, `read_mut`, `write`,
  `read_u32`, `read_u64`, `write_u32`, `write_u64`), its exports, the call's deadline and
  interrupt, `consume_fuel`, and `call`, back into the guest under the same budget, nested at
  most 64 deep (what Proxy-Wasm's hosts do with `proxy_on_memory_allocate`); a trap in it ends
  the outer call.
- `Store::typed_func::<P, R>` and `TypedFunc` (checked once, called from the host or a host
  function), `WasmTy`, `WasmParams`, `WasmResults`; `Store::initialize_reactor` (a WASI
  reactor's `_initialize`).
- WASI preview 1, the subset of ADR-125 (`Linker::wasi_preview1(WasiConfig)`, module
  `akio_wasm::wasi`): arguments, environment, realtime and monotonic clocks, random bytes
  (akio-crypto, the crate's one dependency), standard output and error to a sink
  (`OutputStream`), `poll_oneoff` on clocks sleeping no later than the call's deadline,
  `proc_exit` as the new `Trap::Exit(code)`; no file system and no sockets (`EBADF`, `ENOSYS`),
  `EFAULT` for a pointer outside the memory. All 46 functions are defined.
- Tests: the linker, the views, nested calls and their bounds, typed calls, each WASI function;
  fit's guests (`tests/guests`, gzipped, rebuilt by `tests/guests/build.sh`): the Go `headers`
  plugin (fit's ABI: fields edited, a request answered, `/loop` stopped at its deadline, `/grow`
  and `/panic` trapping, the instance made again), the Proxy-Wasm Go SDK's `http_routing` (memory
  allocated in the guest from host functions), and fit's Rust sync plugin. The `wasm_exec` fuzz
  target's imports now call back into the guest.

### Added: akio-wasm runs modules, milestone W2: translation and interpreter (akio-wasm, akio)

ADR-125, second milestone: `akio-wasm` now runs what it loads, still in safe Rust without
dependencies, experimental until W4.

- `Module::new` translates each function, once, after validating it, to a register form: every
  operand-stack position is a fixed slot, `local.get` copies nothing, constants are immediates, a
  comparison and its branch are one instruction; at most four 16-byte instructions per byte of
  code, in linear time. The interpreter is a `match` loop with explicit frames, never native
  recursion.
- `Store<S>`: instances (`instantiate(&Arc<Module>, &[Extern], &Budget)`, which may import from
  each other), host functions (`func_new(FuncType, Fn(&mut Caller<S>, &[Value], &mut [Value]))`),
  globals, tables and memories made by the host, exports, `call(Func, &[Value], &mut [Value],
  &Budget)`. `Send`, not `Sync`. A trap ends the store (later calls return `Trap::Ended`).
- `InstanceLimits`: memory (128 MiB; `memory.grow` past it returns `-1`), table elements (10 M),
  value stack (1 Mi slots), call depth (10 000).
- `Budget`: a deadline, fuel and an `InterruptHandle`, checked as basic blocks are entered, about
  every 10 000 instructions (bulk memory and table instructions pay by the byte), so a call stops
  within tens of microseconds of its deadline, with no watchdog thread; `Store::fuel_used`.
- `Trap` (the specification's traps with its wording, the run limits, `Deadline`, `OutOfFuel`,
  `Interrupted`, `Host`, `Ended`, `BadCall`), `InstantiateError`, `Value`, `ExternRef`, handles
  `Func`, `Table`, `Memory`, `Global`, `Instance`, `Extern`.
- Floats as the specification has them, with canonical NaNs: execution is deterministic.
- Tests: the whole WebAssembly 2.0 specification suite (21 453 `assert_return`, 2 354
  `assert_trap`, exhaustion, linking, instantiation), the translator's corner cases, budgets,
  every run limit under, at and over, host functions, translation in linear time. Fuzz targets
  `wasm_exec` (`wasm-smith` modules under small limits) and `wasm_diff` (against wasmi), fuzz-only
  dependencies.

### Added: akio-wasm, a WebAssembly runtime for plugins, milestone W1: decoder and validator (akio-wasm, akio)

ADR-125 (accepted), requested by akit (A165) for its WASM plugins (I71) and Proxy-Wasm (I72).
New crate `akio-wasm`, in safe Rust (`#![forbid(unsafe_code)]`) without dependencies, experimental
until its API is complete (W4); `akio::wasm` behind the facade feature `wasm`. This first milestone
loads modules; running them is W2.

- `Module::new(&bytes, &ModuleLimits)` decodes and validates a binary module in one pass, linear in
  its size: WebAssembly 2.0 without SIMD (1.0 with mutable globals, sign extension, non-trapping
  float-to-int, bulk memory, multi-value, reference types; one 32-bit memory), what Go, TinyGo and
  Rust's `wasm32-wasip1` emit. `Module` lists the imports, exports (`export(name)`), types,
  function types, tables, memory, globals and start function.
- Anything else is refused at load with `ErrorKind::Unsupported(Feature)` naming it: SIMD
  (relaxed included), threads, exception handling, tail calls, memory64, several memories,
  extended constants, typed function references, GC, custom page sizes, wide arithmetic,
  components. Other refusals are `Malformed` or `Invalid` with the specification's wording and
  the byte offset.
- `ModuleLimits`, each checked before anything is allocated for what it counts: module size
  (64 MiB), types (100 000) and their arity (1 000), functions (100 000), imports and exports
  (10 000 each), tables (100) and their initial size (10 M), globals (100 000), locals per function
  (50 000), block nesting (1 000), `br_table` targets (100 000), element and data segments
  (100 000 each). Refusals are `ErrorKind::Limit(Limit)`.
- Tests: the decoding and validation commands of the WebAssembly 2.0 specification suite
  (converted by `tools/wasm-spec/convert.sh`, committed under `crates/akio-wasm/tests/spec`), the
  refused features' proposal files as refusal checks, every limit under, at and over, modules at
  the default limits in bounded time. Fuzz target `wasm_decode` (dictionary `fuzz/dict/wasm.dict`).

### Added: a request changed by a middleware, and a request's end heard (akio-http, ADR-126, ADR-127)

- `Context::req_mut() -> Option<&mut Request>` (ADR-126): a middleware changes the request's
  fields, target, method or body before the handler; `path()`, `header()`, the handlers after it,
  `Files` and the response filters see the change. `None` once the request is shared (`detach`, a
  WebSocket upgrade). Route parameters keep reading the path they were matched in. `suspend` now
  moves the request whole into the resumed context, which can change it.
- `Context::on_end(f) -> bool`, `Detached::on_end(f)` and `enum End { Sent, Gone }` (ADR-127): `f`
  runs exactly once when the request is done with: `Sent` once its response was handed to the
  connection in full (a streamed one's once finished, not at its head), `Gone` when its client
  went first (heard while it waits detached or streams) or its response was given up (a
  `Detached` or `BodyStream` dropped unfinished). Several hooks run in order; one added after the
  end runs at once. `on_gone` keeps its meaning and now lives beside them (it no longer takes the
  transport's one peer-gone slot). On HTTP/1.1, HTTP/2 and HTTP/3. A request that registers
  neither allocates nothing more.

### Fixed: the HTTP/3 client no longer deadlocks resuming, cancelling or timing out a request (akio-h3)

A call on a QUIC connection from outside its handler drives the connection on the calling thread,
which runs the handler for whatever is pending, the calling request's own events included. The
client made such calls while holding a lock the handler then took on the same thread, which waited
on itself for good:

- `H3Upload::hold_reads(false)` held the request's lock while resuming the stream; when what was
  held included the response's end, the handler, ending the request, took that lock. A response
  that had nearly all arrived before reads were held hung its resuming thread every time.
- `H3Upload::cancel` held it while resetting the stream; a body piece pending for the stream (a
  receive thread had read the datagram but not handed its events on yet) did the same. So could
  a writable stream pending during `write` or `finish`.
- The request-timeout thread reset an expired stream under the connection's request table, which
  the handler locks for any response.

The handler no longer waits for a request's lock (a request's failure and held flag are atomic,
and a flush it cannot take the lock for is left to the lock's holder), and cancelling and the
timeout reset streams after letting go of their locks. No public API changed; `hold_reads(false)`
may report what was held on the calling thread before it returns, as before.

### Changed: the io_uring backend sends responses through the ring (akio-uring, akio-core)

ADR-106. Behaviour is unchanged; no public API changed:

- io_uring connections no longer `write`/`writev` from the loop. What the loop's callbacks queue
  stays queued and is described to the backend; right before the loop enters the kernel each
  connection's queued bytes become one `IORING_OP_SEND` (or `SENDMSG` for several buffers), and
  every connection's send goes to the kernel in the one `io_uring_enter` the loop makes per batch
  of completions. One send is in flight per connection; short sends continue from where they
  stopped; per-connection order (including sends from other threads, kernel TLS socket
  operations and `sendfile` chunks, which still run from the loop) is kept; backpressure,
  `close_after_send`, `write_timeout` and closes with a send in flight behave as before.
- On io_uring, a queued owned buffer of up to 1 KiB is copied into the queue's tail and returned
  to the pool at once (queued buffers now live until the batch's sends complete).
- `AKIO_URING_SENDS=write` restores the old path (for A/B measurements). epoll and kqueue are
  unchanged.
- `ConnInner` gained `#[doc(hidden)]` backend plumbing for it (`set_ring_sends`,
  `uncork_flush_ring`, `flush_queue_ring`, `ring_redescribe`, `ring_sent`, `ring_release`,
  `RingSend`, `RingSent`, `RING_IOV`).

### Added: work-stealing scheduling for TCP listeners, off by default (akio, akio-epoll, akio-sys)

ADR-104, additive:

- `Listener::scheduling(Scheduling::WorkStealing(WorkStealingConfig))`: each round of a connection
  (read, handler, write) runs on whichever worker of a pool is free, one round of a connection at a
  time; idle workers wait in `epoll_wait` themselves, as Tokio's runtime. Load spreads by work
  rather than by connection. `WorkStealingConfig { pollers, workers }`, 0 = default (1 epoll
  instance; one worker per CPU). `Scheduling::EventLoops` (thread-per-core, ADR-001) stays the
  default.
- `AKIO_DEFAULT_SCHEDULING=work-stealing|event-loops` picks it for listeners that do not choose (a
  test knob).
- epoll/kqueue only; TCP only (UDP listeners keep their event loops); `Engine::set_threads` is
  refused.
- `akio_sys::Registry` (edge-triggered registration from any thread) and `Event::hup`.
- Example `skew-bench`: CPU-bound requests with few or uneven connections, for comparing the modes;
  `churn` (short-lived connections) and `rate` (a fixed low request rate) clients.

### Changed: work-stealing scheduling accepts and closes on the workers, and wakes fewer threads at light load (akio-epoll)

ADR-104, second revision; no API change:

- Accepting no longer runs on the driver: on Linux a work-stealing listener has one
  `SO_REUSEPORT` socket per worker, and a socket's readiness queues an accept job that a worker runs
  (accept, create, register, first round). The connections and their idle / write / handshake timers
  moved from the driver into a table sharded by id, which workers update directly: a close removes
  its connection with no message to the driver and no eventfd write.
- At light load (every other worker parked) a poll wakes no other worker for the first connection
  it found, which its worker runs next; a worker that found work by searching wakes another if more
  is queued; one parked worker keeps a 10 ms watch instead of every parked worker waking every
  10 ms.
- `AKIO_WORK_STEALING_TRACE=1` also reports unparks, driver wake-ups and parks per second.
- A connection is born scheduled, so an edge between its registration and its first round cannot
  queue it twice; `on_shutdown` runs once for a connection accepted while the shutdown starts; a
  watch woken for work hands the watch on; an accept aborted or reset by the peer no longer pauses
  the listening socket.
- gpu51, 8 server CPUs, against work stealing before this change (and event loops): short-lived
  connections 512 x 10 requests 513k → 703k req/s (event loops 716k), 512 x 1 request 103k →
  207k connections/s (event loops 205k), 2048 x 10 requests 691k → 905k req/s (event loops
  757k-878k); at 10k requests/s over 1024 connections 16.3 → 11.3 µs of server CPU per request
  (event loops 9.1) with the same latency; at 50k/s 15.6 → 9.9 µs. Skew cases and echo with 64
  connections unchanged, echo with 256-1024 connections -2.5%.

### Added: work-stealing listeners added, removed and drained at run time, accept filters, a write timeout changed at run time (akio, akio-epoll)

ADR-104, third revision; no API change:

- `Engine::remove_listener` and `shutdown_listener` work on work-stealing listeners as on
  event-loop ones (ADR-099): every per-worker `SO_REUSEPORT` socket is closed before the call
  returns (an accept job that runs later finds no socket), so the port can be bound again and a
  connection right after a same-address replacement is served; open connections keep running, a
  drain sends `on_shutdown` and closes what is left at the deadline, the workers and drivers finish
  once the last connection is gone (except the builder listener whose threads serve `dial`), and the
  engine reaps them; removed listeners still serving count under `max_listeners`.
- Accept filters (`Listener::filter`, `set_listener_filter`) run on work-stealing listeners,
  so `AKIO_DEFAULT_SCHEDULING=work-stealing` no longer leaves a listener with a filter on event
  loops.
- A write timeout set or cleared with `Engine::reload` / `Live::set_write_timeout` applies to open
  work-stealing connections (ADR-108); it was read only from the build-time `Config`.
- `set_listener_threads` is still refused for work-stealing listeners. No throughput change
  measured on gpu51 (work-stealing echo-like, skew and churn cases, event-loops echo).
### Added: CONNECT on HTTP/2 and HTTP/3 streams, and a connection's send direction shut down (akio-http, akio-h3, akio-socks, akio-core)

ADR-122, requested by akit (A134):

- akio-http: a `CONNECT` on an HTTP/2 stream with `:method` and `:authority` alone (RFC 9113
  §8.5) is dispatched at once, its target the authority, its DATA the streamed request body; a
  streamed `2xx` makes the stream a tunnel whose halves close separately. One with `:scheme` or
  `:path`, or without `:authority`, is reset (`PROTOCOL_ERROR`); before, every plain CONNECT was.
  `H2Client` sends a `CONNECT` request that way, its `:authority` the request's `Host` field.
- akio-h3: a `CONNECT` (RFC 9114 §4.4) is dispatched at its head rather than when its stream
  ends.
- akio-socks: `connect_proxy` relays a `CONNECT` on an HTTP/2 or HTTP/3 stream (it returned
  without answering before), with the HTTP/1.1 tunnel's checks, timeouts and failure statuses
  and backpressure both ways; the client's END_STREAM shuts the upstream's send direction down.
- `Conn::shutdown_write_after_send` and `ConnInner::shutdown_write_after_send`: a FIN once the
  queue is written, reads going on (epoll, kqueue, io_uring).

### Added: Unix-domain stream listeners, and a TLS server capped at TLS 1.2 (akio, akio-epoll, akio-uring, akio-sys, akio-tls)

ADR-121, requested by akit (A23, A9):

- `Listener::unix(path)`, `Listener::unix_from_std(UnixListener)` and `Listener::unix_mode(mode)`:
  a stream listener on a socket file served like a TCP one, on epoll, kqueue and io_uring, at
  build time or through `Engine::add_listener`; the mode set before it listens, a stale socket
  file replaced, one in use (or a file that is not a socket) `AddrInUse`. Its connections'
  addresses are `UNIX_ADDR`.
- `EpollGroup::bind_unix_listener`, `UringGroup::bind_unix_listener`.
- `akio_sys::listen_unix` and `akio_sys::accept_stream`.
- `ServerConfigBuilder::tls12_only` and `ClientConfigBuilder::tls12_only` (public; the hidden
  `__tls12_only` calls them). Set with `tls13_only`, `build` fails.

### Added: `Files` as a gateway's static handler, bounded in memory; file bodies encoded (akio-http)

ADR-124, requested by akit (A14, A15, A92):

- `Files::index_files`, `redirect_directories`, `mime_types` (`MimeTypes::builtin`, Go's table,
  and `MimeTypes::system`, with the system's `mime.types` as Go reads them), `default_type`,
  `sniff` (`files::sniff`, Go's `http.DetectContentType`), `error_response` and
  `serve_prefixed` (listings and redirects name the whole path).
- `Files::max_cache_bytes` (default 64 MiB): the bytes kept in memory, twins and compressed
  copies included, evicted least recently used first; `Files::disk_timeout`: a request the disk
  pool has not answered in time gets `503` with `Retry-After: 1`.
- A response whose body is a file and which a response filter gave a stream coding
  (`Response::set_stream_coding`) is sent streamed: read, encoded and written in 64 KiB pieces on
  the disk pool, under the connection's backpressure.

### Changed: `Files` (akio-http)

- `403` for a file that may not be read; `404` for what is neither a regular file nor a
  directory (it is no longer opened: a FIFO held a disk pool thread) and for a file asked for
  with a trailing slash; a name with `:` is served.
- At most 64 MiB of files are kept in memory by default (`max_cache_bytes`).
- Under a route, a request's trailing slash counts (a directory listed, not redirected), though
  the route's wildcard drops it.

### Added: root certificates outside a handshake; ALPN protocols for the handshake only (akio-tls)

ADR-123, requested by akit (A57, A58):

- `RootCerts::store()` and `From<RootCerts> for akio_x509::RootStore`: the roots (the system's
  included) for a `Verifier` of the caller's own.
- `ServerConfigBuilder::handshake_only_alpn(protocols)`: a connection negotiating one of them
  (`acme-tls/1`, RFC 8737) is closed once its handshake completes, and nothing it sends reaches
  the application.

### Added: dialing a Unix-domain socket, and the HTTP client over one (akio, akio-http, akio-sys)

ADR-120, requested by akit (A135):

- `Engine::dial_unix(path, acceptor, on_error)`: a Unix-domain stream connection served like a
  dialed TCP one, on epoll and io_uring, with event loops and with work-stealing scheduling
  (ADR-104); its `peer_addr` and `local_addr` are the new `UNIX_ADDR` (`0.0.0.0:0`).
  `Group::dial_unix` (unsupported by default).
- `Client::with_unix_socket(Option<PathBuf>)`: every request of the client goes to that socket,
  the URL's host still its `Host` and the key of its idle connections.
- `akio_sys::connect_unix_nonblocking`, `ffi::AF_UNIX` and `ffi::sockaddr_un`.

### Added: a proxy's tunnel checked once connected, and its connect timeout (akio-socks)

ADR-119, requested by akit (A132, A133):

- `ProxyConfig::connected` (`Connected`): decides each `CONNECT` tunnel's upstream (SOCKS and
  HTTP) once it opens, before it is used, given the destination as asked (a name or an address),
  the address connected to and the local one; a refusal is SOCKS5 reply 2, SOCKS4 `0x5b` or HTTP
  `502`, and no other address is tried.
- `ProxyConfig::connect_timeout`: the longest time from a `CONNECT` request to its upstream
  being connected; past it SOCKS5 reply 4, SOCKS4 `0x5b` or HTTP `504 Gateway Timeout`.
- The access hook's `Request::client` is the client a trusted PROXY header names (akio-mux's
  `ProxyProtocol` layer in front), as akio-http's requests have it since ADR-118.
- A SOCKS request whose name resolution the logical pool refuses (full) gets reply 1 before the
  close.

### Added: where a regular expression matches, its groups, and Go's templates (akio-regex)

ADR-115, requested by akit (A32):

- `Regex::find`, `find_at`, `find_iter`, `captures`, `captures_at` (`Captures`: `get`, `name`,
  `range`, `len`), `captures_len` and `group_names`: the leftmost-first match, as Go's `regexp`
  and the `regex` crate find it, on a capturing Pike VM in linear time.
- `Regex::expand` and `replace_all`, with Go's `Regexp.Expand` and `ReplaceAllString` rules.
- Lazy repetition and `(?U)` now change where a match ends (they never changed whether a text
  matches). A pattern with more than 1000 groups, or whose groups are repeated past 20 000
  instructions, is refused when compiled.

### Added: body taps, outer response filters and `parse_http_date` (akio-http)

ADR-116, requested by akit (A111, A112, A113):

- `Response::tap_body(impl BodyTap)`, `BodyTap` (`data`, `end`) and `TapEnd` (`Finished`,
  `Trailers`, `Cut`): a response filter sees a streamed body as it is sent, after its stream
  coding, and how it ended.
- `Context::add_outer_response_filter`: a filter that runs after every ordinary one, the last
  added first, so an outer middleware sees the response as the inner ones left it.
- `akio_http::parse_http_date`: an HTTP-date in any of RFC 9110's three formats.

### Added: the HTTP/1 client's TLS server name; a client certificate's key is checked (akio-http, akio-tls)

ADR-117, requested by akit (A108, A109):

- `Client::with_tls_server_name(name)`: every `https://` connection sends `name` in SNI and
  verifies the server's certificate against it, in place of the URL's host; connections are still
  pooled by host and port, and an empty name restores the URL's host.
- `ClientConfigBuilder::build` checks that a client certificate's leaf parses and carries the
  key's public key, as the server builder does; a mismatch is `client certificate: private key
  does not match the certificate` (before, every handshake asking for the certificate failed).

### Changed: a request's peer is the client a trusted PROXY header names (akio-http)

ADR-118, requested by akit (A105):

- `Request::peer` and `Context::peer` are the source of the PROXY header akio-mux's
  `ProxyProtocol` layer attached to the connection, when it names one, over HTTP/1.1 and HTTP/2;
  otherwise the socket's peer, as before. `Conn::peer_addr` is unchanged. akio-http now depends on
  akio-mux.

### Added: the HTTP/2 client heeds the response header and idle timeouts and `CancelToken` (akio-http)

ADR-111, requested by akit (A66):

- `H2Client::request` and `open` heed `ClientRequest::response_header_timeout` (from the
  request's END_STREAM to the final response's HEADERS), `response_idle_timeout` (the longest gap
  between DATA frames from the head on, held reads not counted) and `cancel` (`CancelToken`, which
  now covers HTTP/2 requests too): the stream is reset (`CANCEL`), or a request waiting for a stream
  dropped unsent, and the request fails once with `ClientError::HeaderTimeout`, `IdleTimeout` or
  `Cancelled`, the connection left to its other streams.

### Added: a stream coding any response filter can set, and compressed copies of cached files (akio-http)

ADR-112, requested by akit (A90, A91):

- `akio_http::Coding` (`gzip`, `deflate`, `br`, `zstd`, `name`), `Response::set_stream_coding` /
  `stream_coding` and `Response::is_streaming`: a response filter of the caller's own picks the
  coding a streamed body is encoded with, as the `compress` middleware does.
- `Response::keep_until_sent(value)`: a value kept until the response is sent (a streamed one:
  until its `BodyStream` is finished or dropped), for filters that bound responses under way.
- `Files::compress(&[...])`: a file cached in memory is also kept compressed, one copy per coding,
  made once on the disk pool and served to the clients that prefer it.
- `middleware::compressible` is public; it now also takes fonts, icons, BMP and
  `application/ecmascript`, which the `compress` middleware compresses too.

### Added: the HTTP/1 client hands a connection over on `101 Switching Protocols`; a streamed `2xx` to an HTTP/2 extended CONNECT is a tunnel (akio-http)

ADR-113, requested by akit (A93, A94):

- `ClientRequest::upgrade(protocol)` (`Connection: Upgrade`, `Upgrade: <protocol>`) and
  `ResponseHandler::on_upgrade(&ResponseHead, &RawConn) -> Option<Box<dyn RawHandler>>`: a `101`
  to a request that asked to upgrade settles it (its timeouts and token no longer apply) and hands
  its connection to the returned `RawHandler` as a byte stream, with the bytes that followed the
  head; the default (`None`) delivers the `101` as a bodyless response and closes the connection.
- Changed: a `101` no longer returns its connection to the keep-alive pool; a `101` to a request
  that did not ask to upgrade fails it with `ClientError::Protocol`.
- HTTP/2: a streamed `2xx` answer to an extended CONNECT (`Context::stream_response`,
  `Detached::stream_response`) makes the stream a tunnel, as `upgrade_websocket` does: its halves
  close separately (our END_STREAM no longer resets a peer still sending), and a peer that never
  ends its half is reset (`CANCEL`) 5 s after ours ended. HTTP/3 already behaved so (tested).

### Added: the HTTP/2 client's streamed requests reset, timed and ended with trailers; backpressure per stream; the server's stream limit, `GOAWAY`, the connect timeout and ALPN (akio-http)

ADR-110, requested by akit (A51, A52, A53):

- `H2Upload::stream()` gives an `H2Stream` (`Clone`): `cancel()` resets the stream (`CANCEL`) and
  fails `on_event` once with `ClientError::Cancelled` (also `H2Upload::cancel`); `hold_reads(bool)`
  stops giving the stream's receive window back while held, and gives back what is owed on resume;
  `id()`.
- `H2Client::open` applies `ClientRequest::timeout`: the stream is reset and `on_event` gets
  `ClientError::Timeout`.
- `H2Upload::finish_with_trailers(Headers)`; `H2Upload::try_write` (`Err(Closed)` /
  `Err(Overloaded)`), `queued_bytes` and `on_drain`; writes are bounded by the new
  `H2Options::max_queued_bytes` (64 MiB) and batched per post to the I/O thread.
- `H2Client::max_concurrent_streams`, `open_streams` and `waiting_streams`: the client heeds the
  server's `SETTINGS_MAX_CONCURRENT_STREAMS`; a request past it waits, within the new
  `H2Options::max_pending_streams` (1024), else fails with the new `ClientError::Busy`.
- The new `ClientError::Refused`: the streams above a `GOAWAY`'s last stream id (a streamed
  request's `on_event` is now told), requests made after a `GOAWAY` or waiting when it came, and
  streams reset with `REFUSED_STREAM` (were `Protocol("stream refused")` and `Closed`).
  `H2Client::is_open` is `false` once a `GOAWAY` came or was sent.
- `H2Options::happy_eyeballs`: `H2Client::connect`'s race and connect timeout.
- Over TLS, `dial` and `connect` call `ready` once the server's first frame came, and fail with an
  `io::Error` carrying the new `NotH2 { alpn }` (`NotH2::of`) when ALPN did not choose `h2`.
- Changed: a stream whose response ends before its request body is reset (`CANCEL`) rather than
  left half-open; `H2Upload::write` and `finish` return `false` once the stream is over.

### Added: the HTTP/1 client's response header and idle timeouts and its cancellation, a server request that hears its client go, a write timeout changed at run time (akio-http, akio-h3, akio-core, akio-epoll, akio-uring)

ADR-108, additive, requested by akit (A36, A37, A38):

- `ClientRequest::response_header_timeout` and `response_idle_timeout` (defaults in
  `ClientOptions`): the wait for the response's head once the request is written whole (a
  streamed body: from `RequestBody::finish`), and the longest gap between body reads, stopped
  while `ResponseBody::hold_reads` holds them. They fail the request with the new
  `ClientError::HeaderTimeout` / `IdleTimeout` and close its connection; `ClientError::is_timeout`.
- `CancelToken` with `ClientRequest::cancel_with`: cancels a request at any point (dropped before
  it is sent, its connection closed after), failing it once with the new `ClientError::Cancelled`;
  one token may cover several requests.
- `Context::on_gone` and `Detached::on_gone`: run once if the client goes before the response is
  finished: on HTTP/1 the connection closes or the client's EOF comes (akio-core's new
  `ConnInner::on_peer_gone`), on HTTP/2 the stream is reset or the connection closes, on HTTP/3
  through the new `ConnSink::on_gone` (default: never called), which akio-h3 implements.
- Fixed: an HTTP/1 request whose body streams no longer keeps its context and body sink after its
  client went: the session drops them when the connection closes, and closes the connection when
  the client's EOF comes mid-body.
- `Live::set_write_timeout` / `write_timeout`: `Config::write_timeout` is reloadable
  (`Engine::reload` lists it in `applied`), on epoll and io_uring.
- Fixed: the HTTP deadlines' coarse clock lagged by up to a second when a shorter timeout lowered
  the sweeper's tick while it slept (a client's 300 ms header timeout armed then fired after
  about 40 ms). A registration that shortens the tick now updates the clock and wakes the
  sweeper. Test: `akio-http/tests/deadline_clock.rs`.

### Added: bcrypt, the client's certificate on each request, and requests suspended and resumed (akio-crypto, akio-tls, akio-quic, akio-http, akio-h3)

ADR-109, additive, requested by akit (A63, A64, A65):

- `akio_crypto::bcrypt`: `Hash::parse` / `verify` / `Display`, `hash` and `hash_with_salt`, for
  `$2a$`, `$2b$` and `$2y$` hashes as Go and `htpasswd -B` make them.
- `Request::peer_certificates`: the chain the client sent and the TLS handshake verified, on every
  HTTP/1.1, HTTP/2 and HTTP/3 request, shared per connection; `TlsInfo::peer_certificates`,
  `akio_tls::peer_chain` (`PeerChain`) and `akio_quic::Connection::peer_certificates`.
- `Context::suspend` and `Suspended::resume`: a request paused, then gone on with from any thread
  where it stopped (the next middleware, the handler); `Context::suspend_to_pool` runs work on the
  logical pool with it (`503` when the pool is full). Not for a request whose body is streamed.

### Fixed: a connection right after a listener's removal no longer lands on its old sockets (akio, akio-uring, akio-epoll)

`Engine::remove_listener` and `shutdown_listener` (ADR-099) returned once the change was posted to
the I/O threads, and on io_uring a removed listener's `SO_REUSEPORT` sockets kept listening until
the cancellation of their multishot accepts completed. A listener replaced at its own address (the
new one added first, then the old one removed, as akit's reload does) thus had some of the
connections made right after the removal queued on an old socket and reset when it closed: about
one akit reload test run in four on io_uring, more rarely on epoll. The io_uring threads now take
the socket out of listening (`shutdown(SHUT_RD)`) as soon as they handle the removal, and both
calls return once every I/O thread of the listener has handled it (up to a second for a busy
thread; without waiting when called on an I/O thread). Regression test:
`tests/runtime_listeners.rs`, a listener replaced at its address 50 times.

### Added: certificate signing requests (akio-x509)

ADR-107, additive: `CsrParams` makes a PKCS#10 request (RFC 2986) for a key, with
subjectAltNames, extKeyUsage and further extensions in an `extensionRequest`, as an ACME client
sends to finalize an order (RFC 8555); `CertificateRequest` parses one strictly from DER or PEM and
checks its signature (`verify_signature`), within `MAX_REQUEST_LEN` and `MAX_ATTRIBUTES`. Fuzz
target `x509_csr`; interop with rcgen and OpenSSL.

### Added: streamed bodies with linked backpressure (akio-http, akio-h3)

ADR-101, additive, requested by akit (A19, A20, A21):

- `ClientRequest::streamed(len)` and `Client::request_streamed(req, on_ready, done)`: an HTTP/1
  request body written as it is produced through a `RequestBody` (`write`, `queued_bytes`,
  `on_drain`, `finish`, `finish_with_trailers`), framed by `Content-Length` or chunked. Such a
  request is never retried nor redirected; a response that comes before the body is finished is
  delivered and the connection closed.
- `Client::request_with(req, handler)`: the response delivered as it arrives to a
  `ResponseHandler` (`on_request_body`, `on_head`, `on_data`, `on_end`, `on_error`), its reads held
  and resumed with `ResponseBody::hold_reads`, abandoned with `cancel`. `max_body_bytes` does not
  apply; redirects are not followed.
- `Context::body_reads()` and `BodyReads::hold`: a streamed request body's reads held and resumed
  (the connection's on HTTP/1.1, the stream's flow-control window on HTTP/2 and HTTP/3). The body
  timeout does not fire while they are held.
- `BodyStream::on_drain(f)`: `f` runs once a streamed response's queued bytes are out of the way.
- `transport::ConnSink::hold_reads` and `transport::BodySink::on_drain`, with defaults, which
  akio-h3 implements.

### Added: static files for a gateway: a path the caller names, twins by q value, candidate paths, directory listings (akio-http)

ADR-100, additive:

- `Files::serve(ctx, path)` serves a path the caller names (percent-encoded, checked as the route
  parameter is), for a caller that routes by a path of its own.
- `Files::twins(&[&str])`: the compressed twins served (`br`, `zstd`, `gzip`), in order of
  preference among equal q values; `&[]` looks none up and sends no `Vary: Accept-Encoding`.
- `Files::try_paths(&[&str])`: candidate paths tried in turn (nginx's `try_files`), `{path}`
  standing for the path asked for and a trailing `/` for a directory. What a path resolved to is
  kept (at most 4096 paths) for `check_interval`.
- `Files::hide(f)`: paths for which `f` returns true are answered 404, and candidates passed over.
- `Files::list_directories(max_entries)`: an HTML listing of a directory without an index file,
  asked for with its slash (off by default).

### Changed: `Files` picks a compressed twin by the client's q values (akio-http)

ADR-100: the twin served is the one `Accept-Encoding` ranks highest by q value (RFC 9110
section 12.5.3), among equals the first of `br`, `zstd`, `gzip`. `br;q=0` no longer gets the `br`
twin; `*` gets the first twin; coding names match in any case.

### Added: an HTTP/1 client request's own `Host` and `User-Agent` (akio-http)

Requested by akit (A11), for a reverse proxy that passes its client's fields on. Additive:

- A `Host` field in `ClientRequest::headers` is sent in place of the one taken from the URL; the
  URL still says where to connect and which name TLS asks for. It is kept on a redirect to the
  same origin and dropped on one to another, as credentials are. Before, the field was dropped.
- An empty `User-Agent` field sends none, and no `User-Agent: akio-http` is added, as Go's client
  takes it. Before, an empty field was sent as it was.

### Added: MP4 files read without I/O and cut into HLS segments (akio-media)

ADR-097, additive (akit's request A7):

- `akio_media::mp4`, a reader of MP4 files that are not fragmented, which does no I/O of its
  own: `Locator` names the header reads that find the `moov` (front or back, 64-bit sizes), and
  `Movie::parse` reads the `moov`. A track has its handler, language, name, timescale, edit
  list, format code and codec (`avc1` / `avc3`, `hvc1` / `hev1`, `av01`, `vp08` / `vp09`, `mp4a`,
  `Opus`; others such as `ac-3` are kept as `Codec::Unknown`).
- `SampleIndex`: a compact index of `stts`, `ctts`, `stss`, `stsc`, `stsz` / `stz2` and
  `stco` / `co64` (1.6 MB for an hour at 60 fps with B-frames and AAC), with lookups by index,
  decode time and keyframe, and walks at constant cost a sample. `Mp4Track::keyframe_at` finds
  the keyframe for a time.
- `Plan` cuts a movie into segments at video keyframes. A `Segment` gives the byte ranges to
  read, its canonical packets (`Segment::packets`), and muxes them as fMP4 (`write_fmp4`) or
  MPEG-TS (`write_ts`); `Plan::vod_playlist` writes the VOD playlist.
- `Limits` bounds the `moov` bytes, boxes, tracks, samples a track, edits and segments; tables
  are checked against their boxes, each other and the file size. Fuzz target `mp4_read`; ffmpeg
  interop test `tests/mp4_interop.rs`.
- `fmp4::Muxer::set_next_sequence`: the `mfhd` sequence number of the next fragment, for
  segments made out of order.

### Added: TUN devices (akio-tun, akio, akio-sys)

ADR-096, additive; akit request A8 (fit's VPN track):

- New crate `akio-tun` (`akio::tun` with the cargo feature `tun`): `TunDevice::create(&TunConfig)`
  opens and configures a TUN interface (Linux `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`, optionally
  multi-queue; macOS `utun`): name, MTU, IPv4 / IPv6 addresses, up / down, later through
  `TunControl`. `TunServer::start` or `Engine::serve_tun` serves it: one I/O thread (epoll /
  kqueue, on every backend) and one connection per queue; the handler gets each packet as a
  borrowed `&[u8]` in `on_data`, `Conn::send` and the cloneable `TunWriter` write packets from any
  thread without blocking, through a queue bounded by `max_queued_bytes` (`Overloaded`), with
  `on_drain` and `hold_reads`. A device deleted underneath closes the connection with the error.
  Needs `CAP_NET_ADMIN` (Linux) or root (macOS); its tests skip without them unless
  `AKIO_TEST_EXPECT_TUN=1`.
- akio-sys: `tun_open`, `tun_is_multi_queue`, `utun_open`, `utun_name`, `read_packet`,
  `write_packet`, `tun_gone`, and interface settings by ioctl: `if_mtu`, `if_set_mtu`, `if_is_up`,
  `if_set_up`, `if_index`, `if_add_addr`, `if_del_addr`.

### Added: TLS routing by SNI without terminating it, and the PROXY protocol (akio-mux, akio-core)

ADR-095, for akit's TLS passthrough and load-balanced listeners:

- `Rule::TlsSni(SniMatcher)` (exact names and one-label `*.` wildcards, without case) and
  `Rule::TlsHello(Arc<dyn Fn(&ClientHello) -> bool>)` (server name, ALPN): route a connection by
  its ClientHello without terminating TLS, the hello being replayed to the route. The hello may
  span several reads and TLS records. A mux with one of these routes sniffs up to
  `TLS_SNIFF_BYTES` (16 KiB + 5) unless `max_sniff_bytes` was set.
- `akio_mux::tls`: `parse_client_hello`, `ClientHello` (`server_name`, `alpn`, `offers_alpn`,
  `legacy_version`, `consumed`), `HelloError`, `SniMatcher`; a standalone parser (akio-mux does
  not depend on akio-tls).
- `akio_mux::proxy`: PROXY protocol v1 and v2 (TLVs, CRC32C checked, LOCAL, IPv4 / IPv6 / Unix).
  `ProxyProtocol::new(next)` / `new_any(next)` reads the header before `next` runs
  (`header_timeout` 5 s, `max_header_bytes` 4096, `versions`, `allow_missing`, `trusted`) and
  attaches it to the connection: `proxy::header(&conn)`, `proxy::client_addr(&conn)`. Dial side:
  `ProxyHeader::proxy` / `local` / `with_tlv`, `encode_v1` / `encode_v2`, `proxy::send_header`.
- akio-core: `Conn::attachment::<T>()` and the hidden `ConnInner::attach`, one write-once value
  per connection set by a listener-side layer before the handler runs.
- Fuzz targets `mux_tls_hello` and `proxy_header`.

### Changed: `Mux` tries routes strictly in order (akio-mux)

A route that matches now waits while an earlier route is still undecided (`NeedMore`), instead
of taking the connection at once; at the sniff limit the first match still wins. This is what
"routes are tried in order" promised, and what an SNI route before `Rule::Tls` needs.

### Added: TCP listeners added, removed and drained at run time; accept filters (akio, akio-core, akio-epoll, akio-uring)

ADR-099 (2026-11-23), additive:

- `Engine::add_listener(Listener) -> io::Result<ListenerId>` binds a TCP listener on a running
  (or not yet started) engine as `build` does: its backend (epoll / kqueue / io_uring with the
  fallback and `strict`), threads (`SO_REUSEPORT` per thread on Linux), `Accel`, inherited
  socket, filter, the engine's config with the live settings, NUMA placement. UDP / datagram
  listeners are refused (`InvalidInput`), DPDK ones `Unsupported`.
- `Engine::remove_listener(id)`: stops accepting and closes the listening sockets; open
  connections keep running and each thread exits after its last one.
  `Engine::shutdown_listener(id, drain)`: also `on_shutdown` for every open connection now, and
  those left after `drain` are closed.
- `ListenerId` (builder listeners `0..n`, then the added ones), `Engine::listeners() ->
  Vec<ListenerInfo>` (id, address, threads, accel, udp), `Engine::set_listener_threads(id, n)`.
- `EngineBuilder::max_listeners(n)` (default 1024): listeners at once, removed ones still
  serving included; `add_listener` past it fails with `QuotaExceeded`.
- `Listener::filter(Fn(&SocketAddr) -> bool)`: runs on the I/O thread right after `accept`,
  before `max_connections`, the acceptor and TLS; refused connections are counted in the new
  `LoopCounters::filtered` (`akio_connections_filtered_total`). `Engine::set_listener_filter` /
  `clear_listener_filter` swap it at run time, in force for every accept after the call (one
  atomic load per accept, no lock).
- The per-thread counters of a removed listener's exited threads leave `Metrics::loops`; their
  counts stay in `Metrics::total`.

### Changed: `Engine::wait` waits for `shutdown` (akio)

`wait` (and so `run`) now returns only after `shutdown` was called and every I/O thread, those
of listeners added at run time included, has exited. An engine with no listener and no client
threads used to return at once.

### Added: server certificates chosen per handshake by a resolver that may answer later (akio-tls)

ADR-098, additive (akit's A2: certificates renewed while serving, and on-demand TLS):

- `CertResolver::resolve(&ClientHelloInfo, CertDone)`, set with
  `ServerConfigBuilder::cert_resolver` or `ServerConfig::builder_with_resolver` (no default
  chain). `ClientHelloInfo` gives the SNI name, offered ALPN protocols, signature schemes, cipher
  suites, version and whether it is QUIC. `CertDone` (`Send`) is answered once from any thread:
  `complete(CertifiedKey)`, `use_default()` (the configuration's own chains), `fail(CertAlert)`;
  dropped unanswered it fails with `internal_error`; `is_abandoned()` says nobody waits.
- An answer inside the call goes on in the same call (no suspension, no wake-up). A later one
  suspends that handshake only, as ADR-062's asynchronous anti-replay store does: the I/O thread
  serves its other connections, and the handshake resumes on it when answered. TCP (engine and
  the blocking stream) and QUIC, TLS 1.2 and 1.3; resumed handshakes do not call the resolver,
  and after a HelloRetryRequest it is called once.
- `cert_resolver_timeout` (10 s, then `internal_error`) and `max_pending_cert_resolutions` (1024
  waiting handshakes per configuration; beyond it a handshake that would wait fails).
- `CertifiedKey` (a chain and key checked once, `from_pem`, `with_ocsp_response`, `chain_der`)
  and `CertStore`, a resolver answering inline from names (exact or `*.` one label deep) that are
  replaced at any time with `insert` / `remove` / `set_default`.
- The static-certificate path is unchanged (one `Option` check per full handshake). Same-run A/B
  on the quiet x86_64 host (`tls-bench handshakes`, in-memory full TLS 1.3 handshakes on one
  core, 10 alternating rounds of 2 s, medians, main 50a82315 → branch): X25519 5526 → 5551/s
  (+0.5%), secp256r1 5663 → 5655/s (−0.1%), X25519 with RSA-2048 3280 → 3284/s (+0.1%), all
  within the rounds' spread.

### Added: protocol handlers on the logical pool, per protocol, off by default (akio-core, akio-http, akio-h3, akio-grpc, akio-arpc, akio-quic)

ADR-094, additive:

- `HttpConfig::handlers_on_logical_pool` (HTTP/1.1), `H2Config::handlers_on_logical_pool` (HTTP/2) and
  `H3Config::handlers_on_logical_pool` (HTTP/3) run each complete request's middleware and handler on the
  engine's logical pool. Handlers may block, and the requests of one connection are served at the
  same time.
  - HTTP/1.1 responses still go out in request order, however inline, pooled and detached requests
    interleave.
  - Requests that may take the connection over, and streamed request bodies, stay on the I/O
    thread.
- `GrpcServer::handlers_on_logical_pool(bool)`: each call's handler runs on the pool and gets its messages one
  at a time and in order; different calls run at once.
- `Routes::handlers_on_logical_pool(bool)` (arpc): requests and notifies run on the pool; streams stay inline.
  The new constant `SERVER_BUSY` is the error text when the pool refuses a request.
- A full pool is answered at once: HTTP `503`, gRPC `RESOURCE_EXHAUSTED`, arpc `SERVER_BUSY`.
- `Context::detach_to_pool(f)` and `Context::executor()` (akio-http, with the new `Executor`) send
  one request to the pool.
- Lower-level pieces:
  - `Conn::execute`, `ConnInner::execute` and the re-exported `Job` (akio-core).
  - `Connection::execute` (akio-quic).
  - `ConnSink::execute` and `transport::dispatch_conn_on_pool` (akio-http).

### Added: the interface a UDP datagram arrived on; mDNS places queries by it (akio-core, akio-epoll, akio-sys, akio-webrtc)

ADR-093 (2026-11-23), additive:

- `UdpBinding::set_recv_interface(on)`: asks the kernel to report the interface every datagram
  of a bound socket arrives on (Linux `IP_PKTINFO`, macOS `IP_RECVPKTINFO`, and
  `IPV6_RECVPKTINFO`; elsewhere `ErrorKind::Unsupported`). Off by default.
- `Conn::rx_interface()`: inside `on_data`, the index of the interface the datagram arrived on
  (0 when not asked for or not reported). Per datagram, like the traffic class and TTL. The
  same UDP loop serves bound sockets on epoll, io_uring and kqueue, so all three report it.
- akio-sys: `enable_recv_interface(fd, on)`, `RecvInfo { tos, ttl, interface }`,
  `RecvBatch::info` / `RecvBatch::interface` (Linux), `recv_from_info` (macOS). The receive
  slots' control buffers grow to 128 bytes (Linux, from 96; macOS, from 64) so that GRO, traffic
  class, TTL and packet info fit together.
- akio-webrtc mDNS asks for it on its sockets and places a query on the interface it arrived
  on, inferring the link from the source address only where the platform does not tell. A
  query from a link that shares its prefix with another interface is now answered on its own
  link; unicast answers (QU, legacy unicast) leave out of the interface the query came in on.
- Sockets that do not opt in receive as before (gpu51, 10 same-run rounds: 0.999 of main; opting
  in costs about 0.6 % on a saturated receiver): A/B in
  [BENCHMARKS](docs/BENCHMARKS.md#bound-udp-socket-receive-arrival-interface-adr-093-same-run-ab).
### Added: a keyframe request when a received video packet is given up (akio-webrtc)

ADR-092 update (2026-11-23, "a keyframe request when a packet is given up"), additive:
`RtcConfig::set_keyframe_on_loss(bool)`, on by default.

Changed behaviour in akio-webrtc (frame mode):

- A video frame out of the frame assembler after a given-up packet (`contiguous = false`) or
  with a packet rebuilt only in part, that is not a keyframe, asks the sender for a keyframe: a
  PLI on a line with `nack pli`, otherwise a FIR on a line with `ccm fir`. With or without the
  video playout buffer, whether the packet was given up at the playout deadline or by count.
- The request stays outstanding until a keyframe comes out or `max(RTT, 200 ms)` passes; only
  an undecodable frame after that sends the next. A request of the application's
  (`Peer::request_keyframe`, `request_layer_keyframe`) counts as outstanding too.
- The playout buffer's overflow request (frames dropped without a keyframe) is rate limited
  the same way and follows the same switch.
- The periodic statistics count the requests (`keyframes_requested`).
- `tools/interop/webrtc`: `client-loss`, pion sending VP8 with one packet left out, checks
  that one PLI comes back and none after pion's keyframe.
- Cost: Same-run A/B on gpu51 (`webrtc-bench`, base `main` `50a82315`): no measurable change; `media` 1.002, `video` / `video-jb` frames per second 1.000 and CPU per frame 0.996 / 1.000 (per-round ratio medians, every range spanning 1). See BENCHMARKS.
### Added: ICMP for host candidates, "packet too big" and "time exceeded" to TURN clients (akio-webrtc, akio-turn, akio-sys)

ADR-091's second update (2026-11-23), the items its first update left:

- akio-webrtc: an `Endpoint`'s own sockets (`bind`, `bind_rtcp`, `bind_transport_socket`) hear
  the ICMP errors their datagrams draw (`Engine::bind_udp_icmp`: Linux `IP_RECVERR`, macOS the
  loop's ICMP socket), and a hard one (port or protocol unreachable) fails the host and
  server-reflexive candidates' checks in flight to that address at once (RFC 8445 section
  7.2.5.2.2), as relayed candidates' already did: a check to a closed port fails in
  milliseconds instead of after seven sends over about eight seconds.
- akio-turn server: a `DONT-FRAGMENT` datagram the kernel refuses as larger than the path MTU
  (`EMSGSIZE`) is reported to the client in a Data indication with `ICMP` "fragmentation needed"
  (3/4) on an IPv4 relay or "packet too big" (ICMPv6 2/0) on an IPv6 one, with the path MTU
  (RFC 8656 sections 13.2 and 14), at most once per relay per 100 ms; it was dropped silently.
- akio-turn server: a client's datagram dropped at TTL 1 draws a Data indication with `ICMP`
  time exceeded (11/0, ICMPv6 3/0) for its peer, at most once per allocation per 100 ms (RFC 8656
  section 13.2's router behaviour, delivered in band). Both are turned off with
  `TurnConfig::relay_icmp(false)` and counted in `TurnStats::icmp`. A peer's datagram dropped
  at TTL 1 is still dropped silently: telling a peer would take a raw socket (declined, ADR-091).
- akio-sys: `path_mtu(dest)`, the MTU of the path to an address as the host knows it (Linux
  `IP_MTU` / `IPV6_MTU`, macOS the interface's).
- `tools/interop/webrtc/turn-ttl-df.sh` checks both reports against akio-turn.
### Added: borrowed WebSocket messages; faster WebSocket echo (akio-ws, akio-core)

ADR-114, additive:

- `WsHandler::on_message_ref(&WsSender, MessageRef<'_>)` hands a message borrowed from the
  connection's buffers (`MessageRef::Text(&str)` | `Binary(&[u8])`), valid for the call: no
  allocation or copy per message. Its default copies the message and calls `on_message`, which
  now has an empty default (implement either). `MessageRef::to_message`, `as_bytes`.
- `protocol::Decoder::decode_ref` with `protocol::EventRef` (and `EventRef::to_event`): the
  decoder's events, borrowed. `decode` is unchanged on top of it.
- The decoder keeps its message buffer between messages (up to 64 KiB) and checks a whole
  unfragmented, uncompressed frame in one read for UTF-8 once instead of twice.
- A server sender over TCP without compression sends unfragmented messages without its mutex
  or a scratch copy (header and payload straight into the connection's queue); its close frame
  is queued together with the close, so a racing sender cannot follow it with a data frame.
- Such a session also sends what its handler sends during one read to the connection in one
  piece at the end of the read (no lock per message); other threads' sends meanwhile follow
  that piece, so nothing caused by a message the handler sent overtakes it.
- The `ws-echo` example (the Autobahn target) uses `on_message_ref`.
### Changed: TCP listeners balance connections over their threads at accept time (akio, akio-core, akio-epoll, akio-uring)

ADR-105. `SO_REUSEPORT`'s hash left 1024 equal connections at 119..141 per thread on 8 threads;
at a fixed 1M requests/s (HttpArena `latency-1m`) the busiest thread saturated and p99 reached
1.35 s while the others had room.

- `akio::Balance { Kernel, LeastConnections }` (`#[non_exhaustive]`) and `Listener::balance`.
  The default is `LeastConnections`: a thread that accepts a connection while it holds more than
  `2 + min / 32` connections above the least loaded thread of its listener hands it to that
  thread before anything is read; `on_open` and every callback run there (ADR-001 holds).
- Off for listeners with an attached `Accel::Ebpf` steering program, engines with NUMA
  `incoming_cpu`, and UDP listeners. `Balance::Kernel` restores the previous behaviour.
- `LoopStats::load`, `handoff_begin` / `handoff_done` and the hidden `akio_core::balance` and
  `Group::set_balance` carry it to the epoll/kqueue and io_uring backends.
### Added: timers on the I/O loop (akio-core, akio, akio-http, akio-epoll, akio-uring, akio-dpdk)

ADR-103, additive:

- `akio::timer` (`akio_core::timer`): `after(delay, f)` runs `f` on the calling I/O thread once
  `delay` has passed, from that loop's own timer wheel: no lock, no other thread, no wakeup; `f`
  need not be `Send`. Never early (millisecond wheel); `Timer::cancel`; `on_loop()`;
  `MAX_TIMERS_PER_LOOP` (2^20, then `Error::Overloaded`), `MAX_DELAY` (clamped). Off an I/O
  thread `after` returns `Error::Closed`. Pending timers are dropped when the loop exits; a panic
  in one is caught and logged. Every loop has one: epoll / kqueue TCP and UDP, io_uring, DPDK.
- `akio_http::Context::after(delay, f)`: detaches the request and calls `f(Detached)` on the
  connection's own I/O thread after `delay` (HTTP/1.1 pipelining order kept; HTTP/2, HTTP/3);
  off an I/O thread it falls back to akio-http's timer thread.
- Book: "Timers on the I/O loop"; the migration guides point at it instead of "your own timer
  thread".
### Changed: the compress middleware keeps its gzip/deflate compressors per thread (akio-http)

`compress` used to make a new akio-deflate compressor for every response, allocating and zeroing
about 260 KiB of window and tables. It now keeps one per thread for each format and level in use,
and `reset()` clears only the hash slots the previous body used. The output is byte-identical.
On an M-series core this saves 2 to 2.4 us per 6 KB JSON body (gzip level 5: 22.3 to 19.6 us;
level 1: 12.0 to 10.1 us). Numbers from the quiet benchmark host are pending.
### Changed: HTTP/3 servers use a QPACK dynamic table by default; QUIC routes remembered per UDP peer (akio-h3, akio-quic)

ADR-102 (2026-11-24):

- akio-h3: `H3Config::qpack_encoder_capacity` defaults to 4096 (was 0). `H3ClientOptions` keeps
  0. A response's `date`, `content-type` and other repeated fields become one-byte references
  after their second use, for peers that offer a table (nghttp3: curl's libcurl-ngtcp2, h2load);
  nothing changes with peers that offer none. `date` is now inserted (one value per second).
  Set the capacity to 0 for the old literals-only encoding.
- Fixed (akio-h3): with the encoder on, inserts the encoder stream could not take (the
  connection's send buffer full) were dropped, and the sections referencing them never decoded.
  Inserts are now made only within the encoder stream's send capacity.
- akio-quic: a short-header datagram to the connection ID its UDP peer used last goes straight
  to that connection, without the endpoint's and the connection table's locks; a server
  connection sends through the socket it used last, without the shared socket table.

### Added: mDNS on interfaces that appear later; queries from no known subnet (akio-core, akio-webrtc)

ADR-078's fourth update (2026-11-23), additive:

- `UdpBinding::join_multicast(group, interface)` / `leave_multicast(group, interface)`: join or
  leave a multicast group on a socket already bound (interfaces by index, as
  `Engine::bind_udp_multicast_on` takes them; joining twice is not an error).
- akio-webrtc mDNS reads the interface list again (at most every 5 s, when a name is resolved or
  a query comes from a source on no known subnet) and joins `224.0.0.251` / `ff02::fb` on the
  interfaces that appeared since `resolve_mdns`, leaving those gone: queries go out on them and
  answers there are received.
- A query from a source on no known subnet (a querier with only a 169.254 address) is now
  answered by multicast with each record on its own link only, instead of with every record on
  the default interface or by unicast; a legacy unicast querier gets only the records of every
  link.

### Added: TTL across the TURN relay, DONT-FRAGMENT, ICMP on macOS, ICMP in ICE (akio-turn, akio-ice, akio-webrtc, akio, akio-core, akio-epoll, akio-sys)

ADR-091's update (2026-11-23), the items it left:

- akio-turn server: relayed datagrams go out with the TTL / hop limit they came in with minus
  one, both ways (RFC 5766 section 12, RFC 8656 section 13); one that arrives with 1 is dropped
  and counted (`TurnStats::ttl_expired`). `TurnConfig::copy_ttl` (true; false sends the socket's
  default). macOS cannot set an IPv4 TTL per datagram: those keep the default.
- akio-turn server: `DONT-FRAGMENT` is acted on: a Send indication carrying it goes to the peer
  with DF set (IPv4 to IPv4 from a UDP client, any family from a stream client); everything
  else goes with DF clear. An environment that cannot set DF answers an Allocate carrying it
  with 420 and drops such Send indications (RFC 8656 sections 7.2 and 11.2).
- For embedders: `IpFields`, `TurnCore::handle_client_ip` / `handle_peer_ip`,
  `TurnEnv::send_to_client_ip` / `send_to_peer_ip` (defaults call the `_tos` methods) and
  `TurnEnv::sets_dont_fragment` (default false).
- akio: `Engine::bind_udp_icmp` reports ICMP errors on macOS too, read from an unprivileged ICMP
  socket of the I/O thread; akio-turn's ICMP relaying (RFC 8656 section 11.5) thus works there.
- akio-ice: `IceAgent::handle_icmp_error`: a hard ICMP error (port or protocol unreachable)
  fails the pairs whose check is in flight (RFC 8445 section 7.2.5.2.2); succeeded pairs are
  left to consent freshness. akio-webrtc feeds it the ICMP errors the TURN server relays for
  relayed candidates.
- akio: `UdpBinding::set_dont_fragment`. akio-sys: `set_dont_fragment`, `dont_fragment`,
  `enable_recv_ttl`, `send_to_ip`, `RecvBatch::ttl` / `tos_ttl`, `Batch::push_ip`,
  `recv_from_ip` (macOS), `parse_icmp_error` / `IcmpPacket`, `IcmpListener` /
  `icmp_source_matches` (macOS). Hidden: `Conn::rx_ttl`, `Conn::enable_rx_ttl`,
  `Conn::send_segments_ip`, `UdpBinding::send_to_ip`, `UdpBinding::enable_rx_ttl`.
- Behaviour changes: akio-turn's relayed datagrams carry the decremented TTL (was the socket's,
  normally 64); its relay sockets send with DF clear (Linux set DF on whatever fit the path MTU);
  a `TurnEnv` that does not override `sets_dont_fragment` now answers an Allocate with
  `DONT-FRAGMENT` 420 instead of accepting it.
- `tools/interop/webrtc/turn-ttl-df.sh` (TTL and DF against coturn across a 1500-byte link),
  `turn-relay-bench` takes `TURN_BENCH_COPY_TTL=0`, new fuzz target `sys_icmp_error`.
  Relay A/B against main: no measurable change; TTL copying costs about 5 % against not copying,
  within the spread (docs/BENCHMARKS.md).

### Changed: faster brotli compression, same output (akio-brotli)

akio-brotli's encoder at levels 0..=6 hashes each searched position once, keeps its bucket
tables in a specialized loop per bucket size with byte counters, and codes commands, writes bits
and clusters literal contexts with less work. Output is bit-identical at every level (one-shot,
with dictionaries and streamed). Same-run A/B on gpu51: Silesia 1.21-1.29x faster at levels
1, 4, 5 and 6, HTTP payloads 1.16-1.45x; the `compress` middleware's streams (quality 4) write
16 KiB pieces 1.21x faster and small events 5% faster. No API change; see docs/BENCHMARKS.md
("Brotli: encoder write cost"). `tools/codec-bench` gains `BENCH_DEC=0` and `BENCH_AKIO=0`.

### Fixed: BitTorrent client on port 0 racing other sockets (akio-bittorrent)

`Client::new` with `listen` on port 0 picks one port number for TCP and UDP by probing both,
then lets the engine bind it; another socket could take it in between and `new` failed with
`AddrInUse` (seen as a flaky `tests/resume.rs` under parallel tests). It now picks again and
retries the binds, up to 20 times. A port given explicitly still fails at once.

### Added: the interface list; mDNS records and IPv4 multicast per interface (akio-sys, akio-core, akio, akio-webrtc)

ADR-078's third update (2026-11-23), additive:

- `akio_sys::interfaces()`: the host's network interfaces from `getifaddrs(3)` (Linux and
  macOS): `Interface { name, index, flags, addrs }`, `InterfaceFlags` (`is_up`, `is_running`,
  `is_loopback`, `is_point_to_point`, `is_multicast`, `bits`), `InterfaceAddr { ip, prefix_len }`
  with `contains`; IPv6 link-local addresses come without macOS's embedded scope id.
  `akio_sys::send_to_on(&UdpSocket, data, addr, interface)` sends a datagram out of an interface
  (`IP_PKTINFO` / `IPV6_PKTINFO`).
- `UdpBinding::send_to_on(data, addr, interface)`: the same on an engine binding; to a multicast
  group it picks the link, as `IP_MULTICAST_IF` would for the whole socket.
- `Engine::bind_udp_multicast_on` takes interface indexes for IPv4 groups too (each joined on the
  interface's first IPv4 address; before, anything but `&[0]` was refused with `InvalidInput`).
  An unknown interface, or one without IPv4, is skipped (`AddrNotAvailable` when none is left).
- akio-webrtc mDNS: IPv4 joins `224.0.0.251` on every multicast-capable interface with an IPv4
  address (loopback aside) and sends out of each, as IPv6 does on `ff02::fb`; each concealed
  address (IPv4, global and ULA IPv6 now too) is probed, announced, withdrawn and answered on the
  interface that holds it only (RFC 6762 §6.2), and answers leave from the interface of the query
  (with the records of that interface, and of addresses in its subnets).
  Loopback addresses, and queries from a source on no known subnet, keep going to and being
  answered on every link.
- `tools/interop/webrtc/mdns4.sh`: two IPv4 links in a container, avahi on the non-default one.

### Added: missing video packets given up at the playout deadline, frame-size-aware delay, Opus's band from SDP, late packets that play (akio-rtp, akio-webrtc)

ADR-092 update (2026-11-23), additive in the API:

- `FrameAssembler::blocked()` (the frame waiting behind a missing packet), `give_up_hole()` and
  `accepts(seq)`.
- `VideoPlayout::hole_deadline(ts, now)`: when to give that packet up. It is the waiting
  frame's playout instant, but no sooner than the round trip, the target delay or 10 ms after
  the wait began. `VideoPlayout::hole_given_up()` counts it.
- `VideoPlayout`'s target adds a frame-size term: a Kalman filter of each frame's delay
  variation against its size change (libwebrtc's jitter estimator) gives the delay per byte,
  times the largest recent size minus the average. Keyframes have room however long ago the
  last one was.
- `VideoPlayoutStats::{size_delay, holes_given_up}`.
- `BurstLossModel::on_late_arrival()`: a packet recorded lost that arrived and played.

Changed behaviour in akio-webrtc:

- With `set_video_playout_buffer` on, a missing video packet is given up at that deadline on
  the peer's timer. The video reordering count is then at least 1024 packets (a bound). On a
  lossy line without repair the picture no longer stands still for about 400 ms at each loss.
- Received Opus is rated for the VoIP metrics in the band of the remote's
  `sprop-maxcapturerate` (≤ 12000 narrowband, ≤ 24000 wideband, else fullband).
- Answers no longer echo the offer's Opus `sprop-maxcapturerate` / `maxplaybackrate`.
- A packet the VoIP metrics reported lost that arrives later and plays is taken back from the
  loss count. One that does not play becomes a discard, now also when the frame assembler
  (no jitter buffer) had moved past it.
- `webrtc-interop`: `AKIO_INTEROP_PLAYOUT=1` receives through both playout buffers.
- Same-run A/B on gpu51 (BENCHMARKS, "Video playout buffer, second pass"): no measurable change end to end (VP8 `media` 0.999; `video-jb` CPU per frame 10.01 against 10.03 µs). The buffer alone takes 16 ns more per frame (60.3 against 43.9 ns), the Kalman update.

### Added: a video playout buffer, E-model delay classes and room noise, VoIP packet length and late discards (akio-rtp, akio-webrtc)

ADR-092 (docs/adr/092-video-playout-emodel-classes.md) closes ADR-087's leftovers, additive:

- `VideoPlayout<T>` (with `VideoFrameFlags`, `VideoPlayoutFrame`, `VideoPlayoutStats`,
  `VIDEO_PLAYOUT_MAX_FRAMES`, `VIDEO_PLAYOUT_MAX_BYTES`): a sans-IO playout buffer for complete
  video frames.
  - Frames play at RTP timestamp plus an offset: the fastest transit plus a target.
  - The target covers the 95th percentile of the frames' delay and the latest keyframes'. While
    frames needed repair, it adds a round trip (NACK).
  - Repaired frames stay out of the statistics.
  - Late frames go out at once.
  - The delay shrinks at once at keyframes, else by a frame a second.
  - Bounded to 256 frames and 16 MiB, dropping up to a keyframe or asking for one.
  - Clock jumps resync.
- E-model:
  - `DelaySensitivity` (G.107 / G.107.2 Table 1), with `EModel::with_delay_sensitivity` and
    `delay_sensitivity`.
  - `EModel::with_room_noise(send, receive)`: G.107's `Ps` / `Pr`; G.107.2 (03/2023) `Ro,FB`
    from the noise. Without it, `Ro,FB` stays 148.
  - `EModel::max_rating`.
  - `EModel::for_codec_monotic`: G.113 Table IV.1.
  - `EModel::opus(OpusBand, bitrate)`: narrowband / wideband Opus with Alahmadi, Pocta and
    Melvin's published instrumental values; fullband as before.
- `BurstLossModel::on_late_discard`.
- akio-webrtc:
  - `RtcConfig::set_video_playout_buffer(Option<PlayoutDelay>)` (off by default): received video
    frames go out at their playout instants (`MediaData::playout_time`). RTX completions are
    flagged repaired, the round trip is used on NACK lines, and a PLI is sent when frames are
    dropped with no keyframe.
  - `RtcConfig::set_voip_delay_sensitivity`.
  - `Peer::video_playout_stats(mid)`.
- Changed values without an API change:
  - The XR VoIP block's burst and gap durations, and the bitrate the E-model rates by, use the
    measured packet length, no longer 20 ms always.
  - A packet reported lost and discarded late in a later interval counts as discarded.
- The audio `JitterBuffer` shares its delay estimator with `VideoPlayout` (same behaviour).
- `webrtc-bench video` / `video-jb` and `jitter-bench video`.
- Same-run A/B on gpu51 (BENCHMARKS, "Video playout buffer"): with the buffer off, no
  measurable change (video CPU per frame 8.94 against 8.92 µs, VP8 `media` 1.000). On, it costs
  1.14 µs of CPU per frame, mostly the timer wake-up; the buffer alone takes 44 ns per frame.

### Added: the brotli container writer's other chunks, repeat metadata checked (akio-brotli)

ADR-079 update (2026-11-23), additive:

- `ContainerWriter::add_resource(&Resource, Option<DictionaryRef>)` writes a resource with all
  its metadata: name, modification time (`mt`), custom fields, footer metadata, the hidden flag
  and a hash code; `DictionaryRef::{Resource, Shared}` picks the dictionary.
  `add_global_metadata(fields)` writes global metadata. `part_size(n)` writes long data as runs
  of partial data chunks (one stream continued with "keep decoder"; with a serialized dictionary
  a stream per part). `repeat_metadata(true)` copies every metadata and footer metadata chunk
  into repeat metadata chunks before the central directory, compressed as one stream when that
  is smaller. Metadata is compressed when that is smaller.
- `Resource::fields`, `Resource::footer` and `Container::read` (resources plus global metadata)
  return the metadata the reader skipped before; a container read is written back as it was.
- The reader checks repeat metadata against the chunks it repeats (RFC 9841 section 8.4.9): one
  per metadata and footer metadata chunk, same order and type, fields copied exactly, a field
  given in one copy given in all whose chunk has it, decodable on its own; the central
  directory's repeat pointer must be the first repeat chunk. Containers that broke these rules
  were accepted before.
- Fuzzing: `brotli_container` covers every chunk kind the writer makes and rewrites containers
  that read.

### Added: TURN ICMP relaying, DSCP across the relay, giving back one family (akio-turn, akio, akio-core, akio-sys)

ADR-091, additive:

- akio-turn server: ICMP errors drawn by datagrams relayed to peers go to the client as Data
  indications with an `ICMP` attribute and no `DATA` (RFC 8656 section 11.5; Linux, through
  `IP_RECVERR`): ICMPv4 destination unreachable / time exceeded, ICMPv6 destination
  unreachable / packet too big / time exceeded, for peers with a permission.
  `TurnConfig::relay_icmp` (true), `TurnStats::icmp`, `TurnCore::handle_icmp`.
- akio-turn server: relayed datagrams keep their DSCP as well as their ECN codepoint, both ways
  (section 14's preferred behaviour, as coturn does). `TurnConfig::copy_dscp` (true; false sends
  DSCP 0). For embedders: `TurnCore::handle_client_tos` / `handle_peer_tos`,
  `TurnEnv::send_to_client_tos` / `send_to_peer_tos`, whose defaults pass the ECN bits to the
  `_ecn` methods.
- akio-turn client: `ClientEvent::Icmp { peer, icmp_type, code, mtu }`;
  `Client::release_family(now, v6)` deletes one relayed address of a dual allocation (Refresh,
  lifetime 0, `REQUESTED-ADDRESS-FAMILY`). STUN: `attr::ICMP`, `Message::icmp`,
  `MessageBuilder::icmp`.
- akio: `Engine::bind_udp_icmp(addr, acceptor, on_icmp)` and `akio::IcmpError`: a bound UDP
  socket whose ICMP errors (destination, its port, type, code, MTU, sender) reach a callback on
  its I/O thread (Linux `IP_RECVERR` / `IPV6_RECVERR`, the error queue drained by the loop;
  elsewhere a plain `bind_udp`). `UdpBinding::send_to` retries once on the error an ICMP
  message leaves pending on such a socket.
- akio / akio-core / akio-sys, hidden or low-level: the whole traffic class byte of a datagram
  (`Conn::rx_tos`, `Conn::send_segments_tos`, `UdpBinding::send_to_tos`, `RecvBatch::tos`,
  `SendBatch::push_tos`, `send_to_tos`, `recv_from_tos`); `akio_sys::recv_icmp`,
  `enable_recverr`, `is_icmp_error`, `IcmpReport` (Linux).
- Behaviour change: akio-turn's relayed datagrams carry the sender's DSCP (was the socket's,
  normally 0), and its UDP relay sockets have `IP_RECVERR` on Linux.
- Not changed: `Endpoint::gather_relay` stays single-family (ADR-091 says why); TTL is not
  copied (done later, see ADR-091's update above).
- `turn-relay-bench` takes `TURN_BENCH_TOS`; `tools/interop/webrtc/turn-dual.sh` checks DSCP,
  ICMP and the per-family release. Relay A/B against main:
  no measurable change; DSCP-marked datagrams cost what ECN-marked ones did (docs/BENCHMARKS.md).

### Changed: no allocation per HTTP request on the server, fewer on the HTTP/3 client and QUIC's hot path (akio-http, akio-h3, akio-quic, akio-core, akio-epoll, akio-buf; ADR-081 update)

docs/adr/081-per-thread-head-storage.md, update of 2026-11-23. No public API change; the
snapshots are unchanged.

- **`text` bodies reuse a buffer per thread.** `Response::text` / `Context::text` given a `&str`
  copy it into the thread's spare body buffer instead of making a `String` (other types convert
  as before; a `String` is moved). HTTP/1.1, HTTP/2 and HTTP/3 give the buffer back (up to
  4 KiB) once the body is copied into their output.
- **The HTTP/3 client builds response heads in reused storage.** `Headers` storage that is
  dropped refills the thread's empty response spare, so a response read and dropped in the
  client's callback lends its storage to the next one. The body stays the caller's `Vec<u8>`.
- **QUIC:** datagram buffers from akio-buf's pool; ACK frames read in place, without a vector;
  one acknowledgment list kept per connection; spare frame lists up to the packets in flight.
- **UDP flush (akio-core, akio-epoll):** the `sendmmsg` map and GSO parts without heap vectors,
  no lists for a one-connection flush, the epoll loop's connection list kept.
- Hidden additions: `akio_buf::text::as_str`, `akio_http::transport::{response_headers,
  recycle_response_body}`; akio-core's hidden `ConnInner::flush_datagram_peers` is generic over
  the connection handle.
- Allocator calls (bpftrace, gpu51): HTTP/1.1, pipelined and h2c 1.0 → 0 per request (epoll and
  io_uring); `quic-bench h3` both ends 6.0 → 2.03 (the client's response body and the
  benchmark's request callback); QUIC bulk 482 → 21.5 per MB.
- Same-run A/B on gpu51 under `quiet.sh` (7 rounds, medians): server user cycles per request
  HTTP/1.1 0.975×, pipelined 1.004× (noise), h2c 0.989×; req/s 1.003× / 1.000× / 1.008×;
  HTTP/3 req/s 1.005× (instructions 0.980×); QUIC bulk 1.025×. A first version taking bodies
  from akio-buf's pool cost pipelined HTTP/1.1 3.3% more cycles and was replaced.

### Added: NUMA placement of the engine's threads, off by default (akio, akio-sys, akio-pool)

ADR-088 (docs/adr/088-numa-placement.md), additive:

- `EngineBuilder::numa(NumaConfig)`: `NumaPlacement::{Off, Spread, Nodes, Interface}` put each
  group's I/O threads on NUMA nodes (thread `i` on node `i % n`, the given nodes, or the network
  interface's node), confined to the node's CPUs or, with `per_cpu`, to one CPU each;
  `incoming_cpu` sets `SO_INCOMING_CPU` on each thread's listening socket; `pool` (default) confines
  the logical pool; `strict` fails the build when placement cannot be done. `AKIO_NUMA`
  (`spread`, `nodes:0,1`, `iface:eth0`, `+cpu`, `+incoming`, `+nopool`, `+strict`) configures an
  engine whose builder was not told. `Engine::numa_status()` reports `Off`, `Placed(NumaReport)`
  or `Degraded(reason)`. Linux only; groups pinned by eBPF CPU steering and DPDK groups are left
  alone.
- io_uring (akio-uring) under placement: each loop's ring is created on a scratch thread pinned to
  the loop's CPU set, so the kernel allocates it on that node (the scratch thread and the
  single-issuer / `R_DISABLED` setup stay); with `UringConfig::sqpoll` the kernel polling thread
  is pinned with `IORING_SETUP_SQ_AFF` to one CPU of the set (loops sharing a set take
  successive CPUs), reported as `ThreadPlacement::sq_thread_cpu`. Also applies to eBPF
  steering's `pin_threads`. Nothing changes with placement off.
- `akio_sys::numa`: `nodes`, `interface_node`, `parse_cpulist`, `set_incoming_cpu`,
  `incoming_cpu` (sysfs, `SO_INCOMING_CPU`).
- `tools/bench/numa.sh`: placement A/B through `AKIO_NUMA`. On one-node gpu51 every mode is within
  noise of placement off (HTTP 0.995–1.005x).

### Renamed: the project is now `akio`

The crates.io name `ak` is taken, so the project is renamed from **only** to **akio** (free on
crates.io with every sub-crate name). Every crate, path, identifier and name changed with it;
the entries below already use the new names (the rename from `flash` to `only`, further down,
keeps its own names).

| Before | After |
|---|---|
| crate `only` (`use only::...`) | `akio` (`use akio::...`) |
| crates `only-*` (`only_*` in code), directories `crates/only-*` | `akio-*` (`akio_*`), `crates/akio-*` |
| environment variables `ONLY_*` (`ONLY_TEST_BACKEND`, `ONLY_UDP_GSO`, `ONLY_CRYPTO_PORTABLE`, `ONLY_LOG` ...) | `AKIO_*` |
| Prometheus series `only_*` (`only_connections_open`, `only_http_requests_total` ...) | `akio_*` |
| log targets `only`, `only_http::access`, `only_webrtc` ... | `akio`, `akio_http::access`, `akio_webrtc` ... |
| thread names `only-io-*`, `only-pool`, `only-quic-timer` ... | `akio-io-*`, `akio-pool`, `akio-quic-timer` ... |
| `only_media::srt` alias `OnlyConn` | `AkioConn` |
| API snapshots `api/only-*.txt`, tool Docker images and volumes `only-*` | `api/akio-*.txt`, `akio-*` |
| repository and site `github.com/lesismal/only`, `lesismal.github.io/only` | `github.com/lesismal/akio`, `lesismal.github.io/akio` |

Generated test fixtures (`tests/data`, the signed messages and CRLs) keep their bytes, so the
X.509 tests' `*.only.test` host names, which those certificates carry, stay as they are.

### Changed: mDNS probe delay, link-local names on their own link (akio-webrtc)

ADR-078's second update of 2026-11-22, no API change: a concealed name's first probe waits a
random 0–250 ms (RFC 6762 §8.1), and a link-local IPv6 address is probed, announced, withdrawn
and answered on its own link only (§6.2); other addresses go out on every link as before.

### Added: TURN dual allocations and ECN across the relay (akio-turn, akio-webrtc)

ADR-083, additive:

- akio-turn server: `TurnConfig::additional_relay_ip` / `additional_public_ip` (relays of the
  other address family). Dual allocations follow RFC 8656 `ADDITIONAL-ADDRESS-FAMILY`:
  - the success response carries two `XOR-RELAYED-ADDRESS`, IPv4 first;
  - each family has its own lifetime, and a Refresh with `REQUESTED-ADDRESS-FAMILY` refreshes
    or deletes one, with its permissions and channels;
  - permissions and channels go to the relayed address of the peer's family (443 for a
    missing one);
  - a partial success carries `ADDRESS-ERROR-CODE` 440 or 508; section 7.2's malformed
    combinations get 400 and unsupported families 440.
  `TurnServer::relays_of` / `TurnCore::relays_of` list an allocation's relayed addresses.
- akio-turn server: relayed data keeps its ECN codepoint both ways over UDP and DTLS (RFC 8656
  section 14): `Conn::rx_ecn` in, `UdpBinding::send_to_ecn` / `Conn::send_segments_ecn` out.
  For embedders: `TurnCore::handle_client_ecn` / `handle_peer_ecn`, and
  `TurnEnv::send_to_peer_ecn` / `send_to_client_ecn`, whose defaults drop the codepoint.
- akio-turn client: `ClientConfig::dual_allocation`, `Client::relayed_addrs`,
  `relayed_addr_for`, `address_error`. STUN: `attr::ADDRESS_ERROR_CODE`,
  `Message::address_error_code`, `MessageBuilder::address_error`.
- akio-webrtc: `RelayServer::dual_allocation(true)` makes `Endpoint::gather_relay_via` add a
  relayed candidate per family.
- coturn 4.6 compatibility: `ADDITIONAL-ADDRESS-FAMILY` at the turnbis draft's 0x8032 is
  accepted (answered with `ADDRESS-ERROR-CODE` at 0x8033 too), and the client sends both
  codepoints.
- Behaviour change: with `additional_relay_ip` set, `REQUESTED-ADDRESS-FAMILY` of that family
  succeeds (was 440), and an IPv6 `relay_ip` with an IPv4 additional one allocates IPv4 by
  default. Without it, a dual request is answered with `ADDRESS-ERROR-CODE` 440 (the attribute
  was ignored).
- `turn-relay-bench` takes `TURN_BENCH_ECN`; new `tools/interop/webrtc/turn-dual.sh` (coturn,
  pion/turn) and `turn-family-raw` mode of the pion tool. Relay A/B against main: no measurable change (docs/BENCHMARKS.md).

### Added: fullband and per-bitrate E-model, an audio jitter buffer (akio-rtp, akio-webrtc)

ADR-087 (docs/adr/087-fullband-emodel-audio-jitter-buffer.md), additive:

- `EModel::fullband(ie_fb, bpl_fb)` (ITU-T G.107.2: `R = 148 - 1.48 Idd - Ie,eff,FB`,
  Eq. 7-10 with the burst ratio and `with_burst_robustness(brf)`, rated `R / 1.48`),
  `EModel::is_fullband`, `EModel::scaled_delay_impairment`.
- `EModel::for_codec_rate(name, plc, bitrate)`: G.113's values by bitrate:
  - G.722 at 64 / 56 / 48 kbit/s, with Appendix III / IV concealment (`Bpl,wb` 7.1 / 5.1);
  - AMR-WB by mode, from Tables IV.3 / IV.4;
  - EVS (SWB mode) by rate from Table V.3, with `Brf` 3.28 at 13.2;
  - G.723.1 at 5.3 kbit/s;
  - Opus, fullband by bitrate, with P.863-derived `Ie,FB` (not ITU-T) and EVS's `Bpl`.

  `Plc::of_codec` knows EVS and AMR / AMR-WB.
- `JitterBuffer<T>` (with `PlayoutDelay`, `JitterBufferStats`, `JitterFrame`, `JitterPush`), a
  sans-IO jitter buffer for audio:
  - adaptive playout delay: the 95th percentile of the delay beyond the fastest transit, longer
    at once, shorter at talkspurts (or a frame per second);
  - reordering, duplicates, late and overflow discards, FEC numbers skipped;
  - bounded to 1024 frames and 256 KiB;
  - its RFC 3611 jitter buffer configuration.
- akio-webrtc:
  - `RtcConfig::set_audio_jitter_buffer(Option<PlayoutDelay>)` (off by default). Received audio
    frames go out in order at their playout instants, with `MediaData::playout_time`. Its
    discards and delay fill the XR VoIP metrics' discard and jitter buffer fields.
  - `Peer::jitter_buffer_stats(mid)`.
  - VoIP metrics rate Opus by its measured bitrate.
- Changed values without an API change:
  - The wideband E-model now follows G.107.1 (06/2019, Corrigendum 1): 95 in `Ie,eff,WB`, its
    own talker echo and `1.29 Idd`. ADR-085 had used 129 and the narrowband echo terms.
  - G.722 takes G.113's diotic `Ie,wb` 5 (was 13).
  - In akio-webrtc, Opus streams rate fullband at their measured bitrate.
- `webrtc-bench audio` / `audio-jb` and akio-rtp's `jitter-bench` example.

### Added: RFC 6679 "ice" / "leap" ECN initiation, the remote's `ect=`, ECN retries, DTLS latching for RTCP and the DTLS client (akio-webrtc, akio-ice)

ADR-086, additive API:

- akio-ice: RFC 6679's STUN ECN-CHECK attribute. `IceAgent::check_ecn` sends an ECN-marked check
  on the selected pair. `handle_receive_ecn` echoes the codepoint a check arrived with.
  `poll_transmit_ecn` returns datagrams with their codepoint. `IceEvent::EcnChecked` reports
  the result. `ECN_CHECK_SENDS` / `ECN_CHECK_INTERVAL` / `ECN_CHECK_GIVE_UP` give the timing.
- akio-webrtc, with ECN marking on:
  - Sections offer `a=ecn-capable-rtp:ice,rtp ...` with ICE (`a=ice-options` adds `rtp+ecn`),
    and answer with the first method of ours the offer lists.
  - "ice" verifies the path with a marked STUN check before marking RTP.
  - `RtcConfig::set_ecn_initiation(EcnInitiation::LeapOfFaith)` marks every packet from the
    start, and offers `leap` first.
  - The remote's `ect=` preference picks the codepoint and the CE response.
  - A failed path retries after 10 s, doubling up to 300 s, and stops after three fallbacks
    from full marking.
  - The `ecn_state` statistic can read "verifying".
- akio-webrtc, latching without ICE:
  - RTCP's own DTLS handshake (no rtcp-mux) latches like RTP's.
  - When this side is the DTLS client, a datagram from an unknown source (a keepalive) starts a
    tentative handshake toward it, held to the SDP fingerprint.
  - `RtcConfig::set_plain_keepalive(every)` sends RFC 6263 STUN Binding Indications on every
    plain path.
  - The endpoint offers STUN from unknown sources to latching peers.
- Fixed: DTLS-SRTP without ICE and without BUNDLE never read the remote fingerprint, so no
  handshake started.
- Fixed: the `webrtc_sdp` fuzz harness took `a=crypto:` inside an echoed `m=` field for a key
  line.
- Not done: DTLS re-keying. No peer re-keys: Chrome and pion refuse DTLS 1.2 renegotiation, and
  DTLS 1.3's KeyUpdate leaves the SRTP keys (ADR-086 §6).
- Interop: `latch.sh` adds RTCP's own handshake and the gateway as the DTLS client. The new
  `ecn6679.sh` runs rtp / leap / ice and a clearing router between two akio peers over a
  Linux NAT.

### Added: the RTSP server's REDIRECT, the client following it; RTMP lookups on reconnect (akio-media)

ADR-080 (docs/adr/080-rtsp-server-redirect-rtmp-lookups.md), additive:

- `RtspServer::sessions()` (`RtspSessionInfo`: id, path, peer, recording, redirected),
  `RtspServer::redirect_session(id, &Redirect)` and `RtspServer::redirect_path(path, &Redirect)`
  move live sessions to another URL with a `REDIRECT` request (RFC 2326 10.15): `Redirect::new(location)`,
  `.at(SystemTime)` (sent as `Range: clock=`), `.grace(Duration)` (10 s). The session keeps
  running until its client tears it down (the server then closes the connection) or until the
  grace after the move passes (the server closes it), so clients that ignore the request end
  cleanly too.
- The RTSP client follows a server's `REDIRECT` in a live session: it answers `200`, tears the
  session down when the `Range` start comes (`clock=` or `npt=`; at once without) and sets up at
  the location right away on the `reconnect` engine (a reconnect, no backoff); without
  `reconnect` it ends with the new `ClientError::Redirected(location)`. Behaviour change: it
  answered `501` before.
- Both clients dial the addresses of a host name in turn until one connects. The RTMP client
  looks the name up again on every reconnect try (on a short-lived thread) and retries a failed
  lookup; `RtmpClient::addr` is the address dialed last. Behaviour change: it dialed the address
  resolved at start on every reconnect.
- Tests: `Range` times, the machine's answers, this crate's server moving reconnecting pulls and
  pushes (TCP, UDP, a `Range` time) to another server, a client that ignores the request closed
  after the grace, address walks, an RTMP name that stops resolving and moves. New
  `tools/interop/media/rtsp-server-redirect.sh`: ffmpeg 6.1.1 (gpu51, playing and recording over TCP and UDP; 9.0.2 on macOS too, but for a UDP recording, not tried) answers our server's `REDIRECT` `501` and carries on; GStreamer 1.24.2 `rtspsrc` and `rtspclientsink` (TCP, UDP) answer `200` and carry on; mediamtx 1.15.3 pulling from our server (a path's `source`, TCP and UDP) does not answer, tears the session down at once and pulls the same URL again. None moves to the location; our server ended each of those sessions at its TEARDOWN or 4 s (the test's grace) after the request. Our client moved by our server to mediamtx: the pull keeps carrying media from it (310 to 335 packets in the check) and the push, moved at a `Range` time, is read back from mediamtx, over TCP and UDP. RTMP: on a Docker network the name `rtmpsrv` moves from mediamtx A (172.31.248.10, removed) to mediamtx B (.20) and our reconnecting push and pull, run in a container there, dial .20 (the pull reconnected 11 times while B's path waited for the push to come back). live555 (openRTSP) was not tried: Ubuntu 24.04 and Debian 12 no longer package it.
- Same-run A/B against main on gpu51 (`quiet.sh`, one pinned core, 9 alternating rounds, medians, head / base): RTMP pull 0.997, RTSP pull 1.000, RTSP RECORD ingest 1.002 (`tests/client_bench.rs`); hub fan-out 0.987 / 0.994 / 1.000 (1 / 16 / 256 subscribers), FLV decode 1.010 (H.264) and 1.006 (H.265) (`tests/media_bench.rs`), all within the noise: nothing on the media path changed (the session list is touched at SETUP / ANNOUNCE and TEARDOWN, the lookups at connect time).

### Performance: opening short ChaCha20-Poly1305 messages; P-256 reduction without `mulx` (akio-crypto)

No API change.

- **ChaCha20-Poly1305 64-byte open 0.84× → 0.98× ring, seal 0.99× → 1.11×** (Zen 4, quiet host,
  same-run A/B). Opening was slow because of stores Zen 4 cannot forward, not because the tag must be
  checked first: the Poly1305 key was read back right after the AVX-512 row kernel stored the
  keystream head with zmm stores, and the AAD's partial block was assembled on the stack and
  read back across narrower stores. The row kernel now also returns the key in general
  registers, writes the head store-only into caller-owned uninitialised storage (no zero fill,
  no 256-byte copy), and the partial block is assembled in registers. 1 KiB open +4%, TLS 1.3
  ChaCha20 records at 1 KiB 1.16× → 1.21× rustls + ring. New `tools/ct-dudect` target
  `chacha20poly1305-open-tag-64` for the short-message path.
- **P-256 on x86_64**: the whole-point routines' Montgomery reduction computes `m·p₃` from shifts
  (`p₃ = 2⁶⁴ - 2³² + 1`) instead of one `mulx` per step, which frees the single multiplier port:
  verify +5.2% (1.09× → 1.15× ring), ECDH +1.7% (1.17×), key generation +1.2%, secp256r1 TLS 1.3
  handshakes 1.07× → 1.10× rustls + ring. The same change in the standalone field
  multiplication (latency-bound inversion chains) gained nothing and was left out.

### Changed: brotli's cost per flushed write halved (akio-brotli)

ADR-074's second update of 2026-11-22, no API change. Writing a meta-block allocates nothing
(buffers kept by the encoder and the stream), prefix codes are built in time proportional to the
symbols used, and a stream sends the last code it wrote for a category again where that costs no
more bits than a new one. Quality 4 on gpu51: 1.98 → 1.07 us per flushed 87-byte event, a
16-event response 56.5 → 35.0 us and up to 7.5% smaller; `Compress::stream` br over HTTP 65.2 →
46.3 us server CPU per 16-event response (1.41x responses/s). One-shot output is bit-for-bit the
same at every level. A stream holds 15 KiB more.

### Added: large-window brotli, the shared brotli framing format, custom word lists in the encoder (akio-brotli)

ADR-079, the rest of RFC 9841; additive API:

- `decompress_large_window(data, limit)`, `Decompressor::large_window(bool)`: large-window
  brotli (RFC 9841 section 6, Google's `BROTLI_DECODER_PARAM_LARGE_WINDOW`), windows 2^10..2^30
  and distances up to 2^31 - 4, decoded as Google's decoder does (the distance alphabet's
  limit included); `max_window_bits` now goes up to 30 and still defaults to 24. Regular decoding
  still refuses such streams.
- `compress_large_window(level, data)`, `Compressor::large_window(bool)` (`window_bits` up to 30).
  Checked both ways against Google's `brotli --large_window` (built from source in Docker on
  gpu51, and 1.2.1), distances past 64 MiB included.
- `read_container(data, limit, lookup)`, `ContainerWriter`, `Resource`: the shared brotli
  framing format (RFC 9841 section 8): containers of resources (data chunks, runs of partial
  chunks continuing one stream), metadata (`id`, `mt`), dictionary references by pointer or by
  hash code (resolved by `lookup`), central directory and final footer, all rules checked.
  Hash codes are opaque: the RFC names HighwayHash but no key. New errors `BadContainer`,
  `MissingDictionary`.
- `compress_with_shared_dictionary` searches the custom word lists of a serialized dictionary
  under their transforms at levels 10 and 11 (it used the prefix only): on alice29.txt level 11
  is 7-11% smaller than before and within 0.4% of libbrotli's quality 11; libbrotli decodes it.
- Fuzzing: new target `brotli_container`; `brotli_shared` also round-trips a dictionary's words
  at levels 10 and 11. `tools/interop/brotli-shared/run.sh` checks large windows against
  Google's CLI and has libbrotli decode our level-11 output.

### Added: mDNS name claiming, goodbyes, unicast hop limit 255 (akio-webrtc, akio, akio-sys, akio-ice)

ADR-078's update of 2026-11-22, additive:

- `UdpBinding::set_unicast_hops(u32)`: the TTL / hop limit of a binding's unicast datagrams
  (`IP_TTL` / `IPV6_UNICAST_HOPS`); `akio_sys::set_unicast_hops_v6` / `unicast_hops_v6`. The
  mDNS sockets of `Endpoint::resolve_mdns` send unicast answers (QU, legacy unicast) with 255,
  as multicast ones, per RFC 6762 §11.
- Concealed names (`Endpoint::conceal_host_candidates`) are claimed per RFC 6762 §8 without
  holding the candidate up: three probes 250 ms apart, then two announcements 1 s apart. Another
  host answering the name with another address, or winning a simultaneous probe's tiebreak,
  makes the endpoint give the name up (no longer answered; new peers get a fresh name).
  `Endpoint::close` sends goodbyes (TTL 0) for its names.
- akio-ice (internal): `Message::probe`, `Message::authority`, `Record::tiebreak`.
- `tools/interop/webrtc/mdns6.sh`: avahi 0.8 publishing a name an Endpoint has claimed reports a
  collision.

### Added: engine-driven TURN TCP allocations and the server's own Connect timeout (akio-turn)

ADR-076's update of 2026-11-22, additive API:

- `client::TcpAllocation` (with `ServerTransport`, `AllocationEvent`): an RFC 6062 TCP
  allocation driven by an `akio` engine. `open` dials the control connection (TCP or TLS) and
  allocates; `connect(peer, acceptor, on_error)` and `accept(id, acceptor, on_error)` dial data
  connections served by the application's own acceptor: the ConnectionBind is a transport layer
  under the handler (and over TLS), so the handler is an ordinary `Conn<H>` that only sees the
  peer's bytes. Failures before that (Connect refused, dial, TLS or bind failing) go to
  `on_error`, once. Timers share one thread per process; dropping the last handle ends the
  allocation.
- `TurnConfig::tcp_connect_timeout` (30 s, the RFC 6062 minimum) and its builder: how long a
  Connect waits for the peer before 447. The core keeps this deadline; `TurnServer` now opens the
  peer connection on its accept thread, so the engine's `Config::connect_timeout` no longer
  applies. Behaviour change: an unanswered Connect fails after 30 s instead of the engine's
  10 s default.
- `ClientError::Io(kind, message)`.
- Fixed: the TCP relay accept loop never cleared its event list, which grew with every event and
  replayed old ones.
- `Endpoint` deliberately does not gather relayed TCP candidates (browsers never allocate them,
  and cannot reach ours without an address they never signal); ADR-076 explains.
- `tools/interop/webrtc/turn-tcp.sh` runs the engine client against coturn, pion/turn and
  akio-turn over TCP and TLS.

### Added: codec-side fields of RTCP XR VoIP metrics (akio-rtp, akio-webrtc)

ADR-085 (docs/adr/085-rtcp-xr-voip-quality-fields.md), additive:

- `EModel` computes ITU-T G.107 with its Table 3 defaults from the formulas (`Ro` 94.77, `Is`
  1.41) and the full delay impairment `Idte + Idle + Idd` in place of Cole and Rosenbluth's fit;
  `EModel::wideband` rates wideband codecs on G.107.1's scale (divided by 1.29 for the R field
  and the MOS); `EModel::is_wideband`.
- `EModel::for_codec(name, plc)`: G.113 planning values for PCMU / PCMA (with and without
  concealment), G729, G723 and G722 (`Ie,wb` 13), and a documented assumption for Opus, which
  has no ITU-T value. `Plc::of_codec`: the concealment a codec's decoder always does.
- `EModel::estimate_report` (the end system delay from the application, its jitter buffer or
  the jitter), `EModelScore::fill` (keeps the application's scores), `VoipMetrics::quality`
  (decodes a received block into `VoipQuality`).
- akio-webrtc: VoIP metrics rate each received audio stream by its codec and carry the codec's
  concealment in RX config. `Peer::set_voip_quality(mid, VoipQuality, Option<EModel>)` takes what
  only the application knows: signal and noise levels, RERL, the jitter buffer, the end system
  delay, an external R factor, its own R / MOS. Fields it leaves out are still sent as 127.
- Changed values without an API change: `EModel::delay_impairment` and `EModel::score` (an
  unimpaired R of 93.21 where the constant was 93.2); Opus and G.722 streams now rate on the
  wideband scale.

### Changed: one allocation per HTTP request on the server (akio-http, akio-h3, akio-core, ADR-081)

The allocations per request left after ADR-025 are gone, except the handler's own body
(docs/adr/081-per-thread-head-storage.md). No public API change.

- **Header storage is reused per thread.** Each thread keeps one spare `Headers` storage for
  request heads and one for response heads (a buffer of up to 4 KiB and up to 64 field
  positions). Request heads take the request spare on HTTP/1.1, HTTP/2 and HTTP/3, and give it
  back with the target when the handler is done with a request it did not detach or upgrade.
  `Response::with_body` (and `text`) takes the response spare, and gets it back once the head is
  encoded. `with_body` keeps its two field positions inline instead of reserving a vector for
  four.
- **HTTP/1.1 response heads use akio-buf's pool.** The connection gives the buffer back once it
  is written. akio-core also gives back a pooled buffer that `send_owned` wrote in full right
  away, and the plaintext buffer TLS has sealed.
- **HTTP/2 requests run in a `Context` on the stack**, not a `Box<Context>`. The connection's
  vector of actions is reused per thread, and its output buffer is taken from the pool instead
  of growing from nothing after every flush.
- akio-http's `#[doc(hidden)]` transport hook gains `request_headers` and
  `recycle_response_headers`, which akio-h3 uses. akio-http depends on akio-buf.
- Allocator calls per request (bpftrace, gpu51, epoll and io_uring): HTTP/1.1 5.0 → 1.0,
  pipelined 5.0 → 1.0, h2c 5.5 → 1.0, `quic-bench h3` both ends 9.0 → 6.0. The one left is the
  handler's response body: `ctx.text(200, "...")` makes a `String` from the `&str`.
- Same-run A/B on gpu51 under `quiet.sh` (7 rounds, medians):
  - Server user cycles per request: HTTP/1.1 0.987×, pipelined 0.938×, h2c 0.940×.
  - Instructions per request: 0.937×, 0.898×, 0.929×.
  - req/s: pipelined 1.031×, h2c 1.042×, HTTP/3 1.016×; plain HTTP/1.1 unchanged (client-bound).

### Added: scalable (L4S) CE response, RFC 6679 signalling, ECN over TURN, DTLS latching, DTLS-SRTP MKIs (akio-rtp, akio-webrtc)

ADR-082 (docs/adr/082-webrtc-l4s-rfc6679-dtls-latching-mki.md), additive; nothing changes by
default:

- **Scalable response to CE.** akio-rtp gains `EcnResponse::{Classic, Scalable}`, set with
  `BandwidthEstimator::set_ecn_response`. With the scalable response CE no longer counts as
  loss:
  - The CE fraction is smoothed per round trip with gain 1/16 (`ce_fraction`; the round comes
    from `set_rtt`).
  - It cuts a third rate by `alpha / 2`, at most once per window.
  - A clean round grows that rate additively.
  - CE that arrives during delay over-use still counts as loss (classic fallback).
  - `on_ecn_counts` takes counter-based ECN feedback.

  akio-webrtc uses the scalable response when it marks ECT(1). While marking, it paces at 1.5x
  the estimate with 1 ms bursts (instead of 2.5x and 40 ms). In a simulated 6 Mbps L4S queue,
  ECT(1) gets 4.9 Mbps with 1.3 ms of queue, against 1.36 Mbps for ECT(0) and 7.3 ms of queue
  without ECN.
- **RFC 6679 signalling.** With ECN marking on, sections offer and answer:
  - `a=ecn-capable-rtp:rtp mode=setread; ect=N`,
  - `a=rtcp-fb:<pt> nack ecn`,
  - `a=rtcp-xr:ecn-sum`.

  akio-rtp gains `EcnFeedback` (RTPFB FMT 8), `EcnSummary` (XR block type 13), `EcnReceiver`,
  `EcnCounters` and `EcnDelta`.

  Without RFC 8888, receivers report per-source counters: early on a first ECT packet or a CE
  mark, with every report, and as summaries next to the report blocks. Senders validate the path
  and feed CE to the estimator from the differences between reports.
- **ECN over TURN, off on TCP paths.** Relayed RTP over a UDP allocation goes to the TURN server
  with its codepoint, which RFC 8656 §12 asks the server to copy. Datagrams from a UDP allocation
  keep their codepoint. ICE-TCP candidates and allocations over TCP or TLS never start ECN: they
  stay off instead of failing.
- **Latching before DTLS-SRTP keys.** Without ICE and with latching on, a ClientHello from an
  unknown source gets a stateless cookie exchange. A cookie'd ClientHello moves the pair to that
  source tentatively. The handshake latches once it completes with the SDP fingerprint; on
  failure, close or a 4 s timeout the pair moves back and the peer stays alive. An `actpass`
  offer is answered `passive` when latching.
- **SRTP MKIs with DTLS-SRTP.** `RtcConfig::set_dtls_srtp_mki_length`: a DTLS client offers an
  MKI in `use_srtp`, a server agrees to the client's, and SRTP / SRTCP then carry it.
- **Interop and fuzzing.** `webrtc-interop` gains `AKIO_INTEROP_SIP=dtls` and
  `AKIO_INTEROP_DTLS_MKI`. `tools/interop/webrtc/latch.sh` gains DTLS-SRTP phone cases. The
  `rtp_rtcp` fuzz target round-trips the RFC 6679 formats.

### Added: RFC 9841 shared dictionaries (akio-brotli)

ADR-069 note of 2026-11-22, additive:

- `SharedDictionary` (`new` parses RFC 9841's serialized format, `raw` wraps a raw prefix;
  `prefix`, `is_raw`), `decompress_with_shared_dictionary`,
  `Decompressor::with_shared_dictionary`, `compress_with_shared_dictionary` (the prefix only;
  no static dictionary words when the dictionary has custom ones) and
  `Error::BadDictionary`.
- Decoding with custom word lists (words of 4 to 31 bytes), custom transform lists with all
  23 operations (`ShiftFirst` / `ShiftAll` included) and several dictionaries chosen by literal
  context with fallback, as Google's decoder does. Transforms follow Google's byte layout
  (prefix, operation, suffix) where RFC 9841's prose lists the operation last.
- Tests: hand-made streams for every transform, shift, context selection and fallback;
  libbrotli's output with four kinds of dictionary (`tests/data/shared`);
  `tools/interop/brotli-shared/run.sh` cross-checks with libbrotli (`BROTLI_EXPERIMENTAL`) both
  ways, 20,000 random dictionaries included; new fuzz target `brotli_shared`.
- Decoding without a dictionary keeps its speed (same-run A/B on gpu51: geometric mean 0.996 of main's speed on libbrotli's streams, 0.999 on our own, within the noise; docs/BENCHMARKS.md, "Brotli shared dictionaries").

### Added: RTSP receiver reports, client redirects and lookups on reconnect; HLS keyframe requests (akio-media)

ADR-084 (docs/adr/084-rtsp-receiver-reports-redirects-lookups.md):

- `RtspConfig::receiver_report_interval` (new, default 5 s): RECORD sessions send the publisher
  RTCP receiver reports (RFC 3550 6.4.2) on each track's RTCP channel or port: the fraction and
  number of packets lost, the extended highest sequence number, the interarrival jitter and
  the LSR / DLSR of its last sender report, with an SDES CNAME. `Duration::ZERO` sends none.
- `RtspClientConfig::receiver_report_interval` (new, default 5 s): the same reports from a
  pull to its server. With zero, the empty reports that went with the keep-alives over UDP stay.
- The RTSP client follows redirects: a `300` to `303`, `307` or `308` with a `Location` before
  PLAY or RECORD is answered starts the handshake again there (absolute `rtsp://` URL or an
  absolute path), up to five in a row; credentials go to the same host and port only; a `301`
  is kept for later sessions. Behaviour change: such responses used to fail the client with
  `ClientError::Status`.
- The RTSP client looks its host name up again for every session (each reconnect, each
  redirect), so a server that moved to another address under the same name is found; a lookup
  that fails on a reconnect is retried instead of ending the client.
- Fix, HLS: a segment past `target_duration` without a keyframe asks the publisher for one
  (`Subscription::request_keyframe`, a PLI for a WHIP ingest), at most once per target.
  Chrome's WebRTC AV1 encoder sends keyframes on request only, so a WHIP stream never closed a
  segment and the multivariant playlist of `tools/interop/media/browser.sh` answered 503.
- Tests: reception statistics (losses, wrap, duplicates, jumps, SSRC change, jitter, LSR /
  DLSR), receiver reports read back from RECORD sessions over TCP and UDP and from pulls of a
  scripted server, redirects (chains, loops, credentials, a remembered `301`), a server name
  that moves while clients reconnect, the HLS keyframe request. New
  `tools/interop/media/rtsp-redirect.sh`: mediamtx 1.15.3 redirects (`source: redirect`) followed over TCP and UDP, UDP
  sessions held 75 s on receiver reports, GStreamer 1.24.2 `rtspclientsink` parsing our reports
  over UDP (over TCP it drops interleaved data), a server name moving between two mediamtx
  containers on a Docker network while our push and pull reconnect (main's client times out).
- Same-run A/B against main on gpu51 (`quiet.sh`, one pinned core, alternating rounds, medians, head / base): RTSP pull 1.024, RTSP RECORD ingest 1.087, RTMP pull 0.998 (`tests/client_bench.rs`, 9 rounds); `bench_segmenting` (7 rounds) MPEG-TS 0.981, MPEG-TS LL-HLS 0.995, fMP4 1.015, fMP4 LL-HLS 1.013, AES-128 0.998 to 1.001, SAMPLE-AES MPEG-TS 1.002, `cbcs` 1.004 (the keyframe request is one comparison per packet once a segment passes the target). The RECORD cost (+18 ns per RTP packet) is the receiver reports' arrival time: the clock is read once per read that brings an RTP packet, and the benchmark reads 255 bytes at a time, about one read per packet; larger reads share one clock read across their packets, and `receiver_report_interval` zero skips it. A first version that read the clock per packet and converted with a u128 division cost 1.113 (pull) and 1.104 (RECORD).

### Changed: brotli streaming encoder, fixed costs per write and per stream (akio-brotli)

ADR-074's update of 2026-11-22, no API change:

- Prefix codes are built and stored in time mostly proportional to the symbols a meta-block
  uses (sparse histogram scans, Huffman depths on the stack, canonical codes for used symbols
  only, run-length coded code lengths prepared once). One-shot output is bit for bit the same
  at every level.
- The streaming `Compressor`'s match tables start at a few KiB and grow with the stream up to
  the level's size for one window (they were sized for three windows by level from the
  start). Streamed output changes by +0.00..0.11%.
- Measured (same-run A/B against main on gpu51; docs/BENCHMARKS.md "Brotli streaming encoder:
  fixed costs"): quality 4, window 18: 4.03 → 1.96 us per flushed 87-byte event, 13.5 → 5.3 us
  per stream, 641 → 6 KiB after 3 events, HTML in flushed 16 KiB writes +8.6%. With akio-http's
  `StreamCompress` defaults, br server CPU per 16-event response 123.5 → 67.5 us (1.83x
  responses/s), 16 x 16 KiB HTML -7%, server RSS per held stream 424 → 9 KiB after 3 events.
- `tools/bench/stream-compress.sh` takes `VARIANTS` / `MEM_VARIANTS` and `base-<coding>`
  variants; new example `stream-cost` (akio-brotli).

### Added: SOCKS5 UDP ASSOCIATE with GSS-API protection (akio-socks, akio-ws)

ADR-071's update of 2026-11-22, no API change:

- With GSS-API per-message protection, `UDP ASSOCIATE` is no longer refused: each datagram
  between the client and the relay is one RFC 1961 encapsulated-data message (§5) wrapped with
  the control connection's context, in the server's relay, `SocksClient::udp_associate` and
  `SocksClient::udp_associate_blocking` (which now accepts protection); datagrams that do not
  unwrap are dropped.
- `GssContext` documentation: `unwrap` should accept out-of-sequence tokens, since datagrams are
  lost and reordered.
- `tools/interop/socks/gssapi.sh` gains UDP cases: the independent Python client against Dante
  and akio-socks' server, akio-socks' client (engine and blocking) against both, levels 0 to 2.
  27/27 in all.

### Added: compressed streamed responses (akio-http, akio-brotli)

ADR-074 (docs/adr/074-compressed-streamed-responses.md), additive:

- `Compress::stream: Option<StreamCompress>` (off by default): the `compress` middleware also
  compresses streamed responses (`Context::stream_response`), the coding negotiated from
  `Accept-Encoding` as for buffered ones (br, zstd when offered, gzip, deflate), on status 200
  with a compressible type and no `Content-Encoding`; `Content-Length` is dropped and
  `Vary: Accept-Encoding` set. One encoder per stream, on HTTP/1.1, HTTP/1.0, HTTP/2 and HTTP/3.
- Every `BodyStream::write` is encoded and flushed (deflate sync flush, zstd and brotli
  `Flush::Flush`), so each server-sent event can be decoded on arrival; `finish` ends the
  coding. Small defaults (`StreamCompress`): gzip / deflate 1, zstd 1 with `zstd_window_log` 17,
  brotli 4 with `brotli_window_bits` 18: about 0.3, 0.5 and 1.3 MiB per open stream.
- akio-brotli's streaming `Compressor` slides its buffer at two windows (it waited for a window
  plus a 1 MiB meta-block), so small windows keep a stream small: quality 4, window bits 18
  from 2.0 to 1.3 MiB per stream. Output unchanged.
- Fixed: `etag()` gave streamed 200 responses the ETag of an empty body.
- Measured (same-run A/B against main on gpu51. With `stream` unset streamed responses run at
  main's speed (16 small events per response 0.999x, 16 x 16 KiB 1.011x); compressed, the
  server's CPU is the limit: 6 / 27 / 110 us more per 16-event response for gzip / zstd / br
  (17 us uncompressed), 0.93 / 0.54 / 0.16 GB/s of HTML per core, event bytes down to 35% / 34% /
  26%, HTML to 18% / 6.1% / 5.4%. Server RSS per held stream (1,000 streams) 148 / 112 /
  424 KiB after 3 events and 268 / 324 / 1,106 KiB after 6,000, against 1.2-2.6 KiB uncompressed; docs/BENCHMARKS.md).

### Added: mDNS over IPv6 with hop limit 255, on IPv6-only links (akio-sys, akio, akio-webrtc)

ADR-078 (docs/adr/078-mdns-ipv6-hop-limit-ipv6-only.md), additive:

- `akio_sys::set_multicast_hops_v6` / `multicast_hops_v6` (`IPV6_MULTICAST_HOPS`, which std
  lacks). `Engine::bind_udp_multicast_on` with an IPv6 group now sends with hop limit 255 and
  multicast loopback on, as the IPv4 path sends with TTL 255 (RFC 6762 §11; avahi with
  `check-response-ttl=yes` ignored IPv6 answers sent with the default hop limit 1).
- `Endpoint::conceal_host_candidates` works when the IPv4 or the IPv6 mDNS socket holds the
  shared port: on an IPv6-only link (no route to `224.0.0.251`) names are answered over
  `ff02::fb` instead of the call failing.
- `tools/interop/webrtc/mdns6.sh`: an IPv6-only container (veth, link-local and ULA addresses)
  running the mDNS tests on epoll and io_uring, and avahi 0.8 resolving our concealed name and
  publishing one we resolve and connect to; `browser.sh` checks Chrome 157 against an endpoint
  whose only host candidate is a concealed IPv6 address. New `webrtc-interop` modes
  `mdns-conceal` and `mdns-resolve`.

### Added: TURN TCP allocations, RFC 6062 (akio-turn)

ADR-076 (docs/adr/076-turn-tcp-allocations.md):

- Server: TCP and TLS clients may ask for `REQUESTED-TRANSPORT` TCP. The relayed address is a
  listening TCP socket (one accept thread per server polls them all and hands connections to
  the engine); Connect opens a connection to the peer from the relayed address (446, 447);
  peers holding a permission that connect to it are announced with ConnectionAttempt; a
  ConnectionBind on a new client connection (same credentials, the control connection's nonce
  accepted) turns it into a raw pipe to the peer. Bound connections bypass the allocation
  shards; backpressure is linked both ways (`hold_reads` / `on_drain`), a peer's bytes before
  the bind are held up to the same mark. Unbound connections close after 30 s; closing either
  side closes the other; the allocation going closes all of them.
- `TurnConfig::{tcp_relays (true), max_tcp_connections (64), tcp_relay_buffer (64 KiB)}`,
  `TurnStats::tcp_connections`; `TurnEnv` gains defaulted methods for TCP relays and
  connections, `TurnCore` gains `tcp_connected`, `tcp_incoming`, `tcp_closed`.
- Client: `ClientConfig::tcp_allocation`, `Client::{connect, create_permission,
  data_connection}`, `ClientEvent::{Connected, ConnectFailed, ConnectionAttempt}`,
  `client::{DataConnection, DataState}` (a sans-io ConnectionBind that hands back the peer's
  first bytes).
- STUN: `Method::{CONNECT, CONNECTION_BIND, CONNECTION_ATTEMPT}`, `attr::CONNECTION_ID`.
- Changed: an Allocate for TCP over UDP or DTLS is now 400 (RFC 6062 section 5.1) instead of
  442; transports other than UDP and TCP stay 442.
- Fuzz target `turn_tcp`; `tools/interop/webrtc/turn-tcp.sh`: coturn's
  `turnutils_uclient -T` against akio-turn, the akio_turn client against coturn, pion/turn and
  akio-turn, pion/turn's TCP allocation client against akio-turn and coturn, over TCP and TLS.
- UDP relay path unchanged: same-run A/B against main on gpu51, `turn-relay-bench 8 6 4` (8 pairs, 100-byte datagrams both ways), 6 alternating rounds under quiet.sh: 308.6k vs 268.0k datagrams/s mean total (1.15x; rounds vary by about ±20 %, so read it as no regression, not a gain).

### Added: ECN-capable RTP, latching media without ICE, congestion control without BUNDLE (akio-webrtc, akio-core, akio-sys)

ADR-077 (docs/adr/077-webrtc-ecn-latching-unbundled-cc.md), additive:

- ECN-capable RTP (`RtcConfig::set_ecn_marking(EcnMarking::{Ect0, Ect1})`, off by default):
  with RFC 8888 feedback and the bandwidth estimator, RTP (never RTCP, STUN, DTLS or SCTP) is
  marked, one packet in four until ten marked packets are reported with their mark, then all;
  a cleared or re-marked mark, or marked packets lost where unmarked ones are not, end marking
  on the path (RFC 6679 §7.2-7.4); CE counts as loss for the estimator. Per transport; a new
  path starts over. Chrome 157 receives ECT(1) and validates the path
  (`tools/interop/webrtc/ecn.sh`).
- Latching media without ICE (`RtcConfig::set_latching(Latching::{Once, Rebind(quiet)})`, off by
  default): an RTP / RTCP packet that authenticates under the transport's SRTP keys (and passes
  the replay check) moves the component's pair to its source; the endpoint offers datagrams from
  unknown sources to latching peers for that check only. `tools/interop/webrtc/latch.sh`: a
  SIP-style phone behind an iptables NAT, rebinding included.
- Sessions without BUNDLE negotiate transport-cc and RFC 8888 again and run one estimator and
  pacer over every transport's feedback: RFC 8888 per transport, transport-wide numbering
  following the remote's (one space, as libwebrtc / Chrome number it, or one per transport once
  the remote shows that), per-transport results aligned and ordered for the estimator; paced
  packets, padding and probes leave on their own transport.
- `PeerStats` gains `ecn_marked_sent`, `ecn_failures`, `ecn_state`, `latched`, `twcc_spaces`.
  akio-core: `UdpBinding::send_to_ecn` (doc-hidden); akio-sys: `send_to_ecn` on Linux.
- Behaviour change: an unbundled session's offers and answers carry transport-cc / `ack ccfb`
  (ADR-072 removed them).
- Tools: `webrtc-bench` example (media / data channel throughput between two loopback
  `Endpoint`s); `webrtc-interop` gains `sip-gateway`, `client … sip`, fec-server `direct` and
  `AKIO_INTEROP_{ECN,LATCH,SIP,BWE}`.

### Added: AES-128 I-frame playlists, RTCP sync for RTSP RECORD sessions, query strings on rendition reports (akio-media)

ADR-075 (docs/adr/075-media-aes-iframes-record-sync-report-queries.md):

- HLS I-frame playlists with AES-128 (`HlsConfig::iframe_playlist` was ignored there): each
  I-frame is a resource of its own, `/<path>/iframe-<n>.ts` (`.m4s`), the bytes ADR-070's range
  names encrypted whole with its segment's key, the IV its media sequence number in the I-frame
  playlist; listed without `EXT-X-BYTERANGE` after its segment's `EXT-X-KEY`. Kept with its
  segment and counted against `max_bytes`. Byte ranges into AES-128 segments cannot be
  decrypted by players (no PKCS #7 padding mid-segment). Clear I-frame playlists no longer
  start with `EXT-X-KEY:METHOD=NONE`.
- `RtspConfig::rtcp_sync` (new, default on): RECORD sessions line their tracks up by the
  publisher's RTCP sender reports, as the client's pull does (ADR-070): interleaved RTCP
  channels, RTCP muxed on the RTP channel, the UDP RTP and RTCP ports. `false` keeps the
  arrival-based times of before.
- Behaviour change, the hub: audio (any non-video packet) timed before the first packet a
  subscriber hears is left out until audio reaches that time, rather than handed to sinks that
  clamped it to one repeated timestamp (synchronized streams and AAC priming can lead the GOP's
  keyframe; ffmpeg playing over RTSP reported non-monotonic DTS).
- LL-HLS `EXT-X-RENDITION-REPORT` URIs carry the request's query string without its `_HLS_`
  directives, so tokens reach the other rendition's blocking reloads.
- Tests: AES-128 I-frames decrypting to the unencrypted ranges (both formats, parts, key
  rotation); ffmpeg decoding every AES-128 I-frame to one source frame and playing the I-frame
  playlist; RECORD sessions over TCP, RTP-muxed RTCP and UDP fed skewed sender reports (500 ms,
  early and late; 60 s ignored; sync off). `tools/interop/media/hls-iframes.sh`: hls.js and
  Shaka Player (trick play over fMP4) in headless Chrome. New benchmark `rtsp-record` in
  `tests/client_bench.rs`.
- Same-run A/B against main on gpu51 (`quiet.sh`, one pinned core, 7 alternating rounds, medians, head / base): hub fan-out 1.005 / 0.994 / 0.996 (1 / 16 / 256 subscribers; a first version that checked the new floor per subscriber and packet cost 1.043 at 256, now the loop checks floors only while a subscriber has one to pass); RTSP RECORD ingest (`rtsp-record`, new) 1.007, RTSP pull 1.003, RTMP pull 0.996; `bench_segmenting` MPEG-TS 1.065, MPEG-TS LL-HLS 0.981, fMP4 0.961, fMP4 LL-HLS 1.020, AES-128 0.995 to 0.998, SAMPLE-AES MPEG-TS 1.015, `cbcs` 1.002. Nothing changed on the segmenting packet path (sealed I-frames, queries and the new routes are per segment or per request, and not in this benchmark); the plain MPEG-TS and fMP4 cases move in opposite directions and `cbcs` moved from 1.055 to 1.002 between two runs that differed only in hub.rs: code layout. On macOS aarch64 the same comparison is 0.97 to 1.03 throughout.

### Changed: brotli block splitting (akio-brotli)

ADR-069 note of 2026-11-22, no API change; output changes from level 4:

- Literals, insert-and-copy symbols and distances are split into block types with block switch
  commands. Levels 10-11: Google's iterative block splitter and histogram clustering, context
  maps over block types and contexts for literals and distances, meta-blocks of up to twice the
  window (one-shot), and level 11's second parse pass prices literals by block type. Levels
  4-9: Google's one-pass greedy splitter on meta-blocks of 64 KiB or more, kept only when it
  saves 1% of the meta-block.
- Level 11 on the first 20 MB of Silesia went from 4.7% larger than libbrotli 1.2.1 to 4.5%
  smaller, level 10 from +7.6% to +0.8%; HTTP payloads at 11 are +0.9-1.3% (was +0.9-2.6%),
  certificate chains unchanged; levels 4-9 0.2-0.75% smaller on Silesia and 3-4.4% on mixed
  data, HTTP payloads byte-identical (docs/BENCHMARKS.md, "Brotli block splitting").
- Levels 10-11 are about 30% slower on Silesia (unchanged on text and certificate chains),
  level 4 12% slower on Silesia and 1-6% on payloads above 64 KiB that end up unsplit; level 1
  unchanged. The decoder is unchanged; block-typed streams decode like libbrotli's.
- Tests: block types found and written at levels 4-11, an interleaved corpus in the CLI interop
  tests, `brotli_roundtrip` seeds that produce multi-block-type streams.

### Added: SOCKS5 GSS-API authentication, mechanism supplied by the application (akio-socks, akio-ws)

ADR-071 (docs/adr/071-socks-gssapi-pluggable-mechanism.md), additive:

- RFC 1961 (method 1) in the server (`Socks::gssapi(factory, levels)`) and the client
  (`SocksClient::gssapi(factory, level)`): context establishment, the protection-level
  negotiation, and at `Protection::Integrity` / `Protection::Confidentiality` the wrapping of the
  request, the replies and the whole tunnel (`Protection::None`: authentication only). The
  GSS-API mechanism is the application's, behind `akio_socks::gssapi::GssContext` (`step`,
  `wrap`, `unwrap`, `peer_name`); the workspace links no GSS-API library.
- Establishment steps never run on an I/O thread: the server runs them on the logical pool, the
  client on a helper thread resumed through `TransportWaker`. The server's access hook sees the
  GSS-API peer as `Request::user()`. A GSS-API server turns SOCKS4 and "no authentication" off.
- Refused with protection: `UDP ASSOCIATE` (server reply 7; the client refuses GSS-API for UDP;
  lifted since, see the entry above), the client's blocking helpers (also when the proxy grants
  more than asked), `sockmap`
  splicing, a server inside `Tls::server`.
- `tools/interop/socks/gssapi.sh`: MIT Kerberos KDC in Docker, akio-socks client and server
  (through a test-only `python3-gssapi` shim), Dante rebuilt with GSS-API and an independent
  RFC 1961 client: 15/15 at every level.

### Added: protobuf `utf8_validation = NONE` (akio-protobuf, akio-protobuf-build)

Additive:

- `string` fields with `features.utf8_validation = NONE` are generated as
  `akio_protobuf::ProtoString` (bytes, decoded without a UTF-8 check: `to_str`,
  `to_string_lossy`, `as_bytes`; codec `encoding::ProtoStringCodec`), in every shape (singular,
  repeated, map keys and values, oneofs, extensions); their getters return `&[u8]`.
  `Config::proto2_unchecked_strings(true)` does the same for proto2 strings (their legacy NONE);
  by default proto2 strings stay `String` and are checked, as before.
- Dynamic messages follow the descriptor: a `string` field that does not require UTF-8 (`NONE`,
  and proto2) keeps contents that are not UTF-8 as `Value::Bytes` (`DynamicMessage::set` accepts
  it there); JSON prints them lossily, the text format escapes and parses them. Behaviour change:
  dynamic decoding of a proto2 string that is not UTF-8 now succeeds (it failed before).
- Descriptors: a map field's features are copied to its entry's key and value, as protoc does.
- Generated code of files without `NONE` is byte-identical; conformance runner v35.1 still
  5627 + 909 passed / 0 failed.

### Changed: musl layout tests (akio-sys)

- `akio_sys::ffi`'s layouts and constants are now checked against the `libc` crate on
  `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` (Alpine) too. musl's
  `struct cmsghdr` is 4-aligned where the kernel's and ours are 8-aligned (sizes and offsets
  agree); nothing else differs. docs/api-stability.md lists Linux with musl as tier 2.

### Added: monoio in the benchmark harness, quiche interop (tools)

- `tools/bench-ref/monoio-ref`: a monoio 0.2 reference server (thread-per-core, one runtime and
  one `SO_REUSEPORT` listener per thread; TCP echo, HTTP/1.1 `/plaintext` and `/json` with
  pipelining), run by `tools/bench` as `monoio-uring` and `monoio-epoll` (its io_uring and legacy
  drivers); `http.sh` skips the h2c cases for servers without HTTP/2 (`has_h2`). Results and
  method in docs/BENCHMARKS.md.
- `tools/interop/quic/quiche.sh`: quiche 0.30.1 (built from its release tag in Docker) against
  `akio-h3` / `akio-quic` both ways: quiche-client against the HTTP/3 server (Version
  Negotiation, 50 requests on one connection, a 300 KB POST, a streamed response, 0-RTT, client
  migration) and over HTTP/0.9 (`hq-interop`) against `akio-quic`; `H3Client` and akio-quic's
  client against quiche-server with and without Retry (405 after STOP_SENDING on a 3 MiB upload,
  more concurrent requests than its 100-stream limit, a paused streamed response). The
  `quic-interop` example gains an `hq` mode (server and client), `h3-interop` a `client-quiche`
  mode. No bug found on either side.

### Added: IPv6 autoconfiguration, Accurate ECN and AF_XDP shared UMEM / jumbo frames in the userspace stack (akio-dpdk, akio-ebpf)

ADR-068 (docs/adr/068-userspace-stack-slaac-accecn-af-xdp-multibuffer.md), additive (all off by
default):

- `DpdkConfig::ipv6_slaac`: router solicitations, and from router advertisements a global address
  per /64 prefix (EUI-64), default routers, on-link prefixes, the MTU and the hop limit, with
  RFC 4862 lifetimes. Turns IPv6 on without `address6`. `akio_dpdk::ipv6_addresses(&Device)`
  reports the usable addresses.
- `DpdkConfig::ipv6_dad`: duplicate address detection (RFC 4862 5.4, RFC 7527 nonce) before an
  address is used; a duplicate link-local address turns IPv6 off.
- `DpdkConfig::tcp_accecn`: Accurate ECN (RFC 9768) in the userspace TCP, falling back to RFC 3168
  ECN or none; interoperates with Linux 6.18+ (`net.ipv4.tcp_ecn = 3`).
- `AfXdpConfig::shared_umem` (`XDP_SHARED_UMEM`: one UMEM for all queues, `frames` in total) and
  `AfXdpConfig::multi_buffer` (`XDP_USE_SG`: frames over several chunks, so `DpdkConfig::mtu` up
  to 9000 over AF_XDP); `akio_ebpf::xsk::XskConfig::shared_umem` / `multi_buffer` and
  `XskSocket::send_frags` underneath.
- Router advertisements are copied to every queue of a multi-queue device, like neighbor
  discovery; `#[doc(hidden)] akio_dpdk::tcp_ecn_stats`.

Fixed: on a multi-queue device an ICMP / ICMPv6 error (destination unreachable, packet too big)
for a dialed connection is handed to the queue owning that connection, like its other packets.
RSS hashes such an error by its addresses only, so it could land on another queue and be lost
(a UDP dial to a closed port then timed out instead of failing with "unreachable").

### Added: reconnecting RTMP / RTSP clients, RTCP A/V sync, HLS I-frame playlists, rendition reports, session keys, H.265 `cbcs` (akio-media)

ADR-070 (docs/adr/070-media-reconnect-av-sync-iframes-hevc-cbcs.md), additive:

- **Reconnects**: `akio_media::Reconnect` (`initial_delay` 500 ms, `max_delay` 30 s,
  `max_attempts` `None`; `Reconnect::new(&Arc<Engine>)` holds the engine weakly) in the new
  `RtmpClientConfig::reconnect` and `RtspClientConfig::reconnect` (default `None`). Errors
  another try may cure reconnect after a doubling, bounded backoff that resets once a session
  is live; bad URLs, hub errors and refused credentials stay final. A pull keeps its hub path
  and subscribers and republishes the new session's tracks (a timeline restart for the sinks);
  a push resubscribes from the cached GOP (RTSP: the stream's current tracks announced again).
  RTMP: `ClientState::Reconnecting`, `RtmpClient::reconnects()`, the first connection retried
  too. RTSP: tries on a short-lived thread, `RtspClient::{reconnects, is_live}`; the first
  session must come up.
- **RTSP A/V sync**: `RtspClientConfig::rtcp_sync` (default `true`): a pull maps each track's
  RTP timestamps to the server's NTP clock from its RTCP sender reports, relative to the first
  track synchronized; corrections only move times forward and apply before the stream goes
  live when the reports come early.
- **HLS I-frame playlists**: `HlsConfig::iframe_playlist` (default `false`):
  `/<path>/iframes.m3u8` (`EXT-X-I-FRAMES-ONLY`, `EXT-X-BYTERANGE`; MPEG-TS ranges of the PAT,
  PMT and keyframe PES, an fMP4 fragment per keyframe), `EXT-X-I-FRAME-STREAM-INF` in
  multivariant playlists; not with AES-128. Segment, part and init responses answer a single
  byte range (206 / 416, `Accept-Ranges: bytes`).
- **Rendition reports**: LL-HLS media playlists of a multivariant group carry
  `EXT-X-RENDITION-REPORT` (`LAST-MSN`, `LAST-PART`) for the other renditions.
- **`EXT-X-SESSION-KEY`**: the current key of each encrypted rendition in multivariant
  playlists.
- **SAMPLE-AES `cbcs` for H.265 in fMP4**: the H.265 SPS / PPS / slice segment header parser
  keeps every slice header clear (matches ffmpeg's `trace_headers` on 200 slices).
- Fixed on the way: an RTSP client's hub path is free once `is_closed()` is true (as for RTMP).
- Fuzz target `h265_sample_encryption`; `tests/client_bench.rs` benchmarks the RTMP and RTSP
  pull ingest.
- Performance (gpu51, `quiet.sh`, one pinned core, 7 alternating rounds, medians, head / base):
  HLS segmenting (`bench_segmenting`, ns per packet) MPEG-TS 0.939, MPEG-TS LL-HLS 0.996,
  fMP4 0.950, fMP4 LL-HLS 0.921 (the segment being written is now borrowed in place instead of
  moved out of the stream state and back for every packet; the I-frame state is boxed),
  AES-128 0.987 to 0.996, SAMPLE-AES MPEG-TS 0.997, `cbcs` fMP4 1.019 (the H.264 / H.265
  dispatch per NAL unit); RTMP pull ingest 1.013 and RTSP pull ingest 1.015 (246 and 269 ns per
  message / RTP packet, `tests/client_bench.rs`).

### Added: a pacer, libwebrtc's FEC masks and protection policy, ECN in RFC 8888, network-state and raised-maximum probing (akio-webrtc, akio-rtp)

ADR-073 (docs/adr/073-webrtc-pacer-fec-policy-ecn.md):

- **Pacer** (akio-webrtc): with the bandwidth estimator on, video, FEC and retransmissions leave
  through a queue drained at 2.5 times the estimate with a 40 ms burst allowance
  (retransmissions first, the queue bounded at 8192 packets / 8 MB, drained faster when its
  oldest packet would wait 2 s); audio is never delayed; transport-wide sequence numbers and
  abs-send-time are written as packets leave; queued media fills probe slots; optional padding
  (`RtcConfig::set_padding_rate`). `RtcConfig::enable_pacing(false)` turns it off; without the
  estimator nothing is queued.
- **Probing** (akio-rtp `BandwidthEstimator`): `set_bounds` at run time probes a raised maximum
  (akio-webrtc: `RtcConfig::set_bwe_bounds`, `Peer::set_bitrate_bounds`);
  `set_network_state_estimate` caps probes at an external link-capacity estimate and probes
  towards it (every 5 s, every 3 s while the delay-based rate holds the estimate under 70 % of
  it); the estimator's own link capacity estimate (`link_capacity`) drives the 3 s probes.
- **FEC** (akio-rtp `fec`): libwebrtc's random / bursty mask tables for groups of up to 12
  packets (`packet_masks`, `FecMaskType`), its group rules across frames and key-frame factors
  (`FecProtection`, `FecEncoder::{set_protection, push_frame}`), and its protection policy
  (`ProtectionPolicy`, `protection_factors`: the code-rate table by loss and bits per frame,
  the RTT-aware NACK/FEC hybrid). akio-webrtc uses them per sent stream; `set_fec_protection`
  bounds the factors; `RtcConfig::set_fec_mask(FecMask::{Random, Bursty})`.
- **ECN in RFC 8888 reports**: the endpoint passes each datagram's ECN codepoint (already read
  by the UDP backends) to the peer, RFC 8888 feedback reports it, and the estimator counts
  CE-marked packets as lost (`PacketResult::ecn`, `BandwidthEstimator::ecn_counts`).
- **FlexFEC on simulcast lines** (one unsignaled FlexFEC stream per encoding, named by MID and
  the repaired RID); **RED for PCMU, PCMA and G.722** (`RtcConfig::enable_audio_red`,
  `red/8000`); **video RED without FEC** (`FecMechanism::Red`; `red` without `ulpfec` accepted).
- **Partially rebuilt ULPFEC packets** reach the depacketizer (`FecDecoder::take_partials`,
  `FrameAssembler::push_partial`, `Frame::partial`; such frames are not `contiguous`).
- **R factor and MOS** from the E-model (ITU-T G.107: `EModel`, `mos_from_r`,
  `BurstLossModel::{loss_fraction, burst_ratio}`) in akio-webrtc's RTCP XR VoIP metrics.
- Statistics (`PeerStats` event): `fec_partial`, `paced_dropped`, `ecn_ect_received`,
  `ecn_ce_received`, `ecn_ce_reported`.
- Changed behaviour: media is paced when the estimator runs; FEC protection follows
  libwebrtc's policy instead of three times the loss (with NACK and an RTT under 20 ms, delta
  frames get no FEC); FlexFEC is offered on simulcast lines; VoIP metrics carry R and MOS.
  akio-rtp (internal tier): `PacketResult` has a new field `ecn` and `Frame` a new field
  `partial`.
- Tests: simulated time (a keyframe spread over 156 ms at a 1 Mbps estimate while audio leaves at
  once, retransmission order, queue bounds, a raised maximum probed, ECN through RFC 8888, PCMU
  RED at 10 % loss 297-298 of 300 frames against 263-268, partial frames, simulcast FlexFEC);
  libwebrtc's tables and policy values; estimator links (a raised maximum reached in 0.15 s, a
  network state estimate holding probes, 20 % CE cutting the estimate as 20 % loss). Interop:
  `tools/interop/webrtc/pacing.sh` with Chrome 157 (largest burst towards Chrome 4 packets
  paced against 7 unpaced, 0 against 15 bursts of 6+; Chrome decodes 299-300 of 300 frames),
  `fec.sh` unchanged (ULPFEC 381/400, FlexFEC 391/400 frames at 5 % loss without NACK); real
  loss (`tests/netem.rs`, `tc netem loss 5%` in Docker, NACK removed): 251 of 300 frames whole
  without FEC, 300 with ULPFEC, 299 with FlexFEC, 300 with FlexFEC paced.
- Benchmarks (gpu51, same-run A/B): same-run A/B against the branch point 57696b6b on gpu51 (`quiet.sh`,
  CPUs 2-9, 7 alternating rounds, medians), one-way VP8 between two loopback `Endpoint`s:
  default configuration (no estimator, so no pacer) 0.999x (142.7 vs 142.8 MB/s); FEC held at
  64/256, ULPFEC 0.993x (120.2 vs 121.1 MB/s) and FlexFEC 0.994x (122.2 vs 122.9 MB/s), the
  difference being libwebrtc's masks, whose FEC packets cover more media packets than the
  interleaved ones did (a first build that re-evaluated the policy per frame measured 0.988x /
  0.981x).

### Added: WebRTC transports without BUNDLE or ICE, SDES MKIs and data channels, channel priorities, TURN DTLS connection IDs (akio-webrtc, akio-turn, akio-ice)

ADR-072 (docs/adr/072-webrtc-transports-sdes-priorities-turn-cids.md), additive:

- Data channel priorities (`ChannelPriority` in `ChannelConfig`, sent in DCEP and read from the
  peer's; `Peer::channel_priority` / `set_channel_priority`) and the SCTP stream scheduler
  (`ChannelScheduler`, `RtcConfig::set_sctp_scheduler`; weighted fair queueing by default).
- Sessions without BUNDLE: `RtcConfig::set_bundle_policy(BundlePolicy::Disabled)`, remote offers
  without `a=group:BUNDLE` and answers that refuse ours get an ICE agent, DTLS association and
  SRTP keys per section (Chrome `bundlePolicy: "max-compat"` works both ways);
  `Endpoint::bind_transport_socket` gives the transports sockets of their own;
  `Peer::add_remote_candidate_in` trickles a candidate to its section. Without rtcp-mux such a
  session may now carry several sections and data channels. Transport-wide congestion control
  is not negotiated in an unbundled session.
- RTCP on component 2: server-reflexive and relayed candidates gathered from the RTCP socket by
  `gather_srflx` / `gather_relay(_via)`; `RtcServer::rtcp_candidates` and `RtcServer::rtcp()`
  (`RtcRtcp`) for an ICE-lite server's RTCP listener.
- SDES-SRTP without ICE (`RtcConfig::enable_ice(false)`, or a remote SDP without ICE: plain
  `c=` / `m=` port media, `a=rtcp`), with MKIs and several master keys
  (`RtcConfig::set_sdes_mki_length` for our offers), and next to data channels (DTLS in the
  application section).
- akio-turn: the TURN-over-DTLS listener negotiates 8-byte connection IDs; a client's path
  follows an authenticated record from a new address while its allocation stays
  (`TurnServer::dtls_with_connection_ids` for another length or none). akio-webrtc's DTLS relay
  client sends the server's CID.
- akio-ice: `mdns::MULTICAST_V6`, `mdns::multicast_v6_on`, `Candidate::with_scope_id`,
  `IceAgent::set_fixed_pair` / `is_fixed` (paths without ICE).

### Changed: remote offers without BUNDLE (akio-webrtc)

A remote offer of several sections without `a=group:BUNDLE` is answered with a transport per
section (it was answered with a BUNDLE group the offer did not ask for, which did not connect).

### Added: streaming, dictionaries and better top-level ratios in akio-brotli and akio-zstd

ADR-069 (docs/adr/069-brotli-zstd-streaming-dictionaries-ratios.md), additive API:

- Streaming in both crates, shaped like akio-deflate's: `Compressor::compress(input, &mut out,
  Flush)` (`Flush::{None, Flush, Finish}`, a window setting, `reset`) and
  `Decompressor::decompress_vec` / `decompress` returning `Progress { consumed, produced, done }`,
  with bounded memory whatever the input: the zstd decoder gathers at most a block and holds the
  frame's window (`max_window`, 8 MiB by default); the brotli decoder resumes at the last
  complete command or header unit, so input split anywhere (a byte at a time included) costs
  little more than whole input, and decodes at most 1 MiB ahead of delivery
  (`max_window_bits`). zstd `Flush` writes the pending input as a block, brotli's ends the
  meta-block with an empty metadata block.
- zstd dictionaries: `Dictionary` (raw content, or the trained format of `zstd --train` with
  its Dictionary_ID, tables and repeat offsets), `compress_with_dictionary`,
  `decompress_with_dictionary`, `with_dictionary` on the streaming types; new errors
  `WrongDictionary`, `BadDictionary`. brotli raw (LZ77 prefix) dictionaries, as `brotli -D` and
  Google's `BROTLI_SHARED_DICTIONARY_RAW` use them: `compress_with_dictionary`,
  `decompress_with_dictionary`, `with_dictionary`; new error `WindowTooLarge`. Both checked
  against the CLIs in both directions.
- Ratios: zstd levels 16..=22 parse optimally (libzstd's `btopt` / `btultra`: binary-tree match
  finder, a shortest path priced from symbol statistics carried from block to block, 1-3
  passes) and every level may repeat the previous block's tables; brotli 10..=11 use static
  dictionary words. zstd 19 is now 0.3-1.4% larger than libzstd on the benchmark corpus (was
  1.3-7.6%) and level 16 smaller on Silesia and JSON, brotli 11 0.9-4.7% larger
  than libbrotli (was 3.5-11.4%; block splitting followed, see "brotli block splitting" above).
- Compression at those levels is slower, as in the reference encoders: zstd 19 3.5-10.9 MB/s
  (libzstd 3.9-12), brotli 10-11 about half the speed on text (docs/BENCHMARKS.md).
- Decoding speed about unchanged (same-run A/B against main on the quiet host: -2.2..+4.9% per
  cell; small certificate chains up to 2% slower, about 0.15 us; docs/BENCHMARKS.md).
- Fuzz targets `zstd_stream`, `zstd_stream_roundtrip`, `brotli_stream`, `brotli_stream_roundtrip`.
- akio-http unchanged: streamed responses stay uncompressed (ADR-069 section 4; compressed since, ADR-074).

### Added: kernel TLS for engine connections, hardware-first (akio-tls, akio-core, akio-sys, akio)

ADR-067 (docs/adr/067-kernel-tls-engine-offload.md), additive (off by default):

- `ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` with `akio_tls::Ktls`: after the
  handshake a `Tls` connection on epoll or io_uring hands its record layer to Linux.
  `Ktls::Hardware` offloads only what a NIC with TLS offload does itself (`tls-hw-tx-offload` /
  `tls-hw-rx-offload` on the interface of the local address; AES-GCM), confirms it with the
  kernel's `TlsTxDevice` / `TlsRxDevice` counters and stops offering a combination the driver
  turned down; on hosts without such a NIC it changes nothing. `Ktls::Software` /
  `Ktls::SoftwareTx` use software kTLS (both directions / the send direction only).
  `ktls_zerocopy_sendfile(true)` sets `TLS_TX_ZEROCOPY_RO` on device-offloaded connections.
- With the send direction in the kernel, application bytes skip user-space sealing and
  `send_file` / static files go out with `sendfile(2)`; control records and key updates are
  queued in order. With the receive direction in the kernel, `on_data` gets the decrypted bytes
  directly and control records (alerts, KeyUpdate, close_notify) are read with `recvmsg`.
  io_uring moves the receive direction after stopping its multishot recv on a record boundary.
- `TlsInfo::ktls_tx` / `ktls_rx` (`KtlsPath::Software` / `Hardware`), `TlsCounts::ktls_*` and
  the `akio_tls_ktls_total{side, dir, path}` metric.
- akio-core: `Transport::{wants_offload, offload, kernel_send, take_ops, kernel_record}`
  (default methods), `Offloaded`, `SocketOp` (Linux).
- akio-sys: `netdev_tls_offload`, `netdev_features`, `interface_addrs`, `tls_stat`,
  `ktls_tx_zerocopy_ro`, `ktls_rx_expect_no_pad`, `kernel_at_least` (hidden module).
- Features: `akio-tls/ktls` and `akio/ktls`; `experimental-ktls` stays as an alias.
- The benchmark servers take `AKIO_KTLS=off|hardware|software|software-tx`;
  `tools/bench/ktls-engine.sh` runs the engine A/B.
- Performance (docs/BENCHMARKS.md, "Kernel TLS in the engine"): the default build and
  `Ktls::Hardware` on a host without a TLS-offload NIC are unchanged against main (handshakes/s
  and HTTPS req/s within 0.5% on epoll and io_uring). Software kTLS stays slower on this CPU
  (HTTPS 0.77x), as evaluated before. The hardware path is not measured (no such NIC on the test
  host).
- Tests: `crates/akio/tests/ktls.rs` (epoll and io_uring), curl / `openssl s_client` against
  `http-bench` with kTLS (10/10), `tools/interop/tls/run.sh` with `AKIO_INTEROP_KTLS=require`
  (175/175).

### Added: change notifications for the static file cache (akio-http, akio-sys)

ADR-066 (docs/adr/066-static-files-change-notifications.md), additive (off by default):

- `Files::watch(true)`: the cache follows the disk through inotify (Linux) or kqueue
  `EVFILT_VNODE` (macOS) instead of re-checking every `check_interval`. An entry whose
  directories (root down), file and compressed twins are watched is served without touching the
  disk until a change drops it: a write or attribute change, a rename or deletion of the file, a
  twin or a directory on its path, or a lost-event overflow. One `akio-files-watch` thread per
  `Files`; it exits when the `Files` is dropped.
- Entries the notifications cannot vouch for keep the interval rule: on Linux, symlinks and
  files with several hard links; entries read while a change was being reported; entries past
  `Files::max_watches(n)` (default 1024: directory watches, plus one file descriptor per cached
  file on macOS); everything if notifications cannot be set up or break. Not for network or FUSE
  file systems, where other machines' changes produce no notification.
- akio-sys: `FsWatcher` (`watch_dir`, `watch_file`, `unwatch`, `wait`, `wake`), `FsEvent`,
  `WatchId`.
- The hit path on the I/O thread reads one more relaxed atomic; with `watch` off, nothing else
  changes.

### Added: connectionless UDP listeners, `DatagramsHandler` (akio, akio-core, akio-epoll, akio-uring)

ADR-065 (docs/adr/065-connectionless-datagrams.md), additive (per-peer UDP listeners are
unchanged):

- `Listener::udp(addr).serve_datagrams(factory)`: one `DatagramsHandler` per I/O thread instead
  of a `Conn` per peer. `on_datagrams(&Datagrams, &mut Replies)` gets each receive batch as
  `(peer, &[u8])` pairs; replies to any address queued on `Replies` leave together when it
  returns (`sendmmsg`, runs of equal-size datagrams to one address as UDP GSO, on Linux). No peer
  table, idle timeout or `on_open` / `on_close`: memory does not grow with the number of peers;
  `on_shutdown` sends last datagrams.
- `DatagramSender` (`Send + Sync + Clone`; from the factory, `Replies::sender` or
  `Engine::datagram_sender`) sends to any address from any thread.
- Bounded: the reply queue counts against `Config::max_queued_bytes` (`send_to` then fails with
  `WouldBlock`); datagrams waiting for socket space pause reading on that thread.
- epoll, kqueue and io_uring (a ring poll per socket, the same `recvmmsg` / `sendmmsg` path;
  `AKIO_DEFAULT_BACKEND=uring` applies); not DPDK (`Unsupported`). `Engine::set_threads` is
  refused, as for per-peer UDP listeners.
- Example `udp-dns` (a DNS-style responder); `bench-server udp-dgram`. 64 B echo A/B on
  gpu51: per-peer UDP unchanged (1.02x req/s, 1.00x CPU per request); `serve_datagrams` 1.08x
  (epoll) / 1.09x (io_uring) req/s with 7-8% less server CPU per request.

### Added: cookie jar, Happy Eyeballs, DNS cache and `https://` proxies in the clients; SOCKS fragments and TLS; macOS trust settings (akio, akio-http, akio-ws, akio-socks, akio-tls)

ADR-059 (docs/adr/059-client-cookies-happy-eyeballs-proxy-tls.md), additive:

- `akio_http::cookie::CookieJar` and `Client::with_cookies`: RFC 6265 cookies with the RFC
  6265bis rules (Domain and public suffixes: single labels and IPs always, a list through
  `CookieJar::public_suffixes`; Path; Secure, `__Secure-` / `__Host-`; HttpOnly; SameSite across
  redirect chains that leave the first site; Max-Age / Expires, 400-day cap), bounded
  (`CookieLimits`: 4096 bytes, 50 per domain, 3000 in all, least recently used first), applied
  on every hop of a redirect chain. Off unless attached.
- `akio::dns`: a bounded answer cache (`CacheConfig`: fixed TTL of 30 s since `getaddrinfo`
  gives none, 1024 names, failures not cached by default; `set_cache`, `clear_cache`) and
  shared in-flight lookups; Happy Eyeballs v2 (`HappyEyeballs`, RFC 8305: families interleaved,
  an attempt every 250 ms or at once after a failure, losers closed before sending) on one
  bounded racer thread handing the winner to the engine. The HTTP/1 client
  (`ClientOptions::happy_eyeballs`), the WebSocket client (`DialOptions::happy_eyeballs`) and
  the new `H2Client::connect(engine, host, port, ...)` race this way.
- `https://` proxy URLs (TLS to the proxy, its certificate checked by name; TLS inside TLS for
  `https://` / `wss://` targets) for the HTTP and WebSocket clients and `Proxy::from_env`.
- akio-socks: `SocksClient::tls` (TLS to the proxy on the engine methods), sending UDP datagrams
  in fragments (`UdpAssociation::send_fragmented`, `BlockingUdp::send_fragmented`, and the
  server's opt-in `Socks::udp_fragment_size`); the client's UDP association tries the proxy's
  next address when one is unreachable.
- `RootCerts::system()` on macOS applies the user, admin and system trust settings (`security
  trust-settings-export`): distrusted CAs are left out, CAs trusted in the System or login
  keychain are roots, the System keychain's untrusted certificates no longer are.
- Fuzz targets `cookie_parse` and `tls_trust_plist`. Not done: PAC, the Windows store, GSSAPI.

### Added: a complete QPACK encoder and streamed responses on the HTTP/3 client (akio-h3, akio-quic)

ADR-061 (docs/adr/061-qpack-encoder-h3-streamed-responses.md), additive (defaults unchanged: the
encoder stays off, `qpack_encoder_capacity: 0`):

- QPACK encoder (RFC 9204), when `qpack_encoder_capacity` is set: inserts with static or dynamic
  name references or literal names, only for fields seen twice (never paths, dates, lengths,
  validators, ranges, credentials or cookies); Duplicate for referenced entries about to be
  evicted; dynamic name references in literal field lines; post-base references to entries the
  same section inserted; sections that reference unacknowledged entries only within the peer's
  `SETTINGS_QPACK_BLOCKED_STREAMS` (now read from its SETTINGS; at most 64); eviction of
  acknowledged, unreferenced entries only; Section Acknowledgement, Stream Cancellation and Insert
  Count Increment handled as before.
- `H3Client::open(method, path, headers, on_event) -> H3Upload`: a streamed response reported as
  `H3Event::{Head, Data, Trailers, End, Error}` on the connection's I/O thread (not buffered, not
  bounded by `max_body_bytes`), with the request body written through the returned `H3Upload`
  (upload and download at once work). `H3Upload::hold_reads(bool)` pauses and resumes reading
  the response, so QUIC flow control holds the server back; `H3Upload::cancel()` abandons the
  request. `request_timeout` applies until the head.
- `akio_quic::Connection::hold_reads(id, bool)`: hold a stream's delivery; held data stays in the
  receive buffer and the stream window is not extended until resumed.
- Server push stays out (browsers dropped it; ADR-061).
- Testing: unit tests per encoder rule, a new fuzz target `qpack_encoder` (our encoder against our
  decoder over a link that delays and splits the encoder stream, delays acknowledgements and
  cancels streams), `tools/interop/h3/nghttp3-qpack.py` (libnghttp3's QPACK decoder, the one curl
  uses, checks our encoder through the new `qpack-pipe` example: over the wire, curl, quic-go and
  fib advertise no decoder table), end-to-end tests for streamed responses.
- `quic-bench h3` (gpu51, two same-run A/Bs of 7 alternating rounds against main b22519ae): default configuration (encoder off) at parity, 0.997x and 1.001x in two runs (0.999x over all 14 rounds, 863.9k vs 864.8k req/s; the client's request path only gained a check for streamed responses); with both encoders on, 0.991x of the previous encoder with both on (722.1k vs 728.9k), which is 0.833x of the default (the previous encoder: 0.839x), hence the encoder stays off by default.

### Added: asynchronous 0-RTT anti-replay store, rotating session ticket keys, BoGo (akio-tls, akio-core, akio-quic)

ADR-062 (docs/adr/062-tls-async-anti-replay-ticket-rotation-bogo.md), additive (default
configurations behave as before):

- `AsyncAntiReplayStore` / `ReplayCheck` with `ServerConfigBuilder::async_anti_replay_store`:
  a remote store (Redis and the like) answered without blocking the I/O thread. A 0-RTT
  ClientHello that needs the check suspends its handshake (bytes arriving meanwhile wait,
  bounded) and resumes on its I/O thread when the store calls `ReplayCheck::complete` from any
  thread; `ServerConfigBuilder::anti_replay_timeout` (1 s) rejects the early data when no
  answer comes (fail closed, the handshake goes on as a 1-RTT resumption). Over TCP and QUIC.
- akio-core: `Transport::set_waker` (provided method) and `TransportWaker`, which lets a
  transport waiting on something other than the peer have its I/O thread poll it again.
- `TicketKeys` with `ServerConfigBuilder::session_ticket_keys`: rotating session ticket keys,
  one sealing and up to three earlier ones (`MAX_TICKET_KEYS`) still opening their tickets;
  rotated by the application (`rotate`, `set`), per period from a secret the servers share
  (`TicketKeys::derived`: servers sharing tickets rotate in step), or per period at random
  (`TicketKeys::random`). Scheduled keys cap the advertised ticket lifetime at one period.
- `status_request_v2` (RFC 6961): never sent, ignored when received (decision and reasons in
  the ADR). OCSP validation was already done (ADR-038, ADR-049); DEV-PLAN corrected.
- BoGo: a shim (`crates/akio-tls/examples/bogo-shim.rs`) and `tools/interop/tls/bogo.sh` run BoringSSL's test runner at a pinned commit with `tools/interop/tls/bogo_config.json` (disabled areas and known failures, each with a reason): 882 of 8,110 tests pass, none fail unexpectedly, 1,122 unimplemented, 6,106 disabled.

### Fixed (akio-media)

- RTMP pull: once `RtmpClient::is_closed` is true (or `close` / dropping the handle returns), the hub path is free again; before, a connected pull released it only when its connection finished closing, so pulling the same path right away could fail with `HubError::StreamBusy`. The session now shares the publisher through an `Arc`; a same-run A/B on gpu51 (`quiet.sh`, one pinned core, a pull session fed 282,001 messages of the sample FLV) measured 47.17 ms against 47.24 ms before (0.999×).

### Fixed (akio-tls)

- Found by BoGo: a server without TLS 1.3 no longer refuses TLS_FALLBACK_SCSV (RFC 7507); a ClientHello with supported_groups and no key_share gets `missing_extension` instead of a HelloRetryRequest (RFC 8446 §9.2); the TLS 1.2 server acknowledges server_name (RFC 6066 §3); TLS 1.3 padded plaintexts over 2^14 + 1 bytes are `record_overflow` (RFC 8446 §5.4); the TLS 1.2 client refuses a non-empty server_name acknowledgement, and an unsolicited TLS 1.3 one is `unsupported_extension`; a peer leaf whose keyUsage lacks digitalSignature is `bad_certificate` (RFC 8446 §4.4.2.2); CertificateEntry extensions not asked for are `unsupported_extension` (RFC 8446 §4.4.2); a malformed TLS 1.3 pre_shared_key no longer fails a TLS 1.2 handshake; no tickets for a client without psk_dhe_ke (RFC 8446 §4.2.9); several update_requested KeyUpdates before our next application data get one answer (RFC 8446 §4.6.3).

### Added: cross-process BPF steering, listener migration on prefork reloads, and AF_XDP (akio-ebpf, akio-prefork, akio-dpdk)

ADR-063 (docs/adr/063-shared-steering-migration-af-xdp.md), additive (nothing changes unless
asked for):

- `akio_ebpf::SharedSteering`: one `SK_REUSEPORT` program, socket array and Maglev table pinned
  in bpffs and shared by the `SO_REUSEPORT` sockets of several processes. `create` (owner,
  removes the pins on drop), `open`, `at(first, count)` and `join(fds)`, the latter filling this
  process's slots. CPU or hash steering, with the same hash and table as `attach_reuseport`. On
  Linux 5.14+ the program is loaded for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` (`migrates()`): a
  closing listener's accept queue and pending handshakes move to the socket now in their slot,
  whatever `net.ipv4.tcp_migrate_req` says. `SteerInfo::{shared, migrate}`,
  `Probe::{reuseport_migrate, af_xdp}`, `EbpfConfig::shared` (facade).
- `Prefork::bpf_steering(BpfSteering { steering, threads, dir, strict })` (`ListenMode::ReusePort`,
  Linux): the supervisor pins one group per address (`workers * threads` slots), and each
  worker's `listener(i)` joins its own slots. A restarted or reloaded worker takes its slots
  over, so a reload hands the old worker's share to the new one as soon as it is built, and what
  was still queued migrates when the old listeners close. Without privileges or bpffs the
  workers use the kernel's hashing as before (`strict` fails instead). A `ReusePort` reload
  that cannot migrate logs a warning. `Supervisor::bpf_steering`, `DEFAULT_BPF_DIR`.
- `akio_dpdk::Device::AfXdp(AfXdpConfig)`: AF_XDP sockets as a link of the userspace stack,
  next to TAP and AF_PACKET, without DPDK. One socket and one I/O thread per queue, a UMEM per
  socket, the four rings polled by the thread, and a hand-assembled XDP program that redirects
  each queue to its socket. Zero-copy where the driver has it, copy mode otherwise
  (`ZeroCopy`); native, else generic XDP (`XdpMode`, re-exported). The default MAC is the
  interface's own.
- Tests on veth pairs and namespaces only: shared slots, accept-queue and request migration,
  multi-process steering, reloads and a stopped-then-killed worker under connection churn
  (nothing lost, accept counts add up), and the AF_XDP kernel-peer suite (native, generic,
  IPv6, two queues). Fallbacks are tested without capabilities. `tools/bench/afxdp.sh` and the
  `link-bench` example compare AF_XDP with AF_PACKET (docs/BENCHMARKS).

### Added: WebSocket over HTTP/2 (RFC 8441, akio-http)

ADR-060 (docs/adr/060-h2-websocket.md), additive:

- Server: the HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accepts extended
  CONNECT (`:protocol`, with `:scheme`, `:path` and `:authority`; malformed ones are reset with
  `PROTOCOL_ERROR`). `Context::upgrade_websocket` accepts `:protocol websocket` on HTTP/2 as it
  does on HTTP/3 (version 13, origin policy, subprotocol, `permessage-deflate`, answered `200`),
  and a `Router` GET route answers it, so one `.get("/ws", ...)` serves WebSocket over HTTP/1.1,
  HTTP/2 and HTTP/3. `H2Config::enable_connect_protocol` (default on) turns it off.
- Client: `H2Client::websocket(url, &H2WsOptions, handler, done)` and `websocket_blocking` open
  a WebSocket on a stream of the client's connection, next to its requests; they wait for the
  server's SETTINGS. New `H2WsOptions` (config, deflate offer, subprotocols, origin, headers,
  close timeout, `timeout` 10 s, `max_queued_bytes` 8 MiB) and `ClientError::Status(u16)` for a
  refusal.
- Each WebSocket is paced by its stream's and the connection's flow control; sends fail with
  `Overloaded` past `max_pending_bytes` (server, per stream; `max_conn_pending_bytes` per
  connection) or `max_queued_bytes` (client). Close frames end our half of the stream, the
  peer's END_STREAM ends its half; `RST_STREAM` and a lost connection are a close without
  handshake (1006); graceful shutdown closes WebSockets with 1001. A peer that does not end its
  half within 5 s of ours, or does not answer a client's close within its close timeout, is
  reset (`CANCEL`).
- Interop with Go's HTTP/2 both ways over h2c and TLS (`tools/interop/h2ws/run.sh`: net/http
  server, golang.org/x/net/http2 client), and with headless Chrome, which opens the WebSocket on
  the HTTP/2 connection of the page it loaded. New fuzz target `h2_websocket`; `h2_server` seeds with
  extended CONNECT.
- Performance: requests without `:protocol` take the same branches as before. Same-run A/B on
  gpu51 against `b22519ae` (7 interleaved rounds under `quiet.sh`, epoll): h2c 64 × 16 per-round
  ratio median 0.991, h2c 16 × 128 1.004, both inside the rounds' spread (±10–36%); see
  docs/BENCHMARKS.md. Fuzzing on gpu51: `h2_server` 4.8 M and `h2_websocket` 2.3 M runs
  (10 min each), no crashes.

### Added: OTLP over gRPC and TLS, OTLP logs, span events and links, exemplars, export retry (akio-export, akio-log, akio-core, akio-http)

ADR-064 (docs/adr/064-otlp-grpc-tls-logs-events-exemplars.md), additive API:

- akio-export: `ExporterBuilder::otlp_grpc` / `otlp_grpc_with(endpoint, metadata)` export over
  OTLP/gRPC with akio-grpc's client (a private engine with one client I/O thread, started at
  the first push). `https://` endpoints, for gRPC and HTTP, go over akio-tls: the system's roots
  or `tls_roots(RootCerts)`, `tls_client_cert(chain, key)` for mutual TLS, `tls_server_name`.
- akio-export: `logs(level)` installs an akio-log logger whose records go out as OTLP
  `LogRecord`s (`/v1/logs` or `LogsService/Export`): body, severity, key-values,
  `code.file.path` / `code.line.number`, and the trace and span ids of the span current where
  they were logged. `forward_logs(logger, level)` keeps another logger fed; `log_queue(max,
  batch)` bounds the queue (default 4096 / 512); records from the exporter's own threads are
  not exported.
- akio-log: span events and links: `SpanEvent`, `SpanLink`, `Span::add_event` / `push_event` /
  `add_link`, `SpanBuilder::link`, at most `MAX_EVENTS` / `MAX_LINKS` (128) per span with
  `SpanData::dropped_events` / `dropped_links`; exported over OTLP.
- akio-core: exemplars: `Exemplar`, `ExemplarReservoir`, `ExemplarHistogram`,
  `Registry::histogram_with_exemplars`, `HistogramSnapshot::exemplars` / `with_exemplars`.
  akio-http: `HttpMetrics::with_exemplars()` keeps the request span's ids on the latency
  histogram. Exported over OTLP (not in the Prometheus text format).
- akio-export: `ExportStats` gains `otlp_logs_ok` / `otlp_logs_failed`, `otlp_retried`,
  `metric_points_rejected`, `spans_rejected`, `logs_exported` / `logs_dropped` /
  `logs_rejected` / `logs_queued`; the stats collector the matching `akio_export_*` series.

### Changed: akio-export retries failed pushes

- A retryable failure (no connection, timeout, HTTP 429 / 502 / 503 / 504, gRPC `UNAVAILABLE`
  and the other retryable codes) backs the collector off (`retry(initial, max, max_elapsed)`,
  default 1 s to 30 s with jitter, or `Retry-After`) and keeps each signal's failed batch until
  it is `max_elapsed` old (default 5 min), instead of dropping it; metrics are pushed from a
  fresh snapshot when the backoff ends. `retry(.., .., Duration::ZERO)` drops failed batches as
  before. Other failures still drop the batch. Partial successes are counted.
- `flush()` stops at the first retryable failure (what is left stays queued); `spans_queued`
  includes the batch waiting to be retried.
- `https://` endpoints are accepted (they were an error).

### Added: RTCP on its own ICE component, XR receipt blocks and ULPFEC levels in WebRTC peers (akio-webrtc)

ADR-058 (docs/adr/058-webrtc-rtcp-components-xr-ulpfec-levels.md), additive (a default peer's
SDP and behaviour are unchanged):

- Streams without rtcp-mux (RFC 5761, ICE components from ADR-055): `Endpoint::bind_rtcp`
  binds a second socket whose host candidate is ICE component 2 (`Endpoint::rtcp_addr`). Offers
  without `a=rtcp-mux` (SIP endpoints, older RTP stacks) are then answered with `a=rtcp` and RTCP
  on component 2; offers with it (browsers, pion) as before. `RtcConfig::set_rtcp_mux_policy`
  (`RtcpMuxPolicy::Require` default, `Negotiate`, `Off`) decides what our offers say. DTLS-SRTP
  runs a handshake per component (RFC 5764 §4.1: SRTCP keyed by component 2's), SDES-SRTP keys
  both from the SDP; connected once both components are. Such a session has one media section
  and no data channels (no BUNDLE without rtcp-mux); component 2 has host and peer-reflexive
  candidates only; `RtcServer` has none.
- `RtcConfig::enable_rtcp_xr_blocks(XrBlocks)`: RTCP XR loss RLE, duplicate RLE, packet
  receipt times and VoIP metrics (RFC 3611, `a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times
  voip-metrics`, sent when both sides list them; VoIP metrics on audio only) about received
  streams, once a second from a receipt log, thinned to fit a datagram; received ones become
  `XrReceipts` / `VoipMetrics` events and totals in the statistics.
- `RtcConfig::set_ulpfec_level0(Some(l0))`: ULPFEC with protection levels (RFC 5109 §5) on sent
  video, for receivers that read levels (this stack; Chrome reads level 0 only). Off by
  default.
- The CNAME is RFC 7022's random one (`akio_rtp::random_cname`), new per peer connection;
  received SDES items are reported typed (`SourceDescription` event); `PeerStats` says whether
  RTCP is muxed.
- Fuzzing: `webrtc_sdp` also runs a configuration with component-2 candidates, every XR block
  and ULPFEC levels; two seeds without rtcp-mux. Interop: pion has neither a non-mux policy
  nor ICE components, so the check without rtcp-mux is between `Endpoint`s; the browser and
  pion scripts see unchanged SDP.

### Added: several components per ICE stream (akio-ice)

ADR-055 (docs/adr/055-ice-components.md), additive (one-component agents behave as before):

- `IceConfig::components` (default 1): an agent, full or lite, handles a stream of several
  components (RFC 8445), e.g. RTP (component 1) and RTCP (component 2) on their own ports without
  rtcp-mux. `Candidate::with_component(n)` makes a local candidate of component `n` (its priority
  changes, its foundation stays); remote candidates carry their component as before.
- One checklist for every component with the RFC 8445 §6.1.2.6 initial states (of each foundation
  the pair of the lowest component is Waiting, the others Frozen, also when candidates trickle in
  another order) and unfreezing across components; nomination (regular, aggressive,
  renomination), selection, consent freshness and the lite agent's state per component; ICE
  restarts cover every component, each keeping its selected pair until the new generation
  nominates one. The state is `Connected` / `Completed` only once every component has a selected
  pair, `Disconnected` when consent expires on any, `Failed` when a component can no longer get
  one.
- `IceEvent::ComponentSelectedPair { component, local, remote }`,
  `IceAgent::{components, selected_pair_of, send_pair_of}`; `SelectedPair`, `selected_pair()`
  and `send_pair()` stay component 1's.
- Interop: `tests/libnice.rs` and `tools/interop/ice/run.sh` check two components against
  libnice 0.1.21 in five setups (libnice controlling with aggressive and with regular nomination,
  controlled, lite; akio-ice lite). The `ice_stun` fuzz target also drives two-component agents.
  akio-webrtc still muxes RTP and RTCP on component 1; streams without rtcp-mux there are a
  follow-up.

### Added: ULPFEC protection levels, XR blocks from received packets, typed SDES items (akio-rtp)

ADR-053 (docs/adr/053-ulpfec-levels-xr-receipts-sdes-items.md):

- **ULPFEC levels** (RFC 5109 §7.4, any number): `FecHeader::ulp_levels` / `write_level`;
  `FecEncoder::encode_ulp` builds packets from explicit levels and enforces the §7.4 rules;
  `FecEncoder::set_ulp_level0(Some(l0))` protects the first `l0` bytes of every packet with the
  interleaved FEC packets and the rest of the group once (a single loss per group still comes
  back whole, for about `m * l0 + longest - l0` repair bytes instead of `m * longest`). The
  decoder rebuilds packets range by range in any order and returns them once complete
  (`FecDecoder::partially_recovered` counts the rest). The RFC 5109 §10.2 example matches byte
  for byte (M recovery bit per erratum 3461).
- **XR blocks from received packets** (RFC 3611 §4.1-4.3): `ReceiptLog` builds loss RLE,
  duplicate RLE and packet receipt times blocks (with thinning; receipt times in the RTP
  clock), `RecvStream::{enable_receipt_log, receipt_blocks}` feed one from the stream;
  `RleReport::{encode, decode, reported_seqs}` reproduce the §4.1 examples. Bytes match
  pion/rtcp v1.2.20 (whose writer drops the null chunk of odd chunk counts; ours adds it).
- **VoIP metrics** (§4.7): `BurstLossModel::report` with `VoipQuality` (round trip and end
  system delay, signal / noise level, RERL, R factors and MOS when the application has them,
  sent as 127 otherwise or when out of range, PLC, jitter buffer); `pcm_level_dbm0`.
- **SDES items**: `SdesItem` (text items with constants for every registered type, CNAME ..
  MID; PRIV with prefix and value) converts the pairs of `Rtcp::SourceDescription`;
  `random_cname` (RFC 7022). PRIV prefix lengths above 127 now survive parsing (they became
  U+FFFD); texts and BYE reasons are cut to 255 bytes at a character boundary. Bytes match
  pion/rtcp v1.2.20.
- API additive except `FecHeader`'s new public field `ulp_levels` (akio-rtp is internal tier).
  The `rtp_rtcp` and `rtp_fec` fuzz targets cover all of it (gpu51, 16 min each: `rtp_rtcp` 2.90 M runs, `rtp_fec` 1.59 M runs, no finding in the code; an earlier `rtp_rtcp` run caught a too-strict check in the target itself (RLE chunks ending before the block's interval), kept as a regression input).
- Not done: wiring into akio-webrtc (XR receipt / VoIP blocks, ULPFEC levels, random CNAMEs);
  partially recovered packets are not handed out; no R factor / MOS estimation.

### Added: TURN over DTLS, mDNS over IPv6 and SDES-SRTP (akio-turn, akio-webrtc, akio)

ADR-054 (docs/adr/054-turn-dtls-mdns-ipv6-sdes.md):

- `TurnServer::dtls(&tls::ServerConfig)`: TURN over DTLS (RFC 7350) on a UDP listener, with
  the TLS listener's certificate: stateless cookies, DTLS 1.3 with a DTLS 1.2 fallback, one
  STUN / ChannelData message per record, an allocation per DTLS association (freed by
  close_notify, a fatal alert, idle timeout or a new handshake from the same address);
  `TurnServer::dtls_relay_of`. akio-turn now depends on akio-dtls.
- `RelayServer::dtls` and `turns:host[:port]?transport=udp` URLs (no longer an error):
  `Endpoint` allocations inside a DTLS association on the endpoint's own UDP socket, the
  server's certificate verified against the TLS client configuration's roots; a UDP relayed
  candidate plus the server-reflexive one; made again after a lost association.
- mDNS over IPv6: `Endpoint::resolve_mdns` adds a `[::]:5353` socket joined to `ff02::fb` on
  every interface with a link-local address, queries per interface, answers on the query's link;
  remote link-local addresses keep their interface (SDP carries no scope id). IPv4 behaviour is
  unchanged; hosts without IPv6 run IPv4 only.
- `akio`: `Engine::bind_udp_multicast_on(group, interfaces, acceptor)` joins an IPv6 multicast
  group on each listed interface index (0: the default one; interfaces refusing the join are
  skipped). IPv4 groups take only `&[0]` (`InvalidInput` otherwise). `bind_udp_multicast` is
  `bind_udp_multicast_on(group, &[0], ..)`, unchanged.
- `RtcConfig::enable_sdes_srtp` (off by default): SDES-SRTP (RFC 4568) for SIP gateways: offers
  `RTP/SAVPF` with an `a=crypto` line per suite (AEAD-AES-256/128-GCM, AES-256/128-CM-HMAC-SHA1-80,
  AES-128-CM-HMAC-SHA1-32) and answers SDES offers; SRTP keyed from the SDP, no DTLS, no data
  channels; no MKIs or session parameters. DTLS-SRTP offers are still answered with DTLS-SRTP:
  browsers never see `a=crypto`.
- Fuzzing: new target `turn_dtls`; `webrtc_sdp` tries an SDES configuration.
- Interop: `tools/interop/webrtc/turn-dtls.sh` (coturn 4.6 in Docker): `turnutils_uclient -S`
  against akio-turn's DTLS listener, the akio_turn client and two relayed `Endpoint`s against
  coturn's DTLS listener (DTLS 1.2 negotiated).

### Added: AES-f8 and SEED in SRTP (akio-srtp), SEED in akio-crypto

ADR-052 (docs/adr/052-srtp-f8-seed.md), additive:

- **akio-crypto**: `seed` with `Seed` (RFC 4269: blocks both ways, CTR), `SeedGcm` (SP 800-38D,
  full or truncated tags) and `SeedCcm` (RFC 3610). Constant time without tables: the S-boxes are
  the fixsliced AES's Boyar-Peralta inversion circuit behind a field isomorphism plus affine maps
  (checked against the RFC 4269 tables for every input), G bitsliced over sixteen words (sixteen
  blocks in flight for ECB / CTR / GCM), a one-word path for single blocks and CCM's CBC-MAC; no
  hardware path. ct-dudect targets `seed-key` and `seed-block`.
- **akio-srtp**: `Profile::{AesF8HmacSha1_80, AesF8HmacSha1_32}` (AES-f8, RFC 3711 §4.1.2; SDES
  `F8_128_HMAC_SHA1_80/32`) and `Profile::{SeedCtrHmacSha1_80, SeedCcm80, SeedGcm96}` (RFC 5669,
  SEED-CTR PRF; `SEED_CTR_128_HMAC_SHA1_80`, `SEED_128_CCM_80`, `SEED_128_GCM_96`), with MKIs,
  key derivation rates, RFC 6904 header extension encryption and cryptex like the other profiles.
  `Profile::ALL` lists fifteen; `is_aead` is true for SEED-CCM / SEED-GCM; new
  `Profile::session_salt_len` (12 for AEAD; the SEED AEAD master salt stays 14 bytes). No
  DTLS-SRTP ids, so `akio-webrtc` does not negotiate them (SDES is not implemented there).
- Verified with RFC 3711 B.1, RFC 4269 B, RFC 5669 A.1-A.3 (A.1's tag is HMAC over the
  plaintext without the ROC, so only its keystream is used), RFC 3610 (the CCM construction, with
  AES), OpenSSL `seed-ecb`, and an independent Python implementation (`testdata/f8_seed.py` on
  pyca/cryptography): the libsrtp cross-check's 25 cases / 115 packets under the five profiles,
  byte for byte both ways.
- Benchmarks (gpu51, `quiet.sh`, CPU 2, 1200-byte payloads, protect): AES-f8 2.26 µs (AES-128-CM
  1.18 µs), SEED-CTR 18.3 µs (66 MB/s), SEED-GCM 20.4 µs, SEED-CCM 98 µs (12 MB/s); 160 bytes:
  354 ns, 3.6, 3.9 and 16.1 µs. The existing profiles against main aca9e988 (three alternating
  rounds): AES-CM and 160-byte AES-GCM within ±1.6 %, 1200-byte AES-GCM at parity measured alone
  (+1.5-2.2 % protect inside the full case sequence); two regressions the A/B found on the way
  (+3 % and +2.4 % for AES-GCM) were removed (ADR-052).

### Changed: faster brotli decoding (akio-brotli)

No public API change, output unchanged (docs/BENCHMARKS.md, "Brotli and Zstandard"). Decoding
takes 1.08–1.34× libbrotli 1.2.1's time on the HTTP payloads of `tools/codec-bench brotli` (was
1.42–1.73×) and 1.04–1.32× on Silesia (was 1.13–1.56×).

- The command loop keeps its state (bit reader, output, position, last distances) in locals and
  checks the meta-block end, the output limit and the window's spare room with one comparison per
  write; distance contexts and short distance codes come from tables, roots have a fixed size.
- Prefix code tables are built from the code lengths as they are read, without passes over symbols
  that have no code, and the code length code gets a 32-entry table: table building was 40% of
  decoding a 2.7 KB certificate chain.
- Copies of up to 32 bytes with a period under 16 go in 8-byte chunks.
- The output is zeroed ahead only up to the end of the meta-block, so a small output decoded under
  a large limit no longer zeroes 128 KiB first (2.7 KB chain with a 16 MiB limit: 266 → 370 MB/s).
- `tools/codec-bench`: `BENCH_BR_LIMIT=N` decodes with an output limit of `N` instead of the exact
  size.

### Added: DTLS 1.3 by default, cryptex, encrypted header extensions, Opus RED and FEC on simulcast lines in WebRTC peers (akio-webrtc)

ADR-048 (docs/adr/048-webrtc-dtls13-cryptex-opus-red-simulcast-fec.md):

- **Changed**: peers offer DTLS 1.3 (RFC 9147) with a DTLS 1.2 fallback by default
  (`RtcConfig::enable_dtls13`, `false` for DTLS 1.2 only). Nothing changes in SDP. Chrome 157
  negotiates DTLS 1.3 in either DTLS role; pion and other DTLS 1.2 peers are answered with
  DTLS 1.2 (checked in both roles).
- `RtcConfig::enable_cryptex`: `a=cryptex` (RFC 9335) offered and accepted; once both sides
  signal it, header extensions and CSRCs of sent RTP are encrypted. Checked both ways against
  Chrome 157's `rtpHeaderEncryptionPolicy: "require"` (behind
  `--enable-experimental-web-platform-features`).
- `RtcConfig::enable_encrypted_header_extensions`: RFC 6904 encrypted extension variants
  (`urn:ietf:params:rtp-hdrext:encrypt`) offered for audio level, MID, RID, repaired RID, video
  orientation and playout delay on free one-byte ids, and taken in answers. No browser offers
  them. SRTP MKIs stay out of WebRTC: DTLS-SRTP has no SDP for them and browsers do not use them.
- `RtcConfig::enable_opus_red(Option<u8>)`: Opus RED (`red/48000/2`, payload type 63) listed
  before Opus, which is what makes libwebrtc send it; received redundancy stands in for lost
  packets (duplicates dropped), sent Opus carries up to two earlier packets. Under 10 % loss each
  way Chrome 157 conceals 2-3 % of its audio instead of 20 %.
- ULPFEC on simulcast lines (`FecMechanism::Ulpfec`): each encoding has its own FEC encoder,
  loss estimate and rate, RED and ULPFEC on the encoding's SSRC with its RID, as Chrome sends
  it; received simulcast is repaired per layer (up to 8 FEC decoders per peer). FlexFEC is not
  used on simulcast lines (RID-based simulcast signals no FEC stream).
- Statistics events report the DTLS version, packets received with cryptex and packets
  recovered from RED.
- Interop: `tools/interop/webrtc/browser.sh` (DTLS 1.3 both roles, cryptex both ways, our
  simulcast line with per-encoding ULPFEC through 5 % loss without NACK: Chrome decodes all of it,
  next to nothing without FEC), `fec.sh` (Opus RED under loss, Chrome's per-layer ULPFEC),
  `run.sh` (pion falls back to DTLS 1.2), Firefox 158 with DTLS 1.3 (both DTLS roles). The
  `webrtc-interop` example takes `AKIO_INTEROP_*` switches and a lossy proxy for the SFU.
- Benchmark (gpu51 same-run A/B against main 436b47e7, `quiet.sh`, CPUs 2-9, in-process peers with DTLS 1.2 on both sides, medians of the six quiet pairs: peer connections per second 0.990x, VP8 media 4000-byte frames 0.995x (752 vs 756 MB/s), 120-byte frames 0.993x: no regression. With the new default DTLS 1.3 a handshake costs about 5 % more CPU than DTLS 1.2; media throughput is the same, and with cryptex too).

### Added: P-521, RSA-PSS keys and the client's OCSP response in TLS 1.3 (akio-crypto, akio-x509, akio-tls)

ADR-049 (docs/adr/049-p521-rsa-pss-keys-client-ocsp.md), additive:

- **akio-crypto**: `p521` (ECDH and ECDSA on NIST P-521 with the API of `p256` / `p384`, 66-byte
  scalars, SHA-512 by default, RFC 6979 nonces; portable constant-time code on its own
  `2⁵²¹ - 1` field and complete formulas; ct-dudect targets `p521-ecdh`, `p521-keygen`,
  `p521-sign`); `pkey::PublicKey::{P521, RsaPss}`, `pkey::PrivateKey::{P521, RsaPss}` and
  `pkey::PssParams` for `id-RSASSA-PSS` keys (RFC 4055) with or without parameters, which sign
  and verify RSA-PSS only, within their parameters; `der::oid::SECP521R1`. Wycheproof P-521
  ECDSA / ECDH and RFC 6979 A.2.7 vectors, OpenSSL-made PSS keys.
- **akio-x509**: P-521 and RSA-PSS-key certificates parse, verify and are issued (OpenSSL-made
  chains in `tests/data/pss-p521`).
- **akio-tls**: group secp521r1 (offered last), `ecdsa_secp521r1_sha512` and
  `rsa_pss_pss_sha256/384/512` (server and client certificates, TLS 1.3 and 1.2);
  `ServerConfigBuilder::client_ocsp_policy` asks TLS 1.3 clients for an OCSP response with
  their certificate and validates it (ADR-038 policies; TLS 1.2 client certificates are refused
  under hard fail), `ClientConfigBuilder::client_cert_ocsp_response` sends one when asked, and
  the server's `TlsInfo::ocsp_response` holds it. Interop with OpenSSL and Go
  (`tools/interop/tls/run.sh`). `status_request_v2` stays unimplemented (TLS 1.2 only, obsolete).
- Default ClientHellos list secp521r1 (2 more bytes); nothing else changes in default handshakes.

### Added: bandwidth probing in the estimator (akio-rtp, akio-webrtc)

ADR-050 (docs/adr/050-bwe-probing.md). `akio_rtp::BandwidthEstimator` probes the path like
libwebrtc, so video ramps up in a fraction of a second instead of tens of seconds:

- **akio-rtp**: probe clusters (15 ms / 5 packets or more, paced at a target rate) at 3 and 6
  times the start rate, doubling while results keep up; every 5 s while application-limited
  (`application_limited()`); after a large drop of the estimate; from scratch after
  `on_network_change(now)`. `poll_probe(now)` / `probe_timeout()` / `on_probe_sent` /
  `cancel_probes` drive the sending, `TwccSender::on_sent_probe` and `CcfbSender::on_sent_probe` tag the packets,
  `PacketResult::probe` carries the cluster back, and the measured delivery rate lifts the
  delay- and loss-based rates. `SendStream::padding` builds probe packets (RTX copies of recent
  media, or padding). On by default; `with_probing(false)` keeps the previous behaviour.
  **Breaking** (internal tier): `PacketResult` has a new public field `probe`.
- **akio-webrtc**: with `enable_bwe`, the probes go out as RTX copies of the most active stream's
  recent packets, paced through `poll_output`'s timeout; a new ICE selected pair restarts the
  estimate. Public API unchanged.
- Simulated links, start 300 kbps: 90 % of 0.5 / 2 / 10 Mbps after 0.15 / 0.25 / 0.35 s (was
  5.4 / 23 / 44 s), peaks at most 1.12x the capacity. With Chrome 157 as receiver
  (`tools/interop/webrtc/bwe.sh`, new): 10 Mbps 0.2 s after the connection (the estimate used to
  stay at its 1 Mbps start).

### Changed: faster Zstandard decoding, second pass (akio-zstd)

No public API change (docs/BENCHMARKS.md, "zstd decoding, second pass", "zstd literals" and "zstd
double-symbol Huffman tables"; quiet gpu51, against libzstd 1.5.7 in `tools/codec-bench zstd`):

- Decompression takes 1.16–1.39× libzstd's time on the HTTP payloads (was 1.46–1.64×): JavaScript
  1.38–1.39× (was 1.59–1.61×), certificate chains 1.16–1.27× (was 1.49–1.64×), JSON 1.37–1.38×,
  HTML 1.31–1.33×; Silesia 1.22–1.24× at levels 1 and 3 and 1.39× at 19 (was 1.32–1.33× and
  1.57×). The decoder keeps its tables and literals buffer per thread between calls, as libzstd's
  reused context does (about 20 KB, plus up to 32 KiB of literals), decodes sequences in batches
  of 64 before executing them (one bit read per sequence when the extra bits allow), and decodes
  the four Huffman streams with libzstd's fast loop. Still `#![forbid(unsafe_code)]`, no BMI2
  paths. Fuzzed 16 min per target (`zstd_decompress`, `zstd_roundtrip`).
- Large Huffman-coded literal sections (by libzstd's `HUF_selectDecoder` rule) are decoded with a
  double-symbol table, one or two symbols per lookup: literal decoding 13–21% faster on Zen 4
  and 35–37% on Apple M-series (JavaScript literals, 16–60 KB); end to end JSON, JavaScript and
  HTML 1.6–3% faster, Silesia −0.8…+1.4%. The per-thread decoder keeps the table (16 KB more).
- Compressed output changes: the encoder keeps literals raw unless Huffman coding saves more than
  2 bytes plus 1/64 of them, and below 64 literals, as libzstd does (`ZSTD_minGain`). Our own
  certificate-chain frames decode 2.3–3.2× faster (they decoded at under half the speed of
  libzstd's frames) and are 4–17 bytes larger; JSON, HTML and JavaScript are byte-identical,
  Silesia 0.004% larger.
- `tools/codec-bench`: `BENCH_OWN=0` skips decoding each library's own output, `BENCH_DUMP=DIR`
  writes the zstd frames that are timed.

### Changed: faster brotli and Zstandard decoding and encoding (akio-brotli, akio-zstd)

No public API change (docs/BENCHMARKS.md, "Brotli and Zstandard"; against libbrotli 1.2.1 and
libzstd 1.5.7 in `tools/codec-bench`, which now has `brotli` / `zstd` modes and a corpus script).

- **Decoders** (output unchanged): decompression takes 1.3–1.7× libzstd's time (was 1.7–2.4×) and
  1.1–1.7× libbrotli's (was 1.4–3.1×); on Silesia zstd level 1 decodes 849 MB/s (was 541,
  libzstd 1,120) and brotli level 5 467 MB/s (was 333, libbrotli 716). The output doubles as a window zeroed ahead (never past the limit) so literals and
  matches are copied in 16-byte chunks; branch-free bit reads kept in registers; zstd's four
  Huffman streams decoded in lockstep and predefined sequence tables no longer copied per block;
  brotli decodes three literals per refill through a per-block-type context → tree table. Bounds
  are unchanged: memory stays within the limit, truncated brotli input is caught once per command
  instead of once per literal (still bounded by the output).
- **zstd encoder** (output changes): levels 1–2 use libzstd's `fast` match finder and 3–4
  `double_fast` instead of lazy hash chains, plus a faster Huffman code construction and bit
  writer: 2.1–3.2× faster; sizes within −3…+2% of libzstd's (level 3 is 1–7% larger than before on
  small HTTP payloads, where the old lazy search beat libzstd's level 3).
- **brotli encoder** (output changes): per-hash buckets instead of chains at levels 0–6 (5-byte
  hashes at 5–6), Google's candidate counts at levels 2–4 (level 4: 4 instead of 16), Google's
  skipping through incompressible data, cheaper context clustering below level 10: Silesia 3.4×
  (q4), 2.4× (q5), 2.6× (q6) faster; q5–q6 sizes −1.2…+0.8% (+2–3% on certificate chains, which
  use level 11 in akio-tls), q4 1–9% larger but no longer smaller than libbrotli's q4 at four
  times its search effort. Brotli levels 10–11 and zstd levels 5–22 keep their speed and, but for
  small differences from the context clustering and Huffman code construction, their output.

### Changed: route constraints run on `akio-regex` (akio-http, akio-regex)

ADR-051 (docs/adr/051-router-on-akio-regex.md). The router's regexp parameters
(`/users/{id:[0-9]+}`, also inside partial segments) are now matched by `akio-regex`, the engine
behind akio-log's message filters; the router's own engine (`akio_http::re`, `#[doc(hidden)]`,
not a public API) is gone from normal builds.

- **Same matches.** Constraints still match the whole segment, and `\d \w \s` stay ASCII. Every
  pattern the old engine accepted matches exactly the same segments: a differential test (every
  regexp route in the repository, the old engine's test patterns, 3 000 generated patterns with
  about 30 subjects each, 20 000 random syntax soups) and the `regex_match` fuzz target compare
  the two, with the old engine kept, frozen, as a test-only reference.
- **More syntax**: flags `(?i)` (Unicode case folding), `(?m)`, `(?s)`, `(?U)`, negated and
  scoped; `\A \z`; `\b \B` (ASCII word boundaries); Unicode and dotted group names; programs of
  up to 20 000 instructions. **One narrowing**: two groups with the same name in one constraint
  now panic at registration, as the `regex` crate refuses them (names were never captured).
- **Faster**: about a third less time per constraint check (`[0-9]+` on 7 digits 8.5 → 5.7 ns,
  `\d{4}-\d{2}-\d{2}` 11.9 → 7.6 ns); router-bench's varied-regexp table 46.0 → 42.0 ns per
  lookup, the `[0-9]+` table unchanged at 28.1 ns. Compiling a constraint builds a DFA: 7–13 µs
  at registration instead of 2.1 µs.
- **akio-regex** (internal tier): `RegexBuilder` with `whole_text` (match the whole text, as
  `\A(?:...)\z`) and `ascii_classes` (ASCII `\d \w \s` and `\b`); `Regex` equality includes the
  options. `Regex::is_match` runs the ahead-of-time DFA in a tight loop first, a few percent faster
  for akio-log's message filters too.

### Performance: AES-GCM whole messages on the VAES-AVX2 kernel; P-256 divsteps on aarch64 (akio-crypto)

No API change.

- **VAES-AVX2 AES-GCM kernel** (CPUs with VAES but no AVX-512: Zen 3, Alder Lake / Raptor
  Lake): one call now does the whole message, as the AVX-512 kernel does: `E(J0)`, the AAD (up to
  256 bytes), the 256-byte groups, the tail after them and the length block. AVX2 has no byte
  masks, so the tail goes through a zero-padded stack buffer (four or eight ymm vectors, the
  keystream masked by a constant table). Before, everything but whole 256-byte groups ran on the
  128-bit kernel. Measured on Zen 4 with the AVX2 kernel forced, against the 128-bit kernel in
  the same runs: 200 B 1.00× → 1.84–1.90×, 1 KiB 1.47–1.75× → 1.81–2.12×, 1400 B 1.50–1.70× →
  1.82–2.09×, 64 B 0.91–1.01× → 1.12–1.20×; against ring 1 KiB 0.88–1.00× → 1.03–1.13×. No Zen 3
  or Alder Lake host was available to measure on.
- **aarch64 P-256**: safegcd divsteps in assembly (inversion 1.66 → 1.26 µs on an Apple M4 Pro)
  and OpenSSL's addition formulas on the twin. Sign +9% (1.15× → 1.25× ring), key generation
  +3.5%, ECDH 0.98× → 1.00× ring. First measurement of the aarch64 assembly: P-256 verify 1.04×
  ring, X25519 1.04× (docs/BENCHMARKS.md).

### Added: mDNS ICE candidates, aggressive nomination and renomination, simultaneous-open ICE-TCP (akio-ice, akio-webrtc, akio)

ADR-044 (docs/adr/044-ice-mdns-renomination-tcp-so.md), additive (nothing changes unless used):

- **akio-webrtc**: `Endpoint::resolve_mdns(&engine, timeout)` resolves the `<uuid>.local` host
  candidates browsers send (in descriptions and trickled; one-shot mDNS queries over the shared
  port 5353 and `224.0.0.251`, answers cached, never blocking an I/O thread), so an `Endpoint`
  reaches a browser host to host; `Endpoint::conceal_host_candidates()` writes our own host
  candidates as mDNS names and answers the queries for them. Tested with headless Chrome 157
  with its mDNS concealment on (each side resolves the other's name).
  `RtcConfig::enable_ice_renomination` (`a=ice-options:renomination`) and
  `RtcConfig::enable_ice_aggressive_nomination`. `Endpoint::listen_tcp_so(&engine, addr)`: a
  simultaneous-open ICE-TCP candidate (RFC 6544 `tcptype so`). `Peer::add_remote_candidate`
  accepts mDNS lines when the endpoint resolves them.
- **akio-ice**: `mdns` module (RFC 6762 codec), `Candidate::{parse_resolved, with_hostname,
  hostname, with_related}`, `IceConfig::{aggressive_nomination, renomination}`,
  `IceAgent::set_remote_renomination` (NOMINATION attribute; a better pair found after
  nomination is used). A controlled agent now selects the highest NOMINATION value, or without
  one the highest-priority nominated pair, instead of the last nomination. Fuzz target
  `ice_mdns`.
- **akio**: `Engine::bind_udp_multicast(group, acceptor)` (a multicast group's port shared with
  other members) and `Engine::dial_from(local, addr, acceptor, on_error)` (a connect from a
  bound, shared local port); akio-sys `connect_nonblocking_from`.

### Added: DTLS 1.3 connection ID updates, post-handshake client authentication and early data (akio-dtls)

ADR-045 (docs/adr/045-dtls13-cid-updates-pha-early-data.md), additive and off by default:

- **Connection ID updates** (RFC 9147 §9): `Connection::new_connection_ids(count, immediate)`
  (NewConnectionId), `request_connection_ids(n)` (RequestConnectionId, answered automatically
  by the peer), `rotate_connection_id()`, `spare_connection_ids()`, `local_connection_ids()`,
  `peer_connection_id()`; at most 8 live CIDs, our older CIDs retire once the peer sends with a
  later one, `Event::LocalConnectionIds` reports the set a listener should route.
  `AlertDescription::TooManyCidsRequested`.
- **Post-handshake client authentication** (RFC 8446 §4.6.2): `Config::with_post_handshake_auth`
  (client), `Connection::request_client_certificate` and `Event::ClientCertificate` (server).
- **Early data (0-RTT)** with tickets: `Config::with_early_data(max)`, `Config::with_anti_replay`,
  `AntiReplayStore` / `MemoryAntiReplay` (binder recording and a ticket-age freshness check),
  `Connection::send_early_data`, `Session::max_early_data`, `Event::EarlyData`,
  `HandshakeInfo::early_data`. A ClientHello whose early data is accepted skips the
  HelloRetryRequest cookie exchange.
- `Error::NotAvailable` for operations the connection did not negotiate or is not ready for.
- Post-handshake flights (NewSessionTicket, KeyUpdate and the new messages) share one queue.
- Tests `tests/dtls13_post.rs`; fuzz target `dtls_post_handshake`; interop with wolfSSL 5.8.4
  (early data and post-handshake authentication both ways; the interop image now builds wolfSSL
  with `--enable-earlydata --enable-postauth`, `DTLS_INTEROP_IMAGE` names it); example
  `dtls-hs-bench` (handshakes per second, DTLS 1.3 records). Non-ECDHE key exchanges and CBC
  suites stay out on purpose (README, ADR-045).

### Added: certificate policies, indirect CRLs, Ed448, X448 and DSA verification (akio-x509, akio-crypto, akio-tls)

ADR-046 (docs/adr/046-x509-policies-indirect-crls-ed448-dsa.md):

- **akio-x509**: certificate policy processing (RFC 5280 §6.1 on the RFC 9618 policy graph):
  `Verifier::policies(PolicyOptions)` (initial policy set, explicit policy, inhibit policy
  mapping / anyPolicy), `Verifier::verify_path` → `VerifiedPath { chain, policies:
  ValidPolicies }`, `Error::PolicyViolation`; `Certificate::{certificate_policies,
  policy_mappings, policy_constraints, inhibit_any_policy, is_self_issued}`,
  `PolicyConstraints`, `ext::{ANY_POLICY, POLICY_MAPPINGS, POLICY_CONSTRAINTS,
  INHIBIT_ANY_POLICY}`. Indirect CRLs and CRLs signed by another key of the CA (the signer's
  path is validated to the same root, with revocation): `Verifier::crl_signers`,
  `Crl::find_for`, `RevokedCertificate::certificate_issuer`,
  `DistributionPoint::relative_name`, `IssuingDistributionPoint::relative_name` (new public
  fields); CRL scopes now follow the certificate's distribution points and their reasons.
  rfc822Name and URI name constraints (and the subject's emailAddress), self-issued
  intermediates exempt from name constraints and pathLen, `Verifier::allow_ca_end_entity`,
  `attr::EMAIL_ADDRESS`; Ed448 and DSA certificates and CRLs. NIST PKITS harness
  (`tests/pkits.rs`, `tools/pkits/prepare.sh`): 242/248 runs as expected.
- **akio-crypto**: `hash::{Shake128, Shake256}`, `ed448`, `x448`, `dsa` (verification only),
  `rsa::HashAlg::Sha224`, `pkey::SignatureAlgorithm::{Ed448, DsaSha1, DsaSha224, DsaSha256}`,
  `pkey::{PublicKey, PrivateKey}::Ed448`, `pkey::PublicKey::Dsa`, `der::oid::{ED448, X448, DSA,
  DSA_WITH_SHA1, DSA_WITH_SHA224, DSA_WITH_SHA256}`; `pk_bench 448`; ct-dudect targets `x448`,
  `ed448-keygen`, `ed448-sign`.
- **akio-tls**: group x448 (0x001e, offered last) and signature scheme ed448 (0x0808), TLS 1.3
  and 1.2; interop cases against OpenSSL in `tools/interop/tls/run.sh`.
- Fuzz targets `x509_policy` and `crypto_ed448_dsa`; `x509_parse` and `x509_crl` cover the new
  extensions and indirect-CRL entries.

### Changed: path validation details (akio-x509)

- With CRLs configured, revocation is checked once a candidate path reaches a root (top down)
  instead of while it is built. Paths whose policyConstraints require an explicit policy that
  is absent now fail (`Error::PolicyViolation`), and a certificate with a malformed policy
  extension no longer parses. CRL serial numbers compare as signed INTEGERs (a CRL entry for −1
  no longer matches serial 255), and `CrlParams` / OCSP CertIDs write serials as given.

### Added: FEC, RTCP XR, TMMBR and RFC 8888 feedback in WebRTC peers (akio-webrtc, akio-rtp)

ADR-039 (docs/adr/039-webrtc-fec-xr-tmmbr-ccfb.md), additive and off by default (a default peer's
SDP is unchanged):

- **akio-webrtc**: `RtcConfig::enable_fec(Option<FecMechanism>)` (`FecMechanism::FlexFec`:
  `flexfec-03` with an `a=ssrc-group:FEC-FR` stream; `FecMechanism::Ulpfec`: `red` + RTX +
  `ulpfec`) on video lines without simulcast: received FEC repairs packets before the frame
  assembler and NACK, sent video is protected at three times the loss before repair within
  `RtcConfig::set_fec_protection(min, max)` (per 256 media packets, default 0..=128).
  `RtcConfig::enable_ccfb` negotiates RFC 8888 (`ack ccfb`; the answer drops transport-cc), which
  then replaces transport-wide feedback both for acknowledging and for the bandwidth estimator.
  `RtcConfig::enable_rtcp_xr` (`a=rtcp-xr:rcvr-rtt=all`, `rrtr`): receiver reference times and
  DLRR give a receiving line its RTT; received RRTRs are always answered. `RtcConfig::enable_tmmbr`
  (`ccm tmmbr`) and `Peer::request_max_bitrate(mid, Option<u64>)`; received TMMBRs are answered
  with TMMBN and cap the estimate with REMB. RTCP NTP times now follow the peer's monotonic clock.
- **akio-rtp**: `RecvStream::receive_recovered` (a FEC-rebuilt packet: not NACKed, not counted as
  received) and `FrameAssembler::skip` (a sequence number without media, e.g. ULPFEC or padding,
  is not a gap).
- Interop: `tools/interop/webrtc/fec.sh` against headless Chrome 157 (FlexFEC and ULPFEC both
  ways under loss, RFC 8888 both ways, XR DLRR RTT, TMMBR); the `fec-server` mode of the
  `webrtc-interop` example puts a lossy UDP proxy in front of the server.

### Added: SRTP MKIs and re-keying, key derivation rates, AES-192/256-CM and NULL, RFC 6904 header extension encryption, cryptex (akio-srtp); DTLS-SRTP MKI (akio-dtls)

ADR-040 (docs/adr/040-srtp-mki-cryptex.md):

- **Profiles**: `Profile::Aes192CmHmacSha1_80/32`, `Aes256CmHmacSha1_80/32` (RFC 6188) and
  `NullHmacSha1_80/32` (RFC 5764; SRTCP sent with the E flag clear). `Profile::sdes_name` /
  `from_sdes_name`, `Profile::encrypts`.
- **MKIs and re-keying**: `Context::new_with_mki`, `add_master_key`, `set_send_mki`,
  `remove_master_key`, `send_mki`, `mki_len` (up to 16 master keys, MKIs of 1-255 bytes; the
  packet's MKI selects the key, `Error::UnknownMki` otherwise; rollover counters and replay
  windows stay per SSRC across keys).
- **Key derivation rate**: `Context::with_key_derivation_rate` (0 or a power of two up to 2^24,
  RFC 3711 §4.3.1), session keys cached per master key and stream for the last `r`.
- **Header encryption**: `Context::with_encrypted_header_extensions` (RFC 6904; AES-CM keystream
  for AEAD too, RFC 7714 §8.3) and `Context::with_cryptex` (RFC 9335: CSRCs and whole extension
  bodies, `0xC0DE` / `0xC2DE`, an empty extension added for CSRCs alone; non-cryptex packets still
  accepted).
- **Allocation-free variants**: `protect_rtp_into`, `unprotect_rtp_into`, `protect_rtcp_into`,
  `unprotect_rtcp_into`.
- **akio-dtls**: `Config::with_srtp_mki` (client offer), `Config::with_srtp_accept_mki` (server
  echo, default off), `HandshakeInfo::srtp_mki`; a different non-empty MKI from the server fails
  the handshake (RFC 5764 §4.1.3), DTLS 1.2 and 1.3.
- Tests: RFC 6188, RFC 6904 and RFC 9335 vectors; 230 packets cross-checked byte for byte with
  libsrtp main (`tools/interop/srtp`, every profile, MKIs, RFC 6904, cryptex); new fuzz target
  `srtp_features`. RFC 6904 follows the RFC where libsrtp does not advance its keystream over
  padding between extension elements.
- Benchmark (gpu51, `examples/srtp_bench.rs`, ns per packet, base -> this change): existing profiles unchanged within noise or faster: unprotect 0-5 % faster everywhere (AES-128-CM 160 B 255.2 -> 243.0, AES-128-GCM 1200 B 178.3 -> 176.3), AES-CM protect within ±1.3 %, AEAD protect 1200 B within ±0.3 % and 160 B +1-2 % (AES-128-GCM 86.8 -> 88.6). The per-SSRC state is now looked up once per packet instead of twice. New features at 1200 B with a CSRC and three extension elements, AES-128-GCM protect / unprotect: plain 542.7 / 175.9, MKI 547.6 / 179.3, cryptex 555.7 / 187.1, RFC 6904 626.4 / 252.7.
- Not yet negotiated by `akio-webrtc` (SDP `a=cryptex`, encrypt extmaps, DTLS-SRTP MKI).

### Changed: `akio_srtp::Profile` (breaking, internal tier)

`Profile` is `#[non_exhaustive]`, `Profile::ALL` has ten entries and `Profile::id` returns
`Option<u16>` (the RFC 6188 profiles have no DTLS-SRTP id). New `Error::Config`,
`Error::UnknownMki`, `Error::Unsupported`.

### Added: SCTP HEARTBEATs, peer restart, zero checksum and incoming reset requests (akio-sctp)

ADR-042 (docs/adr/042-sctp-heartbeat-restart-zero-checksum.md); akio-sctp is Internal tier:

- **HEARTBEATs** (RFC 9260 §8.3, `Config::heartbeat_interval`, default 30 s): an idle
  association measures its RTT (`Association::rtt`) and notices a vanished peer: unanswered
  HEARTBEATs count towards `max_retransmissions` (Path.Max.Retrans with one path), then the
  association fails, 60-150 s after the last exchange. Previously only answered.
- **Peer restart** (RFC 9260 §5.2.2, §5.2.4): an INIT on a live association gets an INIT ACK
  with a new tag and Tie-Tags; a restarted peer's COOKIE ECHO closes every channel, drops queued
  data and starts over, with the new `Event::Restarted`. Duplicates get COOKIE ACK, other
  combinations are discarded, restarts while shutting down are refused. Previously ignored.
- **Zero checksum** (RFC 9653, `Config::zero_checksum`, default on): "SCTP over DTLS"
  announced in INIT / INIT ACK; zero checksums accepted, and sent after the handshake when the
  peer announces it too (`Association::zero_checksum`): no CRC-32C on either end of the data
  path. In-memory SCTP 1.20-1.31x faster (`examples/sctp_bench.rs`, same-run A/B against
  46f25f81 on gpu51, medians of 7 rounds); data channels between two loopback `Endpoint`s,
  DTLS included, 1.003x. Firefox 158 and Chrome 157 do not offer it; pion/sctp does.
- **Incoming SSN Reset** and **SSN/TSN Reset** requests (RFC 6525 §5.2.3-4) are performed
  instead of refused: the first is answered with our Outgoing SSN Reset Request (channels
  close), the second once none of our data is in flight (new TSNs both ways, SSNs back to 0).
- `Event` is now `#[non_exhaustive]`.
- Interop: Firefox 158 (usrsctp) through akio-webrtc, both offer directions, with a 150 s idle
  spell (new `tools/interop/webrtc/firefox.sh`, WebDriver BiDi; the `webrtc-interop` example
  takes `AKIO_INTEROP_BIND`); pion/sctp with zero checksums (`tools/interop/sctp/run.sh`);
  Chrome 157 unchanged. Fuzz `sctp_packet` with new seeds, 11 minutes on gpu51, no crash.
- Not implemented, as WebRTC uses none of them: multi-homing, AUTH, ASCONF, ECN.

### Added: SRT rendezvous, AV1 in MPEG-TS, recording to MPEG-TS, HLS SAMPLE-AES (akio-media)

ADR-043 (docs/adr/043-media-srt-rendezvous-av1-ts-sample-aes.md), additive:

- **SRT rendezvous** (HSv5): `srt::Conn::rendezvous` / `Conn::is_rendezvous` and
  `srt::{rendezvous, push_rendezvous, pull_rendezvous}(engine, local, remote, ..)` on a UDP
  socket bound at `local`. Both sides wave, libsrt's cookie contest picks the initiator (HSREQ,
  KMREQ with its key), the responder answers HSRSP / KMRSP and connects on AGREEMENT (or the
  initiator's next packet). Ten times `handshake_timeout`. Tested against libsrt 1.5.4
  (`srt-live-transmit`) pushing and pulling, clear and encrypted.
- **AV1 in MPEG-TS** (AOM "Carriage of AV1 in MPEG-2 TS"): stream type 0x06 with the `AV01`
  registration and AV1 video descriptors, OBUs after start codes with emulation prevention, a
  temporal delimiter per PES; the demuxer also reads GStreamer's `AV1G`. AV1 now goes over SRT,
  HLS MPEG-TS and MPEG-TS recordings. VP8 / VP9 have no MPEG-TS mapping (documented).
- **Recording to MPEG-TS**: `RecordFormat::MpegTs` (`.ts`), tables repeated before every video
  keyframe.
- **HLS SAMPLE-AES**: `hls::EncryptionMethod::{Aes128, SampleAes}`, `HlsEncryption::method`
  (field and builder). MPEG-TS: Apple's sample encryption (stream types 0xdb / 0xcf, `zavc` /
  `aacd` / `apad`; H.264 slices 1:9 after 32 clear bytes, AAC frames), one random IV per key in
  the `IV` attribute. fMP4: `cbcs` (`encv` / `enca` with `sinf` / `tenc` and a constant IV,
  `senc` / `saiz` / `saio`; H.264 slice headers parsed and kept clear). H.264 and AAC tracks
  only (others left out of the segments). ffmpeg decodes both frame for frame.
- Fuzz targets `srt_rendezvous` and `h264_sample_encryption`; AV1 seeds for `mpegts_demux`.

### Added: in-house brotli and Zstandard (akio-brotli, akio-zstd), in certificate compression (akio-tls) and HTTP (akio-http)

ADR-041 (docs/adr/041-brotli-zstd.md), additive:

- **`akio-brotli`** (new internal crate, RFC 7932) and **`akio-zstd`** (new internal crate,
  RFC 8878): pure safe Rust, no dependencies, one-shot `decompress(data, limit)` and
  `compress(Level, data)`. The decoders cover the whole formats (brotli: every window size,
  metadata and uncompressed meta-blocks, block switching, context modes and maps, the static
  dictionary and its 121 transforms; zstd: concatenated and skippable frames, Huffman and
  treeless literals, predefined / RLE / FSE / repeat tables, repeat offsets, content size and
  XXH64 checksum) and accept and reject what the reference decoders do; output and memory stop
  at `limit` (`Error::TooLarge`), so a decompression bomb costs no more than that. The encoders
  (LZ77 over hash chains, Huffman / FSE coding) compress certificate chains at least as well as
  zlib level 9. `akio_zstd::xxh64` is public. Tested with the official test vectors (all 44
  brotli `testdata` streams; zstd's golden decompression, error and compression files, 1000
  `decodecorpus` frames), the `brotli` and `zstd` CLIs in both directions, and differential
  fuzz targets against Google's brotli decoder (`brotli-decompressor`) and libzstd
  (`brotli_decompress`, `brotli_roundtrip`, `zstd_decompress`, `zstd_roundtrip`).
- **akio-tls**: certificate compression (RFC 8879) with brotli and zstd besides zlib. The
  client offers brotli, zstd, zlib; a server sends the smallest of the algorithms the client
  offers (each compressed once per certificate and cached), and the same for client
  certificates. New: `CertCompression { Zlib, Brotli, Zstd }` and
  `certificate_compression_algorithms(&[CertCompression])` on both builders;
  `certificate_compression(true)` now means all three (defaults unchanged: on for servers, off
  for clients). Interop with OpenSSL 3.5 built with brotli, zstd and zlib in both directions
  (`tools/interop/tls/certcomp.Dockerfile`, `tools/interop/tls/run.sh`; `tls-interop
  --cert-comp`).
- **akio-http**: `Compress::brotli` and `Compress::zstd` (levels, default `None`) make
  `middleware::compress` answer `br` / `zstd` to clients that accept them (preference br, zstd,
  gzip, deflate); `Files` also serves `.zst` twins (`Content-Encoding: zstd`).

### Added: HLS encryption and recording (akio-media), AES-CBC (akio-crypto)

ADR-034 (docs/adr/034-media-hls-encryption-recording.md), additive:

- **HLS AES-128**: `HlsConfig::encryption` (`HlsEncryption { keys, rotate_every }`) encrypts
  every segment and LL-HLS part (MPEG-TS and fMP4) with AES-128-CBC + PKCS #7, IV = media
  sequence number (parts separately, from their segment's IV), `#EXT-X-KEY:METHOD=AES-128`
  before the first media of each key; fMP4 init segments stay clear (`METHOD=NONE` before a map
  that follows a key). `KeyProvider` (`key(path, n) -> HlsKey`, `authorize(path, n, &Context)`)
  issues keys and decides requests for `/<path>/key-<n>.key` (403 when refused);
  `HlsKey::with_uri` names an external key server; `RandomKeys` issues random keys. Keys rotate
  every `rotate_every` segments and are served only while a kept segment uses them. `MediaHttp`
  routes `.key` to `Hls`. Tested with ffmpeg playing the encrypted live playlists.
- **Recording**: `akio_media::record::{Recorder, RecordConfig, RecordFormat, RecordHooks,
  RecordFile, NoHooks}` records hub streams to fMP4 or FLV files, cut at keyframes by
  `segment_duration` / `segment_bytes` and at republishes, rotated with `max_files`, with
  `file_name`, `on_start`, `on_stop` (after `sync_all`) and `on_remove` hooks. Files are
  written by the recorder's own writer thread, never an I/O thread; the queue is bounded by
  `max_queued_bytes` (32 MiB), past which the file is closed and packets dropped until the next
  keyframe (`Recorder::dropped`). Recorded files are checked with ffprobe / ffmpeg.
- **akio-crypto**: `Aes::{encrypt_cbc, decrypt_cbc, encrypt_cbc_padded, decrypt_cbc_padded}`
  (SP 800-38A vectors, PKCS #7 checked against OpenSSL).

### Added: ECN on macOS and over akio-dpdk's UDP (akio-sys, akio-quic, akio-dpdk)

ADR-035 (docs/adr/035-ecn-macos-and-userspace-udp.md). QUIC connections now mark ECT(0), read
received codepoints and validate ECN on macOS and over the userspace stack, not only on Linux.
akio-sys gains, on macOS only, `enable_ecn`, `ecn_available`, `recv_from_ecn` and `send_to_ecn`
(one `sendmsg` / `recvmsg` per datagram with an `IP_TOS` / `IPV6_TCLASS` control message;
`AKIO_UDP_ECN=0` turns it off), used by the kqueue UDP loop and akio-core's macOS datagram
writes. akio-dpdk's UDP writes the codepoint into the IP header and reports the one it received
(`Conn::rx_ecn`); akio-core keeps codepoints for virtual datagram sockets (hidden
`ConnInner::drain_output_ecn`). The `quic_conn` fuzz target now picks what the path does to
ECN (kept, bleached, CE, ECT(1)); before, its datagrams were never marked. The quic-go interop
script checks ECN validation on macOS too. The akio-quic README
no longer lists compatible version negotiation as missing (done in ADR-013 and ADR-014). No
change to the Linux API snapshots; unsafe inventory: akio-sys 91 → 97 blocks.

### Added: RTCP XR, TMMBR / TMMBN, RFC 8888 feedback and FEC (akio-rtp)

ADR-036 (docs/adr/036-rtp-xr-tmmbr-ccfb-fec.md). `akio-rtp` is Internal-tier; `Rtcp` gains four
variants (PT 207 and RTPFB 3 / 4 / 11 no longer parse as `Rtcp::Unknown`), everything else is
additive:

- **RTCP XR** (RFC 3611): `Rtcp::ExtendedReport` with `XrBlock` for every block (loss /
  duplicate RLE, receipt times, RRTR, DLRR, statistics summary, VoIP metrics, unknown).
  `RrtrResponder` answers RRTRs with DLRR; `rtt_from_dlrr` and `RecvStream::{handle_dlrr, rtt}`
  give a receiver without sender reports its RTT; `RecvStream::{statistics_summary,
  duplicates}`; `BurstLossModel` (Appendix A.2, reproducing the §4.7.2 example) for VoIP metrics.
- **TMMBR / TMMBN** (RFC 5104): `Rtcp::{Tmmbr, Tmmbn}` with `TmmbItem`; `bounding_set`,
  `bounded_bitrate`, `TmmbrHandler` (requests per requester, 25 s timeout, TMMBN).
- **RFC 8888**: `Rtcp::CongestionControl(CcfbFeedback)` (`CcfbStream`, `CcfbMetric`, ATO
  constants); `CcfbReceiver` generates feedback per media SSRC with ECN (50 ms / 100 packets);
  `CcfbSender` maps it onto `PacketResult`s for `BandwidthEstimator`.
- **FEC** (`akio_rtp::fec`): `FecEncoder` / `FecDecoder` / `FecHeader` for ULPFEC (RFC 5109),
  FlexFEC as libwebrtc's `flexfec-03` and as RFC 8627; interleaved masks per frame, iterative
  byte-identical recovery; `fec::red` (RFC 2198 parse / write / wrap / unwrap).
- Tests against libwebrtc's unit-test vectors, the RFC 3611 example and simulated loss; new fuzz
  target `rtp_fec`, `rtp_rtcp` extended. Not wired into `akio-webrtc` yet.

### Added: SCTP message interleaving (I-DATA) and stream schedulers (akio-sctp)

ADR-037 (docs/adr/037-sctp-idata-schedulers.md), additive (akio-sctp is Internal tier):

- **I-DATA / I-FORWARD-TSN (RFC 8260 §2)**, offered by default (`Config::message_interleaving`)
  and used when the peer offers them too (`Association::message_interleaving`): fragments of
  messages on different channels interleave, so a large message no longer holds up small ones
  on other channels (a 4-byte message queued after a 200 kB one on another channel now arrives
  in the first round trip instead of after it). DATA and FORWARD TSN otherwise, as before; the
  chunk kind not negotiated aborts the association (protocol violation).
- **Stream schedulers (RFC 8260 §3)**: `Config::scheduler` with `Scheduler::{FirstComeFirstServed,
  RoundRobin, RoundRobinPerPacket, Priority, FairCapacity, WeightedFairQueueing}` (default
  weighted fair queueing), by channel priority: `ChannelOptions::with_priority`, the peer's
  DATA_CHANNEL_OPEN value, `Association::set_channel_priority` (RFC 8832 semantics, higher is
  more important; 0 counts as 256). Previously messages went out first come, first served.
- Sender queues per stream with fragments cut as they get TSNs from one shared buffer per
  message; with I-DATA a new message starts only while the started ones fit in half the peer's
  window, so many large messages at once cannot fill it with partial messages; single-chunk
  messages skip reassembly and in-order I-DATA fragments are appended
  directly. Same-run A/B against 59d41cc2 on gpu51 (`quiet.sh`, CPUs 2-9, 7 alternating rounds, medians): in-memory SCTP (`examples/sctp_bench.rs`) 1 KiB messages 1.19x (DATA fallback 1.21x), 64 KiB 1.33x (1.14x), 16 KiB unordered 1.12x (1.08x), four channels 1.20x (1.07x); data-channel throughput between two loopback `Endpoint`s, DTLS included, 0.986x (189.0 vs 191.7 MB/s; 1.009x in an earlier run, rounds vary by ±5%): no regression.
- Interop: pion/sctp v1.12.0 over UDP (new `tools/interop/sctp/run.sh`: both roles, pion's
  interleaving on and off, with and without loss); pion WebRTC negotiates I-DATA; headless
  Chrome 157 both directions on DATA (default) and on I-DATA (`CHROME_ARGS` with its
  `WebRTC-DataChannelMessageInterleaving` field trial, new in `browser.sh`). Fuzz target
  `sctp_packet` drives an I-DATA and a DATA pair. akio-webrtc gets the new defaults without an
  API change.

### Added: certificate revocation: CRLs, OCSP, stapled-response validation (akio-x509, akio-tls)

ADR-038 (docs/adr/038-x509-revocation.md), additive. No network access in the library: the
application fetches CRLs and OCSP responses.

- **akio-tls**: `RevocationPolicy::{Off, SoftFail, HardFail}` (default off, no cost when off);
  `ClientConfigBuilder::ocsp_policy` validates the OCSP response stapled for the server's leaf
  in TLS 1.3 and 1.2 (signed by the issuer or a delegated id-kp-OCSPSigning responder, about the
  leaf, current within 5 minutes of skew) and asks for stapling: soft fail rejects only a valid
  "revoked" (`certificate_revoked`), hard fail requires a valid "good"
  (`bad_certificate_status_response` otherwise). `Crls` with `ClientConfigBuilder::crls` and
  `ServerConfigBuilder::client_crls` check every certificate of the peer chain below the root.
- **akio-x509** (internal crate): `Crl`, `CrlSet` (complete and delta CRLs, reason codes,
  issuingDistributionPoint scopes, removeFromCRL), `Verifier::{crls, revocation_mode,
  clock_skew}`, `RevocationMode`, `OcspResponse` / `OcspValidation` / `OcspRequest` (RFC 6960,
  nonce, CertID SHA-1/256/384/512), `Certificate::{crl_distribution_points, ocsp_urls,
  ca_issuer_urls}`, builders `CrlParams` and `OcspResponseParams`, new `Error` variants.
- Tests with OpenSSL-made CRLs and OCSP responses (`tests/data/revocation/gen.sh`), in-memory TLS
  for every policy, interop against `openssl s_server -status_file` and OpenSSL CRLs; new fuzz
  targets `x509_crl` and `x509_ocsp`.

### Added: protobuf text format (akio-protobuf)

ADR-030 (docs/adr/030-protobuf-text-format.md), additive: `akio_protobuf::text` parses and prints
the text format for generated messages (`to_string`, `to_string_with`, `from_str`,
`from_str_with`) and `DynamicMessage`s (`parse_dynamic`, `to_text`, `from_text`), with
`PrintOptions` (`single_line`, `print_unknown_fields`, `type_pool`), `ParseOptions`
(`allow_unknown_fields`, `type_pool`) and `TextError` (line and column). Scalars, enums by name
or number, strings and bytes with every escape, messages in `{ }` or `< >`, repeated fields in
both forms, maps, oneofs, groups, extensions (`[pkg.ext]`), `Any` expansion
(`[type.googleapis.com/...]`), comments, separators, hex / octal integers, `inf` / `nan`.
Protobuf conformance runner v35.1: text format 909 passed, 0 failed (was 909 skipped); binary +
JSON unchanged at 5627. New fuzz target `protobuf_text` (parse → print → parse).

### Added: BitTorrent fast resume

`akio-bittorrent` (ADR-033, docs/adr/033-bittorrent-fast-resume.md), additive:

- **`ClientConfig::resume_dir`** (default none) and **`resume_interval`** (30 s): each torrent's
  state is saved as `<info hash hex>.resume` on a timer when it changed, soon after a pause, and
  at `Client::close` (after the last write), atomically (temporary file, fsync, rename);
  `Client::remove` deletes it. A torrent added again starts from it without hash-checking its
  data.
- **Format**: versioned bencode closed by a SHA-256 checksum: the have-bitfield, the info
  dictionary, v2 piece layers, each file's size and modification time, peers, trackers, web
  seeds, upload/download totals and seeding time across sessions, rate and seed limits.
  Damaged, truncated, foreign or newer-version data is refused
  (`TorrentEvent::ResumeRejected`, then a full check); it never panics (fuzz target
  `bt_resume`).
- **Validation**: files whose size or time changed have their pieces checked again
  (`TorrentEvent::ResumeAccepted { pieces, rechecking }`, `TorrentStats::pieces_checked`). After
  a crash, files the client was still downloading are trusted on their size (the client's own
  later writes made them newer); the pieces of the last save interval are downloaded again.
- **Bytes**: `Torrent::resume_data`, `AddOptions::resume_data`, `Client::add_resume` (a torrent
  from resume data alone; `AddError::Resume`, `ResumeError`), `Torrent::save_resume_data`.
  Custom storage reports files through `Storage::file_stamps` (`FileStamp`).
- `TorrentStats` gains `total_uploaded` and `total_downloaded`; `seeding_time` and seed limits
  count across sessions when resumed.
- Tests: restart after `close` and after `SIGKILL` mid-download with no piece hashed again, a
  changed file checked again alone, v1, v2 and hybrid torrents, a v2 magnet's piece layers
  restored. bt-bench 512 MiB TCP on gpu51: 1.01x of before (noise). Fuzz `bt_resume` 11 min clean.

### Added: TURN over TCP and TLS from an `Endpoint`, active and server ICE-TCP, simulcast with Chrome

Additive (ADR-032, docs/adr/032-webrtc-turn-streams-ice-tcp-simulcast.md):

- **Relayed candidates over TCP and TLS**: `Endpoint::gather_relay_via(&engine, &server,
  timeout)` with a `RelayServer` (`udp`, `tcp`, `tls(addr, server_name, tls_config, ..)`, or
  `from_url("turn:host?transport=tcp" | "turns:host")` plus `tls_config` for `turns:`). The
  allocation lives on an engine connection; its candidate ranks below a UDP-allocated one and
  brings no server-reflexive candidate; relayed data is dropped past 256 KiB queued.
- **Allocations are made again when lost** (a connection closed, a refresh failed), after 1 s
  and doubling waits up to a minute, by `gather_relay` too: the new relayed candidate replaces
  the old one for new peers and is added to open peers, which keep going when the other side is
  reachable from the relay.
- **Active ICE-TCP**: `Endpoint::dial_tcp(&engine)` adds an active TCP candidate (port 9) and
  dials one connection per pair when its first check goes out; active and passive connections
  share the 256 bound.
- **Passive ICE-TCP on `RtcServer`**: `RtcServer::tcp_candidates(addrs)` and `RtcServer::tcp()`
  (an `RtcTcp` acceptor for the engine's TCP listener); at most twice `max_peers` connections.
- **`Endpoint::candidate_filter(f)`**: the local candidates new peers use and signal (a relay-only
  or TCP-only policy); `Candidate::kind()` and `Candidate::transport()`.
- **`Peer::request_layer_keyframe(mid, rid, kind)`**: PLI or FIR to one received simulcast layer
  (an SFU switching a viewer's layer). Simulcast verified with headless Chrome both ways: three
  VP8 layers from Chrome, layer selection decoded by Chrome, and our simulcast falling back to its
  first layer (Chrome does not receive simulcast).
- `akio-ice` (internal tier): `Candidate::relayed_over_stream`. New fuzz target
  `webrtc_turn_url`. Interop: pion (relays over TCP/TLS on akio-turn and pion/turn, ICE-TCP both
  ways), coturn (relays over TCP/TLS), Chrome (ICE-TCP only, relay only over UDP/TCP/TLS,
  simulcast and layer selection).

### Added: VP8, VP9 and AV1 in akio-media, multivariant HLS playlists

Additive (ADR-031, docs/adr/031-media-vp8-vp9-av1-multivariant-hls.md):

- **VP8, VP9 and AV1 in the hub**: `Codec::{Vp8, Vp9, Av1}` with canonical forms (`vpcC` /
  `av1C` configuration records, frames, AV1 temporal units of sized OBUs) and keyframes from the
  bitstream, so GOP cache, HLS segmenting and slow-player dropping work for them. Carried by
  Enhanced RTMP / FLV (`vp09`, `av01`, `vp08`), RTSP (RFC 7741 / RFC 9628 / AV1 RTP through
  akio-rtp, record and play), fMP4 HLS (`vp08` / `vp09` + `vpcC`, `av01` + `av1C`) and WHIP /
  WHEP (`webrtc::rtc_config` enables them). Not in MPEG-TS. New modules `codec::vp8`,
  `codec::vp9`, `codec::av1`; `Track::video_from_keyframe`, `Track::codec_string` (RFC 6381);
  `rtp::Depacketizer::picture_size`.
- **Multivariant HLS**: `Hls::add_multivariant(name, Multivariant)` serves `/<name>.m3u8` over
  renditions published as separate streams (`Variant`: path, bandwidth configured or measured
  from segments, audio group; `AudioRendition`: group, name, language, default), with
  `BANDWIDTH`, `AVERAGE-BANDWIDTH`, `CODECS`, `RESOLUTION`, `AUDIO` and `EXT-X-MEDIA` audio
  groups, in MPEG-TS and fMP4, with LL-HLS; `Hls::remove_multivariant`.
- Changed: `webrtc::rtc_config` now accepts VP8, VP9 and AV1, so WHIP offers with only those are
  published instead of refused (406). Fixed: `flv::parse_video` dropped the first 3 bytes of
  coded frames of FourCCs other than `avc1` / `hvc1`. HLS no longer stalls a stream whose video
  the segment format cannot carry (VP9 or AV1 in MPEG-TS): it is cut like an audio-only one.
  Fixed: a live playlist's `EXT-X-TARGETDURATION` could change between reloads (1 → 2 after a
  1.007 s segment), which Chrome's own HLS player refuses; it is now rounded to the nearest
  second per RFC 8216 and never decreases.
  Fixed: the RTP AAC depacketizer (RTSP record) panicked on an AU-headers-length of 1 to 8
  bits (found by fuzzing).
- Hot paths, same-run A/B against the previous main on gpu51 (5 alternating rounds, medians,
  head/base): hub fan-out to 1 / 16 / 256 subscribers 1.008 / 1.009 / 1.011; HLS segmenting
  TS 0.976, TS + parts 1.016, fMP4 1.005, fMP4 + parts 1.011; FLV decoding H.264 0.976,
  H.265 0.993. Retired instructions are equal or lower; per-case swings of 1-3% follow
  unrelated code changes (code layout).
- Interop: ffmpeg / ffprobe for VP9 and AV1 over Enhanced RTMP and fMP4 HLS, VP8 / VP9 / AV1
  over RTSP (record and play, TCP and UDP), multivariant playlists in both formats; headless
  Chrome publishes VP8, VP9, AV1 and H.264 over WHIP, decodes them over WHEP and plays a
  multivariant fMP4 LL-HLS playlist (`tools/interop/media/browser.sh`).

### Added: `/regex` message filters in akio-log, on the new internal crate akio-regex

Additive (ADR-047, docs/adr/047-log-regex-filters.md):

- **akio-log**: `AKIO_LOG=info,akio_http=debug/connection (reset|refused)` keeps only the
  records whose formatted message matches the pattern, as env_logger does (everything after the
  first `/` is the pattern; an empty one filters nothing). `Filter::message_regex`,
  `Filter::message_pattern` and `Filter::matches(&Record)` (levels and message; the message is
  streamed into the matcher, no string built); `Filter`'s `Display` writes the pattern back.
  `FmtLogger` matches the message it already formatted for the line. A filter without a pattern
  costs nothing extra. `"info/x".parse::<Filter>()`, an error before, now succeeds; an invalid
  pattern is a `ParseFilterError` naming `/pattern` and the byte where it fails.
- **akio-regex** (new internal crate, no dependencies, `#![forbid(unsafe_code)]`): `Regex::new`,
  `is_match(&str)`, `is_match_fmt(fmt::Arguments)` (no allocation). The `regex` crate's syntax
  without captures, look-around and Unicode classes: Unicode-aware `\d \w \s`, classes, greedy
  and lazy repetition, alternation, groups, `^ $ \A \z \b \B`, flags `i` `m` `s` `U`. A Thompson
  NFA with a DFA built at compile time over character classes (ASCII table, intervals for the
  rest) and a Pike VM fallback: linear time on any pattern, about 1 ns per character.
  Unicode tables generated from regex-syntax by `tools/regex-tables`; differential fuzz target
  `regex_search` against the `regex` crate; `tools/codec-bench logregex` compares the two.

### Changed: faster P-256 key generation, signing and ECDH; RSA squaring by Karatsuba without IFMA

akio-crypto on x86_64 with BMI2 + ADX and AVX2: the P-256 fixed-base comb and the ECDH
multiplication keep the accumulator in one assembly frame for the whole multiplication. On Zen 4
against ring: key generation 1.40x → 1.57x, signing 1.38x → 1.49x, ECDH 1.12x → 1.15x,
secp256r1 TLS handshakes 1.07x → 1.08x rustls+ring. On x86_64 CPUs without AVX-512 IFMA, RSA
squaring at 3072 and 4096 bits is one level of Karatsuba: verification +5% / +9%. Constant-time
properties unchanged (`tools/ct-dudect`: no leak). No public API change (docs/BENCHMARKS.md).

### Added: SOCKS client, SOCKS proxies for the HTTP/WebSocket clients, UDP fragment reassembly, SOCKS4 BIND

Additive (ADR-019, docs/adr/019-socks-client-fragments-socks4-bind.md):

- **`akio_socks::SocksClient`**: SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` (no
  authentication or username/password), SOCKS4 and SOCKS4a `CONNECT` and `BIND`. On the engine:
  `dial` (an acceptor, TLS inside the tunnel if it is a `Tls` acceptor), `bind` (`on_bound`
  gets where the proxy listens), `udp_associate` (a `UdpAssociation`: `send_to`, `close`;
  datagrams to `on_datagram`); every failure before the tunnel opens (unreachable proxy,
  refusal, garbage, timeout) goes to `on_error`. Blocking: `dial_blocking` (a `TcpStream`),
  `bind_blocking` (`BlockingBind::accept`), `udp_associate_blocking` (`BlockingUdp`).
  `from_url("socks5h://user:pass@host")`, `handshake_timeout` (10 s), `bind_timeout` (60 s),
  `Version`, `impl From<SocketAddr> for Dest`, `ProxyRefused` re-exported.
- **SOCKS proxies for `akio_http::client::Client` and `akio_ws::client::dial`**: `Proxy` takes
  `socks5://`, `socks5h://`, `socks4://` and `socks4a://` URLs (port 1080 by default, URL
  credentials as RFC 1929 credentials or the SOCKS4 user id); every request, `http://` too, is
  tunnelled; `socks5`/`socks4` resolve the target first (IPv4 first), `socks5h`/`socks4a` let
  the proxy resolve it. A refusal is a `ProxyRefused` with the closest HTTP status and the new
  `ProxyRefused::socks_reply()`.
- **UDP fragment reassembly** (RFC 1928 `FRAG`) in the SOCKS5 server's relay and the client's
  associations: in-order sequences up to 65,507 bytes, one per association, 5 s timer.
- **SOCKS4 `BIND`** on the server, under the same `Socks::bind(true)` switch and `allow` hook as
  SOCKS5's.
- Behaviour changes: `Proxy::from_env` also reads `all_proxy` / `ALL_PROXY`; a relay that
  dropped fragmented datagrams now reassembles them; SOCKS4 `BIND` requests are served when
  `bind(true)` is set.
- Interop (`tools/interop/socks/run.sh`, 15/15): our client against Dante and against
  akio-socks, curl/PySocks/hand-written clients against the server (fragments, SOCKS4 BIND).
  New fuzz target `socks_client` (client handshake, tunnel transport, reassembly).

### Added: arpc middleware, coders and client pools (akio-arpc)

Additive (ADR-023, docs/adr/023-arpc-middleware-coders-pools.md):

- **Middleware**: `Routes::middleware` (every request and notify) and
  `Routes::method_middleware(method, ..)` take `Fn(&mut Context, Next)`; `next.run(ctx)` runs the
  rest of the chain (code after it runs after the handler), returning without it aborts. Fixed
  order (global, then per method, then the handler) whatever the registration order. New
  `Context::values` / `values_mut` / `responded`. Routes without middleware call the handler
  directly.
- **Coders** (`akio_arpc::coder`): `Coder` trait over whole frames, `Routes::coder`, encode in
  the order added and decode in reverse, as Go's `MessageCoder`. `Gzip::new(threshold)`
  (reserved bit 7, inflation bounded by `max_body_bytes`) and `Appender::new(name, bit)` (bit 0
  for tracing) are wire-compatible with `arpcex/extension/middleware/coder`. `Values` travel with
  `Peer::call_with` / `call_async_with` / `notify_with` and answers are coded with the request's
  values. Checked against fib's Go arpc both ways (`tools/interop/arpc/run.sh`); new fuzz target
  `arpc_coders`.
- **Pools**: `Pool::builder()` (`size`, `balance`: `Balance::RoundRobin` / `LeastPending`,
  `heartbeat`, `reconnect_interval`, `connect_timeout`) `.dial(..)`; calls go to a connection that
  is up, silent connections are closed and replaced by the heartbeat.
- **Bounded pending calls**: `Routes::max_pending_calls` (default
  `DEFAULT_MAX_PENDING_CALLS` = 65536 per connection); past it a call fails with the new
  `CallError::Overloaded`. New `Peer::pending_calls`, `Peer::ping`.
- Measured (gpu51, same-run A/B, medians of 10 rounds): calls without middleware 0.98x of
  before and one middleware 1.00x of none, both within the ~4% noise; +1.5% user instructions
  per call, cycles per call unchanged.

### Added: BitTorrent v2 and hybrid torrents, web seeds, LSD, IPv6 DHT, rate and seed limits

`akio-bittorrent` (ADR-018, docs/adr/018-bittorrent-v2-webseeds-lsd-ipv6-limits.md):

- **BEP 52 v2 and hybrid torrents.** New `merkle` module (SHA-256 trees, piece layers, hash
  request proofs as libtorrent sends them). `metainfo`: `InfoHashV2`, `TorrentVersion`,
  `FileEntry::pieces_root`, `PieceLayers`, `MetaInfo::{info_hash_v2, piece_layers,
  verify_piece}`, `Info::{verify_piece_with, piece_file, file_pieces, ...}`,
  `Builder::version`. v2 files are laid out on piece boundaries (padding files synthesized for
  v2-only torrents), so one piece space serves all three kinds. `MetaInfo::info_hash` is the
  hash peers use (truncated SHA-256 for v2-only torrents). Magnet `urn:btmh:`. Peer wire: the v2
  handshake bit, hash request / hashes / hash reject (`Handshake::with_v2`; the client sets the bit for v2 and
  hybrid torrents only). The client announces and accepts hybrid
  torrents under both hashes, fetches missing piece layers of magnet links with hash requests
  and answers them. Parsing refuses piece layers that do not match their roots and hybrid
  torrents whose two parts disagree.
- **Web seeds (BEP 19)** through akio-http's client: `ClientConfig::web_seeds` (on),
  `AddOptions::web_seeds`, `Torrent::add_web_seed`, `TorrentEvent::WebSeedError`; range requests
  of at most 4 MiB, one piece per web seed, backoff up to 10 minutes.
- **Local Service Discovery (BEP 14)**: module `lsd`, `ClientConfig::lsd` (on; never for
  private torrents), on a thread of its own, bounded to 50 announcements a second.
- **IPv6**: a client listening on `[::]:port` is dual-stack (IPv4 peers keep plain addresses);
  the DHT keeps an IPv6 routing table (BEP 32: `nodes6`, `want`, `Node::set_ipv6`,
  `compact_nodes6`, `Client::dht_nodes6`).
- **Rate limits** (`RateLimits`; `ClientConfig::rate_limits`, `Client::set_rate_limits`,
  `AddOptions::rate_limits`, `Torrent::set_rate_limits`) and **seed limits** (`SeedLimits`
  ratio and time; `TorrentEvent::SeedLimitReached` pauses the torrent). `TorrentStats` gains
  `seeding_time` and `web_seeds_active`.
- Interop: v2 and hybrid torrents both ways with libtorrent 2.0 (by .torrent and by magnet),
  hybrid torrents with aria2 1.37, web seeds from nginx, LSD on a Docker network. Fuzz targets
  `bt_lsd` and `bt_merkle`; `bt_bencode`, `bt_peer_wire`, `bt_krpc` extended.
- BEP 44 is not implemented, on purpose (ADR-018).

### Added: protobuf groups, extensions, editions, JSON and reflection; gRPC server reflection

ADR-022 (docs/adr/022-protobuf-gaps.md):

- **akio-protobuf-build**: proto2 `group` fields, `extend` blocks (typed `Extension` /
  `RepeatedExtension` constants), extension ranges, MessageSet; editions 2023 and 2024 with
  feature resolution (presence, closed enums, packed / expanded, `DELIMITED`, naming style,
  `export` / `local`); custom options and text-format aggregates; descriptors as protoc writes
  them, embedded per package (`FILE_DESCRIPTOR_SET`, `descriptor_pool()`), `Config::descriptors`,
  `Config::file_descriptor_set_path`; `descriptor.proto`, `type.proto`, `api.proto`,
  `source_context.proto` built in.
- **akio-protobuf**: `ExtensionSet`, `Extendable`, `Extension`, `RepeatedExtension`;
  `encoding::GroupCodec`, closed-enum decoders; `Enumeration::is_known`; `reflect`
  (`DescriptorPool`, descriptors, `DynamicMessage`, `Value`, `ReflectMessage`); `json`
  (canonical proto3 JSON, well-known types, `ignore_unknown_fields`); the descriptor well-known
  types in `well_known`.
- **akio-grpc**: `reflection::register` (gRPC server reflection v1 and v1alpha, for grpcurl /
  grpcui), the reflection messages in `reflection::v1` / `v1alpha`; depends on akio-protobuf.
- Verified: protobuf conformance runner v35.1, binary + JSON, 5627 passed, 0 failed
  (`tools/protobuf-test/conformance/run.sh`); descriptor sets equal protoc's; grpcurl
  (`tools/interop/grpc/grpcurl.sh`); fuzz targets `protobuf_json`, `protobuf_descriptor`.

Behaviour changes: proto2 (closed) enum fields keep unknown numbers as unknown fields instead of
storing them; extension fields of proto2 messages are now in `extensions`, not
`unknown_fields`; tags longer than 5 bytes are rejected (as C++ does). Encode/decode
cost is unchanged: same-run A/B against the previous commit on gpu51 (5 alternating runs, medians,
prost as control) gives Point 12/18 ns → 12/18 ns, Feature 19/47 ns → 18/45 ns, AllTypes
encode 309 → 312 ns (+1%, prost 509 → 505) and decode 1629 → 1448 ns (−11%, prost 1788 → 1749).

### Added: DTLS 1.3, connection IDs, PSKs and session resumption in akio-dtls

Additive except where noted (ADR-021, docs/adr/021-dtls13-cid-resumption.md; akio-dtls is an
Internal-tier crate):

- **DTLS 1.3** (RFC 9147) behind the same sans-io `Connection`: unified record headers with
  record number encryption, epochs with KeyUpdate (`Connection::update_keys`, automatic before
  a key's usage limit), ACKs with retransmission of only the unacknowledged fragments,
  stateless HelloRetryRequest cookies (`HelloVerifier::check` answers DTLS 1.3 ClientHellos with
  one), `use_srtp`, the TLS 1.3 exporter. `Config::with_versions` enables it (default: DTLS 1.2
  only, also in `Config::webrtc`); with both versions a connection falls back to DTLS 1.2 for a
  1.2-only peer, with the RFC 8446 downgrade check. New `Version`, `Connection::version`,
  `HandshakeInfo::version`, `CipherSuite::TLS13` and `CipherSuite::is_tls13`.
- **Connection IDs**: RFC 9146 `tls12_cid` records in DTLS 1.2 and DTLS 1.3 CIDs, with
  `Config::with_connection_id`, `Connection::local_connection_id`,
  `HandshakeInfo::{local_connection_id, peer_connection_id}` and `akio_dtls::connection_id` to
  route datagrams by CID.
- **Session resumption**: DTLS 1.2 session IDs (a bounded 1024-entry cache) and RFC 5077
  tickets, DTLS 1.3 NewSessionTicket (`psk_dhe_ke`), with `Config::with_session_resumption`,
  `with_ticket_key` (`TicketKey`), `with_ticket_lifetime` (2 h default, 7 days at most),
  `Event::NewSession(Box<Session>)`, `Connection::client_resume` and `HandshakeInfo::resumed`.
- **External PSKs**: `Psk`, `Config::with_psks`, the DTLS 1.2 PSK / ECDHE-PSK AEAD suites
  (`CipherSuite::PSK`, `is_psk`) and DTLS 1.3 external PSKs; PSK-only servers need no
  certificate. `HandshakeInfo::psk_identity`; alerts `MissingExtension`, `UnknownPskIdentity`.
- Changed: the default `Config` suite list starts with the DTLS 1.3 and PSK suites (each used
  only with its version or a PSK, so DTLS 1.2-only configurations behave as before);
  `Connection::poll_timeout` can return a time after a DTLS 1.3 handshake (final flight until
  acknowledged, tickets, KeyUpdate).
- Tests: DTLS 1.3 over simulated lossy, reordering and duplicating links at MTU 256 with
  KeyUpdates and CIDs, partial-flight retransmission, lost final flight and ACK, cookies,
  resumption, PSKs, version negotiation; the key schedule against RFC 8448. Interop
  (`tools/interop/dtls/run.sh`, new `Dockerfile` and `dtls13.sh`): OpenSSL 4.1 and wolfSSL 5.8.4
  (DTLS 1.3 both ways, HRR, MTU 300, KeyUpdate, resumption, PSKs, version negotiation, CIDs with
  wolfSSL), pion/dtls v3 (CIDs, PSK suites). Fuzz targets `dtls_record` and `dtls_handshake`
  cover CID and unified-header records and the DTLS 1.3 machines. DTLS 1.2 record path, same-run
  A/B on gpu51 (new `dtls-bench` example): 64-byte records 0.97-1.01, 1 KiB 1.00-1.02 of before.

### Added: TURN over TCP and TLS, a TURN client, ICE-TCP and simulcast sending

Additive (ADR-017, docs/adr/017-webrtc-turn-gaps.md):

- **TURN over TCP and TLS** (`akio-turn`): `TurnServer::stream()` returns a `TurnStream`
  acceptor for TCP listeners, and for TLS ones wrapped in `akio::tls::Tls` (`turns:`), with the
  UDP listener's allocations, quotas and credentials. An allocation made over a connection ends
  with it (`TurnCore::remove_client`); new `TurnConfig::stream_allocate_timeout` (30 s: a
  connection that has not allocated is closed) and `max_stream_queue` (256 KiB: relayed data for
  a connection with more queued is dropped). `TurnServer::stream_relay_of`. STUN and ChannelData
  framing in `akio_turn::framing` (`FrameReader`, `frame_len`, `MAX_FRAME`); `TurnEnv` gains the
  provided method `pads_channel_data`. RFC 6062 TCP relays are not implemented (`442`).
- **TURN client** `akio_turn::client::{Client, ClientConfig, ClientEvent, ClientState,
  ClientError}`: sans-io, one allocation over UDP or a stream; long-term credentials, stale
  nonces, refreshes, channels with a permission fallback, binding refreshes while a peer is in
  use, UDP retransmissions; at most 64 peers and 64 KiB waiting for bindings by default.
- **Relayed candidates for `Endpoint`**: `Endpoint::gather_relay(server, username, password,
  timeout)` allocates over the endpoint's UDP socket and adds the relayed candidate (and the
  server-reflexive address the server saw); the allocation is shared by the endpoint's peers,
  refreshed on the WebRTC timer thread and deleted by `Endpoint::close`. At most 4 per
  endpoint. New `Error::Turn`.
- **ICE-TCP** (RFC 6544): `Endpoint::listen_tcp(&engine, addr)` adds a passive TCP host
  candidate on a port of its own; connections are accepted on a dedicated thread (at most 256),
  must send a check for one of the endpoint's peers within 10 seconds, and carry RFC 4571
  frames. TCP candidates rank below UDP ones. `akio-ice` (internal tier) gains `TcpType`,
  `Candidate::host_tcp`, `Candidate::tcp_type` and `akio_ice::tcp`; `ParseError::Tcp` is gone.
- **Simulcast sending** (RFC 8853): `SdpChanges::add_simulcast_media(kind, dir, rids, ..)` and
  `Peer::write_simulcast(mid, rid, ..)`: one RTP stream and RTX stream per RID, `a=rid` /
  `a=simulcast` in the SDP, MID and RID header extensions (repaired RID on retransmissions),
  per-encoding sender reports, NACKs and PLI/FIR (`KeyframeRequest::rid`); the answer's
  `a=simulcast:recv` picks the encodings sent. As an answerer the stack accepts simulcast offers
  (`a=simulcast:recv` in its answer, RTX mapped by repaired RID).
- Interop (`tools/interop/webrtc/run.sh`, new `linux.sh` running everything in Linux
  containers): pion/turn and coturn clients against `akio-turn` over UDP, TCP and TLS; the
  `akio_turn` client against pion/turn, coturn and `akio-turn` over UDP, TCP and TLS; an
  `Endpoint` with only relayed candidates (from `akio-turn`, pion/turn, coturn) and with only its
  passive TCP candidate to pion; simulcast h/m/l received by pion. New fuzz targets
  `turn_stream` and `ice_tcp`.

### Added: fMP4 HLS, RTMP and RTSP clients, WebRTC media in akio-media

Additive (ADR-016, docs/adr/016-media-fmp4-clients-webrtc.md):

- **fMP4 / CMAF HLS**: `HlsConfig::format = SegmentFormat::Fmp4` serves `init-<n>.mp4`,
  `seg-<n>.m4s` and LL-HLS parts `part-<n>.<m>.m4s` (H.264, H.265, AAC, Opus) next to MPEG-TS,
  which stays the default. New module `fmp4` (`Muxer`, `Demuxer`, `write_styp`).
- **RTMP client** `rtmp::client::{push, pull}`: relays a hub stream to an RTMP server or pulls one
  into the hub (Enhanced RTMP H.265/Opus), with timeouts for connect, handshake, each command and
  idle, bounded messages and send queues.
- **RTSP client** `rtsp::client::{pull, push}` (play and record, TCP interleaved or UDP, Digest and
  Basic auth, keep-alives, RTCP reports); `rtsp::message::Reply` and `Parser::client`.
- **WHIP/WHEP media**: with the new cargo feature `webrtc`, `webrtc::RtcMedia` carries H.264,
  H.265, Opus and G.711 through akio-webrtc: WHIP into the hub, WHEP out of it. `WhipServer`
  drops sessions whose peer ended without a `DELETE`.
- **Keyframe requests**: `Publisher::on_keyframe_request`, `Subscription::request_keyframe`,
  `Hub::request_keyframe`, throttled by `HubConfig::keyframe_request_interval` (500 ms); WebRTC
  viewers' PLI/FIR reach WHIP publishers as PLI.
- Interop: ffmpeg/ffprobe (fMP4 HLS plain and LL-HLS, RTMP and RTSP listen modes), mediamtx (RTMP,
  RTSP over TCP and UDP), ffmpeg's WHIP muxer and pion (WHIP, WHEP, PLI round trip). New fuzz
  targets `fmp4_demux`, `rtmp_client`, `rtsp_client`.
- Fixed: akio-webrtc `Endpoint::config`, `close_on_disconnect` and `connect_timeout` panicked
  after `bind`.

### Added: XDP rate limiting, I/O-thread pinning, eBPF hash steering, spliced SOCKS tunnels

Additive (ADR-027, docs/adr/027-ebpf-xdp-pinning-socks-splice.md):

- **`akio::ebpf::xdp::RateLimiter`**: per-source token buckets in XDP. It counts TCP SYNs
  (connection-flood protection) or every packet, keeps sources in a bounded per-CPU LRU map, and
  attaches natively or generically with a BPF link or netlink. It never replaces another
  program, detaches on drop, and exposes `stats()` and `forget()`.
- **`EbpfConfig::pin_threads`**: pins I/O thread `i` of `n` to the CPUs `c % n == i`, so
  `Steering::Cpu` lands on the thread running on the receiving CPU. Also adds
  `ebpf::cpu_pinning`, `SteerInfo::pinned_threads` and
  `akio_sys::process::{allowed_cpus, pin_current_thread}`.
- **eBPF tier for `Steering::Hash`** (privileged): same hash and thread as the classic tier, with
  sockets named in a `REUSEPORT_SOCKARRAY`, independent of the order they joined the group.
- **Sockmap relay**: bytes queued before a splice are relayed instead of waiting for more data.
  New `Relay::splice_inner`, `Relay::splice_inner_with` (write a last handshake message before
  anything is relayed) and `ebpf::byte_counts`.
- **akio-socks**: `ProxyConfig::sockmap` / `Socks::sockmap` splices SOCKS and HTTP `CONNECT`
  tunnels in the kernel (opt-in), falling back to userspace relaying when that is not possible.
- `AKIO_ACCEL` knob in `bench-server`, `ebpf-bench` example, `tools/bench/ebpf.sh`; fuzz target
  `xdp_rate_limit`.

### Added: IPv6, ECN and pacing in akio-dpdk's userspace stack

Additive (ADR-026, docs/adr/026-userspace-ipv6-ecn-pacing.md; akio-dpdk is experimental):

- **IPv6** on `Backend::Dpdk`: `DpdkConfig::address6` turns it on (plus a link-local address
  from the MAC), with `prefix_len6` (64) and `gateway6`. Listeners are dual-stack (the port
  serves both families; listener addresses `::`, `address6` or the link-local one), `dial` /
  `dial_udp` take IPv6 peers. Extension headers walked with limits and parameter problems,
  fragmentation and reassembly (RFC 5722 overlap discard, atomic fragments), ICMPv6 echo and
  errors, a path-MTU cache, NDP with the ARP cache's pending queue (no first-SYN drop), DAD
  probes for our addresses answered, MLDv2 reports; NDP frames fanned out to every queue,
  AF_PACKET joins all-multicast. Static addresses: no SLAAC, router advertisements or DAD.
- **ECN** (`DpdkConfig::tcp_ecn`, RFC 3168) and **pacing** (`DpdkConfig::tcp_pacing`, rate
  `cwnd / srtt` times 2 in slow start, 1.2 after), both off by default. Simulated 20-frame
  bottleneck: ECN 0 drops instead of 29, pacing 14 instead of 29.
- The neighbour cache bounds the bytes queued for unresolved neighbours (4 MiB per stack).
- IPv4 stays as fast as before (memory-wire `stack-bench` on x86, new / main): request/response
  1.02-1.04, UDP and bulk 1.01, sequential connections 0.99; the neighbour caches no longer hash
  with SipHash.
- Not done: checksum / TSO / LRO offloads (the PMDs in reach do them in software).
- Tests: IPv6 and ECN / pacing on the simulated lossy link, dual-stack memory-wire tests,
  kernel interop over IPv6 in Docker (TAP, AF_PACKET, DPDK `net_tap` with two queues: `ping -6`,
  UDP with fragments, TCP both ways, `netem` loss with ECN and pacing); fuzz targets
  `dpdk_ipv6`, `dpdk_icmpv6`, `dpdk_ndp`.

### Changed: UDP datagrams delivered in owned receive buffers (akio-sys, akio-epoll, akio-quic; ADR-024)

The UDP loop (epoll, io_uring and macOS; servers and dialed sockets) receives into pooled receive
slabs and can hand each datagram to the handler as an owned buffer (hidden
`Handler::OWNED_DATA` / `on_data_owned`), GRO batches split without a copy. akio-quic uses it and
decrypts packets in place, so no copy is left between the kernel and the decrypted payload. The
UDP peer table hashes with the keyed folded-multiply hasher (shared with akio-quic as the hidden
`akio_core::hash`) instead of SipHash. `akio-buf` now allows unsafe code in one module (`slab`,
Miri- and loom-checked; docs/unsafe-review.md). Same-run A/B on loopback: QUIC bulk, HTTP/3,
handshakes and UDP echo within 1% (HTTP/3 1.01, the rest 1.00; docs/BENCHMARKS.md). Handlers that
do not opt in, including secured ones, see no change. No public API change.

### Changed: no boxed response sink and no target allocation per HTTP request (ADR-025)

The last two per-request allocations named after the HTTP/3 allocation pass are gone
(docs/adr/025-per-connection-response-sink.md):

- **Target buffers are reused.** When a handler is done with a request it did not detach or
  upgrade, its target buffer (up to 1 KiB) becomes the thread's spare. The next request parsed
  on that thread writes its target into it, on HTTP/1.1, HTTP/2 and HTTP/3. Per thread rather
  than per connection: a per-connection buffer is cold when that connection's turn comes again,
  and cost h2c about 100 cycles per request in a first version. `Request::target` stays a
  `String`, so handlers, routers and middleware are unchanged.
- **One response sink per connection.** akio-http's transport hook (`akio_http::transport`,
  `#[doc(hidden)]`, outside the semver promise) gets:
  - `ConnSink`: `send` / `start_stream`, each with a per-request `u64` tag;
  - `SharedSink`: a thin handle to it;
  - `dispatch_conn` / `start_conn`, and `request_target` for transports building requests.

  akio-h3 answers every request of a connection through one sink (tag: stream index and HEAD
  flag), instead of boxing a sink and cloning three `Arc`s per request. Because the handle is a
  thin pointer, `Context`'s responder stays at 16 bytes. A fat `Arc<dyn ConnSink>` plus the tag
  grew `Context` by 8 bytes, which cost h2c about 1% of cycles, since HTTP/2 boxes a `Context`
  per request.
- Allocator calls per request (bpftrace on x86_64): `quic-bench h3` both ends 11.0 → 9.0;
  HTTP/1.1 server 6.0 → 5.0, pipelined 6.0 → 5.0, h2c 6.5 → 5.5. The earlier HTTP/3 entry's 8.6
  was counted another way; with this method, 776f001e (before ADR-011) makes 10.8.
- Same-run A/B on gpu51 (Zen 4, quiet host):
  - HTTP/3 GET, one connection, 64 in flight: 1.0059× (runs of 7 alternating rounds: 1.0087×
    and 1.0032×).
  - Server user-space cycles per request (`perf stat`, medians of 7): HTTP/1.1 0.951×,
    pipelined 0.968×, h2c 0.973×; instructions −1.2% to −1.4%.

| Before (deprecated, still compiles) | After |
|---|---|
| `impl ResponseSink for S` (`send(self: Box<Self>, resp)`) | `impl ConnSink for C` (`send(&self, tag, resp)`), one per connection |
| `transport::dispatch(&svc, req, Box::new(s))` | `let sink = SharedSink::new(c);` per connection, then `transport::dispatch_conn(&svc, req, &sink, tag)` |
| `transport::start(&svc, req, Box::new(s))` | `transport::start_conn(&svc, req, &sink, tag)` |
| `Request::new(m, path.to_owned())` | `Request::new(m, transport::request_target(path))` (optional) |

### Added: spans, push export (OTLP, StatsD), per-route HTTP labels, HTTP/2 gauges

Additive (ADR-020, docs/adr/020-spans-and-push-export.md):

- **Spans in akio-log** (`akio::log::span`): `Span`, `SpanBuilder`, `span!` / `info_span!` ...,
  `SpanContext` with W3C `traceparent` parsing and printing, `Tracer` (`set_tracer`), a maximum
  span level of its own (`set_max_span_level`, off by default: a disabled span costs one relaxed
  load), `enter` / `in_scope` / `enter_context` / `current`. `FmtLogger` adds `trace_id` /
  `span_id` inside a span. No `tracing` bridge (ADR-020 says why).
- **HTTP request and connection spans**: `akio_http::request` (`info`, kind server) for every
  HTTP/1.x, HTTP/2 and HTTP/3 request, named `"GET /users/:id"` once routed, with method, path,
  route, protocol version, client address and status, child of an incoming `traceparent`;
  `akio_http::connection` (`debug`) per connection. `Context::span_context()`,
  `Context::route()` (`RouteInfo`), `akio_http::trace`.
- **Per-route HTTP metrics**: `HttpMetrics::with_routes(n)` labels requests and latency with
  the route's method and pattern (never the raw path), at most `n` routes (≤ 4096), then
  `route="other"`; unmatched requests are `route="unmatched"`. `HttpMetrics::route_snapshot()`,
  families `akio_http_route_requests_total` and `akio_http_route_request_duration_seconds`.
- **HTTP/2 gauges**: `observe::H2Stats` via the new `H2Config::stats`: connections and streams
  open and total, `RST_STREAM` and `GOAWAY` frames each way (`akio_http2_*`).
- **New crate `akio-export`**: pushes metrics (`Telemetry::collect_all()`, new, and extra
  collectors) and spans from one background thread to an OpenTelemetry collector over OTLP/HTTP
  (protobuf or JSON) and to StatsD / DogStatsD over UDP (counter deltas). Bounded span queue
  (drops and counts when full), failed pushes counted and not retried, timeouts on every OTLP
  step, sampling ratio. End-to-end test against the OpenTelemetry Collector in Docker
  (`tools/otel/e2e.sh`); fuzz targets `log_traceparent`, `export_http_response`, `export_otlp`.
- akio-core: `Metrics::collect_into` and `Telemetry::collect_all` (the engine's series as
  `Families`, identical to the Prometheus rendering).

### Added: hot reload of the read buffer, backlog and UDP idle timeout; I/O thread resizing

ADR-028 (docs/adr/028-hot-reload-buffers-backlog-threads.md):

- `Engine::reload` now applies **`read_buffer`** (each I/O thread swaps its buffer between two
  batches of events, so open connections read with the new size from their next read; io_uring
  moves connections to a new provided-buffer group as their receives are re-armed), **`backlog`**
  (live listening sockets are `listen`ed again; new `akio_sys::set_backlog`) and
  **`udp_idle_timeout`** (open peers' timers re-armed). `ReloadReport::ignored` now names
  `max_pending_responses`, `write_timeout`, `connect_timeout`, `udp_max_peers`, `udp_gro`.
  New `Live` getters/setters for the three settings.
- **`Engine::threads()` / `Engine::set_threads(index, n)`**: grow or shrink the I/O threads of a
  TCP listener or client group while the engine runs (epoll, kqueue, io_uring). Growing adds a
  `SO_REUSEPORT` socket per new thread (Linux) or a clone of the shared socket; shrinking retires
  the highest threads, which hand their listening sockets to the others (nothing queued is reset)
  and keep serving their own connections until they close: connections never move between
  threads. New `Config::retire_timeout` (default `None`, reloadable) shuts down what a retired
  thread still serves after it. `LoopMetrics::retiring`, Prometheus `akio_loop_retiring`. UDP
  listeners, DPDK and BPF-steered listeners return `Unsupported`.
- akio-prefork: **reload in place**: `Controller::reload_in_place` / `Supervisor::reload_in_place`
  and SIGUSR1 run each worker's `Worker::on_reload` hook (apply a new configuration and thread
  count without replacing processes); `Worker::reloads`, `Status::in_place_reloads`.
- Hot path unchanged (same-run A/B in docs/BENCHMARKS.md, "Hot reload").

### Added: documentation site for GitHub Pages, a runner for the book's examples

- `book/site.sh` builds the site published at `lesismal.github.io/akio`: both books, a language
  switch and an API link on every page, localized 404 pages and a site-wide `404.html`, and the
  rustdoc of every published crate under `/api/`. `book/check-site.py` serves it under the same
  base path and checks every internal link, resource and fragment (also the crates' rustdoc
  links back to the book), that both books have the same pages, and the 404 handling.
  `.github/workflows/pages.yml` runs both and deploys on a published release or by hand; the
  release-only `book-deploy` job left `ci.yml`. Enabling Pages is a one-time repository setting.
- `book/check-guides.sh` runs every program the books include code from: the 21 `guide-*`
  examples (each exits 0 or fails), the serve-only ones (`guide-media`, `guide-media-rtsp`,
  `echo`, `udp-echo`, `hello`, `prefork-http`, probed from outside) and the gRPC chapter's
  generated stubs; on Linux in a private network namespace. Passes on macOS, Linux arm64 and
  Linux x86_64, on epoll and (`AKIO_DEFAULT_BACKEND=uring`) on io_uring.
- `AKIO_DEFAULT_BACKEND=uring` (ADR-029, Linux): TCP listeners that do not call
  `Listener::backend` are served by io_uring (non-strict: falls back to epoll with a warning).
  An explicit backend always wins; UDP listeners and client threads are not affected; read once
  per `Engine::build`. A test and diagnostic knob, so unchanged programs (the guide examples) can
  run on io_uring. No public API change.
- `book/check-includes.py` also checks that `book/en` and `book/zh-CN` have the same chapters
  with the same headings, includes, code blocks, table rows and list items.
- Docs brought in line with the code: WebSocket over HTTP/3 is no longer listed as missing;
  `H3Config` / `H3ClientOptions` field names and QPACK defaults, `DialOptions::proxy` /
  `max_redirects`, `AKIO_UDP_ECN` and `AKIO_LOG` in the configuration reference; akio-quic is
  v1 and v2; the guide-example table lists all of them; the Chinese RTSP chapter gained the
  authentication bullet. Three broken rustdoc links fixed (akio-log, akio-h3, akio-bittorrent).

### Added: WebSocket over HTTP/3, QPACK dynamic table, streamed HTTP/3 request bodies

Additive (ADR-011, docs/adr/011-h3-websocket-qpack-streaming.md):

- **WebSocket over HTTP/3** (RFC 9220). Servers advertise extended CONNECT;
  `Context::upgrade_websocket` accepts it with the same checks, subprotocols and
  `permessage-deflate` as on HTTP/1.1, answers `200` and carries the WebSocket on the request
  stream with the same `WsHandler` / `WsSender`. `Router` routes an extended CONNECT for
  `websocket` to the path's GET route, so one `.get("/ws", ...)` serves HTTP/1.1 and HTTP/3.
  New `Request::protocol` (`:protocol`). Client: `H3Client::websocket` /
  `websocket_blocking` with `H3WsOptions`; `H3Error::Status` for a refusal.
- **QPACK dynamic table** (RFC 9204), configured in `H3Config` on servers and in
  `H3ClientOptions` on clients (`H3Client::dial_with`): `qpack_max_table_capacity` (4096) and `qpack_blocked_streams` (16)
  for our decoder (encoder/decoder streams, blocked sections held in order, acknowledgements,
  increments and cancellations), `qpack_encoder_capacity` (0, off) for our encoder, which only
  references acknowledged entries so it never blocks the peer. New error codes
  `code::QPACK_ENCODER_STREAM_ERROR` / `QPACK_DECODER_STREAM_ERROR`. Servers now advertise a
  4 KiB table: nghttp3 (curl) and OpenSSL's QUIC use it at once.
- **Streamed request bodies on HTTP/3**: services with `BodyMode::Stream` get the body through
  `Context::on_body` as it arrives, as on HTTP/1 and HTTP/2, without `max_body_bytes`; the
  request reader never holds DATA payloads. Client: `H3Client::upload` returns an `H3Upload`
  (`write`, `finish`, `queued_bytes`).
- Interop: quic-go (WebSocket over HTTP/3 and streamed uploads both ways), libcurl with
  ngtcp2/nghttp3 and OpenSSL QUIC in Docker (nghttp3 fills our decoder's table). New fuzz
  target `qpack_dynamic`; `h3_frame` and `h3_request` cover the QPACK streams, blocked sections,
  extended CONNECT and the streaming reader.
- HTTP/3 throughput with the encoder off: `quic-bench h3` same-run A/B is 1.025x of the release
  without these features (881.3k vs 859.6k req/s on gpu51, two runs of 7 alternating rounds:
  1.024x and 1.027x, faster in all 14), about 300 fewer instructions per request (x86
  callgrind). A request or response that arrives whole (one HEADERS frame, at most one DATA
  frame) is read without the frame reader or per-stream state, the client decodes it before
  taking its lock, request deadlines index their queue by token instead of hashing, and a
  request opens its stream under the lock it already holds. Both QPACK encoders on cost
  18% on that benchmark (tiny requests, one acknowledgement each), which is why the encoder is
  off by default.

### Changed: safe defaults everywhere, loop-safe I/O, leaner hot paths (ADR-009, docs/rules.md)

New development rules (docs/rules.md, adapted from fit's): never block an I/O thread, bodies
streamed and bounded, linked backpressure, timeouts and safe-default limits everywhere, build
time over request time on the hot path, verification sized to the change. The code was audited
against them; every limit below has a safe default, and 0 / `None` stays the explicit opt-out.

**Engine (akio-core, loops, akio-tls)**
- `Config::write_timeout` 60 s (was `None`); `Config::udp_max_peers` 65536 (was `None`); new
  `Config::connect_timeout` (10 s) for `Engine::dial` on epoll, kqueue and io_uring.
- New `Config::max_pending_responses` (32): pipelined responses behind an unfinished one pause
  reads (and count toward the write watermark / `max_queued_bytes`) instead of piling up.
- TLS handshake timeout: `ServerConfigBuilder::handshake_timeout` /
  `ClientConfigBuilder::handshake_timeout` (10 s), enforced by the loops through the new
  `Transport::handshake_timeout`.
- Hot path: cork state is an atomic, the drain lock is skipped when nothing waits, command
  queues keep their capacity; ~7 → 4 uncontended lock operations per pipelined request.

**HTTP server (akio-http)**
- `HttpConfig::head_timeout` 10 s (slowloris; 408), `keep_alive_timeout` 75 s, `body_timeout`
  60 s; HTTP/2 preface/SETTINGS deadline and idle GOAWAY.
- HTTP/2 Rapid Reset and flood budgets: `H2Config::max_resets` (100 per 30 s, MadeYouReset
  counted), `max_control_frames` (1000 per window) → GOAWAY ENHANCE_YOUR_CALM;
  `max_conn_pending_bytes` (32 MiB) over all streams.
- Static files touch the disk only on a pool (16 threads, 4096 queued, 503 when full); cache
  hits stay on the I/O thread, compressed twins (and their absence) are cached, headers are
  formatted once per entry, the cache is 16 RwLock shards.
- Request path: no shared `Arc` bump per routed request, 405 `Allow` precomputed, requests with
  a body routed once, metrics `in_flight` per shard, inline response filters, CORS / compress /
  limiter / csrf / request_id without per-request formatting or global locks. Pipelined
  HTTP/1.1 and h2c about +3–4% (same-run A/B), plain HTTP/1.1 within 1%.

**HTTP clients (akio-http, akio-h3)**: HTTP/1 response head 64 KiB, body 64 MiB, request
timeout 30 s, idle pool 32 per host / 256 in all, 90 s idle expiry; HTTP/2 frame size checked
before buffering, header blocks 2 × `max_header_list`, body 64 MiB, at most 32 pushes per
request; HTTP/3 body 8 MiB, field sections 64 KiB, request timeout 30 s. New
`ClientError::Timeout` / `TooLarge`, `H3Error::TooLarge`.

**gRPC and arpc**: the global `Mutex<Vec>` deadline threads are replaced by a cancellable,
sharded deadline service (calls with a deadline: gRPC ×17, arpc ×278 calls/s; without: +1%).
`grpc-timeout` clamped to `GrpcServer::max_deadline` (24 h), `GrpcClient::default_timeout`
(30 s), `max_collect_bytes` (64 MiB); arpc `Routes::max_streams_per_conn` (1024) and
`call_timeout` (30 s); fewer copies and locks per message.

**WebSocket, media, WebRTC**: compressed (permessage-deflate) messages are bounded too (close
1009); frames encoded on the stack and buffers reused (plain echo at 1 KiB +7–11%). RTMP chunk
reader parses in place (was O(n²) copying) with a 32 MiB partial cap; HLS segments cut at
`max_bytes` without keyframes; hub 1024 streams / 1000 subscribers per path, WHIP 256 sessions,
SRT 1024 connections, RTMP handshake 10 s / idle 60 s, RTSP session timeout enforced (60 s) and
request timeout 10 s; `RtcServer` / `Endpoint::max_peers` (1024).

**QUIC, HTTP/3, KCP**: per-stream and per-connection QUIC send buffers (16 MiB each) with
`Error::Overloaded` and `QuicHandler::on_stream_writable`; `receive_window` 10 MB (was
unlimited); `ServerConfig::max_connections` (10,000, stateless CONNECTION_REFUSED). HTTP/3 file
bodies are read on the pool only as the stream has room. KCP `max_sessions` 4096 and
`KcpHandler::on_writable`. A 4 MiB per-stream default cost QUIC single-stream bulk about 2.5%, so the stream default
equals the connection's (16 MiB matched the baseline on gpu51).

**SOCKS, mux, TURN, BitTorrent, log, DTLS**
- SOCKS / HTTP CONNECT: **destinations default to public addresses only** (loopback, private,
  link-local, CGNAT, multicast and reserved refused after resolution, including mapped forms;
  also for BIND and UDP ASSOCIATE); handshake 10 s, idle 5 min, early data capped at 256 KiB,
  CONNECT DNS on a bounded pool.
- akio-mux sniff timeout 5 s. TURN allocations sharded by client (relay throughput about
  140k → 513k datagrams/s). BitTorrent tracker DNS off the I/O threads, tracker server 100k
  swarms / 1000 peers per swarm with eviction, uTP inbound table 1024. akio-dtls bounds
  reassembly before the cookie exchange.
- akio-log: opt-in `FmtLogger::non_blocking` (bounded queue, drops and counts); the default
  stays synchronous.

### Added: HTTP and WebSocket client redirects, timeouts, proxies, system roots (ADR-010)

- Redirects, opt-in: `client::RedirectPolicy` (`none()` by default, `limit(n)`,
  `allow_https_downgrade`) with `Client::with_redirects`. 301/302/303/307/308 with RFC 9110
  section 15.4 method and body rules, relative `Location`s, `Authorization` / `Cookie` /
  `Proxy-Authorization` dropped on a redirect to another origin, https → http not followed by
  default, `ClientError::TooManyRedirects` past the limit; `ClientResponse::url` is the URL that
  answered. The WebSocket handshake follows them with `DialOptions::max_redirects` (default 0;
  `WsClientError::TooManyRedirects`).
- Per-request timeout: `ClientRequest::timeout` / `.timeout(d)` and `Client::with_timeout`,
  covering resolution, connecting, TLS, the response and redirects (`ClientError::Timeout`, the
  connection is closed). `H2Client` honours it by resetting the stream.
- Name resolution off the calling thread: new `akio::dns::resolve` (a dependency-free pool of up
  to four resolver threads; IP literals inline), used by the HTTP/1 and WebSocket clients.
- System root certificates: `akio::tls::RootCerts::system()` (`SSL_CERT_FILE` / `SSL_CERT_DIR`,
  macOS keychains via `/usr/bin/security`, Linux/BSD CA bundles and directories). **Behaviour
  change:** `Client` without `with_tls` and `DialOptions::tls = None` now use it for `https://` /
  `wss://` instead of failing.
- HTTP proxies: `akio_ws::proxy::Proxy` (re-exported as `akio_http::client::Proxy`; `all`,
  `http`, `https`, `no_proxy`, opt-in `from_env` for `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`),
  `Client::with_proxy`, `DialOptions::proxy`. `http://` in absolute form, `https://`, `ws://` and
  `wss://` through `CONNECT`; credentials in the proxy URL become `Proxy-Authorization: Basic`;
  a refusal is an `io::Error` carrying `ProxyRefused`.
- The WebSocket client closes its open connections with 1001 (going away) when its engine shuts
  down gracefully (they ended with 1006).

### Added: SOCKS5 BIND and UDP ASSOCIATE, a SOCKS access-control hook, `Engine::adopt_tcp`

- `akio-socks` serves SOCKS5 `BIND` and `UDP ASSOCIATE` (RFC 1928), both off by default
  (`Socks::bind(true)`, `Socks::udp_associate(true)`; `bind_timeout`, `udp_idle_timeout`).
  UDP: one relay socket per association (the engine needs `udp_client_threads`), client
  recognised by IP and port, fragments dropped, answers relayed only from destinations the
  client sent to, ends with the control connection or after the idle timeout. BIND: listener on
  the proxy's address, two replies, the accepted connection relayed with backpressure.
- `Socks::allow(|request| ..)`: an access-control hook over `CONNECT` (SOCKS5/4/4a), `BIND`,
  `UDP ASSOCIATE` and each UDP destination, with the new `Command`, `Dest` and `Request` types.
  Refusals answer reply 2 (SOCKS4: 0x5b) or drop the datagram.
- `Engine::adopt_tcp(stream, acceptor, on_error)` serves a TCP stream accepted outside the engine
  like a dialed connection (epoll and io_uring).
- Interop: `tools/interop/socks/run.sh` (curl, PySocks, BIND and UDP edge cases; Dante as the
  reference server). ADR-012. Additive API (`api/akio-socks.txt`, `api/akio.txt`).

### Added: `AKIO_LOG` filter directives and compile-time log level caps

- `akio::log::Filter`: per-target levels from env_logger-style directives
  (`info,akio_http=debug,akio_quic::conn=trace,akio_http::access=off`), parsed once.
  `akio::log::init_from_env(default)` installs the formatted logger filtered by `AKIO_LOG`; it is
  opt-in, nothing reads the environment otherwise. `FmtLogger::filter` / `init_filtered` take a
  filter built in code.
- akio-log cargo features `max_level_*` / `release_max_level_*` and `STATIC_MAX_LEVEL`, as in
  the `log` crate: statements above the cap are compiled out. Without them the generated code is
  unchanged (disabled `trace!`: 0.400 → 0.401 ns on x86_64, same binary on macOS). ADR-012.
  Additive API (`api/akio-log.txt`).

### Added: shared 0-RTT anti-replay store (akio-tls) and compatible version negotiation (akio-quic)

Additive API (ADR-013, docs/adr/013-shared-anti-replay-and-compatible-vn.md):

- **`AntiReplayStore`** (akio-tls): where a server records the ClientHellos whose early data it
  accepted. One method, `check_and_insert(binder, ttl) -> io::Result<bool>`, atomic, called on
  the handshake path only for ClientHellos whose early data would otherwise be accepted. Errors
  **fail closed** (the early data is rejected, the client sends it again after the handshake).
  `MemoryAntiReplay` is the default (the existing bounded per-configuration record, 100,000
  entries), now public. `ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)`
  plugs in a shared one (Redis `SET key 1 NX PX ttl`, sketched in the book's TLS chapter);
  `ServerConfigBuilder::session_ticket_key([u8; 48])` lets servers in several processes or
  machines accept each other's tickets in the first place. QUIC servers get both through their
  TLS configuration. Accepted ClientHellos are now kept 30 s (was 20 s): twice the 10 s
  freshness window plus one window for the clocks of servers sharing a store to differ by.
- **Compatible version negotiation** (akio-quic, RFC 9368 section 4):
  `ServerConfig::prefer_version(Version)` moves clients that start in the other version and list
  the preferred one in their version_information to it within the handshake, without a round
  trip; also when the ClientHello spans several packets, after a Retry, and with 0-RTT (whose
  packets stay in the client's first version, RFC 9369 section 4.1). Off by default: the server
  answers in the client's version. akio-quic clients always follow such a switch (a forged
  Initial of the other version that does not decrypt does not move them).
- Tests: two TLS servers sharing a ticket key and a "remote" store reject a ClientHello replayed
  from one to the other (accepted with separate records), a failing store rejects early data,
  the same over QUIC on the simulated link; compatible negotiation on the simulated link (no
  extra round trip, Retry and 15% loss, a ClientHello over two packets, 0-RTT across the switch, v2
  to v1, no switch without the preference or without v2 in the client's list, a forged Initial).
  Fuzzing: the `quic_conn` pair now switches to v2, and `tls_server` also runs the ClientHello
  peek. Interop: `tools/interop/quic/ngtcp2-cvn.sh` (new) with ngtcp2 1.11, which implements RFC
  9368, both ways in Docker (its client moved to v2 by akio-h3, with 0-RTT; akio-quic moved to v2
  and to v1 by its server); quic-go does not implement RFC 9368, so `tools/interop/quic/run.sh`
  checks that its clients keep their version against servers preferring the other one.
- Cost: none measured (BENCHMARKS.md, handshake A/B).

### Changed: QUIC session tickets and tokens are bound to the QUIC version (akio-tls, akio-quic)

RFC 9369 section 5 (ADR-014, docs/adr/014-quic-version-bound-resumption.md):

- A session ticket or NEW_TOKEN token belongs to the QUIC version of the connection that issued
  it, the negotiated one after compatible version negotiation. Servers resume only a ticket from
  the version the client started in (another one gets a full handshake without 0-RTT) and
  validate addresses only with tokens from it; Retry tokens are bound the same way.
- Clients never present a v1 ticket or token in v2 or the reverse: they start in the version of
  their newest ticket for the server (else of their token) when they speak it, instead of
  `ClientConfig::version`. A client configured for v1 that a server preferring v2 moved to v2
  starts its next connection in v2 and resumes with 0-RTT, without a switch.
- Upgrading: tickets and tokens issued before are unbound and no longer accepted by QUIC servers
  (one full, unvalidated handshake per client). TLS over TCP is unaffected (format 2 sessions
  still decode). No public API change (the hidden `akio_tls::quic` interface gains versioned
  constructors).
- Tests: akio-tls tickets per version (offered, rejected, moved by `set_ticket_version`, unbound
  handshakes kept apart); akio-quic token checks per version; on the simulated link a client
  moved to v2 resumes in v2 with ticket, token and 0-RTT, and a v1 ticket is not used in v2.
  Interop: `tools/interop/quic/ngtcp2-cvn.sh` now also checks that ngtcp2 1.11's client, which
  restarts in v1 with a ticket from a connection moved to v2, gets a full handshake, and resumes
  with 0-RTT when it starts in v2 (0-RTT across a switch still checked, with a v1 ticket from a
  twin port sharing the ticket key).

### Changed: Poly1305 on AVX2 for CPUs without AVX-512 IFMA

akio-crypto's Poly1305 (and so ChaCha20-Poly1305) absorbs four blocks per step on AVX2 in radix
2²⁶ for runs of 512 bytes and more on x86_64 CPUs without AVX-512 IFMA (Zen 2 and 3, most Intel
client parts); it was the scalar loop. Measured on Zen 4 through the AVX2 path: ChaCha20-Poly1305
seal 16–64 KiB +20%, 1 KiB +7% (docs/BENCHMARKS.md). CPUs with IFMA and messages under 512 bytes
are unchanged. No public API change.

### Added: multi-range static file responses, open-file cache eviction, partial-segment routes

- `files::Files` answers several ranges (`Range: bytes=0-9,500-599`) with `206` and a
  `multipart/byteranges` body (RFC 9110 section 14.6), parts in request order. Overlapping ranges
  and ranges less than 80 bytes apart are coalesced (section 14.2); ranges past the end are
  dropped and `416` comes only when none is left; a header with more than 32 ranges, or parts
  adding up to more than 1 MiB, is ignored and the whole file is sent. `If-Range` applies as for
  single ranges. Malformed range specs keep answering `416`.
- The open-file cache (`Files::max_open_files`) evicts the least recently used handle (CLOCK)
  instead of serving new files uncached once it is full, notices a file renamed over a cached one
  (device and inode are compared along with size and modification time) and drops entries of
  deleted files.
- `Router` patterns may mix literal text and parameters in one segment: `/{name}.txt`,
  `/v{major:[0-9]+}.{minor}`, `/{owner}/{repo}.git` (ADR-007). Matching is linear, with no
  backtracking inside a segment; precedence is static > partial > regexp > parameter > wildcard.
  Lookups stay allocation-free. A static segment containing a `{…}` group is now a pattern, and
  unbalanced braces panic at registration.

No public API change (`api/akio-http.txt` unchanged).

### Added: TLS record_size_limit, certificate compression and OCSP stapling (akio-tls)

Additive configuration (ADR-008, docs/adr/008-tls-extensions.md):

- **record_size_limit** (RFC 8449, TLS 1.3 and 1.2): `ServerConfigBuilder::record_size_limit` /
  `ClientConfigBuilder::record_size_limit` (64 to 16385, default 16385). The client always sends
  its value, the server answers with its own when the client sent one; each side then cuts the
  protected records it writes to the peer's limit and refuses records over its own
  (`record_overflow`). Early data goes under the limit of the connection that issued the ticket.
  Not used over QUIC. Kernel TLS offload (experimental) is refused under a peer limit below
  16 KiB.
- **Certificate compression** (RFC 8879, TLS 1.3, zlib through akio-deflate; no in-house
  brotli/zstd, so only zlib is offered): `certificate_compression(bool)` on both builders, **on
  by default on the server** (chains compressed once and reused, no cost per handshake) and
  **off by default on the client** (inflating a received chain costs about 1–2 µs, ~1% of an
  in-memory handshake). Client certificates are compressed when the server's
  CertificateRequest offers it. Received messages are inflated into
  at most 128 KiB and must match the announced length.
- **OCSP stapling**: `ServerConfigBuilder::ocsp_response(der)` / `sni_ocsp_response(name, der)`
  staple a DER response for clients that ask (TLS 1.3 CertificateEntry, TLS 1.2
  CertificateStatus; not on resumption); `ClientConfigBuilder::ocsp_stapling(true)` asks, and
  the new `TlsInfo::ocsp_response` holds the response. **Not validated** (no OCSP in akio-x509
  yet); the server only checks the configured value is a successful `OCSPResponse` in shape.
- ClientHellos now carry record_size_limit (6 bytes). `akio-tls` depends on `akio-deflate`.
- Fixed: a TLS 1.3 KeyUpdate of the wrong length is `decode_error` (was `illegal_parameter`;
  tlsfuzzer's "large KeyUpdate message" probe failed at random).
- Tests: in-memory matrix with the extensions (both versions, key types, limits down to 64
  bytes both ways, compression either side off, OCSP with SNI and resumption), negative cases,
  fuzz corpora; interop (`tools/interop/tls/run.sh`) with OpenSSL (OCSP verified by s_client,
  zlib compression both ways with Debian's OpenSSL 3.5, max_fragment_length ignored), Go (OCSP
  both ways) and GnuTLS (record_size_limit and OCSP both ways); tlsfuzzer
  `test-record-size-limit.py`, `test-tls13-certificate-compression.py` and
  `test-tls13-client-certificate-compression.py`. Handshakes unchanged (same-run A/B,
  docs/BENCHMARKS.md).

### Added: pluggable metrics collectors (ADR-015)

Application and protocol metrics on the engine's `/metrics` endpoint, with no third-party crate.
New module `akio::metrics` (`akio_core::metrics`): the `Collector` trait, the `Families` snapshot
(Prometheus text 0.0.4 or JSON, or read through `iter` / `get`), instruments `Counter`, `Gauge`,
`Histogram` and a `Registry` of named instruments, `fn_collector`, `DEFAULT_BUCKETS`.
`Telemetry::register_collector(collector, labels)` / `unregister_collector`, `Telemetry::collect`
and `Telemetry::render_prometheus` (engine series, then the collectors), which
`observe::metrics_handler` now serves. Ready-made collectors: akio-http `HttpMetrics` (plus a new
family `akio_http_requests_by_version_total{version}`, field `HttpSnapshot::by_version`,
`observe::VERSION_LABELS`), akio-quic `QuicServer` (`akio_quic_*`: connections, datagrams and
bytes each way, packets sent and lost, congestion events; totals include closed connections) and
akio-tls `Tls::stats()` → `TlsStats` / `TlsCounts` (`akio_tls_handshakes_total{side, version}`,
`akio_tls_resumed_total`, `akio_tls_early_data_total{outcome}`). Additive only; the engine's own
series are unchanged. Example: `cargo run -p akio-http --example guide-metrics`.

The engine's telemetry overhead was measured on a quiet host (same-run A/B, docs/BENCHMARKS.md
"Telemetry overhead"): no measurable cost on HTTP/1.1 (0.998–1.006× with callback timing off or
the counters compiled out); echo rows within their noise. `HttpMetrics::middleware()` with the new
per-version count: 0.997–1.005× the previous middleware.

### Changed: faster ChaCha20-Poly1305 for short messages on AVX-512

On x86_64 with AVX-512, akio-crypto's ChaCha20 runs four blocks with one row of each block per
register (the head of a message and short tails), puts a partial last group through the kernel
under byte masks instead of a buffer, and picks a head of four or eight blocks by measured kernel
cost; the AEAD's Poly1305 skips its streaming buffer. Zen 4, same-run A/B: seal 64 B 408 → 481
MB/s (0.83× → 0.98× ring), 1 KiB 1.00× → 1.08×, 1400 B 0.99× → 1.21×; open 64 B 0.76× → 0.85×;
TLS 1.3 ChaCha20-Poly1305 records at 1 KiB 1.09× → 1.15× rustls + ring (docs/BENCHMARKS.md).
16 KiB and up unchanged. No public API change.

### Changed: RSA verification on AVX-512 IFMA, about 2.5–3.4× faster

On x86_64 with AVX-512 IFMA, the RSA public operation `sᵉ mod n` (signature verification, and the
check of each signature before it is released) now runs in radix 2⁵² for 2048-, 3072- and 4096-bit
moduli (new 3072- and 4096-bit almost-Montgomery multiplications), with 18 products for
`e = 65537` instead of 21; building a public key computes `R² mod n` with a faster long division
and no Montgomery multiplication. Zen 4, same-run A/B on a quiet host: RSA-2048 / 3072 / 4096
PKCS#1 verify 2.51× / 3.00× / 3.39× faster (1.22× / 1.10× / 1.09× → 3.07× / 3.30× / 3.70× ring),
verify including the key parse 2.31× / 2.76× / 3.04× (1.02× / 0.95× / 0.95× → 2.35× / 2.64× /
2.90× ring), signing 2–4%; TLS 1.3 handshakes with an RSA-2048 certificate 1.67× → 1.82× rustls +
ring (docs/BENCHMARKS.md). Without IFMA (and with `AKIO_CRYPTO_PORTABLE=1`) the fewer products and
the faster division still help: portable verify 0.59× → 0.70× ring at 2048 bits. Private-key
exponentiation and its constant-time properties are unchanged. No public API change.

### Changed: fewer allocations per HTTP/3 request

An HTTP/3 request and its response now cost 8.6 allocations at both ends of `quic-bench h3`
instead of 21.6: akio-quic hands stream data to the application without temporary vectors;
akio-h3 writes small response and request heads into akio-quic's per-thread pooled buffers
(a hidden `Bytes::pooled`, not a public API) and widens a HEADERS frame's length in place;
akio-http's `Context` owns its request until a `Detached` or a WebSocket upgrade shares it, and
`Headers` keeps its first two field positions inline (still 48 bytes). QPACK writes `:status`,
`content-length` and the date line (encoded once a second) without a static table search, and a
request head is checked as UTF-8 once. Zen 4, same-run A/B on a quiet host: HTTP/3 GET, one
connection, 64 in flight 820,741 → 883,127 req/s (1.08×); HTTP/1.1 and h2c unchanged within
noise (docs/BENCHMARKS.md). No public API change.

### Fixed: building an io_uring engine no longer exposes that thread to spurious `EINTR`

`io_uring_setup` attaches the calling thread to the new ring, and when a ring is torn down the
kernel's exit work sends every attached thread a signal-like task_work (`TIF_NOTIFY_SIGNAL`). The
backend probe and every I/O thread's ring were created on the thread that called
`EngineBuilder::build` (or `Engine::set_threads`). So when the probe's ring, or later the
engine's rings, were torn down, that thread could be interrupted. A blocking call the kernel
does not restart, such as a socket read with a timeout, then failed with `EINTR`. That happened
long after the build, in code that has nothing to do with io_uring. Rings are now created, and
the probe runs, on a short-lived thread of their own, which the kernel detaches when it exits;
each I/O thread still attaches itself when it enables its ring. This was the occasional failure
of akio-socks' `udp_blocking_and_on_the_engine` on io_uring (about 3 runs in 100 under load):
its blocking `recv_from` returned `EINTR` although every hop of the relay had delivered the
datagram. The new test `uring_engine_teardown_does_not_interrupt_the_building_thread` (akio's
`engine` tests) failed every run before. No public API change; the I/O path is unchanged.

### Fixed: a QUIC client's 0-RTT no longer goes out ahead of its Initial

`akio_quic::dial` opens the client's UDP socket on an engine thread and keeps the datagrams sent
before that in a backlog. The socket was published before the backlog was flushed, so another
thread sending in between (a request right after an `H3Client::dial` resuming with 0-RTT) put its
0-RTT packets on the wire ahead of the Initial. The server, without 0-RTT keys yet, dropped them,
and the requests went again in 1-RTT after the handshake, unmarked, although the server had
accepted 0-RTT. A datagram queued just as the backlog was flushed could also stay there, unsent.
The backlog is now flushed, and the socket published, under the backlog's lock (the same for a
migration probe's socket). This was the occasional failure of akio-h3's `zero_rtt` test (about 2
runs in 100 under load), which now holds the server's handshake flight in a relay until its
requests are sent, and waits for session tickets instead of sleeping. No public API change.

### Fixed: `akio_bittorrent::Client::close` waits for its threads

TSan's first run (below) reported a thread leak: `close` shut the engine and the disk pool down
and returned at once, so I/O-thread callbacks and `Storage` calls could still run after it, and
dropping the client detached the threads. `close` now returns once the engine's I/O threads, the
disk pool and the maintenance thread have exited. It must therefore not be called from one of the
client's own threads (inside a `Storage` method, for example).

### Fixed: the HTTP client no longer holds an engine's graceful shutdown open

`akio_http::client::Client` kept idle keep-alive connections in its pool through the engine's
graceful shutdown, so `Engine::wait` waited out the whole `Config::shutdown_timeout` (10 s by
default) whenever the client had made a request. Idle connections now close when the shutdown
starts; one with a request in flight delivers the response and then closes instead of going
back to the pool.

### Added: AddressSanitizer and ThreadSanitizer runs (`tools/sanitizers/`)

First ASan (with LeakSanitizer) and TSan run of the workspace tests, 2026-11-16: every crate in
Linux arm64 Docker on epoll and io_uring, the crates with unsafe code and the engine backends on
x86_64 (with the AVX-512/IFMA/VAES/BMI2 assembly paths). No memory error, memory leak or data
race; the thread leak above was the one report. `tools/sanitizers/run.sh` runs them per crate,
in Docker or natively, and the heavy CI job `sanitizers` now uses it for the whole workspace
instead of eight crates. Its `rustc-wrapper.sh` builds `compiler_builtins` uninstrumented, without
which every sanitized binary crashed at start-up on aarch64 with `-Zbuild-std`. Two tests were
adjusted for TSan: `akio-sys`'s `signal_to_pipe` raises the signal on the waiting thread (TSan
never ran the handler of a signal delivered to a thread in a raw futex wait), and akio-ws's
client tests scale their 10 s deadlines with `AKIO_TEST_TIMEOUT_SCALE`.

### Changed: RSA signing runs both CRT halves in one AVX-512 IFMA loop

On x86_64 with AVX-512 IFMA, the two half-exponentiations of an RSA private-key operation (mod p
and mod q) now advance together, one digit step of each per iteration of one assembly loop, so
their serial reduction chains overlap instead of each waiting on its own. Zen 4, same-run A/B on a
quiet host: RSA-2048 PKCS#1 sign 3,867 → 5,231/s (1.63× → 2.20× ring), RSA-3072 1,436 → 1,691
(2.19×), RSA-4096 753 → 870 (2.55×); TLS 1.3 handshakes with an RSA-2048 certificate 1.45× →
1.69× rustls + ring (docs/BENCHMARKS.md). Verification, other CPUs and keys whose primes differ in
size are unchanged. Still constant time (no branch on secret data, checked in the disassembly).
No public API change.

### Changed: TLS records sealed and opened without zero-filling the output first

The TLS record layer no longer zero-fills the space for a record's ciphertext or plaintext
before the AEAD writes it: akio-crypto's AES-GCM and ChaCha20-Poly1305 gained hidden
`encrypt_append` / `decrypt_append`, which write straight into a `Vec<u8>`'s spare capacity
(through a small `unsafe` module, `akio_crypto::fill`, that extends the vector only once every
byte was written; a failed open appends nothing and zeroes what it wrote). akio-tls stays
`#![forbid(unsafe_code)]`. TLS 1.3 records on Zen 4 (seal + open, same-run A/B): AES-128-GCM
+6.9–8.3%, AES-256-GCM +7.4–8.7%, ChaCha20-Poly1305 +3.3–6.4% (docs/BENCHMARKS.md). No public
API change.

### Added: `Conn::set_relayed` for application-built relays

Relays built on `hold_reads` / `on_drain` can now opt out of the engine's write-watermark read
pause with `Conn::set_relayed(true)` (and `akio_http::raw::RawConn::set_relayed` for `CONNECT` /
upgrade relays). Without it, a two-way relay to a peer that only reads once it can write could
deadlock: the same bug fixed inside akio-socks, now avoidable in application code. Takes effect
at once; `Config::max_queued_bytes` still applies. Additive public API (snapshots updated).

### Renamed: the project is now `only`

The crates.io name `flash` is taken, so the project was renamed from **flash** to **only**
(DEV-PLAN "1.0.0 release decisions"). Every crate, path, identifier and name changed with it;
the entries below already use the new names.

| Before | After |
|---|---|
| crate `flash` (`use flash::...`) | `only` (`use only::...`) |
| crates `flash-*` (`flash_*` in code), directories `crates/flash-*` | `only-*` (`only_*`), `crates/only-*`: `flash-sys` → `only-sys`, `flash-buf` → `only-buf`, `flash-timer` → `only-timer`, `flash-pool` → `only-pool`, `flash-core` → `only-core`, `flash-epoll` → `only-epoll`, `flash-uring` → `only-uring`, `flash-tls` → `only-tls`, `flash-http` → `only-http`, `flash-ws` → `only-ws`, `flash-mux` → `only-mux`, `flash-socks` → `only-socks`, `flash-arpc` → `only-arpc`, `flash-grpc` → `only-grpc`, `flash-kcp` → `only-kcp`, `flash-quic` → `only-quic`, `flash-h3` → `only-h3`, `flash-ebpf` → `only-ebpf`, `flash-prefork` → `only-prefork`, `flash-dpdk` → `only-dpdk`, `flash-turn` → `only-turn`, `flash-webrtc` → `only-webrtc`, `flash-media` → `only-media`, `flash-bittorrent` → `only-bittorrent` |
| environment variables `FLASH_*` (`FLASH_TEST_BACKEND`, `FLASH_UDP_GSO`, `FLASH_UDP_GRO`, `FLASH_PREFORK_*`, `FLASH_CHAOS*`, `FLASH_DPDK_*` ...) | `ONLY_*` |
| Prometheus series `flash_*` (`flash_connections_open`, `flash_http_requests_total`, `flash_tls_handshake_failures_total` ...) | `only_*` |
| log targets `flash`, `flash_http::access`, `flash_webrtc` ... | `only`, `only_http::access`, `only_webrtc` ... |
| thread names `flash-io-*`, `flash-pool`, `flash-quic-timer` ... | `only-io-*`, `only-pool`, `only-quic-timer` ... |
| `flash_media::srt` alias `FlashConn` | `OnlyConn` |
| API snapshots `api/flash-*.txt`, tool Docker images and volumes `flash-*` | `api/only-*.txt`, `only-*` |

The GitHub repository and the documentation site keep their `lesismal/only` URLs until the
repository itself is renamed.

### Evaluated: io_uring registered files, `SEND_ZC`, `MSG_RING` wake-ups, ring-based sends (not adopted)

- Measured on Linux 7.0 / Ryzen 7 7800X3D against the rule "same-run gain of at least 3%, no
  regression elsewhere" (docs/BENCHMARKS.md, "io_uring features evaluation"); none qualified, so
  the io_uring backend is unchanged. `SEND_ZC` was 12–27% slower with 10–36% more CPU per request
  from 16 KiB to 256 KiB (loopback always copies); `MSG_RING` wake-ups from threads without a ring
  (`IORING_REGISTER_SEND_MSG_RING`) gave +1.5–4.8% on `spawn_blocking` round trips and −1.3% to
  +0.2% elsewhere; a registered ring fd −3.6% to +0.5%; registered files have nothing to save in
  the engine (no submission per request in steady state). Ring-based sends (`IORING_OP_SEND`)
  were +1–4% with 2–6% less CPU per request on a bare ring, but need a redesign of the shared
  write path (writes come from any thread) and are left as a follow-up.
- New measurement harness: the ignored `eval_server` test in akio-uring (`src/eval.rs`, a minimal
  HTTP/1.1 responder on the raw ring: `write` / `SEND` / `SEND_ZC`, optional direct accept and
  registered files) and `tools/bench/uring-eval.sh`. The extra io_uring bindings it uses
  (`SEND`, `SEND_ZC`, direct accept, fixed-file close, sparse `REGISTER_FILES`, `MSG_RING` and
  `REGISTER_SEND_MSG_RING`) are compiled for tests only. No public API change.

### Added: TLS 1.3 early data and QUIC 0-RTT (opt-in, with replay protection)

- **`akio-tls`**: early data (RFC 8446 section 4.2.10), off by default on both sides.
  `ServerConfigBuilder::early_data(max_bytes)` issues tickets with `max_early_data_size` and
  accepts early data for the ticket's first PSK, cipher suite, ALPN protocol and SNI name (never
  after a HelloRetryRequest; more than allowed is `unexpected_message`); it is read before the
  handshake completes and EndOfEarlyData ends it. `ClientConfigBuilder::early_data(true)` sends
  what the application writes before the handshake as early data, up to the ticket's limit, and
  sends it again after the handshake if the server rejects it (also after a HelloRetryRequest).
  New `EarlyData` (`NotAttempted`, `Pending`, `Accepted`, `Rejected`) and
  `TlsInfo::early_data` / `early_data_len`.
- **Replay protection** (always on with early data): a 10-second freshness window on the
  ticket age (RFC 8446 section 8.3) and a per-`ServerConfig` record of the PSK binders of
  accepted ClientHellos, kept for 20 seconds and bounded at 100,000 (section 8.2): a replayed
  ClientHello's early data is rejected, a full record rejects early data until entries expire.
  Not across processes or machines sharing tickets (documented).
- **`akio-quic`**: 0-RTT (RFC 9001 section 4.6), `ServerConfig::zero_rtt` /
  `ClientConfig::zero_rtt` (default off). Resuming clients start from the remembered transport
  parameters (RFC 9000 section 7.4.1), open streams right after `dial` and send them in 0-RTT
  packets (v1 and v2), coalesced behind the Initial. Servers accept 0-RTT only under the limits
  the ticket was issued with, answer in 0.5-RTT, and the client resends rejected or lost 0-RTT
  data (in 0-RTT after a Retry, else in 1-RTT). New `Connection::early_data` and
  `Connection::is_early(stream)`.
- **HTTP**: akio-h3 marks requests that arrived in 0-RTT with `Early-Data: 1` (RFC 8470), and
  `H3Client` sends its requests in 0-RTT when its QUIC config enables it; akio-http over TLS
  marks HTTP/1.1 requests that arrived as early data (and every HTTP/2 request of a connection
  that began with early data). Handlers answer `425 Too Early` to what is not safe to repeat.
- Tests: TLS state machine (accept, reject, HelloRetryRequest, replay, stale ticket age,
  ALPN/SNI binding, `max_early_data` limits), QUIC on the simulated network (accept, reject,
  lost 0-RTT packets, Retry, a replayed first flight, v2), loopback QUIC, HTTP/3 and HTTP/1.1
  over TLS. Interop: 0-RTT with quic-go both ways in v1 and v2 (`tools/interop/quic/run.sh`),
  early data with OpenSSL `s_client` / `s_server -early_data` both ways, accepted and rejected
  (`tools/interop/tls/run.sh`). Fuzz seeds for 0-RTT packets and early-data handshakes.
- Also: packets processed after waiting for their keys, and 0-RTT / 0.5-RTT packets, no longer
  give RTT samples; 0-RTT in flight does not hold back the handshake probe timer.
- Security: early data and 0-RTT are not forward secret and can be replayed beyond what one
  server's record sees; the READMEs and the guide say when (not) to enable them.

### Added: ECN, BBR, client migration, preferred_address and QUIC v2 in `akio-quic`

- **ECN** (RFC 9000 section 13.4, RFC 9002 section 7.1), `TransportConfig::ecn` (on by
  default): on Linux packets go out ECT(0) and received codepoints are reported in ACK_ECN
  frames; the path is validated with a ten-packet testing period and the peer's counts, CE marks
  are congestion events, and a path that bleaches, re-marks or drops marked packets falls back to
  unmarked ones. New `ConnectionStats::ecn_capable` / `ecn_ce_events`. The UDP layer carries the
  codepoint per datagram: `IP_RECVTOS` / `IPV6_RECVTCLASS` on receive, an `IP_TOS` /
  `IPV6_TCLASS` control message per `sendmmsg` message (`akio_sys::enable_ecn`,
  `ecn_available`, `RecvBatch::ecn`, `Batch::push_ecn`; `AKIO_UDP_ECN=0` turns it off).
- **BBR**: `Congestion::Bbr` no longer runs CUBIC. It is BBRv1's model and state machine on
  delivery-rate samples, with BBRv2/v3's bound on rounds that lose or CE-mark more than 2%.
  Through netem in network namespaces on the bench host (100 Mbit/s, 40 ms RTT, a 40 MB echo
  each way): 73 against CUBIC's 5 Mbit/s with 1% loss, 75 against 36 Mbit/s with a 60-packet
  buffer, both 84 Mbit/s on a clean deep buffer. Experimental.
- **Client migration**: `Connection::migrate(&engine)` moves a client connection to a new
  local UDP socket, or to the server's preferred address, after probing the new path under a
  connection ID not used before; it stays on the old path when the probe goes unanswered.
  `Connection::preferred_address()`, `Error::Migration`.
- **preferred_address**: `ServerConfig::preferred_address(addr)` offers it (connection ID
  sequence number 1 and its reset token); `QuicServer` is now `Clone`, so the same server serves
  that address on a second listener.
- **QUIC version 2** (RFC 9369): `Version`, `ClientConfig::version`, `ServerConfig::versions`,
  `Connection::version()`. Servers accept 1 and 2; a client answered with Version Negotiation
  starts over once in a common version, guarded by RFC 9368's version_information parameter.
  Compatible version negotiation (switching inside a handshake) is not implemented.
- Interop (`tools/interop/quic/run.sh`): quic-go both ways in version 2 (below quic-go's first
  key update: quic-go v0.62 derives version 2 key update secrets with the version 1 label,
  against RFC 9369 section 3.3.2), client migration both ways, our side with BBR, and on Linux
  ECN validated against quic-go.
- Answers to path probes from another address now use a connection ID of their own (RFC 9000
  section 9.5); quic-go's migrating clients need that.
- Not done: 0-RTT.

Cost on the loopback benchmarks (`quic-bench`, bench host, CPUs 2–5, median of five alternating
rounds against the merge base): bulk 18,704 → 18,288 Mbit/s (−2.2%; −1.5% with
`AKIO_UDP_ECN=0`), HTTP/3 839,148 → 824,949 req/s (−1.7%; −1.0%), full handshakes 9,725 →
9,615/s (−1.1%; −0.8%). ECN's share is the per-datagram control messages and ACK_ECN counts.

### Evaluated: kernel TLS offload (not adopted, experimental feature)

- Handing akio-tls's record keys to the Linux kernel after the handshake (kTLS) was measured on
  Linux 7.0 / Ryzen 7 7800X3D with HTTP/1.1 over TLS (`tools/bench/ktls.sh`): the kernel's
  software TLS reached 0.83x of akio-tls's own record layer at 1 KiB responses, 0.65x at 16 KiB,
  0.40x at 256 KiB, and 0.48x when it sent a 10 MB file with `sendfile` against akio-tls's
  `pread` plus sealing, with 1.3x to 2.5x the server CPU per byte (docs/BENCHMARKS.md, "Kernel TLS
  (kTLS) evaluation"). It is not wired into `Tls` or the engine.
- The offload stays for re-measuring behind a new **experimental** `akio-tls` feature,
  `experimental-ktls` (off by default, outside the semver promise, no public API): the blocking
  test stream (`akio_tls::stream`, hidden) can offload after the handshake (TLS 1.3 and 1.2,
  AES-128/256-GCM and ChaCha20-Poly1305, alerts, close_notify, NewSessionTicket and KeyUpdate in
  both directions on Linux 6.14+, fallback to user space), with the `ktls-bench` example,
  `tls-interop --ktls` / `AKIO_INTEROP_KTLS=require tools/interop/tls/run.sh` (107/107 against
  OpenSSL and Go) and `crates/akio-tls/tests/ktls.rs` (skipped without the `tls` kernel module).
  `akio-sys` gained the hidden `ktls` module (`TCP_ULP`, `SOL_TLS`, record-type cmsgs) with the
  `linux/tls.h` structures checked against `libc` in the layout tests.
- Docs: the stale "rustls underneath" wording in the README, the book's crate list and the fib
  migration guide, and the ROADMAP's TLS row, now say what is true (own TLS 1.3 / 1.2).

### Performance: AES-GCM on VAES-AVX2 and masked tails in the AVX-512 kernel (`akio-crypto`)

No public API change (a new `#[doc(hidden)]` `AesGcm::with_cipher_avx2` and `AesGcm::kernel`
for tests and benchmarks).

- x86_64 with VAES, VPCLMULQDQ and AVX-512: the whole message runs in one call of the 512-bit
  kernel. An AAD of up to 256 bytes is hashed in the kernel, the last partial group (1 to 255
  bytes) is loaded and stored under AVX-512 byte masks instead of going through the 128-bit path,
  and the length block and `E(J0)` give the tag in the same call; messages under 256 bytes hash
  their AAD, data and length block under one reduction. AES-128-GCM seal 1 KiB 7,902 → 10,433
  MB/s (1.00× → 1.32× ring), 1400 B 8,356 → 10,632 (1.10× → 1.46×), 64 B 1,204 → 1,383
  (1.11× → 1.29×); open 1 KiB 1.04× → 1.22×; 16–64 KiB unchanged (1.16–1.18×).
- x86_64 with VAES and VPCLMULQDQ but no AVX-512 (Zen 3, Alder Lake / Raptor Lake): a new
  VAES-AVX2 kernel, sixteen blocks per iteration in eight 256-bit registers with one GHASH
  reduction per group, for whole 256-byte groups (the rest on the 128-bit path). Measured on
  Zen 4 with the AVX-512 kernel switched off (no Zen 3 available): 1.55–2.35× the 128-bit kernel
  those CPUs used before (AES-128 seal 16 KiB 6,310 → 12,671 MB/s).
- TLS 1.3 records in `akio-tls` follow: AES-128-GCM 1 KiB 1.51× → 1.58× rustls + ring, 16 KiB
  1.56× → 1.60×. The record layer still zero-fills its output before the AEAD writes it: copying
  the plaintext in and sealing in place measured 6% slower at 16 KiB, a reused buffer would trade
  the memset for a copy, and skipping the fill (+10% at 16 KiB) needs `unsafe` in a
  `#![forbid(unsafe_code)]` crate, so it was not done (docs/BENCHMARKS.md).
- Tests: every kernel (AVX-512, AVX2, 128-bit, portable) against the others at every length
  0..=600, large sizes, every AAD length 0..=300 and past 512, misaligned, in place and out of
  place, and on the CAVP and Wycheproof vectors; the `crypto_aead` fuzz target compares the AVX2
  kernel too. Run natively on Zen 4, also with `AKIO_CRYPTO_PORTABLE=1`.
- `unsafe`: +5 blocks and +1 `unsafe fn` in `gcm::hw` / `gcm::hw::vaes` (the AVX2 kernel's two
  `asm!` blocks, the whole-message calls), documented in docs/unsafe-review.md. Miri never
  reaches the `asm!`.

### Fixed: io_uring kept calling `on_data` after reads paused

- `akio-uring`: once a connection's output queue reached `Config::write_high_watermark`, or the
  handler called `hold_reads(true)`, the backend cancelled its multishot recv, but completions
  that arrived before the cancel took effect (on a fast machine with a flooding peer, a dozen or
  more 16 KiB reads) were still handed to `on_data`. An echo-style handler then queued past the
  watermark up to `max_queued_bytes` and got `Error::Overloaded`, and held reads were not held.
  It made `chaos_engine` fail every run on io_uring on a 16-thread Linux 7.0 machine
  ("echo send failed: overloaded"). That input now waits in the connection, in order (an EOF
  behind it too), and is delivered when reads resume, as epoll and kqueue stop reading instead.
  No API change.

### Fixed: SOCKS and HTTP CONNECT tunnels could hang under backpressure

- `akio-socks`: a tunnel (SOCKS5/4/4a or HTTP `CONNECT`) could stop for good while relaying a
  large transfer. The engine's write backpressure (`Config::write_high_watermark`) paused reading
  the upstream connection whenever client data was queued for it, but those reads feed the
  client, not that queue. An upstream that does not read while its own writes are blocked (an
  echo server, most request/response servers) then waited on the proxy while the proxy waited on
  it. It showed up as a rare 10-second hang of `socks5_ipv4_domain_and_backpressure` on a loaded
  machine (kqueue, epoll and io_uring alike); an upstream that sends before it reads hung every
  time. Both ends of a tunnel are now paced only by the relay's own pause/resume. Backends honour
  a new hidden `ConnInner::set_relayed` (epoll, kqueue, io_uring, DPDK). No public API change.

### Performance: HTTP/3 request handling in `akio-h3`, keyed fast hashing in `akio-quic`

HTTP/3 GET with 64 requests in flight on one connection went from 429,038 to 838,721 req/s
(1.95×, median of seven alternating rounds; AMD Ryzen 7 7800X3D, loopback, CPUs 2–5); QUIC bulk
+5%, handshakes flat. In the profile the allocator fell from 31.8% to 11.2% of the samples and
SipHash from 7.3% to 0.1%. No API change; interop with quic-go and fib passes both ways.

- akio-h3: request and response frames are read in place from the received stream data (only a
  trailing partial frame is buffered); a field section is decoded into one reused flat buffer,
  checked as UTF-8 in one pass and copied once into the request's or response's `Headers`, where
  it used to cost two `Vec`s per field, a `String` per name and value and a second header list.
- akio-h3: HEADERS frames are QPACK-encoded straight into the outgoing buffer, with `:status`,
  `date` (formatted once a second per thread) and `content-length` written there instead of being
  added to the response's headers; static-table references are found by name length instead of
  two SipHash maps; a response's HEADERS, a body up to 16 KiB and its trailers go to QUIC in one
  write (larger bodies follow without a copy).
- akio-h3: a request that arrives whole is read without entering the stream table; the stream
  tables are hashed with a multiply-fold (they are bounded by the stream limits we grant).
- akio-quic: the endpoint's connection-ID tables and the tables of connections and client
  sockets (by peer address) use a hasher keyed with fresh random words per table (folded
  64×64→128-bit multiplies) instead of SipHash; a client chooses the connection ID of its first
  Initial, so the key keeps colliding IDs from being computed in advance. Connection IDs hash
  only their used bytes. On its own this is +3% bulk (a lookup per datagram); HTTP/3 with many
  requests per datagram does not notice it.
- akio-quic: in-order stream acknowledgments move the send buffer's front directly instead of
  through the acknowledged-range tree (a node allocated and freed per acknowledgment), and the
  first chunk of a stream's send buffer is held inline, so a stream written once costs no queue
  allocation.
- akio-http: `Response::text` and `Response::with_body` size the header storage once instead of
  growing it field by field.

### Performance: ChaCha20-Poly1305 on AVX-512 and IFMA in `akio-crypto`, out-of-place TLS records

On x86_64 ChaCha20-Poly1305 seals 16 KiB at 4,597 MB/s (1,752 before, 1.30× ring), 1400 B at
2,541 (1,070, 0.96× ring) and 64 B at 412 (283, 0.83×); TLS 1.3 records with
TLS_CHACHA20_POLY1305_SHA256 went from 0.55× to 1.42× rustls + ring at 16 KiB and from 0.64× to
1.02× at 1 KiB (AMD Ryzen 7 7800X3D; docs/BENCHMARKS.md). No API change.

- ChaCha20 sixteen blocks per iteration in zmm registers with `vprold` rotations, the rest of a
  message in one group of sixteen, eight (ymm) or four (xmm) blocks, as `asm!` kernels
  (`chacha::hw::avx512`; the AVX-512 intrinsics are not stable at the MSRV). AVX2 stays the
  path for CPUs without AVX-512.
- Poly1305 eight blocks per step on AVX-512 IFMA (`chacha::hw::ifma`, `vpmadd52luq` /
  `vpmadd52huq` on 44-bit limbs) for runs of 256 bytes and more, detected through
  `Feature::Ifma`; elsewhere, and everywhere on other CPUs and on aarch64, a radix-2⁶⁴ scalar
  loop replaces the 44-bit two-block one (1.3× at 16 KiB on the AVX2 path).
- `ChaCha20Poly1305::encrypt_detached_from` / `decrypt_detached_from` (`#[doc(hidden)]`, like the
  AES-GCM ones): akio-tls seals and opens ChaCha20-Poly1305 records out of place instead of
  copying first. `new_avx2` / `new_portable` (`#[doc(hidden)]`) pin a key to a narrower path
  for tests, the `crypto_aead` fuzz target and `examples/chacha-sizes.rs` (sizes against ring).
- Correctness: every length 0..=600 and large sizes through the AVX-512 / IFMA, AVX2 and
  portable paths, misaligned, in place and out of place, forged tags, counters near the wrap,
  Poly1305 on all-ones blocks and extreme `r` / `s`, run natively on Zen 4 with and without
  `AKIO_CRYPTO_PORTABLE=1`. `unsafe`: +6 blocks, +2 `unsafe fn` (docs/unsafe-review.md).

### Added: aarch64 assembly for P-256 and X25519 in `akio-crypto` (not benchmarked yet)

On aarch64 the P-256 field and group-order arithmetic and the X25519 ladder's field now run in
inline assembly (`ec::hw_aarch64`, `curve25519::hw_aarch64`), the counterparts of the x86_64
BMI2 + ADX code; no API change.

- P-256: Montgomery multiplication and squaring modulo `p` and `n`, addition, subtraction,
  `2ᵏ·a` and `3·a` on four 64-bit limbs with `MUL`/`UMULH` products, `ADDS`/`ADCS`/`SUBS`/`SBCS`
  carry chains and `CSEL` corrections; the reduction modulo `p` needs shifts and subtractions
  only (as OpenSSL's `ecp_nistz256-armv8`), modulo `n` two of the four limb products are shifts.
  `P256` dispatches to a twin curve on this field, as on x86_64; inversions are safegcd (portable
  divsteps) with the final multiplication in assembly, and the twin keeps the portable defaults of
  the `Curve::jac_*` hooks (point formulas, table scans, 4-bit comb) over the assembly field.
- X25519: the ladder's field on four 64-bit limbs (16 `MUL` + 16 `UMULH` per product instead of
  the 25 128-bit products of radix 2⁵¹), folds by `2²⁵⁶ ≡ 38` with `CSEL`, masked swaps.
- Every ARMv8.0 CPU has these instructions: `hardware_features()` reports `umulh` on aarch64;
  `AKIO_CRYPTO_PORTABLE=1` / `set_portable(true)` switch back to the portable code, and Miri
  never runs the assembly.
- Correctness: differential tests against the portable field code on random and edge values and
  on chains of 20,000–50,000 dependent operations, the twin curve against the portable curve
  (key generation, ECDH, signing, verification), the RFC 7748 vectors (including the
  1,000,000-iteration one, `--ignored`), Wycheproof, all on macOS (Apple silicon) and arm64
  Linux. The release code of the secret paths was disassembled: no conditional branch in the
  assembly, and around it only loop counters, public bounds, CPU-feature checks and the final
  identity test.
- **Not benchmarked yet**: the design follows the instruction counts; no aarch64 speed-up is
  claimed until it is measured.

### Performance: HTTP/2 and pipelined HTTP/1 hot paths in `akio-http`

Re-profiled after the in-house replacements (DEV-PLAN "Performance pass"); no API change.

- HTTP/2: frames are parsed in place from the read buffer (no copy per frame, the leftover moved
  once per read); decoded header fields go into one reused buffer instead of two `Vec`s per
  field; header blocks are HPACK-encoded straight into the output, with `:status`, `date` and
  `content-length` written there; a body that fits one DATA frame and the flow-control windows
  skips the stream queue; the stream table uses a multiply-fold hasher instead of SipHash.
- HTTP/2: everything one read produces, including the responses the service sends on the I/O
  thread, is handed to the connection in a single write at the end of the read (one TLS record
  for the batch instead of one per response); responses sent from other threads join the batch
  while a read is being handled and go out immediately otherwise.
- HTTP/2 flow control: the connection and stream receive windows are given back once a quarter
  of them is owed, instead of two WINDOW_UPDATE frames per DATA frame.
- HTTP/1: request heads are parsed with room for 32 fields first (100 only when needed), and the
  fields framing needs (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Expect`)
  are found in one pass.
- Ryzen 7 7800X3D, 4 server threads (epoll): h2c 64 connections x 16 streams 2.28M → 4.05M
  req/s (1.78x, now 1.25x fib), h2c 16 x 128 2.37M → 4.71M, HTTP/2 over TLS 1.58M → 4.03M (2.5x,
  1.33x fib), pipelined HTTP/1.1 x16 3.99M → 4.26M (+7%, 1.14x fib). h2spec: 147/147. Tables
  in docs/BENCHMARKS.md; the harness (`tools/bench`, now with a README) drives HTTP/1.1 with
  `h2load --h1` when wrk is missing and gained h2-over-TLS and many-streams cases.

### Performance: CPU acceleration in `akio-crypto`

`akio-crypto` now uses CPU instructions where the CPU has them, detected at run time, each with
the constant-time portable code as fallback (DEV-PLAN "Performance pass"); no API change.

- x86_64: SHA-NI for SHA-1 / SHA-256, AES-NI CTR eight blocks at a time, AES-GCM with PCLMULQDQ
  GHASH (eight blocks per reduction) fused into the CTR pass, PCLMULQDQ folding for CRC-32 and
  CRC-32C plus the SSE4.2 `crc32` instruction, AVX2 ChaCha20 (eight blocks).
- aarch64: ARMv8 SHA1/SHA2, ARMv8 AES CTR, PMULL GHASH fused with CTR, ARMv8 CRC32 instructions;
  ChaCha20 in a 4-block lane layout the compiler vectorizes (also the portable path elsewhere).
- Safe Rust: Poly1305 in 44-bit limbs (two blocks per step); P-256 with a dedicated Montgomery
  reduction, an addition-chain inversion, a signed comb of affine points for `[k]G` and Jacobian
  wNAF verification without inversion; Ed25519 verification by interleaved wNAF; squaring
  routines for Curve25519, the NIST fields and RSA; fixed-size RSA Montgomery multiplication;
  windowed exponentiation for the remaining inversions.
- `unsafe` stays confined to the instruction modules (`aes::hw`, `gcm::hw`, `hash::hw`,
  `crc::hw`, `chacha::hw`), every call behind detection (docs/unsafe-review.md).
  `AKIO_CRYPTO_PORTABLE=1` forces the portable code (tests, benchmarks); Miri runs it.
- Ryzen 7 7800X3D, one core: SHA-1 3.6x and SHA-256 6.5x (equal to the RustCrypto crates),
  AES-128-GCM 364 → 6 484 MB/s, CRC-32 2.7 → 20 GB/s, ChaCha20-Poly1305 3x, P-256 verify 1.67x /
  sign 1.46x, Ed25519 verify 1.49x, RSA-2048 sign 1.38x; TLS 1.3 handshakes 1.5x and 16 KiB
  AES-GCM records 15x (0.60x and 0.64x rustls + ring). Tables in docs/BENCHMARKS.md.

### Performance: faster TLS 1.3 handshakes (P-256 and X25519 in `akio-crypto`)

The handshake profile was >98% curve arithmetic; no API change (`tools/api/public-api.sh`
unchanged). Measured in memory on one core of the bench host, against rustls 0.23 + ring:
full handshakes 3,055 → 5,027/s with X25519 (0.61× → 1.00× rustls) and 2,306 → 4,552/s with
secp256r1 (0.45× → 0.89×).

- P-256 on x86_64 with BMI2 + ADX (run-time detection, new `cpu` feature `adx`): Montgomery
  multiplication and squaring modulo `p` and modulo the group order, addition, subtraction and
  small multiples in inline assembly (`mulx`, `adcx`/`adox`, `cmov`; new hardware module
  `ec::hw`). The operations run on a twin curve type that shares the Montgomery form and the
  base point tables, so the dispatch happens once per operation.
- Constant-time scalar multiplication in Jacobian coordinates with the `a = -3` formulas:
  Booth-recoded signed 5-bit windows for the variable base (ECDH) and the signed comb with mixed
  additions for the fixed base (key generation, signing). The identity cases are masked selects;
  equal operands cannot occur for scalars in `[1, n)` (proof in the code, `n mod 32 ≥ 17` checked
  by a test). Doublings are 4M + 4S with fused `2ᵏ·a`/`3·a`.
- The P-256 scalar inversion uses a dedicated chain (255 squarings, 40 multiplications); ECDSA
  verification inverts `s` (public) with a binary extended Euclidean algorithm and builds its
  table from projective keys without an inversion. Public keys from `SecretKey::public_key` stay
  projective until encoded (one constant-time inversion then).
- X25519: public keys are `[k]B` on edwards25519 mapped to `u = (1 + y)/(1 - y)` (the Ed25519
  base table, now affine Niels entries with signed digits: 7M per digit), and on x86_64 with
  BMI2 + ADX the ladder runs on four 64-bit limbs in inline assembly (`curve25519::hw`); the
  radix-2⁵¹ ladder stays the portable path.
- Micro-benchmarks against ring (`--example pk_bench`, op/s, before → after): P-256 sign
  34,152 → 59,837 (0.45× → 0.79×), verify 13,404 → 25,138 (0.51× → 0.96×), ECDH 10,380 → 27,288
  (0.35× → 0.91×), key generation 54,581 → 108,263 (0.49× → 0.96×); X25519 30,696 → 36,488
  (0.84× → 1.00×); Ed25519 sign 1.15× → 1.53× ring; P-384 sign, verify, ECDH and key generation
  1.13–1.47× faster than before. RSA is unchanged.
- Constant-time evidence: the disassembly of the secret-scalar paths (x86_64 with the assembly,
  aarch64 portable) has conditional branches only on loop counters, public indices, the public
  exponent bits of the inversion chains, CPU-feature checks and the "result is the identity"
  test (`ct.rs`). Every assembly routine is compared with the portable code on random and edge
  values, and all known-answer tests run with and without `AKIO_CRYPTO_PORTABLE=1`.
- `unsafe`: +13 `asm!` blocks in `akio-crypto` (8 in `ec::hw`, 5 in `curve25519::hw`; see
  docs/unsafe-review.md).

### Performance: wide AES-GCM and CRC in `akio-crypto`, out-of-place TLS records

No public API change (new `#[doc(hidden)]` helpers only).

- x86_64 with VAES, VPCLMULQDQ and AVX-512 (Zen 4, Ice Lake and later; detected with CPUID and
  XCR0): AES-GCM seal and open run as one 512-bit pass, sixteen blocks per loop iteration with
  the AES rounds interleaved with the GHASH of the previous group and one reduction per sixteen
  blocks (the BoringSSL / Linux `aes-gcm-avx10` design, written as `asm!` because those
  intrinsics are newer than the MSRV). The 512-bit kernel was faster than the same kernel on
  256-bit registers at every size on Zen 4, so only it ships; other CPUs keep the AES-NI +
  PCLMULQDQ kernel. CRC-32 / CRC-32C fold 256 bytes per step on 512-bit registers from 512 bytes.
- Every CPU with AES and carry-less multiplication: the last bytes of a message and `J0` go
  through AES in one call, and a short AAD, the tail ciphertext and the length block through one
  GHASH call (64-byte messages 1.8–2.1x).
- `akio-tls` seals and opens records out of place: the AEAD reads the caller's plaintext or the
  received record and writes its output once, instead of copying first and working in place
  (the copy was 30% of a 16 KiB record).
- Ryzen 7 7800X3D, one core: AES-128-GCM seal 16 KiB 6,455 → 15,048 MB/s (0.51x → 1.19x ring),
  1400 B 4,249 → 8,163, 64 B 611 → 1,185; TLS 1.3 records seal + open 16 KiB 2,739 → 6,603 MB/s
  (0.69x → 1.65x rustls + ring); CRC-32 16 KiB 20.0 → 74.9 GB/s (0.27x → 1.02x crc32fast). Tables
  in docs/BENCHMARKS.md.
- `unsafe`: the new `gcm::hw::vaes` kernel, the `asm!` CRC fold and CPUID / XGETBV (`cpu::hw`),
  each documented in docs/unsafe-review.md. Miri never reaches the `asm!` (nothing is detected).

### Performance: P-256 whole-point assembly, wide comb and safegcd in `akio-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on one core of the bench host
against ring 0.17 / rustls 0.23 in the same run (median of five alternating rounds; the host was
loaded by another benchmark, so absolute rates are 20–30% low, see docs/BENCHMARKS.md): P-256
sign 0.77× → 1.25× ring, key generation 0.94× → 1.33×, verify 0.98× → 1.04×, ECDH 0.94× → 0.96×;
TLS 1.3 secp256r1 handshakes 0.94× → 1.12× rustls.

- x86_64 with BMI2 + ADX: the Jacobian doubling (`a = -3`), addition and mixed addition of the
  P-256 twin are each one `asm!` block over a small stack frame, the products and reductions
  fused with the modular additions, subtractions and doublings around them (the accumulator stays
  in registers; the low half of each product is reduced on its own and the high half added
  after). Consecutive doublings (five per ECDH window, runs between additions in verification)
  share one frame. A doubling costs ~355 cycles instead of ~480. The curve trait gained hooks
  for these routines and the table scans, so an aarch64 twin can plug in the same way.
- Fixed base (key generation, signing) on the twin with AVX2: Booth-recoded signed 6-bit digits
  over a 43-row comb of 32 affine points each (88 KiB, built on first use), 43 mixed additions
  instead of 65; every row is scanned with 256-bit loads and `vpcmpeqq` masks. 6- and 7-bit combs
  measured equal, 5 and 8 bits slower. The ECDH window table is scanned the same way. Without
  AVX2 the 4-bit comb stays.
- Inversion modulo the P-256 prime and order by safegcd (Bernstein–Yang divsteps in
  libsecp256k1's form, new module `safegcd`), constant time, with the divsteps in assembly on
  x86_64 and masked Rust elsewhere: the scalar inversion of signing 20.9k → 7.0k cycles, the
  field inversion ~12.7k → ~7–9k. It replaces the Fermat chains on every path, portable included.
- Correctness: the whole-point routines are compared limb for limb with the portable formulas
  on random points with random `Z`, every valid Wycheproof ECDH point, `P + P`, `P + (-P)` and
  the identity; safegcd against Fermat on random and edge inputs for both moduli; the wide comb
  against the complete-formula reference on random and edge scalars (every top digit); the
  equal-operand argument for the wide comb is in `ec/hw.rs`.
- Constant-time evidence (Zen 4 release disassembly): no conditional branch in the point
  routines, the AVX2 scans and `Fe::invert`; one (the loop counter) in each `divsteps_59`; in
  `ecdh_x_impl`, `sign_impl` and `hw::mul_base` only CPU-feature and `OnceLock` checks, loop
  counters, public digit positions and bounds, the output length and the final identity test.
- `unsafe`: +6 blocks and +2 `unsafe fn` in `ec::hw` (the point blocks share one, the divsteps
  block, two AVX2 scans and their two calls; docs/unsafe-review.md).

### Performance: cheaper P-256 point formulas on x86_64 in `akio-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4, CPU 2,
median of five alternating rounds, ring 0.17 in the same run): P-256 ECDH 1.08× → 1.12× ring
(32,351 → 33,904 op/s), sign 1.36× → 1.38×, verify 1.08× → 1.10×, key generation 1.36× →
1.40×. The 0.96× of the previous entry was measured on a loaded host; quiet, the code before this
change already did 1.08×. TLS 1.3 handshakes did not move (secp256r1 1.07×, X25519 1.08× rustls):
one ECDH is about 1% of a handshake.

- The whole-point assembly of the P-256 twin uses the formulas of OpenSSL's `ecp_nistz256`: the
  addition is 12M + 4S with seven modular additions and subtractions instead of add-2007-bl's
  11M + 5S with thirteen (the products cost the same as the squares here, the linear operations
  do not), the mixed addition 8M + 3S instead of 7M + 4S (seven against fourteen), and the
  doubling computes `2Y` first, so `Z₃ = 2Y·Z`, `4β = X·(2Y)²` and `8γ² = ((2Y)²)²/2` (a new
  modular halving) need ten linear operations instead of fourteen. The additions return another
  representative of the same point (`(X, Y, Z)` instead of `(4X, 8Y, 2Z)`); the doubling the same
  limbs.
- The Montgomery reduction inside the point routines keeps `p₃` in `rdx` for its four steps and
  splits `m·2⁹⁶` with `shlx`/`shrx` (the compiler-reserved `rbx` holds the count 32, saved and
  restored in the frame): ten instructions per step become seven.
- Cycles (`perf stat`, Zen 4): addition 745 → 721, mixed addition 537 → 508, doubling 355 → 348,
  variable-base multiplication 148.1k → 140.6k, fixed-base (comb) 29.8k → 28.9k. The doubling
  measures as a fixed ~44 cycles per product: reordering it (independent products first, or the
  `Y` chain first) made it 8–10% slower, an OpenSSL-style reduction interleaved with the product
  rows was neutral, and replacing the `cmov` selections by `xor`/`and` masks was 10% slower, so
  none of them is in.
- Correctness: `points_match_portable` compares the doublings limb for limb and the additions as
  points (cross-multiplied, `Z = 0` exactly where the portable formulas give it), now also with
  the all-zero identity on either side; the halving is checked on random and edge values.
- Constant time: the release disassembly on Zen 4 has the same conditional branches as before in
  `ecdh_x_impl` (17: loop counters, public digit positions and bounds, CPU-feature checks, the
  output length and the final identity test), `hw::mul_base`, `divsteps_59` and `safegcd::inv_with`,
  and none in the point routines.
- `unsafe`: no new block; the point block saves and restores `rbx` (docs/unsafe-review.md).

### Performance: RSA on BMI2 + ADX and AVX-512 IFMA in `akio-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4,
CPU 2, three alternating rounds of the old and new binaries, ring 0.17 in the same run, op/s):
RSA-2048 PKCS#1 v1.5 sign 1,192 → 3,910 (0.49× → 1.61× ring), RSA-3072 371 → 1,455 (0.47× →
1.85×), RSA-4096 156 → 755 (0.45× → 2.19×); verify 39,250 → 79,970 (0.60× → 1.22×), 18,300 →
33,440 (1.10×), 10,110 → 19,090 (1.09×); verify including the public-key parse (one
certificate signature; ring parses on every call) 5,850 → 67,090 (0.09× → 1.02×), 0.95× and
0.95× at 3072 and 4096 bits. akio-tls full handshakes with an RSA-2048 certificate (new
`tls-bench` row): 775 → 2,586/s, 0.43× → 1.44× rustls + ring.

- On x86_64 with AVX-512 IFMA (new `cpu` feature `ifma`: CPUID leaf 7 with the AVX-512 state)
  the CRT exponentiations of 2048-, 3072- and 4096-bit keys run in radix 2⁵² (`bignum::ifma`):
  almost Montgomery multiplication over 20, 32 or 40 digits, one `asm!` block per product with
  the operands in registers (`ymm` for 20 and 32 digits, `zmm` for 40), two accumulators at 20
  digits so each register takes two dependent multiply-adds per step, the low digit and the next
  `yᵢ` computed in general-purpose registers so that chain bypasses the vector unit, the carries
  normalized with a generate / propagate mask word. Results stay below `2p` through the whole
  exponentiation; one masked subtraction at the end. A 1024-bit multiplication takes 416 cycles.
- Without IFMA, with BMI2 + ADX: Montgomery multiplication and squaring for 16 to 64 limbs in
  `asm!` (`bignum::hw`; operand scanning with `mulx` and the two carry chains, rows unrolled with
  the assembler's `.rept`, the next reduction factor taken from a register, a dedicated squaring
  up to 32 limbs, the final subtraction by `cmovnz`): a 1024-bit multiplication 1,240 → 805
  cycles, squaring 1,490 → 681; RSA-2048 signing on this path alone measured 0.99× ring,
  verification 1.20×.
- Exponentiation: fixed 5-bit windows (were 4) over a flat table built with squarings for the
  even entries, every lookup one pass over all 32 entries with AVX2 `vpcmpeqq` masks (the
  constant-time `ct` masks without AVX2).
- `R² mod m`: `64 + k` doublings and six Montgomery squarings instead of `128k` doublings for the
  secret primes (constant time), one long division for public moduli; key parsing is no longer
  the cost of a certificate check. The private operation keeps the blinding (now squared with
  the dedicated squaring), drops four 2048-bit conversions and reduces the blinded input into
  each prime field with three multiplications.
- Karatsuba was not tried: at these sizes the assembly row loops leave little to save.
- Correctness: `asm_matches_generic` (the BMI2 + ADX code at every size against the generic CIOS
  on random values and 0, 1, m - 1, m - 2, R - 1, R - m, full and short top limbs, a 200-step
  chain), `ifma_pow_matches` (the IFMA exponentiation against square-and-multiply, edge bases and
  exponents), `r2_constructions`; `rsa_vs_ring` now signs with 2048-, 3072- (new) and 4096-bit
  (new) keys and requires byte-identical PKCS#1 v1.5 signatures, also with the portable code
  forced; the Wycheproof RSA vectors are unchanged and pass on both paths.
- Constant time: the release disassembly on Zen 4 lists only loop counters, the public limb- and
  digit-count dispatch, CPU-feature, slice and allocation checks, public window offsets, the
  blinding cache and the final fault check in `Mont::mul_into` / `sqr_into`, `ifma::amm`,
  `ifma::pow`, `Mont::pow`, the table scans, `Mont::new`, `crt_combine` and `private_op`
  (counts in `src/ct.rs`).
- `unsafe`: +7 blocks and +1 `unsafe fn` in `akio-crypto` (`bignum::hw`: the two Montgomery
  blocks and the AVX2 scan; `bignum::ifma`: the IFMA blocks); see docs/unsafe-review.md.

### Added: statistical timing test for `akio-crypto` (`tools/ct-dudect`)

A dudect-style test (Welch's t-test of fixed vs random secrets, random interleaving, `rdtsc` /
`cntvct_el0`, percentile cropping and a second-order test, `|t| > 4.5` a leak) of the
secret-dependent paths on the hardware and the portable code: P-256 ECDH, key generation and
signing, X25519 and its key generation, Ed25519 signing, RSA-2048 signing, AES-GCM and
ChaCha20-Poly1305 tag checks, HMAC verification, `ct_eq` and the `ct.rs` primitives, with an A/A
test and two deliberately leaky functions as sanity checks. A new workspace-internal tool (not
published, no new dependency); runs in CI as the informational job `ct-dudect` (not part of
`ci-ok`, t-values kept as an artifact). On Zen 4 nothing leaks beyond two small, intermittent
differences under investigation (the degenerate all-zero X25519 scalar, P-256 portable signing
at the threshold); method and results in [docs/constant-time.md](docs/constant-time.md).

### Performance: stored blocks copied once in `akio-deflate`

No API change; compressed output is byte-identical. Measured on the bench host (Zen 4, CPU 2,
five alternating rounds of the old and new `bench` binaries, zlib-rs in the same run):
inflating random data at level 6 (stored blocks) 15,456 → 34,278 MB/s (0.43× → 0.94×
zlib-rs), level 9 15,357 → 34,003 MB/s. Text and JSON (literals and matches) are unchanged.

- Stored blocks are copied straight from the input to the caller's output instead of through
  the window, and only the last window's worth of a run of stored data (up to 32 KiB, once per
  call, before a compressed block or the trailer needs it) enters the history afterwards.
- `Inflater::decompress_vec` appends stored data with `extend_from_slice` (no zero-filled room
  to copy into); block headers are decoded with no output space. `decompress` reserves room for
  twice the input (at most the limit) up front.
- Tested with stored blocks split at every input byte and every output size in the three
  formats, through `decompress` and `decompress_vec`, and stored blocks longer than the window
  (up to 65,535 bytes) followed by matches at the largest distance, for 512-byte, 4 KiB and
  32 KiB windows.
- Tried and dropped: decoding up to five literals per refill instead of three on the
  literal-heavy path made no measurable difference.

### Performance: QUIC datapath (GRO by default, per-batch ACKs, pooled receive buffers)

No API change (`tools/api/public-api.sh` unchanged: the new hook is `#[doc(hidden)]`). One
default changed: `Config::udp_gro` is now `true`. Measured on the bench host (Zen 4, loopback,
`quic-bench` client and server on CPUs 2–5, median of seven alternating old/new rounds, an
outside workload on the host during some of them): one-stream bulk 6,378 → 16,066 Mbit/s
(2.52×), HTTP/3 427,901 → 443,299 req/s (1.04×), full handshakes 9,294 → 9,542/s (flat). The
quinn-proto build of the same program did 4,613 Mbit/s and 56,934 req/s in the same run as
15,999 Mbit/s and 430,098 req/s for this one (3.5× and 7.6×).

- `akio-core`: `Handler::on_batch_end` (`#[doc(hidden)]`, default no-op, outside the stability
  promise) tells a UDP handler that the receive batch that called its `on_data` is over. The UDP
  loop of akio-epoll, which also serves UDP on the io_uring backend and on macOS, calls it once
  per connection and batch (one `recvmmsg`; up to 32 `recv_from`/`recv` calls on macOS), before
  the batch's replies are flushed; dialed connections that fill a whole batch now flush after
  each one instead of after up to eight. Other backends (akio-dpdk) never call it.
- `Config::udp_gro` defaults to `true` (Linux, where the kernel supports `UDP_GRO`; probed once,
  `AKIO_UDP_GRO=0` still turns it off, `read_buffer` must stay at least 64 KiB). Coalesced
  receives are split by the `UDP_GRO` segment size on server, bound and dialed sockets as before,
  so `on_data` still sees one datagram per call (akio-kcp, akio-turn, akio-webrtc and DNS tests
  pass unchanged). Bulk QUIC 6.4 → 9.8 Gbit/s on its own: a GSO batch from the sender reaches the
  receiving socket whole instead of being segmented. 64-byte UDP echo with GRO on and off, 15
  alternating rounds each: no difference beyond the noise of the case.
- The UDP loop reads the clock once per receive call and chains the end of each timed callback
  into the start of the next (as the TCP loops do): three clock reads per datagram become one.
- akio-quic acknowledges once per receive batch: after each datagram the handler runs and data
  that is ready goes out right away, but an ACK-only packet waits for `on_batch_end` (one per
  batch instead of one per two packets); the QUIC timer is armed once per batch too. A variant
  that also deferred handler events and data to the batch end measured 1.45× on bulk but cost
  28% on HTTP/3 (64 requests in flight became one lock-step batch per round trip), so it is not
  in. Until a socket's first `on_batch_end` (and on backends without it) every datagram is
  driven on its own, as before.
- Received datagrams are copied once into a per-thread pool of buffers (`Arc<Vec<u8>>`) and
  decrypted in place; stream data and datagrams are `Bytes` slices of them, and a buffer is reused
  once all its slices are dropped (on any thread). This replaces two allocations per packet (the
  copy and the `Arc` around it). A copy remains: the handler gets the `recvmmsg` slot by
  reference, and decrypting in place needs a buffer this side owns alone.
- Sent packets are kept in a ring indexed by packet number (`proto/conn/sent.rs`) instead of a
  `BTreeMap`, and the frame lists of acknowledged or lost packets are reused for new packets.
- Profile notes not acted on: SipHash on the peer address and connection ID maps (~2% of the
  receiver), and allocations and header hashing in akio-h3/akio-http (`encode_fields`,
  `Headers`), which dominate the HTTP/3 profile.

### Changed (breaking, before 1.0.0): pre-1.0 dependencies wrapped

rustls 0.23, quinn-proto 0.11, str0m 0.24 and prost 0.13 no longer appear in the covered API, so
upgrading them (or replacing them with in-house code) is not a breaking change after 1.0.0.
Raw access moved behind new `unstable` cargo features (`akio`, `akio-tls`, `akio-quic`,
`akio-webrtc`), outside the semver promise like the `prost` feature of `akio-grpc`
(docs/api-stability.md, "Public dependencies").

| Before | After |
|---|---|
| `akio::tls::rustls` (re-export) | `unstable` feature only |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `akio::tls::ServerConfig::builder(chain, key).alpn([..]).build()?` (also `sni_cert`, `client_auth_required` / `_optional`, `session_cache`, `session_tickets`, `tls13_only`) |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `akio::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?` (also `client_cert`, `sni`, `resumption`, `tls13_only`, `insecure_skip_verify`) |
| `CertificateDer`, `PrivateKeyDer`, `RootCertStore` | `akio::tls::{Certificate, PrivateKey, RootCerts}` (`from_pem`, `from_der`, `from_pkcs8_der`) |
| `Tls::server(Arc<rustls::ServerConfig>, a)`, `Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`, `Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`, `H2Client::dial(.., Some((Arc<..>, name)), ..)`, `DialOptions::tls: Option<Arc<..>>` | the same with `akio::tls::ClientConfig` |
| `akio_quic::{proto, rustls}` re-exports, `VarInt` | `unstable` feature only (`proto`); `VarInt` removed |
| `akio_quic::{StreamId, Dir, ConnectionError, TransportConfig}` (quinn's) | `akio`'s own types (plus `Side`, `Congestion`, `UdpStats`); `ConnectionError` variants are struct-like (`ApplicationClosed { code, reason }`, `TransportError { code, reason }`) |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats` (`udp_tx`, `udp_rx`, `rtt`, `cwnd`, `lost_packets` ...) |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> akio_quic::ServerConfig` (`.transport(&TransportConfig)`, `.migration(bool)`) |
| `server_config_from(rustls::ServerConfig)`, `client_config(RootCertStore, ..)`, `client_config_from(rustls::ClientConfig)` | `server_config_from(&akio::tls::ServerConfig)`, `client_config(RootCerts, ..)`, `client_config_from(&akio::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `akio_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`, `serve(quinn_proto::ServerConfig, ..)`, `H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`, `akio_quic::ServerConfig`, `akio_quic::ClientConfig` |
| `akio_grpc::codec::{encode, decode}` bound on `prost::Message` | bound on `akio_grpc::codec::Message` (`encode_to`, `decode_from`); the `prost` feature implements it for prost messages |
| `akio_webrtc::str0m` re-export, `Peer::with_rtc`, `crypto_provider`, `generate_certificate` | `unstable` feature only (`str0m`, `with_rtc`, `crypto_provider_str0m`); `generate_certificate` is internal |
| str0m's `ChannelId`, `ChannelConfig`, `Reliability`, `Mid`, `Pt`, `MediaKind`, `Direction`, `Frequency`, `MediaTime`, `MediaData`, `MediaAdded`, `KeyframeRequest(Kind)`, `RtpPacket`, `Candidate`, `IceConnectionState`, `RtcConfig`, `Event` | `akio`'s own types of the same names (`ChannelConfig` is `#[non_exhaustive]`: `ChannelConfig::new(label)` then set fields; `MediaData::data` / `RtpPacket::payload` are `Arc<[u8]>`) |
| `create_offer(h, \|api: &mut SdpApi\| ..)`, `renegotiate(..)`; `api.add_channel(label.into())`, `api.add_media(kind, dir, None, None, None)` | `SdpChanges`: `add_channel(label)`, `add_channel_with_config(&cfg)`, `add_media(kind, dir, None, None)`, `set_direction`, `stop_media`, `ice_restart` |
| `Peer::open_channel(ChannelConfig)`, `payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`, `payload_type(mid, akio_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`: `Event::ChannelBufferedAmountLow(id)` or `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`, `impl From<str0m::RtcError> for Error` | `Error::Rtc(akio_webrtc::RtcError)`; new `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### Changed (breaking, before 1.0.0): own logging facade `akio-log` replaces `log`

DEV-PLAN wave B. `akio` no longer depends on the `log` crate; it logs through the new public
crate `akio-log` (no dependencies, re-exported as `akio::log`): levels, targets, structured
key-values with `log`'s macro syntax, a global maximum level in an atomic (a disabled statement
costs one relaxed load: 0.25-0.29 ns against `log`'s 0.36 ns), a `Logger` trait with
`set_logger` / `set_boxed_logger`, and built-in loggers (`akio::log::init(level)` for formatted
lines on stderr, `StderrLogger`). Targets, messages and key names are unchanged; without a
logger, errors and slow-callback warnings still go to stderr. The new `log` cargo feature
(`akio`, `akio-core`, `akio-log`; outside the semver promise) bridges to the `log` crate: records
go to `log`'s logger while no akio-log logger is installed (and `Config::log_level` also sets
`log::max_level`, as before), and `akio::log::bridge::route_log_to_only()` sends `log` records
(str0m, rustls ...) to the akio-log logger.

Migration:

| Before | After |
|---|---|
| `env_logger::init()` (or any `log` logger) | unchanged, with `features = ["log"]` on `akio`; or drop it for `akio::log::init(akio::log::LevelFilter::Info)` |
| `cfg.log_level = Some(log::LevelFilter::Info)` | `Some(akio::log::LevelFilter::Info)` (with the `log` feature, `Some(log::LevelFilter::Info.into())` also works) |
| `Telemetry::set_log_level(log::LevelFilter)` | `set_log_level(akio::log::LevelFilter)` |
| `impl log::Log for MyLogger` | `impl akio::log::Logger for MyLogger` (`enabled` and `flush` have defaults); install with `akio::log::set_logger` |
| `record.key_values().visit(&mut visitor)` | `record.key_values().iter()` / `.get("conn_id")`; values implement `Display` |
| `log::max_level()` | `akio::log::max_level()` |

### Changed: in-house cryptography (`akio-crypto`, DEV-PLAN wave A)

- New internal crate `akio-crypto` (std only, `#![deny(unsafe_code)]` except its AES-NI / ARMv8
  AES module): SHA-1, SHA-224/256, SHA-384/512, MD5, HMAC, HKDF, PBKDF2, CRC-32 / CRC-32C,
  AES-128/192/256 (CPU instructions when detected, else constant-time fixsliced software) with CTR, AES-GCM with a constant-time GHASH, ChaCha20-Poly1305, base64 (strict decoding), OS
  randomness and a ChaCha20 generator. Tested against NIST CAVP, RFC and Wycheproof vectors and
  cross-checked (tests and fuzz targets) against the crates it replaces.
- `akio-kcp`, `akio-turn`, `akio-ws`, `akio-http`, `akio-media`, `akio-bittorrent` and
  `akio-webrtc` use it instead of sha1, sha2, md-5, hmac, pbkdf2, aes, aes-gcm, ctr, crc32fast,
  base64 and getrandom (those remain dev-/fuzz-only references, and transitively under
  str0m/dimpl until wave D). Public APIs and wire formats are unchanged (KCP crypt incl. golden
  datagrams sealed by the old code, TURN MESSAGE-INTEGRITY/FINGERPRINT, WebSocket accept keys,
  BitTorrent info hashes and MSE, SRT key wrap and AES-CTR, RTMP digest handshake, SRTP).
- `akio-sys` (internal, `#[doc(hidden)]`): `fill_random` over `getrandom(2)` / `getentropy(2)`
  with a `/dev/urandom` fallback.
### Added: public-key cryptography and X.509 (`akio-crypto`, new `akio-x509`, DEV-PLAN wave B)

Groundwork for the own TLS 1.2/1.3, DTLS, QUIC and WebRTC stacks (waves C and D); nothing uses
it in the protocol crates yet, so no behaviour changes.

- `akio-crypto` (internal tier; additive API): X25519 (RFC 7748), Ed25519 (RFC 8032, strict
  verification: canonical `S`, encoded-`R` comparison), ECDH and ECDSA on P-256 and P-384
  (RFC 6979 deterministic nonces, DER and fixed-width signatures, SEC1 points with validation),
  RSA PKCS#1 v1.5 and PSS sign/verify with SHA-256/384/512 (SHA-1 verify only) for 2048–8192-bit
  moduli (CRT, blinding, result check), strict DER reader/writer, PEM, and key encodings
  (PKCS#8 v1/v2, SEC1, PKCS#1, SubjectPublicKeyInfo) behind `pkey::{PrivateKey, PublicKey,
  SignatureAlgorithm}`. New `Error` variants `InvalidKey`, `Encoding`, `Unsupported`, `Random`,
  `ZeroSharedSecret`. Constant-time field arithmetic (Montgomery for P-256/P-384 and scalars,
  radix 2⁵¹ for Curve25519), complete addition formulas, table lookups that read every entry.
- New internal crate `akio-x509` (`#![forbid(unsafe_code)]`): certificate parsing (strict DER;
  subjectAltName, basicConstraints, keyUsage, extKeyUsage, nameConstraints, key identifiers),
  chain building and validation against a `RootStore` (validity, CA/pathLen, key usage, EKU,
  DNS/IP/directoryName name constraints, unknown critical extensions, a signature-check budget),
  RFC 6125 server-name matching (leftmost-label wildcards, IP SANs), and generation of
  self-signed and CA-signed certificates (`CertificateParams`, `generate_simple_self_signed`).
- Tests: Wycheproof (X25519, Ed25519, ECDSA P-256/P-384 DER and P1363, ECDH P-256/P-384, RSA
  PKCS#1 v1.5 and PSS verification, RSA signature generation), RFC 7748 / 8032 / 6979 vectors,
  identical signatures and mutual verification with ring and RustCrypto p256/p384, real-world
  chains (Google Trust Services, Let's Encrypt ECDSA and RSA), OpenSSL-made chains and keys
  (RSA-PSS, P-384, Ed25519), rcgen and rustls-webpki interop, constructed negative chains; fuzz
  targets `x509_parse` and `crypto_sig_verify` (differential against ring) with corpus replays.

### Added: own DTLS 1.2 (new `akio-dtls`, DEV-PLAN wave C)

The DTLS layer of the in-house WebRTC stack (wave D will replace str0m's `dimpl` with it);
nothing uses it yet, so no behaviour changes.

- New internal crate `akio-dtls` (`#![forbid(unsafe_code)]`, depends only on `akio-crypto` and
  `akio-x509`): a sans-io DTLS 1.2 (RFC 6347) `Connection` for either role, driven by
  `handle_datagram`, `poll_transmit`, `poll_event`, `poll_timeout` / `handle_timeout` and
  `send_application_data`. Record layer with epochs, 48-bit sequence numbers and a 64-record
  anti-replay window; handshake fragmentation to the configured MTU and out-of-order
  reassembly; flight retransmission with exponential backoff (RFC 6347 §4.2.4) and on a
  repeated peer flight; stateless HMAC-SHA-256 HelloVerifyRequest cookies (`HelloVerifier` for
  listeners that allocate nothing before return routability is proven).
- Cipher suites `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
  CHACHA20_POLY1305_SHA256}`, groups X25519 / P-256 / P-384, ECDSA, Ed25519, RSA-PSS and
  RSA PKCS#1 signatures; extended master secret (RFC 7627, required by default); renegotiation
  refused (RFC 5746).
- WebRTC: `Config::webrtc`, mutual authentication with self-signed certificates checked by
  `PeerVerifier::Fingerprints` (SDP `a=fingerprint`), a callback, or deferred to the caller;
  `Identity::generate_self_signed`, `Fingerprint` (SDP form), `use_srtp` (RFC 5764) with
  `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM`, `SRTP_AES128_CM_HMAC_SHA1_80/32`, SRTP master
  keys in `Event::Connected`, and the RFC 5705 exporter (`export_keying_material`).
- Tests: handshakes over a simulated link with 25 % loss, duplication and reordering at MTU 256,
  every suite with ECDSA P-256/P-384, Ed25519 and RSA certificates, negative cases (wrong
  fingerprints, replays, tampered records, bad cookies, timeouts, missing client certificates,
  no shared suite); interop both directions with OpenSSL `s_client`/`s_server -dtls1_2`
  (3.5 in Docker, 4.1; `-use_srtp` and `-keymatexport` keys identical) and pion/dtls v3
  (`tools/interop/dtls/run.sh`), and in memory with `dimpl` (`tests/dimpl.rs`); fuzz targets
  `dtls_record` and `dtls_handshake` with corpus replays. Not implemented: DTLS 1.3 (RFC 9147),
  connection IDs, session resumption, PSK.
### Changed: own TLS 1.3 and 1.2 in `akio-tls` (DEV-PLAN wave C; no more rustls, ring)

`akio-tls` now implements TLS itself, from the RFCs, on `akio-crypto` and `akio-x509`
(`#![forbid(unsafe_code)]`, no third-party dependencies). The covered API is unchanged
(`api/akio-tls.txt` is identical): `ServerConfig` / `ClientConfig` builders, `Certificate`,
`PrivateKey`, `RootCerts`, `Error`, `Tls`, `TlsInfo`, `tls_info`; akio-http (HTTP/1.1, HTTP/2 by
ALPN), akio-ws (`wss://`), akio-socks, akio-grpc and akio-mux run on it unchanged.

- TLS 1.3 (RFC 8446): full handshake both sides, HelloRetryRequest (with cookie echo), key
  schedule, KeyUpdate (answered, and sent proactively before the AES-GCM record limit),
  NewSessionTicket and PSK resumption (`psk_dhe_ke`; stateless tickets with
  `session_tickets(true)`, single-use cached tickets with the session cache), client
  certificates, middlebox compatibility mode, 0-RTT rejected (skipped as RFC 8446 4.2.10 says).
- TLS 1.2 (RFC 5246 + RFC 7627 extended master secret + RFC 5746 renegotiation indication,
  renegotiation refused with a `no_renegotiation` warning): ECDHE with ECDSA, Ed25519 or RSA
  certificates and AEAD suites only, resumption by session ID and by RFC 5077 tickets, client
  certificates; the RFC 8446 downgrade sentinel is set and checked.
- Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 and the six
  ECDHE-ECDSA/RSA AES-GCM / ChaCha20-Poly1305 TLS 1.2 suites. Groups X25519, secp256r1,
  secp384r1. Signatures ECDSA P-256/P-384, Ed25519, RSA-PSS (rsae) and RSA PKCS#1 v1.5 (TLS 1.2
  and certificates). Extensions: SNI, ALPN, supported_versions, key_share, signature_algorithms,
  psk_key_exchange_modes, pre_shared_key, early_data, cookie, extended_master_secret,
  renegotiation_info, session_ticket, ec_point_formats; unknown ones ignored.
- Record layer: 16 KiB fragments, TLS 1.3 inner content types and padding, strict state
  machines, handshake messages reassembled across records (and refused across key changes),
  close_notify, alerts, bounded warning alerts; certificates verified with `akio-x509`
  (chain, validity, EKU, DNS names and IP addresses); `insecure_skip_verify` unchanged.
- QUIC-facing core (`akio_tls::quic`, `#[doc(hidden)]`, internal): the same TLS 1.3 machines
  without records, driven per encryption level (handshake bytes in and out, traffic secrets per
  level, quic_transport_parameters, ALPN required, no compatibility mode, RFC 9001 key
  derivation helpers with its Appendix A vectors), ready for the in-house QUIC of wave D. Until
  then akio-quic keeps quinn-proto, whose rustls configuration it now builds itself from the
  akio-tls configs (rustls stays a dependency of akio-quic only).
- Tests: RFC 8448 traces (simple 1-RTT, resumption binder, HelloRetryRequest: key schedule,
  transcript, Finished, records byte for byte), in-memory handshakes over every suite, group,
  key type and version, resumption, client authentication, fragmentation down to one byte,
  KeyUpdate, downgrade detection and negative cases; interop matrix
  (`tools/interop/tls/run.sh`, 107 cases: OpenSSL `s_server`/`s_client`, Go `crypto/tls` both
  ways, curl with HTTP/1.1 and HTTP/2), a TLS leg in `tools/interop/grpc/run.sh`, rustls clients
  in `akio`'s TLS tests; tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`: 33
  applicable TLS 1.3 / 1.2 scripts, 985 probes, 5 known and documented failures); fuzz targets
  `tls_server`, `tls_client`, `tls_record` with corpus replays.
- Performance (Apple M4 Pro, 2 server threads, rustls client): full handshakes about 0.7x
  rustls+ring (P-256 ECDSA and X25519 in `akio-crypto` are slower than ring's assembly), small
  records on par, bulk throughput about 0.45x (`akio-crypto`'s GHASH is portable; PMULL /
  PCLMULQDQ is a wave A follow-up).

Migration: the `unstable` feature of akio-tls (and `akio/unstable` for TLS) no longer exposes
anything: `akio::tls::rustls`, `ServerConfig::from_rustls` / `as_rustls` and
`ClientConfig::from_rustls` / `as_rustls` are removed (they were outside the semver promise).
`ServerConfigBuilder::build` now also fails when the private key does not belong to the
certificate. rcgen and rustls left the dev-dependencies of akio-tls, akio-http, akio-ws,
akio-mux, akio-h3, akio-quic and akio-grpc (test certificates come from `akio-x509`); `akio`
keeps a rustls client in its TLS tests as an interop peer.

### Changed: own QUIC v1 in `akio-quic` (DEV-PLAN wave D; no more quinn-proto, rustls, bytes)

`akio-quic` now implements QUIC itself, from RFC 9000, 9001 and 9002 plus RFC 9221 datagrams, as
a sans-io core on `akio-tls` (its record-free TLS 1.3, `akio_tls::quic`) and `akio-crypto`
(`#![forbid(unsafe_code)]`, no third-party dependencies). quinn-proto, the rustls inside it
(with ring) and the `bytes` crate left akio-quic and akio-h3; no library of the workspace
depends on rustls any more. The API is the same apart from the payload type (migration below):
`QuicServer`, `dial`, `Connection`, `QuicHandler`, `ServerConfig` / `ClientConfig` /
`TransportConfig`, `StreamId`, `ConnectionError`, `ConnectionStats`; akio-h3's API is unchanged
(`api/akio-h3.txt` is identical).

- Packets: long and short headers, the three packet number spaces, packet number encoding,
  header protection (AES, ChaCha20), AES-128/256-GCM and ChaCha20-Poly1305 packet protection,
  coalesced packets, Initial and path-validation padding, Version Negotiation, Retry with the
  integrity tag, stateless resets (sent for unknown connection IDs, detected by token), 1-RTT
  key updates (started every few million packets, followed when the peer starts one).
- Frames: every RFC 9000 frame and DATAGRAM, with the per-packet-type rules; streams with stream
  and connection flow control, stream limits (MAX_STREAMS in batches), BLOCKED frames, final
  size checks, RESET_STREAM in answer to STOP_SENDING.
- Recovery (RFC 9002): RTT estimation, packet and time threshold loss detection, probe timeouts
  and handshake anti-deadlock probes, persistent congestion, NewReno and CUBIC (RFC 9438),
  pacing, the 3x anti-amplification limit, ACK delay rules, idle timeout, keep-alive, path MTU
  discovery up to 1452 bytes.
- Endpoint: routing by connection ID (8-byte IDs issued with NEW_CONNECTION_ID, retired and
  replaced), Retry under handshake load, NEW_TOKEN address validation (tokens kept per server
  name in `ClientConfig`), migration with path validation (`ServerConfig::migration(false)`
  refuses it), transport parameter and connection ID checks, session resumption by ticket
  (`server_config` enables tickets).
- I/O: full-size datagrams leave in GSO batches (`Conn::send_segments`, up to 10); writes made
  from a connection's own callbacks are corked and leave with the acknowledgments once the
  callback returns, so an HTTP/3 response's headers, body and FIN usually share one packet.
- Tests: RFC 9001 Appendix A vectors, unit tests per component and a simulated network (loss,
  reordering, duplication, MTU, blackouts, virtual clock) for handshakes, bulk transfers, many
  streams, migration, key updates, Retry, resumption, resets and timeouts; interop with quic-go
  in both directions as raw QUIC (`tools/interop/quic/run.sh`, new: streams and datagrams, then
  Retry, key updates and a 150 MB stream) and as HTTP/3 with quic-go and fib
  (`tools/interop/h3/run.sh`); in Docker, ngtcp2 1.11 (through libcurl-gnutls) and OpenSSL 3.5's
  QUIC (curl, libcurl, `openssl s_client -quic`) as clients of our servers
  (`tools/interop/quic/docker.sh`, new); fuzz targets `quic_packet`, `quic_frame`, `quic_conn` with corpus
  replays.
- Performance against the quinn-proto version, same loopback benchmark
  (`crates/akio-h3/examples/quic-bench.rs`): on an AMD Ryzen 7 7800X3D (Linux, loopback, 3 alternating rounds) full handshakes 6705-6785/s against 6536-6674/s (about 1.0x), bulk throughput on one stream 3.1-3.6 Gbit/s against 4.6-4.7 Gbit/s (about 0.72x; packet protection uses `akio-crypto`'s hardware AES-GCM), and HTTP/3 requests on one connection with 64 in flight 171k/s against 58k/s (about 2.9x, since responses, FINs and acknowledgments share packets).

Migration: stream and datagram payloads are `akio_quic::Bytes` instead of `bytes::Bytes`, the
only signature change (`QuicHandler::on_stream_data`, `QuicHandler::on_datagram`,
`Connection::send` and `Connection::send_datagram` take `impl Into<akio_quic::Bytes>`). It has
the same shape (reference counted; `new`, `from_static`, `copy_from_slice`, `slice`,
`split_to`, `split_off`, `truncate`, `advance`, `Deref<Target = [u8]>`, `From<Vec<u8>>`,
`From<&'static [u8]>`, `From<&'static str>`, `From<String>`, `Vec<u8>: From<Bytes>`), so code
usually only changes its import: `use bytes::Bytes;` becomes `use akio_quic::Bytes;`. The
`unstable` feature of akio-quic is reserved and empty: `akio_quic::proto`,
`ServerConfig::from_quinn` / `as_quinn_mut` and `ClientConfig::from_quinn` / `as_quinn_mut` are
removed (they were outside the semver promise). `Congestion::Bbr` (experimental) runs CUBIC.
`Connection::queued_bytes` counts bytes not sent yet. A dialed connection's UDP socket is now closed once the connection is gone (it used to stay open until the engine stopped), and `open_bi` / `open_uni` never run handler callbacks, so they may be called while holding locks the handler takes. Not implemented: 0-RTT, sending ECN marks,
client-initiated migration, preferred_address, QUIC v2.

### Changed: own WebRTC stack in `akio-webrtc` (DEV-PLAN wave D; no more str0m, dimpl, p256)

`akio-webrtc` runs on an in-house, sans-io WebRTC stack with no third-party dependencies, behind
the unchanged API (`RtcServer`, `Endpoint`, `Peer`, `PeerHandler` and its ordering guarantees,
`ChannelConfig`, `Codec`, `SdpChanges`, `Event`, `RtcError` ...). Four new internal crates, all
`#![forbid(unsafe_code)]` on `akio-crypto`:

- `akio-ice`: ICE (RFC 8445) full agent and ICE-lite: candidate priorities and foundations,
  checklists with pacing and retransmission, peer-reflexive candidates, regular nomination, role
  conflicts (487), checks before the remote credentials, consent freshness (RFC 7675), trickle
  (RFC 8838) and restarts; STUN through `akio-turn`'s codec. RFC 5769 vectors; pion/ice interop.
- `akio-srtp`: SRTP/SRTCP (RFC 3711, RFC 7714) with AES-CM-HMAC-SHA1-80/32 and
  AEAD-AES-128/256-GCM, ROC estimation, replay windows; RFC 3711 and RFC 7714 vectors and
  byte-exact cross-checks with pion/srtp.
- `akio-rtp`: RTP header extensions (one- and two-byte), RTCP (SR, RR, SDES, BYE, generic NACK,
  PLI, FIR, REMB, transport-wide CC feedback), send/receive streams with NACK + RTX (RFC 4588),
  reports and RTT, TWCC and a delay- and loss-based bandwidth estimator; payload formats for
  Opus, G.711, G.722, VP8, VP9, H.264 (RFC 6184), H.265 (RFC 7798) and AV1 with a jitter-free
  frame assembler. Byte-exact cross-checks with pion/rtp, pion/rtcp and pion/interceptor.
- `akio-sctp`: SCTP over DTLS (RFC 8261; RFC 9260 essentials) with congestion control, fast
  retransmit, PR-SCTP FORWARD-TSN (RFC 3758), stream reset (RFC 6525), DCEP data channels
  (RFC 8831/8832); interop with pion/sctp 1.8 and 1.12 over UDP.

`akio-webrtc` itself gained the SDP offer/answer (BUNDLE, rtcp-mux, codec / RTX / rtcp-fb /
extmap negotiation, ssrc and FID groups, setup roles and fingerprints, ICE-lite, candidates,
sctp-port / max-message-size, renegotiation and ICE restarts) and the sans-io peer that glues
the layers together. Tested on a simulated lossy link (ICE + DTLS + SCTP + media) and against
pion (data channels, Opus/VP8 echo, PLI, a TURN relay, both offer directions), fib's Go WebRTC
(both directions) and headless Chrome (`tools/interop/media/browser.sh`: data channels, Chrome's
camera and microphone echoed back and decoded, both offer directions). New fuzz targets
`ice_stun`, `srtp_unprotect`, `rtp_rtcp`, `rtp_codec`, `sctp_packet`; `webrtc_sdp` now drives the
new SDP code.

Migration notes:

- The `unstable` feature of `akio-webrtc` is now reserved and empty: `akio_webrtc::str0m`,
  `crypto_provider_str0m`, `Peer::with_rtc`, `RtcConfig::with_str0m` and
  `OtherEvent::as_str0m` are gone (they were outside the semver promise).
- The covered API is unchanged except that `Event`, `OtherEvent`, `RtcConfig`, `RtcError` and
  `SdpChanges` are now `RefUnwindSafe` (and `RtcError` `UnwindSafe`): auto traits gained, nothing
  lost.
- Behaviour: H.265 is no longer offered by default (`RtcConfig::enable_h265(true)` turns it on),
  DTLS is 1.2 only (browsers and pion negotiate 1.2), the answerer takes the DTLS client role
  (`a=setup:active`), `OtherEvent`'s `Debug` output changed (it was never stable), and
  `Endpoint` still has no TURN client (relayed candidates must come from elsewhere, as before).
- Dependencies: str0m, dimpl, p256 / ecdsa / elliptic-curve, the RustCrypto crates they pulled
  and rand 0.9 left the library graph; akio-dtls's in-memory interop test against dimpl was
  removed. p256/p384 0.13 remain dev-dependencies of akio-crypto's cross-checks, so the
  RUSTSEC-2026-0387 (crypto-bigint) ignore in `deny.toml` now only covers them.

### Changed: in-house HTTP codecs (no more httparse, loona-hpack, regex)

DEV-PLAN "no third-party dependencies", wave A. The public API is unchanged.

- HTTP/1 head parsing (akio-http requests, chunked trailers and client responses, akio-ws client
  handshake responses) uses an in-house parser, `akio_ws::http1` (`#[doc(hidden)]`): zero-copy,
  incremental (a head arriving in many reads is scanned once instead of re-parsed from the start
  on every read; the session also stops copying the buffered bytes on every read) and strict per
  RFC 9110/9112: token methods and field names, visible-ASCII request targets (non-ASCII bytes,
  which httparse let through, are now 400), exactly one SP between request-line elements, a bare
  CR, whitespace before a colon or the first field and obsolete line folding are rejected (also
  in responses), CRLF or bare LF line ends. Header values are no longer `str::trim`med (only
  SP/HTAB around them are removed, as RFC 9110 says). Speed is on par with httparse (SIMD) using
  word-at-a-time scanning in safe code (`tools/codec-bench`).
- HPACK is in-house (`akio_http::hpack`, `#[doc(hidden)]`): encoder with dynamic table, Huffman
  coding when not longer, never-indexed literals for `authorization` / `proxy-authorization` /
  short `cookie`s and the table size updates RFC 7541 §4.2 requires after the peer changes
  `SETTINGS_HEADER_TABLE_SIZE` (loona-hpack sent none); decoder with dynamic table, size updates
  only at the start of a block and within our setting, 32-bit integers, and a header list limit
  applied while decoding (the whole block is still processed so the table stays in step); the
  Huffman decoder walks 4 bits at a time. RFC 7541 Appendix C vectors pass both ways; h2spec
  147/147.
- Route constraints (`{id:[0-9]+}`) use an in-house linear-time engine (`akio_http::re`): literals,
  `.`, classes with ranges/negation/escapes, ASCII `\d \w \s` (and negations), groups (named
  ones too, nothing is captured), `|`, `* + ? {m} {m,} {m,n}` with lazy variants, `^`/`$`;
  unsupported syntax (flags, `\b`, `\p{..}`, backreferences, POSIX classes, class set
  operations, counts above 1000) panics at registration naming the problem. Regexp parameters are
  always available; the `regex` cargo feature of akio-http is kept as a no-op for compatibility.
- Fuzzing: `http1_request` / `http1_client` compare the head parser with httparse, `hpack` with
  loona-hpack (both directions of encode/decode too), new `regex_match` with the `regex` crate;
  those crates remain only as dependencies of `fuzz/` and of the `tools/codec-bench` micro
  benchmarks (both outside the library workspace).
### Changed (internal): own syscall and io_uring bindings (no more `libc`, `io-uring`)

DEV-PLAN "no third-party dependencies", wave B. No public API changes; behaviour, errno and
`EINTR` handling are unchanged.

- `akio-sys` declares its own OS bindings in `akio_sys::ffi` (`#[doc(hidden)]`, internal): C
  types, constants, `#[repr(C)]` structs (`sockaddr_in`/`in6`/`storage`/`ll`, `msghdr`,
  `mmsghdr`, `cmsghdr` with the `CMSG_*` helpers, `iovec`, `epoll_event` (packed on x86_64),
  `kevent`, `timespec`, `pollfd`, `cpu_set_t`, `sigaction`, `utsname`) and `extern "C"`
  declarations of the C library (Linux, glibc or musl) and libSystem (macOS). System calls
  without a C wrapper (`bpf`, `io_uring_*`) use `syscall(2)` with per-architecture numbers.
  Linux x86_64 and aarch64 (riscv64 / loongarch64 share the generic layouts) and macOS
  aarch64 / x86_64; other Linux architectures fail to compile with a clear message instead of
  silently using wrong layouts.
- Every layout and constant is compared with the `libc` crate in a test-only module (`libc` is
  now a dev-dependency only), verified on macOS aarch64, Linux aarch64 and Linux x86_64.
- `akio-uring` has its own io_uring binding (`ring`): `io_uring_setup` / `io_uring_enter` /
  `io_uring_register`, the mmap'd SQ/CQ rings and SQE array with the kernel's memory ordering,
  the submission entries the reactor uses (multishot accept, multishot recv with buffer
  selection, poll add, async cancel and cancel-any, read), CQE flags, opcode probing and
  `IORING_FEAT_*` checks (the probe now also requires `IORING_FEAT_EXT_ARG`), SQPOLL and the
  cooperative / single-issuer / deferred task-run setup. The buffer-ring, `KernelBuf`,
  in-flight cancel and graveyard logic is unchanged.
- `akio-ebpf` and `akio-dpdk` (TAP, AF_PACKET) use `akio_sys::ffi`.

### Changed (experimental tier): akio-dpdk runs its own TCP/IP stack

`akio-dpdk` no longer depends on smoltcp (DEV-PLAN "no third-party dependencies", wave A): the
userspace stack is now `akio`'s own, in `crates/akio-dpdk/src/net` (safe Rust,
`#![forbid(unsafe_code)]`, no dependencies), with the same `Device` kinds, `DpdkConfig` and
`Backend::Dpdk` integration.

- Ethernet II; ARP with a 60 s cache and a queue of packets awaiting resolution (the first SYN to
  a new neighbour is no longer dropped, which cost the smoltcp version a 1 s SYN retransmission);
  IPv4 with fragmentation on send and bounded reassembly (UDP datagrams larger than the MTU now
  work); ICMP echo replies, port / protocol unreachable, and received unreachables delivered to
  dialed UDP connections (closed with `ConnectionRefused`, as on the kernel backends).
- TCP per RFC 9293: RTT / RTO per RFC 6298, SACK (RFC 2018) with RFC 6675-style recovery,
  NewReno fast recovery (RFC 6582), CUBIC (RFC 9438, the default) or NewReno, window scaling and
  timestamps with PAWS (RFC 7323), delayed ACKs, keepalive, TIME-WAIT with reuse, RFC 5961
  challenge ACKs, a listen backlog with SYN cookies.
- The I/O loop is event-driven with a per-connection timer heap (the smoltcp version re-examined
  every connection on each busy iteration); ACKs are coalesced per receive burst; a memory-wire
  end wakes its peer's thread when it sends.
- Dialing works on multi-queue DPDK ports (was `Unsupported`): local ports name their queue and
  replies RSS puts elsewhere are handed over.
- New `DpdkConfig` fields: `syn_cookies` (default `true`), `congestion`
  (new `akio::dpdk::Congestion`, default `Cubic`), `tcp_keepalive` (default `None`).
  `udp_buffer` now bounds the datagrams queued per UDP port.
- TAP and AF_PACKET devices use `libc` directly (`src/sys.rs`); the AF_PACKET socket gets an 8 MiB
  receive buffer and skips the host's outgoing frames.
- Tests: per-layer unit tests, a simulated lossy / reordering link in virtual time, the kernel
  peer suite extended with `tc netem` loss, a 4 MiB window over 20 ms, 500 concurrent
  connections, dials to the kernel and ping; fuzz targets `dpdk_ethernet`, `dpdk_arp`,
  `dpdk_ipv4`, `dpdk_tcp`, `dpdk_udp`, `dpdk_icmp`, `dpdk_stack`. Benchmark example
  `stack-bench`; A/B against the smoltcp version in docs/BENCHMARKS.md.
- `deny.toml`: the 0BSD license and the `bitflags@1` duplicate (both smoltcp's) are gone.

### Changed (performance): QUIC and TLS hot paths (DEV-PLAN performance pass)

No API change. Ryzen 7 7800X3D, loopback, three alternating rounds (docs/BENCHMARKS.md):

- `akio-quic`: single-stream bulk 3.4-3.7 → 5.7-5.8 Gbit/s (1.25x the quinn-proto version, was
  0.72x), HTTP/3 requests on one connection with 64 in flight 171k → 415-426k/s, handshakes +2%.
  The pacer floored the RTT at 1 ms and, once empty, woke the sender for every packet through the
  timer thread; it now uses the measured RTT and waits for a whole burst to refill (as
  quinn-proto does), so paced data leaves in GSO batches from the I/O thread (per GiB: futex calls
  423k → 5.6k, context switches 182k → 9.5k). Also cheaper per-packet bookkeeping (stream maps
  without SipHash, in-order range inserts with one lookup, no per-datagram allocations for the
  batch buffer and space selection).
- `akio-tls`: received records are copied once, straight into the caller's plaintext buffer, and
  decrypted there (they used to go through the receive buffer and be copied out); large writes
  reserve room for all their records at once. Seal + open +5-7% for 16-64 KiB records. Handshakes
  were profiled: over 98% is curve arithmetic and hashing, so they are unchanged. New
  `crates/akio-tls/examples/tls-bench.rs` compares against rustls 0.23 + ring (dev-dependency
  only).

### Changed (performance): akio-deflate at zlib-rs speed (DEV-PLAN performance pass)

`akio-deflate` (still `#![forbid(unsafe_code)]`, no dependencies, no SIMD) now compresses at
0.94-1.48x the speed of flate2 with the zlib-rs backend (was 0.25-0.9x) with output at most 0.5%
larger (identical in 36 of 45 level × corpus cases), and decompresses at 0.82-1.23x (was
0.7-0.85x); measured on x86-64, tables in docs/BENCHMARKS.md. The streams are as valid as before
for every window size (8 laid out as 9); no API change.

- Compression uses zlib-ng's / zlib-rs's level table and match finders: a hash of four bytes
  (three at level 9), `quick` at level 1 (one probe per position, fixed-code blocks written
  directly, replaced by stored blocks when those are smaller), `fast` at level 2, `medium` at
  levels 3-6 (greedy, from level 5 looking one match ahead), lazy `slow` at 7-9 with zlib-ng's
  chain-jumping search at level 9. Candidates are compared 8 bytes at a time with a cheap
  rejection first. **Level 1 output is now up to 40% larger than before** (like zlib-ng's and
  zlib-rs's level 1) and 1.7-2.9x faster; levels 2-9 are 1.03-4x faster, with output between
  12% smaller and 3.4% larger than before.
- `Deflater::reset` (permessage-deflate without context takeover) clears only the hash slots a
  short stream used instead of the whole table; stored blocks are written straight from the
  window; Huffman code construction counts lengths without store-forwarding stalls.
- Decompression: a fast path refills 64 bits without branches and decodes up to three literals
  or a length/distance pair per refill; matches are copied 8 or 16 bytes at a time (also for
  overlapping matches); decoding tables of complete codes are no longer cleared first.
- permessage-deflate echo (`pmd_echo`, level 6, context takeover) against zlib-rs: 1.84x for 64 B
  messages, 1.04x for 512 B, 1.00x for 4 KiB, 0.98x for 64 KiB (was 1.36x / 0.62x / 0.75x /
  0.54x), with the same bytes on the wire as zlib-rs.
- The `bench` example covers levels 1..=9 (`BENCH_LEVELS`), generated corpora plus files and a
  profiling mode (`BENCH_PROFILE`); a new streaming test covers every level, window size and
  flush kind.

### Added

- `akio-protobuf` and `akio-protobuf-build` (DEV-PLAN "no third-party dependencies", wave A):
  an in-house protobuf runtime and code generator replacing prost, with no dependencies.
  - `akio-protobuf`: the wire format, `Message` (encode, decode, merge, length-delimited),
    open enums (`Enumeration`), unknown-field preservation (`UnknownFields`), `Name`, bounded
    decoding (100 nesting levels, checked lengths, UTF-8; a field with an unexpected wire type
    is kept as an unknown field, as in C++ and Go), and `well_known` (`Empty`, `Timestamp`,
    `Duration`, `Any`, wrappers, `FieldMask`, `Struct` / `Value` / `ListValue`, with `std`
    conversions and `Any::pack` / `unpack`). Encodes byte for byte as protoc's C++ runtime.
  - `akio-protobuf-build`: a `.proto` parser (proto3 and proto2: messages, nested types, enums,
    `optional`, `required`, `repeated`, `map`, `oneof`, defaults, packages, imports, built-in
    well-known types) and Rust generator for `build.rs` (`compile(&["x.proto"], out_dir)`,
    `Config`), no `protoc`. Services become `akio-grpc` stubs: a `<service>_server` trait with
    `register`, and a typed `<service>_client`; messages then implement
    `akio_grpc::codec::Message`.
  - Checked against golden encodings from protoc, differentially against prost (tests and the
    `protobuf_diff` fuzz target), and with grpc-go's generated route_guide / helloworld code in
    both directions (`tools/interop/grpc/run.sh`, new `tools/protobuf-test`).
- `akio-grpc`: `Sink::send_message` and `ClientSink::send_message` (encode a `codec::Message`
  and send it), and the re-export `akio_grpc::Headers`.

- `akio-prefork` (M6, optional): serve one program from several worker processes. A supervisor
  re-executes the current binary as N workers (no fork after threads), each running its own
  `Engine`; listeners are shared with `SO_REUSEPORT` (Linux default) or inherited from the
  supervisor (`ListenMode::Inherit`, the macOS default; no connection is refused across restarts
  and reloads); crashed workers are restarted with exponential backoff; SIGTERM/SIGINT drain the
  workers, SIGHUP (or `Supervisor::reload`) starts a new generation and stops each old worker once
  its replacement is ready; optional CPU pinning (Linux); `Worker` gives the index, worker count
  and generation. Example `prefork-http`, book chapter "Multi-process serving (prefork)".
- `akio::Listener::tcp_from_std`: serve an already bound and listening socket (inherited from a
  supervisor, systemd socket activation); internal `EpollGroup::bind_listener` /
  `UringGroup::bind_listener`.
- `akio-sys` (internal): `process` module (child fd inheritance, CPU affinity and parent-death
  signal in `pre_exec`, `take_inherited_fd`, `reserve_reuseport`, a self-pipe `signal_pipe`, `kill`).
- `akio-deflate` (internal, DEV-PLAN "no third-party dependencies", wave A): DEFLATE, zlib and
  gzip in pure safe Rust without dependencies, replacing `flate2`/`zlib-rs` in `akio-ws`
  (permessage-deflate), `akio-http` (compression middleware) and `akio-grpc` (gzip messages).
  Streaming `Inflater` (any input split, bounded output, windows 2^8..2^15, zlib's code checks)
  and `Deflater` (hash chains, lazy matching, zlib levels 0..=9, length-limited dynamic Huffman,
  fixed or stored blocks, sync/full flush, windows 2^8..2^15), Adler-32 and CRC-32. Interop both
  ways with zlib-rs and `gzip(1)`; fuzz targets `deflate_inflate` (differential against zlib-rs)
  and `deflate_roundtrip`; Miri runs its tests, and the Miri job runs the akio-grpc gzip test
  again (the zlib-rs aliasing report in docs/unsafe-review.md no longer applies). Public APIs of
  the other crates are unchanged.
- `akio-ws`: permessage-deflate with a window of 8 bits. A server accepts
  `server_max_window_bits=8` (it used to decline such an offer) and a client told
  `client_max_window_bits=8` compresses (it used to send uncompressed); the compressor keeps
  distances within 250 bytes there. `deflate::Deflater`, `deflate::Inflater` and
  `protocol::Decoder` are now `UnwindSafe` (they no longer hold zlib-rs state).

### Deprecated

- The `prost` feature of `akio-grpc` (outside the semver promise): it still works; use
  `akio-protobuf` / `akio-protobuf-build` instead. It may be removed in a minor release.

### Fixed

- `akio-ws`: every WebSocket connection carried ~2 KB of inline permessage-deflate state (the
  akio-deflate inflater and deflater inside `Option`s), even when compression was not negotiated;
  the state is now boxed. An idle connection after upgrade + one echo: 3,486 → 1,426 bytes.
- io_uring: during a graceful shutdown, connections the multishot accept completed before its
  cancellation took effect were reset; they are now served (`on_shutdown` after their first data),
  and the drain ends only once the accept has ended, so the listening socket is really closed.
- `akio-dpdk` (experimental, M6): a kernel-bypass backend. A userspace TCP/IP stack (smoltcp,
  IPv4) runs on `akio` I/O threads over a DPDK port (EAL init from `EalConfig`, one rx/tx queue
  pair and one thread per queue, mbuf rx/tx bursts, RSS with ARP fanned out between queues), a
  Linux TAP interface, an AF_PACKET socket or an in-process `MemoryWire`. UDP listeners deliver one
  datagram per `on_data` and TCP listeners a byte stream, with `dial` / `dial_udp`, backpressure,
  idle timeouts, telemetry and graceful shutdown, so protocol crates (akio-kcp, ...) run
  unchanged. Listeners on the same device share its stack and threads.
- `akio`: cargo features `dpdk` (`Backend::Dpdk(DpdkConfig)`, re-export `akio::dpdk`) and
  `dpdk-pmd` (also DPDK ports; links libdpdk found with pkg-config). Experimental: outside the
  semver promise (docs/api-stability.md).
- `akio-core` (backend-facing, `#[doc(hidden)]`): `ConnInner::new_virtual` and
  `ConnInner::drain_output` for connections whose bytes a userspace stack moves.
- `tools/dpdk/` (Dockerfile + `test.sh`) and the heavy CI job `dpdk`: builds against the
  distribution's DPDK and runs UDP/TCP echo against the kernel stack over DPDK's `net_tap` PMD
  (one and two queues), over smoltcp's TAP device and over AF_PACKET on a veth pair.
- `Engine::bind_udp` and `UdpBinding` (`akio`, akio-core): an unconnected UDP socket bound
  while the engine runs, served like a UDP listener (one connection per peer address), that
  sends to any address with `UdpBinding::send_to`. What ICE agents and TURN relays need.
- `akio-turn` (new crate): the STUN codec (RFC 8489, with the TURN and ICE attributes,
  `MESSAGE-INTEGRITY`, `FINGERPRINT`), `StunServer`, and `TurnServer`, a TURN relay over UDP
  (RFC 8656): allocations with long-term credentials (`static_auth`, `ephemeral_auth` for the
  TURN REST API), permissions, channels, Send/Data indications, refresh, `EVEN-PORT` and
  `RESERVATION-TOKEN`, stateless nonces, quotas, and a peer policy refusing private and
  loopback peers by default; `TurnCore` is the same server as a sans-io state machine. Interop:
  pion/turn client and coturn's `turnutils_uclient`.
- `akio-webrtc` (new crate): WebRTC on the sans-io `str0m` 0.24 over `akio` UDP. `RtcServer`
  serves a UDP listener (ICE-lite by default, peers demultiplexed by ICE username and source
  address); `Endpoint` runs a full ICE agent on a `bind_udp` socket, with server-reflexive
  candidates from a STUN server. `Peer` (any thread) sends on data channels, writes media,
  requests keyframes, renegotiates; `PeerHandler` callbacks run one at a time per peer. DTLS
  1.2/1.3 with fingerprint verification, SRTP (AES-CM, AES-GCM), SCTP data channels (reliable or
  not, ordered or not), RTP/RTCP with NACK, PLI/FIR, TWCC. A pure-Rust crypto provider
  (RustCrypto and `dimpl`, no C toolchain). Interop with pion (data channels and media in both
  offer directions, through a `akio` TURN relay) and with fib's Go WebRTC (data channels);
  `tools/interop/webrtc/run.sh`.
- Fuzz targets `stun_message`, `turn_server` and `webrtc_sdp`.
- `akio-media` (M7 streaming media), a new crate: one stream hub with RTMP, RTSP, SRT,
  HTTP-FLV, WS-FLV, HLS and WHIP/WHEP signalling around it.
  - `hub`: streams by path, one publisher and many subscribers, GOP cache for fast start,
    `Dropper` (slow players drop to the next keyframe), publish / play auth hooks, reserve
    before the tracks are known, waiting for (re)publishers, `Timeline` timestamp
    normalization, per-stream statistics.
  - RTMP server: simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP
    (H.265 `hvc1`, Opus); AMF0 / AMF3; FLV mux / demux (legacy and enhanced tags).
  - HTTP-FLV and WS-FLV playback (`HttpFlv`), HLS with MPEG-TS segments, LL-HLS parts,
    preload hints and blocking reload (`Hls`), `MediaHttp` dispatching both; MPEG-TS muxer.
  - RTSP 1.0 server (ANNOUNCE/RECORD, DESCRIBE/SETUP/PLAY over TCP-interleaved and UDP,
    Digest/Basic auth), RTP packetization for H.264/H.265/AAC/Opus/G.711 with decode times
    derived for B-frame video, SDP, and WHIP/WHEP HTTP signalling with a `WebRtcEngine`
    integration trait.
  - SRT live mode (HSv5 caller/listener, ARQ, TSBPD, AES-CTR encryption with passphrase,
    stream ID access control) with a hub-backed `SrtServer` and `srt::dial` / `push` / `pull`;
    incremental MPEG-TS demuxer (`mpegts::demux`).
  - Interop-tested with ffmpeg / ffprobe as publisher and player (SRT with libsrt in Docker);
    fuzz targets `rtmp_server`, `flv_demux`, `amf_decode`, `rtsp_server`, `sdp_parse`,
    `rtp_depacketize`, `mpegts_demux`, `srt_listener`, `srt_conn`.
- `akio_ws::WsSender::queued_bytes`, for pacing a producer that streams to a slow peer.
- `akio-bittorrent` (M7): bencode; .torrent v1 files (path safety, `Builder`) and magnet links;
  HTTP and UDP trackers as codecs, a `TrackerClient` (akio-http, `dial_udp`) and a
  `TrackerServer` (a akio-http service and a UDP acceptor on one store); the peer wire protocol
  with the Fast extension, the extension protocol, ut_metadata and ut_pex; MSE/PE (DH-768, RC4);
  uTP with LEDBAT; the mainline DHT; `port::UdpPort`, uTP and the DHT on one `akio` UDP listener;
  and a `client::Client` (magnets, rarest-first picker with endgame, pipelining, choking with
  optimistic unchoke, storage and SHA-1 on a logical pool, PEX, DHT, trackers, events). Interop
  with libtorrent 2.0 and aria2 1.37 (`tools/interop/bittorrent/run.sh`); fuzz targets
  `bt_bencode`, `bt_peer_wire`, `bt_krpc`, `bt_utp`, `bt_tracker`, `bt_mse`.
- `Engine::dial_udp_from`: a peer connection on a UDP listener's own socket, so datagrams to a
  new address leave from the listener's port (DHT nodes, uTP).

### Fixed

- `Engine::dial` no longer picks a UDP group (and fails) when the engine has both TCP listeners
  and UDP listeners or UDP client threads, but no `client_threads`.

## [1.0.0-rc.1] - 2026-11-14

First release candidate of 1.0: the API is frozen for review. The public API of every crate is
recorded in `api/<crate>.txt` and checked in CI.

### Added

**Core engine (M0–M1)**
- Thread-per-core event loops: each I/O thread owns its reactor, connections, buffers and timer
  wheel; callbacks run inline on the owning thread, so per-connection handler state needs no lock
  (ADR-001..004).
- `Handler` / `Acceptor` / `fn_acceptor`, and `Conn`: a cloneable `Send + Sync` handle with
  `send`, `send_owned`, `send_shared` (`SharedBuf`), `send_segments`, `cork`/`flush`,
  `close`/`close_after_send`, `hold_reads`, `on_drain`; using a closed handle returns
  `Error::Closed`.
- Backends: epoll (Linux) and kqueue (macOS) in `akio-epoll`; `SO_REUSEPORT` accept distribution;
  asynchronous `Engine::dial`.
- Backpressure (write high watermark, `max_queued_bytes`), idle and write timeouts, connection
  limit, graceful shutdown with a timeout.
- `loom` models for the connection send path, stress tests with 5,000 simultaneous and 100,000
  idle connections.

**Logical pool, io_uring, UDP, TLS (M2)**
- `akio-pool` adaptive bounded pool; `Conn::spawn_blocking` with the completion back on the
  connection's I/O thread; ordered response slots (`Conn::reserve_response`, `ResponseSlot`,
  `ResponseStream`).
- Slow-callback detection (`Config::slow_callback_threshold`, `slow_hook`).
- `akio-uring`: io_uring backend (multishot accept/recv, provided-buffer rings, kernel probe with
  fallback to epoll); per-listener backend choice (`Listener::backend`).
- UDP: `Listener::udp` (one `Conn` per peer), `Engine::dial_udp`, `recvmmsg`/`sendmmsg`, UDP
  GSO/GRO, `udp_max_peers`.
- `akio-tls`: rustls as a sans-io transport layer under `Conn` (`Tls::server`, `Tls::client`,
  `tls_info`).

**HTTP and WebSocket (M3)**
- `akio-http`: HTTP/1.1 server with pipelining, chunked bodies and trailers, streaming request
  and response bodies, `Router` (static > `:param` > `*wildcard`, regex parameters, nesting,
  layers), middleware (recover, request id, CORS, logger, response time, compress, etag, csrf,
  limiter), static files (`files::Files`: ranges, precompressed twins, cache, `sendfile`), HTTP/1
  client (`client::Client`, `ResponseFuture`).
- `akio-ws`: RFC 6455 with permessage-deflate, `PreparedMessage` broadcast, subprotocols, origin
  check; server upgrade (`Context::upgrade_websocket`) and client (`akio_ws::client`); Autobahn
  suite clean.

**HTTP/2 and more protocols (M4)**
- HTTP/2 server on the same `Service` (h2c prior knowledge and upgrade, ALPN `h2`, flow control,
  HPACK, push) and `h2client::H2Client`; h2spec clean.
- `akio-mux` (several protocols on one port), `akio-arpc` (lesismal/arpc wire format),
  `akio-grpc` (unary and streaming gRPC on akio-http, gzip, deadlines, interceptors, optional
  prost helpers), `akio-socks` (SOCKS5/4/4a and HTTP CONNECT).

**QUIC, HTTP/3, KCP, eBPF (M5)**
- `akio-quic` (quinn-proto over `akio` UDP) and `akio-h3` (HTTP/3 with QPACK, client and server).
- `akio-kcp`: KCP compatible with skywind3000/kcp and kcp-go (crypts, Reed–Solomon FEC).
- `akio-ebpf`: `SO_REUSEPORT` steering by CPU or consistent hash (classic BPF unprivileged, eBPF
  when privileged) via `Accel::Ebpf`, and an in-kernel sockmap `Relay`.

**Production readiness (M6)**
- Telemetry: per-thread counters, `Engine::metrics` (Prometheus and JSON), connection table,
  slow-callback ring, live reload of settings (`Engine::reload`), `akio_http::observe` endpoints
  and HTTP metrics.
- Seeded chaos test suites (engine, fd exhaustion, TLS, HTTP/WebSocket).

**1.0 stabilization**
- 21 fuzz targets with corpora and coverage reporting; `cargo-deny`/`cargo-audit` gate; unsafe
  review (docs/unsafe-review.md), Miri and sanitizer jobs; strict lint set; mdBook guide in English
  and Chinese with migration guides; benchmark report.
- API freeze: `docs/api-stability.md` (semver, MSRV and platform policy), `docs/deprecation.md`,
  this changelog, public API snapshots (`api/*.txt`, `tools/api/public-api.sh`) checked by the CI
  job `public-api`, and a `semver-checks` job that activates once 1.0.0 is published.
- New API from the review: `AnyAcceptor` and `Listener::serve_any` (type-erased acceptors, used
  by `akio-mux`); `Request::new`, `ClientRequest::new`/`body`, `FileBody::new`; re-exports of
  `Part`, `ResponseStream`, `Transport` and `SharedBuf` from `akio` (and `SharedBuf` from
  `akio-core`); `akio_h3::H3Error`; `Display`/`Error` for `InflateError`, `ProtocolError`
  (ws), `FrameError` (arpc) and `QpackError`; `akio_core::Error::source` returns the I/O error.
- Every public type implements `Debug`; builder methods are `#[must_use]`.

### Changed (breaking, with migration)

Config and report structs and the enums that may grow are now `#[non_exhaustive]`: struct
literals no longer compile outside `akio`. Start from `Default` (or a preset) and assign fields:

```rust
// before
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// after
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

Affected structs: `akio`: `Config`, `UringConfig`, `EbpfConfig`, `PoolConfig`, `PoolStats`,
`SlowCallback`, `UdpStats`, `ConnInfo`, `LoopMeta`, `LoopCounters`, `LoopMetrics`, `Metrics`,
`ReloadReport`, `SlowRecord`; `akio-tls`: `TlsInfo`; `akio-http`: `HttpConfig`, `H2Config`,
`H2Options`, `WsOptions`, `Request`, `Response`, `FileBody`, `ClientRequest`, `ClientResponse`,
`Cors`, `Compress`, `LogRecord`, `HttpSnapshot`; `akio-ws`: `WsConfig`, `DialOptions`, `PmdOffer`,
`PmdParams`, `ProtocolError`; `akio-grpc`: `CallOptions`, `Status`, `Metadata`; `akio-kcp`:
`KcpConfig`, `Stats`; `akio-h3`: `H3Config`; `akio-ebpf`: `AttachOptions`, `SteerInfo`, `Probe`;
`akio-arpc`: `proto::Message`. Enums (add a wildcard arm to `match`): `akio::Error`, `Part`,
`Backend`, `Accel`, `AccelStatus`, `akio_http::Method`, `Version`, `BodyMode`, `ClientError`,
`akio_ws::client::WsClientError`, `deflate::InflateError`, `akio_mux::Rule`,
`akio_arpc::CallError`, `proto::Cmd`, `akio_quic::Error`, `akio_h3::qpack::QpackError`,
`akio_kcp::KcpError`, `CloseReason`, `akio_ebpf::Steering`, `HashKey`, `Tier`.

Renames and signature changes:

| Crate | Before | After |
|---|---|---|
| `akio` | `Listener::serve_dyn(Arc<dyn DynAcceptor>)` (hidden) | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| akio-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor` (also `From<Mux> for AnyAcceptor`; pass the `Mux` to `serve_any` directly) |
| akio-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| akio-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| akio-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| akio-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| akio-ws | `client::connect(..)` (blocking) | `client::dial_blocking(..)` |
| akio-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| akio-arpc | `dial(..)` (blocking) | `dial_blocking(..)` |
| akio-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| akio-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)` (same name as `GrpcServer::compress`) |
| akio-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| akio-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| akio-h3 | `server(quic, service)` | `serve(quic, service)` |
| akio-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)` (config before service, as in `akio_http::serve_with`) |
| akio-h3 | `H3Config::max_body`, `max_field_section` | `max_body_bytes`, `max_field_section_bytes` |
| akio-h3 | `Result<Response, String>` from `request`, `request_blocking`, `get` | `Result<Response, H3Error>` (`Closed`, `Reset(code)`, `Protocol`, `Timeout`) |
| akio-kcp | `Config` | `KcpConfig` |
| akio-kcp | `KcpServer::new`, `dial`, `dial_conv`, `Crypt::new` returning `Result<_, String>` | `std::io::Result<_>` (`InvalidInput` for bad settings) |
| akio-kcp | `Kcp::stats: [u64; 4]` (public field) | private; use `Session::stats()` |
| akio-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| akio-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

Moved out of the covered API (now `#[doc(hidden)]`; backend-facing or test helpers that may change
in any release): `akio_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter,
telemetry::json_str, telemetry::prometheus_header}` and backend-only `Telemetry` methods,
`akio::{DynAcceptor, DynHandler}` re-exports, `akio_http::transport`, `akio_ws::WsSession`,
`akio_ebpf::{cbpf, SLOTS, slot_table, expected_index}`.

Versioning: all crates are at `1.0.0-rc.1` and depend on each other with exact (`=`) versions;
`akio-sys`, `akio-buf`, `akio-timer`, `akio-pool`, `akio-epoll` and `akio-uring` are internal
crates without a semver promise of their own (see docs/api-stability.md).

[Unreleased]: https://github.com/lesismal/akio/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/akio/releases/tag/v1.0.0-rc.1
