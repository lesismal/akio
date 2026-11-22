# Sanitizer runs

[中文](README.zh-CN.md)

AddressSanitizer (with LeakSanitizer) and ThreadSanitizer over the workspace tests. They cover
what Miri cannot run: syscalls (sockets, epoll, io_uring, signals), the I/O threads, and the
hardware crypto paths. The CI job `sanitizers` (`.github/workflows/ci.yml`) runs the same script.

```bash
tools/sanitizers/run.sh --docker address            # Linux container (Docker Desktop on macOS)
```

```bash
AKIO_TEST_BACKEND=uring tools/sanitizers/run.sh --docker thread akio-uring akio akio-ws
```

```bash
tools/sanitizers/run.sh thread akio-sys akio-crypto  # natively, on Linux with nightly + rust-src
```

With no crate names, every workspace member with a library or test target is run, except
`akio-dpdk` (needs libdpdk). Each crate is one `cargo test --lib --tests -- --test-threads=1`;
the script prints `crate rc=… reports=… seconds` and keeps one log per crate in
`target/sanitizers/<sanitizer>[-<backend>-docker]/` (or `$SAN_LOG_DIR`). A crate fails on a
test failure, a sanitizer report (`halt_on_error`) or after `SAN_TIMEOUT` seconds (default 1800).

## What the script sets, and why

| Setting | Why |
|---|---|
| `-Zbuild-std`, `-Zsanitizer=<san>` | TSan must see std's atomics and locks, so std is rebuilt instrumented. |
| `RUSTC_WRAPPER=rustc-wrapper.sh` | Builds `compiler_builtins` without the sanitizer. On aarch64 the sanitizer runtimes call its outline-atomics helpers (`__aarch64_swp1_acq`, …) during their own start-up; instrumented, those call back into the uninitialised runtime and every test binary crashes with SIGSEGV before `main` (`__tsan::TraceSwitchPart` under `__tsan::Initialize`). No effect on x86_64. |
| `-Cunsafe-allow-abi-mismatch=sanitizer` | Needed once `compiler_builtins` differs from the rest; it holds no code that touches program memory the sanitizers track. |
| `AKIO_TEST_TIMEOUT_SCALE=10` | Tests with fixed event deadlines multiply them by it: TSan slows a debug build 5–15×. Used by `akio-ws/tests/client.rs`. |
| `ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1:…` | Leaks and stack use-after-return on top of the defaults. |
| `TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1` | First report fails the crate, with both stacks of a lock-order inversion. |
| `lsan.supp`, `tsan.supp` | Suppressions. Empty: nothing needed suppressing. Every entry added must state its reason. |

`--docker` builds `Dockerfile` (nightly, `rust-src`, `llvm-symbolizer`) and runs the script in it
with the checkout mounted. It adds `--security-opt seccomp=unconfined` (Docker's default profile
blocks `io_uring_setup`) and `--ulimit memlock=-1`: io_uring charges rings and buffer rings to
the user's `locked_vm`, which every container running as root on the host shares, against the
container's `RLIMIT_MEMLOCK` (8 MiB in Docker on Linux), so with other io_uring tests running next
to it ring setup failed with `ENOMEM`. Cargo's target directory is the volume
`akio-san-target-<san>` unless `SAN_TARGET` names another (a host path works). On a shared
benchmark host, `SAN_NICE=19` runs the container's tests niced and `SAN_DOCKER_ARGS` adds flags
such as `--cpu-shares=64`; `SAN_PLATFORM=linux/arm64` pins the image's platform.

## Limits

- `asm!` blocks are not instrumented: the hardware crypto kernels' own loads and stores are
  unchecked. ASan does check the Rust code around them that computes the pointers and lengths,
  and the kernels are compared against the portable code by the unit tests these runs execute.
- ThreadSanitizer sees only what the program does through instrumented code and intercepted
  calls. Memory the kernel shares with io_uring (rings, buffer rings) is synchronised by the
  kernel, which TSan cannot see; races there are Miri's and loom's job (`BufRing`, `KernelBuf`
  and `akio-core` tests).
- Under TSan, a signal handler runs only once its thread enters an intercepted call. A
  process-directed signal can land on a thread blocked in a raw `futex` syscall (std's locks
  and channels), which TSan does not intercept, and is then never handled. Tests that need a
  handler to run raise the signal on the thread that waits for it.

## First run (2026-11-16)

Nightly 1.102.0 (2026-11-13). arm64: Docker Desktop on macOS (linuxkit 6.12). x86_64: Docker on
a Zen 4 host (kernel 7.0; AVX-512, IFMA, VAES, BMI2/ADX, so the x86 assembly paths ran), crates
with unsafe code and the engine backends.

| Run | Crates | Result |
|---|---|---|
| ASan, arm64, epoll | all 36 | clean, 1003 tests |
| ASan, arm64, io_uring | akio-uring, akio, akio-http, akio-prefork, akio-socks, akio-ws | clean |
| TSan, arm64, epoll | all 36 | clean after the fixes below (one thread leak, item 5) |
| TSan, arm64, io_uring | as for ASan | clean after the fixes below |
| ASan + TSan, x86_64, epoll | akio-sys, akio-buf, akio-crypto, akio-core, akio-epoll, akio-pool, akio-timer, akio | clean |
| ASan + TSan, x86_64, io_uring | akio-uring, akio | clean |

No memory error, memory leak or data race was reported. What the runs turned up:

1. Every sanitized binary crashed at start-up on aarch64 with `-Zbuild-std`, the SIGSEGV that
   docs/unsafe-review.md had put down to the Docker VM's address space (plain
   `-Zsanitizer=address` without `-Zbuild-std` runs fine there): fixed by `rustc-wrapper.sh`.
2. `akio-sys` `process::tests::signal_to_pipe` hung under TSan (the signal limit above): the
   test now raises the signal on its own thread and checks `kill(2)` with signal 0.
3. `akio-ws` `large_and_fragmented_messages_and_limits` hit its 10 s event deadline under TSan
   (8 MiB with permessage-deflate in a debug build): deadlines now scale with
   `AKIO_TEST_TIMEOUT_SCALE`.
4. io_uring ring setup failed with `ENOMEM` in Docker on the x86_64 host: `--ulimit memlock=-1`.
5. TSan reported a **thread leak** in `akio-bittorrent` (`tests/swarm.rs`): `Client::close`
   shut the engine and the disk pool down without waiting, so it returned while their threads
   could still run callbacks (and `Storage` calls), and dropping the client detached them. It now
   waits for the I/O threads, the disk pool and the maintenance thread.
6. Waiting exposed a second problem: akio-http's client kept idle keep-alive connections open
   through the engine's graceful shutdown, so `Engine::wait` (and now `Client::close` with an
   HTTP tracker) sat out the whole `shutdown_timeout`, 10 s by default. Idle client connections
   now close on shutdown, and one with a request in flight closes after its response
   (regression test `engine_shutdown_does_not_wait_for_idle_keep_alive_connections`).
7. The CI job covered only eight crates and missed `akio-crypto`'s hardware paths; it now runs
   the whole workspace through this script.
