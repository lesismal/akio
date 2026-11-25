# ADR-129: akio-prefork removed

English | [简体中文](129-akio-prefork-removed.zh-CN.md)

Status: accepted (2026-11-25). Supersedes the akio-prefork parts of
[ADR-028](028-hot-reload-buffers-backlog-threads.md) and
[ADR-063](063-shared-steering-migration-af-xdp.md).

## Context

`akio-prefork` (M6, optional) served one program from several worker processes: a supervisor
re-executed the binary as workers, shared the listeners through `SO_REUSEPORT` or an inherited
socket, restarted crashed workers, drained them on SIGTERM, swapped generations on SIGHUP, reloaded
in place on SIGUSR1 (ADR-028) and, with `Prefork::bpf_steering`, kept one BPF steering program
over every worker's sockets so a reload reset no connection (ADR-063).

akio and akit do not use prefork: Rust has no garbage collector whose pauses several processes
would hide, one engine already uses every core, and akit reloads its configuration in one process.
Earlier on 2026-11-25 the crate was put on hold (cb49a04b): it still built, but CI's workspace
test steps, the sanitizer runs and whole-suite runs left it out with `--exclude akio-prefork`, and
whether to delete it was left open. Code that no test runs and nobody uses only costs review,
builds and API surface, and silently rots.

## Decision

Delete `akio-prefork`, and with it everything that existed only for it. Each item was checked
with a search of the workspace (crates, tests, examples, tools, fuzz targets, docs) and of akit;
only items with no other user were removed.

Removed:

- The crate `crates/akio-prefork` (supervisor, workers, `Prefork`, `BpfSteering`,
  `ListenMode`, `Controller`, `Supervisor`, `Status`, `WorkerInfo`, `Worker`, `CpuPinning`), its
  example `prefork-http`, its tests (`prefork`, `bpf`), its READMEs, its workspace entry, its API
  snapshot `api/akio-prefork.txt`, the book chapter "Multi-process serving (prefork)" (en and
  zh-CN) and the references to it (README crate tables, book crate tables, the reload section of
  the observability chapter, `book/check-guides.sh`, docs/api-stability, the semver-checks list
  and `--exclude akio-prefork` in CI, `tools/sanitizers/run.sh`, `tools/api/public-api.sh`,
  rule 18's note).
- `akio::EbpfConfig::shared` and its branch in the engine's steering setup: only akio-prefork's
  workers set it. `EbpfConfig` is `#[non_exhaustive]`, so the field could not be set in a struct
  literal; code that assigned it no longer compiles.
- From `akio_sys::process`: `ChildSetup`, `configure_child` (the `pre_exec` hook: inherited fds,
  `PR_SET_PDEATHSIG`, CPU affinity of the child), `take_inherited_fd`, `reserve_reuseport` (and
  the crate-private `net::bind_reuseport` behind it), `SIGQUIT` and `SIGUSR1`. From the hidden
  `akio_sys::ffi`: `prctl`, `PR_SET_PDEATHSIG`, `getpid`, `getppid`, `ESRCH`, `SIGQUIT`,
  `SIGUSR1` (and their layout checks). Six `unsafe` blocks fewer in akio-sys.

Kept, with only the prefork wording removed from their docs:

- `Listener::tcp_from_std`: serves a listening socket passed by systemd socket activation,
  inherited from a parent process or bound with options akio does not set.
- `akio_ebpf::SharedSteering` (and `expected_index`, `HashKey`, `SteerInfo::shared`): a
  standalone akio-ebpf API with its own tests (`crates/akio-ebpf/tests/shared.rs`: shared slots,
  accept-queue and pending-handshake migration on Linux 5.14+). Nothing in akio wires it to a
  listener any more; a program that shares a `SO_REUSEPORT` group across processes can still use
  it directly.
- `akio_sys::process::{allowed_cpus, pin_current_thread}`: the engine's NUMA placement,
  `EbpfConfig::pin_threads`, akio-epoll and akio-uring pin threads with them.
- `akio_sys::process::{signal_pipe, kill, SIGHUP, SIGINT, SIGTERM, SIGUSR2}`: akit's main loop
  turns SIGHUP/SIGINT/SIGTERM into bytes with `signal_pipe`, and akit's integration tests signal
  the binary with `kill`; `SIGUSR2` is what `signal_pipe`'s own test raises.

## Alternatives

- **Keep it frozen** (the state after cb49a04b): no tests, no fixes, still built and published.
  Rejected: an untested public crate still claims to work, keeps `EbpfConfig::shared` and the
  process plumbing in other crates' public APIs, and every change to the engine or akio-sys would
  have to keep it compiling. If prefork is wanted again, the crate is in git history (last at
  2bced7f3) and can come back with an ADR and tests.
- **Remove the crate but keep `EbpfConfig::shared` and all of `akio_sys::process`.** Rejected:
  nothing else used them, and an API kept "in case" is the same frozen code in a smaller form.

## Consequences

- One crate fewer to build, test, document and publish; akio-sys has a smaller unsafe surface.
- Removed public items (above) are a breaking change for any outside user; there is none known,
  and the workspace is before 1.0.0. The API snapshots of akio and akio-sys were
  regenerated.
- Multi-process serving is not offered: run several processes behind a load balancer, or one
  engine with more I/O threads.
