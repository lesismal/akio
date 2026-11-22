# ADR-029: `AKIO_DEFAULT_BACKEND` selects io_uring for listeners without a backend

English | [简体中文](029-default-backend-env.zh-CN.md)

Status: accepted (2026-11-17)

## Context

A listener's backend is chosen in code (`Listener::backend`, ADR-004); without that call it is
epoll (kqueue on macOS). The test suite runs the engine on io_uring through `AKIO_TEST_BACKEND=uring`,
but that variable is read by the individual test files, which then call `.backend(..)` themselves.
Programs that never choose a backend, the book's `guide-*` examples among them, therefore cannot
be run on io_uring without editing them. Running every guide example on epoll and on io_uring
(`book/check-guides.sh`) needs a switch outside the program.

`akio` already has environment knobs for platform features that tests and operators need to turn
without a rebuild: `AKIO_CRYPTO_PORTABLE`, `AKIO_UDP_GSO`, `AKIO_UDP_GRO`, `AKIO_UDP_ECN`.

## Decision

`akio::Engine::build` reads `AKIO_DEFAULT_BACKEND` once per build, on Linux only:

- `uring` or `io_uring`: every **TCP** listener that did not call `Listener::backend` is served by
  `Backend::IoUring(UringConfig::default())`, which is not strict: where the kernel or a sandbox
  lacks io_uring the listener falls back to epoll and logs a warning, exactly as an explicit
  non-strict io_uring listener does.
- Unset, empty or `epoll`: no change. Any other value is ignored with a warning.
- A backend chosen with `Listener::backend` always wins, whatever it is (an explicit
  `Backend::Epoll` stays epoll). UDP listeners (served by the epoll UDP backend in every case)
  and `client_threads` / `udp_client_threads` groups are not affected.
- On other platforms the variable is ignored.

It is documented as a test and diagnostic knob in the configuration reference, not as a tuning
setting: production code that wants io_uring says so with `Listener::backend`.

No public item changes: `Listener` gains a private field recording whether `backend` was called.
The variable is read at build time only; the I/O paths are untouched.

## Alternatives

- Make `AKIO_TEST_BACKEND` itself drive the default. Rejected: it would change what the existing
  `uring` test leg runs (every test file with a default listener would switch), which is a separate
  decision; a distinct name keeps the test suite's behaviour as it is.
- Have each guide example read a variable and set the backend. Rejected: it adds plumbing to every
  snippet the book shows, and other programs would still have no switch.
- Change `Backend::default()` to a new `Auto` variant. Rejected: a public API change for a test
  need.

## Consequences

- `AKIO_DEFAULT_BACKEND=uring book/check-guides.sh` runs every guide example on io_uring; the
  script fails an example whose engine fell back to epoll.
- Hot path: the variable is read in `build` only. On gpu51 the release `echo` binaries built
  from main and from this change have identical `akio_core` / `akio_epoll` machine code (54,412
  instructions, addresses normalized); a same-run echo A/B (12 rounds) was within the machine's
  noise (total 0.98x, rounds 0.83-1.11x).
- Test: `crates/akio/tests/default_backend.rs` (Linux) runs child processes with the variable unset,
  `epoll`, `uring`, `io_uring` and an unknown value, and checks that the default TCP listener
  follows it while an explicit `Backend::Epoll` listener and a UDP listener do not.
