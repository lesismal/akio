# Security policy

English | [简体中文](SECURITY.zh-CN.md)

## Supported versions

`akio` is pre-1.0. Until 1.0.0 is released, only the latest commit on `main` receives fixes. From
1.0.0 on, the latest minor release of the current major version is supported; a security fix
is released as a patch version and, where it applies, back-ported to the previous minor
release for 3 months after a new minor release.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/lesismal/akio/security/advisories/new)
("Security" tab -> "Report a vulnerability"). Include:

- the affected crate(s), version or commit, OS/kernel and backend (epoll, kqueue, io_uring);
- a description of the issue and its impact (memory safety, denial of service, protocol
  smuggling, information disclosure ...);
- a minimal reproduction (code, packet capture or test case) if you have one;
- whether you want to be credited, and under which name.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of the report | within 3 working days |
| First assessment (accepted / needs info / not a vulnerability) | within 7 days |
| Fix or mitigation for accepted reports | within 30 days for high/critical severity, best effort otherwise |
| Public advisory | when the fix is released, coordinated with the reporter |

Accepted issues are published as GitHub Security Advisories and submitted to the
[RustSec advisory database](https://rustsec.org/), so `cargo audit` / `cargo deny` users are
warned. We follow coordinated disclosure: please give us a reasonable time to ship a fix before
publishing details (90 days by default, shorter if the issue is already being exploited).

## Scope

In scope: every crate in this repository (`crates/*`), including memory-safety bugs in `unsafe`
code (see [docs/unsafe-review.md](docs/unsafe-review.md)), parser and protocol state-machine bugs
(HTTP/1, HTTP/2, HTTP/3, WebSocket, KCP, QUIC glue, SOCKS5, gRPC, mux) that a remote peer can
trigger, resource exhaustion that bypasses the documented limits, and TLS configuration defaults.

Out of scope: the benchmark and interop tools under `tools/`, vulnerabilities in dependencies
that do not affect `akio`'s use of them (report those upstream; we track them with `cargo deny`),
and denial of service that needs more resources than the configured limits allow.

## Hardening already in place

- `cargo deny check` (RustSec advisories, licenses, duplicate versions, sources) and
  `cargo audit` in CI; see [deny.toml](deny.toml).
- `unsafe` is confined to `akio-sys`, `akio-uring` and `akio-ebpf`'s `sys` module; every other
  crate is `#![forbid(unsafe_code)]`. Each `unsafe` block states its invariant in a `SAFETY:`
  comment, enforced by Clippy. Review procedure: [docs/unsafe-review.md](docs/unsafe-review.md).
- Miri on the pure-Rust crates, loom on `akio-core`'s concurrency primitives, fuzzing of the
  protocol parsers, AddressSanitizer and ThreadSanitizer over the workspace tests
  ([tools/sanitizers](tools/sanitizers/README.md)).
