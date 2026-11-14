# ADR-005: Dependency policy

English | [简体中文](005-dependency-policy.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

Core crates (`only-core`, `only-buf`, `only-timer`, `only-pool`) are close to dependency-free; `libc` is allowed for `only-sys`. Mature **sans-io** crates are reused behind feature flags rather than rewritten: `rustls` (TLS), `quinn-proto` or `quiche` (QUIC, decided in M5 after evaluation), `aya` (eBPF), `io-uring` (or a thin in-house wrapper). No in-house cryptography. Protocol state machines we own (HTTP/1, HTTP/2, WebSocket, KCP) are sans-io and fuzzed.

## Consequences

- Security and schedule win over fib's zero-dependency stance.
- Each added dependency needs an ADR note and passes `cargo-deny`/`cargo-audit` in CI (added by 1.0).
- `unsafe` is confined to `only-sys`, the backends and `only-buf`; all other crates `#![forbid(unsafe_code)]`.
