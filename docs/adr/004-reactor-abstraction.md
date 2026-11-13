# ADR-004: Reactor abstraction and per-listener backends

English | [简体中文](004-reactor-abstraction.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

Each backend implements an internal `Reactor` trait (accept, read, write, timer, wake, close). Protocol crates depend only on `Conn`/`Handler`. `Listener::backend(..)` selects the backend per listener; the Engine runs one I/O thread group per backend in use (size configurable per listener, default one per core). The logical pool, timers and buffer pool may be shared engine-wide.

Data ownership: `on_data(&[u8])` is a borrow valid only until the callback returns (epoll: loop buffer; io_uring: provided-buffer-ring entry; DPDK: mbuf). io_uring falls back to epoll when required kernel features are missing; a kqueue implementation backs macOS/BSD for development.

## Consequences

- Mixed-backend engines are possible (e.g. io_uring HTTP + epoll RPC + DPDK UDP).
- Borrowed reads keep all backends zero-copy; keeping data requires an explicit copy.
- The trait is internal until 1.0 and may change; the public surface is `Backend`/`Listener`.
