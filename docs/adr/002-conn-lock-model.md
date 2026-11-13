# ADR-002: Conn handle and lock model

English | [简体中文](002-conn-lock-model.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

`Conn<H>` is a `Clone + Send + Sync` handle over `Arc<ConnInner>`. `ConnInner` holds a generation id, the owner loop's wake channel, atomic state bits, and a `Mutex<WriteState>` (send queue, cork, watermark, close state).

On the I/O thread `send` writes directly when the queue is empty, otherwise enqueues and arms writability. From other threads `send` locks, enqueues, and wakes the owner loop (eventfd / uring `MSG_RING`). Locks guard only the send queue and are **never held while calling user code**. Operations on a closed connection return `Error::Closed`.

## Consequences

- Cross-thread send/close is safe without exposing the loop to users.
- Lock scope is tiny and callback-free, which rules out lock-inversion deadlocks; verified with `loom` in M1.
- The generation id prevents acting on a recycled fd/slot.
