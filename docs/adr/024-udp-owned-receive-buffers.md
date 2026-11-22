# ADR-024: Owned UDP receive buffers and keyed peer tables

English | [简体中文](024-udp-owned-receive-buffers.zh-CN.md)

Status: accepted (2026-11-17)

## Context

After the QUIC datapath pass (DEV-PLAN, M5) a received QUIC datagram still crossed memory twice:
the UDP loop received it into a `recvmmsg` slot (one contiguous buffer per batch), lent it to the
handler as `&[u8]`, and akio-quic copied it into a pooled buffer to decrypt it in place and share
it with the `Bytes` of its frames. `on_data(&[u8])` cannot do better: the slot is reused by the
next `recvmmsg`, so whatever outlives the call must be copied out. The peer tables of the UDP loop
(`HashMap<SocketAddr, u64>`, looked up once per datagram) still hashed with SipHash, which the
earlier akio-quic profiles had shown at ~2% of a receiving thread.

## Decision

**Receive slabs (`akio_buf::slab`, `#[doc(hidden)]`).** One heap allocation viewed through
disjoint owned handles: `ChunkMut` (exclusive, writable range; `split_to`, `truncate`, `freeze`),
`Chunk` (shared, read-only range; `Clone` is a reference-count increment) and `SlabPool` (hands
out a whole slab as a `ChunkMut`, reuses a slab once every handle on it has dropped, on any
thread; bounded). This is the crate's only `unsafe` (`#![deny(unsafe_code)]` with the module
allowed): memory is reached only through the allocation's raw pointer, never a reference to the
whole slab, and the module invariant (live `ChunkMut` ranges are disjoint from each other and from
live `Chunk` ranges) is kept by construction: a `ChunkMut` comes only from a slab nobody else
references (`Arc::get_mut`) or from splitting another `ChunkMut`, a `Chunk` only from freezing
one. Covered by Miri (including a cross-thread drop under the data-race detector) and a loom
model of reuse after a remote drop.

**Receive path.** `akio_sys::RecvBatch` receives each slot into the free tail of its own slab,
two slot sizes (`2 × Config::read_buffer`) long. A datagram is read in place (`get`, as before)
or cut off the slab (`take`, returning a `ChunkMut`); the slot goes on receiving into the rest of
its slab, and into a fresh or freed one from the batch's pool once less than a slot size is
left. Small datagrams thus pack densely: a datagram that is kept pins its slab (at most
`2 × read_buffer`), not a whole batch, and keeping many datagrams costs at most about twice their
size. The loops without `recvmmsg` (macOS) do the same with one slab-backed buffer.

**Handler hook.** `Handler` gets two hidden items: `const OWNED_DATA: bool = false` and
`fn on_data_owned(&mut self, c, data: akio_buf::slab::ChunkMut)` (default: `on_data(c, &data)`).
The UDP loops of the epoll backend (which also serve io_uring and kqueue UDP) ask once per
connection (`DynHandler::wants_owned`) and, for a handler that set `OWNED_DATA` and has no
transport layer, hand each datagram (each GRO segment) over owned. Every other handler reads in
place exactly as before, with no reference counting.

**akio-quic.** `Udp` sets `OWNED_DATA`. A datagram that reaches a connection goes in as
`PktBuf::Chunk` (an internal enum beside the pooled `PktBuf::Vec`): header protection is removed
and the packet decrypted in its own slab range, which is then frozen, and the frames' `Bytes` are
slices of it (`Bytes` gains a private `Chunk` representation; its size is unchanged). Coalesced
packets (handshakes) are still copied into pooled buffers, as before; new connections still get a
pooled copy of their first datagram.

**Keyed peer tables.** The keyed folded-multiply hasher akio-quic introduced for its CID and
address tables (`KeyedHash`: three random words per table, a 64×64→128-bit folded multiply per
word, a keyed final fold) moves to `akio_core::hash` (`#[doc(hidden)]`) with `KeyedMap` /
`KeyedSet`, and the UDP loops' peer tables (`SocketAddr` → connection) use it. Tables of our own
ids (bound sockets, blocked peers) use `IdHasher`. HashDoS resistance is kept where a peer
chooses the key: the key never leaves the process, enters both operands of every multiply, and
differs per table.

## Alternatives considered

- **Keep copying (quinn does)**: quinn copies each datagram out of its receive buffer into a
  `BytesMut`; the copy is the cost this ADR removes.
- **One slab per batch, or a whole slab per slot without carving**: a kept datagram would pin the
  batch (32 × 64 KiB) or a 64 KiB slot for 1.2 KB of data, up to 50× the memory of what is kept.
- **Decrypt every packet of a batch first, then process**: keys can change between packets of a
  batch (a handshake installs new ones), so ordering would break.
- **Unsafe in akio-sys or a new crate**: akio-quic needs the handle types for `Bytes`, and akio-buf
  is already the buffer crate every layer depends on; the unsafe stays one small audited module.
- **A public API**: the hook and the slab types stay `#[doc(hidden)]` (like `on_batch_end`), so
  they can change with the datapath; the public API snapshots do not change.

## Consequences

- No change to the public API or its snapshots; `akio-buf` moves from `forbid` to `deny`
  `unsafe_code` with one allowed module (docs/unsafe-review.md).
- QUIC: no copy of a 1-RTT datagram between the kernel and the frames handed to the application.
- Memory: each UDP loop keeps one slab per `recvmmsg` slot (32 × 2 × `read_buffer`, 4 MiB with
  the defaults, untouched pages cost nothing) plus up to half as many for reuse, where it kept one
  32 × `read_buffer` buffer before. Application code that keeps received QUIC `Bytes` for long
  pins the slab they came from; copy them (`Bytes::copy_from_slice`) to keep them indefinitely.
- Benchmarks (gpu51, same-run A/B against `ab65d376`, docs/BENCHMARKS.md, "After the UDP owned
  receive buffers"): bulk 1.00, HTTP/3 1.01, handshakes 1.00, UDP echo 1.00 req/s and server CPU
  per request. On loopback the saved copy and hash are within noise; nothing regressed.
