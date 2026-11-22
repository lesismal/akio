# ADR-067: Kernel TLS for engine connections, hardware-first

English | [简体中文](067-kernel-tls-engine-offload.zh-CN.md)

Status: accepted (2026-11-21)

## Context

The kTLS evaluation of 2026-11-16 (docs/BENCHMARKS.md, "Kernel TLS (kTLS) evaluation") found
Linux 7.0's software kTLS slower than akio-tls's own record layer in every case measured (0.40x
to 0.83x), so the offload stayed behind the experimental `experimental-ktls` feature: a
blocking test stream, a benchmark and an interop mode, not wired into `Tls` or the engine.

What that left out: NICs that do the record crypto themselves (TLS device offload, `ethtool -k`
`tls-hw-tx-offload` / `tls-hw-rx-offload`; NVIDIA ConnectX-6 Dx and later, some Intel and
Chelsio parts). There the kernel hands plaintext records to the NIC, the CPU does no AES-GCM,
and `sendfile` really is zero-copy. A server cannot get that without kTLS in the engine.

Constraints: no slowdown anywhere by default; no change for connections that do not ask for
kTLS; no vendor-specific code (the kernel's device-offload interface only); the hot paths of
`send`, `on_data` and the loops cost nothing measurable when kTLS is off or not taken.

## Decision

### 1. Policy: `akio_tls::Ktls`

`ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` take:

- `Off` (default): nothing changes.
- `Hardware`: offload only what a NIC does itself. The send direction when the interface that
  owns the connection's local address has `tls-hw-tx-offload` on, the receive direction too when
  it also has `tls-hw-rx-offload`; AES-GCM only. The interface table (`getifaddrs` plus the
  ethtool `SIOCETHTOOL` feature ioctls, no privilege needed) is cached for 30 s; while no
  interface offloads TLS, a new connection reads two relaxed atomics and keeps no kernel TLS
  state at all, exactly as under `Off` (the key derivation for the kernel happens only once a NIC
  is known to take the connection). After installing
  a direction, the kernel's `TlsTxDevice` / `TlsRxDevice` counters (read around the install
  under a process-wide lock) confirm the NIC took it. If the kernel fell back to software (the
  driver lacks this version or key size), that interface, version and AEAD are remembered and
  not offered to the NIC again, so at most one connection per combination runs in software.
- `Software`: always, both directions (software kTLS where no NIC helps). Slower on current
  CPUs; for comparisons, CPUs where the kernel's AES-GCM wins, and sockmap setups.
- `SoftwareTx`: the send direction only.

`ktls_zerocopy_sendfile(true)` sets `TLS_TX_ZEROCOPY_RO` on device-offloaded connections (the
NIC reads `sendfile` pages straight from the page cache; the files must not change mid-send).
TLS 1.3 needs Linux 6.14 (key updates of offloaded directions); otherwise TLS 1.3 connections
stay in user space. The `ktls` cargo feature compiles the offload in (`experimental-ktls` is
kept as its alias); without it, or off Linux, every mode behaves as `Off`.

### 2. Engine hooks (akio-core)

`Transport` gains default methods, all Linux-only:

- `wants_offload` / `offload(fd, local, rx_ok) -> Offloaded { tx, rx }`: the engine offers the
  TCP socket on the owning I/O thread, between reads, with nothing queued for writing, while
  the transport wants it. A connection whose transport never wants it never pays more than one
  relaxed atomic load per flush.
- Send direction in the kernel: application bytes skip `seal` and go to the socket as they are;
  `send_file` uses `sendfile(2)` again instead of reading through memory; `kernel_send(len)`
  lets the transport schedule a TLS 1.3 key update before the bytes. Control records (alerts,
  KeyUpdate, close_notify, NewSessionTicket answers) and new send keys become `SocketOp`s,
  queued in order with the data (`Bytes::Op`, writes stop in front of them).
- Receive direction in the kernel: `on_data` receives what is read as it is; a read failing with
  `EIO` means a control record is next, which the loop reads with `recvmsg` and its record-type
  control message (`ConnInner::kernel_read_record`) and hands to `Transport::kernel_record`;
  a peer's KeyUpdate installs the new receive keys right away. close_notify ends the stream as an
  EOF does.

The receive direction may only move when no read can hold bytes the transport has not seen:

- epoll reads only between the loop's flushes, so it allows it at once (`set_rx_offload_ok`).
- io_uring has a multishot recv in flight: once the send direction moved, the loop cancels the
  recv, and when the cancel has landed with nothing held, calls `offload_rx_now` and re-arms
  (at most 8 attempts per connection; a stream that never stops on a record boundary keeps its
  receive direction in user space). An `-EIO` completion is handled as on epoll.
- The read buffer must take a whole record (`read_buffer` of 16 KiB or more); otherwise only the
  send direction moves.

### 3. akio-tls

- The protocol core can move the send direction alone (`commit_tx_offload`): from then on what it
  sends (handshake messages, alerts, its key updates) comes out as events instead of sealed bytes,
  while records are still opened in user space; the receive direction follows later
  (`commit_rx_offload`) when nothing partial is buffered.
- `TlsTransport` keeps a per-connection `KtlsState` (only when the mode is not `Off`): attach the
  `tls` ULP, install and verify the send keys, then the receive keys (TLS 1.3:
  `TLS_RX_EXPECT_NO_PAD`), count each install in `TlsStats` (`akio_tls_ktls_total{side, dir,
  path}`) and report it in `TlsInfo::ktls_tx` / `ktls_rx` (`KtlsPath::Software` /
  `Hardware`). If the kernel refuses (no module, unsupported suite), nothing changed and the
  connection carries on in user space.

### 4. Not done

- DPDK, QUIC and DTLS: no kernel socket or no TCP record stream.
- A receive direction without the send direction (a NIC with RX offload only): not offloaded.
- Undoing an offload that landed in software under `Hardware` (the kernel cannot detach the ULP):
  that connection keeps software kTLS, and the combination is not tried again.
- Hardware validation: the test host has no TLS-offload NIC (igc, atlantic). The device path is
  covered by the kernel interface it uses and by unit tests of the detection logic; it must be
  measured on real hardware before claims are made about it.

## Consequences

- The default build and `Off` are unchanged in behaviour and, measured, in speed (docs/BENCHMARKS.md,
  "Kernel TLS in the engine").
- On a NIC with TLS offload, `Hardware` removes the record crypto from the CPU and makes
  `sendfile` zero-copy for TLS connections, without risking a slowdown on other hosts.
- `Transport` implementors outside the workspace are unaffected (default methods).

## Tests

- `crates/akio/tests/ktls.rs` (epoll and io_uring, `--features ktls`): software kTLS both ways
  and send-only, TLS 1.3 and 1.2 with AES-GCM and ChaCha20-Poly1305, 6 MiB echoes, peer key
  update requests (20 in a row), server-initiated key updates every 16 records, `sendfile`
  through the kernel, close_notify both ways, an `akio` client with kTLS, and `Hardware` / `Off`
  staying in user space on loopback. The kernel's counters confirm the installs and rekeys
  (`TlsTxSw`, `TlsRxSw`, `TlsRxRekeyOk`, `TlsTxRekeyOk`; no `TlsDecryptError`).
- akio-sys: the ethtool feature lookup against `ethtool -k lo`, `/proc/net/tls_stat` parsing;
  akio-tls: the interface table lookup (IPv4, IPv6, IPv4-mapped, refused combinations).
- The existing stream tests and `tools/interop/tls/run.sh` with `AKIO_INTEROP_KTLS=require`
  (175/175 against OpenSSL 3.0.13 and Go); curl and `openssl s_client` against `http-bench` with
  software kTLS on epoll and io_uring (TLS 1.3 / 1.2, AES-GCM / ChaCha20-Poly1305, a client
  KeyUpdate with update_requested: 10/10).
- Performance (`tools/bench/ktls-engine.sh`, docs/BENCHMARKS.md "Kernel TLS in the engine"):
  handshakes/s and HTTPS req/s of the default build and of `Hardware` without a NIC within 0.5%
  of main on both backends; software kTLS 0.77x on HTTPS.
