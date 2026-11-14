# KCP

`flash-kcp` provides reliable, ordered messages over UDP, wire-compatible with
[skywind3000/kcp](https://github.com/skywind3000/kcp) and with
[kcp-go](https://github.com/xtaci/kcp-go)'s FEC and encryption (so with kcptun and fib's kcp).
Interop with kcp-go v5 is tested in both directions for six crypt/FEC combinations, including
through a relay that drops every seventh datagram (`tools/interop/kcp/run.sh`).

## Server and client

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:config}}
```

```rust,ignore
{{#include ../../../../crates/flash-kcp/examples/guide-kcp.rs:client}}
```

- A `KcpServer` is the acceptor of a **UDP listener**. Each peer address that starts a
  conversation gets a `Session` and a `KcpHandler` from the factory; a new conversation id from
  the same address replaces the old session. `max_sessions(n)` caps them; `sessions()` counts
  them.
- `flash_kcp::dial(&engine, addr, cfg, handler)` starts a client session with a random
  conversation id (`dial_conv` to choose it). The engine needs `udp_client_threads(n)`. Messages
  may be sent right away.
- `KcpHandler::on_message(&mut self, &Session, Vec<u8>)` gets whole messages (in stream mode,
  whatever bytes arrived), in order, on the I/O thread; `on_close(&Session, CloseReason)` runs
  once with `Closed`, `DeadLink`, `Replaced` (the peer started a new conversation) or
  `Transport` (the UDP peer under it closed: the engine's `udp_idle_timeout`, an ICMP error,
  shutdown). An idle KCP session therefore ends after `Config::udp_idle_timeout` (60 s) unless
  the application sends keep-alives more often.
- `Session` (cloneable, any thread): `send(msg)` (fails with `KcpError::Full` when the send
  queue is full: queue or drop, never wait for it inside a callback), `close()`, `conv()`,
  `remote_addr()`, `is_open()`, `wait_send()`, `stats()` (sent, retransmitted,
  fast-retransmitted, lost, FEC-recovered).
- A session is driven by the datagrams its I/O thread reads, by one shared timer thread
  (scheduled by KCP's `next_flush`) and by `send`. Output is flushed on demand.

## `Config`

Both sides should agree on the KCP knobs and **must** agree on crypt and FEC.

| Field | Default | Meaning |
|---|---|---|
| `nodelay` | 0 | 1 = fast retransmission timing |
| `interval` | 100 | internal update interval, ms (10..=5000) |
| `resend` | 0 | fast resend after this many duplicate ACKs (0 off) |
| `no_congestion` | false | turn congestion control off |
| `send_window`, `recv_window` | KCP default | windows in segments |
| `mtu` | KCP default | largest datagram, framing included (at most 1500) |
| `stream` | false | stream mode (messages not preserved) |
| `dead_link` | 20 | transmissions of one segment before closing with `DeadLink` |
| `crypt` | none | `Crypt::new(name, key)`: `none`, `xor`, `aes` (32-byte key), `aes-128`, `aes-192`, `aes-128-gcm` |
| `data_shards`, `parity_shards` | 0, 0 | kcp-go Reed–Solomon FEC (kcptun uses 10/3); either 0 turns it off |
| `write_queue` | 0 | `send` fails beyond this many waiting segments (0 = twice the send window) |

`KcpConfig::fast()` is kcptun's "fast3": nodelay, 10 ms interval, resend after 2, no congestion
control. Keys are taken as already derived: kcptun derives them with PBKDF2-SHA1 from the
passphrase (salt `kcp-go`, 4096 rounds, 32 bytes).
