# ADR-035: ECN on macOS and over the userspace stack's UDP

English | [简体中文](035-ecn-macos-and-userspace-udp.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`akio-quic` implements ECN (RFC 9000 section 13.4, RFC 9002 section 7.1): ECT(0) on sent
packets, ACK_ECN counts, a ten-packet testing period, validation of the peer's counts with
fallback, CE marks as congestion events. Compatible version negotiation (RFC 9368, v1 to v2
within one handshake, ADR-013 and ADR-014) is also done. The crate's README still listed both as
gaps; what was really missing is the codepoint plumbing below QUIC outside Linux:

- **macOS**: the kqueue UDP loop received with `recv_from` and sent with `send_to`, so no
  codepoint went out or came in, and `akio-quic` did not even try ECN there.
- **Userspace stack** (`akio-dpdk`): its UDP built every IP header with TOS 0 and dropped the
  codepoint of received packets; `Conn::send_segments_ecn` dropped the codepoint for a virtual
  socket. A QUIC connection over it on Linux tried ECN, failed validation and fell back.

## Decision

1. **akio-sys, macOS** (new `udp_mac` module): `enable_ecn` (`IP_RECVTOS` and
   `IPV6_RECVTCLASS`), `ecn_available` (`AKIO_UDP_ECN=0` turns it off, as on Linux),
   `recv_from_ecn` (one `recvmsg`, the codepoint from an `IP_RECVTOS` / `IP_TOS` byte or an
   `IPV6_TCLASS` int) and `send_to_ecn` (one `sendmsg` with an `IP_TOS` / `IPV6_TCLASS` int
   control message; an IPv6 socket reaches an IPv4 peer at its IPv4-mapped address). The same
   names as the Linux functions where they mean the same. The control data is built and parsed
   as plain bytes, bounded by `msg_controllen`: only `recvmsg`, `sendmsg`, `setsockopt` and
   two zeroed `sockaddr_storage`s are `unsafe` (5 blocks; `msghdr` and `cmsghdr` are checked
   against `libc` in the layout tests). XNU honours the per-message codepoint on IPv4, IPv6 and
   dual-stack sockets (tested on loopback).
2. **akio-epoll on macOS** receives with `recv_from_ecn` on server and dialed sockets (a
   `recvmsg` instead of a `recvfrom`: the same one system call per datagram) and enables
   `IP_RECVTOS` on every UDP socket. **akio-core on macOS** sends a datagram that carries a
   codepoint with `send_to_ecn`; unmarked datagrams still go out with `send_to` / `send`.
3. **akio-dpdk**: `Iface::udp_send_ecn` writes the codepoint into the IPv4 TOS / IPv6 traffic
   class; received datagrams keep the codepoint of their IP header (of the last fragment when
   reassembled), reported through `Conn::rx_ecn` like the kernel loops. akio-core gains the
   hidden `ConnInner::drain_output_ecn` (the loop drains datagrams with their codepoints) and
   keeps codepoints for any datagram socket, kernel or virtual.
4. **akio-quic** tries ECN on Linux and macOS (`AKIO_UDP_ECN=0` still turns it off); over
   akio-dpdk the codepoints now arrive, so validation succeeds where the path carries them.
   Nothing changes in the protocol logic.
5. The `quic_conn` fuzz target gets a path mode chosen by the input (keep, bleach, CE-mark,
   re-mark ECT(1)) applied to every datagram the pair exchanges, plus a datagram with a fuzzed
   codepoint. Before, the pair delivered every datagram unmarked, so ECN validation and the CE
   response were never reached by the fuzzer.

## Consequences

- Public API: macOS-only additions to `akio-sys` (not in the Linux API snapshots); the rest is
  hidden (`akio-core`'s `ConnInner`) or crate-private (akio-dpdk's `Iface`). No snapshot change.
- macOS QUIC connections validate ECN on loopback and on paths that carry it, against
  akio-quic and quic-go (`tools/interop/quic/run.sh` now checks ECN on macOS too); on a path that
  bleaches or drops marks the existing fallback applies (one PTO at worst).
- A marked datagram on macOS is one `sendmsg` with a 16-byte control message, an unmarked one a
  `sendto` as before: no batching (macOS has no `sendmmsg`), no allocation.
- Not done: ECN on other Unix systems (no backend there); RFC 3168 section 5.3's rule for
  reassembly (CE if any fragment was CE) in akio-dpdk, which keeps the last fragment's codepoint
  (QUIC never fragments); Accurate ECN / L4S.
