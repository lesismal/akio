# ADR-091: TURN ICMP relaying, DSCP across the relay, and giving back one family

English | [简体中文](091-turn-icmp-dscp-family-release.zh-CN.md)

Status: accepted (2026-11-23)

## Context

ADR-083 (dual allocations, ECN across the relay) left four items not done:

1. **ICMP relaying.** RFC 8656 section 11.5: when a datagram the server relayed to a peer draws
   an ICMP error, the server tells the client in a Data indication with an `ICMP` attribute
   (0x8004: type, code, error data) and no `DATA`. akio-turn's relay sockets are unconnected
   UDP sockets, and Linux drops the ICMP errors of those unless `IP_RECVERR` is set.
2. **DSCP copying.** Section 14 prefers the whole traffic class copied, UDP to UDP, both ways:
   the DSCP (upper six bits) as well as the ECN codepoint (low two). Only ECN was copied: the
   engine reported and set the low two bits only.
3. **A per-family Refresh in the client.** The server honours `REQUESTED-ADDRESS-FAMILY` in a
   Refresh (one family refreshed or deleted alone); the client always refreshed both.
4. **Dual allocations by default in `Endpoint::gather_relay`.** ADR-083 kept them opt-in.

coturn 4.6 (the interop reference) copies the TOS byte of relayed datagrams (it calls
`set_socket_tos` per datagram); what it does with ICMP and per-family Refresh was measured
(below).

## Decision

### akio and akio-sys: the traffic class byte, ICMP errors of bound sockets

**The whole traffic class byte.** The engine already received the `IP_TOS` / `IPV6_TCLASS`
control message of each datagram (ADR-077) and kept its low two bits. It now keeps the byte:

- `akio_sys::RecvBatch::tos(i)` (Linux) and `akio_sys::recv_from_tos` (macOS) give the byte;
  `ecn(i)` / `recv_from_ecn` are its low two bits, as before.
- `akio_sys::send_to_tos` and `SendBatch::push_tos` send any byte; the `_ecn` forms mask to
  two bits, as before.
- akio-core: the connection keeps the byte of the datagram being delivered (`rx_tos`, one
  `AtomicU8` as before); `Conn::rx_tos()` and `Conn::send_segments_tos()` sit next to the
  `_ecn` forms (all four `#[doc(hidden)]`, outside the stability promise, as the `_ecn` ones);
  `UdpBinding::send_to_tos` likewise. The datagram queue stores the byte per chunk where it
  stored the codepoint. akio-dpdk's UDP still reports and takes the ECN bits only.
- Unmarked datagrams take the old path: the test is `tos != 0` where it was `ecn != 0`.

**ICMP errors of a bound socket.** `Engine::bind_udp_icmp(addr, acceptor, on_icmp)` is
`bind_udp` plus a callback that gets an `akio::IcmpError` (bound address, the datagram's
destination with its port, the ICMP sender, ICMPv4 or v6, type, code, next-hop MTU) on the
socket's I/O thread. Linux only; elsewhere it is `bind_udp` and the callback never runs.

- The group sets `IP_RECVERR` (and `IPV6_RECVERR` on an IPv6 socket). The kernel then queues
  every ICMP error for the socket. `akio_sys::recv_icmp` reads one with `recvmsg(MSG_ERRQUEUE)`:
  `sock_extended_err` gives the origin, type, code and `ee_info` (the MTU), `SO_EE_OFFENDER`
  the sender, and the message name the original destination, port included, with no
  privileges (RFC 8656 allows port 0 when the platform cannot tell it).
- Two side effects are handled where they show:
  - The socket polls with `EPOLLERR` until its error queue is empty (level-triggered). The
    loop's read handler for a bound socket with a callback drains the queue first (bounded per
    event like a receive), so the event does not spin.
  - The kernel also leaves the error as the socket's pending error, which the next `recvmsg` or
    `sendmsg` returns once (`ECONNREFUSED`, `EHOSTUNREACH`, `EMSGSIZE`, ...) without doing
    anything. The receive loop skips those errors on such a socket instead of stopping the
    batch with a log line; `UdpBinding::send_to` / `send_to_tos` retry once on them
    (`akio_sys::is_icmp_error`), so the datagram that met the pending error is still sent.
- Errors of local origin (`SO_EE_ORIGIN_LOCAL`) are skipped. A panicking callback is caught and
  logged.
- Only bound sockets (`bind_udp_icmp`) get this. Listener sockets, dialed sockets (connected:
  ICMP already surfaces there as a connection error) and plain `bind_udp` are unchanged.
- The `Group` trait gains `bind_udp_icmp` with a default that calls `bind_udp`, so other
  backends compile unchanged; only the epoll UDP loop serves bound sockets today (io_uring
  engines bind UDP through it too).

### akio-turn: server

**DSCP.** `TurnCore::handle_client_tos` / `handle_peer_tos` take the byte; `TurnEnv` gains
`send_to_client_tos` / `send_to_peer_tos`. The `_ecn` entry points and environment methods
stay: `handle_*_ecn` calls `handle_*_tos` with the two bits, and the default `send_to_*_tos`
calls `send_to_*_ecn` with the two bits, so an existing environment sees exactly what it saw.
`TurnConfig::copy_dscp` (true) chooses whether relayed datagrams keep the DSCP (section 14's
preferred behaviour, and coturn's) or go out with DSCP 0 (section 14's alternative, "best
effort"), for an operator who does not want clients and peers to pick their traffic class.
ECN is copied either way. `TurnServer` reads `Conn::rx_tos()` and sends with
`send_segments_tos` / `UdpBinding::send_to_tos`. Stream clients have no byte to give or get, as
before.

**ICMP.** `TurnCore::handle_icmp(now, relay, peer, type, code, mtu, env)`, section 11.5:

- Only ICMPv4 types 3 (destination unreachable) and 11 (time exceeded), ICMPv6 types 1
  (destination unreachable), 2 (packet too big) and 3 (time exceeded); the family is the
  relay's. Anything else is dropped.
- The relayed address must be alive and have a permission for the peer's IP address (ports are
  not compared, as for data). The peer policy applies.
- The client gets a Data indication with `XOR-PEER-ADDRESS` (the destination, its port or 0)
  and `ICMP` (type, code, and the MTU for ICMPv4 3/4 and ICMPv6 2, else 0), no `DATA`, over
  whatever transport it uses (a channel does not matter). No traffic class.
- `TurnStats::icmp` counts them. `TurnConfig::relay_icmp` (true) turns it off.
- `TurnServer` binds relay sockets with `Engine::bind_udp_icmp` when `relay_icmp` is on; the
  callback finds the shard through the relay's route, as a peer's datagram does.

STUN codec: `attr::ICMP`, `Message::icmp`, `MessageBuilder::icmp`.

### akio-turn: client

- `ClientEvent::Icmp { peer, icmp_type, code, mtu }` (section 11.6): a Data indication with
  `ICMP` for an address the client has a permission for (any port), no data delivered.
  `ClientEvent` is `#[non_exhaustive]`, so the variant is additive. `TcpAllocation` ignores it
  (TCP relays draw none).
- `Client::release_family(now, v6)`: gives back one address of a dual allocation, a Refresh
  with lifetime 0 and that `REQUESTED-ADDRESS-FAMILY` (section 8). The address leaves
  `relayed_addrs()` at once, with its peers and their pending requests; the other address
  stays and is refreshed as before (a Refresh without the attribute now covers just it). The
  answer does not matter: an error is ignored (the server lets the address expire). `false`
  when not allocated or when it is the last address (`close` deletes that).
- No per-family *refresh* with its own lifetime: the client refreshes all its addresses on one
  schedule, so refreshing one alone has no use here; deleting one does.

### akio-webrtc: `gather_relay` stays single-family

Plain `Endpoint::gather_relay` still asks for one family; `RelayServer::dual_allocation(true)`
asks for both (ADR-083). Reasons:

- The allocation is shared by every peer of the endpoint, now and later, so the unused family
  can never be given back once ICE has chosen: the second relay port is held for the
  endpoint's life, on servers that are usually someone else's (a hosted TURN service).
- The gain is small: the IPv6 relayed candidate only matters against a peer that has IPv6
  candidates and no IPv4 path, and IPv6-only mobile networks give their hosts IPv4 through
  464XLAT / NAT64. libwebrtc does not ask for dual allocations either.
- pion/turn ignores the attribute; coturn without an IPv6 relay answers 440. Harmless, but no
  gain against them.

An application that knows its peers may be IPv6-only asks for it per server.

## Measured

`tools/interop/webrtc/turn-dual.sh` on gpu51 (Docker, loopback, 127.0.0.1 and ::1 relays): the
akio_turn client asks for a dual allocation, marks its datagrams DSCP EF + ECT(0) (0xba), its
peers mark their echoes AF41 + ECT(1) (0x89), sends to a closed port through each relay, then
gives back the IPv6 relay.

| Server | Traffic class, both ways | ICMP port unreachable | IPv6 family given back |
|---|---|---|---|
| akio-turn | 0xba / 0x89 kept, IPv4 and IPv6 | relayed: 3/3 (IPv4), 1/4 (IPv6) | deleted at once, IPv4 kept |
| coturn 4.6 | 0xba / 0x89 kept, IPv4 and IPv6 | not relayed | deleted within its timer tick (~1 s), IPv4 kept; Refresh answered success |
| pion/turn v5.1.3 | cleared (one relay: it ignores the attribute) | not relayed | – |

The run requires akio-turn's row; the others are printed. coturn copies the TOS byte as its
source says (`set_socket_tos` per datagram); RFC 8656's ICMP Data indication is something it
does not send. The same run passes coturn's `turnutils_uclient -Z` / `-x` against akio-turn
(40 and 80 messages, none lost) and pion/turn's `REQUESTED-ADDRESS-FAMILY` clients;
`turn-tcp.sh` (RFC 6062 against coturn and pion/turn, TCP and TLS) passes unchanged.

## Consequences

- Behaviour change: akio-turn's relayed datagrams now keep the DSCP the sender set (before,
  the socket's, normally 0). `copy_dscp(false)` restores DSCP 0. On a network that bleaches
  DSCP nothing changes.
- Behaviour change: akio-turn's UDP relay sockets have `IP_RECVERR` on Linux, and clients get
  ICMP Data indications for unreachable peers. Older akio_turn clients ignore them (no
  `DATA`); `relay_icmp(false)` turns it off.
- `UdpBinding::send_to` on a `bind_udp_icmp` socket may make two `sendmsg` calls after an ICMP
  error; other sockets never do.
- Public API: additions only (`api/akio.txt`, `api/akio-core.txt`, `api/akio-sys.txt`,
  `api/akio-turn.txt`).
- Performance: UDP relay A/B against main `5cc005c0` on gpu51 (`turn-relay-bench 8 6 4`, 8
  alternating rounds under `quiet.sh`): branch / main per-round median 1.061 (rounds vary by
  about ±20 %): no measurable change. Every datagram marked DSCP EF + ECT(0) against every one
  marked ECT(0) only: median 0.973, mean 1.022, the same cost. docs/BENCHMARKS.md has the table.
- Tests:
  - akio-sys: port unreachable queued on IPv4 and IPv6 loopback, read back with destination,
    sender, type and code; the pending error returned once (Linux). Layout checks for the new
    constants against `libc`.
  - akio (`tests/udp.rs`): `bind_udp_icmp` reports port unreachable while the socket goes on
    echoing, every `send_to` succeeding; on macOS it reports nothing.
  - akio-turn core: DSCP copied both ways on ChannelData, Send and Data indications, cleared with
    `copy_dscp(false)`, an ECN-only environment seeing two bits; ICMP relayed for each
    relayable type of both families (MTU only where section 18.13 says), port 0, dropped for
    other types, no permission, the wrong family's relay, an unknown relay, `relay_icmp(false)`
    and a deleted family.
  - akio-turn client: `release_family` through 30 minutes of refreshes (the server keeps the
    IPv4 relay only), refused for the last address; `ClientEvent::Icmp` for a permitted address
    (any port), ignored otherwise.
  - `tests/dual_ecn.rs` on real sockets: four traffic class bytes (EF, AF41, CS1 with ECN
    codepoints, CS6 alone) both ways on both families, and with `copy_dscp(false)`; on Linux,
    port unreachable relayed to the client on both families, the relays working after it.
  - Platforms: macOS, and gpu51 epoll and io_uring. Clippy clean (rustc 1.100).
  - Fuzzing: `turn_server` takes whole traffic class bytes from client and peers and ICMP
    errors (selector bytes `0xfe`, `0xfc` and even ones from `0x80`), and asserts that relayed
    data keeps the byte and that an ICMP Data indication carries no `DATA`. New seed: DSCP both
    ways and ICMP errors on a dual allocation. Run on gpu51 for 5 minutes per target, the four
    in parallel (libFuzzer with ASan, built as cargo-fuzz does): `turn_server` 2.2M runs,
    `turn_stream` 3.9M, `turn_tcp` 2.6M, `turn_dtls` 2.2M, no finding.
- Not done:
  - TTL: section 14 prefers the outgoing TTL / hop limit to be the incoming one minus 1 (coturn
    does it); the relay sends with the socket's default. It needs `IP_RECVTTL` /
    `IPV6_RECVHOPLIMIT` per datagram and a control message per send, like the TOS byte.
  - `DONT-FRAGMENT` is still accepted and not acted on: relayed datagrams get the socket's DF
    setting (Linux's path MTU discovery default).
  - ICMP on macOS: unconnected UDP sockets get no ICMP errors there.
  - akio-webrtc does not act on `ClientEvent::Icmp` (an ICE check failing does the same work,
    later).
