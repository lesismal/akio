# ADR-091: TURN ICMP relaying, DSCP across the relay, and giving back one family

English | [简体中文](091-turn-icmp-dscp-family-release.zh-CN.md)

Status: accepted (2026-11-23); updated 2026-11-23 (TTL, `DONT-FRAGMENT`, ICMP on macOS, ICMP in
ICE: see the update at the end)

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

## Update (2026-11-23): TTL, DONT-FRAGMENT, ICMP on macOS, ICMP in ICE

The four items left above, each decided and done.

### Context, corrected

RFC 8656 section 14 (UDP to UDP) has no TTL rule, contrary to what "Not done" said above: it
covers DSCP, ECN, the IPv4 fragmentation fields and IPv4 options. RFC 5766 section 12, which it
replaces, had one (preferred: the incoming TTL minus 1, dropped at 0; alternative: the default).
RFC 8656 keeps it where IPv6 is involved: section 13 decrements as a router does (13.2: "acts as
a regular router with respect to decrementing the Hop Limit"; 13.1 and 13.3 by RFC 7915), with
the default as the alternative, and section 3.6 lists a reset TTL among the things a relay may
do. `DONT-FRAGMENT` is sections 7.2 (Allocate), 11.2 (Send) and 14 / 15 (what to set); section 13
says to ignore it when either side is IPv6.

### Decision

**TTL / hop limit: copied minus one, by default (`TurnConfig::copy_ttl`, true).** What it buys is
section 21.1.7's loop: two servers made to relay to each other pass a datagram back and forth
until an allocation expires; authentication and random ports make the loop harder to build, a
decrementing TTL ends it after at most 255 hops whoever built it. coturn decrements towards the
peer (measured below). The cost is one more control message each way, measured below.

- akio-sys: `enable_recv_ttl` (`IP_RECVTTL` / `IPV6_RECVHOPLIMIT`, per socket, off by default:
  only sockets that ask pay for the control message), `RecvBatch::ttl` and `tos_ttl` (one walk
  over the control messages for both), `Batch::push_ip` and `send_to_ip` (`IP_TTL` /
  `IPV6_HOPLIMIT` next to `IP_TOS` / `IPV6_TCLASS`; the control buffer grew from 64 to 96 bytes
  for a third message), `recv_from_ip` on macOS.
- akio-core (hidden, as the `_tos` forms): `Conn::rx_ttl`, `Conn::enable_rx_ttl`,
  `Conn::send_segments_ip`, `UdpBinding::send_to_ip`, `UdpBinding::enable_rx_ttl`. The send
  queue keeps one 16-bit word per chunk (traffic class in the low byte, TTL in the high) where
  it kept the byte; datagrams with different words do not share a GSO message.
- akio-turn: `IpFields` (traffic class, TTL, DF) with `TurnCore::handle_client_ip` /
  `handle_peer_ip` and `TurnEnv::send_to_client_ip` / `send_to_peer_ip`, defaulting to the `_tos`
  methods as those default to the `_ecn` ones. Relayed data goes out with the incoming TTL minus
  one; unknown (0) stays unknown (the socket's default); a datagram that came in with 1 is
  dropped and counted (`TurnStats::ttl_expired`), except data from a peer to a stream client,
  where no hop of the datagram's own follows (section 16). Requests are answered whatever their
  TTL. No ICMP time exceeded is sent for a dropped datagram: that takes a raw socket.
- `TurnServer` asks for the TTL on its relay sockets when it binds them and on a listener's
  socket when a client opens (a `setsockopt` per new client 5-tuple; the socket is shared, so the
  first datagram of the first client may arrive before it).
- macOS: the TTL is read on both families, but XNU ignores an `IP_TTL` control message on send
  (measured: the datagram leaves with the socket's 64), so IPv4 datagrams keep the default
  there; IPv6 ones get their hop limit.

**`DONT-FRAGMENT`: acted on.**

- `TurnEnv::sets_dont_fragment` (default false): an environment that cannot set DF gets
  sections 7.2 and 11.2's answer, the attribute treated as unknown and comprehension-required:
  an Allocate carrying it is answered 420 with it in `UNKNOWN-ATTRIBUTES`, a Send indication
  carrying it is dropped. `TurnServer` says true on Linux and macOS.
- A Send indication with the attribute goes to the peer with DF set when the client is on UDP
  (or DTLS) and both sides are IPv4 (section 14; section 13 ignores it once IPv6 is involved),
  or when the client is on a stream (section 15, either family: `IPV6_DONTFRAG` on an IPv6
  relay). Everything else goes with DF clear: ChannelData, Send without the attribute, data to
  clients. Section 14 prefers copying the incoming DF bit, which a UDP socket cannot read; the
  alternative is DF 0.
- Relay sockets start with DF clear (Linux `IP_PMTUDISC_DONT`; the system default,
  `IP_PMTUDISC_WANT`, sets DF on whatever fits the known path MTU). Linux has no per-datagram DF
  for IPv4, so DF is the socket's: `TurnServer` keeps the relay's current setting and changes it
  (one `setsockopt`) under the relay table's lock, just before a datagram that wants the other
  one, so each datagram goes with the setting it asked for and a client that always (or never)
  asks costs nothing per datagram.
- akio-sys `set_dont_fragment` / `dont_fragment` (`IP_MTU_DISCOVER` on Linux, `IP_DONTFRAG` on
  macOS, `IPV6_DONTFRAG` on IPv6 sockets); `UdpBinding::set_dont_fragment`, public.
- A DF datagram larger than the path MTU the kernel knows fails with `EMSGSIZE` and is dropped.

**ICMP on macOS: read from an ICMP socket.** macOS has no `IP_RECVERR`, but an unprivileged ICMP
socket (`SOCK_DGRAM` with `IPPROTO_ICMP` / `IPPROTO_ICMPV6`, what `ping` uses) receives a copy of
every ICMP message the host gets, errors about other sockets' datagrams included (measured: port
unreachable for a loopback datagram arrives on both families, IPv4 with the outer IP header,
ICMPv6 without). The quoted datagram names its source address and port, which is the bound
socket.

- akio-sys: `IcmpListener` (macOS) and `parse_icmp_error` (both platforms, safe code over the
  bytes: ICMPv4 3 / 11 / 12 and ICMPv6 1 to 4 quoting UDP over the same IP version, ports
  included; anything else is `None`), `icmp_source_matches`.
- akio-epoll on macOS: a UDP loop opens an ICMP socket of a family when its first bound socket
  of that family with an ICMP handler registers, and closes it with the last; errors go to the
  handler of the bound socket whose (family, port) and address the quoted source names, with
  the ICMP message's sender as `from`. Reads are bounded per event, as receives are.
- Costs: each loop's socket gets a copy of every ICMP message the host gets and drops what is
  not its own; a socket bound to `[::]` hears of its IPv6 datagrams only; anyone who can reach
  the host can forge an error naming a relay's port, as on Linux, where the kernel's matching is
  no stronger. `Engine::bind_udp_icmp` documents both platforms.

**akio-webrtc: hard ICMP errors fail the check in flight.** RFC 8445 section 7.2.5.2.2: an agent
may process ICMP errors for connectivity checks, and a hard one should fail the pair.

- akio-ice: `IceAgent::handle_icmp_error(now, local, remote, type, code)`: ICMPv4 destination
  unreachable codes 2 and 3 (protocol, port) and ICMPv6 destination unreachable code 4 (port)
  fail the pairs from `local` to `remote` (port 0 matches any) whose check is in flight, at once
  instead of after seven sends over about six seconds. Pairs that succeeded, the selected one
  included, are left alone: ICMP is not authenticated (section 19.2 describes the spoofing), and
  consent freshness (RFC 7675) is what decides whether a working path still works. Soft errors
  (host or network unreachable, time exceeded, too big) are ignored. A later check from the
  remote revives a failed pair, as for any failed pair.
- akio-webrtc: the relay turns `ClientEvent::Icmp` into a call on every peer of the endpoint
  (every transport's agent) with the relayed address of the peer's family as `local`. Nothing is
  surfaced to applications: there is nothing for them to do that ICE does not. "Packet too big"
  is not used either: DTLS, SCTP and RTP size their packets below any path MTU worth having.

### Measured

`tools/interop/webrtc/turn-ttl-df.sh` on gpu51 (Docker): the akio_turn client and the servers in
one container, the peer in another across the Docker bridge (MTU 1500). The client sends with
TTL 40, the peer answers with TTL 50; then Send indications: 100 bytes with `DONT-FRAGMENT`, 2000
bytes without, 2000 with, 100 with again.

| Server | TTL client → peer | TTL peer → client | 100 B, DF | 2000 B | 2000 B, DF | 100 B, DF again |
|---|---|---|---|---|---|---|
| akio-turn | 39 | 49 | relayed | relayed (fragmented) | refused | relayed |
| coturn 4.6 | 39 | 64 (not copied) | relayed | relayed (fragmented) | refused | not relayed |

The run requires akio-turn's row. `turn-dual.sh` (ADR-083, ADR-091) passes unchanged: DSCP and
ECN copied both ways, ICMP port unreachable relayed (3/3, 1/4), a family released alone.

Performance: UDP relay A/B against main `631d7e27` on gpu51 (`turn-relay-bench 8 6 4`, 8
rounds under `quiet.sh`, order rotated): branch / main per-round median 1.022, mean 1.039 (rounds
vary by about ±20 %): no measurable change. The same branch with `copy_ttl` off against on:
median 0.943, about 5 %, what ECN marks cost in ADR-083. docs/BENCHMARKS.md has the table.

### Tests

- akio-sys: TTL both ways on Linux (`send_to_ip`, and a `sendmmsg` message with GSO, traffic
  class and TTL together) and macOS (hop limit sent on IPv6, the default 64 on IPv4), none
  reported until asked for; DF set and cleared; ICMP port unreachable read from the ICMP socket
  on IPv4 and IPv6 loopback and matched to its sender (macOS); the parser on the captured
  messages, MTU fields, every truncation, other types and protocols; control-message parsing
  of `IP_RECVTTL`. Layout checks for the new constants against `libc`.
- akio (`tests/udp.rs`): `bind_udp_icmp` now reports port unreachable on macOS too.
- akio-turn core: TTL minus one both ways on ChannelData, Send and Data indications, 0 kept,
  1 dropped and counted (requests still answered), `copy_ttl(false)`, stream clients;
  `DONT-FRAGMENT`: 420 naming it and Send dropped without DF support, DF set from an IPv4 UDP
  client to an IPv4 peer and from a stream client, clear for ChannelData, Send without it, IPv6
  relays from UDP clients and data to clients.
- akio-turn on real sockets (`tests/ttl_df.rs`): TTL 40 / 50 arriving as 39 / 49 on both
  families (macOS IPv4: 64), 64 with `copy_ttl(false)`, TTL 1 dropped; Send indications
  alternating DF on IPv4 and IPv6 peers all relayed. `tests/dual_ecn.rs`'s ICMP test now runs
  on macOS.
- akio-ice (`tests/sim.rs`): a check to a closed port fails on the ICMP error at once (the
  test allows 100 ms) instead of seconds, soft errors and other addresses ignored, port 0
  matching; on the simulated network a closed remote candidate gets one check instead of
  seven, the agents connect over the other, and a spoofed error on the selected pair changes
  nothing.
- akio-webrtc (`tests/relay.rs`): through akio-turn, the relayed candidate's check to a closed
  port is sent once (the server relays the ICMP error, the agent fails the pair); with
  `relay_icmp(false)` it is sent three times or more in the same 2.5 s.
- Platforms: macOS, gpu51 epoll and io_uring. Clippy clean.
- Fuzzing: `turn_server` gains selectors `0xf8` / `0xfa` (peer / client datagrams with a TTL)
  and `0xf6` (the environment starts or stops setting DF), and asserts that relayed data goes
  with the TTL minus one, that TTL 1 is never relayed, and that DF is only set by an environment
  that can, towards IPv4; new seed: TTL both ways and `DONT-FRAGMENT` refused then accepted.
  New target `sys_icmp_error` (the parser, its promises asserted), seeded with the macOS
  captures. Run on gpu51 for 5 minutes per target, the five in parallel (libFuzzer with ASan, built as
  cargo-fuzz does): `sys_icmp_error` 152.1M runs, `turn_server` 2.9M, `turn_stream` 5.2M,
  `turn_tcp` 2.7M, `turn_dtls` 2.2M, no finding.

### Not done

- No ICMP time exceeded for a datagram dropped at TTL 1, and no "packet too big" for a DF
  datagram the kernel refuses (section 13.2 prefers telling the sender, with 48 bytes off the
  MTU): both are dropped silently. The first needs a raw socket; the second would mean relaying
  the kernel's local `EMSGSIZE` errors.
- macOS cannot send a per-datagram IPv4 TTL: IPv4 datagrams from relays keep the default there.
- A `[::]` dual-stack socket on macOS hears of its IPv6 datagrams' ICMP errors only.
- ICMP for an endpoint's own host candidates (its unconnected socket, `IP_RECVERR` on Linux) is
  not fed to ICE: only relayed candidates get it, through the TURN server.
