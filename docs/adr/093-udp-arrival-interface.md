# ADR-093: The interface a UDP datagram arrived on, opt-in per bound socket; mDNS places queries by it

English | [简体中文](093-udp-arrival-interface.zh-CN.md)

Status: accepted (2026-11-23)

## Context

ADR-078 update 4 left one item open: the engine does not tell a handler which interface a
datagram arrived on. akio-webrtc's mDNS responder answers each record only on the link of its
address (RFC 6762 §6.2), so it must know the link a query came from. Without the arrival
interface it infers it from the source address (`Mdns::link_of_src`): the source's scope id
(IPv6 link-local), else the interface that holds the address, else the one whose subnet holds
it (the longest prefix). That inference is wrong, or impossible, when:

- **Two interfaces share a prefix** (two NICs on one LAN, a bridge and a veth on the same
  subnet, two VLANs numbered alike): the longest-prefix match is a tie, settled by the order
  of the interface list (the last one wins), so a query from the other link is placed on the
  wrong one. A record of
  an address on the true link is then refused ("the query came from interface N"), and a
  multicast answer leaves on the wrong link.
- **The source is on no subnet of ours** (a querier with only a 169.254 address, a host with
  a stale address): update 4 answers each record on its own link, which reaches the querier
  only when it is on one of them.

The kernel knows the interface: `IP_PKTINFO` (Linux) / `IP_RECVPKTINFO` (macOS) and
`IPV6_RECVPKTINFO` (both) add an `in_pktinfo` / `in6_pktinfo` control message, whose
`ipi_ifindex` / `ipi6_ifindex` is the arrival interface, to every datagram `recvmsg` /
`recvmmsg` returns. The engine already reads control messages on every receive (the traffic
class for ECN, the GRO segment size, the TTL when asked for), so the question is the API and
what it costs the sockets that do not ask.

How the engine receives UDP, per backend:

- **epoll (Linux)** and **io_uring (Linux)**: the UDP client threads, and every UDP listener of
  the io_uring backend, are akio-epoll's `UdpLoop` on both backends (ADR-078 decision 2; the
  io_uring backend runs only connectionless datagram ports, ADR-065, on its own ring). The loop
  reads with `recvmmsg` into `akio_sys::RecvBatch`, which gives each slot a fixed control
  buffer (96 bytes until now).
- **kqueue (macOS)**: the same `UdpLoop`, reading one datagram per `recvmsg`
  (`akio_sys::recv_from_ip`, a 64-byte control buffer).
- **akio-dpdk**: its own UDP stack, no kernel socket.

So one receive path serves every engine `UdpBinding` on every kernel backend.

## Decision

1. **Public API (akio-core), additive.**
   - `UdpBinding::set_recv_interface(&self, on: bool) -> io::Result<()>`: asks the kernel to
     report (or stop reporting) the arrival interface of every datagram the socket receives.
     Linux: `IP_PKTINFO` and `IPV6_RECVPKTINFO`; macOS: `IP_RECVPKTINFO` and
     `IPV6_RECVPKTINFO`. An IPv6 socket sets both (a dual-stack socket receives IPv4 datagrams
     as mapped addresses, reported through the IPv4 option); it succeeds when either option is
     accepted. Elsewhere it fails with `ErrorKind::Unsupported`. Datagrams already queued when
     it is called arrive without the interface.
   - `Conn::rx_interface(&self) -> u32`: inside `on_data` (or `on_data_owned`), the index of the
     interface the datagram arrived on (as `akio_sys::interfaces` lists them, the scope id an
     IPv6 link-local address carries); 0 when not asked for, not reported (akio-dpdk, other
     platforms) or for TCP. A peer's datagrams may arrive on different interfaces; the value is
     per datagram, like `rx_tos` / `rx_ttl`.
   - It is opt-in per bound socket, not a `Config` switch: the protocols that need it (mDNS,
     later perhaps a DHCP or SSDP responder) own their socket, and every other socket keeps
     what it receives today.
2. **akio-sys, additive.** `enable_recv_interface(fd, on) -> bool` (Linux and macOS);
   `RecvInfo { tos, ttl, interface }` (`#[non_exhaustive]`, `Copy`); Linux
   `RecvBatch::info(i) -> RecvInfo` and `RecvBatch::interface(i)` (one walk over a datagram's
   control messages, the walk `tos_ttl` did, now also matching `IP_PKTINFO` /
   `IPV6_PKTINFO`; `tos_ttl` stays and calls it); macOS `recv_from_info(fd, buf) -> (len, sender, RecvInfo)` (`recv_from_ip` calls it).
   The control buffers grow to 128 bytes per slot (Linux: GRO 24 + traffic class 24 + TTL 24
   + `in6_pktinfo` 40 = 112 bytes; macOS: 16 + 16 + 32 = 64, which left no slack). A larger
   `msg_controllen` costs nothing: the kernel writes only the messages it has.
3. **The receive loop (akio-epoll `UdpLoop`)** carries `RecvInfo` instead of `(tos, ttl)` to
   the connection and stores the interface next to the TTL (`ConnInner::set_rx_interface`, a
   relaxed store into the cache line the traffic class and TTL already go to) on all four
   paths: bound and listener sockets, dialed sockets, Linux and macOS. A socket that did not
   opt in has no pktinfo message: its control-message walk is the same as before, with one more
   comparison per message present, and the stored interface is 0.
4. **mDNS uses it.** Both mDNS sockets call `set_recv_interface(true)` when bound (a refusal is
   logged and changes nothing). In `on_query` the query's link is the arrival interface when it
   is reported, and the inference (`link_of_src`, the list re-read for an unknown source) only
   when it is not (0: a platform without it, a datagram queued before the option was set). Two
   cases keep the inference although an interface is reported: a loopback source (this host's
   own queriers, answered on every link as before), and a datagram that arrived on a loopback
   interface (Linux delivers a unicast datagram this host sends to one of its own addresses
   over `lo`; its source still names the link). An index not in the interface list has it read
   again (at most every 5 seconds), as an unknown source did, so an interface that appeared
   since is joined and known before the answer goes out. An arrival interface is never
   "unknown", so update 4's answer-on-every-record's-own-link path is taken only without it. `usable_on` keeps its rule (an address on another interface whose
   subnet holds it is still usable: two NICs on one LAN), now applied to the true arrival
   interface. The reply goes back out of the interface the query came in on: a multicast answer
   as before (IPv4: `send_to_on` when the group was joined there; IPv6: the scope id), and now
   a unicast one too (a QU question, a legacy unicast querier): `send_to_on(reply, src, f)`
   instead of `send_to`, so a querier on no subnet of ours (169.254, which the routing table
   would send out of the default route's interface) gets it on its own link. Linux routes a
   destination with no route as on-link when the outgoing interface is given.

Rejected:

- **Always on.** Every datagram of every socket would carry 32–40 more control bytes and the
  loop would parse them for nothing; most protocols (QUIC, RTP, TURN) never ask.
- **A `Config` switch for the whole engine.** Too coarse: a process that runs mDNS next to a
  QUIC server would pay on the server's sockets.
- **A new handler callback with the interface (`on_data_from`).** Every handler would need a
  default and the loop a second dispatch; the per-datagram connection field already exists for
  the traffic class and TTL, and reading it costs nothing when unused.
- **io_uring `RECVMSG` for the bound sockets.** They are not on the ring (see Context); a
  multishot `recvmsg` with provided buffers would bring its own control-message layout for no
  gain here.

Not done: listener sockets (`Listener::udp`) have no opt-in (no caller; a hidden
`Conn`-level switch like `enable_rx_ttl` can follow when one needs it). The destination address
in the same control message (multicast or unicast, which local address) is not reported.
Platforms other than Linux and macOS keep the inference.

## Consequences

- New public API: `UdpBinding::set_recv_interface`, `Conn::rx_interface` (akio-core, re-exported
  by `akio`); `akio_sys::{enable_recv_interface, RecvInfo}`, `RecvBatch::info` /
  `RecvBatch::interface` (Linux), `recv_from_info` (macOS). Nothing existing changes signature.
- Sockets that do not opt in: same system calls, same control messages; each receive slot's
  control buffer is 32 (Linux) or 64 (macOS) bytes larger; the A/B below measures no
  regression.
- mDNS answers a query from a link that shares its prefix with another interface on the right
  link, and a query from a source on no subnet of ours by multicast on the link it came from.

## Verification

- akio-sys `arrival_interface` (Linux `RecvBatch`, macOS `recv_from_info`): 0 until asked for;
  then the loopback interface's index for IPv4, IPv6 and an IPv4 datagram on a dual-stack
  socket, next to the traffic class, the TTL and (Linux) GRO in one slot; 0 again once turned
  off. macOS `control_parsing_is_bounded`: packet info too short, past the end, IPv4 and IPv6
  layouts.
- akio `tests/udp.rs` `bound_socket_reports_the_arrival_interface_once_asked` (unicast on
  loopback, both families, on and off) and `tests/shared_ports.rs`
  `ipv4_group_reports_the_interface_each_datagram_arrived_on` (a group joined on two
  interfaces, a datagram sent out of each arrives as having arrived on it; macOS lo0 + en1,
  Linux a0 + b0).
- akio-webrtc `tests/mdns.rs` `ipv4_queries_are_placed_on_the_interface_they_arrived_on`: a
  query whose source address is one interface's, sent out of the other, is answered on the
  interface it arrived on and not on the one its source points to. Linux only: macOS refuses
  to send from one interface's address out of another (`EADDRNOTAVAIL`), and the test skips.
- `tools/interop/webrtc/mdns4.sh` step 7: d0 (`10.66.4.1/24`) and e0 (`10.66.4.2/24`) share a
  prefix, each a veth pair to a network namespace with a querier (`10.66.4.11`, `10.66.4.12`);
  each querier asks for the name concealing its own link's address and gets it, from that
  address. The trace shows each query placed on the interface it arrived on. Steps 1–6 and
  `mdns6.sh` stay green; both scripts on Linux 6.12 (Docker Desktop, aarch64) with epoll and
  `AKIO_TEST_BACKEND=uring`.
- Control (same script, the arrival interface ignored in `on_query`): step 7 fails, neither
  querier gets an answer (the tie names one interface for both queries, and d0 / e0 appeared
  after the mDNS sockets started, so the inferred link was not joined either: the answers left
  out of the default interface); the mDNS test above fails. In that control run one
  `shared_ports` test also failed once, unidentified; 50 further runs of `shared_ports` on both
  backends in the same container setup, on the real branch, had no failure.
- macOS: `cargo test --workspace` (two unrelated failures under load, `happy_eyeballs` and
  akio-h3 `features`, passed three times out of three on their own), clippy `-D warnings`.
  gpu51 natively (rustc 1.100): `cargo test --release` of akio-sys, akio-core, akio-epoll, akio
  and akio-webrtc on epoll and with `AKIO_TEST_BACKEND=uring` (88 / 88 test targets ok), clippy
  `--workspace --all-targets -D warnings`.
- Cost (gpu51, same-run A/B, BENCHMARKS "Bound UDP socket receive, arrival interface"): a
  saturated bound socket that does not opt in receives 0.999 of main's rate (10 rounds,
  0.993–1.006); opting in costs 0.6 % (about 5 ns per datagram).
- API snapshots (`tools/api/public-api.sh`): additions only.
