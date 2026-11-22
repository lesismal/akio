# ADR-026: IPv6, ECN and pacing in the userspace TCP/IP stack

English | [简体中文](026-userspace-ipv6-ecn-pacing.zh-CN.md)

Status: accepted (2026-11-17)

## Context

akio-dpdk's own stack (`crates/akio-dpdk/src/net`) was IPv4-only: a listener on an IPv6 address
was refused, `dial` to one failed with `Unsupported`. DEV-PLAN listed "IPv6/NDP, offloads,
pacing/ECN" as not done. `DpdkConfig` is `#[non_exhaustive]` and the crate is experimental
(outside the semver promise), but its API is snapshotted, so new fields are recorded here.

## Decision

1. **IPv6 is on when the stack has an IPv6 address.** `DpdkConfig` gains
   `address6: Option<Ipv6Addr>` (default `None`: IPv4 only, nothing changes),
   `prefix_len6: u8` (64) and `gateway6: Option<Ipv6Addr>`. With `address6` set the stack also
   takes the link-local address derived from its MAC (modified EUI-64). Addresses are static:
   no SLAAC, router advertisements are ignored (the gateway is configured), as the IPv4 side
   has no DHCP.
2. **Listeners are dual-stack.** A listener's port serves IPv4 and IPv6 alike (ports are per
   device already). The listener address may be `0.0.0.0`, the IPv4 address, `::`, `address6`
   or the link-local address; another one is `AddrNotAvailable`, an IPv6 one on a stack without
   `address6` is `Unsupported`. `local_addrs()` reports the IPv6 address for a listener bound to
   an IPv6 one. `dial` / `dial_udp` take either family; a scope id is ignored (one interface).
   A connection's `local_addr` is the address it actually uses (link-local towards link-local
   peers, `address6` otherwise).
3. **What IPv6 covers.** The fixed header and the extension-header chain (hop-by-hop,
   destination options with their action bits, routing headers with segments left refused,
   at most 8 headers, 16 options each), fragmentation (source only) and reassembly in the
   IPv4 reassembler's limits (64 datagrams, 1 MiB, 30 s; overlapping fragments drop the
   datagram, RFC 5722; atomic fragments bypass reassembly, RFC 6946), ICMPv6 (echo, port
   unreachable and parameter problems, rate limited with the ICMPv4 budget and never about
   multicast or unspecified sources; received unreachables and packet-too-big reach UDP and
   TCP), a path-MTU cache (1024 destinations, 10 min), NDP (RFC 4861: solicitations and
   advertisements validated per 7.1, the ARP neighbour cache with its pending queue and NUD
   style refresh made generic over the address family) and an MLDv2 report at start and on
   queries so MLD-snooping switches deliver solicited-node multicast. AF_PACKET sockets join
   all-multicast on their interface for the same reason; ARP and NDP frames are fanned out to
   every queue of a multi-queue port.
4. **No duplicate address detection; our addresses are defended.** DAD would delay every
   start by a second for addresses an operator assigned by hand (the kernel's `nodad`
   equivalent); the stack answers other nodes' DAD probes for its addresses with an
   advertisement to all nodes, so the newcomer detects the conflict.
5. **ECN and pacing are opt-in.** `DpdkConfig::tcp_ecn` (RFC 3168: ECN-setup SYN / SYN-ACK,
   ECT(0) on new data only, ECE until CWR, one window reduction per round trip without a
   retransmission; SYN-cookie connections run without ECN) and `DpdkConfig::tcp_pacing`
   (rate `cwnd / srtt` times 2 in slow start and 1.2 afterwards, a per-connection pacing timer
   in the existing timer heap, bursts of at most two segments or 100 µs) default to `false`:
   both change what goes on the wire and cost CPU, and neither was measured neutral on the
   real-NIC path we cannot test (no DPDK-capable NIC in reach). Simulated: at a 20-frame
   bottleneck queue ECN replaces 29 drops and 27 retransmissions by 10 marks and no drop;
   pacing halves the drops (29 to 14) at the same completion time.
6. **No checksum or segmentation offloads.** The PMDs in reach (`net_tap`, `net_af_packet`)
   compute offloaded checksums and TSO in software inside the driver, so offloading would move
   the cost, not remove it, and the mbuf metadata path (`ol_flags`, `l2_len` / `l3_len`, TSO
   segment size) could not be validated against hardware. Revisit with a real NIC.

## Consequences

- Additive public API: five fields of `DpdkConfig` (snapshot `api/akio-dpdk.txt`).
- The IPv4 path stays monomorphic: a connection keeps IPv4 endpoints inline (IPv6 boxed) and
  hands them to the output path by reference, which sends IPv4 without a family dispatch; the
  pseudo-header address sum is computed once per packet; pacing state and UDP peers are boxed
  so unpaced TCP connections stay main's size; ISNs and SYN cookies hash IPv4's four words as
  before. The connection-table key is 20 bytes for both families (IPv4 in its mapped form),
  hashed as two words, and the neighbour caches use the stack's keyed multiply-mix hasher
  instead of SipHash (one lookup per outgoing segment).
- Cost on IPv4, measured: callgrind over stack-only loops (ignored tests
  `bench_request_response`, `bench_connection_cycle`), instructions vs main: request/response
  -1.5%, connection setup and close +0.9%. gpu51, `stack-bench` over the memory wire, 12
  alternating rounds, medians, new / main: 100 connections request/response 1.04, 1000
  connections 1.02, UDP 1.01, bulk echo 1.01 (64 KiB buffers) and 0.94 (1 MiB buffers, bimodal
  in both arms from round to round: 0.88-1.16 across ten runs), sequential connections 0.99.
- Fuzz targets `dpdk_ipv6`, `dpdk_icmpv6`, `dpdk_ndp`; `dpdk_stack` runs a dual-stack stack.
- Not done: SLAAC / router advertisements, DAD, IPv6 jumbograms, MLDv1, RFC 8899 PLPMTUD,
  Accurate ECN (RFC 9768) and L4S, checksum / TSO / LRO offloads.
