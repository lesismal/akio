# ADR-068: IPv6 autoconfiguration, Accurate ECN and AF_XDP shared UMEM / multi-buffer in the userspace stack

English | [简体中文](068-userspace-stack-slaac-accecn-af-xdp-multibuffer.zh-CN.md)

Status: accepted (2026-11-21)

## Context

akio-dpdk's own TCP/IP stack (`akio-dpdk/src/net`) left three groups of gaps after ADR-026
(IPv6) and ADR-063 (AF_XDP):

- **IPv6 addresses were static.** `DpdkConfig::address6` and `gateway6` had to be given; router
  advertisements were ignored; the stack answered other nodes' duplicate address detection
  (DAD) probes but never probed its own addresses, so a conflicting address was used anyway.
- **ECN feedback was RFC 3168's.** One ECE bit per round trip says that something was marked,
  not how much. Accurate ECN (RFC 9768, AccECN) reports the number of CE-marked packets on every
  ACK and the bytes per codepoint in an option. Linux implements it since 6.18
  (`net.ipv4.tcp_ecn = 3`).
- **AF_XDP was one UMEM per queue, one chunk per frame.** Every queue registered and pinned its
  own UMEM, and a frame had to fit one 4 KiB chunk (MTU at most 3826), so jumbo frames were out.

## Decision

### 1. SLAAC, router advertisements and DAD (opt-in)

- `DpdkConfig::ipv6_slaac` (default `false`) turns IPv6 on even without `address6`. The stack
  sends up to three router solicitations (RFC 4861 10: 4 s apart, after a random delay of up to
  1 s), and takes from each valid router advertisement (link-local source, hop limit 255,
  options of non-zero length):
  - the default router (its lifetime; up to 4 routers, the static `gateway6` first);
  - on-link prefixes (L flag; up to 16, with their valid lifetime);
  - one address per autonomous /64 prefix (A flag): the prefix plus the modified EUI-64
    interface identifier of the MAC, the same identifier as the link-local address (up to 8
    addresses), with the preferred and valid lifetimes of RFC 4862 5.5.3, including the
    "two hours" rule against advertisements cutting the valid lifetime short. Past its
    preferred lifetime an address is deprecated (kept, no longer chosen as a source); past its
    valid lifetime it is removed;
  - the MTU option (1280 up to the device MTU: IPv6 packets and the MSS of new IPv6 connections
    follow it) and the hop limit.
  Source selection picks, for a global destination, the usable global address sharing the
  longest prefix with it, a preferred one before a deprecated one.
- `DpdkConfig::ipv6_dad` (default `false`) runs DAD (RFC 4862 5.4) on every address before it is
  used: the link-local and static ones at start (after the random delay), SLAAC ones when they
  are formed. One probe (`DupAddrDetectTransmits = 1`), a one second wait (`RetransTimer`). A
  tentative address is not used as a source and packets to it are dropped; its solicited-node
  group is joined (MLD report from `::` while the link-local address is tentative). An
  advertisement for it, or another node's probe for it, makes it a duplicate. Probes carry an
  RFC 7527 nonce, so our own probe looped back by the link is not taken for a conflict. A
  duplicate address is never used; a duplicate link-local address turns IPv6 off on the device
  (RFC 4862 5.4.5).
- Multi-queue devices: every queue's stack follows the same timeline and sees router
  advertisements (they are copied to every queue like neighbor solicitations and
  advertisements), but only queue 0 sends solicitations, probes and MLD reports.
- `akio_dpdk::ipv6_addresses(&Device)` reports the usable addresses (kept by queue 0).
- Without `ipv6_slaac` advertisements are ignored, as before; without `ipv6_dad` addresses are
  used at once, as before. Both stay off by default because the defaults must not change what
  an existing configuration does (and DAD delays the first use of an address by about a
  second).
- The interface identifier is EUI-64, not RFC 7217's stable privacy identifiers (RFC 8064). A
  stable secret would have to be configured and shared by the queues; EUI-64 needs nothing,
  matches the link-local address and lets peers compute the address. A duplicate SLAAC address is
  therefore given up rather than retried with another identifier.

### 2. Accurate ECN (opt-in)

`DpdkConfig::tcp_accecn` (default `false`) implements RFC 9768 in the userspace TCP:

- Negotiation: the SYN carries AE, CWR and ECE; the SYN-ACK feeds back the IP-ECN field of the
  SYN (Table 2) with an AccECN option; the client's first ACK feeds back the SYN-ACK's IP-ECN
  field in the handshake encoding (Table 3) on a pure ACK of its own. A peer answering with
  RFC 3168 ECN gets RFC 3168 ECN, one without ECN none, a "broken" reflector none. A server
  with `tcp_accecn` answers RFC 3168 SYNs with RFC 3168 ECN. The SYN's first retransmission
  still asks for AccECN, later ones do not (3.1.4.1); a retransmitted SYN-ACK drops the option,
  the second one the AccECN flags too, after which the server never sends ECT (3.1.5,
  3.2.3.2.2). SYN cookies work: the cookie SYN-ACK feeds back the SYN's IP-ECN field, and the ACE
  field of the completing ACK tells the mode back (5.1).
- Receiver: the CE packet counter (initial 5) in the ACE field of every segment after the
  handshake, and the byte counters for ECT(0), CE and ECT(1) in the AccECN option (order 0,
  truncated to the counters that ever changed, at least the changed ones; given room next to
  two SACK blocks, 3.2.3.3) on every ACK after a counter changed. Change-triggered and
  increment-triggered ACKs (3.2.2.5.1).
- Sender: decodes the ACE field (smallest increment), and the option's 24-bit counters when
  present; Appendix A.2's safety against an ACE wrap hidden by lost ACKs (with the option:
  A.2.2; without it, only when ACKs usually cover few segments, so stretch ACKs are not taken
  for wraps). Mangling tests: an invalid transition of the handshake packets' IP-ECN field, a
  zero ACE on the handshake ACK, zeroed initial option counters, CE bytes without CE packets
  between two ACKs that both carry the CE byte counter (an ACK of a Not-ECT retransmission
  carries the ACE increment without an option, which otherwise looks like mangling).
- Congestion response: new CE marks are answered like ECE in RFC 3168: the window is reduced
  once per window of data, without retransmitting. CWR is never set (the bit is part of ACE).
  The response does not scale with the number of marks: that needs a scalable controller
  (DCTCP / Prague, L4S), which the stack does not have; AccECN's counters make one possible.
- Data is sent ECT(0) as with RFC 3168; control packets and retransmissions stay Not-ECT.
- `akio_dpdk::tcp_ecn_stats()` (`#[doc(hidden)]`) counts AccECN and RFC 3168 connections, CE
  marks received and congestion responses, for tests and benchmarks.

### 3. AF_XDP shared UMEM and multi-buffer frames (opt-in)

- `AfXdpConfig::shared_umem`: one UMEM for all the queues (`XDP_SHARED_UMEM`, Linux 5.10+
  across queues). The first socket registers it; the others bind to it with fill and completion
  rings of their own. `frames` is then the total, split evenly: each socket owns a fixed slice
  of chunks (the kernel only hands a socket back chunks it put on that socket's rings, and each
  socket checks that every address it touches is in its slice), so the I/O threads share no
  lock. Sockets after the first take its mode (the kernel refuses mode flags on them).
- `AfXdpConfig::multi_buffer`: `XDP_USE_SG` (Linux 6.6+). A received frame spanning several
  descriptors (`XDP_PKT_CONTD`) is reassembled (at most 64 KiB, larger ones dropped); a frame
  to send that is larger than a chunk is written over several chunks (at most 18) whose
  descriptors are published on the TX ring at once. The redirect program is loaded with
  `BPF_F_XDP_HAS_FRAGS`, which also lets a veth run native XDP above an MTU of about 3.5 KB.
  With it, `DpdkConfig::mtu` may go up to the stack's limit of 9000 over AF_XDP.

### Verification and the hot path

- Simulated links: RS / RA / SLAAC lifetimes and the two-hours rule, the MTU and hop-limit
  options, DAD success, conflicts (advertisement, another node's probe, a duplicate link-local
  address), the looped-back own probe, a non-zero queue following the timeline silently;
  AccECN negotiation matrix, exact feedback through a CE-marking bottleneck (IPv4 and IPv6),
  ACK loss with hundreds of marks, SYN cookies, SYN and SYN-ACK retransmission fallbacks, the
  option wire format; fuzz seeds for router advertisements and DAD probes, the router
  advertisement parser in the `dpdk_ipv6` / `dpdk_icmpv6` targets, the AccECN option in the TCP
  option round trip.
- Against Linux 7.0 (gpu51, in a privileged container: sysctls of the container's network
  namespace only): AccECN both ways with netem marking CE in both directions, checked from the
  kernel's `TCP_INFO` (`tcpi_ecn_mode` AccECN, AccECN options with counters seen, no failure,
  CE marks and CE bytes fed back); SLAAC from radvd (MTU 1400 reaches the kernel's MSS, a dial
  through the advertised default router), the kernel's DAD of our address failing, ours of the
  kernel's address failing; AF_XDP with a shared UMEM over two queues and jumbo frames (MTU 9000,
  native and generic XDP).
- The IPv4 path stays monomorphic: IPv6 autoconfiguration lives in IPv6-only code and in timers;
  AccECN adds one boxed state per AccECN connection and a branch where RFC 3168 ECN already had
  one. Same-run A/B of `stack-bench` on gpu51 in docs/BENCHMARKS.md.

## Consequences

- Hosts on an IPv6 network with routers need no static IPv6 configuration, and an address
  conflict is detected instead of silently breaking two hosts.
- With AccECN, a peer learns how much congestion there was, not only that there was some; this
  stack still reacts as RFC 3168 does.
- Jumbo frames work over AF_XDP; queues can share one pinned memory area.

## Not done

- AF_XDP for the epoll / io_uring kernel-stack backends: a different design (an AF_XDP socket
  under the kernel's TCP is not possible; it would mean these backends' UDP over AF_XDP), which
  needs an ADR of its own.
- Checksum / TSO / LRO offloads in the mbuf or AF_XDP metadata: no NIC here to validate them on.
- RFC 7217 stable privacy identifiers and RFC 8981 temporary addresses; DHCPv6 (the "M" and
  "O" flags are ignored); route information options (RFC 4191); router preference.
- ECT on SYNs, pure ACKs or retransmissions (RFC 8311 experiments), and a scalable congestion
  controller using AccECN's counters (L4S).
- Zero-copy AF_XDP measured on a real NIC (a veth has none).
