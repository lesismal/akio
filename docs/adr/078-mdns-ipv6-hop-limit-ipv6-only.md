# ADR-078: mDNS over IPv6: hop limit 255, IPv6-only links, interop with Chrome, avahi and mDNSResponder

English | [简体中文](078-mdns-ipv6-hop-limit-ipv6-only.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-044 resolved and concealed `<uuid>.local` ICE candidates over IPv4 (`224.0.0.251`) and left
"mDNS over IPv6 multicast" open. ADR-054 (2026-11-20) added it: a second socket on
`[::]:5353` joined to `ff02::fb` on every interface with a link-local address
(`Engine::bind_udp_multicast_on`), queries on each link, answers on the link of the query, AAAA
records, scope ids kept for remote link-local addresses. ADR-044's "not done" line was never
updated, and a review of what ADR-054 left found three gaps:

- **Hop limit.** RFC 6762 §11 asks for IP TTL / hop limit 255 on every mDNS response, for
  queriers that check it on reception (implementations of the 2004 draft; avahi with
  `check-response-ttl=yes`).
  The engine set the IPv4 multicast TTL to 255, but IPv6 multicast went out with the kernel's
  default hop limit of 1: std has no `set_multicast_hops_v6`, and `akio` forbids unsafe code.
- **IPv6-only links.** `conceal_host_candidates` required the IPv4 socket to be on the shared
  port. On a link without IPv4 (no route to `224.0.0.251`) that socket falls back to an
  ephemeral port, so concealing failed although the IPv6 socket held port 5353 and could answer.
- **Interop.** ADR-054's IPv6 tests ran between our own sockets; no browser or other responder
  had resolved or answered over `ff02::fb`, and no test ran on an IPv6-only link.

## Decision

1. **akio-sys: `set_multicast_hops_v6(&UdpSocket, u32)` and `multicast_hops_v6(&UdpSocket)`**
   (`IPV6_MULTICAST_HOPS`, Linux and macOS; values above 255 are refused with `InvalidInput`
   before the system call). Additive public API.
2. **akio: `Engine::bind_udp_multicast_on` with an IPv6 group** sets the hop limit to 255 and
   multicast loopback on, as the IPv4 path sets TTL 255 (loopback is now set explicitly there
   too). Interface choice stays per datagram: the scope id of the destination
   (`ff02::fb%<index>`) picks the link, which is what `IPV6_MULTICAST_IF` would do per socket.
   UDP client threads are epoll / kqueue on every backend, so this path is the same with
   `AKIO_TEST_BACKEND=uring`.
3. **akio-webrtc: names are answered over whichever family holds the shared port.**
   `conceal_host_candidates` succeeds when the IPv4 *or* the IPv6 socket is on 5353; on an
   IPv6-only link concealed IPv4 and IPv6 addresses are answered over `ff02::fb` (A and AAAA
   records). The debug line of a resolved name now names the answer's source
   (`mdns: <name> is [...] (from <addr>)`), so a log shows the family it came over.
4. Unchanged and confirmed: one question per message (A and AAAA queries apart, as Chromium's
   responder needs), queries on both families, the shared port with `SO_REUSEADDR` /
   `SO_REUSEPORT` next to the system's responder, cache (TTL, at most 2 minutes, 256 names) and
   timeout as over IPv4; the sockets are served by an engine I/O thread and the interface scan
   runs in `resolve_mdns` on the caller's thread.

Not done: unicast responses (to a querier that set the QU bit, and legacy unicast replies) use
the system's unicast TTL / hop limit, not 255; queriers in this project never set QU on the
shared port, and browsers do not either.

## Consequences

- New public API in akio-sys (two functions); `akio` and `akio-webrtc` signatures unchanged.
- An mDNS responder on an IPv6-only network can conceal; before, `conceal_host_candidates`
  returned an error there.
- `bind_udp_multicast_on` with an IPv6 group sends with hop limit 255 for any protocol, as the
  IPv4 path always did with TTL 255.

## Verification

- Unit: akio-sys `multicast_hops_v6_round_trip` (default 1, 255 and 0 set and read back, 256
  refused and the value unchanged). The engine's multicast tests (`crates/akio/tests/
  shared_ports.rs`) skip their IPv4 part where the host has no IPv4 multicast instead of failing.
- **IPv6-only link** (`tools/interop/webrtc/mdns6.sh`, Docker on gpu51): a container with no
  IPv4 network (`--network none`; `224.0.0.251` has no route) and a veth pair with link-local and
  ULA addresses. The akio-webrtc mDNS tests run there, epoll and `AKIO_TEST_BACKEND=uring`, 6/6
  with none skipped (two concealing IPv4 endpoints resolve each other through A records answered
  over `ff02::fb`, which failed before item 3); the engine's multicast tests 4/4 (IPv4 parts
  skipped).
- **avahi 0.8** (same container, `use-ipv4=no`, on one end of the veth, `check-response-ttl=yes`):
  `avahi-resolve -6` resolves the name an `Endpoint` conceals `fd00:6::1` behind; an `Endpoint`
  resolves a name only avahi publishes (`avahi-publish -a`, `fd00:6::2`; the answer arrived from
  `[fd00:6::2]:5353`) and connects to it with a data channel echo, the other side being given no
  candidates so only the resolution can connect them (new `webrtc-interop` modes `mdns-conceal`
  and `mdns-resolve`). Control: a build without item 2 (hop limit 1) is ignored by the same avahi
  (`avahi-resolve` times out) and resolved once `check-response-ttl=no`.
- **Chrome 157** (`browser.sh`, macOS, new section): an `Endpoint` whose only host candidate is its
  global IPv6 address, concealed, offers to headless Chrome with its mDNS concealment on. Chrome
  queries the name over `ff02::fb` on every link and we answer there (AAAA, on the link of the
  query); we resolve Chrome's concealed IPv6 candidate (its first answer arrived over IPv4: Chrome
  answers on the family of the query, and we query both); the selected pair is IPv6 and 100 data
  channel messages echo.
- **mDNSResponder** (macOS, by hand): `dns-sd -G v6` resolves a concealed link-local address
  (answers on en1 and lo0, AAAA, TTL 120), and `mdns-resolve` resolves a name published with
  `dns-sd -P` from the answer that arrived over IPv6 (`fe80::1%lo0`).
- `cargo test` of akio-sys, akio and akio-webrtc on macOS and on gpu51 (epoll and io_uring), clippy
  clean on both (rustc 1.100).

## Update (2026-11-22): claiming our names, goodbyes, unicast hop limit

The two gaps this ADR and the DEV-PLAN left open are closed:

- **Unicast answers with hop limit 255.** RFC 6762 §11 asks for TTL / hop limit 255 on every
  response, unicast ones included (answers to a QU question, legacy unicast replies). The
  shared mDNS sockets now set it for unicast too: new `UdpBinding::set_unicast_hops(u32)`
  (`IP_TTL` / `IPV6_UNICAST_HOPS`, 0..=255, additive in `akio-core` and `akio`) and
  `akio_sys::{set_unicast_hops_v6, unicast_hops_v6}` (std has `set_ttl` for IPv4 only).
  `Engine::bind_udp_multicast_on` itself is unchanged: the unicast limit is the protocol's
  choice, so akio-webrtc sets it on its mDNS bindings.
- **Probing and announcing (RFC 6762 §8), conflicts (§9), goodbyes (§10.1).** A concealed name
  is claimed as unique records must be: three probes 250 ms apart (`ANY` with the QU bit, the
  proposed `A` / `AAAA` record in the authority section; new `Message::probe` in akio-ice), the
  claim won 250 ms after the last, then two announcements 1 s apart (unsolicited responses with
  the cache-flush bit). Claiming does not hold the candidate up: the name is a random UUID that
  the description carries at once, and it is answered from the start. Conflicts give the name up: another host
  answering it with another address (§9), or probing it with a record that wins the §8.2
  tiebreak (class, type, then the record data as bytes; new `Record::tiebreak`) while ours is
  still being probed. A given-up name is no longer answered and its address gets a fresh name for
  the peers made after; peers already holding the old one keep it (a warning is logged). Probes
  of our own that come back by multicast loopback, or identical claims, are recognised by the
  proposed record and not answered; a probe after our claim is answered, which defends the
  name. `Endpoint::close` sends goodbyes (TTL 0) for every name before closing the sockets.
- akio-ice's `Message` gains `authority` (the authority section's address records; akio-ice is
  an internal crate, its API may change in any release).

Not done then: the random 0–250 ms delay before the first probe, announcements per interface
with only that interface's addresses (§6.2). Both done later the same day (second update,
below).

Verification:

- akio-ice: probe round trip (QU `ANY` question, authority records without cache flush, answers
  kept apart), tiebreak order; the `ice_mdns` fuzz target also rebuilds the authority records
  of what it parses as a probe (new seed).
- akio-webrtc `tests/mdns.rs`, against a raw socket on `ff02::fb`: a new name is probed three
  times at least 200 ms apart, claimed at least 200 ms after the last probe and announced twice
  at least 900 ms apart, with no answer to its own probes, and closing the endpoint sends its
  goodbye; an answer with another address gives the name up (the next offer carries a new
  name, and a query for the old one is no longer answered); a simultaneous probe with an `A`
  record loses to our `AAAA ::1`, one with `AAAA fd00::99` wins. akio `tests/shared_ports.rs`:
  `set_unicast_hops` on IPv4 and IPv6 bindings. akio-sys: the IPv6 unicast hop limit round trip.
- `tools/interop/webrtc/mdns6.sh` (gpu51, IPv6-only container): the mDNS tests with epoll and
  io_uring (9/9 each, none skipped), avahi 0.8 still resolves our name and publishes one we
  resolve, and a new step: avahi publishing the name an Endpoint has claimed (with fd00:6::2,
  `avahi-publish -a -R`) probes it, gets our answers and reports "Name collision"; the Endpoint
  keeps its name (avahi-publish then aborts on its own assertion looking for an alternative to
  a UUID label).

## Update 2 (2026-11-22): probe delay, link-local addresses on their own link

- **Random delay before the first probe** (RFC 6762 §8.1): a name's first probe leaves after a
  random 0–250 ms (`akio_sys::fill_random`), so endpoints or hosts that start together do not
  probe in lock step. The name is still in the description and answered at once.
- **Link-local IPv6 addresses stay on their link** (§6.2: an address record should only go
  out on an interface where the address is usable). The name of a link-local address keeps
  the scope id of the host candidate it conceals; its probes, announcements and goodbyes go to
  `ff02::fb` on that link only (not over IPv4, whose single group is on the default
  interface), and a query that arrives over IPv6 on another link is not answered with it.
  Queries over IPv4 are still answered (their link is not known). Other addresses (global,
  ULA, IPv4) go out on every link as before: telling which interface holds them needs the
  interface address list (`getifaddrs`), which the project does not read.

Not done: interface-aware IPv4 and non-link-local IPv6 records (no interface address list);
IPv4 multicast on interfaces other than the default one.

Verification: akio-webrtc `tests/mdns.rs` `link_local_names_stay_on_their_link` (an endpoint
on a link-local address: every copy of its probes and announcements carries that address as
source, which a send on another link would not; a query from another link gets no answer and
one from its link does; skipped with fewer than two links), the claiming tests unchanged with
the delay. macOS (lo0 and en*: all checks) and `tools/interop/webrtc/mdns6.sh` on gpu51 (epoll
and io_uring, avahi steps; the container's two links are the ends of one veth pair, one wire,
so the test notices that a query sent on one reaches the other and skips the other-link
check there).

## Update 3 (2026-11-23): records on the interface that holds the address, IPv4 on every interface

Update 2 left two gaps, both for want of an interface address list: addresses other than IPv6
link-local ones (IPv4, global and ULA IPv6) were probed, announced and answered on every link,
and IPv4 joined `224.0.0.251` on the default interface only, so a host on another IPv4 link
neither heard our announcements nor got answers, and our queries never reached it.

1. **akio-sys: the interface list.** `akio_sys::interfaces()` reads `getifaddrs(3)` (Linux and
   macOS, through the own `ffi` layer: `struct ifaddrs` is now shared by both, macOS declares
   `getifaddrs` / `freeifaddrs` / `if_nametoindex`) into owned values: `Interface { name, index,
   flags, addrs }`, `InterfaceFlags` (up, running, loopback, point-to-point, multicast),
   `InterfaceAddr { ip, prefix_len }` with `contains` (subnet test). Socket addresses are copied
   byte-wise, never referenced in place; on macOS at most `sa_len` bytes (netmasks are cut short)
   and the scope id the BSD kernels embed in link-local addresses is cleared. akio-tls's NIC
   offload check (`ktls::interface_addrs`) now uses it instead of its own `getifaddrs` loop.
2. **Sending out of an interface.** IPv4 multicast has no scope id: `IP_MULTICAST_IF` picks the
   interface for the whole socket, which an engine binding shared between threads cannot switch
   per datagram. `akio_sys::send_to_on(&UdpSocket, data, addr, interface)` names it per datagram
   instead, in an `IP_PKTINFO` / `IPV6_PKTINFO` control message (`ipi_ifindex`), which both
   Linux and macOS honour for a multicast destination; the source address is the system's choice
   on that interface. `UdpBinding::send_to_on` exposes it on engine bindings (additive).
   Checked: a datagram to a group sent out of each interface is looped back from that
   interface's address. macOS refuses a scoped multicast send on `lo0` ("network unreachable"),
   so mDNS leaves loopback out (this host's listeners get the copies looped back from the other
   interfaces).
3. **akio: IPv4 groups joined per interface.** `Engine::bind_udp_multicast_on` took `&[0]` only
   for an IPv4 group; it now takes interface indexes for both families (additive: what was
   refused now works). An IPv4 join names the interface by address, so each index is mapped to
   the interface's first IPv4 address through `akio_sys::interfaces`; unknown interfaces and
   those without IPv4 are skipped, and the call fails (`AddrNotAvailable`, or the last join
   error) only when none is left. Linux allows 20 IPv4 memberships per socket by default
   (`net.ipv4.igmp_max_memberships`); mDNS asks for at most 20.
4. **akio-webrtc: every address on its own interface.** `resolve_mdns` reads the interface
   list once. IPv4 joins `224.0.0.251` on every interface that is up, multicast-capable, not
   loopback and has an IPv4 address (the default interface when there is none, and when every
   per-interface join is refused); IPv6 joins `ff02::fb` as before (the list replaces the
   `/proc/net/if_inet6` / connect probing). Queries, probes, announcements and goodbyes go out of
   each IPv4 interface (`send_to_on`) and to `ff02::fb` on each IPv6 link. A concealed address
   gets the interface that holds it (a link-local IPv6 address: its scope id; the list is read
   again once if no interface holds it), and its records go out on that interface only, over
   both families. A query's interface is its source's scope id, else the interface holding the
   source address, else the one whose subnet holds it (the longest prefix); it is answered only
   with the records usable there, out of that interface: those of that interface, and (except
   IPv6 link-local ones, whose link is their scope) those whose address lies in one of its
   subnets. The second half matters where two interfaces share a link and a prefix (two NICs on
   one LAN, the two ends of a veth pair): a query from a global or ULA source carries no scope
   id, so its interface is inferred from the source and may be the other one. The first run of
   `mdns6.sh` showed it: avahi on v1 queries from `fd00:6::2`, the copy that crossed the veth
   arrived on v0, both read as "from v1", and `fd00:6::1` (on v0, in v1's `fd00:6::/64`) went
   unanswered; avahi still resolved it from our announcements, which cross the wire. Unchanged on purpose: loopback
   addresses have no interface (this host's queriers may ask on any link), and a query from a
   source on no known subnet (a querier with only a 169.254 address, say) is answered with every
   record, as before.

The receive path is unchanged: the engine does not report the interface a datagram arrived on
(no `IP_PKTINFO` on receive), so an IPv4 query's interface is inferred from its source address;
on two interfaces with overlapping subnets the longest prefix wins and ties go to the first.

Not done: interfaces that appear after `resolve_mdns` are not joined (an address to conceal on
none of the known interfaces re-reads the list for its records, not for the joins).

Verification:

- akio-sys: the interface list (a loopback interface with `127.0.0.1/8`, unique sorted indexes,
  no embedded scope in link-local addresses), subnets, `send_to_on` naming the interface (a
  nonexistent one refused), the `ifaddrs` / `in_pktinfo` / `in6_pktinfo` layouts, the `IP_PKTINFO`
  / `IPV6_PKTINFO` / `IFF_*` constants and the control message's `CMSG_LEN` / `CMSG_SPACE` against
  `libc`. akio `tests/shared_ports.rs` `ipv4_group_joined_and_sent_per_interface`: an IPv4 group
  joined on every interface by index, a datagram out of each looped back from that interface's
  address (macOS: en1 and bridge100, lo0 refused as above; gpu51: 5 of 5, Wi-Fi and four bridges
  without carrier).
- akio-webrtc `tests/mdns.rs` `ipv4_names_stay_on_their_interface` (two IPv4 multicast
  interfaces, the address on each in turn): every IPv4 probe and announcement of the name comes
  from the address's interface, a query sent out of the other interface is not answered, one
  out of its own is, from its address. Control: with the interface lookup and the IPv4 interface
  list disabled (the update-2 behaviour) it fails on the non-default interface ("sent on another
  interface").
- `tools/interop/webrtc/mdns4.sh` (gpu51, Docker, two veth pairs, IPv4 on a0 `10.66.1.1/24` and
  b0 `10.66.2.1/24`, default route on a0): the mDNS (11/11, none skipped) and engine multicast
  tests, epoll and io_uring; avahi 0.8 on b0 alone (IPv4 only, `check-response-ttl=yes`) resolves
  the name concealing `10.66.2.1` (b0, not the default interface), does not resolve the one
  concealing `10.66.1.1` (a0; timeout, and the Endpoint logs no answer), and publishes a name
  (`10.66.2.1`) that an Endpoint on `10.66.1.1` resolves (answer from `10.66.2.1:5353`) and
  connects to with 20 data channel echoes.
- `tools/interop/webrtc/mdns6.sh` green again after the on-link rule above (all avahi steps;
  the mDNS tests there skip the IPv4 one by name, as the link has no IPv4).
- macOS and gpu51 (rustc 1.100): `cargo test` of akio-sys, akio-core, akio and akio-webrtc on
  epoll and with `AKIO_TEST_BACKEND=uring`, akio-tls with `ktls` (its offload check now reads
  the interface list), clippy `-D warnings`, `tools/unsafe-inventory.py --check`.
