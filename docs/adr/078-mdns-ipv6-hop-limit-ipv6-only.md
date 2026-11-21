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
  default hop limit of 1: std has no `set_multicast_hops_v6`, and `only` forbids unsafe code.
- **IPv6-only links.** `conceal_host_candidates` required the IPv4 socket to be on the shared
  port. On a link without IPv4 (no route to `224.0.0.251`) that socket falls back to an
  ephemeral port, so concealing failed although the IPv6 socket held port 5353 and could answer.
- **Interop.** ADR-054's IPv6 tests ran between our own sockets; no browser or other responder
  had resolved or answered over `ff02::fb`, and no test ran on an IPv6-only link.

## Decision

1. **only-sys: `set_multicast_hops_v6(&UdpSocket, u32)` and `multicast_hops_v6(&UdpSocket)`**
   (`IPV6_MULTICAST_HOPS`, Linux and macOS; values above 255 are refused with `InvalidInput`
   before the system call). Additive public API.
2. **only: `Engine::bind_udp_multicast_on` with an IPv6 group** sets the hop limit to 255 and
   multicast loopback on, as the IPv4 path sets TTL 255 (loopback is now set explicitly there
   too). Interface choice stays per datagram: the scope id of the destination
   (`ff02::fb%<index>`) picks the link, which is what `IPV6_MULTICAST_IF` would do per socket.
   UDP client threads are epoll / kqueue on every backend, so this path is the same with
   `ONLY_TEST_BACKEND=uring`.
3. **only-webrtc: names are answered over whichever family holds the shared port.**
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

- New public API in only-sys (two functions); `only` and `only-webrtc` signatures unchanged.
- An mDNS responder on an IPv6-only network can conceal; before, `conceal_host_candidates`
  returned an error there.
- `bind_udp_multicast_on` with an IPv6 group sends with hop limit 255 for any protocol, as the
  IPv4 path always did with TTL 255.

## Verification

- Unit: only-sys `multicast_hops_v6_round_trip` (default 1, 255 and 0 set and read back, 256
  refused and the value unchanged). The engine's multicast tests (`crates/only/tests/
  shared_ports.rs`) skip their IPv4 part where the host has no IPv4 multicast instead of failing.
- **IPv6-only link** (`tools/interop/webrtc/mdns6.sh`, Docker on gpu51): a container with no
  IPv4 network (`--network none`; `224.0.0.251` has no route) and a veth pair with link-local and
  ULA addresses. The only-webrtc mDNS tests run there, epoll and `ONLY_TEST_BACKEND=uring`, 6/6
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
- `cargo test` of only-sys, only and only-webrtc on macOS and on gpu51 (epoll and io_uring), clippy
  clean on both (rustc 1.100).
