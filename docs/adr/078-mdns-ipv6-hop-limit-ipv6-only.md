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

## Update (2026-11-22): claiming our names, goodbyes, unicast hop limit

The two gaps this ADR and the DEV-PLAN left open are closed:

- **Unicast answers with hop limit 255.** RFC 6762 §11 asks for TTL / hop limit 255 on every
  response, unicast ones included (answers to a QU question, legacy unicast replies). The
  shared mDNS sockets now set it for unicast too: new `UdpBinding::set_unicast_hops(u32)`
  (`IP_TTL` / `IPV6_UNICAST_HOPS`, 0..=255, additive in `only-core` and `only`) and
  `only_sys::{set_unicast_hops_v6, unicast_hops_v6}` (std has `set_ttl` for IPv4 only).
  `Engine::bind_udp_multicast_on` itself is unchanged: the unicast limit is the protocol's
  choice, so only-webrtc sets it on its mDNS bindings.
- **Probing and announcing (RFC 6762 §8), conflicts (§9), goodbyes (§10.1).** A concealed name
  is claimed as unique records must be: three probes 250 ms apart (`ANY` with the QU bit, the
  proposed `A` / `AAAA` record in the authority section; new `Message::probe` in only-ice), the
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
- only-ice's `Message` gains `authority` (the authority section's address records; only-ice is
  an internal crate, its API may change in any release).

Not done then: the random 0–250 ms delay before the first probe, announcements per interface
with only that interface's addresses (§6.2). Both done later the same day (second update,
below).

Verification:

- only-ice: probe round trip (QU `ANY` question, authority records without cache flush, answers
  kept apart), tiebreak order; the `ice_mdns` fuzz target also rebuilds the authority records
  of what it parses as a probe (new seed).
- only-webrtc `tests/mdns.rs`, against a raw socket on `ff02::fb`: a new name is probed three
  times at least 200 ms apart, claimed at least 200 ms after the last probe and announced twice
  at least 900 ms apart, with no answer to its own probes, and closing the endpoint sends its
  goodbye; an answer with another address gives the name up (the next offer carries a new
  name, and a query for the old one is no longer answered); a simultaneous probe with an `A`
  record loses to our `AAAA ::1`, one with `AAAA fd00::99` wins. only `tests/shared_ports.rs`:
  `set_unicast_hops` on IPv4 and IPv6 bindings. only-sys: the IPv6 unicast hop limit round trip.
- `tools/interop/webrtc/mdns6.sh` (gpu51, IPv6-only container): the mDNS tests with epoll and
  io_uring (9/9 each, none skipped), avahi 0.8 still resolves our name and publishes one we
  resolve, and a new step: avahi publishing the name an Endpoint has claimed (with fd00:6::2,
  `avahi-publish -a -R`) probes it, gets our answers and reports "Name collision"; the Endpoint
  keeps its name (avahi-publish then aborts on its own assertion looking for an alternative to
  a UUID label).

## Update 2 (2026-11-22): probe delay, link-local addresses on their own link

- **Random delay before the first probe** (RFC 6762 §8.1): a name's first probe leaves after a
  random 0–250 ms (`only_sys::fill_random`), so endpoints or hosts that start together do not
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

Verification: only-webrtc `tests/mdns.rs` `link_local_names_stay_on_their_link` (an endpoint
on a link-local address: every copy of its probes and announcements carries that address as
source, which a send on another link would not; a query from another link gets no answer and
one from its link does; skipped with fewer than two links), the claiming tests unchanged with
the delay. macOS (lo0 and en*: all checks) and `tools/interop/webrtc/mdns6.sh` on gpu51 (epoll
and io_uring, avahi steps; the container's two links are the ends of one veth pair, one wire,
so the test notices that a query sent on one reaches the other and skips the other-link
check there).
