# ADR-044: mDNS ICE candidates, renomination and aggressive nomination, simultaneous-open ICE-TCP

English | [简体中文](044-ice-mdns-renomination-tcp-so.zh-CN.md)

Status: accepted (2026-11-19)

## Context

Browsers hide their host addresses: Chrome (and Firefox, Safari) write each host candidate as
a random `<uuid>.local` name (draft-ietf-mmusic-mdns-ice-candidates) and answer multicast DNS
queries (RFC 6762) for it on the local network. `only-ice` parsed such lines into
`ParseError::Mdns` and `only-webrtc` skipped them, so an `Endpoint` could reach a browser on the
same LAN only through the peer-reflexive candidates the browser's own checks created: never when
the browser could not reach us first, and never when both sides conceal. Nor could an `Endpoint`
conceal its own host addresses.

The controlling agent only did regular nomination (RFC 8445 §8.1.1) and never looked at a pair
again once one was nominated, so a better pair that appeared later (a candidate trickled late,
an IPv6 path) was never used; peers built for RFC 5245 sometimes expect aggressive nomination;
and the controlled side switched to whatever pair the remote nominated last, which is wrong with
an aggressive remote (several nominations, the best one wins) and with renomination
(draft-thatcher-ice-renomination: the highest NOMINATION value wins). Simultaneous-open ICE-TCP
(RFC 6544 `tcptype so`) candidates were parsed but no local one could be made.

Several components (RTP and RTCP on separate candidates) stay out of scope: every WebRTC peer
uses rtcp-mux and BUNDLE, and so do the stack's own SDP offers and answers.

## Decision

1. **mDNS codec** (`only_ice::mdns`, sans-io): `Message::parse` (questions and `A` / `AAAA`
   records of the answer and additional sections, compression pointers followed backwards
   only and at most 16 per name, names lowercased, at most 32 questions and 64 records, other
   record types skipped, opcodes and rcodes other than 0 refused), `Message::query(name, qtype,
   unicast)` (one question per message: Chromium's responder ignores a message with several,
   which is how our first two-question queries went unanswered), `Message::response(id,
   questions, records)`, `random_name()` (a v4 UUID `.local` name as browsers make them),
   `is_mdns_name`, `valid_name`. Fuzz target `ice_mdns`.
2. **Candidates with names**: `Candidate::parse_resolved(line, resolve)` passes the name of a
   well-formed line (an mDNS name lowercased, or another FQDN) to `resolve` once and takes the IP
   it returns (`None` keeps `ParseError::Mdns` / `Fqdn`), keeping the name as
   `Candidate::hostname()`; `Candidate::with_hostname(name)` writes a name instead of the IP in
   the SDP while the agent keeps the address; `Candidate::with_related(addr)` sets or hides
   (`0.0.0.0:0`) the related address. `Candidate::parse` is `parse_resolved` with no resolver.
3. **Resolver and responder** (`Endpoint::resolve_mdns(&engine, timeout)`): one socket served by
   an engine I/O thread, never blocking: the mDNS port shared with the system's responder
   (`Engine::bind_udp_multicast`: `0.0.0.0:5353` with `SO_REUSEADDR` / `SO_REUSEPORT`, member of
   `224.0.0.251`), or, when that cannot be bound, an ephemeral port sending legacy unicast
   one-shot queries (RFC 6762 §6.7). Remote `.local` candidates of a description or trickled
   through `Peer::add_remote_candidate` are queued by the peer and resolved: `A` and `AAAA`
   queries at once, again after 1 and 2 seconds, then every 2 seconds until the timeout; every
   answer, asked for or not, is cached for its TTL (at most 2 minutes and 256 names: browsers
   announce their names just before their description arrives and then answer the same record
   at most once a second, RFC 6762 §6), only answers from port 5353 count. Each waiting peer
   gets one candidate per address of the name, unless its remote ufrag changed since (an ICE
   restart). Bounds: 64 names in flight, 16 peers per name, 32 pending lines per peer.
4. **Concealing our host addresses** (`Endpoint::conceal_host_candidates()`, after
   `resolve_mdns` on the shared port): new peers signal each host candidate (UDP and TCP) under a
   random name, one per address, and the related address of the other candidates as
   `0.0.0.0:0`; the socket answers `A` / `AAAA` / `ANY` queries for those names (120 s TTL,
   cache-flush, multicast; unicast when every question has the QU bit; legacy unicast queries
   get the query's id and questions back, 10 s TTL, no cache-flush).
5. **Nomination**: `IceConfig::aggressive_nomination` (controlling: USE-CANDIDATE on every
   check; the first pair that works is selected and a better one that works later replaces it;
   checks of better pairs go on after a selection) and `IceConfig::renomination` with
   `IceAgent::set_remote_renomination` (both sides support draft-thatcher renomination:
   controlling, checks of better pairs go on after nomination and a better valid pair is
   nominated again with a higher NOMINATION value (attribute 0xC001), at once when no better
   pair is still pending, else `nomination_delay` after it became valid). The controlled side
   now picks among nominations: with NOMINATION the highest value wins, without it a nominated
   pair replaces the selected one only if its priority is higher (a lite agent: the last
   nomination unless its NOMINATION value is not higher). Regular nomination is unchanged and
   stays the default. `RtcConfig::enable_ice_renomination` (offers `a=ice-options:trickle
   renomination`, reads the remote's `ice-options`) and
   `RtcConfig::enable_ice_aggressive_nomination` expose them in `only-webrtc`.
6. **Simultaneous-open ICE-TCP** (`Endpoint::listen_tcp_so(&engine, addr)`): a `tcptype so`
   host candidate on a port that listens (`SO_REUSEPORT`) and from which the checks to a remote
   `so` candidate are dialed (`Engine::dial_from`): whichever SYN arrives first, the result is
   one connection (crossing connects are TCP simultaneous open; otherwise the listener accepts
   the other side's, our own connect then fails with `EADDRNOTAVAIL` and what it had queued is
   sent over the accepted connection once it is handed over, within 2 s). Accepted connections
   are identified by their first check as for passive candidates. In only-ice, local active and
   `so` candidates were already able to send checks; the README claimed otherwise and is fixed.
7. **Engine primitives** (`only`): `Engine::bind_udp_multicast(group, acceptor)` and
   `Engine::dial_from(local, addr, acceptor, on_error)`, on `only_sys::connect_nonblocking_from`
   (bind with `SO_REUSEADDR` / `SO_REUSEPORT`, non-blocking connect: two `unsafe` blocks, the
   `bind` and `connect` calls, documented like the existing ones) and a new backend hook
   `Group::dial_stream` (epoll and io_uring: a stream whose connect is in progress goes through
   the dial path).

## Consequences

- Public API: only-ice (Internal tier) `mdns` module, `Candidate::{parse_resolved,
  with_hostname, hostname, with_related}`, `IceConfig::{aggressive_nomination, renomination}`,
  `IceAgent::set_remote_renomination`; only-webrtc `Endpoint::{resolve_mdns,
  conceal_host_candidates, listen_tcp_so}`, `RtcConfig::{enable_ice_renomination,
  enable_ice_aggressive_nomination}`; `only` `Engine::{bind_udp_multicast, dial_from}`;
  only-sys `connect_nonblocking_from`; only-core (hidden) `Group::dial_stream`. All additive;
  with none of it called, SDP and behaviour are unchanged, except that the controlled side
  ignores a later USE-CANDIDATE on a lower-priority pair (RFC 5245 aggressive semantics; with
  regular nomination there is only one per generation). `Peer::add_remote_candidate` with an
  mDNS line returns `Ok` when the endpoint resolves names, the same error as before otherwise.
  only-webrtc depends on only-sys (the `so` listener), `only` on only-sys as a normal
  dependency.
- Tests: the codec (round trips, compression, pointer loops, truncation, counts, opcodes);
  candidates with names; in the simulated network, a better pair trickled after nomination
  with regular nomination (kept), aggressive nomination and renomination (both sides move, 10 %
  loss too, NOMINATION only with renomination), aggressive nomination ending on the best pair,
  and the controlled side following the highest NOMINATION value over an older one; two
  endpoints that both conceal and resolve each other over the host's mDNS (offer candidates and
  trickled ones; a zero timeout makes it fail, so the resolution is what connects them);
  `so`-only endpoints in three rounds; the engine's `dial_from` (two connections from one port)
  and `bind_udp_multicast` (two bindings of one group). macOS and gpu51 (epoll and io_uring).
- Interop (`tools/interop/webrtc/browser.sh`, headless Chrome 157): an `Endpoint` that
  conceals its address offers to a second Chrome with mDNS concealment on (its default): Chrome
  resolves our name (our responder answers its query), we resolve Chrome's (its responder
  answers our one-question queries within a millisecond; before the fix, only its unsolicited
  announcements did), Chrome selects host to host, 100 messages echoed, three rounds; an
  `Endpoint` with aggressive nomination offers to Chrome (data channel echo). pion/webrtc v4
  (`run.sh`): an `Endpoint` with aggressive nomination, and one offering renomination (pion does
  not advertise it, so regular nomination runs), echo data channels; the rest of `run.sh`
  passes unchanged. Browsers and pion have no `so` candidates, and neither advertises
  renomination, so those two are tested between our own agents and endpoints only.
- Fuzzing: `ice_mdns` (messages and lines with names, seeds from the codec and a browser-like
  compressed answer) and `ice_stun` now also drives agents with aggressive nomination and
  renomination. 11 minutes each on gpu51: `ice_mdns` 27.2M runs, `ice_stun` 4.70M runs, no finding
  in the code; the first runs stopped on a check of the harness that was too strict (an active
  TCP candidate read from a line with a port other than 9 is written back with port 9, as RFC
  6544 wants), relaxed, its inputs kept as seeds.
- Not done: several components (rtcp-mux is universal in WebRTC); gathering (STUN / TURN
  clients stay the caller's); mDNS over IPv6 multicast (`ff02::fb`; names may still resolve to
  IPv6 addresses) and probing / announcing our own names (they are random UUIDs, so conflicts are
  not expected); resolving FQDN candidates through DNS; renomination when the remote does not
  advertise it (an ICE restart is the way then).

Note (2026-11-22): mDNS over IPv6 multicast is done. ADR-054 (2026-11-20) added the `ff02::fb`
socket (per-interface joins, AAAA answers on the link of the query, scope ids of remote
link-local addresses); ADR-078 sends it with hop limit 255 (RFC 6762 §11), conceals on
IPv6-only links, and checks it against Chrome 157, avahi 0.8 and mDNSResponder
(`tools/interop/webrtc/mdns6.sh`, `browser.sh`). Probing / announcing our own names is still
not done.
