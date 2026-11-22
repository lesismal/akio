# ADR-083: TURN dual allocations and ECN across the relay

English | [简体中文](083-turn-dual-allocations-ecn-relay.zh-CN.md)

Status: accepted (2026-11-22)

## Context

Two leftovers of `akio-turn`, both listed as not done elsewhere:

- **Dual allocations.** ADR-076 listed "`ADDITIONAL-ADDRESS-FAMILY` dual allocations (not
  supported for UDP either)". RFC 8656 lets one Allocate ask for an IPv4 and an IPv6 relayed
  address at once. The server relayed from one `relay_ip`, so it had one family:
  `REQUESTED-ADDRESS-FAMILY` of the other family got 440, and the attribute was ignored.
- **ECN across the relay.** ADR-077 added the ECN plumbing: the codepoint of each received
  UDP datagram (`Conn::rx_ecn`, from `IP_RECVTOS` / `IPV6_RECVTCLASS` on Linux and macOS), and
  marked sends (`UdpBinding::send_to_ecn`, `Conn::send_segments_ecn`). ADR-082 made akio-webrtc
  mark what it sends through a TURN server over UDP, relying on the server to copy the
  codepoint. It listed "copying the codepoint in akio-turn's own relay" as not done: a path
  through `akio-turn` failed ECN validation after a few probes.

RFC 8656 in short:

- **Allocate (section 7.2).**
  - Both `REQUESTED-ADDRESS-FAMILY` and `ADDITIONAL-ADDRESS-FAMILY`: 400.
  - `RESERVATION-TOKEN` with either of them, or with `EVEN-PORT`: 400.
  - `EVEN-PORT` with the R bit together with `ADDITIONAL-ADDRESS-FAMILY`: 400 (it would need
    two tokens).
  - `ADDITIONAL-ADDRESS-FAMILY` other than IPv6 (0x02): 400.
  - A requested family the server does not relay: 440. Without either attribute the
    allocation is IPv4.
  - A dual request the server can meet only partly succeeds with the IPv4 address and an
    `ADDRESS-ERROR-CODE` (family, 440 or 508) for the other.
  - A full success carries two `XOR-RELAYED-ADDRESS`.
- **Refresh (section 8).**
  - `REQUESTED-ADDRESS-FAMILY` picks the family refreshed, or deleted with lifetime 0.
  - Without it, the refresh applies to all families.
  - A family the allocation lacks: 443.
  - Deleting one family takes its permissions and channels and leaves the other's.
- **Permissions and channels (sections 9, 10, 12).**
  - A peer must be of a family the allocation has, else 443.
  - One CreatePermission may name peers of both families.
- **ECN (section 14, UDP to UDP).**
  - Preferred behaviour: set the outgoing codepoint to the incoming one, both ways.
  - Over TCP to the client (sections 15, 16) there is nothing to copy: Not-ECT out, and the
    peer's codepoint dropped.

## Decision

### Server: dual allocations

**Configuration.** `TurnConfig::additional_relay_ip` is an address of the other family than
`relay_ip`, and `additional_public_ip` its 1:1 NAT address. Both are optional and `None` by
default; an address of `relay_ip`'s own family is ignored.

**Allocations.** An allocation holds one or two relayed addresses (`RelayAddr`: bound address,
public address, expiry), each with its own lifetime.

- The allocation is alive while any of them is, and goes, with its quota, with the last one.
- A dual allocation counts as one allocation for the quotas.
- Permissions are keyed by IP address and channels by peer address, as before, so each belongs
  to its family by construction.
- Data to a peer leaves from the relayed address of the peer's family.
- A peer's datagram is accepted only on the relayed address of its own family. It needs that
  address alive and a permission.

**Family rules** (`families()`, one function shared by the Allocate and by prebinding):

- Exactly section 7.2, in its order.
- Without either attribute: IPv4 when the server relays IPv4. A server configured with an IPv6
  `relay_ip` only still allocates IPv6, as before, rather than refusing with 440 as the RFC
  says. Existing IPv6-only deployments keep working.
- A dual request needs IPv4 (440 on an IPv6-only server).

**Partial success.**

- No IPv6 relay configured: the IPv4 address with `ADDRESS-ERROR-CODE` (IPv6, 440).
- The IPv6 socket fails to bind: the same with 508.
- The IPv4 socket fails to bind: 508 for the whole request.
- A retransmitted Allocate gets the same answer, so the code is stored with the allocation.
- `EVEN-PORT` without the R bit applies to both families.

**Refresh, permissions, channels, Connect:** as the RFC (443, 400 for an unknown family value
in a Refresh). Expiry is per family: the sweep closes an expired relayed address alone, with
its permissions and channels.

**coturn's codepoints.** coturn 4.6 numbers `ADDITIONAL-ADDRESS-FAMILY` 0x8032 and
`ADDRESS-ERROR-CODE` 0x8033, as draft-ietf-tram-turnbis did. RFC 8656 assigned 0x8000 and
0x8001; 0x8032 and 0x8033 are unassigned at IANA. Seen in the interop run:

- coturn's `turnutils_uclient -Z` against akio-turn got one relayed address, then 443 for its
  IPv6 permissions.
- Our client against coturn got one relayed address and no error code.

So the server takes 0x8032 as an alias, under the same rules. A response to a request that used
it carries `ADDRESS-ERROR-CODE` at both codepoints. Both attributes are comprehension-optional,
so a server that knows one ignores the other.

**TCP allocations** (RFC 6062) have one relayed address. A dual request over TCP or TLS gets
the IPv4 listener and `ADDRESS-ERROR-CODE` (IPv6, 440), not an error, so a client that always
asks for both still gets an allocation.

**Prebinding.** An authenticated Allocate gets its relay sockets bound before the shard lock
is taken, as before. `Shared::prebind_ips` now returns the addresses to bind: one, or two for a
dual request the server can meet, none for anything malformed. `Env::open_relay` takes the
prebound socket of the matching address, and unused ones are closed after the shard is
released.

### Server: ECN across the relay

- `TurnEnv` gains `send_to_client_ecn` and `send_to_peer_ecn`. Their defaults call the old
  methods and drop the codepoint, so existing environments compile unchanged.
- `TurnCore` gains `handle_client_ecn` and `handle_peer_ecn`, with the codepoint of the
  datagram. The old entry points pass 0.
- ChannelData and Send indications go to the peer with the client's codepoint. Peer datagrams
  go to the client, as ChannelData or Data indications, with the peer's codepoint.
- Requests and responses never carry one.
- `TurnServer` reads `Conn::rx_ecn()` on the listener connection (UDP clients, and DTLS
  clients: the codepoint of the datagram goes with every record in it) and on the relay
  connection (peers).
- To a peer: a marked datagram goes out with `UdpBinding::send_to_ecn` (one `sendmsg` with
  an `IP_TOS` / `IPV6_TCLASS` control message), an unmarked one with `send_to`.
- To a client: `Conn::send_segments_ecn(data, 0, ecn)` queues one datagram with its codepoint
  through the corked send path; DTLS records go the same way.
- Stream clients neither give nor get a codepoint (sections 15, 16).
- Unmarked traffic takes exactly the old path (the codepoint is checked once). Where the
  platform reports no ECN, `rx_ecn` is 0 and nothing changes.

### Client

- `ClientConfig::dual_allocation` (false) adds `ADDITIONAL-ADDRESS-FAMILY` IPv6 to the
  Allocate, at 0x8000 and at coturn's 0x8032. `address_error` reads either codepoint.
- `Client::relayed_addrs` gives one or two addresses, IPv4 first; `relayed_addr` stays the
  first. `relayed_addr_for(peer)` picks the one of the peer's family.
- `Client::address_error` gives the `ADDRESS-ERROR-CODE` (family, code, reason).
- Refreshes carry no family, so both are refreshed.
- Permissions and channels are per peer as before. The server routes them by family, and a
  peer of a missing family gets 443 (`ClientEvent::PeerFailed`).
- `ClientEvent::Allocated` is unchanged (`relayed` is the first address). Adding a field would
  break exhaustive patterns.
- STUN codec: `attr::ADDRESS_ERROR_CODE`, `Message::address_error_code`,
  `MessageBuilder::address_error`.

### akio-webrtc: relay gathering only

- `RelayServer::dual_allocation(true)` asks for a dual allocation.
- `Endpoint::gather_relay_via` then adds one relayed candidate per family, and returns the
  IPv4 one. A lost allocation is made again with both.
- Data from the server is attributed to the relayed address of the peer's family, so ICE sees
  the right local candidate.
- It is opt-in, and plain `gather_relay` still asks for one family:
  - a dual allocation costs the server a second port;
  - an IPv6 relayed candidate is only useful against peers with IPv6 candidates;
  - pion/turn ignores the attribute and returns one address anyway.
- Nothing else in akio-webrtc changed. Another session works on WebRTC ECN, and akio-webrtc
  already keeps the codepoint of relayed input (ADR-082).

### Not done

- ICMP relaying (`ICMP` attribute, section 11.5). Unchanged.
- DSCP copying (section 14 prefers it too). Only the two ECN bits are copied, through the
  existing API; the TOS byte's upper six bits stay the socket's.
- A per-family `REQUESTED-ADDRESS-FAMILY` in the client's Refresh (refreshing or deleting one
  family). The server supports it; the client always refreshes both.
- Dual allocations by default in `Endpoint::gather_relay` (see above).

## Consequences

- Behaviour change: on a server with `additional_relay_ip`, `REQUESTED-ADDRESS-FAMILY` of the
  other family now succeeds instead of 440. With an IPv6 `relay_ip` and an IPv4
  `additional_relay_ip`, an Allocate without the attribute now gets IPv4 (RFC 8656). Without
  `additional_relay_ip`, nothing changes except that a dual request is answered with
  `ADDRESS-ERROR-CODE` (before, the attribute was ignored).
- ECN validation (ADR-077 / ADR-082) now succeeds through `akio-turn` over UDP and DTLS.
- Public API: additions only (`api/akio-turn.txt`, `api/akio-webrtc.txt`).
- Performance: UDP relay A/B against main on gpu51 (`turn-relay-bench 8 6 4`, alternating under
  `quiet.sh`):
  - 6 rounds: medians 297.5k vs 297.3k datagrams/s;
  - 10 more rounds: means 305.7k vs 304.6k;
  - rounds vary by about ±20 %, so: no measurable change.
  - Every datagram marked (the relay copying): about 0.94x of unmarked, within the spread.
  - docs/BENCHMARKS.md has the table.

Tests:

- Core unit tests (`core/tests_dual.rs`):
  - the dual success and its retransmission, public addresses per family;
  - every 400 / 440 case; IPv4-only, IPv6-only and IPv6-first servers;
  - partial success with 440 and 508; 443 for a missing family;
  - permissions and channels per family both ways, a peer on the wrong family's relay dropped;
  - refresh of one family (the other expires alone, its channels gone, the other's kept), 443
    after it, deletion of one family then the last, refresh and delete of all;
  - a TCP allocation with a dual request;
  - codepoints copied both ways on ChannelData, Send and Data indications, none on responses;
  - prebinding per family.
- Client unit tests: dual allocation through 30 minutes of refreshes with peers of both
  families, close; partial with 440 and an IPv6 peer refused.
- `tests/dual_ecn.rs` on real sockets: 127.0.0.1 and ::1 relays, ECT(1), ECT(0) and CE copied
  both ways per family, unmarked stays unmarked. A sabotaged server that drops the codepoint
  fails it.
- akio-webrtc `tests/relay.rs`: an IPv4 endpoint reaches an IPv6-only endpoint through the
  IPv6 relayed candidate of a dual allocation.
- Platforms: macOS, and gpu51 epoll and io_uring. Clippy clean.
- Interop (`tools/interop/webrtc/turn-dual.sh`, Docker on gpu51, coturn 4.6 relaying from
  127.0.0.1 and ::1, pion/turn v5.1.3):
  - coturn's `turnutils_uclient` with dual allocations (`-Z`) and with IPv6 relays (`-x`),
    clients sending to each other's relayed addresses, against akio-turn and against coturn:
    40 and 80 messages, none lost.
  - The akio_turn client asking for a dual allocation:
    - against coturn: two relayed addresses, 20 datagrams echoed per family;
    - against pion/turn: one, since it ignores the attribute and sends no error code;
    - against akio-turn: two.
  - ECN: akio-turn copies ECT(0) client to peer and ECT(1) peer to client on both families.
    So does coturn. pion/turn clears both.
  - pion/turn's client with `REQUESTED-ADDRESS-FAMILY` IPv4 and IPv6 against akio-turn and
    coturn: the relay of that family, 20 datagrams echoed.
- Fuzzing: `turn_server` now uses a dual-capable server, picks IPv6 peers and ECN codepoints
  from the selector byte, and asserts that relayed data keeps its codepoint and leaves from an
  open relay of the peer's family, and that everything is closed at the end. New seeds: a dual
  session. `turn_stream`'s client side asks for dual allocations. Run on gpu51 for 5 minutes
  per target (libFuzzer, built as cargo-fuzz does): `turn_server` 11.1M runs, `turn_stream`
  14.0M, `turn_tcp` 10.2M and `turn_dtls` 7.3M (both start from the changed server), no
  finding.
