# ADR-032: TURN over TCP and TLS from an `Endpoint`, active and server ICE-TCP, simulcast with Chrome

English | [简体中文](032-webrtc-turn-streams-ice-tcp-simulcast.zh-CN.md)

Status: accepted (2026-11-18)

## Context

[ADR-017](017-webrtc-turn-gaps.md) left these WebRTC gaps open:

- an `Endpoint` allocated relayed candidates over UDP only, although the sans-io
  `akio_turn::client::Client` already spoke TURN over streams; networks that block UDP reach a
  TURN server only over TCP, or TLS on 443 (`turn:?transport=tcp`, `turns:`);
- an `Endpoint` had a passive ICE-TCP candidate but no active one, so it could not reach a
  TCP-only server (pion with an ICE TCP mux, a media server behind a UDP-hostile firewall);
- an `RtcServer` (ICE-lite, one UDP port) had no ICE-TCP at all, so browsers whose UDP is blocked
  could not reach it except through a TURN relay;
- simulcast was tested against pion only, not against Chrome, in either direction, and an SFU
  forwarding one layer of several had no way to ask the sender for a keyframe of that layer only.

## Decision

### 1. Relayed candidates over TCP and TLS (`akio-webrtc`)

- **`RelayServer`**: a TURN server an `Endpoint` allocates on: `RelayServer::udp(addr, user,
  password)`, `::tcp(..)`, `::tls(addr, server_name, tls::ClientConfig, ..)`, or
  `RelayServer::from_url("turn:host[:port][?transport=udp|tcp]" | "turns:host[:port]
  [?transport=tcp]", user, password)` (RFC 7065, ports 3478 and 5349 by default, IPv6 in
  brackets). `from_url` resolves the host (blocking, like `gather_relay` itself); a `turns:`
  server needs `RelayServer::tls_config` before use, since `akio-tls` has no default roots (the
  URL's host is the name the certificate is verified for). `addr()` and `transport()` read it
  back.
- **`Endpoint::gather_relay_via(&Arc<Engine>, &RelayServer, timeout)`**: `gather_relay` over any
  transport. Over a stream the engine dials the connection (`Engine::dial`, wrapped in
  `Tls::client` for TLS), the client runs with `ClientConfig::stream(true)`, and the connection's
  bytes are cut by `akio_turn::framing::FrameReader`. One allocation per server and transport;
  at most 4 per endpoint, as before.
- **Candidates**: the relayed address is UDP whatever the control transport, but a TCP- or
  TLS-allocated candidate ranks below a UDP-allocated one (local preference halved over TCP,
  quartered over TLS, as browsers rank them) and has a foundation of its own
  (`akio_ice::Candidate::relayed_over_stream`, internal tier). No server-reflexive candidate comes
  from a stream allocation: the server saw a TCP address.
- **Backpressure and bounds**: up to 64 KiB of messages wait for the connection to open;
  relayed data (ChannelData, Send indications) is dropped while the connection has more than
  256 KiB queued (stale media; DTLS, SCTP and RTP recover), requests and responses always go.
- **Loss and reconnection**: an allocation that is lost after it was made (its connection
  closed, or over UDP a refresh failed) is made again after 1 second, the wait doubling up to a
  minute, for as long as the endpoint lives; a success resets the wait. The new relayed address
  replaces the old one in the endpoint's candidates and is added to every open peer
  (`Hub::relay_reallocated`), whose agent checks it against the remote candidates it knows: a
  peer whose remote side is reachable from the relay recovers without signalling (tested: data
  flows again about a second after the connection is cut). A peer that reached the other side only
  through the old relayed address needs an ICE restart, whose offer carries the new candidate.
  What a peer still sends from a retired relayed address is dropped instead of leaving from the
  host socket. A failure before the first allocation is reported (`Error::Turn`, `Error::Timeout`)
  and not retried.

### 2. Active ICE-TCP on `Endpoint`

- **`Endpoint::dial_tcp(&Arc<Engine>) -> SocketAddr`** adds an active TCP host candidate: the
  endpoint's primary host address with port 9, which is what the SDP writes for an active
  candidate (RFC 6544 §4.5) and so also the address the agent pairs from. Its agent pairs it with
  the remote passive candidates; the first check of a pair makes the endpoint dial one
  connection for that peer and remote address (RFC 6544 §5.1: a connection per pair), queuing
  up to 64 KiB until it is up; other datagrams to a remote without a connection are dropped.
  Frames arriving on it go to that peer as datagrams from the remote address to the candidate's
  address. A connection that fails or closes is forgotten and the agent's next check dials
  again; a peer's connections close with it. Active and passive connections of an endpoint are
  bounded together (256).
- **Simultaneous-open (`tcptype so`) is not implemented**: neither browsers nor pion offer it,
  and it needs both ends to connect at once through NATs, which ICE over UDP or a TURN relay does
  better.

### 3. Passive ICE-TCP on `RtcServer`

It fits the ICE-lite design: a lite agent only answers checks and never sends them, and a
passive candidate only accepts connections, so the server needs no connection logic of its own.

- **`RtcServer::tcp_candidates(addrs)`** adds passive TCP host candidates to every answer and
  offer; **`RtcServer::tcp() -> RtcTcp`** is the acceptor for the engine's TCP listener at those
  addresses (`Listener::tcp(addr).serve(server.tcp())`), so the server's connections run on the
  engine's I/O threads like any other.
- The rules of the endpoint's passive candidate apply: the first frame must be a check naming
  one of the server's peers within 10 seconds, frames then go to that peer as datagrams, the
  peer's transmits from the candidate's address go back framed (dropped past 1 MiB queued), and a
  peer's connections close with it. At most twice `RtcServer::max_peers` connections (at least
  256; 4096 without a peer limit). The connection's local address picks the candidate (exact
  address, else the same port and family) when the listener is bound to the unspecified address.
- The TCP listener may share the UDP listener's port, so a TCP and a UDP candidate may have one
  address: a peer remembers the remote addresses that reached it over a connection (at most 16,
  under its own lock) and sends to those over it, so the UDP path takes no shared lock; the
  `akio-ice` agent keeps a UDP and a TCP local candidate of one address apart (it used to drop
  the second as a duplicate). A connection looks its peer up once, at its first check.
- Internally the endpoint's and the server's ICE-TCP share one `TcpSide` (passive candidates,
  the active candidate, connections by remote address and by peer and remote).

### 4. Choosing the local candidates: `Endpoint::candidate_filter`

- **`Endpoint::candidate_filter(f)`**: new peers start with only the local candidates `f`
  accepts, in their agents and in their offers and answers: a browser's `iceTransportPolicy`
  (`|c| c.kind() == "relay"`), or ICE-TCP only (`|c| c.transport() == "tcp"`). A reallocated
  relayed candidate is offered to open peers only if it passes. **`Candidate::kind()`** (`host`,
  `srflx`, `prflx`, `relay`) and **`Candidate::transport()`** (`udp`, `tcp`) let the filter (and
  applications) tell candidates apart. Without it a relay-only offer still leaves the agent
  checking from its host candidate, so an interop run could not prove the relay was used.

### 5. Simulcast with Chrome

Verified with headless Chrome (`tools/interop/webrtc/browser.sh`, `sfu` mode of the
`webrtc-interop` example):

- **From Chrome**: Chrome publishes three VP8 encodings (`l`, `m`, `h` at 1/4, 1/2 and full
  scale of 1280x720); the `RtcServer` answer accepts them (`a=simulcast:recv l;m;h`) and every RID
  arrives with its own stream (Chrome reports frames sent on each).
- **Layer selection**: an SFU forwarding one layer to a viewer switches at a keyframe of the new
  layer and asks the publisher for exactly that one: **`Peer::request_layer_keyframe(mid, rid,
  kind)`** sends PLI or FIR to the received stream of that RID only (`Error::UnknownMedia` when
  none arrived). Chrome decodes the selected layer as it is switched l -> m -> h (320, 640 and
  1280 pixels wide). The example rewrites RTP timestamps on a switch; that stays application
  logic, like the choice of layer.
- **To Chrome**: Chrome does not negotiate receiving simulcast: its answer to an offer with
  `a=simulcast:send` carries no `a=simulcast` or `a=rid`. As RFC 8853 says, and as ADR-017
  implemented, only the first encoding is then sent, without the RID extension the answer did
  not accept; Chrome decodes it (1280 pixels). Nothing needed fixing on our side.

## Consequences

- Public API (additive): `RelayServer` (`udp`, `tcp`, `tls`, `from_url`, `tls_config`, `addr`,
  `transport`), `Endpoint::{gather_relay_via, dial_tcp, candidate_filter}`,
  `RtcServer::{tcp_candidates, tcp}`, `RtcTcp` (an `Acceptor`) and its hidden handler `IceTcp`,
  `Peer::request_layer_keyframe`, `Candidate::{kind, transport}`; `akio-ice` (internal tier):
  `Candidate::relayed_over_stream`. Snapshots refreshed. `gather_relay` now also re-allocates a
  lost allocation (it used to stay dead).
- The UDP datapath is unchanged for endpoints and servers without TCP or relays: the TCP side
  and the relay list are only looked at when they exist (the relay count is read without a lock,
  as before). Same-run A/B against main 8bc6a2c4 on gpu51 (`quiet.sh`, CPUs 2-9, alternating
  rounds): RTP media between two loopback `Endpoint`s 1.003x (91.9 vs 91.6 MB/s, 7 rounds), data
  channel throughput 1.024x (191.9 vs 187.3 MB/s, 15 rounds): no regression.
- New fuzz target `webrtc_turn_url` (the TURN URL parser); `webrtc_sdp` seeds now carry active
  TCP and TLS-relayed candidates. The relay stream path reuses `FrameReader` (fuzzed by
  `turn_stream`), the active ICE-TCP path `akio_ice::tcp::FrameReader` (fuzzed by `ice_tcp`).
- Interop: `tools/interop/webrtc/run.sh` (pion): `Endpoint` relayed candidates allocated over
  TCP and TLS on `akio-turn` and pion/turn; ICE-TCP both ways (our passive with pion active, our
  active with pion's passive TCP mux, pion active to the ICE-lite server's passive candidate).
  `linux.sh` (coturn): `Endpoint` relayed candidates allocated over TCP and TLS on coturn.
  `browser.sh` (Chrome): Chrome to the server over ICE-TCP only; Chrome relay-only through
  `akio-turn` over UDP, TCP and TLS; an `Endpoint` with only its passive TCP candidate, and with
  only relayed candidates allocated over TCP and TLS, to Chrome (Chrome's selected pair checked
  in each); simulcast both ways with layer selection.
- Known limit, unchanged: peers of one `Endpoint` share its sockets, so two of its peers talking
  to the same remote socket share a 5-tuple and cannot be told apart once past the ICE username
  (a test uses a third endpoint for that reason).
- Not done: RFC 6062 TCP relays, TURN over DTLS, simultaneous-open ICE-TCP, active ICE-TCP on
  `RtcServer` (a lite agent does not send checks), Chrome receiving simulcast (a Chrome
  limitation).
