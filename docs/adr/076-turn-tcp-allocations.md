# ADR-076: TURN TCP allocations (RFC 6062)

English | [简体中文](076-turn-tcp-allocations.zh-CN.md)

Status: accepted (2026-11-22)

## Context

`only-turn` served TURN over UDP, TCP, TLS and DTLS, but every relay was a UDP socket: an
Allocate asking for `REQUESTED-TRANSPORT` TCP got 442, and the sans-io client could only ask for
UDP. DEV-PLAN recorded "RFC 6062 TCP relays not implemented: WebRTC never uses them", and the
book's WebRTC chapter listed TCP relays as not done.

Browsers indeed never ask for TCP allocations, but other TURN users do: SIP and XMPP clients
relaying TCP media or file transfer, and applications that tunnel a TCP protocol through a TURN
server because it is the one host both sides can reach. coturn and pion/turn implement both
sides of RFC 6062, so an `only` deployment replacing either needs them too.

RFC 6062 in short. A client opens a *control connection* (TCP or TLS) and allocates with
`REQUESTED-TRANSPORT` 6; the relayed address is a listening TCP socket. A **Connect** request
(`XOR-PEER-ADDRESS`) makes the server open a TCP connection from the relayed address to the
peer and answer with a `CONNECTION-ID`. A peer connecting to the relayed address, if it has a
permission, produces a **ConnectionAttempt** indication with a `CONNECTION-ID`. Either way the
client opens a *new* connection to the server and sends **ConnectionBind** with the id; after
its success response, that *client data connection* and the *peer data connection* carry raw
bytes both ways, no TURN framing. Unbound connections are closed after 30 s; closing one side
closes the other; the allocation going closes them all. Errors 446 (Connection Already Exists)
and 447 (Connection Timeout or Failure).

Constraints: the bytes of a bound connection must not pass through the sharded state machine
(no shard lock per read); backpressure must be linked both ways (rules 7 and 8); no I/O thread
may block on `accept` (rule 1); every table and buffer is bounded; another session is editing
`only-webrtc`, so the change stays inside `only-turn`.

## Decision

### Server

**State machine (`TurnCore`, sans-io).** An allocation may carry a TCP part: its connections by
id and by peer transport address (one connection per peer address, RFC 6062 section 3). The core
decides everything RFC 6062 specifies and leaves the sockets to the environment:

- *Allocate* with transport 6: refused with 442 when `TurnConfig::tcp_relays` is off or the
  environment has no TCP support, 400 when the client is not on a stream (the core asks
  `TurnEnv::pads_channel_data`, which is true exactly for TCP/TLS clients) or the request
  carries `DONT-FRAGMENT`, `EVEN-PORT` or `RESERVATION-TOKEN`, 440 for a family mismatch.
  Quotas are those of UDP allocations. Transports other than 6 and 17 stay 442.
- *Connect*: 437 without an allocation, 400 on a UDP allocation or without a peer, 443 for the
  wrong family, 403 when the peer policy (`peer_allowed` / `denied_by_default`) refuses it or
  its port is 0, 446 when a connection with that peer address exists (connecting, waiting or
  bound), 508 beyond `TurnConfig::max_tcp_connections` (64) per allocation. Otherwise the core
  records the connection as *connecting* and calls `TurnEnv::connect_peer`; the request is
  answered later, when the environment calls `TurnCore::tcp_connected` (success with
  `CONNECTION-ID`, or 447). No permission is needed for Connect, as in the RFC.
- *Peers connecting*: `TurnCore::tcp_incoming(relay, peer)` accepts the connection when the
  allocation has an unexpired permission for the peer's IP, the policy allows the peer, there
  is room and no connection with that address exists; it calls `TurnEnv::accept_peer` and then
  sends the ConnectionAttempt (in that order, so a ConnectionBind cannot outrun the
  registration). Otherwise the caller closes the connection at once (section 5.3).
- *ConnectionBind*: authenticated like any request, with one difference: the nonce may be one
  issued to the data connection's own address *or* to the control connection of the
  allocation holding the id (pion and coturn reuse the control connection's nonce; our nonces
  are bound to the client address). The id must name a connection waiting for its bind, of an
  allocation of the same user; anything else is 400 (no difference between "unknown" and
  "someone else's"). 400 also when the request did not arrive on a stream.
- *Deadlines* in `handle_timeout`: a connection not bound 30 s after it was connected or
  accepted is closed; a Connect the environment never reports on is answered 447 after 60 s.
  `TurnCore::tcp_closed` forgets a connection that ended. Deleting or expiring the allocation
  closes every connection (`TurnEnv::close_connection`) and the listener
  (`TurnEnv::close_tcp_relay`).
- ChannelBind on a TCP allocation is 400; Send indications and ChannelData for it are dropped.

New `TurnEnv` methods, all with defaults (so existing environments keep compiling and refuse
TCP allocations with 442): `open_tcp_relay`, `close_tcp_relay`, `connect_peer`, `accept_peer`,
`connection_bound`, `close_connection`. New `TurnCore` methods: `tcp_connected`,
`tcp_incoming`, `tcp_closed`. `TurnStats::tcp_connections` counts open connections.

**`TurnServer` over `only` (`tcp.rs`).**

- The relayed address is a non-blocking listening socket bound on `relay_ip:0` with
  `SO_REUSEADDR` and `SO_REUSEPORT` (`only_sys::listen`), so that connections to peers can
  leave from the same address with `Engine::dial_from` (RFC 6062 section 5.2 requires the
  relayed address as the local endpoint). Because a reuseport bind of port 0 may in principle
  return a port another of our relays holds, a bound address already in the server's listener
  table is closed and bound again (16 tries).
- **One accept thread per server**, started with the first TCP allocation
  ("only-turn-tcp-accept"), polls every relay listener with `only_sys::Poller`; listeners are
  added and removed through a command list and a `Waker`. Accepted sockets go to
  `Engine::adopt_tcp`, so the permission check and the ConnectionAttempt run on an I/O thread
  in the acceptor's `on_open`. No thread per allocation, and no I/O thread ever waits in
  `accept`. The thread exits within a second of the server being dropped.
- Connections are *links* in a server-wide table keyed by `CONNECTION-ID`: the allocation's
  client and shard (a ConnectionBind arrives on another connection, whose client address
  hashes to another shard) and the pair of `only` connections. Ids are server-wide: a counter
  from a random start, never 0.
- Dials asked for under a shard lock are started after the lock is released (a dial may fail
  synchronously, and its failure handler locks the shard again).
- A stream client whose message is a ConnectionBind is answered by the shard owning the id; on
  success the response is sent, then whatever the peer sent meanwhile, and the connection
  turns into a raw relay: the rest of the read after the ConnectionBind goes to the peer
  (`FrameReader::push_until` stops at that message and hands back the tail), and the
  connection leaves the client table, so the sweep of connections that never allocate no
  longer applies to it. Connections that never bind are closed by that sweep after
  `stream_allocate_timeout` (30 s).
- Before the bind, the peer's bytes are held up to `TurnConfig::tcp_relay_buffer` (64 KiB);
  then reading the peer pauses, which closes its TCP window (section 5.2 and the security
  considerations), and resumes at the bind.
- After the bind, each side writes straight into the other's `Conn` without any lock but a
  per-connection one taken once; when the destination has more than `tcp_relay_buffer` bytes
  queued, reading the source pauses (`hold_reads`) until the destination drains
  (`Conn::on_drain`). Both connections are `set_relayed`, so the engine's own write
  backpressure cannot deadlock a pair of peers that only read when they can write.
- Closing either connection closes the other and tells the core (`tcp_closed`); the control
  connection closing removes the allocation, and with it every link.
- Connect waits for the engine's `Config::connect_timeout` (10 s by default). RFC 6062 asks for
  at least 30 s: deployments wanting strict conformance raise that setting on the engine
  serving TURN; the core's own 60 s guard only matters for environments that never report.

### Client (`only_turn::client`, sans-io)

- `ClientConfig::tcp_allocation(true)` (which also sets `stream`) asks for transport 6.
- `Client::connect(now, peer)` sends a Connect; `ClientEvent::Connected { peer, id }` or
  `ClientEvent::ConnectFailed(peer, error)` follows. At most one Connect per peer in flight.
- `Client::create_permission(now, peer)` installs a permission now and keeps refreshing it
  until the client closes, used or not (peers connecting to a TCP relay need one; on UDP
  allocations it is a pinned peer). `ClientEvent::ConnectionAttempt { peer, id }` reports a
  peer that connected.
- `Client::data_connection(now, id) -> Option<DataConnection>` returns a sans-io binder for a
  new connection: `poll_transmit` gives the ConnectionBind (the allocation's credentials and
  nonce), `handle_input(data) -> usize` takes the response (whole or in pieces) and returns how
  many bytes it consumed, so the caller relays `data[n..]` as the peer's first bytes once
  `state()` is `DataState::Bound`; 401/438 challenges are answered up to three times;
  `handle_timeout` / `poll_timeout` fail it after `ClientConfig::timeout`. A stream that does
  not start with STUN fails it.
- `send_to` returns false on a TCP allocation; `ClientEvent` gained three variants
  (non-exhaustive already).

### Codec and framing

`Method::CONNECT`, `CONNECTION_BIND`, `CONNECTION_ATTEMPT` (0x00a-0x00c), `attr::CONNECTION_ID`
(0x002a); `CONNECTION-ID` is a known comprehension-required attribute.
`FrameReader::push_until` (crate-private) is `push` stopping after a chosen message.

## Consequences

- `only-turn` depends on `only-sys` (in-house, already in the graph through `only`) for the
  listener and the poller. No third-party dependency.
- Behaviour change: an Allocate for TCP over UDP or DTLS is now 400 instead of 442 (RFC 6062
  section 5.1); over TCP/TLS it now succeeds unless `TurnConfig::tcp_relays` is false.
- New public API: `TurnConfig::{tcp_relays, max_tcp_connections, tcp_relay_buffer}` and
  `TurnConfig::tcp_relays()`; `TurnEnv::{open_tcp_relay, close_tcp_relay, connect_peer,
  accept_peer, connection_bound, close_connection}`; `TurnCore::{tcp_connected, tcp_incoming,
  tcp_closed}`; `TurnStats::tcp_connections`; `ClientConfig::tcp_allocation` (field and
  builder); `Client::{connect, create_permission, data_connection}`; `ClientEvent::{Connected,
  ConnectFailed, ConnectionAttempt}`; `DataConnection`, `DataState`; the STUN constants above;
  the hidden `TcpPeer` handler.
- A server with TCP allocations holds two sockets per relayed connection and one listener per
  allocation; `max_tcp_connections` × `max_allocations_per_user` bounds what one user holds,
  the engine's `max_connections` the total.
- Reconnecting from the relayed address to the same peer address right after a connection
  closed may fail with 447 while the 4-tuple sits in TIME_WAIT on the server; RFC 6062 asks
  clients to wait 10 s before retrying the same peer anyway.
- UDP relays are untouched on the hot path: the per-datagram code paths only gained a
  `tcp.is_some()` test on the allocation they already read. Same-run A/B against main on gpu51
  (`turn-relay-bench 8 6 4`, 6 alternating rounds under quiet.sh): 308.6k vs 268.0k datagrams/s
  mean total, 1.15x, within the ±20 % spread between rounds: no regression.

Tests: `TurnCore` unit tests (Connect answered on report, 446 while connecting, the 30 s bind
deadline, 447 on failure and from the 60 s guard, port 0 refused, ChannelBind refused,
permissions for peers connecting and their expiry, one connection per peer address, the
connection limit, ConnectionBind with the control connection's nonce or its own, 438 for a
third address, 401 without credentials, 400 for an unknown id, a bound one and another user;
Allocate rules: stream only, no UDP-only attributes, 440, 442 without support or with the
setting off, quota given back; Connect 437 and 400 on UDP allocations); client unit tests
against the core (Connect events, 447, a pinned permission outliving 15 minutes idle,
ConnectionAttempt, `DataConnection` fed one byte at a time with the peer's bytes after the
response, a refusal, a 438 retry, garbage and the deadline); `FrameReader::push_until` at every
cut; integration tests on real TCP and TLS listeners (`tests/tcp.rs`: Connect from the relayed
address, the peer's early bytes held and delivered, 1 MiB each way at once, closing either side
closes the other, peers without a permission closed and with one announced and bound over
TLS, a second bind of the same id refused, the control connection closing everything, 447 /
446 / 508, binds of unknown and other users' ids, Allocate refusals, and backpressure: a data
connection that does not read stalls a 64 MiB peer writer far short of the total, then
everything arrives in order). Fuzzing: new target `turn_tcp` (a core with a TCP environment
driven by control messages, data-connection messages, peers connecting, dial outcomes, closes
and deadlines; and a `DataConnection` fed reads), with seeds reaching every RFC 6062 message.

Interop (`tools/interop/webrtc/turn-tcp.sh`, Docker; coturn 4.6, pion/turn v5.1.3): coturn's
`turnutils_uclient -T` (pairs of clients connecting to each other's relayed addresses) against
only-turn over TCP and TLS; the only_turn client (Connect, then a peer connecting with a
permission; 20 messages and 1 MiB echoed on each) against coturn, pion/turn and only-turn over
TCP and TLS; pion/turn's TCP allocation client (Dial and Accept) against only-turn and coturn.

Not done: TCP allocations from `only-webrtc`'s `Endpoint` (no WebRTC stack uses them); an
engine-driven client wrapper (the sans-io client and the example show the plumbing);
`ADDITIONAL-ADDRESS-FAMILY` dual allocations (not supported for UDP either); a per-Connect
connect timeout separate from the engine's.
