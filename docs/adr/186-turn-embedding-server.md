# ADR-186: akio-turn for an embedding server

English | [简体中文](186-turn-embedding-server.zh-CN.md)

Status: accepted (2026-11-27). akit's A256; A257 (update 1).

## Context

akit's TURN role (`webrtc.turn`) runs akio-turn's `TurnServer` with the settings fit's role gives
pion/fib's TURN server. Three of them had nothing to land on: `port_min`..`port_max`, the range of
ports relayed sockets are bound on (the range a firewall in front of the server opens;
fit-examples' `webrtc-turn` sets 49152-49999); `nonce_secret`, the key nonces are made with, shared
by servers behind one load balancer so that each takes the others' nonces; and
`max_stream_message`, the largest message a TCP or TLS client may send, which bounds what its
connection holds of a message not yet whole (fit: 8 KiB by default). akio-turn bound each relay on
`relay_ip` port 0, keyed its nonces with random bytes of each server's own and an expiry counted
from the server's start, and framed stream messages up to 64 KiB. akit refused a port range and
warned that the other two were not applied.

## Decision

1. **`TurnConfig::relay_ports: Option<(u16, u16)>`** (`relay_ports(min, max)`, in either order,
   port 0 never one; `None`, the default, leaves each port to the kernel). `TurnServer` binds a
   relay with port 0 by trying the range from a random port of it on, as fib does, so that a port
   just freed (which a peer may still be sending to) is not handed out again at once: a port one
   of its own relays holds is skipped without a system call (the relay table), one another socket
   holds is skipped when the bind fails with `AddrInUse` (UDP relays are bound without
   `SO_REUSEPORT`, so the kernel says so). Any other error ends the search (an address that cannot
   be bound fails on every port). A range used up is an error of the environment's `open_relay`,
   which the core answers with 508, as before for a failed bind. A relay with a given port (the
   odd port `EVEN-PORT` sets aside above an even one) must be in the range. `EVEN-PORT` keeps its
   tries for an even port, each now from the range. TCP allocations' listeners (RFC 6062) take the
   range too; they are bound with `SO_REUSEPORT` (connections to peers leave from the relayed
   address), which would let a listener share a port another socket setting it holds, so each
   port is probed first with a bind without it. Both families use the one range.
2. **`TurnConfig::nonce_secret: Option<Vec<u8>>`** (`nonce_secret(&[u8])`). The nonce key is
   derived from it (HMAC-SHA-256 of the secret under a fixed label), else random as before. For
   servers to take each other's nonces the nonce had to stop depending on the server: its expiry
   is now in UNIX seconds (the server's start in wall-clock seconds plus the monotonic time since,
   so a clock step after the start does not move it), checked against the same clock. The format
   is unchanged (16 hex digits of expiry, 16 of HMAC-SHA-1 over the expiry and the client's
   address); the servers' clocks need to agree within a few seconds. The secret is not shown by
   `Debug`.
3. **`TurnConfig::max_stream_message: usize`** (default `framing::MAX_FRAME`, every message TURN
   can carry, so nothing changes unless it is set). `framing::FrameReader::with_max(n)` refuses a
   message whose header claims more than `n` bytes (padding included) with a new
   `FrameError::TooLong`, as soon as the header is in, so a reader holds at most `n` bytes; the
   stream acceptor's readers use the setting, and a connection whose reader fails is closed, as for
   a stream that is not TURN. akio-turn does not raise small values: akit checks the least it
   accepts, as fit does (2048).

## Consequences

- akit binds relays in the member's range and drops its refusal and its two warnings.
- With a range, an Allocate costs a bind per port held by something else, up to the range's size
  when it is used up; ports held by the server's own relays cost a hash lookup.
- A nonce of an older server, whose expiry counted from its start, reads as long expired: clients
  holding one get a 438 and a fresh nonce once, as after any restart.

## Update 1: hooks for the embedding server (A257)

fit's role limits each username's relayed bytes a second each way (`user_bandwidth`, a token
bucket per username and direction, the datagrams past it dropped) through fib's `OnRelay`; counts
and logs fib's `OnEvent` (allocated, refreshed, freed and why, refused with a code, credentials
failed); and lets peers on its own addresses be reached on its relayed ports alone through fib's
`HoldsRelay`, so that two clients relay to each other but nobody reaches the server's other
listeners through the relay. akio-turn's peer filter saw the peer alone, nothing ran per relayed
datagram or per event, and `TurnStats` counted allocations and datagrams.

1. **`TurnConfig::on_relay`** (`RelayHook`, `Fn(&str, bool, usize) -> bool`): the allocation's
   username, toward the peer or not, the payload's length (the peer's datagram, the indication's
   `DATA`, the ChannelData's application data); false drops the datagram. It is asked once the
   permission, the channel, the peer policy and the TTL let the datagram through, right before
   it is sent, so that what it counts is what is relayed; datagrams that fail earlier never reach
   it. It runs where the datagram is handled, on the I/O thread with the allocation's shard
   locked: a bandwidth limiter has to decide before the datagram goes, and moving the decision out
   of the lock would cost a second pass over the shard per datagram. So it must not block nor call
   the server's methods that lock shards. The bytes of a TCP allocation's connections go from one
   connection to the other without the core (ADR-076) and are not seen.
2. **`TurnConfig::on_event`** (`EventHook`, `Fn(&TurnEvent)`): `TurnEvent { kind, user, client,
   relay, lifetime }` with `TurnEventKind::{Allocated, Refreshed, Freed { reason, to_peer,
   to_client }, Refused { method, code }, AuthFailed { method, code }}` and `FreeReason::{Deleted,
   Expired, Closed}`, fib's events. The core keeps them in a list (only when the hook is set) and
   `TurnServer` takes the list as the shard's call ends and calls the hook once the shard is
   unlocked and the answers sent, on the thread that handled the message, swept the allocations
   or closed them: an event handler may log, count and call any of the server's methods, `stats`
   included, without a lock order to respect. A `TurnCore` driven directly delivers them with
   `TurnCore::flush_events`. `AuthFailed` is fib's: credentials that failed (401) or came
   incomplete (400), not a request without any (how every client starts) nor a stale nonce;
   `Refused` is any error answering a request whose credentials passed. A freed allocation tells
   what it relayed each way (`Traffic`, counted per allocation beside the server's totals).
3. **`TurnServer::holds_relay(addr)`**: whether `addr` is one of the server's relayed addresses,
   as clients are told of it (on `public_ip` or `additional_public_ip`, mapped back to the bound
   address) or as bound: the UDP relay table (an allocation's relay, or a port `EVEN-PORT` set
   aside) and the TCP relays' listener table. It locks only those tables, never a shard, so a
   peer filter (which runs under a shard's lock) may ask it, of its own server or another: lock
   order is shard, then relay table, as when a datagram is sent. `TurnCore::holds_relay` answers
   from the core's own tables.
4. **More counters**: `TurnStats` gains `permissions` and `channels` (walked from the
   allocations when stats are read: a scrape, not a datagram), `pending` (authenticated Allocates
   whose relays are being bound before the shard is locked), `dropped` (datagrams from clients or
   peers the server did nothing with: not TURN, malformed, without an allocation, permission or
   channel, refused by the peer policy or `on_relay`, past their TTL), `refused` and the bytes
   relayed each way; `impl AddAssign` sums the stats of several servers. `TurnServer::allocations()`
   reads one counter, no shard locked.

akit keeps fit's limiter in `on_relay`, counts the events into `akit_turn_*` and its logger, and
reaches its own addresses on its relayed ports through `holds_relay` in its peer filter.
