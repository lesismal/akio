# ADR-014: QUIC session tickets and tokens bound to the QUIC version

English | [简体中文](014-quic-version-bound-resumption.zh-CN.md)

Status: accepted (2026-11-17)

## Context

RFC 9369 section 5 makes TLS session tickets and NEW_TOKEN tokens specific to the QUIC version
of the connection that provided them:

- clients **MUST NOT** use a ticket or token from a v1 connection to start a v2 connection, or
  the other way round;
- servers **MUST** validate the originating version of a ticket or token and not accept one
  from another version: a rejected ticket falls back to a full handshake without 0-RTT, a
  rejected token leaves the address unvalidated;
- after compatible version negotiation, tickets and tokens belong to the **negotiated**
  version, not the one the client started in.

akio-tls tickets carried no version and akio-quic tokens neither, so any ticket or token was
accepted in either version. ADR-013 (compatible version negotiation) made the crossing routine:
a client configured for v1 that a server preferring v2 moves to v2 gets v2 tickets, and kept
resuming them in v1.

## Decision

1. **Tickets carry the QUIC version** (akio-tls). The session encoding gets a `quic_version`
   field (format 3; format 2 sessions decode as version 0, "unbound"). TLS over TCP uses 0.
   The hidden QUIC interface between akio-tls and akio-quic (`akio_tls::quic`, `doc(hidden)`,
   not in the public API snapshots) gains:
   - `QuicTls::client_versioned(.., version)`: offers only a ticket of `version` (other
     versions' tickets stay in the cache) and keeps new tickets under it;
   - `QuicTls::server_versioned(.., version)`: resumes only a ticket of `version` (the client's
     first version); another one is skipped like an unknown ticket, so the handshake is a full
     one and early data is rejected. Issued tickets carry `version`;
   - `QuicTls::set_ticket_version(v)`: after a compatible switch, tickets issued (server) or
     received (client) from then on carry `v`; the ticket offered or accepted stays bound to
     the first version, as the client started in it;
   - `akio_tls::quic::ticket_version(&ClientConfig, name)`: the version of the newest usable
     QUIC ticket the client holds for `name`.

   The unversioned constructors (`client`, `client_early`, `server`, `server_early`) are version
   0: they neither take nor accept a bound ticket, and their tickets are not taken by bound
   handshakes. Strict equality also keeps QUIC tickets out of TLS over TCP and the reverse.
2. **Tokens carry the QUIC version** (akio-quic). NEW_TOKEN and Retry tokens seal the version
   (the negotiated one for NEW_TOKEN) next to their timestamp. The server checks it against the
   version of the client's Initial: another version's NEW_TOKEN token counts as no token
   (unvalidated address, possibly a Retry); another version's Retry token is invalid. Tokens
   sealed before this change fail the check the same way (one unvalidated connection).
3. **The client starts where its ticket can be used.** A client keeps each token with its
   version. When it dials, it starts in the version of its newest usable ticket for the server
   name, else of its token, as long as it speaks that version; otherwise in
   `ClientConfig::version`. The token is presented only when its version is the one started in.
   This is the decision for the interaction with ADR-013: the alternative, starting in the
   configured version and dropping a ticket of the other one, makes every connection of a v1
   client to a server preferring v2 a full handshake (each gets a v2 ticket that the next one,
   started in v1, cannot use), losing resumption and 0-RTT exactly where compatible
   negotiation is used. Starting in v2 instead is where the server would move the connection
   anyway, and saves the switch.
4. **0-RTT across a switch is unchanged**: a client starting in v1 with a v1 ticket to a server
   that now prefers v2 (a ticket from before the preference, or from a server sharing the ticket
   key) is resumed with its v1 ticket and 0-RTT in v1 packets, then moved to v2; the tickets of
   that connection are v2's.

## Consequences

- A server rejects a ticket from the other version even from clients that ignore RFC 9369
  section 5. ngtcp2 1.11's example client is one: it resumes a ticket from a connection moved
  to v2 by starting in v1 again. It now gets a full handshake without 0-RTT there; started in
  v2 (`-v v2`) it resumes with 0-RTT. `tools/interop/quic/ngtcp2-cvn.sh` checks all three
  cases (a v1 ticket across the switch, the v2 ticket in v1 rejected, in v2 accepted).
- `ClientConfig::version` is the version a client starts in when it holds nothing for the
  server; with a ticket or token, the version they came from wins. A client restricted to one
  version (internal `ConnConfig::versions`) does not move and just does not use them.
- Tickets issued before the upgrade are unbound (version 0) and no longer resume QUIC
  connections: one full handshake per client after the upgrade. TLS over TCP is unaffected.
- No public API change: only the hidden QUIC interface of akio-tls and crate-private akio-quic
  types change. No measurable cost (four bytes per ticket and token, one comparison).
