# ADR-013: Shared 0-RTT anti-replay store and QUIC compatible version negotiation

English | [简体中文](013-shared-anti-replay-and-compatible-vn.zh-CN.md)

Status: accepted (2026-11-16)

## Context

Two items were left open when TLS 1.3 early data and QUIC 0-RTT landed:

1. **Replay protection across servers.** A server records the PSK binder of every ClientHello
   whose early data it accepts (RFC 8446 section 8.2) and rejects early data of a ClientHello
   seen before. That record lived in each `ServerConfig`. Servers that accept the same tickets
   (several processes behind `SO_REUSEPORT`, several machines behind a load balancer) each had
   their own, so a first flight recorded on its way to one could be replayed to another and
   its early data accepted there. The servers could not share tickets anyway: each
   configuration sealed tickets with a random key of its own.
2. **Compatible version negotiation** (RFC 9368 section 4). only-quic speaks QUIC v1 and v2 and
   sends and checks the version_information transport parameter, but a server always answered
   in the client's version: moving a client to the other version took a Version Negotiation
   round trip.

## Decision

### Anti-replay store (only-tls)

1. A small public trait, called on the handshake path:

   ```rust
   pub trait AntiReplayStore: Send + Sync {
       fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool>;
   }
   ```

   `binder` is the ClientHello's first PSK binder (32 or 48 bytes, an HMAC over the
   ClientHello: unique and unpredictable, so usable as a key as it is); `ttl` is three freshness
   windows (30 s): a replay passes the freshness check up to two windows after the first use,
   and one more covers servers whose clocks differ by up to a window (it was two windows, 20 s,
   when the record was private to one server and one clock). `Ok(true)`: first time, early data accepted; `Ok(false)`: seen
   (or the store is full), rejected. The freshness check (ticket age within 10 s) stays in the
   server and runs first, so the store sees only fresh ClientHellos and keys older than the TTL
   can never be accepted again.
2. **Fail closed.** An `Err` rejects the early data. The handshake continues as a 1-RTT
   resumption and the client sends the same bytes again, so a store outage costs a round trip,
   not the connection, and never accepts an unchecked replay.
3. **Default: `MemoryAntiReplay`**, the existing bounded window (100,000 entries, full means
   reject), now public so an application can wrap or reuse it. Behaviour without the new
   options is unchanged.
4. **Builder options**: `ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)` and
   `ServerConfigBuilder::session_ticket_key([u8; 48])` (16 bytes of key name, a 32-byte
   ChaCha20-Poly1305 key; implies session tickets), without which a shared store has nothing
   to protect. Key rotation stays with the caller (a new configuration); an old key's tickets
   then give full handshakes. QUIC servers get both through their `only_tls::ServerConfig`.
5. **Synchronous on purpose.** The TLS core is sans-io and runs on the connection's I/O
   thread. An async store would need a suspended handshake state in TLS and QUIC for one
   lookup; instead the trait is synchronous and its documentation says to keep it short and
   bounded by a timeout. Only ClientHellos that would otherwise have their early data accepted
   (resumed, fresh, matching ticket) reach the store, so its load is the 0-RTT rate, not the
   connection rate.

**Backing it with Redis** (or memcached, a database): one atomic command per call,

```text
SET only:0rtt:<hex binder> 1 NX PX <ttl ms>   ->  "OK": Ok(true)   nil: Ok(false)
timeout / connection error                    ->  Err(..): early data rejected
```

with a client that has a short timeout (a few milliseconds on a local network) and its own
connection pool. The book's TLS chapter has a sketch; the tests use an in-memory "remote" store
with a switch that makes it fail.

### Compatible version negotiation (only-quic)

1. **Opt-in, server side**: `ServerConfig::prefer_version(Version)`. Default none: the server
   answers in the client's version, as before. A server preferring v2 moves v1 clients to v2,
   one preferring v1 moves v2 clients to v1 (the two are compatible both ways, RFC 9369
   section 4.1). Not on by default because the switch is only as good as the client's v2:
   quic-go, for one, derives v2 key-update secrets with the v1 label and would fail its first
   key update after being moved (it is not moved: it sends no version_information).
2. **When**: only if the client's version_information lists the preferred version among its
   available versions (and its chosen version is the one it started in). Clients that send no
   version_information are never switched.
3. **How (server)**: the server holds the Initial CRYPTO stream back from TLS until the whole
   ClientHello is there (up to 16 KiB; a ClientHello may span several Initial packets),
   reads its transport parameters (`only_tls::quic::client_hello_transport_params`, hidden),
   and if it switches, installs the new version's Initial keys, keeps the old ones to read the
   client's Initials (and 0-RTT) of the first version until the Initial space is dropped, and
   starts TLS with its own version_information naming the new version. Nothing has been
   answered by TLS yet at that point, so no extra round trip and no TLS state to rewind. A
   server without a preference never holds anything back.
4. **How (client)**: a client in its handshake, before it has processed a ServerHello, that
   receives an Initial of another version it supports switches to it if that packet decrypts with the new version's Initial keys (and
   switches back if not, so a forged packet cannot move it). Its 0-RTT packets stay in the
   first version (RFC 9369 section 4.1). Both sides check version_information as RFC 9368
   says: the server against the client's first version, the client against the version in use.
5. **Interop**: ngtcp2 implements RFC 9368; its example client and server (built from Debian's
   source package in Docker, `tools/interop/quic/ngtcp2-cvn.sh`) switch with only-quic/only-h3
   both ways, with 0-RTT. quic-go does not implement it (no version_information, packets of
   another version dropped): `tools/interop/quic/run.sh` checks its clients keep their version
   against servers preferring the other one.

## Consequences

- Public API (additive): only-tls `AntiReplayStore`, `MemoryAntiReplay`,
  `ServerConfigBuilder::anti_replay_store`, `ServerConfigBuilder::session_ticket_key`;
  only-quic `ServerConfig::prefer_version`. Snapshots in `api/` updated.
- A shared store makes replay protection as strong as the store's atomicity: a store that
  answers `Ok(true)` twice for one key (a non-atomic read-then-write, replication lag between
  regions) lets a replay through. A store per region with tickets per region avoids the lag.
- A slow store slows down 0-RTT handshakes on that I/O thread; a failing store turns 0-RTT off,
  not the service.
- The ClientHello peek costs a copy of the client's Initial CRYPTO data, only on servers with a
  preference. Sending a v1 Initial and continuing in v2 is visible on the wire (by design).
- Not done: an asynchronous store interface; ticket key rotation with several live keys. Binding
  session tickets and NEW_TOKEN tokens to the QUIC version that issued them (RFC 9369 section 5),
  which compatible negotiation made routine to get wrong, is done in
  [ADR-014](014-quic-version-bound-resumption.md).
