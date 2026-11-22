# ADR-062: Asynchronous anti-replay store, rotating ticket keys, status_request_v2 and BoGo for akio-tls

English | [简体中文](062-tls-async-anti-replay-ticket-rotation-bogo.zh-CN.md)

Status: accepted (2026-11-20)

## Context

The TLS items still open in the development plan:

1. **OCSP response validation** (RFC 6960) for stapled responses and a TLS 1.3 client's own
   response. Already done by ADR-038 (validation in `akio-x509`, `RevocationPolicy` for the
   server's stapled response) and ADR-049 (`client_ocsp_policy`); the plan's earlier lines
   still said "not done".
2. **`status_request_v2`** (RFC 6961, TLS 1.2's `ocsp_multi`): ADR-049 left it out.
3. **An asynchronous `AntiReplayStore`.** ADR-013 made the shared 0-RTT anti-replay store
   synchronous: the I/O thread waits for the round trip to Redis or similar. Rule 1 says an
   I/O thread never blocks.
4. **Ticket key rotation with several live keys.** `session_ticket_key` takes one key;
   rotating meant a new configuration and a full handshake for every client holding a ticket.
5. **The BoGo test runner** (BoringSSL's `ssl/test/runner`), which rustls used to give
   akio-quic before Wave D.

## Decision

### OCSP (item 1)

Nothing new: `OcspResponse::verify` (signature by the issuer or a delegated responder with
id-kp-OCSPSigning, CertID match, thisUpdate / nextUpdate with clock skew, nonce) is applied to
the server's stapled response under `ClientConfigBuilder::ocsp_policy` and to a TLS 1.3
client's response under `ServerConfigBuilder::client_ocsp_policy`, with the soft / hard fail of
the CRL checks (ADR-038, ADR-049); the fuzz target `x509_ocsp` parses responses. The plan is
corrected.

### status_request_v2 (item 2)

Not implemented, on purpose. RFC 6961 only exists for TLS 1.2 and only adds stapling of the
intermediate certificates' responses; TLS 1.3 carries a response per certificate in
`status_request` (RFC 8446 section 4.4.2.1); OpenSSL, Go, rustls and BoringSSL never shipped
it (Java's JSSE is the one major implementation that did), and the CA/Browser Forum has made
OCSP optional for public CAs. The client never
sends it; a server receiving it ignores it like any unknown extension (no `status_request_v2`
in the ServerHello, no CertificateStatus for it). A test covers both.

### Asynchronous anti-replay store (item 3)

1. **A second trait** rather than a change to the first one (which stays as it is, additive):

   ```rust
   pub trait AsyncAntiReplayStore: Send + Sync {
       fn check_and_insert(&self, binder: &[u8], ttl: Duration, done: ReplayCheck);
   }
   impl ReplayCheck { pub fn complete(self, result: io::Result<bool>); }
   ```

   The call must not block: it sends the request and returns; the client library's callback
   or reader thread calls `complete` from any thread. Answering inside the call (a local cache
   hit) is allowed and suspends nothing. Same meaning of the answer as ADR-013: `Ok(true)`
   accepts the early data, `Ok(false)` or `Err` rejects it (fail closed). A `ReplayCheck`
   dropped unanswered rejects too.
2. **Suspend the handshake, not the thread.** The server checks everything else first (binder
   verified, ticket opened, freshness), then calls the store. If the answer is not in yet, it
   keeps the ClientHello, the chosen PSK and its session, and returns having sent nothing and
   changed nothing that the second pass does not set again (SNI, certificate, ALPN). When the
   answer comes, the same ClientHello is handled again from the start with the PSK and the
   answer given, so nothing is looked up twice (a session cache hands a TLS 1.3 ticket out only
   once) and no handshake state has to be rewound. Bytes that arrive meanwhile (the early data
   records, under keys not decided yet) stay in the receive buffer, bounded by twice the larger
   of 64 KiB and `max_early_data`, plus 128 KiB; past that the connection fails with
   `unexpected_message`.
3. **Waking the connection.** The sans-io core takes a waker. Over TCP it comes from a new
   hook in akio-core: `Transport::set_waker(TransportWaker)` (default: ignore), called once
   when the engine installs the transport; `TransportWaker::wake()` (any thread, holds only a
   weak reference) posts a task to the connection's I/O thread, which polls the transport with
   no input and passes on what it decoded and produced, as for bytes read from the socket.
   Over QUIC, `akio_quic` gives the handshake a waker that drives the connection from the
   answering thread (connections are already usable from any thread), and the connection takes
   the handshake up again in `poll_transmit`, then handles the 0-RTT packets that waited for
   the keys. The blocking test stream waits on the answer.
4. **Timeout.** `ServerConfigBuilder::anti_replay_timeout` (1 s by default, at least 1 ms): a
   check not answered in time rejects the early data and the handshake goes on as a 1-RTT
   resumption. Deadlines are kept by one process-wide thread (`akio-tls-replay-timer`, started
   by the first check that is not answered in the call) holding weak references; a late answer
   is ignored. The handshake timeout still bounds the whole handshake.
5. **The default path does not change.** `MemoryAntiReplay` and `anti_replay_store` are
   answered in the call as before; the suspension adds a branch on an `Option` per handshake
   message and per handshake record, and QUIC one per `poll_transmit` (A/B below).

With Redis, `check_and_insert` issues `SET only:0rtt:<hex binder> 1 NX PX <ttl ms>` on a
non-blocking client and completes the check from its reply (`OK` → `Ok(true)`, nil →
`Ok(false)`, error → `Err`). The book's TLS chapter has the sketch.

### Rotating ticket keys (item 4)

1. **`TicketKeys`**, a shared handle (clones share the keys) given to
   `ServerConfigBuilder::session_ticket_keys`: the first key seals new tickets, up to
   `MAX_TICKET_KEYS - 1` = 3 earlier ones still open the tickets they sealed. Tickets carry
   the 16-byte key name in front, so opening finds the key by name.
2. **Three ways to rotate**:
   - `TicketKeys::new(key)`, then `rotate(key)` / `set(seal, open_only)` when the application
     decides (keys from a secret store, pushed to every server: servers sharing tickets keep
     sharing them through the rotation, as with `session_ticket_key`);
   - `TicketKeys::derived(secret, period)`: the key of period `n = unix_time / period` is
     HKDF-SHA256(secret, "epoch" ‖ n); it seals, and the keys of `n - 1` and `n + 1` open
     (the previous period's tickets, and a server whose clock runs ahead by less than a
     period). Servers sharing tickets rotate in step with nothing to coordinate but the secret
     and their clocks;
   - `TicketKeys::random(period)`: a random key per period, the previous one still opening
     for one more period; private to the process.
3. **No thread.** Scheduled keys move to the current period when a handshake seals or opens a
   ticket after the period changed (one comparison under a read lock; the write lock only on
   the change). The default ticketer (one key for the configuration's life) and
   `session_ticket_key` do not go through the lock at all.
4. **Lifetime.** With scheduled keys, tickets advertise at most one period (`min(6 h, period)`),
   the time they are sure to open; TLS 1.2 tickets and cached sessions use the same lifetime.
5. **Not done:** TLS 1.2 ticket renewal on resumption (RFC 5077 section 3.3). A TLS 1.2 client
   resuming with a ticket sealed under an older key keeps it until that key leaves the set and
   then makes one full handshake; TLS 1.3 clients get new tickets after every handshake.

### BoGo (item 5)

A shim, `crates/akio-tls/examples/bogo-shim.rs`, drives akio-tls (through the blocking test
stream) the way BoringSSL's `bssl_shim` drives BoringSSL: it connects to the runner, writes
its shim id, handshakes as client or server, checks the `-expect-*` flags against what was
negotiated and echoes the test messages; flags may carry the `-on-initial-` / `-on-resume-` /
`-on-retry-` prefixes, and a client keeps its session cache across the `-resume-count`
connections. A flag it does not know, or one asking for something akio-tls does not do or
cannot report (the peer's signature algorithm, keying material export, verification
callbacks), makes it exit with 89, which the runner counts as unimplemented.
`tools/interop/tls/bogo.sh` builds the shim, fetches the runner at a pinned BoringSSL commit
(`ddd73296`, 2026-11-19; Go 1.27), and runs it with `-allow-unimplemented -loose-errors` (the
shim reports akio-tls's own error messages, not BoringSSL's codes) and
`tools/interop/tls/bogo_config.json`, whose `DisabledTests` name, each with a reason, the
areas akio-tls does not implement (DTLS and QUIC, which BoGo drives through other shims;
TLS 1.0/1.1, CBC, RSA key exchange, PSK suites, renegotiation, ECH, delegated credentials,
Channel ID, ALPS, post-quantum groups and other BoringSSL-only features) and every single
test still expected to fail: an alert other than BoringSSL's (14), behaviour the RFCs allow
and BoringSSL does differently (about 40: where the compatibility CCS goes after a
HelloRetryRequest, rejected early data resent automatically, no resumption of TLS 1.2
sessions without EMS, ...), and the akio-tls bugs found and not fixed yet.

Result on the x86 host: of 8,110 tests, **882 pass, 0 fail**, 1,122 are unimplemented and
6,106 disabled (about 2,700 of them DTLS and QUIC). The run found eleven protocol bugs, all
fixed here (and a bound on skipped early data looser than the RFC's, listed as a difference):
TLS_FALLBACK_SCSV refused by a server without TLS 1.3 (RFC 7507 section 3); a ClientHello
with supported_groups and no key_share answered with a HelloRetryRequest instead of
`missing_extension` (RFC 8446 section 9.2); the TLS 1.2 server not acknowledging server_name,
and the TLS 1.2 client accepting a non-empty acknowledgement (RFC 6066 section 3); an
unsolicited TLS 1.3 server_name acknowledgement answered with `illegal_parameter` instead of
`unsupported_extension`; TLS 1.3 padded plaintexts over 2^14 + 1 bytes accepted (RFC 8446
section 5.4); a peer leaf whose keyUsage lacks digitalSignature accepted for signing
(RFC 8446 section 4.4.2.2, RFC 5246 section 7.4.2), now `bad_certificate`, verified or not;
CertificateEntry extensions not asked for accepted (anything but a requested status_request
is `unsupported_extension`, RFC 8446 section 4.4.2); a TLS 1.2-only ClientHello refused over
its malformed TLS 1.3 pre_shared_key (its parse error is now raised only if TLS 1.3 is
negotiated); tickets sent to a client without psk_dhe_ke (RFC 8446 section 4.2.9); and each
of several update_requested KeyUpdates answered (one answer now until our next application
data, RFC 8446 section 4.6.3, as BoringSSL does). With the fixes, `tools/interop/tls/run.sh` passes
175 of 175 cases on the x86 host (OpenSSL 3.0.13, Go, curl).

## Consequences

- Public API (additive): akio-core `Transport::set_waker` (provided method), `TransportWaker`;
  akio-tls `AsyncAntiReplayStore`, `ReplayCheck`, `ServerConfigBuilder::async_anti_replay_store`,
  `ServerConfigBuilder::anti_replay_timeout`, `TicketKeys`, `MAX_TICKET_KEYS`,
  `ServerConfigBuilder::session_ticket_keys`. Hidden (outside the promise): `QuicTls::set_waker`,
  `QuicTls::suspended`, `QuicTls::resume`, `Connection::suspended`, `Connection::wait_resumable`.
- A suspended handshake holds its ClientHello and what arrived after it (bounded) until the
  answer or the timeout; a store that never answers costs each 0-RTT handshake the timeout, not
  the connection.
- Replay protection is still as strong as the store's atomicity (ADR-013).
- Stricter than before (the BoGo fixes): a peer whose leaf certificate has a keyUsage without
  digitalSignature, or that sends CertificateEntry extensions not asked for, now fails the
  handshake, also in insecure (unverified) mode; such peers break the RFCs and other stacks
  refuse them too.
- `TicketKeys::derived` makes the shared secret a long-term key: whoever has it can open every
  ticket of every period. Rotating it means a new secret (and full handshakes for the clients
  holding tickets).
- Measured cost on the default path: A/B below.

## Cost

Same-run A/B on the quiet host (docs/BENCHMARKS.md), default configurations: TLS full
handshakes X25519 0.99×, secp256r1 0.99×, RSA-2048 1.00× (the rustls column of the same runs
moved as much); QUIC full handshakes 1.00× (seven rounds), resumed dial to answer 0.99× (0-RTT)
and 1.00× (1-RTT).
