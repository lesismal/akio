# ADR-045: DTLS 1.3 connection ID updates, post-handshake client authentication and early data in akio-dtls

English | [简体中文](045-dtls13-cid-updates-pha-early-data.zh-CN.md)

Status: accepted (2026-11-19)

## Context

ADR-021 brought DTLS 1.3 (RFC 9147), connection IDs (RFC 9146 for DTLS 1.2, the CID in the
DTLS 1.3 unified header), PSKs and resumption to akio-dtls, and listed as not done: DTLS 1.3
0-RTT, NewConnectionId / RequestConnectionId, post-handshake client authentication,
non-ECDHE certificate key exchanges and CBC suites. akio-dtls is an Internal-tier crate
(docs/api-stability.md); akio-webrtc is its only user in the workspace and keeps DTLS 1.2
(ADR-021 §2), so none of this changes WebRTC.

## Decision

1. **Post-handshake flights are queued.** The DTLS 1.3 machine sends one flight at a time
   (RFC 9147 §7 reliability: ACKs, partial retransmission). NewSessionTicket and KeyUpdate
   used ad-hoc "after the current flight" flags; they and the new messages now go through one
   queue of post-handshake flights (at most 32), each built when it starts, so message
   sequence numbers stay in order and each uses the keys current at that time (the
   post-handshake Finished depends on the client application traffic secret, which a
   KeyUpdate changes). A KeyUpdate requested while one is queued or in flight is merged into it.
2. **Connection ID updates (RFC 9147 §9)**, DTLS 1.3 only (RFC 9146 has no such message):
   `Connection::new_connection_ids(count, immediate)` sends NewConnectionId with fresh random
   CIDs of the negotiated length (`cid_immediate` or `cid_spare`), `request_connection_ids(n)`
   sends RequestConnectionId (one outstanding at a time), `rotate_connection_id()` switches the
   CID we send to the next spare one the peer gave, `spare_connection_ids()` counts them.
   Received RequestConnectionId is answered at once with up to as many CIDs as fit under 8
   live ones (fewer, or an empty list, as §9 allows); more than 4 unanswered requests queued
   is `too_many_cids_requested` (new `AlertDescription::TooManyCidsRequested`). Both messages
   are refused with `unexpected_message` without non-empty CIDs (§9). DTLS 1.3 has no
   RetireConnectionId, so our CIDs retire implicitly: the peer uses CIDs in the order issued
   (§9 "SHOULD"), and a record authenticated under a later CID retires the earlier ones (a
   datagram reordered across the switch is dropped, as any lost datagram). `cid_immediate`
   drops our older spares (the peer may retire them). The set a connection accepts is
   `Connection::local_connection_ids()` and every change is `Event::LocalConnectionIds(set)`,
   so a listener routing by `connection_id(datagram, len)` keeps an exact map. All local CIDs
   keep the configured length, which routing needs.
3. **Post-handshake client authentication (RFC 8446 §4.6.2)**, DTLS 1.3:
   `Config::with_post_handshake_auth(true)` makes a client send `post_handshake_auth` and
   answer a CertificateRequest with Certificate, CertificateVerify and Finished over the
   handshake transcript plus the request (a client without an identity, or without a key for the
   requested schemes, declines with an empty Certificate). A server calls
   `Connection::request_client_certificate()` (one request at a time, a random 16-byte context)
   and gets `Event::ClientCertificate(chain)` once the Finished verifies; the chain went
   through the `PeerVerifier` (a refusal is fatal, `bad_certificate`) and
   `HandshakeInfo::peer_certificates` / `peer_fingerprint` are updated. The answer
   acknowledges the request flight; both are also ACKed (RFC 9147 §7).
4. **Early data (0-RTT)** with resumption tickets, opt-in with `Config::with_early_data(max)`
   (default 0):
   - Server: NewSessionTickets carry `early_data` (max_early_data_size, kept in the sealed
     ticket state, format 2; format-1 tickets still open, without early data). Early data is
     accepted only for the first PSK identity, a ticket allowing it, the ticket's cipher suite
     (a server prefers that suite when early data is offered), no HelloRetryRequest, a fresh
     ticket age (client and server ages within 10 s, plus 1 s for the ticket's whole-second
     issue time) and the first use of the ClientHello: the binder is recorded in an
     `AntiReplayStore` for three windows (RFC 8446 §8.2 "ClientHello recording", the design
     of akio-tls's store from ADR-013, kept separate because akio-dtls must not depend on
     akio-tls; `MemoryAntiReplay` of 100,000 entries per configuration by default,
     `Config::with_anti_replay` to share one; store errors reject the early data). Accepted
     records (epoch 1, `client_early_traffic_secret`) are delivered as `Event::EarlyData`
     before `Event::Connected`, more than max_early_data_size is `unexpected_message`, and
     epoch 1 is dropped at connect; rejected early data is skipped without buffering.
     `HandshakeInfo::early_data` tells either side whether it was accepted.
   - Cookies: with `with_hello_verify(true)` (the default) every ClientHello without a cookie
     gets a HelloRetryRequest, which rejects early data. A ClientHello whose early data is
     accepted skips that round trip: its binder proves the client holds our ticket, the
     anti-replay record lets the ClientHello through once, and the abbreviated server flight
     (no certificates) is smaller than the ClientHello, so it cannot amplify. The check runs
     before the HelloRetryRequest only for ClientHellos offering early data; a bad binder there
     falls back to the HelloRetryRequest (the fatal error then comes with the second
     ClientHello, as before). `HelloVerifier::check` in front of the connections cannot see
     tickets and still always asks for a cookie: its clients never get early data accepted.
   - Client: with a non-zero `with_early_data`, `Connection::client_resume` offers early data
     when the session allows it (`Session::max_early_data`); `Connection::send_early_data`
     sends records until the server's Finished (DTLS 1.3 has no EndOfEarlyData, RFC 9147
     §5.6). A HelloRetryRequest or a server that does not echo `early_data` ends it
     (`Error::NotAvailable` from then on); the application resends as 1-RTT data if it must.
   - External PSKs do not get early data (no provisioned parameters).
5. **Errors**: the new operations fail with a new `Error::NotAvailable(reason)` when the
   connection did not negotiate what they need or is not in the state for them (DTLS 1.2, no
   CIDs, no `post_handshake_auth`, a request outstanding, early data not offered or rejected);
   `Error::NotConnected` / `Error::Closed` as before.
6. **Not done, on purpose**: non-ECDHE certificate key exchanges (static RSA, DHE) and CBC
   suites. RFC 8996 / RFC 9325 deprecate the former's lack of forward secrecy and the latter's
   MAC-then-encrypt record protection (Lucky13-style padding oracles); RFC 8827 / RFC 9325
   require ECDHE with AEAD for WebRTC and recommend only AEAD suites; every peer we interoperate
   with (OpenSSL, wolfSSL, pion, browsers) negotiates ECDHE AEAD suites. Adding them would add
   attack surface without a peer that needs it.

Public API added (akio-dtls): `AntiReplayStore`, `MemoryAntiReplay`;
`Config::{with_early_data, with_anti_replay, with_post_handshake_auth}`;
`Connection::{new_connection_ids, request_connection_ids, rotate_connection_id,
spare_connection_ids, local_connection_ids, peer_connection_id, request_client_certificate,
send_early_data}`; `Session::max_early_data`; `Event::{EarlyData, ClientCertificate,
LocalConnectionIds}`; `HandshakeInfo::early_data`; `Error::NotAvailable`;
`AlertDescription::TooManyCidsRequested`. All additive (`Event`, `Error`, `AlertDescription`
and `HandshakeInfo` are non-exhaustive).

## Consequences

- Interop (`tools/interop/dtls/dtls13.sh`, the image of `tools/interop/dtls/Dockerfile` now
  builds wolfSSL with `--enable-earlydata --enable-postauth`): wolfSSL 5.8.4 client `-r -0`
  has its early data accepted by our server (cookies on and off); our client's early data is
  accepted and read by wolfSSL's server (`-r -0 -J n`) and rejected after its default
  HelloRetryRequest cookie, the connection still resumed; post-handshake authentication both
  ways (wolfSSL server `-Q` verifies our Certificate, CertificateVerify and Finished; wolfSSL
  client `-Q` answers our request with its certificate). Neither OpenSSL 4.1 nor wolfSSL 5.8
  implements NewConnectionId / RequestConnectionId: they are tested between our ends, in
  memory over lossy links and over UDP in the interop script. The DTLS 1.2 interop runs
  (OpenSSL 3.x, pion) are unchanged. GnuTLS has no RFC 9146 CIDs, so it cannot test DTLS 1.2
  CIDs; pion and wolfSSL keep doing that.
- Benchmarks (gpu51, same run, base ec0d9616 vs this change, three interleaved rounds):
  DTLS 1.2 records 64 B 1.00-1.03 / 1 KiB 0.99-1.01 (AES-128-GCM, ChaCha20 alike), DTLS 1.3
  records 0.98-1.02, full handshakes 1.00 (DTLS 1.2 and 1.3), DTLS 1.3 resumption 1.00-1.01
  (`dtls-bench`, new `dtls-hs-bench`): no regression; the new paths cost nothing until used.
- Fuzzing: new target `dtls_post_handshake` (arbitrary post-handshake messages processed as if
  decrypted by connected ends while real CID, KeyUpdate and authentication flights run, then
  arbitrary early data and datagrams at a server accepting 0-RTT); `dtls_record` parses and
  re-encodes the new messages; `dtls_handshake` configurations offer post-handshake auth and
  early data and run the new API calls.
- Early data is replayable by design (RFC 8446 §8): applications must send only idempotent
  requests in it, which `Event::EarlyData` and `Config::with_early_data` document.
