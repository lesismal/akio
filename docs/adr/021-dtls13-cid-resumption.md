# ADR-021: DTLS 1.3, connection IDs, PSKs and session resumption in only-dtls

English | [简体中文](021-dtls13-cid-resumption.zh-CN.md)

Status: accepted (2026-11-18)

## Context

only-dtls (wave C) implemented DTLS 1.2 only: full ECDHE handshakes with certificates, no
connection IDs, no resumption, no pre-shared keys. DEV-PLAN wave D listed as not done: DTLS 1.3
(RFC 9147) with its ACKs, connection IDs (RFC 9146 for DTLS 1.2 and the DTLS 1.3 CID),
resumption (DTLS 1.2 session IDs and tickets, DTLS 1.3 PSK tickets) and PSKs. only-dtls is an
Internal-tier crate (docs/api-stability.md), so its API may change with an ADR; only-webrtc is
its only user in the workspace.

## Decision

1. **Two state machines behind one `Connection`.** The DTLS 1.2 machine stays as it was
   (internal `Conn12`); DTLS 1.3 is a second sans-io machine (`Conn13`). `Connection` holds
   one of them. With `Config::with_versions` containing DTLS 1.3 a connection starts as
   DTLS 1.3: a client's ClientHello is a DTLS 1.3 one that also carries everything a DTLS 1.2
   server needs (1.2 suites, extended master secret, `ec_point_formats`, renegotiation SCSV)
   when 1.2 is enabled too; a server answers a ClientHello that offers 1.3 with 1.3. A peer
   that only speaks DTLS 1.2 (a DTLS 1.2 ServerHello or a HelloVerifyRequest for a client, a
   ClientHello without `supported_versions` 1.3 for a server) makes the connection hand its
   state (sent ClientHello, reassembled fragments, sequence numbers, timers) to the DTLS 1.2
   machine, which processes the same datagram again. The RFC 8446 §4.1.3 downgrade sentinel is
   set by such servers and checked by such clients.
2. **DTLS 1.2 stays the default, also for WebRTC.** `Config::new` and `Config::webrtc` enable
   DTLS 1.2 only. pion/dtls (v3) has no DTLS 1.3 and WebRTC stacks negotiate DTLS 1.2 today;
   offering 1.3 to them costs a larger ClientHello (key share) for nothing. Users opt in with
   `with_versions(vec![Version::Dtls13, Version::Dtls12])`.
3. **The DTLS 1.3 key schedule is only-dtls's own**, on only-crypto's HKDF, not only-tls's:
   only-tls depends on only-core / only-log / only-deflate (the engine), which the sans-io
   WebRTC stack must not pull in, and its labels use `"tls13 "` where DTLS 1.3 uses `"dtls13"`.
   The structure is the same as only-tls's and is checked against RFC 8448 with the TLS prefix;
   there are no published DTLS 1.3 trace vectors, so the DTLS labels are checked by interop.
4. **DTLS 1.3 records and reliability.** DTLSPlaintext in epoch 0, then the unified header
   with 16-bit sequence numbers, an explicit length, the CID when negotiated and record number
   encryption (AES-ECB / ChaCha20 masks); epoch 2 for the handshake, 3 and up for application
   data (one per KeyUpdate), each with its replay window. Every handshake record sent is
   remembered with the fragments it carried; ACKs mark fragments and retransmissions resend
   only the unacknowledged ones. A receiver ACKs at once on a repeat of the peer's flight or
   on its final flight, at the next timer on a gap (coalescing the datagrams that arrived
   together), and after a quarter of the RTO when a flight stays incomplete. Bounds: 16
   messages ahead, 64 KiB per message, 8 KiB ClientHello before the cookie (as in DTLS 1.2),
   32 buffered early records, 32 record numbers per ACK, 256 remembered records per flight,
   post-handshake flights given up after 8 retransmissions.
5. **HelloRetryRequest cookies are stateless.** The cookie carries the chosen suite, the
   group the HRR asks for and the hash of ClientHello1, MACed with the `HelloVerifier` secret,
   so the server rebuilds the transcript from ClientHello2. `HelloVerifier::check` answers a
   ClientHello offering DTLS 1.3 with such a HelloRetryRequest (`HelloCheck::Respond`) and
   accepts the second ClientHello; a connection created with cookies off trusts the cookie the
   listener checked. The HRR mirrors ClientHello1's record number; the ServerHello continues
   from ClientHello2's (OpenSSL 4.1 clients never settle their final flight otherwise).
6. **Connection IDs**: `Config::with_connection_id(Some(len))` makes each connection ask the
   peer for a random CID of `len` bytes (0: send one if the peer asks, need none). DTLS 1.2
   uses RFC 9146 `tls12_cid` records with the RFC 9146 additional data; DTLS 1.3 negotiates the
   CID in ClientHello / ServerHello (as wolfSSL does) and puts it in the unified header.
   `Connection::local_connection_id` and the free function `connection_id(datagram, len)` let
   a listener route datagrams by CID. Not done: NewConnectionId / RequestConnectionId.
7. **Resumption is sans-io on the client**: the client gets `Event::NewSession(Session)`
   (a DTLS 1.2 session ID or ticket at connect, each DTLS 1.3 NewSessionTicket) and resumes with
   `Connection::client_resume(config, now, &session)`. `Config::with_session_resumption(true)`
   turns it on for both sides: servers issue RFC 5077 tickets to clients that ask (session IDs
   in a bounded 1024-entry cache otherwise) and one DTLS 1.3 NewSessionTicket, sealed with
   AES-256-GCM under a `TicketKey` (random per config, or `with_ticket_key` to share it).
   Tickets carry the peer's certificate chain, which the verifier checks again on resumption,
   so fingerprint pinning holds for resumed sessions. Lifetime 2 hours by default
   (`with_ticket_lifetime`, at most 7 days), measured in Unix seconds so tickets survive
   restarts. DTLS 1.3 resumption is `psk_dhe_ke` only (always forward secret); 0-RTT is not
   implemented.
8. **External PSKs**: `Config::with_psks(Vec<Psk>)`. Clients offer the first; servers accept
   any listed identity and need no certificate when they only do PSK. DTLS 1.2 adds the
   AEAD PSK and ECDHE-PSK suites (`CipherSuite::PSK`, offered only with a PSK); DTLS 1.3 uses
   external PSKs with SHA-256 in `psk_dhe_ke`.

Public API added (only-dtls): `Version`, `Psk`, `Session`, `TicketKey`, `connection_id`;
`Config::{with_versions, with_psks, with_session_resumption, with_ticket_key,
with_ticket_lifetime, with_connection_id}`; `Connection::{client_resume, version,
local_connection_id, update_keys}`; `Event::NewSession`; `HandshakeInfo::{version, resumed,
psk_identity, local_connection_id, peer_connection_id}`; `CipherSuite::{PSK, TLS13, is_tls13,
is_psk}` and nine suite variants; `AlertDescription::{MissingExtension, UnknownPskIdentity}`.
`Config::new`'s default suite list now has the DTLS 1.3 and PSK suites in front (filtered by
version and PSK availability, so DTLS 1.2-only behaviour is unchanged).
`Connection::poll_timeout` can return a time after the handshake for DTLS 1.3 connections
(final flight until ACKed, NewSessionTicket, KeyUpdate).

## Consequences

- Interop (`tools/interop/dtls/run.sh`): OpenSSL 4.1 (built in `tools/interop/dtls/Dockerfile`;
  Debian's OpenSSL 3.5 has no DTLS 1.3) and wolfSSL 5.8.4 for DTLS 1.3 both ways, version
  negotiation and downgrade, HRR (cookie and group), small MTUs, KeyUpdate, resumption, PSKs,
  CIDs (wolfSSL, both versions); pion/dtls v3 for DTLS 1.2 CIDs and PSK suites both ways.
- The DTLS 1.2 path is unchanged for configurations that do not use the new options; WebRTC
  keeps its handshake byte for byte.
- Not done: 0-RTT, NewConnectionId / RequestConnectionId, post-handshake client
  authentication, DTLS 1.3 for WebRTC by default.
