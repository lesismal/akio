# only-dtls

[中文](README.zh-CN.md)

Sans-io DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147) for [`only`](https://github.com/lesismal/only), on
[`only-crypto`](../only-crypto) and [`only-x509`](../only-x509), in safe Rust
(`#![forbid(unsafe_code)]`) with no other dependencies. It is the DTLS layer of the in-house
WebRTC stack of DEV-PLAN wave D (DTLS-SRTP keys, SCTP data channels), used by `only-webrtc`. An internal crate (docs/api-stability.md): its API follows that stack
and may change in any release.

## Driving a connection

A `Connection` has no sockets, threads or clocks. The caller passes in every received datagram
and the current time and sends what comes out:

```rust,ignore
use std::sync::Arc;
use std::time::Instant;
use only_dtls::{Config, Connection, Event, Identity, PeerVerifier, Role};

let identity = Identity::generate_self_signed()?;           // its fingerprint goes into the SDP
let remote = only_dtls::Fingerprint::parse("sha-256 AB:CD:...")?; // from the remote SDP
let config = Arc::new(Config::webrtc(identity, PeerVerifier::Fingerprints(vec![remote])));
let mut conn = Connection::new(config, Role::Client, Instant::now(), b"203.0.113.9:5000")?;
loop {
    while let Some(datagram) = conn.poll_transmit() { /* socket.send(&datagram) */ }
    while let Some(event) = conn.poll_event() {
        match event {
            Event::Connected(info) => { /* info.srtp_keys, info.peer_fingerprint */ }
            Event::ApplicationData(data) => { /* SCTP packet */ }
            Event::Closed => { /* close_notify */ }
            _ => {}
        }
    }
    // wait for a datagram until conn.poll_timeout(), then:
    // conn.handle_datagram(Instant::now(), &datagram)?  or  conn.handle_timeout(Instant::now())?
}
```

- `Connection::client` / `Connection::server` / `Connection::new(config, role, now, peer)`:
  WebRTC picks the role from `a=setup` (`active` = client). `peer` is any stable encoding of
  the remote transport address; it is bound into HelloVerifyRequest cookies.
- `send_application_data(&[u8])` sends one record (≤ 16384 bytes) as one datagram.
- `export_keying_material(label, context, len)` is the RFC 5705 exporter;
  `HandshakeInfo::srtp_keys` already holds the `EXTRACTOR-dtls_srtp` output split into client
  and server master keys and salts (`SrtpKeys::local(role)` / `remote(role)`).
- `close()` sends close_notify. Fatal errors send the matching alert and are returned from
  `handle_datagram` / `handle_timeout`.
- `HelloVerifier::check(now, peer, datagram)` lets a listener answer ClientHellos statelessly
  (`Respond(hello_verify_request)`) and create a `Connection` only for a valid cookie
  (`Accept`).

## Protocol coverage

- Record layer: epochs, 48-bit sequence numbers, a 64-record anti-replay window per epoch,
  several records per datagram; unauthenticated, replayed or malformed records are dropped
  silently (RFC 6347 §4.1.2.7); epoch-0 alerts are ignored once connected.
- Handshake: full ECDHE handshake in both roles; messages fragmented to `Config::with_mtu` and
  reassembled from any order (16-message window, 64 KiB per message); flights retransmitted
  with exponential backoff (default 1 s doubling to 60 s, RFC 6347 §4.2.4) and when the peer
  repeats its previous flight; handshake deadline (default 30 s); stateless HMAC-SHA-256
  cookies with a secret that rotates every minute.
- Cipher suites: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (WebRTC baseline),
  `..._AES_256_GCM_SHA384`, `..._CHACHA20_POLY1305_SHA256`, and the same three with RSA.
  Groups X25519, P-256, P-384 (uncompressed points). Signatures ECDSA (SHA-256/384/512),
  Ed25519, RSA-PSS and RSA PKCS#1 v1.5 with SHA-256/384/512.
- Extensions: `extended_master_secret` (RFC 7627; required by default), `use_srtp`
  (RFC 5764: `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM`, `SRTP_AES128_CM_HMAC_SHA1_80`,
  `SRTP_AES128_CM_HMAC_SHA1_32`; the `srtp_mki` field: `Config::with_srtp_mki` offers one,
  `Config::with_srtp_accept_mki` echoes the client's, `HandshakeInfo::srtp_mki` tells which is
  in use), `renegotiation_info` (RFC 5746), `supported_groups`,
  `ec_point_formats`, `signature_algorithms`. Renegotiation is refused (`no_renegotiation`).
- Authentication: mutual by default (`with_require_client_certificate`). No CA path
  validation: `PeerVerifier::Fingerprints` pins certificates (SDP `a=fingerprint`),
  `PeerVerifier::Custom` runs a callback (for example `only_x509::Verifier`), `AcceptAny`
  leaves the check to the caller (`HandshakeInfo::peer_fingerprint`). The peer always proves
  possession of the certificate key.

DTLS 1.3, connection IDs, resumption and PSKs (ADR-021):

- Versions: `Config::with_versions` (default DTLS 1.2 only, also `Config::webrtc`). With both,
  a connection starts as DTLS 1.3 and continues as DTLS 1.2 with a 1.2-only peer (RFC 8446
  downgrade sentinel set and checked).
- DTLS 1.3: suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`; unified record header (16-bit sequence numbers, explicit
  length) with record number encryption; epoch 2 for the handshake, 3+ for data, one more per
  KeyUpdate (`Connection::update_keys`; automatic after 2^23 records); ACKs: on gaps, after a
  quarter of the RTO for an incomplete flight, at once for final flights and repeats; only
  unacknowledged fragments are retransmitted; stateless HelloRetryRequest cookies (cipher
  suite, group, ClientHello1 hash under the `HelloVerifier` HMAC), also from
  `HelloVerifier::check`; `use_srtp` in EncryptedExtensions; the TLS 1.3 exporter.
- Connection IDs: `Config::with_connection_id(Some(len))`; RFC 9146 `tls12_cid` records in
  DTLS 1.2, the CID in the unified header in DTLS 1.3; `connection_id(datagram, len)` routes.
- Resumption: `Config::with_session_resumption(true)`; DTLS 1.2 session IDs (cache of 1024)
  and RFC 5077 tickets, DTLS 1.3 NewSessionTicket (`psk_dhe_ke`); tickets sealed with
  AES-256-GCM under a `TicketKey`, carrying the peer chain (checked again on resumption);
  `Event::NewSession` / `Connection::client_resume`.
- PSKs: `Config::with_psks`; `TLS_PSK_WITH_*` and `TLS_ECDHE_PSK_WITH_*` AEAD suites in
  DTLS 1.2, external PSKs (SHA-256) in DTLS 1.3.

Not implemented: DTLS 1.3 0-RTT, NewConnectionId / RequestConnectionId, post-handshake client
authentication, non-ECDHE certificate key exchanges, CBC suites.

## Testing

- Simulated links (`tests/loopback.rs`): 24 seeds with 25 % loss, 10 % duplication and up to
  400 ms of reordering at MTU 256 (cookies on and off), datagram sizes checked against the MTU,
  every cipher suite with P-256, P-384, Ed25519 and RSA server certificates and three client
  certificate types, every SRTP profile, SRTP MKI negotiation (also over DTLS 1.3); negative
  cases: wrong fingerprints (both directions),
  custom verifier refusal, replayed / tampered / truncated records, unauthenticated alerts,
  corrupted cookies, the stateless `HelloVerifier` (other address, expiry, garbage), timeout and
  backoff schedule, close_notify, no shared suite, missing client certificate, API misuse.
- Interop (`tools/interop/dtls/run.sh`): OpenSSL `s_server -dtls1_2` / `s_client -dtls1_2`
  (3.5 in the rust:1 image, 4.1 on the host) in both directions with every suite, `-use_srtp`
  profiles, `-mtu 300`, mutual authentication, and `-keymatexport EXTRACTOR-dtls_srtp` equal to
  our keys; pion/dtls v3.1 both directions for every SRTP profile with ECDSA, ChaCha20 and RSA
  suites, keying material compared; the in-house WebRTC stack's interop runs (pion, Chrome) exercise it end to end.
- DTLS 1.3 and the new features (`tests/dtls13.rs`): 32 seeds at MTU 256 with 25 % loss,
  duplication and reordering (cookies, CIDs, tickets on some), KeyUpdates both ways over the
  lossy link; one lost datagram resent as one fragment after the client's ACK; lost final
  flight and lost ACK; HRR cookies in the connection and in `HelloVerifier`; every DTLS 1.3
  suite with four key types; version negotiation (six combinations, cookies on and off);
  DTLS 1.3 and DTLS 1.2 resumption (also over a lossy link); external PSKs (wrong key: bad
  binder); every DTLS 1.2 PSK suite; CIDs in both versions with asymmetric lengths; replayed
  and tampered DTLS 1.3 records. The key schedule is checked against RFC 8448 with the TLS
  prefix.
- Interop for DTLS 1.3 (`tools/interop/dtls/dtls13.sh`, from `run.sh`, in the image of
  `tools/interop/dtls/Dockerfile`): OpenSSL 4.1 `-dtls1_3` both ways (SRTP keys compared,
  RSA/ChaCha20 at MTU 300, HRR for a group and for a cookie, KeyUpdate both ways, resumption,
  PSKs in both versions, version negotiation with `-dtls`, `-dtls1_2` and `-listen`), wolfSSL
  5.8.4 (CIDs in both versions and directions, HRR, KeyUpdate, resumption); pion/dtls CIDs and
  PSK suites both ways.
- Fuzzing: targets `dtls_record` (record splitter, fragment and message parsers, re-encoding)
  and `dtls_handshake` (arbitrary datagrams into client and server state machines mid-handshake
  and connected) in `fuzz/`; `fuzzing::tests` replays their corpora on stable.
