# only-dtls

[中文](README.zh-CN.md)

Sans-io DTLS 1.2 (RFC 6347) for [`only`](https://github.com/lesismal/only), on
[`only-crypto`](../only-crypto) and [`only-x509`](../only-x509), in safe Rust
(`#![forbid(unsafe_code)]`) with no other dependencies. It is the DTLS layer of the in-house
WebRTC stack planned in DEV-PLAN wave D (DTLS-SRTP keys, SCTP data channels), where it will
replace str0m's `dimpl`. An internal crate (docs/api-stability.md): its API follows that stack
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
  `SRTP_AES128_CM_HMAC_SHA1_32`, no MKI), `renegotiation_info` (RFC 5746), `supported_groups`,
  `ec_point_formats`, `signature_algorithms`. Renegotiation is refused (`no_renegotiation`).
- Authentication: mutual by default (`with_require_client_certificate`). No CA path
  validation: `PeerVerifier::Fingerprints` pins certificates (SDP `a=fingerprint`),
  `PeerVerifier::Custom` runs a callback (for example `only_x509::Verifier`), `AcceptAny`
  leaves the check to the caller (`HandshakeInfo::peer_fingerprint`). The peer always proves
  possession of the certificate key.

Not implemented: DTLS 1.3 (RFC 9147) and its ACK messages, connection IDs (RFC 9146),
session resumption and tickets, PSK and non-ECDHE key exchanges, CBC suites, SRTP MKIs.

## Testing

- Simulated links (`tests/loopback.rs`): 24 seeds with 25 % loss, 10 % duplication and up to
  400 ms of reordering at MTU 256 (cookies on and off), datagram sizes checked against the MTU,
  every cipher suite with P-256, P-384, Ed25519 and RSA server certificates and three client
  certificate types, every SRTP profile; negative cases: wrong fingerprints (both directions),
  custom verifier refusal, replayed / tampered / truncated records, unauthenticated alerts,
  corrupted cookies, the stateless `HelloVerifier` (other address, expiry, garbage), timeout and
  backoff schedule, close_notify, no shared suite, missing client certificate, API misuse.
- Interop (`tools/interop/dtls/run.sh`): OpenSSL `s_server -dtls1_2` / `s_client -dtls1_2`
  (3.5 in the rust:1 image, 4.1 on the host) in both directions with every suite, `-use_srtp`
  profiles, `-mtu 300`, mutual authentication, and `-keymatexport EXTRACTOR-dtls_srtp` equal to
  our keys; pion/dtls v3.1 both directions for every SRTP profile with ECDSA, ChaCha20 and RSA
  suites, keying material compared; str0m's `dimpl` in memory, both roles (`tests/dimpl.rs`).
- Fuzzing: targets `dtls_record` (record splitter, fragment and message parsers, re-encoding)
  and `dtls_handshake` (arbitrary datagrams into client and server state machines mid-handshake
  and connected) in `fuzz/`; `fuzzing::tests` replays their corpora on stable.
