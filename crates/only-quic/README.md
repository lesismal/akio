# only-quic

[中文](README.zh-CN.md)

QUIC v1 (RFC 9000, RFC 9001, RFC 9002) with unreliable datagrams (RFC 9221) for
[`only`](https://github.com/lesismal/only), implemented in this crate on
[`only-tls`](../only-tls) (TLS 1.3 without records) and [`only-crypto`](../only-crypto):
a sans-io protocol core in safe Rust (`#![forbid(unsafe_code)]`), no third-party dependencies.
It replaced quinn-proto, its rustls and the `bytes` crate (DEV-PLAN wave D) behind the same API.

A `QuicServer` is the acceptor of a UDP listener: one endpoint routes every datagram to its
connection by connection ID, so a client that changes address keeps its connection. `dial`
starts a client connection on an engine with UDP client threads. Handlers implement
`QuicHandler` (stream data, resets, stops, datagrams, close); writes never block. Configure with
`server_config` / `client_config` (or the `*_from` variants taking `only::tls` configurations)
and `TransportConfig` (stream limits, windows, idle timeout, keep-alive, MTU discovery,
datagram buffers, NewReno or CUBIC).

```rust,no_run
use only::{Engine, Listener};
use only_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
}
let certs = only::tls::Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = only::tls::PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = only_quic::server_config(certs, key, &[b"echo"]).unwrap();
let engine = Engine::builder()
    .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(QuicServer::new(cfg, |_c: &Connection| Echo)))
    .build()
    .unwrap();
engine.run().unwrap();
```

## Protocol

- **Packets**: long and short headers, Initial / Handshake / 1-RTT packet number spaces,
  packet number encoding and decoding, header protection (AES and ChaCha20), AEAD packet
  protection (AES-128/256-GCM, ChaCha20-Poly1305), coalesced packets, padding of Initial and
  path validation datagrams, Version Negotiation, Retry with its integrity tag, stateless resets
  (sent for unknown connection IDs, rate-limited and smaller than the trigger; detected by
  token), 1-RTT key updates (RFC 9001 section 6: started every few million packets, followed
  when the peer starts one, previous keys kept for late packets).
- **Frames**: all of RFC 9000 (PADDING, PING, ACK with ranges and ECN counts, RESET_STREAM,
  STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
  DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
  PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE) and DATAGRAM (RFC 9221),
  with the per-packet-type rules of RFC 9000 section 12.4.
- **Streams**: bidirectional and unidirectional, implicit opening, stream and connection flow
  control with window updates, stream limits with batched MAX_STREAMS, final size checks,
  RESET_STREAM answering STOP_SENDING.
- **Recovery** (RFC 9002): RTT estimation, packet and time threshold loss detection, probe
  timeouts with backoff and handshake anti-deadlock probes, persistent congestion, NewReno and
  CUBIC (RFC 9438), pacing, the 3x anti-amplification limit until the address is validated,
  ACK delay and immediate ACK rules, idle timeout, keep-alive, path MTU discovery (DPLPMTUD
  probes up to 1452 bytes).
- **Handshake**: TLS 1.3 through `only_tls::quic::QuicTls` (ALPN required), transport
  parameters with the initial_source / original_destination / retry_source connection ID
  checks, session resumption by ticket, address validation with Retry tokens and NEW_TOKEN
  tokens (kept per server name in the `ClientConfig`).
- **Connection IDs**: 8-byte IDs issued with NEW_CONNECTION_ID up to the peer's limit, retired
  and replaced, routed by the endpoint; the peer's IDs and reset tokens tracked with
  retire_prior_to.
- **Migration**: a client that changes address (NAT rebinding, port change) is followed after
  path validation (PATH_CHALLENGE / PATH_RESPONSE) with a fresh congestion state when the IP
  changes and a new connection ID if the peer gave one; `ServerConfig::migration(false)`
  refuses it.
- **I/O**: full-size datagrams leave in batches for one GSO send (`Conn::send_segments`, up to
  10 segments); writes made from a connection's own callbacks are corked and go out together
  with the acknowledgments once the callback returns. Received datagrams are handled one by one
  (handler events and data to send right away), but acknowledgments are made once per receive
  batch, at the I/O loop's internal batch-end hook; UDP GRO (on by default on Linux) hands a bulk
  receiver whole GSO batches. A received packet is copied once into a per-thread pooled buffer,
  decrypted there, and its stream data and datagrams are slices of it; the buffer is reused once
  they are all dropped. Sent packets are tracked in a ring indexed by packet number. A shared
  timer thread drives timeouts.

Not implemented: 0-RTT (sending or accepting; `only-tls` rejects early data), sending ECN marks
(received ECN counts are parsed; the socket layer does not expose the TOS byte), client-side
active migration (the API has no way to rebind), preferred_address (parsed, not used), BBR
(`Congestion::Bbr` runs CUBIC), QUIC v2.

## Internals

- `proto` (crate-private): the sans-io core: `packet` (headers, protection, packet numbers),
  `crypto` (packet keys, header protection, Initial keys, Retry tag, key update, tokens),
  `frame`, `params` (transport parameters), `stream` (send and receive buffers), `ranges`,
  `recovery` (RTT, NewReno, CUBIC, pacer), `conn` (the connection: receive path, send path,
  streams), `endpoint` (connection ID routing, Retry, Version Negotiation, stateless reset),
  and `sim`, a simulated lossy, reordering, duplicating link with a virtual clock for tests.
- `bytes`: the `Bytes` payload type (cheaply cloneable, sliceable; received data is a slice of
  the decrypted packet) and the per-thread pool of receive buffers.
- `fuzzing` (`#[doc(hidden)]`, feature `fuzzing`): entry points of the `quic_packet`,
  `quic_frame` and `quic_conn` fuzz targets.

## Testing

- RFC 9001 Appendix A vectors: Initial secrets and keys, the client and server Initial
  packets, Retry integrity tag, ChaCha20 short header packet, key update secrets.
- Unit tests per component and simulated-network tests: handshake under 30 % loss; lossy (10 %),
  reordering, duplicating links with a 1350-byte MTU carrying 2 MB plus 40 streams; small
  windows and stream limits; NAT rebinding and port changes; migration refused; key updates
  started by either side and automatic ones every 100 packets; ChaCha20 and AES-256 suites;
  Retry; NEW_TOKEN and resumption; Version Negotiation; stateless reset; idle timeout and
  keep-alive; close before and after the handshake; datagrams; reset and stop; a 4-second
  blackout; NewReno.
- Interop: `tools/interop/quic/run.sh` (quic-go raw QUIC echo of streams and datagrams, both
  directions, with Retry, key updates and 150 MB), `tools/interop/h3/run.sh` (HTTP/3 with
  quic-go and fib, both directions) and `tools/interop/quic/docker.sh` (ngtcp2 through
  libcurl-gnutls and OpenSSL 3.5's QUIC through curl, libcurl and `openssl s_client -quic`, as
  clients of our HTTP/3 and echo servers, in Debian's `rust:1` image).
- Fuzz targets `quic_packet`, `quic_frame`, `quic_conn`, with corpus replay tests on stable.
