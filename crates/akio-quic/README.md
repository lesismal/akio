# akio-quic

[中文](README.zh-CN.md)

QUIC v1 (RFC 9000, RFC 9001, RFC 9002) and v2 (RFC 9369) with unreliable datagrams (RFC 9221) for
[`akio`](https://github.com/lesismal/akio), implemented in this crate on
[`akio-tls`](../akio-tls) (TLS 1.3 without records) and [`akio-crypto`](../akio-crypto):
a sans-io protocol core in safe Rust (`#![forbid(unsafe_code)]`), no third-party dependencies.
It replaced quinn-proto, its rustls and the `bytes` crate (DEV-PLAN wave D) behind the same API.

A `QuicServer` is the acceptor of a UDP listener: one endpoint routes every datagram to its
connection by connection ID, so a client that changes address keeps its connection. `dial`
starts a client connection on an engine with UDP client threads. Handlers implement
`QuicHandler` (stream data, resets, stops, datagrams, close); writes never block. Configure with
`server_config` / `client_config` (or the `*_from` variants taking `akio::tls` configurations)
and `TransportConfig` (stream limits, windows, idle timeout, keep-alive, MTU discovery,
datagram buffers, NewReno, CUBIC or BBR, ECN).

```rust,no_run
use akio::{Engine, Listener};
use akio_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
}
let certs = akio::tls::Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = akio::tls::PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = akio_quic::server_config(certs, key, &[b"echo"]).unwrap();
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
  path validation datagrams, QUIC versions 1 and 2 (RFC 9369: its salt, HKDF labels, Retry key
  and long header type bits), Version Negotiation (a client starts over once in a version both
  sides speak, guarded by the version_information parameter of RFC 9368 against downgrades;
  `ClientConfig::version`, `ServerConfig::versions`), Retry with its integrity tag, stateless resets
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
  timeouts with backoff and handshake anti-deadlock probes, persistent congestion, NewReno,
  CUBIC (RFC 9438) and BBR (below), pacing, the 3x anti-amplification limit until the address is
  validated,
  ACK delay and immediate ACK rules, idle timeout, keep-alive, path MTU discovery (DPLPMTUD
  probes up to 1452 bytes).
- **Handshake**: TLS 1.3 through `akio_tls::quic::QuicTls` (ALPN required), transport
  parameters with the initial_source / original_destination / retry_source connection ID
  checks, session resumption by ticket, address validation with Retry tokens and NEW_TOKEN
  tokens (kept per server name in the `ClientConfig`).
- **Connection IDs**: 8-byte IDs issued with NEW_CONNECTION_ID up to the peer's limit, retired
  and replaced, routed by the endpoint; the peer's IDs and reset tokens tracked with
  retire_prior_to.
- **ECN** (RFC 9000 section 13.4, RFC 9002 section 7.1; `TransportConfig::ecn`, on by default):
  packets go out ECT(0) where the UDP layer sets the codepoint (an `IP_TOS` / `IPV6_TCLASS`
  control message per `sendmmsg` message on Linux, per `sendmsg` on macOS, the IP header itself
  under akio-dpdk's userspace stack; `AKIO_UDP_ECN=0` turns it off on the kernel sockets),
  received codepoints are read from `IP_RECVTOS` / `IPV6_RECVTCLASS` control messages (or the IP
  header under akio-dpdk) and reported in
  ACK_ECN frames, the path is validated with a ten-packet testing period (cut short by a probe
  timeout, so a path that drops marked packets costs one PTO) and the peer's counts, CE marks are
  congestion events, and a path that bleaches, re-marks or drops marks falls back to unmarked
  packets. `ConnectionStats::ecn_capable` / `ecn_ce_events`.
- **BBR** (`Congestion::Bbr`, experimental): BBRv1's model and state machine (Startup at 2/ln 2,
  Drain, ProbeBW gain cycling, ProbeRTT) on delivery-rate samples, with the loss and ECN bound of
  BBRv2/v3: a round losing or CE-marking more than 2% of its bytes ends Startup and caps the data
  in flight at the larger of a BDP and 0.7 of the window, growing back an eighth per clean round.
  The pacer follows its pacing rate. v3's bandwidth and inflight lower bounds, probing schedule
  and DCTCP-style ECN fraction are left out.
- **Migration**: a client that changes address (NAT rebinding, port change) is followed after
  path validation (PATH_CHALLENGE / PATH_RESPONSE) with a fresh congestion state when the IP
  changes and a new connection ID if the peer gave one; `ServerConfig::migration(false)`
  refuses it. A client moves on its own with `Connection::migrate(&engine)`: to the server's
  preferred address when it offered one (`ServerConfig::preferred_address`, served by a clone of
  the same `QuicServer` on a second listener), else to a new local UDP socket; the new path is
  probed under a connection ID not used before and adopted once answered (congestion, ECN and
  RTT state start over, the old socket closes), or abandoned after three PTOs. Answers to
  probes from another address use a connection ID of their own (RFC 9000 section 9.5).
- **I/O**: full-size datagrams leave in batches for one GSO send (`Conn::send_segments`, up to
  10 segments); writes made from a connection's own callbacks are corked and go out together
  with the acknowledgments once the callback returns. Received datagrams are handled one by one
  (handler events and data to send right away), but acknowledgments are made once per receive
  batch, at the I/O loop's internal batch-end hook; UDP GRO (on by default on Linux) hands a bulk
  receiver whole GSO batches. A received packet is copied once into a per-thread pooled buffer,
  decrypted there, and its stream data and datagrams are slices of it; the buffer is reused once
  they are all dropped. Sent packets are tracked in a ring indexed by packet number. A shared
  timer thread drives timeouts.

**0-RTT** (RFC 9001 section 4.6), off by default on both sides: `ServerConfig::zero_rtt(true)`
and `ClientConfig::zero_rtt(true)`. A client resuming with a ticket that allows it starts from
the transport parameters the server gave last time (RFC 9000 7.4.1: limits only, no connection
IDs, tokens or addresses), opens streams right after `dial` and sends their data in 0-RTT
packets (the application data packet number space, coalesced behind the Initial; version 1 and
2). The server accepts 0-RTT only under the same limits as when the ticket was issued, with
`akio-tls`'s replay protection (a 10-second freshness window and a bounded record of recent
ClientHellos per server, see its README), and answers in 0.5-RTT. Rejected or lost 0-RTT data is
sent again (in 1-RTT, or in 0-RTT to the new connection ID after a Retry). The client sees
`Connection::early_data()`; the server sees `Connection::is_early(stream)`, and akio-h3 marks
such requests `Early-Data: 1` (RFC 8470). **0-RTT data can be replayed** (to another server
sharing tickets, or within the window by an attacker who can make the client retry) and is not
forward secret: only act on requests that are safe to repeat, answer the others `425 Too Early`.

Compatible version negotiation (RFC 9368 section 4, ADR-013 and ADR-014) moves a version 1
client to version 2 inside one handshake when the server prefers it (`ServerConfig::prefer_version`),
with the version_information downgrade checks; interop with ngtcp2 in
`tools/interop/quic/ngtcp2-cvn.sh` (quic-go does not implement RFC 9368). ECN marks are set and
read on Linux, macOS and over akio-dpdk (ADR-035); elsewhere connections do not mark.

quic-go (v0.62) derives version 2 key update secrets with the v1 label `quic ku` where RFC 9369
section 3.3.2 (and its test vector A.5) says `quicv2 ku`; it starts its first key update after
100 packets, so version 2 connections with quic-go stall there. This crate follows the RFC.

## Internals

- `proto` (crate-private): the sans-io core: `packet` (headers, protection, packet numbers),
  `crypto` (packet keys, header protection, Initial keys, Retry tag, key update, tokens),
  `frame`, `params` (transport parameters), `stream` (send and receive buffers), `ranges`,
  `recovery` (RTT, NewReno, CUBIC, pacer), `bbr` (BBR and its rate samples), `conn` (the
  connection: receive path, send path, streams, `ecn`, `migrate`), `endpoint` (connection ID
  routing, Retry, Version Negotiation, stateless reset), and `sim`, a simulated lossy,
  reordering, duplicating link with a virtual clock for tests, optionally behind a rate-limited
  drop-tail bottleneck that CE-marks, bleaches or black-holes ECN.
- `bytes`: the `Bytes` payload type (cheaply cloneable, sliceable; received data is a slice of
  the decrypted packet) and the per-thread pool of receive buffers.
- `fuzzing` (`#[doc(hidden)]`, feature `fuzzing`): entry points of the `quic_packet`,
  `quic_frame` and `quic_conn` fuzz targets.

## Testing

- RFC 9001 Appendix A vectors: Initial secrets and keys, the client and server Initial
  packets, Retry integrity tag, ChaCha20 short header packet, key update secrets; RFC 9369
  Appendix A for version 2 (Initial keys, Retry tag, ChaCha20 packet and key update).
- Unit tests per component and simulated-network tests: handshake under 30 % loss; lossy (10 %),
  reordering, duplicating links with a 1350-byte MTU carrying 2 MB plus 40 streams; small
  windows and stream limits; NAT rebinding and port changes; migration refused; key updates
  started by either side and automatic ones every 100 packets; ChaCha20 and AES-256 suites;
  Retry; NEW_TOKEN and resumption; Version Negotiation; stateless reset; idle timeout and
  keep-alive; close before and after the handshake; datagrams; reset and stop; a 4-second
  blackout; NewReno; ECN validated and CE marks backed off on behind a marking AQM, fallback when
  bleached, black-holed or off; BBR filling a 20 Mbit/s bottleneck with a small queue, 4x
  CUBIC's goodput under 1% random loss, bounded loss on a shallow buffer; client migration to a
  new port (twice), a failed probe staying put, refusal by disable_active_migration, the move to
  a preferred address; version 2 with Retry and key updates, a client starting over in version 2
  after Version Negotiation, a forged one detected as a downgrade. Over loopback: migration to the
  preferred address and to a new port, version 2, and on Linux and macOS the ECN validation.
  The `quic_conn` fuzz target also chooses what the path does to ECN (kept, bleached, CE-marked,
  re-marked ECT(1)).
- Interop: `tools/interop/quic/run.sh` (quic-go raw QUIC echo of streams and datagrams, both
  directions, with Retry, key updates and 150 MB; version 2 both ways; client migration both
  ways, ours with BBR; on Linux, ECN validated against quic-go), `tools/interop/h3/run.sh` (HTTP/3 with
  quic-go and fib, both directions) and `tools/interop/quic/docker.sh` (ngtcp2 through
  libcurl-gnutls and OpenSSL 3.5's QUIC through curl, libcurl and `openssl s_client -quic`, as
  clients of our HTTP/3 and echo servers, in Debian's `rust:1` image).
- Fuzz targets `quic_packet`, `quic_frame`, `quic_conn`, with corpus replay tests on stable.
