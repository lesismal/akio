# only-sctp

[中文](README.zh-CN.md)

Sans-io SCTP over DTLS (RFC 8261) with WebRTC data channels (RFC 8831, RFC 8832) for
[`only`](https://github.com/lesismal/only), on [`only-crypto`](../only-crypto), in safe Rust
(`#![forbid(unsafe_code)]`) with no other dependencies. It is the data channel layer of the
in-house WebRTC stack planned in DEV-PLAN wave D, where it replaces str0m's SCTP. An internal
crate (docs/api-stability.md): its API follows that stack and may change in any release.

## Driving an association

An `Association` has no sockets, threads or clocks. The caller feeds it every DTLS
application-data record (one SCTP packet each) and sends every packet it produces as one DTLS
record:

```rust,ignore
use std::time::Instant;
use only_sctp::{Association, ChannelOptions, Config, Event};

let mut sctp = Association::new(Config::new(dtls_client), Instant::now());
if dtls_client {
    sctp.connect(Instant::now()); // either side may; INIT collisions converge
}
let chat = sctp.open_channel(Instant::now(), ChannelOptions::new("chat"))?;
sctp.send(Instant::now(), chat, b"hello", false)?; // queued until the association is up
loop {
    while let Some(packet) = sctp.poll_transmit(Instant::now()) { /* dtls.send(&packet) */ }
    while let Some(event) = sctp.poll_event() {
        match event {
            Event::Connected => {}
            Event::ChannelOpen { stream, label, .. } => {}
            Event::ChannelData { stream, data, binary } => {}
            Event::BufferedAmountLow { stream } => {}
            Event::ChannelClose { stream } => {}
            Event::Closed => return, // always last
        }
    }
    // wait for a record until sctp.poll_timeout(), then:
    // sctp.handle_packet(Instant::now(), &record)  or  sctp.handle_timeout(Instant::now())
}
```

- `Config::new(dtls_client)`: ports 5000, MTU 1200, 256 KiB message limits both ways
  (`max_message_size` is the remote `a=max-message-size`; a larger incoming message aborts the
  association), 1 MiB receive window and per-channel buffer, 10 retransmissions; RTO 1 s
  initial, 200 ms minimum, 10 s maximum.
- `open_channel` picks the lowest free stream id of our parity (DTLS client even, server odd)
  or `ChannelOptions::negotiated`; it may be called before the association is up.
  `send` returns `Ok(false)` when the channel already buffers more than `max_buffered_amount`;
  `buffered_amount` counts queued and unacknowledged bytes; `BufferedAmountLow` fires when it
  falls to the threshold (default 0) after having been above it.
- `close_channel` resets the outgoing stream after the queued data; `ChannelClose` fires once
  both directions are reset (the peer answers with its own reset) and the stream id is free
  again. `shutdown` is graceful, `abort` immediate; when the association ends every open
  channel gets `ChannelClose`, then `Closed`.

## Protocol coverage

- Packets and handshake (RFC 9260): CRC-32C stored little-endian (as usrsctp and pion),
  bundling up to the MTU, unknown chunks and parameters handled by their high-order bits;
  INIT / INIT ACK / COOKIE ECHO / COOKIE ACK with a self-contained HMAC-SHA-256 cookie, INIT
  and COOKIE ECHO retransmission (8 tries), INIT collision and duplicate COOKIE ECHO; Supported
  Extensions RE-CONFIG and FORWARD TSN.
- Data transfer: fragmentation and reassembly (bounded by the receive limits), ordered and
  unordered delivery, SACK with gap blocks and duplicate TSNs (delayed every second packet or
  200 ms, immediate on gaps), slow start and congestion avoidance, the peer's window, T3-rtx
  with RTO from SRTT / RTTVAR (Karn), fast retransmit and fast recovery, association failure
  after `max_retransmissions` timeouts; HEARTBEAT answered; SHUTDOWN in both roles; ABORT.
- Partial reliability (RFC 3758): per-message retransmission limits and lifetimes, FORWARD
  TSN with stream / SSN pairs both ways, only when the peer supports it.
- Stream reset (RFC 6525): Outgoing SSN Reset Request / Response with "in progress" and retry;
  several outstanding peer requests are accepted in any order; add-streams requests are
  accepted.
- Data channels (RFC 8831 / 8832): DCEP OPEN / ACK, every channel type, negotiated channels,
  PPIDs 50, 51, 53, 56, 57 (and the deprecated partial 52, 54 on receive), messages ordered
  until the peer's ACK.

Not implemented: I-DATA and message interleaving (RFC 8260), stream schedulers and priorities
(first come, first served), multi-homing, sending HEARTBEATs, peer restart, AUTH, ASCONF, ECN,
zero checksum (RFC 9653), incoming SSN reset and SSN/TSN reset requests (refused).

## Testing

- Unit tests: codec round trips and checksum placement, reassembly with TSN wrap-around,
  FORWARD TSN, DCEP.
- Simulated link (`tests/link.rs`, simulated time): 15 % loss, 5 % duplication and up to 40 ms
  of reordering at MTUs down to 300 bytes; ordered, unordered, both directions, 60 kB to
  256 KiB messages, retransmission-limited and lifetime channels with FORWARD TSN, empty
  messages, backpressure and `BufferedAmountLow`, channel close from either side and stream id
  reuse, simultaneous INIT, sending before the association is up, negotiated channels,
  shutdown, abort, failure when the peer vanishes, INIT giving up, 10 MB through a lossless
  link, oversized incoming messages, garbage packets. `SCTP_SEEDS=<n>` runs more seeds.
- Interop over UDP (`examples/udp_peer.rs`) against pion/sctp v1.12.0 and v1.8.33 with
  pion/datachannel, both roles, up to 25 % loss each way: echoes on ordered and unordered
  channels, pion-opened reliable and partially reliable channels, closing from both sides,
  shutdown.
- Fuzzing: target `sctp_packet` (arbitrary packets, raw and with a fixed-up checksum, into
  fresh, handshaking and established associations) in `fuzz/`; `fuzzing::tests` replays its
  corpus on stable.
