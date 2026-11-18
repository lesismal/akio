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
            Event::Restarted => {} // the peer restarted: channels closed, up again
            Event::Closed => return, // always last
            _ => {}
        }
    }
    // wait for a record until sctp.poll_timeout(), then:
    // sctp.handle_packet(Instant::now(), &record)  or  sctp.handle_timeout(Instant::now())
}
```

- `Config::new(dtls_client)`: ports 5000, MTU 1200, 256 KiB message limits both ways
  (`max_message_size` is the remote `a=max-message-size`; a larger incoming message aborts the
  association), 1 MiB receive window and per-channel buffer, 10 retransmissions; RTO 1 s
  initial, 200 ms minimum, 10 s maximum; I-DATA offered (`message_interleaving`) and the
  weighted fair queueing scheduler (`scheduler`); HEARTBEATs after 30 s idle
  (`heartbeat_interval`); zero checksums offered (`zero_checksum`, RFC 9653: turn it off when
  the packets do not travel over DTLS).
- Channels share the association through the `Scheduler` (RFC 8260 §3): first come first
  served, round robin, round robin per packet, priority, fair capacity, or weighted fair
  queueing (the default) by channel priority (`ChannelOptions::with_priority`, the peer's
  DATA_CHANNEL_OPEN value, `set_channel_priority`; higher is more important, as in RFC 8832).
  With I-DATA (both sides offer it; `message_interleaving()` tells) the unit is a chunk, so a
  large message no longer holds up small ones on other channels (new messages start only while
  the started ones fit in half the peer's window); with DATA a started message goes out whole.
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
  Extensions RE-CONFIG, FORWARD TSN, I-DATA and I-FORWARD-TSN.
- Peer restart (RFC 9260 §5.2.2, §5.2.4): an INIT on a live association gets an INIT ACK with a
  new tag and Tie-Tags; the COOKIE ECHO of a restarted peer (case A) closes every channel, drops
  queued data, starts over with the new tags and TSNs and emits `Event::Restarted`; duplicates
  get COOKIE ACK, other combinations are discarded, and a restart while shutting down is
  refused (SHUTDOWN ACK + "Cookie Received While Shutting Down", or ABORT).
- Zero checksum (RFC 9653): Zero Checksum Acceptable with "SCTP over DTLS" in INIT / INIT ACK;
  packets with a zero checksum accepted; once the peer announced it too
  (`Association::zero_checksum`), packets after the handshake go out without a CRC-32C.
- Data transfer: fragmentation and reassembly (bounded by the receive limits), ordered and
  unordered delivery, SACK with gap blocks and duplicate TSNs (delayed every second packet or
  200 ms, immediate on gaps), slow start and congestion avoidance, the peer's window, T3-rtx
  with RTO from SRTT / RTTVAR (Karn), fast retransmit and fast recovery, association failure
  after `max_retransmissions` timeouts; SHUTDOWN in both roles; ABORT.
- HEARTBEAT (RFC 9260 §8.3): answered; sent after `heartbeat_interval` + RTO without data in
  flight; the HEARTBEAT ACK is an RTT measurement (`Association::rtt`) and clears the error
  count; each one unanswered within the RTO is an error (RTO doubled, the next HEARTBEAT at
  once), and after `max_retransmissions` errors the association fails (Path.Max.Retrans =
  Association.Max.Retrans with one path), so an idle association notices a vanished peer.
- Message interleaving (RFC 8260 §2): I-DATA chunks (32-bit MIDs, FSNs) when both sides offer
  them, fragments of different streams interleaved, reassembly per stream and message; DATA
  otherwise, and an ABORT for the chunk kind not negotiated. Stream schedulers and priorities
  (RFC 8260 §3) as above.
- Partial reliability (RFC 3758): per-message retransmission limits and lifetimes, FORWARD
  TSN with stream / SSN pairs both ways (I-FORWARD-TSN with stream / MID entries under I-DATA),
  only when the peer supports it.
- Stream reset (RFC 6525): Outgoing SSN Reset Request / Response with "in progress" and retry;
  several outstanding peer requests are accepted in any order; add-streams requests are
  accepted. Incoming SSN Reset Requests are answered with our Outgoing SSN Reset Request for
  those streams (their channels close); SSN/TSN Reset Requests are performed once none of our
  data is in flight ("in progress" until then): new TSNs both ways, every SSN back to 0.
- Data channels (RFC 8831 / 8832): DCEP OPEN / ACK, every channel type, negotiated channels,
  PPIDs 50, 51, 53, 56, 57 (and the deprecated partial 52, 54 on receive), messages ordered
  until the peer's ACK.

Not implemented, as WebRTC uses none of them (one association over one DTLS connection):
multi-homing, AUTH (RFC 4895), ASCONF (RFC 5061), ECN. We never send Incoming SSN Reset or
SSN/TSN Reset Requests (we answer them). See ADR-042 for the HEARTBEAT, restart, zero checksum
and reset request design.

## Testing

- Unit tests: codec round trips and checksum placement (DATA, I-DATA, I-FORWARD-TSN),
  reassembly with TSN wrap-around, interleaved and out-of-order I-DATA reassembly, FORWARD TSN
  and I-FORWARD-TSN, DCEP, DATA / I-DATA mismatch aborts.
- Simulated link (`tests/link.rs`, simulated time): 15 % loss, 5 % duplication and up to 40 ms
  of reordering at MTUs down to 300 bytes; ordered, unordered, both directions, 60 kB to
  256 KiB messages, retransmission-limited and lifetime channels with FORWARD TSN, empty
  messages, backpressure and `BufferedAmountLow`, channel close from either side and stream id
  reuse, simultaneous INIT, sending before the association is up, negotiated channels,
  shutdown, abort, failure when the peer vanishes, INIT giving up, 10 MB through a lossless
  link, oversized incoming messages, garbage packets; I-DATA negotiation in every combination,
  head-of-line blocking (a 200 kB message and a 4-byte one on two channels), scheduler shares
  (equal, 3:1 weighted, strict priority, FCFS order, one stream per packet), priorities changed
  at runtime, partial reliability with interleaved reliable and partially reliable channels,
  many large messages on many channels at once; HEARTBEAT RTT when idle, failure of an idle
  association whose peer vanished (none with HEARTBEATs off), HEARTBEATs over a link losing 15 %
  each way for 30 minutes; zero checksum negotiation in every combination; peer restart with
  data queued on both sides, then both directions and shutdown; a stray INIT on a live
  association. Unit tests: Incoming SSN Reset answered by our Outgoing request, SSN/TSN Reset in
  progress then performed, restart refused while shutting down.
  DATA and I-DATA run on alternate seeds; `SCTP_SEEDS=<n>` runs more seeds.
- Interop over UDP (`examples/udp_peer.rs`, `tools/interop/sctp/run.sh`) against pion/sctp
  v1.12.0 with pion/datachannel, both roles, pion's interleaving on (I-DATA / I-FORWARD-TSN)
  and off (DATA), without loss and with every 10th packet dropped each way: echoes on ordered
  and unordered channels, pion-opened reliable and partially reliable channels, closing from
  both sides, shutdown (earlier also v1.8.33, and up to 25 % loss, where pion may take longer
  than the 60 s limit); zero checksums offered by both (pion's `WithEnableZeroChecksum`), both
  roles, with and without loss. Firefox 158 (usrsctp) through only-webrtc
  (`tools/interop/webrtc/firefox.sh`, WebDriver BiDi), both offer directions: ordered and
  unordered echoes, 70 kB and 200 kB messages, 150 s idle (our HEARTBEATs answered), a channel
  closed by Firefox and a new one on the reused id. Neither Firefox nor Chrome 157 offers zero
  checksums. Through only-webrtc (`tools/interop/webrtc`): pion negotiates I-DATA;
  Chrome 157 uses DATA unless started with
  `--force-fieldtrials=WebRTC-DataChannelMessageInterleaving/Enabled/`, which passes too.
- Fuzzing: target `sctp_packet` (arbitrary packets, raw and with a fixed-up checksum, into
  fresh, handshaking and established associations, one pair on I-DATA and one on DATA, all
  accepting zero checksums; seeds with HEARTBEATs, a peer restart and every RE-CONFIG request)
  in `fuzz/`; `fuzzing::tests` replays its
  corpus on stable.
