# SRT

`only_media::srt` speaks SRT (Secure Reliable Transport, draft-sharabayko-srt-01) in live
mode: MPEG-TS over UDP, losses repaired by retransmission within a fixed latency, as ffmpeg,
OBS and hardware encoders send it. An `SrtServer` in front of the media [hub](media.md) takes
publishers in and plays streams out; `dial`, `push` and `pull` are the caller side.

Interop with ffmpeg's libsrt is tested (`crates/only-media/tests/srt_ffmpeg.rs`, run in Linux
Docker with Debian's ffmpeg; the test skips when ffmpeg has no SRT, as Homebrew's): ffmpeg
publishing in and ffprobe / ffmpeg playing out, with and without a passphrase, and `only`
pushing to and pulling from ffmpeg in `mode=listener`.

## Server

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:server}}
```

- The server is the acceptor of a **UDP listener**: each peer address gets its own handler,
  and a caller that restarts (a new socket ID from the same address) replaces its session.
- The **stream ID** names the stream: plainly (`live/s`, `live/s?token=x`, which plays) or in
  the access control syntax (`#!::r=live/s,m=publish,u=alice`). `m=publish` publishes,
  `m=request` (the default) plays; `bidirectional` is refused. The query of a plain stream ID
  reaches the hub's `on_publish` / `on_subscribe` hooks as `PeerInfo::query`.
- `SrtConfig::on_connect` sees the request (address, stream ID, latency, whether it
  encrypts) and the parsed `StreamId`, and may reject with any `RejectReason`
  (`FORBIDDEN` = 1403, ...), which the caller hears in the handshake.
- A **publisher** reserves its path during the handshake (`Hub::reserve`), so a second
  publisher of a busy path is rejected there (`CONFLICT`, 1409). Its MPEG-TS is demuxed
  (`only_media::mpegts::demux`) and the stream goes live once the program's tracks are known
  (H.264, H.265, AAC, Opus, MP3).
- A **player** subscribes to the hub and receives the stream muxed into MPEG-TS, seven
  transport packets per SRT packet, with PAT/PMT before every keyframe and timestamps that keep
  increasing across a republish. It starts from the GOP cache (`play_gop_cache`, on by
  default). A player whose peer acknowledges too little (`max_send_backlog`, 2 MiB) has packets
  dropped, video until the next keyframe (`hub::Dropper`). Without `play_wait`, playing a
  stream that is not live is rejected (`NOT_FOUND`, 1404); with it the player waits.
- **Encryption**: with `passphrase` set, every caller must encrypt with the same passphrase
  (AES-CTR, 128/192/256-bit keys as the caller chooses with `pbkeylen`); a wrong one is
  rejected with `BAD_SECRET`, an unencrypted caller with `UNSECURE`.

## Callers

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:publish}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:player}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:play}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-srt.rs:relay}}
```

- `srt::dial(&engine, addr, Config, handler)` opens a raw caller session (the engine needs
  `udp_client_threads`); it returns once the socket is open and the handshake goes on in the
  background (`SrtSession::is_connected`). `SrtSession::send` takes payloads of up to 1456
  bytes (1316 for MPEG-TS) and fails with `BufferFull` rather than block. The `SrtHandler`
  gets payloads in order at their delivery time, then `on_close` with the reason
  (`Rejected(reason)`, `PeerClosed`, `PeerIdle`, `HandshakeTimeout`, ...).
- `srt::push(&engine, addr, Config, &hub, path)` sends a hub stream to a listener (an SRT
  server with `m=publish` in the stream ID, or `ffmpeg -i 'srt://:port?mode=listener'`);
  `srt::pull` plays from a listener into a hub path, which it reserves right away.
- `Config`: `latency` (both sides use the larger of the two; default 120 ms), `passphrase` and
  `pbkeylen`, `stream_id`, `flow_window` / `send_buffer_packets` (8192 packets each),
  `handshake_timeout` (3 s), `peer_idle_timeout` (5 s).

## The protocol without I/O

`srt::Conn` is the whole protocol as a state machine: feed it datagrams (`handle`) and the
time (`handle_timeout` at `next_timeout`), drain `take_output` and `poll_event`.
`srt::Listener` answers inductions statelessly with a SYN cookie and turns an accepted
conclusion into a connected `Conn`. Both are what the server and callers above drive, and
what the unit tests run over a simulated lossy link. They implement:

- the HSv5 handshake with the HSREQ/HSRSP (TSBPD, too-late drop, periodic NAK, retransmission
  flag), KMREQ/KMRSP and stream ID extensions, and rejection codes both ways;
- full ACKs every 10 ms and light ACKs every 64 packets, ACKACK and the RTT estimate;
  immediate NAKs for gaps and periodic NAKs every `(RTT + 4 * RTTVar) / 2` for losses still
  open; retransmission bounded by the send buffer and the peer's flow window; DROPREQ for
  packets the sender gave up on;
- timestamp-based delivery (TSBPD) on a time base that follows the least delay seen and a
  drifting sender clock; packets still missing when a later one is due are dropped as too
  late;
- keepalives, SHUTDOWN, a peer idle timeout; key refreshes (KMREQ control packets) from the
  peer are installed.

Not implemented: rendezvous mode, file mode and its congestion control, AES-GCM, packet
filters (FEC), socket groups (bonding), the HSv4 handshake of SRT before 1.3, and starting a
key refresh (a connection keeps its key, about 2^31 packets).
