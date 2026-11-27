# ADR-187: What an SFU needs of akio-webrtc: RTP forwarding, a receive cap, consent timeouts

English | [简体中文](187-webrtc-sfu.zh-CN.md)

Status: accepted (2026-11-27). akit's A260 and A261 (with A259, a peer's own configuration).

## Context

akit's WHIP/WHEP media server (I113) does what fit's does on pion: it answers a publisher with one
codec of each kind and the stream's viewers with the same codecs, forwards the publisher's RTP
packets to every viewer as they arrive (pion's `TrackLocalStaticRTP.WriteRTP`: the viewer track's
SSRC and payload type, the header extensions mapped by URI), tells the publisher `max_bitrate` once
a second as REMB, and ends a session whose peer has been silent for `ice_timeout`
(`ICEDisconnectedTimeout` / `ICEFailedTimeout`). akio-webrtc had RTP mode for receiving
(`on_rtp`), but sent media only as samples it packetized itself (`write_media`), sent REMB never
(TMMBR only, which browsers do not honour), and lost consent after a fixed 30 s, closing the peer
at `Disconnected`. The stopgaps (depacketize every frame and packetize it again per viewer; drop
past the cap without telling the publisher) cost a frame's delay and per-viewer work, and a
publisher that is never told keeps sending what is dropped.

## Decision

1. **`Peer::write_rtp(mid, &RtpPacket)`** writes a packet received in RTP mode as it is. It goes
   out with the line's own SSRC, the payload type negotiated on that line for the packet's codec
   (the first of that codec; a viewer answered with the publisher's codecs has just those), the
   packet's payload and marker, and the extensions akio-rtp knows (audio level, video orientation,
   transmission offset, playout delay) under the line's own extension ids: "mapped by URI" falls
   out of carrying values, not ids. MID, RID and the send-time extensions (abs-send-time,
   transport-wide sequence number) are this side's, filled as the packet leaves; it is paced and
   counted for TWCC like a sample's packets. No RED or FEC is added.
2. **Renumbering per sent stream** (`rtc/forward.rs`'s `Renumber`). Within one source (one SSRC
   written) a fixed offset maps extended sequence numbers and timestamps: a packet lost upstream
   stays a gap the viewer sees and NACKs, and one repaired upstream later (the SFU's receiving
   peer NACKs its publisher; RTP mode hands out the RTX-repaired packet under its original number)
   fills its gap, late. A new source (a publisher replaced, another simulcast layer) starts right
   after the last number sent, its timestamps after the last one by the time between the two
   arrivals; packets of the earlier source are dropped from then on, as are packets far (16384)
   behind the newest. Numbers the stream took in between (samples written, padding probes on the
   media stream) are skipped by shifting the offset. Choosing the sequence number is the
   forwarder's, not the stream's: akio-rtp gets `SendStream::write_with_seq`, which keeps its
   retransmission history in sequence order (a late packet is inserted, a number written again
   replaced; lookups by offset, then binary search), so NACKs from viewers are answered from what
   was sent, with RTX where negotiated; the next plain write follows the highest number, and only
   the newest packet moves the sender report's RTP / wallclock pair.
3. **`RtpPacket` carries what forwarding needs**: `mid`, `rid`, `codec` and `extensions` (the
   struct is `#[non_exhaustive]`, so the fields are additions). `Codec::kind()` becomes public, to
   pick the viewer's section of a packet's kind.
4. **`Peer::set_receive_bitrate_cap(Option<u64>)`** sends REMB (draft-alvestrand-rmcat-remb) with
   the cap about every media stream received (signalled ones before any arrived), once at once and
   then with every RTCP report (once a second). akio has no receive-side estimate (the remote
   estimates the path from transport-wide feedback), so the REMB carries the cap alone; libwebrtc
   takes it as the upper bound of its estimate. `None` stops sending; the last one stays in force
   at the remote, as it does in libwebrtc, so a cap is lifted with a higher one. A REMB received
   is now reported (`Other::RemoteBitrateEstimate { bitrate, ssrcs }` in `Event::Other`'s Debug).
5. **`RtcConfig::set_ice_timeouts(disconnected, failed)`**: consent silence for `disconnected`
   (at least 1 s) reports `Disconnected` (the agent's consent timeout; a full agent checks at
   least three times within it), and for `failed` the new `IceConnectionState::Failed`. Consent
   back before `failed` returns to `Connected`. With `failed` past `disconnected`, a server or
   endpoint that closes peers on loss of consent (`close_on_disconnect`, the default) closes them
   at `Failed`; otherwise (and without the setting) nothing changes: `Disconnected` at 30 s
   closes them. The `Failed` deadline is a timer about time, armed when `Disconnected` is reported.
6. **A peer's own configuration** (A259): `RtcServer::accept_offer_with(config, offer, handler)`
   and `create_offer_with`, and the same on `Endpoint`, build the peer from `config` instead of
   the server's closure; the ICE mode, candidates, peer limit and connect timeout stay the
   server's.

## Consequences

- akit's media server runs publishers in RTP mode and writes each packet to the viewers of its
  stream from the publisher's `on_rtp`, on the I/O thread that received it: per viewer a header
  rewrite, a copy into the history and an SRTP seal. A viewer's `on_keyframe_request` is passed to
  the publisher (`request_keyframe`), throttled by akit as fit does; `max_bitrate` becomes
  `set_receive_bitrate_cap` (akit keeps its two-second token bucket for what passes it anyway);
  `ice_timeout` becomes `set_ice_timeouts(min(8 s, ice_timeout), ice_timeout)` on each session's
  configuration.
- Header extensions akio-rtp does not parse (dependency descriptor, abs-capture-time, color space,
  video layers allocation) are not forwarded: they are dropped on receipt.
- Viewers' NACKs for packets the SFU never had (lost upstream and not yet repaired) go unanswered;
  the repaired packet fills the gap when it comes. A viewer's REMB or TWCC is not passed upstream.
- Cost: none on paths that do not use these calls. RTP mode builds an `ExtensionValues` (no
  allocation) and clones the RID per packet; a forwarded packet costs what a packetized one does,
  plus a binary search for a late one. DEV-PLAN section 4 names what a benchmark task should
  measure.
- Tests: akio-rtp `send_stream_written_with_chosen_sequence_numbers`; akio-webrtc's simulation
  (`rtc/tests_forward.rs`: two publishers into RTP-mode peers, one replacing the other, forwarded
  to a viewer with a tenth of the packets lost on each leg: every frame intact and in order, the
  SFU's retransmissions answering the viewer, the publisher's the SFU, PLI viewer -> SFU ->
  publisher, REMB once at once and every second about both streams; extensions by URI, gaps,
  late packets, switches and timestamps; renumbering past numbers taken; consent `Disconnected`
  then `Failed`, back before `Failed`, and no `Failed` without a longer failed timeout; REMB at
  once and every second, none before a cap or after `None`), and
  `tests/sfu.rs` over UDP (`Endpoint` publishers and viewers, an `RtcServer` answering each with
  the picked codecs: frames intact at both viewers, across a publisher replaced; PLI; REMB).
- Not done: forwarding to a simulcast line's other encodings (`write_rtp` writes the first);
  passing unknown header extensions through; a receive-side bandwidth estimate.
