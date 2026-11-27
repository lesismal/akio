# ADR-187: What an SFU needs of akio-webrtc: a receive cap, consent timeouts

English | [简体中文](187-webrtc-sfu.zh-CN.md)

Status: accepted (2026-11-27). akit's A261.

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

1. **`Peer::set_receive_bitrate_cap(Option<u64>)`** sends REMB (draft-alvestrand-rmcat-remb) with
   the cap about every media stream received (signalled ones before any arrived), once at once and
   then with every RTCP report (once a second). akio has no receive-side estimate (the remote
   estimates the path from transport-wide feedback), so the REMB carries the cap alone; libwebrtc
   takes it as the upper bound of its estimate. `None` stops sending; the last one stays in force
   at the remote, as it does in libwebrtc, so a cap is lifted with a higher one. A REMB received
   is now reported (`Other::RemoteBitrateEstimate { bitrate, ssrcs }` in `Event::Other`'s Debug).
2. **`RtcConfig::set_ice_timeouts(disconnected, failed)`**: consent silence for `disconnected`
   (at least 1 s) reports `Disconnected` (the agent's consent timeout; a full agent checks at
   least three times within it), and for `failed` the new `IceConnectionState::Failed`. Consent
   back before `failed` returns to `Connected`. With `failed` past `disconnected`, a server or
   endpoint that closes peers on loss of consent (`close_on_disconnect`, the default) closes them
   at `Failed`; otherwise (and without the setting) nothing changes: `Disconnected` at 30 s
   closes them. The `Failed` deadline is a timer about time, armed when `Disconnected` is reported.

## Consequences

- akit's media server caps each publisher with `set_receive_bitrate_cap(Some(max_bitrate))` (it
  keeps its two-second token bucket for what passes it anyway) and sets
  `set_ice_timeouts(min(8 s, ice_timeout), ice_timeout)` on each session's configuration (A259's
  `accept_offer_with`).
- Cost: none on paths that do not use these calls: one deadline in a peer's timer while consent is
  lost, one REMB a second with the reports of a capped peer, one event per REMB received.
- Tests: akio-webrtc's simulation (`rtc/tests_forward.rs`: consent `Disconnected` then `Failed`
  at the timeouts, back before `Failed`, and no `Failed` without a longer failed timeout; REMB at
  once and every second about both streams received, none before a cap or after `None`).
- Not done: a receive-side bandwidth estimate.
