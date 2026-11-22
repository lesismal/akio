# ADR-084: RTSP receiver reports, client redirects, lookups on reconnect; HLS keyframe requests

English | [简体中文](084-rtsp-receiver-reports-redirects-lookups.zh-CN.md)

Status: accepted (2026-11-22)

## Context

After ADR-075 the RTSP chapter of the book still listed, among what is not supported:

- **RTCP receiver reports to recorders.** A RECORD session read the publisher's sender reports
  (ADR-075) but sent nothing back. RFC 3550 6.4 has every receiver report what it receives;
  publishers use the reports for their statistics and rate control (GStreamer's `rtpbin`
  exposes them, some cameras and encoders adapt to the losses), and a UDP publisher behind a
  NAT gets no packet back that keeps the binding open. The client's pull sent only an empty
  receiver report (no report block) to each UDP RTCP port with every keep-alive.
- **Client redirects.** A `3xx` response failed the client with `ClientError::Status`.
  mediamtx answers a path configured as `source: redirect` with `302`, load balancers and
  camera managers send `301` / `302` to the server that has the stream.
- **Re-resolving the host name on reconnect.** The client resolved the URL's host once, when
  `pull` / `push` was called, and every reconnect dialed that address again. A server that
  comes back at another address under the same name (a container rescheduled, DNS failover)
  was never found.

The previous media session also reported that `tools/interop/media/browser.sh` failed on
main at its AV1 multivariant step: the multivariant playlist answered `503 no rendition is
ready`.

## Decision

1. **Receiver reports from the `Recorder`.** The ingest shared by the server's RECORD
   sessions and the client's pull keeps, per media, what RFC 3550 appendix A counts
   (`rtp::Reception`, crate-internal): the source's SSRC, the extended highest sequence number
   (cycles counted, a jump of 3000 or more ignored unless the next packet follows it, which
   restarts the count, as A.1's probation does; late and duplicate packets counted), the
   packets expected and received at the previous report (for the fraction lost), the
   interarrival jitter (A.8, integer form, arrival times on the track's RTP clock), and the
   middle 32 bits of the last sender report's NTP time with its arrival (LSR / DLSR). A new
   SSRC restarts the counts. Each media's report goes in a compound packet, the RR (one
   report block) followed by an SDES with a CNAME (`only-media-<16 hex digits>`, random per
   session), as RFC 3550 6.1 asks of every compound packet.
   - **Server**: `RtspConfig::receiver_report_interval` (new public field, default 5 s,
     RFC 3550's minimum interval; `Duration::ZERO` sends none). Reports are due per media,
     the first half an interval after its first packet, then every interval; they are
     produced on the packet path (no timer per session) and sent right after the packet
     that made one due: on the track's interleaved RTCP channel, or from the server's RTCP
     socket to the publisher's RTCP port (UDP routes now remember it). A publisher that
     stops sending stops getting reports, as RFC 3550 wants for sources not heard from.
   - **Client**: `RtspClientConfig::receiver_report_interval` (new public field, same
     default). The session's timer (every 500 ms at most) sends the reports due on the
     track's RTCP channel or from its RTCP socket to the server's RTCP port, with the SSRC
     the client already used for its empty reports. With zero, the empty reports with the
     keep-alives stay as before.
   - Cost: per RTP packet, a header read and a sequence number and jitter update; the arrival
     time is read from the clock once per read (TCP) or datagram (UDP) that brings RTP, since
     what one read brought arrived together (below); nothing when the interval is zero.
   - Rejected: a timer per RECORD session (a timer and a weak handle per session for what the
     packet path already sees); sending reports for sources that stopped (RFC 3550 6.4 skips
     them); reports in the server's players (players report to us, not the other way).
2. **Redirects in the client.** The sans-IO machine turns a `300` to `303`, `307` or `308`
   with a `Location` answering any request before the session is live into a redirect event
   (`304` and `305 Use Proxy`, whose location is a proxy, are refusals as before). The
   session ends (with a TEARDOWN only when a SETUP already got a session) and the client starts the handshake again at the location: an `rtsp://` URL, or an
   absolute path on the same server. At most five redirects in a row; the sixth fails with
   its `ClientError::Status` (a loop ends there too). The URL's credentials go to the same
   host and port only, unless the location carries its own (as browsers and ADR-010's HTTP
   client do across origins). `RtspClientConfig::addr` pins the client's own URL, not a
   redirect's other server. A `301 Moved Permanently` is kept for the client's later
   sessions (reconnects start there); `302` / `303` / `307` are followed again from the
   client's URL each time, since the server that redirects may balance load. Redirected
   sessions do not count as reconnects and do not go through the backoff. A pull's hub path
   stays reserved throughout. No public API change beyond what the docs promise: the error
   of a refused redirect is the `Status` it was before.
   - Rejected: the `REDIRECT` request a server may send during a session (RFC 2326 10.15);
     no server we test with sends it, and moving a live session needs the reconnect
     machinery without its backoff. It stays answered `501`.
3. **Lookups on every session.** The client keeps its URL instead of an address and looks the
   host up again for every session: each reconnect try (on its short-lived thread, which
   already blocks on the handshake) and each redirect. The first session uses the address
   `pull` / `push` resolved (also for the hub's `PeerInfo`), so nothing is looked up twice.
   A lookup that fails on a reconnect is retryable like a refused connect (the name may come
   back); the first session's failure still goes to the caller. IP literals and
   `RtspClientConfig::addr` skip the lookup. The RTMP client keeps dialing its first address
   (the `Reconnect` documentation now says which does what).
4. **HLS asks for keyframes.** The browser failure was in only-media: Chrome's WebRTC AV1
   encoder sends keyframes on request only (a PLI), so after the first one a WHIP stream had
   no keyframe to cut an HLS segment at, no rendition had a finished segment and the
   multivariant playlist never got its bandwidths. The HLS muxer now asks the publisher for
   a keyframe (`Subscription::request_keyframe`, which a WebRTC ingest turns into a PLI;
   the hub throttles requests per stream) when the segment being written passes
   `target_duration` without one, at most once per target of media time. Publishers without
   a keyframe hook (RTMP, RTSP, SRT) are unaffected. The script was right.

## Consequences

- Public API (additive, `api/only-media.txt`): `RtspConfig::receiver_report_interval`,
  `RtspClientConfig::receiver_report_interval` (and the re-export of the latter).
- Behaviour changes: RECORD sessions and pulls send receiver reports by default (5 s); a
  `3xx` with a `Location` is followed instead of failing the client; a reconnecting RTSP
  client finds a server whose name moved, and a name that stops resolving no longer ends a
  reconnecting client; HLS asks WebRTC publishers for a keyframe when a segment runs long.
- Tests: `rtp::Reception` (losses and the fraction since the last block, a sequence wrap,
  duplicates, a lone jump ignored and a second one restarting, a new SSRC, jitter of a late
  packet, LSR / DLSR) and the compound packet; RECORD sessions over TCP and UDP whose reports
  a raw client reads back (losses across a wrap, the LSR of its sender report, the CNAME, none
  with the interval zero); pulls from a scripted server over TCP and UDP whose reports it
  collects; the machine's redirect events (`305` and a location-less `3xx` refused);
  redirect URLs and credentials; pull and push redirected twice to this crate's server, a
  loop ended after five, a `301` remembered across a reconnect; a name (a test resolver hook)
  that stops resolving, then moves to another forwarder: pull and push reconnect there; an
  HLS segment past the target asking a keyframe hook. Passing on macOS and on gpu51 with epoll
  and `ONLY_TEST_BACKEND=uring`; clippy clean.
- Interop (`tools/interop/media/rtsp-redirect.sh`, gpu51, Docker):
  mediamtx 1.15.3 on the host network: a pull of the path `moved`
  (`source: redirect`) follows its `302` to `rsrc` over TCP and UDP and carries both tracks;
  pushes and pulls over UDP held for 75 s, past mediamtx's 60 s session timeout, stay up on the
  pull's receiver reports alone (57 -> 4942 and 94 -> 3355 packets; ffprobe reads both pushes).
  GStreamer 1.24.2 `rtspclientsink` recording over UDP: its RTP session parses every report
  (8 in 7 s at a 1 s interval; the block about its SSRC, 0 lost, the LSR of its sender report
  echoed with the DLSR); over TCP the 8 reports reach it, but rtspclientsink drops interleaved
  data in RECORD mode ("ignoring data message") before its RTP session sees them. On a Docker
  network, the name `rtspsrv` moves from mediamtx A (172.31.249.10, removed) to mediamtx B
  (.20): our reconnecting push and pull, run in a container on that network, reconnect once
  each and carry media from B, over TCP and over UDP; the same test against main's client times
  out (it keeps dialing .10). ffmpeg 9.0.2 (macOS) and 6.1.1 (gpu51) still publish to the
  server over TCP and UDP with the reports going back (`tests/rtsp_interop.rs`).
- `tools/interop/media/browser.sh` passes again (Chrome 157 headless, macOS): hls.js plays
  the AV1 ladder and switches renditions; Chrome's own player played it too in that run
  (informational).
- Cost: Same-run A/B against main on gpu51 (`quiet.sh`, one pinned core, alternating rounds, medians, head / base): RTSP pull 1.024, RTSP RECORD ingest 1.087, RTMP pull 0.998 (`tests/client_bench.rs`, 9 rounds); `bench_segmenting` (7 rounds) MPEG-TS 0.981, MPEG-TS LL-HLS 0.995, fMP4 1.015, fMP4 LL-HLS 1.013, AES-128 0.998 to 1.001, SAMPLE-AES MPEG-TS 1.002, `cbcs` 1.004 (the keyframe request is one comparison per packet once a segment passes the target). The RECORD cost (+18 ns per RTP packet) is the receiver reports' arrival time: the clock is read once per read that brings an RTP packet, and the benchmark reads 255 bytes at a time, about one read per packet; larger reads share one clock read across their packets, and `receiver_report_interval` zero skips it. A first version that read the clock per packet and converted with a u128 division cost 1.113 (pull) and 1.104 (RECORD).
- Not done: the server's `REDIRECT` request (above); RTSP 2.0, RTSPS and HTTP tunnelling,
  multicast and seeking stay out of scope; extended reports (RFC 3611) and reports in the
  server's players; the RTMP client still dials its first address on reconnect.
