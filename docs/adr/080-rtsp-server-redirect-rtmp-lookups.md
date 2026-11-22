# ADR-080: The RTSP server's REDIRECT, the client following it; RTMP lookups on reconnect

English | [简体中文](080-rtsp-server-redirect-rtmp-lookups.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-084 left two things in only-media's RTSP and RTMP clients undone:

- **The server's `REDIRECT`.** RFC 2326 10.15 lets a server tell a client in a session to go
  elsewhere: a `REDIRECT` request with a `Location` and, optionally, a `Range` saying when.
  An operator who drains a server for maintenance, or sheds load to another one, has no other
  way to move live players and publishers in RTSP 1.0 than to cut them off. Our server could
  not send it, and our client answered it `501`. ADR-084 rejected it then because no server we
  test with sends one and moving a live session needs the reconnect machinery without its
  backoff.
- **RTMP lookups on reconnect.** The RTSP client looks its host name up again for every
  session since ADR-084; the RTMP client resolved the name once in `push` / `pull` and every
  reconnect dialed that address, so a server that came back elsewhere under the same name
  (a container rescheduled, DNS failover) was never found. Neither client tried a name's other
  addresses when the first one refused.

## Decision

1. **The server sends `REDIRECT`.** `RtspServer` keeps a list of its sessions: a connection
   joins it when its stream is set up (the first SETUP of a player, ANNOUNCE of a publisher)
   and leaves it at TEARDOWN or close. New public API:
   - `RtspServer::sessions() -> Vec<RtspSessionInfo>`: id (the `Session` header's), hub path,
     peer address, whether it records, whether it was redirected.
   - `RtspServer::redirect_session(id, &Redirect) -> bool` and
     `RtspServer::redirect_path(path, &Redirect) -> usize` (every session of the path,
     players and its publisher).
   - `Redirect { location, at: Option<SystemTime>, grace }` (`Redirect::new(location)`, `.at`,
     `.grace`; default grace 10 s): the request is
     `REDIRECT <session URL> RTSP/1.0` with the server's own `CSeq`, the `Session`, the
     `Location` and, with `at`, `Range: clock=YYYYMMDDThhmmss.fffZ-` (RFC 2326 3.7).
   - **Ending cleanly.** The session keeps playing or recording after the request: a client
     that follows tears it down when the move takes effect and sets up at the location, so a
     player can switch without a gap. When a redirected session's TEARDOWN is answered the
     server closes the connection after the answer. A client that does not follow (none of the
     third-party clients below does) is closed `grace` after the move takes effect (after `at`,
     else after the request), by a timer job that only closes the connection if the session is
     still listed and no later redirect replaced this one. The client's answer to the request
     is read and ignored.
   - Cost: a map insert and remove per session, under a lock the media path never takes.
   - Rejected: closing the connection right after the request (a client that follows needs the
     session until it set up the new one, RFC 2326 asks it to TEARDOWN); a per-session location
     template in `redirect_path` (callers that want one go through `sessions()` and
     `redirect_session`); keeping track of the client's answer (none of the clients we tried
     says anything useful in it: `501`, `200` or nothing, below).
2. **The client follows `REDIRECT`.** The sans-IO machine answers a server request
   `REDIRECT` in a live session with `200` and the session (`455` before it is live, `400`
   without a usable `Location`: an `rtsp://` URL or an absolute path, `454` when its `Session`
   is not ours) and emits a move: the location (credentials go along to the same server only,
   as for 3xx) and when, from the `Range` start: `clock=` a UTC time, `npt=` counted from the
   PLAY / RECORD answer, at once without or when it passed (a day at most). The session's timer
   (500 ms at most) ends the session when the time comes: TEARDOWN, connection closed. The
   client then starts a session at the location at once, on a thread of its own and without the
   backoff, on the `RtspClientConfig::reconnect` engine; it counts in `reconnects()`. If that
   session fails, the usual reconnects follow, from the client's URL (or a remembered `301`):
   the server that redirected may be a load balancer, and a crashed target should not keep the
   client away from it. A connection that closes after the `REDIRECT` but before its time moves
   too. Without `reconnect` (no engine to dial on, `pull` / `push` take `&Engine`) the client
   ends with the new `ClientError::Redirected(location)`, so the caller can start one there.
   - Rejected: honouring a `REDIRECT` before the session is live (the 3xx path covers the
     handshake; a request there is answered 455); making a redirect permanent for later
     reconnects.
3. **Lookups and address walks in the RTMP client.** `push` / `pull` resolve every address of
   the host (IP literals and `RtmpClientConfig::addr` as before). Each reconnect try looks the
   name up again, on a short-lived thread (the timer thread must not block); a failed lookup on
   a reconnect is retried like a refused connect (`ClientError::Resolve` is retryable now; the
   first lookup's failure still goes to the caller). Within a try, a refused or timed-out
   connect dials the next address of the list at once (a new connection generation, so a late
   answer of the previous one is ignored); the try fails when the list is exhausted. The walk
   needs an engine to dial on from the I/O and timer threads, the reconnect's, so without
   `reconnect` only the first address is dialed, as before. `RtmpClient::addr` is now the
   address dialed last. The RTSP client walks the addresses of each session the same way (it
   always has the caller's engine there), and both share one lookup (`reconnect::lookup`,
   crate-internal, with a test resolver for names under `.test`).

## Consequences

- Public API (additive, `api/only-media.txt`): `rtsp::Redirect`, `rtsp::RtspSessionInfo`,
  `RtspServer::{sessions, redirect_session, redirect_path}`, `ClientError::Redirected` (RTSP;
  `ClientError` is `#[non_exhaustive]`).
- Behaviour changes: the RTSP client follows a server's `REDIRECT` (or ends with `Redirected`)
  instead of answering 501; both clients dial a name's other addresses when the first does not
  connect; the RTMP client finds a server that moved, and a name that stops resolving no longer
  ends a reconnecting RTMP client; `RtmpClient::addr` can change across reconnects.
- Tests: `Range` times (`clock=` both ways across leap years, `npt=` forms, malformed ones);
  the machine's answers to `REDIRECT` (at once, a clock time ahead, an npt, a time passed;
  455, 400, 454); this crate's server moving a reconnecting pull and push to a second server
  over TCP and UDP (a push at its `Range` time and not before), the first server's list
  emptied, a client without reconnect ending with the location; a raw client that ignores
  the request closed after the grace, with the request it got checked; RTSP sessions walking
  a name's addresses past refused ones; an RTMP pull and push walking past a refused address,
  then a name that stops resolving (retried), then moves.
- Interop (`tools/interop/media/rtsp-server-redirect.sh`, gpu51, Docker): ffmpeg 6.1.1 (gpu51, playing and recording over TCP and UDP; 9.0.2 on macOS too, but for a UDP recording, not tried) answers our server's `REDIRECT` `501` and carries on; GStreamer 1.24.2 `rtspsrc` and `rtspclientsink` (TCP, UDP) answer `200` and carry on; mediamtx 1.15.3 pulling from our server (a path's `source`, TCP and UDP) does not answer, tears the session down at once and pulls the same URL again. None moves to the location; our server ended each of those sessions at its TEARDOWN or 4 s (the test's grace) after the request. Our client moved by our server to mediamtx: the pull keeps carrying media from it (310 to 335 packets in the check) and the push, moved at a `Range` time, is read back from mediamtx, over TCP and UDP. RTMP: on a Docker network the name `rtmpsrv` moves from mediamtx A (172.31.248.10, removed) to mediamtx B (.20) and our reconnecting push and pull, run in a container there, dial .20 (the pull reconnected 11 times while B's path waited for the push to come back). live555 (openRTSP) was not tried: Ubuntu 24.04 and Debian 12 no longer package it.
- Cost: BENCH
- Not done: RTSP 2.0's `PLAY_NOTIFY` and its redirect, RTSPS, HTTP tunnelling, multicast and
  seeking stay out of scope; the RTMP client walks the addresses only with `reconnect` set.
