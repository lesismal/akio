# ADR-042: SCTP HEARTBEATs, peer restart, zero checksum and incoming reset requests

English | [简体中文](042-sctp-heartbeat-restart-zero-checksum.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`only-sctp`, the data channel layer of the in-house WebRTC stack, answered HEARTBEATs but never
sent any, so an idle association neither measured its RTT nor noticed a peer that had gone away:
without data in flight no timer ran, and the association stayed "up" until DTLS or ICE gave up.
An INIT arriving on a live association was ignored, so a peer that restarted its SCTP stack
(RFC 9260 §5.2.2) could never get back in. Every packet carried a CRC-32C although DTLS already
authenticates it; RFC 9653 lets both ends agree to send a zero checksum instead, and dcSCTP
(Chrome) and pion/sctp implement it. RE-CONFIG requests other than Outgoing SSN Reset and the
add-streams ones (Incoming SSN Reset, SSN/TSN Reset, RFC 6525 §5.2.3-4) were refused. And the
stack had never been run against usrsctp, the SCTP of Firefox.

Multi-homing, AUTH (RFC 4895), ASCONF (RFC 5061) and ECN are not used by WebRTC, which runs
one association over one DTLS connection, so they stay out of scope.

## Decision

1. **HEARTBEATs** (RFC 9260 §8.3, `Config::heartbeat_interval`, default 30 s, `None` turns
   them off). Once established, an association with no DATA in flight for HB.interval + RTO
   sends a HEARTBEAT whose 12-byte Heartbeat Information is a sequence number and our tag; with
   data in flight T3-rtx watches the path and the timer just rearms. A matching HEARTBEAT ACK
   is an RTT measurement (SRTT / RTTVAR / RTO as for DATA, `Association::rtt`) and clears the
   error count. A HEARTBEAT unanswered within the RTO counts one error, doubles the RTO and is
   followed by the next HEARTBEAT at once; the error count is the one T3-rtx timeouts use, and
   past `max_retransmissions` the association fails (ABORT, `Closed`). With a single path,
   Path.Max.Retrans and Association.Max.Retrans are the same number: an idle association with a
   vanished peer fails 60-150 s after the last exchange (30 s + RTO, then about 70 s of
   backoff), as a busy one does through T3-rtx. No jitter is added to the interval: there is
   one destination, so HEARTBEATs of many paths cannot synchronise. HEARTBEATs are sent only in
   ESTABLISHED (the shutdown states have their own T2 timer).
2. **Peer restart** (RFC 9260 §5.2.2, §5.2.4). The state cookie now also carries the tag and
   initial TSN of the INIT ACK it was sent in and the Tie-Tags. An INIT on a live association is
   answered with an INIT ACK carrying a new tag and initial TSN (derived with HMAC from the
   cookie key and the INIT, so a retransmitted INIT gets the same ones), our current tags as
   Tie-Tags; nothing changes yet. A COOKIE ECHO is checked against the tag in its cookie (not
   our current one) and sorted by the §5.2.4 table: case A (both tags new, Tie-Tags match our
   current tags) is a restart: every channel gets `ChannelClose` (the peer lost them), queued
   and unacknowledged data is dropped, sender, receiver and RE-CONFIG state start over with the
   cookie's tags and TSNs, a COOKIE ACK goes out and `Event::Restarted` follows. Case D
   (duplicate) is answered with COOKIE ACK as before; case B on an established association and
   case C are discarded (our INIT collision handling keeps one tag per side, so the peer's tag
   cannot legitimately change). In SHUTDOWN-ACK-SENT a restart is refused with SHUTDOWN ACK and
   an ERROR "Cookie Received While Shutting Down"; in the other shutdown states the association
   is aborted (the peer's side of it is gone). `Event` becomes `#[non_exhaustive]`.
3. **Zero checksum** (RFC 9653, `Config::zero_checksum`, default on). INIT and INIT ACK carry
   Zero Checksum Acceptable (0x8001) with EDMID 1, "SCTP over DTLS"; while it is on, packets
   with a checksum field of 0 are accepted without computing the CRC (any other value must
   still be the right CRC-32C). When the peer announced EDMID 1 too
   (`Association::zero_checksum`), every packet sent on the established association has a zero
   checksum; INIT, INIT ACK and COOKIE ECHO, and packets with another verification tag, always
   carry the CRC. The flag rides in the state cookie with the others. `udp_peer` (plain UDP)
   turns it off unless asked.
4. **Incoming SSN Reset Request** (RFC 6525 §5.2.3): the peer asks us to reset our outgoing
   streams (all of them when the list is empty). Channels among them close as if
   `close_channel` had been called; streams without a channel are reset too. The answer is our
   Outgoing SSN Reset Request for them, sent once their queued messages have TSNs, with the
   request's sequence number as its Re-configuration Response Sequence Number; a retransmitted
   request resends it. Streams whose reset is already in flight or done need nothing; a request
   that needs nothing at all gets "Success - Nothing to do"; a second one while the first is
   pending gets "In progress".
5. **SSN/TSN Reset Request** (RFC 6525 §5.2.4): performed when none of our data is in flight
   and no message is half given TSNs ("In progress" until then, so no data is lost; the peer
   retries): the response carries the Sender's Next TSN (ours, unchanged) and the Receiver's
   Next TSN (our cumulative TSN + 1 + 2^31), the receiver starts over at the latter (as if a
   FORWARD TSN covered every stream, deferred incoming resets performed), and every SSN / MID
   restarts at 0 both ways. Retransmissions get the same response. We never send this request.
6. **Firefox / usrsctp interop** (`tools/interop/webrtc/firefox.sh`, new): headless Firefox
   driven over WebDriver BiDi (Firefox no longer speaks the DevTools Protocol) by a small Go
   program on gorilla/websocket. Both offer directions, which also puts usrsctp in both SCTP
   roles.

## Consequences

- Public API (only-sctp, Internal tier): `Config::{heartbeat_interval, zero_checksum}` with
  builders, `Association::{rtt, zero_checksum}`, `Event::Restarted`; `Event` is now
  `#[non_exhaustive]` (a match needs a wildcard arm; only-webrtc already had one). only-webrtc
  is unchanged and gets the new defaults; its `webrtc-interop` example takes
  `ONLY_INTEROP_BIND` for the client's local address.
- Cookies are 49 bytes instead of 37; cookies from before this change no longer verify (they
  live for one handshake).
- Tests: HEARTBEAT RTT on an idle link, failure of an idle association after its peer vanished
  (60-150 s), none without HEARTBEATs, HEARTBEATs over a link losing 15 % each way for 30
  minutes; zero checksum negotiation in all four combinations over a lossy link (zero only when
  both offer, CRC otherwise); peer restart with data queued on both sides, channels closed,
  stream ids reused, both directions and shutdown afterwards, on DATA and I-DATA; a stray INIT
  without a COOKIE ECHO changes nothing; Incoming SSN Reset answered by our Outgoing request
  (retransmission, channel closed on both sides, channel-less stream); SSN/TSN Reset in
  progress while data is in flight, then performed, data accepted at the new TSN with SSN 0
  and our SSNs restarted; a restart refused while shutting down; codecs for the new parameters
  and the zero checksum.
- Fuzzing: the `sctp_packet` associations accept zero checksums, so random bytes reach the
  parsers without a CRC fix-up; new seeds cover HEARTBEAT / HEARTBEAT ACK, a full peer restart
  and every RE-CONFIG request kind with b's answers (941 seeds). 11 minutes on gpu51, 1.51M
  runs, no crash.
- Interop: pion/sctp v1.12.0 over UDP with zero checksums offered on both sides, both roles,
  with and without loss (`tools/interop/sctp/run.sh`); Firefox 158 (usrsctp) both offer
  directions: ordered and unordered/unreliable echoes, 70 kB and 200 kB messages, an empty one,
  150 s idle (only-sctp's HEARTBEATs answered by usrsctp: unanswered ones would have failed the
  association by then), a channel closed by Firefox (stream reset both ways) and a new one on
  the reused id. Neither Firefox 158 nor Chrome 157 offers zero checksums (Chrome's dcSCTP
  implements them behind an experiment that is off by default), so in browsers the CRC-32C
  stays; headless Chrome 157 passes `browser.sh` unchanged. On Linux Firefox gathered no loopback
  candidates even with `media.peerconnection.ice.loopback`, so the script takes a LAN address
  (`IP=`).
- Performance: with zero checksums the CRC-32C is gone from both ends of the data path.
  Same-run A/B against 46f25f81 on gpu51 (`quiet.sh`, CPUs 2-9, 7 alternating rounds,
  medians), in-memory SCTP (`examples/sctp_bench.rs`, both sides only-sctp): 1 KiB messages
  1.21x (DATA 1.21x), 64 KiB 1.31x (1.24x), 16 KiB unordered 1.27x (1.24x), four channels
  1.25x (1.20x); data-channel throughput between two loopback `Endpoint`s, DTLS included,
  1.003x (189.6 vs 189.1 MB/s, DTLS dominates): no regression. Idle HEARTBEATs cost one
  packet each way per 30 s.
- Not done: multi-homing, AUTH, ASCONF, ECN (WebRTC uses none of them); sending Incoming or
  SSN/TSN Reset Requests; a cookie lifetime (cookies travel inside DTLS, so replays from
  outside are not possible).
