# ADR-037: SCTP message interleaving (I-DATA) and stream schedulers

English | [简体中文](037-sctp-idata-schedulers.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`akio-sctp`, the data channel layer of the in-house WebRTC stack, sent messages first come,
first served in DATA chunks. A DATA message's fragments need consecutive TSNs, so once a large
message started, every other channel waited for its last fragment: a 256 KiB file transfer on one
channel held up a chat message on another for as long as the transfer took to leave the
congestion window. The channel priority sent in DATA_CHANNEL_OPEN was recorded and never used.

RFC 8260 fixes both. I-DATA chunks (type 0x40) carry a 32-bit message identifier (MID) per stream
and a fragment sequence number (FSN), so fragments of messages on different streams can be
interleaved; I-FORWARD-TSN (0xC2) names abandoned messages by stream and MID. Section 3 defines
stream schedulers. Both ends must list I-DATA in Supported Extensions, and once it is negotiated
DATA must not be used. Peers checked: pion/sctp v1.12.0 implements RFC 8260 and offers it by
default (weighted fair queueing); Chrome 157 (dcSCTP) implements it but offers it only with the
field trial `WebRTC-DataChannelMessageInterleaving`, so Chrome runs on DATA today.

## Decision

1. **Negotiation.** `Config::message_interleaving` (default `true`) lists I-DATA and
   I-FORWARD-TSN in our INIT / INIT ACK. I-DATA is used when both sides list I-DATA
   (`Association::message_interleaving` tells which); the peer's offer is carried in the state
   cookie (a bit next to the FORWARD TSN flag, so older cookies still decode). Otherwise DATA and
   FORWARD TSN as before. A DATA chunk on an I-DATA association, or I-DATA on a DATA one, aborts
   with "protocol violation" (RFC 8260 §2.2.3); a FORWARD TSN of the kind not in use is ignored.
2. **Sending.** Messages queue per stream and are fragmented when each fragment gets its TSN
   (DATA payloads keep their size; I-DATA fragments are 4 bytes smaller), as slices of one shared
   buffer per message. MIDs count separately for ordered and unordered messages of a stream and
   restart at 0 with an outgoing stream reset. A partially reliable message abandoned while part of
   it was still unsent still takes one never-sent TSN for its last fragment, with I-DATA as with
   DATA: otherwise, when every fragment that was sent arrived, the peer's cumulative TSN would pass
   the message before any forward chunk said to skip it, and an ordered stream would stay blocked
   on a message that can never complete (found by the lossy link tests). The I-FORWARD-TSN lists
   the highest skipped MID per ordered stream and every skipped unordered message. With I-DATA
   the receiver must hold every started message whole until it completes, so the sender starts
   a new message only while the started-but-unfinished ones plus it fit in half the peer's
   initial window, and otherwise serves the started ones first: without that, enough large
   messages on enough channels (8 x 250 kB) filled the peer's window with partial messages none
   of which could complete, and the association stalled until it failed (found in review;
   `many_concurrent_large_messages`).
3. **Receiving.** I-DATA fragments are reassembled per (stream, U, MID) by FSN, ordered messages
   delivered by MID with 32-bit serial arithmetic. An I-FORWARD-TSN advances the cumulative TSN,
   drops ordered partial messages up to the MID and delivers what was waiting, and drops the named
   unordered message. Unlike FORWARD TSN it does not drop fragments by TSN: with interleaving,
   fragments below the new cumulative TSN may belong to messages still in progress. The memory
   caps, duplicate and window handling are those of DATA; a fragment with FSN 0 but no B bit is
   dropped (and acknowledged); an oversized message aborts as before, checked as fragments arrive.
   Fragments that continue a started message are taken up to the larger of the two memory caps
   (as the next in-sequence TSN is), so started messages can complete even when a peer
   interleaves more than we would. Partial messages are kept ordered by (stream, U, MID), so an
   I-FORWARD-TSN entry drops its range without scanning the others.
4. **Schedulers** (`Config::scheduler`, `Scheduler`, RFC 8260 §3): first come first served, round
   robin, round robin per packet, priority, fair capacity and weighted fair queueing (default).
   The unit served is a chunk with I-DATA and a whole message with DATA (a started DATA message
   always goes out whole). Retransmissions go first regardless. Weighted fair queueing uses start
   tags: a stream's virtual finish time grows by bytes / weight and a stream that was idle starts
   at the current virtual time, so it banks no credit.
5. **Priorities** are the data channel priorities of RFC 8832 (higher is more important; WebRTC
   uses 128, 256, 512, 1024) rather than RFC 8260's socket option values: a channel's
   `ChannelOptions::priority` (new `with_priority`), the peer's DATA_CHANNEL_OPEN value for
   channels it opened, or `Association::set_channel_priority` at any time. They are the weights of
   weighted fair queueing and the order of the priority scheduler. 0, which pion sends when no
   priority is set, schedules as 256.
6. **Defaults.** I-DATA on and weighted fair queueing, as pion does: with the default priority the
   channels share the association equally, and with interleaving a small message overtakes a large
   one in the next packet. Applications keep first come, first served with
   `Scheduler::FirstComeFirstServed` and DATA with `message_interleaving: false`.

## Consequences

- Public API (akio-sctp, Internal tier, additive): `Config::{message_interleaving, scheduler}`
  with builders, `Scheduler` (`#[non_exhaustive]`), `ChannelOptions::with_priority`,
  `Association::{set_channel_priority, message_interleaving}`. akio-webrtc is unchanged and gets
  the new defaults.
- Head-of-line blocking: a 200 kB message queued before a 4-byte one on another channel, on a
  20 ms simulated link: with I-DATA and any interleaving scheduler the small one arrives in
  the first round trip, well before the large one; with first come first served, or without
  I-DATA, after it (`head_of_line_blocking`).
- Performance: the per-stream queues, one shared buffer per message, the single-chunk receive
  path and in-order I-DATA appends make the SCTP layer faster than before, I-DATA's 4 extra
  header bytes per chunk notwithstanding. Same-run A/B against 59d41cc2 on gpu51 (`quiet.sh`, CPUs 2-9, 7 alternating rounds, medians): in-memory SCTP (`examples/sctp_bench.rs`) 1 KiB messages 1.19x (DATA fallback 1.21x), 64 KiB 1.33x (1.14x), 16 KiB unordered 1.12x (1.08x), four channels 1.20x (1.07x); data-channel throughput between two loopback `Endpoint`s, DTLS included, 0.986x (189.0 vs 191.7 MB/s; 1.009x in an earlier run, rounds vary by ±5%): no regression.
- Tests: codec round trips, interleaved and out-of-order reassembly across the TSN wrap,
  I-FORWARD-TSN by MID, negotiation in every combination and from either side, head-of-line
  blocking, scheduler shares (equal, 3:1 weighted, strict priority, FCFS order, one stream per
  packet), priorities changed at runtime, partial reliability with interleaved reliable and
  partially reliable channels over a lossy, reordering link; the link suite runs DATA and I-DATA
  on alternate seeds. The fuzz target `sctp_packet` drives an I-DATA pair and a DATA pair, with
  I-DATA, I-FORWARD-TSN and mismatched chunks in its seeds.
- Interop: pion/sctp v1.12.0 over UDP (`tools/interop/sctp/run.sh`, new: both roles, pion's
  interleaving on and off, with and without loss); akio-webrtc with pion WebRTC (I-DATA
  negotiated on every association) and headless Chrome 157 both offer directions (DATA by
  default; I-DATA with the field trial forced on also passes).
- Not done: usrsctp (Firefox) interop, not checked; per-stream scheduler parameters beyond the
  priority; exposing priorities or the scheduler in akio-webrtc's API (channels use the default
  priority there).
