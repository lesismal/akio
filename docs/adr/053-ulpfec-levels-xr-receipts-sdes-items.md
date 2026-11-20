# ADR-053: ULPFEC protection levels, XR blocks from received packets, typed SDES items

English | [简体中文](053-ulpfec-levels-xr-receipts-sdes-items.zh-CN.md)

Status: accepted (2026-11-20)

## Context

The only-rtp README listed three gaps left by ADR-036:

- **ULPFEC level 1.** `fec` wrote and read ULPFEC with one protection level whose length is the
  longest protected packet. RFC 5109 §5 / §7.4 lets a FEC packet carry several levels: level 0
  protects the first L0 bytes after the fixed header of its packets (plus their header fields),
  level 1 the next L1 bytes of a possibly different set, and so on (Uneven Level Protection).
  The parser ignored everything after the level-0 payload; a packet longer than the protection
  length could not be rebuilt at all.
- **Generating XR blocks.** Every RFC 3611 block parsed and wrote, but nothing produced the loss
  RLE (§4.1), duplicate RLE (§4.2) or packet receipt times (§4.3) blocks from what a receiver
  saw, and VoIP metrics (§4.7) only had the loss / burst / gap fields from `BurstLossModel`.
- **SDES beyond type / text pairs.** `Rtcp::SourceDescription` holds `(item type, String)`
  pairs. PRIV (RFC 3550 §6.5.8) is a prefix length octet, a prefix and a value; a prefix
  length above 127 is not UTF-8 and was replaced by U+FFFD on parsing. Writing cut texts at
  255 bytes, possibly inside a character.

Constraints: only-webrtc constructs `Rtcp::SourceDescription(Vec<(u32, Vec<(u8, String)>)>)`
and parses FEC headers, and another session is editing it, so the variant's type stays and
only-webrtc is not touched. libwebrtc, Chrome and pion use neither ULPFEC levels nor RLE /
receipt-time blocks, so the byte-level references are the RFC examples and pion/rtcp's block
writer.

## Decision

1. **ULPFEC levels, any number, in `fec`.**
   - `FecHeader` gains `ulp_levels: Vec<UlpLevel>` (offsets, protection length and where the
     level's payload starts); the parser reads level headers while bytes remain after the
     level-0 payload (a protection length past the payload still means one level, as before)
     and rejects a truncated level, a payload past the end or an empty mask. The L bit covers
     every level; `FecHeader::write_level(i)` writes a level header.
   - `FecEncoder::encode_ulp(media, fec)` builds packets from explicit levels
     (`UlpLevelSpec { mask, protection_len }` per level, level 0 first) and checks the rules of
     §7.4: a packet at most once per level above 0, at level 0 more than once only with equal
     protection lengths, and at level p only if it is at level p - 1 somewhere. Header fields
     come from the level-0 packets (§8.1; RFC 5109's §10.2 figures show M = 0, erratum 3461
     confirms the text). SN base stays the group's lowest sequence number, as before and as
     libwebrtc does.
   - `FecEncoder::set_ulp_level0(Some(l0))` is a ready-made scheme: the interleaved FEC packets
     of a group protect the first `l0` bytes of each packet (and the headers), and the last one
     also carries a level 1 over the whole group for the rest. A single loss per group comes
     back whole, several come back with their start (CSRCs, extensions, payload descriptors);
     repair bytes drop from `m * longest` to about `m * l0 + longest - l0`. Default `None`:
     whole-packet protection exactly as before. Only for receivers that implement levels:
     libwebrtc's ULPFEC reader takes level 0 alone, so toward Chrome a lost packet longer than
     `l0` would be rebuilt wrong; only-webrtc keeps whole-packet ULPFEC.
   - The decoder rebuilds packets piecewise: each received or rebuilt packet has a known
     header (or not) and known byte ranges; a level whose packets are all known over its range
     but one rebuilds that range (level 0 also the header and length), in any order — a level-1
     range can be rebuilt before the header is known. A packet is returned once complete;
     `FecDecoder::partially_recovered()` counts the others. Single-level FEC (libwebrtc's ULPFEC,
     both FlexFECs) goes through the same path with one range covering everything.
2. **XR blocks from received packets.** `ReceiptLog` (one source) records each packet's first
   receipt time and duplicates over an interval of at most 65533 sequence numbers (§4.1 forbids
   65534 or more), unwrapping sequence numbers as Appendix A.1 requires (within 32768 of the
   last, a tie without rollover). It produces the loss RLE (1 = received), duplicate RLE (0 =
   duplicated, as §4.2 defines it) and receipt times blocks for any thinning; receipt times are
   in the RTP clock anchored at the first packet's timestamp (§4.3 asks for comparable units),
   one block per run of received reported sequence numbers (a receipt-times block must not
   cover a loss). `RleReport::encode` uses a run chunk for runs of 15 or more or the tail of the
   trace, bit vectors otherwise: exactly the second encodings of the §4.1 examples.
   `RleReport::decode` / `reported_seqs` read chunks back. `RecvStream::enable_receipt_log`
   feeds a log from `receive` (FEC-rebuilt packets stay lost, as in receiver reports) and
   `receipt_blocks` returns the selected blocks and starts the next interval.
3. **Complete VoIP metrics.** `BurstLossModel::report(ssrc, packet_ms, &VoipQuality)` adds the
   fields only the application knows: round trip and end system delay, signal / noise level,
   RERL, R factors and MOS (out-of-range values sent as 127, as §4.7.5 requires), PLC and the
   jitter buffer (receiver configuration byte, nominal / maximum / absolute maximum). The
   crate computes none of the quality scores (G.107's E-model needs codec impairment factors
   the RTP layer does not have); `pcm_level_dbm0` measures a level from 16-bit PCM (full-scale
   sine = +3.14 dBm0).
4. **Typed SDES items without changing the variant.** `SdesItem` (`Text { item_type, text }`,
   `Priv { prefix, value }`) converts from / to the pairs, with constants for every registered
   type (CNAME .. MID, IANA registry: H323-CADDR, APSI RFC 6776, RGRP RFC 8861, RtpStreamId /
   RepairedRtpStreamId RFC 8852, CCID RFC 8849, MID RFC 9143). In the pair form PRIV's prefix
   length is the first `char` (U+0000..=U+00FF, one octet on the wire), so lengths up to 255
   survive; for lengths below 128 the text is byte-for-byte what it was before. Texts (and BYE
   reasons) are cut to 255 bytes at a character boundary. `random_cname` gives RFC 7022's
   short-term persistent CNAME (96 random bits in base64). RFC 6051 (rapid synchronisation)
   defines a header extension and a feedback message, not SDES items, and is not part of this.

## Consequences

- Tests (`crates/only-rtp/src/tests_levels.rs`): the RFC 5109 §10.2 example byte for byte
  (with erratum 3461), recovery of each single loss (B and C whole, A and D up to L0 + L1),
  level 1 arriving before level 0, two losses (starts only, the rest after a late arrival);
  the level rules; long masks and malformed levels; the level-0 mode on a lossy link (400
  frames of 2..12 packets, 10 % loss: every single loss recovered, every packet returned equals
  the original, fewer repair bytes than whole-packet FEC for L0 = 0, 40, 100). RFC 3611 §4.1
  examples (45 packets, two or three losses, T = 0 and T = 2) from a fed log; pion/rtcp
  v1.2.20 bytes of loss / duplicate RLE and receipt times blocks; 300 random traces round
  trip through encode / decode with thinning and wraparound; receipt logs across the 16-bit
  wrap with duplicates, capacity, intervals and the tie rule; `RecvStream` integration. VoIP
  report fields and `pcm_level_dbm0`. pion/rtcp v1.2.20 bytes of SDES with PRIV, MID and
  RtpStreamId; a 200-octet PRIV prefix; truncation; RFC 7022 vectors.
- pion's RLE writer omits the null chunk an odd chunk count needs (its block length is then
  one word short); the pion vectors use even counts, and the odd case is checked against
  RFC 3611's text.
- Fuzzing: `rtp_rtcp` converts every parsed SDES pair to an item and back, re-encodes every
  parsed RLE block's trace, builds VoIP reports from parsed blocks and feeds a receipt log from
  the RTP payload (its blocks write, parse back and never report an unreceived packet as
  received); `rtp_fec` rewrites parsed ULPFEC levels, runs the encoder in the level-0 mode, and
  encodes explicit two-level packets whose single loss must come back exactly. 16 minutes per
  target on gpu51: `rtp_rtcp` 2.90 M runs, `rtp_fec` 1.59 M runs, no finding in the code
  (an earlier run caught a too-strict check in the target, kept as a regression input).
- API, additive except `FecHeader`'s new field (only-rtp is internal tier; struct literals add
  `ulp_levels: Vec::new()`): `fec::{UlpLevel, UlpLevelSpec}`, `FecHeader::write_level`,
  `FecEncoder::{set_ulp_level0, encode_ulp}`, `FecDecoder::partially_recovered`,
  `ReceiptLog`, `MAX_XR_SPAN`, `RleReport::{encode, decode, reported_seqs}`,
  `RecvStream::{enable_receipt_log, receipt_log, receipt_blocks}`, `VoipQuality`, `Plc`,
  `JitterBufferConfig`, `BurstLossModel::report`, `pcm_level_dbm0`, `SdesItem`,
  `random_cname`. Changed behaviour: parsed PRIV items with a prefix length above 127 keep it
  (as U+0080..U+00FF) instead of U+FFFD; written texts are cut at a character boundary.
- Not done: wiring into only-webrtc (sending `ReceiptLog` blocks or VoIP metrics in its XR,
  using `set_ulp_level0` on audio / video lines, a random CNAME from `random_cname`) — left for
  a follow-up because another session owns only-webrtc. Partial packets are not handed out (a
  depacketizer would need to accept a truncated payload). No R factor / MOS estimation.
