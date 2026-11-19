# ADR-048: DTLS 1.3, cryptex, encrypted header extensions, Opus RED and FEC on simulcast lines in only-webrtc

[中文](048-webrtc-dtls13-cryptex-opus-red-simulcast-fec.zh-CN.md)

Status: accepted (2026-11-19)

## Context

The libraries had the pieces but `only-webrtc`'s peers did not use them: `only-dtls` speaks DTLS
1.3 (ADR-021, ADR-045) yet peers ran DTLS 1.2 only; `only-srtp` has cryptex (RFC 9335), RFC 6904
header extension encryption and MKIs (ADR-040) but nothing negotiated them; `only-rtp` has RED
(RFC 2198) and ULPFEC (ADR-036), wired for video on plain lines only (ADR-039), so audio had no
redundancy and simulcast lines no FEC.

What Chrome 157 does, found against it (`tools/interop/webrtc/browser.sh`, `fec.sh`, and offers
captured over DevTools):

- **DTLS 1.3** is on by default (no field trial): against a peer that offers DTLS 1.3 it
  negotiates it in either DTLS role (`RTCTransportStats.tlsVersion` `FEFC`,
  `TLS_AES_128_GCM_SHA256`), and DTLS 1.2 otherwise. Nothing in SDP changes.
- **Cryptex** is offered as a session-level `a=cryptex` when the page sets
  `RTCConfiguration.rtpHeaderEncryptionPolicy` ("negotiate" or "require"), which Chrome 157
  exposes only with `--enable-experimental-web-platform-features`. With "require" it rejects a
  description without cryptex. RFC 6904 (`urn:ietf:params:rtp-hdrext:encrypt`) is never offered
  or accepted: libwebrtc has the code but Chrome has no switch for it.
- **Opus RED**: Chrome offers `a=rtpmap:63 red/48000/2` with `a=fmtp:63 111/111` *after* Opus,
  and receives RED whenever it is negotiated. It *sends* RED only when the remote description
  lists `red` before Opus (libwebrtc takes the first non-RED codec as the send codec and uses a
  RED payload type only if it comes earlier); the redundant blocks are always the packets right
  before the primary one (it stops at the first that does not fit), one by default.
- **Simulcast** (RID-based, `a=simulcast`) carries `red` / `rtx` / `ulpfec` like any video line;
  Chrome sends ULPFEC in RED on each layer's own SSRC (with its RID). FlexFEC needs an
  `a=ssrc-group:FEC-FR` of signaled SSRCs, which RID-based simulcast does not have; Chrome does
  not send FlexFEC with simulcast. Chrome does not report received ULPFEC in
  `fecPacketsReceived` (only FlexFEC).
- **MKIs**: DTLS-SRTP carries an MKI only inside the DTLS `use_srtp` extension (RFC 5764 §4.1.1);
  SDP has no attribute for it (the MKI field of SDES `a=crypto` belongs to SDES, which WebRTC
  forbids, RFC 8827). libwebrtc never offers an MKI.

## Decision

1. **DTLS 1.3** (`RtcConfig::enable_dtls13(bool)`): peers offer DTLS 1.3 with DTLS 1.2 as the
   fallback (`only_dtls::Config::with_versions([Dtls13, Dtls12])` on the WebRTC profile): a
   client sends a DTLS 1.3 ClientHello that DTLS 1.2 servers answer with DTLS 1.2, a server
   takes DTLS 1.3 when offered. SRTP keys come from the DTLS 1.3 exporter as before; the RFC 7983
   demultiplexer already took DTLS 1.3's unified headers (first byte 32-63). **Default on**: it
   was opt-in until Chrome 157 (both DTLS roles, data channels, audio, video, AES-GCM SRTP),
   Firefox 158 and pion (DTLS 1.2: falls back in both roles) were checked; `enable_dtls13(false)`
   restores DTLS 1.2 only. The negotiated version is logged (debug) and reported in the
   statistics events.
2. **Cryptex** (`RtcConfig::enable_cryptex(bool)`, default off): offers a session-level
   `a=cryptex` (as Chrome) and answers one found at session or media level of an offer.
   Negotiated means both sides signaled it; then every sent packet with header extensions or
   CSRCs is encrypted with cryptex (`only_srtp::Context::with_cryptex`). The receiving context
   decrypts cryptex whenever this side offers or accepts it, so packets the remote sends right
   after its answer (before ours is applied) are not lost. Cryptex is a property of the BUNDLE
   transport (one SRTP context pair), re-applied after each negotiation.
3. **RFC 6904** (`RtcConfig::enable_encrypted_header_extensions(bool)`, default off): an offer
   also lists encrypted variants (`a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`) of the
   extensions that say most about the media or session, in this order: audio level, MID, RID,
   repaired RID, video orientation, playout delay, on the one-byte ids no line uses (five with
   our default maps; the two-byte form is not used because not every receiver takes it). An
   answer takes the encrypted variant of any extension offered both ways (RFC 6904 §4); without
   the option encrypted variants are ignored. The negotiated ids (union over the BUNDLE) go to
   both SRTP contexts (`with_encrypted_header_extensions`). With cryptex as well, cryptex wins on
   the wire.
4. **MKIs are not negotiated** in `only-webrtc`: there is no SDP mechanism for DTLS-SRTP MKIs,
   no browser uses them, and between two `only` peers DTLS already re-keys by a new handshake.
   `only-dtls` keeps `with_srtp_mki` for other DTLS-SRTP users.
5. **Opus RED** (`RtcConfig::enable_opus_red(Option<u8>)`, default `None`): with `Some(n)` an
   audio line offers or accepts `red/48000/2` (payload type 63, `fmtp 63 <opus>/<opus>`), listed
   *before* Opus so libwebrtc sends RED; a remote RED is accepted only when all its blocks are a
   negotiated Opus payload type. Receiving: a RED packet's redundant blocks stand in for the
   packets before it (the last block sequence number - 1, the one before - 2 ..., timestamps from
   the offsets; blocks out of order or of another payload type are skipped) and enter the receive
   stream as recovered packets (`RecvStream::receive_recovered`: a copy of a packet already
   received is dropped, receiver reports keep the loss before repair), then the primary block as
   the packet itself. Sending (`n` = 1 or 2; 0 sends plain Opus but still receives RED): each
   Opus payload goes in RED with up to `n` previous payloads, newest first and contiguous like
   libwebrtc, while the 14-bit timestamp offset and the MTU allow.
6. **FEC on simulcast lines**: with `FecMechanism::Ulpfec`, simulcast lines offer and accept
   `red` / `rtx` / `ulpfec` like other video lines, and each encoding has its own FEC state (an
   encoder on its SSRC, the smoothed loss of its receiver reports, the rate policy of ADR-039):
   media goes in RED, ULPFEC blocks follow on the encoding's SSRC with its RID. Received
   simulcast is repaired per SSRC as before (up to 8 decoders per peer, was 4). FlexFEC is not
   offered or accepted on simulcast lines (sent or received), for the reason above.
7. **Statistics**: the periodic statistics event adds the DTLS version, packets received with
   cryptex, and packets recovered from Opus RED.

## Consequences

- Additive public API: four `RtcConfig` methods. Behaviour change: peers offer DTLS 1.3 by
  default (SDP unchanged; DTLS 1.2 peers unaffected). Every other option is off by default, so a
  default peer's SDP is as before.
- Interop (`tools/interop/webrtc`): Chrome 157 DTLS 1.3 in both roles; cryptex both ways with
  Chrome's "require" policy, with DTLS 1.3 and AEAD-AES-128-GCM SRTP; Opus RED under 10 % loss
  each way: Chrome conceals 2-3 % of its samples instead of 20 % and the server takes 300-400
  packets from Chrome's RED; Chrome's three simulcast layers with its ULPFEC through 5 % loss
  (the server rebuilds packets of every layer); the SFU's simulcast line with our per-encoding
  ULPFEC through 5 % loss and no NACK: Chrome decodes 300 of 301 frames, without FEC the line
  does not decode at all; pion and Firefox 158 fall back to (or negotiate) the right version.
- Benchmarks (gpu51, same-run A/B, see the CHANGELOG): handshakes and media throughput of a
  default peer unchanged within noise; DTLS 1.3 handshakes cost a few percent more CPU than DTLS
  1.2 ones.
- Not done: RFC 6904 with a browser (none offers it); MKIs (above); FlexFEC on simulcast lines;
  RED for codecs other than Opus and for video RED without FEC; sending RED only when the remote
  lists RED first (we send it whenever configured and negotiated; every receiver must take it).
