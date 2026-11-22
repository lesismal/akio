# ADR-052: AES-f8 and SEED in SRTP, SEED in akio-crypto

English | [简体中文](052-srtp-f8-seed.zh-CN.md)

Status: accepted (2026-11-20)

## Context

After ADR-040, the `akio-srtp` README still listed two transforms as not implemented:

- **AES-f8** (RFC 3711 §4.1.2), the optional RFC 3711 cipher from 3GPP (UMTS f8): an OFB variant
  whose IV is masked under a second key. SDP security descriptions name it
  `F8_128_HMAC_SHA1_80` (RFC 4568 §6.2.3; the RFC 4568 grammar also lists
  `F8_128_HMAC_SHA1_32`).
- **SEED** (RFC 5669), the Korean national block cipher (RFC 4269) in three suites:
  `SEED_CTR_128_HMAC_SHA1_80` (mandatory to implement), `SEED_128_CCM_80` and `SEED_128_GCM_96`,
  with keys derived by a SEED-CTR PRF.

Neither has a DTLS-SRTP protection profile id, so WebRTC never negotiates them; they matter to
SDES-keyed SIP/VoIP peers (SEED in Korean deployments). `akio-crypto` had no SEED and no CCM.
libsrtp, our usual cross-check reference, implements neither.

## Decision

1. **SEED in `akio-crypto`** (`akio_crypto::seed`): `Seed` (RFC 4269; `new`, `from_slice`,
   `encrypt_block`/`decrypt_block`, `encrypt_blocks`/`decrypt_blocks`, `apply_ctr` with a
   128-bit counter), `SeedGcm` (SP 800-38D: 96-bit nonces, 16-byte tags or truncated to 15-12, 8
   or 4 bytes; the portable constant-time GHASH of `gcm`; the tag is checked before anything is
   decrypted) and `SeedCcm` (RFC 3610: 7- to 13-byte nonces, even tags of 4 to 16 bytes; the
   output is zeroed when the tag does not verify). The CCM construction is generic inside the
   crate and also checked with AES against RFC 3610.

   **Constant time, no tables.** SEED's S-boxes are `S0(x) = A0·x²⁴⁷ ⊕ 0xA9` and
   `S1(x) = A1·x²⁵¹ ⊕ 0x38` in GF(2⁸) modulo x⁸+x⁶+x⁵+x+1, and `x²⁴⁷ = (x⁻¹)⁸`,
   `x²⁵¹ = (x⁻¹)⁴` are linear in `x⁻¹`: an inversion followed by an affine map, like AES's. The
   inversion is the Boyar-Peralta circuit the fixsliced AES already has (`aes::fixslice::sub_bytes`
   without its NOTs, `M·y⁻¹` in AES's field), behind the field isomorphism that sends x to 0x19,
   with three derived linear maps around it (68 XORs, chosen among the eight isomorphisms) that
   the tests check against the RFC 4269 tables for every input. The G function runs bitsliced on
   sixteen 32-bit words at once (eight 64-bit bit planes, 64 byte lanes, a three-step swapmove
   transpose in and out; G's permutation layer and the modular additions stay on words), so CTR,
   GCM and ECB keep sixteen blocks in flight and the key schedule's 32 G calls (independent of
   each other) take two passes. A single block (CCM's CBC-MAC, `encrypt_block`) uses a one-word G
   with an 8×8 in-register transpose: 2.4 times faster than a sixteen-lane pass. There is no
   SEED instruction, so this is the only path. Rejected: the RFC's SS tables (4 KiB of
   secret-indexed loads), full table scans per lookup, a generic GF(2⁸) exponentiation (about
   three times the gates of the Boyar-Peralta circuit).

2. **Profiles.** `Profile` gains `AesF8HmacSha1_80`, `AesF8HmacSha1_32`, `SeedCtrHmacSha1_80`,
   `SeedCcm80` and `SeedGcm96` (SDES names `F8_128_HMAC_SHA1_80/32`,
   `SEED_CTR_128_HMAC_SHA1_80`, `SEED_128_CCM_80`, `SEED_128_GCM_96`; no DTLS-SRTP id;
   `Profile::ALL` lists fifteen, the new ones after AES-192-CM). All have 16-byte master keys and
   14-byte master salts. Tags: f8 10 or 4 bytes (SRTCP 10), SEED-CTR 10, SEED-CCM 10 and SEED-GCM
   12 (SRTP and SRTCP). `is_aead` is now true for SEED-CCM and SEED-GCM too; new
   `session_salt_len` (12 for every AEAD profile, 14 otherwise).

   *The SEED AEAD master salt.* RFC 5669 §3 only says the 12-octet session salt comes from the
   key derivation. It does not shorten the master salt, so it stays at RFC 3711's default
   112 bits (the 96-bit master salt of AES-GCM is RFC 7714's own choice); the PRF output for
   label 2 / 5 is truncated to 12 bytes. Another implementation reading RFC 5669 the RFC 7714 way
   would need a 12-byte master salt; there is none to compare with.

3. **AES-f8** (RFC 3711 §4.1.2). IV `0x00 || M || PT || SEQ || TS || SSRC || ROC` for SRTP (the
   first twelve header bytes with byte 0 cleared, then the ROC), `0⁴ || E || index || first 8
   bytes` for SRTCP; `m = k_s || 0x55…`, `IV' = E(k_e ⊕ m, IV)`,
   `S(j) = E(k_e, IV' ⊕ j ⊕ S(j-1))`. Each block depends on the previous one, so f8 runs one
   block at a time (AES instructions; the portable fixsliced AES pays four blocks per block). The
   PRF is AES-CM (RFC 3711 §4.3.3). Cryptex encrypts the same portion as with AES-CM; its IV only
   reads fixed-header bytes 1-11, which cryptex does not change. RFC 6904 uses f8 with the header
   key and salt and the packet's IV (RFC 6904 §3.2); the keystream is generated forward across
   the selected elements (`F8Stream`), never re-run per element.

4. **SEED in SRTP** (RFC 5669). The SEED-CTR PRF (§4: AES-CM's construction with SEED) for all
   three suites. SEED-CTR is AES-CM with SEED. SEED-CCM and SEED-GCM use RFC 5669 §3's nonces
   (the same as RFC 7714's) and RFC 7714's associated data: the RTP header; for SRTCP the first
   8 bytes with the E flag and index, or the whole packet with an empty plaintext when E is
   clear. The tag ends the ciphertext and the MKI follows it, as for AES-GCM. CCM authenticates
   the plaintext (RFC 5669 §2.2), so a receiver decrypts before it can verify; the result is
   zeroed on failure, never returned, and the replay window is untouched. RFC 6904 with SEED-CCM
   or SEED-GCM uses SEED-CTR with the header key and the 12-byte header salt (RFC 6904 §3.2), as
   AES-GCM uses AES-CM.

5. **Internals.** The session's AEAD seal / open go through one interface for SEED-GCM and
   SEED-CCM (tag lengths from the profile, no fixed 16-byte tag; AES-GCM keeps its direct path,
   and f8 and SEED sit in out-of-line functions so the per-packet code of the WebRTC transforms
   does not grow), SRTCP encryption takes the
   header and index word (f8 needs them), and the header extension keystream is a small forward
   stream over AES-CM, SEED-CTR or f8. No new parsing, so no new fuzz target: `srtp_unprotect`
   and `srtp_features` iterate `Profile::ALL` and cover the five new profiles.

6. **Not wired into negotiation.** `akio-webrtc` keys SRTP through DTLS-SRTP, which has no ids for
   these suites, and does not implement SDP security descriptions (`a=crypto`). If SDES is ever
   added, `Profile::from_sdes_name` already maps the names; that is a follow-up, not part of this
   change.

## Verification

- **SEED**: RFC 4269 Appendix B.1-B.4 both ways, singly and in batches (and the B.4 round keys);
  G against the RFC tables for every S-box input on both paths; OpenSSL 3.0.13 `seed-ecb`
  (legacy provider) for three keys; CTR across batch boundaries and the 128-bit counter wrap.
  RFC 5669 Appendix A.1 (keystream), A.2 (SEED-CCM), A.3 (SEED-GCM) with tampering; RFC 3610
  packet vectors #1 and #19 for the CCM construction with AES.
- **SRTP**: RFC 3711 Appendix B.1 (the f8 IV, IV' and ciphertext, and a whole packet at ROC
  0xd462564a), RFC 5669 A.1 (the SEED-CTR payload), A.2 and A.3 as whole SRTP packets both ways.
  RFC 5669 A.1's tag is not compared: it reproduces as HMAC-SHA1 over the RTP header and the
  *plaintext* without the ROC, not RFC 3711 §4.2's header, ciphertext and ROC.
- **Independent cross-check**: `testdata/f8_seed.py` implements f8, SEED-CTR, CCM, GCM/GHASH,
  both PRFs, RFC 6904, cryptex and the packet layouts from the RFCs alone, on pyca/cryptography
  41's AES and SEED in ECB mode, and checks itself against RFC 3711 B.1/B.3, RFC 4269 and
  RFC 5669 A.1-A.3 first. `testdata/f8_seed.txt`: the inputs of the libsrtp cross-check under
  the five profiles, 25 cases and 115 packets (no MKI; two MKI keys switched mid-stream; RFC 6904
  one- and two-byte extensions; cryptex with and without CSRCs, and with an MKI; RTP and SRTCP),
  protected byte for byte and unprotected back, plus seven SEED-CTR PRF outputs.
- **Behaviour**: the generic tests now run all fifteen profiles: replay and reordering,
  rollover with reordering and a second wrap, SRTCP replay, tampering of every byte, truncation,
  wrong keys, MKI re-keying, key derivation rate 16 across key blocks, RFC 6904, cryptex round
  trips, buffer reuse; the fuzz corpora replay on stable.
- **Timing**: ct-dudect targets `seed-key` (key schedule and CTR, all-zero vs random key) and
  `seed-block` (one block, all-zero vs random plaintext): `seed-key` |t| 1.50 over 15.5M measurements, `seed-block` 1.52 over 50.6M (60 s each, gpu51 quieted, core 2): no difference (docs/constant-time.md)..
- **Speed** (gpu51, `quiet.sh`, CPU 2): per packet with 160 / 1200-byte payloads, protect:
  AES-f8 354 ns / 2.26 µs (AES-128-CM in the same run 251 ns / 1.18 µs: f8's blocks are
  serial), SEED-CTR 3.6 / 18.3 µs (66 MB/s at 1200 bytes), SEED-GCM 3.9 / 20.4 µs, SEED-CCM
  16.1 / 98 µs (12 MB/s); unprotect within 10 % of protect. `akio-crypto` alone: SEED one block
  15.3 MB/s (about 1 µs), SEED-CTR 68.8 MB/s, SEED-GCM 61.3 MB/s, SEED-CCM 12.2 MB/s. Existing
  profiles against main aca9e988 (three alternating rounds, medians): AES-CM and 160-byte AES-GCM
  within ±1.6 %; 1200-byte AES-GCM at parity measured alone (protect 0.999, unprotect 1.012),
  +1.5-2.2 % protect inside the full sequence of cases (where it costs three times as much as
  alone, allocation-bound). Two regressions found by the A/B and removed: AES-GCM going through
  the new generic AEAD helper (+3 %; it has its own arm again, with f8 and SEED out of line) and
  SEED-GCM sharing `Ghash::update_padded` / `finish` with AES-GCM, which changed how they were
  inlined (+2.4 % AES-GCM unprotect at 1200 bytes; SEED-GCM now uses its own out-of-line
  `portable_ghash`).

## Consequences

- `Profile` and `Profile::ALL` grow again (internal tier; `Profile` is `#[non_exhaustive]`).
  `is_aead` covers SEED-CCM and SEED-GCM, which also changes what `rtcp_tag_len` returns for
  them (their own tag length, not 16). Existing profiles behave exactly as before.
- SEED is software-only and an order of magnitude slower than AES with instructions; SEED-CCM
  in particular, whose CBC-MAC runs one block at a time. Fine for SIP/VoIP rates, not for bulk.
- `akio-crypto` gains a second block cipher and its first CCM; the CCM code is generic and could
  serve AES-CCM if a protocol needs it.
