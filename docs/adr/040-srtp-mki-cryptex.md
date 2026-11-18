# ADR-040: SRTP MKIs, key derivation rates, more profiles, header extension encryption and cryptex

English | [简体中文](040-srtp-mki-cryptex.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`only-srtp` covered what WebRTC negotiates today: the four DTLS-SRTP profiles
(AES-128-CM-HMAC-SHA1-80/32, AEAD-AES-128/256-GCM), one master key per context, key derivation
rate 0, and headers always in the clear. Its README listed what was missing: Master Key
Identifiers (MKIs) and re-keying, non-zero key derivation rates, the NULL cipher, the
AES-192/256-CM profiles (RFC 6188), encrypted header extensions (RFC 6904) and cryptex
(RFC 9335). `only-dtls` parsed the `srtp_mki` field of `use_srtp` but refused a non-empty one.

Cryptex matters most: header extensions (audio levels, MIDs, transport-wide sequence numbers)
and CSRCs leak who speaks and which application sends; cryptex, negotiated with `a=cryptex`,
encrypts them. MKIs and the other profiles matter to SIP/SDES peers and to DTLS-SRTP
re-keying. The reference implementation is libsrtp (main, which has cryptex, MKIs and RFC 6904
and is what libwebrtc uses).

## Decision

1. **Profiles.** `Profile` gains `Aes192CmHmacSha1_80/32`, `Aes256CmHmacSha1_80/32` (RFC 6188:
   24/32-byte master keys, 14-byte salts, 160-bit HMAC-SHA1 keys, the AES-192/256 CM PRF) and
   `NullHmacSha1_80/32` (RFC 5764 0x0005 / 0x0006: no encryption, a 16-byte master key and
   14-byte salt for the key derivation, SRTCP sent with the E flag clear, as libsrtp). `Profile`
   becomes `#[non_exhaustive]`; `Profile::ALL` lists all ten (the four WebRTC ones first, in the
   old order). The RFC 6188 profiles have no DTLS-SRTP code point, so `Profile::id` now returns
   `Option<u16>` (breaking, internal tier); `name` gives the DTLS-SRTP name or, for those, the
   SDES crypto suite; `sdes_name` / `from_sdes_name` map the SDP security descriptions names;
   `encrypts` tells the NULL profiles apart.
2. **MKIs and re-keying** (RFC 3711 §3.1, §8.1). `Context::new_with_mki(profile, mki, key, salt)`
   (1 to 255 bytes, the DTLS limit) makes every packet carry the MKI: before the HMAC tag for
   AES-CM / NULL (not authenticated), after the AEAD tag for GCM (RFC 7714 §8.1, §9). A context
   holds up to `MAX_MASTER_KEYS` (16) master keys with MKIs of one length: `add_master_key`,
   `set_send_mki` (what `protect_*` uses), `remove_master_key` (never the sending key),
   `send_mki`, `mki_len`. `unprotect_*` picks the key by the packet's MKI before anything else
   (`Error::UnknownMki` when none matches). Rollover counters, replay windows and SRTCP indices
   stay per SSRC across keys, as RFC 3711 keeps them in the crypto context, not the key.
   Contexts without MKI are unchanged (`Context::new`).
3. **Key derivation rate** (RFC 3711 §4.3.1). `with_key_derivation_rate(rate)` accepts 0 or a
   power of two up to 2^24 (`Error::Config` otherwise) and applies to every master key: session
   keys are derived with `r = index DIV rate` (48-bit SRTP index, 31-bit SRTCP index) XORed
   right-aligned under the label. Each master key keeps the session keys of the last `r` it used
   per stream; a packet at another `r` derives first (on the receive side into a temporary that
   replaces the cached keys only after the packet authenticates, so forged packets cannot evict
   them). Rate 0 never derives again and costs one branch.
4. **RFC 6904 header extension encryption.** `with_encrypted_header_extensions(&ids)` (one-byte
   IDs 1-14, two-byte IDs 1-255, as negotiated by `urn:ietf:params:rtp-hdrext:encrypt`) derives
   header keys with labels 6 and 7 and XORs an AES-CM keystream, IV as for the payload, into the
   data bytes of the selected elements only: element headers, padding and the 4-byte extension
   header stay in the clear, and the keystream offset is the byte offset in the extension. With
   GCM the keystream is AES-128/256-CM with the 12-byte header salt zero-padded to 14 bytes
   (RFC 7714 §8.3, as libsrtp) and the encrypted extension is AAD. Encryption runs before the
   tag; decryption after the tag verified. An element running past the extension is
   `Error::Malformed`. NULL profiles leave headers alone (RFC 6904 §3.2: all-zero keystream).
   One divergence from libsrtp, found by the cross-check: libsrtp does not advance its keystream
   over padding bytes between elements, while RFC 6904 §3 aligns keystream and mask with the
   extension bytes; we follow the RFC, so the two disagree only for extensions with padding
   between elements (the cross-check vectors have none, `header_extension_encryption` covers
   that case).
5. **Cryptex (RFC 9335).** `with_cryptex(true)`: `protect_rtp` encrypts the CSRCs and the whole
   extension body of every packet that has either, marking the extension `0xC0DE` / `0xC2DE`;
   a packet with CSRCs and no extension gets an empty `0xC0DE` one (§5.1, which libsrtp leaves
   to the caller). The CSRC list and the extension header are swapped in the output buffer so
   that AAD (fixed header and extension header) and plaintext are contiguous (§6.2, Figure 2),
   for AES-CM and GCM alike, and swapped back. Extensions other than `0xBEDE` / `0x1000` (two-byte
   with appbits, non-RFC 8285) are `Error::Unsupported` rather than sent with clear CSRCs.
   `unprotect_rtp` decrypts packets marked `0xC0DE` / `0xC2DE`, restores `0xBEDE` / `0x1000`,
   keeps an added empty extension (§5.2) and still accepts packets without cryptex. Cryptex
   packets never also use RFC 6904. NULL profiles ignore cryptex both ways (nothing to encrypt).
6. **Allocation-free variants.** `protect_rtp_into`, `unprotect_rtp_into`, `protect_rtcp_into`,
   `unprotect_rtcp_into` write into a caller's buffer (cleared, left empty on error); the
   `Vec`-returning methods call them. Per packet nothing else allocates (except re-deriving
   session keys under a non-zero key derivation rate, once per block of packets): session keys
   are derived through stack arrays, the RFC 6904 keystream uses a 272-byte stack buffer, the
   cryptex swap is in place, and unencrypted AEAD SRTCP builds its AAD in the output buffer
   instead of a temporary `Vec`.
7. **New errors** (`Error` is non-exhaustive): `Config`, `UnknownMki`, `Unsupported`.
8. **DTLS-SRTP MKI** (RFC 5764 §4.1.3). `only-dtls` `Config::with_srtp_mki(mki)` (client: offer
   it; panics beyond 255 bytes) and `Config::with_srtp_accept_mki(bool)` (server: echo the
   client's MKI; default off, so an SRTP layer that ignores MKIs keeps working);
   `HandshakeInfo::srtp_mki` is the MKI both sides use (`None` without). A client whose server
   echoes a different non-empty MKI fails the handshake with illegal_parameter; DTLS 1.2
   ServerHello and DTLS 1.3 EncryptedExtensions alike.
9. **Not wired into only-webrtc yet**: `a=cryptex`, RFC 6904 extmaps and DTLS-SRTP MKIs in the
   SDP offer/answer are a follow-up (another branch is changing only-webrtc's SDP).

## Verification

- Vectors: RFC 3711 B.2/B.3, RFC 6188 §7 (AES-192/256 keystreams and PRFs), RFC 6904 A.1/A.2
  (header keys, header extension ciphertext), RFC 9335 Appendix A (all twelve cryptex packets,
  AES-CM and GCM), RFC 7714 as before; the key derivation rate's PRF input checked by hand.
- libsrtp cross-check (`testdata/libsrtp.txt`, made by `tools/interop/srtp/vec.c` against
  libsrtp main 052aa29 with OpenSSL 3.0.13): 230 packets, every profile without and with two
  MKI keys switched mid-stream, RFC 6904 with one- and two-byte extensions, cryptex with and
  without CSRCs (and with an MKI), RTP and SRTCP; protect byte for byte and unprotect back.
- Behaviour: re-keying with packets in flight under both keys, forged and unknown MKIs, every
  configuration error, key derivation rate 16 with reordering across key blocks and SRTCP,
  cryptex tampering of every byte, buffer reuse without reallocation; DTLS MKI negotiation over
  DTLS 1.2 and 1.3 (accepted, refused, none offered, 255 bytes, no common profile).
- Fuzzing: new target `srtp_features` (MKIs, header extension encryption, cryptex, key
  derivation rate per profile, round trips), at least 10 minutes on gpu51, and `srtp_unprotect`
  now runs all ten profiles.
- Benchmarks on gpu51 (`examples/srtp_bench.rs`, quiet host, three alternating rounds against
  the base): unprotect 0-5 % faster for every existing profile, AES-CM protect within ±1.3 %,
  AEAD protect within ±0.3 % at 1200 B and +1-2 % at 160 B (about 2 ns). Two things found on the
  way: the per-SSRC map was looked up twice per packet (the old code got away with it because
  LLVM merged the two SipHash calls; the larger function no longer inlines the hash), now once;
  and embedding the GCM key in the session cost ~3 ns per small packet against boxing it.
  Numbers in the CHANGELOG entry.

## Consequences

- Breaking for `only-srtp` users (internal tier): `Profile::id` returns `Option<u16>`, `Profile`
  and `Profile::ALL` grow. `only-webrtc` only uses `from_id` and is unaffected.
- One `Context` can now outlive a DTLS re-handshake: add the new key under its MKI, switch
  sending, remove the old one once its packets have drained.
