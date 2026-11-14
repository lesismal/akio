# only-srtp

[中文](README.zh-CN.md)

SRTP and SRTCP (RFC 3711, RFC 7714) for [`only`](https://github.com/lesismal/only), on
[`only-crypto`](../only-crypto), in safe Rust (`#![forbid(unsafe_code)]`) with no other
dependencies. It is the media encryption layer of the in-house WebRTC stack (keys come from
DTLS-SRTP, [`only-dtls`](../only-dtls)). An internal crate (docs/api-stability.md): its API
follows that stack and may change in any release.

## Using a context

A `Context` is one direction of an SRTP session. It has no I/O: packets go in, packets come
out. Create one for what you send (keyed with your master key) and one for what you receive
(keyed with the peer's):

```rust,ignore
use only_srtp::{Context, Error, Profile};

let profile = Profile::from_id(srtp_profile_id).unwrap();     // negotiated by use_srtp
let mut tx = Context::new(profile, &local_key, &local_salt)?;  // from SrtpKeys::local(role)
let mut rx = Context::new(profile, &remote_key, &remote_salt)?
    .with_replay_window(1024);                                  // video with NACK/RTX
let srtp = tx.protect_rtp(&rtp_packet)?;
let srtcp = tx.protect_rtcp(&compound_rtcp)?;
match rx.unprotect_rtp(&datagram) {
    Ok(rtp) => { /* deliver */ }
    Err(Error::Replay) => { /* duplicate: drop silently */ }
    Err(_) => { /* forged, corrupted or not SRTP: drop */ }
}
```

- `protect_rtp` encrypts the payload (and padding) and appends the tag; the header, CSRCs and
  header extension stay in the clear and are authenticated. The rollover counter is tracked
  per SSRC from the sequence numbers.
- `unprotect_rtp` estimates the packet index (RFC 3711 §3.3.1), rejects replays, verifies the
  tag before decrypting, and only then updates the replay window and rollover counter.
- `protect_rtcp` / `unprotect_rtcp` use a 31-bit SRTCP index per sender SSRC with the E flag
  set; received packets with the E flag clear are authenticated only. SRTCP is replay
  protected too.
- `Profile` gives `key_len`, `salt_len`, `rtp_tag_len`, `rtcp_tag_len`,
  `keying_material_len` and the IANA ids (`id` / `from_id`).

## Coverage

- Profiles: `SRTP_AES128_CM_HMAC_SHA1_80`, `SRTP_AES128_CM_HMAC_SHA1_32` (SRTCP keeps 80-bit
  tags, RFC 5764 §4.1.2), `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM` (RFC 7714).
- Key derivation with the AES-CM PRF and key derivation rate 0 (RFC 3711 §4.3; RFC 6188 for
  256-bit keys).
- Replay window of 64 packets by default, up to 32768 (`with_replay_window`); at most 1024
  SSRCs per direction (`with_max_ssrcs`), least recently used evicted.

Not implemented: MKIs, non-zero key derivation rates and re-keying, the NULL cipher,
AES-192/256-CM profiles, encrypted header extensions (RFC 6904), cryptex (RFC 9335).

## Testing

- RFC 3711 Appendix B.2 (AES-CM keystream) and B.3 (key derivation) vectors; RFC 7714 §16-17
  vectors for AEAD_AES_128_GCM and AEAD_AES_256_GCM, RTP and SRTCP (encrypted and
  authentication-only).
- Cross-check against pion/srtp v3.1.3: packets with CSRCs, header extensions and padding,
  across the sequence number rollover, and SRTCP, for all four profiles, byte for byte both
  ways.
- Replay and reordering inside / outside the window, rollover with reordering around it and
  a second wrap, tampering of every byte, truncation, wrong keys, SSRC eviction.
- Fuzzing: target `srtp_unprotect` (arbitrary input through every profile's unprotect, plus
  protect / unprotect round trips) in `fuzz/`; `fuzzing::tests` replays its corpus on stable.
