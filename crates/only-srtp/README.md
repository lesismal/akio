# only-srtp

[中文](README.zh-CN.md)

SRTP and SRTCP (RFC 3711, RFC 6188, RFC 6904, RFC 7714, RFC 9335) for [`only`](https://github.com/lesismal/only), on
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
- `protect_rtp_into` / `unprotect_rtp_into` (and the RTCP ones) write into a reused buffer:
  no allocation per packet.
- `Profile` gives `key_len`, `salt_len`, `rtp_tag_len`, `rtcp_tag_len`,
  `keying_material_len`, the DTLS-SRTP ids (`id` / `from_id`; `None` for AES-192/256-CM) and
  the SDES crypto suite names (`sdes_name` / `from_sdes_name`).

### MKIs and re-keying

```rust,ignore
let mut rx = Context::new_with_mki(profile, &[1], &key1, &salt1)?; // MKI from use_srtp / SDES
// Re-keying: packets under either key are accepted while the old ones drain.
rx.add_master_key(&[2], &key2, &salt2)?;
tx.add_master_key(&[2], &key2, &salt2)?;
tx.set_send_mki(&[2])?;
// ... later
rx.set_send_mki(&[2])?; // a receive context's "send" key is just the one it may not remove
rx.remove_master_key(&[1]);
```

Every packet carries the MKI (before the HMAC tag, after the AEAD tag); the receiver picks the
key by it (`Error::UnknownMki` otherwise). Rollover counters and replay windows stay per SSRC
across keys. Up to 16 master keys, MKIs of 1 to 255 bytes.

### Header encryption

```rust,ignore
// RFC 9335 cryptex (a=cryptex): CSRCs and the whole extension body encrypted.
let tx = Context::new(profile, &key, &salt)?.with_cryptex(true);
// RFC 6904 (a=extmap:N urn:ietf:params:rtp-hdrext:encrypt ...): chosen elements' data only.
let tx = Context::new(profile, &key, &salt)?.with_encrypted_header_extensions(&[1, 3]);
```

With cryptex, packets that have CSRCs or an extension go out marked `0xC0DE` / `0xC2DE` (an
empty extension is added for CSRCs alone); receivers decrypt those and still accept packets
without cryptex. Extensions other than one-byte `0xBEDE` and two-byte `0x1000` cannot use
cryptex (`Error::Unsupported`). RFC 6904 leaves IDs, lengths and padding in the clear; with
AEAD the keystream is AES-CM (RFC 7714 §8.3).

### Key derivation rate

`with_key_derivation_rate(2^n)` (n up to 24) derives session keys again every 2^n packets of
index (SRTP and SRTCP each by their own index), as RFC 3711 §4.3.1; 0, the default, derives
them once.

## Coverage

- Profiles: `SRTP_AES128_CM_HMAC_SHA1_80`, `SRTP_AES128_CM_HMAC_SHA1_32` (SRTCP keeps 80-bit
  tags, RFC 5764 §4.1.2), `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM` (RFC 7714),
  `AES_192_CM_HMAC_SHA1_80/32` and `AES_256_CM_HMAC_SHA1_80/32` (RFC 6188),
  `SRTP_NULL_HMAC_SHA1_80/32` (authentication only; SRTCP with the E flag clear).
- Key derivation with the AES-CM PRF (RFC 3711 §4.3; RFC 6188 for 192- and 256-bit keys), at
  any key derivation rate; MKIs with up to 16 master keys per context; RFC 6904 header
  extension encryption; cryptex (RFC 9335).
- Replay window of 64 packets by default, up to 32768 (`with_replay_window`); at most 1024
  SSRCs per direction (`with_max_ssrcs`), least recently used evicted.

Not implemented: the AES-f8 and SEED transforms, RFC 4771 rollover counter carrying, separate
key derivation rates for SRTP and SRTCP. RFC 6904 follows the RFC where libsrtp differs
(libsrtp does not advance the keystream over padding between extension elements; ADR-040).
`only-webrtc` negotiates cryptex (`a=cryptex`) and RFC 6904
(`urn:ietf:params:rtp-hdrext:encrypt` extmaps) in SDP (ADR-048), but not MKIs: DTLS-SRTP carries
an MKI only in the DTLS `use_srtp` extension, SDP has no attribute for it, and browsers do not
use one.

## Testing

- RFC 3711 Appendix B.2 (AES-CM keystream) and B.3 (key derivation) vectors; RFC 7714 §16-17
  vectors for AEAD_AES_128_GCM and AEAD_AES_256_GCM, RTP and SRTCP (encrypted and
  authentication-only).
- Cross-check against pion/srtp v3.1.3: packets with CSRCs, header extensions and padding,
  across the sequence number rollover, and SRTCP, for all four profiles, byte for byte both
  ways.
- RFC 6188 §7 (AES-192/256 keystreams and PRFs), RFC 6904 Appendix A (header keys and an
  encrypted header extension), RFC 9335 Appendix A (all twelve cryptex packets, AES-CM and
  GCM).
- Cross-check against libsrtp (main, `testdata/libsrtp.txt` from `tools/interop/srtp`): 230
  packets over every profile, without and with two MKI keys switched mid-stream, RFC 6904
  one- and two-byte extensions, cryptex with and without CSRCs, RTP and SRTCP, byte for byte.
- Replay and reordering inside / outside the window, rollover with reordering around it and
  a second wrap, tampering of every byte, truncation, wrong keys, SSRC eviction; re-keying with
  packets in flight, forged and unknown MKIs, key derivation rate with reordering across key
  blocks, configuration errors, buffer reuse.
- Fuzzing: targets `srtp_unprotect` (arbitrary input through every profile's unprotect, plus
  protect / unprotect round trips) and `srtp_features` (MKIs, header extension encryption,
  cryptex, key derivation rate) in `fuzz/`; `fuzzing::tests` replays their corpora on stable.
- Benchmark: `cargo run --release -p only-srtp --example srtp_bench`.
