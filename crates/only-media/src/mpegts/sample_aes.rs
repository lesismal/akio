//! HLS `SAMPLE-AES` in MPEG-TS (Apple, "MPEG-2 Stream Encryption Format for HTTP Live
//! Streaming"): samples encrypted inside their elementary streams with AES-128-CBC, the
//! headers a demuxer needs left clear.
//!
//! * H.264 (stream type 0xdb, `zavc`): NAL units of coded slices (types 1 and 5) longer than
//!   48 bytes, after emulation prevention bytes are taken out: 32 bytes clear, then one
//!   encrypted 16-byte block in every ten (1:9), the last 16 bytes or fewer clear; the CBC
//!   chain starts from the IV in every NAL unit, and emulation prevention is applied again to
//!   the result.
//! * AAC in ADTS (stream type 0xcf, `aacd`, with the `apad` audio setup information): the
//!   header and 16 more bytes clear, then every whole 16-byte block encrypted, the rest clear;
//!   the CBC chain starts from the IV in every frame.
//!
//! The decryption side is here too, for tests and fuzzing.

use only_crypto::aes::Aes;

use crate::bits::unescape_rbsp;

/// Stream type of H.264 with SAMPLE-AES.
pub(crate) const STREAM_H264_SAMPLE_AES: u8 = 0xdb;
/// Stream type of AAC in ADTS with SAMPLE-AES.
pub(crate) const STREAM_AAC_SAMPLE_AES: u8 = 0xcf;

/// Clear bytes at the start of an encrypted NAL unit.
const NAL_CLEAR: usize = 32;
/// Clear bytes after the ADTS header of an encrypted frame.
const AUDIO_CLEAR: usize = 16;

/// The key and IV of the segment being written.
#[derive(Clone)]
pub(crate) struct SampleKey {
    pub(crate) aes: Aes,
    pub(crate) iv: [u8; 16],
}

impl std::fmt::Debug for SampleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SampleKey").finish_non_exhaustive()
    }
}

/// Appends `rbsp` with emulation prevention bytes (`00 00 0x`, x <= 3, gets a `03`).
fn push_escaped(out: &mut Vec<u8>, rbsp: &[u8]) {
    let mut zeros = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
}

/// `rbsp` with emulation prevention bytes.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn escape(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len() + 8);
    push_escaped(&mut out, rbsp);
    out
}

/// Runs the 1:9 pattern of an H.264 slice over `rbsp` (encrypting or decrypting).
fn nal_pattern(key: &SampleKey, rbsp: &mut [u8], decrypt: bool) {
    let mut iv = key.iv;
    let mut at = NAL_CLEAR;
    while rbsp.len().saturating_sub(at) > 16 {
        let block = &mut rbsp[at..at + 16];
        let _ = if decrypt {
            key.aes.decrypt_cbc(&mut iv, block)
        } else {
            key.aes.encrypt_cbc(&mut iv, block)
        };
        at += 16 + 144;
    }
}

/// Whether a NAL unit (as found, with emulation prevention bytes) is encrypted.
fn nal_encrypted(nal: &[u8]) -> bool {
    nal.len() > 48 && matches!(nal[0] & 0x1f, 1 | 5)
}

/// Appends the NAL unit `nal` (as found, with emulation prevention bytes), encrypted when it
/// is a coded slice long enough.
pub(crate) fn push_nal(out: &mut Vec<u8>, key: &SampleKey, nal: &[u8]) {
    if !nal_encrypted(nal) {
        out.extend_from_slice(nal);
        return;
    }
    let mut rbsp = unescape_rbsp(nal);
    nal_pattern(key, &mut rbsp, false);
    push_escaped(out, &rbsp);
}

/// Decrypts a NAL unit as received (emulation prevention applied again, as the clear NAL unit
/// had it).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn decrypt_nal(key: &SampleKey, nal: &[u8]) -> Vec<u8> {
    if !nal_encrypted(nal) {
        return nal.to_vec();
    }
    let mut rbsp = unescape_rbsp(nal);
    nal_pattern(key, &mut rbsp, true);
    let mut out = Vec::with_capacity(rbsp.len() + 8);
    push_escaped(&mut out, &rbsp);
    out
}

/// Encrypts (or decrypts) an ADTS frame's payload in place: `payload` is what follows the
/// header.
pub(crate) fn audio_frame(key: &SampleKey, payload: &mut [u8], decrypt: bool) {
    if payload.len() < AUDIO_CLEAR + 16 {
        return;
    }
    let end = AUDIO_CLEAR + (payload.len() - AUDIO_CLEAR) / 16 * 16;
    let mut iv = key.iv;
    let data = &mut payload[AUDIO_CLEAR..end];
    let _ = if decrypt {
        key.aes.decrypt_cbc(&mut iv, data)
    } else {
        key.aes.encrypt_cbc(&mut iv, data)
    };
}

/// The PMT descriptors of an H.264 SAMPLE-AES stream: `private_data_indicator` `zavc`.
pub(crate) fn h264_descriptors(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x0f, 4, b'z', b'a', b'v', b'c']);
}

/// The PMT descriptors of an AAC SAMPLE-AES stream: `private_data_indicator` `aacd` and the
/// registration descriptor `apad` with the audio setup information (`zaac`, no priming,
/// version 1, the `AudioSpecificConfig`).
pub(crate) fn aac_descriptors(out: &mut Vec<u8>, asc: &[u8]) {
    out.extend_from_slice(&[0x0f, 4, b'a', b'a', b'c', b'd']);
    let asc = &asc[..asc.len().min(200)];
    out.extend_from_slice(&[0x05, (4 + 8 + asc.len()) as u8, b'a', b'p', b'a', b'd']);
    out.extend_from_slice(b"zaac");
    out.extend_from_slice(&[0, 0, 1, asc.len() as u8]);
    out.extend_from_slice(asc);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SampleKey {
        SampleKey {
            aes: Aes::new128(&[7; 16]),
            iv: [9; 16],
        }
    }

    #[test]
    fn nal_units() {
        let k = key();
        // Short or not a slice: as is.
        for nal in [vec![0x65; 48], vec![0x67; 200], vec![0x06; 100]] {
            let mut out = Vec::new();
            push_nal(&mut out, &k, &nal);
            assert_eq!(out, nal);
        }
        // A slice with zero runs (emulation prevention in and out).
        let mut nal = vec![0x65];
        for i in 0..600u32 {
            nal.push(if i % 7 < 3 { 0 } else { (i % 251) as u8 });
        }
        let mut esc = vec![nal[0]];
        push_escaped(&mut esc, &nal[1..]);
        let mut out = Vec::new();
        push_nal(&mut out, &k, &esc);
        assert_ne!(out, esc);
        // 32 clear bytes (of the RBSP), then a block, nine clear blocks, a block...
        let rbsp = unescape_rbsp(&out);
        assert_eq!(rbsp[..32], nal[..32]);
        assert_ne!(rbsp[32..48], nal[32..48]);
        assert_eq!(rbsp[48..192], nal[48..192]);
        assert_ne!(rbsp[192..208], nal[192..208]);
        // No start code inside.
        assert!(
            !out.windows(3)
                .any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 3 && w[2] != 3)
        );
        assert_eq!(decrypt_nal(&k, &out), esc);
        // Exactly 16 bytes after the last stride stay clear.
        let mut n = vec![0x41; 32 + 160 + 16];
        n[1] = 0x9a;
        let mut out = Vec::new();
        push_nal(&mut out, &k, &n);
        assert_eq!(out[192..], n[192..]);
        assert_ne!(out[32..48], n[32..48]);
    }

    #[test]
    fn audio_frames() {
        let k = key();
        let plain: Vec<u8> = (0..100u8).collect();
        let mut p = plain.clone();
        audio_frame(&k, &mut p, false);
        assert_eq!(p[..16], plain[..16]);
        assert_ne!(p[16..96], plain[16..96]);
        assert_eq!(p[96..], plain[96..]);
        audio_frame(&k, &mut p, true);
        assert_eq!(p, plain);
        let mut short = vec![1u8; 31];
        audio_frame(&k, &mut short, false);
        assert_eq!(short, vec![1u8; 31]);
        let mut d = Vec::new();
        aac_descriptors(&mut d, &[0x12, 0x10]);
        assert_eq!(
            d,
            [
                0x0f, 4, b'a', b'a', b'c', b'd', 0x05, 14, b'a', b'p', b'a', b'd', b'z', b'a',
                b'a', b'c', 0, 0, 1, 2, 0x12, 0x10
            ]
        );
    }
}
