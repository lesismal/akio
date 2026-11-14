//! Session key derivation (RFC 3711 §4.3) and the per-packet transforms: AES-CM with
//! HMAC-SHA1 (RFC 3711 §4.1.1, §4.2) and AEAD AES-GCM (RFC 7714 §8, §9).

use only_crypto::aes::Aes;
use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha1;
use only_crypto::mac::Hmac;

use crate::{Error, Profile};

/// Key derivation labels (RFC 3711 §4.3.2).
const LABEL_RTP_ENC: u8 = 0;
const LABEL_RTP_AUTH: u8 = 1;
const LABEL_RTP_SALT: u8 = 2;
const LABEL_RTCP_ENC: u8 = 3;
const LABEL_RTCP_AUTH: u8 = 4;
const LABEL_RTCP_SALT: u8 = 5;

/// Derived session keys for both RTP and RTCP.
#[derive(Clone)]
pub(crate) struct SessionKeys {
    pub(crate) rtp_key: Vec<u8>,
    pub(crate) rtp_salt: Vec<u8>,
    pub(crate) rtp_auth: Vec<u8>,
    pub(crate) rtcp_key: Vec<u8>,
    pub(crate) rtcp_salt: Vec<u8>,
    pub(crate) rtcp_auth: Vec<u8>,
}

/// The AES-CM PRF with key derivation rate 0: `AES-CM(master_key, (master_salt XOR label << 48)
/// * 2^16)`, truncated to `len` bytes. AES-128 or AES-256 follows the master key length
/// (RFC 6188 for 256-bit keys, used by `AEAD_AES_256_GCM`).
fn prf(aes: &Aes, master_salt: &[u8], label: u8, len: usize) -> Vec<u8> {
    let mut iv = [0u8; 16];
    let n = master_salt.len().min(14);
    iv[..n].copy_from_slice(&master_salt[..n]);
    iv[7] ^= label;
    let mut out = vec![0u8; len];
    aes.apply_ctr(&iv, &mut out);
    out
}

pub(crate) fn derive(
    profile: Profile,
    master_key: &[u8],
    master_salt: &[u8],
) -> Result<SessionKeys, Error> {
    if master_key.len() != profile.key_len() || master_salt.len() != profile.salt_len() {
        return Err(Error::KeyLength);
    }
    let aes = Aes::new(master_key).map_err(|_| Error::KeyLength)?;
    let (k, s, a) = (
        profile.key_len(),
        profile.salt_len(),
        profile.auth_key_len(),
    );
    Ok(SessionKeys {
        rtp_key: prf(&aes, master_salt, LABEL_RTP_ENC, k),
        rtp_salt: prf(&aes, master_salt, LABEL_RTP_SALT, s),
        rtp_auth: prf(&aes, master_salt, LABEL_RTP_AUTH, a),
        rtcp_key: prf(&aes, master_salt, LABEL_RTCP_ENC, k),
        rtcp_salt: prf(&aes, master_salt, LABEL_RTCP_SALT, s),
        rtcp_auth: prf(&aes, master_salt, LABEL_RTCP_AUTH, a),
    })
}

fn salt<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = s.len().min(N);
    out[..n].copy_from_slice(&s[..n]);
    out
}

/// Per-direction cipher state (one per [`Context`](crate::Context), so the size difference
/// between the variants does not matter).
#[allow(clippy::large_enum_variant)]
pub(crate) enum Cipher {
    Cm {
        rtp: Aes,
        rtp_salt: [u8; 14],
        rtp_auth: Hmac<Sha1>,
        rtcp: Aes,
        rtcp_salt: [u8; 14],
        rtcp_auth: Hmac<Sha1>,
        rtp_tag: usize,
    },
    Gcm {
        rtp: AesGcm,
        rtp_salt: [u8; 12],
        rtcp: AesGcm,
        rtcp_salt: [u8; 12],
    },
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Cipher::Cm { .. } => "Cipher::AesCmHmacSha1",
            Cipher::Gcm { .. } => "Cipher::AesGcm",
        })
    }
}

/// SRTCP authentication tag length for the AES-CM profiles.
const RTCP_CM_TAG: usize = 10;
/// AES-GCM tag length.
const GCM_TAG: usize = 16;
/// E flag of the SRTCP index word.
pub(crate) const E_FLAG: u32 = 0x8000_0000;

impl Cipher {
    pub(crate) fn new(profile: Profile, k: &SessionKeys) -> Result<Cipher, Error> {
        if profile.is_aead() {
            Ok(Cipher::Gcm {
                rtp: AesGcm::new(&k.rtp_key).map_err(|_| Error::KeyLength)?,
                rtp_salt: salt(&k.rtp_salt),
                rtcp: AesGcm::new(&k.rtcp_key).map_err(|_| Error::KeyLength)?,
                rtcp_salt: salt(&k.rtcp_salt),
            })
        } else {
            Ok(Cipher::Cm {
                rtp: Aes::new(&k.rtp_key).map_err(|_| Error::KeyLength)?,
                rtp_salt: salt(&k.rtp_salt),
                rtp_auth: Hmac::new(&k.rtp_auth),
                rtcp: Aes::new(&k.rtcp_key).map_err(|_| Error::KeyLength)?,
                rtcp_salt: salt(&k.rtcp_salt),
                rtcp_auth: Hmac::new(&k.rtcp_auth),
                rtp_tag: profile.rtp_tag_len(),
            })
        }
    }

    pub(crate) fn rtp_tag_len(&self) -> usize {
        match self {
            Cipher::Cm { rtp_tag, .. } => *rtp_tag,
            Cipher::Gcm { .. } => GCM_TAG,
        }
    }

    pub(crate) fn rtcp_tag_len(&self) -> usize {
        match self {
            Cipher::Cm { .. } => RTCP_CM_TAG,
            Cipher::Gcm { .. } => GCM_TAG,
        }
    }

    /// Encrypts and authenticates the RTP packet `p` (header length `hlen`) with rollover
    /// counter `roc`.
    pub(crate) fn protect_rtp(&self, p: &[u8], hlen: usize, ssrc: u32, roc: u32) -> Vec<u8> {
        let seq = u16::from_be_bytes([p[2], p[3]]);
        let mut out = Vec::with_capacity(p.len() + self.rtp_tag_len());
        out.extend_from_slice(p);
        match self {
            Cipher::Cm {
                rtp,
                rtp_salt,
                rtp_auth,
                rtp_tag,
                ..
            } => {
                let iv = cm_iv(rtp_salt, ssrc, (u64::from(roc) << 16) | u64::from(seq));
                rtp.apply_ctr(&iv, &mut out[hlen..]);
                let mac = rtp_auth
                    .clone()
                    .chain(&out)
                    .chain(&roc.to_be_bytes())
                    .finalize();
                out.extend_from_slice(&mac[..*rtp_tag]);
            }
            Cipher::Gcm { rtp, rtp_salt, .. } => {
                let iv = gcm_rtp_iv(rtp_salt, ssrc, roc, seq);
                let (hdr, body) = out.split_at_mut(hlen);
                let tag = rtp.encrypt_in_place_detached(&iv, hdr, body);
                out.extend_from_slice(&tag);
            }
        }
        out
    }

    /// Verifies and decrypts the SRTP packet `p` (header length `hlen`, already checked to be
    /// followed by at least a tag). Returns the RTP packet.
    pub(crate) fn unprotect_rtp(
        &self,
        p: &[u8],
        hlen: usize,
        ssrc: u32,
        roc: u32,
    ) -> Result<Vec<u8>, Error> {
        let seq = u16::from_be_bytes([p[2], p[3]]);
        let body_end = p.len() - self.rtp_tag_len();
        let (data, tag) = p.split_at(body_end);
        let mut out = data.to_vec();
        match self {
            Cipher::Cm {
                rtp,
                rtp_salt,
                rtp_auth,
                ..
            } => {
                let mac = rtp_auth
                    .clone()
                    .chain(data)
                    .chain(&roc.to_be_bytes())
                    .finalize();
                if !only_crypto::ct_eq(&mac[..tag.len()], tag) {
                    return Err(Error::Authentication);
                }
                let iv = cm_iv(rtp_salt, ssrc, (u64::from(roc) << 16) | u64::from(seq));
                rtp.apply_ctr(&iv, &mut out[hlen..]);
            }
            Cipher::Gcm { rtp, rtp_salt, .. } => {
                let iv = gcm_rtp_iv(rtp_salt, ssrc, roc, seq);
                let (hdr, body) = out.split_at_mut(hlen);
                rtp.decrypt_in_place_detached(&iv, hdr, body, tag)
                    .map_err(|_| Error::Authentication)?;
            }
        }
        Ok(out)
    }

    /// Encrypts and authenticates the compound RTCP packet `p` (at least 8 bytes) with SRTCP
    /// index `index` (31 bits); the E flag is set.
    pub(crate) fn protect_rtcp(&self, p: &[u8], ssrc: u32, index: u32) -> Vec<u8> {
        let word = (E_FLAG | index).to_be_bytes();
        let mut out = Vec::with_capacity(p.len() + 4 + self.rtcp_tag_len());
        out.extend_from_slice(p);
        match self {
            Cipher::Cm {
                rtcp,
                rtcp_salt,
                rtcp_auth,
                ..
            } => {
                let iv = cm_iv(rtcp_salt, ssrc, u64::from(index));
                rtcp.apply_ctr(&iv, &mut out[8..]);
                out.extend_from_slice(&word);
                let mac = rtcp_auth.clone().chain(&out).finalize();
                out.extend_from_slice(&mac[..RTCP_CM_TAG]);
            }
            Cipher::Gcm {
                rtcp, rtcp_salt, ..
            } => {
                let iv = gcm_rtcp_iv(rtcp_salt, ssrc, index);
                let mut aad = [0u8; 12];
                aad[..8].copy_from_slice(&p[..8]);
                aad[8..].copy_from_slice(&word);
                let tag = rtcp.encrypt_in_place_detached(&iv, &aad, &mut out[8..]);
                out.extend_from_slice(&tag);
                out.extend_from_slice(&word);
            }
        }
        out
    }

    /// Verifies and decrypts an SRTCP packet. Returns `(index, rtcp packet)`; the caller does
    /// the replay check on `index` first via `peek_rtcp_index`.
    pub(crate) fn unprotect_rtcp(&self, p: &[u8], ssrc: u32) -> Result<Vec<u8>, Error> {
        let tag_len = self.rtcp_tag_len();
        match self {
            Cipher::Cm {
                rtcp,
                rtcp_salt,
                rtcp_auth,
                ..
            } => {
                let (data, tag) = p.split_at(p.len() - tag_len);
                let mac = rtcp_auth.clone().chain(data).finalize();
                if !only_crypto::ct_eq(&mac[..tag_len], tag) {
                    return Err(Error::Authentication);
                }
                let (body, w) = data.split_at(data.len() - 4);
                let word = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
                let mut out = body.to_vec();
                if word & E_FLAG != 0 {
                    let iv = cm_iv(rtcp_salt, ssrc, u64::from(word & !E_FLAG));
                    rtcp.apply_ctr(&iv, &mut out[8..]);
                }
                Ok(out)
            }
            Cipher::Gcm {
                rtcp, rtcp_salt, ..
            } => {
                let (rest, w) = p.split_at(p.len() - 4);
                let (data, tag) = rest.split_at(rest.len() - GCM_TAG);
                let word = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
                let iv = gcm_rtcp_iv(rtcp_salt, ssrc, word & !E_FLAG);
                if word & E_FLAG != 0 {
                    let mut aad = [0u8; 12];
                    aad[..8].copy_from_slice(&data[..8]);
                    aad[8..].copy_from_slice(w);
                    let mut out = data.to_vec();
                    rtcp.decrypt_in_place_detached(&iv, &aad, &mut out[8..], tag)
                        .map_err(|_| Error::Authentication)?;
                    Ok(out)
                } else {
                    // RFC 7714 §9.2: unencrypted SRTCP, the whole packet is AAD.
                    let mut aad = Vec::with_capacity(data.len() + 4);
                    aad.extend_from_slice(data);
                    aad.extend_from_slice(w);
                    rtcp.decrypt_in_place_detached(&iv, &aad, &mut [], tag)
                        .map_err(|_| Error::Authentication)?;
                    Ok(data.to_vec())
                }
            }
        }
    }
}

/// AES-CM IV (RFC 3711 §4.1.1): `(k_s * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)`.
fn cm_iv(salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(salt);
    for (d, s) in iv[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
        *d ^= s;
    }
    for (d, s) in iv[8..14].iter_mut().zip(&index.to_be_bytes()[2..]) {
        *d ^= s;
    }
    iv
}

/// RFC 7714 §8.1: `(00 00 || SSRC || ROC || SEQ) XOR salt`.
fn gcm_rtp_iv(salt: &[u8; 12], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[6..10].copy_from_slice(&roc.to_be_bytes());
    iv[10..12].copy_from_slice(&seq.to_be_bytes());
    for (d, s) in iv.iter_mut().zip(salt) {
        *d ^= s;
    }
    iv
}

/// RFC 7714 §9.1: `(00 00 || SSRC || 00 00 || 0 || SRTCP index) XOR salt`.
fn gcm_rtcp_iv(salt: &[u8; 12], ssrc: u32, index: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[8..12].copy_from_slice(&(index & !E_FLAG).to_be_bytes());
    for (d, s) in iv.iter_mut().zip(salt) {
        *d ^= s;
    }
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 3711 Appendix B.3.
    #[test]
    fn rfc3711_b3_key_derivation() {
        let k = derive(
            Profile::Aes128CmHmacSha1_80,
            &hex("E1F97A0D3E018BE0D64FA32C06DE4139"),
            &hex("0EC675AD498AFEEBB6960B3AABE6"),
        )
        .unwrap();
        assert_eq!(k.rtp_key, hex("C61E7A93744F39EE10734AFE3FF7A087"));
        assert_eq!(k.rtp_salt, hex("30CBBC08863D8C85D49DB34A9AE1"));
        assert_eq!(k.rtp_auth, hex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4"));
        let mut aes = Aes::new(&hex("E1F97A0D3E018BE0D64FA32C06DE4139")).unwrap();
        // The longer auth-key keystream of B.3 (first 64 bytes).
        let long = prf(&aes, &hex("0EC675AD498AFEEBB6960B3AABE6"), 1, 64);
        assert_eq!(
            long,
            hex(
                "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCE\
                 E049646C43D9327AD175578EF72270986371C10C9A369AC2F94A8C5FBCDDDC25"
            )
        );
        aes = Aes::new(&[0u8; 16]).unwrap();
        assert_eq!(prf(&aes, &[0; 14], 0, 0), Vec::<u8>::new());
    }

    /// RFC 3711 Appendix B.2: AES-CM keystream with SSRC, ROC and SEQ zero.
    #[test]
    fn rfc3711_b2_keystream() {
        let aes = Aes::new(&hex("2B7E151628AED2A6ABF7158809CF4F3C")).unwrap();
        let salt: [u8; 14] = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD").try_into().unwrap();
        let iv = cm_iv(&salt, 0, 0);
        assert_eq!(iv.to_vec(), hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"));
        let mut ks = vec![0u8; 48];
        aes.apply_ctr(&iv, &mut ks);
        assert_eq!(
            ks,
            hex(
                "E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB\
                 41E95B3BB0A2E8DD477901E4FCA894C0"
            )
        );
    }

    #[test]
    fn wrong_lengths() {
        assert!(derive(Profile::AeadAes128Gcm, &[0; 16], &[0; 14]).is_err());
        assert!(derive(Profile::AeadAes256Gcm, &[0; 16], &[0; 12]).is_err());
        assert!(derive(Profile::Aes128CmHmacSha1_32, &[0; 16], &[0; 14]).is_ok());
    }
}
