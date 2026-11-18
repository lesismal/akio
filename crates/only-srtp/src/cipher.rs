//! Key derivation (RFC 3711 §4.3, RFC 6188 §3, RFC 6904 §4.1) and the per-packet primitives:
//! AES-CM / NULL with HMAC-SHA1 (RFC 3711 §4.1.1, §4.2) and AEAD AES-GCM (RFC 7714 §8, §9),
//! plus the header extension keystream (RFC 6904 §3, RFC 7714 §8.3).

use only_crypto::aes::Aes;
use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha1;
use only_crypto::mac::Hmac;

use crate::{Error, Profile};

/// Key derivation labels (RFC 3711 §4.3.2, RFC 6904 §4.1).
const LABEL_RTP_ENC: u8 = 0;
const LABEL_RTP_AUTH: u8 = 1;
const LABEL_RTP_SALT: u8 = 2;
const LABEL_RTCP_ENC: u8 = 3;
const LABEL_RTCP_AUTH: u8 = 4;
const LABEL_RTCP_SALT: u8 = 5;
const LABEL_RTP_HDR_ENC: u8 = 6;
const LABEL_RTP_HDR_SALT: u8 = 7;

/// AES-GCM tag length.
pub(crate) const GCM_TAG: usize = 16;
/// E flag of the SRTCP index word.
pub(crate) const E_FLAG: u32 = 0x8000_0000;

/// A master key and salt: the input of the AES-CM PRF.
pub(crate) struct Master {
    aes: Aes,
    /// The master salt, left-aligned and zero-padded to 14 bytes (AEAD salts are 12 bytes).
    salt: [u8; 14],
}

impl Master {
    pub(crate) fn new(profile: Profile, key: &[u8], salt: &[u8]) -> Result<Master, Error> {
        if key.len() != profile.key_len() || salt.len() != profile.salt_len() {
            return Err(Error::KeyLength);
        }
        let aes = Aes::new(key).map_err(|_| Error::KeyLength)?;
        let mut s = [0u8; 14];
        s[..salt.len()].copy_from_slice(salt);
        Ok(Master { aes, salt: s })
    }

    /// The AES-CM PRF: `AES-CM(master_key, (master_salt XOR (label || r)) * 2^16)` truncated to
    /// `out.len()`, `label || r` right-aligned in the 112-bit salt field (`r`: index DIV key
    /// derivation rate, 48 bits). AES-128/192/256 follows the master key (RFC 6188).
    pub(crate) fn prf(&self, label: u8, r: u64, out: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        iv[7] ^= label;
        for (d, s) in iv[8..14].iter_mut().zip(&r.to_be_bytes()[2..]) {
            *d ^= s;
        }
        out.fill(0);
        self.aes.apply_ctr(&iv, out);
    }
}

/// The encryption transform of one session. The GCM key is boxed: its own allocation keeps the
/// layout of its tables independent of where the session sits (measurably faster for small
/// packets than embedding it).
#[allow(clippy::large_enum_variant)]
pub(crate) enum Enc {
    Null,
    Cm(Aes),
    Gcm(Box<AesGcm>),
}

/// The session keys of one stream type (SRTP or SRTCP) derived from one master key at one
/// `r`.
pub(crate) struct Session {
    pub(crate) enc: Enc,
    /// Session salt (12 bytes and 2 zero bytes for AEAD).
    pub(crate) salt: [u8; 14],
    /// HMAC-SHA1 keyed with the session authentication key (not for AEAD).
    pub(crate) auth: Option<Hmac<Sha1>>,
    /// RFC 6904 header extension keystream generator: AES-CM with the header key and salt
    /// (SRTP only, when header extension encryption is configured and the profile encrypts).
    pub(crate) hdr: Option<(Aes, [u8; 14])>,
}

/// Which stream a [`Session`] protects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Rtp,
    Rtcp,
}

impl Session {
    /// Derives the session keys for `stream` at `r` from `master` (header extension keys too
    /// when `hdr` and the profile encrypts).
    pub(crate) fn derive(
        profile: Profile,
        master: &Master,
        stream: Stream,
        r: u64,
        hdr: bool,
    ) -> Result<Session, Error> {
        let (enc, auth, salt) = match stream {
            Stream::Rtp => (LABEL_RTP_ENC, LABEL_RTP_AUTH, LABEL_RTP_SALT),
            Stream::Rtcp => (LABEL_RTCP_ENC, LABEL_RTCP_AUTH, LABEL_RTCP_SALT),
        };
        let (k, s, a) = (
            profile.cipher_key_len(),
            if profile.encrypts() {
                profile.salt_len()
            } else {
                0
            },
            profile.auth_key_len(),
        );
        let mut key = [0u8; 32];
        let mut sk = [0u8; 14];
        let mut ak = [0u8; 20];
        master.prf(enc, r, &mut key[..k]);
        master.prf(salt, r, &mut sk[..s]);
        master.prf(auth, r, &mut ak[..a]);
        let mut session = Session::from_keys(profile, &key[..k], &sk[..s], &ak[..a])?;
        if hdr && stream == Stream::Rtp && profile.encrypts() {
            let mut hk = [0u8; 32];
            let mut hs = [0u8; 14];
            master.prf(LABEL_RTP_HDR_ENC, r, &mut hk[..k]);
            master.prf(LABEL_RTP_HDR_SALT, r, &mut hs[..profile.salt_len()]);
            let aes = Aes::new(&hk[..k]).map_err(|_| Error::KeyLength)?;
            session.hdr = Some((aes, hs));
            hk.fill(0);
        }
        key.fill(0);
        ak.fill(0);
        Ok(session)
    }

    /// A session from explicit session keys (`key` empty for NULL, `auth` empty for AEAD).
    pub(crate) fn from_keys(
        profile: Profile,
        key: &[u8],
        salt: &[u8],
        auth: &[u8],
    ) -> Result<Session, Error> {
        let enc = if !profile.encrypts() {
            Enc::Null
        } else if profile.is_aead() {
            Enc::Gcm(Box::new(AesGcm::new(key).map_err(|_| Error::KeyLength)?))
        } else {
            Enc::Cm(Aes::new(key).map_err(|_| Error::KeyLength)?)
        };
        let mut s = [0u8; 14];
        let n = salt.len().min(14);
        s[..n].copy_from_slice(&salt[..n]);
        Ok(Session {
            enc,
            salt: s,
            auth: (!profile.is_aead()).then(|| Hmac::new(auth)),
            hdr: None,
        })
    }

    /// Encrypts `buf[aad..]` of an SRTP packet (GCM: `buf[..aad]` is the associated data and
    /// the tag is appended).
    #[inline(always)]
    pub(crate) fn seal_rtp(&self, buf: &mut Vec<u8>, aad: usize, ssrc: u32, roc: u32, seq: u16) {
        match &self.enc {
            Enc::Null => {}
            Enc::Cm(aes) => {
                aes.apply_ctr(&cm_iv(&self.salt, ssrc, index(roc, seq)), &mut buf[aad..]);
            }
            Enc::Gcm(g) => {
                let iv = gcm_rtp_iv(&self.salt, ssrc, roc, seq);
                let (a, body) = buf.split_at_mut(aad);
                let tag = g.encrypt_in_place_detached(&iv, a, body);
                buf.extend_from_slice(&tag);
            }
        }
    }

    /// Decrypts `buf[aad..]` of an SRTP packet; for GCM verifies `tag` first.
    #[inline]
    pub(crate) fn open_rtp(
        &self,
        buf: &mut [u8],
        aad: usize,
        tag: &[u8],
        ssrc: u32,
        roc: u32,
        seq: u16,
    ) -> Result<(), Error> {
        match &self.enc {
            Enc::Null => Ok(()),
            Enc::Cm(aes) => {
                aes.apply_ctr(&cm_iv(&self.salt, ssrc, index(roc, seq)), &mut buf[aad..]);
                Ok(())
            }
            Enc::Gcm(g) => {
                let iv = gcm_rtp_iv(&self.salt, ssrc, roc, seq);
                let (a, body) = buf.split_at_mut(aad);
                g.decrypt_in_place_detached(&iv, a, body, tag)
                    .map_err(|_| Error::Authentication)
            }
        }
    }

    /// HMAC-SHA1 over `parts` (not for AEAD sessions).
    #[inline]
    pub(crate) fn mac(&self, a: &[u8], b: &[u8]) -> [u8; 20] {
        match &self.auth {
            Some(h) => h.clone().chain(a).chain(b).finalize(),
            None => [0; 20],
        }
    }

    /// Encrypts or decrypts `body` (everything after the first 8 bytes) of an SRTCP packet
    /// with an AES-CM / NULL session.
    #[inline]
    pub(crate) fn ctr_rtcp(&self, body: &mut [u8], ssrc: u32, idx: u32) {
        if let Enc::Cm(aes) = &self.enc {
            aes.apply_ctr(&cm_iv(&self.salt, ssrc, u64::from(idx)), body);
        }
    }

    /// The AES-GCM cipher, if this is an AEAD session.
    #[inline]
    pub(crate) fn gcm(&self) -> Option<&AesGcm> {
        match &self.enc {
            Enc::Gcm(g) => Some(g),
            _ => None,
        }
    }

    /// RFC 6904: XORs the masked header extension keystream into the extension elements of
    /// `ext` (an RFC 8285 header extension, its 4-byte header included) whose IDs are in
    /// `ids`. Does nothing without header keys or for a profile that is not RFC 8285.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when an element runs past the end of the extension.
    #[inline]
    pub(crate) fn crypt_header_extension(
        &self,
        ids: &[u64; 4],
        ext: &mut [u8],
        ssrc: u32,
        idx: u64,
    ) -> Result<(), Error> {
        match &self.hdr {
            Some((aes, salt)) => crypt_elements(aes, salt, ids, ext, ssrc, idx),
            None => Ok(()),
        }
    }
}

/// [`Session::crypt_header_extension`] with header keys.
#[inline(never)]
fn crypt_elements(
    aes: &Aes,
    salt: &[u8; 14],
    ids: &[u64; 4],
    ext: &mut [u8],
    ssrc: u32,
    idx: u64,
) -> Result<(), Error> {
    let profile = u16::from_be_bytes([ext[0], ext[1]]);
    let two_byte = match profile {
        0xbede => false,
        p if p & 0xfff0 == 0x1000 => true,
        _ => return Ok(()),
    };
    let iv = u128::from_be_bytes(cm_iv(salt, ssrc, idx));
    let data = &mut ext[4..];
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0 {
            i += 1; // padding
            continue;
        }
        let (id, len, at) = if two_byte {
            let Some(&l) = data.get(i + 1) else {
                return Err(Error::Malformed);
            };
            (b, usize::from(l), i + 2)
        } else {
            if b >> 4 == 15 {
                break; // RFC 8285 §4.2: stop parsing
            }
            (b >> 4, usize::from(b & 0x0f) + 1, i + 1)
        };
        if at + len > data.len() {
            return Err(Error::Malformed);
        }
        if ids[usize::from(id) / 64] & (1 << (id % 64)) != 0 && len > 0 {
            // Keystream bytes at..at+len: the block holding `at`, then onwards.
            let mut ks = [0u8; 16 + 256];
            let skip = at % 16;
            let ctr = iv.wrapping_add((at / 16) as u128).to_be_bytes();
            aes.apply_ctr(&ctr, &mut ks[..skip + len]);
            for (d, k) in data[at..at + len].iter_mut().zip(&ks[skip..]) {
                *d ^= k;
            }
        }
        i = at + len;
    }
    Ok(())
}

fn index(roc: u32, seq: u16) -> u64 {
    (u64::from(roc) << 16) | u64::from(seq)
}

/// AES-CM IV (RFC 3711 §4.1.1): `(k_s * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)`.
pub(crate) fn cm_iv(salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
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
fn gcm_rtp_iv(salt: &[u8; 14], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
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
pub(crate) fn gcm_rtcp_iv(salt: &[u8; 14], ssrc: u32, index: u32) -> [u8; 12] {
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
    use crate::tests::hex;

    fn prf(p: Profile, key: &str, salt: &str, label: u8, r: u64, len: usize) -> Vec<u8> {
        let m = Master::new(p, &hex(key), &hex(salt)).unwrap();
        let mut out = vec![0u8; len];
        m.prf(label, r, &mut out);
        out
    }

    /// RFC 3711 Appendix B.3 and RFC 6904 Appendix A.1.
    #[test]
    fn rfc3711_b3_and_rfc6904_a1_key_derivation() {
        let (k, s) = (
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
        );
        let p = Profile::Aes128CmHmacSha1_80;
        assert_eq!(
            prf(p, k, s, 0, 0, 16),
            hex("C61E7A93744F39EE10734AFE3FF7A087")
        );
        assert_eq!(prf(p, k, s, 2, 0, 14), hex("30CBBC08863D8C85D49DB34A9AE1"));
        assert_eq!(
            prf(p, k, s, 1, 0, 64),
            hex(
                "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCE\
                 E049646C43D9327AD175578EF72270986371C10C9A369AC2F94A8C5FBCDDDC25"
            )
        );
        assert_eq!(
            prf(p, k, s, 6, 0, 16),
            hex("549752054D6FB708622C4A2E596A1B93")
        );
        assert_eq!(prf(p, k, s, 7, 0, 14), hex("AB01818174C40D39A3781F7C2D27"));
        assert_eq!(prf(p, k, s, 0, 0, 0), Vec::<u8>::new());
    }

    /// RFC 6188 §7.2 (AES_256_CM_PRF) and §7.4 (AES_192_CM_PRF).
    #[test]
    fn rfc6188_key_derivation() {
        let p = Profile::Aes256CmHmacSha1_80;
        let (k, s) = (
            "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6",
            "3b04803de51ee7c96423ab5b78d2",
        );
        assert_eq!(
            prf(p, k, s, 0, 0, 32),
            hex("5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4")
        );
        assert_eq!(prf(p, k, s, 2, 0, 14), hex("fa31791685ca444a9e07c6c64e93"));
        assert_eq!(
            prf(p, k, s, 1, 0, 20),
            hex("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05")
        );
        let p = Profile::Aes192CmHmacSha1_32;
        let (k, s) = (
            "73edc66c4fa15776fb57f9505c17136550ffda71f3e8e5f1",
            "c8522f3acd4ce86d5add78edbb11",
        );
        assert_eq!(
            prf(p, k, s, 0, 0, 24),
            hex("31874736a8f1143870c26e4857d8a5b2c4a354407faadabb")
        );
        assert_eq!(prf(p, k, s, 2, 0, 14), hex("2372b82d639b6d8503a47adc0a6c"));
        assert_eq!(
            prf(p, k, s, 1, 0, 20),
            hex("355b10973cd95b9eacf4061c7e1a7151e7cfbfcb")
        );
    }

    /// Key derivation rate: `r` XORed right-aligned under the label.
    #[test]
    fn kdr_input_block() {
        let p = Profile::Aes128CmHmacSha1_80;
        let (k, s) = (
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
        );
        let aes = Aes::new(&hex(k)).unwrap();
        // label 0, r = 0x0102_0304_0506: x = 0EC675AD498AFEEB B794083EAEE0.
        let mut want = [0u8; 16];
        aes.apply_ctr(
            &hex("0EC675AD498AFEEBB794083EAEE00000").try_into().unwrap(),
            &mut want,
        );
        assert_eq!(prf(p, k, s, 0, 0x0102_0304_0506, 16), want);
    }

    /// RFC 3711 Appendix B.2, RFC 6188 §7.1 and §7.3: AES-CM keystreams with SSRC, ROC and
    /// SEQ zero.
    #[test]
    fn aes_cm_keystreams() {
        let salt: [u8; 14] = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD").try_into().unwrap();
        let iv = cm_iv(&salt, 0, 0);
        assert_eq!(iv.to_vec(), hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"));
        for (key, want) in [
            (
                "2B7E151628AED2A6ABF7158809CF4F3C",
                "E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB\
                 41E95B3BB0A2E8DD477901E4FCA894C0",
            ),
            (
                "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
                "92bdd28a93c3f52511c677d08b5515a49da71b2378a854f67050756ded165bac\
                 63c4868b7096d88421b563b8c94c9a31",
            ),
            (
                "eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7",
                "35096cba4610028dc1b57503804ce37c5de986291dcce161d5165ec4568f5c9a\
                 474a40c77894bc17180202272a4c264d",
            ),
        ] {
            let aes = Aes::new(&hex(key)).unwrap();
            let mut ks = vec![0u8; 48];
            aes.apply_ctr(&iv, &mut ks);
            assert_eq!(ks, hex(want));
        }
    }

    /// RFC 6904 Appendix A.2: header extension encryption with AES-CM.
    #[test]
    fn rfc6904_a2_header_encryption() {
        let mut s =
            Session::from_keys(Profile::Aes128CmHmacSha1_80, &[0; 16], &[0; 14], &[]).unwrap();
        s.hdr = Some((
            Aes::new(&hex("549752054D6FB708622C4A2E596A1B93")).unwrap(),
            hex("AB01818174C40D39A3781F7C2D27").try_into().unwrap(),
        ));
        let mut ids = [0u64; 4];
        for id in [1, 3, 4] {
            ids[0] |= 1 << id;
        }
        let plain = hex("BEDE0006 17414273A475262748220000C8308E4655996386B395FB00");
        let mut ext = plain.clone();
        s.crypt_header_extension(&ids, &mut ext, 0xcafe_babe, 0x1234)
            .unwrap();
        assert_eq!(
            ext,
            hex("BEDE0006 17588A9270F4E15E1C220000C8309546A994F0BC54789700")
        );
        s.crypt_header_extension(&ids, &mut ext, 0xcafe_babe, 0x1234)
            .unwrap();
        assert_eq!(ext, plain);
        // An element running past the end.
        let mut bad = hex("BEDE0001 1F000000");
        assert_eq!(
            s.crypt_header_extension(&ids, &mut bad, 1, 1),
            Err(Error::Malformed)
        );
        // Not RFC 8285: untouched.
        let mut other = hex("ABCD0001 11223344");
        s.crypt_header_extension(&ids, &mut other, 1, 1).unwrap();
        assert_eq!(other, hex("ABCD0001 11223344"));
    }

    #[test]
    fn wrong_lengths() {
        assert!(Master::new(Profile::AeadAes128Gcm, &[0; 16], &[0; 14]).is_err());
        assert!(Master::new(Profile::AeadAes256Gcm, &[0; 16], &[0; 12]).is_err());
        assert!(Master::new(Profile::Aes192CmHmacSha1_80, &[0; 24], &[0; 14]).is_ok());
        assert!(Master::new(Profile::NullHmacSha1_32, &[0; 16], &[0; 14]).is_ok());
    }
}
