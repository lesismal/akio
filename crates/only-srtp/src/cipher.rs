//! Key derivation (RFC 3711 §4.3, RFC 5669 §4, RFC 6188 §3, RFC 6904 §4.1) and the per-packet
//! primitives: AES-CM / NULL with HMAC-SHA1 (RFC 3711 §4.1.1, §4.2), AES-f8 (RFC 3711 §4.1.2),
//! AEAD AES-GCM (RFC 7714 §8, §9), SEED-CTR, SEED-CCM and SEED-GCM (RFC 5669), plus the header
//! extension keystream (RFC 6904 §3, RFC 7714 §8.3).

use only_crypto::aes::Aes;
use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha1;
use only_crypto::mac::Hmac;
use only_crypto::seed::{Seed, SeedCcm, SeedGcm};

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

/// E flag of the SRTCP index word.
pub(crate) const E_FLAG: u32 = 0x8000_0000;

/// The block cipher of the key derivation PRF: AES-CM (RFC 3711, RFC 6188) or SEED-CTR
/// (RFC 5669 §4). One per master key and rarely used: not worth boxing the AES key.
#[allow(clippy::large_enum_variant)]
enum Prf {
    Aes(Aes),
    Seed(Seed),
}

/// A master key and salt: the input of the PRF.
pub(crate) struct Master {
    prf: Prf,
    /// The master salt, left-aligned and zero-padded to 14 bytes (AES-GCM salts are 12 bytes).
    salt: [u8; 14],
}

impl Master {
    pub(crate) fn new(profile: Profile, key: &[u8], salt: &[u8]) -> Result<Master, Error> {
        if key.len() != profile.key_len() || salt.len() != profile.salt_len() {
            return Err(Error::KeyLength);
        }
        let prf = if profile.is_seed() {
            Prf::Seed(Seed::from_slice(key).map_err(|_| Error::KeyLength)?)
        } else {
            Prf::Aes(Aes::new(key).map_err(|_| Error::KeyLength)?)
        };
        let mut s = [0u8; 14];
        s[..salt.len()].copy_from_slice(salt);
        Ok(Master { prf, salt: s })
    }

    /// The PRF: `AES-CM(master_key, (master_salt XOR (label || r)) * 2^16)` truncated to
    /// `out.len()`, `label || r` right-aligned in the 112-bit salt field (`r`: index DIV key
    /// derivation rate, 48 bits). AES-128/192/256 follows the master key (RFC 6188); the SEED
    /// profiles use SEED-CTR the same way (RFC 5669 §4).
    pub(crate) fn prf(&self, label: u8, r: u64, out: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        iv[7] ^= label;
        for (d, s) in iv[8..14].iter_mut().zip(&r.to_be_bytes()[2..]) {
            *d ^= s;
        }
        out.fill(0);
        match &self.prf {
            Prf::Aes(aes) => aes.apply_ctr(&iv, out),
            Prf::Seed(seed) => seed.apply_ctr(&iv, out),
        }
    }
}

/// AES-f8 keys (RFC 3711 §4.1.2): the session key `k_e` for the keystream and `k_e XOR m`,
/// `m = k_s || 0x55…`, for the masked IV `IV' = E(k_e XOR m, IV)`.
pub(crate) struct F8 {
    aes: Aes,
    iv_aes: Aes,
}

impl F8 {
    pub(crate) fn new(key: &[u8], salt: &[u8]) -> Result<F8, Error> {
        if salt.len() > key.len() {
            return Err(Error::KeyLength);
        }
        let mut masked = [0x55u8; 32];
        masked[..salt.len()].copy_from_slice(salt);
        let masked = &mut masked[..key.len()];
        for (m, k) in masked.iter_mut().zip(key) {
            *m ^= k;
        }
        let f8 = F8 {
            aes: Aes::new(key).map_err(|_| Error::KeyLength)?,
            iv_aes: Aes::new(masked).map_err(|_| Error::KeyLength)?,
        };
        masked.fill(0);
        Ok(f8)
    }

    /// The keystream for `iv`, from its first byte.
    fn stream(&self, iv: &[u8; 16]) -> F8Stream<'_> {
        let mut ivp = *iv;
        self.iv_aes.encrypt_block(&mut ivp);
        F8Stream {
            aes: &self.aes,
            ivp,
            s: [0; 16],
            j: 0,
        }
    }
}

/// An f8 keystream being generated: `S(j) = E(k_e, IV' XOR j XOR S(j-1))`, `S(-1) = 0`. The
/// blocks depend on each other, so it only moves forward.
struct F8Stream<'a> {
    aes: &'a Aes,
    ivp: [u8; 16],
    /// `S(j-1)`, the block last generated (zero before the first).
    s: [u8; 16],
    /// Blocks generated so far.
    j: u32,
}

impl F8Stream<'_> {
    fn next_block(&mut self) {
        let mut b = self.ivp;
        for (b, s) in b.iter_mut().zip(&self.s) {
            *b ^= s;
        }
        for (b, j) in b[12..].iter_mut().zip(self.j.to_be_bytes()) {
            *b ^= j;
        }
        self.aes.encrypt_block(&mut b);
        self.s = b;
        self.j += 1;
    }

    /// XORs keystream bytes `at..at + data.len()` into `data`; `at` is not before the block
    /// last generated.
    fn xor_at(&mut self, at: usize, data: &mut [u8]) {
        let mut pos = at;
        let mut i = 0;
        while i < data.len() {
            let block = pos / 16;
            while self.j as usize <= block {
                self.next_block();
            }
            debug_assert_eq!(self.j as usize, block + 1);
            let off = pos % 16;
            let n = (16 - off).min(data.len() - i);
            for (d, k) in data[i..i + n].iter_mut().zip(&self.s[off..]) {
                *d ^= k;
            }
            i += n;
            pos += n;
        }
    }
}

/// The f8 SRTP IV (RFC 3711 §4.1.2.2): `0x00 || M || PT || SEQ || TS || SSRC || ROC`, from the
/// first twelve bytes of the RTP header.
pub(crate) fn f8_rtp_iv(head: &[u8], roc: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[1..12].copy_from_slice(&head[1..12]);
    iv[12..].copy_from_slice(&roc.to_be_bytes());
    iv
}

/// The f8 SRTCP IV (RFC 3711 §4.1.2.3): `0..0 || E || SRTCP index || V || P || RC || PT ||
/// length || SSRC`, from the E flag and index word and the first eight bytes of the packet.
fn f8_rtcp_iv(head: &[u8], word: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[4..8].copy_from_slice(&word.to_be_bytes());
    iv[8..].copy_from_slice(&head[..8]);
    iv
}

/// The encryption transform of one session. The AES-GCM key and the f8 key pair are boxed:
/// their own allocation keeps the layout of their tables independent of where the session sits
/// (measurably faster for small packets than embedding the GCM key).
#[allow(clippy::large_enum_variant)]
pub(crate) enum Enc {
    Null,
    Cm(Aes),
    F8(Box<F8>),
    Gcm(Box<AesGcm>),
    SeedCtr(Seed),
    SeedCcm(SeedCcm),
    SeedGcm(SeedGcm),
}

/// The RFC 6904 header extension keystream generator: the payload's transform keyed with the
/// header key and salt (labels 6 and 7); SEED-CTR for the SEED AEAD profiles (RFC 6904 §3.2),
/// AES-CM for AES-GCM (RFC 7714 §8.3). AES-CM and SEED-CTR inline, as in [`Enc`].
#[allow(clippy::large_enum_variant)]
pub(crate) enum HdrCipher {
    Cm(Aes),
    F8(Box<F8>),
    SeedCtr(Seed),
}

/// The session keys of one stream type (SRTP or SRTCP) derived from one master key at one
/// `r`.
pub(crate) struct Session {
    pub(crate) enc: Enc,
    /// Session salt (12 bytes and 2 zero bytes for AEAD).
    pub(crate) salt: [u8; 14],
    /// HMAC-SHA1 keyed with the session authentication key (not for AEAD).
    pub(crate) auth: Option<Hmac<Sha1>>,
    /// RFC 6904 header extension keystream generator and header salt (SRTP only, when header
    /// extension encryption is configured and the profile encrypts).
    pub(crate) hdr: Option<(HdrCipher, [u8; 14])>,
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
                profile.session_salt_len()
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
            master.prf(LABEL_RTP_HDR_SALT, r, &mut hs[..s]);
            let cipher = if profile.is_seed() {
                HdrCipher::SeedCtr(Seed::from_slice(&hk[..k]).map_err(|_| Error::KeyLength)?)
            } else if profile.is_f8() {
                HdrCipher::F8(Box::new(F8::new(&hk[..k], &hs[..s])?))
            } else {
                HdrCipher::Cm(Aes::new(&hk[..k]).map_err(|_| Error::KeyLength)?)
            };
            session.hdr = Some((cipher, hs));
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
        let seed_key =
            || -> Result<&[u8; 16], Error> { key.try_into().map_err(|_| Error::KeyLength) };
        let enc = match profile {
            _ if !profile.encrypts() => Enc::Null,
            Profile::AeadAes128Gcm | Profile::AeadAes256Gcm => {
                Enc::Gcm(Box::new(AesGcm::new(key).map_err(|_| Error::KeyLength)?))
            }
            Profile::SeedCtrHmacSha1_80 => Enc::SeedCtr(Seed::new(seed_key()?)),
            Profile::SeedCcm80 => Enc::SeedCcm(SeedCcm::new(seed_key()?)),
            Profile::SeedGcm96 => Enc::SeedGcm(SeedGcm::new(seed_key()?)),
            _ if profile.is_f8() => Enc::F8(Box::new(F8::new(key, salt)?)),
            _ => Enc::Cm(Aes::new(key).map_err(|_| Error::KeyLength)?),
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

    /// Encrypts `buf[aad..]` of an SRTP packet (AEAD: `buf[..aad]` is the associated data and
    /// the tag is appended). `buf` starts with the RTP header (f8 takes its IV from it).
    #[inline(always)]
    pub(crate) fn seal_rtp(
        &self,
        buf: &mut Vec<u8>,
        aad: usize,
        ssrc: u32,
        roc: u32,
        seq: u16,
    ) -> Result<(), Error> {
        match &self.enc {
            Enc::Null => {}
            Enc::Cm(aes) => {
                aes.apply_ctr(&cm_iv(&self.salt, ssrc, index(roc, seq)), &mut buf[aad..]);
            }
            Enc::SeedCtr(seed) => {
                seed.apply_ctr(&cm_iv(&self.salt, ssrc, index(roc, seq)), &mut buf[aad..]);
            }
            Enc::F8(f8) => {
                let iv = f8_rtp_iv(buf, roc);
                f8.stream(&iv).xor_at(0, &mut buf[aad..]);
            }
            Enc::Gcm(_) | Enc::SeedCcm(_) | Enc::SeedGcm(_) => {
                let iv = gcm_rtp_iv(&self.salt, ssrc, roc, seq);
                let (a, body) = buf.split_at_mut(aad);
                let (tag, n) = self.aead_seal(&iv, a, body)?;
                buf.extend_from_slice(&tag[..n]);
            }
        }
        Ok(())
    }

    /// Decrypts `buf[aad..]` of an SRTP packet (`buf` starts with the RTP header); for AEAD
    /// verifies `tag` first (SEED-CCM: after decrypting, zeroing `buf[aad..]` on failure).
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
            Enc::SeedCtr(seed) => {
                seed.apply_ctr(&cm_iv(&self.salt, ssrc, index(roc, seq)), &mut buf[aad..]);
                Ok(())
            }
            Enc::F8(f8) => {
                let iv = f8_rtp_iv(buf, roc);
                f8.stream(&iv).xor_at(0, &mut buf[aad..]);
                Ok(())
            }
            Enc::Gcm(_) | Enc::SeedCcm(_) | Enc::SeedGcm(_) => {
                let iv = gcm_rtp_iv(&self.salt, ssrc, roc, seq);
                let (a, body) = buf.split_at_mut(aad);
                self.aead_open(&iv, a, body, tag)
            }
        }
    }

    /// AEAD sessions: encrypts `body` and returns the tag (its first `n` bytes).
    pub(crate) fn aead_seal(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<([u8; 16], usize), Error> {
        match &self.enc {
            Enc::Gcm(g) => Ok((g.encrypt_in_place_detached(iv, aad, body), 16)),
            Enc::SeedGcm(g) => Ok((g.encrypt_in_place_detached(iv, aad, body), 12)),
            Enc::SeedCcm(c) => {
                let mut tag = [0u8; 16];
                c.encrypt_in_place_detached(iv, aad, body, &mut tag[..10])
                    .map_err(|_| Error::Malformed)?;
                Ok((tag, 10))
            }
            _ => Err(Error::Unsupported),
        }
    }

    /// AEAD sessions: verifies `tag` over `aad` and `body` and decrypts `body`.
    pub(crate) fn aead_open(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let opened = match &self.enc {
            Enc::Gcm(g) => g.decrypt_in_place_detached(iv, aad, body, tag),
            Enc::SeedGcm(g) => g.decrypt_in_place_detached(iv, aad, body, tag),
            Enc::SeedCcm(c) => c.decrypt_in_place_detached(iv, aad, body, tag),
            _ => return Err(Error::Unsupported),
        };
        opened.map_err(|_| Error::Authentication)
    }

    /// HMAC-SHA1 over `parts` (not for AEAD sessions).
    #[inline]
    pub(crate) fn mac(&self, a: &[u8], b: &[u8]) -> [u8; 20] {
        match &self.auth {
            Some(h) => h.clone().chain(a).chain(b).finalize(),
            None => [0; 20],
        }
    }

    /// Encrypts or decrypts `body` (everything after the first 8 bytes, `head`) of an SRTCP
    /// packet with a non-AEAD session; `word` is the E flag and SRTCP index.
    #[inline]
    pub(crate) fn crypt_rtcp(&self, head: &[u8], word: u32, body: &mut [u8], ssrc: u32) {
        let idx = u64::from(word & !E_FLAG);
        match &self.enc {
            Enc::Cm(aes) => aes.apply_ctr(&cm_iv(&self.salt, ssrc, idx), body),
            Enc::SeedCtr(seed) => seed.apply_ctr(&cm_iv(&self.salt, ssrc, idx), body),
            Enc::F8(f8) => f8.stream(&f8_rtcp_iv(head, word)).xor_at(0, body),
            _ => {}
        }
    }

    /// RFC 6904: XORs the masked header extension keystream into the extension elements of
    /// `ext` (an RFC 8285 header extension, its 4-byte header included) whose IDs are in
    /// `ids`; `head` is the packet's fixed header, `roc` its rollover counter. Does nothing
    /// without header keys or for a profile that is not RFC 8285.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when an element runs past the end of the extension.
    #[inline]
    pub(crate) fn crypt_header_extension(
        &self,
        ids: &[u64; 4],
        ext: &mut [u8],
        head: &[u8],
        roc: u32,
    ) -> Result<(), Error> {
        match &self.hdr {
            Some((cipher, salt)) => crypt_elements(cipher, salt, ids, ext, head, roc),
            None => Ok(()),
        }
    }
}

/// The header extension keystream of one packet, read at increasing offsets.
enum HdrStream<'a> {
    Cm(&'a Aes, u128),
    SeedCtr(&'a Seed, u128),
    F8(F8Stream<'a>),
}

impl HdrStream<'_> {
    /// XORs keystream bytes `at..at + data.len()` (at most 256) into `data`.
    fn xor_at(&mut self, at: usize, data: &mut [u8]) {
        let iv = match self {
            HdrStream::F8(s) => return s.xor_at(at, data),
            HdrStream::Cm(_, iv) | HdrStream::SeedCtr(_, iv) => *iv,
        };
        // Keystream bytes at..at+len: the block holding `at`, then onwards.
        let mut ks = [0u8; 16 + 256];
        let skip = at % 16;
        let ctr = iv.wrapping_add((at / 16) as u128).to_be_bytes();
        let ks = &mut ks[..skip + data.len()];
        match self {
            HdrStream::Cm(aes, _) => aes.apply_ctr(&ctr, ks),
            HdrStream::SeedCtr(seed, _) => seed.apply_ctr(&ctr, ks),
            HdrStream::F8(_) => {}
        }
        for (d, k) in data.iter_mut().zip(&ks[skip..]) {
            *d ^= k;
        }
    }
}

/// [`Session::crypt_header_extension`] with header keys.
#[inline(never)]
fn crypt_elements(
    cipher: &HdrCipher,
    salt: &[u8; 14],
    ids: &[u64; 4],
    ext: &mut [u8],
    head: &[u8],
    roc: u32,
) -> Result<(), Error> {
    let profile = u16::from_be_bytes([ext[0], ext[1]]);
    let two_byte = match profile {
        0xbede => false,
        p if p & 0xfff0 == 0x1000 => true,
        _ => return Ok(()),
    };
    let ssrc = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let idx = index(roc, u16::from_be_bytes([head[2], head[3]]));
    let ctr = || u128::from_be_bytes(cm_iv(salt, ssrc, idx));
    let mut ks = match cipher {
        HdrCipher::Cm(aes) => HdrStream::Cm(aes, ctr()),
        HdrCipher::SeedCtr(seed) => HdrStream::SeedCtr(seed, ctr()),
        HdrCipher::F8(f8) => HdrStream::F8(f8.stream(&f8_rtp_iv(head, roc))),
    };
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
            ks.xor_at(at, &mut data[at..at + len]);
        }
        i = at + len;
    }
    Ok(())
}

fn index(roc: u32, seq: u16) -> u64 {
    (u64::from(roc) << 16) | u64::from(seq)
}

/// AES-CM / SEED-CTR IV (RFC 3711 §4.1.1): `(k_s * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)`.
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

/// RFC 7714 §8.1, RFC 5669 §3.1: `(00 00 || SSRC || ROC || SEQ) XOR salt`.
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

/// RFC 7714 §9.1, RFC 5669 §3.2: `(00 00 || SSRC || 00 00 || 0 || SRTCP index) XOR salt`.
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
            HdrCipher::Cm(Aes::new(&hex("549752054D6FB708622C4A2E596A1B93")).unwrap()),
            hex("AB01818174C40D39A3781F7C2D27").try_into().unwrap(),
        ));
        let head = hex("80001234 00000000 cafebabe");
        let head1 = hex("80000001 00000000 00000001");
        let mut ids = [0u64; 4];
        for id in [1, 3, 4] {
            ids[0] |= 1 << id;
        }
        let plain = hex("BEDE0006 17414273A475262748220000C8308E4655996386B395FB00");
        let mut ext = plain.clone();
        s.crypt_header_extension(&ids, &mut ext, &head, 0).unwrap();
        assert_eq!(
            ext,
            hex("BEDE0006 17588A9270F4E15E1C220000C8309546A994F0BC54789700")
        );
        s.crypt_header_extension(&ids, &mut ext, &head, 0).unwrap();
        assert_eq!(ext, plain);
        // An element running past the end.
        let mut bad = hex("BEDE0001 1F000000");
        assert_eq!(
            s.crypt_header_extension(&ids, &mut bad, &head1, 0),
            Err(Error::Malformed)
        );
        // Not RFC 8285: untouched.
        let mut other = hex("ABCD0001 11223344");
        s.crypt_header_extension(&ids, &mut other, &head1, 0)
            .unwrap();
        assert_eq!(other, hex("ABCD0001 11223344"));
    }

    /// RFC 3711 Appendix B.1: the AES-f8 keystream, with the appendix's 32-bit salt; read in
    /// pieces at increasing offsets (as RFC 6904 elements are) it is the same.
    #[test]
    fn rfc3711_b1_f8() {
        let f8 = F8::new(&hex("234829008467be186c3de14aae72d62c"), &hex("32f2870d")).unwrap();
        let iv = f8_rtp_iv(&hex("806e5cba50681de55c621599"), 0xd462_564a);
        assert_eq!(iv.to_vec(), hex("006e5cba50681de55c621599d462564a"));
        let mut s = f8.stream(&iv);
        assert_eq!(s.ivp.to_vec(), hex("595b699bbd3bc0df26062093c1ad8f73"));
        let mut p =
            hex("70736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67");
        s.xor_at(0, &mut p);
        assert_eq!(
            p,
            hex("019ce7a26e7854014a6366aa95d4eefd1ad4172a14f9faf455b7f1d4b62bd08f562c0eef7c4802")
        );
        let mut full = [0u8; 80];
        f8.stream(&iv).xor_at(0, &mut full);
        let mut pieces = [0u8; 80];
        let mut s = f8.stream(&iv);
        for (from, to) in [(0, 5), (5, 16), (16, 17), (20, 21), (40, 41), (41, 80)] {
            s.xor_at(from, &mut pieces[from..to]);
        }
        for (from, to) in [(0, 17), (20, 21), (40, 80)] {
            assert_eq!(pieces[from..to], full[from..to]);
        }
        assert_eq!(
            f8_rtcp_iv(&hex("80c80006cafebabe"), 0x8000_0005).to_vec(),
            hex("00000000 80000005 80c80006cafebabe")
        );
        assert!(F8::new(&[0; 16], &[0; 17]).is_err());
    }

    /// The SEED-CTR PRF (RFC 5669 §4) on the RFC 3711 B.3 master key and salt, against the
    /// independent implementation of testdata/f8_seed.py (`kdf` lines).
    #[test]
    fn seed_ctr_prf() {
        let mut n = 0;
        for line in include_str!("../testdata/f8_seed.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            if f[0] != "kdf" {
                continue;
            }
            let want = hex(f[4]);
            let got = prf(
                Profile::SeedCtrHmacSha1_80,
                "E1F97A0D3E018BE0D64FA32C06DE4139",
                "0EC675AD498AFEEBB6960B3AABE6",
                f[2].parse().unwrap(),
                u64::from_str_radix(f[3], 16).unwrap(),
                want.len(),
            );
            assert_eq!(got, want, "{line}");
            n += 1;
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn wrong_lengths() {
        assert!(Master::new(Profile::AeadAes128Gcm, &[0; 16], &[0; 14]).is_err());
        assert!(Master::new(Profile::AeadAes256Gcm, &[0; 16], &[0; 12]).is_err());
        assert!(Master::new(Profile::Aes192CmHmacSha1_80, &[0; 24], &[0; 14]).is_ok());
        assert!(Master::new(Profile::NullHmacSha1_32, &[0; 16], &[0; 14]).is_ok());
        assert!(Master::new(Profile::SeedGcm96, &[0; 16], &[0; 14]).is_ok());
        assert!(Master::new(Profile::SeedGcm96, &[0; 16], &[0; 12]).is_err());
        assert!(Session::from_keys(Profile::SeedCcm80, &[0; 15], &[0; 12], &[]).is_err());
    }
}
