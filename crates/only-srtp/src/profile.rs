//! Protection profiles (RFC 5764 §4.1.2, RFC 7714 §14.2).

/// An SRTP protection profile as negotiated by DTLS-SRTP (`use_srtp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001): AES-128 counter mode, 80-bit HMAC-SHA1 tags.
    Aes128CmHmacSha1_80,
    /// `SRTP_AES128_CM_HMAC_SHA1_32` (0x0002): as above with 32-bit SRTP tags (SRTCP keeps
    /// 80-bit tags, RFC 5764 §4.1.2).
    Aes128CmHmacSha1_32,
    /// `SRTP_AEAD_AES_128_GCM` (0x0007, RFC 7714).
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM` (0x0008, RFC 7714).
    AeadAes256Gcm,
}

impl Profile {
    /// Every profile, most preferred first (the AEAD profiles, then the AES-CM ones).
    pub const ALL: [Profile; 4] = [
        Profile::AeadAes128Gcm,
        Profile::AeadAes256Gcm,
        Profile::Aes128CmHmacSha1_80,
        Profile::Aes128CmHmacSha1_32,
    ];

    /// The IANA DTLS-SRTP protection profile id.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Profile::Aes128CmHmacSha1_80 => 0x0001,
            Profile::Aes128CmHmacSha1_32 => 0x0002,
            Profile::AeadAes128Gcm => 0x0007,
            Profile::AeadAes256Gcm => 0x0008,
        }
    }

    /// The profile with IANA id `id`, if supported.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Profile> {
        match id {
            0x0001 => Some(Profile::Aes128CmHmacSha1_80),
            0x0002 => Some(Profile::Aes128CmHmacSha1_32),
            0x0007 => Some(Profile::AeadAes128Gcm),
            0x0008 => Some(Profile::AeadAes256Gcm),
            _ => None,
        }
    }

    /// The registered name, for example `SRTP_AEAD_AES_128_GCM`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Profile::Aes128CmHmacSha1_80 => "SRTP_AES128_CM_HMAC_SHA1_80",
            Profile::Aes128CmHmacSha1_32 => "SRTP_AES128_CM_HMAC_SHA1_32",
            Profile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            Profile::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
        }
    }

    /// Master (and session) key length in bytes.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Profile::AeadAes256Gcm => 32,
            _ => 16,
        }
    }

    /// Master (and session) salt length in bytes: 14 for AES-CM, 12 for AEAD.
    #[must_use]
    pub fn salt_len(self) -> usize {
        if self.is_aead() { 12 } else { 14 }
    }

    /// Bytes added to an RTP packet by [`Context::protect_rtp`](crate::Context::protect_rtp):
    /// the authentication tag (10, 4, 16, 16).
    #[must_use]
    pub fn rtp_tag_len(self) -> usize {
        match self {
            Profile::Aes128CmHmacSha1_80 => 10,
            Profile::Aes128CmHmacSha1_32 => 4,
            Profile::AeadAes128Gcm | Profile::AeadAes256Gcm => 16,
        }
    }

    /// SRTCP authentication tag length: 10 for both AES-CM profiles, 16 for AEAD.
    #[must_use]
    pub fn rtcp_tag_len(self) -> usize {
        if self.is_aead() { 16 } else { 10 }
    }

    /// Length of the DTLS-SRTP keying material to export for this profile
    /// (`2 * (key_len + salt_len)`, RFC 5764 §4.2).
    #[must_use]
    pub fn keying_material_len(self) -> usize {
        2 * (self.key_len() + self.salt_len())
    }

    /// Whether this is an AEAD (AES-GCM) profile.
    #[must_use]
    pub fn is_aead(self) -> bool {
        matches!(self, Profile::AeadAes128Gcm | Profile::AeadAes256Gcm)
    }

    pub(crate) fn auth_key_len(self) -> usize {
        if self.is_aead() { 0 } else { 20 }
    }
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn ids_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::from_id(p.id()), Some(p));
            assert!(p.name().starts_with("SRTP_"));
        }
        assert_eq!(Profile::from_id(3), None);
        assert_eq!(Profile::AeadAes256Gcm.keying_material_len(), 88);
        assert_eq!(Profile::Aes128CmHmacSha1_80.keying_material_len(), 60);
    }
}
