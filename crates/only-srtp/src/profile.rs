//! Protection profiles (RFC 3711, RFC 5764 §4.1.2, RFC 6188, RFC 7714 §14.2).

/// An SRTP protection profile (crypto suite): as negotiated by DTLS-SRTP (`use_srtp`) or named
/// by SDP security descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// `AES_192_CM_HMAC_SHA1_80` (RFC 6188; SDP security descriptions only, no DTLS-SRTP id).
    Aes192CmHmacSha1_80,
    /// `AES_192_CM_HMAC_SHA1_32` (RFC 6188; SRTCP keeps 80-bit tags).
    Aes192CmHmacSha1_32,
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188; SDP security descriptions only, no DTLS-SRTP id).
    Aes256CmHmacSha1_80,
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188; SRTCP keeps 80-bit tags).
    Aes256CmHmacSha1_32,
    /// `SRTP_NULL_HMAC_SHA1_80` (0x0005): no encryption, 80-bit HMAC-SHA1 tags. Packets are
    /// authenticated only; for testing and debugging.
    NullHmacSha1_80,
    /// `SRTP_NULL_HMAC_SHA1_32` (0x0006): no encryption, 32-bit SRTP tags (80-bit SRTCP tags).
    NullHmacSha1_32,
}

impl Profile {
    /// Every profile: the four WebRTC profiles in preference order (AEAD, then AES-128-CM),
    /// then AES-256-CM and AES-192-CM, then the NULL cipher.
    pub const ALL: [Profile; 10] = [
        Profile::AeadAes128Gcm,
        Profile::AeadAes256Gcm,
        Profile::Aes128CmHmacSha1_80,
        Profile::Aes128CmHmacSha1_32,
        Profile::Aes256CmHmacSha1_80,
        Profile::Aes256CmHmacSha1_32,
        Profile::Aes192CmHmacSha1_80,
        Profile::Aes192CmHmacSha1_32,
        Profile::NullHmacSha1_80,
        Profile::NullHmacSha1_32,
    ];

    /// The IANA DTLS-SRTP protection profile id; `None` for the AES-192/256-CM profiles,
    /// which have none.
    #[must_use]
    pub fn id(self) -> Option<u16> {
        match self {
            Profile::Aes128CmHmacSha1_80 => Some(0x0001),
            Profile::Aes128CmHmacSha1_32 => Some(0x0002),
            Profile::NullHmacSha1_80 => Some(0x0005),
            Profile::NullHmacSha1_32 => Some(0x0006),
            Profile::AeadAes128Gcm => Some(0x0007),
            Profile::AeadAes256Gcm => Some(0x0008),
            Profile::Aes192CmHmacSha1_80
            | Profile::Aes192CmHmacSha1_32
            | Profile::Aes256CmHmacSha1_80
            | Profile::Aes256CmHmacSha1_32 => None,
        }
    }

    /// The profile with DTLS-SRTP id `id`, if supported.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.id() == Some(id))
    }

    /// The registered name: the DTLS-SRTP profile name (`SRTP_AEAD_AES_128_GCM`) when it has
    /// one, else the SDP security descriptions crypto suite (`AES_256_CM_HMAC_SHA1_80`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Profile::Aes128CmHmacSha1_80 => "SRTP_AES128_CM_HMAC_SHA1_80",
            Profile::Aes128CmHmacSha1_32 => "SRTP_AES128_CM_HMAC_SHA1_32",
            Profile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            Profile::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
            Profile::NullHmacSha1_80 => "SRTP_NULL_HMAC_SHA1_80",
            Profile::NullHmacSha1_32 => "SRTP_NULL_HMAC_SHA1_32",
            p => p.sdes_name().unwrap_or("?"),
        }
    }

    /// The SDP security descriptions crypto suite name (RFC 4568, RFC 6188, RFC 7714), for
    /// example `AES_CM_128_HMAC_SHA1_80`; `None` for the NULL profiles, which have none.
    #[must_use]
    pub fn sdes_name(self) -> Option<&'static str> {
        Some(match self {
            Profile::Aes128CmHmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Profile::Aes128CmHmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
            Profile::AeadAes128Gcm => "AEAD_AES_128_GCM",
            Profile::AeadAes256Gcm => "AEAD_AES_256_GCM",
            Profile::Aes192CmHmacSha1_80 => "AES_192_CM_HMAC_SHA1_80",
            Profile::Aes192CmHmacSha1_32 => "AES_192_CM_HMAC_SHA1_32",
            Profile::Aes256CmHmacSha1_80 => "AES_256_CM_HMAC_SHA1_80",
            Profile::Aes256CmHmacSha1_32 => "AES_256_CM_HMAC_SHA1_32",
            Profile::NullHmacSha1_80 | Profile::NullHmacSha1_32 => return None,
        })
    }

    /// The profile with SDP security descriptions crypto suite name `name`, if supported.
    #[must_use]
    pub fn from_sdes_name(name: &str) -> Option<Profile> {
        Profile::ALL
            .into_iter()
            .find(|p| p.sdes_name() == Some(name))
    }

    /// Master (and session) key length in bytes: 16, 24 or 32 (16 for the NULL profiles,
    /// whose master key still keys the key derivation).
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Profile::AeadAes256Gcm
            | Profile::Aes256CmHmacSha1_80
            | Profile::Aes256CmHmacSha1_32 => 32,
            Profile::Aes192CmHmacSha1_80 | Profile::Aes192CmHmacSha1_32 => 24,
            _ => 16,
        }
    }

    /// Master (and session) salt length in bytes: 12 for AEAD, 14 for the others.
    #[must_use]
    pub fn salt_len(self) -> usize {
        if self.is_aead() { 12 } else { 14 }
    }

    /// Length of the SRTP authentication tag appended by
    /// [`Context::protect_rtp`](crate::Context::protect_rtp): 16 for AEAD, 10 or 4 for the
    /// HMAC-SHA1 profiles (`_80` / `_32`). An MKI, when used, adds its length on top.
    #[must_use]
    pub fn rtp_tag_len(self) -> usize {
        match self {
            Profile::AeadAes128Gcm | Profile::AeadAes256Gcm => 16,
            Profile::Aes128CmHmacSha1_32
            | Profile::Aes192CmHmacSha1_32
            | Profile::Aes256CmHmacSha1_32
            | Profile::NullHmacSha1_32 => 4,
            _ => 10,
        }
    }

    /// SRTCP authentication tag length: 16 for AEAD, 10 for every HMAC-SHA1 profile.
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

    /// Whether packets are encrypted (false for the NULL profiles).
    #[must_use]
    pub fn encrypts(self) -> bool {
        !matches!(self, Profile::NullHmacSha1_80 | Profile::NullHmacSha1_32)
    }

    pub(crate) fn auth_key_len(self) -> usize {
        if self.is_aead() { 0 } else { 20 }
    }

    /// Session encryption key length (0 for NULL).
    pub(crate) fn cipher_key_len(self) -> usize {
        if self.encrypts() { self.key_len() } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn ids_round_trip() {
        for p in Profile::ALL {
            if let Some(id) = p.id() {
                assert_eq!(Profile::from_id(id), Some(p));
                assert!(p.name().starts_with("SRTP_"));
            } else {
                assert_eq!(Some(p.name()), p.sdes_name());
            }
            if let Some(n) = p.sdes_name() {
                assert_eq!(Profile::from_sdes_name(n), Some(p));
            }
            assert!(p.rtp_tag_len() <= p.rtcp_tag_len());
        }
        assert_eq!(Profile::from_id(3), None);
        assert_eq!(Profile::from_sdes_name("F8_128_HMAC_SHA1_80"), None);
        assert_eq!(Profile::AeadAes256Gcm.keying_material_len(), 88);
        assert_eq!(Profile::Aes128CmHmacSha1_80.keying_material_len(), 60);
        assert_eq!(Profile::Aes192CmHmacSha1_32.keying_material_len(), 76);
        assert_eq!(Profile::NullHmacSha1_32.rtp_tag_len(), 4);
        assert!(!Profile::NullHmacSha1_80.encrypts());
    }
}
