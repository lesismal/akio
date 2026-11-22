//! Types shared by CRLs and OCSP: revocation reasons and statuses, and the clock skew both
//! tolerate.

use crate::Error;

/// The clock skew tolerated by default when checking that a CRL or OCSP response is current
/// (thisUpdate in the future, nextUpdate in the past): 5 minutes.
pub const DEFAULT_CLOCK_SKEW: u32 = 300;

/// `CRLReason` (RFC 5280 §5.3.1), as carried by CRL entries and OCSP `RevokedInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RevocationReason {
    /// unspecified (0).
    Unspecified,
    /// keyCompromise (1).
    KeyCompromise,
    /// cACompromise (2).
    CaCompromise,
    /// affiliationChanged (3).
    AffiliationChanged,
    /// superseded (4).
    Superseded,
    /// cessationOfOperation (5).
    CessationOfOperation,
    /// certificateHold (6): suspended; a later delta CRL may lift it with removeFromCRL.
    CertificateHold,
    /// removeFromCRL (8): only meaningful in a delta CRL, lifts a hold.
    RemoveFromCrl,
    /// privilegeWithdrawn (9).
    PrivilegeWithdrawn,
    /// aACompromise (10).
    AaCompromise,
}

impl RevocationReason {
    /// The reason for an ENUMERATED value (7 is unused and rejected).
    pub fn from_code(v: u64) -> Result<RevocationReason, Error> {
        use RevocationReason as R;
        Ok(match v {
            0 => R::Unspecified,
            1 => R::KeyCompromise,
            2 => R::CaCompromise,
            3 => R::AffiliationChanged,
            4 => R::Superseded,
            5 => R::CessationOfOperation,
            6 => R::CertificateHold,
            8 => R::RemoveFromCrl,
            9 => R::PrivilegeWithdrawn,
            10 => R::AaCompromise,
            _ => return Err(Error::Encoding),
        })
    }

    /// The ENUMERATED value.
    #[must_use]
    pub fn code(self) -> u8 {
        use RevocationReason as R;
        match self {
            R::Unspecified => 0,
            R::KeyCompromise => 1,
            R::CaCompromise => 2,
            R::AffiliationChanged => 3,
            R::Superseded => 4,
            R::CessationOfOperation => 5,
            R::CertificateHold => 6,
            R::RemoveFromCrl => 8,
            R::PrivilegeWithdrawn => 9,
            R::AaCompromise => 10,
        }
    }

    /// The bit of this reason in [`ReasonFlags`] (`None` for unspecified and removeFromCRL,
    /// which have none).
    #[must_use]
    pub fn flag(self) -> Option<ReasonFlags> {
        use RevocationReason as R;
        let bit = match self {
            R::Unspecified | R::RemoveFromCrl => return None,
            R::KeyCompromise => 1,
            R::CaCompromise => 2,
            R::AffiliationChanged => 3,
            R::Superseded => 4,
            R::CessationOfOperation => 5,
            R::CertificateHold => 6,
            R::PrivilegeWithdrawn => 7,
            R::AaCompromise => 8,
        };
        Some(ReasonFlags(1 << bit))
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RevocationReason as R;
        f.write_str(match self {
            R::Unspecified => "unspecified",
            R::KeyCompromise => "keyCompromise",
            R::CaCompromise => "cACompromise",
            R::AffiliationChanged => "affiliationChanged",
            R::Superseded => "superseded",
            R::CessationOfOperation => "cessationOfOperation",
            R::CertificateHold => "certificateHold",
            R::RemoveFromCrl => "removeFromCRL",
            R::PrivilegeWithdrawn => "privilegeWithdrawn",
            R::AaCompromise => "aACompromise",
        })
    }
}

/// `ReasonFlags` (RFC 5280 §4.2.1.13): bit `i` for named bit `i` (1 keyCompromise …
/// 8 aACompromise; bit 0 is unused).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ReasonFlags(pub u16);

impl ReasonFlags {
    /// Every reason (bits 1 to 8).
    pub const ALL: ReasonFlags = ReasonFlags(0x1fe);

    /// From the contents of a BIT STRING (the unused-bits byte first).
    pub(crate) fn from_bit_string(c: &[u8]) -> Result<ReasonFlags, Error> {
        let (&unused, bits) = c.split_first().ok_or(Error::Encoding)?;
        if unused > 7 || bits.len() > 2 || (bits.is_empty() && unused != 0) {
            return Err(Error::Encoding);
        }
        let mut v = 0u16;
        for (i, b) in bits.iter().enumerate() {
            for j in 0..8 {
                if b & (0x80 >> j) != 0 {
                    v |= 1 << (8 * i + j);
                }
            }
        }
        Ok(ReasonFlags(v & Self::ALL.0))
    }

    /// The BIT STRING encoding (named-bit list, trailing zeros cut): `(bytes, bit count)`.
    pub(crate) fn to_bits(self) -> (Vec<u8>, usize) {
        let v = self.0 & Self::ALL.0;
        let nbits = 16 - v.leading_zeros() as usize;
        let mut bytes = vec![0u8; nbits.div_ceil(8)];
        for i in 0..nbits {
            if v & (1 << i) != 0 {
                bytes[i / 8] |= 0x80 >> (i % 8);
            }
        }
        (bytes, nbits)
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub fn contains(self, other: ReasonFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union.
    #[must_use]
    pub fn union(self, other: ReasonFlags) -> ReasonFlags {
        ReasonFlags(self.0 | other.0)
    }
}

/// The revocation status of one certificate, from a CRL set or an OCSP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Not revoked, according to current, authentic information.
    Good,
    /// Revoked (or on hold) since `time` (Unix seconds).
    Revoked {
        /// revocationDate / revocationTime, Unix seconds.
        time: i64,
        /// The reason, when given.
        reason: Option<RevocationReason>,
    },
    /// No current, authentic information covers the certificate (no CRL in scope, a stale
    /// one, or an OCSP responder that does not know it).
    Unknown,
}

/// Compares two non-negative DER INTEGER contents by value.
pub(crate) fn uint_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let strip = |x: &[u8]| -> usize { x.iter().take_while(|&&b| b == 0).count() };
    let (a, b) = (&a[strip(a)..], &b[strip(b)..]);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Whether information valid from `this_update` to `next_update` is current at `now`, give or
/// take `skew` seconds.
pub(crate) fn is_current(this_update: i64, next_update: i64, now: i64, skew: i64) -> bool {
    this_update <= now.saturating_add(skew) && now.saturating_sub(skew) <= next_update
}
