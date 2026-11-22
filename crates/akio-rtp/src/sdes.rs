//! SDES items (RFC 3550 §6.5 and the IANA "RTCP SDES Item Types" registry): typed views of
//! the `(item type, text)` pairs of [`Rtcp::SourceDescription`](crate::Rtcp), including
//! PRIV's prefix / value structure (§6.5.8), and RFC 7022 random CNAMEs.
//!
//! On the wire every item is a type octet, a length octet and up to 255 octets of UTF-8
//! text; a chunk's list ends with a null octet and is padded with more to 32 bits. In the
//! pair form, PRIV's text starts with the prefix length as a `char` (U+0000..=U+00FF, one
//! octet on the wire, so prefixes up to 255 octets survive a round trip), then the prefix
//! and the value.

/// A typed SDES item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SdesItem {
    /// An item whose content is one text string: every registered type but PRIV
    /// ([`SdesItem::CNAME`] .. [`SdesItem::NOTE`], [`SdesItem::H323_CADDR`] ..
    /// [`SdesItem::MID`]) and unassigned ones.
    Text {
        /// The item type (never 0 or 8).
        item_type: u8,
        /// The text.
        text: String,
    },
    /// PRIV (8): a private extension, named by `prefix` (RFC 3550 §6.5.8: a short name
    /// registered or derived from a domain) and carrying `value`. Together at most 254
    /// octets.
    Priv {
        /// The extension's name.
        prefix: String,
        /// Its value.
        value: String,
    },
}

/// Cuts `s` to at most `max` bytes at a character boundary.
pub(crate) fn truncate(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

impl SdesItem {
    /// END: terminates an item list (never an item).
    pub const END: u8 = 0;
    /// Canonical endpoint identifier (RFC 3550 §6.5.1; RFC 7022 for choosing one).
    pub const CNAME: u8 = 1;
    /// User name (§6.5.2).
    pub const NAME: u8 = 2;
    /// Electronic mail address (§6.5.3).
    pub const EMAIL: u8 = 3;
    /// Phone number (§6.5.4).
    pub const PHONE: u8 = 4;
    /// Geographic location (§6.5.5).
    pub const LOC: u8 = 5;
    /// Application or tool name (§6.5.6).
    pub const TOOL: u8 = 6;
    /// Notice / status (§6.5.7).
    pub const NOTE: u8 = 7;
    /// Private extensions (§6.5.8).
    pub const PRIV: u8 = 8;
    /// H.323 callable address.
    pub const H323_CADDR: u8 = 9;
    /// Application specific identifier (RFC 6776).
    pub const APSI: u8 = 10;
    /// Reporting group identifier (RFC 8861).
    pub const RGRP: u8 = 11;
    /// RTP stream identifier (RFC 8852).
    pub const RTP_STREAM_ID: u8 = 12;
    /// Repaired RTP stream identifier (RFC 8852).
    pub const REPAIRED_RTP_STREAM_ID: u8 = 13;
    /// CLUE capture identifier (RFC 8849).
    pub const CCID: u8 = 14;
    /// Media identification (RFC 9143).
    pub const MID: u8 = 15;

    /// A text item of type `item_type`.
    #[must_use]
    pub fn text(item_type: u8, text: impl Into<String>) -> SdesItem {
        SdesItem::Text {
            item_type,
            text: text.into(),
        }
    }

    /// A CNAME item.
    #[must_use]
    pub fn cname(text: impl Into<String>) -> SdesItem {
        SdesItem::text(SdesItem::CNAME, text)
    }

    /// A PRIV item.
    #[must_use]
    pub fn private(prefix: impl Into<String>, value: impl Into<String>) -> SdesItem {
        SdesItem::Priv {
            prefix: prefix.into(),
            value: value.into(),
        }
    }

    /// The item type.
    #[must_use]
    pub fn item_type(&self) -> u8 {
        match self {
            SdesItem::Text { item_type, .. } => *item_type,
            SdesItem::Priv { .. } => SdesItem::PRIV,
        }
    }

    /// The typed form of a pair from [`Rtcp::SourceDescription`](crate::Rtcp). A PRIV
    /// item whose prefix length does not fit (or is missing) stays a text item of type 8.
    #[must_use]
    pub fn from_pair(item_type: u8, text: &str) -> SdesItem {
        if item_type == SdesItem::PRIV {
            let mut chars = text.chars();
            if let Some(n) = chars.next().and_then(|c| u8::try_from(u32::from(c)).ok()) {
                let rest = chars.as_str();
                let n = usize::from(n);
                if n <= rest.len() && rest.is_char_boundary(n) {
                    return SdesItem::private(&rest[..n], &rest[n..]);
                }
            }
        }
        SdesItem::text(item_type, text)
    }

    /// The pair form for [`Rtcp::SourceDescription`](crate::Rtcp). A PRIV item longer than
    /// the 255 octets an item holds loses the end of its value (and of its prefix past 254
    /// octets), at character boundaries.
    #[must_use]
    pub fn to_pair(&self) -> (u8, String) {
        match self {
            SdesItem::Text { item_type, text } => (*item_type, text.clone()),
            SdesItem::Priv { prefix, value } => {
                let prefix = truncate(prefix, 254);
                let value = truncate(value, 254 - prefix.len());
                let mut s = String::with_capacity(2 + prefix.len() + value.len());
                s.push(char::from(prefix.len() as u8));
                s.push_str(prefix);
                s.push_str(value);
                (SdesItem::PRIV, s)
            }
        }
    }
}

/// A CNAME per RFC 7022 §4.2 (short-term persistent): the 96 random bits `random`
/// (from a cryptographically secure generator, new for every session) in base64, 16
/// characters.
#[must_use]
pub fn random_cname(random: &[u8; 12]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(16);
    for c in random.chunks_exact(3) {
        let v = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            s.push(char::from(B64[(v >> shift) as usize & 63]));
        }
    }
    s
}

/// The text of a PRIV item read from the wire (`octets` after the length octet): the
/// prefix length octet becomes a `char`, so lengths above 127 survive.
pub(crate) fn priv_text(octets: &[u8]) -> String {
    match octets.split_first() {
        None => String::new(),
        Some((&n, rest)) => {
            let mut s = String::with_capacity(octets.len() + 1);
            s.push(char::from(n));
            s.push_str(&String::from_utf8_lossy(rest));
            s
        }
    }
}

/// The octets of an item's text on the wire (at most 255): for PRIV the leading `char` up
/// to U+00FF becomes the prefix length octet.
pub(crate) fn wire_octets(item_type: u8, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().min(255));
    let mut rest = text;
    if item_type == SdesItem::PRIV {
        let mut chars = text.chars();
        if let Some(n) = chars.next().and_then(|c| u8::try_from(u32::from(c)).ok()) {
            out.push(n);
            rest = chars.as_str();
        }
    }
    out.extend_from_slice(truncate(rest, 255 - out.len()).as_bytes());
    out
}
