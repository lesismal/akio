//! Errors and alerts.

use std::fmt;

/// A TLS alert description (RFC 5246 §7.2, RFC 5746, RFC 7301, RFC 8446 §6, RFC 4279).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AlertDescription {
    /// `close_notify` (0).
    CloseNotify,
    /// `unexpected_message` (10).
    UnexpectedMessage,
    /// `bad_record_mac` (20).
    BadRecordMac,
    /// `record_overflow` (22).
    RecordOverflow,
    /// `handshake_failure` (40).
    HandshakeFailure,
    /// `bad_certificate` (42).
    BadCertificate,
    /// `unsupported_certificate` (43).
    UnsupportedCertificate,
    /// `certificate_revoked` (44).
    CertificateRevoked,
    /// `certificate_expired` (45).
    CertificateExpired,
    /// `certificate_unknown` (46).
    CertificateUnknown,
    /// `illegal_parameter` (47).
    IllegalParameter,
    /// `unknown_ca` (48).
    UnknownCa,
    /// `access_denied` (49).
    AccessDenied,
    /// `decode_error` (50).
    DecodeError,
    /// `decrypt_error` (51).
    DecryptError,
    /// `too_many_cids_requested` (52, RFC 9147 §9).
    TooManyCidsRequested,
    /// `protocol_version` (70).
    ProtocolVersion,
    /// `insufficient_security` (71).
    InsufficientSecurity,
    /// `internal_error` (80).
    InternalError,
    /// `user_canceled` (90).
    UserCanceled,
    /// `no_renegotiation` (100).
    NoRenegotiation,
    /// `unsupported_extension` (110).
    UnsupportedExtension,
    /// `missing_extension` (109).
    MissingExtension,
    /// `unknown_psk_identity` (115).
    UnknownPskIdentity,
    /// Any other code.
    Other(u8),
}

impl AlertDescription {
    /// The wire code.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        use AlertDescription as A;
        match self {
            A::CloseNotify => 0,
            A::UnexpectedMessage => 10,
            A::BadRecordMac => 20,
            A::RecordOverflow => 22,
            A::HandshakeFailure => 40,
            A::BadCertificate => 42,
            A::UnsupportedCertificate => 43,
            A::CertificateRevoked => 44,
            A::CertificateExpired => 45,
            A::CertificateUnknown => 46,
            A::IllegalParameter => 47,
            A::UnknownCa => 48,
            A::AccessDenied => 49,
            A::DecodeError => 50,
            A::DecryptError => 51,
            A::TooManyCidsRequested => 52,
            A::ProtocolVersion => 70,
            A::InsufficientSecurity => 71,
            A::InternalError => 80,
            A::UserCanceled => 90,
            A::NoRenegotiation => 100,
            A::UnsupportedExtension => 110,
            A::MissingExtension => 109,
            A::UnknownPskIdentity => 115,
            A::Other(v) => v,
        }
    }

    /// The description for a wire code.
    #[must_use]
    pub fn from_u8(v: u8) -> AlertDescription {
        use AlertDescription as A;
        match v {
            0 => A::CloseNotify,
            10 => A::UnexpectedMessage,
            20 => A::BadRecordMac,
            22 => A::RecordOverflow,
            40 => A::HandshakeFailure,
            42 => A::BadCertificate,
            43 => A::UnsupportedCertificate,
            44 => A::CertificateRevoked,
            45 => A::CertificateExpired,
            46 => A::CertificateUnknown,
            47 => A::IllegalParameter,
            48 => A::UnknownCa,
            49 => A::AccessDenied,
            50 => A::DecodeError,
            51 => A::DecryptError,
            52 => A::TooManyCidsRequested,
            70 => A::ProtocolVersion,
            71 => A::InsufficientSecurity,
            80 => A::InternalError,
            90 => A::UserCanceled,
            100 => A::NoRenegotiation,
            110 => A::UnsupportedExtension,
            109 => A::MissingExtension,
            115 => A::UnknownPskIdentity,
            v => A::Other(v),
        }
    }
}

impl fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} ({})", self.to_u8())
    }
}

/// Why a DTLS operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The peer sent a fatal alert.
    PeerAlert(AlertDescription),
    /// The peer violated the protocol; this alert was sent to it (fatal).
    Protocol {
        /// The alert sent.
        alert: AlertDescription,
        /// What went wrong.
        reason: &'static str,
    },
    /// The peer's certificate was rejected (missing, unparsable, or refused by the
    /// [`PeerVerifier`](crate::PeerVerifier)); a `bad_certificate` alert was sent.
    Certificate(String),
    /// The handshake did not complete within
    /// [`Config::handshake_timeout`](crate::Config::handshake_timeout).
    Timeout,
    /// Application data before the handshake completed.
    NotConnected,
    /// The connection is closed (close_notify sent or received, or a fatal error happened).
    Closed,
    /// A record larger than the 2^14-byte DTLS limit.
    TooLarge,
    /// The configuration cannot be used (for example a server without a certificate).
    Config(&'static str),
    /// The keying-material exporter was used before the handshake completed or with a
    /// reserved label.
    Exporter(&'static str),
    /// A cryptographic primitive failed (random number generator, invalid key).
    Crypto(akio_crypto::Error),
    /// The operation needs something this connection did not negotiate or is not in the
    /// state for (DTLS 1.3, connection IDs, the peer's `post_handshake_auth`, accepted early
    /// data, no request of the same kind outstanding).
    NotAvailable(&'static str),
}

impl Error {
    pub(crate) fn protocol(alert: AlertDescription, reason: &'static str) -> Error {
        Error::Protocol { alert, reason }
    }

    pub(crate) fn decode(reason: &'static str) -> Error {
        Error::protocol(AlertDescription::DecodeError, reason)
    }

    /// The alert this error sends to the peer, if any.
    pub(crate) fn alert(&self) -> Option<AlertDescription> {
        match self {
            Error::Protocol { alert, .. } => Some(*alert),
            Error::Certificate(_) => Some(AlertDescription::BadCertificate),
            Error::Crypto(_) => Some(AlertDescription::InternalError),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PeerAlert(a) => write!(f, "dtls: peer sent fatal alert {a}"),
            Error::Protocol { alert, reason } => write!(f, "dtls: {reason} (sent {alert})"),
            Error::Certificate(m) => write!(f, "dtls: peer certificate rejected: {m}"),
            Error::Timeout => f.write_str("dtls: handshake timed out"),
            Error::NotConnected => f.write_str("dtls: handshake not complete"),
            Error::Closed => f.write_str("dtls: connection closed"),
            Error::TooLarge => f.write_str("dtls: record larger than 16384 bytes"),
            Error::Config(m) => write!(f, "dtls: invalid configuration: {m}"),
            Error::NotAvailable(m) => write!(f, "dtls: not available: {m}"),
            Error::Exporter(m) => write!(f, "dtls: keying material exporter: {m}"),
            Error::Crypto(e) => write!(f, "dtls: crypto: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<akio_crypto::Error> for Error {
    fn from(e: akio_crypto::Error) -> Error {
        Error::Crypto(e)
    }
}
