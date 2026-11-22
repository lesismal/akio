//! Alerts (RFC 8446 section 6, RFC 5246 section 7.2) and the fatal-error type of the core.

use std::fmt;

/// An alert description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Alert {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    NoRenegotiation,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
    /// Any other code.
    Other(u8),
}

impl Alert {
    /// The wire code.
    pub fn code(self) -> u8 {
        use Alert::*;
        match self {
            CloseNotify => 0,
            UnexpectedMessage => 10,
            BadRecordMac => 20,
            RecordOverflow => 22,
            HandshakeFailure => 40,
            BadCertificate => 42,
            UnsupportedCertificate => 43,
            CertificateRevoked => 44,
            CertificateExpired => 45,
            CertificateUnknown => 46,
            IllegalParameter => 47,
            UnknownCa => 48,
            AccessDenied => 49,
            DecodeError => 50,
            DecryptError => 51,
            ProtocolVersion => 70,
            InsufficientSecurity => 71,
            InternalError => 80,
            InappropriateFallback => 86,
            UserCanceled => 90,
            NoRenegotiation => 100,
            MissingExtension => 109,
            UnsupportedExtension => 110,
            UnrecognizedName => 112,
            BadCertificateStatusResponse => 113,
            UnknownPskIdentity => 115,
            CertificateRequired => 116,
            NoApplicationProtocol => 120,
            Other(c) => c,
        }
    }

    /// From the wire code.
    pub fn from_code(c: u8) -> Alert {
        use Alert::*;
        match c {
            0 => CloseNotify,
            10 => UnexpectedMessage,
            20 => BadRecordMac,
            22 => RecordOverflow,
            40 => HandshakeFailure,
            42 => BadCertificate,
            43 => UnsupportedCertificate,
            44 => CertificateRevoked,
            45 => CertificateExpired,
            46 => CertificateUnknown,
            47 => IllegalParameter,
            48 => UnknownCa,
            49 => AccessDenied,
            50 => DecodeError,
            51 => DecryptError,
            70 => ProtocolVersion,
            71 => InsufficientSecurity,
            80 => InternalError,
            86 => InappropriateFallback,
            90 => UserCanceled,
            100 => NoRenegotiation,
            109 => MissingExtension,
            110 => UnsupportedExtension,
            112 => UnrecognizedName,
            113 => BadCertificateStatusResponse,
            115 => UnknownPskIdentity,
            116 => CertificateRequired,
            120 => NoApplicationProtocol,
            c => Other(c),
        }
    }
}

/// A fatal protocol error: the alert to send (or the one the peer sent) and why.
#[derive(Clone, PartialEq, Eq)]
pub struct Fatal {
    /// The alert.
    pub alert: Alert,
    /// The peer sent the alert (nothing must be sent back).
    pub from_peer: bool,
    msg: String,
}

impl Fatal {
    pub(crate) fn new(alert: Alert, msg: impl Into<String>) -> Fatal {
        Fatal {
            alert,
            from_peer: false,
            msg: msg.into(),
        }
    }

    pub(crate) fn peer(alert: Alert) -> Fatal {
        Fatal {
            alert,
            from_peer: true,
            msg: String::new(),
        }
    }

    /// The human-readable reason.
    pub fn message(&self) -> &str {
        &self.msg
    }
}

impl fmt::Debug for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.from_peer {
            write!(f, "peer sent fatal alert {:?}", self.alert)
        } else {
            write!(f, "{} (alert {:?})", self.msg, self.alert)
        }
    }
}

impl std::error::Error for Fatal {}

/// Shorthand for an error with `alert`.
pub(crate) fn fatal<T>(alert: Alert, msg: &str) -> Result<T, Fatal> {
    Err(Fatal::new(alert, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_roundtrip() {
        for c in 0..=255u8 {
            assert_eq!(Alert::from_code(c).code(), c);
        }
        let f = Fatal::new(Alert::DecodeError, "x");
        assert!(f.to_string().contains("DecodeError"));
        assert!(
            Fatal::peer(Alert::HandshakeFailure)
                .to_string()
                .contains("peer")
        );
    }
}
