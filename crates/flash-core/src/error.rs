use std::{fmt, io};

/// Errors returned by connection operations.
#[derive(Debug)]
pub enum Error {
    /// The connection is closed (or closing); the operation had no effect.
    Closed,
    /// The logical pool queue or the connection's send queue is over its limit.
    Overloaded,
    /// An OS-level error.
    Io(io::Error),
}

/// Shorthand result type.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Closed => f.write_str("connection closed"),
            Error::Overloaded => f.write_str("overloaded"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_conversion() {
        assert_eq!(Error::Closed.to_string(), "connection closed");
        assert_eq!(Error::Overloaded.to_string(), "overloaded");
        let e: Error = io::Error::new(io::ErrorKind::BrokenPipe, "pipe").into();
        assert!(matches!(e, Error::Io(ref x) if x.kind() == io::ErrorKind::BrokenPipe));
        assert_eq!(e.to_string(), "io error: pipe");
        let dynerr: &dyn std::error::Error = &e;
        assert!(dynerr.source().is_none());
    }
}
