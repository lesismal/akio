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
