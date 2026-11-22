//! The TLS protocol core, written from the RFCs on `akio-crypto` and `akio-x509`: record layer,
//! TLS 1.3 and TLS 1.2 handshake state machines, key schedules, session resumption.
//!
//! Internal: the stable API is the crate root. [`Connection`] is the byte-stream form;
//! `crate::quic` drives the same TLS 1.3 machines without records for QUIC.

pub(crate) mod alert;
pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod common;
pub(crate) mod conn;
pub(crate) mod kx;
pub(crate) mod msgs;
pub(crate) mod record;
pub(crate) mod server;
pub(crate) mod session;
pub(crate) mod sig;
pub mod suites;
pub(crate) mod tls12;

#[cfg(test)]
mod early_tests;
#[cfg(test)]
mod ext_tests;
#[cfg(test)]
mod revocation_tests;
#[cfg(test)]
mod rfc8448;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use alert::Fatal;
pub use common::{Keys, Level};
pub use conn::Connection;
#[cfg(feature = "ktls")]
pub use conn::{DirKeys, Offload, OffloadEvent};
pub use kx::Group;
