//! GSS-API authentication (RFC 1961, ADR-071): the application supplies the mechanism.
//!
//! A [`GssContext`] is one security context: wrap the system's GSS-API library (MIT or Heimdal
//! Kerberos, through a binding of the application's choice), SSPI, or any other mechanism.
//! only-socks runs the RFC 1961 exchange around it: method selection, the context tokens, the
//! protection-level negotiation and, at levels other than [`Protection::None`], the
//! per-message wrapping of the SOCKS request, its replies and the whole tunnel.
//!
//! * Server: [`Socks::gssapi`](crate::Socks::gssapi) — the factory makes an acceptor context
//!   per connection; its [`peer_name`](GssContext::peer_name) is the user the access-control
//!   hook sees.
//! * Client: [`SocksClient::gssapi`](crate::SocksClient::gssapi) — the factory makes an
//!   initiator context for the proxy's host name (Kerberos: the service principal is usually
//!   `rcmd@<proxy host>` for Dante, or whatever the proxy's keytab holds).
//!
//! Establishment steps ([`GssContext::step`]) may block — a Kerberos initiator may ask the KDC
//! for a ticket — so they never run on an I/O thread: the server runs them on the logical
//! pool, the client on a short-lived helper thread per step. `wrap` / `unwrap` run on the I/O
//! thread for every message and must not block.
//!
//! ```
//! use only_socks::gssapi::{GssContext, GssStep};
//! use std::io;
//!
//! /// A mechanism that accepts anyone and protects nothing: shows the shape only.
//! struct Anyone;
//!
//! impl GssContext for Anyone {
//!     fn step(&mut self, _token: &[u8]) -> io::Result<GssStep> {
//!         Ok(GssStep::Complete(Vec::new()))
//!     }
//!     fn wrap(&mut self, _confidential: bool, msg: &[u8]) -> io::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//!     fn unwrap(&mut self, token: &[u8]) -> io::Result<Vec<u8>> {
//!         Ok(token.to_vec())
//!     }
//! }
//! ```

pub use only_ws::gss::{GssContext, GssStep, Protection};

// Internal: the messages and the protection layer, shared with the client in only-ws.
pub(crate) use only_ws::gss::{
    ABORT, GssLayer, MTYP_AUTH, MTYP_PROTECTION, parse_msg, protection_msg, protection_of, push_msg,
};

/// The server's factory: one acceptor context per connection.
pub(crate) type ServerFactory =
    std::sync::Arc<dyn Fn() -> std::io::Result<Box<dyn GssContext>> + Send + Sync>;
