#![forbid(unsafe_code)]
//! flash core: connections, handlers and the backend-facing traits.
//!
//! * [`Handler`] and [`Acceptor`] are what applications implement.
//! * [`Conn`] is the cloneable, thread-safe connection handle.
//! * [`Config`] holds the tunables.
//! * `Group`, `ConnInner`, `LoopLink`, `DynAcceptor`, `DynHandler`: backend-facing plumbing
//!   (hidden from the docs); backends such as `flash-epoll` implement them and the `flash` crate
//!   composes them into an `Engine`.

mod config;
mod conn;
mod error;
mod group;
mod handler;
mod sync;

pub use config::Config;
pub use conn::{Conn, ConnInner, LoopLink};
pub use error::{Error, Result};
pub use group::Group;
pub use handler::{Acceptor, DynAcceptor, DynHandler, FnAcceptor, Handler, fn_acceptor};
