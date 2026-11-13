#![forbid(unsafe_code)]
//! flash core API: `Engine`, `Listener`, `Handler`, `Conn`.
//!
//! **M0 status:** this is the API *prototype* chosen in ADR-003. Types and signatures are real and
//! compile-checked (see `tests/api.rs`); bodies are `unimplemented!()` until M1.

mod conn;
mod engine;
mod error;
mod handler;

pub use conn::Conn;
pub use engine::{Accel, Backend, Engine, EngineBuilder, Listener, UringConfig};
pub use error::{Error, Result};
pub use handler::{Acceptor, FnAcceptor, Handler, fn_acceptor};
