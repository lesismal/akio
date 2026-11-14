#![forbid(unsafe_code)]
//! WebSocket (RFC 6455) for flash.
//!
//! * [`protocol`]: sans-io framing, a decoder that reassembles fragmented messages and enforces
//!   the RFC (masking, reserved bits, control-frame rules, minimal lengths, close codes, UTF-8
//!   validated as bytes arrive).
//! * [`deflate`]: `permessage-deflate` (RFC 7692) with context takeover options.
//! * [`WsSession`] drives a connection and calls a [`WsHandler`]; [`WsSender`] sends from any
//!   thread; [`PreparedMessage`] encodes a broadcast once.
//!
//! * [`client`]: dial `ws://` / `wss://` URLs on a `flash::Engine` and serve them with the same
//!   handler model.
//!
//! The server-side HTTP upgrade lives in `flash-http` (`Context::upgrade_websocket`).

pub mod client;
pub mod deflate;
pub mod protocol;
mod session;
mod timer;

pub use session::{
    INTERNAL_ERROR, Message, PreparedMessage, WsConfig, WsHandler, WsSender, WsSession, accept_key,
    select_subprotocol, valid_key,
};
