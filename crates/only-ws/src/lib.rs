#![forbid(unsafe_code)]
//! WebSocket (RFC 6455) for `only`.
//!
//! * [`protocol`]: sans-io framing, a decoder that reassembles fragmented messages and enforces
//!   the RFC (masking, reserved bits, control-frame rules, minimal lengths, close codes, UTF-8
//!   validated as bytes arrive).
//! * [`deflate`]: `permessage-deflate` (RFC 7692) with context takeover options.
//! * [`WsSession`] drives a connection and calls a [`WsHandler`]; [`WsSender`] sends from any
//!   thread; [`PreparedMessage`] encodes a broadcast once.
//!
//! * [`client`]: dial `ws://` / `wss://` URLs on a `only::Engine` and serve them with the same
//!   handler model.
//!
//! The server-side HTTP upgrade lives in `only-http` (`Context::upgrade_websocket`).
//!
//! Guide: [WebSocket](https://lesismal.github.io/only/en/protocols/websocket.html)
//! (中文: [WebSocket](https://lesismal.github.io/only/zh-CN/protocols/websocket.html)).
#![warn(clippy::unwrap_used)]

pub mod client;
pub mod deflate;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
// The HTTP/1 head parser shared with only-http: `#[doc(hidden)]`, outside the semver promise.
#[doc(hidden)]
pub mod http1;
pub mod protocol;
mod session;
mod timer;

pub use session::{
    Message, PreparedMessage, WsConfig, WsHandler, WsSender, WsSession, accept_key,
    select_subprotocol, valid_key,
};
