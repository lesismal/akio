#![forbid(unsafe_code)]
//! flash core: connections, handlers and the backend-facing traits.
//!
//! * [`Handler`] and [`Acceptor`] are what applications implement.
//! * [`Conn`] is the cloneable, thread-safe connection handle.
//! * [`Config`] holds the tunables.
//! * `Group`, `ConnInner`, `LoopLink`, `DynAcceptor`, `DynHandler`: backend-facing plumbing
//!   (hidden from the docs); backends such as `flash-epoll` implement them and the `flash` crate
//!   composes them into an `Engine`.
//!
//! Guide: [Handlers, acceptors and `Conn`](https://lesismal.github.io/flash/en/concepts/handlers.html)
//! (中文: [Handler、Acceptor 与 `Conn`](https://lesismal.github.io/flash/zh-CN/concepts/handlers.html)).

mod config;
mod conn;
mod error;
mod group;
mod handler;
mod sync;
pub mod telemetry;

pub use config::{Config, SlowCallback, SlowHook};
pub use conn::{Conn, ConnInner, LoopLink, Part, ResponseSlot, ResponseStream, Task, Transport};
pub use error::{Error, Result};
pub use flash_pool::{Pool, PoolConfig, PoolStats};
pub use group::{Group, UdpStats};
pub use handler::{Acceptor, DynAcceptor, DynHandler, FnAcceptor, Handler, fn_acceptor};
pub use telemetry::{
    ConnInfo, Live, LoopCounters, LoopMeta, LoopMetrics, LoopStats, Metrics, ReloadReport,
    SlowRecord, Telemetry,
};
