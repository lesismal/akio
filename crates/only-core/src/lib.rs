#![forbid(unsafe_code)]
//! `only` core: connections, handlers and the backend-facing traits.
//!
//! * [`Handler`] and [`Acceptor`] are what applications implement.
//! * [`Conn`] is the cloneable, thread-safe connection handle.
//! * [`Config`] holds the tunables.
//! * `Group`, `ConnInner`, `LoopLink`, `LoopStats`, `Pool`, `DynAcceptor`, `DynHandler`:
//!   backend-facing plumbing, `#[doc(hidden)]` and outside the semver promise
//!   (docs/api-stability.md); backends such as `only-epoll` implement them and the `only`
//!   crate composes them into an `Engine`.
//!
//! Guide: [Handlers, acceptors and `Conn`](https://lesismal.github.io/only/en/concepts/handlers.html)
//! (中文: [Handler、Acceptor 与 `Conn`](https://lesismal.github.io/only/zh-CN/concepts/handlers.html)).
#![warn(clippy::unwrap_used)]

mod config;
mod conn;
mod datagrams;
mod error;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod group;
mod handler;
#[doc(hidden)]
pub mod hash;
pub mod metrics;
mod sync;
pub mod telemetry;

pub use config::{Config, SlowCallback, SlowHook};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use conn::KernelRead;
pub use conn::{Conn, Part, ResponseSlot, ResponseStream, Transport, TransportWaker};
#[doc(hidden)]
pub use conn::{ConnInner, LoopLink, Task};
#[cfg(target_os = "linux")]
pub use conn::{Offloaded, SocketOp};
#[doc(hidden)]
pub use datagrams::{DatagramPort, DatagramsFactory, datagrams_factory};
pub use datagrams::{DatagramSender, Datagrams, DatagramsHandler, DatagramsIter, Replies};
pub use error::{Error, Result};
#[doc(hidden)]
pub use group::Group;
pub use group::{UdpBinding, UdpStats};
pub use handler::{Acceptor, AnyAcceptor, FnAcceptor, Handler, fn_acceptor};
#[doc(hidden)]
pub use handler::{DynAcceptor, DynHandler};
pub use only_buf::SharedBuf;
#[doc(hidden)]
pub use only_pool::Pool;
pub use only_pool::{PoolConfig, PoolStats};
#[doc(hidden)]
pub use telemetry::LoopStats;
pub use telemetry::{
    ConnInfo, Live, LoopCounters, LoopMeta, LoopMetrics, Metrics, ReloadReport, SlowRecord,
    Telemetry,
};

/// Hashes connection ids (sequential `u64`s) for the backends' connection tables: one multiply
/// instead of SipHash on every event. Ids are not attacker-chosen, so no DoS-resistant hash is
/// needed. Backend-facing.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }
    #[inline]
    fn write_u64(&mut self, n: u64) {
        // Fibonacci hashing: spreads sequential ids over the high bits hashbrown uses too.
        self.0 = (self.0 ^ n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

/// A map keyed by connection id, hashed with [`IdHasher`]. Backend-facing.
#[doc(hidden)]
pub type IdMap<V> = std::collections::HashMap<u64, V, std::hash::BuildHasherDefault<IdHasher>>;
