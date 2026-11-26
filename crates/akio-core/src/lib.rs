#![forbid(unsafe_code)]
//! `akio` core: connections, handlers and the backend-facing traits.
//!
//! * [`Handler`] and [`Acceptor`] are what applications implement.
//! * [`Conn`] is the cloneable, thread-safe connection handle.
//! * [`Config`] holds the tunables.
//! * `Group`, `ConnInner`, `LoopLink`, `LoopStats`, `Pool`, `DynAcceptor`, `DynHandler`:
//!   backend-facing plumbing, `#[doc(hidden)]` and outside the semver promise
//!   (docs/api-stability.md); backends such as `akio-epoll` implement them and the `akio`
//!   crate composes them into an `Engine`.
//!
//! Guide: [Handlers, acceptors and `Conn`](https://lesismal.github.io/akio/en/concepts/handlers.html)
//! (中文: [Handler、Acceptor 与 `Conn`](https://lesismal.github.io/akio/zh-CN/concepts/handlers.html)).
#![warn(clippy::unwrap_used)]

#[doc(hidden)]
pub mod balance;
mod budget;
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
pub mod timer;

/// The address a Unix-domain connection reports as its peer and its local address (`0.0.0.0:0`):
/// such a socket has no IP address (`Engine::dial_unix`, ADR-120).
pub const UNIX_ADDR: std::net::SocketAddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::UNSPECIFIED,
    0,
));

pub use akio_buf::SharedBuf;
#[doc(hidden)]
pub use akio_pool::Pool;
#[doc(hidden)]
pub use akio_pool::ThreadHook;
pub use akio_pool::{Job, PoolConfig, PoolStats};
pub use config::{Config, SlowCallback, SlowHook};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use conn::KernelRead;
pub use conn::{Conn, Part, ResponseSlot, ResponseStream, Transport, TransportWaker};
#[doc(hidden)]
pub use conn::{ConnInner, LoopLink, RING_IOV, RingSend, RingSent, Task};
#[cfg(target_os = "linux")]
pub use conn::{Offloaded, SocketOp};
#[doc(hidden)]
pub use datagrams::{DatagramPort, DatagramsFactory, datagrams_factory};
pub use datagrams::{DatagramSender, Datagrams, DatagramsHandler, DatagramsIter, Replies};
pub use error::{Error, Result};
#[doc(hidden)]
pub use group::{AcceptFilter, FilterCell, FilterView, Group, ListenSocket};
#[doc(hidden)]
pub use group::{Countdown, CountdownToken};
pub use group::{IcmpError, IcmpHandler, UdpBinding, UdpStats};
pub use handler::{Acceptor, AnyAcceptor, FnAcceptor, Handler, fn_acceptor};
#[doc(hidden)]
pub use handler::{DynAcceptor, DynHandler};
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
