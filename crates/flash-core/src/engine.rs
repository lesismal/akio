use std::net::SocketAddr;

use crate::{Acceptor, Result};

/// I/O backend of one listener (ADR-004).
#[derive(Clone, Debug)]
pub enum Backend {
    /// epoll (Linux); kqueue on macOS/BSD. The default.
    Epoll,
    /// io_uring, falling back to epoll when the kernel lacks required features.
    IoUring(UringConfig),
}

/// io_uring tuning.
#[derive(Clone, Debug, Default)]
pub struct UringConfig {
    /// Submission queue depth (0 = default).
    pub entries: u32,
    /// Use a kernel SQ polling thread.
    pub sqpoll: bool,
}

/// Acceleration/steering layer, orthogonal to [`Backend`] (ADR-006).
#[derive(Clone, Debug, Default)]
pub enum Accel {
    /// No acceleration: plain `SO_REUSEPORT` hashing.
    #[default]
    None,
    /// eBPF: REUSEPORT thread selection, sockmap relay (M5).
    Ebpf,
}

/// One bound address group with its own acceptor and backend.
pub struct Listener {
    #[allow(dead_code)]
    addr: SocketAddr,
    #[allow(dead_code)]
    backend: Backend,
    #[allow(dead_code)]
    accel: Accel,
}

impl Listener {
    /// A TCP listener on `addr`.
    pub fn tcp(addr: SocketAddr) -> Self {
        Listener {
            addr,
            backend: Backend::Epoll,
            accel: Accel::None,
        }
    }

    /// Chooses this listener's backend.
    pub fn backend(mut self, b: Backend) -> Self {
        self.backend = b;
        self
    }

    /// Chooses this listener's acceleration layer.
    pub fn accel(mut self, a: Accel) -> Self {
        self.accel = a;
        self
    }

    /// Attaches the acceptor that serves this listener.
    pub fn serve<A: Acceptor>(self, _acceptor: A) -> Self {
        // M1: stores a type-erased acceptor.
        self
    }
}

/// Builds an [`Engine`].
#[derive(Default)]
pub struct EngineBuilder {}

impl EngineBuilder {
    /// Adds a listener.
    pub fn listen(self, _l: Listener) -> Self {
        self
    }

    /// Validates the configuration and creates the engine.
    pub fn build(self) -> Result<Engine> {
        unimplemented!("M1")
    }
}

/// A running set of I/O threads, backends and the logical pool.
pub struct Engine {}

impl Engine {
    /// Starts a builder.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// Runs until [`shutdown`](Self::shutdown).
    pub fn run(&self) -> Result<()> {
        unimplemented!("M1")
    }

    /// Graceful shutdown: notifies acceptors, waits for connections to drain.
    pub fn shutdown(&self) {
        unimplemented!("M1")
    }
}
