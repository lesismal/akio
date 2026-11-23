//! TUN devices on the engine (cargo feature `tun`, ADR-096).

use std::{io, sync::Arc};

use akio_core::{Acceptor, Config};

use crate::Engine;

impl Engine {
    /// Serves the TUN `device` with `acceptor`: one I/O thread per queue, each queue a
    /// connection whose handler gets every packet read from the device (`on_data`, one packet a
    /// call) and whose `Conn::send` writes one packet to it (see [`tun`](crate::tun)). The
    /// threads share the engine's logical pool (`Conn::spawn_blocking`), telemetry (metrics,
    /// connection table, slow callbacks) and settings: the queue bounds (`max_queued_bytes`,
    /// `write_high_watermark`), `shutdown_timeout` and the slow-callback threshold are the
    /// engine's, reloadable with [`Engine::reload`]. For limits of its own, start a
    /// [`TunServer`](crate::tun::TunServer) with its own [`Config`].
    ///
    /// The returned server owns the threads: [`shutdown`](crate::tun::TunServer::shutdown) (or
    /// dropping it) ends them and destroys the interface. [`Engine::shutdown`] does not reach
    /// them; shut the server down alongside the engine.
    pub fn serve_tun<A: Acceptor>(
        &self,
        device: crate::tun::TunDevice,
        acceptor: A,
    ) -> io::Result<crate::tun::TunServer> {
        let mut cfg = Config::default();
        cfg.telemetry = self.telemetry.clone();
        crate::tun::TunServer::start_dyn(device, Arc::new(acceptor), cfg, self.pool.clone())
    }
}
