use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use only_core::{Config, DynAcceptor, Group, LoopMeta, LoopStats, Pool, UdpStats};

use crate::{
    DpdkConfig,
    stack::{Cmd, GroupLink, GroupSpec, Listen, Stack, StackCtl},
};

static NEXT_GID: AtomicU64 = AtomicU64::new(1);

/// Backend name in metrics labels.
const BACKEND: &str = "dpdk";

/// One listener (or dial-only client group) on a userspace stack. Listeners naming the same
/// device share its stack and I/O threads (one per queue); each keeps its own acceptor, config,
/// telemetry and shutdown.
pub struct DpdkGroup {
    stack: Arc<Stack>,
    spec: Arc<GroupSpec>,
    addr: SocketAddr,
    started: AtomicBool,
    shut: AtomicBool,
    rr: AtomicUsize,
}

impl std::fmt::Debug for DpdkGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpdkGroup")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl DpdkGroup {
    /// Opens (or joins) the stack of `dcfg.device` and registers a listener on it: UDP when
    /// `udp`, TCP otherwise. The listener address must be the stack's address or unspecified;
    /// port 0 picks a free port. With `listen == None` the group only serves dialed connections.
    /// Nothing runs until [`Group::start`].
    pub fn bind(
        listen: Option<(SocketAddr, Arc<dyn DynAcceptor>)>,
        udp: bool,
        dcfg: &DpdkConfig,
        cfg: Config,
        pool: Arc<Pool>,
    ) -> io::Result<DpdkGroup> {
        if let Some((a, _)) = &listen {
            match a.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() || ip == dcfg.address => {}
                IpAddr::V4(ip) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("{ip} is not the stack's address ({})", dcfg.address),
                    ));
                }
                IpAddr::V6(_) if dcfg.address6.is_none() => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the userspace stack has no IPv6 address (set DpdkConfig::address6)",
                    ));
                }
                IpAddr::V6(_) => {}
            }
        }
        // An IPv6 listener address must be one of the stack's (the link-local one depends on
        // the device's MAC, known once the stack is open).
        let want6 = match listen.as_ref().map(|(a, _)| a.ip()) {
            Some(IpAddr::V6(a)) => Some(a),
            _ => None,
        };
        let check = |ctl: &StackCtl| match want6 {
            Some(ip)
                if !(ip.is_unspecified()
                    || Some(ip) == dcfg.address6
                    || ip == crate::net::link_local(ctl.mac)) =>
            {
                Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("{ip} is not one of the stack's IPv6 addresses"),
                ))
            }
            _ => Ok(()),
        };
        cfg.telemetry.bind(&cfg);
        let cfg = Arc::new(cfg);
        let (stack, port) =
            Stack::acquire(dcfg, listen.as_ref().map(|(a, _)| (udp, a.port())), check)?;
        // Listeners are dual-stack; one bound to an IPv6 address reports that address.
        let ip = match want6 {
            Some(a) if !a.is_unspecified() => IpAddr::V6(a),
            Some(_) => IpAddr::V6(
                dcfg.address6
                    .unwrap_or_else(|| crate::net::link_local(stack.ctl.mac)),
            ),
            None => IpAddr::V4(stack.ctl.ip),
        };
        let addr = SocketAddr::new(ip, port);
        let listener = listen.as_ref().map(|_| addr);
        let gid = NEXT_GID.fetch_add(1, Ordering::Relaxed);
        let links: Vec<Arc<GroupLink>> = stack
            .ctl
            .shared
            .iter()
            .enumerate()
            .map(|(i, sh)| {
                let stats = Arc::new(LoopStats::new(LoopMeta::new(BACKEND, listener, i)));
                let shared = sh.clone();
                cfg.telemetry.register_loop(
                    stats.clone(),
                    Box::new({
                        let shared = Arc::downgrade(&shared);
                        move |c| {
                            if let Some(sh) = shared.upgrade() {
                                sh.post(Cmd::Core(gid, c));
                            }
                        }
                    }),
                );
                Arc::new(GroupLink {
                    shared,
                    pool: pool.clone(),
                    stats,
                })
            })
            .collect();
        let listen = listen.map(|(_, acceptor)| Listen {
            udp,
            port,
            acceptor,
        });
        let spec = Arc::new(GroupSpec::new(gid, listen, cfg, links));
        for sh in &stack.ctl.shared {
            sh.post(Cmd::Attach(spec.clone()));
        }
        Ok(DpdkGroup {
            stack,
            spec,
            addr,
            started: AtomicBool::new(false),
            shut: AtomicBool::new(false),
            rr: AtomicUsize::new(0),
        })
    }

    fn post_dial(
        &self,
        addr: SocketAddr,
        udp: bool,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        // With several queues the NIC's RSS decides which queue a reply lands on: the dialing
        // queue picks a local port with `port % queues == queue`, and a reply that lands on
        // another queue is handed over to it.
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.stack.queues();
        self.stack.ctl.shared[i].post(Cmd::Dial {
            gid: self.spec.gid,
            addr,
            udp,
            acceptor,
            on_error,
        });
    }
}

impl Group for DpdkGroup {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn udp_stats(&self) -> UdpStats {
        let mut s = UdpStats::default();
        s.peers = self.spec.peers.load(Ordering::Relaxed);
        s.rejected = self.spec.rejected.load(Ordering::Relaxed);
        s
    }

    fn start(&self) -> io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        for l in &self.spec.links {
            l.stats.set_running(true);
        }
        self.stack.start()
    }

    fn shutdown(&self) {
        if self.shut.swap(true, Ordering::AcqRel) {
            return;
        }
        for sh in &self.stack.ctl.shared {
            sh.post(Cmd::Shutdown(self.spec.gid));
        }
    }

    fn join(&self) {
        if !self.stack.started() {
            return;
        }
        self.spec.wait_done();
        self.stack.join_if_closed();
    }

    fn dial(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.post_dial(addr, false, acceptor, on_error);
    }

    fn dial_udp(
        &self,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        self.post_dial(addr, true, acceptor, on_error);
    }
}
