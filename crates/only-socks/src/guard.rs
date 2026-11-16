//! Timeouts of proxy sessions and the resolver of the HTTP `CONNECT` proxy.
//!
//! The engine has no per-connection timer, so one watchdog thread per process checks the
//! sessions that have a timeout: a handshake (greeting through upstream connect) that takes too
//! long, or a tunnel with no byte in either direction for the idle period, is closed. The I/O
//! threads only store a coarse clock value into an atomic per chunk relayed; the clock itself is
//! advanced by the watchdog, so the data path reads no clock and takes no lock. Sessions register
//! once, in one of [`SHARDS`] lists picked by connection id.

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use only_core::ConnInner;

use crate::UpstreamSlot;

const SHARDS: usize = 16;

/// Watchdog period bounds: a quarter of the shortest timeout in use, within these.
const MIN_TICK_MS: u64 = 10;
const MAX_TICK_MS: u64 = 1000;

struct Watchdog {
    base: Instant,
    /// Milliseconds since `base`, advanced every tick.
    now: AtomicU64,
    tick_ms: AtomicU64,
    shards: [Mutex<Vec<Weak<Watch>>>; SHARDS],
}

/// The watchdog, started on first use with period `tick` (ms).
fn watchdog(tick: u64) -> &'static Watchdog {
    static W: OnceLock<&'static Watchdog> = OnceLock::new();
    W.get_or_init(|| {
        let w: &'static Watchdog = Box::leak(Box::new(Watchdog {
            base: Instant::now(),
            now: AtomicU64::new(0),
            tick_ms: AtomicU64::new(tick),
            shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
        }));
        std::thread::Builder::new()
            .name("only-socks-timeouts".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(w.tick_ms.load(Ordering::Relaxed)));
                    // Check against the clock value the I/O threads have been storing since
                    // the last tick, then advance it: a session touched during this period
                    // reads as idle for 0 (not up to a tick), so nothing fires early; a
                    // timeout fires at most a tick or two late.
                    let now = w.now.load(Ordering::Relaxed);
                    for s in &w.shards {
                        let mut g = s.lock().unwrap_or_else(|p| p.into_inner());
                        g.retain(|weak| {
                            let Some(watch) = weak.upgrade() else {
                                return false;
                            };
                            if !watch.client.is_open() {
                                return false;
                            }
                            if watch.expired(now) {
                                watch.fire();
                                return false;
                            }
                            true
                        });
                    }
                    w.now
                        .store(w.base.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
            })
            .expect("only-socks timeout thread");
        w
    })
}

/// The coarse clock: milliseconds since the watchdog started, at most one tick behind.
fn now_ms() -> u64 {
    watchdog(MAX_TICK_MS).now.load(Ordering::Relaxed)
}

/// The timeouts of one proxy session (client connection plus its upstream).
pub(crate) struct Watch {
    client: Arc<ConnInner>,
    upstream: UpstreamSlot,
    opened: u64,
    last: AtomicU64,
    relaying: AtomicBool,
    /// 0 when off.
    handshake_ms: u64,
    idle_ms: u64,
}

fn ms(d: Option<Duration>) -> u64 {
    d.map_or(0, |d| (d.as_millis() as u64).max(1))
}

impl Watch {
    /// Watches `client`; `None` when neither timeout is set.
    pub(crate) fn start(
        client: &Arc<ConnInner>,
        upstream: &UpstreamSlot,
        handshake: Option<Duration>,
        idle: Option<Duration>,
    ) -> Option<Arc<Watch>> {
        let (handshake_ms, idle_ms) = (ms(handshake), ms(idle));
        if handshake_ms == 0 && idle_ms == 0 {
            return None;
        }
        let shortest = [handshake_ms, idle_ms]
            .into_iter()
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(MAX_TICK_MS);
        // Timeouts fire within a quarter of the shortest one in use (one tick of the clock).
        let tick = (shortest / 4).clamp(MIN_TICK_MS, MAX_TICK_MS);
        let w = watchdog(tick);
        w.tick_ms.fetch_min(tick, Ordering::Relaxed);
        // The same coarse clock as `touch`, so both ends of a comparison lag alike.
        let now = w.now.load(Ordering::Relaxed);
        let watch = Arc::new(Watch {
            client: client.clone(),
            upstream: upstream.clone(),
            opened: now,
            last: AtomicU64::new(now),
            relaying: AtomicBool::new(false),
            handshake_ms,
            idle_ms,
        });
        let shard = &w.shards[(client.id() as usize) % SHARDS];
        shard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Arc::downgrade(&watch));
        Some(watch)
    }

    /// Bytes moved: the tunnel is not idle.
    #[inline]
    pub(crate) fn touch(&self) {
        if self.idle_ms != 0 {
            self.last.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// The upstream is connected: the handshake timeout no longer applies.
    pub(crate) fn established(&self) {
        self.last.store(now_ms(), Ordering::Relaxed);
        self.relaying.store(true, Ordering::Relaxed);
    }

    fn expired(&self, now: u64) -> bool {
        if self.relaying.load(Ordering::Relaxed) {
            self.idle_ms != 0
                && now.saturating_sub(self.last.load(Ordering::Relaxed)) >= self.idle_ms
        } else {
            self.handshake_ms != 0 && now.saturating_sub(self.opened) >= self.handshake_ms
        }
    }

    fn fire(&self) {
        self.client.close();
        let up = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(up) = up {
            up.close();
        }
    }
}

// ---- resolver ------------------------------------------------------------------------------

/// Threads resolving `CONNECT` targets, and how many requests may wait for one.
const RESOLVERS: usize = 4;
const RESOLVE_QUEUE: usize = 1024;

pub(crate) type Resolved = Box<dyn FnOnce(io::Result<Vec<SocketAddr>>) + Send>;

type Job = (String, u16, Resolved);

/// Resolves `host:port` on a resolver thread and hands the result to `done` there. Fails at once
/// (handing `done` back) when [`RESOLVE_QUEUE`] requests are already waiting.
///
/// An HTTP `CONNECT` tunnel is a raw connection with no typed handle to the engine's logical
/// pool, so it gets a small bounded pool of its own; name resolution never runs on an I/O thread.
pub(crate) fn resolve(host: String, port: u16, done: Resolved) -> Result<(), Resolved> {
    static TX: OnceLock<mpsc::SyncSender<Job>> = OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Job>(RESOLVE_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..RESOLVERS {
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("only-socks-dns-{i}"))
                .spawn(move || {
                    loop {
                        let job = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                        let Ok((host, port, done)) = job else { return };
                        let r = (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|a| a.collect::<Vec<_>>());
                        done(r);
                    }
                });
        }
        tx
    });
    tx.try_send((host, port, done)).map_err(|e| match e {
        mpsc::TrySendError::Full(j) | mpsc::TrySendError::Disconnected(j) => j.2,
    })
}
