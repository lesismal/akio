//! Timeouts of proxy sessions and the resolver of the HTTP `CONNECT` proxy.
//!
//! The engine has no per-connection timer, so one watchdog thread per process checks the
//! sessions that have a timeout: a handshake (greeting through upstream connect) that takes too
//! long, or a tunnel with no byte in either direction for the idle period, is closed. Sessions
//! register once, in one of [`SHARDS`] lists picked by connection id.
//!
//! A timeout never fires before it has really elapsed: the handshake start is read from the
//! real clock, and activity is a flag the I/O threads raise (no clock read, no lock, and no write
//! at all while it is already raised) and the watchdog stamps with its own real time when it
//! sees it, which is never earlier than the activity. A timeout fires at most a tick late.

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
    tick_ms: AtomicU64,
    shards: [Mutex<Vec<Weak<Watch>>>; SHARDS],
}

/// The process's watchdog, started on first use with period `tick` (ms).
fn watchdog(tick: u64) -> &'static Watchdog {
    static W: OnceLock<&'static Watchdog> = OnceLock::new();
    W.get_or_init(|| spawn_watchdog(tick))
}

/// Starts a watchdog thread with period `tick` (ms).
fn spawn_watchdog(tick: u64) -> &'static Watchdog {
    {
        let w: &'static Watchdog = Box::leak(Box::new(Watchdog {
            base: Instant::now(),
            tick_ms: AtomicU64::new(tick),
            shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
        }));
        std::thread::Builder::new()
            .name("only-socks-timeouts".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(w.tick_ms.load(Ordering::Relaxed)));
                    let now = w.now();
                    for s in &w.shards {
                        let mut g = s.lock().unwrap_or_else(|p| p.into_inner());
                        g.retain(|weak| {
                            let Some(watch) = weak.upgrade() else {
                                return false;
                            };
                            if !watch.client.is_open() {
                                return false;
                            }
                            // Activity since the last tick happened before now.
                            if watch.active.swap(false, Ordering::Relaxed) {
                                watch.last.store(now, Ordering::Relaxed);
                            }
                            if watch.expired(now) {
                                watch.fire();
                                return false;
                            }
                            true
                        });
                    }
                }
            })
            .expect("only-socks timeout thread");
        w
    }
}

impl Watchdog {
    /// Real milliseconds since the watchdog started.
    fn now(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }
}

/// The timeouts of one proxy session (client connection plus its upstream).
pub(crate) struct Watch {
    client: Arc<ConnInner>,
    upstream: UpstreamSlot,
    /// The watchdog checking this session (its clock is the one `opened` and `last` use).
    dog: &'static Watchdog,
    /// Real time of registration ([`Watchdog::now`]).
    opened: u64,
    /// Real time at or after the last activity seen.
    last: AtomicU64,
    /// Bytes moved since the watchdog last looked.
    active: AtomicBool,
    relaying: AtomicBool,
    disarmed: AtomicBool,
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
        // Timeouts fire within a quarter of the shortest one in use (one tick) late.
        let tick = (shortest / 4).clamp(MIN_TICK_MS, MAX_TICK_MS);
        Some(Watch::start_on(
            watchdog(tick),
            tick,
            client,
            upstream,
            handshake_ms,
            idle_ms,
        ))
    }

    fn start_on(
        w: &'static Watchdog,
        tick: u64,
        client: &Arc<ConnInner>,
        upstream: &UpstreamSlot,
        handshake_ms: u64,
        idle_ms: u64,
    ) -> Arc<Watch> {
        w.tick_ms.fetch_min(tick, Ordering::Relaxed);
        let now = w.now();
        let watch = Arc::new(Watch {
            dog: w,
            client: client.clone(),
            upstream: upstream.clone(),
            opened: now,
            last: AtomicU64::new(now),
            active: AtomicBool::new(false),
            relaying: AtomicBool::new(false),
            disarmed: AtomicBool::new(false),
            handshake_ms,
            idle_ms,
        });
        let shard = &w.shards[(client.id() as usize) % SHARDS];
        shard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Arc::downgrade(&watch));
        watch
    }

    /// Bytes moved: the tunnel is not idle.
    #[inline]
    pub(crate) fn touch(&self) {
        if self.idle_ms != 0 && !self.active.load(Ordering::Relaxed) {
            self.active.store(true, Ordering::Relaxed);
        }
    }

    /// The upstream is connected: the handshake timeout no longer applies.
    pub(crate) fn established(&self) {
        self.last.store(self.dog.now(), Ordering::Relaxed);
        self.relaying.store(true, Ordering::Relaxed);
    }

    /// Neither timeout applies any more (the session is governed by something else).
    pub(crate) fn disarm(&self) {
        self.disarmed.store(true, Ordering::Relaxed);
    }

    fn expired(&self, now: u64) -> bool {
        if self.disarmed.load(Ordering::Relaxed) {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn closed_after(c: &Arc<ConnInner>, within: Duration) -> Option<Duration> {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if !c.is_open() {
                return Some(t0.elapsed());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        None
    }

    /// Regression: `opened` and `touch` used a coarse clock advanced only at tick ends. A session
    /// registered near the end of a long sleep (a 1 s tick, set by sessions with the default
    /// timeouts) took the previous tick's value as its start, and the next check (a short tick
    /// later) saw a whole old tick elapsed: a 300 ms handshake timeout fired a few
    /// milliseconds after connect (seen on io_uring). Timeouts must never fire early.
    #[test]
    fn never_fires_before_the_timeout() {
        let slot: UpstreamSlot = Arc::new(Mutex::new(None));
        // A watchdog of our own with a 1 s tick; register just before its first tick ends.
        let dog = spawn_watchdog(1000);
        std::thread::sleep(Duration::from_millis(950));
        let c = only_core::fuzzing::conn_inner();
        let t0 = Instant::now();
        let _w = Watch::start_on(dog, 75, &c, &slot, 300, 0);
        closed_after(&c, Duration::from_secs(3)).expect("closed");
        let t = t0.elapsed();
        assert!(t >= Duration::from_millis(300), "fired after {t:?}");
        // The same on the process's watchdog, at varied phases.
        for phase in [0u64, 40, 90] {
            std::thread::sleep(Duration::from_millis(phase));
            let c = only_core::fuzzing::conn_inner();
            let t0 = Instant::now();
            let _w = Watch::start(&c, &slot, Some(Duration::from_millis(300)), None);
            closed_after(&c, Duration::from_secs(3)).expect("closed");
            let t = t0.elapsed();
            assert!(t >= Duration::from_millis(300), "fired after {t:?}");
        }
        // Idle: busy past the timeout stays open, then quiet closes, never early.
        let c = only_core::fuzzing::conn_inner();
        let w = Watch::start(&c, &slot, None, Some(Duration::from_millis(300))).expect("watch");
        w.established();
        for _ in 0..10 {
            w.touch();
            std::thread::sleep(Duration::from_millis(60));
            assert!(c.is_open(), "closed while busy");
        }
        w.touch();
        let t0 = Instant::now();
        closed_after(&c, Duration::from_secs(3)).expect("closed when idle");
        assert!(
            t0.elapsed() >= Duration::from_millis(300),
            "{:?}",
            t0.elapsed()
        );
    }
}
