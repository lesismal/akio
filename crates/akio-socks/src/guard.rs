//! Timeouts of proxy sessions and the resolver of the HTTP `CONNECT` proxy.
//!
//! The engine has no per-connection timer, so one watchdog thread per process checks the
//! sessions that have a timeout: a handshake (greeting through upstream connect) that takes too
//! long, or a tunnel with no byte in either direction for the idle period, is closed; a
//! `CONNECT` whose upstream is not connected within the connect timeout fails with a reply. Sessions
//! register once, in one of [`SHARDS`] lists picked by connection id.
//!
//! A timeout never fires before it has really elapsed: the handshake start is read from the
//! real clock, and activity is a flag the I/O threads raise (no clock read, no lock, and no write
//! at all while it is already raised) and the watchdog stamps with its own real time when it
//! sees it, which is never earlier than the activity. A timeout fires at most a tick late: a
//! session whose timeout shortens the tick wakes the watchdog, which would otherwise sleep out
//! the longer tick it had begun.

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Condvar, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use akio_core::ConnInner;

use crate::UpstreamSlot;

const SHARDS: usize = 16;

/// See [`Watch::set_probe`].
pub(crate) type Probe = Box<dyn Fn() -> u64 + Send + Sync>;

/// Watchdog period bounds: a quarter of the shortest timeout in use, within these.
const MIN_TICK_MS: u64 = 10;
const MAX_TICK_MS: u64 = 1000;

struct Watchdog {
    base: Instant,
    tick_ms: AtomicU64,
    shards: [Mutex<Vec<Weak<Watch>>>; SHARDS],
    /// The watchdog waits out its tick on `wake`, holding `nap` while it reads the tick: a
    /// shorter tick set meanwhile ([`Watchdog::shorten`]) is seen or wakes it.
    nap: Mutex<()>,
    wake: Condvar,
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
            nap: Mutex::new(()),
            wake: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("akio-socks-timeouts".into())
            .spawn(move || {
                loop {
                    {
                        let g = w.nap.lock().unwrap_or_else(|p| p.into_inner());
                        let tick = Duration::from_millis(w.tick_ms.load(Ordering::Relaxed));
                        // Woken early (a shorter tick): one check now, then the new tick.
                        drop(w.wake.wait_timeout(g, tick));
                    }
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
                            if let Some(p) = watch.probe.get() {
                                let v = p();
                                if watch.probe_last.swap(v, Ordering::Relaxed) != v {
                                    watch.active.store(true, Ordering::Relaxed);
                                }
                            }
                            if watch.active.swap(false, Ordering::Relaxed) {
                                watch.last.store(now, Ordering::Relaxed);
                            }
                            if watch.connect_expired(now) {
                                watch.fire_connect();
                                return false;
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
            .expect("akio-socks timeout thread");
        w
    }
}

impl Watchdog {
    /// Real milliseconds since the watchdog started.
    fn now(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// Makes the tick `tick` if that is shorter, waking the watchdog: it may be sleeping a
    /// longer tick (one set by sessions with long timeouts), which would make a short timeout
    /// fire that much late.
    fn shorten(&self, tick: u64) {
        if self.tick_ms.fetch_min(tick, Ordering::Relaxed) > tick {
            let _g = self.nap.lock().unwrap_or_else(|p| p.into_inner());
            self.wake.notify_one();
        }
    }
}

/// The client end of a proxy session: its connection, or the HTTP/2 or HTTP/3 stream of a
/// `CONNECT` (A134).
pub(crate) trait Side: Send + Sync {
    /// Still open.
    fn is_open(&self) -> bool;
    /// Closes it now (a stream is reset).
    fn close(&self);
    /// Spreads sessions over the watchdog's shards.
    fn id(&self) -> u64;
}

impl Side for ConnInner {
    fn is_open(&self) -> bool {
        ConnInner::is_open(self)
    }
    fn close(&self) {
        ConnInner::close(self);
    }
    fn id(&self) -> u64 {
        ConnInner::id(self)
    }
}

/// The timeouts of one proxy session (client connection plus its upstream).
pub(crate) struct Watch {
    client: Arc<dyn Side>,
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
    /// Runs (on the watchdog thread) when a timeout closes the session.
    on_fire: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Activity counter of a spliced tunnel (its bytes never reach the handlers): a change
    /// since the last tick is activity.
    probe: OnceLock<Probe>,
    probe_last: AtomicU64,
    /// 0 when off.
    handshake_ms: u64,
    idle_ms: u64,
    connect_ms: u64,
    /// Real time the `CONNECT` request came ([`Watch::connecting`]); `u64::MAX` before.
    connect_at: AtomicU64,
    /// Fails the `CONNECT` when its connect timeout passes.
    on_connect_timeout: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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
        connect: Option<Duration>,
    ) -> Option<Arc<Watch>> {
        Watch::start_side(client.clone(), upstream, handshake, idle, connect)
    }

    /// [`start`](Self::start) for any client [`Side`].
    pub(crate) fn start_side(
        client: Arc<dyn Side>,
        upstream: &UpstreamSlot,
        handshake: Option<Duration>,
        idle: Option<Duration>,
        connect: Option<Duration>,
    ) -> Option<Arc<Watch>> {
        let (handshake_ms, idle_ms, connect_ms) = (ms(handshake), ms(idle), ms(connect));
        if handshake_ms == 0 && idle_ms == 0 && connect_ms == 0 {
            return None;
        }
        let shortest = [handshake_ms, idle_ms, connect_ms]
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
            [handshake_ms, idle_ms, connect_ms],
        ))
    }

    fn start_on(
        w: &'static Watchdog,
        tick: u64,
        client: Arc<dyn Side>,
        upstream: &UpstreamSlot,
        [handshake_ms, idle_ms, connect_ms]: [u64; 3],
    ) -> Arc<Watch> {
        w.shorten(tick);
        let now = w.now();
        let watch = Arc::new(Watch {
            dog: w,
            client,
            upstream: upstream.clone(),
            opened: now,
            last: AtomicU64::new(now),
            active: AtomicBool::new(false),
            relaying: AtomicBool::new(false),
            disarmed: AtomicBool::new(false),
            on_fire: Mutex::new(None),
            probe: OnceLock::new(),
            probe_last: AtomicU64::new(0),
            handshake_ms,
            idle_ms,
            connect_ms,
            connect_at: AtomicU64::new(u64::MAX),
            on_connect_timeout: Mutex::new(None),
        });
        let shard = &w.shards[(watch.client.id() as usize) % SHARDS];
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

    /// From now on activity is read from `probe` (a counter that changes while bytes move).
    pub(crate) fn set_probe(&self, probe: Probe) {
        let _ = self.probe.set(probe);
    }

    /// The upstream is connected: the handshake timeout no longer applies.
    pub(crate) fn established(&self) {
        self.last.store(self.dog.now(), Ordering::Relaxed);
        self.relaying.store(true, Ordering::Relaxed);
    }

    /// The `CONNECT` request came now: `on_timeout` runs (on the watchdog thread) when its
    /// upstream is not connected within the connect timeout, which it fails, unless it settled
    /// before. Nothing happens when the connect timeout is off.
    pub(crate) fn connecting(&self, on_timeout: Box<dyn FnOnce() + Send>) {
        if self.connect_ms == 0 {
            return;
        }
        *self
            .on_connect_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(on_timeout);
        self.connect_at.store(self.dog.now(), Ordering::Relaxed);
    }

    /// Runs `f` when a timeout closes the session.
    pub(crate) fn on_fire(&self, f: Box<dyn FnOnce() + Send>) {
        *self.on_fire.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
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

    fn connect_expired(&self, now: u64) -> bool {
        let at = self.connect_at.load(Ordering::Relaxed);
        at != u64::MAX
            && !self.disarmed.load(Ordering::Relaxed)
            && !self.relaying.load(Ordering::Relaxed)
            && now.saturating_sub(at) >= self.connect_ms
    }

    /// The connect timeout passed: the `CONNECT` fails with its reply, which closes the client
    /// once sent.
    fn fire_connect(&self) {
        let f = self
            .on_connect_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        match f {
            Some(f) => f(),
            None => self.client.close(),
        }
    }

    fn fire(&self) {
        self.client.close();
        let f = self
            .on_fire
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(f) = f {
            f();
        }
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
                .name(format!("akio-socks-dns-{i}"))
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
        let c = akio_core::fuzzing::conn_inner();
        let t0 = Instant::now();
        let _w = Watch::start_on(dog, 75, c.clone(), &slot, [300, 0, 0]);
        closed_after(&c, Duration::from_secs(3)).expect("closed");
        let t = t0.elapsed();
        assert!(t >= Duration::from_millis(300), "fired after {t:?}");
        // The same on the process's watchdog, at varied phases.
        for phase in [0u64, 40, 90] {
            std::thread::sleep(Duration::from_millis(phase));
            let c = akio_core::fuzzing::conn_inner();
            let t0 = Instant::now();
            let _w = Watch::start(&c, &slot, Some(Duration::from_millis(300)), None, None);
            closed_after(&c, Duration::from_secs(3)).expect("closed");
            let t = t0.elapsed();
            assert!(t >= Duration::from_millis(300), "fired after {t:?}");
        }
        // Idle: busy past the timeout stays open, then quiet closes, never early.
        let c = akio_core::fuzzing::conn_inner();
        let w =
            Watch::start(&c, &slot, None, Some(Duration::from_millis(300)), None).expect("watch");
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

    /// Regression: a session whose timeout shortened the tick waited for the watchdog to sleep
    /// out the longer tick it had begun: a 300 ms idle timeout registered just after sessions
    /// with the default timeouts (a 1 s tick) fired about a second late (seen as the akio-socks
    /// idle-reset test taking 1 s instead of 0.3 s when run with the others).
    #[test]
    fn a_shorter_timeout_wakes_a_watchdog_on_a_long_tick() {
        let slot: UpstreamSlot = Arc::new(Mutex::new(None));
        // A watchdog of our own, asleep for a second; a 100 ms handshake timeout registered as
        // its tick begins (a 25 ms tick).
        let dog = spawn_watchdog(1000);
        let c = akio_core::fuzzing::conn_inner();
        let t0 = Instant::now();
        let _w = Watch::start_on(dog, 25, c.clone(), &slot, [100, 0, 0]);
        closed_after(&c, Duration::from_secs(3)).expect("closed");
        let t = t0.elapsed();
        assert!(t >= Duration::from_millis(100), "fired after {t:?}");
        // At most a 25 ms tick late, not the second the watchdog had begun to sleep.
        assert!(t < Duration::from_millis(600), "fired after {t:?}");
    }
}
