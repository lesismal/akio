//! Name resolution off the calling thread (ADR-010), a bounded answer cache and connection
//! racing (Happy Eyeballs v2, RFC 8305; ADR-059).
//!
//! [`resolve`] hands a `host:port` lookup to a small process-wide pool of resolver threads and
//! calls back with the addresses, so a client never blocks an I/O thread (or its caller) in
//! `getaddrinfo`. IP literals are answered on the calling thread without a hop. The pool has no
//! dependency: up to [`MAX_THREADS`] threads named `only-dns`, started on demand, each leaving
//! after [`IDLE`] without work. Concurrent lookups of the same name share one `getaddrinfo`.
//!
//! **Cache.** Answers are kept for a fixed time ([`CacheConfig::ttl`], 30 s by default) in a
//! process-wide table of at most [`CacheConfig::max_entries`] names (1024). `getaddrinfo` does
//! not report the records' TTLs, so the cache cannot honour them: the fixed TTL is the upper
//! bound of how stale an answer may be, and should stay below the shortest TTL the names a
//! process uses are published with when they move (load balancers, failover). Failures are not
//! cached unless [`CacheConfig::negative_ttl`] is set. A cached answer is given on the calling
//! thread, like a literal. [`set_cache`] changes the settings ([`CacheConfig::disabled`] turns
//! it off), [`clear_cache`] forgets every answer.
//!
//! **Happy Eyeballs.** [`HappyEyeballs::dial`] connects to the first of several addresses that
//! answers: addresses are interleaved by family starting with the system's first choice
//! ([`interleave`]), a new attempt starts every [`HappyEyeballs::attempt_delay`] (250 ms) or as
//! soon as the previous one fails, and the first connection up wins; the others are closed
//! before any byte is sent. The race runs on one dedicated thread (`only-connect`, started on
//! demand, leaving after [`IDLE`] without races) that waits for at most [`MAX_RACES`] races at
//! once; the winning socket is handed to the engine ([`Engine::adopt_tcp`]), so the acceptor
//! sees an ordinary dialed connection. A single address is dialed by the engine directly. The
//! clients of only-http and only-ws dial this way.
//!
//! ```no_run
//! only::dns::resolve("example.com", 443, |r| match r {
//!     Ok(addrs) => println!("{addrs:?}"),
//!     Err(e) => eprintln!("{e}"),
//! });
//! ```

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak},
    time::{Duration, Instant},
};

use crate::{Acceptor, Conn, Engine};

/// Most resolver threads running at once.
pub const MAX_THREADS: usize = 4;
/// How long an idle resolver thread (or the connection racer) waits for work before it exits.
pub const IDLE: Duration = Duration::from_secs(10);
/// Default [`CacheConfig::ttl`].
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);
/// Default [`CacheConfig::max_entries`].
pub const DEFAULT_CACHE_ENTRIES: usize = 1024;
/// Default [`HappyEyeballs::attempt_delay`] (RFC 8305 section 5).
pub const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// Default [`HappyEyeballs::connect_timeout`] (the engine's default connect timeout).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Most races the connection racer runs at once; more are dialed one address after another by
/// the engine instead.
pub const MAX_RACES: usize = 256;
/// Most addresses one race tries (the first ones after [`interleave`]).
pub const MAX_RACE_ADDRS: usize = 16;

type Done = Box<dyn FnOnce(io::Result<Vec<SocketAddr>>) + Send>;

/// The answer cache's settings ([`set_cache`]). Start from `CacheConfig::default()` and set
/// the fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheConfig {
    /// How long an answer is reused. `getaddrinfo` does not give the records' TTLs, so this
    /// fixed time stands in for them. Zero: answers are not cached. Default
    /// [`DEFAULT_CACHE_TTL`] (30 s).
    pub ttl: Duration,
    /// How long a failed lookup is remembered (answered with the same error kind). Default
    /// zero: failures are not cached.
    pub negative_ttl: Duration,
    /// Most names kept; when full, expired answers go first, then the ones expiring soonest.
    /// Zero: nothing is cached. Default [`DEFAULT_CACHE_ENTRIES`] (1024).
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> CacheConfig {
        CacheConfig {
            ttl: DEFAULT_CACHE_TTL,
            negative_ttl: Duration::ZERO,
            max_entries: DEFAULT_CACHE_ENTRIES,
        }
    }
}

impl CacheConfig {
    /// No caching: every [`resolve`] of a name looks it up.
    pub fn disabled() -> CacheConfig {
        CacheConfig {
            ttl: Duration::ZERO,
            negative_ttl: Duration::ZERO,
            max_entries: 0,
        }
    }
}

struct Entry {
    answer: Result<Arc<[IpAddr]>, (io::ErrorKind, String)>,
    expires: Instant,
}

struct Job {
    /// The cache key (the name, lower case).
    host: String,
}

struct State {
    queue: VecDeque<Job>,
    threads: usize,
    idle: usize,
    /// Callers waiting for a lookup in progress, with the port each wants.
    inflight: HashMap<String, Vec<(u16, Done)>>,
    cache: HashMap<String, Entry>,
    cfg: CacheConfig,
}

struct Pool {
    state: Mutex<State>,
    cv: Condvar,
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Pool {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            threads: 0,
            idle: 0,
            inflight: HashMap::new(),
            cache: HashMap::new(),
            cfg: CacheConfig::default(),
        }),
        cv: Condvar::new(),
    })
}

fn lock() -> MutexGuard<'static, State> {
    pool().state.lock().unwrap_or_else(|e| e.into_inner())
}

/// Replaces the cache settings (process-wide). Answers already cached keep their expiry; a
/// smaller `max_entries` takes effect as new answers come in.
pub fn set_cache(cfg: CacheConfig) {
    let mut st = lock();
    st.cfg = cfg;
    if cfg.max_entries == 0 {
        st.cache.clear();
    }
}

/// The cache settings in force.
pub fn cache_config() -> CacheConfig {
    lock().cfg
}

/// Forgets every cached answer.
pub fn clear_cache() {
    lock().cache.clear();
}

/// An IP literal (`127.0.0.1`, `::1`, `[::1]`), parsed without a lookup.
pub fn literal(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok()
}

fn answer(e: &Entry, port: u16) -> io::Result<Vec<SocketAddr>> {
    match &e.answer {
        Ok(ips) => Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()),
        Err((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
    }
}

/// Resolves `host` (a name or an IP literal) with `port` and calls `done` with every address in
/// the order the system returned them (an empty answer is an `io::ErrorKind::NotFound` error).
///
/// IP literals and cached answers are given at once on the calling thread; other names are
/// looked up on a resolver thread, which also runs `done` (keep it short: it should only start
/// the next step, such as `Engine::dial`). A lookup cannot be cancelled; a caller that gave up
/// ignores the late answer.
pub fn resolve(
    host: &str,
    port: u16,
    done: impl FnOnce(io::Result<Vec<SocketAddr>>) + Send + 'static,
) {
    if let Some(ip) = literal(host) {
        return done(Ok(vec![SocketAddr::new(ip, port)]));
    }
    let key = host.to_ascii_lowercase();
    let p = pool();
    let mut st = lock();
    if let Some(e) = st.cache.get(&key) {
        if e.expires > Instant::now() {
            let r = answer(e, port);
            drop(st);
            return done(r);
        }
        st.cache.remove(&key);
    }
    if let Some(waiting) = st.inflight.get_mut(&key) {
        waiting.push((port, Box::new(done)));
        return;
    }
    st.inflight
        .insert(key.clone(), vec![(port, Box::new(done) as Done)]);
    st.queue.push_back(Job { host: key });
    if st.idle > 0 {
        p.cv.notify_one();
        return;
    }
    if st.threads < MAX_THREADS {
        st.threads += 1;
        drop(st);
        let spawned = std::thread::Builder::new()
            .name("only-dns".into())
            .spawn(worker);
        if spawned.is_err() {
            // No thread: run what is queued here rather than never answering.
            let mut st = lock();
            st.threads -= 1;
            let jobs: Vec<Job> = if st.threads == 0 {
                st.queue.drain(..).collect()
            } else {
                Vec::new()
            };
            drop(st);
            jobs.into_iter().for_each(run);
        }
    }
    // Otherwise every thread is busy; the first to finish takes the job.
}

fn lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for a in (host, 0).to_socket_addrs()? {
        if !ips.contains(&a.ip()) {
            ips.push(a.ip());
        }
    }
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} did not resolve"),
        ));
    }
    Ok(ips)
}

/// Makes room for one more entry: expired ones first, then the one expiring soonest.
fn evict(cache: &mut HashMap<String, Entry>, max: usize, now: Instant) {
    if cache.len() < max {
        return;
    }
    cache.retain(|_, e| e.expires > now);
    while cache.len() >= max {
        let Some(k) = cache
            .iter()
            .min_by_key(|(_, e)| e.expires)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        cache.remove(&k);
    }
}

fn run(job: Job) {
    let r = lookup(&job.host).map(Arc::<[IpAddr]>::from);
    let now = Instant::now();
    let waiting = {
        let mut st = lock();
        let cfg = st.cfg;
        let ttl = if r.is_ok() { cfg.ttl } else { cfg.negative_ttl };
        if cfg.max_entries > 0 && !ttl.is_zero() {
            evict(&mut st.cache, cfg.max_entries, now);
            let answer = match &r {
                Ok(ips) => Ok(ips.clone()),
                Err(e) => Err((e.kind(), e.to_string())),
            };
            st.cache.insert(
                job.host.clone(),
                Entry {
                    answer,
                    expires: now + ttl,
                },
            );
        }
        st.inflight.remove(&job.host).unwrap_or_default()
    };
    for (port, done) in waiting {
        done(match &r {
            Ok(ips) => Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()),
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        });
    }
}

fn worker() {
    let p = pool();
    let mut st = lock();
    loop {
        if let Some(job) = st.queue.pop_front() {
            drop(st);
            run(job);
            st = lock();
            continue;
        }
        st.idle += 1;
        let (g, t) =
            p.cv.wait_timeout(st, IDLE)
                .unwrap_or_else(|e| e.into_inner());
        st = g;
        st.idle -= 1;
        if t.timed_out() && st.queue.is_empty() {
            st.threads -= 1;
            return;
        }
    }
}

// ---- Happy Eyeballs ----------------------------------------------------------------------

/// Orders addresses for connection attempts (RFC 8305 section 4): the families alternate,
/// starting with the family of the first address, each family keeping its own order.
pub fn interleave(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return Vec::new();
    };
    let (mut a, mut b): (VecDeque<SocketAddr>, VecDeque<SocketAddr>) =
        addrs.iter().partition(|x| x.is_ipv6() == first.is_ipv6());
    let mut out = Vec::with_capacity(addrs.len());
    loop {
        match (a.pop_front(), b.pop_front()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Connection racing settings (RFC 8305): how often a new attempt starts and how long each
/// may take. Start from `HappyEyeballs::default()` and set the fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HappyEyeballs {
    /// Time between the starts of two attempts while the earlier is still connecting (RFC 8305
    /// recommends 250 ms, at least 100 ms, at most 2 s). Clamped to 10 ms ..= 2 s. Default
    /// [`ATTEMPT_DELAY`].
    pub attempt_delay: Duration,
    /// How long one attempt may take before it counts as failed. Default [`CONNECT_TIMEOUT`]
    /// (10 s).
    pub connect_timeout: Duration,
}

impl Default for HappyEyeballs {
    fn default() -> HappyEyeballs {
        HappyEyeballs {
            attempt_delay: ATTEMPT_DELAY,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

/// An acceptor shared by several attempts.
struct Shared<A>(Arc<A>);

impl<A: Acceptor> Acceptor for Shared<A> {
    type Handler = A::Handler;
    fn on_open(&self, c: &Conn<A::Handler>) -> A::Handler {
        self.0.on_open(c)
    }
    fn on_shutdown(&self, c: &Conn<A::Handler>) {
        self.0.on_shutdown(c);
    }
    fn transport(&self) -> Option<Box<dyn crate::Transport>> {
        self.0.transport()
    }
}

type OnError = Box<dyn FnOnce(io::Error) + Send>;

/// Dials `addrs[i..]` one after another (the racer is full).
fn in_turn<A: Acceptor>(
    engine: &Engine,
    weak: Weak<Engine>,
    addrs: Arc<Vec<SocketAddr>>,
    i: usize,
    acceptor: Arc<A>,
    on_error: OnError,
) {
    let addr = addrs[i];
    engine.dial(addr, Shared(acceptor.clone()), move |e| {
        match weak.upgrade() {
            Some(engine) if i + 1 < addrs.len() => {
                in_turn(
                    &engine,
                    Arc::downgrade(&engine),
                    addrs,
                    i + 1,
                    acceptor,
                    on_error,
                );
            }
            _ => on_error(e),
        }
    });
}

impl HappyEyeballs {
    /// Connects to the first of `addrs` (in the order [`resolve`] gives them) that answers,
    /// racing them as the [module docs](self) say, and serves that connection with
    /// `acceptor`: `on_open` runs on an I/O thread once it is up. `on_error` gets the last
    /// attempt's error when none connects (or `NotFound` for no address). The engine must be
    /// started.
    pub fn dial<A: Acceptor>(
        &self,
        engine: &Arc<Engine>,
        addrs: Vec<SocketAddr>,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let mut addrs = interleave(&addrs);
        addrs.truncate(MAX_RACE_ADDRS);
        match addrs.len() {
            0 => {
                return on_error(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no address to connect to",
                ));
            }
            1 => return engine.dial(addrs[0], acceptor, on_error),
            _ => {}
        }
        let weak = Arc::downgrade(engine);
        let finish: Finish = Box::new(move |o| {
            let gone = || io::Error::new(io::ErrorKind::NotConnected, "the engine is gone");
            match o {
                Outcome::Won(s) => match weak.upgrade() {
                    Some(e) => e.adopt_tcp(s, acceptor, on_error),
                    None => on_error(gone()),
                },
                Outcome::Failed(e) => on_error(e),
                Outcome::Busy(addrs) => match weak.upgrade() {
                    Some(e) => in_turn(
                        &e,
                        weak,
                        Arc::new(addrs),
                        0,
                        Arc::new(acceptor),
                        Box::new(on_error),
                    ),
                    None => on_error(gone()),
                },
            }
        });
        submit(Race {
            addrs,
            next: 0,
            open: Vec::new(),
            next_at: Instant::now(),
            delay: self
                .attempt_delay
                .clamp(Duration::from_millis(10), Duration::from_secs(2)),
            timeout: self.connect_timeout.max(Duration::from_millis(1)),
            err: None,
            finish: Some(finish),
        });
    }

    /// Resolves `host` ([`resolve`], cached) and [`dial`](Self::dial)s its addresses with
    /// `port`. A resolution failure goes to `on_error`.
    pub fn connect<A: Acceptor>(
        &self,
        engine: &Arc<Engine>,
        host: &str,
        port: u16,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let (me, engine) = (*self, engine.clone());
        resolve(host, port, move |r| match r {
            Ok(addrs) => me.dial(&engine, addrs, acceptor, on_error),
            Err(e) => on_error(e),
        });
    }
}

enum Outcome {
    Won(TcpStream),
    Failed(io::Error),
    /// The racer is full (or could not start): dial in turn instead.
    Busy(Vec<SocketAddr>),
}

type Finish = Box<dyn FnOnce(Outcome) + Send>;

struct Attempt {
    token: u64,
    /// `None`: a simulated black hole ([`black_hole`]), never answers.
    stream: Option<TcpStream>,
    deadline: Instant,
}

fn black_holes() -> MutexGuard<'static, Vec<SocketAddr>> {
    static B: OnceLock<Mutex<Vec<SocketAddr>>> = OnceLock::new();
    B.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Testing aid, not public API: connection races treat attempts to `addr` as lost in a black
/// hole (they never connect and time out), as a network that drops IPv6 SYNs would.
#[doc(hidden)]
pub fn black_hole(addr: SocketAddr) {
    black_holes().push(addr);
}

struct Race {
    addrs: Vec<SocketAddr>,
    /// Index of the next address to try.
    next: usize,
    open: Vec<Attempt>,
    /// When the next attempt may start while others are still open.
    next_at: Instant,
    delay: Duration,
    timeout: Duration,
    err: Option<io::Error>,
    finish: Option<Finish>,
}

struct Submit {
    queue: Vec<Race>,
    /// The running racer's waker (none: no racer thread).
    waker: Option<Arc<only_sys::Waker>>,
    /// Races queued or running.
    races: usize,
}

fn submissions() -> MutexGuard<'static, Submit> {
    static S: OnceLock<Mutex<Submit>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Submit {
            queue: Vec::new(),
            waker: None,
            races: 0,
        })
    })
    .lock()
    .unwrap_or_else(|e| e.into_inner())
}

const WAKE: u64 = u64::MAX;
/// Attempt tokens: race id times this, plus the address index.
const SLOTS: u64 = 32;

fn busy(mut r: Race) {
    if let Some(f) = r.finish.take() {
        f(Outcome::Busy(std::mem::take(&mut r.addrs)));
    }
}

fn submit(race: Race) {
    let mut s = submissions();
    if s.races >= MAX_RACES {
        drop(s);
        return busy(race);
    }
    s.races += 1;
    s.queue.push(race);
    if let Some(w) = &s.waker {
        w.wake();
        return;
    }
    let started = only_sys::Poller::new().and_then(|p| {
        let w = Arc::new(only_sys::Waker::new(&p, WAKE)?);
        let w2 = w.clone();
        std::thread::Builder::new()
            .name("only-connect".into())
            .spawn(move || racer(p, w2))?;
        Ok(w)
    });
    match started {
        Ok(w) => s.waker = Some(w),
        Err(_) => {
            let queued: Vec<Race> = std::mem::take(&mut s.queue);
            s.races -= queued.len();
            drop(s);
            queued.into_iter().for_each(busy);
        }
    }
}

impl Race {
    fn fail_attempt(&mut self, i: usize, poller: &only_sys::Poller, e: io::Error, now: Instant) {
        let a = self.open.swap_remove(i);
        if let Some(s) = &a.stream {
            poller.delete(s.as_raw_fd());
        }
        self.err = Some(e);
        // The next address goes at once (RFC 8305 section 5).
        self.next_at = now;
    }

    /// Expires attempts, starts the next one when due; `Some` when the race is over.
    fn step(&mut self, id: u64, poller: &only_sys::Poller, now: Instant) -> Option<Outcome> {
        let mut i = 0;
        while i < self.open.len() {
            if self.open[i].deadline <= now {
                let e = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");
                self.fail_attempt(i, poller, e, now);
            } else {
                i += 1;
            }
        }
        while self.next < self.addrs.len() && (self.open.is_empty() || now >= self.next_at) {
            let idx = self.next;
            self.next += 1;
            let token = id * SLOTS + idx as u64;
            let addr = self.addrs[idx];
            let started = if black_holes().contains(&addr) {
                Ok(None)
            } else {
                only_sys::connect_nonblocking(addr).and_then(|s| {
                    poller.add(s.as_raw_fd(), token, false, true)?;
                    Ok(Some(s))
                })
            };
            match started {
                Ok(stream) => {
                    self.open.push(Attempt {
                        token,
                        stream,
                        deadline: now + self.timeout,
                    });
                    self.next_at = now + self.delay;
                    break;
                }
                // Unreachable family, no route, ...: the next address at once.
                Err(e) => self.err = Some(e),
            }
        }
        if self.open.is_empty() && self.next >= self.addrs.len() {
            let e = self
                .err
                .take()
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"));
            return Some(Outcome::Failed(e));
        }
        None
    }

    /// The next instant this race needs attention.
    fn wake_at(&self) -> Option<Instant> {
        let next = (self.next < self.addrs.len()).then_some(self.next_at);
        self.open.iter().map(|a| a.deadline).chain(next).min()
    }

    /// An attempt became writable: connected (the race is won) or failed.
    fn ready(&mut self, token: u64, poller: &only_sys::Poller, now: Instant) -> Option<Outcome> {
        let i = self.open.iter().position(|a| a.token == token)?;
        let s = self.open[i].stream.as_ref()?;
        let r = match s.take_error() {
            Ok(None) => s.peer_addr().map(|_| ()),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                let won = self.open.swap_remove(i).stream?;
                poller.delete(won.as_raw_fd());
                for s in self.open.drain(..).filter_map(|a| a.stream) {
                    poller.delete(s.as_raw_fd());
                }
                Some(Outcome::Won(won))
            }
            Err(e) => {
                self.fail_attempt(i, poller, e, now);
                self.step(token / SLOTS, poller, now)
            }
        }
    }
}

fn racer(mut poller: only_sys::Poller, waker: Arc<only_sys::Waker>) {
    let mut races: HashMap<u64, Race> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut events = Vec::new();
    let mut last_busy = Instant::now();
    loop {
        let mut over: Vec<(Finish, Outcome)> = Vec::new();
        {
            let mut s = submissions();
            if s.queue.is_empty() && races.is_empty() && last_busy.elapsed() >= IDLE {
                s.waker = None;
                return;
            }
            for r in s.queue.drain(..) {
                races.insert(next_id, r);
                next_id = if next_id + 1 >= u64::MAX / SLOTS {
                    1
                } else {
                    next_id + 1
                };
            }
        }
        let now = Instant::now();
        let mut ended = Vec::new();
        for (&id, r) in &mut races {
            if let Some(o) = r.step(id, &poller, now) {
                ended.push((id, o));
            }
        }
        for ev in events.drain(..) {
            let only_sys::Event { token, .. } = ev;
            if token == WAKE {
                waker.drain();
                continue;
            }
            let id = token / SLOTS;
            if let Some(o) = races
                .get_mut(&id)
                .and_then(|r| r.ready(token, &poller, now))
            {
                ended.push((id, o));
            }
        }
        for (id, o) in ended {
            if let Some(mut r) = races.remove(&id) {
                if let Some(f) = r.finish.take() {
                    over.push((f, o));
                }
            }
        }
        if !over.is_empty() {
            submissions().races -= over.len();
            for (f, o) in over {
                f(o);
            }
        }
        let now = Instant::now();
        let timeout = races
            .values()
            .filter_map(Race::wake_at)
            .min()
            .map_or(IDLE, |t| t.saturating_duration_since(now));
        if poller.wait(&mut events, Some(timeout)).is_err() {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !races.is_empty() {
            last_busy = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn literals_resolve_inline() {
        let (tx, rx) = mpsc::channel();
        let me = std::thread::current().id();
        resolve("[::1]", 80, move |r| {
            tx.send((r.map(|a| a[0]).ok(), std::thread::current().id()))
                .ok();
        });
        let (a, t) = rx.try_recv().expect("answered inline");
        assert_eq!(a, Some("[::1]:80".parse().unwrap()));
        assert_eq!(t, me);
        assert_eq!(literal("10.1.2.3"), Some("10.1.2.3".parse().unwrap()));
        assert_eq!(literal("example.com"), None);
    }

    #[test]
    fn names_resolve_on_a_resolver_thread() {
        // A name nobody else caches in this test binary.
        let (tx, rx) = mpsc::channel();
        for _ in 0..16 {
            let tx = tx.clone();
            resolve("LocalHost", 8080, move |r| {
                let name = std::thread::current().name().map(str::to_owned);
                tx.send((r.map(|a| a.iter().all(|a| a.port() == 8080)).ok(), name))
                    .ok();
            });
        }
        for _ in 0..16 {
            let (ok, name) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(ok, Some(true));
            assert_eq!(name.as_deref(), Some("only-dns"));
        }
        // Cached now: answered on this thread, with this port.
        let (tx, rx) = mpsc::channel();
        resolve("localhost", 9, move |r| {
            tx.send(r.map(|a| a.iter().all(|a| a.port() == 9)).ok())
                .ok();
        });
        assert_eq!(rx.try_recv().expect("cached: inline"), Some(true));
        let (tx, rx) = mpsc::channel();
        resolve("no-such-host.invalid", 1, move |r| {
            tx.send(r.is_err()).ok();
        });
        assert!(rx.recv_timeout(Duration::from_secs(30)).unwrap());
    }

    #[test]
    fn eviction_and_expiry() {
        let now = Instant::now();
        let mut c = HashMap::new();
        let e = |secs| Entry {
            answer: Ok(Arc::from(vec![IpAddr::from([127, 0, 0, 1])])),
            expires: now + Duration::from_secs(secs),
        };
        c.insert("a".to_owned(), e(5));
        c.insert("b".to_owned(), e(1));
        c.insert("c".to_owned(), e(9));
        evict(&mut c, 3, now);
        assert_eq!(c.len(), 2);
        assert!(!c.contains_key("b"), "the one expiring soonest goes");
        evict(&mut c, 2, now + Duration::from_secs(6));
        assert_eq!(c.len(), 1, "expired ones go first");
        assert!(c.contains_key("c"));
        let mut c2 = HashMap::new();
        c2.insert("x".to_owned(), e(1));
        evict(&mut c2, 5, now);
        assert_eq!(c2.len(), 1, "room left: nothing goes");
    }

    #[test]
    fn interleaving() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let v = [
            a("[::1]:1"),
            a("[::2]:1"),
            a("[::3]:1"),
            a("1.0.0.1:1"),
            a("1.0.0.2:1"),
        ];
        assert_eq!(
            interleave(&v),
            [v[0], v[3], v[1], v[4], v[2]],
            "IPv6 first as the system chose"
        );
        let w = [a("1.0.0.1:1"), a("[::1]:1"), a("1.0.0.2:1"), a("1.0.0.3:1")];
        assert_eq!(interleave(&w), [w[0], w[1], w[2], w[3]]);
        assert!(interleave(&[]).is_empty());
        assert_eq!(interleave(&v[..1]), [v[0]]);
    }
}
