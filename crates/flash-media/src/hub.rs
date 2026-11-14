//! The hub joins the protocols: a registry of streams by path (`app/name`), each fed by one
//! [`Publisher`] and fanned out to any number of subscribers ([`Sink`]s), so a stream an RTMP
//! encoder publishes plays over RTMP, HTTP-FLV, WS-FLV, HLS, RTSP or SRT. Packets are in the
//! canonical form of [`crate::av`]; no protocol knows about another.
//!
//! An ingest calls [`Hub::publish`] with the stream's tracks (or [`Hub::reserve`] while it does
//! not know them yet, so a second publisher is refused in the handshake), then
//! [`Publisher::write`] for every access unit; dropping the publisher unpublishes. An egress
//! calls [`Hub::subscribe`] with a [`Sink`], which hears [`Sink::on_tracks`], then
//! [`Sink::on_packet`] for every packet, and [`Sink::on_close`] at the end; dropping the
//! [`Subscription`] unsubscribes. [`HubConfig`]'s hooks are where authentication goes, for
//! every protocol at once.
//!
//! Fan-out is synchronous: each stream has one mutex, and [`Publisher::write`] calls every
//! sink under it, on the publisher's I/O thread. A sink therefore must not block (it queues
//! onto its connection, and drops when that is too far behind, as [`Dropper`] does) and must
//! not call into the hub, except [`Subscription::close`], which never blocks.
//!
//! Each stream keeps a GOP cache so a new subscriber starts at once with a picture: a stream
//! with video keeps every packet from the last video keyframe on (audio included), an
//! audio-only stream its last second, bounded by [`HubConfig::gop_cache_bytes`]. Subscribe
//! delivers the tracks and the cache under the stream's mutex, so the subscriber's packets
//! continue it with nothing lost or out of order.
//!
//! A subscription with [`SubscribeOptions::wait`] may exist before its publisher (a player
//! that connects first) and survives the publisher leaving for up to that long, hearing
//! `on_tracks` again from the next one; [`Timeline`] keeps the egress timestamps increasing
//! across such a republish.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, TryLockError, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use crate::av::{Packet, SECOND, Time, Tracks};

/// Why a publish or subscribe was refused, or a subscription ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HubError {
    /// The path already has a publisher.
    StreamBusy,
    /// No such stream (or no publisher came within the wait).
    NotFound,
    /// The hub is closed.
    Closed,
    /// A limit ([`HubConfig::max_streams`], [`HubConfig::max_subscribers`]) was reached.
    Limit,
    /// The publisher left and the subscription does not wait for another.
    Unpublished,
    /// A hook refused, with its reason.
    Denied(String),
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HubError::StreamBusy => f.write_str("stream already has a publisher"),
            HubError::NotFound => f.write_str("stream not found"),
            HubError::Closed => f.write_str("hub closed"),
            HubError::Limit => f.write_str("hub limit reached"),
            HubError::Unpublished => f.write_str("stream unpublished"),
            HubError::Denied(r) => write!(f, "denied: {r}"),
        }
    }
}

impl std::error::Error for HubError {}

/// The GOP cache bound of a [`HubConfig`] that leaves it at its default.
pub const DEFAULT_GOP_CACHE_BYTES: usize = 16 << 20;

const AUDIO_WINDOW: Time = SECOND;
const PACKET_OVERHEAD: usize = 64;

/// Describes a publisher or subscriber, for hooks and statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerInfo {
    /// The protocol: "rtmp", "rtsp", "srt", "http-flv", "ws-flv", "hls", "whip"...
    pub protocol: &'static str,
    /// The peer's address, when there is one.
    pub remote: Option<SocketAddr>,
    /// The query string of the URL (where tokens travel), without `?`.
    pub query: String,
}

impl PeerInfo {
    /// Info for `protocol` from `remote` with `query`.
    pub fn new(
        protocol: &'static str,
        remote: Option<SocketAddr>,
        query: impl Into<String>,
    ) -> PeerInfo {
        PeerInfo {
            protocol,
            remote,
            query: query.into(),
        }
    }
}

/// A hook deciding whether a publish or play of a path may go ahead.
pub type AuthHook = Arc<dyn Fn(&str, &PeerInfo) -> Result<(), String> + Send + Sync>;
/// A hook observing a path's publisher leaving.
pub type PathHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Configures a [`Hub`].
#[derive(Clone)]
#[non_exhaustive]
pub struct HubConfig {
    /// Bound of each stream's GOP cache in bytes; 0 disables the cache.
    pub gop_cache_bytes: usize,
    /// Most streams (paths with a publisher or waiting subscribers); 0 is unlimited.
    pub max_streams: usize,
    /// Most subscriptions per path; 0 is unlimited.
    pub max_subscribers: usize,
    /// Authorizes a publish (the authentication hook of every ingest). Runs without the hub's
    /// locks held.
    pub on_publish: Option<AuthHook>,
    /// Observes a publisher leaving.
    pub on_unpublish: Option<PathHook>,
    /// Authorizes a play (every egress).
    pub on_subscribe: Option<AuthHook>,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            gop_cache_bytes: DEFAULT_GOP_CACHE_BYTES,
            max_streams: 0,
            max_subscribers: 0,
            on_publish: None,
            on_unpublish: None,
            on_subscribe: None,
        }
    }
}

impl fmt::Debug for HubConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubConfig")
            .field("gop_cache_bytes", &self.gop_cache_bytes)
            .field("max_streams", &self.max_streams)
            .field("max_subscribers", &self.max_subscribers)
            .finish_non_exhaustive()
    }
}

/// Receives a stream. Calls are serialized per subscription and come from whichever thread
/// publishes, subscribes or closes, under the stream's mutex: they must not block and must not
/// call into the hub (but [`Subscription::close`]).
pub trait Sink: Send + 'static {
    /// The stream's tracks: when the subscription starts, and again whenever the publisher
    /// changes them or a new publisher arrives. Packets after it index these tracks.
    fn on_tracks(&mut self, tracks: &Tracks);
    /// One packet, shared by every subscriber.
    fn on_packet(&mut self, pkt: &Arc<Packet>);
    /// The end: [`HubError::Unpublished`], [`HubError::NotFound`] (no publisher came within
    /// the wait) or [`HubError::Closed`]. Not called for [`Subscription::close`].
    fn on_close(&mut self, _err: HubError) {}
    /// Called once by [`Hub::subscribe`] with the stream's counter of packets dropped for slow
    /// subscribers, which [`Dropper`] adds to ([`StreamInfo::packets_dropped`]).
    fn attach(&mut self, _dropped: &Arc<AtomicU64>) {}
}

/// Configures a subscription.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SubscribeOptions {
    /// Who subscribes, for the hook and statistics.
    pub info: PeerInfo,
    /// When set, the subscription may exist before the publisher and survives a republish:
    /// after the publisher leaves it waits up to this long for the next one.
    pub wait: Option<Duration>,
    /// When set, how long to wait for the first publisher, in place of `wait`.
    pub start_wait: Option<Duration>,
    /// Start from the next keyframe rather than the cached GOP (lower latency, slower start).
    pub no_gop_cache: bool,
}

impl SubscribeOptions {
    /// Options for a subscriber described by `info`.
    pub fn new(info: PeerInfo) -> SubscribeOptions {
        SubscribeOptions {
            info,
            ..SubscribeOptions::default()
        }
    }

    /// Sets [`wait`](Self::wait).
    #[must_use]
    pub fn wait(mut self, d: Duration) -> SubscribeOptions {
        self.wait = Some(d);
        self
    }
}

/// A snapshot of one stream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StreamInfo {
    /// The path.
    pub path: String,
    /// The current tracks (empty while reserved or without publisher).
    pub tracks: Tracks,
    /// Whether a publisher with known tracks is live.
    pub publishing: bool,
    /// Whether a publisher reserved the path and its tracks are not known yet.
    pub reserved: bool,
    /// The publisher.
    pub publisher: PeerInfo,
    /// When the current publisher started.
    pub since: Option<SystemTime>,
    /// Live subscriptions.
    pub subscribers: usize,
    /// Payload bytes of the current publisher.
    pub bytes_in: u64,
    /// Packets of the current publisher.
    pub packets_in: u64,
    /// Packets dropped for slow subscribers ([`Dropper`]), all subscribers together.
    pub packets_dropped: u64,
}

struct HubInner {
    cfg: HubConfig,
    streams: Mutex<HashMap<String, Arc<Stream>>>,
    closed: AtomicBool,
    ids: AtomicU64,
}

/// A registry of streams by path, each with at most one publisher and any number of
/// subscribers. Cheap to clone.
#[derive(Clone)]
pub struct Hub(Arc<HubInner>);

impl fmt::Debug for Hub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hub")
            .field("streams", &self.lock_map().len())
            .finish_non_exhaustive()
    }
}

impl Default for Hub {
    fn default() -> Self {
        Hub::new(HubConfig::default())
    }
}

struct Stream {
    hub: Weak<HubInner>,
    path: String,
    /// Asks whoever holds `state` to unlink closed subscriptions.
    sweep: AtomicBool,
    dropped: Arc<AtomicU64>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    removed: bool,
    publisher: Option<u64>,
    reserved: bool,
    pub_info: PeerInfo,
    since: Option<SystemTime>,
    tracks: Option<Tracks>,
    video: Vec<bool>,
    has_video: bool,
    subs: Vec<Sub>,
    gop: VecDeque<Arc<Packet>>,
    gop_bytes: usize,
    gop_valid: bool,
    bytes_in: u64,
    packets_in: u64,
}

struct Sub {
    id: u64,
    closed: Arc<AtomicBool>,
    sink: Box<dyn Sink>,
    wait_key: bool,
    started: bool,
    wait: Option<Duration>,
    start_wait: Option<Duration>,
    timer_gen: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl State {
    fn live(&self) -> bool {
        self.publisher.is_some() && !self.reserved
    }

    fn set_tracks(&mut self, tracks: Tracks) {
        self.video = tracks.iter().map(|t| t.codec.is_video()).collect();
        self.has_video = self.video.iter().any(|&v| v);
        self.tracks = Some(tracks);
        self.clear_gop();
    }

    fn clear_gop(&mut self) {
        self.gop.clear();
        self.gop_bytes = 0;
        self.gop_valid = false;
    }

    fn cache(&mut self, pkt: &Arc<Packet>, video: bool, limit: usize) {
        if limit == 0 {
            return;
        }
        if self.has_video {
            if video && pkt.keyframe {
                self.clear_gop();
                self.gop_valid = true;
            }
            if !self.gop_valid {
                return;
            }
        }
        self.gop.push_back(pkt.clone());
        self.gop_bytes += pkt.data.len() + PACKET_OVERHEAD;
        if self.has_video {
            if self.gop_bytes > limit {
                self.clear_gop();
            }
            return;
        }
        while self.gop.len() > 1 {
            let front = &self.gop[0];
            if pkt.dts - front.dts > AUDIO_WINDOW || self.gop_bytes > limit {
                self.gop_bytes -= front.data.len() + PACKET_OVERHEAD;
                self.gop.pop_front();
            } else {
                break;
            }
        }
    }

    fn compact(&mut self) {
        self.subs.retain(|s| !s.closed.load(Ordering::Acquire));
    }

    fn arm_timer(st: &Arc<Stream>, s: &mut Sub) {
        let d = if s.started {
            s.wait
        } else {
            s.start_wait.or(s.wait)
        };
        let Some(d) = d else { return };
        s.timer_gen += 1;
        let (id, gen_) = (s.id, s.timer_gen);
        let weak = Arc::downgrade(st);
        crate::timer::after(d, move || {
            if let Some(st) = weak.upgrade() {
                st.expire(id, gen_);
            }
        });
    }
}

impl Stream {
    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Releases the state: unlinks closed subscriptions and takes an empty stream out of the
    /// registry.
    fn release(self: &Arc<Self>, g: MutexGuard<'_, State>) {
        self.release_once(g);
        // A close between the swap and the unlock left its sweep to the next holder.
        while self.sweep.load(Ordering::Acquire) {
            match self.state.try_lock() {
                Ok(g) => self.release_once(g),
                Err(TryLockError::Poisoned(p)) => self.release_once(p.into_inner()),
                Err(TryLockError::WouldBlock) => return,
            }
        }
    }

    fn release_once(self: &Arc<Self>, mut g: MutexGuard<'_, State>) {
        if self.sweep.swap(false, Ordering::AcqRel) {
            g.compact();
        }
        let empty = g.publisher.is_none() && g.subs.is_empty() && !g.removed;
        drop(g);
        if empty {
            self.reap();
        }
    }

    fn reap(self: &Arc<Self>) {
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        let me = self.clone();
        let work = move |map: &mut HashMap<String, Arc<Stream>>| {
            let mut g = me.lock();
            if me.sweep.swap(false, Ordering::AcqRel) {
                g.compact();
            }
            if !g.removed && g.publisher.is_none() && g.subs.is_empty() {
                if map.get(&me.path).is_some_and(|s| Arc::ptr_eq(s, &me)) {
                    map.remove(&me.path);
                }
                g.removed = true;
            }
        };
        // The hub's mutex is taken before a stream's: from here only by try_lock, else later.
        match hub.streams.try_lock() {
            Ok(mut map) => work(&mut map),
            Err(TryLockError::Poisoned(p)) => work(&mut p.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let hub = hub.clone();
                crate::timer::after(Duration::ZERO, move || work(&mut lock(&hub.streams)));
            }
        }
    }

    fn expire(self: &Arc<Self>, id: u64, gen_: u64) {
        let mut g = self.lock();
        if !g.live() {
            if let Some(s) = g.subs.iter_mut().find(|s| s.id == id) {
                if s.timer_gen == gen_
                    && s.closed
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    let err = if s.started {
                        HubError::Unpublished
                    } else {
                        HubError::NotFound
                    };
                    s.sink.on_close(err);
                    self.sweep.store(true, Ordering::Release);
                }
            }
        }
        self.release(g);
    }

    fn info(self: &Arc<Self>) -> Option<StreamInfo> {
        let g = self.lock();
        let info = StreamInfo {
            path: self.path.clone(),
            tracks: g.tracks.clone().unwrap_or_else(|| Arc::from(Vec::new())),
            publishing: g.live(),
            reserved: g.publisher.is_some() && g.reserved,
            publisher: g.pub_info.clone(),
            since: g.since,
            subscribers: g
                .subs
                .iter()
                .filter(|s| !s.closed.load(Ordering::Acquire))
                .count(),
            bytes_in: g.bytes_in,
            packets_in: g.packets_in,
            packets_dropped: self.dropped.load(Ordering::Relaxed),
        };
        let removed = g.removed;
        self.release(g);
        (!removed).then_some(info)
    }
}

impl Hub {
    /// A hub configured by `cfg`.
    pub fn new(cfg: HubConfig) -> Hub {
        Hub(Arc::new(HubInner {
            cfg,
            streams: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            ids: AtomicU64::new(1),
        }))
    }

    fn lock_map(&self) -> MutexGuard<'_, HashMap<String, Arc<Stream>>> {
        lock(&self.0.streams)
    }

    fn next_id(&self) -> u64 {
        self.0.ids.fetch_add(1, Ordering::Relaxed)
    }

    /// The stream of `path`, created when `create` is set.
    fn stream(&self, path: &str, create: bool) -> Result<Arc<Stream>, HubError> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(HubError::Closed);
        }
        let mut map = self.lock_map();
        if let Some(st) = map.get(path) {
            return Ok(st.clone());
        }
        if !create {
            return Err(HubError::NotFound);
        }
        if self.0.cfg.max_streams > 0 && map.len() >= self.0.cfg.max_streams {
            return Err(HubError::Limit);
        }
        let st = Arc::new(Stream {
            hub: Arc::downgrade(&self.0),
            path: path.to_owned(),
            sweep: AtomicBool::new(false),
            dropped: Arc::new(AtomicU64::new(0)),
            state: Mutex::new(State::default()),
        });
        map.insert(path.to_owned(), st.clone());
        Ok(st)
    }

    /// Makes the caller the publisher of `path` with `tracks`. Fails with
    /// [`HubError::StreamBusy`] when the path has a publisher, with [`HubError::Denied`] when
    /// [`HubConfig::on_publish`] refuses, or with [`HubError::Limit`] / [`HubError::Closed`].
    /// Subscriptions waiting on the path start.
    pub fn publish(
        &self,
        path: &str,
        tracks: Tracks,
        info: PeerInfo,
    ) -> Result<Publisher, HubError> {
        let p = self.claim(path, info)?;
        {
            let mut g = p.st.lock();
            go_live(&p.st, &mut g, tracks);
            p.st.release(g);
        }
        Ok(p)
    }

    /// Claims `path` for a publisher whose tracks are not known yet: the first
    /// [`Publisher::set_tracks`] makes the stream live. Meanwhile [`Publisher::write`] drops
    /// what it is given and a second publisher is refused.
    pub fn reserve(&self, path: &str, info: PeerInfo) -> Result<Publisher, HubError> {
        let p = self.claim(path, info)?;
        let mut g = p.st.lock();
        g.reserved = true;
        p.st.release(g);
        Ok(p)
    }

    fn claim(&self, path: &str, info: PeerInfo) -> Result<Publisher, HubError> {
        if let Some(hook) = &self.0.cfg.on_publish {
            // Refuse a busy path before the (possibly slow) hook, which runs without locks.
            if let Ok(st) = self.stream(path, false) {
                let g = st.lock();
                let busy = g.publisher.is_some();
                st.release(g);
                if busy {
                    return Err(HubError::StreamBusy);
                }
            } else if self.0.closed.load(Ordering::Acquire) {
                return Err(HubError::Closed);
            }
            hook(path, &info).map_err(HubError::Denied)?;
        }
        loop {
            let st = self.stream(path, true)?;
            let mut g = st.lock();
            if g.removed {
                drop(g);
                continue;
            }
            if g.publisher.is_some() {
                st.release(g);
                return Err(HubError::StreamBusy);
            }
            let id = self.next_id();
            g.publisher = Some(id);
            g.reserved = false;
            g.pub_info = info;
            g.since = Some(SystemTime::now());
            g.bytes_in = 0;
            g.packets_in = 0;
            drop(g);
            return Ok(Publisher {
                st,
                id,
                limit: self.0.cfg.gop_cache_bytes,
            });
        }
    }

    /// Adds `sink` to the subscribers of `path`. When the stream is live, `sink` hears
    /// `on_tracks` and the cached GOP before this returns. Without a publisher, fails with
    /// [`HubError::NotFound`] unless the options let the subscription wait.
    pub fn subscribe(
        &self,
        path: &str,
        sink: impl Sink,
        opts: SubscribeOptions,
    ) -> Result<Subscription, HubError> {
        self.subscribe_boxed(path, Box::new(sink), opts)
    }

    /// [`subscribe`](Self::subscribe) with a boxed sink.
    pub fn subscribe_boxed(
        &self,
        path: &str,
        mut sink: Box<dyn Sink>,
        opts: SubscribeOptions,
    ) -> Result<Subscription, HubError> {
        if let Some(hook) = &self.0.cfg.on_subscribe {
            hook(path, &opts.info).map_err(HubError::Denied)?;
        }
        let waits = opts.wait.is_some() || opts.start_wait.is_some();
        loop {
            let st = self.stream(path, waits)?;
            let mut g = st.lock();
            if g.removed {
                drop(g);
                continue;
            }
            g.compact();
            if !g.live() && !waits {
                st.release(g);
                return Err(HubError::NotFound);
            }
            if self.0.cfg.max_subscribers > 0 && g.subs.len() >= self.0.cfg.max_subscribers {
                st.release(g);
                return Err(HubError::Limit);
            }
            sink.attach(&st.dropped);
            let closed = Arc::new(AtomicBool::new(false));
            let mut s = Sub {
                id: self.next_id(),
                closed: closed.clone(),
                sink: Box::new(NullSink),
                wait_key: false,
                started: false,
                wait: opts.wait,
                start_wait: opts.start_wait,
                timer_gen: 0,
            };
            if g.live() {
                s.started = true;
                if let Some(t) = g.tracks.clone() {
                    sink.on_tracks(&t);
                }
                s.wait_key = g.has_video;
                if !opts.no_gop_cache && (g.gop_valid || !g.has_video) {
                    for p in &g.gop {
                        sink.on_packet(p);
                    }
                    s.wait_key = false;
                }
            } else {
                State::arm_timer(&st, &mut s);
            }
            s.sink = sink;
            g.subs.push(s);
            st.release(g);
            return Ok(Subscription {
                st,
                closed,
                dropped: None,
            });
        }
    }

    /// A snapshot of every stream, sorted by path.
    pub fn streams(&self) -> Vec<StreamInfo> {
        let list: Vec<Arc<Stream>> = self.lock_map().values().cloned().collect();
        let mut v: Vec<StreamInfo> = list.iter().filter_map(Stream::info).collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    /// A snapshot of the stream at `path`.
    pub fn stream_info(&self, path: &str) -> Option<StreamInfo> {
        let st = self.lock_map().get(path).cloned()?;
        st.info()
    }

    /// Closes the hub: every subscription hears `on_close(Closed)`, publishers' packets are
    /// dropped from then on, and publish and subscribe fail with [`HubError::Closed`].
    pub fn close(&self) {
        if self.0.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let streams: Vec<Arc<Stream>> = self.lock_map().drain().map(|(_, s)| s).collect();
        let mut unpublished = Vec::new();
        for st in streams {
            let mut g = st.lock();
            g.removed = true;
            if g.publisher.take().is_some() {
                unpublished.push(st.path.clone());
            }
            for s in &mut g.subs {
                if s.closed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    s.sink.on_close(HubError::Closed);
                }
            }
            g.subs.clear();
            g.clear_gop();
        }
        if let Some(cb) = &self.0.cfg.on_unpublish {
            unpublished.sort();
            for p in &unpublished {
                cb(p);
            }
        }
    }
}

struct NullSink;

impl Sink for NullSink {
    fn on_tracks(&mut self, _tracks: &Tracks) {}
    fn on_packet(&mut self, _pkt: &Arc<Packet>) {}
}

fn go_live(st: &Arc<Stream>, g: &mut State, tracks: Tracks) {
    let _ = st;
    g.reserved = false;
    g.set_tracks(tracks.clone());
    let has_video = g.has_video;
    for s in &mut g.subs {
        if s.closed.load(Ordering::Acquire) {
            continue;
        }
        s.timer_gen += 1; // cancels a pending wait timeout
        s.started = true;
        s.wait_key = has_video;
        s.sink.on_tracks(&tracks);
    }
}

/// Feeds one stream; dropping it unpublishes ([`close`](Self::close)).
pub struct Publisher {
    st: Arc<Stream>,
    id: u64,
    limit: usize,
}

impl fmt::Debug for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Publisher")
            .field("path", &self.st.path)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    /// The path published to.
    pub fn path(&self) -> &str {
        &self.st.path
    }

    /// Whether this publisher is still the stream's (not closed, hub not closed).
    pub fn is_active(&self) -> bool {
        self.st.lock().publisher == Some(self.id)
    }

    /// Hands `pkt` to the stream: it goes into the GOP cache and to every subscriber before
    /// this returns. Packets of a closed or reserved publisher, or of a track index the stream
    /// does not have, are dropped.
    pub fn write(&self, pkt: Packet) {
        self.write_shared(Arc::new(pkt));
    }

    /// [`write`](Self::write) with a packet already shared.
    pub fn write_shared(&self, pkt: Arc<Packet>) {
        let mut g = self.st.lock();
        if g.publisher != Some(self.id) || g.reserved || pkt.track >= g.video.len() {
            self.st.release(g);
            return;
        }
        g.bytes_in += pkt.data.len() as u64;
        g.packets_in += 1;
        let video = g.video[pkt.track];
        g.cache(&pkt, video, self.limit);
        for s in &mut g.subs {
            if s.closed.load(Ordering::Acquire) {
                continue;
            }
            if video && s.wait_key {
                if !pkt.keyframe {
                    continue;
                }
                s.wait_key = false;
            }
            s.sink.on_packet(&pkt);
        }
        self.st.release(g);
    }

    /// Replaces the stream's tracks (a codec configuration change): the GOP cache is dropped
    /// and every subscriber hears `on_tracks` again, then video from the next keyframe. The
    /// first call on a reserved publisher makes the stream live.
    pub fn set_tracks(&self, tracks: Tracks) {
        let mut g = self.st.lock();
        if g.publisher != Some(self.id) {
            self.st.release(g);
            return;
        }
        if g.reserved {
            go_live(&self.st, &mut g, tracks);
            self.st.release(g);
            return;
        }
        g.set_tracks(tracks.clone());
        let has_video = g.has_video;
        for s in &mut g.subs {
            if s.closed.load(Ordering::Acquire) {
                continue;
            }
            s.wait_key = has_video;
            s.sink.on_tracks(&tracks);
        }
        self.st.release(g);
    }

    /// The tracks of the stream, `None` while reserved.
    pub fn tracks(&self) -> Option<Tracks> {
        let g = self.st.lock();
        if g.publisher == Some(self.id) && !g.reserved {
            g.tracks.clone()
        } else {
            None
        }
    }

    /// Unpublishes: waiting subscriptions stay for the next publisher, the others hear
    /// `on_close(Unpublished)`. Idempotent.
    pub fn close(&self) {
        let mut g = self.st.lock();
        if g.publisher != Some(self.id) {
            self.st.release(g);
            return;
        }
        let was_reserved = g.reserved;
        g.publisher = None;
        g.reserved = false;
        g.pub_info = PeerInfo::default();
        g.tracks = None;
        g.video.clear();
        g.has_video = false;
        g.clear_gop();
        let mut subs = std::mem::take(&mut g.subs);
        for s in &mut subs {
            if s.closed.load(Ordering::Acquire) {
                continue;
            }
            if s.wait.is_some() || !s.started {
                if !was_reserved {
                    State::arm_timer(&self.st, s);
                }
                continue;
            }
            s.closed.store(true, Ordering::Release);
            self.st.sweep.store(true, Ordering::Release);
            s.sink.on_close(HubError::Unpublished);
        }
        g.subs = subs;
        self.st.release(g);
        if let Some(hub) = self.st.hub.upgrade() {
            if let Some(cb) = &hub.cfg.on_unpublish {
                cb(&self.st.path);
            }
        }
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.close();
    }
}

/// One sink's subscription; dropping it unsubscribes ([`close`](Self::close)).
pub struct Subscription {
    st: Arc<Stream>,
    closed: Arc<AtomicBool>,
    dropped: Option<Arc<AtomicU64>>,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("path", &self.st.path)
            .finish_non_exhaustive()
    }
}

impl Subscription {
    /// The path subscribed to.
    pub fn path(&self) -> &str {
        &self.st.path
    }

    /// The stream's counter of packets dropped for slow subscribers, for a [`Dropper`].
    pub fn drop_counter(&mut self) -> Arc<AtomicU64> {
        self.dropped
            .get_or_insert_with(|| self.st.dropped.clone())
            .clone()
    }

    /// Whether the subscription is over (closed, or ended by the hub).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Ends the subscription; its sink hears no `on_close`. Never blocks, so it may be called
    /// from anywhere, a sink's own callbacks included: when the stream is busy it only marks
    /// the subscription and whoever holds the stream unlinks it.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.st.sweep.store(true, Ordering::Release);
        match self.st.state.try_lock() {
            Ok(g) => self.st.release(g),
            Err(TryLockError::Poisoned(p)) => self.st.release(p.into_inner()),
            Err(TryLockError::WouldBlock) => {}
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.close();
    }
}

/// The slow-consumer policy every egress uses: while `backlog()` (what the consumer has queued
/// and not yet sent, such as a connection's queued bytes) is over `limit`, packets are dropped
/// instead of passed on; once a video packet was dropped, video is held back until the next
/// keyframe (a decoder cannot use frames that depend on a dropped one), while audio resumes as
/// soon as the backlog is under the limit. Tracks and close always pass.
pub struct Dropper<S> {
    next: S,
    backlog: Box<dyn Fn() -> usize + Send>,
    limit: usize,
    video: Vec<bool>,
    video_wait: bool,
    dropped: Option<Arc<AtomicU64>>,
}

impl<S> fmt::Debug for Dropper<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dropper")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<S: Sink> Dropper<S> {
    /// Wraps `next`, dropping while `backlog() > limit`.
    pub fn new(next: S, backlog: impl Fn() -> usize + Send + 'static, limit: usize) -> Dropper<S> {
        Dropper {
            next,
            backlog: Box::new(backlog),
            limit,
            video: Vec::new(),
            video_wait: false,
            dropped: None,
        }
    }

    /// Counts the dropped packets into `counter` (see [`Subscription::drop_counter`]).
    #[must_use]
    pub fn count_into(mut self, counter: Arc<AtomicU64>) -> Dropper<S> {
        self.dropped = Some(counter);
        self
    }

    fn drop_one(&self) {
        if let Some(c) = &self.dropped {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<S: Sink> Sink for Dropper<S> {
    fn on_tracks(&mut self, tracks: &Tracks) {
        self.video = tracks.iter().map(|t| t.codec.is_video()).collect();
        self.video_wait = false;
        self.next.on_tracks(tracks);
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        let video = self.video.get(pkt.track).copied().unwrap_or(false);
        if (self.backlog)() > self.limit {
            if video {
                self.video_wait = true;
            }
            self.drop_one();
            return;
        }
        if video && self.video_wait {
            if !pkt.keyframe {
                self.drop_one();
                return;
            }
            self.video_wait = false;
        }
        self.next.on_packet(pkt);
    }

    fn on_close(&mut self, err: HubError) {
        self.next.on_close(err);
    }

    fn attach(&mut self, dropped: &Arc<AtomicU64>) {
        if self.dropped.is_none() {
            self.dropped = Some(dropped.clone());
        }
        self.next.attach(dropped);
    }
}

/// Turns the decode times of a hub stream's packets into egress timestamps that increase per
/// kind of track (video, audio) across republishes and track changes, which players need.
///
/// After [`restart`](Self::restart) (the publisher changed), the next packet whose time is not
/// past the last of its kind, or is more than ten seconds past it, starts a new clock after the
/// last timestamp by as long as the stream was quiet (20 ms to ten seconds); a packet carrying
/// on its track's times carries the clock on. A packet behind its track's last timestamp gets
/// the last one. With [`from_zero`](Self::from_zero) the first packet is at 0.
#[derive(Debug, Clone, Default)]
pub struct Timeline {
    from_zero: bool,
    started: bool,
    restart: bool,
    offset: Time,
    last: Time,
    last_video: Option<Time>,
    last_audio: Option<Time>,
    last_at: Option<Instant>,
}

const MAX_JUMP: Time = 10 * SECOND;
const MIN_GAP: Time = 20 * crate::av::MILLISECOND;

impl Timeline {
    /// A timeline that starts at the first packet's own time.
    pub fn new() -> Timeline {
        Timeline::default()
    }

    /// A timeline whose first packet is at 0.
    pub fn from_zero() -> Timeline {
        Timeline {
            from_zero: true,
            ..Timeline::default()
        }
    }

    /// The next packets may follow a new clock.
    pub fn restart(&mut self) {
        self.restart = self.started;
    }

    /// The largest timestamp given, 0 before any.
    pub fn last(&self) -> Time {
        self.last
    }

    /// The last timestamp of video or audio, or [`last`](Self::last) when there was none.
    pub fn last_of(&self, video: bool) -> Time {
        let l = if video {
            self.last_video
        } else {
            self.last_audio
        };
        l.unwrap_or(self.last)
    }

    /// The offset to add to a packet's times (the same for its PTS), after stamping its DTS.
    pub fn offset(&self) -> Time {
        self.offset
    }

    /// The timestamp of a video or audio packet at `dts`.
    pub fn stamp(&mut self, video: bool, dts: Time) -> Time {
        let now = Instant::now();
        if !self.started {
            self.started = true;
            if self.from_zero {
                self.offset = -dts;
            }
        } else if self.restart {
            self.restart = false;
            let r = self.last_of(video);
            let ts = dts + self.offset;
            if ts <= r || ts > r + MAX_JUMP {
                let quiet = self.last_at.map_or(MIN_GAP, |at| {
                    i64::try_from(now.duration_since(at).as_nanos()).unwrap_or(MAX_JUMP)
                });
                self.offset = self.last + quiet.clamp(MIN_GAP, MAX_JUMP) - dts;
            }
        }
        self.last_at = Some(now);
        let slot = if video {
            &mut self.last_video
        } else {
            &mut self.last_audio
        };
        let ts = (dts + self.offset).max(0).max(slot.unwrap_or(Time::MIN));
        *slot = Some(ts);
        self.last = self.last.max(ts);
        ts
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::av::{Codec, MILLISECOND, Track};

    #[derive(Default)]
    struct Rec {
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Sink for Rec {
        fn on_tracks(&mut self, t: &Tracks) {
            lock(&self.log).push(format!("tracks {}", t.len()));
        }
        fn on_packet(&mut self, p: &Arc<Packet>) {
            lock(&self.log).push(format!(
                "pkt {} {} {}",
                p.track,
                p.dts / MILLISECOND,
                p.keyframe
            ));
        }
        fn on_close(&mut self, e: HubError) {
            lock(&self.log).push(format!("close {e}"));
        }
    }

    fn av_tracks() -> Tracks {
        Arc::from(vec![
            Track::new(Codec::H264, vec![]),
            Track::new(Codec::Aac, vec![]),
        ])
    }

    fn pkt(track: usize, ms: i64, key: bool) -> Packet {
        Packet::new(track, ms * MILLISECOND, ms * MILLISECOND, key, vec![0; 10])
    }

    fn rec() -> (Rec, Arc<Mutex<Vec<String>>>) {
        let r = Rec::default();
        let log = r.log.clone();
        (r, log)
    }

    #[test]
    fn publish_subscribe_gop_cache() {
        let hub = Hub::default();
        let p = hub
            .publish("live/a", av_tracks(), PeerInfo::default())
            .unwrap();
        assert_eq!(
            hub.publish("live/a", av_tracks(), PeerInfo::default())
                .unwrap_err(),
            HubError::StreamBusy
        );
        p.write(pkt(1, 0, true)); // audio before any keyframe: not cached (video stream)
        p.write(pkt(0, 0, true));
        p.write(pkt(1, 10, true));
        p.write(pkt(0, 40, false));
        let (r, log) = rec();
        let sub = hub
            .subscribe("live/a", r, SubscribeOptions::default())
            .unwrap();
        p.write(pkt(0, 80, false));
        assert_eq!(
            *lock(&log),
            vec![
                "tracks 2",
                "pkt 0 0 true",
                "pkt 1 10 true",
                "pkt 0 40 false",
                "pkt 0 80 false"
            ]
        );
        let info = hub.stream_info("live/a").unwrap();
        assert!(info.publishing);
        assert_eq!(info.subscribers, 1);
        assert_eq!(info.packets_in, 5);
        drop(sub);
        assert_eq!(hub.stream_info("live/a").unwrap().subscribers, 0);
        drop(p);
        assert!(hub.stream_info("live/a").is_none());
        assert!(hub.streams().is_empty());
    }

    #[test]
    fn no_gop_cache_waits_for_keyframe_and_unpublish_closes() {
        let hub = Hub::default();
        let p = hub.publish("a", av_tracks(), PeerInfo::default()).unwrap();
        p.write(pkt(0, 0, true));
        let (r, log) = rec();
        let mut o = SubscribeOptions::default();
        o.no_gop_cache = true;
        let _s = hub.subscribe("a", r, o).unwrap();
        p.write(pkt(0, 40, false));
        p.write(pkt(1, 41, true));
        p.write(pkt(0, 80, true));
        p.close();
        assert_eq!(
            *lock(&log),
            vec![
                "tracks 2",
                "pkt 1 41 true",
                "pkt 0 80 true",
                "close stream unpublished"
            ]
        );
        assert_eq!(
            hub.subscribe("a", Rec::default(), SubscribeOptions::default())
                .unwrap_err(),
            HubError::NotFound
        );
    }

    #[test]
    fn wait_for_publisher_and_republish() {
        let hub = Hub::default();
        let (r, log) = rec();
        let _s = hub
            .subscribe(
                "a",
                r,
                SubscribeOptions::default().wait(Duration::from_secs(5)),
            )
            .unwrap();
        assert!(!hub.stream_info("a").unwrap().publishing);
        let p = hub.reserve("a", PeerInfo::default()).unwrap();
        p.write(pkt(0, 0, true)); // dropped while reserved
        assert!(hub.stream_info("a").unwrap().reserved);
        p.set_tracks(av_tracks());
        p.write(pkt(0, 0, true));
        drop(p);
        let p2 = hub.publish("a", av_tracks(), PeerInfo::default()).unwrap();
        p2.write(pkt(0, 0, true));
        assert_eq!(
            *lock(&log),
            vec!["tracks 2", "pkt 0 0 true", "tracks 2", "pkt 0 0 true"]
        );
    }

    #[test]
    fn wait_expires() {
        let hub = Hub::default();
        let (r, log) = rec();
        let mut o = SubscribeOptions::default();
        o.start_wait = Some(Duration::from_millis(20));
        let s = hub.subscribe("x", r, o).unwrap();
        for _ in 0..200 {
            if s.is_closed() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*lock(&log), vec!["close stream not found"]);
        drop(s);
        for _ in 0..200 {
            if hub.streams().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(hub.streams().is_empty());
    }

    struct SelfClose {
        sub: Arc<Mutex<Option<Subscription>>>,
        n: usize,
    }

    impl Sink for SelfClose {
        fn on_tracks(&mut self, _t: &Tracks) {}
        fn on_packet(&mut self, _p: &Arc<Packet>) {
            self.n += 1;
            if let Some(s) = lock(&self.sub).as_ref() {
                s.close();
            }
        }
    }

    #[test]
    fn close_from_inside_a_sink() {
        let hub = Hub::default();
        let p = hub.publish("a", av_tracks(), PeerInfo::default()).unwrap();
        let slot = Arc::new(Mutex::new(None));
        let s = hub
            .subscribe(
                "a",
                SelfClose {
                    sub: slot.clone(),
                    n: 0,
                },
                SubscribeOptions::default(),
            )
            .unwrap();
        *lock(&slot) = Some(s);
        p.write(pkt(0, 0, true));
        p.write(pkt(0, 40, true));
        assert_eq!(hub.stream_info("a").unwrap().subscribers, 0);
    }

    #[test]
    fn hooks_and_limits() {
        let mut cfg = HubConfig::default();
        cfg.on_publish = Some(Arc::new(|path: &str, info: &PeerInfo| {
            if info.query == "token=ok" {
                Ok(())
            } else {
                Err(format!("bad token for {path}"))
            }
        }));
        let unpub = Arc::new(Mutex::new(Vec::new()));
        let u2 = unpub.clone();
        cfg.on_unpublish = Some(Arc::new(move |p: &str| lock(&u2).push(p.to_owned())));
        cfg.max_subscribers = 1;
        let hub = Hub::new(cfg);
        let bad = hub.publish("a", av_tracks(), PeerInfo::new("rtmp", None, "token=no"));
        assert!(matches!(bad, Err(HubError::Denied(_))));
        let p = hub
            .publish("a", av_tracks(), PeerInfo::new("rtmp", None, "token=ok"))
            .unwrap();
        let _s = hub
            .subscribe("a", Rec::default(), SubscribeOptions::default())
            .unwrap();
        assert_eq!(
            hub.subscribe("a", Rec::default(), SubscribeOptions::default())
                .unwrap_err(),
            HubError::Limit
        );
        drop(p);
        assert_eq!(*lock(&unpub), vec!["a"]);
        let (r, log) = rec();
        let _w = hub
            .subscribe(
                "b",
                r,
                SubscribeOptions::default().wait(Duration::from_secs(9)),
            )
            .unwrap();
        hub.close();
        assert_eq!(*lock(&log), vec!["close hub closed"]);
        assert_eq!(
            hub.publish("a", av_tracks(), PeerInfo::default())
                .unwrap_err(),
            HubError::Closed
        );
    }

    #[test]
    fn audio_only_cache_keeps_a_second() {
        let hub = Hub::default();
        let p = hub
            .publish(
                "a",
                Arc::from(vec![Track::new(Codec::Aac, vec![])]),
                PeerInfo::default(),
            )
            .unwrap();
        for i in 0..100 {
            p.write(pkt(0, i * 23, true));
        }
        let (r, log) = rec();
        let _s = hub.subscribe("a", r, SubscribeOptions::default()).unwrap();
        let n = lock(&log).len() - 1;
        assert!((40..=46).contains(&n), "{n}");
    }

    #[test]
    fn dropper_holds_video_to_keyframe() {
        let backlog = Arc::new(AtomicU64::new(0));
        let b2 = backlog.clone();
        let (r, log) = rec();
        let counter = Arc::new(AtomicU64::new(0));
        let mut d = Dropper::new(r, move || b2.load(Ordering::Relaxed) as usize, 100)
            .count_into(counter.clone());
        d.on_tracks(&av_tracks());
        d.on_packet(&Arc::new(pkt(0, 0, true)));
        backlog.store(500, Ordering::Relaxed);
        d.on_packet(&Arc::new(pkt(0, 40, false)));
        backlog.store(0, Ordering::Relaxed);
        d.on_packet(&Arc::new(pkt(1, 50, true)));
        d.on_packet(&Arc::new(pkt(0, 80, false)));
        d.on_packet(&Arc::new(pkt(0, 120, true)));
        assert_eq!(
            *lock(&log),
            vec![
                "tracks 2",
                "pkt 0 0 true",
                "pkt 1 50 true",
                "pkt 0 120 true"
            ]
        );
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn timeline_keeps_increasing() {
        let ms = MILLISECOND;
        let mut t = Timeline::from_zero();
        assert_eq!(t.stamp(true, 1000 * ms), 0);
        assert_eq!(t.stamp(false, 1010 * ms), 10 * ms);
        assert_eq!(t.stamp(true, 1040 * ms), 40 * ms);
        // Audio a little behind its own last: clamped.
        assert_eq!(t.stamp(false, 1005 * ms), 10 * ms);
        t.restart();
        // A new publisher starting from 0 again: continues after the last timestamp.
        let v = t.stamp(true, 0);
        assert!(v >= 60 * ms && v < 200 * ms, "{v}");
        assert_eq!(t.stamp(true, 40 * ms), v + 40 * ms);
        // Restart that carries on the same clock is left alone.
        t.restart();
        assert_eq!(t.stamp(true, 80 * ms), v + 80 * ms);
        let mut plain = Timeline::new();
        assert_eq!(plain.stamp(true, 5 * ms), 5 * ms);
    }
}
