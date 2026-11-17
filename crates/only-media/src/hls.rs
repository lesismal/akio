//! HLS (RFC 8216) playback of hub streams, with the Low-Latency extensions (partial segments,
//! preload hints, blocking playlist reload) of its second edition.
//!
//! [`Hls`] is a only-http [`Service`] answering `GET /<path>/index.m3u8` (the media
//! playlist), `/<path>/seg-<n>.ts` and, with [`HlsConfig::part_duration`], `/<path>/part-<n>.<m>.ts`.
//! The first playlist request of a stream starts a muxer that subscribes to the hub (404 when
//! the stream has no publisher, unless [`HlsConfig::play_wait`] lets it wait) and cuts the stream
//! into segments held in memory: at the first video keyframe
//! [`HlsConfig::target_duration`] after the segment start (audio-only streams on time). It keeps
//! a sliding window of [`HlsConfig::playlist_size`] segments plus a few more for late readers,
//! bounded by [`HlsConfig::max_bytes`], and stops after [`HlsConfig::idle_timeout`] without
//! requests. A republish or codec change starts a new segment after `EXT-X-DISCONTINUITY`.
//!
//! Segments are MPEG-TS by default. With [`HlsConfig::format`] set to [`SegmentFormat::Fmp4`]
//! they are fragmented MP4 (CMAF, see [`crate::fmp4`]): the playlist (version 7, 9 with parts)
//! points at an init segment with `#EXT-X-MAP:URI="init-<n>.mp4"`, and segments and parts are
//! `seg-<n>.m4s` and `part-<n>.<m>.m4s`. Each part is one `moof` + `mdat` fragment, a segment
//! is a `styp` followed by the fragments of its parts (one fragment without parts). `<n>` of
//! the init segment changes when the tracks do (a republish with other codecs or
//! configuration), and a new `EXT-X-MAP` follows the `EXT-X-DISCONTINUITY`; the init segments
//! the kept segments use stay available. Names of the other format answer 404.
//!
//! Requests that must wait (the first playlist, a blocking reload `?_HLS_msn=&_HLS_part=`, the
//! segment or part being written, a hinted part) are parked without holding a thread and
//! answered by the publisher's thread when what they wait for is cut (or after three target
//! durations with 503).
//!
//! Not supported: encryption, delta updates (`_HLS_skip`), rendition reports,
//! multivariant playlists.

use std::{
    collections::{HashMap, VecDeque},
    fmt::{self, Write as _},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use only_http::{Context, Detached, Response, Service};

use crate::{
    av::{Packet, SECOND, Time, Tracks},
    fmp4,
    hub::{Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
    mpegts::Muxer,
};

/// The container of HLS media segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum SegmentFormat {
    /// MPEG-TS: `seg-<n>.ts` and `part-<n>.<m>.ts` (`video/mp2t`), playlist version 3 (9 with
    /// parts).
    #[default]
    MpegTs,
    /// Fragmented MP4 (CMAF): an `init-<n>.mp4` init segment (`video/mp4`) named by
    /// `#EXT-X-MAP`, then `seg-<n>.m4s` and `part-<n>.<m>.m4s` (`video/iso.segment`), playlist
    /// version 7 (9 with parts). Carries H.264, H.265, AAC and Opus.
    Fmp4,
}

impl SegmentFormat {
    /// The extension of media segments and parts (`".ts"`, `".m4s"`).
    pub fn extension(self) -> &'static str {
        match self {
            SegmentFormat::MpegTs => ".ts",
            SegmentFormat::Fmp4 => ".m4s",
        }
    }

    /// The content type of media segments and parts.
    pub fn content_type(self) -> &'static str {
        match self {
            SegmentFormat::MpegTs => "video/mp2t",
            SegmentFormat::Fmp4 => "video/iso.segment",
        }
    }
}

/// Configures [`Hls`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HlsConfig {
    /// The segment length aimed at (segments start at keyframes, so they are at least this
    /// long when the keyframe interval is longer).
    pub target_duration: Duration,
    /// Segments listed in the playlist.
    pub playlist_size: usize,
    /// Segments kept after leaving the playlist, for clients that read it just before.
    pub keep_segments: usize,
    /// Bound of the bytes a stream's segments take. The segment being written is bounded by it
    /// too: one that reaches it without a keyframe to cut at (a stream without keyframes, or a
    /// very long GOP) is cut there, and the next segment starts without a keyframe.
    pub max_bytes: usize,
    /// When set, segments are also published in parts of about this length (LL-HLS).
    pub part_duration: Option<Duration>,
    /// A muxer without requests for this long stops.
    pub idle_timeout: Duration,
    /// How long the first playlist request waits for a stream not published yet (`None`: 404).
    pub play_wait: Option<Duration>,
    /// The `Access-Control-Allow-Origin` value sent (`None`: no CORS header).
    pub cors_origin: Option<String>,
    /// The segment container: MPEG-TS (the default) or fragmented MP4.
    pub format: SegmentFormat,
}

impl Default for HlsConfig {
    fn default() -> Self {
        HlsConfig {
            target_duration: Duration::from_secs(2),
            playlist_size: 6,
            keep_segments: 3,
            max_bytes: 64 << 20,
            part_duration: None,
            idle_timeout: Duration::from_secs(30),
            play_wait: None,
            cors_origin: Some("*".to_owned()),
            format: SegmentFormat::MpegTs,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn dur_ns(d: Duration) -> Time {
    i64::try_from(d.as_nanos()).unwrap_or(Time::MAX)
}

struct Inner {
    hub: Hub,
    cfg: HlsConfig,
    muxers: Mutex<HashMap<String, Arc<Stream>>>,
}

/// The HLS service. Cheap to clone.
#[derive(Clone)]
pub struct Hls(Arc<Inner>);

impl fmt::Debug for Hls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hls")
            .field("cfg", &self.0.cfg)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Part {
    duration: Time,
    independent: bool,
    data: Arc<Vec<u8>>,
}

#[derive(Debug)]
struct Segment {
    seq: u64,
    duration: Time,
    discontinuity: bool,
    /// The init segment it needs (fMP4).
    init: u64,
    data: Arc<Vec<u8>>,
    parts: Vec<Part>,
}

/// The segment being written.
#[derive(Debug)]
struct Building {
    seq: u64,
    start: Time,
    discontinuity: bool,
    init: u64,
    data: Vec<u8>,
    parts: Vec<Part>,
    part_start: Time,
    part_offset: usize,
    part_independent: bool,
    last: Time,
}

impl Building {
    /// Memory held: the segment and its parts (which copy the segment's bytes).
    fn bytes(&self) -> usize {
        self.data.len() + self.parts.iter().map(|p| p.data.len()).sum::<usize>()
    }
}

enum Want {
    /// A playlist with at least one segment, or the given msn / part.
    Playlist {
        msn: Option<u64>,
        part: Option<usize>,
    },
    Segment(u64),
    Part(u64, usize),
    Init(u64),
}

struct Waiter {
    want: Want,
    resp: Detached,
    deadline: Instant,
}

#[derive(Default)]
struct State {
    segments: VecDeque<Segment>,
    building: Option<Building>,
    next_seq: u64,
    bytes: usize,
    disc_seq: u64,
    target: Time,
    waiters: Vec<Waiter>,
    last_access: Option<Instant>,
    ended: bool,
    /// fMP4 init segments by number: the current one and those kept segments use.
    inits: VecDeque<(u64, Arc<Vec<u8>>)>,
    /// The number of the current init segment.
    init: u64,
    /// The number the next new init segment gets.
    next_init: u64,
}

impl State {
    /// Drops the init segments nothing refers to any more.
    fn prune_inits(&mut self) {
        let (segments, building, cur) = (&self.segments, &self.building, self.init);
        self.inits.retain(|(n, _)| {
            *n == cur
                || building.as_ref().is_some_and(|b| b.init == *n)
                || segments.iter().any(|s| s.init == *n)
        });
    }
}

/// One stream's muxer.
struct Stream {
    path: String,
    cfg: HlsConfig,
    cors: Option<String>,
    state: Mutex<State>,
    sub: Mutex<Option<Subscription>>,
}

impl Hls {
    /// A service playing streams of `hub`.
    pub fn new(hub: Hub, cfg: HlsConfig) -> Hls {
        Hls(Arc::new(Inner {
            hub,
            cfg,
            muxers: Mutex::new(HashMap::new()),
        }))
    }

    /// Paths with a running muxer.
    pub fn active(&self) -> Vec<String> {
        let mut v: Vec<String> = lock(&self.0.muxers).keys().cloned().collect();
        v.sort();
        v
    }

    fn stream(&self, path: &str, ctx: &Context) -> Result<Arc<Stream>, HubError> {
        if let Some(s) = lock(&self.0.muxers).get(path) {
            if !lock(&s.state).ended {
                return Ok(s.clone());
            }
        }
        let cfg = &self.0.cfg;
        let st = Arc::new(Stream {
            path: path.to_owned(),
            cfg: cfg.clone(),
            cors: cfg.cors_origin.clone(),
            state: Mutex::new(State {
                target: dur_ns(cfg.target_duration),
                last_access: Some(Instant::now()),
                ..State::default()
            }),
            sub: Mutex::new(None),
        });
        let info = PeerInfo::new("hls", Some(ctx.peer()), ctx.req().query().unwrap_or(""));
        let mut opts = SubscribeOptions::new(info);
        opts.wait = cfg.play_wait;
        let sink = HlsSink {
            st: st.clone(),
            muxer: None,
            timeline: Timeline::from_zero(),
            video: Vec::new(),
            has_video: false,
            started: false,
            disc_pending: false,
            forced_cut: false,
        };
        let sub = self.0.hub.subscribe(path, sink, opts)?;
        *lock(&st.sub) = Some(sub);
        lock(&self.0.muxers).insert(path.to_owned(), st.clone());
        self.arm_idle(&st);
        Ok(st)
    }

    fn arm_idle(&self, st: &Arc<Stream>) {
        let weak_hls = Arc::downgrade(&self.0);
        let weak = Arc::downgrade(st);
        let every = (st.cfg.idle_timeout / 2).max(Duration::from_millis(50));
        crate::timer::after(every, move || idle_check(&weak_hls, &weak));
    }
}

fn idle_check(hls: &Weak<Inner>, st: &Weak<Stream>) {
    let (Some(hls), Some(st)) = (hls.upgrade(), st.upgrade()) else {
        return;
    };
    let idle = {
        let g = lock(&st.state);
        g.ended
            || g.waiters.is_empty()
                && g.last_access
                    .is_none_or(|t| t.elapsed() > st.cfg.idle_timeout)
    };
    if idle {
        st.stop();
        let mut m = lock(&hls.muxers);
        if m.get(&st.path).is_some_and(|s| Arc::ptr_eq(s, &st)) {
            m.remove(&st.path);
        }
        return;
    }
    Hls(hls).arm_idle(&st);
}

/// Parses `_HLS_msn` and `_HLS_part` from a query.
fn blocking_params(q: Option<&str>) -> (Option<u64>, Option<usize>) {
    let (mut msn, mut part) = (None, None);
    for kv in q.unwrap_or("").split('&') {
        match kv.split_once('=') {
            Some(("_HLS_msn", v)) => msn = v.parse().ok(),
            Some(("_HLS_part", v)) => part = v.parse().ok(),
            _ => {}
        }
    }
    (msn, part)
}

impl Service for Hls {
    fn call(&self, ctx: &mut Context) {
        let p = ctx.path().trim_start_matches('/').to_owned();
        let Some((path, file)) = p.rsplit_once('/') else {
            return ctx.text(404, "not found");
        };
        if path.is_empty() || path.contains("..") {
            return ctx.text(404, "not found");
        }
        let format = self.0.cfg.format;
        let ext = format.extension();
        let want = if file == "index.m3u8" {
            let (msn, part) = blocking_params(ctx.req().query());
            Want::Playlist { msn, part }
        } else if let Some(n) = file
            .strip_prefix("init-")
            .and_then(|f| f.strip_suffix(".mp4"))
            .filter(|_| format == SegmentFormat::Fmp4)
        {
            match n.parse() {
                Ok(n) => Want::Init(n),
                Err(_) => return ctx.text(404, "not found"),
            }
        } else if let Some(n) = file.strip_prefix("seg-").and_then(|f| f.strip_suffix(ext)) {
            match n.parse() {
                Ok(n) => Want::Segment(n),
                Err(_) => return ctx.text(404, "not found"),
            }
        } else if let Some((n, m)) = file
            .strip_prefix("part-")
            .and_then(|f| f.strip_suffix(ext))
            .and_then(|f| f.split_once('.'))
        {
            match (n.parse(), m.parse()) {
                (Ok(n), Ok(m)) => Want::Part(n, m),
                _ => return ctx.text(404, "not found"),
            }
        } else {
            return ctx.text(404, "not found");
        };
        let st = if matches!(want, Want::Playlist { .. }) {
            match self.stream(path, ctx) {
                Ok(s) => s,
                Err(HubError::Denied(r)) => return ctx.text(403, r),
                Err(e) => return ctx.text(404, e.to_string()),
            }
        } else {
            match lock(&self.0.muxers).get(path) {
                Some(s) => s.clone(),
                None => return ctx.text(404, "not found"),
            }
        };
        let mut g = lock(&st.state);
        g.last_access = Some(Instant::now());
        if let Some(resp) = st.answer(&g, &want) {
            drop(g);
            return ctx.respond(resp);
        }
        if !st.may_wait(&g, &want) {
            drop(g);
            return ctx.text(404, "not found");
        }
        let Some(d) = ctx.detach() else { return };
        let wait = 3 * st.cfg.target_duration + st.cfg.play_wait.unwrap_or_default();
        g.waiters.push(Waiter {
            want,
            resp: d,
            deadline: Instant::now() + wait,
        });
        drop(g);
        let weak = Arc::downgrade(&st);
        crate::timer::after(wait + Duration::from_millis(5), move || {
            if let Some(st) = weak.upgrade() {
                st.expire_waiters();
            }
        });
    }
}

impl Stream {
    fn stop(&self) {
        let sub = lock(&self.sub).take();
        drop(sub);
        let waiters = {
            let mut g = lock(&self.state);
            g.ended = true;
            std::mem::take(&mut g.waiters)
        };
        for w in waiters {
            w.resp.respond(Response::text(404, "stream ended"));
        }
    }

    fn headers(&self, mut r: Response, playlist: bool) -> Response {
        if playlist {
            r = r.header("Cache-Control", "no-cache");
        } else {
            r = r.header("Cache-Control", "max-age=60");
        }
        if let Some(o) = &self.cors {
            r = r.header("Access-Control-Allow-Origin", o);
        }
        r
    }

    /// The response for `want`, if it can be answered now.
    fn answer(&self, g: &State, want: &Want) -> Option<Response> {
        match *want {
            Want::Playlist { msn, part } => {
                // A plain request waits for a whole segment (players that do not know LL-HLS
                // need one); a blocking reload for what it asks.
                match msn {
                    Some(msn) if !self.has(g, msn, part) => return None,
                    None if g.segments.is_empty() => return None,
                    _ => {}
                }
                let body = self.playlist(g);
                Some(self.headers(
                    Response::with_body(200, "application/vnd.apple.mpegurl", body.into_bytes()),
                    true,
                ))
            }
            Want::Segment(n) => {
                let s = g.segments.iter().find(|s| s.seq == n)?;
                Some(self.headers(
                    Response::with_body(200, self.cfg.format.content_type(), s.data.to_vec()),
                    false,
                ))
            }
            Want::Init(n) => {
                let (_, data) = g.inits.iter().find(|(id, _)| *id == n)?;
                Some(self.headers(Response::with_body(200, "video/mp4", data.to_vec()), false))
            }
            Want::Part(n, m) => {
                let part = if let Some(s) = g.segments.iter().find(|s| s.seq == n) {
                    s.parts.get(m)
                } else {
                    g.building
                        .as_ref()
                        .filter(|b| b.seq == n)
                        .and_then(|b| b.parts.get(m))
                }?;
                Some(self.headers(
                    Response::with_body(200, self.cfg.format.content_type(), part.data.to_vec()),
                    false,
                ))
            }
        }
    }

    /// Whether segment `msn` (or its part `part`) is out.
    fn has(&self, g: &State, msn: u64, part: Option<usize>) -> bool {
        let done = g.segments.back().is_some_and(|s| s.seq >= msn);
        match part {
            None => done,
            Some(p) => {
                done || g
                    .building
                    .as_ref()
                    .is_some_and(|b| b.seq == msn && b.parts.len() > p)
                    || g.building.as_ref().is_some_and(|b| b.seq > msn)
            }
        }
    }

    /// Whether `want` may come: what is not out yet but will be soon.
    fn may_wait(&self, g: &State, want: &Want) -> bool {
        if g.ended {
            return false;
        }
        let next = g.building.as_ref().map_or(g.next_seq, |b| b.seq);
        match *want {
            Want::Playlist { msn, .. } => msn.is_none_or(|m| m <= next + 1),
            Want::Segment(n) => n == next,
            Want::Part(n, _) => n == next || n == next + 1,
            Want::Init(_) => false,
        }
    }

    fn playlist(&self, g: &State) -> String {
        let parts = self.cfg.part_duration.map(dur_ns);
        let first = g.segments.len().saturating_sub(self.cfg.playlist_size);
        let listed: Vec<&Segment> = g.segments.iter().skip(first).collect();
        let max_dur = listed
            .iter()
            .map(|s| s.duration)
            .max()
            .unwrap_or(0)
            .max(g.target);
        let target = (max_dur + SECOND - 1) / SECOND;
        let mut s = String::with_capacity(512);
        s.push_str("#EXTM3U\n");
        let fmp4 = self.cfg.format == SegmentFormat::Fmp4;
        let ext = self.cfg.format.extension();
        let version = match (parts.is_some(), fmp4) {
            (true, _) => 9,
            (false, true) => 7,
            (false, false) => 3,
        };
        let _ = writeln!(s, "#EXT-X-VERSION:{version}");
        let _ = writeln!(s, "#EXT-X-TARGETDURATION:{target}");
        let msn = listed
            .first()
            .map_or_else(|| g.building.as_ref().map_or(0, |b| b.seq), |s| s.seq);
        let _ = writeln!(s, "#EXT-X-MEDIA-SEQUENCE:{msn}");
        let disc_before = g.disc_seq
            + g.segments
                .iter()
                .take(first)
                .filter(|s| s.discontinuity)
                .count() as u64;
        if disc_before > 0 {
            let _ = writeln!(s, "#EXT-X-DISCONTINUITY-SEQUENCE:{disc_before}");
        }
        let secs = |t: Time| t as f64 / SECOND as f64;
        if let Some(pd) = parts {
            let _ = writeln!(
                s,
                "#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,PART-HOLD-BACK={:.3}",
                3.0 * secs(pd)
            );
            let _ = writeln!(s, "#EXT-X-PART-INF:PART-TARGET={:.3}", secs(pd));
        }
        // Parts are listed for the last three target durations.
        let part_window = 3 * g.target;
        let mut tail: Time = g.building.as_ref().map_or(0, |b| b.last - b.start);
        let mut show_parts = vec![false; listed.len()];
        for (i, seg) in listed.iter().enumerate().rev() {
            show_parts[i] = parts.is_some() && tail < part_window;
            tail += seg.duration;
        }
        // The init segment the media listed so far needs (fMP4).
        let mut map: Option<u64> = None;
        let mut write_map = |s: &mut String, init: u64| {
            if fmp4 && map != Some(init) {
                let _ = writeln!(s, "#EXT-X-MAP:URI=\"init-{init}.mp4\"");
                map = Some(init);
            }
        };
        for (i, seg) in listed.iter().enumerate() {
            if seg.discontinuity {
                s.push_str("#EXT-X-DISCONTINUITY\n");
            }
            write_map(&mut s, seg.init);
            if show_parts[i] {
                for (k, p) in seg.parts.iter().enumerate() {
                    write_part(&mut s, seg.seq, k, p, ext);
                }
            }
            let _ = writeln!(
                s,
                "#EXTINF:{:.3},\nseg-{}{ext}",
                secs(seg.duration),
                seg.seq
            );
        }
        if parts.is_some() {
            if let Some(b) = &g.building {
                if b.parts.is_empty() {
                    // The hinted part would need a discontinuity or a new map, which only go
                    // before listed media: no hint until the first part is out.
                    let new_map = fmp4 && listed.last().is_none_or(|l| l.init != b.init);
                    if b.discontinuity || new_map {
                        return s;
                    }
                } else {
                    if b.discontinuity {
                        s.push_str("#EXT-X-DISCONTINUITY\n");
                    }
                    write_map(&mut s, b.init);
                }
                for (k, p) in b.parts.iter().enumerate() {
                    write_part(&mut s, b.seq, k, p, ext);
                }
                let _ = writeln!(
                    s,
                    "#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part-{}.{}{ext}\"",
                    b.seq,
                    b.parts.len()
                );
            }
        }
        s
    }

    /// Answers the waiters that can be answered (after a part or segment was cut).
    fn wake(&self, g: &mut State) -> Vec<(Detached, Response)> {
        let mut out = Vec::new();
        let waiters = std::mem::take(&mut g.waiters);
        for w in waiters {
            match self.answer(g, &w.want) {
                Some(r) => out.push((w.resp, r)),
                None => g.waiters.push(w),
            }
        }
        out
    }

    fn expire_waiters(&self) {
        let now = Instant::now();
        let expired: Vec<Waiter> = {
            let mut g = lock(&self.state);
            let (gone, keep): (Vec<Waiter>, Vec<Waiter>) = std::mem::take(&mut g.waiters)
                .into_iter()
                .partition(|w| w.deadline <= now);
            g.waiters = keep;
            gone
        };
        for w in expired {
            w.resp
                .respond(Response::text(503, "timed out waiting for the stream"));
        }
    }
}

fn write_part(s: &mut String, seq: u64, k: usize, p: &Part, ext: &str) {
    let _ = write!(
        s,
        "#EXT-X-PART:DURATION={:.3},URI=\"part-{seq}.{k}{ext}\"",
        p.duration as f64 / SECOND as f64
    );
    if p.independent {
        s.push_str(",INDEPENDENT=YES");
    }
    s.push('\n');
}

/// The muxer of the segment format.
enum SegMuxer {
    Ts(Muxer),
    Mp4(fmp4::Muxer),
}

impl SegMuxer {
    fn carries(&self, index: usize) -> bool {
        match self {
            SegMuxer::Ts(m) => m.carries(index),
            SegMuxer::Mp4(m) => m.carries(index),
        }
    }

    /// Bytes written but not in the segment yet (an fMP4 fragment being built).
    fn pending(&self) -> usize {
        match self {
            SegMuxer::Ts(_) => 0,
            SegMuxer::Mp4(m) => m.pending_bytes(),
        }
    }

    /// Moves what is pending into `out` as a fragment ending at `end`.
    fn flush(&mut self, end: Time, out: &mut Vec<u8>) {
        if let SegMuxer::Mp4(m) = self {
            m.flush(Some(end), out);
        }
    }
}

/// The hub sink cutting segments.
struct HlsSink {
    st: Arc<Stream>,
    muxer: Option<SegMuxer>,
    timeline: Timeline,
    video: Vec<bool>,
    has_video: bool,
    started: bool,
    disc_pending: bool,
    /// The last segment was cut at `max_bytes` without a keyframe: the next one starts at once.
    forced_cut: bool,
}

impl HlsSink {
    /// Closes the segment being written at `end` (the next segment's start).
    fn close_segment(st: &Stream, g: &mut State, end: Time, mux: Option<&mut SegMuxer>) {
        let Some(mut b) = g.building.take() else {
            return;
        };
        if let Some(m) = mux {
            m.flush(end, &mut b.data);
        }
        if b.data.is_empty() {
            g.building = None;
            return;
        }
        Self::close_part(st, &mut b, end, None);
        let data = Arc::new(b.data);
        g.bytes += data.len() + b.parts.iter().map(|p| p.data.len()).sum::<usize>();
        g.segments.push_back(Segment {
            seq: b.seq,
            duration: (end - b.start).max(1),
            discontinuity: b.discontinuity,
            init: b.init,
            data,
            parts: b.parts,
        });
        g.next_seq = b.seq + 1;
        let keep = st.cfg.playlist_size + st.cfg.keep_segments;
        while g.segments.len() > keep.max(1) || (g.bytes > st.cfg.max_bytes && g.segments.len() > 1)
        {
            if let Some(old) = g.segments.pop_front() {
                g.bytes -= old.data.len() + old.parts.iter().map(|p| p.data.len()).sum::<usize>();
                if old.discontinuity {
                    g.disc_seq += 1;
                }
            }
        }
        g.prune_inits();
    }

    fn close_part(st: &Stream, b: &mut Building, end: Time, mux: Option<&mut SegMuxer>) {
        if st.cfg.part_duration.is_none() {
            return;
        }
        if let Some(m) = mux {
            m.flush(end, &mut b.data);
        }
        if b.data.len() == b.part_offset {
            return;
        }
        b.parts.push(Part {
            duration: (end - b.part_start).max(1),
            independent: b.part_independent,
            data: Arc::new(b.data[b.part_offset..].to_vec()),
        });
        b.part_offset = b.data.len();
        b.part_start = end;
    }
}

impl Sink for HlsSink {
    fn on_tracks(&mut self, tracks: &Tracks) {
        let respond = {
            let mut g = lock(&self.st.state);
            let end = g.building.as_ref().map_or(0, |b| b.last);
            Self::close_segment(&self.st, &mut g, end, self.muxer.as_mut());
            if self.started {
                self.timeline.restart();
                self.disc_pending = true;
            }
            self.started = true;
            self.muxer = Some(match self.st.cfg.format {
                SegmentFormat::Fmp4 => {
                    let m = fmp4::Muxer::new(tracks);
                    let same = g
                        .inits
                        .iter()
                        .find(|(n, _)| *n == g.init)
                        .is_some_and(|(_, d)| d.as_slice() == m.init_segment());
                    if !same {
                        let n = g.next_init;
                        g.next_init += 1;
                        g.inits.push_back((n, Arc::new(m.init_segment().to_vec())));
                        g.init = n;
                        g.prune_inits();
                    }
                    SegMuxer::Mp4(m)
                }
                _ => SegMuxer::Ts(Muxer::new(tracks)),
            });
            self.video = tracks.iter().map(|t| t.codec.is_video()).collect();
            self.has_video = self.video.iter().any(|&v| v);
            self.st.wake(&mut g)
        };
        for (d, r) in respond {
            d.respond(r);
        }
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        let Some(m) = self.muxer.as_mut() else { return };
        if !m.carries(pkt.track) {
            return;
        }
        let video = self.video.get(pkt.track).copied().unwrap_or(false);
        let dts = self.timeline.stamp(video, pkt.dts);
        let pts = (pkt.pts + self.timeline.offset()).max(dts);
        let target = dur_ns(self.st.cfg.target_duration);
        let part_target = self.st.cfg.part_duration.map(dur_ns);
        let respond = {
            let mut g = lock(&self.st.state);
            let cut_point = if self.has_video {
                video && pkt.keyframe
            } else {
                true
            };
            let mut woke = false;
            if let Some(b) = &g.building {
                // Without a keyframe the segment would grow forever: cut it at `max_bytes`.
                let full = b.bytes() + m.pending() + pkt.data.len() > self.st.cfg.max_bytes;
                if (cut_point && dts - b.start >= target) || full {
                    Self::close_segment(&self.st, &mut g, dts, Some(&mut *m));
                    woke = true;
                    self.forced_cut = !cut_point;
                }
            } else if self.has_video && !(video && pkt.keyframe) && !self.forced_cut {
                // Segments start at a keyframe.
                return;
            }
            let first = g.building.is_none();
            if first {
                self.forced_cut = false;
                let seq = g.next_seq;
                let disc = std::mem::take(&mut self.disc_pending) && !g.segments.is_empty();
                let mut data = Vec::new();
                if let SegMuxer::Mp4(_) = m {
                    fmp4::write_styp(&mut data);
                }
                g.building = Some(Building {
                    seq,
                    start: dts,
                    discontinuity: disc,
                    init: g.init,
                    data,
                    parts: Vec::new(),
                    part_start: dts,
                    part_offset: 0,
                    part_independent: true,
                    last: dts,
                });
            }
            let Some(mut b) = g.building.take() else {
                return;
            };
            if let Some(pt) = part_target {
                let part_len = b.data.len() - b.part_offset + m.pending();
                if !first && part_len > 0 && dts - b.part_start >= pt {
                    Self::close_part(&self.st, &mut b, dts, Some(&mut *m));
                    b.part_independent = video && pkt.keyframe;
                    woke = true;
                } else if part_len == 0 && video && pkt.keyframe {
                    b.part_independent = true;
                }
            }
            match m {
                SegMuxer::Ts(m) => {
                    if b.data.is_empty() || video && pkt.keyframe {
                        m.write_tables(&mut b.data);
                    }
                    let p = Packet::new(pkt.track, dts, pts, pkt.keyframe, pkt.data.clone());
                    m.write_packet(&p, &mut b.data);
                }
                SegMuxer::Mp4(m) => {
                    m.write_sample(pkt.track, dts, pts, pkt.keyframe, &pkt.data);
                }
            }
            b.last = b.last.max(dts);
            g.building = Some(b);
            if woke {
                self.st.wake(&mut g)
            } else {
                Vec::new()
            }
        };
        for (d, r) in respond {
            d.respond(r);
        }
    }

    fn on_close(&mut self, _err: HubError) {
        let respond = {
            let mut g = lock(&self.st.state);
            let end = g.building.as_ref().map_or(0, |b| b.last);
            Self::close_segment(&self.st, &mut g, end, self.muxer.as_mut());
            self.st.wake(&mut g)
        };
        for (d, r) in respond {
            d.respond(r);
        }
        self.st.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params() {
        assert_eq!(
            blocking_params(Some("_HLS_msn=5&_HLS_part=2")),
            (Some(5), Some(2))
        );
        assert_eq!(blocking_params(Some("x=1")), (None, None));
        assert_eq!(blocking_params(None), (None, None));
    }

    /// Packets of the sample stream (H.264 + AAC) and its tracks.
    fn sample() -> (Tracks, Vec<Packet>) {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        let data = include_bytes!("../testdata/h264_aac.flv");
        for t in Demuxer::new().feed(data).expect("flv") {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        (tracks.expect("tracks"), pkts)
    }

    fn sink(cfg: HlsConfig) -> HlsSink {
        HlsSink {
            st: Arc::new(Stream {
                path: "t".to_owned(),
                cors: None,
                state: Mutex::new(State {
                    target: dur_ns(cfg.target_duration),
                    ..State::default()
                }),
                cfg,
                sub: Mutex::new(None),
            }),
            muxer: None,
            timeline: Timeline::from_zero(),
            video: Vec::new(),
            has_video: false,
            started: false,
            disc_pending: false,
            forced_cut: false,
        }
    }

    /// A video stream with a single keyframe: before the fix the segment being written grew
    /// without limit (it is only cut at keyframes). Now it is cut at `max_bytes`, the stream
    /// keeps flowing into new segments, and memory stays bounded.
    #[test]
    fn segment_without_keyframes_is_cut_at_max_bytes() {
        let (tracks, pkts) = sample();
        let mut s = sink(HlsConfig {
            max_bytes: 20_000,
            part_duration: Some(Duration::from_millis(200)), // parts count toward the bound
            ..HlsConfig::default()
        });
        s.on_tracks(&tracks);
        let mut seen_key = false;
        let mut fed = 0;
        for round in 0..20i64 {
            for p in &pkts {
                // Only the very first keyframe stays one.
                let key = p.keyframe && !seen_key && round == 0;
                seen_key |= key;
                let shift = round * 10 * SECOND;
                let q = Arc::new(Packet::new(
                    p.track,
                    p.dts + shift,
                    p.pts + shift,
                    key,
                    p.data.clone(),
                ));
                fed += q.data.len();
                s.on_packet(&q);
                let g = lock(&s.st.state);
                let building = g.building.as_ref().map_or(0, Building::bytes);
                let biggest = 64 << 10; // one packet's overshoot (TS overhead included)
                assert!(building <= 20_000 + biggest, "building {building}");
                assert!(g.bytes <= 2 * 20_000 + 2 * biggest, "kept {}", g.bytes);
            }
        }
        let g = lock(&s.st.state);
        assert!(fed > 200_000, "fed only {fed}");
        assert!(g.next_seq > 5, "segments cut: {}", g.next_seq);
        // Every packet after the cut went somewhere: segments keep coming (no drop until a
        // keyframe that never arrives).
        assert!(g.segments.iter().all(|seg| !seg.data.is_empty()));
    }

    /// With keyframes, segments are still cut only at keyframes when under `max_bytes`.
    #[test]
    fn segments_still_start_at_keyframes_under_the_limit() {
        let (tracks, pkts) = sample();
        let mut s = sink(HlsConfig::default());
        s.on_tracks(&tracks);
        for round in 0..20i64 {
            let shift = round * 10 * SECOND;
            for p in &pkts {
                let q = Packet::new(
                    p.track,
                    p.dts + shift,
                    p.pts + shift,
                    p.keyframe,
                    p.data.clone(),
                );
                s.on_packet(&Arc::new(q));
                assert!(!s.forced_cut);
            }
        }
        let g = lock(&s.st.state);
        assert!(g.next_seq >= 1, "no segment cut");
    }

    /// Packets and tracks of the H.265 + AAC sample.
    fn sample_h265() -> (Tracks, Vec<Packet>) {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        let data = include_bytes!("../testdata/h265_aac.flv");
        for t in Demuxer::new().feed(data).expect("flv") {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        (tracks.expect("tracks"), pkts)
    }

    /// Feeds `pkts` `rounds` times in a row, shifted by `span` each round.
    fn feed(s: &mut HlsSink, pkts: &[Packet], rounds: i64, span: Time) {
        for round in 0..rounds {
            for p in pkts {
                let q = Packet::new(
                    p.track,
                    p.dts + round * span,
                    p.pts + round * span,
                    p.keyframe,
                    p.data.clone(),
                );
                s.on_packet(&Arc::new(q));
            }
        }
    }

    fn fmp4_cfg(parts: bool) -> HlsConfig {
        HlsConfig {
            format: SegmentFormat::Fmp4,
            target_duration: Duration::from_millis(500),
            part_duration: parts.then(|| Duration::from_millis(200)),
            playlist_size: 20,
            ..HlsConfig::default()
        }
    }

    fn boxes(b: &[u8]) -> Vec<[u8; 4]> {
        let mut v = Vec::new();
        let mut p = 0;
        while p + 8 <= b.len() {
            let n = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
            v.push([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]);
            p += n.max(8);
        }
        assert_eq!(p, b.len());
        v
    }

    /// LL-HLS in fMP4: version 9, one map, `.m4s` parts and segments; each part is whole
    /// fragments, a segment is a styp and its parts, and segments start with a keyframe.
    #[test]
    fn fmp4_playlist_with_parts() {
        let (tracks, pkts) = sample();
        let mut s = sink(fmp4_cfg(true));
        s.on_tracks(&tracks);
        feed(&mut s, &pkts, 2, 2 * SECOND);
        let g = lock(&s.st.state);
        let pl = s.st.playlist(&g);
        assert!(pl.contains("#EXT-X-VERSION:9\n"), "{pl}");
        assert_eq!(pl.matches("#EXT-X-MAP:").count(), 1, "{pl}");
        let map = pl.find("#EXT-X-MAP:URI=\"init-0.mp4\"\n").expect("map");
        assert!(map < pl.find("#EXTINF").expect("segments"), "{pl}");
        assert!(pl.contains("#EXT-X-PART:"), "{pl}");
        assert!(
            pl.contains("seg-0.m4s\n") && pl.contains(".m4s\",INDEPENDENT=YES"),
            "{pl}"
        );
        assert!(
            pl.contains("#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part-"),
            "{pl}"
        );
        assert!(!pl.contains(".ts"), "{pl}");
        assert!(g.segments.len() >= 3);
        let init = g
            .inits
            .iter()
            .find(|(n, _)| *n == 0)
            .expect("init")
            .1
            .clone();
        for seg in &g.segments {
            assert_eq!(seg.init, 0);
            // styp + the parts, byte for byte.
            assert_eq!(&seg.data[4..8], b"styp");
            let joined: Vec<u8> = seg
                .parts
                .iter()
                .flat_map(|p| p.data.iter().copied())
                .collect();
            assert_eq!(joined, *seg.data);
            for (k, p) in seg.parts.iter().enumerate() {
                let b = boxes(&p.data);
                let b: Vec<_> = b.into_iter().filter(|t| t != b"styp").collect();
                assert!(b.len() >= 2 && b.len() % 2 == 0, "part {k}: {b:?}");
                assert!(b.chunks(2).all(|c| c == [*b"moof", *b"mdat"]));
            }
            let mut all = init.to_vec();
            all.extend_from_slice(&seg.data);
            let (t, got) = fmp4::demux_all(&all).expect("segment parses");
            assert_eq!(t.expect("tracks").len(), 2);
            let first_video = got.iter().find(|p| p.track == 0).expect("video");
            assert!(first_video.keyframe);
            assert!(seg.parts[0].independent);
        }
    }

    /// Without parts: version 7, one fragment per segment.
    #[test]
    fn fmp4_playlist_without_parts() {
        let (tracks, pkts) = sample();
        let mut s = sink(fmp4_cfg(false));
        s.on_tracks(&tracks);
        feed(&mut s, &pkts, 2, 2 * SECOND);
        let g = lock(&s.st.state);
        let pl = s.st.playlist(&g);
        assert!(pl.contains("#EXT-X-VERSION:7\n"), "{pl}");
        assert!(pl.contains("#EXT-X-MAP:URI=\"init-0.mp4\""), "{pl}");
        assert!(!pl.contains("#EXT-X-PART") && !pl.contains(".ts"), "{pl}");
        for seg in &g.segments {
            assert_eq!(boxes(&seg.data), [*b"styp", *b"moof", *b"mdat"]);
            assert!(seg.parts.is_empty());
        }
        // The init segment answers; one that does not exist does not.
        assert!(s.st.answer(&g, &Want::Init(0)).is_some());
        assert!(s.st.answer(&g, &Want::Init(1)).is_none());
        assert!(!s.st.may_wait(&g, &Want::Init(1)));
    }

    /// A codec change: discontinuity and a new map; a republish with the same tracks: a
    /// discontinuity only. Init segments nothing uses are dropped.
    #[test]
    fn fmp4_discontinuity_and_new_map() {
        let (tracks, pkts) = sample();
        let (tracks2, pkts2) = sample_h265();
        let mut s = sink(fmp4_cfg(true));
        s.on_tracks(&tracks);
        feed(&mut s, &pkts, 1, 0);
        s.on_tracks(&tracks2);
        feed(&mut s, &pkts2, 1, 0);
        s.on_tracks(&tracks2);
        feed(&mut s, &pkts2, 1, 0);
        {
            let g = lock(&s.st.state);
            let pl = s.st.playlist(&g);
            assert_eq!(
                pl.matches("#EXT-X-DISCONTINUITY\n#EXT-X-MAP:URI=\"init-1.mp4\"\n")
                    .count(),
                1,
                "{pl}"
            );
            assert_eq!(pl.matches("#EXT-X-DISCONTINUITY\n").count(), 2, "{pl}");
            assert_eq!(pl.matches("#EXT-X-MAP:").count(), 2, "{pl}");
            assert!(!pl.contains("init-2.mp4"), "{pl}");
            assert_eq!(g.init, 1);
            assert_eq!(g.inits.len(), 2);
            assert!(s.st.answer(&g, &Want::Init(0)).is_some());
        }
        // Codec changes without packets keep only what is referenced.
        for i in 0..50 {
            s.on_tracks(if i % 2 == 0 { &tracks } else { &tracks2 });
        }
        let g = lock(&s.st.state);
        assert!(g.inits.len() <= 3, "{}", g.inits.len());
        assert!(g.inits.iter().any(|(n, _)| *n == g.init));
    }

    /// A stream without keyframes in fMP4: cut at `max_bytes` (pending fragment data counts),
    /// memory bounded.
    #[test]
    fn fmp4_segments_are_bounded_by_max_bytes() {
        let (tracks, pkts) = sample();
        let mut cfg = fmp4_cfg(true);
        cfg.max_bytes = 20_000;
        let mut s = sink(cfg);
        s.on_tracks(&tracks);
        let mut seen_key = false;
        for round in 0..20i64 {
            for p in &pkts {
                let key = p.keyframe && !seen_key;
                seen_key |= key;
                let shift = round * 10 * SECOND;
                let q = Packet::new(p.track, p.dts + shift, p.pts + shift, key, p.data.clone());
                s.on_packet(&Arc::new(q));
                let pending = match s.muxer.as_ref() {
                    Some(SegMuxer::Mp4(m)) => m.pending_bytes(),
                    _ => 0,
                };
                let g = lock(&s.st.state);
                let building = g.building.as_ref().map_or(0, Building::bytes) + pending;
                let biggest = 64 << 10;
                assert!(building <= 20_000 + biggest, "building {building}");
                assert!(g.bytes <= 2 * 20_000 + 2 * biggest, "kept {}", g.bytes);
            }
        }
        let g = lock(&s.st.state);
        assert!(g.next_seq > 5, "segments cut: {}", g.next_seq);
        assert_eq!(g.inits.len(), 1);
    }
}
