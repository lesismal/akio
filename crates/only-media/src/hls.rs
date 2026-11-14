//! HLS (RFC 8216) playback of hub streams, with the Low-Latency extensions (partial segments,
//! preload hints, blocking playlist reload) of its second edition.
//!
//! [`Hls`] is a only-http [`Service`] answering `GET /<path>/index.m3u8` (the media
//! playlist), `/<path>/seg-<n>.ts` and, with [`HlsConfig::part_duration`], `/<path>/part-<n>.<m>.ts`.
//! The first playlist request of a stream starts a muxer that subscribes to the hub (404 when
//! the stream has no publisher, unless [`HlsConfig::play_wait`] lets it wait) and cuts the stream
//! into MPEG-TS segments held in memory: at the first video keyframe
//! [`HlsConfig::target_duration`] after the segment start (audio-only streams on time). It keeps
//! a sliding window of [`HlsConfig::playlist_size`] segments plus a few more for late readers,
//! bounded by [`HlsConfig::max_bytes`], and stops after [`HlsConfig::idle_timeout`] without
//! requests. A republish or codec change starts a new segment after `EXT-X-DISCONTINUITY`.
//!
//! Requests that must wait (the first playlist, a blocking reload `?_HLS_msn=&_HLS_part=`, the
//! segment or part being written, a hinted part) are parked without holding a thread and
//! answered by the publisher's thread when what they wait for is cut (or after three target
//! durations with 503).
//!
//! Not supported: fMP4 segments, encryption, delta updates (`_HLS_skip`), rendition reports,
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
    hub::{Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
    mpegts::Muxer,
};

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
    /// Bound of the bytes a stream's segments take.
    pub max_bytes: usize,
    /// When set, segments are also published in parts of about this length (LL-HLS).
    pub part_duration: Option<Duration>,
    /// A muxer without requests for this long stops.
    pub idle_timeout: Duration,
    /// How long the first playlist request waits for a stream not published yet (`None`: 404).
    pub play_wait: Option<Duration>,
    /// The `Access-Control-Allow-Origin` value sent (`None`: no CORS header).
    pub cors_origin: Option<String>,
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
    data: Arc<Vec<u8>>,
    parts: Vec<Part>,
}

/// The segment being written.
#[derive(Debug)]
struct Building {
    seq: u64,
    start: Time,
    discontinuity: bool,
    data: Vec<u8>,
    parts: Vec<Part>,
    part_start: Time,
    part_offset: usize,
    part_independent: bool,
    last: Time,
}

enum Want {
    /// A playlist with at least one segment, or the given msn / part.
    Playlist {
        msn: Option<u64>,
        part: Option<usize>,
    },
    Segment(u64),
    Part(u64, usize),
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
        let want = if file == "index.m3u8" {
            let (msn, part) = blocking_params(ctx.req().query());
            Want::Playlist { msn, part }
        } else if let Some(n) = file
            .strip_prefix("seg-")
            .and_then(|f| f.strip_suffix(".ts"))
        {
            match n.parse() {
                Ok(n) => Want::Segment(n),
                Err(_) => return ctx.text(404, "not found"),
            }
        } else if let Some((n, m)) = file
            .strip_prefix("part-")
            .and_then(|f| f.strip_suffix(".ts"))
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
                    Response::with_body(200, "video/mp2t", s.data.to_vec()),
                    false,
                ))
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
                    Response::with_body(200, "video/mp2t", part.data.to_vec()),
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
        let _ = writeln!(s, "#EXT-X-VERSION:{}", if parts.is_some() { 9 } else { 3 });
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
        for (i, seg) in listed.iter().enumerate() {
            if seg.discontinuity {
                s.push_str("#EXT-X-DISCONTINUITY\n");
            }
            if show_parts[i] {
                for (k, p) in seg.parts.iter().enumerate() {
                    write_part(&mut s, seg.seq, k, p);
                }
            }
            let _ = writeln!(s, "#EXTINF:{:.3},\nseg-{}.ts", secs(seg.duration), seg.seq);
        }
        if parts.is_some() {
            if let Some(b) = &g.building {
                if b.discontinuity && !b.parts.is_empty() {
                    s.push_str("#EXT-X-DISCONTINUITY\n");
                }
                for (k, p) in b.parts.iter().enumerate() {
                    write_part(&mut s, b.seq, k, p);
                }
                let _ = writeln!(
                    s,
                    "#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part-{}.{}.ts\"",
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

fn write_part(s: &mut String, seq: u64, k: usize, p: &Part) {
    let _ = write!(
        s,
        "#EXT-X-PART:DURATION={:.3},URI=\"part-{seq}.{k}.ts\"",
        p.duration as f64 / SECOND as f64
    );
    if p.independent {
        s.push_str(",INDEPENDENT=YES");
    }
    s.push('\n');
}

/// The hub sink cutting segments.
struct HlsSink {
    st: Arc<Stream>,
    muxer: Option<Muxer>,
    timeline: Timeline,
    video: Vec<bool>,
    has_video: bool,
    started: bool,
    disc_pending: bool,
}

impl HlsSink {
    /// Closes the segment being written at `end` (the next segment's start).
    fn close_segment(st: &Stream, g: &mut State, end: Time) {
        let Some(mut b) = g.building.take() else {
            return;
        };
        if b.data.is_empty() {
            g.building = None;
            return;
        }
        Self::close_part(st, &mut b, end);
        let data = Arc::new(b.data);
        g.bytes += data.len() + b.parts.iter().map(|p| p.data.len()).sum::<usize>();
        g.segments.push_back(Segment {
            seq: b.seq,
            duration: (end - b.start).max(1),
            discontinuity: b.discontinuity,
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
    }

    fn close_part(st: &Stream, b: &mut Building, end: Time) {
        if st.cfg.part_duration.is_none() || b.data.len() == b.part_offset {
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
            Self::close_segment(&self.st, &mut g, end);
            if self.started {
                self.timeline.restart();
                self.disc_pending = true;
            }
            self.started = true;
            self.muxer = Some(Muxer::new(tracks));
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
                if cut_point && dts - b.start >= target {
                    Self::close_segment(&self.st, &mut g, dts);
                    woke = true;
                }
            } else if self.has_video && !(video && pkt.keyframe) {
                // Segments start at a keyframe.
                return;
            }
            let first = g.building.is_none();
            if first {
                let seq = g.next_seq;
                let disc = std::mem::take(&mut self.disc_pending) && !g.segments.is_empty();
                g.building = Some(Building {
                    seq,
                    start: dts,
                    discontinuity: disc,
                    data: Vec::new(),
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
                if !first && b.data.len() > b.part_offset && dts - b.part_start >= pt {
                    Self::close_part(&self.st, &mut b, dts);
                    b.part_independent = video && pkt.keyframe;
                    woke = true;
                } else if b.data.len() == b.part_offset && video && pkt.keyframe {
                    b.part_independent = true;
                }
            }
            if b.data.is_empty() || video && pkt.keyframe {
                m.write_tables(&mut b.data);
            }
            let p = Packet::new(pkt.track, dts, pts, pkt.keyframe, pkt.data.clone());
            m.write_packet(&p, &mut b.data);
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
            Self::close_segment(&self.st, &mut g, end);
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
}
