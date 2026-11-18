//! Recording hub streams to files: fragmented MP4, FLV or MPEG-TS, cut into files by duration
//! and size,
//! with rotation and start / stop hooks.
//!
//! [`Recorder::start`] subscribes to a stream; packets are muxed on the publisher's thread,
//! as for players, and the bytes go to the recorder's **writer thread**, which owns every file:
//! it creates, writes, syncs, closes and deletes them and runs the [`RecordHooks`]. No file
//! operation runs on an I/O thread (docs/rules.md 1.3: a hub sink has no connection to reach the
//! engine's logical pool through, so the recorder brings a thread of its own).
//!
//! The queue between them is bounded by [`RecordConfig::max_queued_bytes`]: when the disk does
//! not keep up and the queue is full, the file being written is closed and packets are dropped
//! until the queue is half empty and a video keyframe comes (any packet for audio-only
//! streams), which starts the next file. Files are never left with a hole in the middle.
//!
//! A file starts at a video keyframe (the GOP cache gives the first one at once) and is cut at
//! the first keyframe after [`RecordConfig::segment_duration`] or
//! [`RecordConfig::segment_bytes`]; a republish or a codec change also starts a new file.
//! Timestamps start at 0 in each file. fMP4 files are an init segment (`ftyp` + `moov`) and
//! fragments of up to a second, each starting at a keyframe when there is one; FLV files are
//! the FLV header, `onMetaData`, the sequence headers and the tags; MPEG-TS files are the
//! [`mpegts::Muxer`](crate::mpegts::Muxer)'s stream, with the PAT and PMT at the start, again
//! before every video keyframe and at least every second. With
//! [`RecordConfig::max_files`] only the newest files of each recording are kept.
//!
//! ```no_run
//! use std::time::Duration;
//! use only_media::{Hub, record::{RecordConfig, RecordFormat, Recorder}};
//!
//! let hub = Hub::default();
//! let mut cfg = RecordConfig::new("/var/lib/recordings");
//! cfg.format = RecordFormat::Flv;
//! cfg.segment_duration = Some(Duration::from_secs(600));
//! let rec = Recorder::new(hub.clone(), cfg);
//! rec.start("live/cam").unwrap(); // waits for the publisher (`RecordConfig::wait`)
//! // ...
//! rec.stop("live/cam");
//! ```
//!
//! To record every stream, start a recording from the hub's `on_publish` hook (it runs without
//! the hub's locks held, and the recording waits for the publisher being authorized).

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    fs::File,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    av::{Packet, SECOND, Time, Tracks},
    flv::{self, Encoder, EncoderConfig},
    fmp4,
    hub::{Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
    mpegts,
};

/// The container of recorded files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum RecordFormat {
    /// Fragmented MP4 (`.mp4`): H.264, H.265, VP8, VP9, AV1, AAC, Opus.
    #[default]
    Fmp4,
    /// FLV (`.flv`, Enhanced RTMP tags for H.265, VP8, VP9, AV1 and Opus): one video and one
    /// audio track.
    Flv,
    /// MPEG-TS (`.ts`): H.264, H.265, AV1, AAC, Opus, MP3.
    MpegTs,
}

impl RecordFormat {
    /// The file extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            RecordFormat::Fmp4 => "mp4",
            RecordFormat::Flv => "flv",
            RecordFormat::MpegTs => "ts",
        }
    }
}

/// Default [`RecordConfig::max_queued_bytes`].
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 32 << 20;

/// Configures a [`Recorder`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RecordConfig {
    /// The directory files are written to (created when missing).
    pub dir: PathBuf,
    /// The container.
    pub format: RecordFormat,
    /// Starts a new file at the first keyframe after this much media; `None`: no limit.
    pub segment_duration: Option<Duration>,
    /// Starts a new file at the first keyframe after the file reached this many bytes (and at
    /// once, without a keyframe, past four times as many); `None`: no limit.
    pub segment_bytes: Option<u64>,
    /// Keeps only the newest this many files of each recording, deleting older ones as new ones
    /// are closed; 0 keeps every file.
    pub max_files: usize,
    /// Bound of the bytes waiting for the writer thread, over every recording of the recorder
    /// (see the module documentation for what happens past it).
    pub max_queued_bytes: usize,
    /// How long a recording waits for its stream's first publisher and, after the publisher
    /// leaves, for the next one before it ends; `None`: [`Recorder::start`] needs a live
    /// stream, and the recording ends with its publisher.
    pub wait: Option<Duration>,
    /// FLV encoding options.
    pub flv: EncoderConfig,
}

impl RecordConfig {
    /// Records into `dir`: fMP4, one file per publish, every file kept.
    pub fn new(dir: impl Into<PathBuf>) -> RecordConfig {
        RecordConfig {
            dir: dir.into(),
            format: RecordFormat::Fmp4,
            segment_duration: None,
            segment_bytes: None,
            max_files: 0,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            wait: Some(Duration::from_secs(10)),
            flv: EncoderConfig::default(),
        }
    }
}

/// A recorded file, as the [`RecordHooks`] see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordFile {
    /// The hub path of the stream.
    pub stream: String,
    /// The file.
    pub path: PathBuf,
    /// The file's number in its recording: 0, 1, ...
    pub index: u64,
    /// When the file was started.
    pub started: SystemTime,
    /// The media it holds (0 when it starts).
    pub duration: Duration,
    /// Its size in bytes (0 when it starts).
    pub bytes: u64,
}

/// Observes a [`Recorder`]'s files. Every method runs on the recorder's writer thread, never
/// on an I/O thread, so it may block (move a file, update a database), though while it does
/// the recorder writes nothing.
pub trait RecordHooks: Send + Sync + 'static {
    /// The file name of file `index` of `stream`'s recording, started at `started`, relative to
    /// [`RecordConfig::dir`] (it may hold directories; a name with `..` or an absolute one is
    /// not used). Called on the publisher's thread: it must not block. Default:
    /// `<stream>-<unix time in ms>-<index>.<ext>`, the stream path with every character other
    /// than ASCII letters, digits, `-` and `_` replaced by `_`.
    fn file_name(&self, stream: &str, index: u64, started: SystemTime, ext: &str) -> String {
        default_name(stream, index, started, ext)
    }

    /// A file was created (`file.duration` and `file.bytes` are 0).
    fn on_start(&self, file: &RecordFile) {
        let _ = file;
    }

    /// A file was closed: completely written and synced to disk when `result` is `Ok`, else
    /// what failed (creating it, writing or syncing; the file may then be partial or missing).
    fn on_stop(&self, file: &RecordFile, result: Result<(), &io::Error>) {
        let _ = (file, result);
    }

    /// A file was deleted to keep [`RecordConfig::max_files`].
    fn on_remove(&self, path: &Path) {
        let _ = path;
    }
}

/// [`RecordHooks`] that keep the defaults.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl RecordHooks for NoHooks {}

fn default_name(stream: &str, index: u64, started: SystemTime, ext: &str) -> String {
    let ms = started
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let s: String = stream
        .trim_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{s}-{ms}-{index}.{ext}")
}

/// Whether `name` stays inside the directory it is joined to.
fn contained(name: &str) -> bool {
    let p = Path::new(name);
    !name.is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
        && p.file_name().is_some()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn dur_ns(d: Duration) -> Time {
    i64::try_from(d.as_nanos()).unwrap_or(Time::MAX)
}

/// What the sinks send the writer thread.
enum Op {
    Open {
        rec: u64,
        file: RecordFile,
    },
    Write {
        rec: u64,
        data: Vec<u8>,
    },
    Close {
        rec: u64,
        duration: Duration,
    },
    /// The recording ended: forget its rotation state.
    End {
        rec: u64,
    },
}

struct Inner {
    hub: Hub,
    cfg: RecordConfig,
    hooks: Arc<dyn RecordHooks>,
    /// Running recordings by stream path, with their id.
    active: Mutex<HashMap<String, (u64, Subscription)>>,
    next_id: AtomicU64,
    /// Bytes sent to the writer and not written yet.
    queued: Arc<AtomicUsize>,
    /// The writer thread's queue (started with the first recording).
    tx: Mutex<Option<Sender<Op>>>,
    /// Packets dropped because the queue was full.
    dropped: Arc<AtomicU64>,
}

/// Records hub streams to files. Cheap to clone; the writer thread ends once the recorder and
/// all its recordings are gone.
#[derive(Clone)]
pub struct Recorder(Arc<Inner>);

impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("cfg", &self.0.cfg)
            .finish_non_exhaustive()
    }
}

impl Recorder {
    /// A recorder of `hub`'s streams without hooks.
    pub fn new(hub: Hub, cfg: RecordConfig) -> Recorder {
        Recorder::with_hooks(hub, cfg, NoHooks)
    }

    /// A recorder of `hub`'s streams calling `hooks`.
    pub fn with_hooks(hub: Hub, cfg: RecordConfig, hooks: impl RecordHooks) -> Recorder {
        Recorder(Arc::new(Inner {
            hub,
            cfg,
            hooks: Arc::new(hooks),
            active: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            queued: Arc::new(AtomicUsize::new(0)),
            tx: Mutex::new(None),
            dropped: Arc::new(AtomicU64::new(0)),
        }))
    }

    /// Starts recording `path`. With [`RecordConfig::wait`] the stream need not be published
    /// yet; without, it must be ([`HubError::NotFound`]). A path already recorded is left as
    /// it is (`Ok`). The hub's `on_subscribe` hook sees protocol `"record"`. Fails with
    /// [`HubError::Closed`] when the writer thread cannot be started.
    pub fn start(&self, path: &str) -> Result<(), HubError> {
        if lock(&self.0.active).contains_key(path) {
            return Ok(());
        }
        let tx = self.writer().ok_or(HubError::Closed)?;
        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        let sink = RecordSink {
            inner: Arc::downgrade(&self.0),
            id,
            stream: path.to_owned(),
            tx,
            format: self.0.cfg.format,
            queued: self.0.queued.clone(),
            dropped: self.0.dropped.clone(),
            max_queued: self.0.cfg.max_queued_bytes.max(1),
            seg_dur: self.0.cfg.segment_duration.map(dur_ns),
            seg_bytes: self.0.cfg.segment_bytes,
            hooks: self.0.hooks.clone(),
            tracks: None,
            carried: Vec::new(),
            video: Vec::new(),
            has_video: false,
            timeline: Timeline::from_zero(),
            mux: None,
            buf: Vec::new(),
            index: 0,
            overflow: false,
            flv: self.0.cfg.flv.clone(),
            dir: self.0.cfg.dir.clone(),
        };
        let mut opts = SubscribeOptions::new(PeerInfo::new("record", None, ""));
        opts.wait = self.0.cfg.wait;
        // Not under `active`: the hub calls the sink (which may take `active`) while
        // subscribing.
        let sub = self.0.hub.subscribe(path, sink, opts)?;
        let old = lock(&self.0.active).insert(path.to_owned(), (id, sub));
        drop(old);
        Ok(())
    }

    /// Stops recording `path` (the file being written is closed); whether it was recorded.
    pub fn stop(&self, path: &str) -> bool {
        let old = lock(&self.0.active).remove(path);
        old.is_some()
    }

    /// Stops every recording.
    pub fn stop_all(&self) {
        let all = std::mem::take(&mut *lock(&self.0.active));
        drop(all);
    }

    /// The paths being recorded, sorted.
    pub fn active(&self) -> Vec<String> {
        let mut v: Vec<String> = lock(&self.0.active).keys().cloned().collect();
        v.sort();
        v
    }

    /// Packets dropped because the writer did not keep up ([`RecordConfig::max_queued_bytes`]).
    pub fn dropped(&self) -> u64 {
        self.0.dropped.load(Ordering::Relaxed)
    }

    /// Bytes waiting for the writer thread.
    pub fn queued_bytes(&self) -> usize {
        self.0.queued.load(Ordering::Relaxed)
    }

    /// The writer thread's queue, starting the thread if needed.
    fn writer(&self) -> Option<Sender<Op>> {
        let mut g = lock(&self.0.tx);
        if let Some(tx) = g.as_ref() {
            return Some(tx.clone());
        }
        let (tx, rx) = channel();
        let w = Writer {
            hooks: self.0.hooks.clone(),
            queued: self.0.queued.clone(),
            max_files: self.0.cfg.max_files,
            open: HashMap::new(),
            done: HashMap::new(),
        };
        std::thread::Builder::new()
            .name("only-media-record".to_owned())
            .spawn(move || w.run(rx))
            .ok()?;
        *g = Some(tx.clone());
        Some(tx)
    }
}

/// The muxer of the file being written.
enum Mux {
    Mp4 {
        m: fmp4::Muxer,
        /// The current fragment's start.
        frag_start: Time,
    },
    Flv(Encoder),
    Ts {
        m: mpegts::Muxer,
        /// When the tables were written last.
        tables: Time,
    },
}

/// The file being written.
struct Current {
    mux: Mux,
    /// The file's first timestamp (stream time), subtracted from every packet's.
    base: Time,
    last: Time,
    bytes: u64,
}

/// The hub sink of one recording.
struct RecordSink {
    inner: Weak<Inner>,
    id: u64,
    stream: String,
    tx: Sender<Op>,
    format: RecordFormat,
    queued: Arc<AtomicUsize>,
    dropped: Arc<AtomicU64>,
    max_queued: usize,
    seg_dur: Option<Time>,
    seg_bytes: Option<u64>,
    hooks: Arc<dyn RecordHooks>,
    tracks: Option<Tracks>,
    /// Which tracks are carried.
    carried: Vec<bool>,
    /// Which tracks are carried video.
    video: Vec<bool>,
    has_video: bool,
    timeline: Timeline,
    mux: Option<Current>,
    /// Bytes muxed and not sent to the writer yet.
    buf: Vec<u8>,
    /// The next file's number.
    index: u64,
    /// The queue was full: dropping until it drains and a file can start.
    overflow: bool,
    flv: EncoderConfig,
    dir: PathBuf,
}

/// Bytes gathered before they are sent to the writer.
const SEND_CHUNK: usize = 256 << 10;
/// The longest fMP4 fragment.
const MAX_FRAGMENT: Time = SECOND;

impl RecordSink {
    fn send(&self, op: Op) {
        // The writer only stops after every sender is gone.
        let _ = self.tx.send(op);
    }

    /// Sends what is buffered.
    fn push(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let data = std::mem::take(&mut self.buf);
        self.queued.fetch_add(data.len(), Ordering::Relaxed);
        if let Some(c) = &mut self.mux {
            c.bytes += data.len() as u64;
        }
        self.send(Op::Write { rec: self.id, data });
    }

    /// Closes the file being written, if any.
    fn close_file(&mut self) {
        let Some(mut c) = self.mux.take() else { return };
        if let Mux::Mp4 { m, .. } = &mut c.mux {
            m.flush(Some(c.last), &mut self.buf);
        }
        self.queued.fetch_add(self.buf.len(), Ordering::Relaxed);
        c.bytes += self.buf.len() as u64;
        let data = std::mem::take(&mut self.buf);
        if !data.is_empty() {
            self.send(Op::Write { rec: self.id, data });
        }
        let duration = Duration::from_nanos(u64::try_from(c.last - c.base).unwrap_or(0));
        self.send(Op::Close {
            rec: self.id,
            duration,
        });
    }

    /// Starts a file at `ts` with the current tracks.
    fn open_file(&mut self, ts: Time) {
        let Some(tracks) = &self.tracks else { return };
        let started = SystemTime::now();
        let ext = self.format.extension();
        let name = self.hooks.file_name(&self.stream, self.index, started, ext);
        let name = if contained(&name) {
            name
        } else {
            default_name(&self.stream, self.index, started, ext)
        };
        let file = RecordFile {
            stream: self.stream.clone(),
            path: self.dir.join(name),
            index: self.index,
            started,
            duration: Duration::ZERO,
            bytes: 0,
        };
        self.index += 1;
        self.send(Op::Open { rec: self.id, file });
        let mux = match self.format {
            RecordFormat::Fmp4 => {
                let m = fmp4::Muxer::new(tracks);
                self.buf.extend_from_slice(m.init_segment());
                Mux::Mp4 { m, frag_start: 0 }
            }
            RecordFormat::Flv => {
                let mut e = Encoder::new(self.flv.clone());
                e.set_tracks(tracks);
                let (v, a) = e.carried();
                flv::write_header(&mut self.buf, v.is_some(), a.is_some());
                for (t, body) in e.headers() {
                    flv::write_tag(&mut self.buf, t, 0, &body);
                }
                Mux::Flv(e)
            }
            RecordFormat::MpegTs => {
                let mut m = mpegts::Muxer::new(tracks);
                m.write_tables(&mut self.buf);
                Mux::Ts { m, tables: 0 }
            }
        };
        self.mux = Some(Current {
            mux,
            base: ts,
            last: ts,
            bytes: 0,
        });
    }

    /// Which of `tracks` the format carries.
    fn carried(&self, tracks: &Tracks) -> Vec<bool> {
        match self.format {
            RecordFormat::Fmp4 => {
                let m = fmp4::Muxer::new(tracks);
                (0..tracks.len()).map(|i| m.carries(i)).collect()
            }
            RecordFormat::Flv => {
                let mut e = Encoder::default();
                e.set_tracks(tracks);
                let (v, a) = e.carried();
                (0..tracks.len())
                    .map(|i| v == Some(i) || a == Some(i))
                    .collect()
            }
            RecordFormat::MpegTs => {
                let m = mpegts::Muxer::new(tracks);
                (0..tracks.len()).map(|i| m.carries(i)).collect()
            }
        }
    }
}

impl Sink for RecordSink {
    fn on_tracks(&mut self, tracks: &Tracks) {
        self.close_file();
        self.timeline.restart();
        let carried = self.carried(tracks);
        self.video = tracks
            .iter()
            .zip(&carried)
            .map(|(t, &c)| c && t.codec.is_video())
            .collect();
        self.has_video = self.video.iter().any(|&v| v);
        // Without a carried track there is nothing to record until the next tracks.
        self.tracks = carried.iter().any(|&c| c).then(|| tracks.clone());
        self.carried = carried;
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if self.tracks.is_none() || !self.carried.get(pkt.track).copied().unwrap_or(false) {
            return;
        }
        let video = self.video.get(pkt.track).copied().unwrap_or(false);
        let ts = self.timeline.stamp(video, pkt.dts);
        let pts = (pkt.pts + self.timeline.offset()).max(ts);
        let cut_point = !self.has_video || video && pkt.keyframe;
        // The writer fell behind: close the file and drop until it catches up.
        let queued = self.queued.load(Ordering::Relaxed) + self.buf.len();
        if !self.overflow && queued > self.max_queued {
            self.overflow = true;
            self.close_file();
        }
        if self.overflow {
            if queued > self.max_queued / 2 || !cut_point {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.overflow = false;
        }
        if let Some(c) = &self.mux {
            let len = c.bytes + self.buf.len() as u64;
            let long = self.seg_dur.is_some_and(|d| ts - c.base >= d);
            let big = self.seg_bytes.is_some_and(|b| len >= b);
            let huge = self.seg_bytes.is_some_and(|b| len >= b.saturating_mul(4));
            if cut_point && (long || big) || huge {
                self.close_file();
            }
        }
        if self.mux.is_none() {
            if !cut_point {
                return; // files start at a keyframe
            }
            self.open_file(ts);
        }
        let Some(c) = &mut self.mux else { return };
        let rel = (ts - c.base).max(0);
        let rel_pts = (pts - c.base).max(rel);
        c.last = c.last.max(ts);
        match &mut c.mux {
            Mux::Mp4 { m, frag_start } => {
                let frag_cut = if self.has_video {
                    video && pkt.keyframe || rel - *frag_start >= MAX_FRAGMENT
                } else {
                    rel - *frag_start >= MAX_FRAGMENT
                };
                if frag_cut && m.has_pending() {
                    m.flush(Some(rel), &mut self.buf);
                    *frag_start = rel;
                }
                if !m.write_sample(pkt.track, rel, rel_pts, pkt.keyframe, &pkt.data) {
                    // The fragment is full (1 GiB or 2^20 samples): start another.
                    m.flush(Some(rel), &mut self.buf);
                    *frag_start = rel;
                    m.write_sample(pkt.track, rel, rel_pts, pkt.keyframe, &pkt.data);
                }
            }
            Mux::Flv(e) => {
                let q = Packet::new(pkt.track, rel, rel_pts, pkt.keyframe, pkt.data.clone());
                if let Some((t, body)) = e.packet(&q) {
                    let ms = u32::try_from(flv::ms(rel)).unwrap_or(u32::MAX);
                    flv::write_tag(&mut self.buf, t, ms, &body);
                }
            }
            Mux::Ts { m, tables } => {
                if rel > 0 && (video && pkt.keyframe || rel - *tables >= SECOND) {
                    m.write_tables(&mut self.buf);
                    *tables = rel;
                }
                let q = Packet::new(pkt.track, rel, rel_pts, pkt.keyframe, pkt.data.clone());
                m.write_packet(&q, &mut self.buf);
            }
        }
        if self.buf.len() >= SEND_CHUNK || cut_point && !self.buf.is_empty() && video {
            self.push();
        }
    }

    fn on_close(&mut self, _err: HubError) {
        self.close_file();
        self.send(Op::End { rec: self.id });
        // The recording is over: forget it (if it is still this one).
        if let Some(inner) = self.inner.upgrade() {
            let old = {
                let mut g = lock(&inner.active);
                if g.get(&self.stream).is_some_and(|(id, _)| *id == self.id) {
                    g.remove(&self.stream)
                } else {
                    None
                }
            };
            drop(old);
        }
    }
}

impl Drop for RecordSink {
    fn drop(&mut self) {
        // Stopped (or the hub dropped it): close the file. After `on_close` this sends only
        // `End` again, which the writer ignores.
        self.close_file();
        self.send(Op::End { rec: self.id });
    }
}

/// A file the writer has open.
struct Open {
    file: Option<io::BufWriter<File>>,
    info: RecordFile,
    err: Option<io::Error>,
}

/// The writer thread's state.
struct Writer {
    hooks: Arc<dyn RecordHooks>,
    queued: Arc<AtomicUsize>,
    max_files: usize,
    open: HashMap<u64, Open>,
    /// Closed files of each recording, oldest first (for `max_files`).
    done: HashMap<u64, VecDeque<PathBuf>>,
}

impl Writer {
    fn run(mut self, rx: Receiver<Op>) {
        while let Ok(op) = rx.recv() {
            match op {
                Op::Open { rec, file } => self.open(rec, file),
                Op::Write { rec, data } => {
                    self.write(rec, &data);
                    self.queued.fetch_sub(data.len(), Ordering::Relaxed);
                }
                Op::Close { rec, duration } => self.close(rec, duration),
                Op::End { rec } => {
                    self.done.remove(&rec);
                }
            }
        }
    }

    fn open(&mut self, rec: u64, info: RecordFile) {
        let created = info
            .path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| File::create(&info.path));
        let (file, err) = match created {
            Ok(f) => (Some(io::BufWriter::with_capacity(256 << 10, f)), None),
            Err(e) => (None, Some(e)),
        };
        if err.is_none() {
            self.hooks.on_start(&info);
        }
        self.open.insert(rec, Open { file, info, err });
    }

    fn write(&mut self, rec: u64, data: &[u8]) {
        let Some(o) = self.open.get_mut(&rec) else {
            return;
        };
        if o.err.is_some() {
            return;
        }
        if let Some(f) = &mut o.file {
            match f.write_all(data) {
                Ok(()) => o.info.bytes += data.len() as u64,
                Err(e) => o.err = Some(e),
            }
        }
    }

    fn close(&mut self, rec: u64, duration: Duration) {
        let Some(mut o) = self.open.remove(&rec) else {
            return;
        };
        o.info.duration = duration;
        if let (Some(f), None) = (o.file.take(), &o.err) {
            let synced = f
                .into_inner()
                .map_err(io::IntoInnerError::into_error)
                .and_then(|f| f.sync_all());
            if let Err(e) = synced {
                o.err = Some(e);
            }
        }
        self.hooks
            .on_stop(&o.info, o.err.as_ref().map_or(Ok(()), Err));
        if o.err.is_some() && o.info.bytes == 0 {
            return;
        }
        let kept = self.done.entry(rec).or_default();
        kept.push_back(o.info.path);
        while self.max_files > 0 && kept.len() > self.max_files {
            if let Some(old) = kept.pop_front() {
                if std::fs::remove_file(&old).is_ok() {
                    self.hooks.on_remove(&old);
                }
            }
        }
    }
}
