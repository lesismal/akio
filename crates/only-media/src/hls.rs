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
//! **Multivariant playlists**: renditions of one source published as separate hub streams
//! (`live/cam_1080`, `live/cam_720`, an audio-only `live/cam_audio`...) are tied together by
//! [`Hls::add_multivariant`], which serves `/<name>.m3u8` (a [`Multivariant`]): one
//! `EXT-X-STREAM-INF` per [`Variant`] with `BANDWIDTH` (configured, or the peak bitrate of the
//! variant's segments plus its audio group's, with `AVERAGE-BANDWIDTH`), `CODECS` (RFC 6381
//! strings of the tracks the segment format carries), `RESOLUTION` and `AUDIO`, and one
//! `EXT-X-MEDIA:TYPE=AUDIO` per [`AudioRendition`] of a group. URIs are relative to the
//! multivariant playlist and carry its query string (for the hub's `on_subscribe` hook). A
//! request starts the muxers of every rendition and is answered once each has its tracks and,
//! when its bandwidth is measured, a segment (or after three target durations plus
//! [`HlsConfig::play_wait`] with the renditions that are ready; 503 with none). It works with
//! both segment formats and with LL-HLS (the media playlists carry the parts).
//!
//! **Encryption**: with [`HlsConfig::encryption`] every segment and part is encrypted whole
//! with AES-128 in CBC mode with PKCS #7 padding (`#EXT-X-KEY:METHOD=AES-128`), MPEG-TS and fMP4
//! alike. The IV is the segment's media sequence number (no `IV` attribute: RFC 8216 5.2), and a
//! part, which is a resource of its own, is encrypted separately with the IV of its segment.
//! fMP4 init segments stay clear: an `EXT-X-MAP` that follows a key is preceded by
//! `#EXT-X-KEY:METHOD=NONE`, and the key is named again before the next segment. A
//! [`KeyProvider`] issues the keys (key `n` of a stream, a new one every
//! [`HlsEncryption::rotate_every`] segments) and authorizes key requests, answered at
//! `/<path>/key-<n>.key` unless the provider names another URI. Segments of a key are only
//! served while the key is (they leave the window together).
//!
//! With [`EncryptionMethod::SampleAes`] the samples are encrypted inside the container instead
//! (`#EXT-X-KEY:METHOD=SAMPLE-AES`), H.264 and AAC tracks only (others are left out of the
//! segments): in MPEG-TS Apple's sample encryption (stream types 0xdb / 0xcf, slices in a 1:9
//! pattern after 32 clear bytes, AAC frames after the header and 16 bytes), one random IV per
//! key written as the `IV` attribute; in fMP4 the `cbcs` scheme (`encv` / `enca`, a constant
//! IV in `tenc`, `senc` / `saiz` / `saio` with each slice's NAL and slice headers clear, AAC
//! frames whole). Init segments and LL-HLS parts need nothing more: they are plain slices of
//! the encrypted stream.
//!
//! Not supported: SAMPLE-AES for H.265 and other codecs (H.265 `cbcs` needs its slice segment
//! header parsed), `EXT-X-SESSION-KEY`, delta updates (`_HLS_skip`), rendition reports,
//! `I-FRAME` playlists, subtitles and closed captions.

use std::{
    collections::{HashMap, VecDeque},
    fmt::{self, Write as _},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use only_http::{Context, Detached, Response, Service};

use only_crypto::aes::Aes;

use crate::{
    av::{Packet, SECOND, Time, Tracks},
    fmp4,
    hub::{Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
    mpegts::{Muxer, sample_aes::SampleKey},
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
    /// When set, segments and parts are encrypted (`EXT-X-KEY`): whole with AES-128, or
    /// sample by sample with SAMPLE-AES ([`HlsEncryption::method`]).
    pub encryption: Option<HlsEncryption>,
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
            encryption: None,
        }
    }
}

/// An AES-128 key of a stream, as a [`KeyProvider`] issues it.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HlsKey {
    /// The key.
    pub key: [u8; 16],
    /// The key's URI in the playlist (`URI` of `EXT-X-KEY`); `None` names the key Hls serves
    /// itself, `key-<n>.key` next to the media playlist.
    pub uri: Option<String>,
}

impl HlsKey {
    /// `key`, served by Hls.
    pub fn new(key: [u8; 16]) -> HlsKey {
        HlsKey { key, uri: None }
    }

    /// `key`, which players fetch from `uri` (absolute, or relative to the media playlist):
    /// for a key server of the application's own.
    pub fn with_uri(key: [u8; 16], uri: impl Into<String>) -> HlsKey {
        HlsKey {
            key,
            uri: Some(uri.into()),
        }
    }
}

impl fmt::Debug for HlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HlsKey")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

/// Issues the keys of encrypted streams and authorizes requests for them.
pub trait KeyProvider: Send + Sync + 'static {
    /// Key number `n` (0, 1, ...) of stream `path`, for the segments from the next one on.
    /// Called on the publisher's I/O thread with the stream's muxer locked: it must not block
    /// (no key server round trip; fetch or derive keys ahead of time) nor call into [`Hls`].
    /// A muxer that stops and starts again (idle, a republish after it ended) starts again at
    /// 0, and so do its media sequence numbers, which are the IVs: return a fresh key for every
    /// call, never one derived from `path` and `n` alone, or a restarted stream reuses key and
    /// IV pairs.
    fn key(&self, path: &str, n: u64) -> HlsKey;

    /// Whether the request in `ctx` may have key `n` of `path` (`key-<n>.key`); refused
    /// requests get 403. Runs on the requester's I/O thread: it must not block. Players send
    /// the cookies and headers of the playlist's origin; a token in the playlist's query string
    /// does not reach key URIs, so check cookies or headers, or name keys with
    /// [`HlsKey::with_uri`] and authorize them elsewhere. Default: every request.
    fn authorize(&self, path: &str, n: u64, ctx: &Context) -> bool {
        let _ = (path, n, ctx);
        true
    }
}

/// A [`KeyProvider`] issuing random keys (from a ChaCha20 generator seeded by the operating
/// system), served by Hls to every request.
pub struct RandomKeys(Mutex<only_crypto::rand::ChaChaRng>);

impl RandomKeys {
    /// A provider seeded from the operating system's generator.
    pub fn new() -> std::io::Result<RandomKeys> {
        Ok(RandomKeys(Mutex::new(
            only_crypto::rand::ChaChaRng::from_os()?,
        )))
    }
}

impl fmt::Debug for RandomKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RandomKeys")
    }
}

impl KeyProvider for RandomKeys {
    fn key(&self, _path: &str, _n: u64) -> HlsKey {
        let mut key = [0u8; 16];
        lock(&self.0).fill(&mut key);
        HlsKey::new(key)
    }
}

/// How [`Hls`] encrypts segments (`METHOD` of `EXT-X-KEY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum EncryptionMethod {
    /// `AES-128`: every segment and part encrypted whole (AES-128-CBC, PKCS #7), MPEG-TS and
    /// fMP4 alike; every player supports it.
    #[default]
    Aes128,
    /// `SAMPLE-AES`: the samples encrypted inside the container, its structure and the codec
    /// headers clear. MPEG-TS: Apple's MPEG-2 stream encryption format (H.264 slices with a
    /// 1:9 pattern after 32 clear bytes, AAC frames after 16), stream types 0xdb / 0xcf. fMP4:
    /// the `cbcs` scheme of ISO/IEC 23001-7 (`encv` / `enca`, a constant IV, H.264 slice
    /// headers clear and the slice data in a 1:9 pattern, AAC frames whole). Only H.264 and
    /// AAC tracks are carried: others are left out of the segments rather than sent clear.
    SampleAes,
}

/// Configures encryption of [`Hls`] segments ([`HlsConfig::encryption`]).
#[derive(Clone)]
#[non_exhaustive]
pub struct HlsEncryption {
    /// Issues and authorizes the keys.
    pub keys: Arc<dyn KeyProvider>,
    /// A new key every this many segments; 0 (the default) keeps one key for as long as the
    /// stream's muxer runs.
    pub rotate_every: u32,
    /// The method (AES-128 by default).
    pub method: EncryptionMethod,
}

impl HlsEncryption {
    /// Encryption with keys from `keys`, not rotated.
    pub fn new(keys: impl KeyProvider) -> HlsEncryption {
        HlsEncryption {
            keys: Arc::new(keys),
            rotate_every: 0,
            method: EncryptionMethod::Aes128,
        }
    }

    /// Sets [`method`](Self::method).
    #[must_use]
    pub fn method(mut self, method: EncryptionMethod) -> HlsEncryption {
        self.method = method;
        self
    }

    /// Sets [`rotate_every`](Self::rotate_every).
    #[must_use]
    pub fn rotate_every(mut self, segments: u32) -> HlsEncryption {
        self.rotate_every = segments;
        self
    }
}

// `HlsConfig` stays unwind safe with a provider in it: a provider that panics does so before
// the muxer's state changes (the key is stored after `key` returns, and every lock ignores
// poisoning), so nothing observes a half-made update.
impl std::panic::UnwindSafe for HlsEncryption {}
impl std::panic::RefUnwindSafe for HlsEncryption {}

impl fmt::Debug for HlsEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HlsEncryption")
            .field("rotate_every", &self.rotate_every)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// A key in use: its number, schedule and URI.
struct Key {
    n: u64,
    aes: Aes,
    uri: Option<String>,
    raw: [u8; 16],
    /// SAMPLE-AES in MPEG-TS: the IV of every segment of the key (the `IV` attribute).
    iv: [u8; 16],
}

/// A random IV (the time when the system has no random source: an IV only has to differ).
fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    if only_crypto::rand::fill_random(&mut iv).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        iv = t.to_be_bytes();
    }
    iv
}

/// The IV of segment `seq` (and its parts): its media sequence number, big-endian.
fn iv_of(seq: u64) -> [u8; 16] {
    u128::from(seq).to_be_bytes()
}

/// Bytes of a segment encrypted at a time while it is written (spreads the cost over the
/// segment rather than paying it all at its end).
const ENCRYPT_CHUNK: usize = 64 << 10;

/// The ciphertext of the segment being written, encrypted as its bytes come (AES-128); with
/// SAMPLE-AES, which the muxer applies, only the key.
struct Encrypting {
    key: Arc<Key>,
    /// AES-128: the segment is encrypted whole.
    whole: bool,
    /// The CBC chaining value.
    iv: [u8; 16],
    /// Plaintext bytes encrypted so far (a whole number of blocks).
    done: usize,
    out: Vec<u8>,
}

impl fmt::Debug for Encrypting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypting")
            .field("key", &self.key.n)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Encrypting {
    /// Encrypts what was added to `data` once it is [`ENCRYPT_CHUNK`] or more (kept out of the
    /// packet path of unencrypted streams).
    #[inline(never)]
    fn step(&mut self, data: &[u8]) {
        if self.whole && data.len() - self.done >= ENCRYPT_CHUNK {
            self.more(data);
        }
    }

    /// The ciphertext of a part of segment `seq`: a resource of its own, encrypted from the
    /// segment's IV.
    #[inline(never)]
    fn part(&self, seq: u64, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() + 16);
        self.key
            .aes
            .encrypt_cbc_padded(&iv_of(seq), plain, &mut out);
        out
    }

    /// Encrypts the whole blocks of `data` not encrypted yet.
    fn more(&mut self, data: &[u8]) {
        let end = data.len() - (data.len() - self.done) % 16;
        if end > self.done {
            let at = self.out.len();
            self.out.extend_from_slice(&data[self.done..end]);
            let _ = self.key.aes.encrypt_cbc(&mut self.iv, &mut self.out[at..]);
            self.done = end;
        }
    }

    /// Encrypts the rest of `data` with its padding and returns the ciphertext.
    fn finish(mut self, data: &[u8]) -> Vec<u8> {
        self.more(data);
        let rest = &data[self.done..];
        let pad = 16 - rest.len();
        let at = self.out.len();
        self.out.extend_from_slice(rest);
        self.out.resize(at + 16, pad as u8);
        let _ = self.key.aes.encrypt_cbc(&mut self.iv, &mut self.out[at..]);
        self.out
    }
}

/// One rendition of a [`Multivariant`] playlist: a hub stream, listed with
/// `EXT-X-STREAM-INF`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Variant {
    /// The hub path of the stream; its media playlist is `/<path>/index.m3u8`.
    pub path: String,
    /// `BANDWIDTH` in bits per second; `None` measures it: the peak bitrate of the stream's
    /// segments (and of its audio group's), with `AVERAGE-BANDWIDTH` their mean.
    pub bandwidth: Option<u64>,
    /// The `GROUP-ID` of the [`AudioRendition`]s that play with this variant (`AUDIO`).
    pub audio_group: Option<String>,
}

impl Variant {
    /// The variant playing hub stream `path`, its bandwidth measured, no audio group.
    pub fn new(path: impl Into<String>) -> Variant {
        Variant {
            path: path.into(),
            bandwidth: None,
            audio_group: None,
        }
    }
}

/// An alternative audio rendition of a [`Multivariant`] playlist: an audio-only hub stream,
/// listed with `EXT-X-MEDIA:TYPE=AUDIO`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioRendition {
    /// `GROUP-ID`.
    pub group: String,
    /// `NAME`, unique in the group.
    pub name: String,
    /// The hub path of the stream; its media playlist is `/<path>/index.m3u8`.
    pub path: String,
    /// `LANGUAGE` (RFC 5646), if any.
    pub language: Option<String>,
    /// `DEFAULT=YES`: played unless the user picks another.
    pub default: bool,
}

impl AudioRendition {
    /// A rendition of group `group` named `name` playing hub stream `path`.
    pub fn new(
        group: impl Into<String>,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> AudioRendition {
        AudioRendition {
            group: group.into(),
            name: name.into(),
            path: path.into(),
            language: None,
            default: false,
        }
    }
}

/// A multivariant (master) playlist over renditions published as separate streams, served
/// by [`Hls::add_multivariant`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Multivariant {
    /// The variants, in the order listed (players start with the first).
    pub variants: Vec<Variant>,
    /// The alternative audio renditions.
    pub audio: Vec<AudioRendition>,
}

impl Multivariant {
    /// A playlist with no rendition yet.
    pub fn new() -> Multivariant {
        Multivariant::default()
    }

    /// Every hub path it refers to.
    fn paths(&self) -> impl Iterator<Item = &str> {
        self.variants
            .iter()
            .map(|v| v.path.as_str())
            .chain(self.audio.iter().map(|a| a.path.as_str()))
    }
}

/// What a master playlist needs of a rendition, known once its muxer has its tracks.
#[derive(Debug, Clone, Default)]
struct Desc {
    /// RFC 6381 strings of the carried tracks.
    codecs: Vec<String>,
    /// The picture size of the first carried video track.
    resolution: Option<(u32, u32)>,
    /// Channels of the first carried audio track.
    channels: Option<u8>,
}

/// A rendition's description and bitrates (peak, average; 0 without segments).
struct Rendition {
    desc: Desc,
    peak: u64,
    average: u64,
}

/// The URI of `target` relative to the directory of `from` (both hub-style paths).
fn relative(from: &str, target: &str) -> String {
    let base: Vec<&str> = from.split('/').filter(|c| !c.is_empty()).collect();
    let base = &base[..base.len().saturating_sub(1)];
    let to: Vec<&str> = target.split('/').filter(|c| !c.is_empty()).collect();
    let common = base.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out = "../".repeat(base.len() - common);
    out.push_str(&to[common..].join("/"));
    out
}

/// Quotes an attribute value (a quoted-string has no `"` nor line breaks).
fn quoted(v: &str) -> String {
    v.chars()
        .filter(|c| !matches!(c, '"' | '\r' | '\n'))
        .collect()
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
    /// Multivariant playlists by name (served at `/<name>.m3u8`).
    masters: Mutex<HashMap<String, Arc<Multivariant>>>,
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
    /// The key it is encrypted with.
    key: Option<u64>,
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
    /// The key it is encrypted with and, with AES-128, its ciphertext so far (boxed: the
    /// building segment is moved in and out of the state for every packet).
    enc: Option<Box<Encrypting>>,
}

impl Building {
    /// Memory held: the segment, its ciphertext and its parts (which copy the segment's
    /// bytes).
    fn bytes(&self) -> usize {
        self.data.len()
            + self.enc.as_ref().map_or(0, |e| e.out.len())
            + self.parts.iter().map(|p| p.data.len()).sum::<usize>()
    }

    fn key(&self) -> Option<u64> {
        self.enc.as_ref().map(|e| e.key.n)
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
    /// The rendition's description for multivariant playlists (set with the tracks; boxed to
    /// keep the state the segmenting path touches small).
    desc: Option<Box<Desc>>,
    /// The longest segment cut so far, in seconds rounded to the nearest (RFC 8216 4.3.3.1
    /// compares rounded durations with the target duration, which must not change).
    longest: u64,
    /// Encryption keys: the current one and those kept segments use.
    keys: VecDeque<Arc<Key>>,
    /// Segments started with the current key (the last of `keys`).
    key_segments: u32,
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

    /// Drops the keys nothing refers to any more (the last one is current).
    fn prune_keys(&mut self) {
        let (segments, building) = (&self.segments, &self.building);
        let last = self.keys.back().map(|k| k.n);
        self.keys.retain(|k| {
            Some(k.n) == last
                || building.as_ref().is_some_and(|b| b.key() == Some(k.n))
                || segments.iter().any(|s| s.key == Some(k.n))
        });
    }

    /// The key a new segment of `st` is encrypted with: the current one, or a new one when
    /// there is none yet or it was used for `rotate_every` segments.
    #[inline(never)]
    fn key_for_segment(&mut self, st: &Stream) -> Option<Arc<Key>> {
        let enc = st.cfg.encryption.as_ref()?;
        let rotate = enc.rotate_every > 0 && self.key_segments >= enc.rotate_every;
        if self.keys.is_empty() || rotate {
            let n = self.keys.back().map_or(0, |k| k.n + 1);
            let k = enc.keys.key(&st.path, n);
            let sample_ts =
                enc.method == EncryptionMethod::SampleAes && st.cfg.format == SegmentFormat::MpegTs;
            self.keys.push_back(Arc::new(Key {
                n,
                aes: Aes::new128(&k.key),
                uri: k.uri,
                raw: k.key,
                iv: if sample_ts { random_iv() } else { [0; 16] },
            }));
            self.key_segments = 0;
            self.prune_keys();
        }
        self.key_segments += 1;
        self.keys.back().cloned()
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

impl Stream {
    fn sample_aes(&self) -> bool {
        self.cfg
            .encryption
            .as_ref()
            .is_some_and(|e| e.method == EncryptionMethod::SampleAes)
    }
}

impl Hls {
    /// A service playing streams of `hub`.
    pub fn new(hub: Hub, cfg: HlsConfig) -> Hls {
        Hls(Arc::new(Inner {
            hub,
            cfg,
            muxers: Mutex::new(HashMap::new()),
            masters: Mutex::new(HashMap::new()),
        }))
    }

    /// Serves `playlist` at `/<name>.m3u8` (`name` like a hub path, `live/cam`), replacing
    /// the playlist of that name if there was one. The renditions' streams need not be
    /// published yet: those that are not are left out of the answers until they are.
    pub fn add_multivariant(&self, name: &str, playlist: Multivariant) {
        let name = name.trim_matches('/').to_owned();
        lock(&self.0.masters).insert(name, Arc::new(playlist));
    }

    /// Stops serving the multivariant playlist `name`; whether there was one.
    pub fn remove_multivariant(&self, name: &str) -> bool {
        lock(&self.0.masters)
            .remove(name.trim_matches('/'))
            .is_some()
    }

    /// The description and bitrates of the rendition at `path`, once its muxer knows its
    /// tracks; `None` before (or when no muxer runs).
    fn rendition(&self, path: &str) -> Option<Rendition> {
        let st = lock(&self.0.muxers).get(path).cloned()?;
        let g = lock(&st.state);
        let desc = (**g.desc.as_ref()?).clone();
        let (mut peak, mut bytes, mut dur) = (0u64, 0u128, 0u128);
        for seg in &g.segments {
            let d = seg.duration.max(1) as u128;
            let b = seg.data.len() as u128 * 8;
            peak = peak.max(u64::try_from(b * SECOND as u128 / d).unwrap_or(u64::MAX));
            bytes += b;
            dur += d;
        }
        let average = (bytes * SECOND as u128)
            .checked_div(dur)
            .map_or(0, |v| u64::try_from(v).unwrap_or(u64::MAX));
        Some(Rendition {
            desc,
            peak,
            average,
        })
    }

    /// The multivariant playlist `name` of `m`; `None` while a rendition is not ready (all of
    /// them, unless `late`: then those ready, `None` with none).
    fn master_playlist(
        &self,
        name: &str,
        m: &Multivariant,
        query: &str,
        late: bool,
    ) -> Option<String> {
        let suffix = if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        };
        let uri = |path: &str| format!("{}{suffix}", relative(name, &format!("{path}/index.m3u8")));
        let audio: Vec<(&AudioRendition, Rendition)> = m
            .audio
            .iter()
            .filter_map(|a| self.rendition(&a.path).map(|r| (a, r)))
            .collect();
        let variants: Vec<(&Variant, Rendition)> = m
            .variants
            .iter()
            .filter_map(|v| self.rendition(&v.path).map(|r| (v, r)))
            .filter(|(v, r)| v.bandwidth.is_some() || r.peak > 0)
            .collect();
        let ready = variants.len() == m.variants.len()
            && audio.len() == m.audio.len()
            && audio.iter().all(|(_, r)| r.peak > 0);
        if variants.is_empty() || !(ready || late) {
            return None;
        }
        let fmp4 = self.0.cfg.format == SegmentFormat::Fmp4;
        let mut s = String::with_capacity(512);
        s.push_str("#EXTM3U\n");
        let _ = writeln!(s, "#EXT-X-VERSION:{}", if fmp4 { 7 } else { 3 });
        for (a, r) in &audio {
            let _ = write!(
                s,
                "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"{}\",NAME=\"{}\"",
                quoted(&a.group),
                quoted(&a.name)
            );
            if let Some(l) = &a.language {
                let _ = write!(s, ",LANGUAGE=\"{}\"", quoted(l));
            }
            let default = if a.default { "YES" } else { "NO" };
            let _ = write!(s, ",DEFAULT={default},AUTOSELECT=YES");
            if let Some(ch) = r.desc.channels {
                let _ = write!(s, ",CHANNELS=\"{ch}\"");
            }
            let _ = writeln!(s, ",URI=\"{}\"", uri(&a.path));
        }
        for (v, r) in &variants {
            let group: Vec<&(&AudioRendition, Rendition)> = audio
                .iter()
                .filter(|(a, _)| Some(&a.group) == v.audio_group.as_ref())
                .collect();
            let mut codecs = r.desc.codecs.clone();
            for (_, ar) in &group {
                for c in &ar.desc.codecs {
                    if !codecs.contains(c) {
                        codecs.push(c.clone());
                    }
                }
            }
            let audio_peak = group.iter().map(|(_, a)| a.peak).max().unwrap_or(0);
            let audio_avg = group.iter().map(|(_, a)| a.average).max().unwrap_or(0);
            let bandwidth = v.bandwidth.unwrap_or(r.peak + audio_peak).max(1);
            let _ = write!(s, "#EXT-X-STREAM-INF:BANDWIDTH={bandwidth}");
            if v.bandwidth.is_none() && r.average > 0 {
                let _ = write!(s, ",AVERAGE-BANDWIDTH={}", r.average + audio_avg);
            }
            if !codecs.is_empty() {
                let _ = write!(s, ",CODECS=\"{}\"", codecs.join(","));
            }
            if let Some((w, h)) = r.desc.resolution {
                let _ = write!(s, ",RESOLUTION={w}x{h}");
            }
            if let Some(g) = v.audio_group.as_ref().filter(|_| !group.is_empty()) {
                let _ = write!(s, ",AUDIO=\"{}\"", quoted(g));
            }
            let _ = writeln!(s, "\n{}", uri(&v.path));
        }
        Some(s)
    }

    /// Answers a multivariant playlist request: starts the renditions' muxers, then answers
    /// at once if every rendition is ready, else parks the request (checked every 50 ms).
    fn master(&self, name: &str, m: Arc<Multivariant>, ctx: &mut Context) {
        for path in m.paths() {
            if let Ok(st) = self.stream(path, ctx) {
                lock(&st.state).last_access = Some(Instant::now());
            }
        }
        let query = ctx.req().query().unwrap_or("").to_owned();
        if let Some(body) = self.master_playlist(name, &m, &query, false) {
            return ctx.respond(self.master_response(body));
        }
        let Some(d) = ctx.detach() else { return };
        let cfg = &self.0.cfg;
        let deadline = Instant::now() + 3 * cfg.target_duration + cfg.play_wait.unwrap_or_default();
        master_wait(
            Arc::downgrade(&self.0),
            name.to_owned(),
            m,
            query,
            d,
            deadline,
        );
    }

    fn master_response(&self, body: String) -> Response {
        let mut r = Response::with_body(200, "application/vnd.apple.mpegurl", body.into_bytes())
            .header("Cache-Control", "no-cache");
        if let Some(o) = &self.0.cfg.cors_origin {
            r = r.header("Access-Control-Allow-Origin", o);
        }
        r
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

    /// Answers a request for key `n` of `path` (`key-<n>.key`).
    fn serve_key(&self, path: &str, n: &str, ctx: &mut Context) {
        let (Some(enc), Ok(n)) = (&self.0.cfg.encryption, n.parse::<u64>()) else {
            return ctx.text(404, "not found");
        };
        let Some(st) = lock(&self.0.muxers).get(path).cloned() else {
            return ctx.text(404, "not found");
        };
        let raw = {
            let mut g = lock(&st.state);
            g.last_access = Some(Instant::now());
            g.keys.iter().find(|k| k.n == n).map(|k| k.raw)
        };
        let Some(raw) = raw else {
            return ctx.text(404, "not found");
        };
        if !enc.keys.authorize(path, n, ctx) {
            return ctx.text(403, "forbidden");
        }
        let mut r = Response::with_body(200, "application/octet-stream", raw.to_vec())
            .header("Cache-Control", "private, no-store");
        if let Some(o) = &st.cors {
            r = r.header("Access-Control-Allow-Origin", o);
        }
        ctx.respond(r);
    }

    fn arm_idle(&self, st: &Arc<Stream>) {
        let weak_hls = Arc::downgrade(&self.0);
        let weak = Arc::downgrade(st);
        let every = (st.cfg.idle_timeout / 2).max(Duration::from_millis(50));
        crate::timer::after(every, move || idle_check(&weak_hls, &weak));
    }
}

/// Checks a parked multivariant playlist request every 50 ms until it can be answered or its
/// deadline passes.
fn master_wait(
    hls: Weak<Inner>,
    name: String,
    m: Arc<Multivariant>,
    query: String,
    d: Detached,
    deadline: Instant,
) {
    crate::timer::after(Duration::from_millis(50), move || {
        let Some(inner) = hls.upgrade() else {
            d.respond(Response::text(503, "stopped"));
            return;
        };
        let h = Hls(inner);
        let late = Instant::now() >= deadline;
        match h.master_playlist(&name, &m, &query, late) {
            Some(body) => d.respond(h.master_response(body)),
            None if late => d.respond(Response::text(503, "no rendition is ready")),
            None => master_wait(hls, name, m, query, d, deadline),
        }
    });
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
        if let Some(name) = p.strip_suffix(".m3u8") {
            let m = lock(&self.0.masters).get(name).cloned();
            if let Some(m) = m {
                return self.master(name, m, ctx);
            }
        }
        let Some((path, file)) = p.rsplit_once('/') else {
            return ctx.text(404, "not found");
        };
        if path.is_empty() || path.contains("..") {
            return ctx.text(404, "not found");
        }
        if let Some(n) = file
            .strip_prefix("key-")
            .and_then(|f| f.strip_suffix(".key"))
        {
            return self.serve_key(path, n, ctx);
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
        // The configured target (rounded up) or the longest segment so far (rounded to the
        // nearest second): it only grows, so reloads see the same value unless a segment
        // outgrows it.
        let target = (g.target.max(1) + SECOND - 1) / SECOND;
        let target = (target as u64).max(g.longest);
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
        // The init segment and the key in effect (fMP4 init segments are clear: a map after a
        // key is preceded by METHOD=NONE).
        let mut map: Option<u64> = None;
        let mut key: Option<u64> = None;
        let sample_ts = self.sample_aes() && !fmp4;
        let method = if self.sample_aes() {
            "SAMPLE-AES"
        } else {
            "AES-128"
        };
        let mut write_media = |s: &mut String, init: u64, k: Option<u64>| {
            if fmp4 && map != Some(init) {
                if key.take().is_some() {
                    s.push_str("#EXT-X-KEY:METHOD=NONE\n");
                }
                let _ = writeln!(s, "#EXT-X-MAP:URI=\"init-{init}.mp4\"");
                map = Some(init);
            }
            if k != key {
                match k.and_then(|n| g.keys.iter().find(|x| x.n == n)) {
                    Some(x) => {
                        let _ = match &x.uri {
                            Some(u) => {
                                write!(s, "#EXT-X-KEY:METHOD={method},URI=\"{}\"", quoted(u))
                            }
                            None => write!(s, "#EXT-X-KEY:METHOD={method},URI=\"key-{}.key\"", x.n),
                        };
                        if sample_ts {
                            s.push_str(",IV=0x");
                            for b in x.iv {
                                let _ = write!(s, "{b:02X}");
                            }
                        }
                        s.push('\n');
                    }
                    None => s.push_str("#EXT-X-KEY:METHOD=NONE\n"),
                }
                key = k;
            }
        };
        for (i, seg) in listed.iter().enumerate() {
            if seg.discontinuity {
                s.push_str("#EXT-X-DISCONTINUITY\n");
            }
            write_media(&mut s, seg.init, seg.key);
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
                    // The hinted part would need a discontinuity, a new map or a new key,
                    // which only go before listed media: no hint until the first part is out.
                    let new_map = fmp4 && listed.last().is_none_or(|l| l.init != b.init);
                    let new_key = listed
                        .last()
                        .map_or_else(|| b.key().is_some(), |l| l.key != b.key());
                    if b.discontinuity || new_map || new_key {
                        return s;
                    }
                } else {
                    if b.discontinuity {
                        s.push_str("#EXT-X-DISCONTINUITY\n");
                    }
                    write_media(&mut s, b.init, b.key());
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
        if g.waiters.is_empty() {
            // The common case on the publisher's thread: nothing to build or answer.
            return Vec::new();
        }
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

    /// SAMPLE-AES: the key (and IV) of the next segment.
    #[inline(never)]
    fn set_sample_key(&mut self, key: &Key) {
        match self {
            SegMuxer::Ts(m) => m.set_sample_key(SampleKey {
                aes: key.aes.clone(),
                iv: key.iv,
            }),
            SegMuxer::Mp4(m) => m.set_sample_key(key.aes.clone()),
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
        let key = b.key();
        let data = Arc::new(match b.enc.take() {
            Some(e) if e.whole => (*e).finish(&b.data),
            _ => b.data,
        });
        g.bytes += data.len() + b.parts.iter().map(|p| p.data.len()).sum::<usize>();
        let duration = (end - b.start).max(1);
        g.longest = g.longest.max(((duration + SECOND / 2) / SECOND) as u64);
        g.segments.push_back(Segment {
            seq: b.seq,
            duration,
            discontinuity: b.discontinuity,
            init: b.init,
            key,
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
        g.prune_keys();
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
        let plain = &b.data[b.part_offset..];
        let data = match &b.enc {
            Some(e) if e.whole => e.part(b.seq, plain),
            _ => plain.to_vec(),
        };
        b.parts.push(Part {
            duration: (end - b.part_start).max(1),
            independent: b.part_independent,
            data: Arc::new(data),
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
                    let m = if self.st.sample_aes() {
                        fmp4::Muxer::cbcs(tracks)
                    } else {
                        fmp4::Muxer::new(tracks)
                    };
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
                _ if self.st.sample_aes() => SegMuxer::Ts(Muxer::sample_aes(tracks)),
                _ => SegMuxer::Ts(Muxer::new(tracks)),
            });
            // Only carried video counts: a stream whose video the format cannot carry (VP9 or
            // AV1 in MPEG-TS) is cut like an audio-only one.
            let m = self.muxer.as_ref();
            self.video = tracks
                .iter()
                .enumerate()
                .map(|(i, t)| t.codec.is_video() && m.is_some_and(|m| m.carries(i)))
                .collect();
            self.has_video = self.video.iter().any(|&v| v);
            let carried = |i: usize| m.is_some_and(|m| m.carries(i));
            let mut desc = Desc::default();
            let kept = tracks.iter().enumerate().filter(|&(i, _)| carried(i));
            for t in kept.map(|(_, t)| t) {
                if let Some(c) = t.codec_string().filter(|c| !desc.codecs.contains(c)) {
                    desc.codecs.push(c);
                }
                if t.is_video() && t.width > 0 && desc.resolution.is_none() {
                    desc.resolution = Some((t.width, t.height));
                }
                if t.codec.is_audio() && desc.channels.is_none() && t.channels > 0 {
                    desc.channels = Some(t.channels);
                }
            }
            g.desc = Some(Box::new(desc));
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
                let enc = g.key_for_segment(&self.st).map(|key| {
                    let whole = !self.st.sample_aes();
                    if !whole {
                        m.set_sample_key(&key);
                    }
                    Box::new(Encrypting {
                        key,
                        whole,
                        iv: iv_of(seq),
                        done: 0,
                        out: Vec::new(),
                    })
                });
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
                    enc,
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
            if let Some(e) = &mut b.enc {
                e.step(&b.data);
            }
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

    #[test]
    fn relative_uris() {
        assert_eq!(
            relative("live/cam", "live/cam_720/index.m3u8"),
            "cam_720/index.m3u8"
        );
        assert_eq!(relative("cam", "a/b/index.m3u8"), "a/b/index.m3u8");
        assert_eq!(relative("x/y/m", "x/z/index.m3u8"), "../z/index.m3u8");
        assert_eq!(relative("a/b/c", "d/index.m3u8"), "../../d/index.m3u8");
        assert_eq!(quoted("a\"b\nc"), "abc");
    }

    /// Feeds `pkts` of `tracks` into a sink registered in `hls` under `path`.
    fn rendition(hls: &Hls, path: &str, tracks: &Tracks, pkts: &[Packet], rounds: i64) {
        let mut s = sink(hls.0.cfg.clone());
        s.on_tracks(tracks);
        feed(&mut s, pkts, rounds, 2 * SECOND);
        lock(&hls.0.muxers).insert(path.to_owned(), s.st.clone());
    }

    /// Only the audio track of the sample, as track 0.
    fn audio_only(tracks: &Tracks, pkts: &[Packet]) -> (Tracks, Vec<Packet>) {
        let a = tracks
            .iter()
            .position(|t| t.codec.is_audio())
            .expect("audio");
        let t: Tracks = Arc::from(vec![tracks[a].clone()]);
        let p = pkts
            .iter()
            .filter(|p| p.track == a)
            .map(|p| Packet::new(0, p.dts, p.pts, true, p.data.clone()))
            .collect();
        (t, p)
    }

    /// Variants with measured and configured bandwidth, an audio group, codecs per format,
    /// readiness and the late answer.
    #[test]
    fn multivariant_playlist() {
        for format in [SegmentFormat::MpegTs, SegmentFormat::Fmp4] {
            let mut cfg = fmp4_cfg(true);
            cfg.format = format;
            let hls = Hls::new(Hub::default(), cfg);
            let (tracks, pkts) = sample();
            let (htracks, hpkts) = sample_h265();
            let (atracks, apkts) = audio_only(&tracks, &pkts);
            let mut m = Multivariant::new();
            let mut hi = Variant::new("live/cam_hi");
            hi.audio_group = Some("aud".into());
            let mut lo = Variant::new("live/cam_lo");
            lo.bandwidth = Some(150_000);
            lo.audio_group = Some("aud".into());
            m.variants = vec![hi, lo];
            let mut en = AudioRendition::new("aud", "English", "live/cam_en");
            en.language = Some("en".into());
            en.default = true;
            m.audio = vec![en];
            // Nothing published yet: not ready, and late with nothing is still nothing.
            assert!(hls.master_playlist("live/cam", &m, "", false).is_none());
            assert!(hls.master_playlist("live/cam", &m, "", true).is_none());
            rendition(&hls, "live/cam_hi", &htracks, &hpkts, 2);
            assert!(hls.master_playlist("live/cam", &m, "", false).is_none());
            let late = hls.master_playlist("live/cam", &m, "", true).expect("late");
            assert_eq!(late.matches("#EXT-X-STREAM-INF").count(), 1, "{late}");
            assert!(
                !late.contains("AUDIO=") && !late.contains("EXT-X-MEDIA"),
                "{late}"
            );
            rendition(&hls, "live/cam_lo", &tracks, &pkts, 2);
            rendition(&hls, "live/cam_en", &atracks, &apkts, 2);
            let pl = hls
                .master_playlist("live/cam", &m, "token=1", false)
                .expect("ready");
            let fmp4 = format == SegmentFormat::Fmp4;
            let version = if fmp4 { 7 } else { 3 };
            assert!(
                pl.starts_with(&format!("#EXTM3U\n#EXT-X-VERSION:{version}\n")),
                "{pl}"
            );
            assert!(
                pl.contains(
                    "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",NAME=\"English\",LANGUAGE=\"en\",\
                     DEFAULT=YES,AUTOSELECT=YES,CHANNELS=\"2\",URI=\"cam_en/index.m3u8?token=1\"\n"
                ),
                "{pl}"
            );
            let lines: Vec<&str> = pl.lines().collect();
            let inf: Vec<usize> = (0..lines.len())
                .filter(|&i| lines[i].starts_with("#EXT-X-STREAM-INF:"))
                .collect();
            assert_eq!(inf.len(), 2, "{pl}");
            let (hi, lo) = (lines[inf[0]], lines[inf[1]]);
            assert_eq!(lines[inf[0] + 1], "cam_hi/index.m3u8?token=1");
            assert_eq!(lines[inf[1] + 1], "cam_lo/index.m3u8?token=1");
            let bw: u64 = hi["#EXT-X-STREAM-INF:BANDWIDTH=".len()..]
                .split(',')
                .next()
                .and_then(|v| v.parse().ok())
                .expect("bandwidth");
            // About 140 kb/s of video plus the audio group, in segments with overhead.
            assert!((100_000..2_000_000).contains(&bw), "{hi}");
            assert!(hi.contains(",AVERAGE-BANDWIDTH="), "{hi}");
            assert!(hi.contains(",RESOLUTION=320x240,AUDIO=\"aud\""), "{hi}");
            assert!(hi.contains(",CODECS=\"hvc1.1.6.L60.90,mp4a.40.2\""), "{hi}");
            assert!(
                lo.starts_with(
                    "#EXT-X-STREAM-INF:BANDWIDTH=150000,CODECS=\"avc1.64000D,mp4a.40.2\""
                ),
                "{lo}"
            );
            assert!(!lo.contains("AVERAGE-BANDWIDTH"), "{lo}");
        }
    }

    /// VP9 is listed in fMP4; in MPEG-TS (which cannot carry it) the variant is audio only.
    #[test]
    fn multivariant_codecs_follow_the_format() {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in Demuxer::new()
            .feed(include_bytes!("../testdata/vp9_opus.flv"))
            .expect("flv")
        {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        let tracks = tracks.expect("tracks");
        for (format, want) in [
            (
                SegmentFormat::Fmp4,
                "CODECS=\"vp09.00.20.08,opus\",RESOLUTION=320x240\n",
            ),
            (SegmentFormat::MpegTs, "CODECS=\"opus\"\n"),
        ] {
            let mut cfg = fmp4_cfg(false);
            cfg.format = format;
            let hls = Hls::new(Hub::default(), cfg);
            rendition(&hls, "v", &tracks, &pkts, 3);
            let mut m = Multivariant::new();
            m.variants.push(Variant::new("v"));
            let pl = hls.master_playlist("m", &m, "", false).expect("ready");
            assert!(pl.contains(want), "{format:?}: {pl}");
            // Audio-only TS segments are still cut (the uncarried VP9 does not hold them).
            assert!(!lock(&lock(&hls.0.muxers)["v"].state).segments.is_empty());
        }
    }

    fn target_of(pl: &str) -> u64 {
        pl.lines()
            .find_map(|l| l.strip_prefix("#EXT-X-TARGETDURATION:"))
            .and_then(|v| v.parse().ok())
            .expect("target duration")
    }

    /// `EXT-X-TARGETDURATION` does not change between reloads of a live playlist (RFC 8216
    /// 6.2.1; Chrome's player refuses a change): segments of a little over the target round
    /// to it, and only a longer one raises it, for good.
    #[test]
    fn target_duration_is_stable() {
        let (tracks, pkts) = sample(); // keyframes every second
        let mut s = sink(HlsConfig {
            target_duration: Duration::from_secs(1),
            ..HlsConfig::default()
        });
        s.on_tracks(&tracks);
        let mut seen = Vec::new();
        for round in 0..6i64 {
            feed_round(&mut s, &pkts, round);
            let g = lock(&s.st.state);
            if !g.segments.is_empty() {
                seen.push(target_of(&s.st.playlist(&g)));
            }
        }
        assert!(seen.len() >= 5 && seen.iter().all(|&t| t == 1), "{seen:?}");
        // A 2.6 s segment (a keyframe lost) raises it to 3, and it stays.
        let mut g = lock(&s.st.state);
        g.longest = g.longest.max(3);
        assert_eq!(target_of(&s.st.playlist(&g)), 3);
    }

    fn feed_round(s: &mut HlsSink, pkts: &[Packet], round: i64) {
        let span = 2 * SECOND + 80 * crate::av::MILLISECOND;
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

    /// Segmenting cost in ns per packet (best of seven runs) for MPEG-TS and fMP4, with and
    /// without LL-HLS parts, H.264 + AAC; for same-run A/B comparisons:
    /// `cargo test -p only-media --release --lib bench_segmenting -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_segmenting() {
        let (tracks, pkts) = sample();
        let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40 * crate::av::MILLISECOND;
        let rounds = 60i64;
        let all: Vec<Arc<Packet>> = (0..rounds)
            .flat_map(|r| {
                pkts.iter().map(move |p| {
                    Arc::new(Packet::new(
                        p.track,
                        p.dts + r * span,
                        p.pts + r * span,
                        p.keyframe,
                        p.data.clone(),
                    ))
                })
            })
            .collect();
        let ll = Some(Duration::from_millis(200));
        let (aes, saes) = (
            Some(EncryptionMethod::Aes128),
            Some(EncryptionMethod::SampleAes),
        );
        for (name, format, parts, method) in [
            ("ts", SegmentFormat::MpegTs, None, None),
            ("ts-ll", SegmentFormat::MpegTs, ll, None),
            ("fmp4", SegmentFormat::Fmp4, None, None),
            ("fmp4-ll", SegmentFormat::Fmp4, ll, None),
            // Encryption (not in the baseline: its cost).
            ("ts-aes", SegmentFormat::MpegTs, None, aes),
            ("ts-ll-aes", SegmentFormat::MpegTs, ll, aes),
            ("fmp4-ll-aes", SegmentFormat::Fmp4, ll, aes),
            ("ts-sample-aes", SegmentFormat::MpegTs, None, saes),
            ("fmp4-cbcs", SegmentFormat::Fmp4, None, saes),
        ] {
            if std::env::var("BENCH_ONLY").is_ok_and(|o| o != name) {
                continue;
            }
            let ns = (0..7)
                .map(|_| {
                    let mut s = sink(HlsConfig {
                        format,
                        part_duration: parts,
                        target_duration: Duration::from_secs(1),
                        encryption: method.map(|m| HlsEncryption::new(TestKeys).method(m)),
                        ..HlsConfig::default()
                    });
                    s.on_tracks(&tracks);
                    let t = Instant::now();
                    for p in &all {
                        s.on_packet(p);
                    }
                    t.elapsed().as_nanos() as f64 / all.len() as f64
                })
                .fold(f64::MAX, f64::min);
            println!("BENCH {name} {ns:.1}");
        }
    }

    /// Keys 0, 1, ... derived from the number (deterministic for tests).
    struct TestKeys;

    impl KeyProvider for TestKeys {
        fn key(&self, path: &str, n: u64) -> HlsKey {
            assert_eq!(path, "t");
            HlsKey::new([n as u8 + 1; 16])
        }
    }

    fn decrypt(key: u64, seq: u64, data: &[u8]) -> Vec<u8> {
        let aes = Aes::new128(&[key as u8 + 1; 16]);
        let mut d = data.to_vec();
        aes.decrypt_cbc_padded(&iv_of(seq), &mut d)
            .expect("padding");
        d
    }

    /// Encrypted segments and parts decrypt (IV = media sequence number, parts separately) to
    /// what the same stream gives unencrypted; the playlist names each key once, before the
    /// first media it applies to, rotates every `rotate_every` segments, keeps fMP4 init
    /// segments clear (METHOD=NONE before a map that follows a key), and keys leave with the
    /// segments that use them.
    #[test]
    fn encrypted_segments_and_parts() {
        let (tracks, pkts) = sample();
        for format in [SegmentFormat::MpegTs, SegmentFormat::Fmp4] {
            for parts in [false, true] {
                let mut cfg = fmp4_cfg(parts);
                cfg.format = format;
                cfg.playlist_size = 4;
                cfg.keep_segments = 1;
                let mut plain = sink(cfg.clone());
                cfg.encryption = Some(HlsEncryption::new(TestKeys).rotate_every(3));
                let mut enc = sink(cfg);
                for s in [&mut plain, &mut enc] {
                    s.on_tracks(&tracks);
                    feed(s, &pkts, 2, 2 * SECOND);
                    // A republish with the same tracks: a discontinuity (fMP4: same map).
                    s.on_tracks(&tracks);
                    feed(s, &pkts, 2, 2 * SECOND);
                }
                let gp = lock(&plain.st.state);
                let ge = lock(&enc.st.state);
                assert_eq!(gp.segments.len(), ge.segments.len());
                assert!(ge.segments.len() >= 4, "{}", ge.segments.len());
                for (p, e) in gp.segments.iter().zip(&ge.segments) {
                    assert_eq!(p.seq, e.seq);
                    let k = e.key.expect("encrypted");
                    assert_eq!(k, e.seq / 3, "rotation every 3 segments");
                    assert_ne!(*p.data, *e.data);
                    assert_eq!(e.data.len() % 16, 0);
                    assert_eq!(decrypt(k, e.seq, &e.data), *p.data);
                    assert_eq!(p.parts.len(), e.parts.len());
                    assert_eq!(parts, !e.parts.is_empty());
                    for (pp, ep) in p.parts.iter().zip(&e.parts) {
                        assert_eq!(decrypt(k, e.seq, &ep.data), *pp.data);
                    }
                }
                // Only the keys of kept segments (and the current one) stay.
                let first = ge.segments.front().map(|s| s.seq / 3).expect("segments");
                assert!(ge.keys.iter().all(|k| k.n >= first), "{:?}", ge.keys.len());
                let pl = enc.st.playlist(&ge);
                // The keys of the listed segments, each once.
                let mut want: Vec<u64> = ge
                    .segments
                    .iter()
                    .skip(ge.segments.len().saturating_sub(4))
                    .map(|s| s.seq / 3)
                    .collect();
                want.dedup();
                let keys: Vec<u64> = pl
                    .lines()
                    .filter_map(|l| l.strip_prefix("#EXT-X-KEY:METHOD=AES-128,URI=\"key-"))
                    .map(|l| l.trim_end_matches(".key\"").parse().expect("key number"))
                    .collect();
                if format == SegmentFormat::Fmp4 {
                    // The map comes first, before any key; the republish (same tracks)
                    // keeps the map, so no METHOD=NONE.
                    let map = pl.find("#EXT-X-MAP:").expect("map");
                    assert!(map < pl.find("#EXT-X-KEY:").expect("key"), "{pl}");
                    assert!(!pl.contains("METHOD=NONE"), "{pl}");
                }
                assert_eq!(keys, want, "{pl}");
                // Each key tag comes before the first media line of its segments.
                let first_media = pl
                    .lines()
                    .position(|l| l.starts_with("#EXT-X-PART:") || l.starts_with("#EXTINF:"))
                    .expect("media");
                let first_key = pl
                    .lines()
                    .position(|l| l.starts_with("#EXT-X-KEY:"))
                    .expect("key");
                assert!(first_key < first_media, "{pl}");
            }
        }
    }

    /// fMP4 with a new init segment after a key: METHOD=NONE keeps the map clear, then the
    /// key is named again before the next segment.
    #[test]
    fn encrypted_fmp4_new_map_is_clear() {
        let (tracks, pkts) = sample();
        let mut cfg = fmp4_cfg(false);
        cfg.encryption = Some(HlsEncryption::new(TestKeys));
        let mut s = sink(cfg);
        s.on_tracks(&tracks);
        feed(&mut s, &pkts, 1, 2 * SECOND);
        // A republish with other tracks (audio only): a new init segment.
        let (atracks, apkts) = (
            tracks
                .iter()
                .filter(|t| t.codec.is_audio())
                .cloned()
                .collect::<Tracks>(),
            pkts.iter()
                .filter(|p| tracks[p.track].codec.is_audio())
                .map(|p| Packet::new(0, p.dts, p.pts, p.keyframe, p.data.clone()))
                .collect::<Vec<_>>(),
        );
        s.on_tracks(&atracks);
        feed(&mut s, &apkts, 1, 2 * SECOND);
        let g = lock(&s.st.state);
        let pl = s.st.playlist(&g);
        let seq: Vec<&str> = pl
            .lines()
            .filter(|l| l.starts_with("#EXT-X-KEY") || l.starts_with("#EXT-X-MAP"))
            .collect();
        assert_eq!(
            seq,
            [
                "#EXT-X-MAP:URI=\"init-0.mp4\"",
                "#EXT-X-KEY:METHOD=AES-128,URI=\"key-0.key\"",
                "#EXT-X-KEY:METHOD=NONE",
                "#EXT-X-MAP:URI=\"init-1.mp4\"",
                "#EXT-X-KEY:METHOD=AES-128,URI=\"key-0.key\"",
            ],
            "{pl}"
        );
    }

    /// A provider's URI is written as given (quoted), in place of `key-<n>.key`.
    #[test]
    fn key_uri_from_the_provider() {
        struct Remote;
        impl KeyProvider for Remote {
            fn key(&self, _path: &str, n: u64) -> HlsKey {
                HlsKey::with_uri([7; 16], format!("https://keys.example/k\"{n}"))
            }
        }
        let (tracks, pkts) = sample();
        let cfg = HlsConfig {
            encryption: Some(HlsEncryption::new(Remote)),
            ..HlsConfig::default()
        };
        let mut s = sink(cfg);
        s.on_tracks(&tracks);
        feed(&mut s, &pkts, 2, 2 * SECOND);
        let g = lock(&s.st.state);
        let pl = s.st.playlist(&g);
        assert!(
            pl.contains("#EXT-X-KEY:METHOD=AES-128,URI=\"https://keys.example/k0\"\n"),
            "{pl}"
        );
        assert_eq!(pl.matches("#EXT-X-KEY").count(), 1, "{pl}");
        assert!(format!("{:?}", HlsKey::new([9; 16])).find("9").is_none());
    }

    /// Encrypting a segment in pieces as it grows gives the one-shot padded ciphertext.
    #[test]
    fn incremental_encryption() {
        let key = Arc::new(Key {
            n: 0,
            aes: Aes::new128(&[3; 16]),
            uri: None,
            raw: [3; 16],
            iv: [0; 16],
        });
        for n in [0usize, 1, 15, 16, 17, 100, 188 * 700 + 5] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + i / 255) as u8).collect();
            let mut e = Encrypting {
                key: key.clone(),
                whole: true,
                iv: iv_of(9),
                done: 0,
                out: Vec::new(),
            };
            let mut at = 0;
            while at < n {
                at = (at + 1 + at / 3).min(n);
                e.more(&data[..at]);
                assert_eq!(e.done % 16, 0);
                assert_eq!(e.out.len(), e.done);
            }
            let got = e.finish(&data);
            let mut want = Vec::new();
            key.aes.encrypt_cbc_padded(&iv_of(9), &data, &mut want);
            assert_eq!(got, want, "{n}");
        }
    }
}
