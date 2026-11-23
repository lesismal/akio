//! A sans-io reader of MP4 files that are not fragmented (ISO/IEC 14496-12, the ISO base
//! media file format: the `.mp4`, `.m4v`, `.m4a` and `.mov` files ffmpeg, encoders and cameras
//! write), and a planner that cuts them into HLS segments at video keyframes without
//! transcoding.
//!
//! The reader does no I/O. A caller serving files reads byte ranges itself, on the logical
//! pool or a thread of its own ([rule 3](https://github.com/lesismal/akio/blob/main/docs/rules.md)),
//! and hands the bytes in:
//!
//! 1. [`Locator`] walks the top-level box headers ([`Locator::next_read`] names the bytes it
//!    wants, [`Locator::feed`] takes them) to the `moov`, which may come before the media data
//!    (ffmpeg's `-movflags +faststart`) or after it (ffmpeg's default), and says where it is
//!    ([`MoovLocation`]). A file whose top level has a `moof` is [`Mp4Error::Fragmented`]
//!    ([`crate::fmp4::Demuxer`] reads those).
//! 2. [`Movie::parse`] takes the `moov` box, read whole (at most [`Limits::max_moov_bytes`]),
//!    and builds every track ([`Mp4Track`]): handler, language, name, timescale, edit list,
//!    the codec as [`crate::av::Track`] (`avc1` / `avc3` + `avcC`, `hvc1` / `hev1` + `hvcC`,
//!    `av01` + `av1C`, `vp08` / `vp09` + `vpcC`, `mp4a` + `esds`, `Opus` + `dOps`; other
//!    formats such as `ac-3` and `ec-3` are [`Codec::Unknown`](crate::av::Codec::Unknown)
//!    with their [`format`](Mp4Track::format) kept) and its [`SampleIndex`].
//! 3. [`Plan::new`] cuts the movie into segments of about a target duration at the keyframes
//!    of its first video track; [`Plan::segment`] gives a [`Segment`]: the samples of every
//!    track it holds and, with [`Segment::byte_ranges`], the ranges of the file to read for
//!    them. [`Segment::packets`] turns those bytes into canonical [`Packet`](crate::av::Packet)s,
//!    and [`Segment::write_fmp4`] / [`Segment::write_ts`] mux them for HLS
//!    ([`Plan::vod_playlist`] writes the playlist).
//!
//! The sample index keeps the file's tables in compact form rather than an entry per sample:
//! sizes at the narrowest width that holds them (none when constant), runs of `stts` and
//! `ctts` (dense composition offsets only when the runs would take more), sync samples, and
//! per chunk its offset and first sample. Lookups by index and by time are binary searches;
//! [`SampleIndex::iter`] walks samples in decode order at constant cost each. An hour at 60 fps
//! with B-frames and AAC (384,750 samples) takes 1.6 MB.
//!
//! Nothing in a file is trusted: every size, count and offset is checked against the bytes
//! it claims and against [`Limits`] (boxes, tracks, samples a track, edits, `moov` bytes), no
//! allocation is made from a count the `moov`'s bytes do not account for, the parser never
//! recurses on input (box depth is fixed by the layout it reads), and every chunk's samples
//! must lie within the file. Errors are [`Mp4Error`], never a panic.
//!
//! Edit lists: the empty edits before the first edit that plays delay the track, and that
//! edit's media time is presented at its start, as ffmpeg and players do ([`Mp4Track::shift`]);
//! later edits are kept in [`Mp4Track::edits`] and not applied. Left out: compressed `moov`
//! (`cmov`), sample descriptions after the first, sample groups and encryption.
//!
//! ```
//! use akio_media::mp4::{Limits, Locator, Movie, Plan};
//! # fn read_at(file: &[u8], off: u64, len: usize) -> Vec<u8> {
//! #     let s = off as usize; file[s..(s + len).min(file.len())].to_vec()
//! # }
//! # fn demo(file: &[u8]) -> Result<(), akio_media::mp4::Mp4Error> {
//! // On a pool thread: find the moov with a few small reads, then read it whole.
//! let limits = Limits::default();
//! let mut loc = Locator::new(file.len() as u64, &limits);
//! let at = loop {
//!     let (off, len) = loc.next_read();
//!     if let Some(at) = loc.feed(&read_at(file, off, len))? {
//!         break at;
//!     }
//! };
//! let moov = read_at(file, at.offset, at.size as usize);
//! let movie = Movie::parse(&moov, &at, &limits)?;
//! let plan = Plan::new(&movie, 6 * akio_media::av::SECOND)?;
//! for i in 0..plan.len() {
//!     let seg = plan.segment(&movie, i);
//!     let ranges: Vec<_> = seg
//!         .byte_ranges(&movie, 0)
//!         .into_iter()
//!         .map(|r| (r.start, read_at(file, r.start, (r.end - r.start) as usize)))
//!         .collect();
//!     let parts: Vec<(u64, &[u8])> = ranges.iter().map(|(o, b)| (*o, &b[..])).collect();
//!     let packets = seg.packets(&movie, &parts)?;
//!     # let _ = packets;
//! }
//! # Ok(()) }
//! ```

mod index;
mod parse;
mod segment;
#[cfg(test)]
mod tests;

use std::fmt;

use crate::av::{Codec, Time, Track, from_ticks, to_ticks};

pub use index::{Sample, SampleIndex, Samples};
pub use segment::{Plan, Segment};

/// A malformed, unsupported or oversized MP4 input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mp4Error {
    /// A box or field runs past the end of its container, or fewer bytes were given than
    /// asked for.
    Truncated,
    /// The named box or table is malformed, or the tables disagree with each other.
    Invalid(&'static str),
    /// The named limit of [`Limits`] was exceeded.
    Limit(&'static str),
    /// The file has no `moov` among its top-level boxes, or ends before one.
    NoMoov,
    /// The file is fragmented (a `moof` at the top level or an `mvex` in the `moov`).
    Fragmented,
    /// The bytes of a sample were not among those given to [`Segment::packets`].
    MissingData,
}

impl fmt::Display for Mp4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mp4Error::Truncated => f.write_str("mp4: truncated box"),
            Mp4Error::Invalid(what) => write!(f, "mp4: malformed {what}"),
            Mp4Error::Limit(what) => write!(f, "mp4: too many {what}"),
            Mp4Error::NoMoov => f.write_str("mp4: no moov"),
            Mp4Error::Fragmented => f.write_str("mp4: fragmented file"),
            Mp4Error::MissingData => f.write_str("mp4: sample data not given"),
        }
    }
}

impl std::error::Error for Mp4Error {}

/// The reader's bounds: the work and memory a file can make it take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest `moov` box [`Locator`] accepts (it is read whole). Default 64 MiB: a two-hour
    /// film's `moov` is under 10 MB.
    pub max_moov_bytes: u64,
    /// Most box headers read: top-level ones by [`Locator`], and those in the `moov` by
    /// [`Movie::parse`]. Default 65,536.
    pub max_boxes: usize,
    /// Most tracks in a `moov`. Default 64.
    pub max_tracks: usize,
    /// Most samples in a track. Default 2^24 (more than 77 hours at 60 fps).
    pub max_samples: u32,
    /// Most edit list entries of a track. Default 1024.
    pub max_edits: usize,
    /// Most segments [`Plan::new`] cuts. Default 2^20.
    pub max_segments: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_moov_bytes: 64 << 20,
            max_boxes: 1 << 16,
            max_tracks: 64,
            max_samples: 1 << 24,
            max_edits: 1024,
            max_segments: 1 << 20,
        }
    }
}

/// Bytes [`Locator::next_read`] asks for at most: a box header with a 64-bit size.
pub const HEADER_BYTES: usize = 16;

/// Where the `moov` of a file is, as [`Locator`] found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MoovLocation {
    /// Offset of the `moov` box (its header) in the file.
    pub offset: u64,
    /// Size of the `moov` box, header included: read `offset..offset + size`.
    pub size: u64,
    /// The file's size, as given to [`Locator::new`].
    pub file_size: u64,
    /// The `ftyp`'s major brand, if the file starts with one before the `moov`.
    pub major_brand: Option<[u8; 4]>,
}

impl MoovLocation {
    /// A location for a `moov` box at `offset` of `size` bytes in a file of `file_size`
    /// bytes, for a caller that found it itself.
    pub fn new(offset: u64, size: u64, file_size: u64) -> MoovLocation {
        MoovLocation {
            offset,
            size,
            file_size,
            major_brand: None,
        }
    }
}

/// Finds the `moov` of a file through the reads it asks for: box headers, from the start of
/// the file, until the `moov`.
///
/// Each [`next_read`](Self::next_read) names an offset and a length (at most
/// [`HEADER_BYTES`]); [`feed`](Self::feed) takes the bytes read there, or more (a caller that
/// read the first 64 KiB of the file passes them all, and every header within them is
/// taken). The locator reads only headers, never media data, and at most
/// [`Limits::max_boxes`] of them.
#[derive(Debug, Clone)]
pub struct Locator {
    file_size: u64,
    pos: u64,
    boxes: usize,
    max_boxes: usize,
    max_moov: u64,
    major_brand: Option<[u8; 4]>,
}

impl Locator {
    /// A locator for a file of `file_size` bytes.
    pub fn new(file_size: u64, limits: &Limits) -> Locator {
        Locator {
            file_size,
            pos: 0,
            boxes: 0,
            max_boxes: limits.max_boxes,
            max_moov: limits.max_moov_bytes,
            major_brand: None,
        }
    }

    /// The bytes to read next: `(offset, len)`, `len` at most [`HEADER_BYTES`] (less at the
    /// end of the file, 0 once the file is past).
    pub fn next_read(&self) -> (u64, usize) {
        let left = self.file_size.saturating_sub(self.pos);
        (self.pos, left.min(HEADER_BYTES as u64) as usize)
    }

    /// Takes `data`, the bytes of the file from the offset [`next_read`](Self::next_read)
    /// gave (at least the length it gave, or more). Returns the `moov`'s location once it is
    /// found, `None` while more reads are needed.
    ///
    /// Errors: [`Mp4Error::NoMoov`] at the end of the file or for a box running past it (a
    /// file cut short), [`Mp4Error::Fragmented`] for a `moof`, [`Mp4Error::Limit`] past
    /// [`Limits::max_boxes`] or for a `moov` over [`Limits::max_moov_bytes`],
    /// [`Mp4Error::Truncated`] when `data` is shorter than asked for.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<MoovLocation>, Mp4Error> {
        let start = self.pos;
        let mut progressed = false;
        loop {
            if self.pos >= self.file_size {
                return Err(Mp4Error::NoMoov);
            }
            let left = self.file_size - self.pos;
            let at = (self.pos - start) as usize;
            let avail = data.len().saturating_sub(at);
            let need = 8u64.min(left) as usize;
            if left < 8 {
                return Err(Mp4Error::NoMoov);
            }
            if avail < need {
                break;
            }
            let h = &data[at..];
            let size32 = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
            let typ = [h[4], h[5], h[6], h[7]];
            let (size, hdr) = match size32 {
                0 => (left, 8),
                1 => {
                    if left < 16 {
                        return Err(Mp4Error::NoMoov);
                    }
                    if avail < 16 {
                        break;
                    }
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&h[8..16]);
                    (u64::from_be_bytes(b), 16)
                }
                n => (u64::from(n), 8),
            };
            self.boxes += 1;
            if self.boxes > self.max_boxes {
                return Err(Mp4Error::Limit("boxes"));
            }
            if size < hdr || size > left {
                // A box running past the end: the file was cut short.
                return Err(Mp4Error::NoMoov);
            }
            progressed = true;
            match &typ {
                b"ftyp" if self.major_brand.is_none() && size >= 12 && avail >= 12 => {
                    self.major_brand = Some([h[8], h[9], h[10], h[11]]);
                }
                b"moov" => {
                    if size > self.max_moov {
                        return Err(Mp4Error::Limit("moov bytes"));
                    }
                    return Ok(Some(MoovLocation {
                        offset: self.pos,
                        size,
                        file_size: self.file_size,
                        major_brand: self.major_brand,
                    }));
                }
                b"moof" => return Err(Mp4Error::Fragmented),
                _ => {}
            }
            self.pos += size;
        }
        if !progressed {
            return Err(Mp4Error::Truncated);
        }
        Ok(None)
    }
}

/// One entry of a track's edit list (ISO/IEC 14496-12 8.6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Edit {
    /// Duration in the movie's timescale.
    pub duration: u64,
    /// Where the edit starts in the media, in the track's timescale; -1 for an empty edit
    /// (which delays what follows).
    pub media_time: i64,
    /// The media rate as 16.16 fixed point: `1 << 16` normally, 0 for a dwell.
    pub rate: i32,
}

/// One track of a [`Movie`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Mp4Track {
    /// `track_ID` of the `tkhd`.
    pub id: u32,
    /// The `hdlr`'s handler type: `vide`, `soun`, `subt`, `text`, `hint`, ...
    pub handler: [u8; 4],
    /// The ISO 639-2/T language code of the `mdhd`, `und` when unset.
    pub language: String,
    /// The track's name: the `udta`'s `name` box when it has one, else the `hdlr`'s name
    /// (ffmpeg writes "VideoHandler", "SoundHandler"); empty if neither.
    pub name: String,
    /// The media clock: sample times are ticks of it.
    pub timescale: u32,
    /// The media duration from `mdhd` in ticks of [`timescale`](Self::timescale); 0 if unknown.
    pub duration: u64,
    /// The four-character code of the first sample entry (`avc1`, `hvc1`, `mp4a`, `Opus`,
    /// `ac-3`, ...); zeros without one.
    pub format: [u8; 4],
    /// The codec as the media stack carries it, read from the first sample entry, with its
    /// configuration as stored (see [`Movie::av_tracks`] for the canonical form). A format
    /// the stack does not carry, or a sample entry that does not parse, is
    /// [`Codec::Unknown`]: its samples are still indexed.
    pub track: Track,
    /// The edit list, if any.
    pub edits: Vec<Edit>,
    /// What the edit list adds to a media time to give its presentation time, in ticks: the
    /// empty edits before the first that plays, less where that one starts in the media.
    pub shift: i64,
    /// The sample tables.
    pub index: SampleIndex,
    /// NAL unit length size of an H.264 / H.265 track (0 otherwise).
    nal_length: u8,
}

impl Mp4Track {
    /// Whether this track carries a video codec the stack knows.
    pub fn is_video(&self) -> bool {
        self.track.codec.is_video()
    }

    /// The presentation-timeline time of `ticks` of the media clock: `ticks +` [`shift`](Self::shift),
    /// in nanoseconds.
    pub fn time(&self, ticks: i64) -> Time {
        from_ticks(ticks.saturating_add(self.shift), self.timescale)
    }

    /// The media-clock ticks of the presentation-timeline time `t` (the inverse of
    /// [`time`](Self::time)).
    pub fn ticks(&self, t: Time) -> i64 {
        to_ticks(t, self.timescale).saturating_sub(self.shift)
    }

    /// A sample's decode time on the presentation timeline.
    pub fn dts(&self, s: &Sample) -> Time {
        self.time(s.dts as i64)
    }

    /// A sample's presentation time.
    pub fn pts(&self, s: &Sample) -> Time {
        self.time((s.dts as i64).saturating_add(i64::from(s.cts)))
    }

    /// The last keyframe presented at or before `t`, or the first keyframe when every one
    /// is later; `None` for a track without samples or keyframes.
    pub fn keyframe_at(&self, t: Time) -> Option<u32> {
        let ix = &self.index;
        let ticks = self.ticks(t).max(0) as u64;
        let after = ix.first_at_or_after_dts(ticks.saturating_add(1));
        let mut k = match after.checked_sub(1) {
            Some(i) => ix.keyframe_at_or_before(i),
            None => None,
        };
        // A keyframe's presentation follows its decode with B-frames: step back while it is
        // presented after `t`.
        while let Some(i) = k {
            let s = ix.sample(i)?;
            if self.pts(&s) <= t {
                return Some(i);
            }
            k = i.checked_sub(1).and_then(|p| ix.keyframe_at_or_before(p));
        }
        ix.keyframe_at_or_after(0)
    }

    /// The track's duration on the presentation timeline: from its first sample's decode
    /// time to the end of its last sample (0 without samples).
    pub fn sample_duration(&self) -> Time {
        let ix = &self.index;
        if ix.is_empty() {
            return 0;
        }
        from_ticks(
            ix.end_dts().saturating_sub(ix.first_dts()) as i64,
            self.timescale,
        )
    }
}

/// A parsed MP4 file: its movie header and tracks. It holds no part of the file but the
/// codec configurations and the sample index.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Movie {
    /// The `ftyp`'s major brand (`isom`, `mp42`, `qt  `, ...) when [`Locator`] saw one.
    pub major_brand: Option<[u8; 4]>,
    /// The movie clock of `mvhd`, in which [`Edit::duration`] counts.
    pub timescale: u32,
    /// The movie's duration from `mvhd`, in ticks of [`timescale`](Self::timescale); 0 if
    /// unknown.
    pub duration: u64,
    /// The file's size.
    pub file_size: u64,
    /// Where the `moov` is.
    pub moov_offset: u64,
    /// The `moov`'s size.
    pub moov_size: u64,
    /// The tracks, in the order of the `trak` boxes.
    pub tracks: Vec<Mp4Track>,
}

impl Movie {
    /// Parses `moov`, the whole `moov` box (header included) [`Locator`] found at `at`.
    pub fn parse(moov: &[u8], at: &MoovLocation, limits: &Limits) -> Result<Movie, Mp4Error> {
        parse::movie(moov, at, limits)
    }

    /// Locates and parses the `moov` of a file held whole in memory: a convenience for small
    /// files and tests.
    pub fn from_bytes(file: &[u8], limits: &Limits) -> Result<Movie, Mp4Error> {
        let mut loc = Locator::new(file.len() as u64, limits);
        let at = loop {
            let (off, _) = loc.next_read();
            let rest = file.get(off as usize..).unwrap_or_default();
            if let Some(at) = loc.feed(rest)? {
                break at;
            }
        };
        let s = at.offset as usize;
        let moov = file
            .get(s..s + at.size as usize)
            .ok_or(Mp4Error::Truncated)?;
        Movie::parse(moov, &at, limits)
    }

    /// The movie's duration from `mvhd` in nanoseconds (0 if unknown).
    pub fn duration_time(&self) -> Time {
        from_ticks(
            i64::try_from(self.duration).unwrap_or(i64::MAX),
            self.timescale,
        )
    }

    /// The tracks as the media stack carries them, in track order (packets of
    /// [`Segment::packets`] index these): H.264 and H.265 configurations rewritten to 4-byte
    /// NAL unit lengths (the canonical form; the samples are rewritten to match).
    pub fn av_tracks(&self) -> Vec<Track> {
        self.tracks
            .iter()
            .map(|t| {
                let mut a = t.track.clone();
                if t.nal_length != 0 && t.nal_length != 4 {
                    match a.codec {
                        Codec::H264 if a.config.len() > 4 => a.config[4] |= 3,
                        Codec::H265 if a.config.len() > 21 => a.config[21] |= 3,
                        _ => {}
                    }
                }
                a
            })
            .collect()
    }

    /// Heap bytes the sample indexes of all tracks take.
    pub fn index_bytes(&self) -> usize {
        self.tracks.iter().map(|t| t.index.heap_bytes()).sum()
    }
}
