//! Cutting a movie into HLS segments at keyframes, and muxing a segment's samples.

use std::{fmt::Write as _, ops::Range};

use crate::{
    av::{Codec, Packet, SECOND, Time},
    fmp4, mpegts,
};

use super::{Movie, Mp4Error, Mp4Track};

/// Segment boundaries of a [`Movie`]: cut at the keyframes of its first video track (or, for
/// a movie without video, of its first track of a known codec, where every audio sample is
/// one), each segment at least the target duration long but for the last.
///
/// Times are on the movie's presentation timeline (edit lists applied, see
/// [`Mp4Track::shift`]) moved later by [`delay`](Self::delay), so that no decode time is
/// negative: the packets of [`Segment::packets`] carry the same times. A plan holds 16 bytes
/// a segment; each [`Segment`] is computed when asked for.
#[derive(Debug, Clone)]
pub struct Plan {
    reference: Option<usize>,
    /// The reference track's first sample of each segment, and the segment's start time.
    cuts: Vec<(u32, Time)>,
    end: Time,
    delay: Time,
}

impl Plan {
    /// Cuts `movie` into segments of at least `target` (a new segment starts at the first
    /// keyframe presented `target` or more after the one before; ffmpeg's `-hls_time` cuts
    /// the same way). A movie without samples has no segments.
    ///
    /// Errors: [`Mp4Error::Invalid`] for a `target` that is not positive,
    /// [`Mp4Error::Limit`] past [`Limits::max_segments`](super::Limits::max_segments)
    /// (the default limits; see [`with_limit`](Self::with_limit)).
    pub fn new(movie: &Movie, target: Time) -> Result<Plan, Mp4Error> {
        Plan::with_limit(movie, target, super::Limits::default().max_segments)
    }

    /// [`new`](Self::new) with at most `max_segments` segments.
    pub fn with_limit(movie: &Movie, target: Time, max_segments: usize) -> Result<Plan, Mp4Error> {
        if target <= 0 {
            return Err(Mp4Error::Invalid("segment target duration"));
        }
        let live = || movie.tracks.iter().filter(|t| !t.index.is_empty());
        let reference = movie
            .tracks
            .iter()
            .position(|t| t.is_video() && !t.index.is_empty())
            .or_else(|| {
                movie
                    .tracks
                    .iter()
                    .position(|t| t.track.codec != Codec::Unknown && !t.index.is_empty())
            });
        // The delay that makes every decode (and presentation) time non-negative.
        let earliest = live()
            .map(|t| {
                let first = t.index.first_dts() as i64;
                t.time(first.saturating_add(i64::from(t.index.min_cts().min(0))))
            })
            .min()
            .unwrap_or(0);
        let delay = (-earliest).max(0);
        let end = live()
            .map(|t| t.time(t.index.end_dts() as i64))
            .max()
            .unwrap_or(0)
            .saturating_add(delay);
        let mut plan = Plan {
            reference,
            cuts: Vec::new(),
            end,
            delay,
        };
        let Some(r) = reference else {
            return Ok(plan);
        };
        let t = &movie.tracks[r];
        let start = live()
            .filter_map(|t| t.index.sample(0).map(|s| t.pts(&s)))
            .min()
            .unwrap_or(0)
            .saturating_add(delay);
        plan.cuts.push((0, start));
        let mut due = start.saturating_add(target);
        let mut cut = |k: u32, pts: Time, cuts: &mut Vec<(u32, Time)>| -> Result<(), Mp4Error> {
            let at = pts.saturating_add(delay);
            if at < due {
                return Ok(());
            }
            if cuts.len() >= max_segments {
                return Err(Mp4Error::Limit("segments"));
            }
            cuts.push((k, at));
            while due <= at {
                due = due.saturating_add(target);
            }
            Ok(())
        };
        match t.index.sync_samples() {
            None => {
                for s in t.index.iter(1) {
                    cut(s.index, t.pts(&s), &mut plan.cuts)?;
                }
            }
            Some(sync) => {
                for &k in sync.iter().filter(|&&k| k > 0) {
                    if let Some(s) = t.index.sample(k) {
                        cut(k, t.pts(&s), &mut plan.cuts)?;
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Number of segments.
    pub fn len(&self) -> usize {
        self.cuts.len()
    }

    /// Whether there are no segments.
    pub fn is_empty(&self) -> bool {
        self.cuts.is_empty()
    }

    /// The track whose keyframes the segments start at, if any.
    pub fn reference_track(&self) -> Option<usize> {
        self.reference
    }

    /// What every time of the plan and its packets adds to the movie's presentation times.
    pub fn delay(&self) -> Time {
        self.delay
    }

    /// The end of the last segment.
    pub fn end(&self) -> Time {
        self.end
    }

    /// Start time of segment `i` (`end()` past the last).
    pub fn start(&self, i: usize) -> Time {
        self.cuts.get(i).map_or(self.end, |c| c.1)
    }

    /// Duration of segment `i` (0 past the last).
    pub fn duration(&self, i: usize) -> Time {
        if i >= self.cuts.len() {
            return 0;
        }
        (self.start(i + 1) - self.start(i)).max(0)
    }

    /// The segment presenting `t` (the first for a time before it, the last for one after).
    pub fn segment_at(&self, t: Time) -> Option<usize> {
        if self.cuts.is_empty() {
            return None;
        }
        Some(self.cuts.partition_point(|c| c.1 <= t).max(1) - 1)
    }

    /// `EXT-X-TARGETDURATION`: the longest segment in seconds, rounded to the nearest, at
    /// least 1 (RFC 8216 4.3.3.1).
    pub fn target_duration(&self) -> u64 {
        (0..self.len())
            .map(|i| ((self.duration(i) + SECOND / 2) / SECOND) as u64)
            .max()
            .unwrap_or(0)
            .max(1)
    }

    /// Segment `i` of `movie` (the movie the plan was made from): the samples of each track
    /// it holds. Past the last segment, a segment without samples.
    pub fn segment(&self, movie: &Movie, i: usize) -> Segment {
        let n = self.cuts.len();
        let samples = movie
            .tracks
            .iter()
            .enumerate()
            .map(|(j, t)| {
                if i >= n {
                    let l = t.index.len();
                    return l..l;
                }
                self.boundary(movie, j, t, i)..self.boundary(movie, j, t, i + 1)
            })
            .collect();
        Segment {
            index: i,
            start: self.start(i),
            end: self.start(i + 1),
            samples,
            delay: self.delay,
        }
    }

    /// The first sample of track `j` in segment `c` (its length for `c` past the last).
    fn boundary(&self, _movie: &Movie, j: usize, t: &Mp4Track, c: usize) -> u32 {
        let len = t.index.len();
        if c == 0 {
            return 0;
        }
        let Some(&(k, at)) = self.cuts.get(c) else {
            return len;
        };
        if Some(j) == self.reference {
            return k;
        }
        let ticks = t.ticks(at - self.delay).max(0) as u64;
        let i = t.index.first_at_or_after_dts(ticks);
        if t.is_video() {
            t.index.keyframe_at_or_after(i).unwrap_or(len)
        } else {
            i
        }
    }

    /// A VOD media playlist of the segments: `uri(i)` names segment `i`, `init` the fMP4 init
    /// segment (`EXT-X-MAP`; `None` for MPEG-TS segments).
    pub fn vod_playlist(&self, init: Option<&str>, mut uri: impl FnMut(usize) -> String) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "#EXTM3U");
        let _ = writeln!(s, "#EXT-X-VERSION:{}", if init.is_some() { 7 } else { 3 });
        let _ = writeln!(s, "#EXT-X-TARGETDURATION:{}", self.target_duration());
        let _ = writeln!(s, "#EXT-X-MEDIA-SEQUENCE:0");
        let _ = writeln!(s, "#EXT-X-PLAYLIST-TYPE:VOD");
        let _ = writeln!(s, "#EXT-X-INDEPENDENT-SEGMENTS");
        if let Some(init) = init {
            let _ = writeln!(s, "#EXT-X-MAP:URI=\"{init}\"");
        }
        for i in 0..self.len() {
            let d = self.duration(i);
            let _ = writeln!(s, "#EXTINF:{}.{:06},", d / SECOND, (d % SECOND) / 1000);
            let _ = writeln!(s, "{}", uri(i));
        }
        let _ = writeln!(s, "#EXT-X-ENDLIST");
        s
    }
}

/// One segment of a [`Plan`]: the samples of every track it holds, in decode order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Segment {
    /// Its index in the plan.
    pub index: usize,
    /// Start time (the presentation time of its first keyframe; the movie's first
    /// presentation for the first segment).
    pub start: Time,
    /// End time: the start of the next segment, or the end of the movie.
    pub end: Time,
    /// Per track of the movie, the samples in the segment.
    pub samples: Vec<Range<u32>>,
    delay: Time,
}

impl Segment {
    /// Number of samples over all tracks.
    pub fn sample_count(&self) -> usize {
        self.samples.iter().map(|r| r.len()).sum()
    }

    /// The byte ranges of the file to read for the segment's samples, sorted and merged
    /// where they touch or are at most `max_gap` bytes apart (reading a gap costs less than
    /// another read).
    pub fn byte_ranges(&self, movie: &Movie, max_gap: u64) -> Vec<Range<u64>> {
        let mut v: Vec<Range<u64>> = Vec::with_capacity(self.sample_count());
        for (t, r) in movie.tracks.iter().zip(&self.samples) {
            for s in t.index.range(r.start, r.end) {
                if s.size > 0 {
                    v.push(s.offset..s.offset + u64::from(s.size));
                }
            }
        }
        v.sort_unstable_by_key(|r| r.start);
        let mut out: Vec<Range<u64>> = Vec::new();
        for r in v {
            match out.last_mut() {
                Some(last) if r.start <= last.end.saturating_add(max_gap) => {
                    last.end = last.end.max(r.end);
                }
                _ => out.push(r),
            }
        }
        out
    }

    /// The segment's samples as canonical packets in decode order (by time over the tracks),
    /// indexing [`Movie::av_tracks`], with the plan's times. `data` holds the bytes read: each
    /// `(offset, bytes)` the file's bytes from `offset` (the ranges of
    /// [`byte_ranges`](Self::byte_ranges), or any that cover them). H.264 and H.265 samples
    /// with NAL unit lengths of 1 or 2 bytes are rewritten with 4.
    ///
    /// Errors: [`Mp4Error::MissingData`] for a sample `data` does not cover,
    /// [`Mp4Error::Invalid`] for a sample whose NAL unit lengths do not add up (only checked
    /// where they are rewritten).
    pub fn packets(&self, movie: &Movie, data: &[(u64, &[u8])]) -> Result<Vec<Packet>, Mp4Error> {
        let mut parts: Vec<(u64, &[u8])> = data.to_vec();
        parts.sort_unstable_by_key(|p| p.0);
        let find = |off: u64, size: u32| -> Option<&[u8]> {
            let end = off.checked_add(u64::from(size))?;
            let p = parts.partition_point(|p| p.0 <= off);
            parts[..p].iter().rev().find_map(|&(at, b)| {
                let e = at.checked_add(b.len() as u64)?;
                (end <= e).then(|| &b[(off - at) as usize..(end - at) as usize])
            })
        };
        let mut out = Vec::with_capacity(self.sample_count());
        for (j, (t, r)) in movie.tracks.iter().zip(&self.samples).enumerate() {
            for s in t.index.range(r.start, r.end) {
                let b = find(s.offset, s.size).ok_or(Mp4Error::MissingData)?;
                let data = match t.nal_length {
                    1 | 2 => widen_nal_lengths(b, usize::from(t.nal_length))?,
                    _ => b.to_vec(),
                };
                let dts = t.dts(&s).saturating_add(self.delay);
                let pts = t.pts(&s).saturating_add(self.delay);
                let keyframe = s.keyframe || !t.is_video();
                out.push(Packet::new(j, dts, pts, keyframe, data));
            }
        }
        out.sort_by_key(|p| p.dts);
        Ok(out)
    }

    /// Muxes the segment as one fMP4 fragment (`moof` + `mdat`, sequence number `index + 1`)
    /// appended to `out`. `muxer` is a [`fmp4::Muxer`] of [`Movie::av_tracks`]; its
    /// [`init_segment`](fmp4::Muxer::init_segment) is the playlist's `EXT-X-MAP`. Tracks it
    /// does not carry are left out.
    ///
    /// Errors: those of [`packets`](Self::packets), and [`Mp4Error::Limit`] for a segment past
    /// the muxer's fragment limits (1 GiB, 2^20 samples a track).
    pub fn write_fmp4(
        &self,
        movie: &Movie,
        data: &[(u64, &[u8])],
        muxer: &mut fmp4::Muxer,
        out: &mut Vec<u8>,
    ) -> Result<(), Mp4Error> {
        let packets = self.packets(movie, data)?;
        muxer.set_next_sequence(u32::try_from(self.index + 1).unwrap_or(u32::MAX));
        for p in &packets {
            if muxer.carries(p.track) && !muxer.write_packet(p) {
                return Err(Mp4Error::Limit("fragment bytes or samples"));
            }
        }
        muxer.flush(Some(self.end), out);
        Ok(())
    }

    /// Muxes the segment as MPEG-TS appended to `out`: PAT and PMT, then a PES a sample (with
    /// the parameter sets before each keyframe). `muxer` is an [`mpegts::Muxer`] of
    /// [`Movie::av_tracks`]; tracks it does not carry are left out.
    pub fn write_ts(
        &self,
        movie: &Movie,
        data: &[(u64, &[u8])],
        muxer: &mut mpegts::Muxer,
        out: &mut Vec<u8>,
    ) -> Result<(), Mp4Error> {
        let packets = self.packets(movie, data)?;
        muxer.write_tables(out);
        for p in &packets {
            muxer.write_packet(p, out);
        }
        Ok(())
    }
}

/// An access unit with `n`-byte NAL unit lengths rewritten with 4-byte ones.
fn widen_nal_lengths(b: &[u8], n: usize) -> Result<Vec<u8>, Mp4Error> {
    let mut out = Vec::with_capacity(b.len() + b.len() / 8 + 8);
    let mut rest = b;
    while !rest.is_empty() {
        if rest.len() < n {
            return Err(Mp4Error::Invalid("sample (NAL unit lengths)"));
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        let body = rest
            .get(n..n + len)
            .ok_or(Mp4Error::Invalid("sample (NAL unit lengths)"))?;
        out.extend_from_slice(&(len as u32).to_be_bytes());
        out.extend_from_slice(body);
        rest = &rest[n + len..];
    }
    Ok(out)
}
