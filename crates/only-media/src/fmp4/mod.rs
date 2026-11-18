//! Fragmented MP4 (ISO/IEC 14496-12 ISO BMFF, CMAF profile of ISO/IEC 23000-19): a muxer from
//! canonical packets ([`Muxer`], for HLS fMP4 segments) and a demuxer back to them
//! ([`Demuxer`], used to check the muxer and as a fuzz target).
//!
//! The muxer writes an init segment (`ftyp` with the `iso6`, `cmfc` and `mp41` brands and a
//! `moov` with one `trak` per carried track and `mvex`/`trex`) and then fragments: a `moof`
//! (`mfhd`, one `traf` per track with samples: `tfhd` with default-base-is-moof, `tfdt` with
//! the 64-bit decode time of its first sample, one `trun` with per-sample duration, size,
//! flags and composition offsets) followed by its `mdat`. A media segment can start with a
//! `styp` ([`write_styp`]).
//!
//! Codecs: H.264 (`avc1` + `avcC`), H.265 (`hvc1` + `hvcC`), AAC (`mp4a` + `esds`) and Opus
//! (`Opus` + `dOps`, built from the track's `OpusHead` when it has one). Other tracks (G.711,
//! MP3, unknown) are left out. Timescales are 90 kHz for video and the sample rate for audio
//! (48 kHz for Opus). The canonical packets are already in ISO BMFF form (AVCC with 4-byte
//! lengths, raw AAC access units, Opus packets), so samples are copied as they are.
//!
//! Sample durations come from the next sample's decode time; the last sample of a track in a
//! fragment ends at the fragment end given to [`Muxer::flush`] (video) or lasts as long as the
//! codec frame (audio: the previous duration, or 1024 samples for AAC and the TOC duration for
//! Opus). Every `tfdt` carries the absolute decode time, so rounding never accumulates.

mod demux;
mod mux;

use std::fmt;

pub use demux::{Demuxer, Event};
pub use mux::{Muxer, write_styp};

#[cfg(test)]
pub(crate) use demux::parse_all as demux_all;

/// A malformed or unsupported fragmented MP4 input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fmp4Error {
    /// A box or field runs past the end of its container.
    Truncated,
    /// The named box is malformed.
    Invalid(&'static str),
    /// The named limit (tracks, nesting, samples, box size) was exceeded.
    Limit(&'static str),
}

impl fmt::Display for Fmp4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fmp4Error::Truncated => f.write_str("fmp4: truncated box"),
            Fmp4Error::Invalid(what) => write!(f, "fmp4: malformed {what}"),
            Fmp4Error::Limit(what) => write!(f, "fmp4: too many {what}"),
        }
    }
}

impl std::error::Error for Fmp4Error {}

/// Sample flags of a sync sample: `sample_depends_on = 2` (independent).
pub(crate) const FLAGS_SYNC: u32 = 0x0200_0000;
/// Sample flags of a non-sync sample: `sample_depends_on = 1`, `sample_is_non_sync_sample`.
pub(crate) const FLAGS_NON_SYNC: u32 = 0x0101_0000;
/// The `sample_is_non_sync_sample` bit.
pub(crate) const FLAG_NON_SYNC: u32 = 0x0001_0000;

/// `tfhd` flag: the base data offset is the start of the `moof`.
pub(crate) const TFHD_DEFAULT_BASE_IS_MOOF: u32 = 0x02_0000;
/// `trun` flags.
pub(crate) const TRUN_DATA_OFFSET: u32 = 0x001;
pub(crate) const TRUN_FIRST_SAMPLE_FLAGS: u32 = 0x004;
pub(crate) const TRUN_DURATION: u32 = 0x100;
pub(crate) const TRUN_SIZE: u32 = 0x200;
pub(crate) const TRUN_FLAGS: u32 = 0x400;
pub(crate) const TRUN_CTS: u32 = 0x800;

#[cfg(test)]
mod tests;
