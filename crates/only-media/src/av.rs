//! The types every protocol of the media stack shares: codecs ([`Codec`]), the description of
//! an elementary stream ([`Track`]) and one timed unit of it ([`Packet`]).
//!
//! Every ingest converts what it receives into one canonical form and every egress muxes from
//! that form, so a stream published over RTMP plays over RTSP, HLS or SRT with no
//! protocol-to-protocol glue. The canonical form is the one ISO BMFF (MP4) uses:
//!
//! * [`Track::config`]: the codec's out-of-band configuration: the
//!   `AVCDecoderConfigurationRecord` for H.264, the `HEVCDecoderConfigurationRecord` for H.265,
//!   the `AudioSpecificConfig` for AAC, the `OpusHead` for Opus (optional), empty for G.711.
//! * [`Packet::data`]: one access unit or frame: H.264 and H.265 as AVCC (each NAL unit
//!   prefixed by a 4-byte big-endian length, no access unit delimiters); AAC as one raw access
//!   unit without ADTS header; Opus as one Opus packet; G.711 as the samples.
//!
//! Times are nanoseconds ([`Time`]) from the start of the stream (or any fixed epoch), so
//! tracks with different clocks compare directly; [`to_ticks`] and [`from_ticks`] convert to
//! and from the tick counts of a codec clock, rounding to the nearest.

use std::{fmt, sync::Arc};

/// A timestamp or duration in nanoseconds.
pub type Time = i64;

/// One second in [`Time`] units.
pub const SECOND: Time = 1_000_000_000;
/// One millisecond in [`Time`] units.
pub const MILLISECOND: Time = 1_000_000;

/// The codecs the media stack knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Codec {
    /// Not known: tracks of this codec are dropped by the egresses.
    #[default]
    Unknown,
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AAC (any profile carried by an `AudioSpecificConfig`).
    Aac,
    /// Opus.
    Opus,
    /// G.711 µ-law.
    Pcmu,
    /// G.711 A-law.
    Pcma,
    /// MPEG-1/2 audio layer III.
    Mp3,
}

impl Codec {
    /// Whether this is a video codec.
    pub fn is_video(self) -> bool {
        matches!(self, Codec::H264 | Codec::H265)
    }

    /// Whether this is an audio codec.
    pub fn is_audio(self) -> bool {
        matches!(
            self,
            Codec::Aac | Codec::Opus | Codec::Pcmu | Codec::Pcma | Codec::Mp3
        )
    }

    /// The name used in logs and statistics ("H264", "AAC", ...).
    pub fn name(self) -> &'static str {
        match self {
            Codec::Unknown => "unknown",
            Codec::H264 => "H264",
            Codec::H265 => "H265",
            Codec::Aac => "AAC",
            Codec::Opus => "Opus",
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
            Codec::Mp3 => "MP3",
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One elementary stream of a media stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Track {
    /// The codec.
    pub codec: Codec,
    /// The codec configuration in its ISO BMFF form (see the [module docs](self)).
    pub config: Vec<u8>,
    /// Picture size, when known (video).
    pub width: u32,
    /// Picture height, when known (video).
    pub height: u32,
    /// Sample rate in Hz (audio).
    pub sample_rate: u32,
    /// Channel count (audio).
    pub channels: u8,
}

impl Track {
    /// A track of `codec` with configuration `config` and nothing else known yet.
    pub fn new(codec: Codec, config: Vec<u8>) -> Track {
        Track {
            codec,
            config,
            ..Track::default()
        }
    }

    /// A video track of `codec` with its configuration record; the picture size is read from
    /// the SPS when it parses.
    pub fn video(codec: Codec, config: Vec<u8>) -> Track {
        let mut t = Track::new(codec, config);
        let size = match codec {
            Codec::H264 => crate::codec::h264::Config::parse(&t.config)
                .ok()
                .and_then(|c| c.sps.first().and_then(|s| crate::codec::h264::sps_size(s))),
            Codec::H265 => crate::codec::h265::Config::parse(&t.config)
                .ok()
                .and_then(|c| c.size()),
            _ => None,
        };
        if let Some((w, h)) = size {
            t.width = w;
            t.height = h;
        }
        t
    }

    /// An AAC track from its `AudioSpecificConfig`, with rate and channels filled in when the
    /// configuration parses.
    pub fn aac(config: Vec<u8>) -> Track {
        let mut t = Track::new(Codec::Aac, config);
        if let Ok(c) = crate::codec::aac::Config::parse(&t.config) {
            t.sample_rate = c.sample_rate;
            t.channels = c.channels;
        }
        t
    }

    /// An audio track of `codec` at `sample_rate` with `channels`.
    pub fn audio(codec: Codec, config: Vec<u8>, sample_rate: u32, channels: u8) -> Track {
        Track {
            codec,
            config,
            sample_rate,
            channels,
            ..Track::default()
        }
    }

    /// Whether this is a video track.
    pub fn is_video(&self) -> bool {
        self.codec.is_video()
    }

    /// The RTP / MPEG clock rate of this track: 90 kHz for video, the sample rate for audio
    /// (48 kHz for Opus, 8 kHz for G.711).
    pub fn clock_rate(&self) -> u32 {
        match self.codec {
            Codec::Opus => 48_000,
            Codec::Pcmu | Codec::Pcma => 8_000,
            c if c.is_video() => 90_000,
            _ if self.sample_rate > 0 => self.sample_rate,
            _ => 90_000,
        }
    }
}

/// The tracks of a stream, shared by every subscriber.
pub type Tracks = Arc<[Track]>;

/// One access unit or frame of a track.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Packet {
    /// Index of the track in the stream's [`Tracks`].
    pub track: usize,
    /// Decoding time.
    pub dts: Time,
    /// Presentation time (`>= dts` for video with B-frames, `== dts` otherwise).
    pub pts: Time,
    /// A random access point (IDR / IRAP for video; every audio frame is one).
    pub keyframe: bool,
    /// The payload in its canonical form (see the [module docs](self)).
    pub data: Vec<u8>,
}

impl Packet {
    /// A packet of `track` at `dts` / `pts`.
    pub fn new(track: usize, dts: Time, pts: Time, keyframe: bool, data: Vec<u8>) -> Packet {
        Packet {
            track,
            dts,
            pts,
            keyframe,
            data,
        }
    }

    /// The composition time offset, `pts - dts`.
    pub fn cts(&self) -> Time {
        self.pts - self.dts
    }
}

fn round_div(a: i128, b: i128) -> i128 {
    if a >= 0 {
        (a + b / 2) / b
    } else {
        -((-a + b / 2) / b)
    }
}

/// Converts `t` to ticks of a `rate` Hz clock, rounding to the nearest tick. 0 for `rate == 0`.
pub fn to_ticks(t: Time, rate: u32) -> i64 {
    if rate == 0 {
        return 0;
    }
    let v = round_div(i128::from(t) * i128::from(rate), i128::from(SECOND));
    i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX })
}

/// Converts `ticks` of a `rate` Hz clock to [`Time`], rounding to the nearest nanosecond.
pub fn from_ticks(ticks: i64, rate: u32) -> Time {
    if rate == 0 {
        return 0;
    }
    let v = round_div(i128::from(ticks) * i128::from(SECOND), i128::from(rate));
    i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_round_trip() {
        assert_eq!(to_ticks(SECOND, 90_000), 90_000);
        assert_eq!(to_ticks(-SECOND, 90_000), -90_000);
        assert_eq!(to_ticks(SECOND / 3, 90_000), 30_000);
        assert_eq!(to_ticks(5555, 90_000), 0);
        assert_eq!(to_ticks(5556, 90_000), 1);
        assert_eq!(to_ticks(-5556, 90_000), -1);
        assert_eq!(to_ticks(20 * MILLISECOND, 48_000), 960);
        assert_eq!(to_ticks(SECOND, 0), 0);
        assert_eq!(from_ticks(1, 3), 333_333_333);
        assert_eq!(from_ticks(2, 3), 666_666_667);
        assert_eq!(from_ticks(-2, 3), -666_666_667);
        assert_eq!(from_ticks(90_000 * 3600, 90_000), 3600 * SECOND);
        for ticks in [0i64, 1, 7, 12345, -999, 1 << 40] {
            for rate in [1000u32, 8000, 44100, 48000, 90000] {
                assert_eq!(to_ticks(from_ticks(ticks, rate), rate), ticks);
            }
        }
    }

    #[test]
    fn codec_kinds() {
        assert!(Codec::H264.is_video() && !Codec::H264.is_audio());
        assert!(Codec::Aac.is_audio() && !Codec::Aac.is_video());
        assert!(!Codec::Unknown.is_audio() && !Codec::Unknown.is_video());
        assert_eq!(Codec::H265.to_string(), "H265");
        let p = Packet::new(0, SECOND, SECOND + 40 * MILLISECOND, true, vec![]);
        assert_eq!(p.cts(), 40 * MILLISECOND);
    }
}
