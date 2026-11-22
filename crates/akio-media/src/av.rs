//! The types every protocol of the media stack shares: codecs ([`Codec`]), the description of
//! an elementary stream ([`Track`]) and one timed unit of it ([`Packet`]).
//!
//! Every ingest converts what it receives into one canonical form and every egress muxes from
//! that form, so a stream published over RTMP plays over RTSP, HLS or SRT with no
//! protocol-to-protocol glue. The canonical form is the one ISO BMFF (MP4) uses:
//!
//! * [`Track::config`]: the codec's out-of-band configuration: the
//!   `AVCDecoderConfigurationRecord` for H.264, the `HEVCDecoderConfigurationRecord` for H.265,
//!   the `VPCodecConfigurationRecord` (`vpcC` without version and flags) for VP8 and VP9, the
//!   `AV1CodecConfigurationRecord` (`av1C`, with the sequence header OBU) for AV1, the
//!   `AudioSpecificConfig` for AAC, the `OpusHead` for Opus (optional), empty for G.711.
//! * [`Packet::data`]: one access unit or frame: H.264 and H.265 as AVCC (each NAL unit
//!   prefixed by a 4-byte big-endian length, no access unit delimiters); VP8 and VP9 as one
//!   frame (a VP9 superframe as it came); AV1 as one temporal unit of OBUs with `obu_size` and
//!   no temporal delimiter ([`crate::codec::av1::to_sample`]); AAC as one raw access unit
//!   without ADTS header; Opus as one Opus packet; G.711 as the samples.
//!
//! A packet is a keyframe when a decoder can start there: an IDR (H.264) or IRAP (H.265)
//! picture, a VP8 or VP9 keyframe, an AV1 temporal unit whose first frame is a shown
//! `KEY_FRAME`. The hub's GOP cache, HLS segmenting and the dropping of slow players rely on
//! it, so every ingest sets it from the bitstream.
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
    /// VP8.
    Vp8,
    /// VP9.
    Vp9,
    /// AV1.
    Av1,
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
        matches!(
            self,
            Codec::H264 | Codec::H265 | Codec::Vp8 | Codec::Vp9 | Codec::Av1
        )
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
            Codec::Vp8 => "VP8",
            Codec::Vp9 => "VP9",
            Codec::Av1 => "AV1",
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
    /// the SPS (H.264, H.265) or the sequence header (AV1) when it parses. A VP8 or VP9 record
    /// has no size: set [`width`](Self::width) and [`height`](Self::height), or use
    /// [`video_from_keyframe`](Self::video_from_keyframe).
    pub fn video(codec: Codec, config: Vec<u8>) -> Track {
        let mut t = Track::new(codec, config);
        let size = match codec {
            Codec::H264 => crate::codec::h264::Config::parse(&t.config)
                .ok()
                .and_then(|c| c.sps.first().and_then(|s| crate::codec::h264::sps_size(s))),
            Codec::H265 => crate::codec::h265::Config::parse(&t.config)
                .ok()
                .and_then(|c| c.size()),
            Codec::Av1 => crate::codec::av1::Config::parse(&t.config)
                .ok()
                .and_then(|c| c.sequence_header())
                .map(|s| (s.max_width, s.max_height)),
            _ => None,
        };
        if let Some((w, h)) = size {
            t.width = w;
            t.height = h;
        }
        t
    }

    /// The video track of a VP8, VP9 or AV1 stream whose keyframe (in the canonical form) is
    /// `frame`, for streams that carry no configuration out of band (RTP, WebRTC): the
    /// configuration record and picture size come from the keyframe's header (AV1: its
    /// sequence header). `None` for another codec, an inter frame, or a header that does not
    /// parse.
    pub fn video_from_keyframe(codec: Codec, frame: &[u8]) -> Option<Track> {
        use crate::codec::{av1, vp8, vp9};
        match codec {
            Codec::Vp8 => {
                let (w, h) = vp8::keyframe_size(frame)?;
                let mut t = Track::new(codec, vp8::config(w, h).encode());
                (t.width, t.height) = (w, h);
                Some(t)
            }
            Codec::Vp9 => {
                let k = vp9::parse_keyframe(frame)?;
                let mut t = Track::new(codec, k.config().encode());
                (t.width, t.height) = (k.width, k.height);
                Some(t)
            }
            Codec::Av1 => {
                if !av1::is_keyframe(frame) {
                    return None;
                }
                let c = av1::Config::from_sequence_header(av1::sequence_header_obu(frame)?)?;
                Some(Track::video(codec, c.encode()))
            }
            _ => None,
        }
    }

    /// The RFC 6381 codec string of this track as HLS `CODECS` lists it (`avc1.64001F`,
    /// `hvc1.1.6.L93.B0`, `vp09.00.31.08`, `av01.0.04M.08`, `mp4a.40.2`, `opus`, `mp4a.40.34`
    /// for MP3); `None` for G.711, an unknown codec, or a configuration that does not parse.
    pub fn codec_string(&self) -> Option<String> {
        use crate::codec::{aac, av1, h264, h265, vp9};
        match self.codec {
            Codec::H264 => {
                let c = h264::Config::parse(&self.config).ok()?;
                Some(format!(
                    "avc1.{:02X}{:02X}{:02X}",
                    c.profile, c.compat, c.level
                ))
            }
            Codec::H265 => {
                let c = h265::Config::parse(&self.config).ok()?;
                let h = &c.header;
                let space = ["", "A", "B", "C"][usize::from(h[0] >> 6)];
                let compat = u32::from_be_bytes([h[1], h[2], h[3], h[4]]).reverse_bits();
                let tier = if h[0] & 0x20 != 0 { 'H' } else { 'L' };
                let mut s = format!("hvc1.{space}{}.{compat:X}.{tier}{}", h[0] & 0x1f, h[11]);
                let constraints = &h[5..11];
                let used = constraints
                    .iter()
                    .rposition(|&b| b != 0)
                    .map_or(0, |i| i + 1);
                for b in &constraints[..used] {
                    s.push_str(&format!(".{b:X}"));
                }
                Some(s)
            }
            Codec::Vp8 | Codec::Vp9 => {
                let c = vp9::Config::parse(&self.config).ok()?;
                Some(c.codec_string(if self.codec == Codec::Vp8 {
                    "vp08"
                } else {
                    "vp09"
                }))
            }
            Codec::Av1 => Some(av1::Config::parse(&self.config).ok()?.codec_string()),
            Codec::Aac => {
                let ot = aac::Config::parse(&self.config).map_or(2, |c| c.object_type);
                Some(format!("mp4a.40.{ot}"))
            }
            Codec::Opus => Some("opus".to_owned()),
            Codec::Mp3 => Some("mp4a.40.34".to_owned()),
            _ => None,
        }
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
        for c in [Codec::Vp8, Codec::Vp9, Codec::Av1] {
            assert!(c.is_video() && !c.is_audio());
        }
        assert_eq!(Codec::Av1.name(), "AV1");
        let p = Packet::new(0, SECOND, SECOND + 40 * MILLISECOND, true, vec![]);
        assert_eq!(p.cts(), 40 * MILLISECOND);
    }

    #[test]
    fn codec_strings_and_keyframe_tracks() {
        use crate::codec::{h264, h265};
        let sps = [0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9];
        let t = Track::new(Codec::H264, h264::Config::from_sets(&sps, &[0x68]).encode());
        assert_eq!(t.codec_string().as_deref(), Some("avc1.64001F"));
        // libx265 320x240 Main: general_profile_idc 1, compat 0x60000000, level 60.
        let mut h = vec![0x01, 0x60, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 60];
        h.resize(21, 0);
        let c = h265::Config {
            header: h,
            length_size: 4,
            ..h265::Config::default()
        };
        let t = Track::new(Codec::H265, c.encode());
        assert_eq!(t.codec_string().as_deref(), Some("hvc1.1.6.L60.90"));
        assert_eq!(
            Track::aac(vec![0x12, 0x10]).codec_string().as_deref(),
            Some("mp4a.40.2")
        );
        assert_eq!(
            Track::audio(Codec::Opus, vec![], 48_000, 2)
                .codec_string()
                .as_deref(),
            Some("opus")
        );
        assert!(
            Track::audio(Codec::Pcmu, vec![], 8000, 1)
                .codec_string()
                .is_none()
        );
        // VP9 from a keyframe header, VP8 from a keyframe tag.
        let vp9 = [
            0x82, 0x49, 0x83, 0x42, 0x00, 0x13, 0xf0, 0x0e, 0xf6, 0x00, 0x00,
        ];
        let t = Track::video_from_keyframe(Codec::Vp9, &vp9).unwrap();
        assert_eq!((t.width, t.height), (320, 240));
        assert_eq!(t.codec_string().as_deref(), Some("vp09.00.20.08"));
        let vp8 = [0x50, 0x2d, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00];
        let t = Track::video_from_keyframe(Codec::Vp8, &vp8).unwrap();
        assert_eq!((t.width, t.height), (320, 240));
        assert_eq!(t.codec_string().as_deref(), Some("vp08.00.20.08"));
        assert!(Track::video_from_keyframe(Codec::Vp8, &[0x31, 0, 0]).is_none());
        assert!(Track::video_from_keyframe(Codec::H264, &vp8).is_none());
        // AV1: a temporal unit with its sequence header and a KEY_FRAME.
        let seq = [
            0x0a, 0x0b, 0x02, 0x00, 0x00, 0x05, 0x21, 0xe7, 0xfd, 0xe0, 0x17, 0xc0, 0x02,
        ];
        let mut tu = seq.to_vec();
        tu.extend_from_slice(&[0x32, 0x02, 0x10, 0xaa]);
        let t = Track::video_from_keyframe(Codec::Av1, &tu).unwrap();
        assert_eq!((t.width, t.height), (320, 240));
        assert_eq!(t.codec_string().as_deref(), Some("av01.0.00M.08"));
        assert_eq!(Track::video(Codec::Av1, t.config.clone()), t);
    }
}
