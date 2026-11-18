//! VP9: the `VPCodecConfigurationRecord` (VP Codec ISO Media File Format Binding, `vpcC`) that
//! is the configuration of VP8 and VP9 tracks, and the keyframe header of a VP9 frame (VP9
//! bitstream specification 6.2, uncompressed header), from which the record and the picture
//! size of a stream without out-of-band configuration (WebRTC, RTSP) are made.

use crate::bits::BitReader;

use super::CodecError;

/// A `VPCodecConfigurationRecord` (without the `vpcC` box's version and flags), with no codec
/// initialization data (VP8 and VP9 define none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// Profile (0 to 3).
    pub profile: u8,
    /// Level (10 = 1.0, 11, 20 ... 62; 0 when not known).
    pub level: u8,
    /// Bits per sample: 8, 10 or 12.
    pub bit_depth: u8,
    /// 0: 4:2:0 vertical, 1: 4:2:0 co-located with luma, 2: 4:2:2, 3: 4:4:4.
    pub chroma_subsampling: u8,
    /// Full-range (JPEG) samples rather than studio swing.
    pub full_range: bool,
    /// ISO/IEC 23091-2 colour primaries (2: unspecified).
    pub colour_primaries: u8,
    /// ISO/IEC 23091-2 transfer characteristics (2: unspecified).
    pub transfer_characteristics: u8,
    /// ISO/IEC 23091-2 matrix coefficients (0: RGB / identity, 2: unspecified).
    pub matrix_coefficients: u8,
}

impl Config {
    /// Parses a record (8 bytes and its initialization data, which is skipped).
    pub fn parse(b: &[u8]) -> Result<Config, CodecError> {
        if b.len() < 8 {
            return Err(CodecError::Short);
        }
        let init = usize::from(u16::from_be_bytes([b[6], b[7]]));
        if b.len() < 8 + init || b[0] > 3 {
            return Err(CodecError::Invalid("VP codec configuration record"));
        }
        Ok(Config {
            profile: b[0],
            level: b[1],
            bit_depth: b[2] >> 4,
            chroma_subsampling: (b[2] >> 1) & 7,
            full_range: b[2] & 1 == 1,
            colour_primaries: b[3],
            transfer_characteristics: b[4],
            matrix_coefficients: b[5],
        })
    }

    /// Encodes the record (8 bytes).
    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.profile,
            self.level,
            (self.bit_depth << 4)
                | ((self.chroma_subsampling & 7) << 1)
                | u8::from(self.full_range),
            self.colour_primaries,
            self.transfer_characteristics,
            self.matrix_coefficients,
            0,
            0,
        ]
    }

    /// The RFC 6381 codec string for the sample entry `fourcc` (`vp09` or `vp08`), short form:
    /// `vp09.PP.LL.DD`.
    pub fn codec_string(&self, fourcc: &str) -> String {
        format!(
            "{fourcc}.{:02}.{:02}.{:02}",
            self.profile, self.level, self.bit_depth
        )
    }
}

/// The level whose largest picture fits `width` x `height` (VP9 levels, Annex A), `0` for an
/// unknown size.
pub fn level_for(width: u32, height: u32) -> u8 {
    const LEVELS: [(u8, u64); 9] = [
        (10, 36_864),
        (11, 73_728),
        (20, 122_880),
        (21, 245_760),
        (30, 552_960),
        (31, 983_040),
        (40, 2_228_224),
        (50, 8_912_896),
        (60, 35_651_584),
    ];
    let samples = u64::from(width) * u64::from(height);
    if samples == 0 {
        return 0;
    }
    LEVELS
        .iter()
        .find(|(_, max)| samples <= *max)
        .map_or(62, |(l, _)| *l)
}

/// What the uncompressed header of a VP9 keyframe declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Keyframe {
    /// Profile (0 to 3).
    pub profile: u8,
    /// Bits per sample.
    pub bit_depth: u8,
    /// The `color_space` field (0 unknown, 1 BT.601, 2 BT.709, 3 SMPTE 170, 4 SMPTE 240,
    /// 5 BT.2020, 7 sRGB).
    pub color_space: u8,
    /// Full-range samples.
    pub full_range: bool,
    /// Horizontal chroma subsampling.
    pub subsampling_x: bool,
    /// Vertical chroma subsampling.
    pub subsampling_y: bool,
    /// Picture width.
    pub width: u32,
    /// Picture height.
    pub height: u32,
}

impl Keyframe {
    /// The configuration record of a stream starting with this keyframe.
    pub fn config(&self) -> Config {
        let chroma_subsampling = match (self.subsampling_x, self.subsampling_y) {
            (true, true) => 1,
            (true, false) => 2,
            _ => 3,
        };
        // color_space to ISO/IEC 23091-2 (primaries, transfer, matrix).
        let (cp, tc, mc) = match self.color_space {
            1 | 3 => (6, 6, 6),
            2 => (1, 1, 1),
            4 => (7, 7, 7),
            5 => (9, if self.bit_depth > 10 { 15 } else { 14 }, 9),
            7 => (1, 13, 0),
            _ => (2, 2, 2),
        };
        Config {
            profile: self.profile,
            level: level_for(self.width, self.height),
            bit_depth: self.bit_depth,
            chroma_subsampling,
            full_range: self.full_range,
            colour_primaries: cp,
            transfer_characteristics: tc,
            matrix_coefficients: mc,
        }
    }
}

/// Reads the frame marker, profile and the bits up to `frame_type`: `(profile, keyframe)`;
/// `None` when not a VP9 frame or a frame that shows an existing one.
fn frame_start(r: &mut BitReader<'_>) -> Option<(u8, bool)> {
    if r.bits(2)? != 2 {
        return None;
    }
    let low = r.bit()?;
    let high = r.bit()?;
    let profile = ((high << 1) | low) as u8;
    if profile == 3 {
        r.bit()?; // reserved_zero
    }
    if r.flag()? {
        return None; // show_existing_frame
    }
    Some((profile, r.bit()? == 0))
}

/// Whether `frame` (a VP9 frame or superframe) starts with a keyframe.
pub fn is_keyframe(frame: &[u8]) -> bool {
    frame_start(&mut BitReader::new(frame)).is_some_and(|(_, key)| key)
}

/// The keyframe header at the start of `frame`; `None` for an inter frame or a malformed one.
pub fn parse_keyframe(frame: &[u8]) -> Option<Keyframe> {
    let mut r = BitReader::new(frame);
    let (profile, key) = frame_start(&mut r)?;
    if !key {
        return None;
    }
    r.skip(2)?; // show_frame, error_resilient_mode
    if r.bits(24)? != 0x49_8342 {
        return None;
    }
    let mut bit_depth = 8;
    if profile >= 2 {
        bit_depth = if r.flag()? { 12 } else { 10 };
    }
    let color_space = r.bits(3)? as u8;
    let (full_range, ssx, ssy);
    if color_space != 7 {
        full_range = r.flag()?;
        if profile == 1 || profile == 3 {
            ssx = r.flag()?;
            ssy = r.flag()?;
            r.bit()?; // reserved_zero
        } else {
            (ssx, ssy) = (true, true);
        }
    } else {
        full_range = true;
        (ssx, ssy) = (false, false);
        if profile == 1 || profile == 3 {
            r.bit()?;
        }
    }
    let width = r.bits(16)? + 1;
    let height = r.bits(16)? + 1;
    Some(Keyframe {
        profile,
        bit_depth,
        color_space,
        full_range,
        subsampling_x: ssx,
        subsampling_y: ssy,
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of a 320x240 profile 0 keyframe (libvpx-vp9, yuv420p).
    pub(crate) const KEY_320X240: &[u8] = &[
        0x82, 0x49, 0x83, 0x42, 0x00, 0x13, 0xf0, 0x0e, 0xf6, 0x00, 0x00,
    ];

    #[test]
    fn keyframe_header() {
        let k = parse_keyframe(KEY_320X240).unwrap();
        assert_eq!(
            (k.profile, k.bit_depth, k.width, k.height),
            (0, 8, 320, 240)
        );
        assert!(k.subsampling_x && k.subsampling_y && !k.full_range);
        assert!(is_keyframe(KEY_320X240));
        let c = k.config();
        assert_eq!(
            (c.profile, c.level, c.bit_depth, c.chroma_subsampling),
            (0, 20, 8, 1)
        );
        assert_eq!(c.codec_string("vp09"), "vp09.00.20.08");
        assert_eq!(Config::parse(&c.encode()), Ok(c));
        // Inter frame (frame_type 1), and a frame showing an existing one.
        assert!(!is_keyframe(&[0x86, 0x00]));
        assert!(parse_keyframe(&[0x86, 0x00]).is_none());
        assert!(!is_keyframe(&[0x88]));
        assert!(!is_keyframe(&[0x00, 0x00]));
        assert!(parse_keyframe(&KEY_320X240[..6]).is_none());
        // Profile 1 4:4:4 (as ffmpeg's flv muxer carries it: version/flags stripped).
        let ffmpeg = [0x01, 0x14, 0x87, 0x02, 0x02, 0x00, 0x00, 0x00];
        let c = Config::parse(&ffmpeg).unwrap();
        assert_eq!(
            (c.profile, c.level, c.bit_depth, c.chroma_subsampling),
            (1, 20, 8, 3)
        );
        assert!(c.full_range);
        assert!(Config::parse(&ffmpeg[..7]).is_err());
        assert_eq!(level_for(1920, 1080), 40);
        assert_eq!(level_for(0, 0), 0);
        assert_eq!(level_for(10_000, 10_000), 62);
    }
}
