//! H.265 / HEVC: NAL unit types, the `HEVCDecoderConfigurationRecord` (ISO/IEC 14496-15
//! 8.3.3.1) and the parts of a sequence parameter set the record and the egresses need.
//!
//! Annex B and AVCC framing are the same as H.264's: see [`super::h264`].

use crate::bits::{BitReader, unescape_rbsp};

use super::{CodecError, h264::read_set};

/// NAL unit type of a video parameter set.
pub const NAL_VPS: u8 = 32;
/// NAL unit type of a sequence parameter set.
pub const NAL_SPS: u8 = 33;
/// NAL unit type of a picture parameter set.
pub const NAL_PPS: u8 = 34;
/// NAL unit type of an access unit delimiter.
pub const NAL_AUD: u8 = 35;
/// NAL unit type of a prefix SEI.
pub const NAL_SEI_PREFIX: u8 = 39;

/// The type of the NAL unit whose first header byte is `b0`.
pub fn nal_type(b0: u8) -> u8 {
    (b0 >> 1) & 0x3f
}

/// Whether a NAL unit type is an intra random access point (BLA, IDR, CRA).
pub fn is_irap(t: u8) -> bool {
    (16..=23).contains(&t)
}

/// Whether an AVCC access unit holds an IRAP picture.
pub fn is_keyframe(data: &[u8]) -> bool {
    super::h264::avcc_nalus(data)
        .iter()
        .any(|n| !n.is_empty() && is_irap(nal_type(n[0])))
}

/// What the record needs from an SPS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpsInfo {
    /// `general_profile_space`, `general_tier_flag` and `general_profile_idc` as one byte.
    pub profile_byte: u8,
    /// `general_profile_compatibility_flags`.
    pub compat: u32,
    /// `general_constraint_indicator_flags` (48 bits).
    pub constraints: [u8; 6],
    /// `general_level_idc`.
    pub level: u8,
    /// `chroma_format_idc`.
    pub chroma_format: u32,
    /// `bit_depth_luma_minus8`.
    pub bit_depth_luma_minus8: u32,
    /// `bit_depth_chroma_minus8`.
    pub bit_depth_chroma_minus8: u32,
    /// `sps_max_sub_layers_minus1 + 1`.
    pub sub_layers: u8,
    /// `sps_temporal_id_nesting_flag`.
    pub temporal_id_nested: bool,
    /// Picture width after the conformance window.
    pub width: u32,
    /// Picture height after the conformance window.
    pub height: u32,
}

/// Parses the fields [`SpsInfo`] holds from an SPS (NAL header included).
pub fn parse_sps(sps: &[u8]) -> Option<SpsInfo> {
    let rbsp = unescape_rbsp(sps.get(2..)?);
    let mut r = BitReader::new(&rbsp);
    r.bits(4)?; // sps_video_parameter_set_id
    let max_sub_layers_minus1 = r.bits(3)?;
    let nested = r.flag()?;
    let profile_byte = r.bits(8)? as u8;
    let compat = r.bits(32)?;
    let mut constraints = [0u8; 6];
    for c in &mut constraints {
        *c = r.bits(8)? as u8;
    }
    let level = r.bits(8)? as u8;
    let mut profile_present = [false; 8];
    let mut level_present = [false; 8];
    for i in 0..max_sub_layers_minus1 as usize {
        profile_present[i] = r.flag()?;
        level_present[i] = r.flag()?;
    }
    if max_sub_layers_minus1 > 0 {
        for _ in max_sub_layers_minus1..8 {
            r.bits(2)?;
        }
    }
    for i in 0..max_sub_layers_minus1 as usize {
        if profile_present[i] {
            r.skip(88)?;
        }
        if level_present[i] {
            r.skip(8)?;
        }
    }
    r.ue()?; // sps_seq_parameter_set_id
    let chroma_format = r.ue()?;
    let mut separate = false;
    if chroma_format == 3 {
        separate = r.flag()?;
    }
    let mut width = r.ue()?;
    let mut height = r.ue()?;
    if r.flag()? {
        let (l, ri, t, b) = (r.ue()?, r.ue()?, r.ue()?, r.ue()?);
        let (sw, sh) = match (chroma_format, separate) {
            (1, _) => (2, 2),
            (2, _) => (2, 1),
            _ => (1, 1),
        };
        width = width.checked_sub(sw * l.checked_add(ri)?)?;
        height = height.checked_sub(sh * t.checked_add(b)?)?;
    }
    let bit_depth_luma_minus8 = r.ue()?;
    let bit_depth_chroma_minus8 = r.ue()?;
    Some(SpsInfo {
        profile_byte,
        compat,
        constraints,
        level,
        chroma_format,
        bit_depth_luma_minus8,
        bit_depth_chroma_minus8,
        sub_layers: max_sub_layers_minus1 as u8 + 1,
        temporal_id_nested: nested,
        width,
        height,
    })
}

/// An `HEVCDecoderConfigurationRecord`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// The 21 bytes after `configurationVersion`, as found (profile, level, formats...).
    pub header: Vec<u8>,
    /// Bytes in a NAL unit length prefix.
    pub length_size: u8,
    /// Video parameter sets.
    pub vps: Vec<Vec<u8>>,
    /// Sequence parameter sets.
    pub sps: Vec<Vec<u8>>,
    /// Picture parameter sets.
    pub pps: Vec<Vec<u8>>,
}

impl Config {
    /// A record from one VPS, SPS and PPS; `None` when the SPS does not parse.
    pub fn from_sets(vps: &[u8], sps: &[u8], pps: &[u8]) -> Option<Config> {
        let i = parse_sps(sps)?;
        let mut h = Vec::with_capacity(22);
        h.push(i.profile_byte);
        h.extend_from_slice(&i.compat.to_be_bytes());
        h.extend_from_slice(&i.constraints);
        h.push(i.level);
        h.extend_from_slice(&[0xf0, 0x00]); // min_spatial_segmentation_idc = 0
        h.push(0xfc); // parallelismType = 0
        h.push(0xfc | (i.chroma_format as u8 & 3));
        h.push(0xf8 | (i.bit_depth_luma_minus8 as u8 & 7));
        h.push(0xf8 | (i.bit_depth_chroma_minus8 as u8 & 7));
        h.extend_from_slice(&[0, 0]); // avgFrameRate
        // constantFrameRate 0, numTemporalLayers, temporalIdNested, lengthSizeMinusOne 3
        h.push(((i.sub_layers & 7) << 3) | (u8::from(i.temporal_id_nested) << 2) | 3);
        Some(Config {
            header: h,
            length_size: 4,
            vps: vec![vps.to_vec()],
            sps: vec![sps.to_vec()],
            pps: vec![pps.to_vec()],
        })
    }

    /// Parses a record.
    pub fn parse(b: &[u8]) -> Result<Config, CodecError> {
        if b.len() < 23 || b[0] != 1 {
            return Err(CodecError::Invalid("HEVC configuration record"));
        }
        let mut c = Config {
            header: b[1..22].to_vec(),
            length_size: (b[21] & 3) + 1,
            ..Config::default()
        };
        let n = b[22];
        let mut p = 23;
        for _ in 0..n {
            let hdr = b.get(p..p + 3).ok_or(CodecError::Short)?;
            let typ = hdr[0] & 0x3f;
            let count = u16::from_be_bytes([hdr[1], hdr[2]]);
            p += 3;
            for _ in 0..count {
                let (set, np) = read_set(b, p)?;
                p = np;
                match typ {
                    NAL_VPS => c.vps.push(set),
                    NAL_SPS => c.sps.push(set),
                    NAL_PPS => c.pps.push(set),
                    _ => {}
                }
            }
        }
        Ok(c)
    }

    /// Encodes the record.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![1];
        let mut h = self.header.clone();
        h.resize(21, 0);
        h[20] = (h[20] & !3) | (self.length_size.clamp(1, 4) - 1);
        b.extend_from_slice(&h);
        let arrays: Vec<(u8, &Vec<Vec<u8>>)> = [
            (NAL_VPS, &self.vps),
            (NAL_SPS, &self.sps),
            (NAL_PPS, &self.pps),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
        b.push(arrays.len() as u8);
        for (t, sets) in arrays {
            b.push(0x80 | t);
            b.extend_from_slice(&(sets.len() as u16).to_be_bytes());
            for s in sets {
                b.extend_from_slice(&(s.len() as u16).to_be_bytes());
                b.extend_from_slice(s);
            }
        }
        b
    }

    /// The picture size from the first SPS.
    pub fn size(&self) -> Option<(u32, u32)> {
        self.sps
            .first()
            .and_then(|s| parse_sps(s))
            .map(|i| (i.width, i.height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ffmpeg -f lavfi -i testsrc=size=320x240 -pix_fmt yuv420p -c:v libx265
    pub(crate) const VPS: &[u8] = &[
        0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x95, 0x98, 0x09,
    ];
    pub(crate) const SPS: &[u8] = &[
        0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x03, 0x00, 0x3c, 0xa0, 0x0a, 0x08, 0x0f, 0x16, 0x59, 0x59, 0xa4, 0x93, 0x2b, 0xc0, 0x5a,
        0x02, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x32, 0x10,
    ];
    pub(crate) const PPS: &[u8] = &[0x44, 0x01, 0xc1, 0x72, 0xb4, 0x62, 0x40];

    #[test]
    fn sps_and_record() {
        let i = parse_sps(SPS).unwrap();
        assert_eq!((i.width, i.height), (320, 240));
        assert_eq!(i.profile_byte, 1);
        assert_eq!(i.level, 60);
        let c = Config::from_sets(VPS, SPS, PPS).unwrap();
        let b = c.encode();
        let back = Config::parse(&b).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.size(), Some((320, 240)));
        assert!(Config::parse(&b[..30]).is_err());
        assert!(parse_sps(&SPS[..10]).is_none());
        assert_eq!(nal_type(SPS[0]), NAL_SPS);
        assert!(is_irap(19) && !is_irap(1));
    }
}
