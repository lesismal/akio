//! AV1: OBUs of the low-overhead bitstream format (AV1 specification 5.3), the sequence header
//! (5.5), the `AV1CodecConfigurationRecord` (AV1 Codec ISO Media File Format Binding, `av1C`)
//! and keyframe detection from the frame header (5.9).
//!
//! The canonical packet of an AV1 track is one temporal unit as ISO BMFF stores a sample: OBUs
//! with `obu_has_size_field = 1` and no temporal delimiter ([`to_sample`]).

use std::borrow::Cow;

use crate::bits::BitReader;

use super::CodecError;

/// OBU type of a sequence header.
pub const OBU_SEQUENCE_HEADER: u8 = 1;
/// OBU type of a temporal delimiter.
pub const OBU_TEMPORAL_DELIMITER: u8 = 2;
/// OBU type of a frame header.
pub const OBU_FRAME_HEADER: u8 = 3;
/// OBU type of a frame (header and tile group).
pub const OBU_FRAME: u8 = 6;
/// OBU type of a tile list.
pub const OBU_TILE_LIST: u8 = 8;

/// One OBU of a temporal unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Obu<'a> {
    /// `obu_type`.
    pub obu_type: u8,
    /// The OBU header (1 or 2 bytes, with the extension).
    pub header: &'a [u8],
    /// Whether it has `obu_size`.
    pub sized: bool,
    /// The payload.
    pub payload: &'a [u8],
    /// The whole OBU as found (header, size and payload).
    pub data: &'a [u8],
}

fn read_leb128(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, byte) in b.iter().take(8).enumerate() {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn write_leb128(out: &mut Vec<u8>, mut v: usize) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Splits a temporal unit into OBUs, up to the end or the first malformed OBU (forbidden bit,
/// truncated header or size). An OBU without `obu_size` runs to the end.
pub fn obus(data: &[u8]) -> Vec<Obu<'_>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(&h) = data.get(pos) {
        if h & 0x80 != 0 {
            break;
        }
        let start = pos;
        let hlen = if h & 0x04 != 0 { 2 } else { 1 };
        let Some(header) = data.get(pos..pos + hlen) else {
            break;
        };
        pos += hlen;
        let sized = h & 0x02 != 0;
        let size = if sized {
            let Some((v, n)) = data.get(pos..).and_then(read_leb128) else {
                break;
            };
            pos += n;
            match usize::try_from(v) {
                Ok(v) if v <= data.len() - pos => v,
                _ => break,
            }
        } else {
            data.len() - pos
        };
        out.push(Obu {
            obu_type: (h >> 3) & 0x0f,
            header,
            sized,
            payload: &data[pos..pos + size],
            data: &data[start..pos + size],
        });
        pos += size;
    }
    out
}

/// A temporal unit as ISO BMFF stores it: temporal delimiters and tile lists dropped, every OBU
/// with `obu_size`, nothing after the first malformed OBU. Borrowed when already so.
pub fn to_sample(tu: &[u8]) -> Cow<'_, [u8]> {
    let list = obus(tu);
    let used: usize = list.iter().map(|o| o.data.len()).sum();
    let clean = used == tu.len()
        && list.iter().all(|o| {
            o.sized && o.obu_type != OBU_TEMPORAL_DELIMITER && o.obu_type != OBU_TILE_LIST
        });
    if clean {
        return Cow::Borrowed(tu);
    }
    let mut out = Vec::with_capacity(tu.len() + 8);
    for o in list {
        if o.obu_type == OBU_TEMPORAL_DELIMITER || o.obu_type == OBU_TILE_LIST {
            continue;
        }
        if o.sized {
            out.extend_from_slice(o.data);
        } else {
            out.push(o.header[0] | 0x02);
            out.extend_from_slice(&o.header[1..]);
            write_leb128(&mut out, o.payload.len());
            out.extend_from_slice(o.payload);
        }
    }
    Cow::Owned(out)
}

/// The fields of a sequence header the stack uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SequenceHeader {
    /// `seq_profile` (0 main, 1 high, 2 professional).
    pub profile: u8,
    /// `seq_level_idx[0]`.
    pub level: u8,
    /// `seq_tier[0]`.
    pub tier: bool,
    /// `reduced_still_picture_header`.
    pub reduced_still_picture_header: bool,
    /// `frame_id_numbers_present_flag`.
    pub frame_id_numbers_present: bool,
    /// `high_bitdepth`.
    pub high_bitdepth: bool,
    /// `twelve_bit`.
    pub twelve_bit: bool,
    /// `mono_chrome`.
    pub monochrome: bool,
    /// `subsampling_x`.
    pub subsampling_x: bool,
    /// `subsampling_y`.
    pub subsampling_y: bool,
    /// `chroma_sample_position`.
    pub chroma_sample_position: u8,
    /// Largest picture width.
    pub max_width: u32,
    /// Largest picture height.
    pub max_height: u32,
}

fn uvlc(r: &mut BitReader<'_>) -> Option<u32> {
    let mut zeros = 0;
    while r.bit()? == 0 {
        zeros += 1;
        if zeros >= 32 {
            return Some(u32::MAX);
        }
    }
    Some(r.bits(zeros)?.saturating_add((1u32 << zeros) - 1))
}

impl SequenceHeader {
    /// Parses the payload of a sequence header OBU.
    pub fn parse(payload: &[u8]) -> Option<SequenceHeader> {
        let mut r = BitReader::new(payload);
        let mut s = SequenceHeader {
            profile: r.bits(3)? as u8,
            ..SequenceHeader::default()
        };
        r.bit()?; // still_picture
        s.reduced_still_picture_header = r.flag()?;
        if s.reduced_still_picture_header {
            s.level = r.bits(5)? as u8;
        } else {
            let mut decoder_model = false;
            let mut buffer_delay_len = 0;
            if r.flag()? {
                // timing_info
                r.skip(64)?;
                if r.flag()? {
                    uvlc(&mut r)?;
                }
                decoder_model = r.flag()?;
                if decoder_model {
                    buffer_delay_len = r.bits(5)? + 1;
                    r.skip(32 + 5 + 5)?;
                }
            }
            let initial_display_delay = r.flag()?;
            let points = r.bits(5)? + 1;
            for i in 0..points {
                r.skip(12)?; // operating_point_idc
                let level = r.bits(5)? as u8;
                let tier = level > 7 && r.flag()?;
                if i == 0 {
                    s.level = level;
                    s.tier = tier;
                }
                if decoder_model && r.flag()? {
                    r.skip(2 * buffer_delay_len as usize + 1)?;
                }
                if initial_display_delay && r.flag()? {
                    r.skip(4)?;
                }
            }
        }
        let wbits = r.bits(4)? + 1;
        let hbits = r.bits(4)? + 1;
        s.max_width = r.bits(wbits)?.checked_add(1)?;
        s.max_height = r.bits(hbits)?.checked_add(1)?;
        if !s.reduced_still_picture_header {
            s.frame_id_numbers_present = r.flag()?;
            if s.frame_id_numbers_present {
                r.skip(7)?;
            }
        }
        r.skip(3)?; // use_128x128_superblock, enable_filter_intra, enable_intra_edge_filter
        if !s.reduced_still_picture_header {
            r.skip(4)?; // interintra, masked compound, warped motion, dual filter
            let order_hint = r.flag()?;
            if order_hint {
                r.skip(2)?; // enable_jnt_comp, enable_ref_frame_mvs
            }
            let force_sct = if r.flag()? { 2 } else { r.bit()? };
            if force_sct > 0 && !r.flag()? {
                r.bit()?; // seq_force_integer_mv
            }
            if order_hint {
                r.skip(3)?;
            }
        }
        r.skip(3)?; // enable_superres, enable_cdef, enable_restoration
        // color_config
        s.high_bitdepth = r.flag()?;
        if s.profile == 2 && s.high_bitdepth {
            s.twelve_bit = r.flag()?;
        }
        s.monochrome = s.profile != 1 && r.flag()?;
        let (mut cp, mut tc, mut mc) = (2, 2, 2);
        if r.flag()? {
            cp = r.bits(8)?;
            tc = r.bits(8)?;
            mc = r.bits(8)?;
        }
        if s.monochrome {
            r.bit()?;
            (s.subsampling_x, s.subsampling_y) = (true, true);
        } else if cp == 1 && tc == 13 && mc == 0 {
            (s.subsampling_x, s.subsampling_y) = (false, false);
        } else {
            r.bit()?; // color_range
            (s.subsampling_x, s.subsampling_y) = match s.profile {
                0 => (true, true),
                1 => (false, false),
                _ if s.twelve_bit => {
                    let x = r.flag()?;
                    (x, x && r.flag()?)
                }
                _ => (true, false),
            };
            if s.subsampling_x && s.subsampling_y {
                s.chroma_sample_position = r.bits(2)? as u8;
            }
        }
        Some(s)
    }

    /// Bits per sample.
    pub fn bit_depth(&self) -> u8 {
        match (self.high_bitdepth, self.twelve_bit) {
            (false, _) => 8,
            (true, false) => 10,
            (true, true) => 12,
        }
    }
}

/// An `AV1CodecConfigurationRecord`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// `seq_profile`.
    pub profile: u8,
    /// `seq_level_idx_0`.
    pub level: u8,
    /// `seq_tier_0`.
    pub tier: bool,
    /// `high_bitdepth`.
    pub high_bitdepth: bool,
    /// `twelve_bit`.
    pub twelve_bit: bool,
    /// `monochrome`.
    pub monochrome: bool,
    /// `chroma_subsampling_x`.
    pub subsampling_x: bool,
    /// `chroma_subsampling_y`.
    pub subsampling_y: bool,
    /// `chroma_sample_position`.
    pub chroma_sample_position: u8,
    /// `configOBUs`: the sequence header OBU (with `obu_size`), possibly metadata OBUs.
    pub config_obus: Vec<u8>,
}

impl Config {
    /// The record of a stream whose sequence header OBU (whole, as found in a temporal unit)
    /// is `obu`; `None` when it does not parse.
    pub fn from_sequence_header(obu: &[u8]) -> Option<Config> {
        let o = *obus(obu).first()?;
        if o.obu_type != OBU_SEQUENCE_HEADER {
            return None;
        }
        let s = SequenceHeader::parse(o.payload)?;
        Some(Config {
            profile: s.profile,
            level: s.level,
            tier: s.tier,
            high_bitdepth: s.high_bitdepth,
            twelve_bit: s.twelve_bit,
            monochrome: s.monochrome,
            subsampling_x: s.subsampling_x,
            subsampling_y: s.subsampling_y,
            chroma_sample_position: s.chroma_sample_position,
            config_obus: to_sample(o.data).into_owned(),
        })
    }

    /// Parses a record.
    pub fn parse(b: &[u8]) -> Result<Config, CodecError> {
        if b.len() < 4 {
            return Err(CodecError::Short);
        }
        if b[0] != 0x81 {
            return Err(CodecError::Invalid("AV1 configuration record"));
        }
        Ok(Config {
            profile: b[1] >> 5,
            level: b[1] & 0x1f,
            tier: b[2] & 0x80 != 0,
            high_bitdepth: b[2] & 0x40 != 0,
            twelve_bit: b[2] & 0x20 != 0,
            monochrome: b[2] & 0x10 != 0,
            subsampling_x: b[2] & 0x08 != 0,
            subsampling_y: b[2] & 0x04 != 0,
            chroma_sample_position: b[2] & 3,
            config_obus: b[4..].to_vec(),
        })
    }

    /// Encodes the record (no initial presentation delay).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + self.config_obus.len());
        b.push(0x81);
        b.push((self.profile << 5) | (self.level & 0x1f));
        b.push(
            (u8::from(self.tier) << 7)
                | (u8::from(self.high_bitdepth) << 6)
                | (u8::from(self.twelve_bit) << 5)
                | (u8::from(self.monochrome) << 4)
                | (u8::from(self.subsampling_x) << 3)
                | (u8::from(self.subsampling_y) << 2)
                | (self.chroma_sample_position & 3),
        );
        b.push(0);
        b.extend_from_slice(&self.config_obus);
        b
    }

    /// The sequence header of `config_obus`.
    pub fn sequence_header(&self) -> Option<SequenceHeader> {
        obus(&self.config_obus)
            .iter()
            .find(|o| o.obu_type == OBU_SEQUENCE_HEADER)
            .and_then(|o| SequenceHeader::parse(o.payload))
    }

    /// Bits per sample.
    pub fn bit_depth(&self) -> u8 {
        match (self.high_bitdepth, self.twelve_bit) {
            (false, _) => 8,
            (true, false) => 10,
            (true, true) => 12,
        }
    }

    /// The RFC 6381 codec string, short form: `av01.P.LLT.DD`.
    pub fn codec_string(&self) -> String {
        format!(
            "av01.{}.{:02}{}.{:02}",
            self.profile,
            self.level,
            if self.tier { 'H' } else { 'M' },
            self.bit_depth()
        )
    }
}

/// The sequence header OBU of a temporal unit (whole, as found), if it has one.
pub fn sequence_header_obu(tu: &[u8]) -> Option<&[u8]> {
    obus(tu)
        .into_iter()
        .find(|o| o.obu_type == OBU_SEQUENCE_HEADER)
        .map(|o| o.data)
}

/// Whether a temporal unit starts a keyframe: its first frame header is a shown `KEY_FRAME`
/// (`reduced_still_picture_header` and frame ids are taken from the unit's sequence header,
/// if it has one).
pub fn is_keyframe(tu: &[u8]) -> bool {
    let list = obus(tu);
    let seq = list
        .iter()
        .find(|o| o.obu_type == OBU_SEQUENCE_HEADER)
        .and_then(|o| SequenceHeader::parse(o.payload));
    let Some(fh) = list
        .iter()
        .find(|o| o.obu_type == OBU_FRAME_HEADER || o.obu_type == OBU_FRAME)
    else {
        return false;
    };
    if seq.is_some_and(|s| s.reduced_still_picture_header) {
        return true;
    }
    let mut r = BitReader::new(fh.payload);
    // show_existing_frame, then frame_type (2 bits, KEY_FRAME = 0) and show_frame.
    matches!((r.bit(), r.bits(2), r.bit()), (Some(0), Some(0), Some(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration ffmpeg's flv muxer wrote for libsvtav1 320x240 yuv420p.
    pub(crate) const AV1C_320X240: &[u8] = &[
        0x81, 0x00, 0x0c, 0x00, 0x0a, 0x0b, 0x02, 0x00, 0x00, 0x05, 0x21, 0xe7, 0xfd, 0xe0, 0x17,
        0xc0, 0x02,
    ];

    #[test]
    fn config_and_sequence_header() {
        let c = Config::parse(AV1C_320X240).unwrap();
        assert_eq!((c.profile, c.level, c.tier), (0, 0, false));
        assert!(c.subsampling_x && c.subsampling_y && !c.high_bitdepth);
        assert_eq!(c.encode(), AV1C_320X240);
        let s = c.sequence_header().unwrap();
        assert_eq!((s.max_width, s.max_height), (320, 240));
        assert_eq!((s.profile, s.level, s.bit_depth()), (0, 0, 8));
        assert!(s.subsampling_x && s.subsampling_y);
        let again = Config::from_sequence_header(&c.config_obus).unwrap();
        assert_eq!(again, c);
        assert_eq!(c.codec_string(), "av01.0.00M.08");
        assert!(Config::parse(&[0x81, 0]).is_err());
        assert!(Config::parse(&[0x01, 0, 0, 0]).is_err());
    }

    #[test]
    fn samples_and_keyframes() {
        let seq = &AV1C_320X240[4..];
        // TD, sequence header, a KEY_FRAME frame OBU (show_existing 0, KEY, show 1).
        let mut tu = vec![0x12, 0x00];
        tu.extend_from_slice(seq);
        tu.extend_from_slice(&[0x32, 0x02, 0x10, 0xaa]);
        assert!(is_keyframe(&tu));
        let s = to_sample(&tu);
        assert!(matches!(s, Cow::Owned(_)));
        assert_eq!(&s[..seq.len()], seq);
        assert!(matches!(to_sample(&s), Cow::Borrowed(_)));
        assert_eq!(sequence_header_obu(&tu), Some(seq));
        // An inter frame (frame_type 1).
        assert!(!is_keyframe(&[0x32, 0x02, 0x30, 0xaa]));
        // A frame without obu_size gets one.
        let s = to_sample(&[0x30, 0x10, 0xaa]);
        assert_eq!(&*s, &[0x32, 0x02, 0x10, 0xaa]);
        assert!(!is_keyframe(&[]));
        // Truncated: what parses is kept.
        assert_eq!(&*to_sample(&[0x32, 0x05, 0x10]), &[] as &[u8]);
    }
}
