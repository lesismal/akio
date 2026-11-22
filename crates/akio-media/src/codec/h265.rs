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
        width = width.checked_sub(l.checked_add(ri)?.checked_mul(sw)?)?;
        height = height.checked_sub(t.checked_add(b)?.checked_mul(sh)?)?;
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

// ---- slice segment headers (for `cbcs` subsamples) ----------------------------------------

/// Most short-term reference picture sets an SPS may hold (H.265 7.4.3.2.1).
const MAX_ST_RPS: usize = 64;
/// Most pictures on each side of a short-term reference picture set.
const MAX_RPS_PICS: usize = 16;

/// A short-term reference picture set: the POC deltas of the pictures before (`neg`) and after
/// (`pos`) the current one, each with `used_by_curr_pic`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Rps {
    neg: Vec<(i32, bool)>,
    pos: Vec<(i32, bool)>,
}

impl Rps {
    fn used(&self) -> usize {
        self.neg.iter().chain(&self.pos).filter(|(_, u)| *u).count()
    }
}

/// What a slice segment header's length depends on in an SPS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SliceSps {
    id: u32,
    separate_colour_plane: bool,
    chroma_array_type: u32,
    log2_max_poc_lsb: u32,
    rps: Vec<Rps>,
    long_term: bool,
    /// `used_by_curr_pic_lt_sps_flag` of each long-term picture the SPS lists.
    lt_used: Vec<bool>,
    temporal_mvp: bool,
    sao: bool,
    /// Bits of `slice_segment_address`: Ceil(Log2(PicSizeInCtbsY)).
    address_bits: u32,
}

/// What a slice segment header's length depends on in a PPS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlicePps {
    id: u32,
    sps_id: u32,
    dependent_slice_segments: bool,
    output_flag_present: bool,
    extra_bits: u32,
    cabac_init_present: bool,
    l0_default: u32,
    l1_default: u32,
    chroma_qp_offsets_present: bool,
    weighted_pred: bool,
    weighted_bipred: bool,
    entry_points: bool,
    loop_filter_across_slices: bool,
    deblocking_override: bool,
    deblocking_disabled: bool,
    lists_modification: bool,
    header_extension: bool,
    chroma_qp_offset_list: bool,
}

/// Ceil(Log2(n)), 0 for n <= 1.
fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

/// Skips `profile_tier_level(1, max_sub_layers_minus1)`.
fn skip_profile_tier_level(r: &mut BitReader<'_>, max_sub_layers_minus1: u32) -> Option<()> {
    r.skip(96)?; // general profile (88 bits) and level (8 bits)
    let mut profile_present = [false; 8];
    let mut level_present = [false; 8];
    for i in 0..max_sub_layers_minus1 as usize {
        profile_present[i] = r.flag()?;
        level_present[i] = r.flag()?;
    }
    if max_sub_layers_minus1 > 0 {
        r.skip(2 * (8 - max_sub_layers_minus1 as usize))?;
    }
    for i in 0..max_sub_layers_minus1 as usize {
        if profile_present[i] {
            r.skip(88)?;
        }
        if level_present[i] {
            r.skip(8)?;
        }
    }
    Some(())
}

/// Skips `scaling_list_data()` (7.3.4).
fn skip_scaling_list_data(r: &mut BitReader<'_>) -> Option<()> {
    for size_id in 0..4u32 {
        let step = if size_id == 3 { 3 } else { 1 };
        let mut matrix = 0;
        while matrix < 6 {
            if r.flag()? {
                let coefs = 64.min(1u32 << (4 + (size_id << 1)));
                if size_id > 1 {
                    r.se()?;
                }
                for _ in 0..coefs {
                    r.se()?;
                }
            } else {
                r.ue()?;
            }
            matrix += step;
        }
    }
    Some(())
}

/// Parses `st_ref_pic_set(idx)` (7.3.7) given the sets before it; `slice` when it is the one
/// of a slice header (`idx` = the SPS's set count, predicted from any of them).
fn st_ref_pic_set(r: &mut BitReader<'_>, idx: usize, sets: &[Rps], slice: bool) -> Option<Rps> {
    if idx != 0 && r.flag()? {
        let delta_idx = if slice { r.ue()? as usize + 1 } else { 1 };
        let rf = sets.get(idx.checked_sub(delta_idx)?)?;
        let sign = r.flag()?;
        let abs = i64::from(r.ue()?) + 1;
        if abs > 1 << 15 {
            return None;
        }
        let delta = if sign { -abs } else { abs } as i32;
        let (nn, np) = (rf.neg.len(), rf.pos.len());
        let n = nn + np;
        let mut used = [false; 2 * MAX_RPS_PICS + 1];
        let mut use_delta = [true; 2 * MAX_RPS_PICS + 1];
        for j in 0..=n {
            used[j] = r.flag()?;
            if !used[j] {
                use_delta[j] = r.flag()?;
            }
        }
        // Equations 7-61 and 7-62.
        let mut neg = Vec::new();
        for j in (0..np).rev() {
            let d = rf.pos[j].0 + delta;
            if d < 0 && use_delta[nn + j] {
                neg.push((d, used[nn + j]));
            }
        }
        if delta < 0 && use_delta[n] {
            neg.push((delta, used[n]));
        }
        for j in 0..nn {
            let d = rf.neg[j].0 + delta;
            if d < 0 && use_delta[j] {
                neg.push((d, used[j]));
            }
        }
        let mut pos = Vec::new();
        for j in (0..nn).rev() {
            let d = rf.neg[j].0 + delta;
            if d > 0 && use_delta[j] {
                pos.push((d, used[j]));
            }
        }
        if delta > 0 && use_delta[n] {
            pos.push((delta, used[n]));
        }
        for j in 0..np {
            let d = rf.pos[j].0 + delta;
            if d > 0 && use_delta[nn + j] {
                pos.push((d, used[nn + j]));
            }
        }
        if neg.len() > MAX_RPS_PICS || pos.len() > MAX_RPS_PICS {
            return None;
        }
        return Some(Rps { neg, pos });
    }
    let nn = r.ue()? as usize;
    let np = r.ue()? as usize;
    if nn > MAX_RPS_PICS || np > MAX_RPS_PICS {
        return None;
    }
    let mut rps = Rps::default();
    let mut poc = 0i32;
    for _ in 0..nn {
        poc = poc.checked_sub(r.ue()?.min(1 << 15) as i32 + 1)?;
        rps.neg.push((poc, r.flag()?));
    }
    poc = 0;
    for _ in 0..np {
        poc = poc.checked_add(r.ue()?.min(1 << 15) as i32 + 1)?;
        rps.pos.push((poc, r.flag()?));
    }
    Some(rps)
}

/// Parses what slice headers need from an SPS (NAL header included); `None` when it does not
/// parse or uses what is not handled (a layer other than 0).
pub(crate) fn slice_sps(nal: &[u8]) -> Option<SliceSps> {
    if nal.len() < 3 || nal_type(nal[0]) != NAL_SPS || (nal[0] & 1) != 0 || nal[1] >> 3 != 0 {
        return None;
    }
    let rbsp = unescape_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    r.bits(4)?; // sps_video_parameter_set_id
    let max_sub_layers_minus1 = r.bits(3)?;
    if max_sub_layers_minus1 > 6 {
        return None;
    }
    r.flag()?; // sps_temporal_id_nesting_flag
    skip_profile_tier_level(&mut r, max_sub_layers_minus1)?;
    let id = r.ue()?;
    let chroma_format = r.ue()?;
    let separate_colour_plane = chroma_format == 3 && r.flag()?;
    let width = r.ue()?;
    let height = r.ue()?;
    if r.flag()? {
        for _ in 0..4 {
            r.ue()?; // conformance window
        }
    }
    r.ue()?; // bit_depth_luma_minus8
    r.ue()?; // bit_depth_chroma_minus8
    let log2_max_poc_lsb = r.ue()?.checked_add(4).filter(|&v| v <= 16)?;
    let ordering_all = r.flag()?;
    let from = if ordering_all {
        0
    } else {
        max_sub_layers_minus1
    };
    for _ in from..=max_sub_layers_minus1 {
        r.ue()?;
        r.ue()?;
        r.ue()?;
    }
    let min_cb = r.ue()?.checked_add(3).filter(|&v| v <= 6)?;
    let ctb = min_cb.checked_add(r.ue()?).filter(|&v| v <= 6)?;
    r.ue()?; // log2_min_luma_transform_block_size_minus2
    r.ue()?; // log2_diff_max_min_luma_transform_block_size
    r.ue()?; // max_transform_hierarchy_depth_inter
    r.ue()?; // max_transform_hierarchy_depth_intra
    if r.flag()? && r.flag()? {
        skip_scaling_list_data(&mut r)?;
    }
    r.flag()?; // amp_enabled_flag
    let sao = r.flag()?;
    if r.flag()? {
        r.skip(8)?; // pcm sample bit depths
        r.ue()?;
        r.ue()?;
        r.flag()?;
    }
    let num_rps = r.ue()? as usize;
    if num_rps > MAX_ST_RPS {
        return None;
    }
    let mut rps = Vec::with_capacity(num_rps);
    for i in 0..num_rps {
        let set = st_ref_pic_set(&mut r, i, &rps, false)?;
        rps.push(set);
    }
    let long_term = r.flag()?;
    let mut lt_used = Vec::new();
    if long_term {
        let n = r.ue()?;
        if n > 32 {
            return None;
        }
        for _ in 0..n {
            r.skip(log2_max_poc_lsb as usize)?;
            lt_used.push(r.flag()?);
        }
    }
    let temporal_mvp = r.flag()?;
    let size = 1u64 << ctb;
    let ctbs = u64::from(width).div_ceil(size) * u64::from(height).div_ceil(size);
    Some(SliceSps {
        id,
        separate_colour_plane,
        chroma_array_type: if separate_colour_plane {
            0
        } else {
            chroma_format
        },
        log2_max_poc_lsb,
        rps,
        long_term,
        lt_used,
        temporal_mvp,
        sao,
        address_bits: ceil_log2(ctbs),
    })
}

/// Parses what slice headers need from a PPS (NAL header included); `None` when it does not
/// parse or carries the multilayer, 3D or screen content extensions.
pub(crate) fn slice_pps(nal: &[u8]) -> Option<SlicePps> {
    if nal.len() < 3 || nal_type(nal[0]) != NAL_PPS || (nal[0] & 1) != 0 || nal[1] >> 3 != 0 {
        return None;
    }
    let rbsp = unescape_rbsp(&nal[2..]);
    let mut r = BitReader::new(&rbsp);
    let mut p = SlicePps {
        id: r.ue()?,
        sps_id: r.ue()?,
        dependent_slice_segments: r.flag()?,
        output_flag_present: r.flag()?,
        extra_bits: r.bits(3)?,
        ..SlicePps::default()
    };
    r.flag()?; // sign_data_hiding_enabled_flag
    p.cabac_init_present = r.flag()?;
    p.l0_default = r.ue()?.checked_add(1).filter(|&n| n <= 15)?;
    p.l1_default = r.ue()?.checked_add(1).filter(|&n| n <= 15)?;
    r.se()?; // init_qp_minus26
    r.flag()?; // constrained_intra_pred_flag
    let transform_skip = r.flag()?;
    if r.flag()? {
        r.ue()?; // diff_cu_qp_delta_depth
    }
    r.se()?; // pps_cb_qp_offset
    r.se()?; // pps_cr_qp_offset
    p.chroma_qp_offsets_present = r.flag()?;
    p.weighted_pred = r.flag()?;
    p.weighted_bipred = r.flag()?;
    r.flag()?; // transquant_bypass_enabled_flag
    let tiles = r.flag()?;
    let entropy_sync = r.flag()?;
    p.entry_points = tiles || entropy_sync;
    if tiles {
        let cols = r.ue()?;
        let rows = r.ue()?;
        if cols > 63 || rows > 63 {
            return None;
        }
        if !r.flag()? {
            for _ in 0..cols + rows {
                r.ue()?;
            }
        }
        r.flag()?; // loop_filter_across_tiles_enabled_flag
    }
    p.loop_filter_across_slices = r.flag()?;
    if r.flag()? {
        p.deblocking_override = r.flag()?;
        p.deblocking_disabled = r.flag()?;
        if !p.deblocking_disabled {
            r.se()?;
            r.se()?;
        }
    }
    if r.flag()? {
        skip_scaling_list_data(&mut r)?;
    }
    p.lists_modification = r.flag()?;
    r.ue()?; // log2_parallel_merge_level_minus2
    p.header_extension = r.flag()?;
    if r.flag()? {
        let range = r.flag()?;
        let other = r.bits(3)?; // multilayer, 3D, screen content
        r.bits(4)?;
        if other != 0 {
            return None;
        }
        if range {
            if transform_skip {
                r.ue()?;
            }
            r.flag()?; // cross_component_prediction_enabled_flag
            p.chroma_qp_offset_list = r.flag()?;
            if p.chroma_qp_offset_list {
                r.ue()?;
                let n = r.ue()?;
                if n > 5 {
                    return None;
                }
                for _ in 0..=n {
                    r.se()?;
                    r.se()?;
                }
            }
            r.ue()?;
            r.ue()?;
        }
    }
    Some(p)
}

/// Whether a NAL unit type is a coded slice segment.
pub(crate) fn is_slice(t: u8) -> bool {
    t <= 9 || (16..=21).contains(&t)
}

/// The length in bytes (NAL header and emulation prevention bytes included) of the slice
/// segment header of `nal` (H.265 7.3.6.1, up to its `byte_alignment()`): what `cbcs` keeps
/// clear before the slice data. `None` when `nal` is not a slice of layer 0, its parameter
/// sets are unknown, or it does not parse.
pub(crate) fn slice_header_len(nal: &[u8], sps: &[SliceSps], pps: &[SlicePps]) -> Option<usize> {
    if nal.len() < 3 || (nal[0] & 1) != 0 || nal[1] >> 3 != 0 {
        return None;
    }
    let t = nal_type(nal[0]);
    if !is_slice(t) {
        return None;
    }
    // Only the header is read: unescape a bounded prefix (headers are short; the entry points
    // of a picture with many tiles or rows make the longest).
    let rbsp = unescape_rbsp(&nal[2..nal.len().min(2 + 4096)]);
    let mut r = BitReader::new(&rbsp);
    let first = r.flag()?;
    if (16..=23).contains(&t) {
        r.flag()?; // no_output_of_prior_pics_flag
    }
    let pps_id = r.ue()?;
    let pps = pps.iter().find(|x| x.id == pps_id)?;
    let sps = sps.iter().find(|x| x.id == pps.sps_id)?;
    let mut dependent = false;
    if !first {
        if pps.dependent_slice_segments {
            dependent = r.flag()?;
        }
        r.skip(sps.address_bits as usize)?;
    }
    if !dependent {
        r.skip(pps.extra_bits as usize)?;
        let slice_type = r.ue()?;
        let (b, p) = match slice_type {
            0 => (true, false),
            1 => (false, true),
            2 => (false, false),
            _ => return None,
        };
        if pps.output_flag_present {
            r.flag()?;
        }
        if sps.separate_colour_plane {
            r.skip(2)?;
        }
        let mut temporal_mvp = false;
        let mut total_curr = 0usize;
        if t != 19 && t != 20 {
            r.skip(sps.log2_max_poc_lsb as usize)?;
            let rps = if r.flag()? {
                let bits = ceil_log2(sps.rps.len() as u64);
                let idx = r.bits(bits)? as usize;
                sps.rps.get(idx)?.clone()
            } else {
                st_ref_pic_set(&mut r, sps.rps.len(), &sps.rps, true)?
            };
            total_curr = rps.used();
            if sps.long_term {
                let n_sps = if sps.lt_used.is_empty() { 0 } else { r.ue()? };
                let n_pics = r.ue()?;
                if n_sps as usize > sps.lt_used.len() || n_pics > 32 {
                    return None;
                }
                for i in 0..n_sps + n_pics {
                    if i < n_sps {
                        let bits = ceil_log2(sps.lt_used.len() as u64);
                        let idx = r.bits(bits)? as usize;
                        total_curr += usize::from(*sps.lt_used.get(idx)?);
                    } else {
                        r.skip(sps.log2_max_poc_lsb as usize)?;
                        total_curr += usize::from(r.flag()?);
                    }
                    if r.flag()? {
                        r.ue()?; // delta_poc_msb_cycle_lt
                    }
                }
            }
            if sps.temporal_mvp {
                temporal_mvp = r.flag()?;
            }
        }
        let (mut sao_luma, mut sao_chroma) = (false, false);
        if sps.sao {
            sao_luma = r.flag()?;
            if sps.chroma_array_type != 0 {
                sao_chroma = r.flag()?;
            }
        }
        if p || b {
            let (mut l0, mut l1) = (pps.l0_default, pps.l1_default);
            if r.flag()? {
                l0 = r.ue()?.checked_add(1).filter(|&n| n <= 15)?;
                if b {
                    l1 = r.ue()?.checked_add(1).filter(|&n| n <= 15)?;
                }
            }
            if pps.lists_modification && total_curr > 1 {
                let bits = ceil_log2(total_curr as u64) as usize;
                if r.flag()? {
                    r.skip(bits * l0 as usize)?;
                }
                if b && r.flag()? {
                    r.skip(bits * l1 as usize)?;
                }
            }
            if b {
                r.flag()?; // mvd_l1_zero_flag
            }
            if pps.cabac_init_present {
                r.flag()?;
            }
            if temporal_mvp {
                let from_l0 = if b { r.flag()? } else { true };
                if (from_l0 && l0 > 1) || (!from_l0 && l1 > 1) {
                    r.ue()?; // collocated_ref_idx
                }
            }
            if (pps.weighted_pred && p) || (pps.weighted_bipred && b) {
                // pred_weight_table(): every reference has another POC than the picture.
                r.ue()?;
                let chroma = sps.chroma_array_type != 0;
                if chroma {
                    r.se()?;
                }
                for count in [l0, if b { l1 } else { 0 }] {
                    let mut luma = [false; 16];
                    let mut chr = [false; 16];
                    for f in luma.iter_mut().take(count as usize) {
                        *f = r.flag()?;
                    }
                    if chroma {
                        for f in chr.iter_mut().take(count as usize) {
                            *f = r.flag()?;
                        }
                    }
                    for i in 0..count as usize {
                        if luma[i] {
                            r.se()?;
                            r.se()?;
                        }
                        if chr[i] {
                            for _ in 0..4 {
                                r.se()?;
                            }
                        }
                    }
                }
            }
            r.ue()?; // five_minus_max_num_merge_cand
        }
        r.se()?; // slice_qp_delta
        if pps.chroma_qp_offsets_present {
            r.se()?;
            r.se()?;
        }
        if pps.chroma_qp_offset_list {
            r.flag()?;
        }
        let mut disabled = pps.deblocking_disabled;
        if pps.deblocking_override && r.flag()? {
            disabled = r.flag()?;
            if !disabled {
                r.se()?;
                r.se()?;
            }
        }
        if pps.loop_filter_across_slices && (sao_luma || sao_chroma || !disabled) {
            r.flag()?;
        }
    }
    if pps.entry_points {
        let n = r.ue()?;
        if n > 0 {
            let len = r.ue()?.checked_add(1).filter(|&l| l <= 32)?;
            r.skip((n as usize).checked_mul(len as usize)?)?;
        }
    }
    if pps.header_extension {
        let n = r.ue()?;
        if n > 256 {
            return None;
        }
        r.skip(8 * n as usize)?;
    }
    // byte_alignment(): a one, then zeros to the byte boundary.
    if !r.flag()? {
        return None;
    }
    let rbsp_bytes = 2 + r.pos().div_ceil(8);
    stored_len(nal, rbsp_bytes)
}

/// The stored bytes of `nal` holding its first `rbsp` bytes (each `00 00 03` adds the 03); the
/// first two are the NAL header.
fn stored_len(nal: &[u8], rbsp: usize) -> Option<usize> {
    let (mut stored, mut seen, mut zeros) = (2usize, 2usize, 0);
    for &v in &nal[2..] {
        if seen == rbsp {
            break;
        }
        stored += 1;
        if zeros >= 2 && v == 3 {
            zeros = 0;
            continue;
        }
        zeros = if v == 0 { zeros + 1 } else { 0 };
        seen += 1;
    }
    (seen == rbsp).then_some(stored)
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

    /// Slice segment header lengths match what ffmpeg's `trace_headers` bitstream filter
    /// reports (the byte after `alignment_bit_equal_to_one`, NAL header included, in RBSP
    /// bytes) for every slice of two samples: x265 with B-frames, wavefront entry points and
    /// SAO (`h265_aac.flv`), and x265 with three slices per picture, weighted prediction, four
    /// references and a B-pyramid, parameter sets in band (`h265_slices.hevc`).
    #[test]
    fn slice_headers_against_ffmpeg() {
        use crate::flv::{Decoder, Demuxer, Event};
        const WANT_FLV: [usize; 50] = [
            10, 12, 10, 15, 12, 12, 12, 12, 16, 12, 11, 16, 12, 11, 11, 16, 12, 11, 15, 12, 11, 15,
            11, 13, 12, 11, 13, 10, 10, 10, 16, 12, 11, 11, 17, 13, 11, 12, 17, 13, 11, 11, 17, 13,
            11, 11, 16, 13, 12, 12,
        ];
        const WANT_SLICES: [usize; 150] = [
            5, 5, 8, 9, 10, 12, 10, 11, 13, 11, 12, 13, 11, 12, 13, 11, 11, 13, 11, 12, 14, 12, 13,
            15, 12, 12, 14, 12, 12, 14, 12, 13, 15, 12, 13, 15, 12, 12, 14, 12, 12, 14, 12, 13, 15,
            12, 13, 15, 12, 12, 14, 12, 12, 14, 12, 13, 15, 12, 13, 15, 12, 12, 14, 12, 12, 14, 9,
            9, 12, 12, 13, 15, 12, 12, 14, 12, 12, 14, 9, 10, 12, 10, 11, 13, 11, 11, 13, 11, 11,
            13, 11, 12, 14, 12, 13, 15, 12, 12, 14, 12, 12, 14, 12, 13, 15, 12, 13, 15, 12, 13, 14,
            12, 13, 14, 12, 12, 14, 12, 13, 15, 12, 13, 15, 12, 12, 14, 12, 13, 15, 12, 13, 15, 12,
            12, 14, 11, 12, 14, 12, 13, 15, 12, 13, 15, 12, 12, 15, 12, 12, 14,
        ];
        // RBSP bytes of the stored header (ffmpeg counts after removing emulation prevention).
        let rbsp = |n: &[u8], len: usize| 2 + unescape_rbsp(&n[2..len]).len();
        let (mut sps, mut pps) = (Vec::new(), Vec::new());
        let take = |n: &[u8], sps: &mut Vec<SliceSps>, pps: &mut Vec<SlicePps>| match nal_type(n[0])
        {
            NAL_SPS => sps.push(slice_sps(n).expect("sps")),
            NAL_PPS => pps.push(slice_pps(n).expect("pps")),
            _ => {}
        };
        let mut got = Vec::new();
        let mut dec = Decoder::new();
        for t in Demuxer::new()
            .feed(include_bytes!("../../testdata/h265_aac.flv"))
            .unwrap()
        {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => {
                        let c = Config::parse(&t[0].config).unwrap();
                        for n in c.sps.iter().chain(&c.pps) {
                            take(n, &mut sps, &mut pps);
                        }
                    }
                    Event::Packet(p) if p.track == 0 => {
                        for n in super::super::h264::avcc_nalus(&p.data) {
                            if is_slice(nal_type(n[0])) {
                                let len = slice_header_len(n, &sps, &pps).expect("parses");
                                got.push(rbsp(n, len));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(got, WANT_FLV);
        let (mut sps, mut pps, mut got) = (Vec::new(), Vec::new(), Vec::new());
        for n in super::super::h264::split_annexb(include_bytes!("../../testdata/h265_slices.hevc"))
        {
            take(n, &mut sps, &mut pps);
            if is_slice(nal_type(n[0])) {
                let len = slice_header_len(n, &sps, &pps).expect("parses");
                assert!(len < n.len());
                got.push(rbsp(n, len));
            }
        }
        assert_eq!(got, WANT_SLICES);
        // Parameter sets missing, other NAL units, truncation and other layers fail.
        let n = super::super::h264::split_annexb(include_bytes!("../../testdata/h265_slices.hevc"))
            .into_iter()
            .find(|n| is_slice(nal_type(n[0])))
            .unwrap();
        assert!(slice_header_len(n, &[], &pps).is_none());
        assert!(slice_header_len(n, &sps, &[]).is_none());
        assert!(slice_header_len(&n[..4], &sps, &pps).is_none());
        assert!(slice_header_len(SPS, &sps, &pps).is_none());
        let mut layered = n.to_vec();
        layered[1] |= 0x08;
        assert!(slice_header_len(&layered, &sps, &pps).is_none());
        assert!(slice_sps(&SPS[..12]).is_none() && slice_sps(PPS).is_none());
        assert!(slice_pps(&PPS[..3]).is_none() && slice_pps(SPS).is_none());
    }

    /// Inter-predicted reference picture sets follow equations 7-61 / 7-62.
    #[test]
    fn predicted_rps() {
        use crate::bits::BitWriter;
        let base = Rps {
            neg: vec![(-1, true), (-3, true)],
            pos: vec![(2, true)],
        };
        // inter_ref_pic_set_prediction_flag 1, delta_rps_sign 1, abs_delta_rps_minus1 0 (-1),
        // then used_by_curr_pic_flag 1 for j = 0..=3.
        let mut w = BitWriter::default();
        w.put(0b11, 2);
        w.put(1, 1); // ue(0)
        w.put(0b1111, 4);
        w.put(0, 8);
        let out = w.finish();
        let mut r = BitReader::new(&out);
        let got = st_ref_pic_set(&mut r, 1, std::slice::from_ref(&base), false).unwrap();
        assert_eq!(got.neg, [(-1, true), (-2, true), (-4, true)]);
        assert_eq!(got.pos, [(1, true)]);
        assert_eq!(got.used(), 4);
    }
}
