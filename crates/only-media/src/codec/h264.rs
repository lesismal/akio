//! H.264 / AVC: NAL units, Annex B and AVCC framing, the `AVCDecoderConfigurationRecord`
//! (ISO/IEC 14496-15 5.3.3.1) and the picture size from a sequence parameter set.

use crate::bits::{BitReader, unescape_rbsp};

use super::CodecError;

/// NAL unit type of a non-IDR slice.
pub const NAL_SLICE: u8 = 1;
/// NAL unit type of an IDR slice (a keyframe).
pub const NAL_IDR: u8 = 5;
/// NAL unit type of supplemental enhancement information.
pub const NAL_SEI: u8 = 6;
/// NAL unit type of a sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// NAL unit type of a picture parameter set.
pub const NAL_PPS: u8 = 8;
/// NAL unit type of an access unit delimiter.
pub const NAL_AUD: u8 = 9;

/// The type of the NAL unit starting with `header`.
pub fn nal_type(header: u8) -> u8 {
    header & 0x1f
}

/// Splits an Annex B byte stream (start codes `00 00 01` / `00 00 00 01`) into NAL units.
/// Bytes before the first start code are taken as a NAL unit too, so a lone NAL unit without
/// start code comes back whole.
pub fn split_annexb(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push((i, i + 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    if starts.is_empty() {
        if !data.is_empty() {
            out.push(data);
        }
        return out;
    }
    let lead = trim_zeros(&data[..starts[0].0]);
    if !lead.is_empty() {
        out.push(lead);
    }
    for (k, &(_, begin)) in starts.iter().enumerate() {
        let end = starts.get(k + 1).map_or(data.len(), |s| s.0);
        let nal = trim_zeros(&data[begin..end]);
        if !nal.is_empty() {
            out.push(nal);
        }
    }
    out
}

fn trim_zeros(mut b: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = b {
        b = rest;
    }
    b
}

/// The NAL units of an AVCC access unit (4-byte lengths); stops at the first malformed length.
pub fn avcc_nalus(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 4 {
        let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if n > rest.len() - 4 {
            break;
        }
        if n > 0 {
            out.push(&rest[4..4 + n]);
        }
        rest = &rest[4 + n..];
    }
    out
}

/// Appends `nal` to `out` with a 4-byte length prefix.
pub fn push_avcc(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
    out.extend_from_slice(nal);
}

/// Converts NAL units to one AVCC access unit.
pub fn to_avcc<'a>(nalus: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nalus {
        push_avcc(&mut out, n);
    }
    out
}

/// Appends the NAL units of an AVCC access unit to `out` as Annex B (4-byte start codes).
pub fn avcc_to_annexb(data: &[u8], out: &mut Vec<u8>) {
    for n in avcc_nalus(data) {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(n);
    }
}

/// Whether an AVCC access unit holds an IDR slice.
pub fn is_keyframe(data: &[u8]) -> bool {
    avcc_nalus(data)
        .iter()
        .any(|n| !n.is_empty() && nal_type(n[0]) == NAL_IDR)
}

/// An `AVCDecoderConfigurationRecord`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// `AVCProfileIndication`.
    pub profile: u8,
    /// `profile_compatibility`.
    pub compat: u8,
    /// `AVCLevelIndication`.
    pub level: u8,
    /// Bytes in a NAL unit length prefix (1, 2 or 4).
    pub length_size: u8,
    /// Sequence parameter sets.
    pub sps: Vec<Vec<u8>>,
    /// Picture parameter sets.
    pub pps: Vec<Vec<u8>>,
}

impl Config {
    /// A record from one SPS and PPS (profile and level are taken from the SPS).
    pub fn from_sets(sps: &[u8], pps: &[u8]) -> Config {
        Config {
            profile: sps.get(1).copied().unwrap_or(0),
            compat: sps.get(2).copied().unwrap_or(0),
            level: sps.get(3).copied().unwrap_or(0),
            length_size: 4,
            sps: vec![sps.to_vec()],
            pps: vec![pps.to_vec()],
        }
    }

    /// Parses a record.
    pub fn parse(b: &[u8]) -> Result<Config, CodecError> {
        if b.len() < 7 || b[0] != 1 {
            return Err(CodecError::Invalid("AVC configuration record"));
        }
        let mut c = Config {
            profile: b[1],
            compat: b[2],
            level: b[3],
            length_size: (b[4] & 3) + 1,
            ..Config::default()
        };
        let mut p = 5;
        let nsps = usize::from(b[p] & 0x1f);
        p += 1;
        for _ in 0..nsps {
            let (set, np) = read_set(b, p)?;
            c.sps.push(set);
            p = np;
        }
        let npps = usize::from(*b.get(p).ok_or(CodecError::Short)?);
        p += 1;
        for _ in 0..npps {
            let (set, np) = read_set(b, p)?;
            c.pps.push(set);
            p = np;
        }
        Ok(c)
    }

    /// Encodes the record.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![
            1,
            self.profile,
            self.compat,
            self.level,
            0xfc | (self.length_size.clamp(1, 4) - 1),
            0xe0 | (self.sps.len().min(31) as u8),
        ];
        for s in self.sps.iter().take(31) {
            b.extend_from_slice(&(s.len() as u16).to_be_bytes());
            b.extend_from_slice(s);
        }
        b.push(self.pps.len().min(255) as u8);
        for s in self.pps.iter().take(255) {
            b.extend_from_slice(&(s.len() as u16).to_be_bytes());
            b.extend_from_slice(s);
        }
        b
    }
}

pub(crate) fn read_set(b: &[u8], p: usize) -> Result<(Vec<u8>, usize), CodecError> {
    let len = b.get(p..p + 2).ok_or(CodecError::Short)?;
    let n = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let set = b.get(p + 2..p + 2 + n).ok_or(CodecError::Short)?;
    Ok((set.to_vec(), p + 2 + n))
}

/// The picture size (width, height) a sequence parameter set (NAL header included) declares.
pub fn sps_size(sps: &[u8]) -> Option<(u32, u32)> {
    sps_fields(sps).map(|(_, size)| size)
}

/// The fields of a sequence parameter set a slice header's syntax depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpsInfo {
    id: u32,
    /// `ChromaArrayType`.
    chroma_array_type: u32,
    separate_colour_plane: bool,
    log2_max_frame_num: u32,
    poc_type: u32,
    log2_max_poc_lsb: u32,
    delta_pic_order_always_zero: bool,
    frame_mbs_only: bool,
}

/// The fields of a picture parameter set a slice header's syntax depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PpsInfo {
    id: u32,
    sps_id: u32,
    cabac: bool,
    bottom_field_pic_order_in_frame_present: bool,
    num_ref_idx_l0_default: u32,
    num_ref_idx_l1_default: u32,
    weighted_pred: bool,
    weighted_bipred_idc: u32,
    deblocking_filter_control_present: bool,
    redundant_pic_cnt_present: bool,
}

/// Parses a sequence parameter set (NAL header included): the fields slices need and the
/// picture size.
fn sps_fields(sps: &[u8]) -> Option<(SpsInfo, (u32, u32))> {
    let rbsp = unescape_rbsp(sps.get(1..)?);
    let mut r = BitReader::new(&rbsp);
    let profile = r.bits(8)?;
    r.skip(16)?; // constraint flags + level
    let id = r.ue()?;
    let mut chroma_format_idc = 1;
    let mut separate_colour_plane = false;
    if matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = r.ue()?;
        if chroma_format_idc == 3 {
            separate_colour_plane = r.flag()?;
        }
        r.ue()?; // bit_depth_luma_minus8
        r.ue()?; // bit_depth_chroma_minus8
        r.flag()?; // qpprime_y_zero_transform_bypass_flag
        if r.flag()? {
            let lists = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..lists {
                if r.flag()? {
                    let size = if i < 6 { 16 } else { 64 };
                    let (mut last, mut next) = (8i32, 8i32);
                    for _ in 0..size {
                        if next != 0 {
                            let delta = r.se()?;
                            next = (last + delta + 256) % 256;
                        }
                        if next != 0 {
                            last = next;
                        }
                    }
                }
            }
        }
    }
    let log2_max_frame_num = r.ue()?.checked_add(4).filter(|&v| v <= 16)?;
    let poc_type = r.ue()?;
    let mut log2_max_poc_lsb = 0;
    let mut delta_pic_order_always_zero = false;
    match poc_type {
        0 => {
            log2_max_poc_lsb = r.ue()?.checked_add(4).filter(|&v| v <= 16)?;
        }
        1 => {
            delta_pic_order_always_zero = r.flag()?;
            r.se()?;
            r.se()?;
            let n = r.ue()?;
            if n > 255 {
                return None;
            }
            for _ in 0..n {
                r.se()?;
            }
        }
        _ => {}
    }
    r.ue()?; // max_num_ref_frames
    r.flag()?; // gaps_in_frame_num_value_allowed_flag
    let w_mbs = r.ue()?.checked_add(1)?;
    let h_units = r.ue()?.checked_add(1)?;
    let frame_mbs_only = r.flag()?;
    if !frame_mbs_only {
        r.flag()?;
    }
    r.flag()?; // direct_8x8_inference_flag
    let (mut cl, mut cr, mut ct, mut cb) = (0, 0, 0, 0);
    if r.flag()? {
        cl = r.ue()?;
        cr = r.ue()?;
        ct = r.ue()?;
        cb = r.ue()?;
    }
    let field = if frame_mbs_only { 1 } else { 2 };
    let (sub_w, sub_h) = match (chroma_format_idc, separate_colour_plane) {
        (0, _) | (3, true) => (1, field),
        (1, _) => (2, 2 * field),
        (2, _) => (2, field),
        _ => (1, field),
    };
    let w = w_mbs
        .checked_mul(16)?
        .checked_sub(cl.checked_add(cr)?.checked_mul(sub_w)?)?;
    let h = h_units
        .checked_mul(16 * field)?
        .checked_sub(ct.checked_add(cb)?.checked_mul(sub_h)?)?;
    let info = SpsInfo {
        id,
        chroma_array_type: if separate_colour_plane {
            0
        } else {
            chroma_format_idc
        },
        separate_colour_plane,
        log2_max_frame_num,
        poc_type,
        log2_max_poc_lsb,
        delta_pic_order_always_zero,
        frame_mbs_only,
    };
    Some((info, (w, h)))
}

/// The slice-relevant fields of a sequence parameter set (NAL header included).
pub(crate) fn sps_info(sps: &[u8]) -> Option<SpsInfo> {
    sps_fields(sps).map(|(i, _)| i)
}

/// The slice-relevant fields of a picture parameter set (NAL header included); `None` for
/// one with slice groups (FMO, Baseline only), which this does not follow.
pub(crate) fn pps_info(pps: &[u8]) -> Option<PpsInfo> {
    let rbsp = unescape_rbsp(pps.get(1..)?);
    let mut r = BitReader::new(&rbsp);
    let id = r.ue()?;
    let sps_id = r.ue()?;
    let cabac = r.flag()?;
    let bottom_field_pic_order_in_frame_present = r.flag()?;
    if r.ue()? != 0 {
        return None; // num_slice_groups_minus1
    }
    let num_ref_idx_l0_default = r.ue()?.checked_add(1).filter(|&n| n <= 32)?;
    let num_ref_idx_l1_default = r.ue()?.checked_add(1).filter(|&n| n <= 32)?;
    let weighted_pred = r.flag()?;
    let weighted_bipred_idc = r.bits(2)?;
    r.se()?; // pic_init_qp_minus26
    r.se()?; // pic_init_qs_minus26
    r.se()?; // chroma_qp_index_offset
    let deblocking_filter_control_present = r.flag()?;
    r.flag()?; // constrained_intra_pred_flag
    let redundant_pic_cnt_present = r.flag()?;
    Some(PpsInfo {
        id,
        sps_id,
        cabac,
        bottom_field_pic_order_in_frame_present,
        num_ref_idx_l0_default,
        num_ref_idx_l1_default,
        weighted_pred,
        weighted_bipred_idc,
        deblocking_filter_control_present,
        redundant_pic_cnt_present,
    })
}

/// The length of a coded slice NAL unit's NAL header and slice header (H.264 7.3.3), in bytes
/// of the NAL unit as stored (emulation prevention bytes counted), rounded up to a whole byte:
/// what `cbcs` leaves clear before the slice data. `None` when the slice's parameter sets are
/// not among `sps` / `pps` or the header does not parse.
pub(crate) fn slice_header_len(nal: &[u8], sps: &[SpsInfo], pps: &[PpsInfo]) -> Option<usize> {
    let header = *nal.first()?;
    let nal_type = header & 0x1f;
    if nal_type != NAL_SLICE && nal_type != NAL_IDR {
        return None;
    }
    let idr = nal_type == NAL_IDR;
    let nal_ref_idc = (header >> 5) & 3;
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    r.ue()?; // first_mb_in_slice
    let slice_type = r.ue()? % 5;
    let (p, b, i, sp, si) = (
        slice_type == 0,
        slice_type == 1,
        slice_type == 2,
        slice_type == 3,
        slice_type == 4,
    );
    let pps_id = r.ue()?;
    let pps = pps.iter().find(|x| x.id == pps_id)?;
    let sps = sps.iter().find(|x| x.id == pps.sps_id)?;
    if sps.separate_colour_plane {
        r.skip(2)?; // colour_plane_id
    }
    r.skip(sps.log2_max_frame_num as usize)?; // frame_num
    let mut field_pic = false;
    if !sps.frame_mbs_only {
        field_pic = r.flag()?;
        if field_pic {
            r.flag()?; // bottom_field_flag
        }
    }
    if idr {
        r.ue()?; // idr_pic_id
    }
    if sps.poc_type == 0 {
        r.skip(sps.log2_max_poc_lsb as usize)?;
        if pps.bottom_field_pic_order_in_frame_present && !field_pic {
            r.se()?;
        }
    }
    if sps.poc_type == 1 && !sps.delta_pic_order_always_zero {
        r.se()?;
        if pps.bottom_field_pic_order_in_frame_present && !field_pic {
            r.se()?;
        }
    }
    if pps.redundant_pic_cnt_present {
        r.ue()?;
    }
    if b {
        r.flag()?; // direct_spatial_mv_pred_flag
    }
    let (mut l0, mut l1) = (pps.num_ref_idx_l0_default, pps.num_ref_idx_l1_default);
    if (p || sp || b) && r.flag()? {
        l0 = r.ue()?.checked_add(1).filter(|&n| n <= 32)?;
        if b {
            l1 = r.ue()?.checked_add(1).filter(|&n| n <= 32)?;
        }
    }
    // ref_pic_list_modification()
    let lists = if b { 2 } else { usize::from(!(i || si)) };
    for _ in 0..lists {
        if r.flag()? {
            let mut n = 0;
            loop {
                let idc = r.ue()?;
                match idc {
                    0..=2 => {
                        r.ue()?;
                    }
                    3 => break,
                    _ => return None,
                }
                n += 1;
                if n > 66 {
                    return None;
                }
            }
        }
    }
    if (pps.weighted_pred && (p || sp)) || (pps.weighted_bipred_idc == 1 && b) {
        // pred_weight_table()
        r.ue()?; // luma_log2_weight_denom
        if sps.chroma_array_type != 0 {
            r.ue()?;
        }
        for count in [l0, if b { l1 } else { 0 }] {
            for _ in 0..count {
                if r.flag()? {
                    r.se()?;
                    r.se()?;
                }
                if sps.chroma_array_type != 0 && r.flag()? {
                    for _ in 0..4 {
                        r.se()?;
                    }
                }
            }
        }
    }
    if nal_ref_idc != 0 {
        // dec_ref_pic_marking()
        if idr {
            r.skip(2)?;
        } else if r.flag()? {
            let mut n = 0;
            loop {
                let op = r.ue()?;
                match op {
                    0 => break,
                    1 | 3 => {
                        r.ue()?;
                        if op == 3 {
                            r.ue()?;
                        }
                    }
                    2 | 4 | 6 => {
                        r.ue()?;
                    }
                    5 => {}
                    _ => return None,
                }
                n += 1;
                if n > 100 {
                    return None;
                }
            }
        }
    }
    if pps.cabac && !i && !si {
        r.ue()?; // cabac_init_idc
    }
    r.se()?; // slice_qp_delta
    if sp || si {
        if sp {
            r.flag()?; // sp_for_switch_flag
        }
        r.se()?; // slice_qs_delta
    }
    if pps.deblocking_filter_control_present && r.ue()? != 1 {
        r.se()?;
        r.se()?;
    }
    // The header ends inside the RBSP at `pos` bits (after the NAL header byte).
    let rbsp_bytes = 1 + r.pos().div_ceil(8);
    // Map RBSP bytes to stored bytes (each `00 00 03` adds the 03).
    let (mut stored, mut seen, mut zeros) = (1usize, 1usize, 0);
    for &v in &nal[1..] {
        if seen == rbsp_bytes {
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
    (seen == rbsp_bytes).then_some(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ffmpeg -f lavfi -i testsrc=size=320x240 -c:v libx264 -profile:v high: SPS and PPS.
    pub(crate) const SPS: &[u8] = &[
        0x67, 0x64, 0x00, 0x0d, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00,
        0x10, 0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99, 0x60,
    ];
    pub(crate) const PPS: &[u8] = &[0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0];

    /// Slice header lengths match what ffmpeg's `trace_headers` bitstream filter reports for
    /// every slice of the sample (x264 with B-frames, weighted prediction and CABAC): the
    /// position after `slice_beta_offset_div2`, rounded up to a byte.
    #[test]
    fn slice_headers_against_ffmpeg() {
        use crate::flv::{Decoder, Demuxer, Event};
        const WANT: [usize; 50] = [
            6, 6, 6, 6, 12, 7, 6, 11, 7, 6, 12, 7, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 6, 6,
            6, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6, 12, 8, 6,
        ];
        let data = include_bytes!("../../testdata/h264_aac.flv");
        let mut dec = Decoder::new();
        let (mut sps, mut pps, mut got) = (Vec::new(), Vec::new(), Vec::new());
        for t in Demuxer::new().feed(data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => {
                        let c = Config::parse(&t[0].config).unwrap();
                        sps = c.sps.iter().filter_map(|s| sps_info(s)).collect();
                        pps = c.pps.iter().filter_map(|s| pps_info(s)).collect();
                    }
                    Event::Packet(p) if p.track == 0 => {
                        for n in avcc_nalus(&p.data) {
                            if matches!(nal_type(n[0]), NAL_SLICE | NAL_IDR) {
                                got.push(slice_header_len(n, &sps, &pps).unwrap());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(got, WANT);
        // Emulation prevention bytes inside the header count; missing parameter sets fail.
        assert_eq!(slice_header_len(&[0x65, 0x88], &sps, &pps), None);
        assert_eq!(slice_header_len(&[0x65, 0x88, 0x84], &[], &pps), None);
        assert_eq!(slice_header_len(&[0x67, 0x88], &sps, &pps), None);
    }

    #[test]
    fn sps_picture_size() {
        assert_eq!(sps_size(SPS), Some((320, 240)));
        assert_eq!(sps_size(&[0x67]), None);
        assert_eq!(sps_size(&SPS[..6]), None);
    }

    #[test]
    fn config_round_trip() {
        let c = Config::from_sets(SPS, PPS);
        let b = c.encode();
        let back = Config::parse(&b).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.profile, 0x64);
        assert!(Config::parse(&b[..b.len() - 1]).is_err());
        assert!(Config::parse(&[0, 1, 2]).is_err());
        let t = crate::av::Track::video(crate::av::Codec::H264, b);
        assert_eq!((t.width, t.height), (320, 240));
    }

    #[test]
    fn framing() {
        let annexb = [
            0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 4, 5, 0,
        ];
        let nals = split_annexb(&annexb);
        assert_eq!(nals, vec![&[0x67, 1, 2][..], &[0x68, 3], &[0x65, 4, 5]]);
        let avcc = to_avcc(nals.iter().copied());
        assert!(is_keyframe(&avcc));
        assert_eq!(avcc_nalus(&avcc), nals);
        let mut back = Vec::new();
        avcc_to_annexb(&avcc, &mut back);
        assert_eq!(split_annexb(&back), nals);
        assert_eq!(split_annexb(&[0x41, 9]), vec![&[0x41, 9][..]]);
        assert!(avcc_nalus(&[0, 0, 0, 9, 1]).is_empty());
        assert!(!is_keyframe(&to_avcc([&[0x41u8, 1][..]])));
    }
}
