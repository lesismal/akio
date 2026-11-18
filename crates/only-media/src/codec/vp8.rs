//! VP8 (RFC 6386): keyframes and their picture size, read from the frame tag.
//!
//! A VP8 track's [`Track::config`](crate::av::Track::config) is a
//! `VPCodecConfigurationRecord` ([`vp9::Config`]), as for VP9; [`config`] makes one, since a
//! VP8 stream carries nothing more.

use super::vp9;

/// Whether `frame` is a keyframe (the frame tag's `frame_type` bit is 0).
pub fn is_keyframe(frame: &[u8]) -> bool {
    frame.first().is_some_and(|b| b & 1 == 0)
}

/// The picture size (width, height) a keyframe declares; `None` for an inter frame or a frame
/// too short or without the keyframe start code.
pub fn keyframe_size(frame: &[u8]) -> Option<(u32, u32)> {
    if !is_keyframe(frame) || frame.get(3..6)? != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let w = u32::from(u16::from_le_bytes([*frame.get(6)?, *frame.get(7)?]) & 0x3fff);
    let h = u32::from(u16::from_le_bytes([*frame.get(8)?, *frame.get(9)?]) & 0x3fff);
    (w > 0 && h > 0).then_some((w, h))
}

/// The `VPCodecConfigurationRecord` of a VP8 stream: profile 0, 8-bit 4:2:0, BT.601 (VP8
/// knows nothing else); the level follows the picture size (`0` when not known).
pub fn config(width: u32, height: u32) -> vp9::Config {
    vp9::Config {
        profile: 0,
        level: vp9::level_for(width, height),
        bit_depth: 8,
        chroma_subsampling: 1,
        full_range: false,
        colour_primaries: 2,
        transfer_characteristics: 2,
        matrix_coefficients: 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyframe_and_size() {
        // A keyframe tag (frame_type 0, version 0, show_frame 1), start code, 320x240.
        let key = [
            0x50, 0x2d, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, 0x00,
        ];
        assert!(is_keyframe(&key));
        assert_eq!(keyframe_size(&key), Some((320, 240)));
        let inter = [0x31, 0x02, 0x00, 0x11];
        assert!(!is_keyframe(&inter));
        assert_eq!(keyframe_size(&inter), None);
        assert_eq!(keyframe_size(&key[..8]), None);
        assert!(!is_keyframe(&[]));
        let c = config(320, 240);
        assert_eq!(vp9::Config::parse(&c.encode()), Ok(c));
        assert_eq!(c.level, 20);
    }
}
