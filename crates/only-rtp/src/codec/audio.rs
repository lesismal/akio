//! Pass-through payload format: Opus (RFC 7587), G.711 and G.722 (RFC 3551), unknown codecs.

use super::{CodecError, Depacketizer, Packetizer};

/// One payload per frame, the frame itself, marker clear. Frames larger than `mtu` are still
/// sent whole (audio frames cannot be split).
#[derive(Debug, Default, Clone)]
pub struct PassthroughPacketizer {
    _priv: (),
}

impl PassthroughPacketizer {
    /// A new packetizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Packetizer for PassthroughPacketizer {
    fn packetize(&mut self, _mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)> {
        if frame.is_empty() {
            return Vec::new();
        }
        vec![(frame.to_vec(), false)]
    }
}

/// Every payload is one whole frame.
#[derive(Debug, Default, Clone)]
pub struct PassthroughDepacketizer {
    _priv: (),
}

impl PassthroughDepacketizer {
    /// A new depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Depacketizer for PassthroughDepacketizer {
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
        out.extend_from_slice(payload);
        Ok(())
    }

    fn is_frame_start(&self, _payload: &[u8]) -> bool {
        true
    }

    fn is_frame_end(&self, _payload: &[u8], _marker: bool) -> bool {
        true
    }

    fn is_keyframe(&self, _payload: &[u8]) -> bool {
        true
    }
}
