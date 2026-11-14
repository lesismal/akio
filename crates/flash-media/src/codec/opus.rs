//! Opus: the `OpusHead` identification header (RFC 7845 5.1) and packet durations.

use super::CodecError;

/// The fields of an `OpusHead`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Head {
    /// Output channel count.
    pub channels: u8,
    /// Samples (at 48 kHz) to discard from the decoder output at the start.
    pub pre_skip: u16,
    /// The original input sample rate (informational).
    pub input_rate: u32,
}

impl Head {
    /// An `OpusHead` for `channels` channels.
    pub fn new(channels: u8) -> Head {
        Head {
            channels,
            pre_skip: 0,
            input_rate: 48_000,
        }
    }

    /// Parses an `OpusHead` (mapping family 0 only; the rest of the header is ignored).
    pub fn parse(b: &[u8]) -> Result<Head, CodecError> {
        if b.len() < 19 || &b[..8] != b"OpusHead" {
            return Err(CodecError::Invalid("OpusHead"));
        }
        Ok(Head {
            channels: b[9],
            pre_skip: u16::from_le_bytes([b[10], b[11]]),
            input_rate: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    /// Encodes the 19-byte header (mapping family 0).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = b"OpusHead".to_vec();
        b.push(1);
        b.push(self.channels);
        b.extend_from_slice(&self.pre_skip.to_le_bytes());
        b.extend_from_slice(&self.input_rate.to_le_bytes());
        b.extend_from_slice(&[0, 0, 0]); // output gain, mapping family 0
        b
    }
}

/// The duration of an Opus packet in 48 kHz samples (RFC 6716 3.1), 0 when malformed.
pub fn packet_samples(p: &[u8]) -> u32 {
    let Some(&toc) = p.first() else { return 0 };
    let config = toc >> 3;
    let frame = match config {
        0..=11 => [480, 960, 1920, 2880][usize::from(config & 3)],
        12..=15 => [480, 960][usize::from(config & 1)],
        _ => [120, 240, 480, 960][usize::from(config & 3)],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => p.get(1).map_or(0, |b| u32::from(b & 0x3f)),
    };
    frame * frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_and_durations() {
        let h = Head::new(2);
        let b = h.encode();
        assert_eq!(b.len(), 19);
        assert_eq!(Head::parse(&b).unwrap(), h);
        assert!(Head::parse(&b[..10]).is_err());
        assert_eq!(packet_samples(&[0xfc]), 960); // config 31, 20 ms
        assert_eq!(packet_samples(&[0x78 | 1]), 2 * 960); // config 15 (20 ms), 2 frames
        assert_eq!(packet_samples(&[3 | (1 << 3), 3]), 3 * 960);
        assert_eq!(packet_samples(&[]), 0);
    }
}
