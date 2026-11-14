//! AAC: the `AudioSpecificConfig` (ISO/IEC 14496-3 1.6.2.1) and ADTS framing (1.A.2).

use crate::bits::{BitReader, BitWriter};

use super::CodecError;

/// The sample rates of the 4-bit sampling frequency index.
pub const SAMPLE_RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

/// Samples per AAC frame (AAC-LC).
pub const FRAME_SAMPLES: u32 = 1024;

/// The fields of an `AudioSpecificConfig` the stack uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// Audio object type (2 = AAC-LC, 5 = SBR / HE-AAC, 29 = PS).
    pub object_type: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Channel configuration (1 = mono, 2 = stereo, ...).
    pub channels: u8,
}

fn rate_index(rate: u32) -> Option<u32> {
    SAMPLE_RATES
        .iter()
        .position(|&r| r == rate)
        .map(|i| i as u32)
}

impl Config {
    /// An `AudioSpecificConfig` description.
    pub fn new(object_type: u8, sample_rate: u32, channels: u8) -> Config {
        Config {
            object_type,
            sample_rate,
            channels,
        }
    }

    /// Parses an `AudioSpecificConfig`.
    pub fn parse(b: &[u8]) -> Result<Config, CodecError> {
        let mut r = BitReader::new(b);
        const BAD: CodecError = CodecError::Invalid("AudioSpecificConfig");
        let mut ot = r.bits(5).ok_or(BAD)?;
        if ot == 31 {
            ot = 32 + r.bits(6).ok_or(BAD)?;
        }
        let idx = r.bits(4).ok_or(BAD)?;
        let rate = if idx == 15 {
            r.bits(24).ok_or(BAD)?
        } else {
            *SAMPLE_RATES.get(idx as usize).ok_or(BAD)?
        };
        let ch = r.bits(4).ok_or(BAD)?;
        Ok(Config {
            object_type: ot.min(255) as u8,
            sample_rate: rate,
            channels: ch as u8,
        })
    }

    /// Encodes a two-byte (or longer, for unusual rates) `AudioSpecificConfig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BitWriter::default();
        if self.object_type >= 31 {
            w.put(31, 5);
            w.put(u32::from(self.object_type) - 32, 6);
        } else {
            w.put(u32::from(self.object_type), 5);
        }
        match rate_index(self.sample_rate) {
            Some(i) => w.put(i, 4),
            None => {
                w.put(15, 4);
                w.put(self.sample_rate, 24);
            }
        }
        w.put(u32::from(self.channels), 4);
        w.put(0, 3); // GASpecificConfig: frameLengthFlag, dependsOnCoreCoder, extensionFlag
        w.finish()
    }

    /// An ADTS header for a frame of `payload_len` bytes (MPEG-4, no CRC).
    pub fn adts_header(&self, payload_len: usize) -> [u8; 7] {
        let profile = u32::from(self.object_type.clamp(1, 4) - 1);
        let idx = rate_index(self.sample_rate).unwrap_or(4);
        let len = (payload_len + 7) as u32;
        let ch = u32::from(self.channels & 7);
        [
            0xff,
            0xf1,
            ((profile << 6) | (idx << 2) | (ch >> 2)) as u8,
            (((ch & 3) << 6) | (len >> 11)) as u8,
            ((len >> 3) & 0xff) as u8,
            (((len & 7) << 5) | 0x1f) as u8,
            0xfc,
        ]
    }
}

/// One frame found in an ADTS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdtsFrame<'a> {
    /// The configuration the header describes.
    pub config: Config,
    /// The raw access unit (header removed).
    pub payload: &'a [u8],
}

/// Splits an ADTS byte stream into frames. Returns the frames and the number of bytes used;
/// a partial frame at the end is left for the next call.
pub fn split_adts(data: &[u8]) -> Result<(Vec<AdtsFrame<'_>>, usize), CodecError> {
    let mut out = Vec::new();
    let mut p = 0;
    while data.len() - p >= 7 {
        let h = &data[p..];
        if h[0] != 0xff || h[1] & 0xf0 != 0xf0 {
            return Err(CodecError::Invalid("ADTS sync word"));
        }
        let protection_absent = h[1] & 1 == 1;
        let profile = (h[2] >> 6) + 1;
        let idx = usize::from((h[2] >> 2) & 0xf);
        let ch = ((h[2] & 1) << 2) | (h[3] >> 6);
        let len = (usize::from(h[3] & 3) << 11) | (usize::from(h[4]) << 3) | usize::from(h[5] >> 5);
        let hlen = if protection_absent { 7 } else { 9 };
        if len < hlen {
            return Err(CodecError::Invalid("ADTS frame length"));
        }
        if len > h.len() {
            break;
        }
        let rate = *SAMPLE_RATES
            .get(idx)
            .ok_or(CodecError::Invalid("ADTS sampling index"))?;
        out.push(AdtsFrame {
            config: Config::new(profile, rate, ch),
            payload: &h[hlen..len],
        });
        p += len;
    }
    Ok((out, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_adts() {
        let c = Config::parse(&[0x12, 0x10]).unwrap();
        assert_eq!(c, Config::new(2, 44100, 2));
        assert_eq!(c.encode(), vec![0x12, 0x10]);
        let odd = Config::new(2, 12345, 1);
        assert_eq!(Config::parse(&odd.encode()).unwrap(), odd);
        let ext = Config::new(42, 48000, 2);
        assert_eq!(Config::parse(&ext.encode()).unwrap(), ext);
        assert!(Config::parse(&[0x12]).is_err());

        let mut stream = Vec::new();
        for n in [10usize, 300] {
            stream.extend_from_slice(&c.adts_header(n));
            stream.extend(std::iter::repeat_n(7u8, n));
        }
        stream.extend_from_slice(&c.adts_header(5)[..4]);
        let (frames, used) = split_adts(&stream).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].payload.len(), 300);
        assert_eq!(frames[0].config, c);
        assert_eq!(used, 7 + 10 + 7 + 300);
        assert!(split_adts(&[0, 1, 2, 3, 4, 5, 6, 7]).is_err());
    }
}
