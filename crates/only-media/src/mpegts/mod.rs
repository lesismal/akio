//! MPEG-TS (ISO/IEC 13818-1): a muxer from canonical packets ([`Muxer`], for HLS and SRT
//! playback) and a demuxer back to them ([`demux`], for SRT ingest).
//!
//! Codecs: H.264 (stream type 0x1b), H.265 (0x24), AAC in ADTS (0x0f), Opus (private data
//! with the `Opus` registration descriptor, ETSI TS 102 366 style framing as ffmpeg writes it)
//! and MP3 (0x03).

pub mod demux;
mod mux;

pub use mux::Muxer;

/// Size of a transport stream packet.
pub const PACKET_SIZE: usize = 188;
/// The PID of the program association table.
pub const PID_PAT: u16 = 0;
/// The PID the muxer gives the program map table.
pub const PID_PMT: u16 = 0x1000;
/// The first elementary stream PID the muxer assigns.
pub const PID_FIRST_ES: u16 = 0x100;

/// Stream type of H.264.
pub const STREAM_H264: u8 = 0x1b;
/// Stream type of H.265.
pub const STREAM_H265: u8 = 0x24;
/// Stream type of AAC with ADTS.
pub const STREAM_AAC: u8 = 0x0f;
/// Stream type of MPEG-1 audio (MP3).
pub const STREAM_MP3: u8 = 0x03;
/// Stream type of MPEG-2 audio.
pub const STREAM_MP2_AUDIO: u8 = 0x04;
/// Stream type of PES private data (Opus with its registration descriptor).
pub const STREAM_PRIVATE: u8 = 0x06;

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04c1_1db7
            } else {
                c << 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// The CRC-32/MPEG-2 of `data`, as PSI sections carry it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = (c << 8) ^ CRC_TABLE[((c >> 24) as u8 ^ b) as usize];
    }
    c
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc() {
        assert_eq!(super::crc32(b"123456789"), 0x0376_e6e7);
    }
}
