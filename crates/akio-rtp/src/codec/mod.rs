//! Payload formats: packetizers and depacketizers per codec, and frame assembly.
//!
//! - [`packetizer`] turns one media frame (an encoded sample) into RTP payloads, each at most
//!   `mtu` bytes, paired with the marker bit the caller puts in the RTP header.
//! - [`depacketizer`] turns RTP payloads back into frame bytes and classifies packets (frame
//!   start / end, keyframe).
//! - [`FrameAssembler`] reorders packets by extended sequence number and emits complete frames
//!   in order as soon as they are complete ("jitter-free": it never waits on time, only on
//!   its reorder capacity).
//!
//! | Codec | Format | Packetizer | Depacketizer output |
//! |---|---|---|---|
//! | Opus, PCMU, PCMA, G.722, other | RFC 7587 / RFC 3551 | one payload per frame, never split | the payload |
//! | VP8 | RFC 7741 | X=1, I=1, 15-bit PictureID, S=1 on the first packet | the VP8 frame |
//! | VP9 | RFC 9628 | non-flexible, I=1 15-bit PictureID, B/E, SS on keyframes | the VP9 frame (layer frames concatenated) |
//! | H.264 | RFC 6184 mode 1 | single NAL, STAP-A, FU-A; AUD/filler dropped | Annex-B, 4-byte start codes |
//! | H.265 | RFC 7798 | single NAL, AP (48), FU (49); no DONL | Annex-B, 4-byte start codes |
//! | AV1 | AV1 RTP spec | aggregation header Z/Y/W/N, OBU fragmentation | OBUs with `obu_has_size_field = 1` |
//!
//! An empty frame produces no payloads for every codec, and an `mtu` too small to carry the
//! codec's headers plus one byte of data produces no payloads (audio frames are never split, so
//! they ignore `mtu`).
//!
//! ```
//! use std::time::Instant;
//! use akio_rtp::codec::{CodecKind, FrameAssembler, packetizer};
//!
//! let frame = vec![0x10u8; 3000]; // a VP8 keyframe (P bit 0)
//! let mut assembler = FrameAssembler::new(CodecKind::Vp8, 30);
//! let now = Instant::now();
//! let packets = packetizer(CodecKind::Vp8).packetize(1200, &frame);
//! assert_eq!(packets.len(), 3);
//! // Delivered out of order: the frame comes out once it is complete.
//! for (seq, (payload, marker)) in packets.iter().enumerate().rev() {
//!     assembler.push(seq as u64, 90_000, *marker, payload, now);
//! }
//! let f = assembler.pop().unwrap();
//! assert!(f.keyframe && f.contiguous);
//! assert_eq!(f.data, frame);
//! ```

mod assembler;
mod audio;
mod av1;
mod h264;
mod h265;
mod vp8;
mod vp9;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzz;

#[cfg(test)]
mod tests;

use std::fmt;

pub use assembler::{Frame, FrameAssembler};
pub use audio::{PassthroughDepacketizer, PassthroughPacketizer};
pub use av1::{Av1Depacketizer, Av1Packetizer};
pub use h264::{H264Depacketizer, H264Packetizer};
pub use h265::{H265Depacketizer, H265Packetizer};
pub use vp8::{Vp8Depacketizer, Vp8Packetizer};
pub use vp9::{Vp9Depacketizer, Vp9Packetizer};

/// Largest frame the depacketizers and [`FrameAssembler`] build (4 MiB); bigger frames are
/// dropped.
pub const MAX_FRAME_SIZE: usize = 4 << 20;

/// The media codec of an RTP stream, which selects the payload format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodecKind {
    /// Opus (RFC 7587).
    Opus,
    /// G.711 mu-law (RFC 3551).
    Pcmu,
    /// G.711 A-law (RFC 3551).
    Pcma,
    /// G.722 (RFC 3551).
    G722,
    /// H.264 (RFC 6184, packetization-mode 1).
    H264,
    /// H.265 (RFC 7798).
    H265,
    /// VP8 (RFC 7741).
    Vp8,
    /// VP9 (RFC 9628).
    Vp9,
    /// AV1 (RTP Payload Format for AV1).
    Av1,
    /// Anything else: payloads pass through unchanged and every packet is one frame.
    Other,
}

impl CodecKind {
    /// Every kind, for iteration.
    pub const ALL: [CodecKind; 10] = [
        CodecKind::Opus,
        CodecKind::Pcmu,
        CodecKind::Pcma,
        CodecKind::G722,
        CodecKind::H264,
        CodecKind::H265,
        CodecKind::Vp8,
        CodecKind::Vp9,
        CodecKind::Av1,
        CodecKind::Other,
    ];

    /// Whether this is an audio codec (Opus, PCMU, PCMA, G.722).
    #[must_use]
    pub fn is_audio(self) -> bool {
        matches!(
            self,
            CodecKind::Opus | CodecKind::Pcmu | CodecKind::Pcma | CodecKind::G722
        )
    }

    /// Whether every RTP packet carries exactly one whole frame (audio and [`CodecKind::Other`]).
    #[must_use]
    pub fn is_single_packet(self) -> bool {
        self.is_audio() || self == CodecKind::Other
    }
}

/// A malformed or unsupported RTP payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The payload is shorter than its headers or a declared length.
    Truncated,
    /// A packet type this implementation does not handle (H.264 STAP-B/MTAP and reserved
    /// types, H.265 PACI and reserved types).
    UnsupportedType(u8),
    /// A header field has an invalid value.
    Malformed(&'static str),
    /// A continuation fragment arrived without the fragment that starts its unit.
    FragmentWithoutStart,
    /// The frame (or a fragmented unit) exceeds [`MAX_FRAME_SIZE`].
    FrameTooLarge,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Truncated => f.write_str("truncated RTP payload"),
            CodecError::UnsupportedType(t) => write!(f, "unsupported RTP payload packet type {t}"),
            CodecError::Malformed(what) => write!(f, "malformed RTP payload: {what}"),
            CodecError::FragmentWithoutStart => {
                f.write_str("continuation fragment without its start fragment")
            }
            CodecError::FrameTooLarge => f.write_str("frame exceeds the maximum frame size"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Splits frames into RTP payloads.
pub trait Packetizer: Send + fmt::Debug {
    /// RTP payloads for one frame, each at most `mtu` bytes (audio: exactly one payload, even
    /// if it exceeds `mtu`), paired with the marker bit for its RTP header: video sets it on
    /// the last payload of the frame, audio never sets it. Empty frames, and an `mtu` too small
    /// for the codec, give no payloads.
    fn packetize(&mut self, mtu: usize, frame: &[u8]) -> Vec<(Vec<u8>, bool)>;
}

/// Reassembles frames from RTP payloads and classifies packets.
pub trait Depacketizer: Send + fmt::Debug {
    /// Appends this packet's part of the frame to `out`. Packets of one frame are passed in
    /// sequence-number order; on error `out` may hold a partial write and the frame should be
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the payload is malformed or uses an unsupported packet type.
    fn depacketize(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError>;

    /// Whether this packet starts a partition that can begin a frame (VP8 S=1 and PID=0, VP9 B=1
    /// on the base spatial layer, H.264/H.265 a NAL unit start, AV1 Z=0, audio always).
    fn is_frame_start(&self, payload: &[u8]) -> bool;

    /// Whether this packet ends a frame (the RTP marker bit for video; always for audio).
    fn is_frame_end(&self, payload: &[u8], marker: bool) -> bool;

    /// Best effort: whether this packet carries the start of a keyframe (VP8/VP9 P=0, H.264
    /// IDR or SPS, H.265 IRAP/VPS/SPS, AV1 N=1 or a sequence header).
    fn is_keyframe(&self, payload: &[u8]) -> bool;

    /// Forgets any partially depacketized unit (a fragmented NAL unit or OBU).
    /// [`FrameAssembler`] calls it before each frame.
    fn reset(&mut self) {}
}

/// The packetizer for `kind`. VP8 and VP9 start their PictureID at a random value.
#[must_use]
pub fn packetizer(kind: CodecKind) -> Box<dyn Packetizer> {
    match kind {
        CodecKind::Vp8 => Box::new(Vp8Packetizer::new(random_picture_id())),
        CodecKind::Vp9 => Box::new(Vp9Packetizer::new(random_picture_id())),
        CodecKind::H264 => Box::new(H264Packetizer::new()),
        CodecKind::H265 => Box::new(H265Packetizer::new()),
        CodecKind::Av1 => Box::new(Av1Packetizer::new()),
        CodecKind::Opus
        | CodecKind::Pcmu
        | CodecKind::Pcma
        | CodecKind::G722
        | CodecKind::Other => Box::new(PassthroughPacketizer::new()),
    }
}

/// The depacketizer for `kind`.
#[must_use]
pub fn depacketizer(kind: CodecKind) -> Box<dyn Depacketizer> {
    match kind {
        CodecKind::Vp8 => Box::new(Vp8Depacketizer::new()),
        CodecKind::Vp9 => Box::new(Vp9Depacketizer::new()),
        CodecKind::H264 => Box::new(H264Depacketizer::new()),
        CodecKind::H265 => Box::new(H265Depacketizer::new()),
        CodecKind::Av1 => Box::new(Av1Depacketizer::new()),
        CodecKind::Opus
        | CodecKind::Pcmu
        | CodecKind::Pcma
        | CodecKind::G722
        | CodecKind::Other => Box::new(PassthroughDepacketizer::new()),
    }
}

/// A random 15-bit PictureID from the std hasher's per-process random keys.
fn random_picture_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0x5a);
    (h.finish() & 0x7fff) as u16
}
