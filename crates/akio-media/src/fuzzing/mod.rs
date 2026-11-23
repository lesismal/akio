//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests in each module replay `fuzz/corpus/<target>` on stable.

pub mod fmp4;
pub mod hls;
pub mod mp4;
pub mod rtmp;
pub mod rtsp;
pub mod srt;
