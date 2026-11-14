#![forbid(unsafe_code)]
//! Streaming media on flash: RTMP, RTSP, SRT, FLV, HTTP-FLV, WS-FLV, HLS and WHIP/WHEP
//! signalling around one stream [`hub`].
//!
//! Every protocol converts what it receives into the canonical packets of [`av`] and muxes
//! from them, so one publisher plays over every other protocol.
#![warn(clippy::unwrap_used)]

pub mod amf;
pub mod av;
mod bits;
pub mod codec;
pub mod flv;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod hub;
pub mod mpegts;
pub mod rtmp;
pub mod rtp;
pub mod rtsp;
pub mod sdp;
pub mod srt;
mod timer;
pub mod whip;

pub use av::{Codec, Packet, Track, Tracks};
pub use hub::{
    Hub, HubConfig, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription,
};
