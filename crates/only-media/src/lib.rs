#![forbid(unsafe_code)]
//! Streaming media on `only`: RTMP, RTSP, SRT, FLV, HTTP-FLV, WS-FLV, HLS and WHIP/WHEP
//! signalling around one stream [`hub`].
//!
//! Every protocol converts what it receives into the canonical packets of [`av`] and muxes
//! from them, so one publisher plays over every other protocol.
//!
//! * [`hub`]: streams by path, one publisher and many subscribers, GOP cache, slow-player
//!   dropping ([`hub::Dropper`]), auth hooks, waiting for publishers, [`hub::Timeline`], stats.
//! * Ingest and egress: [`rtmp::RtmpServer`], [`rtsp::RtspServer`], [`srt::SrtServer`] (and
//!   the [`srt`] caller), [`httpflv::HttpFlv`] (HTTP-FLV and WS-FLV), [`hls::Hls`] (with LL-HLS),
//!   [`http::MediaHttp`] dispatching the HTTP formats, [`whip::WhipServer`] (signalling), and
//!   with the `webrtc` cargo feature `webrtc::RtcMedia` (WHIP/WHEP media over `only-webrtc`).
//! * Formats and codecs: [`flv`], [`mpegts`], [`rtp`], [`sdp`], [`amf`], [`codec`].
//!
//! Guide: [Streaming media](https://lesismal.github.io/only/en/protocols/media.html),
//! [RTSP and WHIP/WHEP](https://lesismal.github.io/only/en/protocols/media-rtsp.html),
//! [SRT](https://lesismal.github.io/only/en/protocols/media-srt.html)
//! (中文: [流媒体](https://lesismal.github.io/only/zh-CN/protocols/media.html)、
//! [RTSP 与 WHIP/WHEP](https://lesismal.github.io/only/zh-CN/protocols/media-rtsp.html)、
//! [SRT](https://lesismal.github.io/only/zh-CN/protocols/media-srt.html)).
#![warn(clippy::unwrap_used)]

pub mod amf;
pub mod av;
mod bits;
pub mod codec;
pub mod flv;
pub mod fmp4;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod hls;
pub mod http;
pub mod httpflv;
pub mod hub;
pub mod mpegts;
pub mod rtmp;
pub mod rtp;
pub mod rtsp;
pub mod sdp;
pub mod srt;
mod timer;
mod watch;
#[cfg(feature = "webrtc")]
pub mod webrtc;
pub mod whip;

pub use av::{Codec, Packet, Track, Tracks};
pub use hub::{
    Hub, HubConfig, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription,
};
