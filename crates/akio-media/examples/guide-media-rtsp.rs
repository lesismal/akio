//! Companion of the book's "RTSP and WHIP/WHEP" chapter: an RTSP server (TCP and UDP) and
//! the WHIP/WHEP signalling endpoints in front of one hub.
//!
//! `cargo run -p akio-media --example guide-media-rtsp` serves until killed (set
//! `AKIO_RTSP_SECS` to stop after that many seconds), then try
//!
//! ```text
//! ffmpeg -re -f lavfi -i testsrc=size=640x360:rate=25 -c:v libx264 -bf 0 \
//!     -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam
//! ffprobe rtsp://127.0.0.1:8554/live/cam
//! ```

use std::{sync::Arc, thread, time::Duration};

use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{
    Hub, HubConfig, PeerInfo,
    rtsp::{RtspConfig, RtspServer},
    whip::{NoMedia, WhipConfig, WhipServer},
};

fn main() -> std::io::Result<()> {
    // ANCHOR: hub
    let mut cfg = HubConfig::default();
    // One authorization hook for every protocol: RTSP here, RTMP/SRT/WHIP elsewhere.
    cfg.on_publish = Some(Arc::new(|path: &str, info: &PeerInfo| {
        if path.starts_with("live/") {
            Ok(())
        } else {
            Err(format!("{} may not publish {path}", info.protocol))
        }
    }));
    let hub = Hub::new(cfg);
    // ANCHOR_END: hub

    // ANCHOR: rtsp
    let mut rtsp_cfg = RtspConfig::default();
    rtsp_cfg.play_wait = Some(Duration::from_secs(10)); // players survive a republish
    let rtsp = RtspServer::new(hub.clone(), rtsp_cfg);
    // RTP/AVP over UDP on 8000 (RTP) and 8001 (RTCP); TCP interleaved needs nothing extra.
    rtsp.listen_udp("127.0.0.1:8000".parse().expect("addr"))?;
    // ANCHOR_END: rtsp

    // ANCHOR: whip
    // WHIP ingest at POST /whip/<path>, WHEP playback at POST /whep/<path>. `NoMedia`
    // answers 501: plug in a WebRTC engine (an implementation of `WebRtcEngine`) to carry media.
    let whip = WhipServer::new(hub.clone(), Arc::new(NoMedia), WhipConfig::default());
    let app = whip.routes(Router::new());
    // ANCHOR_END: whip

    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:8554".parse().expect("addr")).serve(rtsp))
            .listen(Listener::tcp("127.0.0.1:8080".parse().expect("addr")).serve(serve(app)))
            .build()?,
    );
    engine.start()?;
    println!("rtsp://127.0.0.1:8554/live/<name>, WHIP/WHEP on http://127.0.0.1:8080");
    if let Some(secs) = std::env::var("AKIO_RTSP_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        let e = engine.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            e.shutdown();
        });
    }
    // ANCHOR: stats
    let h = hub;
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5));
            for s in h.streams() {
                println!(
                    "{}: publishing={} subscribers={} packets={}",
                    s.path, s.publishing, s.subscribers, s.packets_in
                );
            }
        }
    });
    // ANCHOR_END: stats
    engine.wait();
    Ok(())
}
