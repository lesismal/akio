//! Companion of the book's "Streaming media" chapter: one hub with an RTMP server and the HTTP
//! playback formats (HTTP-FLV, WS-FLV, HLS with LL-HLS parts) in front of it.
//!
//! `cargo run -p only-media --example guide-media` serves until killed (set
//! `ONLY_MEDIA_SECS` to stop after that many seconds), then try
//!
//! ```text
//! ffmpeg -re -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine \
//!     -c:v libx264 -g 50 -c:a aac -f flv rtmp://127.0.0.1:1935/live/cam
//! ffprobe rtmp://127.0.0.1:1935/live/cam
//! ffprobe http://127.0.0.1:8080/live/cam.flv
//! ffplay http://127.0.0.1:8080/live/cam/index.m3u8
//! ```

use std::{sync::Arc, thread, time::Duration};

use only::{Engine, Listener};
use only_http::{Router, serve};
use only_media::{
    Hub, HubConfig, PeerInfo, Sink, SubscribeOptions, Tracks,
    av::Packet,
    hls::{AudioRendition, Hls, HlsConfig, Multivariant, Variant},
    http::MediaHttp,
    httpflv::{HttpFlv, HttpFlvConfig},
    rtmp::{RtmpConfig, RtmpServer},
};

// ANCHOR: sink
/// A sink of your own: count what a stream carries (a recorder, a relay or a transcoder
/// hook would look the same). Callbacks run on the publisher's I/O thread: never block.
struct Counter {
    path: String,
    packets: u64,
}

impl Sink for Counter {
    fn on_tracks(&mut self, tracks: &Tracks) {
        let codecs: Vec<String> = tracks.iter().map(|t| t.codec.to_string()).collect();
        println!("{}: tracks {codecs:?}", self.path);
    }

    fn on_packet(&mut self, _pkt: &Arc<Packet>) {
        self.packets += 1;
    }
}
// ANCHOR_END: sink

fn main() -> std::io::Result<()> {
    // ANCHOR: hub
    let mut cfg = HubConfig::default();
    cfg.gop_cache_bytes = 8 << 20; // per stream; 0 disables the fast-start cache
    // One authorization hook for every ingest: RTMP here, RTSP/SRT/WHIP elsewhere.
    cfg.on_publish = Some(Arc::new(|path: &str, info: &PeerInfo| {
        if info.query.contains("token=secret") || path.starts_with("live/") {
            Ok(())
        } else {
            Err("bad token".to_owned())
        }
    }));
    let hub = Hub::new(cfg);
    // ANCHOR_END: hub

    // ANCHOR: rtmp
    let mut rtmp_cfg = RtmpConfig::default();
    rtmp_cfg.play_wait = Some(Duration::from_secs(10)); // players survive a republish
    let rtmp = RtmpServer::new(hub.clone(), rtmp_cfg);
    // ANCHOR_END: rtmp

    // ANCHOR: http
    let mut hls_cfg = HlsConfig::default();
    hls_cfg.target_duration = Duration::from_secs(2);
    hls_cfg.part_duration = Some(Duration::from_millis(500)); // LL-HLS parts
    let hls = Hls::new(hub.clone(), hls_cfg);
    // ANCHOR: multivariant
    // Renditions published as separate streams, tied together at /live/show.m3u8.
    let mut show = Multivariant::new();
    for (path, bps) in [("live/show_720", None), ("live/show_360", Some(800_000))] {
        let mut v = Variant::new(path);
        v.bandwidth = bps; // None: measured from the segments
        v.audio_group = Some("aud".into());
        show.variants.push(v);
    }
    let mut english = AudioRendition::new("aud", "English", "live/show_en");
    english.language = Some("en".into());
    english.default = true;
    show.audio.push(english);
    hls.add_multivariant("live/show", show);
    // ANCHOR_END: multivariant
    let media = MediaHttp::new()
        .flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()))
        .hls(hls);
    // GET /live/cam.flv (HTTP-FLV, or WS-FLV on a WebSocket upgrade), /live/cam/index.m3u8 (HLS)
    let app = Router::new()
        .get("/streams", {
            let hub = hub.clone();
            move |ctx: &mut only_http::Context| {
                let list: Vec<String> = hub
                    .streams()
                    .iter()
                    .map(|s| {
                        format!(
                            "{} subscribers={} packets={}",
                            s.path, s.subscribers, s.packets_in
                        )
                    })
                    .collect();
                ctx.text(200, list.join("\n"));
            }
        })
        .get("/*path", media);
    // ANCHOR_END: http

    // ANCHOR: engine
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:1935".parse().expect("addr")).serve(rtmp))
            .listen(Listener::tcp("127.0.0.1:8080".parse().expect("addr")).serve(serve(app)))
            .build()?,
    );
    engine.start()?;
    // ANCHOR_END: engine
    println!(
        "rtmp://127.0.0.1:1935/live/<name>, http://127.0.0.1:8080/live/<name>.flv | /index.m3u8"
    );

    // ANCHOR: subscribe
    // Watch a stream from the application: the subscription waits for the publisher and is
    // closed when dropped.
    let sub = hub
        .subscribe(
            "live/cam",
            Counter {
                path: "live/cam".into(),
                packets: 0,
            },
            SubscribeOptions::default().wait(Duration::from_secs(3600)),
        )
        .expect("subscribe");
    // ANCHOR_END: subscribe

    let secs = std::env::var("ONLY_MEDIA_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    if let Some(secs) = secs {
        let e = engine.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            e.shutdown();
        });
    }
    engine.wait();
    drop(sub);
    Ok(())
}
