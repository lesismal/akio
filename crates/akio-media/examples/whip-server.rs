//! A WHIP/WHEP server with WebRTC media (cargo feature `webrtc`), with RTMP, HTTP-FLV and
//! fMP4 LL-HLS on the same hub, for trying it out and for the interop checks of
//! `tools/interop/webrtc/media.sh` and `tools/interop/media/browser.sh`.
//!
//! ```text
//! cargo run -p akio-media --features webrtc --example whip-server -- \
//!     127.0.0.1:8189 127.0.0.1:8080 127.0.0.1:1935
//! ffmpeg -re -i in.mp4 -c:v libx264 -bf 0 -c:a libopus -f whip http://127.0.0.1:8080/whip/live/s
//! curl http://127.0.0.1:8080/streams          # path, tracks, packets
//! ffprobe rtmp://127.0.0.1:1935/live/s        # the WHIP stream over RTMP
//! ffprobe http://127.0.0.1:8080/live/s.flv    # and HTTP-FLV
//! ffprobe http://127.0.0.1:8080/live/s/index.m3u8  # and fMP4 LL-HLS
//! ```
//!
//! `http://127.0.0.1:8080/live/abr.m3u8` is a multivariant playlist over the streams
//! `live/abr_hi` and `live/abr_lo` (publish both, with any codecs fMP4 carries).
//!
//! WHEP players POST their offer to `http://127.0.0.1:8080/whep/live/s`; RTMP publishers'
//! streams (H.264 with Opus or G.711, AAC is not sent) play over WHEP too. The UDP address is
//! the host candidate of every answer: use an address the peers can reach. Set
//! `AKIO_MEDIA_SECS` to stop after that many seconds, `AKIO_MEDIA_PART_MS` for the LL-HLS part
//! length (250 ms by default, 0 for plain HLS).

use std::{net::SocketAddr, sync::Arc, thread, time::Duration};

use akio::{Engine, Listener};
use akio_http::{Context, Router, serve};
use akio_media::{
    Hub,
    hls::{Hls, HlsConfig, Multivariant, SegmentFormat, Variant},
    http::MediaHttp,
    httpflv::{HttpFlv, HttpFlvConfig},
    rtmp::{RtmpConfig, RtmpServer},
    webrtc::{RtcMedia, RtcMediaConfig},
    whip::{WhipConfig, WhipServer},
};

fn arg(i: usize, default: &str) -> SocketAddr {
    std::env::args()
        .nth(i)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .expect("an address")
}

fn main() -> std::io::Result<()> {
    let udp = arg(1, "127.0.0.1:8189");
    let http = arg(2, "127.0.0.1:8080");
    let rtmp_addr = arg(3, "127.0.0.1:1935");

    let hub = Hub::default();
    let rtc = RtcMedia::rtc_server(vec![udp]);
    let media = RtcMedia::new(rtc.clone(), RtcMediaConfig::default());
    let whip = WhipServer::new(hub.clone(), Arc::new(media), WhipConfig::default());
    let mut hls_cfg = HlsConfig::default();
    hls_cfg.format = SegmentFormat::Fmp4;
    hls_cfg.target_duration = Duration::from_secs(1);
    // LL-HLS parts of AKIO_MEDIA_PART_MS milliseconds (250 by default, 0 for none).
    let part_ms = std::env::var("AKIO_MEDIA_PART_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(250);
    hls_cfg.part_duration = (part_ms > 0).then(|| Duration::from_millis(part_ms));
    hls_cfg.play_wait = Some(Duration::from_secs(10));
    let hls = Hls::new(hub.clone(), hls_cfg);
    let mut abr = Multivariant::new();
    abr.variants = vec![Variant::new("live/abr_hi"), Variant::new("live/abr_lo")];
    hls.add_multivariant("live/abr", abr);
    let flv = MediaHttp::new()
        .flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()))
        .hls(hls);
    let app = whip
        .routes(Router::new())
        .get("/streams", {
            let hub = hub.clone();
            move |ctx: &mut Context| {
                let list: Vec<String> = hub
                    .streams()
                    .iter()
                    .map(|s| {
                        let codecs: Vec<&str> = s.tracks.iter().map(|t| t.codec.name()).collect();
                        let size = s
                            .tracks
                            .iter()
                            .find(|t| t.is_video())
                            .map_or(String::new(), |t| format!(" size={}x{}", t.width, t.height));
                        format!(
                            "{} tracks={} packets={} subscribers={}{size}",
                            s.path,
                            codecs.join(","),
                            s.packets_in,
                            s.subscribers
                        )
                    })
                    .collect();
                ctx.text(200, list.join("\n"));
            }
        })
        .get("/*path", flv);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::udp(udp).serve(rtc))
            .listen(Listener::tcp(http).serve(serve(app)))
            .listen(Listener::tcp(rtmp_addr).serve(RtmpServer::new(hub, RtmpConfig::default())))
            .build()?,
    );
    engine.start()?;
    println!(
        "whip/whep on http://{http}/whip|whep/<path>, webrtc on udp {udp}, rtmp on {rtmp_addr}"
    );
    if let Some(secs) = std::env::var("AKIO_MEDIA_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        let e = engine.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            e.shutdown();
        });
    }
    engine.wait();
    whip.close_all();
    Ok(())
}
