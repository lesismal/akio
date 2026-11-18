//! A WHIP/WHEP server with WebRTC media (cargo feature `webrtc`), with RTMP and HTTP-FLV on
//! the same hub, for trying it out and for the interop checks of
//! `tools/interop/webrtc/media.sh`.
//!
//! ```text
//! cargo run -p only-media --features webrtc --example whip-server -- \
//!     127.0.0.1:8189 127.0.0.1:8080 127.0.0.1:1935
//! ffmpeg -re -i in.mp4 -c:v libx264 -bf 0 -c:a libopus -f whip http://127.0.0.1:8080/whip/live/s
//! curl http://127.0.0.1:8080/streams          # path, tracks, packets
//! ffprobe rtmp://127.0.0.1:1935/live/s        # the WHIP stream over RTMP
//! ffprobe http://127.0.0.1:8080/live/s.flv    # and HTTP-FLV
//! ```
//!
//! WHEP players POST their offer to `http://127.0.0.1:8080/whep/live/s`; RTMP publishers'
//! streams (H.264 with Opus or G.711, AAC is not sent) play over WHEP too. The UDP address is
//! the host candidate of every answer: use an address the peers can reach. Set
//! `ONLY_MEDIA_SECS` to stop after that many seconds.

use std::{net::SocketAddr, sync::Arc, thread, time::Duration};

use only::{Engine, Listener};
use only_http::{Context, Router, serve};
use only_media::{
    Hub,
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
    let flv = MediaHttp::new().flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()));
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
                        format!(
                            "{} tracks={} packets={} subscribers={}",
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
    if let Some(secs) = std::env::var("ONLY_MEDIA_SECS")
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
