//! Companion of the book's "SRT" chapter: an SRT server in front of a hub, a caller publishing
//! MPEG-TS into it, a player reading it back, and a relay pulling it into another path.
//!
//! `cargo run -p only-media --example guide-media-srt` runs the demo on loopback and exits;
//! `cargo run -p only-media --example guide-media-srt -- serve 0.0.0.0:9000` just serves, for
//! ffmpeg:
//!
//! ```text
//! ffmpeg -re -f lavfi -i testsrc -f lavfi -i sine -c:v libx264 -c:a aac -f mpegts \
//!     'srt://127.0.0.1:9000?streamid=#!::r=live/s,m=publish'
//! ffprobe 'srt://127.0.0.1:9000?streamid=#!::r=live/s,m=request'
//! ```

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use only::{Engine, Listener};
use only_media::{
    Hub,
    srt::{self, Config, RejectReason, SrtConfig, SrtHandler, SrtServer},
};

// ANCHOR: player
/// What a raw caller session receives: here the MPEG-TS bytes of the stream it plays.
struct Player {
    bytes: Arc<AtomicUsize>,
}

impl SrtHandler for Player {
    fn on_data(&mut self, data: Vec<u8>) {
        self.bytes.fetch_add(data.len(), Ordering::Relaxed);
    }
    fn on_close(&mut self, err: Option<srt::SrtError>) {
        println!("player closed: {err:?}");
    }
}
// ANCHOR_END: player

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let serve = args.get(1).is_some_and(|a| a == "serve");
    let addr = args.get(2).map_or("127.0.0.1:0", String::as_str);

    // ANCHOR: server
    let hub = Hub::default();
    let mut cfg = SrtConfig::default()
        .latency(Duration::from_millis(200))
        .play_wait(Duration::from_secs(10)); // players may connect before the publisher
    // Authorize by stream ID (`#!::r=live/s,m=publish,u=alice` or `live/s?token=...`).
    cfg.on_connect = Some(Arc::new(|req: &srt::Request, id: &srt::StreamId| {
        if id.resource.starts_with("live/") {
            Ok(())
        } else {
            println!("refusing {} from {}", id.resource, req.remote);
            Err(RejectReason::FORBIDDEN)
        }
    }));
    let server = SrtServer::new(hub.clone(), cfg);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::udp(addr.parse().expect("address")).serve(server.clone()))
            .udp_client_threads(1) // for the callers below (dial, push, pull)
            .build()?,
    );
    engine.start()?;
    let addr = engine.local_addrs()[0];
    println!("SRT on {addr}");
    // ANCHOR_END: server
    if serve {
        engine.wait();
        return Ok(());
    }

    // ANCHOR: publish
    // A caller publishing MPEG-TS: what ffmpeg or OBS do with `streamid=#!::r=live/s,m=publish`.
    let publisher = srt::dial(
        &engine,
        addr,
        Config::default().stream_id("#!::r=live/s,m=publish"),
        Player {
            bytes: Arc::default(),
        },
    )
    .expect("dial");
    while !publisher.is_connected() {
        std::thread::sleep(Duration::from_millis(5));
    }
    let ts = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/h264_aac.ts"))?;
    for (i, chunk) in ts.chunks(srt::TS_PAYLOAD_SIZE).enumerate() {
        publisher.send(chunk).expect("send");
        if i % 4 == 3 {
            std::thread::sleep(Duration::from_millis(20)); // roughly real time
        }
    }
    // ANCHOR_END: publish

    // ANCHOR: play
    let bytes = Arc::new(AtomicUsize::new(0));
    let player = srt::dial(
        &engine,
        addr,
        Config::default().stream_id("live/s"), // plain stream IDs default to m=request
        Player {
            bytes: bytes.clone(),
        },
    )
    .expect("dial");
    // ANCHOR_END: play

    // ANCHOR: relay
    // Pull live/s back from the server (any SRT listener works) into another hub path.
    let relay_hub = Hub::default();
    let relay = srt::pull(
        &engine,
        addr,
        Config::default().stream_id("#!::r=live/s,m=request"),
        &relay_hub,
        "mirror/s",
    )
    .expect("pull");
    // ANCHOR_END: relay

    std::thread::sleep(Duration::from_millis(800));
    if let Some(info) = hub.stream_info("live/s") {
        println!(
            "live/s: {} tracks, {} packets in, {} subscribers",
            info.tracks.len(),
            info.packets_in,
            info.subscribers
        );
    }
    println!(
        "player got {} bytes; relay live: {}; server connections: {}",
        bytes.load(Ordering::Relaxed),
        relay_hub
            .stream_info("mirror/s")
            .is_some_and(|s| s.publishing),
        server.connections()
    );
    println!("publisher stats: {:?}", publisher.stats());
    relay.close();
    player.close();
    publisher.close();
    Ok(())
}
