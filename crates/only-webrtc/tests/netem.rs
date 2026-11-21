//! FEC and pacing between two `Endpoint`s over a loopback interface that `tc netem` makes lossy
//! (ADR-068). Opt-in: `ONLY_NETEM_TEST=1` with the loss already set up, for example in a
//! container with `NET_ADMIN`:
//!
//! ```text
//! tc qdisc add dev lo root netem loss 5%
//! ONLY_NETEM_TEST=1 cargo test --release -p only-webrtc --test netem -- --nocapture
//! ```
//!
//! VP8 frames of three packets go one way with NACK removed from the SDP, so FEC is the only
//! repair: without FEC about one frame in seven loses a packet; with ULPFEC or FlexFEC (held at
//! a factor of 128) most come back whole.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{
    Codec, Direction, Endpoint, FecMechanism, Frequency, MediaData, MediaKind, MediaTime, Peer,
    PeerHandler, RtcConfig,
};

const FRAMES: u64 = 300;
const FRAME: usize = 3000;

struct Count {
    whole: Arc<AtomicU64>,
    up: Arc<AtomicBool>,
}

impl PeerHandler for Count {
    fn on_connected(&mut self, _p: &Peer) {
        self.up.store(true, Ordering::Release);
    }
    fn on_media_data(&mut self, _p: &Peer, d: &MediaData) {
        if d.data.len() == FRAME && d.data[2..] == frame(0)[2..] {
            self.whole.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn frame(i: u64) -> Vec<u8> {
    let mut f: Vec<u8> = (0..FRAME as u32).map(|k| (k * 7) as u8).collect();
    f[0] = if i == 0 { 0x10 } else { 0x11 };
    f[1] = i as u8;
    f
}

fn no_nack(s: &str) -> String {
    s.split("\r\n")
        .filter(|l| !(l.starts_with("a=rtcp-fb:") && l.ends_with(" nack")))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Whole frames out of [`FRAMES`] with `fec`, NACK removed; `bwe`: the estimator (and the
/// pacer) on.
fn run(fec: Option<FecMechanism>, bwe: bool) -> u64 {
    let e = Engine::builder().udp_client_threads(1).build().unwrap();
    e.start().unwrap();
    let cfg = move || {
        let c: RtcConfig = only_webrtc::rtc_config()
            .enable_fec(fec)
            .set_fec_protection(128, 128);
        if bwe { c.enable_bwe(Some(2_000_000)) } else { c }
    };
    let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .config(cfg);
    let (whole, up) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicBool::new(false)));
    let mut video = None;
    let (pa, offer) = a
        .create_offer(
            Count {
                whole: Arc::new(AtomicU64::new(0)),
                up: up.clone(),
            },
            |api| video = Some(api.add_media(MediaKind::Video, Direction::SendOnly, None, None)),
        )
        .unwrap();
    let (_pb, answer) = b
        .accept_offer(
            &no_nack(&offer),
            Count {
                whole: whole.clone(),
                up: Arc::new(AtomicBool::new(false)),
            },
        )
        .unwrap();
    pa.accept_answer(&no_nack(&answer)).unwrap();
    let t = Instant::now();
    while !up.load(Ordering::Acquire) {
        assert!(t.elapsed() < Duration::from_secs(20), "no connection");
        std::thread::sleep(Duration::from_millis(5));
    }
    let video = video.unwrap();
    let vp8 = pa.payload_type(video, Codec::Vp8).unwrap();
    for i in 0..FRAMES {
        let t = MediaTime::new(i * 3000, Frequency::NINETY_KHZ);
        pa.write_media(video, vp8, Instant::now(), t, &frame(i)).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(500));
    whole.load(Ordering::Relaxed)
}

#[test]
fn fec_repairs_netem_loss() {
    if std::env::var("ONLY_NETEM_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set ONLY_NETEM_TEST=1 with tc netem loss on lo");
        return;
    }
    let plain = run(None, false);
    let ulp = run(Some(FecMechanism::Ulpfec), false);
    let flex = run(Some(FecMechanism::FlexFec), false);
    let paced = run(Some(FecMechanism::FlexFec), true);
    println!(
        "whole frames of {FRAMES}: no FEC {plain}, ULPFEC {ulp}, FlexFEC {flex}, FlexFEC paced {paced}"
    );
    for (n, what) in [(ulp, "ULPFEC"), (flex, "FlexFEC"), (paced, "FlexFEC paced")] {
        assert!(n > plain + FRAMES / 20 && n >= FRAMES * 9 / 10, "{what}: {n} vs {plain}");
    }
}
