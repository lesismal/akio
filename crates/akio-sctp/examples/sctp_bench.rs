//! In-memory data channel throughput: two associations wired back to back (no loss, no DTLS),
//! the sender keeping every channel's buffered amount near 1 MiB. Prints MB/s of delivered
//! payload per scenario; used for before/after comparisons of the SCTP data path.
//!
//!   cargo run --release -p akio-sctp --example sctp_bench [MB per scenario, default 200] [data]
//!
//! `data`: DATA chunks (no I-DATA, as with a peer that does not offer it).

use std::time::{Duration, Instant};

use akio_sctp::{Association, ChannelOptions, Config, Event};

fn run(name: &str, total: usize, msg: usize, channels: usize, ordered: bool, idata: bool) {
    let start = Instant::now();
    let mut now = start;
    let cfg = |client| Config::new(client).with_message_interleaving(idata);
    let mut a = Association::new(cfg(true), now);
    let mut b = Association::new(cfg(false), now);
    a.connect(now);
    let ids: Vec<u16> = (0..channels)
        .map(|i| {
            a.open_channel(
                now,
                ChannelOptions::new(&format!("c{i}")).with_ordered(ordered),
            )
            .expect("open")
        })
        .collect();
    let payload = vec![0x5a; msg];
    let mut queued = 0usize;
    let mut received = 0usize;
    let mut packets = 0u64;
    let wall = Instant::now();
    while received < total {
        for &c in &ids {
            while queued < total && a.buffered_amount(c) < 1 << 20 {
                if !a.send(now, c, &payload, true).expect("send") {
                    break;
                }
                queued += msg;
            }
        }
        let mut idle = true;
        while let Some(p) = a.poll_transmit(now) {
            b.handle_packet(now, &p);
            packets += 1;
            idle = false;
        }
        while let Some(p) = b.poll_transmit(now) {
            a.handle_packet(now, &p);
            idle = false;
        }
        while let Some(e) = b.poll_event() {
            if let Event::ChannelData { data, .. } = e {
                received += data.len();
            }
        }
        while a.poll_event().is_some() {}
        if idle {
            now += Duration::from_millis(5);
            a.handle_timeout(now);
            b.handle_timeout(now);
        }
    }
    let secs = wall.elapsed().as_secs_f64();
    println!(
        "{name:<28} {:>9.1} MB/s  ({} packets, {:.3} s)",
        received as f64 / secs / 1e6,
        packets,
        secs
    );
}

fn main() {
    let mb: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let idata = std::env::args().nth(2).as_deref() != Some("data");
    let total = mb << 20;
    run(
        "1 channel, 64 KiB messages",
        total,
        64 << 10,
        1,
        true,
        idata,
    );
    run(
        "1 channel, 1 KiB messages",
        total / 4,
        1 << 10,
        1,
        true,
        idata,
    );
    run("1 unordered, 16 KiB", total, 16 << 10, 1, false, idata);
    run(
        "4 channels, 64 KiB messages",
        total,
        64 << 10,
        4,
        true,
        idata,
    );
}
