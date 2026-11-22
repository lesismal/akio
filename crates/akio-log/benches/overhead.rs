//! Cost of a disabled log statement (the hot-path case), akio-log against the `log` crate.
//!
//! `cargo bench -p akio-log --bench overhead` (add `--features log` for the bridge's check).
//! The last lines are the per-record cost of a `Filter` with and without a `/regex` message
//! filter (ADR-047).
#![allow(missing_docs)]

use std::{hint::black_box, time::Instant};

const N: u64 = 200_000_000;

fn bench(name: &str, f: impl Fn(u64)) {
    bench_n(name, N, f);
}

fn bench_n(name: &str, n: u64, f: impl Fn(u64)) {
    for i in 0..n / 100 {
        f(i);
    }
    let t = Instant::now();
    for i in 0..n {
        f(black_box(i));
    }
    let ns = t.elapsed().as_secs_f64() * 1e9 / n as f64;
    println!("{name:<44} {ns:.3} ns/op");
}

struct Null;
impl akio_log::Logger for Null {
    fn log(&self, r: &akio_log::Record<'_>) {
        black_box(r);
    }
}
impl log::Log for Null {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        black_box(r);
    }
    fn flush(&self) {}
}

fn main() {
    akio_log::set_logger(&Null).unwrap();
    log::set_logger(&Null).unwrap();
    akio_log::set_max_level(akio_log::LevelFilter::Info);
    log::set_max_level(log::LevelFilter::Info);

    for _ in 0..2 {
        // Spans stay off (no tracer, maximum span level `Off`) while logging is on: the
        // statement costs one atomic load.
        bench("akio-log trace! (disabled, 2 key-values)", |i| {
            akio_log::trace!(target: "akio", conn_id = i, dialed = false; "connection opened");
        });
        bench("log trace! (disabled, 2 key-values)", |i| {
            log::trace!(target: "akio", conn_id = i, dialed = false; "connection opened");
        });
        bench("akio-log log_enabled! (disabled)", |_| {
            black_box(akio_log::log_enabled!(target: "akio", akio_log::Level::Trace));
        });
        bench("log log_enabled! (disabled)", |_| {
            black_box(log::log_enabled!(target: "akio", log::Level::Trace));
        });
        bench("akio-log info_span! (spans off, 2 fields)", |i| {
            black_box(akio_log::info_span!(target: "akio", "request", conn_id = i, dialed = false));
        });
        bench("akio-log span::enabled (spans off)", |_| {
            black_box(akio_log::span::enabled(akio_log::Level::Info));
        });
        bench("akio-log info! (enabled, null logger, 2 kvs)", |i| {
            akio_log::info!(target: "akio", conn_id = i, dialed = false; "connection opened");
        });
        bench("log info! (enabled, null logger, 2 kvs)", |i| {
            log::info!(target: "akio", conn_id = i, dialed = false; "connection opened");
        });
    }

    let plain: akio_log::Filter = "info,akio_http=debug".parse().unwrap();
    let regex: akio_log::Filter = "info,akio_http=debug/connection (reset|refused)"
        .parse()
        .unwrap();
    for _ in 0..2 {
        for (name, f) in [
            ("Filter::matches (no regex)", &plain),
            ("Filter::matches (/regex, 72-byte msg)", &regex),
        ] {
            bench_n(name, 5_000_000, |i| {
                let peer = "10.0.0.7:51234";
                let args = format_args!(
                    "conn {i} from {peer} closed after {}ms: timed out",
                    i % 1000
                );
                let rec = akio_log::Record::new(akio_log::Level::Info, "akio_http::server", args);
                black_box(f.matches(black_box(&rec)));
            });
        }
    }
}
