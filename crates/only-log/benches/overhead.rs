//! Cost of a disabled log statement (the hot-path case), only-log against the `log` crate.
//!
//! `cargo bench -p only-log --bench overhead` (add `--features log` for the bridge's check).
#![allow(missing_docs)]

use std::{hint::black_box, time::Instant};

const N: u64 = 200_000_000;

fn bench(name: &str, f: impl Fn(u64)) {
    for i in 0..N / 100 {
        f(i);
    }
    let t = Instant::now();
    for i in 0..N {
        f(black_box(i));
    }
    let ns = t.elapsed().as_secs_f64() * 1e9 / N as f64;
    println!("{name:<44} {ns:.3} ns/op");
}

struct Null;
impl only_log::Logger for Null {
    fn log(&self, r: &only_log::Record<'_>) {
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
    only_log::set_logger(&Null).unwrap();
    log::set_logger(&Null).unwrap();
    only_log::set_max_level(only_log::LevelFilter::Info);
    log::set_max_level(log::LevelFilter::Info);

    for _ in 0..2 {
        // Spans stay off (no tracer, maximum span level `Off`) while logging is on: the
        // statement costs one atomic load.
        bench("only-log trace! (disabled, 2 key-values)", |i| {
            only_log::trace!(target: "only", conn_id = i, dialed = false; "connection opened");
        });
        bench("log trace! (disabled, 2 key-values)", |i| {
            log::trace!(target: "only", conn_id = i, dialed = false; "connection opened");
        });
        bench("only-log log_enabled! (disabled)", |_| {
            black_box(only_log::log_enabled!(target: "only", only_log::Level::Trace));
        });
        bench("log log_enabled! (disabled)", |_| {
            black_box(log::log_enabled!(target: "only", log::Level::Trace));
        });
        bench("only-log info_span! (spans off, 2 fields)", |i| {
            black_box(only_log::info_span!(target: "only", "request", conn_id = i, dialed = false));
        });
        bench("only-log span::enabled (spans off)", |_| {
            black_box(only_log::span::enabled(only_log::Level::Info));
        });
        bench("only-log info! (enabled, null logger, 2 kvs)", |i| {
            only_log::info!(target: "only", conn_id = i, dialed = false; "connection opened");
        });
        bench("log info! (enabled, null logger, 2 kvs)", |i| {
            log::info!(target: "only", conn_id = i, dialed = false; "connection opened");
        });
    }
}
