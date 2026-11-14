//! flash-http served by several worker processes.
//!
//! `cargo run --release -p flash-prefork --example prefork-http`, then
//! `curl localhost:8080/` a few times (the answering pid changes), `kill -HUP <supervisor pid>`
//! to reload the workers, `kill <supervisor pid>` or Ctrl-C to drain and stop them.
//! `PREFORK_INHERIT=1` serves an inherited listener instead of `SO_REUSEPORT`
//! (the default on macOS).

use std::time::Duration;

use flash::{Config, Engine};
use flash_http::{Context, Router, serve};
use flash_prefork::{CpuPinning, ListenMode, Prefork, Worker};

// ANCHOR: worker
/// What every worker runs: an ordinary flash-http engine on the listener the supervisor
/// prepared, served until the supervisor asks this worker to stop.
fn worker(w: Worker) -> std::io::Result<()> {
    let (index, generation) = (w.index(), w.generation());
    let app = Router::new().get("/", move |ctx: &mut Context| {
        let pid = std::process::id();
        ctx.text(
            200,
            format!("worker {index} (generation {generation}, pid {pid})\n"),
        );
    });
    let mut cfg = Config::default();
    // Drain in-flight requests for up to 5 s, below the supervisor's shutdown timeout.
    cfg.shutdown_timeout = Duration::from_secs(5);
    let engine = Engine::builder()
        .config(cfg)
        .listen(w.listener(0)?.threads(2).serve(serve(app)))
        .build()?;
    w.serve(&engine)
}
// ANCHOR_END: worker

fn main() -> std::io::Result<()> {
    // ANCHOR: supervisor
    let mode = if std::env::var_os("PREFORK_INHERIT").is_some() {
        ListenMode::Inherit
    } else {
        ListenMode::Auto
    };
    if !flash_prefork::is_worker() {
        println!("supervisor pid {}", std::process::id());
    }
    Prefork::new()
        .workers(4)
        .listen("127.0.0.1:8080".parse().expect("address"))
        .mode(mode)
        .pin_cpus(CpuPinning::None)
        .shutdown_timeout(Duration::from_secs(10))
        .restart_backoff(Duration::from_millis(100), Duration::from_secs(5))
        .run(worker)
    // ANCHOR_END: supervisor
}
