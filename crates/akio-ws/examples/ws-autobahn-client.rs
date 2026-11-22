//! Echo client for the Autobahn|Testsuite fuzzing server (`wstest -m fuzzingserver`):
//! `cargo run --release -p akio-ws --example ws-autobahn-client -- ws://127.0.0.1:9001 akio-client`
//!
//! Runs every case (or those whose id starts with one of the comma-separated prefixes in
//! `CASES`, e.g. `CASES=12.,13.`), echoing each message, then asks the server to write its
//! reports. `PMD_NCT=1` offers `client_no_context_takeover`, which unlocks the
//! permessage-deflate cases where the server asks for it.

use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use akio::Engine;
use akio_ws::{
    Message, WsConfig, WsHandler, WsSender,
    client::{self, DialOptions},
    deflate::PmdOffer,
};

struct Echo(mpsc::Sender<()>);

impl WsHandler for Echo {
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        let _ = match msg {
            Message::Text(t) => ws.send_text(&t),
            Message::Binary(b) => ws.send_binary(&b),
        };
    }
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        let _ = self.0.send(());
    }
}

/// Collects text messages, signals the close.
struct Collect(mpsc::Sender<Option<String>>);

impl WsHandler for Collect {
    fn on_message(&mut self, _ws: &WsSender, msg: Message) {
        if let Message::Text(t) = msg {
            let _ = self.0.send(Some(t));
        }
    }
    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        let _ = self.0.send(None);
    }
}

/// Opens `url` and returns the first text message (empty when none came before the close).
fn fetch_text(engine: &Arc<Engine>, url: &str, opts: &DialOptions) -> String {
    let (tx, rx) = mpsc::channel();
    if let Err(e) = client::dial_blocking(engine, url, opts, Collect(tx)) {
        eprintln!("{url}: {e}");
        return String::new();
    }
    let mut first = None;
    while let Ok(Some(t)) = rx.recv_timeout(Duration::from_secs(30)) {
        first.get_or_insert(t);
    }
    first.unwrap_or_default()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "ws://127.0.0.1:9001".into());
    let agent = args.next().unwrap_or_else(|| "akio-client".into());
    let prefixes: Vec<String> = std::env::var("CASES")
        .map(|v| v.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    let nct = std::env::var("PMD_NCT").is_ok_and(|v| v == "1");

    let engine = Arc::new(Engine::builder().client_threads(1).build().expect("engine"));
    engine.start().expect("start");
    let mut opts = DialOptions::default();
    opts.config = {
        let mut v = WsConfig::default();
        v.max_message_bytes = 64 << 20;
        v
    };
    opts.pmd = {
        let mut v = PmdOffer::default();
        v.client_no_context_takeover = nct;
        v
    };
    opts.handshake_timeout = Duration::from_secs(30);
    let count: usize = fetch_text(&engine, &format!("{base}/getCaseCount"), &opts)
        .trim()
        .parse()
        .expect("case count");
    println!("{count} cases");
    let t0 = Instant::now();
    let mut ran = 0;
    for case in 1..=count {
        if !prefixes.is_empty() {
            let info = fetch_text(&engine, &format!("{base}/getCaseInfo?case={case}"), &opts);
            // {"id": "12.1.1", "description": ...}
            let id = info
                .split("\"id\"")
                .nth(1)
                .and_then(|r| r.split('"').nth(1))
                .unwrap_or("");
            if !prefixes.iter().any(|p| id.starts_with(p.as_str())) {
                continue;
            }
        }
        let (tx, rx) = mpsc::channel();
        let url = format!("{base}/runCase?case={case}&agent={agent}");
        match client::dial_blocking(&engine, &url, &opts, Echo(tx)) {
            Ok(_) => {
                if rx.recv_timeout(Duration::from_secs(120)).is_err() {
                    eprintln!("case {case}: no close within 120 s");
                }
            }
            Err(e) => eprintln!("case {case}: {e}"),
        }
        ran += 1;
    }
    println!("ran {ran} cases in {:.1} s", t0.elapsed().as_secs_f64());
    fetch_text(
        &engine,
        &format!("{base}/updateReports?agent={agent}"),
        &opts,
    );
    engine.shutdown();
    engine.wait();
}
