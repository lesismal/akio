//! Structured logs through the `akio-log` facade (`akio::log`; a logger is process-global: one
//! test binary).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Mutex,
    thread,
    time::Duration,
};

use akio::log::{Level, LevelFilter, Logger, Metadata, Record};
use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

/// One captured record: level, target, message and key-values rendered as strings.
#[derive(Debug, Clone)]
struct Rec {
    level: Level,
    target: String,
    msg: String,
    kv: Vec<(String, String)>,
}

static RECORDS: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

struct Capture;

impl Logger for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &Record<'_>) {
        RECORDS.lock().unwrap().push(Rec {
            level: r.level(),
            target: r.target().to_owned(),
            msg: r.args().to_string(),
            kv: r
                .key_values()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect(),
        });
    }
}

fn find(f: impl Fn(&Rec) -> bool) -> Option<Rec> {
    RECORDS.lock().unwrap().iter().find(|r| f(r)).cloned()
}

fn kv<'a>(r: &'a Rec, k: &str) -> Option<&'a str> {
    r.kv.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

struct Sleepy;
impl Handler for Sleepy {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        thread::sleep(Duration::from_millis(20));
        let _ = c.send(data);
    }
}

#[test]
fn lifecycle_slow_callbacks_and_connections_are_logged_with_key_values() {
    akio::log::set_logger(&Capture).unwrap();
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.slow_callback_threshold = Some(Duration::from_millis(5));
            v.shutdown_timeout = Duration::from_millis(300);
            v.log_level = Some(LevelFilter::Trace);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Sleepy>| Sleepy)),
        )
        .build()
        .unwrap();
    assert_eq!(akio::log::max_level(), LevelFilter::Trace);
    e.start().unwrap();
    let started = find(|r| r.msg == "engine started").expect("lifecycle record");
    assert_eq!(started.level, Level::Info);
    assert_eq!(started.target, "akio");
    assert!(
        kv(&started, "listeners")
            .unwrap()
            .starts_with("[127.0.0.1:")
    );

    let mut c = TcpStream::connect(e.local_addrs()[0]).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"x").unwrap();
    let mut b = [0u8; 1];
    c.read_exact(&mut b).unwrap();

    // No slow hook: the report goes to the logger, with structured fields.
    let slow = find(|r| r.msg.starts_with("slow callback")).expect("slow callback record");
    assert_eq!(slow.level, Level::Warn);
    assert_eq!(kv(&slow, "kind"), Some("on_data"));
    assert!(kv(&slow, "elapsed_us").unwrap().parse::<u64>().unwrap() >= 15_000);
    let opened = find(|r| r.msg == "connection opened").expect("trace record");
    assert_eq!(
        kv(&opened, "peer"),
        Some(c.local_addr().unwrap().to_string().as_str())
    );
    assert_eq!(kv(&opened, "dialed"), Some("false"));

    // Reload through the engine: logged, and the level changes globally.
    let mut cfg = Config::default();
    cfg.log_level = Some(LevelFilter::Info);
    cfg.idle_timeout = Some(Duration::from_secs(60));
    let rep = e.reload(&cfg);
    assert!(rep.applied.contains(&"log_level") && rep.applied.contains(&"idle_timeout"));
    assert_eq!(akio::log::max_level(), LevelFilter::Info);
    assert!(find(|r| r.msg == "configuration reloaded").is_some());

    drop(c);
    e.shutdown();
    e.wait();
    assert!(find(|r| r.msg == "engine shutting down").is_some());
    // Trace records are filtered out now.
    assert!(find(|r| r.msg == "connection closed").is_none());
}
