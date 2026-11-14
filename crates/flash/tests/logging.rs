//! Structured logs through the `log` facade (a logger is process-global: one test binary).
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

use flash::{Config, Conn, Engine, Handler, Listener, fn_acceptor};
use log::kv::{Key, Value, VisitSource};

/// One captured record: level, target, message and key-values rendered as strings.
#[derive(Debug, Clone)]
struct Rec {
    level: log::Level,
    target: String,
    msg: String,
    kv: Vec<(String, String)>,
}

static RECORDS: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

struct Capture;

struct Kv<'a>(&'a mut Vec<(String, String)>);
impl<'kvs> VisitSource<'kvs> for Kv<'_> {
    fn visit_pair(&mut self, k: Key<'kvs>, v: Value<'kvs>) -> Result<(), log::kv::Error> {
        self.0.push((k.to_string(), v.to_string()));
        Ok(())
    }
}

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        let mut kv = Vec::new();
        let _ = r.key_values().visit(&mut Kv(&mut kv));
        RECORDS.lock().unwrap().push(Rec {
            level: r.level(),
            target: r.target().to_owned(),
            msg: r.args().to_string(),
            kv,
        });
    }
    fn flush(&self) {}
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
    log::set_logger(&Capture).unwrap();
    let e = Engine::builder()
        .config(Config {
            slow_callback_threshold: Some(Duration::from_millis(5)),
            shutdown_timeout: Duration::from_millis(300),
            // The engine sets the global level from the config.
            log_level: Some(log::LevelFilter::Trace),
            ..Config::default()
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Sleepy>| Sleepy)),
        )
        .build()
        .unwrap();
    assert_eq!(log::max_level(), log::LevelFilter::Trace);
    e.start().unwrap();
    let started = find(|r| r.msg == "engine started").expect("lifecycle record");
    assert_eq!(started.level, log::Level::Info);
    assert_eq!(started.target, "flash");

    let mut c = TcpStream::connect(e.local_addrs()[0]).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"x").unwrap();
    let mut b = [0u8; 1];
    c.read_exact(&mut b).unwrap();

    // No slow hook: the report goes to the logger, with structured fields.
    let slow = find(|r| r.msg.starts_with("slow callback")).expect("slow callback record");
    assert_eq!(slow.level, log::Level::Warn);
    assert_eq!(kv(&slow, "kind"), Some("on_data"));
    assert!(kv(&slow, "elapsed_us").unwrap().parse::<u64>().unwrap() >= 15_000);
    let opened = find(|r| r.msg == "connection opened").expect("trace record");
    assert_eq!(
        kv(&opened, "peer"),
        Some(c.local_addr().unwrap().to_string().as_str())
    );

    // Reload through the engine: logged, and the level changes globally.
    let mut cfg = Config {
        log_level: Some(log::LevelFilter::Info),
        ..Config::default()
    };
    cfg.idle_timeout = Some(Duration::from_secs(60));
    let rep = e.reload(&cfg);
    assert!(rep.applied.contains(&"log_level") && rep.applied.contains(&"idle_timeout"));
    assert_eq!(log::max_level(), log::LevelFilter::Info);
    assert!(find(|r| r.msg == "configuration reloaded").is_some());

    drop(c);
    e.shutdown();
    e.wait();
    assert!(find(|r| r.msg == "engine shutting down").is_some());
    // Trace records are filtered out now.
    assert!(find(|r| r.msg == "connection closed").is_none());
}
