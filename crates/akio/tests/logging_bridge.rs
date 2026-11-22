//! The `log` feature: with only a `log` crate logger installed (env_logger style), `akio`'s
//! records reach it with the same targets and key-values, and `Config::log_level` sets `log`'s
//! maximum level. The dev-dependency on akio-log turns the feature on for the tests.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Mutex,
    time::Duration,
};

use log::kv::{Key, Value, VisitSource};
use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

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

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

#[test]
fn records_reach_the_log_crate_logger() {
    log::set_logger(&Capture).unwrap();
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v.log_level = Some(log::LevelFilter::Trace.into());
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .unwrap();
    // `Config::log_level` set both facades' maximum level.
    assert_eq!(log::max_level(), log::LevelFilter::Trace);
    assert_eq!(akio::log::max_level(), akio::log::LevelFilter::Trace);
    e.start().unwrap();
    let started = find(|r| r.msg == "engine started").expect("lifecycle record");
    assert_eq!(
        (started.level, started.target.as_str()),
        (log::Level::Info, "akio")
    );

    let mut c = TcpStream::connect(e.local_addrs()[0]).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"x").unwrap();
    let mut b = [0u8; 1];
    c.read_exact(&mut b).unwrap();
    let opened = find(|r| r.msg == "connection opened").expect("trace record");
    assert_eq!(opened.level, log::Level::Trace);
    assert_eq!(
        kv(&opened, "peer"),
        Some(c.local_addr().unwrap().to_string().as_str())
    );
    assert!(kv(&opened, "conn_id").unwrap().parse::<u64>().is_ok());

    // The application lowers `log`'s level directly (as env_logger users do): only follows.
    log::set_max_level(log::LevelFilter::Info);
    assert!(!akio::log::log_enabled!(target: "akio", akio::log::Level::Debug));
    drop(c);
    e.shutdown();
    e.wait();
    assert!(find(|r| r.msg == "engine shutting down").is_some());
    assert!(find(|r| r.msg == "connection closed").is_none());
}
