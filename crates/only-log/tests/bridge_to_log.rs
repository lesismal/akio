//! Feature `log`: with no only-log logger, records reach the `log` crate's logger.
#![allow(missing_docs, clippy::type_complexity)]
#![cfg(feature = "log")]

use std::sync::Mutex;

use log::kv::{Key, Value, VisitSource};
use only_log::{Level, LevelFilter};

static RECORDS: Mutex<Vec<(log::Level, String, String, Vec<(String, String)>)>> =
    Mutex::new(Vec::new());

struct Capture;
struct Kv<'a>(&'a mut Vec<(String, String)>);
impl<'kvs> VisitSource<'kvs> for Kv<'_> {
    fn visit_pair(&mut self, k: Key<'kvs>, v: Value<'kvs>) -> Result<(), log::kv::Error> {
        self.0.push((k.to_string(), v.to_string()));
        Ok(())
    }
}
impl log::Log for Capture {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.target() != "muted"
    }
    fn log(&self, r: &log::Record<'_>) {
        let mut kv = Vec::new();
        let _ = r.key_values().visit(&mut Kv(&mut kv));
        RECORDS
            .lock()
            .unwrap()
            .push((r.level(), r.target().to_owned(), r.args().to_string(), kv));
    }
    fn flush(&self) {}
}

#[test]
fn records_and_levels_go_through_log() {
    log::set_logger(&Capture).unwrap();
    // An application set `log`'s level (env_logger does): only-log follows it.
    log::set_max_level(log::LevelFilter::Info);
    assert_eq!(only_log::max_level(), LevelFilter::Info);
    assert!(only_log::enabled(Level::Info, "only"));
    assert!(!only_log::enabled(Level::Info, "muted"));
    assert!(!only_log::enabled(Level::Debug, "only"));

    let peer = std::net::SocketAddr::from(([10, 1, 2, 3], 80));
    only_log::info!(target: "only", conn_id = 7u64, peer:% = peer, ok = true, ratio = 0.5,
        name = "x", list:? = [1, 2]; "hello {}", 1);
    only_log::debug!(target: "only", "filtered");
    only_log::error!(target: "muted", "muted");
    // `Config::log_level` path: sets both maxima.
    only_log::set_max_level(LevelFilter::Trace);
    assert_eq!(log::max_level(), log::LevelFilter::Trace);
    only_log::trace!(target: "only", "visible");

    let recs = RECORDS.lock().unwrap().clone();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(
        (recs[0].0, recs[0].1.as_str(), recs[0].2.as_str()),
        (log::Level::Info, "only", "hello 1")
    );
    let kv: Vec<(&str, &str)> = recs[0].3.iter().map(|(k, v)| (&k[..], &v[..])).collect();
    assert_eq!(
        kv,
        [
            ("conn_id", "7"),
            ("peer", "10.1.2.3:80"),
            ("ok", "true"),
            ("ratio", "0.5"),
            ("name", "x"),
            ("list", "[1, 2]")
        ]
    );
    assert_eq!(recs[1].0, log::Level::Trace);

    // Level conversions.
    for l in Level::ALL {
        assert_eq!(Level::from(log::Level::from(l)), l);
    }
    for f in [LevelFilter::Off, LevelFilter::Warn, LevelFilter::Trace] {
        assert_eq!(LevelFilter::from(log::LevelFilter::from(f)), f);
    }
}
