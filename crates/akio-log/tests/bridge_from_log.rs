//! Feature `log`: `route_log_to_only` delivers `log` records to the akio-log logger, without
//! looping back.
#![allow(missing_docs, clippy::type_complexity)]
#![cfg(feature = "log")]

use std::sync::Mutex;

use akio_log::{Level, LevelFilter, Logger, Metadata, Record};

static RECORDS: Mutex<Vec<(Level, String, String, Vec<(String, String)>)>> = Mutex::new(Vec::new());

struct Capture;
impl Logger for Capture {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        m.target() != "muted"
    }
    fn log(&self, r: &Record<'_>) {
        RECORDS.lock().unwrap().push((
            r.level(),
            r.target().to_owned(),
            r.args().to_string(),
            r.key_values()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect(),
        ));
    }
}

#[test]
fn log_records_reach_only_log() {
    // Before an akio-log logger exists, the adapter drops records (no loop through `log`).
    akio_log::bridge::route_log_to_only().unwrap();
    assert!(akio_log::bridge::route_log_to_only().is_err());
    log::set_max_level(log::LevelFilter::Trace);
    log::error!("dropped");
    akio_log::error!("dropped too");
    assert!(RECORDS.lock().unwrap().is_empty());

    akio_log::set_logger(&Capture).unwrap();
    akio_log::set_max_level(LevelFilter::Debug);
    assert_eq!(log::max_level(), log::LevelFilter::Debug);
    log::info!(target: "dep", id = 3, name = "n", addr:% = "1.2.3.4"; "from {}", "log");
    log::trace!(target: "dep", "filtered by the level");
    log::warn!(target: "muted", "filtered by the logger");
    assert!(log::log_enabled!(target: "dep", log::Level::Debug));
    assert!(!log::log_enabled!(target: "muted", log::Level::Error));
    akio_log::debug!(target: "own", "direct");
    log::logger().flush();

    let recs = RECORDS.lock().unwrap().clone();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(
        (recs[0].0, recs[0].1.as_str(), recs[0].2.as_str()),
        (Level::Info, "dep", "from log")
    );
    let kv: Vec<(&str, &str)> = recs[0].3.iter().map(|(k, v)| (&k[..], &v[..])).collect();
    assert_eq!(kv, [("id", "3"), ("name", "n"), ("addr", "1.2.3.4")]);
    assert_eq!((recs[1].1.as_str(), recs[1].2.as_str()), ("own", "direct"));
}
