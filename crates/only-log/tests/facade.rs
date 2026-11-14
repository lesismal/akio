//! The facade with a logger installed (process-global: one test binary, one test).
#![allow(missing_docs)]

use std::sync::Mutex;

use only_log::{Level, LevelFilter, Logger, Metadata, Record};

#[derive(Debug, Clone)]
struct Rec {
    level: Level,
    target: String,
    msg: String,
    kv: Vec<(String, String)>,
    module: Option<String>,
    line: Option<u32>,
}

static RECORDS: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

struct Capture;
impl Logger for Capture {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        m.target() != "muted"
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
            module: r.module_path().map(str::to_owned),
            line: r.line(),
        });
    }
}

fn take() -> Vec<Rec> {
    std::mem::take(&mut *RECORDS.lock().unwrap())
}

#[test]
fn macros_levels_targets_and_key_values() {
    #[cfg(not(feature = "log"))]
    assert_eq!(only_log::max_level(), LevelFilter::Off);
    assert!(only_log::logger().is_none());
    only_log::set_logger(&Capture).unwrap();
    assert!(only_log::set_logger(&Capture).is_err());
    assert!(only_log::set_boxed_logger(Box::new(Capture)).is_err());
    assert!(only_log::logger().is_some());
    assert_eq!(only_log::max_level(), LevelFilter::Off);

    // Off: nothing, and the arguments are not evaluated.
    let mut evaluated = false;
    only_log::error!("{}", {
        evaluated = true;
        1
    });
    assert!(!evaluated);
    assert!(take().is_empty());
    assert!(!only_log::enabled(Level::Error, "x"));

    only_log::set_max_level(LevelFilter::Info);
    assert_eq!(only_log::max_level(), LevelFilter::Info);
    let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
    let listeners = vec![peer];
    let id = 42u64;
    let kind = "on_data";
    only_log::info!(target: "only", conn_id = id, peer:% = peer, listeners:? = listeners,
        kind = kind, dialed = false, elapsed_us = 1500u128 as u64; "connection {}", "opened");
    only_log::warn!("plain {id}");
    only_log::error!(target: "only", "with target");
    only_log::debug!(target: "only", "filtered");
    only_log::trace!("filtered");
    only_log::log!(Level::Info, k = 1u8; "generic");
    only_log::log!(target: "muted", Level::Error, "muted by the logger");
    let recs = take();
    assert_eq!(recs.len(), 4, "{recs:?}");
    let r = &recs[0];
    assert_eq!((r.level, r.target.as_str()), (Level::Info, "only"));
    assert_eq!(r.msg, "connection opened");
    let kv: Vec<(&str, &str)> = r.kv.iter().map(|(k, v)| (&k[..], &v[..])).collect();
    assert_eq!(
        kv,
        [
            ("conn_id", "42"),
            ("peer", "127.0.0.1:9"),
            ("listeners", "[127.0.0.1:9]"),
            ("kind", "on_data"),
            ("dialed", "false"),
            ("elapsed_us", "1500")
        ]
    );
    assert_eq!(r.module.as_deref(), Some(module_path!()));
    assert!(r.line.is_some());
    assert_eq!(
        (recs[1].level, recs[1].target.as_str(), recs[1].msg.as_str()),
        (Level::Warn, module_path!(), "plain 42")
    );
    assert_eq!(recs[2].target, "only");
    assert_eq!((recs[3].msg.as_str(), recs[3].kv.len()), ("generic", 1));

    assert!(only_log::log_enabled!(target: "only", Level::Info));
    assert!(!only_log::log_enabled!(Level::Debug));
    assert!(!only_log::log_enabled!(target: "muted", Level::Error));
    assert!(only_log::enabled(Level::Warn, "x"));

    // log_or_stderr: through the logger when enabled, stderr otherwise.
    only_log::log_or_stderr(Level::Warn, "only", format_args!("fallback {}", 1));
    only_log::log_or_stderr(Level::Trace, "only", format_args!("to stderr"));
    let recs = take();
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].msg.as_str(), recs[0].line), ("fallback 1", None));

    // Runtime level change.
    only_log::set_max_level(LevelFilter::Trace);
    only_log::trace!("now visible");
    assert_eq!(take().len(), 1);
    only_log::flush();
}
