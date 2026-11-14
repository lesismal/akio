//! No logger installed: records are dropped, `enabled` is false, `log_or_stderr` prints.
#![allow(missing_docs)]

use only_log::{Level, LevelFilter};

#[test]
fn without_a_logger_nothing_is_enabled() {
    only_log::set_max_level(LevelFilter::Trace);
    assert_eq!(only_log::max_level(), LevelFilter::Trace);
    assert!(!only_log::enabled(Level::Error, "only"));
    assert!(!only_log::log_enabled!(target: "only", Level::Error));
    only_log::error!(target: "only", k = 1u8; "dropped");
    only_log::log_or_stderr(Level::Error, "only", format_args!("printed to stderr"));
    only_log::flush();
}
