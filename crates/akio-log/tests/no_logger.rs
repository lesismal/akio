//! No logger installed: records are dropped, `enabled` is false, `log_or_stderr` prints.
#![allow(missing_docs)]

use akio_log::{Level, LevelFilter};

#[test]
fn without_a_logger_nothing_is_enabled() {
    akio_log::set_max_level(LevelFilter::Trace);
    assert_eq!(akio_log::max_level(), LevelFilter::Trace);
    assert!(!akio_log::enabled(Level::Error, "akio"));
    assert!(!akio_log::log_enabled!(target: "akio", Level::Error));
    akio_log::error!(target: "akio", k = 1u8; "dropped");
    akio_log::log_or_stderr(Level::Error, "akio", format_args!("printed to stderr"));
    akio_log::flush();
}
