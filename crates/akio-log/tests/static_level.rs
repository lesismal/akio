//! The compile-time cap. Without a `max_level_*` feature it is `Trace`; CI also runs this file
//! with `--features max_level_info` (and `release_max_level_warn` in release), where `debug!`
//! and `trace!` are compiled out: their arguments are never evaluated, whatever the run-time
//! maximum.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};

use akio_log::{Level, LevelFilter, Logger, Record, STATIC_MAX_LEVEL};

static SEEN: AtomicUsize = AtomicUsize::new(0);

struct Count;
impl Logger for Count {
    fn log(&self, _r: &Record<'_>) {
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
}

/// What the enabled features should give.
fn expected() -> LevelFilter {
    let release = !cfg!(debug_assertions);
    if release && cfg!(feature = "release_max_level_warn") {
        LevelFilter::Warn
    } else if cfg!(feature = "max_level_info") {
        LevelFilter::Info
    } else {
        LevelFilter::Trace
    }
}

#[test]
fn statements_above_the_cap_are_compiled_out() {
    assert_eq!(STATIC_MAX_LEVEL, expected());
    akio_log::set_logger(&Count).unwrap();
    akio_log::set_max_level(LevelFilter::Trace);

    let mut evaluated = [false; 5];
    akio_log::error!("{}", {
        evaluated[0] = true;
        0
    });
    akio_log::warn!("{}", {
        evaluated[1] = true;
        0
    });
    akio_log::info!("{}", {
        evaluated[2] = true;
        0
    });
    akio_log::debug!("{}", {
        evaluated[3] = true;
        0
    });
    akio_log::trace!("{}", {
        evaluated[4] = true;
        0
    });
    for (i, l) in Level::ALL.into_iter().enumerate() {
        assert_eq!(evaluated[i], l <= STATIC_MAX_LEVEL, "{l}");
        assert_eq!(akio_log::log_enabled!(l), l <= STATIC_MAX_LEVEL, "{l}");
        assert_eq!(akio_log::enabled(l, "x"), l <= STATIC_MAX_LEVEL, "{l}");
    }
    let want = Level::ALL
        .iter()
        .filter(|l| **l <= STATIC_MAX_LEVEL)
        .count();
    assert_eq!(SEEN.load(Ordering::Relaxed), want);
}
