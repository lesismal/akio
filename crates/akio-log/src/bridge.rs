//! Bridge to the [`log`](https://docs.rs/log) crate (cargo feature `log`; outside the semver
//! promise: it follows `log` 0.4 and may move to a newer `log` in a minor release).
//!
//! Both directions:
//!
//! - **akio-log → `log`**, automatic: while no akio-log logger is installed, every record goes
//!   to `log::logger()` with its level, target, message, source location and key-values, and
//!   the effective [`max_level`](crate::max_level) is `log::max_level()`. Applications that
//!   already set up env_logger, `tracing-log`, fern ... keep seeing `akio`'s records unchanged.
//!   [`set_max_level`](crate::set_max_level) (and so `akio`'s `Config::log_level`) also sets
//!   `log`'s maximum level, as before.
//! - **`log` → akio-log**, opt-in: [`route_log_to_only`] installs [`LogAdapter`] as `log`'s
//!   logger, so records of crates that use `log` reach the akio-log logger.
//!
//! The two never loop: akio-log forwards to `log` only while it has no logger of its own, and
//! [`LogAdapter`] delivers only to an installed akio-log logger (and drops records otherwise).
//!
//! The level types convert both ways with `From` / `Into`.

use crate::{Level, LevelFilter, Metadata, Record, Value};

impl From<Level> for log::Level {
    fn from(l: Level) -> log::Level {
        match l {
            Level::Error => log::Level::Error,
            Level::Warn => log::Level::Warn,
            Level::Info => log::Level::Info,
            Level::Debug => log::Level::Debug,
            Level::Trace => log::Level::Trace,
        }
    }
}

impl From<log::Level> for Level {
    fn from(l: log::Level) -> Level {
        match l {
            log::Level::Error => Level::Error,
            log::Level::Warn => Level::Warn,
            log::Level::Info => Level::Info,
            log::Level::Debug => Level::Debug,
            log::Level::Trace => Level::Trace,
        }
    }
}

impl From<LevelFilter> for log::LevelFilter {
    fn from(l: LevelFilter) -> log::LevelFilter {
        match l {
            LevelFilter::Off => log::LevelFilter::Off,
            LevelFilter::Error => log::LevelFilter::Error,
            LevelFilter::Warn => log::LevelFilter::Warn,
            LevelFilter::Info => log::LevelFilter::Info,
            LevelFilter::Debug => log::LevelFilter::Debug,
            LevelFilter::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<log::LevelFilter> for LevelFilter {
    fn from(l: log::LevelFilter) -> LevelFilter {
        match l {
            log::LevelFilter::Off => LevelFilter::Off,
            log::LevelFilter::Error => LevelFilter::Error,
            log::LevelFilter::Warn => LevelFilter::Warn,
            log::LevelFilter::Info => LevelFilter::Info,
            log::LevelFilter::Debug => LevelFilter::Debug,
            log::LevelFilter::Trace => LevelFilter::Trace,
        }
    }
}

/// Whether `log`'s logger wants the record (no akio-log logger installed).
pub(crate) fn log_enabled(level: Level, target: &str) -> bool {
    log::logger().enabled(
        &log::Metadata::builder()
            .level(level.into())
            .target(target)
            .build(),
    )
}

struct Kvs<'a>(crate::KeyValues<'a>);

impl log::kv::Source for Kvs<'_> {
    fn visit<'kvs>(
        &'kvs self,
        visitor: &mut dyn log::kv::VisitSource<'kvs>,
    ) -> Result<(), log::kv::Error> {
        for (k, v) in self.0.0 {
            visitor.visit_pair(log::kv::Key::from_str(k), to_log_value(v))?;
        }
        Ok(())
    }
}

fn to_log_value<'v>(v: &'v Value<'_>) -> log::kv::Value<'v> {
    use crate::ValueInner as V;
    match v.0 {
        V::Str(s) => log::kv::Value::from(s),
        V::U64(n) => log::kv::Value::from(n),
        V::I64(n) => log::kv::Value::from(n),
        V::U128(n) => log::kv::Value::from(n),
        V::I128(n) => log::kv::Value::from(n),
        V::F64(n) => log::kv::Value::from(n),
        V::Bool(b) => log::kv::Value::from(b),
        V::Char(c) => log::kv::Value::from(c),
        V::Display(_) | V::Debug(_) => log::kv::Value::from_dyn_display(v),
    }
}

/// Sends `record` to `log`'s logger (no akio-log logger installed).
pub(crate) fn forward(record: &Record<'_>) {
    let kvs = Kvs(record.key_values());
    let logger = log::logger();
    let meta = log::Metadata::builder()
        .level(record.level().into())
        .target(record.target())
        .build();
    if !logger.enabled(&meta) {
        return;
    }
    logger.log(
        &log::Record::builder()
            .metadata(meta)
            .args(*record.args())
            .module_path(record.module_path())
            .file(record.file())
            .line(record.line())
            .key_values(&kvs)
            .build(),
    );
}

/// A `log::Log` that hands `log` records to the installed akio-log logger (records are dropped
/// while none is installed). Install it with [`route_log_to_only`].
#[derive(Clone, Copy, Debug, Default)]
pub struct LogAdapter;

impl log::Log for LogAdapter {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        crate::logger().is_some_and(|l| l.enabled(&Metadata::new(m.level().into(), m.target())))
    }

    fn log(&self, r: &log::Record<'_>) {
        let Some(l) = crate::logger() else {
            return;
        };
        let meta = Metadata::new(r.level().into(), r.target());
        if r.level() > log::max_level() || !l.enabled(&meta) {
            return;
        }
        struct Collect<'kvs>(Vec<(log::kv::Key<'kvs>, log::kv::Value<'kvs>)>);
        impl<'kvs> log::kv::VisitSource<'kvs> for Collect<'kvs> {
            fn visit_pair(
                &mut self,
                k: log::kv::Key<'kvs>,
                v: log::kv::Value<'kvs>,
            ) -> Result<(), log::kv::Error> {
                self.0.push((k, v));
                Ok(())
            }
        }
        let mut c = Collect(Vec::new());
        let _ = r.key_values().visit(&mut c);
        let kvs: Vec<(&str, Value<'_>)> =
            c.0.iter()
                .map(|(k, v)| {
                    let v = v.to_borrowed_str().map_or_else(
                        || Value::from_display(v),
                        |s| Value(crate::ValueInner::Str(s)),
                    );
                    (k.as_str(), v)
                })
                .collect();
        l.log(
            &Record::new(meta.level(), meta.target(), *r.args())
                .with_key_values(&kvs)
                .with_location(r.module_path(), r.file(), r.line()),
        );
    }

    fn flush(&self) {
        if let Some(l) = crate::logger() {
            l.flush();
        }
    }
}

/// Installs [`LogAdapter`] as the `log` crate's logger and aligns `log`'s maximum level with
/// [`max_level`](crate::max_level) (later [`set_max_level`](crate::set_max_level) calls keep
/// both in step). Fails if `log` already has a logger.
pub fn route_log_to_only() -> Result<(), log::SetLoggerError> {
    static ADAPTER: LogAdapter = LogAdapter;
    log::set_logger(&ADAPTER)?;
    if crate::logger().is_some() {
        log::set_max_level(crate::max_level().into());
    }
    Ok(())
}
