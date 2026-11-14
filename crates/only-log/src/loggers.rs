//! Built-in loggers: [`StderrLogger`] and the formatted [`FmtLogger`].

use std::{
    fmt::Write as _,
    io::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    LevelFilter, Logger, Metadata, Record, SetLoggerError, set_boxed_logger, set_max_level,
};

/// Prints `target: message` per record to stderr: the same lines `only` prints when no logger
/// is installed ([`log_or_stderr`](crate::log_or_stderr)), now for every enabled record.
///
/// ```
/// only_log::set_logger(&only_log::StderrLogger).ok();
/// only_log::set_max_level(only_log::LevelFilter::Warn);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct StderrLogger;

impl Logger for StderrLogger {
    fn log(&self, record: &Record<'_>) {
        let line = format!("{}: {}\n", record.target(), record.args());
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
}

/// A formatted line logger: UTC timestamp (microseconds), level, target, message and the
/// key-values as `key=value` (values with spaces, quotes or `=` are quoted):
///
/// ```text
/// 2026-11-14T08:00:00.000123Z INFO  only: engine started listeners=[127.0.0.1:8080]
/// ```
///
/// Writes each record with one `write` to stderr (or stdout). The global
/// [`max_level`](crate::max_level) is its level; per-target ceilings can lower it.
///
/// ```
/// use only_log::{FmtLogger, LevelFilter};
/// FmtLogger::new()
///     .target_level("only_http::access", LevelFilter::Off) // no access log
///     .init(LevelFilter::Debug)
///     .ok();
/// ```
#[derive(Clone, Debug, Default)]
pub struct FmtLogger {
    targets: Vec<(String, LevelFilter)>,
    stdout: bool,
    no_timestamps: bool,
}

impl FmtLogger {
    /// Stderr, timestamps on, no per-target ceilings.
    pub fn new() -> FmtLogger {
        FmtLogger::default()
    }

    /// Caps `target` and its submodules (`target::...`) at `level`; the longest matching prefix
    /// wins.
    #[must_use]
    pub fn target_level(mut self, target: impl Into<String>, level: LevelFilter) -> FmtLogger {
        self.targets.push((target.into(), level));
        self
    }

    /// Writes to stdout instead of stderr.
    #[must_use]
    pub fn stdout(mut self) -> FmtLogger {
        self.stdout = true;
        self
    }

    /// Leaves out the timestamp (when the output is already timestamped, e.g. by journald).
    #[must_use]
    pub fn without_timestamps(mut self) -> FmtLogger {
        self.no_timestamps = true;
        self
    }

    /// Installs this logger and sets the global maximum level to `level`.
    pub fn init(self, level: LevelFilter) -> Result<(), SetLoggerError> {
        set_boxed_logger(Box::new(self))?;
        set_max_level(level);
        Ok(())
    }

    /// Renders `record` as one line (with the trailing newline).
    pub fn format(&self, record: &Record<'_>) -> String {
        let mut s = String::with_capacity(128);
        if !self.no_timestamps {
            push_timestamp(&mut s, SystemTime::now());
            s.push(' ');
        }
        let _ = write!(
            s,
            "{:<5} {}: {}",
            record.level(),
            record.target(),
            record.args()
        );
        for (k, v) in record.key_values().iter() {
            let start = s.len() + k.len() + 2;
            let _ = write!(s, " {k}={v}");
            if s[start..]
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b == b'"' || b == b'=')
                || s.len() == start
            {
                let raw = s.split_off(start);
                let _ = write!(s, "{raw:?}");
            }
        }
        s.push('\n');
        s
    }
}

impl Logger for FmtLogger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        let t = m.target();
        let mut best: Option<(usize, LevelFilter)> = None;
        for (p, l) in &self.targets {
            let hit = t == p
                || (t.len() > p.len()
                    && t.starts_with(p.as_str())
                    && t[p.len()..].starts_with("::"));
            if hit && best.is_none_or(|(n, _)| p.len() > n) {
                best = Some((p.len(), *l));
            }
        }
        best.is_none_or(|(_, l)| m.level() <= l)
    }

    fn log(&self, record: &Record<'_>) {
        let line = self.format(record);
        let _ = if self.stdout {
            std::io::stdout().lock().write_all(line.as_bytes())
        } else {
            std::io::stderr().lock().write_all(line.as_bytes())
        };
    }

    fn flush(&self) {
        let _ = if self.stdout {
            std::io::stdout().flush()
        } else {
            std::io::stderr().flush()
        };
    }
}

/// Installs a [`FmtLogger`] on stderr and sets the global maximum level: logging in one call.
///
/// ```
/// only_log::init(only_log::LevelFilter::Info).ok();
/// only_log::info!("ready");
/// ```
pub fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
    FmtLogger::new().init(level)
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC).
fn push_timestamp(s: &mut String, t: SystemTime) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, day) = civil_from_days(days as i64);
    let _ = write!(
        s,
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        d.subsec_micros()
    );
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Level, ToValue, Value};
    use std::time::Duration;

    #[test]
    fn timestamps() {
        let mut s = String::new();
        push_timestamp(&mut s, UNIX_EPOCH);
        assert_eq!(s, "1970-01-01T00:00:00.000000Z");
        s.clear();
        // 2024-02-29T23:59:59.000042Z (leap day).
        push_timestamp(
            &mut s,
            UNIX_EPOCH + Duration::from_secs(1_709_251_199) + Duration::from_micros(42),
        );
        assert_eq!(s, "2024-02-29T23:59:59.000042Z");
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_771), (2026, 11, 14));
    }

    #[test]
    fn fmt_lines() {
        let f = FmtLogger::new().without_timestamps();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let kvs = [
            ("conn_id", 7u64.to_value()),
            ("peer", Value::from_display(&addr)),
            ("msg", "two words".to_value()),
            ("empty", "".to_value()),
            ("eq", "a=b".to_value()),
        ];
        let check = |r: Record<'_>| {
            assert_eq!(
                f.format(&r),
                "INFO  only: connection opened conn_id=7 peer=127.0.0.1:80 msg=\"two words\" \
                 empty=\"\" eq=\"a=b\"\n"
            );
            let with_ts = FmtLogger::new().format(&r);
            assert_eq!(with_ts.as_bytes()[10], b'T');
            assert!(with_ts[28..].starts_with("INFO  only: connection opened"));
        };
        check(
            Record::new(Level::Info, "only", format_args!("connection {}", "opened"))
                .with_key_values(&kvs),
        );
    }

    #[test]
    fn target_ceilings() {
        let f = FmtLogger::new()
            .target_level("only", LevelFilter::Warn)
            .target_level("only_http::access", LevelFilter::Off)
            .target_level("only::x", LevelFilter::Trace);
        let on = |l, t| f.enabled(&Metadata::new(l, t));
        assert!(on(Level::Warn, "only"));
        assert!(!on(Level::Info, "only"));
        assert!(!on(Level::Info, "only::y"));
        assert!(on(Level::Trace, "only::x::z"));
        assert!(on(Level::Trace, "only_webrtc"));
        assert!(!on(Level::Error, "only_http::access"));
        assert!(on(Level::Info, "only_http"));
        assert!(on(Level::Trace, "app"));
    }
}
