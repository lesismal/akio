//! Built-in loggers: [`StderrLogger`] and the formatted [`FmtLogger`].

use std::{
    fmt::Write as _,
    io::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    Filter, LevelFilter, Logger, Metadata, Record, SetLoggerError, filter::ENV_VAR,
    set_boxed_logger, set_max_level,
};

/// Prints `target: message` per record to stderr: the same lines `akio` prints when no logger
/// is installed ([`log_or_stderr`](crate::log_or_stderr)), now for every enabled record.
///
/// ```
/// akio_log::set_logger(&akio_log::StderrLogger).ok();
/// akio_log::set_max_level(akio_log::LevelFilter::Warn);
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
/// 2026-11-14T08:00:00.000123Z INFO  akio: engine started listeners=[127.0.0.1:8080]
/// ```
///
/// Writes each record with one `write` to stderr (or stdout). The global
/// [`max_level`](crate::max_level) is its level; per-target ceilings can lower it, and a
/// [`Filter`] (`AKIO_LOG=info,akio_http=debug`, see [`init_from_env`]) sets the level per
/// target, optionally with a message regex (`AKIO_LOG=info/timed out`) that the formatted
/// message must match.
///
/// By default the write happens on the thread that logs, under the standard stream's lock:
/// when stderr is a pipe nobody drains (a stalled log collector), that thread blocks, and an
/// `akio` I/O thread logging then stalls every connection it serves.
/// [`non_blocking`](Self::non_blocking) hands lines to a writer thread through a bounded queue
/// instead and drops (and counts) lines when it is full: use it in servers whose log output may
/// back up.
///
/// ```
/// use akio_log::{FmtLogger, LevelFilter};
/// FmtLogger::new()
///     .target_level("akio_http::access", LevelFilter::Off) // no access log
///     .init(LevelFilter::Debug)
///     .ok();
/// ```
#[derive(Clone, Debug, Default)]
pub struct FmtLogger {
    filter: Filter,
    stdout: bool,
    no_timestamps: bool,
    sink: Option<Arc<AsyncSink>>,
}

/// A suggested [`FmtLogger::non_blocking`] queue size: 16 384 lines (a few MiB at most).
pub const DEFAULT_QUEUE_LINES: usize = 16_384;

enum Msg {
    Line(String),
    Flush(mpsc::SyncSender<()>),
}

/// The queue and counters of a non-blocking [`FmtLogger`].
struct AsyncSink {
    tx: mpsc::SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    /// Serialises the blocking `Flush` send (rare) against itself.
    flushing: Mutex<()>,
}

impl std::fmt::Debug for AsyncSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSink")
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl AsyncSink {
    /// A writer thread draining up to `lines` queued lines into `out`.
    fn start(lines: usize, mut out: Box<dyn std::io::Write + Send>) -> AsyncSink {
        let (tx, rx) = mpsc::sync_channel::<Msg>(lines.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let seen = dropped.clone();
        let _ = std::thread::Builder::new()
            .name("akio-log".into())
            .spawn(move || {
                let mut reported = 0u64;
                let mut buf = Vec::with_capacity(64 << 10);
                while let Ok(first) = rx.recv() {
                    let mut acks = Vec::new();
                    let mut take = |m: Msg, buf: &mut Vec<u8>| match m {
                        Msg::Line(l) => buf.extend_from_slice(l.as_bytes()),
                        Msg::Flush(ack) => acks.push(ack),
                    };
                    take(first, &mut buf);
                    // Batch what is already queued into one write.
                    while buf.len() < (64 << 10) {
                        match rx.try_recv() {
                            Ok(m) => take(m, &mut buf),
                            Err(_) => break,
                        }
                    }
                    let d = seen.load(Ordering::Relaxed);
                    if d > reported {
                        let _ = writeln!(
                            buf,
                            "akio_log: {} log lines dropped (queue full)",
                            d - reported
                        );
                        reported = d;
                    }
                    let _ = out.write_all(&buf);
                    buf.clear();
                    if !acks.is_empty() {
                        let _ = out.flush();
                        for a in acks {
                            let _ = a.send(());
                        }
                    }
                }
            });
        AsyncSink {
            tx,
            dropped,
            flushing: Mutex::new(()),
        }
    }

    fn push(&self, line: String) {
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Waits (at most a second) until everything queued before it is written.
    fn flush(&self) {
        let _g = self.flushing.lock().unwrap_or_else(|p| p.into_inner());
        let (ack, done) = mpsc::sync_channel(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut m = Msg::Flush(ack);
        loop {
            match self.tx.try_send(m) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(back)) if std::time::Instant::now() < deadline => {
                    m = back;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return,
            }
        }
        let _ = done.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
    }
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
        self.filter = self.filter.directive(target, level);
        self
    }

    /// Filters records with `filter` (its per-target levels and its default level) instead
    /// of the ceilings set so far. [`init`](Self::init) still sets the global maximum; use
    /// [`init_filtered`](Self::init_filtered) to set it from the filter.
    #[must_use]
    pub fn filter(mut self, filter: Filter) -> FmtLogger {
        self.filter = filter;
        self
    }

    /// Installs this logger with `filter` and sets the global maximum level to
    /// [`filter.max_level()`](Filter::max_level).
    pub fn init_filtered(self, filter: Filter) -> Result<(), SetLoggerError> {
        let max = filter.max_level();
        self.filter(filter).init(max)
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

    /// Writes from a writer thread of its own instead of the logging thread: each record is
    /// formatted where it is logged and queued (up to `lines` lines,
    /// [`DEFAULT_QUEUE_LINES`] is a good size); when the queue is full the line is dropped and
    /// counted ([`dropped`](Self::dropped)), and the writer reports the count in a line of its
    /// own once it catches up. Logging never blocks on the output, so a stalled stderr pipe
    /// cannot stall an I/O thread. Call it after [`stdout`](Self::stdout);
    /// [`flush`](crate::flush) waits (at most a second) for the queue to be written, so call it
    /// before the process exits.
    #[must_use]
    pub fn non_blocking(mut self, lines: usize) -> FmtLogger {
        let out: Box<dyn std::io::Write + Send> = if self.stdout {
            Box::new(std::io::stdout())
        } else {
            Box::new(std::io::stderr())
        };
        self.sink = Some(Arc::new(AsyncSink::start(lines, out)));
        self
    }

    /// Lines dropped because the [`non_blocking`](Self::non_blocking) queue was full (0 when
    /// writing synchronously). Clones share the count: keep one before [`init`](Self::init).
    pub fn dropped(&self) -> u64 {
        self.sink
            .as_ref()
            .map_or(0, |s| s.dropped.load(Ordering::Relaxed))
    }

    /// Installs this logger and sets the global maximum level to `level`.
    pub fn init(self, level: LevelFilter) -> Result<(), SetLoggerError> {
        set_boxed_logger(Box::new(self))?;
        set_max_level(level);
        Ok(())
    }

    /// Renders `record` as one line (with the trailing newline).
    pub fn format(&self, record: &Record<'_>) -> String {
        self.format_line(record).0
    }

    /// The line and where the message is in it.
    fn format_line(&self, record: &Record<'_>) -> (String, std::ops::Range<usize>) {
        let mut s = String::with_capacity(128);
        if !self.no_timestamps {
            push_timestamp(&mut s, SystemTime::now());
            s.push(' ');
        }
        let _ = write!(s, "{:<5} {}: ", record.level(), record.target());
        let start = s.len();
        let _ = write!(s, "{}", record.args());
        let msg = start..s.len();
        if let Some(c) = crate::span::current() {
            let _ = write!(
                s,
                " trace_id={:032x} span_id={:016x}",
                c.trace_id(),
                c.span_id()
            );
        }
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
        (s, msg)
    }
}

impl Logger for FmtLogger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        self.filter.enabled(m)
    }

    fn log(&self, record: &Record<'_>) {
        let (line, msg) = self.format_line(record);
        // The message filter (`/regex`) runs on the message as formatted for the line.
        if self
            .filter
            .message_filter()
            .is_some_and(|re| !re.is_match(&line[msg]))
        {
            return;
        }
        if let Some(sink) = &self.sink {
            return sink.push(line);
        }
        let _ = if self.stdout {
            std::io::stdout().lock().write_all(line.as_bytes())
        } else {
            std::io::stderr().lock().write_all(line.as_bytes())
        };
    }

    fn flush(&self) {
        if let Some(sink) = &self.sink {
            return sink.flush();
        }
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
/// akio_log::init(akio_log::LevelFilter::Info).ok();
/// akio_log::info!("ready");
/// ```
pub fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
    FmtLogger::new().init(level)
}

/// Installs a [`FmtLogger`] on stderr filtered by the `AKIO_LOG` environment variable
/// (env_logger-style directives, see [`Filter`]), parsed once, here:
///
/// ```text
/// AKIO_LOG=info,akio_http=debug,akio_quic::conn=trace,akio_http::access=off
/// ```
///
/// When `AKIO_LOG` is unset or blank, `default` is the level of every target (as with
/// [`init`]). When it does not parse, a line saying why goes to stderr and `default` is used.
/// The global maximum level becomes the filter's [`max_level`](Filter::max_level). Nothing
/// reads the variable unless this is called: [`init`] and the default behaviour do not.
///
/// ```
/// akio_log::init_from_env(akio_log::LevelFilter::Info).ok();
/// ```
pub fn init_from_env(default: LevelFilter) -> Result<(), SetLoggerError> {
    let filter = match Filter::from_env(ENV_VAR) {
        Some(Ok(f)) => f,
        Some(Err(e)) => {
            eprintln!("akio-log: ignoring {ENV_VAR}: {e}");
            Filter::new(default)
        }
        None => Filter::new(default),
    };
    FmtLogger::new().init_filtered(filter)
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
                "INFO  akio: connection opened conn_id=7 peer=127.0.0.1:80 msg=\"two words\" \
                 empty=\"\" eq=\"a=b\"\n"
            );
            let with_ts = FmtLogger::new().format(&r);
            assert_eq!(with_ts.as_bytes()[10], b'T');
            assert!(with_ts[28..].starts_with("INFO  akio: connection opened"));
        };
        check(
            Record::new(Level::Info, "akio", format_args!("connection {}", "opened"))
                .with_key_values(&kvs),
        );
    }

    /// An output that blocks until released, like a pipe nobody reads.
    struct Stalled {
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
        got: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for Stalled {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let (m, cv) = &*self.gate;
            let mut open = m.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            self.got.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// With the output stalled, logging returns at once: lines beyond the queue are dropped and
    /// counted, and the count is reported once the output drains.
    #[test]
    fn non_blocking_drops_and_counts() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let got = Arc::new(Mutex::new(Vec::new()));
        let out = Stalled {
            gate: gate.clone(),
            got: got.clone(),
        };
        let mut f = FmtLogger::new().without_timestamps();
        f.sink = Some(Arc::new(AsyncSink::start(8, Box::new(out))));
        let t0 = std::time::Instant::now();
        for i in 0..100 {
            f.log(&Record::new(Level::Info, "t", format_args!("line {i}")));
        }
        assert!(t0.elapsed() < Duration::from_secs(1), "never blocked");
        // The writer holds at most one batch; the queue at most 8 lines.
        let dropped = f.dropped();
        assert!(
            (100 - 8 - 64..=100 - 8).contains(&(dropped as i64)),
            "{dropped}"
        );
        // Release the output: the queued lines and a drop report come out.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        f.flush();
        assert_eq!(f.dropped(), dropped, "nothing dropped once drained");
        f.log(&Record::new(Level::Info, "t", format_args!("after")));
        f.flush();
        let text = String::from_utf8(got.lock().unwrap().clone()).unwrap();
        // Drops are reported as they are noticed, possibly over several lines.
        let reports: Vec<u64> = text
            .lines()
            .filter_map(|l| l.strip_prefix("akio_log: "))
            .map(|l| l.split(' ').next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(reports.iter().sum::<u64>(), dropped, "{text}");
        assert!(text.ends_with("INFO  t: after\n"), "{text}");
        let logged = text.lines().filter(|l| l.starts_with("INFO")).count() as u64;
        assert_eq!(logged, 100 - dropped + 1);
    }

    #[test]
    fn target_ceilings() {
        let f = FmtLogger::new()
            .target_level("akio", LevelFilter::Warn)
            .target_level("akio_http::access", LevelFilter::Off)
            .target_level("akio::x", LevelFilter::Trace);
        let on = |l, t| f.enabled(&Metadata::new(l, t));
        assert!(on(Level::Warn, "akio"));
        assert!(!on(Level::Info, "akio"));
        assert!(!on(Level::Info, "akio::y"));
        assert!(on(Level::Trace, "akio::x::z"));
        assert!(on(Level::Trace, "akio_webrtc"));
        assert!(!on(Level::Error, "akio_http::access"));
        assert!(on(Level::Info, "akio_http"));
        assert!(on(Level::Trace, "app"));
    }
}
