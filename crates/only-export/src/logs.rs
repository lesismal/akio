//! OTLP logs: the logger installed by [`ExporterBuilder::logs`](crate::ExporterBuilder::logs)
//! copies each record (message, key-values, source location, the current span's ids) into the
//! bounded log queue, and optionally hands it to another logger too.

use std::{cell::Cell, fmt::Write as _, sync::Arc, time::SystemTime};

use only_log::{
    Level, LevelFilter, Logger, Metadata, Record,
    span::{self, FieldValue, SpanContext},
};

use crate::queue::Queue;

thread_local! {
    /// Set on the exporter's own threads: their records are not exported (no feedback loop
    /// from logs about exporting logs).
    static SUPPRESS: Cell<bool> = const { Cell::new(false) };
}

/// Marks the calling thread as one of the exporter's.
pub(crate) fn suppress_this_thread() {
    SUPPRESS.with(|s| s.set(true));
}

/// One log record, owned.
#[derive(Clone, Debug)]
pub(crate) struct LogData {
    pub(crate) time: SystemTime,
    pub(crate) level: Level,
    pub(crate) target: String,
    pub(crate) message: String,
    pub(crate) fields: Vec<(String, FieldValue)>,
    pub(crate) file: Option<String>,
    pub(crate) line: Option<u32>,
    /// The span current on the logging thread.
    pub(crate) span: Option<SpanContext>,
}

impl LogData {
    pub(crate) fn from_record(r: &Record<'_>) -> LogData {
        let mut message = String::new();
        let _ = write!(message, "{}", r.args());
        LogData {
            time: SystemTime::now(),
            level: r.level(),
            target: r.target().to_owned(),
            message,
            fields: r
                .key_values()
                .iter()
                .map(|(k, v)| (k.to_owned(), FieldValue::from_value(v)))
                .collect(),
            file: r.file().map(str::to_owned),
            line: r.line(),
            span: span::current(),
        }
    }
}

fn within(level: Level, max: LevelFilter) -> bool {
    level as usize <= max as usize
}

/// The installed logger.
pub(crate) struct OtlpLogger {
    pub(crate) queue: Arc<Queue<LogData>>,
    pub(crate) level: LevelFilter,
    pub(crate) forward: Option<(Arc<dyn Logger>, LevelFilter)>,
}

impl OtlpLogger {
    fn exports(&self, level: Level) -> bool {
        within(level, self.level)
            && self.queue.open.load(std::sync::atomic::Ordering::Relaxed)
            && !SUPPRESS.with(Cell::get)
    }
}

impl Logger for OtlpLogger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        self.exports(m.level())
            || self
                .forward
                .as_ref()
                .is_some_and(|(l, max)| within(m.level(), *max) && l.enabled(m))
    }

    fn log(&self, r: &Record<'_>) {
        if self.exports(r.level()) {
            self.queue.push(LogData::from_record(r));
        }
        if let Some((l, max)) = &self.forward {
            if within(r.level(), *max) && l.enabled(r.metadata()) {
                l.log(r);
            }
        }
    }

    fn flush(&self) {
        if let Some((l, _)) = &self.forward {
            l.flush();
        }
    }
}
