#![forbid(unsafe_code)]
//! The logging facade of [`only`](https://docs.rs/only), without dependencies.
//!
//! Libraries log through the macros ([`error!`], [`warn!`], [`info!`], [`debug!`], [`trace!`],
//! [`log!`]); the application installs one [`Logger`] for the whole process with
//! [`set_logger`] / [`set_boxed_logger`], or one of the built-in loggers with [`init`].
//! Records carry a [`Level`], a target (the module path unless given), the formatted message
//! and structured key-values:
//!
//! ```
//! use only_log::{info, warn, LevelFilter};
//!
//! only_log::init(LevelFilter::Info).unwrap(); // `2026-11-14T08:00:00.000123Z INFO  ...` on stderr
//!
//! let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 9000));
//! info!(target: "only", conn_id = 7u64, peer:% = peer, dialed = false; "connection opened");
//! warn!("{} retries left", 3);
//! ```
//!
//! Key-value syntax (the same as the `log` crate's): `key = value` for strings, numbers, `bool`
//! and `char` (anything implementing [`ToValue`]), `key:% = value` captures with `Display`,
//! `key:? = value` with `Debug`. The key-values come before a `;`, then the format string.
//!
//! # Cost when disabled
//!
//! Every macro first compares the record's level with the global maximum ([`max_level`]),
//! one relaxed atomic load, before it evaluates any argument. [`set_max_level`] changes it at
//! run time (`only`'s `Config::log_level` and hot reload call it). The default is
//! [`LevelFilter::Off`], so nothing is formatted until a level is set ([`init`] sets one).
//!
//! # No logger installed
//!
//! Without a logger, [`enabled`] and [`log_enabled!`] return `false` and records are dropped;
//! [`log_or_stderr`] prints those it is given to stderr instead, which is how `only` keeps
//! errors and slow-callback warnings visible when an application installs nothing.
//!
//! # The `log` crate
//!
//! With the `log` cargo feature, only-log bridges to the [`log`](https://docs.rs/log) crate
//! (see the `bridge` module): while no only-log logger is installed, records go to `log`'s
//! global logger (env_logger, `tracing-log` ... keep working) and the maximum level is `log`'s;
//! `log` records from other crates can be routed into only-log; the level types convert both
//! ways. The feature tracks `log` 0.4 and is outside the semver promise.
#![warn(clippy::unwrap_used)]

use std::{
    error::Error,
    fmt,
    str::FromStr,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(feature = "log")]
pub mod bridge;
mod loggers;
mod macros;

pub use loggers::{DEFAULT_QUEUE_LINES, FmtLogger, StderrLogger, init};

// ---- levels ---------------------------------------------------------------------------------

/// The importance of a record. `Error` is the most important; a lower [`LevelFilter`] lets
/// fewer levels through (`Level::Error < Level::Trace`, as in the `log` crate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum Level {
    /// Failures that need attention.
    Error = 1,
    /// Something unexpected that was handled.
    Warn = 2,
    /// Lifecycle events.
    Info = 3,
    /// Diagnostics for developers.
    Debug = 4,
    /// Very verbose diagnostics (per connection, per packet ...).
    Trace = 5,
}

/// A maximum level: records of a more verbose level are filtered out. `Off` disables
/// everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(usize)]
pub enum LevelFilter {
    /// Nothing passes.
    #[default]
    Off = 0,
    /// Only `Error`.
    Error = 1,
    /// `Error` and `Warn`.
    Warn = 2,
    /// Up to `Info`.
    Info = 3,
    /// Up to `Debug`.
    Debug = 4,
    /// Everything.
    Trace = 5,
}

const LEVEL_NAMES: [&str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

impl Level {
    /// Every level, most important first.
    pub const ALL: [Level; 5] = [
        Level::Error,
        Level::Warn,
        Level::Info,
        Level::Debug,
        Level::Trace,
    ];

    /// The upper-case name (`"ERROR"` ... `"TRACE"`).
    pub const fn as_str(self) -> &'static str {
        LEVEL_NAMES[self as usize]
    }

    /// The filter that lets this level and the more important ones through.
    pub const fn to_level_filter(self) -> LevelFilter {
        match self {
            Level::Error => LevelFilter::Error,
            Level::Warn => LevelFilter::Warn,
            Level::Info => LevelFilter::Info,
            Level::Debug => LevelFilter::Debug,
            Level::Trace => LevelFilter::Trace,
        }
    }
}

impl LevelFilter {
    /// The upper-case name (`"OFF"`, `"ERROR"` ... `"TRACE"`).
    pub const fn as_str(self) -> &'static str {
        LEVEL_NAMES[self as usize]
    }

    /// The most verbose level this filter lets through (`None` for `Off`).
    pub const fn to_level(self) -> Option<Level> {
        match self {
            LevelFilter::Off => None,
            LevelFilter::Error => Some(Level::Error),
            LevelFilter::Warn => Some(Level::Warn),
            LevelFilter::Info => Some(Level::Info),
            LevelFilter::Debug => Some(Level::Debug),
            LevelFilter::Trace => Some(Level::Trace),
        }
    }

    const fn from_usize(v: usize) -> LevelFilter {
        match v {
            0 => LevelFilter::Off,
            1 => LevelFilter::Error,
            2 => LevelFilter::Warn,
            3 => LevelFilter::Info,
            4 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }
}

impl From<Level> for LevelFilter {
    fn from(l: Level) -> LevelFilter {
        l.to_level_filter()
    }
}

impl PartialEq<LevelFilter> for Level {
    fn eq(&self, other: &LevelFilter) -> bool {
        *self as usize == *other as usize
    }
}

impl PartialOrd<LevelFilter> for Level {
    fn partial_cmp(&self, other: &LevelFilter) -> Option<std::cmp::Ordering> {
        (*self as usize).partial_cmp(&(*other as usize))
    }
}

impl PartialEq<Level> for LevelFilter {
    fn eq(&self, other: &Level) -> bool {
        *self as usize == *other as usize
    }
}

impl PartialOrd<Level> for LevelFilter {
    fn partial_cmp(&self, other: &Level) -> Option<std::cmp::Ordering> {
        (*self as usize).partial_cmp(&(*other as usize))
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl fmt::Display for LevelFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A level name that is not one of `error`, `warn`, `info`, `debug`, `trace` (or `off` for a
/// [`LevelFilter`]), compared case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseLevelError(());

impl fmt::Display for ParseLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown log level (expected off, error, warn, info, debug or trace)")
    }
}

impl Error for ParseLevelError {}

impl FromStr for LevelFilter {
    type Err = ParseLevelError;
    fn from_str(s: &str) -> Result<LevelFilter, ParseLevelError> {
        LEVEL_NAMES
            .iter()
            .position(|n| n.eq_ignore_ascii_case(s.trim()))
            .map(LevelFilter::from_usize)
            .ok_or(ParseLevelError(()))
    }
}

impl FromStr for Level {
    type Err = ParseLevelError;
    fn from_str(s: &str) -> Result<Level, ParseLevelError> {
        s.parse::<LevelFilter>()?
            .to_level()
            .ok_or(ParseLevelError(()))
    }
}

// ---- key-values -----------------------------------------------------------------------------

/// The value of a key-value pair: a primitive, a string, or anything `Display` / `Debug`,
/// borrowed for the duration of the log call.
#[derive(Clone, Copy)]
pub struct Value<'a>(ValueInner<'a>);

#[derive(Clone, Copy)]
enum ValueInner<'a> {
    Str(&'a str),
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    F64(f64),
    Bool(bool),
    Char(char),
    Display(&'a dyn fmt::Display),
    Debug(&'a dyn fmt::Debug),
}

impl<'a> Value<'a> {
    /// A value rendered with `v`'s `Display` (the `key:% = v` syntax).
    pub fn from_display<T: fmt::Display>(v: &'a T) -> Value<'a> {
        Value(ValueInner::Display(v))
    }

    /// A value rendered with `v`'s `Debug` (the `key:? = v` syntax).
    pub fn from_debug<T: fmt::Debug>(v: &'a T) -> Value<'a> {
        Value(ValueInner::Debug(v))
    }

    /// A value rendered with a `Display` trait object.
    pub fn from_dyn_display(v: &'a dyn fmt::Display) -> Value<'a> {
        Value(ValueInner::Display(v))
    }

    /// The string, if this value is one.
    pub fn to_str(&self) -> Option<&'a str> {
        match self.0 {
            ValueInner::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The number, if this value is an integer that fits.
    pub fn to_u64(&self) -> Option<u64> {
        match self.0 {
            ValueInner::U64(v) => Some(v),
            ValueInner::I64(v) => u64::try_from(v).ok(),
            ValueInner::U128(v) => u64::try_from(v).ok(),
            ValueInner::I128(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }

    /// The number, if this value is an integer that fits.
    pub fn to_i64(&self) -> Option<i64> {
        match self.0 {
            ValueInner::U64(v) => i64::try_from(v).ok(),
            ValueInner::I64(v) => Some(v),
            ValueInner::U128(v) => i64::try_from(v).ok(),
            ValueInner::I128(v) => i64::try_from(v).ok(),
            _ => None,
        }
    }

    /// The number, if this value is a float.
    pub fn to_f64(&self) -> Option<f64> {
        match self.0 {
            ValueInner::F64(v) => Some(v),
            _ => None,
        }
    }

    /// The flag, if this value is a `bool`.
    pub fn to_bool(&self) -> Option<bool> {
        match self.0 {
            ValueInner::Bool(v) => Some(v),
            _ => None,
        }
    }

    /// The character, if this value is a `char`.
    pub fn to_char(&self) -> Option<char> {
        match self.0 {
            ValueInner::Char(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ValueInner::Str(v) => fmt::Display::fmt(v, f),
            ValueInner::U64(v) => fmt::Display::fmt(&v, f),
            ValueInner::I64(v) => fmt::Display::fmt(&v, f),
            ValueInner::U128(v) => fmt::Display::fmt(&v, f),
            ValueInner::I128(v) => fmt::Display::fmt(&v, f),
            ValueInner::F64(v) => fmt::Display::fmt(&v, f),
            ValueInner::Bool(v) => fmt::Display::fmt(&v, f),
            ValueInner::Char(v) => fmt::Display::fmt(&v, f),
            ValueInner::Display(v) => fmt::Display::fmt(v, f),
            ValueInner::Debug(v) => fmt::Debug::fmt(v, f),
        }
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ValueInner::Str(v) => fmt::Debug::fmt(v, f),
            ValueInner::Char(v) => fmt::Debug::fmt(&v, f),
            ValueInner::F64(v) => fmt::Debug::fmt(&v, f),
            _ => fmt::Display::fmt(self, f),
        }
    }
}

/// Conversion into a [`Value`] (the `key = value` syntax of the macros).
pub trait ToValue {
    /// The value, borrowing `self`.
    fn to_value(&self) -> Value<'_>;
}

impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value<'_> {
        (**self).to_value()
    }
}

impl ToValue for Value<'_> {
    fn to_value(&self) -> Value<'_> {
        *self
    }
}

impl ToValue for str {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::Str(self))
    }
}

impl ToValue for String {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::Str(self))
    }
}

impl ToValue for bool {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::Bool(*self))
    }
}

impl ToValue for char {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::Char(*self))
    }
}

impl ToValue for f32 {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::F64(f64::from(*self)))
    }
}

impl ToValue for f64 {
    fn to_value(&self) -> Value<'_> {
        Value(ValueInner::F64(*self))
    }
}

macro_rules! to_value_int {
    ($variant:ident as $wide:ty: $($t:ty),*) => {$(
        impl ToValue for $t {
            fn to_value(&self) -> Value<'_> {
                Value(ValueInner::$variant(*self as $wide))
            }
        }
    )*};
}
to_value_int!(U64 as u64: u8, u16, u32, u64, usize);
to_value_int!(I64 as i64: i8, i16, i32, i64, isize);
to_value_int!(U128 as u128: u128);
to_value_int!(I128 as i128: i128);

/// The key-value pairs of a [`Record`], in the order they were written.
#[derive(Clone, Copy, Default)]
pub struct KeyValues<'a>(&'a [(&'a str, Value<'a>)]);

impl<'a> KeyValues<'a> {
    /// Wraps pairs (for building a [`Record`] by hand, e.g. to test a [`Logger`]).
    pub const fn new(pairs: &'a [(&'a str, Value<'a>)]) -> KeyValues<'a> {
        KeyValues(pairs)
    }

    /// The pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, Value<'a>)> + 'a {
        self.0.iter().copied()
    }

    /// The value of the first pair named `key`.
    pub fn get(&self, key: &str) -> Option<Value<'a>> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    /// How many pairs there are.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for KeyValues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

// ---- records --------------------------------------------------------------------------------

/// The level and target of a record: what [`Logger::enabled`] decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Metadata<'a> {
    level: Level,
    target: &'a str,
}

impl<'a> Metadata<'a> {
    /// Metadata for `level` and `target`.
    pub const fn new(level: Level, target: &'a str) -> Metadata<'a> {
        Metadata { level, target }
    }

    /// The level.
    pub const fn level(&self) -> Level {
        self.level
    }

    /// The target (`"only"`, `"only_http::access"`, a module path ...).
    pub const fn target(&self) -> &'a str {
        self.target
    }
}

/// One log record, passed to [`Logger::log`]. The message is formatted lazily: write
/// [`args`](Record::args) where it goes.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    metadata: Metadata<'a>,
    args: fmt::Arguments<'a>,
    kvs: KeyValues<'a>,
    module_path: Option<&'a str>,
    file: Option<&'a str>,
    line: Option<u32>,
}

impl<'a> Record<'a> {
    /// A record without key-values or source location (the macros fill both in).
    pub const fn new(level: Level, target: &'a str, args: fmt::Arguments<'a>) -> Record<'a> {
        Record {
            metadata: Metadata { level, target },
            args,
            kvs: KeyValues(&[]),
            module_path: None,
            file: None,
            line: None,
        }
    }

    /// Sets the key-values.
    #[must_use]
    pub const fn with_key_values(mut self, kvs: &'a [(&'a str, Value<'a>)]) -> Record<'a> {
        self.kvs = KeyValues(kvs);
        self
    }

    /// Sets the module path, file and line the record comes from.
    #[must_use]
    pub const fn with_location(
        mut self,
        module_path: Option<&'a str>,
        file: Option<&'a str>,
        line: Option<u32>,
    ) -> Record<'a> {
        self.module_path = module_path;
        self.file = file;
        self.line = line;
        self
    }

    /// Level and target.
    pub const fn metadata(&self) -> &Metadata<'a> {
        &self.metadata
    }

    /// The level.
    pub const fn level(&self) -> Level {
        self.metadata.level
    }

    /// The target.
    pub const fn target(&self) -> &'a str {
        self.metadata.target
    }

    /// The message, to be formatted (`write!(out, "{}", record.args())`).
    pub const fn args(&self) -> &fmt::Arguments<'a> {
        &self.args
    }

    /// The structured key-values.
    pub const fn key_values(&self) -> KeyValues<'a> {
        self.kvs
    }

    /// The module the record was logged from.
    pub const fn module_path(&self) -> Option<&'a str> {
        self.module_path
    }

    /// The source file the record was logged from.
    pub const fn file(&self) -> Option<&'a str> {
        self.file
    }

    /// The source line the record was logged from.
    pub const fn line(&self) -> Option<u32> {
        self.line
    }
}

// ---- the global logger ----------------------------------------------------------------------

/// A log sink. Install one per process with [`set_logger`] or [`set_boxed_logger`].
///
/// The facade calls [`enabled`](Logger::enabled) before [`log`](Logger::log), and only for
/// records within the global [`max_level`], so `log` does not need to filter again.
pub trait Logger: Send + Sync {
    /// Whether records with this metadata are wanted (default: all of them).
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let _ = metadata;
        true
    }

    /// Writes one record.
    fn log(&self, record: &Record<'_>);

    /// Flushes buffered records (default: nothing to do).
    fn flush(&self) {}
}

static LOGGER: OnceLock<&'static dyn Logger> = OnceLock::new();
static MAX_LEVEL: AtomicUsize = AtomicUsize::new(0);

/// A logger was already installed ([`set_logger`] succeeds once per process).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetLoggerError(());

impl fmt::Display for SetLoggerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a logger is already installed")
    }
}

impl Error for SetLoggerError {}

/// Installs the process-wide logger. Only the first call succeeds. Does not change
/// [`max_level`] (call [`set_max_level`], or use [`init`] / [`FmtLogger::init`], which do both).
pub fn set_logger(logger: &'static dyn Logger) -> Result<(), SetLoggerError> {
    LOGGER.set(logger).map_err(|_| SetLoggerError(()))
}

/// [`set_logger`] for a boxed logger (leaked once installed; dropped if one already is).
pub fn set_boxed_logger(logger: Box<dyn Logger>) -> Result<(), SetLoggerError> {
    if LOGGER.get().is_some() {
        return Err(SetLoggerError(()));
    }
    set_logger(Box::leak(logger))
}

/// The installed logger, if any.
pub fn logger() -> Option<&'static dyn Logger> {
    LOGGER.get().copied()
}

/// Sets the global maximum level. Records more verbose than it are skipped by the macros
/// before any argument is evaluated. With the `log` feature this also sets `log`'s maximum
/// level, so both facades filter alike.
pub fn set_max_level(level: LevelFilter) {
    MAX_LEVEL.store(level as usize, Ordering::Relaxed);
    #[cfg(feature = "log")]
    log::set_max_level(level.into());
}

/// The global maximum level ([`LevelFilter::Off`] until set). With the `log` feature and no
/// only-log logger installed, it is `log`'s maximum level (the records go there).
#[inline]
pub fn max_level() -> LevelFilter {
    LevelFilter::from_usize(__private::max_level_raw())
}

/// Whether a record of `level` and `target` would be written: within [`max_level`] and
/// accepted by the installed logger. `false` when no logger is installed (with the `log`
/// feature: asks `log`'s logger then).
#[inline]
pub fn enabled(level: Level, target: &str) -> bool {
    __private::enabled_fast(level) && __private::logger_enabled(level, target)
}

/// Flushes the installed logger.
pub fn flush() {
    if let Some(l) = logger() {
        l.flush();
    }
    #[cfg(feature = "log")]
    if logger().is_none() {
        log::logger().flush();
    }
}

/// Logs `args` at `level` under `target` when a logger accepts it ([`enabled`]), else prints
/// `target: message` to stderr, so the record is never lost silently. For rare, important
/// records (errors, fallbacks), not hot paths.
pub fn log_or_stderr(level: Level, target: &str, args: fmt::Arguments<'_>) {
    if enabled(level, target) {
        __private::log(args, level, &(target, "", ""), 0, &[]);
    } else {
        eprintln!("{target}: {args}");
    }
}

#[doc(hidden)]
pub mod __private {
    //! Macro support; not a public API.
    use super::{
        KeyValues, LOGGER, Level, MAX_LEVEL, Metadata, Ordering, Record, ToValue, Value, fmt,
    };

    pub use core::{file, format_args, line, module_path, stringify};

    /// The effective maximum level as a number (`Off` = 0 ... `Trace` = 5).
    #[inline(always)]
    pub fn max_level_raw() -> usize {
        #[cfg(feature = "log")]
        if LOGGER.get().is_none() {
            return log::max_level() as usize;
        }
        MAX_LEVEL.load(Ordering::Relaxed)
    }

    /// The macros' first check: `level` within the global maximum.
    #[inline(always)]
    pub fn enabled_fast(level: Level) -> bool {
        level as usize <= max_level_raw()
    }

    /// Whether the installed logger (or `log`'s, with the bridge) wants this record.
    pub fn logger_enabled(level: Level, target: &str) -> bool {
        if let Some(l) = LOGGER.get() {
            return l.enabled(&Metadata { level, target });
        }
        #[cfg(feature = "log")]
        return crate::bridge::log_enabled(level, target);
        #[cfg(not(feature = "log"))]
        false
    }

    #[inline(always)]
    pub fn value<T: ToValue + ?Sized>(v: &T) -> Value<'_> {
        v.to_value()
    }

    #[inline(always)]
    pub fn display<T: fmt::Display>(v: &T) -> Value<'_> {
        Value::from_display(v)
    }

    #[inline(always)]
    pub fn debug<T: fmt::Debug>(v: &T) -> Value<'_> {
        Value::from_debug(v)
    }

    /// Builds the record and hands it to the logger (after its `enabled` check).
    pub fn log(
        args: fmt::Arguments<'_>,
        level: Level,
        &(target, module_path, file): &(&str, &'static str, &'static str),
        line: u32,
        kvs: &[(&str, Value<'_>)],
    ) {
        let record = Record {
            metadata: Metadata { level, target },
            args,
            kvs: KeyValues(kvs),
            module_path: (!module_path.is_empty()).then_some(module_path),
            file: (!file.is_empty()).then_some(file),
            line: (line != 0).then_some(line),
        };
        match LOGGER.get() {
            Some(l) if l.enabled(&record.metadata) => l.log(&record),
            Some(_) => {}
            #[cfg(feature = "log")]
            None => crate::bridge::forward(&record),
            #[cfg(not(feature = "log"))]
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_order_parse_and_print_like_log() {
        assert!(Level::Error < Level::Trace);
        assert!(Level::Info <= LevelFilter::Info);
        assert!(Level::Debug > LevelFilter::Info);
        assert!(LevelFilter::Off < Level::Error);
        assert_eq!(LevelFilter::default(), LevelFilter::Off);
        for (i, f) in [
            LevelFilter::Off,
            LevelFilter::Error,
            LevelFilter::Warn,
            LevelFilter::Info,
            LevelFilter::Debug,
            LevelFilter::Trace,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(LevelFilter::from_usize(i), f);
            assert_eq!(f.as_str().parse::<LevelFilter>(), Ok(f));
            assert_eq!(f.as_str().to_lowercase().parse::<LevelFilter>(), Ok(f));
            assert_eq!(f.to_level().map_or(f, Level::to_level_filter), f);
        }
        assert_eq!("Warn".parse::<Level>(), Ok(Level::Warn));
        assert!("off".parse::<Level>().is_err());
        assert!("verbose".parse::<LevelFilter>().is_err());
        assert_eq!(format!("{:<5}|", Level::Info), "INFO |");
        assert_eq!(LevelFilter::Trace.to_string(), "TRACE");
        assert_eq!(Level::ALL.len(), 5);
    }

    #[test]
    fn values_render_and_convert() {
        let addr = std::net::SocketAddr::from(([10, 0, 0, 1], 80));
        let list = vec!["a", "b"];
        let kvs = [
            ("s", "text".to_value()),
            ("u", 7u16.to_value()),
            ("i", (-3i32).to_value()),
            ("b", true.to_value()),
            ("f", 1.5f64.to_value()),
            ("c", 'x'.to_value()),
            ("big", u128::MAX.to_value()),
            ("addr", Value::from_display(&addr)),
            ("list", Value::from_debug(&list)),
        ];
        let kv = KeyValues::new(&kvs);
        assert_eq!(kv.len(), 9);
        assert!(!kv.is_empty());
        let s = |k| kv.get(k).unwrap().to_string();
        assert_eq!(s("s"), "text");
        assert_eq!(s("u"), "7");
        assert_eq!(s("i"), "-3");
        assert_eq!(s("b"), "true");
        assert_eq!(s("f"), "1.5");
        assert_eq!(s("c"), "x");
        assert_eq!(s("big"), u128::MAX.to_string());
        assert_eq!(s("addr"), "10.0.0.1:80");
        assert_eq!(s("list"), r#"["a", "b"]"#);
        assert_eq!(kv.get("u").unwrap().to_u64(), Some(7));
        assert_eq!(kv.get("i").unwrap().to_i64(), Some(-3));
        assert_eq!(kv.get("i").unwrap().to_u64(), None);
        assert_eq!(kv.get("big").unwrap().to_u64(), None);
        assert_eq!(kv.get("b").unwrap().to_bool(), Some(true));
        assert_eq!(kv.get("f").unwrap().to_f64(), Some(1.5));
        assert_eq!(kv.get("c").unwrap().to_char(), Some('x'));
        assert_eq!(kv.get("s").unwrap().to_str(), Some("text"));
        assert_eq!(format!("{:?}", kv.get("s").unwrap()), r#""text""#);
        assert!(kv.get("missing").is_none());
        assert_eq!(
            kv.iter().map(|(k, _)| k).collect::<Vec<_>>()[..2],
            ["s", "u"]
        );
        let owned = String::from("own");
        assert_eq!(owned.to_value().to_str(), Some("own"));
        assert_eq!((&&5u8).to_value().to_u64(), Some(5));
    }

    #[test]
    fn records_built_by_hand() {
        let kvs = [("k", 1u8.to_value())];
        let check = |r: Record<'_>| {
            assert_eq!(r.level(), Level::Warn);
            assert_eq!(r.target(), "t");
            assert_eq!(r.args().to_string(), "m 1");
            assert_eq!(r.key_values().len(), 1);
            assert_eq!(
                (r.module_path(), r.file(), r.line()),
                (Some("m"), Some("f.rs"), Some(3))
            );
            assert_eq!(*r.metadata(), Metadata::new(Level::Warn, "t"));
            assert!(format!("{r:?}").contains("Warn"));
        };
        check(
            Record::new(Level::Warn, "t", format_args!("m {}", 1))
                .with_key_values(&kvs)
                .with_location(Some("m"), Some("f.rs"), Some(3)),
        );
    }
}
