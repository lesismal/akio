//! The logging macros (the `log` crate's syntax: `target:`, key-values before `;`).

/// Logs a record at a given level.
///
/// ```
/// use only_log::{Level, log};
/// let level = Level::Warn;
/// log!(target: "app", level, attempt = 3u32, peer:% = "10.0.0.1:80"; "retrying {}", "now");
/// log!(level, "no target: the module path is used");
/// ```
#[macro_export]
macro_rules! log {
    (target: $target:expr, $lvl:expr, $($key:ident $(:$cap:tt)? = $value:expr),+ ; $($arg:tt)+) => {{
        let __lvl: $crate::Level = $lvl;
        if $crate::__private::enabled_fast(__lvl) {
            $crate::__private::log(
                $crate::__private::format_args!($($arg)+),
                __lvl,
                &($target, $crate::__private::module_path!(), $crate::__private::file!()),
                $crate::__private::line!(),
                &[$(($crate::__private::stringify!($key), $crate::__log_value!($($cap)? ; $value))),+],
            );
        }
    }};
    (target: $target:expr, $lvl:expr, $($arg:tt)+) => {{
        let __lvl: $crate::Level = $lvl;
        if $crate::__private::enabled_fast(__lvl) {
            $crate::__private::log(
                $crate::__private::format_args!($($arg)+),
                __lvl,
                &($target, $crate::__private::module_path!(), $crate::__private::file!()),
                $crate::__private::line!(),
                &[],
            );
        }
    }};
    ($lvl:expr, $($arg:tt)+) => {
        $crate::log!(target: $crate::__private::module_path!(), $lvl, $($arg)+)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __log_value {
    (% ; $v:expr) => {
        $crate::__private::display(&$v)
    };
    (? ; $v:expr) => {
        $crate::__private::debug(&$v)
    };
    (; $v:expr) => {
        $crate::__private::value(&$v)
    };
}

/// Logs a record at [`Level::Error`](crate::Level::Error). See [`log!`](crate::log!).
#[macro_export]
macro_rules! error {
    (target: $target:expr, $($arg:tt)+) => { $crate::log!(target: $target, $crate::Level::Error, $($arg)+) };
    ($($arg:tt)+) => { $crate::log!(target: $crate::__private::module_path!(), $crate::Level::Error, $($arg)+) };
}

/// Logs a record at [`Level::Warn`](crate::Level::Warn). See [`log!`](crate::log!).
#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($arg:tt)+) => { $crate::log!(target: $target, $crate::Level::Warn, $($arg)+) };
    ($($arg:tt)+) => { $crate::log!(target: $crate::__private::module_path!(), $crate::Level::Warn, $($arg)+) };
}

/// Logs a record at [`Level::Info`](crate::Level::Info). See [`log!`](crate::log!).
#[macro_export]
macro_rules! info {
    (target: $target:expr, $($arg:tt)+) => { $crate::log!(target: $target, $crate::Level::Info, $($arg)+) };
    ($($arg:tt)+) => { $crate::log!(target: $crate::__private::module_path!(), $crate::Level::Info, $($arg)+) };
}

/// Logs a record at [`Level::Debug`](crate::Level::Debug). See [`log!`](crate::log!).
#[macro_export]
macro_rules! debug {
    (target: $target:expr, $($arg:tt)+) => { $crate::log!(target: $target, $crate::Level::Debug, $($arg)+) };
    ($($arg:tt)+) => { $crate::log!(target: $crate::__private::module_path!(), $crate::Level::Debug, $($arg)+) };
}

/// Logs a record at [`Level::Trace`](crate::Level::Trace). See [`log!`](crate::log!).
#[macro_export]
macro_rules! trace {
    (target: $target:expr, $($arg:tt)+) => { $crate::log!(target: $target, $crate::Level::Trace, $($arg)+) };
    ($($arg:tt)+) => { $crate::log!(target: $crate::__private::module_path!(), $crate::Level::Trace, $($arg)+) };
}

/// Whether a record of this level (and target, default: the module path) would be written:
/// within [`max_level`](crate::max_level) (checked first, one atomic load) and accepted by the
/// installed logger. Use it to skip expensive preparation of key-values.
///
/// ```
/// use only_log::{Level, log_enabled};
/// if log_enabled!(target: "app", Level::Debug) { /* gather details */ }
/// let _ = log_enabled!(Level::Trace);
/// ```
#[macro_export]
macro_rules! log_enabled {
    (target: $target:expr, $lvl:expr) => {{
        let __lvl: $crate::Level = $lvl;
        $crate::__private::enabled_fast(__lvl) && $crate::__private::logger_enabled(__lvl, $target)
    }};
    ($lvl:expr) => {
        $crate::log_enabled!(target: $crate::__private::module_path!(), $lvl)
    };
}
