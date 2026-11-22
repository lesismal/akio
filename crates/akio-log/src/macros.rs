//! The logging macros (the `log` crate's syntax: `target:`, key-values before `;`).

/// Logs a record at a given level.
///
/// ```
/// use akio_log::{Level, log};
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
/// use akio_log::{Level, log_enabled};
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

/// Starts a [`Span`](crate::span::Span) of a given level, with fields in the key-value syntax of
/// [`log!`](crate::log!) (no `;`, no message). Returns
/// [`Span::none`](crate::span::Span::none) after one level check when spans of that level are
/// off ([`max_span_level`](crate::span::max_span_level)).
///
/// ```
/// use akio_log::{Level, span};
/// let s = span!(target: "app", Level::Info, "handle", conn_id = 7u64, peer:% = "10.0.0.1:80");
/// let remote = akio_log::span::SpanContext::from_traceparent(
///     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
/// let child = span!(parent: remote, Level::Debug, "decode");
/// # drop((s, child));
/// ```
#[macro_export]
macro_rules! span {
    (target: $target:expr, parent: $parent:expr, $lvl:expr, $name:expr $(, $key:ident $(:$cap:tt)? = $value:expr)* $(,)?) => {{
        let __lvl: $crate::Level = $lvl;
        if $crate::span::enabled(__lvl) {
            $crate::span::Span::__macro_start(
                __lvl,
                $target,
                $name,
                $crate::span::Parent::Explicit($parent),
                &[$(($crate::__private::stringify!($key), $crate::__log_value!($($cap)? ; $value))),*],
            )
        } else {
            $crate::span::Span::none()
        }
    }};
    (target: $target:expr, $lvl:expr, $name:expr $(, $key:ident $(:$cap:tt)? = $value:expr)* $(,)?) => {{
        let __lvl: $crate::Level = $lvl;
        if $crate::span::enabled(__lvl) {
            $crate::span::Span::__macro_start(
                __lvl,
                $target,
                $name,
                $crate::span::Parent::Current,
                &[$(($crate::__private::stringify!($key), $crate::__log_value!($($cap)? ; $value))),*],
            )
        } else {
            $crate::span::Span::none()
        }
    }};
    (parent: $parent:expr, $lvl:expr, $name:expr $(, $($rest:tt)*)?) => {
        $crate::span!(target: $crate::__private::module_path!(), parent: $parent, $lvl, $name $(, $($rest)*)?)
    };
    ($lvl:expr, $name:expr $(, $($rest:tt)*)?) => {
        $crate::span!(target: $crate::__private::module_path!(), $lvl, $name $(, $($rest)*)?)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __level_span {
    ($lvl:expr; target: $target:expr, parent: $parent:expr, $($rest:tt)+) => {
        $crate::span!(target: $target, parent: $parent, $lvl, $($rest)+)
    };
    ($lvl:expr; target: $target:expr, $($rest:tt)+) => {
        $crate::span!(target: $target, $lvl, $($rest)+)
    };
    ($lvl:expr; parent: $parent:expr, $($rest:tt)+) => {
        $crate::span!(parent: $parent, $lvl, $($rest)+)
    };
    ($lvl:expr; $($rest:tt)+) => {
        $crate::span!($lvl, $($rest)+)
    };
}

/// [`span!`](crate::span!) at [`Level::Error`](crate::Level::Error).
#[macro_export]
macro_rules! error_span {
    ($($arg:tt)+) => { $crate::__level_span!($crate::Level::Error; $($arg)+) };
}

/// [`span!`](crate::span!) at [`Level::Warn`](crate::Level::Warn).
#[macro_export]
macro_rules! warn_span {
    ($($arg:tt)+) => { $crate::__level_span!($crate::Level::Warn; $($arg)+) };
}

/// [`span!`](crate::span!) at [`Level::Info`](crate::Level::Info).
#[macro_export]
macro_rules! info_span {
    ($($arg:tt)+) => { $crate::__level_span!($crate::Level::Info; $($arg)+) };
}

/// [`span!`](crate::span!) at [`Level::Debug`](crate::Level::Debug).
#[macro_export]
macro_rules! debug_span {
    ($($arg:tt)+) => { $crate::__level_span!($crate::Level::Debug; $($arg)+) };
}

/// [`span!`](crate::span!) at [`Level::Trace`](crate::Level::Trace).
#[macro_export]
macro_rules! trace_span {
    ($($arg:tt)+) => { $crate::__level_span!($crate::Level::Trace; $($arg)+) };
}
