//! Per-target level filters and their text syntax ([`Filter`], `ONLY_LOG=info,only_http=debug`).

use std::{error::Error, fmt, str::FromStr};

use crate::{LevelFilter, Metadata};

/// The environment variable [`init_from_env`](crate::init_from_env) and
/// [`Filter::from_env`] read.
pub const ENV_VAR: &str = "ONLY_LOG";

/// A level per target, plus a level for every other target: what decides whether a record is
/// written. Parsed from env_logger-style directives, or built with [`new`](Filter::new) and
/// [`directive`](Filter::directive).
///
/// Syntax: comma-separated directives, each one of
///
/// - `level`: the level of targets no other directive matches (`off`, `error`, `warn`, `info`,
///   `debug`, `trace`, any case);
/// - `target=level`: the level of `target` and of its submodules (`target::...`);
/// - `target`: `target` and its submodules at `trace`.
///
/// ```
/// use only_log::{Filter, Level, LevelFilter, Metadata};
///
/// let f: Filter = "info,only_http=debug,only_quic::conn=trace,only_http::access=off".parse().unwrap();
/// let on = |l, t| f.enabled(&Metadata::new(l, t));
/// assert!(on(Level::Info, "app"));
/// assert!(!on(Level::Debug, "app"));
/// assert!(on(Level::Debug, "only_http::server"));
/// assert!(!on(Level::Error, "only_http::access"));
/// assert!(on(Level::Trace, "only_quic::conn"));
/// assert!(!on(Level::Trace, "only_quic::stream"));
/// assert_eq!(f.max_level(), LevelFilter::Trace); // what the global maximum must let through
/// ```
///
/// Differences from env_logger: a target matches itself and `target::...` only (`only` does
/// not match `only_http`; env_logger matches any string prefix), the most specific (longest)
/// matching target wins whatever the order, and a `/regex` message filter is rejected. Without
/// a bare `level`, targets no directive names are off, as with env_logger. When a directive
/// repeats a target (or a bare level appears twice), the last one wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    default: LevelFilter,
    targets: Vec<(String, LevelFilter)>,
}

impl Default for Filter {
    /// Everything at `trace`: the filter leaves the decision to the global maximum level.
    fn default() -> Filter {
        Filter::new(LevelFilter::Trace)
    }
}

impl Filter {
    /// A filter that lets `default` through for every target.
    pub fn new(default: LevelFilter) -> Filter {
        Filter {
            default,
            targets: Vec::new(),
        }
    }

    /// Sets the level of `target` and its submodules (`target::...`), replacing an earlier one
    /// for the same target.
    #[must_use]
    pub fn directive(mut self, target: impl Into<String>, level: LevelFilter) -> Filter {
        let target = target.into();
        match self.targets.iter_mut().find(|(t, _)| *t == target) {
            Some(slot) => slot.1 = level,
            None => self.targets.push((target, level)),
        }
        self
    }

    /// Sets the level of targets no directive matches.
    #[must_use]
    pub fn default_level(mut self, level: LevelFilter) -> Filter {
        self.default = level;
        self
    }

    /// Parses the directives in the environment variable `var` (`ONLY_LOG` is [`ENV_VAR`]):
    /// `None` when it is unset or blank (or not UTF-8), else the parse result.
    pub fn from_env(var: &str) -> Option<Result<Filter, ParseFilterError>> {
        let v = std::env::var(var).ok()?;
        (!v.trim().is_empty()).then(|| v.parse())
    }

    /// The level that applies to `target`: that of the longest directive matching it, else the
    /// default.
    pub fn level_for(&self, target: &str) -> LevelFilter {
        let mut best: Option<(usize, LevelFilter)> = None;
        for (p, l) in &self.targets {
            let hit = target == p
                || (target.len() > p.len()
                    && target.starts_with(p.as_str())
                    && target[p.len()..].starts_with("::"));
            if hit && best.is_none_or(|(n, _)| p.len() > n) {
                best = Some((p.len(), *l));
            }
        }
        best.map_or(self.default, |(_, l)| l)
    }

    /// Whether a record with this metadata passes (its level within [`level_for`]).
    ///
    /// [`level_for`]: Filter::level_for
    pub fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level_for(metadata.target())
    }

    /// The most verbose level any target is allowed: the global maximum level to set
    /// ([`set_max_level`](crate::set_max_level)) so that every record the filter accepts
    /// reaches the logger.
    pub fn max_level(&self) -> LevelFilter {
        self.targets
            .iter()
            .map(|(_, l)| *l)
            .fold(self.default, LevelFilter::max)
    }

    /// The level of targets no directive matches.
    pub fn default_level_filter(&self) -> LevelFilter {
        self.default
    }

    /// The per-target directives, in the order they were first given.
    pub fn directives(&self) -> impl Iterator<Item = (&str, LevelFilter)> {
        self.targets.iter().map(|(t, l)| (t.as_str(), *l))
    }
}

impl FromStr for Filter {
    type Err = ParseFilterError;

    /// Parses `info,only_http=debug,...` (see [`Filter`]). With no bare level, targets that no
    /// directive names are off.
    fn from_str(s: &str) -> Result<Filter, ParseFilterError> {
        let mut f = Filter::new(LevelFilter::Off);
        for d in s.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            if d.contains('/') {
                return Err(ParseFilterError::new(
                    d,
                    "message filters (`/regex`) are not supported",
                ));
            }
            match d.split_once('=') {
                Some((t, l)) => {
                    let t = t.trim();
                    let l: LevelFilter = l
                        .parse()
                        .map_err(|_| ParseFilterError::new(d, "unknown level"))?;
                    if t.is_empty() {
                        return Err(ParseFilterError::new(d, "empty target"));
                    }
                    f = f.directive(t, l);
                }
                None => match d.parse::<LevelFilter>() {
                    Ok(l) => f.default = l,
                    Err(_) if valid_target(d) => f = f.directive(d, LevelFilter::Trace),
                    Err(_) => return Err(ParseFilterError::new(d, "not a level or a target")),
                },
            }
        }
        Ok(f)
    }
}

/// A target name: what a module path or a `target:` string usually is.
fn valid_target(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-' | b'.'))
}

impl fmt::Display for Filter {
    /// The directive syntax, which parses back to an equal filter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.default.as_str().to_ascii_lowercase();
        f.write_str(&d)?;
        for (t, l) in &self.targets {
            write!(f, ",{t}={}", l.as_str().to_ascii_lowercase())?;
        }
        Ok(())
    }
}

/// A directive [`Filter`] could not parse: which one and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseFilterError {
    directive: String,
    reason: &'static str,
}

impl ParseFilterError {
    fn new(directive: &str, reason: &'static str) -> ParseFilterError {
        ParseFilterError {
            directive: directive.to_owned(),
            reason,
        }
    }

    /// The directive that failed.
    pub fn directive(&self) -> &str {
        &self.directive
    }
}

impl fmt::Display for ParseFilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid log directive `{}`: {}",
            self.directive, self.reason
        )
    }
}

impl Error for ParseFilterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Level;

    fn on(f: &Filter, l: Level, t: &str) -> bool {
        f.enabled(&Metadata::new(l, t))
    }

    #[test]
    fn parses_env_logger_directives() {
        let f: Filter = " info , only_http=DEBUG,only_quic::conn=trace,only_http::access=off,app "
            .parse()
            .unwrap();
        assert_eq!(f.default_level_filter(), LevelFilter::Info);
        assert!(on(&f, Level::Info, "other"));
        assert!(!on(&f, Level::Debug, "other"));
        assert!(on(&f, Level::Debug, "only_http"));
        assert!(on(&f, Level::Debug, "only_http::server::h1"));
        assert!(!on(&f, Level::Trace, "only_http"));
        assert!(!on(&f, Level::Error, "only_http::access"));
        assert!(!on(&f, Level::Error, "only_http::access::x"));
        assert!(on(&f, Level::Info, "only_http::accessor")); // segment boundary
        assert!(on(&f, Level::Trace, "only_quic::conn"));
        assert!(!on(&f, Level::Debug, "only_quic"));
        assert!(on(&f, Level::Trace, "app::db")); // bare target: trace
        assert!(!on(&f, Level::Debug, "only_http2")); // not a module of only_http
        assert_eq!(f.max_level(), LevelFilter::Trace);
        assert_eq!(f.to_string().parse::<Filter>().unwrap(), f);
    }

    #[test]
    fn defaults_overrides_and_errors() {
        let f: Filter = "only=debug".parse().unwrap();
        assert_eq!(f.default_level_filter(), LevelFilter::Off);
        assert!(!on(&f, Level::Error, "app"));
        assert_eq!(f.max_level(), LevelFilter::Debug);
        let f: Filter = "warn,a=info,a=error,debug".parse().unwrap();
        assert_eq!(f.default_level_filter(), LevelFilter::Debug);
        assert_eq!(
            f.directives().collect::<Vec<_>>(),
            [("a", LevelFilter::Error)]
        );
        assert_eq!("".parse::<Filter>().unwrap(), Filter::new(LevelFilter::Off));
        assert_eq!(
            ",,".parse::<Filter>().unwrap().max_level(),
            LevelFilter::Off
        );
        for bad in ["a=loud", "=info", "info/foo", "a b", "a=info=x"] {
            let e = bad.parse::<Filter>().unwrap_err();
            assert!(
                e.to_string().contains("invalid log directive"),
                "{bad}: {e}"
            );
            assert!(!e.directive().is_empty());
        }
        let f = Filter::default().directive("x", LevelFilter::Off);
        assert!(on(&f, Level::Trace, "y"));
        assert!(!on(&f, Level::Error, "x::y"));
        let f = f.default_level(LevelFilter::Warn);
        assert_eq!(f.level_for("z"), LevelFilter::Warn);
    }

    #[test]
    fn unset_variable() {
        // Set variables are covered by tests/env_filter.rs (a child process with ONLY_LOG set:
        // `std::env::set_var` is unsafe in edition 2024 and this crate forbids unsafe code).
        assert!(Filter::from_env("ONLY_LOG_FILTER_UNIT_TEST_UNSET").is_none());
        assert_eq!(ENV_VAR, "ONLY_LOG");
    }
}
