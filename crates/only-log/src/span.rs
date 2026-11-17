//! Spans: timed, nested units of work with fields, exported by a [`Tracer`].
//!
//! A span has a name, a level and target (filtered like log records, but against their own
//! maximum, [`max_span_level`], which is [`LevelFilter::Off`] until set), a [`SpanContext`]
//! (W3C trace id and span id), an optional parent, fields, a kind and a status. It starts when
//! it is created and ends when it is dropped (or [`Span::end`] is called); the finished span
//! ([`SpanData`]) goes to the installed [`Tracer`].
//!
//! ```
//! use only_log::info_span;
//!
//! let span = info_span!(target: "app", "load_user", user_id = 42u64);
//! {
//!     let _in = span.enter(); // spans created here are its children
//!     let mut child = info_span!("query", table = "users");
//!     child.record("rows", 1u64);
//! } // `child` ends here, then the guard restores the previous current span
//! drop(span);
//! ```
//!
//! # Cost when disabled
//!
//! The macros compare the level with the compile-time cap ([`STATIC_MAX_LEVEL`]) and
//! [`max_span_level`] (one relaxed atomic load) before they evaluate anything, and return
//! [`Span::none`], which is a null pointer: recording into it, entering it and dropping it do
//! nothing. Spans are independent of logging: turning logs on does not turn spans on.
//!
//! # Parents and propagation
//!
//! A new span's parent is, in order: the one given with `parent:` (a [`SpanContext`], possibly
//! remote, e.g. from an incoming `traceparent` header, see [`SpanContext::from_traceparent`]),
//! else the span entered on this thread ([`Span::enter`], [`current`]), else none (a new trace).
//! Entering is a thread-local swap; on an event loop, enter a span only around the code that
//! runs for it, never across callbacks.
//!
//! Sampling is decided once per trace, by [`Tracer::sample`] for a root (or remote-parent)
//! span; children of a local span follow their parent. An unsampled span still carries a
//! context (so its children and outgoing `traceparent` headers stay unsampled) but records
//! nothing.

use std::{
    borrow::Cow,
    cell::Cell,
    collections::hash_map::RandomState,
    error::Error,
    fmt,
    hash::{BuildHasher, Hasher},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime},
};

use crate::{Level, LevelFilter, Metadata, STATIC_MAX_LEVEL, Value, ValueInner};

// ---- span context ---------------------------------------------------------------------------

/// The identity of a span: W3C trace id and span id, the sampled flag, and whether it came from
/// another process (a remote parent).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanContext {
    trace_id: u128,
    span_id: u64,
    flags: u8,
    remote: bool,
}

const FLAG_SAMPLED: u8 = 1;

impl SpanContext {
    /// A context; `None` when either id is zero (invalid in W3C Trace Context).
    pub fn new(trace_id: u128, span_id: u64, sampled: bool, remote: bool) -> Option<SpanContext> {
        (trace_id != 0 && span_id != 0).then_some(SpanContext {
            trace_id,
            span_id,
            flags: if sampled { FLAG_SAMPLED } else { 0 },
            remote,
        })
    }

    /// The 128-bit trace id (never zero).
    pub const fn trace_id(&self) -> u128 {
        self.trace_id
    }

    /// The 64-bit span id (never zero).
    pub const fn span_id(&self) -> u64 {
        self.span_id
    }

    /// Whether the trace is sampled (recorded).
    pub const fn is_sampled(&self) -> bool {
        self.flags & FLAG_SAMPLED != 0
    }

    /// Whether the context was received from another process.
    pub const fn is_remote(&self) -> bool {
        self.remote
    }

    /// The trace flags byte (`01` = sampled).
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Parses a W3C `traceparent` header value (`00-<32 hex>-<16 hex>-<2 hex>`); the result is
    /// remote. Unknown versions are accepted as long as the first four fields parse (as the
    /// specification asks); version `ff`, zero ids and malformed values are `None`.
    pub fn from_traceparent(value: &str) -> Option<SpanContext> {
        let v = value.trim().as_bytes();
        if v.len() < 55 || (v.len() > 55 && (v[0..2] == *b"00" || v[55] != b'-')) {
            return None;
        }
        if v[2] != b'-' || v[35] != b'-' || v[52] != b'-' {
            return None;
        }
        let version = hex_u128(&v[0..2])? as u8;
        if version == 0xff {
            return None;
        }
        let trace_id = hex_u128(&v[3..35])?;
        let span_id = hex_u128(&v[36..52])? as u64;
        let flags = hex_u128(&v[53..55])? as u8;
        let mut c = SpanContext::new(trace_id, span_id, false, true)?;
        c.flags = flags;
        Some(c)
    }

    /// The `traceparent` header value (version `00`).
    pub fn to_traceparent(&self) -> String {
        let mut s = String::with_capacity(55);
        let _ = fmt::Write::write_fmt(
            &mut s,
            format_args!(
                "00-{:032x}-{:016x}-{:02x}",
                self.trace_id, self.span_id, self.flags
            ),
        );
        s
    }
}

impl fmt::Debug for SpanContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanContext")
            .field("trace_id", &format_args!("{:032x}", self.trace_id))
            .field("span_id", &format_args!("{:016x}", self.span_id))
            .field("sampled", &self.is_sampled())
            .field("remote", &self.remote)
            .finish()
    }
}

/// Lower-case or upper-case hex, at most 32 digits.
fn hex_u128(s: &[u8]) -> Option<u128> {
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let mut v = 0u128;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u128::from(d);
    }
    Some(v)
}

// ---- ids ------------------------------------------------------------------------------------

thread_local! {
    static RNG: Cell<u64> = const { Cell::new(0) };
    static CURRENT: Cell<Option<SpanContext>> = const { Cell::new(None) };
}

/// A random non-zero `u64` (splitmix64 over a per-thread state seeded from the process'
/// random hash keys, the time and the thread id). Fast and unique enough for ids; not for secrets.
fn random_u64() -> u64 {
    RNG.with(|s| {
        let mut x = s.get();
        if x == 0 {
            let mut h = RandomState::new().build_hasher();
            h.write_u128(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
            );
            std::hash::Hash::hash(&std::thread::current().id(), &mut h);
            x = h.finish() | 1;
        }
        loop {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            s.set(x);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            if z != 0 {
                return z;
            }
        }
    })
}

/// The span entered on this thread ([`Span::enter`]), if any.
pub fn current() -> Option<SpanContext> {
    CURRENT.with(Cell::get)
}

// ---- field values ---------------------------------------------------------------------------

/// An owned span field value.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum FieldValue {
    /// A string.
    Str(Cow<'static, str>),
    /// A signed integer.
    I64(i64),
    /// An unsigned integer.
    U64(u64),
    /// A float.
    F64(f64),
    /// A flag.
    Bool(bool),
}

impl FieldValue {
    /// Converts a borrowed log [`Value`] (strings and `Display` / `Debug` values are copied).
    pub fn from_value(v: Value<'_>) -> FieldValue {
        match v.0 {
            ValueInner::Str(s) => FieldValue::Str(Cow::Owned(s.to_owned())),
            ValueInner::U64(v) => FieldValue::U64(v),
            ValueInner::I64(v) => FieldValue::I64(v),
            ValueInner::U128(v) => u64::try_from(v)
                .map_or_else(|_| FieldValue::Str(v.to_string().into()), FieldValue::U64),
            ValueInner::I128(v) => i64::try_from(v)
                .map_or_else(|_| FieldValue::Str(v.to_string().into()), FieldValue::I64),
            ValueInner::F64(v) => FieldValue::F64(v),
            ValueInner::Bool(v) => FieldValue::Bool(v),
            ValueInner::Char(c) => FieldValue::Str(c.to_string().into()),
            ValueInner::Display(_) | ValueInner::Debug(_) => FieldValue::Str(v.to_string().into()),
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Str(s) => f.write_str(s),
            FieldValue::I64(v) => fmt::Display::fmt(v, f),
            FieldValue::U64(v) => fmt::Display::fmt(v, f),
            FieldValue::F64(v) => fmt::Display::fmt(v, f),
            FieldValue::Bool(v) => fmt::Display::fmt(v, f),
        }
    }
}

impl From<&'static str> for FieldValue {
    fn from(s: &'static str) -> FieldValue {
        FieldValue::Str(Cow::Borrowed(s))
    }
}

impl From<String> for FieldValue {
    fn from(s: String) -> FieldValue {
        FieldValue::Str(Cow::Owned(s))
    }
}

impl From<Cow<'static, str>> for FieldValue {
    fn from(s: Cow<'static, str>) -> FieldValue {
        FieldValue::Str(s)
    }
}

impl From<bool> for FieldValue {
    fn from(v: bool) -> FieldValue {
        FieldValue::Bool(v)
    }
}

impl From<f64> for FieldValue {
    fn from(v: f64) -> FieldValue {
        FieldValue::F64(v)
    }
}

macro_rules! field_int {
    ($variant:ident as $wide:ty: $($t:ty),*) => {$(
        impl From<$t> for FieldValue {
            fn from(v: $t) -> FieldValue {
                FieldValue::$variant(v as $wide)
            }
        }
    )*};
}
field_int!(U64 as u64: u8, u16, u32, u64, usize);
field_int!(I64 as i64: i8, i16, i32, i64, isize);

// ---- finished spans -------------------------------------------------------------------------

/// What a span represents (OpenTelemetry's `SpanKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum SpanKind {
    /// Work inside the process.
    #[default]
    Internal,
    /// The server side of a request (an HTTP request served, a connection accepted).
    Server,
    /// The client side of a request.
    Client,
    /// A message sent for later processing.
    Producer,
    /// A message received for processing.
    Consumer,
}

/// The outcome of a span.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SpanStatus {
    /// Not set (the default: neither success nor failure was recorded).
    #[default]
    Unset,
    /// Explicitly successful.
    Ok,
    /// Failed, with a description.
    Error(Cow<'static, str>),
}

/// A finished span, handed to [`Tracer::on_end`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SpanData {
    /// The name (`"GET /users/:id"`, `"query"` ...).
    pub name: Cow<'static, str>,
    /// The target (a module path unless given).
    pub target: &'static str,
    /// The level.
    pub level: Level,
    /// The kind.
    pub kind: SpanKind,
    /// The span's own context.
    pub context: SpanContext,
    /// The parent's context, if any (remote when it came from another process).
    pub parent: Option<SpanContext>,
    /// Wall-clock start.
    pub start: SystemTime,
    /// Wall-clock end (the start plus the monotonic duration).
    pub end: SystemTime,
    /// The fields, in the order they were recorded (a key recorded twice keeps its last value).
    pub fields: Vec<(Cow<'static, str>, FieldValue)>,
    /// The status.
    pub status: SpanStatus,
}

impl SpanData {
    /// The value of the field `key`.
    pub fn field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// How long the span lasted.
    pub fn duration(&self) -> std::time::Duration {
        self.end.duration_since(self.start).unwrap_or_default()
    }
}

// ---- the tracer -----------------------------------------------------------------------------

/// A span sink. Install one per process with [`set_tracer`] / [`set_boxed_tracer`], and set
/// [`set_max_span_level`] (spans are off until then).
///
/// Called on the thread that ends the span (an I/O thread for request spans): `on_end` must
/// not block. Queue the span and export it from another thread (`only-export` does).
pub trait Tracer: Send + Sync {
    /// Whether spans with this metadata are wanted (default: all of them within the level).
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let _ = metadata;
        true
    }

    /// Whether a new trace (or a span with a remote parent) is sampled. The default follows a
    /// remote parent's flag and samples every new trace.
    fn sample(&self, trace_id: u128, parent: Option<&SpanContext>) -> bool {
        let _ = trace_id;
        parent.is_none_or(SpanContext::is_sampled)
    }

    /// Receives a finished, sampled span.
    fn on_end(&self, span: SpanData);
}

static TRACER: OnceLock<&'static dyn Tracer> = OnceLock::new();
static SPAN_MAX: AtomicUsize = AtomicUsize::new(0);

/// A tracer was already installed ([`set_tracer`] succeeds once per process).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetTracerError(());

impl fmt::Display for SetTracerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a tracer is already installed")
    }
}

impl Error for SetTracerError {}

/// Installs the process-wide tracer. Only the first call succeeds. Does not change
/// [`max_span_level`].
pub fn set_tracer(tracer: &'static dyn Tracer) -> Result<(), SetTracerError> {
    TRACER.set(tracer).map_err(|_| SetTracerError(()))
}

/// [`set_tracer`] for a boxed tracer (leaked once installed; dropped if one already is).
pub fn set_boxed_tracer(tracer: Box<dyn Tracer>) -> Result<(), SetTracerError> {
    if TRACER.get().is_some() {
        return Err(SetTracerError(()));
    }
    set_tracer(Box::leak(tracer))
}

/// The installed tracer, if any.
pub fn tracer() -> Option<&'static dyn Tracer> {
    TRACER.get().copied()
}

/// Sets the maximum span level. Spans more verbose than it are not created: the macros return
/// [`Span::none`] after one atomic load.
pub fn set_max_span_level(level: LevelFilter) {
    SPAN_MAX.store(level as usize, Ordering::Relaxed);
}

/// The maximum span level ([`LevelFilter::Off`] until set).
pub fn max_span_level() -> LevelFilter {
    LevelFilter::from_usize(SPAN_MAX.load(Ordering::Relaxed))
}

/// Whether a span of `level` would be created now: within the compile-time cap and
/// [`max_span_level`]. One relaxed atomic load; the tracer's own filter is asked later, when
/// the span is started.
#[inline(always)]
pub fn enabled(level: Level) -> bool {
    level as usize <= STATIC_MAX_LEVEL as usize
        && level as usize <= SPAN_MAX.load(Ordering::Relaxed)
}

// ---- spans ----------------------------------------------------------------------------------

/// Where a new span's parent comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Parent {
    /// The span entered on this thread, if any (the default).
    #[default]
    Current,
    /// No parent: a new trace.
    Root,
    /// This context (local or remote); `None` means a new trace.
    Explicit(Option<SpanContext>),
}

struct Inner {
    ctx: SpanContext,
    rec: Option<Recording>,
}

struct Recording {
    name: Cow<'static, str>,
    target: &'static str,
    level: Level,
    kind: SpanKind,
    parent: Option<SpanContext>,
    start: SystemTime,
    t0: Instant,
    fields: Vec<(Cow<'static, str>, FieldValue)>,
    status: SpanStatus,
}

/// A span in progress; ends when dropped (or with [`Span::end`]). A disabled span
/// ([`Span::none`]) is a null pointer and every method on it does nothing.
#[derive(Default)]
pub struct Span(Option<Box<Inner>>);

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => f.write_str("Span(none)"),
            Some(i) => f
                .debug_struct("Span")
                .field("context", &i.ctx)
                .field("recording", &i.rec.is_some())
                .finish(),
        }
    }
}

/// Builds a span whose fields are added one by one (the macros use it too).
#[derive(Debug)]
#[must_use = "call `start` to create the span"]
pub struct SpanBuilder {
    level: Level,
    target: &'static str,
    name: Cow<'static, str>,
    kind: SpanKind,
    parent: Parent,
    fields: Vec<(Cow<'static, str>, FieldValue)>,
}

impl SpanBuilder {
    /// A span named `name`, of `level` under `target`.
    pub fn new(
        level: Level,
        target: &'static str,
        name: impl Into<Cow<'static, str>>,
    ) -> SpanBuilder {
        SpanBuilder {
            level,
            target,
            name: name.into(),
            kind: SpanKind::Internal,
            parent: Parent::Current,
            fields: Vec::new(),
        }
    }

    /// Sets the kind.
    pub fn kind(mut self, kind: SpanKind) -> SpanBuilder {
        self.kind = kind;
        self
    }

    /// Sets where the parent comes from.
    pub fn parent(mut self, parent: Parent) -> SpanBuilder {
        self.parent = parent;
        self
    }

    /// Adds a field.
    pub fn field(
        mut self,
        key: impl Into<Cow<'static, str>>,
        value: impl Into<FieldValue>,
    ) -> SpanBuilder {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// Starts the span: [`Span::none`] unless spans of this level are [`enabled`] and a tracer
    /// is installed that wants it.
    pub fn start(self) -> Span {
        if !enabled(self.level) {
            return Span::none();
        }
        let SpanBuilder {
            level,
            target,
            name,
            kind,
            parent,
            fields,
        } = self;
        Span::begin(level, target, name, kind, parent, |out| *out = fields)
    }
}

impl Span {
    /// A disabled span.
    pub const fn none() -> Span {
        Span(None)
    }

    /// Starts a span with no fields (see [`SpanBuilder`] for the options).
    pub fn start(level: Level, target: &'static str, name: impl Into<Cow<'static, str>>) -> Span {
        SpanBuilder::new(level, target, name).start()
    }

    /// The common path of the builder and the macros: the level was checked by the caller.
    fn begin(
        level: Level,
        target: &'static str,
        name: Cow<'static, str>,
        kind: SpanKind,
        parent: Parent,
        fill: impl FnOnce(&mut Vec<(Cow<'static, str>, FieldValue)>),
    ) -> Span {
        let Some(tracer) = tracer() else {
            return Span::none();
        };
        if !tracer.enabled(&Metadata { level, target }) {
            return Span::none();
        }
        let parent = match parent {
            Parent::Current => current(),
            Parent::Root => None,
            Parent::Explicit(p) => p,
        };
        let (trace_id, sampled) = match parent {
            Some(p) if !p.remote => (p.trace_id, p.is_sampled()),
            Some(p) => (p.trace_id, tracer.sample(p.trace_id, Some(&p))),
            None => {
                let t = (u128::from(random_u64()) << 64) | u128::from(random_u64());
                (t, tracer.sample(t, None))
            }
        };
        let ctx = SpanContext {
            trace_id,
            span_id: random_u64(),
            flags: if sampled { FLAG_SAMPLED } else { 0 },
            remote: false,
        };
        let rec = sampled.then(|| {
            let mut fields = Vec::new();
            fill(&mut fields);
            Recording {
                name,
                target,
                level,
                kind,
                parent,
                start: SystemTime::now(),
                t0: Instant::now(),
                fields,
                status: SpanStatus::Unset,
            }
        });
        Span(Some(Box::new(Inner { ctx, rec })))
    }

    #[doc(hidden)]
    pub fn __macro_start(
        level: Level,
        target: &'static str,
        name: &'static str,
        parent: Parent,
        kvs: &[(&'static str, Value<'_>)],
    ) -> Span {
        Span::begin(
            level,
            target,
            Cow::Borrowed(name),
            SpanKind::Internal,
            parent,
            |out| {
                out.reserve_exact(kvs.len());
                for (k, v) in kvs {
                    out.push((Cow::Borrowed(*k), FieldValue::from_value(*v)));
                }
            },
        )
    }

    /// Whether this span exists (enabled, sampled or not).
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    /// Whether this span records (exists and is sampled): use it to skip preparing fields.
    pub fn is_recording(&self) -> bool {
        self.0.as_ref().is_some_and(|i| i.rec.is_some())
    }

    /// The span's context (for children on other threads, or an outgoing `traceparent`).
    pub fn context(&self) -> Option<SpanContext> {
        self.0.as_ref().map(|i| i.ctx)
    }

    fn rec(&mut self) -> Option<&mut Recording> {
        self.0.as_mut().and_then(|i| i.rec.as_mut())
    }

    /// Sets a field (replacing an earlier value of the same key).
    pub fn record(&mut self, key: impl Into<Cow<'static, str>>, value: impl Into<FieldValue>) {
        if let Some(r) = self.rec() {
            let key = key.into();
            let value = value.into();
            match r.fields.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => r.fields.push((key, value)),
            }
        }
    }

    /// Renames the span (e.g. to `"GET /users/:id"` once the route is known).
    pub fn set_name(&mut self, name: impl Into<Cow<'static, str>>) {
        if let Some(r) = self.rec() {
            r.name = name.into();
        }
    }

    /// Sets the kind.
    pub fn set_kind(&mut self, kind: SpanKind) {
        if let Some(r) = self.rec() {
            r.kind = kind;
        }
    }

    /// Sets the status.
    pub fn set_status(&mut self, status: SpanStatus) {
        if let Some(r) = self.rec() {
            r.status = status;
        }
    }

    /// Makes this the current span of the thread until the guard is dropped. Does nothing for
    /// [`Span::none`].
    pub fn enter(&self) -> Entered<'_> {
        let prev = self
            .0
            .as_ref()
            .map(|i| CURRENT.with(|c| c.replace(Some(i.ctx))));
        Entered {
            prev,
            _span: std::marker::PhantomData,
        }
    }

    /// Runs `f` with this span entered.
    pub fn in_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.enter();
        f()
    }

    /// Ends the span now (dropping it does the same).
    pub fn end(self) {}
}

impl Drop for Span {
    #[inline]
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            finish(inner);
        }
    }
}

/// Hands a finished span to the tracer (out of line, so dropping a disabled span inlines to a
/// null check).
#[inline(never)]
fn finish(inner: Box<Inner>) {
    let Some(r) = inner.rec else { return };
    let Some(t) = tracer() else { return };
    t.on_end(SpanData {
        name: r.name,
        target: r.target,
        level: r.level,
        kind: r.kind,
        context: inner.ctx,
        parent: r.parent,
        start: r.start,
        end: r.start + r.t0.elapsed(),
        fields: r.fields,
        status: r.status,
    });
}

/// The guard of [`Span::enter`]: restores the previous current span when dropped.
#[must_use = "the span is current only while the guard lives"]
pub struct Entered<'a> {
    /// `None`: nothing was entered (a disabled span). `Some(prev)`: restore `prev`.
    prev: Option<Option<SpanContext>>,
    _span: std::marker::PhantomData<&'a Span>,
}

impl fmt::Debug for Entered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entered").finish_non_exhaustive()
    }
}

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        if let Some(prev) = self.prev {
            CURRENT.with(|c| c.set(prev));
        }
    }
}

/// Enters `ctx` (e.g. a span's context carried to another thread) until the guard is dropped.
pub fn enter_context(ctx: SpanContext) -> Entered<'static> {
    Entered {
        prev: Some(CURRENT.with(|c| c.replace(Some(ctx)))),
        _span: std::marker::PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_round_trip() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let c = SpanContext::from_traceparent(tp).unwrap();
        assert_eq!(c.trace_id(), 0x4bf92f3577b34da6a3ce929d0e0e4736);
        assert_eq!(c.span_id(), 0x00f067aa0ba902b7);
        assert!(c.is_sampled() && c.is_remote());
        assert_eq!(c.to_traceparent(), tp);
        let u = SpanContext::from_traceparent(&tp.replace("-01", "-00")).unwrap();
        assert!(!u.is_sampled());
        // Future versions may append fields after a dash.
        assert!(SpanContext::from_traceparent(&format!("01{}-extra", &tp[2..])).is_some());
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
        ] {
            assert!(SpanContext::from_traceparent(bad).is_none(), "{bad}");
        }
        assert!(SpanContext::new(0, 1, true, false).is_none());
    }

    #[test]
    fn ids_are_nonzero_and_differ() {
        let a: Vec<u64> = (0..1000).map(|_| random_u64()).collect();
        let mut b = a.clone();
        b.sort_unstable();
        b.dedup();
        assert_eq!(b.len(), a.len());
        assert!(a.iter().all(|&v| v != 0));
    }

    #[test]
    fn disabled_spans_do_nothing() {
        // No tracer in this unit-test binary.
        let mut s = Span::start(Level::Error, "t", "x");
        assert!(s.is_none() && !s.is_recording() && s.context().is_none());
        s.record("k", 1u8);
        s.set_name("y");
        let _g = s.enter();
        assert!(current().is_none());
        assert_eq!(size_of::<Span>(), size_of::<usize>());
    }

    #[test]
    fn field_values() {
        let s = String::from("v");
        assert_eq!(
            FieldValue::from_value(crate::ToValue::to_value(&s)),
            FieldValue::from(String::from("v"))
        );
        assert_eq!(
            FieldValue::from_value(crate::ToValue::to_value(&-3i32)),
            FieldValue::I64(-3)
        );
        assert_eq!(
            FieldValue::from_value(crate::ToValue::to_value(&u128::MAX)).to_string(),
            u128::MAX.to_string()
        );
        assert_eq!(
            FieldValue::from_value(Value::from_display(&1.5f64)),
            FieldValue::Str("1.5".into())
        );
        assert_eq!(FieldValue::from(7usize), FieldValue::U64(7));
        assert_eq!(FieldValue::from(true).to_string(), "true");
    }
}
