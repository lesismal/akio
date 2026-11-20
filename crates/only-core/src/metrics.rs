//! Pluggable metrics: application and protocol series served next to the engine's own (ADR-015).
//!
//! * A [`Collector`] adds samples to a [`Families`] snapshot when asked (a scrape), never on the
//!   I/O hot path. Register one with [`Telemetry::register_collector`](crate::Telemetry::register_collector)
//!   and it appears in [`Telemetry::render_prometheus`](crate::Telemetry::render_prometheus), which
//!   only-http's `metrics_handler` serves.
//! * [`Counter`], [`Gauge`] and [`Histogram`] are instruments for application code (relaxed
//!   atomics, no locks on update); a [`Registry`] owns named instruments and is a `Collector`.
//! * [`Families`] renders as the Prometheus text format ([`Families::to_prometheus`]) or JSON
//!   ([`Families::to_json`]), or can be read through [`Families::iter`].
//!
//! ```
//! use std::sync::Arc;
//! use only_core::{Telemetry, metrics::Registry};
//!
//! let reg = Registry::new();
//! let jobs = reg.counter("app_jobs_total", "Jobs finished.", &[("queue", "mail")]);
//! jobs.inc();
//!
//! let tel = Telemetry::new();
//! tel.register_collector(Arc::new(reg.clone()), &[]);
//! assert!(tel.render_prometheus().contains("app_jobs_total{queue=\"mail\"} 1"));
//! ```

use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use crate::telemetry::json_str;

/// Something that contributes samples to a scrape.
///
/// `collect` runs on the thread serving the scrape (with only-http, on a helper thread, not an
/// I/O thread's hot path), each time metrics are rendered. Keep it cheap: read atomics or take a
/// short lock, never block.
pub trait Collector: Send + Sync {
    /// Adds this collector's samples to `out`.
    fn collect(&self, out: &mut Families);
}

impl<C: Collector + ?Sized> Collector for Arc<C> {
    fn collect(&self, out: &mut Families) {
        (**self).collect(out);
    }
}

impl<C: Collector + ?Sized> Collector for Box<C> {
    fn collect(&self, out: &mut Families) {
        (**self).collect(out);
    }
}

/// Identifies a registration with [`Telemetry::register_collector`](crate::Telemetry::register_collector).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CollectorId(pub(crate) u64);

/// The Prometheus type of a [`Family`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A value that only goes up (resets when the process restarts).
    Counter,
    /// A value that goes up and down.
    Gauge,
    /// Observations counted into buckets, with their sum.
    Histogram,
}

impl Kind {
    /// `"counter"`, `"gauge"` or `"histogram"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// The buckets of a histogram at one moment.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct HistogramSnapshot {
    /// Upper bounds of the buckets (inclusive), strictly increasing and finite.
    pub bounds: Vec<f64>,
    /// Observations per bucket, **not** cumulative: `counts[i]` were in `(bounds[i-1],
    /// bounds[i]]`; the last entry (`counts[bounds.len()]`) counts those above every bound.
    pub counts: Vec<u64>,
    /// Sum of all observations.
    pub sum: f64,
    /// Recent observations made inside a sampled span, with its trace and span ids (at most one
    /// per bucket; empty unless the histogram keeps exemplars). Exported over OTLP; the
    /// Prometheus text format has no place for them.
    pub exemplars: Vec<Exemplar>,
}

impl HistogramSnapshot {
    /// A snapshot from its parts; `None` unless `counts` has one entry more than `bounds` and
    /// `bounds` is finite and strictly increasing.
    pub fn new(bounds: Vec<f64>, counts: Vec<u64>, sum: f64) -> Option<HistogramSnapshot> {
        let ok = counts.len() == bounds.len() + 1
            && bounds.iter().all(|b| b.is_finite())
            && bounds.windows(2).all(|w| w[0] < w[1]);
        ok.then_some(HistogramSnapshot {
            bounds,
            counts,
            sum,
            exemplars: Vec::new(),
        })
    }

    /// Sets the exemplars.
    #[must_use]
    pub fn with_exemplars(mut self, exemplars: Vec<Exemplar>) -> HistogramSnapshot {
        self.exemplars = exemplars;
        self
    }

    /// Observations in total.
    pub fn count(&self) -> u64 {
        self.counts.iter().fold(0u64, |a, &c| a.wrapping_add(c))
    }

    fn valid(&self) -> bool {
        self.counts.len() == self.bounds.len() + 1
            && self.bounds.iter().all(|b| b.is_finite())
            && self.bounds.windows(2).all(|w| w[0] < w[1])
    }
}

/// The value of one [`Sample`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// A counter's value.
    Counter(f64),
    /// A gauge's value.
    Gauge(f64),
    /// A histogram's buckets.
    Histogram(HistogramSnapshot),
}

/// One labelled value of a [`Family`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Sample {
    /// Label names and values (constant labels of the registration first).
    pub labels: Vec<(String, String)>,
    /// The value.
    pub value: Value,
}

impl Sample {
    /// The value of label `name`.
    pub fn label(&self, name: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// All samples of one metric name.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Family {
    /// Metric name, e.g. `app_jobs_total`.
    pub name: String,
    /// Help text (from the first sample added).
    pub help: String,
    /// Type.
    pub kind: Kind,
    /// Samples, in the order they were added.
    pub samples: Vec<Sample>,
}

/// A metrics snapshot: the families the collectors added, grouped by name.
///
/// Names must match `[a-zA-Z_:][a-zA-Z0-9_:]*` and label names `[a-zA-Z_][a-zA-Z0-9_]*` (not
/// starting with `__`); label values may be anything (they are escaped when rendered). A sample
/// with an invalid name, a duplicate label name, or a kind other than its family's is dropped and
/// counted in [`Families::dropped`]: building a snapshot never panics.
#[derive(Clone, Debug, Default)]
pub struct Families {
    families: Vec<Family>,
    index: HashMap<String, usize>,
    extra: Vec<(String, String)>,
    dropped: usize,
}

fn valid_name(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_' || c == b':')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':')
}

fn valid_label(s: &str) -> bool {
    let mut b = s.bytes();
    !s.starts_with("__")
        && matches!(b.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

impl Families {
    /// An empty snapshot.
    pub fn new() -> Families {
        Families::default()
    }

    /// Adds a counter sample.
    pub fn counter(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.add(name, help, Kind::Counter, labels, Value::Counter(value));
    }

    /// Adds a gauge sample.
    pub fn gauge(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.add(name, help, Kind::Gauge, labels, Value::Gauge(value));
    }

    /// Adds a histogram sample (rendered as `<name>_bucket`, `<name>_sum`, `<name>_count`).
    pub fn histogram(
        &mut self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        value: &HistogramSnapshot,
    ) {
        if !value.valid() {
            self.dropped += 1;
            return;
        }
        self.add(
            name,
            help,
            Kind::Histogram,
            labels,
            Value::Histogram(value.clone()),
        );
    }

    /// Runs `collector`, adding `labels` to each of its samples (a sample's own label of the
    /// same name wins).
    pub fn collect_from<K: AsRef<str>, V: AsRef<str>>(
        &mut self,
        collector: &dyn Collector,
        labels: &[(K, V)],
    ) {
        let saved = std::mem::replace(
            &mut self.extra,
            labels
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
                .collect(),
        );
        if self.extra.iter().any(|(k, _)| !valid_label(k)) {
            self.dropped += 1;
            self.extra = saved;
            return;
        }
        collector.collect(self);
        self.extra = saved;
    }

    fn add(&mut self, name: &str, help: &str, kind: Kind, labels: &[(&str, &str)], value: Value) {
        if !valid_name(name) {
            self.dropped += 1;
            return;
        }
        let mut all: Vec<(String, String)> = Vec::with_capacity(self.extra.len() + labels.len());
        for (k, v) in &self.extra {
            if !labels.iter().any(|(n, _)| n == k) {
                all.push((k.clone(), v.clone()));
            }
        }
        for (i, (k, v)) in labels.iter().enumerate() {
            if !valid_label(k)
                || (kind == Kind::Histogram && *k == "le")
                || labels[..i].iter().any(|(n, _)| n == k)
            {
                self.dropped += 1;
                return;
            }
            all.push(((*k).to_owned(), (*v).to_owned()));
        }
        let sample = Sample { labels: all, value };
        match self.index.get(name) {
            Some(&i) => {
                let f = &mut self.families[i];
                if f.kind != kind {
                    self.dropped += 1;
                    return;
                }
                f.samples.push(sample);
            }
            None => {
                self.index.insert(name.to_owned(), self.families.len());
                self.families.push(Family {
                    name: name.to_owned(),
                    help: help.to_owned(),
                    kind,
                    samples: vec![sample],
                });
            }
        }
    }

    /// The families, in the order their first sample was added.
    pub fn iter(&self) -> std::slice::Iter<'_, Family> {
        self.families.iter()
    }

    /// The family named `name`.
    pub fn get(&self, name: &str) -> Option<&Family> {
        self.index.get(name).map(|&i| &self.families[i])
    }

    /// Number of families.
    pub fn len(&self) -> usize {
        self.families.len()
    }

    /// No family at all.
    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    /// Samples dropped because of an invalid name or label, or a kind clash.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// Renders the Prometheus text exposition format (version 0.0.4).
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();
        self.write_prometheus(&mut out);
        out
    }

    /// Appends the Prometheus rendering to `out`.
    pub fn write_prometheus(&self, out: &mut String) {
        for f in &self.families {
            out.push_str("# HELP ");
            out.push_str(&f.name);
            out.push(' ');
            for ch in f.help.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    c => out.push(c),
                }
            }
            let _ = writeln!(out, "\n# TYPE {} {}", f.name, f.kind.as_str());
            for s in &f.samples {
                match &s.value {
                    Value::Counter(v) | Value::Gauge(v) => {
                        out.push_str(&f.name);
                        prom_labels(out, &s.labels, None);
                        out.push(' ');
                        prom_f64(out, *v);
                        out.push('\n');
                    }
                    Value::Histogram(h) => {
                        let mut cum = 0u64;
                        for (i, ub) in h.bounds.iter().enumerate() {
                            cum = cum.wrapping_add(h.counts[i]);
                            let _ = write!(out, "{}_bucket", f.name);
                            prom_labels(out, &s.labels, Some(*ub));
                            let _ = writeln!(out, " {cum}");
                        }
                        cum = cum.wrapping_add(h.counts[h.bounds.len()]);
                        let _ = write!(out, "{}_bucket", f.name);
                        prom_labels(out, &s.labels, Some(f64::INFINITY));
                        let _ = writeln!(out, " {cum}");
                        let _ = write!(out, "{}_sum", f.name);
                        prom_labels(out, &s.labels, None);
                        out.push(' ');
                        prom_f64(out, h.sum);
                        let _ = write!(out, "\n{}_count", f.name);
                        prom_labels(out, &s.labels, None);
                        let _ = writeln!(out, " {cum}");
                    }
                }
            }
        }
    }

    /// Renders as JSON: an array of `{"name", "help", "type", "samples": [{"labels": {...},
    /// "value": n}]}`; a histogram sample has `"bounds"`, `"counts"` (not cumulative, the last
    /// above every bound) and `"sum"` instead of `"value"`. Non-finite numbers are `null`.
    pub fn to_json(&self) -> String {
        let mut o = String::from("[");
        for (i, f) in self.families.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str("{\"name\":");
            json_str(&mut o, &f.name);
            o.push_str(",\"help\":");
            json_str(&mut o, &f.help);
            let _ = write!(o, ",\"type\":\"{}\",\"samples\":[", f.kind.as_str());
            for (j, s) in f.samples.iter().enumerate() {
                if j > 0 {
                    o.push(',');
                }
                o.push_str("{\"labels\":{");
                for (k, (n, v)) in s.labels.iter().enumerate() {
                    if k > 0 {
                        o.push(',');
                    }
                    json_str(&mut o, n);
                    o.push(':');
                    json_str(&mut o, v);
                }
                o.push('}');
                match &s.value {
                    Value::Counter(v) | Value::Gauge(v) => {
                        o.push_str(",\"value\":");
                        json_f64(&mut o, *v);
                    }
                    Value::Histogram(h) => {
                        o.push_str(",\"bounds\":[");
                        for (k, b) in h.bounds.iter().enumerate() {
                            if k > 0 {
                                o.push(',');
                            }
                            json_f64(&mut o, *b);
                        }
                        o.push_str("],\"counts\":[");
                        for (k, c) in h.counts.iter().enumerate() {
                            if k > 0 {
                                o.push(',');
                            }
                            let _ = write!(o, "{c}");
                        }
                        o.push_str("],\"sum\":");
                        json_f64(&mut o, h.sum);
                    }
                }
                o.push('}');
            }
            o.push_str("]}");
        }
        o.push(']');
        o
    }
}

fn prom_f64(out: &mut String, v: f64) {
    if v.is_nan() {
        out.push_str("NaN");
    } else if v == f64::INFINITY {
        out.push_str("+Inf");
    } else if v == f64::NEG_INFINITY {
        out.push_str("-Inf");
    } else {
        let _ = write!(out, "{v}");
    }
}

fn json_f64(out: &mut String, v: f64) {
    if v.is_finite() {
        let _ = write!(out, "{v}");
    } else {
        out.push_str("null");
    }
}

fn prom_labels(out: &mut String, labels: &[(String, String)], le: Option<f64>) {
    if labels.is_empty() && le.is_none() {
        return;
    }
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        for ch in v.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    if let Some(le) = le {
        if !labels.is_empty() {
            out.push(',');
        }
        out.push_str("le=\"");
        prom_f64(out, le);
        out.push('"');
    }
    out.push('}');
}

// ---- instruments ------------------------------------------------------------------------------

/// A counter for application code: a cheap clone of a shared atomic.
#[derive(Clone, Debug, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    /// A counter at 0 (not exported until a [`Registry`] or your own [`Collector`] reports it).
    pub fn new() -> Counter {
        Counter::default()
    }

    /// Adds 1.
    #[inline]
    pub fn inc(&self) {
        self.add(1);
    }

    /// Adds `n`.
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Adds `d` to the `f64` stored as bits in `a` (a compare-exchange loop; `fetch_update` is
/// deprecated on newer toolchains and its replacement is newer than the MSRV).
#[inline]
fn add_f64(a: &AtomicU64, d: f64) {
    let mut cur = a.load(Ordering::Relaxed);
    loop {
        let next = (f64::from_bits(cur) + d).to_bits();
        match a.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(x) => cur = x,
        }
    }
}

/// A gauge for application code (an `f64` in a shared atomic).
#[derive(Clone, Debug, Default)]
pub struct Gauge(Arc<AtomicU64>);

impl Gauge {
    /// A gauge at 0.
    pub fn new() -> Gauge {
        Gauge::default()
    }

    /// Sets the value.
    #[inline]
    pub fn set(&self, v: f64) {
        self.0.store(v.to_bits(), Ordering::Relaxed);
    }

    /// Adds `d` (negative to subtract).
    #[inline]
    pub fn add(&self, d: f64) {
        add_f64(&self.0, d);
    }

    /// Adds 1.
    #[inline]
    pub fn inc(&self) {
        self.add(1.0);
    }

    /// Subtracts 1.
    #[inline]
    pub fn dec(&self) {
        self.add(-1.0);
    }

    /// Current value.
    pub fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }
}

/// One observation kept as an example of its bucket, with the trace it was made in: a latency
/// spike on a dashboard leads to the span that caused it (OpenTelemetry's exemplar).
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Exemplar {
    /// The observed value.
    pub value: f64,
    /// When it was observed.
    pub time: SystemTime,
    /// The trace id of the span current then.
    pub trace_id: u128,
    /// The span id of that span.
    pub span_id: u64,
}

impl Exemplar {
    /// An exemplar from its parts.
    pub fn new(value: f64, time: SystemTime, trace_id: u128, span_id: u64) -> Exemplar {
        Exemplar {
            value,
            time,
            trace_id,
            span_id,
        }
    }
}

/// The latest exemplar of each bucket of a histogram (OpenTelemetry's aligned-histogram
/// reservoir). Offering one is a thread-local read and, inside a sampled span, a clock read and
/// a `try_lock` that never waits: when two threads offer to the same bucket at once, one of
/// the two exemplars is kept.
#[derive(Debug)]
pub struct ExemplarReservoir {
    slots: Box<[Mutex<Option<Exemplar>>]>,
}

impl ExemplarReservoir {
    /// A reservoir for `buckets` buckets.
    pub fn new(buckets: usize) -> ExemplarReservoir {
        ExemplarReservoir {
            slots: (0..buckets).map(|_| Mutex::new(None)).collect(),
        }
    }

    /// Keeps `value` as the exemplar of `bucket` when the thread is inside a sampled span
    /// ([`only_log::span::current`]).
    #[inline]
    pub fn offer_current(&self, bucket: usize, value: f64) {
        if let Some(ctx) = only_log::span::current() {
            if ctx.is_sampled() {
                self.offer(bucket, value, ctx.trace_id(), ctx.span_id());
            }
        }
    }

    /// Keeps `value` as the exemplar of `bucket`, observed now in the span `span_id` of
    /// `trace_id`. A bucket out of range is ignored.
    pub fn offer(&self, bucket: usize, value: f64, trace_id: u128, span_id: u64) {
        if let Some(slot) = self.slots.get(bucket) {
            if let Ok(mut g) = slot.try_lock() {
                *g = Some(Exemplar::new(value, SystemTime::now(), trace_id, span_id));
            }
        }
    }

    /// The exemplars kept, in bucket order.
    pub fn snapshot(&self) -> Vec<Exemplar> {
        self.slots
            .iter()
            .filter_map(|s| *s.lock().unwrap_or_else(|p| p.into_inner()))
            .collect()
    }
}

/// Prometheus' default histogram bounds, in seconds (5 ms to 10 s).
pub const DEFAULT_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug)]
struct HistInner {
    bounds: Box<[f64]>,
    counts: Box<[AtomicU64]>,
    sum: AtomicU64,
    exemplars: Option<ExemplarReservoir>,
}

/// A histogram for application code: fixed buckets, relaxed atomics.
#[derive(Clone, Debug)]
pub struct Histogram(Arc<HistInner>);

impl Default for Histogram {
    /// A histogram with [`DEFAULT_BUCKETS`].
    fn default() -> Histogram {
        Histogram::new(&DEFAULT_BUCKETS)
    }
}

impl Histogram {
    /// A histogram with upper bounds `bounds` (non-finite values dropped, sorted, duplicates
    /// removed); one more bucket counts observations above all of them.
    pub fn new(bounds: &[f64]) -> Histogram {
        Histogram::build(bounds, false)
    }

    /// [`Histogram::new`] keeping exemplars: each bucket remembers its latest observation made
    /// inside a sampled span ([`ExemplarReservoir`]), reported in
    /// [`HistogramSnapshot::exemplars`] and exported over OTLP with the span's trace id.
    pub fn with_exemplars(bounds: &[f64]) -> Histogram {
        Histogram::build(bounds, true)
    }

    fn build(bounds: &[f64], exemplars: bool) -> Histogram {
        let mut b: Vec<f64> = bounds.iter().copied().filter(|x| x.is_finite()).collect();
        b.sort_by(f64::total_cmp);
        b.dedup();
        let counts = (0..=b.len()).map(|_| AtomicU64::new(0)).collect();
        Histogram(Arc::new(HistInner {
            exemplars: exemplars.then(|| ExemplarReservoir::new(b.len() + 1)),
            bounds: b.into_boxed_slice(),
            counts,
            sum: AtomicU64::new(0f64.to_bits()),
        }))
    }

    /// `count` bounds `start`, `start * factor`, `start * factor²` ... (`start > 0`,
    /// `factor > 1`; otherwise only `start`).
    pub fn exponential(start: f64, factor: f64, count: usize) -> Histogram {
        let mut b = Vec::with_capacity(count);
        let mut x = start;
        for _ in 0..count {
            b.push(x);
            if !(start > 0.0 && factor > 1.0) {
                break;
            }
            x *= factor;
        }
        Histogram::new(&b)
    }

    /// Records one observation (NaN is ignored).
    #[inline]
    pub fn observe(&self, v: f64) {
        if v.is_nan() {
            return;
        }
        let h = &*self.0;
        let i = h.bounds.partition_point(|&b| b < v);
        h.counts[i].fetch_add(1, Ordering::Relaxed);
        add_f64(&h.sum, v);
        if let Some(ex) = &h.exemplars {
            ex.offer_current(i, v);
        }
    }

    /// Records a duration in seconds.
    #[inline]
    pub fn observe_duration(&self, d: Duration) {
        self.observe(d.as_secs_f64());
    }

    /// The current buckets.
    pub fn snapshot(&self) -> HistogramSnapshot {
        let h = &*self.0;
        HistogramSnapshot {
            bounds: h.bounds.to_vec(),
            counts: h.counts.iter().map(|c| c.load(Ordering::Relaxed)).collect(),
            sum: f64::from_bits(h.sum.load(Ordering::Relaxed)),
            exemplars: h
                .exemplars
                .as_ref()
                .map_or_else(Vec::new, ExemplarReservoir::snapshot),
        }
    }
}

#[derive(Clone, Debug)]
enum Inst {
    Counter(Counter),
    Gauge(Gauge),
    Histogram(Histogram),
}

#[derive(Debug)]
struct Entry {
    name: String,
    help: String,
    labels: Vec<(String, String)>,
    inst: Inst,
}

/// Named instruments, reported as a [`Collector`]. Clones share the same instruments.
///
/// Asking again for the same name and labels returns the instrument already registered. Asking
/// for an existing name and labels with another instrument type, or with an invalid name, returns
/// a detached instrument that is never reported.
#[derive(Clone, Debug, Default)]
pub struct Registry(Arc<Mutex<Vec<Entry>>>);

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    fn get_or_add(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        make: impl FnOnce() -> Inst,
        same: impl Fn(&Inst) -> Option<Inst>,
    ) -> Inst {
        let labels: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = g.iter().find(|e| e.name == name && e.labels == labels) {
            return same(&e.inst).unwrap_or_else(make);
        }
        let inst = make();
        if valid_name(name) && labels.iter().all(|(k, _)| valid_label(k)) {
            g.push(Entry {
                name: name.to_owned(),
                help: help.to_owned(),
                labels,
                inst: inst.clone(),
            });
        }
        inst
    }

    /// The counter `name` with `labels`, registered on first use.
    pub fn counter(&self, name: &str, help: &str, labels: &[(&str, &str)]) -> Counter {
        let i = self.get_or_add(
            name,
            help,
            labels,
            || Inst::Counter(Counter::new()),
            |i| match i {
                Inst::Counter(c) => Some(Inst::Counter(c.clone())),
                _ => None,
            },
        );
        match i {
            Inst::Counter(c) => c,
            _ => Counter::new(),
        }
    }

    /// The gauge `name` with `labels`, registered on first use.
    pub fn gauge(&self, name: &str, help: &str, labels: &[(&str, &str)]) -> Gauge {
        let i = self.get_or_add(
            name,
            help,
            labels,
            || Inst::Gauge(Gauge::new()),
            |i| match i {
                Inst::Gauge(g) => Some(Inst::Gauge(g.clone())),
                _ => None,
            },
        );
        match i {
            Inst::Gauge(g) => g,
            _ => Gauge::new(),
        }
    }

    /// The histogram `name` with `labels`, registered on first use with `bounds` (ignored when
    /// it already exists).
    pub fn histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        bounds: &[f64],
    ) -> Histogram {
        let i = self.get_or_add(
            name,
            help,
            labels,
            || Inst::Histogram(Histogram::new(bounds)),
            |i| match i {
                Inst::Histogram(h) => Some(Inst::Histogram(h.clone())),
                _ => None,
            },
        );
        match i {
            Inst::Histogram(h) => h,
            _ => Histogram::new(bounds),
        }
    }

    /// [`histogram`](Self::histogram), created with [`Histogram::with_exemplars`] on first use.
    pub fn histogram_with_exemplars(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        bounds: &[f64],
    ) -> Histogram {
        let i = self.get_or_add(
            name,
            help,
            labels,
            || Inst::Histogram(Histogram::with_exemplars(bounds)),
            |i| match i {
                Inst::Histogram(h) => Some(Inst::Histogram(h.clone())),
                _ => None,
            },
        );
        match i {
            Inst::Histogram(h) => h,
            _ => Histogram::with_exemplars(bounds),
        }
    }
}

impl Collector for Registry {
    fn collect(&self, out: &mut Families) {
        let g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        for e in g.iter() {
            let labels: Vec<(&str, &str)> = e
                .labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            match &e.inst {
                Inst::Counter(c) => out.counter(&e.name, &e.help, &labels, c.get() as f64),
                Inst::Gauge(v) => out.gauge(&e.name, &e.help, &labels, v.get()),
                Inst::Histogram(h) => out.histogram(&e.name, &e.help, &labels, &h.snapshot()),
            }
        }
    }
}

/// A [`Collector`] made from a closure; see [`fn_collector`].
pub struct FnCollector<F>(F);

impl<F> std::fmt::Debug for FnCollector<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnCollector").finish_non_exhaustive()
    }
}

impl<F: Fn(&mut Families) + Send + Sync> Collector for FnCollector<F> {
    fn collect(&self, out: &mut Families) {
        (self.0)(out);
    }
}

/// A collector that runs `f` on every scrape.
///
/// ```
/// use only_core::metrics::{Families, fn_collector};
/// let c = fn_collector(|out: &mut Families| out.gauge("app_up", "Always 1.", &[], 1.0));
/// # let _ = c;
/// ```
pub fn fn_collector<F: Fn(&mut Families) + Send + Sync>(f: F) -> FnCollector<F> {
    FnCollector(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_validates_and_renders() {
        let mut f = Families::new();
        f.counter("a_total", "A.", &[("k", "x")], 1.0);
        f.gauge("b", "B.", &[], 2.5);
        f.counter("a_total", "ignored help", &[("k", "y\"\n\\")], 3.0);
        f.gauge("a_total", "kind clash", &[], 1.0);
        f.counter("1bad", "", &[], 1.0);
        f.counter("c", "", &[("__x", "v")], 1.0);
        f.counter("c", "", &[("k", "1"), ("k", "2")], 1.0);
        assert_eq!(f.dropped(), 4);
        assert_eq!(f.len(), 2);
        assert_eq!(f.get("a_total").map(|f| f.samples.len()), Some(2));
        assert_eq!(
            f.to_prometheus(),
            "# HELP a_total A.\n# TYPE a_total counter\na_total{k=\"x\"} 1\n\
             a_total{k=\"y\\\"\\n\\\\\"} 3\n# HELP b B.\n# TYPE b gauge\nb 2.5\n"
        );
        assert_eq!(
            f.to_json(),
            "[{\"name\":\"a_total\",\"help\":\"A.\",\"type\":\"counter\",\"samples\":[\
             {\"labels\":{\"k\":\"x\"},\"value\":1},{\"labels\":{\"k\":\"y\\\"\\n\\\\\"},\"value\":3}]},\
             {\"name\":\"b\",\"help\":\"B.\",\"type\":\"gauge\",\"samples\":[{\"labels\":{},\"value\":2.5}]}]"
        );
    }

    #[test]
    fn special_floats() {
        let mut f = Families::new();
        f.gauge("g", "", &[("i", "nan")], f64::NAN);
        f.gauge("g", "", &[("i", "inf")], f64::INFINITY);
        f.gauge("g", "", &[("i", "-inf")], f64::NEG_INFINITY);
        let p = f.to_prometheus();
        assert!(p.contains("g{i=\"nan\"} NaN\n"));
        assert!(p.contains("g{i=\"inf\"} +Inf\n"));
        assert!(p.contains("g{i=\"-inf\"} -Inf\n"));
        assert!(f.to_json().contains("\"value\":null"));
    }

    #[test]
    fn histogram_buckets() {
        let h = Histogram::new(&[1.0, 0.5, f64::NAN, 2.0, 1.0]);
        for v in [0.1, 0.5, 0.7, 1.0, 3.0, f64::NAN] {
            h.observe(v);
        }
        let s = h.snapshot();
        assert_eq!(s.bounds, vec![0.5, 1.0, 2.0]);
        assert_eq!(s.counts, vec![2, 2, 0, 1]);
        assert_eq!(s.count(), 5);
        assert!((s.sum - 5.3).abs() < 1e-9);
        let mut f = Families::new();
        f.histogram("lat", "L.", &[("r", "a")], &s);
        f.histogram("bad", "", &[("le", "x")], &s);
        let bad = HistogramSnapshot {
            bounds: vec![2.0, 1.0],
            counts: vec![0, 0, 0],
            sum: 0.0,
            exemplars: Vec::new(),
        };
        f.histogram("bad", "", &[], &bad);
        assert_eq!(f.dropped(), 2);
        let p = f.to_prometheus();
        assert!(p.contains("lat_bucket{r=\"a\",le=\"0.5\"} 2\n"));
        assert!(p.contains("lat_bucket{r=\"a\",le=\"1\"} 4\n"));
        assert!(p.contains("lat_bucket{r=\"a\",le=\"2\"} 4\n"));
        assert!(p.contains("lat_bucket{r=\"a\",le=\"+Inf\"} 5\n"));
        assert!(p.contains("lat_count{r=\"a\"} 5\n"));
        assert!(
            f.to_json()
                .contains("\"bounds\":[0.5,1,2],\"counts\":[2,2,0,1]")
        );
        let e = Histogram::exponential(0.001, 10.0, 4).snapshot().bounds;
        assert_eq!(e.len(), 4);
        assert!((e[3] - 1.0).abs() < 1e-12);
        assert_eq!(
            Histogram::exponential(1.0, 0.5, 4).snapshot().bounds,
            vec![1.0]
        );
        assert!(HistogramSnapshot::new(vec![1.0], vec![1], 0.0).is_none());
    }

    #[test]
    fn registry_and_const_labels() {
        let r = Registry::new();
        let c = r.counter("jobs_total", "Jobs.", &[("q", "a")]);
        c.add(2);
        r.counter("jobs_total", "Jobs.", &[("q", "a")]).inc();
        let g = r.gauge("depth", "Depth.", &[]);
        g.set(4.0);
        g.dec();
        // Same name and labels, other type: detached.
        r.gauge("jobs_total", "", &[("q", "a")]).set(99.0);
        r.counter("bad name", "", &[]).inc();
        r.histogram("lat_seconds", "Lat.", &[], &DEFAULT_BUCKETS)
            .observe_duration(Duration::from_millis(7));
        let mut f = Families::new();
        f.collect_from(&r, &[("server", "s1"), ("q", "ignored")]);
        let p = f.to_prometheus();
        assert!(p.contains("jobs_total{server=\"s1\",q=\"a\"} 3\n"), "{p}");
        assert!(p.contains("depth{server=\"s1\",q=\"ignored\"} 3\n"), "{p}");
        assert!(p.contains("lat_seconds_bucket{server=\"s1\",q=\"ignored\",le=\"0.01\"} 1\n"));
        assert!(!p.contains("99"));
        assert_eq!(f.len(), 3);
        // Closures through fn_collector; invalid constant labels drop the whole collector.
        let mut f = Families::new();
        let x = fn_collector(|o: &mut Families| o.counter("x", "", &[], 1.0));
        f.collect_from(&x, &[("1", "v")]);
        assert!(f.is_empty());
        assert_eq!(f.dropped(), 1);
        let none: &[(&str, &str)] = &[];
        f.collect_from(&x, none);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn exemplars_follow_the_current_sampled_span() {
        use only_log::span::{SpanContext, enter_context};
        let h = Histogram::with_exemplars(&[1.0, 2.0]);
        h.observe(0.5); // no span: no exemplar
        {
            let _g = enter_context(SpanContext::new(0xabc, 0x12, true, false).unwrap());
            h.observe(1.5);
            h.observe(0.25);
        }
        {
            let _g = enter_context(SpanContext::new(0xdef, 0x34, false, false).unwrap());
            h.observe(9.0); // unsampled: none
        }
        let s = h.snapshot();
        assert_eq!(s.counts, vec![2, 1, 1]);
        let ex: Vec<(f64, u128, u64)> = s
            .exemplars
            .iter()
            .map(|e| (e.value, e.trace_id, e.span_id))
            .collect();
        assert_eq!(ex, vec![(0.25, 0xabc, 0x12), (1.5, 0xabc, 0x12)]);
        // Without exemplars nothing is kept, inside a span or not.
        let plain = Histogram::new(&[1.0]);
        let _g = enter_context(SpanContext::new(1, 2, true, false).unwrap());
        plain.observe(0.5);
        assert!(plain.snapshot().exemplars.is_empty());
        // The registry hands out the same instrument again.
        let reg = Registry::new();
        let a = reg.histogram_with_exemplars("lat", "L.", &[], &[1.0]);
        a.observe(0.5);
        let b = reg.histogram_with_exemplars("lat", "L.", &[], &[1.0]);
        assert_eq!(b.snapshot().exemplars.len(), 1);
        let mut f = Families::new();
        reg.collect(&mut f);
        match &f.get("lat").unwrap().samples[0].value {
            Value::Histogram(h) => assert_eq!(h.exemplars[0].trace_id, 1),
            v => panic!("{v:?}"),
        }
        // Out of range buckets are ignored.
        ExemplarReservoir::new(1).offer(5, 1.0, 1, 1);
    }
}
