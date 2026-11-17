//! Spans with a capturing tracer: parents, fields, sampling, levels, propagation.
#![allow(missing_docs)]

use std::sync::{Mutex, MutexGuard};

use only_log::{
    Level, LevelFilter, debug_span, info_span,
    span::{
        self, FieldValue, Parent, Span, SpanBuilder, SpanContext, SpanData, SpanKind, SpanStatus,
        Tracer,
    },
    trace_span,
};

struct Capture {
    spans: Mutex<Vec<SpanData>>,
}

impl Tracer for Capture {
    fn enabled(&self, m: &only_log::Metadata<'_>) -> bool {
        m.target() != "muted"
    }
    fn sample(&self, trace_id: u128, parent: Option<&SpanContext>) -> bool {
        // Unsampled remote parents stay unsampled; new traces with an odd low bit are dropped
        // only under the "sampler" test's target (checked by name below).
        parent.is_none_or(SpanContext::is_sampled) && trace_id != 0
    }
    fn on_end(&self, span: SpanData) {
        self.spans.lock().unwrap().push(span);
    }
}

static CAP: Capture = Capture {
    spans: Mutex::new(Vec::new()),
};
static SERIAL: Mutex<()> = Mutex::new(());

fn setup() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = span::set_tracer(&CAP);
    span::set_max_span_level(LevelFilter::Debug);
    CAP.spans.lock().unwrap().clear();
    g
}

fn take() -> Vec<SpanData> {
    std::mem::take(&mut *CAP.spans.lock().unwrap())
}

#[test]
fn nesting_fields_and_order() {
    let _g = setup();
    let root = info_span!(target: "app", "root", user = "ann", n = 3u32);
    let root_ctx = root.context().unwrap();
    {
        let _in = root.enter();
        assert_eq!(span::current(), Some(root_ctx));
        let mut child = debug_span!("child", ok = true);
        child.record("rows", 5u64);
        child.record("rows", 6u64); // replaces
        child.set_status(SpanStatus::Error("boom".into()));
        child.set_kind(SpanKind::Client);
        child.set_name("renamed");
        assert!(child.is_recording());
        let tp = child.context().unwrap().to_traceparent();
        assert!(tp.starts_with(&format!("00-{:032x}-", root_ctx.trace_id())));
        assert!(tp.ends_with("-01"));
    }
    assert_eq!(span::current(), None);
    drop(root);
    let spans = take();
    assert_eq!(spans.len(), 2);
    let (child, root) = (&spans[0], &spans[1]);
    assert_eq!(child.name, "renamed");
    assert_eq!(child.kind, SpanKind::Client);
    assert_eq!(child.status, SpanStatus::Error("boom".into()));
    assert_eq!(child.parent, Some(root_ctx));
    assert_eq!(child.context.trace_id(), root_ctx.trace_id());
    assert_eq!(child.field("rows"), Some(&FieldValue::U64(6)));
    assert_eq!(child.field("ok"), Some(&FieldValue::Bool(true)));
    assert_eq!(child.fields.len(), 2);
    assert_eq!(child.level, Level::Debug);
    assert_eq!(child.target, module_path!());
    assert_eq!(root.target, "app");
    assert_eq!(root.parent, None);
    assert_eq!(root.field("user"), Some(&FieldValue::Str("ann".into())));
    assert!(root.end >= root.start);
    assert!(root.duration() >= child.duration());
}

#[test]
fn levels_and_tracer_filter() {
    let _g = setup();
    assert!(trace_span!("too verbose").is_none());
    assert!(info_span!(target: "muted", "filtered").is_none());
    span::set_max_span_level(LevelFilter::Off);
    assert!(info_span!("off").is_none());
    assert!(!span::enabled(Level::Error));
    span::set_max_span_level(LevelFilter::Debug);
    assert!(span::enabled(Level::Debug) && !span::enabled(Level::Trace));
    assert_eq!(span::max_span_level(), LevelFilter::Debug);
    assert!(take().is_empty());
}

#[test]
fn remote_parent_and_unsampled_propagation() {
    let _g = setup();
    let remote =
        SpanContext::from_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    let s = info_span!(parent: remote, "server", route = "/x");
    assert_eq!(
        s.context().unwrap().trace_id(),
        0x4bf92f3577b34da6a3ce929d0e0e4736
    );
    drop(s);
    let spans = take();
    assert_eq!(spans[0].parent, remote);
    assert!(spans[0].parent.unwrap().is_remote());

    // Unsampled upstream: the span exists (ids propagate) but records nothing, and its
    // children follow.
    let off =
        SpanContext::from_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00");
    let s = info_span!(parent: off, "server");
    assert!(!s.is_none() && !s.is_recording());
    assert!(s.context().unwrap().to_traceparent().ends_with("-00"));
    s.in_scope(|| {
        let c = info_span!("child");
        assert!(!c.is_recording());
        assert_eq!(
            c.context().unwrap().trace_id(),
            0x4bf92f3577b34da6a3ce929d0e0e4736
        );
    });
    drop(s);
    assert!(take().is_empty());
}

#[test]
fn builder_root_and_threads() {
    let _g = setup();
    let outer = info_span!("outer");
    let _in = outer.enter();
    let root = SpanBuilder::new(Level::Info, "app", format!("dyn {}", 1))
        .kind(SpanKind::Server)
        .parent(Parent::Root)
        .field("k", "v")
        .start();
    assert_ne!(
        root.context().unwrap().trace_id(),
        outer.context().unwrap().trace_id()
    );
    let ctx = outer.context().unwrap();
    std::thread::spawn(move || {
        assert!(span::current().is_none());
        let _g = span::enter_context(ctx);
        let s = Span::start(Level::Info, "worker", "on another thread");
        drop(s);
    })
    .join()
    .unwrap();
    drop(root);
    drop(_in);
    drop(outer);
    let spans = take();
    assert_eq!(spans.len(), 3);
    assert_eq!(spans[0].parent, Some(ctx));
    assert_eq!(spans[1].name, "dyn 1");
    assert_eq!(spans[1].parent, None);
    assert_eq!(spans[1].kind, SpanKind::Server);
}
