//! Round trips of the OTLP encodings against the schema: `tests/otlp.proto` (the
//! opentelemetry-proto messages the exporter writes) is compiled with only-protobuf-build, the
//! protobuf bodies are decoded with only-protobuf's dynamic messages (no unknown field, every
//! value back), and every field of the message tree is checked against its descriptor (number,
//! wire type, OTLP/JSON name). Fixed examples, then seeded random spans, records and metrics.

use std::{
    borrow::Cow,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use only_core::metrics::{Exemplar, Families, HistogramSnapshot};
use only_log::{
    Level,
    span::{FieldValue, SpanContext, SpanData, SpanEvent, SpanKind, SpanLink, SpanStatus},
};
use only_protobuf::reflect::{DescriptorPool, DynamicMessage, Kind, MessageDescriptor, Value};

use crate::{
    Encoding,
    logs::LogData,
    otlp,
    tree::{Field, Msg, Node},
};

fn pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("only-export-otlp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let set = dir.join("otlp.bin");
        let proto = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/otlp.proto");
        only_protobuf_build::Config::new()
            .file_descriptor_set_path(&set)
            .compile(&[proto], dir.join("rs"))
            .unwrap();
        let bytes = std::fs::read(&set).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        DescriptorPool::decode(&bytes).unwrap()
    })
}

fn desc(name: &str) -> MessageDescriptor {
    pool()
        .get_message_by_name(&format!("otlp.{name}"))
        .unwrap_or_else(|| panic!("no {name}"))
}

/// Checks every field of `fields` against `d`: it exists, its JSON name is the one the tree
/// prints, the node fits the field's type and cardinality; then recurses into messages.
fn check_schema(fields: &[Field], d: &MessageDescriptor) {
    for f in fields {
        let fd = d
            .get_field(f.num)
            .unwrap_or_else(|| panic!("{}: no field {} ({})", d.full_name(), f.num, f.name));
        assert_eq!(fd.json_name(), f.name, "{}.{}", d.full_name(), fd.name());
        let packed = matches!(f.val, Node::PackedFixed64(_) | Node::PackedDouble(_));
        assert_eq!(
            fd.is_list(),
            f.repeated || packed,
            "{}.{} cardinality",
            d.full_name(),
            fd.name()
        );
        let ok = match (&f.val, fd.kind()) {
            (Node::Msg(m), Kind::Message(_)) => {
                check_schema(m, &fd.message_type().unwrap());
                true
            }
            (Node::Str(_), Kind::String)
            | (Node::Id(_), Kind::Bytes)
            | (Node::Fixed64(_) | Node::PackedFixed64(_), Kind::Fixed64)
            | (Node::Fixed32(_), Kind::Fixed32)
            | (Node::I64(_), Kind::Int64)
            | (Node::U32(_), Kind::Uint32 | Kind::Enum(_))
            | (Node::Double(_) | Node::PackedDouble(_), Kind::Double)
            | (Node::Bool(_), Kind::Bool) => true,
            _ => false,
        };
        assert!(
            ok,
            "{}.{}: {:?} vs {:?}",
            d.full_name(),
            fd.name(),
            f.val,
            fd.kind()
        );
    }
}

fn assert_no_unknown(m: &DynamicMessage) {
    assert!(
        m.unknown_fields().is_empty(),
        "unknown fields in {}",
        m.descriptor().full_name()
    );
    for (_, v) in m.fields() {
        match v {
            Value::Message(c) => assert_no_unknown(c),
            Value::List(l) => {
                for x in l {
                    if let Value::Message(c) = x {
                        assert_no_unknown(c);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Encodes `root` (an `Export*ServiceRequest` of type `name`), checks the tree against the
/// schema, decodes the protobuf and returns it.
fn decode(name: &str, root: Msg) -> DynamicMessage {
    let d = desc(name);
    check_schema(&root.0, &d);
    let pb = Encoding::Protobuf.encode(root);
    let m = DynamicMessage::decode(d, &pb).unwrap();
    assert_no_unknown(&m);
    m
}

// ---- reading dynamic messages ---------------------------------------------------------------

fn get(m: &DynamicMessage, name: &str) -> Value {
    m.get_by_name(name)
        .unwrap_or_else(|| panic!("no field {name} in {}", m.descriptor().full_name()))
        .into_owned()
}

fn msgs(m: &DynamicMessage, name: &str) -> Vec<DynamicMessage> {
    match get(m, name) {
        Value::List(l) => l
            .into_iter()
            .map(|v| match v {
                Value::Message(m) => m,
                v => panic!("{v:?}"),
            })
            .collect(),
        v => panic!("{name}: {v:?}"),
    }
}

fn msg(m: &DynamicMessage, name: &str) -> DynamicMessage {
    match get(m, name) {
        Value::Message(m) => m,
        v => panic!("{name}: {v:?}"),
    }
}

fn text(m: &DynamicMessage, name: &str) -> String {
    match get(m, name) {
        Value::String(s) => s,
        v => panic!("{name}: {v:?}"),
    }
}

fn bytes(m: &DynamicMessage, name: &str) -> Vec<u8> {
    match get(m, name) {
        Value::Bytes(b) => b,
        v => panic!("{name}: {v:?}"),
    }
}

fn u64_of(m: &DynamicMessage, name: &str) -> u64 {
    match get(m, name) {
        Value::U64(v) => v,
        Value::U32(v) => u64::from(v),
        Value::I64(v) => v as u64,
        Value::EnumNumber(v) => v as u64,
        v => panic!("{name}: {v:?}"),
    }
}

/// An `AnyValue` back as the field value the exporter maps to it.
fn any(m: &DynamicMessage) -> FieldValue {
    let (fd, v) = m.fields().next().expect("an AnyValue with a value");
    match (fd.name(), v) {
        ("string_value", Value::String(s)) => FieldValue::Str(s.clone().into()),
        ("bool_value", Value::Bool(b)) => FieldValue::Bool(*b),
        ("int_value", Value::I64(i)) => FieldValue::I64(*i),
        ("double_value", Value::F64(f)) => FieldValue::F64(*f),
        (n, v) => panic!("{n}: {v:?}"),
    }
}

fn attrs(m: &DynamicMessage, name: &str) -> Vec<(String, FieldValue)> {
    msgs(m, name)
        .iter()
        .map(|kv| (text(kv, "key"), any(&msg(kv, "value"))))
        .collect()
}

/// What the exporter sends for a field value: integers as `int64` (an unsigned one past
/// `i64::MAX` as its decimal string), floats as `double`.
fn expected(v: &FieldValue) -> FieldValue {
    match v {
        FieldValue::U64(u) => match i64::try_from(*u) {
            Ok(i) => FieldValue::I64(i),
            Err(_) => FieldValue::Str(u.to_string().into()),
        },
        v => v.clone(),
    }
}

fn expected_fields(f: &[(Cow<'static, str>, FieldValue)]) -> Vec<(String, FieldValue)> {
    f.iter()
        .map(|(k, v)| (k.to_string(), expected(v)))
        .collect()
}

/// Compares floats bit for bit (NaN included).
fn same(a: &[(String, FieldValue)], b: &[(String, FieldValue)]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|((ka, va), (kb, vb))| {
            ka == kb
                && match (va, vb) {
                    (FieldValue::F64(x), FieldValue::F64(y)) => x.to_bits() == y.to_bits(),
                    _ => va == vb,
                }
        })
}

fn nanos(t: SystemTime) -> u64 {
    otlp::unix_nanos(t)
}

// ---- checks per signal ----------------------------------------------------------------------

fn check_spans(spans: &[SpanData]) {
    let resource = [("service.name".to_owned(), "svc".to_owned())];
    let req = decode(
        "ExportTraceServiceRequest",
        otlp::traces_request(spans, &resource),
    );
    let rs = msgs(&req, "resource_spans");
    assert_eq!(rs.len(), 1);
    assert_eq!(
        attrs(&msg(&rs[0], "resource"), "attributes"),
        vec![("service.name".into(), FieldValue::Str("svc".into()))]
    );
    let mut got = Vec::new();
    for ss in msgs(&rs[0], "scope_spans") {
        let scope = text(&msg(&ss, "scope"), "name");
        for s in msgs(&ss, "spans") {
            got.push((scope.clone(), s));
        }
    }
    assert_eq!(got.len(), spans.len());
    for d in spans {
        let id = d.context.span_id().to_be_bytes().to_vec();
        let (scope, s) = got
            .iter()
            .find(|(_, s)| bytes(s, "span_id") == id)
            .expect("every span comes back");
        assert_eq!(scope, d.target);
        assert_eq!(bytes(s, "trace_id"), d.context.trace_id().to_be_bytes());
        match &d.parent {
            Some(p) => assert_eq!(bytes(s, "parent_span_id"), p.span_id().to_be_bytes()),
            None => assert!(bytes(s, "parent_span_id").is_empty()),
        }
        assert_eq!(text(s, "name"), d.name);
        let kind = match d.kind {
            SpanKind::Internal => 1,
            SpanKind::Server => 2,
            SpanKind::Client => 3,
            SpanKind::Producer => 4,
            _ => 5,
        };
        assert_eq!(u64_of(s, "kind"), kind);
        assert_eq!(u64_of(s, "start_time_unix_nano"), nanos(d.start));
        assert_eq!(u64_of(s, "end_time_unix_nano"), nanos(d.end));
        assert!(same(&attrs(s, "attributes"), &expected_fields(&d.fields)));
        let st = msg(s, "status");
        match &d.status {
            SpanStatus::Error(m) => {
                assert_eq!(u64_of(&st, "code"), 2);
                assert_eq!(text(&st, "message"), *m);
            }
            SpanStatus::Ok => assert_eq!(u64_of(&st, "code"), 1),
            _ => assert_eq!(u64_of(&st, "code"), 0),
        }
        assert_eq!(
            u64_of(s, "flags") & 0xff,
            u64::from(d.context.flags()),
            "W3C flags"
        );
        let events = msgs(s, "events");
        assert_eq!(events.len(), d.events.len());
        for (e, want) in events.iter().zip(&d.events) {
            assert_eq!(text(e, "name"), want.name);
            assert_eq!(u64_of(e, "time_unix_nano"), nanos(want.time));
            assert!(same(
                &attrs(e, "attributes"),
                &expected_fields(&want.fields)
            ));
        }
        assert_eq!(
            u64_of(s, "dropped_events_count"),
            u64::from(d.dropped_events)
        );
        let links = msgs(s, "links");
        assert_eq!(links.len(), d.links.len());
        for (l, want) in links.iter().zip(&d.links) {
            assert_eq!(bytes(l, "trace_id"), want.context.trace_id().to_be_bytes());
            assert_eq!(bytes(l, "span_id"), want.context.span_id().to_be_bytes());
            let flags = u64_of(l, "flags");
            assert_eq!(flags & 0xff, u64::from(want.context.flags()));
            assert_eq!(flags & 0x200 != 0, want.context.is_remote());
            assert!(same(
                &attrs(l, "attributes"),
                &expected_fields(&want.fields)
            ));
        }
        assert_eq!(u64_of(s, "dropped_links_count"), u64::from(d.dropped_links));
    }
}

fn check_logs(records: &[LogData]) {
    let req = decode("ExportLogsServiceRequest", otlp::logs_request(records, &[]));
    let mut got = Vec::new();
    for rl in msgs(&req, "resource_logs") {
        for sl in msgs(&rl, "scope_logs") {
            let scope = text(&msg(&sl, "scope"), "name");
            for r in msgs(&sl, "log_records") {
                got.push((scope.clone(), r));
            }
        }
    }
    assert_eq!(got.len(), records.len());
    // Records come back grouped by target, in their order within a target.
    for want in records {
        let i = got
            .iter()
            .position(|(scope, _)| *scope == want.target)
            .expect("the record's scope");
        let (_, r) = got.remove(i);
        assert_eq!(u64_of(&r, "time_unix_nano"), nanos(want.time));
        assert_eq!(u64_of(&r, "observed_time_unix_nano"), nanos(want.time));
        assert_eq!(
            u64_of(&r, "severity_number"),
            u64::from(otlp::severity(want.level))
        );
        assert_eq!(text(&r, "severity_text"), want.level.as_str());
        assert_eq!(
            any(&msg(&r, "body")),
            FieldValue::Str(want.message.clone().into())
        );
        let mut fields: Vec<(String, FieldValue)> = want
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), expected(v)))
            .collect();
        if let Some(f) = &want.file {
            fields.push(("code.file.path".into(), FieldValue::Str(f.clone().into())));
        }
        if let Some(l) = want.line {
            fields.push(("code.line.number".into(), FieldValue::I64(i64::from(l))));
        }
        assert!(same(&attrs(&r, "attributes"), &fields));
        match &want.span {
            Some(c) => {
                assert_eq!(bytes(&r, "trace_id"), c.trace_id().to_be_bytes());
                assert_eq!(bytes(&r, "span_id"), c.span_id().to_be_bytes());
                assert_eq!(u64_of(&r, "flags"), u64::from(c.flags()));
            }
            None => {
                assert!(bytes(&r, "trace_id").is_empty() && bytes(&r, "span_id").is_empty());
            }
        }
    }
}

fn check_metrics(f: &Families) {
    let t0 = UNIX_EPOCH + Duration::from_secs(7);
    let t1 = t0 + Duration::from_secs(3);
    let req = decode(
        "ExportMetricsServiceRequest",
        otlp::metrics_request(f, &[], t0, t1),
    );
    let sm = msgs(&msgs(&req, "resource_metrics")[0], "scope_metrics");
    let metrics = msgs(&sm[0], "metrics");
    assert_eq!(metrics.len(), f.len());
    for (m, fam) in metrics.iter().zip(f.iter()) {
        assert_eq!(text(m, "name"), fam.name);
        let hist = match fam.kind {
            only_core::metrics::Kind::Histogram => msg(m, "histogram"),
            _ => continue,
        };
        assert_eq!(u64_of(&hist, "aggregation_temporality"), 2);
        let points = msgs(&hist, "data_points");
        assert_eq!(points.len(), fam.samples.len());
        for (p, s) in points.iter().zip(&fam.samples) {
            let only_core::metrics::Value::Histogram(h) = &s.value else {
                panic!()
            };
            assert_eq!(u64_of(p, "count"), h.count());
            assert_eq!(u64_of(p, "start_time_unix_nano"), nanos(t0));
            let ex = msgs(p, "exemplars");
            assert_eq!(ex.len(), h.exemplars.len());
            for (e, want) in ex.iter().zip(&h.exemplars) {
                assert_eq!(bytes(e, "trace_id"), want.trace_id.to_be_bytes());
                assert_eq!(bytes(e, "span_id"), want.span_id.to_be_bytes());
                assert_eq!(u64_of(e, "time_unix_nano"), nanos(want.time));
                match get(e, "as_double") {
                    Value::F64(v) => assert_eq!(v.to_bits(), want.value.to_bits()),
                    v => panic!("{v:?}"),
                }
            }
        }
    }
}

// ---- examples -------------------------------------------------------------------------------

fn ctx(t: u128, s: u64, sampled: bool, remote: bool) -> SpanContext {
    SpanContext::new(t, s, sampled, remote).unwrap()
}

fn example_span() -> SpanData {
    let mut d = SpanData::__fuzz(ctx(
        0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736,
        0x00f0_67aa_0ba9_02b7,
        true,
        false,
    ));
    d.name = "GET /users/:id".into();
    d.target = "only_http::request";
    d.kind = SpanKind::Server;
    d.parent = Some(ctx(
        0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736,
        0x1111,
        true,
        true,
    ));
    d.start = UNIX_EPOCH + Duration::from_nanos(1_700_000_000_123_456_789);
    d.end = d.start + Duration::from_millis(3);
    d.fields = vec![
        ("http.route".into(), "/users/:id".into()),
        ("status".into(), FieldValue::U64(200)),
        ("big".into(), FieldValue::U64(u64::MAX)),
        ("neg".into(), FieldValue::I64(-5)),
        ("ratio".into(), FieldValue::F64(0.25)),
        ("ok".into(), FieldValue::Bool(true)),
    ];
    d.status = SpanStatus::Error("boom".into());
    d.events = vec![
        SpanEvent::new("retry", d.start + Duration::from_millis(1)).field("attempt", 2u64),
        SpanEvent::new("cache miss", d.start + Duration::from_millis(2)),
    ];
    d.dropped_events = 3;
    d.links = vec![
        SpanLink::new(ctx(7, 9, true, true)).field("reason", "fan-in"),
        SpanLink::new(ctx(8, 10, false, false)),
    ];
    d.dropped_links = 1;
    d
}

fn example_log(span: Option<SpanContext>) -> LogData {
    LogData {
        time: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        level: Level::Warn,
        target: "app::db".into(),
        message: "slow query \"x\"".into(),
        fields: vec![
            ("rows".into(), FieldValue::U64(3)),
            ("table".into(), "users".into()),
        ],
        file: Some("src/db.rs".into()),
        line: Some(42),
        span,
    }
}

#[test]
fn spans_with_events_and_links_round_trip() {
    let mut plain = SpanData::__fuzz(ctx(1, 2, true, false));
    plain.target = "other";
    check_spans(&[example_span(), plain]);
}

#[test]
fn logs_round_trip_with_and_without_a_span() {
    let mut other = example_log(None);
    other.target = "app::http".into();
    other.level = Level::Trace;
    other.file = None;
    other.line = None;
    check_logs(&[
        example_log(Some(ctx(0xabc, 0xdef, true, false))),
        other,
        example_log(None),
    ]);
}

#[test]
fn metrics_with_exemplars_round_trip() {
    let mut f = Families::new();
    f.counter("reqs_total", "Requests.", &[("route", "/a")], 3.0);
    f.gauge("open", "Open.", &[], -1.5);
    let h = HistogramSnapshot::new(vec![0.1, 1.0], vec![1, 2, 0], 1.25)
        .unwrap()
        .with_exemplars(vec![
            Exemplar::new(0.05, UNIX_EPOCH + Duration::from_secs(9), 0xabc, 0x12),
            Exemplar::new(
                0.5,
                UNIX_EPOCH + Duration::from_secs(9),
                u128::MAX,
                u64::MAX,
            ),
        ]);
    f.histogram("lat_seconds", "Latency.", &[("route", "/a")], &h);
    f.histogram(
        "lat_seconds",
        "Latency.",
        &[("route", "/b")],
        &HistogramSnapshot::new(vec![1.0], vec![0, 0], 0.0).unwrap(),
    );
    check_metrics(&f);
}

#[test]
fn partial_success_is_read_from_every_response() {
    let mut body = Vec::new();
    let mut ps = Msg::new();
    ps.set(1, "rejectedSpans", Node::I64(7))
        .str(2, "errorMessage", "too big");
    let mut resp = Msg::new();
    resp.msg(1, "partialSuccess", ps);
    check_schema(&resp.0, &desc("ExportTraceServiceResponse"));
    crate::tree::to_protobuf(&resp.0, &mut body);
    assert_eq!(otlp::partial_success(&body), (7, "too big".into()));
    assert_eq!(otlp::partial_success(&[]), (0, "".into()));
    assert_eq!(otlp::partial_success(&[0xff, 0xff]), (0, "".into()));
    // An unknown field before it is skipped.
    let mut other = vec![0x10, 0x01];
    other.extend_from_slice(&body);
    assert_eq!(otlp::partial_success(&other).0, 7);
}

// ---- seeded random inputs (the fuzz target `export_otlp` explores further) ------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn string(&mut self) -> String {
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', ' ', '"', '\\', '\n', '\u{1}', 'é', '中', '😀', '/', ':',
        ];
        (0..self.below(12))
            .map(|_| ALPHABET[self.below(ALPHABET.len() as u64) as usize])
            .collect()
    }
    fn value(&mut self) -> FieldValue {
        match self.below(6) {
            0 => FieldValue::Str(self.string().into()),
            1 => FieldValue::I64(self.next() as i64),
            2 => FieldValue::U64(self.next() >> self.below(2)),
            3 => FieldValue::F64(f64::from_bits(self.next())),
            4 => FieldValue::Bool(self.below(2) == 1),
            _ => FieldValue::F64(-0.0),
        }
    }
    fn fields(&mut self) -> Vec<(Cow<'static, str>, FieldValue)> {
        (0..self.below(4))
            .map(|_| (Cow::Owned(self.string()), self.value()))
            .collect()
    }
    fn time(&mut self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.next() >> 2)
    }
    fn ctx(&mut self) -> SpanContext {
        let t = (u128::from(self.next()) << 64 | u128::from(self.next())).max(1);
        ctx(
            t,
            self.next().max(1),
            self.below(2) == 1,
            self.below(2) == 1,
        )
    }
}

#[test]
fn random_spans_logs_and_exemplars_round_trip() {
    const TARGETS: [&str; 3] = ["a", "b::c", ""];
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..300 {
        let spans: Vec<SpanData> = (0..=r.below(4))
            .map(|_| {
                let mut d = SpanData::__fuzz(r.ctx());
                d.name = r.string().into();
                d.target = TARGETS[r.below(3) as usize];
                d.kind = [
                    SpanKind::Internal,
                    SpanKind::Server,
                    SpanKind::Client,
                    SpanKind::Producer,
                    SpanKind::Consumer,
                ][r.below(5) as usize];
                d.parent = (r.below(2) == 1).then(|| r.ctx());
                d.start = r.time();
                d.end = r.time();
                d.fields = r.fields();
                d.status = match r.below(3) {
                    0 => SpanStatus::Unset,
                    1 => SpanStatus::Ok,
                    _ => SpanStatus::Error(r.string().into()),
                };
                for _ in 0..r.below(3) {
                    let mut e = SpanEvent::new(r.string(), r.time());
                    e.fields = r.fields();
                    d.events.push(e);
                }
                for _ in 0..r.below(3) {
                    let mut l = SpanLink::new(r.ctx());
                    l.fields = r.fields();
                    d.links.push(l);
                }
                d.dropped_events = r.below(3) as u32;
                d.dropped_links = r.below(3) as u32;
                d
            })
            .collect();
        check_spans(&spans);

        let records: Vec<LogData> = (0..=r.below(4))
            .map(|_| LogData {
                time: r.time(),
                level: Level::ALL[r.below(5) as usize],
                target: TARGETS[r.below(3) as usize].to_owned(),
                message: r.string(),
                fields: r
                    .fields()
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v))
                    .collect(),
                file: (r.below(2) == 1).then(|| r.string()),
                line: (r.below(2) == 1).then(|| r.next() as u32),
                span: (r.below(2) == 1).then(|| r.ctx()),
            })
            .collect();
        check_logs(&records);

        let mut f = Families::new();
        let n = 1 + r.below(4) as usize;
        let bounds: Vec<f64> = (0..n).map(|i| i as f64 + 0.5).collect();
        let counts: Vec<u64> = (0..=n).map(|_| r.below(100)).collect();
        let ex = (0..r.below(3))
            .map(|_| {
                let c = r.ctx();
                Exemplar::new(
                    f64::from_bits(r.next()),
                    r.time(),
                    c.trace_id(),
                    c.span_id(),
                )
            })
            .collect();
        let h = HistogramSnapshot::new(bounds, counts, 1.0)
            .unwrap()
            .with_exemplars(ex);
        f.histogram("h", "", &[("k", &r.string())], &h);
        check_metrics(&f);
    }
}
