//! OTLP request bodies (opentelemetry-proto v1: `ExportMetricsServiceRequest`,
//! `ExportTraceServiceRequest`) built from `Families` and finished spans.

use std::time::{SystemTime, UNIX_EPOCH};

use only_core::metrics::{Families, Kind, Value};
use only_log::span::{FieldValue, SpanData, SpanKind, SpanStatus};

use crate::tree::{Msg, Node};

/// The encoding of OTLP/HTTP request bodies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    /// Binary protobuf (`application/x-protobuf`), the OTLP/HTTP default.
    #[default]
    Protobuf,
    /// OTLP/JSON (`application/json`).
    Json,
}

impl Encoding {
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Encoding::Protobuf => "application/x-protobuf",
            Encoding::Json => "application/json",
        }
    }

    pub(crate) fn encode(self, root: Msg) -> Vec<u8> {
        match self {
            Encoding::Protobuf => {
                let mut out = Vec::with_capacity(4096);
                crate::tree::to_protobuf(&root.0, &mut out);
                out
            }
            Encoding::Json => {
                let mut out = String::with_capacity(8192);
                crate::tree::to_json(&root.0, &mut out);
                out.into_bytes()
            }
        }
    }
}

pub(crate) fn unix_nanos(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

fn any_str(s: &str) -> Msg {
    let mut v = Msg::new();
    v.str(1, "stringValue", s);
    v
}

fn kv(key: &str, value: Msg) -> Msg {
    let mut m = Msg::new();
    m.str(1, "key", key).msg(2, "value", value);
    m
}

fn field_any(v: &FieldValue) -> Msg {
    let mut a = Msg::new();
    match v {
        FieldValue::Str(s) => {
            a.str(1, "stringValue", s.as_ref());
        }
        FieldValue::Bool(b) => {
            a.set(2, "boolValue", Node::Bool(*b));
        }
        FieldValue::I64(i) => {
            a.set(3, "intValue", Node::I64(*i));
        }
        FieldValue::U64(u) => match i64::try_from(*u) {
            Ok(i) => {
                a.set(3, "intValue", Node::I64(i));
            }
            Err(_) => {
                a.str(1, "stringValue", u.to_string());
            }
        },
        FieldValue::F64(f) => {
            a.set(4, "doubleValue", Node::Double(*f));
        }
        other => {
            a.str(1, "stringValue", other.to_string());
        }
    }
    a
}

/// `Resource` with the given attributes.
pub(crate) fn resource(attrs: &[(String, String)]) -> Msg {
    let mut r = Msg::new();
    for (k, v) in attrs {
        r.push_msg(1, "attributes", kv(k, any_str(v)));
    }
    r
}

fn scope(name: &str) -> Msg {
    let mut s = Msg::new();
    s.str(1, "name", name)
        .str(2, "version", env!("CARGO_PKG_VERSION"));
    s
}

fn point_attrs(m: &mut Msg, num: u32, labels: &[(String, String)]) {
    for (k, v) in labels {
        m.push_msg(num, "attributes", kv(k, any_str(v)));
    }
}

/// `ExportMetricsServiceRequest` for one snapshot; cumulative temporality from `start`.
pub(crate) fn metrics_request(
    f: &Families,
    resource_attrs: &[(String, String)],
    start: SystemTime,
    now: SystemTime,
) -> Msg {
    let (t0, t1) = (unix_nanos(start), unix_nanos(now));
    let mut sm = Msg::new();
    sm.msg(1, "scope", scope("only"));
    for fam in f.iter() {
        let mut metric = Msg::new();
        metric.str(1, "name", fam.name.as_str());
        if !fam.help.is_empty() {
            metric.str(2, "description", fam.help.as_str());
        }
        let mut data = Msg::new();
        for s in &fam.samples {
            match &s.value {
                Value::Counter(v) | Value::Gauge(v) => {
                    let mut p = Msg::new();
                    point_attrs(&mut p, 7, &s.labels);
                    if fam.kind == Kind::Counter {
                        p.set(2, "startTimeUnixNano", Node::Fixed64(t0));
                    }
                    p.set(3, "timeUnixNano", Node::Fixed64(t1)).set(
                        4,
                        "asDouble",
                        Node::Double(*v),
                    );
                    data.push_msg(1, "dataPoints", p);
                }
                Value::Histogram(h) => {
                    let mut p = Msg::new();
                    point_attrs(&mut p, 9, &s.labels);
                    p.set(2, "startTimeUnixNano", Node::Fixed64(t0))
                        .set(3, "timeUnixNano", Node::Fixed64(t1))
                        .set(4, "count", Node::Fixed64(h.count()))
                        .set(5, "sum", Node::Double(h.sum))
                        .set(6, "bucketCounts", Node::PackedFixed64(h.counts.clone()))
                        .set(7, "explicitBounds", Node::PackedDouble(h.bounds.clone()));
                    data.push_msg(1, "dataPoints", p);
                }
                _ => {}
            }
        }
        match fam.kind {
            Kind::Counter => {
                data.set(2, "aggregationTemporality", Node::U32(2)).set(
                    3,
                    "isMonotonic",
                    Node::Bool(true),
                );
                metric.msg(7, "sum", data);
            }
            Kind::Gauge => {
                metric.msg(5, "gauge", data);
            }
            Kind::Histogram => {
                data.set(2, "aggregationTemporality", Node::U32(2));
                metric.msg(9, "histogram", data);
            }
            _ => continue,
        }
        sm.push_msg(2, "metrics", metric);
    }
    let mut rm = Msg::new();
    rm.msg(1, "resource", resource(resource_attrs))
        .push_msg(2, "scopeMetrics", sm);
    let mut req = Msg::new();
    req.push_msg(1, "resourceMetrics", rm);
    req
}

fn span_kind(k: SpanKind) -> u32 {
    match k {
        SpanKind::Internal => 1,
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
        _ => 0,
    }
}

fn span_msg(s: &SpanData) -> Msg {
    let mut m = Msg::new();
    m.set(
        1,
        "traceId",
        Node::Id(s.context.trace_id().to_be_bytes().to_vec()),
    )
    .set(
        2,
        "spanId",
        Node::Id(s.context.span_id().to_be_bytes().to_vec()),
    );
    if let Some(p) = &s.parent {
        m.set(
            4,
            "parentSpanId",
            Node::Id(p.span_id().to_be_bytes().to_vec()),
        );
    }
    m.str(5, "name", s.name.as_ref())
        .set(6, "kind", Node::U32(span_kind(s.kind)))
        .set(7, "startTimeUnixNano", Node::Fixed64(unix_nanos(s.start)))
        .set(8, "endTimeUnixNano", Node::Fixed64(unix_nanos(s.end)));
    for (k, v) in &s.fields {
        m.push_msg(9, "attributes", kv(k, field_any(v)));
    }
    let mut st = Msg::new();
    match &s.status {
        SpanStatus::Unset => {}
        SpanStatus::Ok => {
            st.set(3, "code", Node::U32(1));
        }
        SpanStatus::Error(msg) => {
            st.str(2, "message", msg.as_ref())
                .set(3, "code", Node::U32(2));
        }
        _ => {}
    }
    m.msg(15, "status", st);
    // W3C trace flags, plus "has remote parent" information (bits 8 and 9 of `flags`).
    let mut flags = u32::from(s.context.flags());
    if let Some(p) = &s.parent {
        flags |= 0x100 | if p.is_remote() { 0x200 } else { 0 };
    } else {
        flags |= 0x100;
    }
    m.set(16, "flags", Node::Fixed32(flags));
    m
}

/// `ExportTraceServiceRequest` for a batch of spans, one scope per span target.
pub(crate) fn traces_request(spans: &[SpanData], resource_attrs: &[(String, String)]) -> Msg {
    let mut targets: Vec<&'static str> = Vec::new();
    for s in spans {
        if !targets.contains(&s.target) {
            targets.push(s.target);
        }
    }
    let mut rs = Msg::new();
    rs.msg(1, "resource", resource(resource_attrs));
    for t in targets {
        let mut ss = Msg::new();
        ss.msg(1, "scope", scope(t));
        for s in spans.iter().filter(|s| s.target == t) {
            ss.push_msg(2, "spans", span_msg(s));
        }
        rs.push_msg(2, "scopeSpans", ss);
    }
    let mut req = Msg::new();
    req.push_msg(1, "resourceSpans", rs);
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::metrics::HistogramSnapshot;

    #[test]
    fn metrics_json_shape() {
        let mut f = Families::new();
        f.counter("reqs_total", "Requests.", &[("route", "/a")], 3.0);
        f.gauge("open", "Open.", &[], -1.5);
        let h = HistogramSnapshot::new(vec![0.1, 1.0], vec![1, 2, 0], 1.25).unwrap();
        f.histogram("lat_seconds", "Latency.", &[], &h);
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1);
        let req = metrics_request(&f, &[("service.name".into(), "svc".into())], t, t);
        let js = String::from_utf8(Encoding::Json.encode(req)).unwrap();
        assert!(js.starts_with(r#"{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"svc"}}]},"scopeMetrics":[{"scope":{"name":"only""#), "{js}");
        assert!(js.contains(r#"{"name":"reqs_total","description":"Requests.","sum":{"dataPoints":[{"attributes":[{"key":"route","value":{"stringValue":"/a"}}],"startTimeUnixNano":"1000000000","timeUnixNano":"1000000000","asDouble":3.0}],"aggregationTemporality":2,"isMonotonic":true}}"#), "{js}");
        assert!(
            js.contains(
                r#""gauge":{"dataPoints":[{"timeUnixNano":"1000000000","asDouble":-1.5}]}"#
            ),
            "{js}"
        );
        assert!(js.contains(r#""count":"3","sum":1.25,"bucketCounts":["1","2","0"],"explicitBounds":[0.1,1.0]}],"aggregationTemporality":2}"#), "{js}");
        let pb = Encoding::Protobuf.encode(metrics_request(&f, &[], t, t));
        assert_eq!(pb[0], 0x0a, "field 1, length-delimited");
    }
}
