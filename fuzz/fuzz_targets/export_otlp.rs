#![no_main]
//! OTLP bodies built from strings a peer controls (span names, fields, span events and links,
//! log messages and key-values): the JSON must parse (serde_json) and carry the same strings
//! back, the protobuf must decode to them, and StatsD lines must keep their framing whatever the
//! label values hold.

use akio_protobuf::encoding::{Reader, WireType};

fn len_fields(buf: &[u8], num: u32) -> Vec<&[u8]> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (f, wt) = r.read_tag().expect("tag");
        if wt == WireType::Len {
            let b = r.read_bytes().expect("bytes");
            if f == num {
                out.push(b);
            }
        } else {
            r.skip_field(f, wt).expect("skip");
        }
    }
    out
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let mut parts = s.splitn(3, '\u{0}');
    let (name, key, value) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let js = akio_export::fuzzing::otlp_span_json(name, key, value);
    let v: serde_json::Value = serde_json::from_str(&js).expect("valid JSON");
    let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(span["name"].as_str(), Some(name));
    assert_eq!(span["attributes"][0]["key"].as_str(), Some(key));
    assert_eq!(
        span["attributes"][0]["value"]["stringValue"].as_str(),
        Some(value)
    );
    assert_eq!(span["events"][0]["name"].as_str(), Some(key));
    assert_eq!(
        span["events"][0]["attributes"][0]["value"]["stringValue"].as_str(),
        Some(value)
    );
    assert_eq!(span["links"][0]["attributes"][0]["key"].as_str(), Some(key));

    let js = akio_export::fuzzing::otlp_log_json(key, name, key, value);
    let v: serde_json::Value = serde_json::from_str(&js).expect("valid JSON");
    let scope = &v["resourceLogs"][0]["scopeLogs"][0];
    assert_eq!(scope["scope"]["name"].as_str(), Some(key));
    let rec = &scope["logRecords"][0];
    assert_eq!(rec["body"]["stringValue"].as_str(), Some(name));
    assert_eq!(rec["attributes"][0]["key"].as_str(), Some(key));
    assert_eq!(
        rec["attributes"][0]["value"]["stringValue"].as_str(),
        Some(value)
    );
    let pb = akio_export::fuzzing::otlp_log_protobuf(key, name, key, value);
    let records: Vec<&[u8]> = len_fields(&pb, 1)
        .into_iter()
        .flat_map(|rl| len_fields(rl, 2))
        .flat_map(|sl| len_fields(sl, 2))
        .collect();
    assert_eq!(records.len(), 1);
    let body = len_fields(records[0], 5);
    assert_eq!(len_fields(body[0], 1), [name.as_bytes()]);

    let pb = akio_export::fuzzing::otlp_span_protobuf(name, key, value);
    let spans: Vec<&[u8]> = len_fields(&pb, 1)
        .into_iter()
        .flat_map(|rs| len_fields(rs, 2))
        .flat_map(|ss| len_fields(ss, 2))
        .collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(len_fields(spans[0], 5), [name.as_bytes()]);

    for line in akio_export::fuzzing::statsd_lines("m", "l", value) {
        assert!(!line.contains('\n'), "{line:?}");
        let pipes = line.matches('|').count();
        assert!(pipes == 1 || pipes == 2, "{line:?}");
        assert!(
            line.split('|').nth(1).is_some_and(|t| t == "c" || t == "g"),
            "{line:?}"
        );
    }
});
